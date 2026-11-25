//! M2 Tier 2 Vault, Controlled Cryptographic Shredding, Outbox Reconciliation,
//! Blocked Tier 2 Rekey, and Mobile State Snapshot (`MNP1`) extensions on `LocalStore`.

use super::*;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use mynote_core::crypto::{VaultHeaderV1, MAGIC_MNB1, MAGIC_MNW1};
use mynote_core::ids::{MarkId, SnapshotId};
use mynote_core::model::{ShredMarkRow, ShredMarkState};
use mynote_core::snapshot::{pack_state_snapshot, SnapshotHeaderV1};
use mynote_core::sync::{OutboxKeyAction, ShredResultDto};
use mynote_core::vault::{T_GRACE_DEFAULT_MS, T_GRACE_MIN_MS};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultHeaderDto {
    pub gen: i64,
    pub blob_b64: String,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockedTier2OpDto {
    pub op_id: String,
    pub block_id: String,
    pub buffer_id: String,
    pub lang: String,
    pub public_hint: Option<String>,
    pub old_key_id: String,
    pub reason: String,
    pub mnb1_b64: String,
    pub mnw1_b64: Option<String>,
    pub head_op_ids: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Tier2OpInput<'a> {
    pub op_id: &'a str,
    pub key_id: &'a str,
    pub mnb1: &'a [u8],
    pub mnw1: Option<&'a [u8]>,
}

pub(super) fn shred_state_to_str(s: ShredMarkState) -> &'static str {
    match s {
        ShredMarkState::PendingConfirm => "pending_confirm",
        ShredMarkState::Scheduled => "scheduled",
        ShredMarkState::Cancelled => "cancelled",
        ShredMarkState::Executed => "executed",
    }
}

pub(super) fn str_to_shred_state(s: &str) -> ShredMarkState {
    match s {
        "pending_confirm" => ShredMarkState::PendingConfirm,
        "scheduled" => ShredMarkState::Scheduled,
        "cancelled" => ShredMarkState::Cancelled,
        "executed" => ShredMarkState::Executed,
        _ => ShredMarkState::PendingConfirm,
    }
}

pub(super) fn shred_state_rank(s: ShredMarkState) -> u8 {
    match s {
        ShredMarkState::PendingConfirm => 0,
        ShredMarkState::Scheduled => 1,
        ShredMarkState::Cancelled => 2,
        ShredMarkState::Executed => 3,
    }
}

fn validate_mnb1_header(key_id: KeyId, mnb1: &[u8]) -> Result<(), CoreError> {
    if mnb1.len() < 45 + 16 || &mnb1[0..4] != MAGIC_MNB1 || mnb1[4] != 1 {
        return Err(CoreError::new(
            ErrorCode::IntegrityError,
            "invalid MNB1 ciphertext header",
            "Re-encrypt Tier 2 payload via WasmVaultSession",
        ));
    }
    if &mnb1[5..21] != key_id.as_bytes() {
        return Err(CoreError::new(
            ErrorCode::IntegrityError,
            "MNB1 header key_id does not match request key_id",
            "Ensure Tier 2 op key_id matches the MNB1 header",
        ));
    }
    Ok(())
}

fn validate_mnw1_header(mnw1: &[u8]) -> Result<(), CoreError> {
    if mnw1.len() < 45 + 16 || &mnw1[0..4] != MAGIC_MNW1 || mnw1[4] != 1 {
        return Err(CoreError::new(
            ErrorCode::IntegrityError,
            "invalid MNW1 wrapped BDEK header",
            "Re-wrap Tier 2 BDEK via WasmVaultSession",
        ));
    }
    Ok(())
}

impl LocalStore {
    /// Return the 32-byte X25519 recovery public key stored in `RecoveryKeyringV1`.
    pub fn recovery_pk(&self) -> Result<[u8; 32], CoreError> {
        Ok(self.current_keyring()?.recovery_pk)
    }

    /// Return the current `VaultHeaderV1` from `key_material`, if Vault has been initialized.
    pub fn get_vault_header(&self) -> Result<Option<VaultHeaderDto>, CoreError> {
        let row: Option<(i64, Vec<u8>, i64)> = self
            .conn
            .query_row(
                "SELECT gen, blob, updated_at_ms FROM key_material WHERE kind = 'vault_header'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query vault_header"))?;
        Ok(row.map(|(gen, blob, updated_at_ms)| VaultHeaderDto {
            gen,
            blob_b64: B64.encode(blob),
            updated_at_ms,
        }))
    }

    /// Store or monotonically advance `VaultHeaderV1` (`vault init` / `vault passwd`).
    /// Daemon never receives VKEK or passphrase — only opaque `VaultHeaderV1` bytes.
    pub fn put_vault_header(&mut self, gen: i64, blob: &[u8]) -> Result<VaultHeaderDto, CoreError> {
        let parsed: VaultHeaderV1 = rmp_serde::from_slice(blob).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("invalid VaultHeaderV1 msgpack: {e}"),
                "Provide a valid VaultHeaderV1 encoded by mynote-core/mynote-wasm",
            )
        })?;
        if parsed.v != 1 {
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                format!("unsupported VaultHeaderV1 version {}", parsed.v),
                "Use VaultHeaderV1 v=1",
            ));
        }
        let existing: Option<(i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT gen, blob FROM key_material WHERE kind = 'vault_header'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .unwrap_or(None);
        if let Some((cur_gen, cur_blob)) = existing {
            if gen < cur_gen {
                return Err(CoreError::new(
                    ErrorCode::CasMismatch,
                    format!("vault_header gen {gen} < current gen {cur_gen}"),
                    "Sync the latest VaultHeaderV1 before updating passphrase",
                ));
            }
            if gen == cur_gen {
                if cur_blob != blob {
                    return Err(CoreError::new(
                        ErrorCode::IntegrityError,
                        format!("conflicting vault_header bytes at gen={cur_gen}"),
                        "Bump vault_header gen monotonically",
                    ));
                }
                return Ok(VaultHeaderDto {
                    gen: cur_gen,
                    blob_b64: B64.encode(blob),
                    updated_at_ms: parsed.updated_at_ms,
                });
            }
        }
        let now = now_ms() as i64;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO key_material (kind, gen, blob, updated_at_ms)
                 VALUES ('vault_header', ?1, ?2, ?3)",
                params![gen, blob, now],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "save vault_header"))?;
        Ok(VaultHeaderDto {
            gen,
            blob_b64: B64.encode(blob),
            updated_at_ms: now,
        })
    }

    /// Enrich a `BlockDetailDto` for the local Desktop Daemon REST/WS boundary (`docs/interface-contracts.md` §3.2).
    /// For locked (`tier == 2`) leaves, populates `key_id`, `mnb1_b64`, and inner `mnw1_b64` (unwrapped from outer `MNR1`
    /// via `SMK`, NEVER plaintext!) while keeping `content: None`.
    pub fn get_block_for_daemon(&self, block_id_str: &str) -> Result<BlockDetailDto, CoreError> {
        let mut detail = self.get_block(block_id_str)?;
        self.attach_daemon_ciphertexts(&mut detail)?;
        Ok(detail)
    }

    pub fn list_blocks_for_daemon(&self, buffer_selector: &str) -> Result<Vec<BlockDetailDto>, CoreError> {
        let mut list = self.list_blocks_detailed(buffer_selector)?;
        for item in &mut list {
            self.attach_daemon_ciphertexts(item)?;
        }
        Ok(list)
    }

    fn attach_daemon_ciphertexts(&self, detail: &mut BlockDetailDto) -> Result<(), CoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT op_id, key_id, ciphertext, tier FROM block_leaves WHERE block_id = ?1")
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query leaf blobs"))?;
        type LeafBlobRow = (Option<String>, Option<Vec<u8>>, Option<i64>);
        let mut by_op: BTreeMap<String, LeafBlobRow> = BTreeMap::new();
        let rows = stmt
            .query_map([&detail.id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<Vec<u8>>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                ))
            })
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map leaf blobs"))?;
        for r in rows.flatten() {
            by_op.insert(r.0, (r.1, r.2, r.3));
        }

        for v in &mut detail.versions {
            if let Some((kid_opt, ct_opt, tier_opt)) = by_op.get(&v.op_id) {
                v.key_id = kid_opt.clone();
                if *tier_opt == Some(2) {
                    v.content = None;
                    if let Some(ct) = ct_opt {
                        v.mnb1_b64 = Some(B64.encode(ct));
                    }
                    if let Some(kid_s) = kid_opt {
                        if let Ok(kid) = KeyId::parse(kid_s) {
                            if let Ok((2, mnw1)) = self.unwrap_bdek(kid) {
                                v.mnw1_b64 = Some(B64.encode(mnw1));
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Directly create a Tier 2 encrypted block (`POST /v1/local/blocks` Tier 2 branch).
    /// Reuses caller's `op_id` and `key_id` verbatim (`F-01`); Daemon never sees plaintext or VKEK.
    #[allow(clippy::too_many_arguments)]
    pub fn add_tier2_block(
        &mut self,
        block_id_str: &str,
        t2: Tier2OpInput<'_>,
        buffer_selector: &str,
        lang: &str,
        after_id: Option<&str>,
        public_hint: Option<&str>,
        actor: &str,
    ) -> Result<WriteReceipt, CoreError> {
        let blk_id = BlockId::parse(block_id_str)?;
        let op_id = OpId::parse(t2.op_id)?;
        let key_id = KeyId::parse(t2.key_id)?;
        validate_mnb1_header(key_id, t2.mnb1)?;
        let mnw1 = t2.mnw1.ok_or_else(|| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                "mnw1_b64 is required when creating a new Tier 2 block",
                "Encrypt new Tier 2 block via WasmVaultSession.encryptNewBlock",
            )
        })?;
        validate_mnw1_header(mnw1)?;

        let buf_id = self.resolve_buffer_id(buffer_selector)?;
        let pos = self.compute_block_position(buf_id, after_id, None)?;
        let now = now_ms();
        let hlc = self.hlc_clock.tick(now);
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();
        let keyring_gen = self.current_keyring()?.keyring_gen;

        let krec = KeyRecordV1 {
            v: 1,
            key_id,
            block_id: blk_id.0,
            tier: 2,
            created_hlc: hlc.canonical_string(),
            created_by: self.device_id.clone(),
            bdek: mnw1.to_vec(),
        };
        let mnr1 = encrypt_mnr1(smk_kid, &smk, keyring_gen, &krec, rand_bytes::<24>()?)?;
        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: blk_id.to_string(),
            op_type: OpType::Create,
            parent_op_ids: vec![],
            hlc: hlc.clone(),
            actor: actor.to_string(),
            body: OpBodyV1::BlockContent {
                buffer_id: Some(buf_id),
                position: Some(pos),
                lang: Some(lang.to_string()),
                public_hint: Some(public_hint.map(ToString::to_string)),
                tier: 2,
                key_id,
                mnb1: t2.mnb1.to_vec(),
            },
        };
        let mns1 = encrypt_mns1(smk_kid, &smk, op_id, &self.device_id, &inner, rand_bytes::<24>()?)?;

        self.conn
            .execute(
                "INSERT INTO block_keys (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                 VALUES (?1, ?2, 2, ?3, ?4, ?5, ?6, 0)",
                params![
                    key_id.to_string(),
                    blk_id.to_string(),
                    keyring_gen as i64,
                    mnr1,
                    hlc.canonical_string(),
                    now as i64,
                ],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert tier2 key"))?;
        self.insert_sync_op(
            op_id,
            None,
            EntityType::Block,
            &blk_id.to_string(),
            &[],
            OpType::Create,
            &hlc,
            actor,
            Some(key_id),
            smk_kid,
            &mns1,
            now as i64,
        )?;
        let mat = self.rematerialize_block(blk_id)?;
        self.refresh_mirror()?;

        Ok(WriteReceipt {
            block_id: mat.id.to_string(),
            op_id: op_id.to_string(),
            head_op_ids: mat.head_op_ids().into_iter().map(|o| o.to_string()).collect(),
            buffer_id: mat.buffer_id.to_string(),
            idempotent_replay: None,
        })
    }

    /// Update or resolve a Tier 2 locked block (`PATCH /v1/local/blocks/:id` Tier 2 branch).
    /// Reuses caller's `op_id` verbatim (`F-01`); if `mnw1` is omitted, validates `key_id` already exists as Tier 2.
    #[allow(clippy::too_many_arguments)]
    pub fn update_tier2_block(
        &mut self,
        block_id_str: &str,
        t2: Tier2OpInput<'_>,
        expected_heads: &[String],
        lang: Option<&str>,
        public_hint: Option<Option<&str>>,
        actor: &str,
    ) -> Result<WriteReceipt, CoreError> {
        let detail = self.get_block(block_id_str)?;
        self.check_bootstrap_gate(EntityType::Block, &detail.id, OpType::Update)?;
        let exp_set: BTreeSet<String> = expected_heads.iter().cloned().collect();
        let act_set: BTreeSet<String> = detail.head_op_ids.iter().cloned().collect();
        if exp_set != act_set {
            return Err(CoreError::new(
                ErrorCode::HeadMismatch,
                format!("block {block_id_str} heads changed concurrently"),
                "Refresh block state and retry",
            )
            .with_details(serde_json::json!({
                "expected_heads": expected_heads,
                "actual_heads": detail.head_op_ids,
            })));
        }

        let blk_id = BlockId::parse(block_id_str)?;
        let op_id = OpId::parse(t2.op_id)?;
        let key_id = KeyId::parse(t2.key_id)?;
        validate_mnb1_header(key_id, t2.mnb1)?;

        let parents: Vec<OpId> = detail
            .head_op_ids
            .iter()
            .map(|s| OpId::parse(s))
            .collect::<Result<_, _>>()?;
        let now = now_ms();
        let hlc = self.hlc_clock.tick(now);
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();

        if let Some(mnw1) = t2.mnw1 {
            validate_mnw1_header(mnw1)?;
            let keyring_gen = self.current_keyring()?.keyring_gen;
            let krec = KeyRecordV1 {
                v: 1,
                key_id,
                block_id: blk_id.0,
                tier: 2,
                created_hlc: hlc.canonical_string(),
                created_by: self.device_id.clone(),
                bdek: mnw1.to_vec(),
            };
            let mnr1 = encrypt_mnr1(smk_kid, &smk, keyring_gen, &krec, rand_bytes::<24>()?)?;
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO block_keys (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                     VALUES (?1, ?2, 2, ?3, ?4, ?5, ?6, 0)",
                    params![
                        key_id.to_string(),
                        blk_id.to_string(),
                        keyring_gen as i64,
                        mnr1,
                        hlc.canonical_string(),
                        now as i64,
                    ],
                )
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert tier2 key"))?;
        } else {
            let (tier, _) = self.unwrap_bdek(key_id)?;
            if tier != 2 {
                return Err(CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("key_id {key_id} is not a Tier 2 key"),
                    "Provide a Tier 2 key_id or rekey with mnw1",
                ));
            }
        }

        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: blk_id.to_string(),
            op_type: OpType::Update,
            parent_op_ids: parents.clone(),
            hlc: hlc.clone(),
            actor: actor.to_string(),
            body: OpBodyV1::BlockContent {
                buffer_id: None,
                position: None,
                lang: lang.map(ToString::to_string),
                public_hint: public_hint.map(|opt| opt.map(ToString::to_string)),
                tier: 2,
                key_id,
                mnb1: t2.mnb1.to_vec(),
            },
        };
        let mns1 = encrypt_mns1(smk_kid, &smk, op_id, &self.device_id, &inner, rand_bytes::<24>()?)?;
        self.insert_sync_op(
            op_id,
            None,
            EntityType::Block,
            &blk_id.to_string(),
            &parents,
            OpType::Update,
            &hlc,
            actor,
            Some(key_id),
            smk_kid,
            &mns1,
            now as i64,
        )?;
        let mat = self.rematerialize_block(blk_id)?;
        self.refresh_mirror()?;

        Ok(WriteReceipt {
            block_id: mat.id.to_string(),
            op_id: op_id.to_string(),
            head_op_ids: mat.head_op_ids().into_iter().map(|o| o.to_string()).collect(),
            buffer_id: mat.buffer_id.to_string(),
            idempotent_replay: None,
        })
    }

    /// Rekey & lock a block to Tier 2 Vault (`POST /v1/local/blocks/:id/lock`, `mynote vault lock`).
    /// Atomically writes `LOCK` op + new Tier 2 key, removes plaintext from `block_leaves` & `blocks_fts`,
    /// checkpoints WAL + optimizes FTS5, and queues local `shred_marks` for all old unshredded keys!
    #[allow(clippy::too_many_arguments)]
    pub fn lock_block_tier2(
        &mut self,
        block_id_str: &str,
        t2: Tier2OpInput<'_>,
        expected_heads: &[String],
        lang: Option<&str>,
        public_hint: Option<&str>,
        grace_ms: i64,
        actor: &str,
    ) -> Result<WriteReceipt, CoreError> {
        let detail = self.get_block(block_id_str)?;
        self.check_bootstrap_gate(EntityType::Block, &detail.id, OpType::Lock)?;
        if !expected_heads.is_empty() {
            let exp_set: BTreeSet<String> = expected_heads.iter().cloned().collect();
            let act_set: BTreeSet<String> = detail.head_op_ids.iter().cloned().collect();
            if exp_set != act_set {
                return Err(CoreError::new(
                    ErrorCode::HeadMismatch,
                    format!("block {block_id_str} heads changed concurrently"),
                    "Refresh block state and retry lock",
                )
                .with_details(serde_json::json!({
                    "expected_heads": expected_heads,
                    "actual_heads": detail.head_op_ids,
                })));
            }
        }
        if grace_ms < T_GRACE_MIN_MS {
            return Err(CoreError::new(
                ErrorCode::GraceTooShort,
                format!("grace_ms {grace_ms} is shorter than minimum {T_GRACE_MIN_MS}"),
                "Use default grace (7 days) or minimum grace (24 hours)",
            ));
        }

        let blk_id = BlockId::parse(block_id_str)?;
        let op_id = OpId::parse(t2.op_id)?;
        let new_key_id = KeyId::parse(t2.key_id)?;
        validate_mnb1_header(new_key_id, t2.mnb1)?;
        let mnw1 = t2.mnw1.ok_or_else(|| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                "mnw1_b64 is required when locking a block",
                "Encrypt with WasmVaultSession.rekeyToVault",
            )
        })?;
        validate_mnw1_header(mnw1)?;

        // Collect all prior unshredded keys BEFORE inserting the new Tier 2 key
        let old_keys = self.collect_entity_unshredded_key_ids(EntityType::Block, &blk_id.to_string())?;
        let parents: Vec<OpId> = detail
            .head_op_ids
            .iter()
            .map(|s| OpId::parse(s))
            .collect::<Result<_, _>>()?;
        let now = now_ms();
        let hlc = self.hlc_clock.tick(now);
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();
        let keyring_gen = self.current_keyring()?.keyring_gen;

        let krec = KeyRecordV1 {
            v: 1,
            key_id: new_key_id,
            block_id: blk_id.0,
            tier: 2,
            created_hlc: hlc.canonical_string(),
            created_by: self.device_id.clone(),
            bdek: mnw1.to_vec(),
        };
        let mnr1 = encrypt_mnr1(smk_kid, &smk, keyring_gen, &krec, rand_bytes::<24>()?)?;
        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: blk_id.to_string(),
            op_type: OpType::Lock,
            parent_op_ids: parents.clone(),
            hlc: hlc.clone(),
            actor: actor.to_string(),
            body: OpBodyV1::BlockContent {
                buffer_id: None,
                position: None,
                lang: lang.map(ToString::to_string),
                public_hint: Some(
                    public_hint
                        .map(ToString::to_string)
                        .or(detail.public_hint.clone()),
                ),
                tier: 2,
                key_id: new_key_id,
                mnb1: t2.mnb1.to_vec(),
            },
        };
        let mns1 = encrypt_mns1(smk_kid, &smk, op_id, &self.device_id, &inner, rand_bytes::<24>()?)?;

        self.conn
            .execute(
                "INSERT INTO block_keys (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                 VALUES (?1, ?2, 2, ?3, ?4, ?5, ?6, 0)",
                params![
                    new_key_id.to_string(),
                    blk_id.to_string(),
                    keyring_gen as i64,
                    mnr1,
                    hlc.canonical_string(),
                    now as i64,
                ],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert tier2 lock key"))?;
        self.insert_sync_op(
            op_id,
            None,
            EntityType::Block,
            &blk_id.to_string(),
            &parents,
            OpType::Lock,
            &hlc,
            actor,
            Some(new_key_id),
            smk_kid,
            &mns1,
            now as i64,
        )?;
        let mat = self.rematerialize_block(blk_id)?;

        // Queue shred marks for old keys (subject to INV-KEY-LIVENESS self-check!)
        if self.key_self_check()?.0 {
            let old_only: Vec<KeyId> = old_keys.into_iter().filter(|k| *k != new_key_id).collect();
            self.queue_local_shred_marks(&old_only, grace_ms, now as i64)?;
        }

        // Immediately purge plaintext tokens from FTS5, WAL, and Markdown mirror (`SEC-01`)
        self.scrub_fts_and_wal()?;
        self.refresh_mirror()?;

        Ok(WriteReceipt {
            block_id: mat.id.to_string(),
            op_id: op_id.to_string(),
            head_op_ids: mat.head_op_ids().into_iter().map(|o| o.to_string()).collect(),
            buffer_id: mat.buffer_id.to_string(),
            idempotent_replay: None,
        })
    }

    /// Unlock a Tier 2 block back to Tier 1 plaintext (`POST /v1/local/blocks/:id/unlock`, `mynote vault unlock`).
    /// Generates a brand new Tier 1 BDEK; optionally schedules shred of old Tier 2 keys if `shred_old_key == true`.
    #[allow(clippy::too_many_arguments)]
    pub fn unlock_block_tier1(
        &mut self,
        block_id_str: &str,
        expected_heads: &[String],
        plaintext_content: &str,
        lang: Option<&str>,
        shred_old_key: bool,
        actor: &str,
    ) -> Result<WriteReceipt, CoreError> {
        let detail = self.get_block(block_id_str)?;
        self.check_bootstrap_gate(EntityType::Block, &detail.id, OpType::Unlock)?;
        if !expected_heads.is_empty() {
            let exp_set: BTreeSet<String> = expected_heads.iter().cloned().collect();
            let act_set: BTreeSet<String> = detail.head_op_ids.iter().cloned().collect();
            if exp_set != act_set {
                return Err(CoreError::new(
                    ErrorCode::HeadMismatch,
                    format!("block {block_id_str} heads changed concurrently"),
                    "Refresh block state and retry unlock",
                )
                .with_details(serde_json::json!({
                    "expected_heads": expected_heads,
                    "actual_heads": detail.head_op_ids,
                })));
            }
        }

        let blk_id = BlockId::parse(block_id_str)?;
        let old_keys = self.collect_entity_unshredded_key_ids(EntityType::Block, &blk_id.to_string())?;
        let parents: Vec<OpId> = detail
            .head_op_ids
            .iter()
            .map(|s| OpId::parse(s))
            .collect::<Result<_, _>>()?;
        let now = now_ms();
        let op_id = OpId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let new_key_id = KeyId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let bdek = Zeroizing::new(rand_bytes::<32>()?);
        let hlc = self.hlc_clock.tick(now);
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();
        let keyring_gen = self.current_keyring()?.keyring_gen;

        let mnb1 = encrypt_mnb1(
            blk_id.as_bytes(),
            op_id,
            new_key_id,
            &bdek,
            plaintext_content,
            rand_bytes::<24>()?,
        )?;
        let krec = KeyRecordV1 {
            v: 1,
            key_id: new_key_id,
            block_id: blk_id.0,
            tier: 1,
            created_hlc: hlc.canonical_string(),
            created_by: self.device_id.clone(),
            bdek: bdek.to_vec(),
        };
        let mnr1 = encrypt_mnr1(smk_kid, &smk, keyring_gen, &krec, rand_bytes::<24>()?)?;
        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: blk_id.to_string(),
            op_type: OpType::Unlock,
            parent_op_ids: parents.clone(),
            hlc: hlc.clone(),
            actor: actor.to_string(),
            body: OpBodyV1::BlockContent {
                buffer_id: None,
                position: None,
                lang: lang.map(ToString::to_string),
                public_hint: None,
                tier: 1,
                key_id: new_key_id,
                mnb1,
            },
        };
        let mns1 = encrypt_mns1(smk_kid, &smk, op_id, &self.device_id, &inner, rand_bytes::<24>()?)?;

        self.conn
            .execute(
                "INSERT INTO block_keys (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                 VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, 0)",
                params![
                    new_key_id.to_string(),
                    blk_id.to_string(),
                    keyring_gen as i64,
                    mnr1,
                    hlc.canonical_string(),
                    now as i64,
                ],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert tier1 unlock key"))?;
        self.insert_sync_op(
            op_id,
            None,
            EntityType::Block,
            &blk_id.to_string(),
            &parents,
            OpType::Unlock,
            &hlc,
            actor,
            Some(new_key_id),
            smk_kid,
            &mns1,
            now as i64,
        )?;
        let mat = self.rematerialize_block(blk_id)?;

        if shred_old_key && self.key_self_check()?.0 {
            let old_only: Vec<KeyId> = old_keys.into_iter().filter(|k| *k != new_key_id).collect();
            self.queue_local_shred_marks(&old_only, T_GRACE_DEFAULT_MS, now as i64)?;
        }
        self.refresh_mirror()?;

        Ok(WriteReceipt {
            block_id: mat.id.to_string(),
            op_id: op_id.to_string(),
            head_op_ids: mat.head_op_ids().into_iter().map(|o| o.to_string()).collect(),
            buffer_id: mat.buffer_id.to_string(),
            idempotent_replay: None,
        })
    }

    /// Purge history via rekey (`docs/sync-protocol.md` §5.5): re-encrypts current Tier 1 content
    /// under a fresh BDEK and schedules shred marks for all old unshredded keys.
    pub fn purge_block_history(
        &mut self,
        block_id_str: &str,
        tier2_rekey: Option<Tier2OpInput<'_>>,
        grace_ms: i64,
        actor: &str,
    ) -> Result<(WriteReceipt, Vec<KeyId>), CoreError> {
        let detail = self.get_block(block_id_str)?;
        self.check_bootstrap_gate(EntityType::Block, &detail.id, OpType::Update)?;
        if grace_ms < T_GRACE_MIN_MS {
            return Err(CoreError::new(
                ErrorCode::GraceTooShort,
                format!("grace_ms {grace_ms} < minimum {T_GRACE_MIN_MS}"),
                "Grace period must be at least 24 hours",
            ));
        }
        let blk_id = BlockId::parse(block_id_str)?;
        let old_keys = self.collect_entity_unshredded_key_ids(EntityType::Block, &blk_id.to_string())?;
        let now = now_ms();

        let (receipt, new_key_id) = if let Some(t2) = tier2_rekey {
            let new_kid = KeyId::parse(t2.key_id)?;
            let r = self.update_tier2_block(block_id_str, t2, &detail.head_op_ids, None, None, actor)?;
            (r, new_kid)
        } else {
            if detail.is_locked {
                return Err(CoreError::new(
                    ErrorCode::BlockLocked,
                    "purging history of a locked block requires Tier 2 rekey payload from WasmVaultSession",
                    "Unlock Vault in the UI and re-submit purge_history",
                ));
            }
            let content = detail.content.unwrap_or_default();
            let parents: Vec<OpId> = detail
                .head_op_ids
                .iter()
                .map(|s| OpId::parse(s))
                .collect::<Result<_, _>>()?;
            let op_id = OpId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
            let new_kid = KeyId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
            let bdek = Zeroizing::new(rand_bytes::<32>()?);
            let hlc = self.hlc_clock.tick(now);
            let smk_kid = self.current_smk_kid;
            let smk = self.current_smk()?.clone();
            let keyring_gen = self.current_keyring()?.keyring_gen;

            let mnb1 = encrypt_mnb1(
                blk_id.as_bytes(),
                op_id,
                new_kid,
                &bdek,
                &content,
                rand_bytes::<24>()?,
            )?;
            let krec = KeyRecordV1 {
                v: 1,
                key_id: new_kid,
                block_id: blk_id.0,
                tier: 1,
                created_hlc: hlc.canonical_string(),
                created_by: self.device_id.clone(),
                bdek: bdek.to_vec(),
            };
            let mnr1 = encrypt_mnr1(smk_kid, &smk, keyring_gen, &krec, rand_bytes::<24>()?)?;
            let inner = InnerOpV1 {
                v: 1,
                entity_type: EntityType::Block,
                entity_id: blk_id.to_string(),
                op_type: OpType::Update,
                parent_op_ids: parents.clone(),
                hlc: hlc.clone(),
                actor: actor.to_string(),
                body: OpBodyV1::BlockContent {
                    buffer_id: None,
                    position: None,
                    lang: None,
                    public_hint: None,
                    tier: 1,
                    key_id: new_kid,
                    mnb1,
                },
            };
            let mns1 = encrypt_mns1(smk_kid, &smk, op_id, &self.device_id, &inner, rand_bytes::<24>()?)?;
            self.conn
                .execute(
                    "INSERT INTO block_keys (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                     VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, 0)",
                    params![
                        new_kid.to_string(),
                        blk_id.to_string(),
                        keyring_gen as i64,
                        mnr1,
                        hlc.canonical_string(),
                        now as i64,
                    ],
                )
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert rekey"))?;
            self.insert_sync_op(
                op_id,
                None,
                EntityType::Block,
                &blk_id.to_string(),
                &parents,
                OpType::Update,
                &hlc,
                actor,
                Some(new_kid),
                smk_kid,
                &mns1,
                now as i64,
            )?;
            let mat = self.rematerialize_block(blk_id)?;
            self.refresh_mirror()?;
            (
                WriteReceipt {
                    block_id: mat.id.to_string(),
                    op_id: op_id.to_string(),
                    head_op_ids: mat.head_op_ids().into_iter().map(|o| o.to_string()).collect(),
                    buffer_id: mat.buffer_id.to_string(),
                    idempotent_replay: None,
                },
                new_kid,
            )
        };

        let old_only: Vec<KeyId> = old_keys.into_iter().filter(|k| *k != new_key_id).collect();
        if self.key_self_check()?.0 {
            self.queue_local_shred_marks(&old_only, grace_ms, now as i64)?;
        }
        Ok((receipt, old_only))
    }

    /// Restore a Tier 2 locked block from the recycle bin using caller-encrypted `UPDATE` op (`mnb1`).
    pub fn restore_trash_tier2(
        &mut self,
        block_id_str: &str,
        t2: Tier2OpInput<'_>,
        actor: &str,
    ) -> Result<WriteReceipt, CoreError> {
        let blk_id = BlockId::parse(block_id_str)?;
        self.check_bootstrap_gate(EntityType::Block, &blk_id.to_string(), OpType::Update)?;
        let state: Option<String> = self
            .conn
            .query_row(
                "SELECT state FROM blocks WHERE id = ?1",
                [blk_id.to_string()],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);
        match state.as_deref() {
            Some("TRASHED") => {}
            Some("SHREDDED") => {
                return Err(CoreError::new(
                    ErrorCode::KeyShredded,
                    format!("block '{block_id_str}' has already been shredded"),
                    "Cannot restore a shredded block",
                ));
            }
            _ => {
                return Err(CoreError::new(
                    ErrorCode::NotFound,
                    format!("block '{block_id_str}' is not in the recycle bin"),
                    "Run 'mynote trash ls'",
                ));
            }
        }
        let op_id = OpId::parse(t2.op_id)?;
        let key_id = KeyId::parse(t2.key_id)?;
        validate_mnb1_header(key_id, t2.mnb1)?;

        let all_keys = self.collect_entity_unshredded_key_ids(EntityType::Block, &blk_id.to_string())?;
        if self.is_key_executed(&key_id) {
            return Err(CoreError::new(
                ErrorCode::KeyShredded,
                format!("key {key_id} has already been shredded"),
                "Cannot restore a shredded block",
            ));
        }
        self.cancel_local_shred_marks_for_keys(&all_keys)?;

        let parents = self.current_entity_leaves(EntityType::Block, &blk_id.to_string())?;
        let now = now_ms();
        let hlc = self.hlc_clock.tick(now);
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();
        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: blk_id.to_string(),
            op_type: OpType::Update,
            parent_op_ids: parents.clone(),
            hlc: hlc.clone(),
            actor: actor.to_string(),
            body: OpBodyV1::BlockContent {
                buffer_id: None,
                position: None,
                lang: None,
                public_hint: None,
                tier: 2,
                key_id,
                mnb1: t2.mnb1.to_vec(),
            },
        };
        let mns1 = encrypt_mns1(smk_kid, &smk, op_id, &self.device_id, &inner, rand_bytes::<24>()?)?;
        self.insert_sync_op(
            op_id,
            None,
            EntityType::Block,
            &blk_id.to_string(),
            &parents,
            OpType::Update,
            &hlc,
            actor,
            Some(key_id),
            smk_kid,
            &mns1,
            now as i64,
        )?;
        let mat = self.rematerialize_block(blk_id)?;
        self.refresh_mirror()?;
        Ok(WriteReceipt {
            block_id: mat.id.to_string(),
            op_id: op_id.to_string(),
            head_op_ids: mat.head_op_ids().into_iter().map(|o| o.to_string()).collect(),
            buffer_id: mat.buffer_id.to_string(),
            idempotent_replay: None,
        })
    }

    /// Return the latest locked content ciphertext `(op_id, key_id, mnb1_b64, mnw1_b64)` of a trashed Tier 2 block
    /// so UI can decrypt & re-encrypt on restore.
    pub fn trashed_tier2_blob(
        &self,
        block_id_str: &str,
    ) -> Result<Option<(String, String, String, String)>, CoreError> {
        let blk_id = BlockId::parse(block_id_str)?;
        let decoded = self.load_entity_decoded_ops(EntityType::Block, &blk_id.to_string())?;
        for d in decoded.iter().rev() {
            if let OpBodyV1::BlockContent {
                tier: 2,
                key_id,
                mnb1,
                ..
            } = &d.inner.body
            {
                if let Ok((2, mnw1)) = self.unwrap_bdek(*key_id) {
                    return Ok(Some((
                        d.op_id.to_string(),
                        key_id.to_string(),
                        B64.encode(mnb1),
                        B64.encode(mnw1),
                    )));
                }
            }
        }
        Ok(None)
    }

    pub(super) fn collect_entity_unshredded_key_ids(
        &self,
        entity_type: EntityType,
        entity_id: &str,
    ) -> Result<Vec<KeyId>, CoreError> {
        let et = match entity_type {
            EntityType::Buffer => "buffer",
            EntityType::Block => "block",
        };
        let mut stmt = self
            .conn
            .prepare(
                "SELECT DISTINCT o.key_id FROM sync_ops o
                 JOIN block_keys k ON k.key_id = o.key_id
                 WHERE o.entity_type = ?1 AND o.entity_id = ?2
                   AND o.key_id IS NOT NULL AND k.key_record IS NOT NULL",
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query entity keys"))?;
        let rows = stmt
            .query_map(params![et, entity_id], |r| r.get::<_, String>(0))
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map entity keys"))?;
        let mut out = BTreeSet::new();
        for s in rows.flatten() {
            if let Ok(kid) = KeyId::parse(&s) {
                if !self.is_key_executed(&kid) {
                    out.insert(kid);
                }
            }
        }
        Ok(out.into_iter().collect())
    }

    pub(super) fn is_key_executed(&self, key_id: &KeyId) -> bool {
        let k_null: Option<i64> = self
            .conn
            .query_row(
                "SELECT CASE WHEN key_record IS NULL THEN 1 ELSE 0 END FROM block_keys WHERE key_id = ?1",
                [key_id.to_string()],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);
        if k_null == Some(1) {
            return true;
        }
        let has_exec: i64 = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM shred_marks WHERE key_id = ?1 AND state = 'executed')",
                [key_id.to_string()],
                |r| r.get(0),
            )
            .unwrap_or(0);
        has_exec != 0
    }

    pub(super) fn queue_local_shred_marks(
        &mut self,
        key_ids: &[KeyId],
        grace_ms: i64,
        now_i64: i64,
    ) -> Result<Vec<ShredMarkRow>, CoreError> {
        let seen_seq = self
            .get_local_meta("last_seq")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let mut created = Vec::new();
        for &kid in key_ids {
            // Skip if an active mark already exists for this key
            let has_active: i64 = self
                .conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM shred_marks WHERE key_id = ?1 AND state IN ('pending_confirm', 'scheduled'))",
                    [kid.to_string()],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if has_active != 0 || self.is_key_executed(&kid) {
                continue;
            }
            let mid = MarkId::from_ulid(self.ulid_gen.next(now_i64.max(1) as u64, rand_bytes::<10>()?));
            self.conn
                .execute(
                    "INSERT INTO shred_marks
                     (mark_id, key_id, requested_by, requested_at_ms, seen_seq, grace_ms, not_before_ms, state, server_acked)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 'pending_confirm', 0)",
                    params![
                        mid.to_string(),
                        kid.to_string(),
                        self.device_id.as_str(),
                        now_i64,
                        seen_seq,
                        grace_ms,
                    ],
                )
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert local shred_mark"))?;
            created.push(ShredMarkRow {
                mark_id: mid,
                key_id: kid,
                seen_seq,
                requested_by: self.device_id.clone(),
                requested_at_ms: now_i64,
                grace_ms,
                not_before_ms: None,
                state: ShredMarkState::PendingConfirm,
                confirmed_at_ms: None,
                cancelled_by: None,
                executed_at_ms: None,
            });
        }
        Ok(created)
    }

    pub(super) fn cancel_local_shred_marks_for_keys(&mut self, key_ids: &[KeyId]) -> Result<(), CoreError> {
        let mut cancel_set = self.load_pending_cancel_keys();
        for &kid in key_ids {
            let had_server_acked: i64 = self
                .conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM shred_marks WHERE key_id = ?1 AND server_acked = 1 AND state IN ('pending_confirm', 'scheduled'))",
                    [kid.to_string()],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            self.conn
                .execute(
                    "UPDATE shred_marks SET state = 'cancelled', cancelled_by = ?1
                     WHERE key_id = ?2 AND state IN ('pending_confirm', 'scheduled')",
                    params![self.device_id.as_str(), kid.to_string()],
                )
                .map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        e.to_string(),
                        "cancel local shred_marks",
                    )
                })?;
            if had_server_acked != 0 {
                cancel_set.insert(kid);
            }
        }
        self.save_pending_cancel_keys(&cancel_set)
    }

    pub(super) fn load_pending_cancel_keys(&self) -> BTreeSet<KeyId> {
        self.get_local_meta("pending_cancel_key_ids")
            .and_then(|raw| serde_json::from_str::<Vec<String>>(&raw).ok())
            .map(|list| list.into_iter().filter_map(|s| KeyId::parse(&s).ok()).collect())
            .unwrap_or_default()
    }

    pub(super) fn save_pending_cancel_keys(&self, keys: &BTreeSet<KeyId>) -> Result<(), CoreError> {
        let list: Vec<String> = keys.iter().map(ToString::to_string).collect();
        let json = serde_json::to_string(&list).unwrap_or_else(|_| "[]".into());
        self.set_local_meta("pending_cancel_key_ids", &json)
    }

    pub(super) fn load_shred_marks(&self, only_server_acked: bool) -> Result<Vec<ShredMarkRow>, CoreError> {
        let sql = if only_server_acked {
            "SELECT mark_id, key_id, seen_seq, requested_by, requested_at_ms, grace_ms, not_before_ms, state, confirmed_at_ms, cancelled_by, executed_at_ms
             FROM shred_marks WHERE server_acked = 1 ORDER BY mark_id ASC"
        } else {
            "SELECT mark_id, key_id, seen_seq, requested_by, requested_at_ms, grace_ms, not_before_ms, state, confirmed_at_ms, cancelled_by, executed_at_ms
             FROM shred_marks WHERE server_acked = 0 AND state IN ('pending_confirm', 'scheduled') ORDER BY mark_id ASC"
        };
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query shred_marks"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, Option<i64>>(8)?,
                    r.get::<_, Option<String>>(9)?,
                    r.get::<_, Option<i64>>(10)?,
                ))
            })
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map shred_marks"))?;
        let mut out = Vec::new();
        for row in rows.flatten() {
            let Ok(mark_id) = MarkId::parse(&row.0) else {
                continue;
            };
            let Ok(key_id) = KeyId::parse(&row.1) else {
                continue;
            };
            let Ok(requested_by) = DeviceId::parse(row.3) else {
                continue;
            };
            let cancelled_by = row.9.and_then(|s| DeviceId::parse(s).ok());
            out.push(ShredMarkRow {
                mark_id,
                key_id,
                seen_seq: row.2,
                requested_by,
                requested_at_ms: row.4,
                grace_ms: row.5,
                not_before_ms: row.6,
                state: str_to_shred_state(&row.7),
                confirmed_at_ms: row.8,
                cancelled_by,
                executed_at_ms: row.10,
            });
        }
        Ok(out)
    }

    pub(super) fn upsert_shred_mark_row(
        &self,
        mark: &ShredMarkRow,
        server_acked: bool,
    ) -> Result<(), CoreError> {
        type ExistingShredRow = (String, Option<i64>, Option<i64>, Option<String>, Option<i64>, i64);
        let existing: Option<ExistingShredRow> = self
            .conn
            .query_row(
                "SELECT state, not_before_ms, confirmed_at_ms, cancelled_by, executed_at_ms, server_acked
                 FROM shred_marks WHERE mark_id = ?1",
                [mark.mark_id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .optional()
            .unwrap_or(None);

        let (state, not_before, confirmed, cancelled_by, executed, acked_i) =
            if let Some((cur_state_s, cur_nb, cur_conf, cur_canc, cur_exec, cur_ack)) = existing {
                let cur_state = str_to_shred_state(&cur_state_s);
                let next_state = if shred_state_rank(mark.state) > shred_state_rank(cur_state) {
                    mark.state
                } else {
                    cur_state
                };
                let opt_min = |a: Option<i64>, b: Option<i64>| match (a, b) {
                    (Some(x), Some(y)) => Some(x.min(y)),
                    (Some(x), None) | (None, Some(x)) => Some(x),
                    (None, None) => None,
                };
                (
                    next_state,
                    opt_min(cur_nb, mark.not_before_ms),
                    opt_min(cur_conf, mark.confirmed_at_ms),
                    mark.cancelled_by.as_ref().map(|d| d.to_string()).or(cur_canc),
                    opt_min(cur_exec, mark.executed_at_ms),
                    if server_acked || cur_ack != 0 { 1i64 } else { 0i64 },
                )
            } else {
                (
                    mark.state,
                    mark.not_before_ms,
                    mark.confirmed_at_ms,
                    mark.cancelled_by.as_ref().map(|d| d.to_string()),
                    mark.executed_at_ms,
                    if server_acked { 1i64 } else { 0i64 },
                )
            };

        self.conn
            .execute(
                "INSERT INTO shred_marks
                 (mark_id, key_id, requested_by, requested_at_ms, seen_seq, grace_ms, not_before_ms, state, confirmed_at_ms, cancelled_by, executed_at_ms, server_acked)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT(mark_id) DO UPDATE SET
                   not_before_ms = excluded.not_before_ms,
                   state = excluded.state,
                   confirmed_at_ms = excluded.confirmed_at_ms,
                   cancelled_by = excluded.cancelled_by,
                   executed_at_ms = excluded.executed_at_ms,
                   server_acked = excluded.server_acked",
                params![
                    mark.mark_id.to_string(),
                    mark.key_id.to_string(),
                    mark.requested_by.as_str(),
                    mark.requested_at_ms,
                    mark.seen_seq,
                    mark.grace_ms,
                    not_before,
                    shred_state_to_str(state),
                    confirmed,
                    cancelled_by,
                    executed,
                    acked_i,
                ],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "upsert shred_mark"))?;
        Ok(())
    }

    pub(super) fn apply_shred_results_acked(
        &self,
        results: &[ShredResultDto],
        cancelled_keys: &[KeyId],
    ) -> Result<(), CoreError> {
        for r in results {
            self.conn
                .execute(
                    "UPDATE shred_marks
                     SET state = ?1,
                         not_before_ms = CASE
                             WHEN not_before_ms IS NULL THEN ?2
                             WHEN ?2 IS NULL THEN not_before_ms
                             ELSE MIN(not_before_ms, ?2)
                         END,
                         server_acked = 1
                     WHERE key_id = ?3 AND state IN ('pending_confirm', 'scheduled')",
                    params![shred_state_to_str(r.state), r.not_before_ms, r.key_id.to_string()],
                )
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "ack shred_mark"))?;
        }
        if !cancelled_keys.is_empty() {
            let mut pend = self.load_pending_cancel_keys();
            for kid in cancelled_keys {
                pend.remove(kid);
                self.conn
                    .execute(
                        "UPDATE shred_marks SET state = 'cancelled', server_acked = 1
                         WHERE key_id = ?1 AND state IN ('pending_confirm', 'scheduled', 'cancelled')",
                        [kid.to_string()],
                    )
                    .ok();
            }
            self.save_pending_cancel_keys(&pend)?;
        }
        Ok(())
    }

    /// Compute `(shred_state, shred_not_before_ms)` for a trashed block (`list_trash`, `delete_block`).
    pub(super) fn block_trash_shred_status(&self, block_id: &str) -> (String, Option<i64>) {
        let mut stmt = match self.conn.prepare(
            "SELECT DISTINCT sm.state, sm.not_before_ms, sm.server_acked
             FROM shred_marks sm
             JOIN sync_ops so ON so.key_id = sm.key_id
             WHERE so.entity_type = 'block' AND so.entity_id = ?1
               AND sm.state != 'cancelled'",
        ) {
            Ok(s) => s,
            Err(_) => return ("unscheduled".to_string(), None),
        };
        let rows: Vec<(String, Option<i64>, i64)> = stmt
            .query_map([block_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .collect();
        if rows.is_empty() {
            return ("unscheduled".to_string(), None);
        }
        let mut min_nb: Option<i64> = None;
        let mut has_scheduled = false;
        let mut has_pending_confirm = false;
        let mut has_pending_sync = false;
        for (st, nb, acked) in rows {
            if acked == 0 {
                has_pending_sync = true;
            } else if st == "scheduled" {
                has_scheduled = true;
                if let Some(t) = nb {
                    min_nb = Some(min_nb.map_or(t, |cur| cur.min(t)));
                }
            } else if st == "pending_confirm" {
                has_pending_confirm = true;
            }
        }
        if has_scheduled {
            ("scheduled".to_string(), min_nb)
        } else if has_pending_confirm {
            ("pending_confirm".to_string(), None)
        } else if has_pending_sync {
            ("pending_sync".to_string(), None)
        } else {
            ("unscheduled".to_string(), None)
        }
    }

    /// Collect all active (`pending_confirm` or `scheduled`) shred key_ids for a list of trashed blocks
    /// (or all trashed blocks when `block_ids` is `None`), used by UI `trash/actions/prepare` & `commit`.
    #[allow(clippy::type_complexity)]
    pub fn collect_trash_action_keys(
        &self,
        action: &str,
        block_ids: Option<&[String]>,
    ) -> Result<(Vec<String>, Vec<KeyId>, Option<i64>), CoreError> {
        let target_blocks: Vec<String> = match block_ids {
            Some(ids) => ids.to_vec(),
            None => self.list_trash()?.into_iter().map(|t| t.id).collect(),
        };
        let mut keys = BTreeSet::new();
        let mut earliest_nb: Option<i64> = None;
        for bid in &target_blocks {
            let filter_state = match action {
                "confirm_pending" => "sm.state = 'pending_confirm'",
                "expedite" => "sm.state IN ('scheduled', 'pending_confirm')",
                _ => "sm.state IN ('scheduled', 'pending_confirm')",
            };
            let sql = format!(
                "SELECT DISTINCT sm.key_id, sm.not_before_ms
                 FROM shred_marks sm
                 JOIN sync_ops so ON so.key_id = sm.key_id
                 WHERE so.entity_type = 'block' AND so.entity_id = ?1 AND {filter_state}"
            );
            let mut stmt = self
                .conn
                .prepare(&sql)
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query trash keys"))?;
            let rows = stmt
                .query_map([bid], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?))
                })
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map trash keys"))?;
            for (ks, nb) in rows.flatten() {
                if let Ok(kid) = KeyId::parse(&ks) {
                    if !self.is_key_executed(&kid) {
                        keys.insert(kid);
                        if let Some(t) = nb {
                            earliest_nb = Some(earliest_nb.map_or(t, |cur| cur.min(t)));
                        }
                    }
                }
            }
            // If expedite/purge targets a block whose marks aren't yet created, include its unshredded keys
            if action == "expedite" || action == "purge_history" {
                for kid in self.collect_entity_unshredded_key_ids(EntityType::Block, bid)? {
                    keys.insert(kid);
                }
            }
        }
        Ok((target_blocks, keys.into_iter().collect(), earliest_nb))
    }

    /// Reconcile local unpushed outbox ops against server shred marks (`docs/sync-protocol.md` §5.7):
    /// - Delete-intent (`CancelAndPush`): handled automatically by `build_pending_push()` (`cancel_key_ids`).
    /// - Rekey-intent / Shredded (`NeedsRekey`):
    ///   - Tier 1: automatically rekeys onto a fresh Tier 1 BDEK (zero data loss, does NOT cancel shred mark!).
    ///   - Tier 2: marks `sync_blocked_reason = 'NEEDS_VAULT_REKEY'` & preserves `mnw1` so other ops keep syncing!
    pub fn reconcile_outbox_against_shred_marks(&mut self) -> Result<Vec<String>, CoreError> {
        self.reconcile_outbox_with_imminent_shreds(&BTreeSet::new())
    }

    pub(super) fn reconcile_outbox_with_imminent_shreds(
        &mut self,
        imminent_shreds: &BTreeSet<KeyId>,
    ) -> Result<Vec<String>, CoreError> {
        let mut snap = self.export_engine_snapshot()?;
        for &kid in imminent_shreds {
            snap.keys
                .records
                .entry(kid)
                .and_modify(|r| r.key_record = None)
                .or_insert(KeyRecordRow {
                    key_id: kid,
                    wrap_gen: 1,
                    key_record: None,
                    created_at_ms: 0,
                });
        }
        let mut needs_vault_rekey_ops = Vec::new();
        let unpushed: Vec<LocalOpRecord> = snap
            .ops
            .values()
            .filter(|o| o.server_seq.is_none() && o.sync_blocked_reason.is_none())
            .cloned()
            .collect();

        for op in unpushed {
            let OutboxKeyAction::NeedsRekey { .. } = snap.classify_unpushed_op(&op) else {
                continue;
            };
            // NEVER resurrect a superseded ancestor or locally deleted block!
            let live_leaves = self
                .current_entity_leaves(op.entity_type, &op.entity_id)
                .unwrap_or_default();
            if !live_leaves.contains(&op.op_id) {
                continue;
            }
            let Some(old_kid) = op.key_id else { continue };
            let Some(smk) = self.smks.get(&op.smk_kid).cloned() else {
                continue;
            };
            let Ok(inner) = decrypt_mns1(op.smk_kid, &smk, op.op_id, &op.device_id, op.key_id, &op.envelope)
            else {
                continue;
            };
            match &inner.body {
                OpBodyV1::BlockContent {
                    tier: 1,
                    mnb1,
                    buffer_id,
                    position,
                    lang,
                    public_hint,
                    ..
                } => {
                    // Auto-rekey Tier 1 offline op using local plaintext (or unwrap old key before shred)
                    let blk_id = BlockId::parse(&inner.entity_id)?;
                    let plaintext = if let Ok(old_bdek) = self.unwrap_tier1_bdek(old_kid) {
                        decrypt_mnb1(blk_id.as_bytes(), op.op_id, old_kid, &old_bdek, mnb1).ok()
                    } else {
                        self.conn
                            .query_row(
                                "SELECT content FROM block_leaves WHERE block_id = ?1 AND op_id = ?2",
                                params![blk_id.to_string(), op.op_id.to_string()],
                                |r| r.get::<_, Option<String>>(0),
                            )
                            .optional()
                            .unwrap_or(None)
                            .flatten()
                    };
                    if let Some(pt) = plaintext {
                        // Fill complete metadata in case block was shredded remotely (sync-protocol §5.7 row 3)
                        let existing_meta: Option<(String, String, String)> = self
                            .conn
                            .query_row(
                                "SELECT buffer_id, position, lang FROM blocks WHERE id = ?1",
                                [blk_id.to_string()],
                                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                            )
                            .optional()
                            .unwrap_or(None);
                        let (fill_buf, fill_pos, fill_lang) = match existing_meta {
                            Some((b, p, l)) => (
                                buffer_id.or_else(|| BufferId::parse(&b).ok()),
                                position.clone().or(Some(p)),
                                lang.clone().or(Some(l)),
                            ),
                            None => (*buffer_id, position.clone(), lang.clone()),
                        };
                        let now = now_ms();
                        let new_op_id = OpId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
                        let new_kid = KeyId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
                        let new_bdek = Zeroizing::new(rand_bytes::<32>()?);
                        let hlc = self.hlc_clock.tick(now);
                        let cur_smk_kid = self.current_smk_kid;
                        let cur_smk = self.current_smk()?.clone();
                        let keyring_gen = self.current_keyring()?.keyring_gen;

                        let new_mnb1 = encrypt_mnb1(
                            blk_id.as_bytes(),
                            new_op_id,
                            new_kid,
                            &new_bdek,
                            &pt,
                            rand_bytes::<24>()?,
                        )?;
                        let krec = KeyRecordV1 {
                            v: 1,
                            key_id: new_kid,
                            block_id: blk_id.0,
                            tier: 1,
                            created_hlc: hlc.canonical_string(),
                            created_by: self.device_id.clone(),
                            bdek: new_bdek.to_vec(),
                        };
                        let mnr1 =
                            encrypt_mnr1(cur_smk_kid, &cur_smk, keyring_gen, &krec, rand_bytes::<24>()?)?;
                        let new_inner = InnerOpV1 {
                            v: 1,
                            entity_type: EntityType::Block,
                            entity_id: blk_id.to_string(),
                            op_type: inner.op_type,
                            parent_op_ids: inner.parent_op_ids.clone(),
                            hlc: hlc.clone(),
                            actor: inner.actor.clone(),
                            body: OpBodyV1::BlockContent {
                                buffer_id: fill_buf,
                                position: fill_pos,
                                lang: fill_lang,
                                public_hint: public_hint.clone(),
                                tier: 1,
                                key_id: new_kid,
                                mnb1: new_mnb1,
                            },
                        };
                        let new_mns1 = encrypt_mns1(
                            cur_smk_kid,
                            &cur_smk,
                            new_op_id,
                            &self.device_id,
                            &new_inner,
                            rand_bytes::<24>()?,
                        )?;
                        self.conn
                            .execute(
                                "INSERT INTO block_keys (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                                 VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, 0)",
                                params![
                                    new_kid.to_string(),
                                    blk_id.to_string(),
                                    keyring_gen as i64,
                                    mnr1,
                                    hlc.canonical_string(),
                                    now as i64,
                                ],
                            )
                            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "rekey outbox key"))?;
                        // Replace unpublished local op with rekeyed op
                        self.conn
                            .execute(
                                "DELETE FROM sync_ops WHERE op_id = ?1 AND server_seq IS NULL",
                                [op.op_id.to_string()],
                            )
                            .ok();
                        self.insert_sync_op(
                            new_op_id,
                            None,
                            EntityType::Block,
                            &blk_id.to_string(),
                            &inner.parent_op_ids,
                            inner.op_type,
                            &hlc,
                            &inner.actor,
                            Some(new_kid),
                            cur_smk_kid,
                            &new_mns1,
                            now as i64,
                        )?;
                        let _ = self.rematerialize_block(blk_id);
                    }
                }
                OpBodyV1::BlockContent { tier: 2, .. } => {
                    // Save wrapped mnw1 before old key is shredded so UI can decrypt & rekey upon unlock!
                    if let Ok((2, mnw1)) = self.unwrap_bdek(old_kid) {
                        let slot_key = format!("blocked_t2_mnw1:{}", op.op_id);
                        let _ = self.set_local_meta(&slot_key, &B64.encode(mnw1));
                    }
                    self.conn
                        .execute(
                            "UPDATE sync_ops SET sync_blocked_reason = 'NEEDS_VAULT_REKEY' WHERE op_id = ?1",
                            [op.op_id.to_string()],
                        )
                        .ok();
                    needs_vault_rekey_ops.push(op.op_id.to_string());
                }
                _ => {}
            }
        }
        Ok(needs_vault_rekey_ops)
    }

    /// List offline Tier 2 ops blocked with `NEEDS_VAULT_REKEY` so the UI can rekey them when Vault unlocks.
    pub fn list_blocked_tier2_ops(&self) -> Result<Vec<BlockedTier2OpDto>, CoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT op_id, device_id, entity_id, key_id, smk_kid, envelope, sync_blocked_reason
                 FROM sync_ops WHERE sync_blocked_reason = 'NEEDS_VAULT_REKEY' AND server_seq IS NULL",
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query blocked ops"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                    r.get::<_, String>(6)?,
                ))
            })
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map blocked ops"))?;
        let mut out = Vec::new();
        for (op_id_s, dev_s, entity_id, kid_s, smk_s, env, reason) in rows.flatten() {
            let Ok(op_id) = OpId::parse(&op_id_s) else {
                continue;
            };
            let Ok(dev) = DeviceId::parse(dev_s) else { continue };
            let Ok(smk_kid) = SmkKid::parse(&smk_s) else {
                continue;
            };
            let Some(smk) = self.smks.get(&smk_kid) else {
                continue;
            };
            let kid = kid_s.as_deref().and_then(|s| KeyId::parse(s).ok());
            let Ok(inner) = decrypt_mns1(smk_kid, smk, op_id, &dev, kid, &env) else {
                continue;
            };
            if let OpBodyV1::BlockContent {
                tier: 2,
                key_id,
                mnb1,
                buffer_id,
                lang,
                public_hint,
                ..
            } = inner.body
            {
                let mnw1_b64 = self
                    .get_local_meta(&format!("blocked_t2_mnw1:{op_id_s}"))
                    .or_else(|| {
                        self.unwrap_bdek(key_id)
                            .ok()
                            .filter(|(t, _)| *t == 2)
                            .map(|(_, w)| B64.encode(w))
                    });
                let head_op_ids = self
                    .current_entity_leaves(EntityType::Block, &entity_id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|o| o.to_string())
                    .collect();
                let (buf_str, blk_lang) = self
                    .conn
                    .query_row(
                        "SELECT buffer_id, lang FROM blocks WHERE id = ?1",
                        [&entity_id],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                    )
                    .unwrap_or_else(|_| {
                        (
                            buffer_id.map(|b| b.to_string()).unwrap_or_default(),
                            lang.unwrap_or_else(|| "text".into()),
                        )
                    });
                out.push(BlockedTier2OpDto {
                    op_id: op_id_s,
                    block_id: entity_id,
                    buffer_id: buf_str,
                    lang: blk_lang,
                    public_hint: public_hint.flatten(),
                    old_key_id: key_id.to_string(),
                    reason,
                    mnb1_b64: B64.encode(mnb1),
                    mnw1_b64,
                    head_op_ids,
                });
            }
        }
        Ok(out)
    }

    /// Replace a `NEEDS_VAULT_REKEY` blocked Tier 2 op with a freshly rekeyed Tier 2 op from `WasmVaultSession`.
    pub fn rekey_blocked_tier2_op(
        &mut self,
        blocked_op_id: &str,
        t2: Tier2OpInput<'_>,
        actor: &str,
    ) -> Result<WriteReceipt, CoreError> {
        let entity_id: String = self
            .conn
            .query_row(
                "SELECT entity_id FROM sync_ops WHERE op_id = ?1 AND sync_blocked_reason = 'NEEDS_VAULT_REKEY' AND server_seq IS NULL",
                [blocked_op_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "lookup blocked op"))?
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::NotFound,
                    format!("blocked Tier 2 op '{blocked_op_id}' not found"),
                    "Refresh blocked ops list",
                )
            })?;
        let blk_id = BlockId::parse(&entity_id)?;
        let new_op_id = OpId::parse(t2.op_id)?;
        let new_kid = KeyId::parse(t2.key_id)?;
        validate_mnb1_header(new_kid, t2.mnb1)?;
        let mnw1 = t2.mnw1.ok_or_else(|| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                "mnw1_b64 is required when rekeying a blocked Tier 2 op",
                "Use WasmVaultSession.rekeyToVault",
            )
        })?;
        validate_mnw1_header(mnw1)?;

        // Remove unpublished blocked op and saved mnw1 slot BEFORE computing live parents
        self.conn
            .execute(
                "DELETE FROM sync_ops WHERE op_id = ?1 AND server_seq IS NULL",
                [blocked_op_id],
            )
            .ok();
        self.conn
            .execute(
                "DELETE FROM local_meta WHERE key = ?1",
                [format!("blocked_t2_mnw1:{blocked_op_id}")],
            )
            .ok();

        let parents = self.current_entity_leaves(EntityType::Block, &entity_id)?;
        let now = now_ms();
        let hlc = self.hlc_clock.tick(now);
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();
        let keyring_gen = self.current_keyring()?.keyring_gen;

        let krec = KeyRecordV1 {
            v: 1,
            key_id: new_kid,
            block_id: blk_id.0,
            tier: 2,
            created_hlc: hlc.canonical_string(),
            created_by: self.device_id.clone(),
            bdek: mnw1.to_vec(),
        };
        let mnr1 = encrypt_mnr1(smk_kid, &smk, keyring_gen, &krec, rand_bytes::<24>()?)?;
        let existing_meta: Option<(String, String, String)> = self
            .conn
            .query_row(
                "SELECT buffer_id, position, lang FROM blocks WHERE id = ?1",
                [&entity_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .unwrap_or(None);
        let (buf_opt, pos_opt, lang_opt) = match existing_meta {
            Some((b, p, l)) => (BufferId::parse(&b).ok(), Some(p), Some(l)),
            None => (None, None, None),
        };
        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: entity_id.clone(),
            op_type: OpType::Update,
            parent_op_ids: parents.clone(),
            hlc: hlc.clone(),
            actor: actor.to_string(),
            body: OpBodyV1::BlockContent {
                buffer_id: buf_opt,
                position: pos_opt,
                lang: lang_opt,
                public_hint: None,
                tier: 2,
                key_id: new_kid,
                mnb1: t2.mnb1.to_vec(),
            },
        };
        let mns1 = encrypt_mns1(
            smk_kid,
            &smk,
            new_op_id,
            &self.device_id,
            &inner,
            rand_bytes::<24>()?,
        )?;
        self.conn
            .execute(
                "INSERT INTO block_keys (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                 VALUES (?1, ?2, 2, ?3, ?4, ?5, ?6, 0)",
                params![
                    new_kid.to_string(),
                    entity_id,
                    keyring_gen as i64,
                    mnr1,
                    hlc.canonical_string(),
                    now as i64,
                ],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert rekeyed tier2 key"))?;
        self.insert_sync_op(
            new_op_id,
            None,
            EntityType::Block,
            &entity_id,
            &parents,
            OpType::Update,
            &hlc,
            actor,
            Some(new_kid),
            smk_kid,
            &mns1,
            now as i64,
        )?;
        let mat = self.rematerialize_block(blk_id)?;
        self.refresh_mirror()?;
        Ok(WriteReceipt {
            block_id: mat.id.to_string(),
            op_id: new_op_id.to_string(),
            head_op_ids: mat.head_op_ids().into_iter().map(|o| o.to_string()).collect(),
            buffer_id: mat.buffer_id.to_string(),
            idempotent_replay: None,
        })
    }

    /// Execute physical local key destruction when server confirms `Executed` (`sync-protocol.md` §5.4 #4, `SEC-01`, `INV-SHRED-BOUND`).
    /// Runs INV-KEY-LIVENESS guard + outbox rescue BEFORE setting `block_keys.key_record = NULL`.
    pub(super) fn execute_shred_in_tx(
        &self,
        key_id: KeyId,
        remote_meta: Option<(u32, i64)>,
    ) -> Result<bool, CoreError> {
        // 1. Live-leaf INV-KEY-LIVENESS safety guard (`sync-protocol.md` §5.4 #4):
        // Never wipe a key that is still actively used by a live leaf of an ACTIVE block!
        let live_on_active: i64 = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM block_leaves bl
                    JOIN blocks b ON b.id = bl.block_id
                    WHERE b.state = 'ACTIVE' AND bl.key_id = ?1 AND bl.body_state IN ('PLAINTEXT', 'SEALED')
                 )",
                [key_id.to_string()],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if live_on_active != 0 {
            return Ok(false);
        }

        // 2. Nullify key_record in block_keys (or insert NULL tombstone row if unseen) and mark shred_marks executed
        let updated = self
            .conn
            .execute(
                "UPDATE block_keys SET key_record = NULL, server_acked = 1 WHERE key_id = ?1",
                [key_id.to_string()],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "nullify shredded key"))?;
        if updated == 0 {
            let (wrap_gen, created_at_ms) = remote_meta.unwrap_or((1, now_ms() as i64));
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO block_keys
                     (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                     VALUES (?1, ?2, 1, ?3, NULL, '', ?4, 1)",
                    params![
                        key_id.to_string(),
                        Ulid::ZERO.to_string(),
                        wrap_gen as i64,
                        created_at_ms,
                    ],
                )
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert shredded key")
                })?;
        }
        self.conn
            .execute(
                "UPDATE shred_marks SET state = 'executed', server_acked = 1
                 WHERE key_id = ?1 AND state != 'cancelled'",
                [key_id.to_string()],
            )
            .ok();

        // Remove from pending_cancel_key_ids if present
        let mut cancel_set = self.load_pending_cancel_keys();
        if cancel_set.remove(&key_id) {
            let _ = self.save_pending_cancel_keys(&cancel_set);
        }
        Ok(true)
    }

    /// Force FTS5 segment merge + optimize and truncate WAL under `PRAGMA secure_delete = ON`
    /// so zero shredded/locked plaintext bytes linger in SQLite B-trees or `.db-wal` (`SEC-01`, `INV-SHRED-BOUND`).
    pub fn scrub_fts_and_wal(&self) -> Result<(), CoreError> {
        self.conn
            .execute_batch(
                "INSERT INTO blocks_fts(blocks_fts, rank) VALUES('merge', -1);
                 INSERT INTO blocks_fts(blocks_fts) VALUES('optimize');
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "fts/wal scrub"))?;
        Ok(())
    }

    /// Full forensic scrub after `ExecuteShred`: FTS5 optimize + `VACUUM` + WAL truncate + mirror refresh.
    pub fn full_forensic_shred_scrub(&self) -> Result<(), CoreError> {
        self.scrub_fts_and_wal()?;
        self.conn
            .execute_batch("VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "vacuum shred scrub"))?;
        self.refresh_mirror()?;
        Ok(())
    }

    /// One-time M1 -> M2 trash migration (`docs/sync-protocol.md` §5.9):
    /// creates `T_grace` marks for any pre-existing `TRASHED` blocks that have zero shred marks.
    pub fn migrate_m1_trashed_blocks_if_needed(&mut self) -> Result<Vec<ShredMarkRow>, CoreError> {
        if self.get_local_meta("m2_trash_migrated").as_deref() == Some("1") {
            return Ok(Vec::new());
        }
        let trashed = self.list_trash()?;
        let mut marks = Vec::new();
        let now = now_ms() as i64;
        if self.key_self_check()?.0 {
            for item in trashed {
                if item.shred_state == "unscheduled" {
                    let kids = self.collect_entity_unshredded_key_ids(EntityType::Block, &item.id)?;
                    let mut created = self.queue_local_shred_marks(&kids, T_GRACE_DEFAULT_MS, now)?;
                    marks.append(&mut created);
                }
            }
        }
        self.set_local_meta("m2_trash_migrated", "1")?;
        Ok(marks)
    }

    /// Pack an encrypted `MNP1` mobile state snapshot at current `last_seq` (`docs/sync-protocol.md` §9.1).
    pub fn build_state_snapshot(&mut self) -> Result<(SnapshotHeaderV1, Vec<u8>), CoreError> {
        let snap = self.export_engine_snapshot()?;
        if !snap.bootstrap_completed || snap.journal_epoch.is_none() {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "cannot build mobile state snapshot before sync bootstrap completes",
                "Run 'mynote sync' first",
            ));
        }
        let now = now_ms();
        let snapshot_id = SnapshotId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();
        pack_state_snapshot(
            &snap,
            snapshot_id,
            snap.last_seq,
            smk_kid,
            &smk,
            now as i64,
            rand_bytes::<24>()?,
            rand_bytes::<24>()?,
        )
    }
}
