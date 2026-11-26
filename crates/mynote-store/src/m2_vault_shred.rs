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
pub struct BlockHistoryContentDto {
    pub block_id: String,
    pub op_id: String,
    pub op_type: String,
    pub hlc: String,
    pub device_id: String,
    pub actor: String,
    pub created_at_ms: i64,
    pub is_locked: bool,
    pub key_id: String,
    pub lang: Option<String>,
    pub content: Option<String>,
    pub mnb1_b64: Option<String>,
    pub mnw1_b64: Option<String>,
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
    // MNB1 layout: 45B header + 256B-padded ciphertext (>=256B) + 16B Poly1305 tag (`data-structures.md` §3.1/§3.2)
    if mnb1.len() < 45 + 256 + 16
        || !(mnb1.len() - 61).is_multiple_of(256)
        || &mnb1[0..4] != MAGIC_MNB1
        || mnb1[4] != 1
    {
        return Err(CoreError::new(
            ErrorCode::IntegrityError,
            "invalid MNB1 ciphertext header or padding",
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
    // MNW1 wraps exactly 32B BDEK: 45B header + 32B ciphertext + 16B tag = 93B (`data-structures.md` §3.4.2)
    if mnw1.len() != 45 + 32 + 16 || &mnw1[0..4] != MAGIC_MNW1 || mnw1[4] != 1 {
        return Err(CoreError::new(
            ErrorCode::IntegrityError,
            "invalid MNW1 wrapped BDEK header or length",
            "Re-wrap Tier 2 BDEK via WasmVaultSession",
        ));
    }
    Ok(())
}

impl LocalStore {
    /// Execute a multi-statement store mutation atomically inside a SQLite SAVEPOINT (re-entrant safe).
    pub(super) fn with_savepoint<T, F>(&mut self, name: &str, f: F) -> Result<T, CoreError>
    where
        F: FnOnce(&mut Self) -> Result<T, CoreError>,
    {
        self.conn
            .execute_batch(&format!("SAVEPOINT {name};"))
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "begin savepoint"))?;
        match f(self) {
            Ok(v) => {
                self.conn
                    .execute_batch(&format!("RELEASE SAVEPOINT {name};"))
                    .map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "commit savepoint")
                    })?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.conn.execute_batch(&format!(
                    "ROLLBACK TO SAVEPOINT {name}; RELEASE SAVEPOINT {name};"
                ));
                Err(e)
            }
        }
    }

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
        if parsed.kdf.alg != "argon2id"
            || !(mynote_core::crypto::MIN_ARGON2_M_KIB..=mynote_core::crypto::MAX_ARGON2_M_KIB)
                .contains(&parsed.kdf.m_kib)
            || !(mynote_core::crypto::MIN_ARGON2_T..=mynote_core::crypto::MAX_ARGON2_T)
                .contains(&parsed.kdf.t)
            || !(mynote_core::crypto::MIN_ARGON2_P..=mynote_core::crypto::MAX_ARGON2_P)
                .contains(&parsed.kdf.p)
        {
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                "VaultHeaderV1 Argon2id parameters out of safe bounds",
                "Use standard Argon2id parameters",
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
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query vault_header"))?;
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

    /// Decrypt a specific concurrent Tier 1 (`tier == 1`) live leaf on a locked block on demand
    /// after the Desktop UI has unlocked the Vault (`docs/sync-protocol.md` §4.2, H17).
    pub fn get_tier1_leaf_plaintext(&self, block_id_str: &str, op_id_str: &str) -> Result<String, CoreError> {
        let blk_id = BlockId::parse(block_id_str)?;
        let op_id = OpId::parse(op_id_str)?;
        type Tier1LeafRow = (Option<i64>, Option<String>, Option<String>, String);
        let row: Option<Tier1LeafRow> = self
            .conn
            .query_row(
                "SELECT tier, content, key_id, body_state
                 FROM block_leaves WHERE block_id = ?1 AND op_id = ?2",
                params![blk_id.to_string(), op_id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query tier1 leaf"))?;
        let (tier_opt, content_opt, key_id_opt, body_state) = row.ok_or_else(|| {
            CoreError::new(
                ErrorCode::NotFound,
                format!("leaf '{op_id_str}' not found on block '{block_id_str}'"),
                "Refresh block state",
            )
        })?;
        if tier_opt != Some(1) {
            return Err(CoreError::new(
                ErrorCode::BlockLocked,
                "leaf is not an unlocked Tier 1 version",
                "Decrypt Tier 2 leaves inside WasmVaultSession",
            ));
        }
        if let Some(pt) = content_opt {
            return Ok(pt);
        }
        if body_state != "PLAINTEXT" {
            return Err(CoreError::new(
                ErrorCode::KeyMissing,
                format!("Tier 1 leaf is in state {body_state}"),
                "Sync missing key or resolve conflict",
            ));
        }
        let kid = KeyId::parse(key_id_opt.as_deref().unwrap_or(""))?;
        let decoded = self.load_entity_decoded_ops(EntityType::Block, &blk_id.to_string())?;
        let op = decoded.iter().find(|d| d.op_id == op_id).ok_or_else(|| {
            CoreError::new(
                ErrorCode::NotFound,
                "leaf op missing from sync_ops",
                "Sync latest ops",
            )
        })?;
        if let OpBodyV1::BlockContent { tier: 1, mnb1, .. } = &op.inner.body {
            let bdek = self.unwrap_tier1_bdek(kid)?;
            return decrypt_mnb1(blk_id.as_bytes(), op_id, kid, &bdek, mnb1);
        }
        Err(CoreError::new(
            ErrorCode::IntegrityError,
            "leaf op does not contain Tier 1 content",
            "Refresh block state",
        ))
    }

    /// Fetch a single historical `BlockContent` op for Desktop Daemon Time Travel (`GET /v1/local/blocks/{id}/history/{op_id}`).
    /// - Tier 1: unwraps BDEK with SMK, decrypts `MNB1` -> `content: Some(pt)`, `is_locked: false`.
    /// - Tier 2 (`SEC-03` HARD INVARIANT): unwraps outer `MNR1` with SMK to extract `mnw1` ONLY ->
    ///   `content: None`, `is_locked: true`, `mnb1_b64: Some(...)`, `mnw1_b64: Some(...)`.
    pub fn get_block_history_op_for_daemon(
        &self,
        block_id_str: &str,
        op_id_str: &str,
    ) -> Result<BlockHistoryContentDto, CoreError> {
        let blk_id = BlockId::parse(block_id_str)?;
        let target_op_id = OpId::parse(op_id_str)?;
        let decoded = self.load_entity_decoded_ops(EntityType::Block, &blk_id.to_string())?;
        if decoded.is_empty() {
            return Err(CoreError::new(
                ErrorCode::NotFound,
                format!("block '{block_id_str}' not found"),
                "Check block ID",
            ));
        }
        let target = decoded.iter().find(|d| d.op_id == target_op_id).ok_or_else(|| {
            CoreError::new(
                ErrorCode::NotFound,
                format!("op '{op_id_str}' not found in block '{block_id_str}'"),
                format!("Run 'mynote block history {block_id_str} --json'"),
            )
        })?;
        let (op_lang, tier, key_id, mnb1) = match &target.inner.body {
            OpBodyV1::BlockContent {
                lang,
                tier,
                key_id,
                mnb1,
                ..
            } => (lang.clone(), *tier, *key_id, mnb1.as_slice()),
            _ => {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "op '{op_id_str}' has no block content (op_type={})",
                        op_type_str(target.inner.op_type)
                    ),
                    "Select a content-bearing history op",
                ));
            }
        };

        if self.is_key_executed(&key_id) {
            return Err(CoreError::new(
                ErrorCode::KeyShredded,
                format!("key {key_id} for op '{op_id_str}' has been permanently shredded"),
                "Shredded historical versions cannot be recovered",
            ));
        }

        let effective_lang = op_lang.or_else(|| {
            self.conn
                .query_row(
                    "SELECT lang FROM blocks WHERE id = ?1",
                    [blk_id.to_string()],
                    |r| r.get::<_, String>(0),
                )
                .optional()
                .ok()
                .flatten()
        });

        match tier {
            1 => {
                let bdek = self.unwrap_tier1_bdek(key_id)?;
                let pt = decrypt_mnb1(blk_id.as_bytes(), target.op_id, key_id, &bdek, mnb1)?;
                Ok(BlockHistoryContentDto {
                    block_id: blk_id.to_string(),
                    op_id: target.op_id.to_string(),
                    op_type: op_type_str(target.inner.op_type).to_string(),
                    hlc: target.inner.hlc.canonical_string(),
                    device_id: target.device_id.to_string(),
                    actor: target.inner.actor.clone(),
                    created_at_ms: target.created_at_ms,
                    is_locked: false,
                    key_id: key_id.to_string(),
                    lang: effective_lang,
                    content: Some(pt),
                    mnb1_b64: None,
                    mnw1_b64: None,
                })
            }
            2 => {
                let rec = self.unwrap_key_record_full(key_id)?;
                if rec.tier != 2 || rec.bdek.len() != 93 || rec.block_id != blk_id.0 {
                    return Err(CoreError::new(
                        ErrorCode::IntegrityError,
                        format!("invalid Tier 2 key record for key {key_id} on block {blk_id}"),
                        "Verify key integrity or restore from backup",
                    ));
                }
                Ok(BlockHistoryContentDto {
                    block_id: blk_id.to_string(),
                    op_id: target.op_id.to_string(),
                    op_type: op_type_str(target.inner.op_type).to_string(),
                    hlc: target.inner.hlc.canonical_string(),
                    device_id: target.device_id.to_string(),
                    actor: target.inner.actor.clone(),
                    created_at_ms: target.created_at_ms,
                    is_locked: true,
                    key_id: key_id.to_string(),
                    lang: effective_lang,
                    content: None,
                    mnb1_b64: Some(B64.encode(mnb1)),
                    mnw1_b64: Some(B64.encode(&rec.bdek)),
                })
            }
            _ => Err(CoreError::new(
                ErrorCode::IntegrityError,
                format!("unsupported block content tier {tier} in op '{op_id_str}'"),
                "Inspect block history or restore from backup",
            )),
        }
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

        // Reject duplicate CREATE onto an existing block_id (H7)
        let already_exists: i64 = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM blocks WHERE id = ?1)
                     OR EXISTS(SELECT 1 FROM sync_ops WHERE entity_type = 'block' AND entity_id = ?1)",
                [blk_id.to_string()],
                |r| r.get(0),
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "check block exists"))?;
        if already_exists != 0 {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                format!("block_id '{block_id_str}' already exists"),
                "Generate a fresh BlockId via WasmVaultSession.encryptNewBlock",
            ));
        }

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

        let mat = self.with_savepoint("add_tier2_block", |this| {
            this.conn
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
            this.insert_sync_op(
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
            this.rematerialize_block(blk_id)
        })?;
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
    /// Reuses caller's `op_id` verbatim (`F-01`); if `mnw1` is omitted, validates `key_id` already exists as Tier 2
    /// owned by this exact block and not shredded.
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
        let keyring_gen = self.current_keyring()?.keyring_gen;

        let new_mnr1 = if let Some(mnw1) = t2.mnw1 {
            validate_mnw1_header(mnw1)?;
            let krec = KeyRecordV1 {
                v: 1,
                key_id,
                block_id: blk_id.0,
                tier: 2,
                created_hlc: hlc.canonical_string(),
                created_by: self.device_id.clone(),
                bdek: mnw1.to_vec(),
            };
            Some(encrypt_mnr1(
                smk_kid,
                &smk,
                keyring_gen,
                &krec,
                rand_bytes::<24>()?,
            )?)
        } else {
            if self.is_key_executed(&key_id) {
                return Err(CoreError::new(
                    ErrorCode::KeyShredded,
                    format!("key_id {key_id} has been shredded"),
                    "Rekey via WasmVaultSession.rekeyToVault",
                ));
            }
            let rec = self.unwrap_key_record_full(key_id)?;
            if rec.tier != 2 || rec.block_id != blk_id.0 {
                return Err(CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("key_id {key_id} is not a Tier 2 key owned by block {blk_id}"),
                    "Provide a Tier 2 key owned by this block or rekey with mnw1",
                ));
            }
            None
        };

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

        let mat = self.with_savepoint("update_tier2_block", |this| {
            if let Some(mnr1) = new_mnr1 {
                this.conn
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
                    .map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert tier2 key")
                    })?;
            }
            this.insert_sync_op(
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
            this.rematerialize_block(blk_id)
        })?;
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
    /// Atomically writes `LOCK` op + new Tier 2 key + shred marks for old keys, removes plaintext from
    /// `block_leaves` & `blocks_fts`, and checkpoints WAL + optimizes FTS5!
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

        let mat = self.with_savepoint("lock_block_tier2", |this| {
            this.conn
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
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert tier2 lock key")
                })?;
            this.insert_sync_op(
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
            let mat = this.rematerialize_block(blk_id)?;
            if this.key_self_check()?.0 {
                let old_only: Vec<KeyId> = old_keys.into_iter().filter(|k| *k != new_key_id).collect();
                this.queue_local_shred_marks(&old_only, grace_ms, now as i64)?;
            }
            Ok(mat)
        })?;

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

        let blk_id = BlockId::parse(block_id_str)?;
        let old_keys = self.collect_entity_unshredded_key_ids(EntityType::Block, &blk_id.to_string())?;
        let parents: Vec<OpId> = detail
            .head_op_ids
            .iter()
            .map(|s| OpId::parse(s))
            .collect::<Result<_, _>>()?;
        let now = now_ms();
        let op_id = OpId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let new_key_id = KeyId::from_ulid(Ulid::from_parts(now, rand_bytes::<10>()?));
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

        let mat = self.with_savepoint("unlock_block_tier1", |this| {
            this.conn
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
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert tier1 unlock key")
                })?;
            this.insert_sync_op(
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
            let mat = this.rematerialize_block(blk_id)?;
            if shred_old_key && this.key_self_check()?.0 {
                let old_only: Vec<KeyId> = old_keys.into_iter().filter(|k| *k != new_key_id).collect();
                this.queue_local_shred_marks(&old_only, T_GRACE_DEFAULT_MS, now as i64)?;
            }
            Ok(mat)
        })?;
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
        expected_heads: Option<&[String]>,
        tier2_rekey: Option<Tier2OpInput<'_>>,
        grace_ms: i64,
        actor: &str,
    ) -> Result<(WriteReceipt, Vec<KeyId>), CoreError> {
        let detail = self.get_block(block_id_str)?;
        self.check_bootstrap_gate(EntityType::Block, &detail.id, OpType::Update)?;
        if detail.has_conflict {
            return Err(CoreError::new(
                ErrorCode::HeadMismatch,
                format!("block {block_id_str} has unresolved concurrent versions"),
                "Resolve multi-leaf conflict before purging history",
            ));
        }
        if let Some(exp) = expected_heads {
            let exp_set: BTreeSet<String> = exp.iter().cloned().collect();
            let act_set: BTreeSet<String> = detail.head_op_ids.iter().cloned().collect();
            if exp_set != act_set {
                return Err(CoreError::new(
                    ErrorCode::HeadMismatch,
                    format!("block {block_id_str} heads changed concurrently"),
                    "Refresh block state and retry purge_history",
                )
                .with_details(serde_json::json!({
                    "expected_heads": exp,
                    "actual_heads": detail.head_op_ids,
                })));
            }
        }
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

        let (receipt, queued_old_keys) = self.with_savepoint("purge_block_history", |this| {
            let (receipt, new_key_id) = if let Some(t2) = tier2_rekey {
                if t2.mnw1.is_none() {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        "mnw1_b64 is required when purging history of a Tier 2 block",
                        "Rekey via WasmVaultSession.rekeyToVault",
                    ));
                }
                let new_kid = KeyId::parse(t2.key_id)?;
                let r = this.update_tier2_block(block_id_str, t2, &detail.head_op_ids, None, None, actor)?;
                (r, new_kid)
            } else {
                if detail.is_locked {
                    return Err(CoreError::new(
                        ErrorCode::BlockLocked,
                        "purging history of a locked block requires Tier 2 rekey payload from WasmVaultSession",
                        "Unlock Vault in the UI and re-submit purge_history",
                    ));
                }
                // HARD INVARIANT §3.1: NEVER coerce missing/undecryptable content to `""` (C5)!
                let content = detail.content.as_deref().ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::KeyMissing,
                        format!("block {block_id_str} has no readable plaintext (KeyUnavailable/DecryptFailed)"),
                        "Sync missing keys or inspect block integrity before purging history",
                    )
                })?;
                let parents: Vec<OpId> = detail
                    .head_op_ids
                    .iter()
                    .map(|s| OpId::parse(s))
                    .collect::<Result<_, _>>()?;
                let op_id = OpId::from_ulid(this.ulid_gen.next(now, rand_bytes::<10>()?));
                let new_kid = KeyId::from_ulid(Ulid::from_parts(now, rand_bytes::<10>()?));
                let bdek = Zeroizing::new(rand_bytes::<32>()?);
                let hlc = this.hlc_clock.tick(now);
                let smk_kid = this.current_smk_kid;
                let smk = this.current_smk()?.clone();
                let keyring_gen = this.current_keyring()?.keyring_gen;

                let mnb1 = encrypt_mnb1(
                    blk_id.as_bytes(),
                    op_id,
                    new_kid,
                    &bdek,
                    content,
                    rand_bytes::<24>()?,
                )?;
                let krec = KeyRecordV1 {
                    v: 1,
                    key_id: new_kid,
                    block_id: blk_id.0,
                    tier: 1,
                    created_hlc: hlc.canonical_string(),
                    created_by: this.device_id.clone(),
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
                let mns1 =
                    encrypt_mns1(smk_kid, &smk, op_id, &this.device_id, &inner, rand_bytes::<24>()?)?;
                this.conn
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
                this.insert_sync_op(
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
                let mat = this.rematerialize_block(blk_id)?;
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
            let queued = if this.key_self_check()?.0 {
                this.queue_local_shred_marks(&old_only, grace_ms, now as i64)?;
                old_only
            } else {
                Vec::new()
            };
            Ok((receipt, queued))
        })?;
        self.refresh_mirror()?;
        Ok((receipt, queued_old_keys))
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
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query trash block"))?;
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

        if self.is_key_executed(&key_id) {
            return Err(CoreError::new(
                ErrorCode::KeyShredded,
                format!("key {key_id} has already been shredded"),
                "Cannot restore a shredded block",
            ));
        }

        let parents = self.current_entity_leaves(EntityType::Block, &blk_id.to_string())?;
        let now = now_ms();
        let hlc = self.hlc_clock.tick(now);
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();
        let keyring_gen = self.current_keyring()?.keyring_gen;

        let new_mnr1 = if let Some(mnw1) = t2.mnw1 {
            validate_mnw1_header(mnw1)?;
            let krec = KeyRecordV1 {
                v: 1,
                key_id,
                block_id: blk_id.0,
                tier: 2,
                created_hlc: hlc.canonical_string(),
                created_by: self.device_id.clone(),
                bdek: mnw1.to_vec(),
            };
            Some(encrypt_mnr1(
                smk_kid,
                &smk,
                keyring_gen,
                &krec,
                rand_bytes::<24>()?,
            )?)
        } else {
            let rec = self.unwrap_key_record_full(key_id)?;
            if rec.tier != 2 || rec.block_id != blk_id.0 {
                return Err(CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("key {key_id} is not a Tier 2 key owned by block {blk_id}"),
                    "Re-encrypt with a valid Tier 2 key for this block",
                ));
            }
            None
        };

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

        let mat = self.with_savepoint("restore_trash_tier2", |this| {
            if let Some(mnr1) = new_mnr1 {
                this.conn
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
                    .map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert restored tier2 key")
                    })?;
            } else {
                // Only cancel shred marks on the restored key (never resurrect prior LOCK/purge_history old Tier 1 keys!)
                this.cancel_local_shred_marks_for_keys(&[key_id])?;
            }
            this.insert_sync_op(
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
            this.rematerialize_block(blk_id)
        })?;
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

    /// Collect all `KeyId`s currently referenced by live leaves of any `ACTIVE` block or `ACTIVE` buffer.
    pub(super) fn collect_active_live_key_ids(&self) -> Result<BTreeSet<KeyId>, CoreError> {
        let mut live = BTreeSet::new();
        {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT DISTINCT bl.key_id
                     FROM block_leaves bl
                     JOIN blocks b ON b.id = bl.block_id
                     WHERE b.state = 'ACTIVE'
                       AND bl.key_id IS NOT NULL
                       AND bl.body_state IN ('PLAINTEXT', 'SEALED', 'DECRYPT_FAILED', 'KEY_UNAVAILABLE')",
                )
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "scan active block keys")
                })?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(|e| {
                CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map active block keys")
            })?;
            for s in rows.flatten() {
                if let Ok(kid) = KeyId::parse(&s) {
                    if !self.is_key_executed(&kid) {
                        live.insert(kid);
                    }
                }
            }
        }
        {
            let mut stmt = self
                .conn
                .prepare("SELECT DISTINCT key_id FROM buffers WHERE state = 'ACTIVE'")
                .map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        e.to_string(),
                        "scan active buffer keys",
                    )
                })?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(|e| {
                CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map active buffer keys")
            })?;
            for s in rows.flatten() {
                if let Ok(kid) = KeyId::parse(&s) {
                    if !self.is_key_executed(&kid) {
                        live.insert(kid);
                    }
                }
            }
        }
        Ok(live)
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
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "check active mark"))?;
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
                .map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        e.to_string(),
                        "check server_acked shred_marks",
                    )
                })?;
            // Delete unacked local marks cleanly (never pollute server_acked digest); cancel server-acked marks.
            self.conn
                .execute(
                    "DELETE FROM shred_marks
                     WHERE key_id = ?1 AND server_acked = 0 AND state IN ('pending_confirm', 'scheduled')",
                    [kid.to_string()],
                )
                .map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        e.to_string(),
                        "delete unacked local shred_marks",
                    )
                })?;
            self.conn
                .execute(
                    "UPDATE shred_marks SET state = 'cancelled', cancelled_by = ?1
                     WHERE key_id = ?2 AND server_acked = 1 AND state IN ('pending_confirm', 'scheduled')",
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

    /// Auto-delete unacked local `shred_marks` whose `key_id` is now live on an `ACTIVE` block/buffer
    /// (e.g. after Update-Wins revival during `PullResponse`, preventing C7 live-key shred!).
    pub(super) fn cancel_active_unacked_shred_marks_in_tx(&self) -> Result<usize, CoreError> {
        let live_keys = self.collect_active_live_key_ids()?;
        let mut removed = 0usize;
        for kid in live_keys {
            let n = self
                .conn
                .execute(
                    "DELETE FROM shred_marks
                     WHERE key_id = ?1 AND server_acked = 0 AND state IN ('pending_confirm', 'scheduled')",
                    [kid.to_string()],
                )
                .map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        e.to_string(),
                        "prune unacked shred_marks for active live keys",
                    )
                })?;
            removed += n;
        }
        Ok(removed)
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
        let live_active = if only_server_acked {
            BTreeSet::new()
        } else {
            self.collect_active_live_key_ids().unwrap_or_default()
        };
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
            if !only_server_acked && live_active.contains(&key_id) {
                continue;
            }
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
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query shred_mark"))?;

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
            let new_rank = shred_state_rank(r.state) as i64;
            self.conn
                .execute(
                    "UPDATE shred_marks
                     SET state = CASE
                             WHEN ?4 >= (CASE state
                                 WHEN 'pending_confirm' THEN 0
                                 WHEN 'scheduled' THEN 1
                                 WHEN 'cancelled' THEN 2
                                 WHEN 'executed' THEN 3
                                 ELSE 0 END)
                             THEN ?1 ELSE state
                         END,
                         not_before_ms = CASE
                             WHEN not_before_ms IS NULL THEN ?2
                             WHEN ?2 IS NULL THEN not_before_ms
                             ELSE MIN(not_before_ms, ?2)
                         END,
                         server_acked = 1
                     WHERE key_id = ?3 AND state IN ('pending_confirm', 'scheduled')",
                    params![
                        shred_state_to_str(r.state),
                        r.not_before_ms,
                        r.key_id.to_string(),
                        new_rank,
                    ],
                )
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "ack shred_mark"))?;
        }
        if !cancelled_keys.is_empty() {
            let mut pend = self.load_pending_cancel_keys();
            for kid in cancelled_keys {
                pend.remove(kid);
                // Only update server_acked=1 marks so a newer unacked offline delete mark (server_acked=0)
                // is NEVER cancelled or injected as a phantom row into keys_digest (H8)!
                self.conn
                    .execute(
                        "UPDATE shred_marks SET state = 'cancelled'
                         WHERE key_id = ?1 AND server_acked = 1 AND state IN ('pending_confirm', 'scheduled')",
                        [kid.to_string()],
                    )
                    .map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "ack cancelled shred_mark")
                    })?;
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
        if has_pending_confirm {
            ("pending_confirm".to_string(), min_nb)
        } else if has_scheduled {
            ("scheduled".to_string(), min_nb)
        } else if has_pending_sync {
            ("pending_sync".to_string(), None)
        } else {
            ("unscheduled".to_string(), None)
        }
    }

    /// Collect eligible shred key_ids for UI `trash/actions/prepare` & `commit`.
    /// HARD INVARIANT (`INV-KEY-LIVENESS`, C8):
    /// - `confirm_pending`: only `server_acked = 1 AND state = 'pending_confirm'` marks;
    /// - `expedite`: ONLY `TRASHED` blocks' `server_acked = 1 AND state = 'scheduled'` marks,
    ///   strictly excluding any `key_id` live on an `ACTIVE` block/buffer!
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
        let live_active = self.collect_active_live_key_ids()?;
        let mut eligible_blocks = Vec::new();
        let mut keys = BTreeSet::new();
        let mut earliest_nb: Option<i64> = None;

        for bid in &target_blocks {
            if action == "expedite" {
                let state: Option<String> = self
                    .conn
                    .query_row("SELECT state FROM blocks WHERE id = ?1", [bid], |r| r.get(0))
                    .optional()
                    .map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "check block state")
                    })?;
                if state.as_deref() != Some("TRASHED") {
                    continue;
                }
            }
            eligible_blocks.push(bid.clone());

            if action == "purge_history" {
                for kid in self.collect_entity_unshredded_key_ids(EntityType::Block, bid)? {
                    keys.insert(kid);
                }
                continue;
            }

            let filter_state = match action {
                "confirm_pending" => "sm.server_acked = 1 AND sm.state = 'pending_confirm'",
                "expedite" => "sm.server_acked = 1 AND sm.state = 'scheduled'",
                _ => "sm.server_acked = 1 AND sm.state IN ('scheduled', 'pending_confirm')",
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
                    if !self.is_key_executed(&kid) && !live_active.contains(&kid) {
                        keys.insert(kid);
                        if let Some(t) = nb {
                            earliest_nb = Some(earliest_nb.map_or(t, |cur| cur.min(t)));
                        }
                    }
                }
            }
        }
        Ok((eligible_blocks, keys.into_iter().collect(), earliest_nb))
    }

    /// Reconcile local unpushed outbox ops against server shred marks (`docs/sync-protocol.md` §5.7):
    /// - Delete-intent (`CancelAndPush`): handled automatically by `build_pending_push()` (`cancel_key_ids`).
    /// - Rekey-intent / Shredded (`NeedsRekey`):
    ///   - Tier 1: automatically rekeys onto a fresh Tier 1 BDEK (zero data loss, does NOT cancel shred mark!).
    ///   - Tier 2: marks `sync_blocked_reason = 'NEEDS_VAULT_REKEY'` & preserves `mnw1` so other ops keep syncing!
    pub fn reconcile_outbox_against_shred_marks(&mut self) -> Result<Vec<String>, CoreError> {
        let (rekey_ops, _) = self.with_savepoint("reconcile_outbox", |this| {
            this.reconcile_outbox_with_imminent_shreds(&BTreeSet::new())
        })?;
        Ok(rekey_ops)
    }

    pub(super) fn reconcile_outbox_with_imminent_shreds(
        &mut self,
        imminent_shreds: &BTreeSet<KeyId>,
    ) -> Result<(Vec<String>, usize), CoreError> {
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
        let mut rekeyed_tier1_count = 0usize;
        let unpushed: Vec<LocalOpRecord> = snap
            .ops
            .values()
            .filter(|o| o.server_seq.is_none() && o.sync_blocked_reason.is_none())
            .cloned()
            .collect();

        let mut unpushed_by_id: BTreeMap<OpId, &LocalOpRecord> = BTreeMap::new();
        let mut needs_rekey_ids: BTreeSet<OpId> = BTreeSet::new();
        for o in &unpushed {
            unpushed_by_id.insert(o.op_id, o);
            if matches!(snap.classify_unpushed_op(o), OutboxKeyAction::NeedsRekey { .. }) {
                needs_rekey_ids.insert(o.op_id);
            }
        }
        if needs_rekey_ids.is_empty() {
            return Ok((needs_vault_rekey_ops, 0));
        }

        // Helper: walk backwards from `start_parents` through any unpushed ops in `needs_rekey_ids`,
        // returning `(rebased_parents, collapsed_ancestors)` so multi-op offline chains on a retiring
        // key collapse cleanly without leaving orphaned ancestors stuck on `KEY_PENDING_SHRED` (H8).
        // When `allow_collapse_create` is false (e.g. a non-content leaf like DELETE), an unpushed
        // `OpType::Create` ancestor is NEVER collapsed so the block's initial metadata is preserved.
        let collapse_retiring_ancestors =
            |start_parents: &[OpId], allow_collapse_create: bool| -> (Vec<OpId>, BTreeSet<OpId>, bool) {
                let mut frontier: BTreeSet<OpId> = BTreeSet::new();
                let mut collapsed: BTreeSet<OpId> = BTreeSet::new();
                let mut collapsed_create = false;
                let mut stack: Vec<OpId> = start_parents.to_vec();
                let mut visited: BTreeSet<OpId> = BTreeSet::new();
                while let Some(pid) = stack.pop() {
                    if !visited.insert(pid) {
                        continue;
                    }
                    if needs_rekey_ids.contains(&pid) {
                        if let Some(anc) = unpushed_by_id.get(&pid) {
                            if anc.op_type == OpType::Create && !allow_collapse_create {
                                frontier.insert(pid);
                                continue;
                            }
                            if anc.op_type == OpType::Create {
                                collapsed_create = true;
                            }
                            collapsed.insert(pid);
                            for &gp in &anc.parent_op_ids {
                                stack.push(gp);
                            }
                        } else {
                            frontier.insert(pid);
                        }
                    } else {
                        frontier.insert(pid);
                    }
                }
                (frontier.into_iter().collect(), collapsed, collapsed_create)
            };

        // Helper: only delete/block an ancestor if no other surviving op references it as a parent.
        let safe_ancestors_to_drop = |leaf_op_id: OpId, collapsed: &BTreeSet<OpId>| -> Vec<OpId> {
            collapsed
                .iter()
                .copied()
                .filter(|anc| {
                    !snap.ops.values().any(|other| {
                        other.op_id != leaf_op_id
                            && !collapsed.contains(&other.op_id)
                            && other.parent_op_ids.contains(anc)
                    })
                })
                .collect()
        };

        for op in &unpushed {
            // NEVER resurrect a superseded ancestor or locally deleted block!
            let live_leaves = self
                .current_entity_leaves(op.entity_type, &op.entity_id)
                .unwrap_or_default();
            if !live_leaves.contains(&op.op_id) {
                continue;
            }
            let self_needs_rekey = needs_rekey_ids.contains(&op.op_id);
            let (rebased_parents, collapsed_ancestors, collapsed_create) =
                collapse_retiring_ancestors(&op.parent_op_ids, self_needs_rekey);
            if !self_needs_rekey && collapsed_ancestors.is_empty() {
                continue;
            }

            let Some(smk) = self.smks.get(&op.smk_kid).cloned() else {
                continue;
            };
            let Ok(inner) = decrypt_mns1(op.smk_kid, &smk, op.op_id, &op.device_id, op.key_id, &op.envelope)
            else {
                continue;
            };

            // Case 1: Live leaf itself is NOT on a retiring key (e.g. local DELETE or LOCK on a fresh key),
            // but has unpushed non-Create ancestor(s) on a retiring key. Rebase its `parent_op_ids` with a
            // fresh MNS1 nonce and drop the superseded unpushed retiring ancestor(s) (H8).
            if !self_needs_rekey {
                let mut rebased_inner = inner.clone();
                rebased_inner.parent_op_ids = rebased_parents.clone();
                let new_mns1 = encrypt_mns1(
                    op.smk_kid,
                    &smk,
                    op.op_id,
                    &op.device_id,
                    &rebased_inner,
                    rand_bytes::<24>()?,
                )?;
                let parent_json =
                    serde_json::to_string(&rebased_parents.iter().map(|p| p.to_string()).collect::<Vec<_>>())
                        .map_err(|e| {
                            CoreError::new(ErrorCode::IntegrityError, e.to_string(), "serialize parents")
                        })?;
                for anc in safe_ancestors_to_drop(op.op_id, &collapsed_ancestors) {
                    self.conn
                        .execute(
                            "DELETE FROM sync_ops WHERE op_id = ?1 AND server_seq IS NULL",
                            [anc.to_string()],
                        )
                        .map_err(|e| {
                            CoreError::new(ErrorCode::IntegrityError, e.to_string(), "drop retiring ancestor")
                        })?;
                }
                self.conn
                    .execute(
                        "UPDATE sync_ops SET parent_op_ids = ?1, envelope = ?2
                         WHERE op_id = ?3 AND server_seq IS NULL",
                        params![parent_json, new_mns1, op.op_id.to_string()],
                    )
                    .map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "rebase leaf parents")
                    })?;
                match op.entity_type {
                    EntityType::Block => {
                        if let Ok(blk_id) = BlockId::parse(&op.entity_id) {
                            let _ = self.rematerialize_block(blk_id);
                        }
                    }
                    EntityType::Buffer => {
                        if let Ok(buf_id) = BufferId::parse(&op.entity_id) {
                            let _ = self.rematerialize_buffer(buf_id);
                        }
                    }
                }
                rekeyed_tier1_count += 1;
                continue;
            }

            let rekeyed_op_type = if collapsed_create && rebased_parents.is_empty() {
                OpType::Create
            } else {
                inner.op_type
            };

            let Some(old_kid) = op.key_id else { continue };
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
                        let new_kid = KeyId::from_ulid(Ulid::from_parts(now, rand_bytes::<10>()?));
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
                            op_type: rekeyed_op_type,
                            parent_op_ids: rebased_parents.clone(),
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
                        // Replace unpublished local op & any collapsed retiring ancestors with rekeyed op
                        for anc in safe_ancestors_to_drop(op.op_id, &collapsed_ancestors) {
                            self.conn
                                .execute(
                                    "DELETE FROM sync_ops WHERE op_id = ?1 AND server_seq IS NULL",
                                    [anc.to_string()],
                                )
                                .map_err(|e| {
                                    CoreError::new(
                                        ErrorCode::IntegrityError,
                                        e.to_string(),
                                        "drop collapsed retiring ancestor",
                                    )
                                })?;
                        }
                        self.conn
                            .execute(
                                "DELETE FROM sync_ops WHERE op_id = ?1 AND server_seq IS NULL",
                                [op.op_id.to_string()],
                            )
                            .map_err(|e| {
                                CoreError::new(ErrorCode::IntegrityError, e.to_string(), "delete rekeyed op")
                            })?;
                        self.insert_sync_op(
                            new_op_id,
                            None,
                            EntityType::Block,
                            &blk_id.to_string(),
                            &rebased_parents,
                            rekeyed_op_type,
                            &hlc,
                            &inner.actor,
                            Some(new_kid),
                            cur_smk_kid,
                            &new_mns1,
                            now as i64,
                        )?;
                        let _ = self.rematerialize_block(blk_id);
                        rekeyed_tier1_count += 1;
                    }
                }
                OpBodyV1::BufferMeta {
                    name_mnb1: Some(old_name_mnb1),
                    position,
                    ..
                } => {
                    let buf_id = BufferId::parse(&inner.entity_id)?;
                    let name_pt = if let Ok(old_bdek) = self.unwrap_tier1_bdek(old_kid) {
                        decrypt_mnb1(buf_id.as_bytes(), op.op_id, old_kid, &old_bdek, old_name_mnb1).ok()
                    } else {
                        self.conn
                            .query_row(
                                "SELECT name FROM buffers WHERE id = ?1",
                                [buf_id.to_string()],
                                |r| r.get::<_, String>(0),
                            )
                            .optional()
                            .unwrap_or(None)
                    };
                    if let Some(name_str) = name_pt {
                        let now = now_ms();
                        let new_op_id = OpId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
                        let new_kid = KeyId::from_ulid(Ulid::from_parts(now, rand_bytes::<10>()?));
                        let new_bdek = Zeroizing::new(rand_bytes::<32>()?);
                        let hlc = self.hlc_clock.tick(now);
                        let cur_smk_kid = self.current_smk_kid;
                        let cur_smk = self.current_smk()?.clone();
                        let keyring_gen = self.current_keyring()?.keyring_gen;

                        let new_name_mnb1 = encrypt_mnb1(
                            buf_id.as_bytes(),
                            new_op_id,
                            new_kid,
                            &new_bdek,
                            &name_str,
                            rand_bytes::<24>()?,
                        )?;
                        let krec = KeyRecordV1 {
                            v: 1,
                            key_id: new_kid,
                            block_id: buf_id.0,
                            tier: 1,
                            created_hlc: hlc.canonical_string(),
                            created_by: self.device_id.clone(),
                            bdek: new_bdek.to_vec(),
                        };
                        let mnr1 =
                            encrypt_mnr1(cur_smk_kid, &cur_smk, keyring_gen, &krec, rand_bytes::<24>()?)?;
                        let new_inner = InnerOpV1 {
                            v: 1,
                            entity_type: EntityType::Buffer,
                            entity_id: buf_id.to_string(),
                            op_type: rekeyed_op_type,
                            parent_op_ids: rebased_parents.clone(),
                            hlc: hlc.clone(),
                            actor: inner.actor.clone(),
                            body: OpBodyV1::BufferMeta {
                                key_id: new_kid,
                                name_mnb1: Some(new_name_mnb1),
                                position: position.clone(),
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
                                    buf_id.to_string(),
                                    keyring_gen as i64,
                                    mnr1,
                                    hlc.canonical_string(),
                                    now as i64,
                                ],
                            )
                            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "rekey buffer key"))?;
                        for anc in safe_ancestors_to_drop(op.op_id, &collapsed_ancestors) {
                            self.conn
                                .execute(
                                    "DELETE FROM sync_ops WHERE op_id = ?1 AND server_seq IS NULL",
                                    [anc.to_string()],
                                )
                                .map_err(|e| {
                                    CoreError::new(
                                        ErrorCode::IntegrityError,
                                        e.to_string(),
                                        "drop buffer ancestor",
                                    )
                                })?;
                        }
                        self.conn
                            .execute(
                                "DELETE FROM sync_ops WHERE op_id = ?1 AND server_seq IS NULL",
                                [op.op_id.to_string()],
                            )
                            .map_err(|e| {
                                CoreError::new(
                                    ErrorCode::IntegrityError,
                                    e.to_string(),
                                    "delete rekeyed buffer op",
                                )
                            })?;
                        self.insert_sync_op(
                            new_op_id,
                            None,
                            EntityType::Buffer,
                            &buf_id.to_string(),
                            &rebased_parents,
                            rekeyed_op_type,
                            &hlc,
                            &inner.actor,
                            Some(new_kid),
                            cur_smk_kid,
                            &new_mns1,
                            now as i64,
                        )?;
                        let _ = self.rematerialize_buffer(buf_id);
                        rekeyed_tier1_count += 1;
                    }
                }
                OpBodyV1::BlockContent { tier: 2, .. } => {
                    // Save wrapped mnw1 before old key is shredded so UI can decrypt & rekey upon unlock!
                    if let Ok((2, mnw1)) = self.unwrap_bdek(old_kid) {
                        let slot_key = format!("blocked_t2_mnw1:{}", op.op_id);
                        self.set_local_meta(&slot_key, &B64.encode(mnw1))?;
                    }
                    self.conn
                        .execute(
                            "UPDATE sync_ops SET sync_blocked_reason = 'NEEDS_VAULT_REKEY' WHERE op_id = ?1",
                            [op.op_id.to_string()],
                        )
                        .map_err(|e| {
                            CoreError::new(
                                ErrorCode::IntegrityError,
                                e.to_string(),
                                "mark op NEEDS_VAULT_REKEY",
                            )
                        })?;
                    for anc in safe_ancestors_to_drop(op.op_id, &collapsed_ancestors) {
                        self.conn
                            .execute(
                                "UPDATE sync_ops SET sync_blocked_reason = 'NEEDS_VAULT_REKEY_ANCESTOR'
                                 WHERE op_id = ?1 AND server_seq IS NULL AND sync_blocked_reason IS NULL",
                                [anc.to_string()],
                            )
                            .map_err(|e| {
                                CoreError::new(
                                    ErrorCode::IntegrityError,
                                    e.to_string(),
                                    "mark ancestor NEEDS_VAULT_REKEY_ANCESTOR",
                                )
                            })?;
                    }
                    needs_vault_rekey_ops.push(op.op_id.to_string());
                }
                _ => {}
            }
        }
        Ok((needs_vault_rekey_ops, rekeyed_tier1_count))
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
    /// Atomic via SQLite savepoint (H7); executes deferred shred + forensic scrub on `old_kid` if already
    /// server-executed (C3 Path B).
    pub fn rekey_blocked_tier2_op(
        &mut self,
        blocked_op_id: &str,
        t2: Tier2OpInput<'_>,
        actor: &str,
    ) -> Result<WriteReceipt, CoreError> {
        let (entity_id, dev_s, old_kid_s, old_smk_s, old_env): (
            String,
            String,
            Option<String>,
            String,
            Vec<u8>,
        ) = self
            .conn
            .query_row(
                "SELECT entity_id, device_id, key_id, smk_kid, envelope
                 FROM sync_ops
                 WHERE op_id = ?1 AND sync_blocked_reason = 'NEEDS_VAULT_REKEY' AND server_seq IS NULL",
                [blocked_op_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
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
        self.check_bootstrap_gate(EntityType::Block, &entity_id, OpType::Update)?;
        let blk_id = BlockId::parse(&entity_id)?;
        let blocked_oid = OpId::parse(blocked_op_id)?;
        let old_kid = old_kid_s.as_deref().and_then(|s| KeyId::parse(s).ok());
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
        if self.is_key_executed(&new_kid) {
            return Err(CoreError::new(
                ErrorCode::KeyShredded,
                format!("key '{new_kid}' is already shredded"),
                "Generate a fresh key_id for rekeying",
            ));
        }

        // Preserve public_hint / metadata from blocked op BEFORE deleting it
        let mut preserved_hint: Option<Option<String>> = None;
        let mut fallback_buf: Option<BufferId> = None;
        let mut fallback_pos: Option<String> = None;
        let mut fallback_lang: Option<String> = None;
        if let (Ok(dev), Ok(smk_kid)) = (DeviceId::parse(dev_s), SmkKid::parse(&old_smk_s)) {
            if let Some(smk) = self.smks.get(&smk_kid) {
                if let Ok(old_inner) = decrypt_mns1(smk_kid, smk, blocked_oid, &dev, old_kid, &old_env) {
                    if let OpBodyV1::BlockContent {
                        buffer_id,
                        position,
                        lang,
                        public_hint,
                        ..
                    } = old_inner.body
                    {
                        preserved_hint = public_hint;
                        fallback_buf = buffer_id;
                        fallback_pos = position;
                        fallback_lang = lang;
                    }
                }
            }
        }

        let (receipt, shred_executed) = self.with_savepoint("rekey_blocked_tier2", |this| {
            // Remove unpublished blocked op, any blocked retiring ancestors on this entity, and saved mnw1 slot
            this.conn
                .execute(
                    "DELETE FROM sync_ops
                     WHERE entity_type = 'block' AND entity_id = ?1 AND server_seq IS NULL
                       AND (op_id = ?2 OR sync_blocked_reason = 'NEEDS_VAULT_REKEY_ANCESTOR')",
                    params![entity_id, blocked_op_id],
                )
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "delete blocked tier2 op")
                })?;
            this.conn
                .execute(
                    "DELETE FROM local_meta WHERE key = ?1",
                    [format!("blocked_t2_mnw1:{blocked_op_id}")],
                )
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "delete blocked mnw1 slot")
                })?;

            let parents = this.current_entity_leaves(EntityType::Block, &entity_id)?;
            let now = now_ms();
            let hlc = this.hlc_clock.tick(now);
            let smk_kid = this.current_smk_kid;
            let smk = this.current_smk()?.clone();
            let keyring_gen = this.current_keyring()?.keyring_gen;

            let krec = KeyRecordV1 {
                v: 1,
                key_id: new_kid,
                block_id: blk_id.0,
                tier: 2,
                created_hlc: hlc.canonical_string(),
                created_by: this.device_id.clone(),
                bdek: mnw1.to_vec(),
            };
            let mnr1 = encrypt_mnr1(smk_kid, &smk, keyring_gen, &krec, rand_bytes::<24>()?)?;
            let existing_meta: Option<(String, String, String)> = this
                .conn
                .query_row(
                    "SELECT buffer_id, position, lang FROM blocks WHERE id = ?1",
                    [&entity_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "read block meta"))?;
            let (buf_opt, pos_opt, lang_opt) = match existing_meta {
                Some((b, p, l)) => (
                    BufferId::parse(&b).ok().or(fallback_buf),
                    Some(p),
                    Some(l),
                ),
                None => (fallback_buf, fallback_pos, fallback_lang),
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
                    public_hint: preserved_hint,
                    tier: 2,
                    key_id: new_kid,
                    mnb1: t2.mnb1.to_vec(),
                },
            };
            let mns1 = encrypt_mns1(
                smk_kid,
                &smk,
                new_op_id,
                &this.device_id,
                &inner,
                rand_bytes::<24>()?,
            )?;
            this.conn
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
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert rekeyed tier2 key")
                })?;
            this.insert_sync_op(
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
            let mat = this.rematerialize_block(blk_id)?;

            // C3 Path B: if `old_kid` already has an `executed` shred mark (whose physical wipe was
            // previously deferred while this blocked op kept `old_kid` live), execute physical shred now!
            let mut executed_old = false;
            if let Some(okid) = old_kid {
                if this.is_key_executed(&okid) {
                    executed_old = this.execute_shred_in_tx(okid, None)?;
                    if executed_old {
                        let _ = this.rematerialize_block(blk_id);
                    }
                }
            }
            Ok((
                WriteReceipt {
                    block_id: mat.id.to_string(),
                    op_id: new_op_id.to_string(),
                    head_op_ids: mat.head_op_ids().into_iter().map(|o| o.to_string()).collect(),
                    buffer_id: mat.buffer_id.to_string(),
                    idempotent_replay: None,
                },
                executed_old,
            ))
        })?;

        if shred_executed {
            self.full_forensic_shred_scrub()?;
        } else {
            self.refresh_mirror()?;
        }
        Ok(receipt)
    }

    /// Execute physical local key destruction when server confirms `Executed` (`sync-protocol.md` §5.4 #4, `SEC-01`, `INV-SHRED-BOUND`).
    /// Runs fail-closed INV-KEY-LIVENESS guard BEFORE setting `block_keys.key_record = NULL`.
    pub(super) fn execute_shred_in_tx(
        &self,
        key_id: KeyId,
        remote_meta: Option<(u32, i64)>,
    ) -> Result<bool, CoreError> {
        // 1. Live-leaf INV-KEY-LIVENESS safety guard (`sync-protocol.md` §5.4 #4, fail-closed):
        // Never wipe a key that is still actively used by a live leaf of an ACTIVE block or ACTIVE buffer!
        let live_on_active: i64 = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM block_leaves bl
                    JOIN blocks b ON b.id = bl.block_id
                    WHERE b.state = 'ACTIVE' AND bl.key_id = ?1 AND bl.body_state IN ('PLAINTEXT', 'SEALED')
                 ) OR EXISTS(
                    SELECT 1 FROM buffers buf
                    WHERE buf.state = 'ACTIVE' AND buf.key_id = ?1
                 )",
                [key_id.to_string()],
                |r| r.get(0),
            )
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    e.to_string(),
                    "check active key liveness",
                )
            })?;
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
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    e.to_string(),
                    "mark shred_marks executed",
                )
            })?;

        // Clean up any orphaned `blocked_t2_mnw1:*` backups whose blocked op no longer exists
        self.conn
            .execute(
                "DELETE FROM local_meta
                 WHERE key LIKE 'blocked_t2_mnw1:%'
                   AND substr(key, 17) NOT IN (
                       SELECT op_id FROM sync_ops
                       WHERE sync_blocked_reason = 'NEEDS_VAULT_REKEY' AND server_seq IS NULL
                   )",
                [],
            )
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    e.to_string(),
                    "prune stale blocked_t2_mnw1",
                )
            })?;

        // Remove from pending_cancel_key_ids if present
        let mut cancel_set = self.load_pending_cancel_keys();
        if cancel_set.remove(&key_id) {
            self.save_pending_cancel_keys(&cancel_set)?;
        }
        Ok(true)
    }

    /// Sweep any `block_keys.key_record IS NOT NULL` rows whose `shred_marks.state = 'executed'`
    /// so deferred physical key destruction always completes once the key is no longer live (C3).
    pub(super) fn sweep_unexecuted_shreds_in_tx(&self) -> Result<Vec<KeyId>, CoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT DISTINCT bk.key_id
                 FROM block_keys bk
                 JOIN shred_marks sm ON sm.key_id = bk.key_id
                 WHERE bk.key_record IS NOT NULL AND sm.state = 'executed'",
            )
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    e.to_string(),
                    "query unexecuted shreds",
                )
            })?;
        let key_strs: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map unexecuted shreds"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    e.to_string(),
                    "collect unexecuted shreds",
                )
            })?;
        let mut executed = Vec::new();
        for ks in key_strs {
            if let Ok(kid) = KeyId::parse(&ks) {
                if self.execute_shred_in_tx(kid, None)? {
                    executed.push(kid);
                }
            }
        }
        Ok(executed)
    }

    fn wal_checkpoint_truncate(&self) -> Result<(), CoreError> {
        for attempt in 0..3 {
            let (busy, _log, _checkpointed): (i64, i64, i64) = self
                .conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "wal checkpoint"))?;
            if busy == 0 {
                return Ok(());
            }
            if attempt < 2 {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        Err(CoreError::new(
            ErrorCode::IntegrityError,
            "PRAGMA wal_checkpoint(TRUNCATE) remained busy after 3 attempts",
            "Close concurrent DB readers and retry scrub",
        ))
    }

    /// Force FTS5 segment merge + optimize and truncate WAL under `PRAGMA secure_delete = ON`
    /// so zero shredded/locked plaintext bytes linger in SQLite B-trees or `.db-wal` (`SEC-01`, `INV-SHRED-BOUND`).
    pub fn scrub_fts_and_wal(&self) -> Result<(), CoreError> {
        self.conn
            .execute_batch(
                "INSERT INTO blocks_fts(blocks_fts, rank) VALUES('merge', -1);
                 INSERT INTO blocks_fts(blocks_fts) VALUES('optimize');",
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "fts scrub"))?;
        self.wal_checkpoint_truncate()
    }

    /// Full forensic scrub after `ExecuteShred`: FTS5 optimize + `VACUUM` + WAL truncate + mirror refresh.
    pub fn full_forensic_shred_scrub(&self) -> Result<(), CoreError> {
        self.scrub_fts_and_wal()?;
        self.conn
            .execute_batch("VACUUM;")
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "vacuum shred scrub"))?;
        self.wal_checkpoint_truncate()?;
        self.refresh_mirror()?;
        Ok(())
    }

    /// One-time M1 -> M2 trash migration (`docs/sync-protocol.md` §5.9):
    /// creates `T_grace` marks for any pre-existing `TRASHED` blocks and buffers that have zero shred marks.
    /// Does NOT set `m2_trash_migrated = "1"` until caller confirms cloud `POST /v1/keys/shred` succeeded
    /// and calls `mark_m1_trash_migrated()`.
    pub fn collect_m1_trashed_migration_marks(&mut self) -> Result<(bool, Vec<ShredMarkRow>), CoreError> {
        if self.get_local_meta("m2_trash_migrated").as_deref() == Some("1") {
            return Ok((true, Vec::new()));
        }
        if !self.key_self_check()?.0 {
            return Ok((false, Vec::new()));
        }
        let trashed_blocks = self.list_trash()?;
        let trashed_buffers: Vec<String> = {
            let mut stmt = self
                .conn
                .prepare("SELECT id FROM buffers WHERE state = 'TRASHED'")
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "list trashed buffers")
                })?;
            let rows = stmt
                .query_map([], |r| r.get(0))
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map trashed buffers"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        e.to_string(),
                        "collect trashed buffers",
                    )
                })?;
            rows
        };
        let now = now_ms() as i64;
        let mut target_keys = BTreeSet::new();
        for item in &trashed_blocks {
            let kids = self.collect_entity_unshredded_key_ids(EntityType::Block, &item.id)?;
            if item.shred_state == "unscheduled" {
                let _ = self.queue_local_shred_marks(&kids, T_GRACE_DEFAULT_MS, now)?;
            }
            for k in kids {
                target_keys.insert(k);
            }
        }
        for buf_id in &trashed_buffers {
            let kids = self.collect_entity_unshredded_key_ids(EntityType::Buffer, buf_id)?;
            let _ = self.queue_local_shred_marks(&kids, T_GRACE_DEFAULT_MS, now)?;
            for k in kids {
                target_keys.insert(k);
            }
        }
        let unacked: Vec<ShredMarkRow> = self
            .load_shred_marks(false)?
            .into_iter()
            .filter(|m| target_keys.contains(&m.key_id))
            .collect();
        Ok((true, unacked))
    }

    /// Persist `m2_trash_migrated = "1"` only AFTER cloud `POST /v1/keys/shred` succeeds.
    pub fn mark_m1_trash_migrated(&self) -> Result<(), CoreError> {
        self.set_local_meta("m2_trash_migrated", "1")
    }

    /// Pack an encrypted `MNP1` mobile state snapshot at current `last_seq` (`docs/sync-protocol.md` §9.1).
    pub fn build_state_snapshot(&mut self) -> Result<(SnapshotHeaderV1, Vec<u8>), CoreError> {
        let snap = self.export_engine_snapshot()?;
        if !snap.bootstrap_completed || snap.journal_epoch.is_none() || snap.reconciling_epoch.is_some() {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "cannot build mobile state snapshot before sync bootstrap/reconciliation completes",
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
