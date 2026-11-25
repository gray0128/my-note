use crate::crypto::{
    decrypt_mnb1, decrypt_mnr1, decrypt_mns1, peek_envelope_kid, KeyRecordV1, MAGIC_MNR1, MAGIC_MNS1,
};
use crate::error::{CoreError, ErrorCode};
use crate::hlc::{ClockSkewWarning, Hlc, HlcClock};
use crate::ids::{BlockId, BufferId, DeviceId, JournalEpoch, KeyId, OpId, SmkKid};
use crate::keys::KeyTableState;
use crate::materialize::{materialize_block, materialize_buffer, DecodedOp};
use crate::model::{
    EntityType, KeyMaterialKind, KeyRecordRow, LeafBody, MaterializedBlock, MaterializedBuffer, OpType,
    ShredMarkRow, ShredMarkState,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub const MAX_PUSH_BATCH_OPS: usize = 500;
/// Conservative estimated JSON wire size cap per push batch (< 4 MiB Cloudflare relay limit).
pub const MAX_PUSH_BATCH_JSON_BYTES: usize = 3_600_000;
pub const DEFAULT_PULL_LIMIT: u16 = 500;

/// Stored local op record (in `sync_ops` table).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalOpRecord {
    pub op_id: OpId,
    pub server_seq: Option<i64>,
    pub sync_blocked_reason: Option<String>,
    pub device_id: DeviceId,
    pub entity_type: EntityType,
    pub entity_id: String,
    pub parent_op_ids: Vec<OpId>,
    pub op_type: OpType,
    pub hlc: Hlc,
    pub actor: String,
    pub key_id: Option<KeyId>,
    pub smk_kid: SmkKid,
    pub envelope: Vec<u8>,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteEnvelopeRow {
    pub seq: i64,
    pub op_id: OpId,
    pub key_id: Option<KeyId>,
    pub device_id: DeviceId,
    pub created_at: i64,
    pub envelope: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckedOp {
    pub op_id: OpId,
    pub seq: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushOpDto {
    pub op_id: OpId,
    /// Immutable originating author device_id bound into MNS1 AAD (`data-structures.md` §3.3).
    /// Must be preserved when a peer device rescues another device's op during PITR Set-Union reconciliation.
    pub device_id: DeviceId,
    pub key_id: Option<KeyId>,
    pub envelope: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequestDto {
    pub expected_epoch: JournalEpoch,
    pub seen_seq: i64,
    pub key_records: Vec<KeyRecordRow>,
    pub ops: Vec<PushOpDto>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyTableSyncDto {
    pub push_records: Vec<KeyRecordRow>,
    pub keyring_material: Option<(u32, Vec<u8>)>,
    pub vault_header_material: Option<(i64, Vec<u8>)>,
}

/// Complete Sans-I/O input state to `step()` (`docs/sync-protocol.md` §1.2).
#[derive(Clone)]
pub struct EngineSnapshot {
    pub device_id: DeviceId,
    pub bootstrap_completed: bool,
    pub journal_epoch: Option<JournalEpoch>,
    pub last_seq: i64,
    pub reconciling_epoch: Option<JournalEpoch>,
    pub hlc: Hlc,
    /// All known ops (local + remote), never truncated.
    pub ops: BTreeMap<OpId, LocalOpRecord>,
    pub keys: KeyTableState,
    /// All SMK generations held in device keychain (old generations permanently retained).
    pub smks: BTreeMap<SmkKid, Zeroizing<[u8; 32]>>,
}

impl EngineSnapshot {
    pub fn new(device_id: DeviceId, initial_now_ms: u64) -> Self {
        Self {
            hlc: Hlc::new(initial_now_ms, 0, device_id.clone()),
            device_id,
            bootstrap_completed: false,
            journal_epoch: None,
            last_seq: 0,
            reconciling_epoch: None,
            ops: BTreeMap::new(),
            keys: KeyTableState::default(),
            smks: BTreeMap::new(),
        }
    }

    /// Bootstrap Gate check (`docs/sync-protocol.md` §3 #1, `INV-SYNC-3`):
    /// Before `bootstrap_completed == true`, mutations against remote-existing entities are forbidden.
    pub fn check_bootstrap_gate(&self, entity_id: &str, op_type: OpType) -> Result<(), CoreError> {
        if self.bootstrap_completed || op_type == OpType::Create {
            return Ok(());
        }
        // Only permit editing an entity that was created locally on THIS device while unbootstrapped
        let created_only_locally = self.ops.values().any(|o| {
            o.entity_id == entity_id && o.op_type == OpType::Create && o.device_id == self.device_id
        }) && self
            .ops
            .values()
            .filter(|o| o.entity_id == entity_id)
            .all(|o| o.server_seq.is_none() && o.device_id == self.device_id);
        if created_only_locally {
            return Ok(());
        }
        Err(CoreError::new(
            ErrorCode::InvalidArgument,
            format!(
                "Bootstrap Gate blocked {:?} on remote entity '{entity_id}' before initial sync",
                op_type
            ),
            "Complete initial sync bootstrap before modifying existing remote entities",
        ))
    }

    /// Unwrap a Tier 1 BDEK from `block_keys` using permanently retained SMK generations.
    pub fn unwrap_key_record(&self, key_id: KeyId) -> Option<KeyRecordV1> {
        if self.keys.is_shredded(&key_id) {
            return None;
        }
        let row = self.keys.records.get(&key_id)?;
        let mnr1 = row.key_record.as_ref()?;
        let smk_kid_bytes = peek_envelope_kid(MAGIC_MNR1, mnr1).ok()?;
        let smk_kid = SmkKid::from_bytes(smk_kid_bytes);
        let smk = self.smks.get(&smk_kid)?;
        decrypt_mnr1(smk_kid, smk, key_id, row.wrap_gen, mnr1).ok()
    }

    /// Project a single block deterministically from all known ops and current key table.
    pub fn materialize_block_view(&self, block_id: BlockId) -> Option<MaterializedBlock> {
        let target = block_id.to_string();
        let mut decoded = Vec::new();
        let mut referenced_keys: BTreeSet<KeyId> = BTreeSet::new();

        for rec in self.ops.values() {
            if rec.entity_type != EntityType::Block || rec.entity_id != target {
                continue;
            }
            if let Some(kid) = rec.key_id {
                referenced_keys.insert(kid);
            }
            let Some(smk) = self.smks.get(&rec.smk_kid) else {
                continue;
            };
            if let Ok(inner) = decrypt_mns1(
                rec.smk_kid,
                smk,
                rec.op_id,
                &rec.device_id,
                rec.key_id,
                &rec.envelope,
            ) {
                decoded.push(DecodedOp {
                    op_id: rec.op_id,
                    device_id: rec.device_id.clone(),
                    created_at_ms: rec.created_at_ms,
                    inner,
                });
            }
        }

        let has_unshredded_key = referenced_keys.iter().any(|k| !self.keys.is_shredded(k));

        materialize_block(
            block_id,
            &decoded,
            has_unshredded_key,
            |op_id, kid, tier, mnb1| {
                if self.keys.is_shredded(&kid) {
                    return LeafBody::KeyUnavailable {
                        key_id: kid,
                        shredded: true,
                    };
                }
                if tier == 2 {
                    return LeafBody::Sealed {
                        key_id: kid,
                        mnb1: mnb1.to_vec(),
                    };
                }
                match self.unwrap_key_record(kid) {
                    Some(krec) if krec.tier == 1 && krec.bdek.len() == 32 => {
                        let mut bdek = Zeroizing::new([0u8; 32]);
                        bdek.copy_from_slice(&krec.bdek);
                        match decrypt_mnb1(block_id.as_bytes(), op_id, kid, &bdek, mnb1) {
                            Ok(pt) => LeafBody::Plaintext(pt),
                            Err(e) => LeafBody::DecryptFailed {
                                error_code: e.code().as_str().to_string(),
                            },
                        }
                    }
                    Some(_) => LeafBody::DecryptFailed {
                        error_code: ErrorCode::IntegrityError.as_str().to_string(),
                    },
                    None => LeafBody::KeyUnavailable {
                        key_id: kid,
                        shredded: false,
                    },
                }
            },
        )
    }

    /// Project a single buffer deterministically from all known ops and current key table.
    pub fn materialize_buffer_view(&self, buffer_id: BufferId) -> Option<MaterializedBuffer> {
        let target = buffer_id.to_string();
        let mut decoded = Vec::new();
        let mut referenced_keys: BTreeSet<KeyId> = BTreeSet::new();

        for rec in self.ops.values() {
            if rec.entity_type != EntityType::Buffer || rec.entity_id != target {
                continue;
            }
            if let Some(kid) = rec.key_id {
                referenced_keys.insert(kid);
            }
            let Some(smk) = self.smks.get(&rec.smk_kid) else {
                continue;
            };
            if let Ok(inner) = decrypt_mns1(
                rec.smk_kid,
                smk,
                rec.op_id,
                &rec.device_id,
                rec.key_id,
                &rec.envelope,
            ) {
                decoded.push(DecodedOp {
                    op_id: rec.op_id,
                    device_id: rec.device_id.clone(),
                    created_at_ms: rec.created_at_ms,
                    inner,
                });
            }
        }

        let has_unshredded_key = referenced_keys.iter().any(|k| !self.keys.is_shredded(k));

        materialize_buffer(buffer_id, &decoded, has_unshredded_key, |op_id, kid, mnb1| {
            let krec = self.unwrap_key_record(kid)?;
            if krec.bdek.len() != 32 {
                return None;
            }
            let mut bdek = Zeroizing::new([0u8; 32]);
            bdek.copy_from_slice(&krec.bdek);
            decrypt_mnb1(buffer_id.as_bytes(), op_id, kid, &bdek, mnb1).ok()
        })
    }

    /// Collect all materialized blocks in deterministic `(position, id)` order.
    pub fn all_blocks(&self) -> Vec<MaterializedBlock> {
        let mut ids: BTreeSet<BlockId> = BTreeSet::new();
        for rec in self.ops.values() {
            if rec.entity_type == EntityType::Block {
                if let Ok(id) = BlockId::parse(&rec.entity_id) {
                    ids.insert(id);
                }
            }
        }
        let mut blocks: Vec<MaterializedBlock> = ids
            .into_iter()
            .filter_map(|id| self.materialize_block_view(id))
            .collect();
        blocks.sort_by(|a, b| {
            crate::fractional_index::compare_order(
                &a.position,
                &a.id.to_string(),
                &b.position,
                &b.id.to_string(),
            )
        });
        blocks
    }

    /// Collect all materialized buffers in deterministic `(position, id)` order.
    pub fn all_buffers(&self) -> Vec<MaterializedBuffer> {
        let mut ids: BTreeSet<BufferId> = BTreeSet::new();
        for rec in self.ops.values() {
            if rec.entity_type == EntityType::Buffer {
                if let Ok(id) = BufferId::parse(&rec.entity_id) {
                    ids.insert(id);
                }
            }
        }
        let mut bufs: Vec<MaterializedBuffer> = ids
            .into_iter()
            .filter_map(|id| self.materialize_buffer_view(id))
            .collect();
        bufs.sort_by(|a, b| {
            crate::fractional_index::compare_order(
                &a.position,
                &a.id.to_string(),
                &b.position,
                &b.id.to_string(),
            )
        });
        bufs
    }

    /// Build next push batch if bootstrapped and not mid-reconciliation.
    pub fn build_pending_push(&self) -> Option<PushRequestDto> {
        if !self.bootstrap_completed || self.reconciling_epoch.is_some() {
            return None;
        }
        let epoch = self.journal_epoch?;
        let mut pending: Vec<&LocalOpRecord> = self
            .ops
            .values()
            .filter(|o| {
                o.server_seq.is_none()
                    && o.sync_blocked_reason.is_none()
                    && o.key_id.is_none_or(|k| !self.keys.is_shredded(&k))
            })
            .collect();
        if pending.is_empty() {
            return None;
        }
        pending.sort_by_key(|a| (a.created_at_ms, a.op_id));

        let mut needed_keys = BTreeSet::new();
        let mut ops = Vec::with_capacity(pending.len().min(MAX_PUSH_BATCH_OPS));
        let mut est_json_bytes: usize = 256;

        for o in pending {
            if ops.len() >= MAX_PUSH_BATCH_OPS {
                break;
            }
            let op_bytes = 160 + (o.envelope.len().saturating_mul(4)).div_ceil(3);
            let key_bytes = match o.key_id {
                Some(kid) if !needed_keys.contains(&kid) => self
                    .keys
                    .records
                    .get(&kid)
                    .and_then(|r| r.key_record.as_ref())
                    .map_or(0, |kr| 160 + (kr.len().saturating_mul(4)).div_ceil(3)),
                _ => 0,
            };
            let added = op_bytes.saturating_add(key_bytes);
            if !ops.is_empty() && est_json_bytes.saturating_add(added) > MAX_PUSH_BATCH_JSON_BYTES {
                break;
            }
            est_json_bytes = est_json_bytes.saturating_add(added);
            if let Some(kid) = o.key_id {
                needed_keys.insert(kid);
            }
            ops.push(PushOpDto {
                op_id: o.op_id,
                device_id: o.device_id.clone(),
                key_id: o.key_id,
                envelope: o.envelope.clone(),
            });
        }

        let key_records: Vec<KeyRecordRow> = needed_keys
            .into_iter()
            .filter_map(|k| self.keys.records.get(&k).cloned())
            .filter(|r| r.key_record.is_some())
            .collect();

        Some(PushRequestDto {
            expected_epoch: epoch,
            seen_seq: self.last_seq,
            key_records,
            ops,
        })
    }

    /// Apply a list of `StoreMutation`s directly to an in-memory snapshot (used by DST & tests).
    pub fn apply_mutations(&mut self, mutations: &[StoreMutation]) {
        for m in mutations {
            match m {
                StoreMutation::AppendOp(rec) => {
                    self.ops
                        .entry(rec.op_id)
                        .and_modify(|cur| {
                            if cur.server_seq.is_none() && rec.server_seq.is_some() {
                                cur.server_seq = rec.server_seq;
                            }
                        })
                        .or_insert_with(|| rec.clone());
                }
                StoreMutation::MarkOpsSynced { epoch, acked } => {
                    self.journal_epoch = Some(*epoch);
                    for a in acked {
                        if let Some(op) = self.ops.get_mut(&a.op_id) {
                            op.server_seq = Some(a.seq);
                        }
                    }
                }
                StoreMutation::ClearServerSeqsForReconcile { new_epoch } => {
                    // ANTI-WIPE INVARIANT: NEVER delete local ops; only clear old epoch's server_seq!
                    for op in self.ops.values_mut() {
                        op.server_seq = None;
                    }
                    self.reconciling_epoch = Some(*new_epoch);
                    self.last_seq = 0;
                }
                StoreMutation::UpsertBlockKey(row) => {
                    self.keys.insert_record(row.clone());
                }
                StoreMutation::UpsertShredMark(mark) => {
                    self.keys.insert_mark(mark.clone());
                }
                StoreMutation::UpsertKeyMaterial { kind, gen, blob, .. } => match kind {
                    KeyMaterialKind::Keyring => self.keys.update_keyring_material(*gen as u32, blob.clone()),
                    KeyMaterialKind::VaultHeader => {
                        self.keys.update_vault_header_material(*gen, blob.clone())
                    }
                },
                StoreMutation::ExecuteShred { key_id } => {
                    self.keys.executed_tombstones.insert(*key_id);
                    if let Some(r) = self.keys.records.get_mut(key_id) {
                        r.key_record = None;
                    }
                }
                StoreMutation::SetSyncMeta {
                    bootstrap_completed,
                    journal_epoch,
                    last_seq,
                    reconciling_epoch,
                    hlc,
                } => {
                    self.bootstrap_completed = *bootstrap_completed;
                    self.journal_epoch = *journal_epoch;
                    self.last_seq = *last_seq;
                    self.reconciling_epoch = *reconciling_epoch;
                    self.hlc = hlc.clone();
                }
                StoreMutation::IntegrityAlert { .. } | StoreMutation::ClockSkewAlert(_) => {}
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum SyncEvent {
    StartSync,
    WsWake {
        epoch: JournalEpoch,
        head_seq: i64,
    },
    PullResponse {
        now_ms: u64,
        epoch: JournalEpoch,
        ops: Vec<RemoteEnvelopeRow>,
        keys_digest: String,
        head_seq: i64,
        has_more: bool,
    },
    PushAcked {
        epoch: JournalEpoch,
        acked: Vec<AckedOp>,
        head_seq: i64,
    },
    PushEpochMismatch {
        remote_epoch: JournalEpoch,
    },
    KeyTableResponse {
        records: Vec<KeyRecordRow>,
        marks: Vec<ShredMarkRow>,
        keyring: Option<(u32, Vec<u8>)>,
        vault_header: Option<(i64, Vec<u8>)>,
        server_now_ms: i64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreMutation {
    AppendOp(LocalOpRecord),
    MarkOpsSynced {
        epoch: JournalEpoch,
        acked: Vec<AckedOp>,
    },
    ClearServerSeqsForReconcile {
        new_epoch: JournalEpoch,
    },
    UpsertBlockKey(KeyRecordRow),
    UpsertShredMark(ShredMarkRow),
    UpsertKeyMaterial {
        kind: KeyMaterialKind,
        gen: i64,
        blob: Vec<u8>,
        updated_at_ms: i64,
    },
    ExecuteShred {
        key_id: KeyId,
    },
    SetSyncMeta {
        bootstrap_completed: bool,
        journal_epoch: Option<JournalEpoch>,
        last_seq: i64,
        reconciling_epoch: Option<JournalEpoch>,
        hlc: Hlc,
    },
    IntegrityAlert {
        op_id: OpId,
        reason: String,
    },
    ClockSkewAlert(ClockSkewWarning),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncCommand {
    HttpPush(PushRequestDto),
    HttpPull { since_seq: i64, limit: u16 },
    SyncKeyTable(KeyTableSyncDto),
}

/// Pure Sans-I/O sync protocol transition (`docs/sync-protocol.md` §1.2, §2.4, §6).
pub fn step(
    state: &EngineSnapshot,
    event: SyncEvent,
) -> Result<(Vec<StoreMutation>, Vec<SyncCommand>), CoreError> {
    let mut mutations = Vec::new();
    let mut commands = Vec::new();

    match event {
        SyncEvent::StartSync => {
            if !state.bootstrap_completed {
                commands.push(SyncCommand::SyncKeyTable(build_key_sync_dto(state)));
                commands.push(SyncCommand::HttpPull {
                    since_seq: 0,
                    limit: DEFAULT_PULL_LIMIT,
                });
            } else {
                commands.push(SyncCommand::HttpPull {
                    since_seq: state.last_seq,
                    limit: DEFAULT_PULL_LIMIT,
                });
                if let Some(push) = state.build_pending_push() {
                    commands.push(SyncCommand::HttpPush(push));
                }
            }
        }

        SyncEvent::WsWake { epoch, head_seq } => {
            let epoch_changed = state.journal_epoch.is_some_and(|e| e != epoch);
            if epoch_changed || head_seq < state.last_seq {
                mutations.push(StoreMutation::ClearServerSeqsForReconcile { new_epoch: epoch });
                commands.push(SyncCommand::SyncKeyTable(build_key_sync_dto(state)));
                commands.push(SyncCommand::HttpPull {
                    since_seq: 0,
                    limit: DEFAULT_PULL_LIMIT,
                });
            } else if head_seq > state.last_seq {
                commands.push(SyncCommand::HttpPull {
                    since_seq: state.last_seq,
                    limit: DEFAULT_PULL_LIMIT,
                });
            }
        }

        SyncEvent::PushEpochMismatch { remote_epoch } => {
            mutations.push(StoreMutation::ClearServerSeqsForReconcile {
                new_epoch: remote_epoch,
            });
            commands.push(SyncCommand::SyncKeyTable(build_key_sync_dto(state)));
            commands.push(SyncCommand::HttpPull {
                since_seq: 0,
                limit: DEFAULT_PULL_LIMIT,
            });
        }

        SyncEvent::PullResponse {
            now_ms,
            epoch,
            ops,
            keys_digest,
            head_seq,
            has_more,
        } => {
            // Detect epoch change or DO PITR seq rollback -> Set-Union reconciliation (NEVER wipe!)
            let active_epoch = state.reconciling_epoch.or(state.journal_epoch);
            let is_epoch_mismatch = active_epoch.is_some_and(|e| e != epoch);
            let is_seq_rollback = state.reconciling_epoch.is_none() && head_seq < state.last_seq;
            if is_epoch_mismatch || is_seq_rollback {
                mutations.push(StoreMutation::ClearServerSeqsForReconcile { new_epoch: epoch });
                commands.push(SyncCommand::SyncKeyTable(build_key_sync_dto(state)));
                commands.push(SyncCommand::HttpPull {
                    since_seq: 0,
                    limit: DEFAULT_PULL_LIMIT,
                });
                return Ok((mutations, commands));
            }

            let mut clock = HlcClock::from_last(state.hlc.clone());
            let mut max_seen_seq = state.last_seq;

            for row in ops {
                max_seen_seq = max_seen_seq.max(row.seq);
                let smk_kid_bytes = match peek_envelope_kid(MAGIC_MNS1, &row.envelope) {
                    Ok(k) => k,
                    Err(e) => {
                        mutations.push(StoreMutation::IntegrityAlert {
                            op_id: row.op_id,
                            reason: e.message().to_string(),
                        });
                        continue;
                    }
                };
                let smk_kid = SmkKid::from_bytes(smk_kid_bytes);
                let Some(smk) = state.smks.get(&smk_kid) else {
                    mutations.push(StoreMutation::IntegrityAlert {
                        op_id: row.op_id,
                        reason: format!("missing SMK generation {smk_kid}"),
                    });
                    continue;
                };
                match decrypt_mns1(smk_kid, smk, row.op_id, &row.device_id, row.key_id, &row.envelope) {
                    Ok(inner) => {
                        let (_, skew_warn) = clock.receive(now_ms, &inner.hlc);
                        if let Some(w) = skew_warn {
                            mutations.push(StoreMutation::ClockSkewAlert(w));
                        }
                        mutations.push(StoreMutation::AppendOp(LocalOpRecord {
                            op_id: row.op_id,
                            server_seq: Some(row.seq),
                            sync_blocked_reason: None,
                            device_id: row.device_id,
                            entity_type: inner.entity_type,
                            entity_id: inner.entity_id,
                            parent_op_ids: inner.parent_op_ids,
                            op_type: inner.op_type,
                            hlc: inner.hlc,
                            actor: inner.actor,
                            key_id: row.key_id,
                            smk_kid,
                            envelope: row.envelope,
                            created_at_ms: row.created_at,
                        }));
                    }
                    Err(e) => {
                        // INV-SYNC-5: Tampered envelope explicitly rejected; ZERO empty overwrite!
                        mutations.push(StoreMutation::IntegrityAlert {
                            op_id: row.op_id,
                            reason: e.message().to_string(),
                        });
                    }
                }
            }

            let next_reconciling = if has_more {
                state
                    .reconciling_epoch
                    .or_else(|| (!state.bootstrap_completed).then_some(epoch))
            } else {
                None
            };
            let keys_match = keys_digest == state.keys.digest();
            let next_bootstrapped = state.bootstrap_completed || (!has_more && keys_match);

            mutations.push(StoreMutation::SetSyncMeta {
                bootstrap_completed: next_bootstrapped,
                journal_epoch: Some(epoch),
                last_seq: max_seen_seq,
                reconciling_epoch: next_reconciling,
                hlc: clock.current(),
            });

            if has_more {
                commands.push(SyncCommand::HttpPull {
                    since_seq: max_seen_seq,
                    limit: DEFAULT_PULL_LIMIT,
                });
            } else {
                if !keys_match {
                    commands.push(SyncCommand::SyncKeyTable(build_key_sync_dto(state)));
                }
                // Apply our own mutations on a scratch clone to compute exact pending ops to push
                let mut next_state = state.clone();
                next_state.apply_mutations(&mutations);
                if let Some(push) = next_state.build_pending_push() {
                    commands.push(SyncCommand::HttpPush(push));
                }
            }
        }

        SyncEvent::PushAcked {
            epoch,
            acked,
            head_seq,
        } => {
            if state.journal_epoch.is_some_and(|e| e != epoch) {
                mutations.push(StoreMutation::ClearServerSeqsForReconcile { new_epoch: epoch });
                commands.push(SyncCommand::SyncKeyTable(build_key_sync_dto(state)));
                commands.push(SyncCommand::HttpPull {
                    since_seq: 0,
                    limit: DEFAULT_PULL_LIMIT,
                });
                return Ok((mutations, commands));
            }
            mutations.push(StoreMutation::MarkOpsSynced { epoch, acked });
            let mut next_state = state.clone();
            next_state.apply_mutations(&mutations);
            if head_seq > next_state.last_seq {
                commands.push(SyncCommand::HttpPull {
                    since_seq: next_state.last_seq,
                    limit: DEFAULT_PULL_LIMIT,
                });
            }
            if let Some(push) = next_state.build_pending_push() {
                commands.push(SyncCommand::HttpPush(push));
            }
        }

        SyncEvent::KeyTableResponse {
            records,
            marks,
            keyring,
            vault_header,
            server_now_ms,
        } => {
            for rec in records {
                if rec.key_record.is_none() && !state.keys.is_shredded(&rec.key_id) {
                    mutations.push(StoreMutation::ExecuteShred { key_id: rec.key_id });
                }
                mutations.push(StoreMutation::UpsertBlockKey(rec));
            }
            for mark in marks {
                if mark.state == ShredMarkState::Executed && !state.keys.is_shredded(&mark.key_id) {
                    mutations.push(StoreMutation::ExecuteShred { key_id: mark.key_id });
                }
                mutations.push(StoreMutation::UpsertShredMark(mark));
            }
            if let Some((gen, blob)) = keyring {
                if state.keys.keyring_material.as_ref().is_none_or(|(g, _)| gen > *g) {
                    mutations.push(StoreMutation::UpsertKeyMaterial {
                        kind: KeyMaterialKind::Keyring,
                        gen: gen as i64,
                        blob,
                        updated_at_ms: server_now_ms,
                    });
                }
            }
            if let Some((gen, blob)) = vault_header {
                if state
                    .keys
                    .vault_header_material
                    .as_ref()
                    .is_none_or(|(g, _)| gen > *g)
                {
                    mutations.push(StoreMutation::UpsertKeyMaterial {
                        kind: KeyMaterialKind::VaultHeader,
                        gen,
                        blob,
                        updated_at_ms: server_now_ms,
                    });
                }
            }
            if !state.bootstrap_completed
                && state.journal_epoch.is_some()
                && state.reconciling_epoch.is_none()
            {
                mutations.push(StoreMutation::SetSyncMeta {
                    bootstrap_completed: true,
                    journal_epoch: state.journal_epoch,
                    last_seq: state.last_seq,
                    reconciling_epoch: None,
                    hlc: state.hlc.clone(),
                });
                let mut next_state = state.clone();
                next_state.apply_mutations(&mutations);
                if let Some(push) = next_state.build_pending_push() {
                    commands.push(SyncCommand::HttpPush(push));
                }
            }
        }
    }

    Ok((mutations, commands))
}

fn build_key_sync_dto(state: &EngineSnapshot) -> KeyTableSyncDto {
    let push_records: Vec<KeyRecordRow> = state
        .keys
        .records
        .values()
        .filter(|r| r.key_record.is_some() && !state.keys.is_shredded(&r.key_id))
        .cloned()
        .collect();
    KeyTableSyncDto {
        push_records,
        keyring_material: state.keys.keyring_material.clone(),
        vault_header_material: state.keys.vault_header_material.clone(),
    }
}
