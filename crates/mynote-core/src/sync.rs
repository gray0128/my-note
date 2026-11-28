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
pub struct ShredResultDto {
    pub key_id: KeyId,
    pub state: ShredMarkState,
    pub not_before_ms: Option<i64>,
}

/// Classification of an unpushed local op against current key table & remote entity state
/// (`docs/sync-protocol.md` §5.7 Update-Wins vs rekey vs shredded).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxKeyAction {
    /// Key is live and unshredded; push op normally.
    PushNormal,
    /// Key has an active shred mark from a `DELETE` (block is Trashed on remote) or explicit restore:
    /// atomically include `key_id` in `cancel_key_ids` in the same push batch (Update-Wins revival).
    CancelAndPush,
    /// Key is pending shred on an Active block (rekey intent such as `LOCK`/`purge_history`)
    /// OR already `Executed`: op must be rekeyed (Tier 1 auto-rekey; Tier 2 `NEEDS_VAULT_REKEY`).
    NeedsRekey { key_shredded: bool },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxLeafPlan {
    pub op_id: OpId,
    pub self_needs_rekey: bool,
    pub frontier_parents: Vec<OpId>,
    pub merged_parents: Vec<OpId>,
    pub collapsed_ancestors: BTreeSet<OpId>,
    pub collapsed_create: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutboxReconcilePlan {
    pub leaves: Vec<OutboxLeafPlan>,
    pub stranded_superseded_ops: BTreeSet<OpId>,
    pub protected_ancestors: BTreeSet<OpId>,
    pub blocked_rekey_ancestors: BTreeSet<OpId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequestDto {
    pub expected_epoch: JournalEpoch,
    pub seen_seq: i64,
    pub key_records: Vec<KeyRecordRow>,
    #[serde(default)]
    pub cancel_key_ids: Vec<KeyId>,
    pub ops: Vec<PushOpDto>,
    #[serde(default)]
    pub shred_marks: Vec<ShredMarkRow>,
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
    /// Locally created shred marks not yet acknowledged by the server (`server_acked = 0`).
    pub pending_shred_marks: Vec<ShredMarkRow>,
    /// Key IDs whose pending/scheduled shred marks must be cancelled on the server.
    pub pending_cancel_key_ids: BTreeSet<KeyId>,
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
            pending_shred_marks: Vec::new(),
            pending_cancel_key_ids: BTreeSet::new(),
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
                    if !self.keys.is_key_available(&kid) {
                        return LeafBody::KeyUnavailable {
                            key_id: kid,
                            shredded: false,
                        };
                    }
                    return match self.unwrap_key_record(kid) {
                        Some(krec) if krec.tier == 2 => LeafBody::Sealed {
                            key_id: kid,
                            mnb1: mnb1.to_vec(),
                        },
                        Some(_) => LeafBody::DecryptFailed {
                            error_code: ErrorCode::IntegrityError.as_str().to_string(),
                        },
                        None => LeafBody::KeyUnavailable {
                            key_id: kid,
                            shredded: false,
                        },
                    };
                }
                if tier != 1 {
                    return LeafBody::DecryptFailed {
                        error_code: ErrorCode::IntegrityError.as_str().to_string(),
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

    /// Collect all distinct unshredded `KeyId`s referenced by ops of `(entity_type, entity_id)`.
    pub fn collect_entity_unshredded_keys(&self, entity_type: EntityType, entity_id: &str) -> Vec<KeyId> {
        let mut keys = BTreeSet::new();
        for rec in self.ops.values() {
            if rec.entity_type == entity_type && rec.entity_id == entity_id {
                if let Some(kid) = rec.key_id {
                    if !self.keys.is_shredded(&kid) {
                        keys.insert(kid);
                    }
                }
            }
        }
        keys.into_iter().collect()
    }

    /// Returns true if the remote-confirmed (`server_seq.is_some()`) projection of `(entity_type, entity_id)`
    /// is `Trashed` AND `kid` was directly superseded by a remote `DELETE` leaf (not replaced earlier by
    /// `LOCK` / `purge_history` prior to deletion, per `docs/sync-protocol.md` §5.7).
    pub fn is_remote_key_trashed_by_delete(
        &self,
        entity_type: EntityType,
        entity_id: &str,
        kid: KeyId,
    ) -> bool {
        let mut decoded = Vec::new();
        let mut referenced_keys = BTreeSet::new();
        let mut op_keys: BTreeMap<OpId, Option<KeyId>> = BTreeMap::new();
        for rec in self.ops.values() {
            if rec.entity_type != entity_type || rec.entity_id != entity_id {
                continue;
            }
            // Index key_id across all known ops (including unacked/reconciling parents) so a remote
            // DELETE whose parent CREATE is awaiting PITR re-ack still resolves `parent -> kid`.
            op_keys.insert(rec.op_id, rec.key_id);
            if rec.server_seq.is_none() {
                continue;
            }
            if let Some(k) = rec.key_id {
                referenced_keys.insert(k);
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
        if decoded.is_empty() {
            return false;
        }
        let has_unshredded = referenced_keys.iter().any(|k| !self.keys.is_shredded(k));
        let is_trashed = match entity_type {
            EntityType::Block => {
                let Ok(bid) = BlockId::parse(entity_id) else {
                    return false;
                };
                materialize_block(bid, &decoded, has_unshredded, |_, k, tier, mnb1| {
                    if self.keys.is_shredded(&k) {
                        LeafBody::KeyUnavailable {
                            key_id: k,
                            shredded: true,
                        }
                    } else if tier == 2 {
                        LeafBody::Sealed {
                            key_id: k,
                            mnb1: mnb1.to_vec(),
                        }
                    } else {
                        LeafBody::Plaintext(String::new())
                    }
                })
                .is_some_and(|m| m.state == crate::model::BlockState::Trashed)
            }
            EntityType::Buffer => {
                let Ok(bid) = BufferId::parse(entity_id) else {
                    return false;
                };
                materialize_buffer(bid, &decoded, has_unshredded, |_, k, _| {
                    (!self.keys.is_shredded(&k)).then(String::new)
                })
                .is_some_and(|m| m.state == crate::model::BlockState::Trashed)
            }
        };
        if !is_trashed {
            return false;
        }
        // Only treat `kid` as delete-intent if it was live on a direct parent of a remote DELETE op.
        let mut referenced_parents: BTreeSet<OpId> = BTreeSet::new();
        for op in &decoded {
            if op.inner.op_type.is_dag_op() {
                for p in &op.inner.parent_op_ids {
                    referenced_parents.insert(*p);
                }
            }
        }
        let mut saw_tombstone_with_parents = false;
        for op in &decoded {
            if !referenced_parents.contains(&op.op_id)
                && matches!(op.inner.body, crate::model::OpBodyV1::Tombstone { .. })
            {
                if !op.inner.parent_op_ids.is_empty() {
                    saw_tombstone_with_parents = true;
                }
                for parent_id in &op.inner.parent_op_ids {
                    if op_keys.get(parent_id).copied().flatten() == Some(kid) {
                        return true;
                    }
                }
            }
        }
        !saw_tombstone_with_parents
    }

    /// Returns true if the remote-confirmed (`server_seq.is_some()`) projection of `(entity_type, entity_id)`
    /// is `Trashed`.
    pub fn is_remote_entity_trashed(&self, entity_type: EntityType, entity_id: &str) -> bool {
        self.ops
            .values()
            .find(|r| r.server_seq.is_some() && r.entity_type == entity_type && r.entity_id == entity_id)
            .and_then(|r| r.key_id)
            .is_some_and(|k| self.is_remote_key_trashed_by_delete(entity_type, entity_id, k))
    }

    /// Classify an unpushed local op against current key table & remote entity state (`§5.7`).
    pub fn classify_unpushed_op(&self, op: &LocalOpRecord) -> OutboxKeyAction {
        let Some(kid) = op.key_id else {
            return OutboxKeyAction::PushNormal;
        };
        if self.keys.is_shredded(&kid) {
            return OutboxKeyAction::NeedsRekey { key_shredded: true };
        }
        if self.keys.has_pending_or_scheduled_mark(&kid) {
            if self.pending_cancel_key_ids.contains(&kid)
                || self.is_remote_key_trashed_by_delete(op.entity_type, &op.entity_id, kid)
            {
                return OutboxKeyAction::CancelAndPush;
            }
            return OutboxKeyAction::NeedsRekey { key_shredded: false };
        }
        OutboxKeyAction::PushNormal
    }

    /// Compute a deterministic causal-closure plan for reconciling unpushed ops against retiring/shredded keys.
    ///
    /// Every rekeyed or rebased leaf receives a fresh `op_id` from its caller and sets `parent_op_ids` to
    /// `merged_parents` (`frontier_parents ∪ collapsed_ancestors ∪ {old_op_id}`), ensuring:
    /// 1. No `op_id` ever maps to two different `MNS1` envelopes across peers or pre/post-PITR epochs;
    /// 2. Peers that never saw `collapsed_ancestors` still supersede `frontier_parents`;
    /// 3. Peers or R2 `MNA1` archives that DID see `collapsed_ancestors` or `old_op_id` still supersede them.
    pub fn plan_outbox_reconciliation(&self) -> OutboxReconcilePlan {
        let unpushed: Vec<&LocalOpRecord> = self
            .ops
            .values()
            .filter(|o| o.server_seq.is_none() && o.sync_blocked_reason.is_none())
            .collect();
        if unpushed.is_empty() {
            return OutboxReconcilePlan::default();
        }
        let mut unpushed_by_id: BTreeMap<OpId, &LocalOpRecord> = BTreeMap::new();
        let mut needs_rekey_ids: BTreeSet<OpId> = BTreeSet::new();
        for o in &unpushed {
            unpushed_by_id.insert(o.op_id, o);
            if matches!(self.classify_unpushed_op(o), OutboxKeyAction::NeedsRekey { .. }) {
                needs_rekey_ids.insert(o.op_id);
            }
        }
        if needs_rekey_ids.is_empty() {
            return OutboxReconcilePlan::default();
        }

        let mut children_in_unpushed: BTreeMap<OpId, Vec<OpId>> = BTreeMap::new();
        for o in &unpushed {
            for &p in &o.parent_op_ids {
                if unpushed_by_id.contains_key(&p) {
                    children_in_unpushed.entry(p).or_default().push(o.op_id);
                }
            }
        }
        let mut tainted_unpushed: BTreeSet<OpId> = needs_rekey_ids.clone();
        let mut t_stack: Vec<OpId> = needs_rekey_ids.iter().copied().collect();
        while let Some(cur) = t_stack.pop() {
            if let Some(kids) = children_in_unpushed.get(&cur) {
                for &kid_op in kids {
                    if tainted_unpushed.insert(kid_op) {
                        t_stack.push(kid_op);
                    }
                }
            }
        }

        let mut referenced_parents: BTreeSet<(EntityType, &str, OpId)> = BTreeSet::new();
        let mut entities_with_surviving_create: BTreeSet<(EntityType, &str)> = BTreeSet::new();
        for cand in self.ops.values() {
            if cand.op_type.is_dag_op() {
                for &p in &cand.parent_op_ids {
                    referenced_parents.insert((cand.entity_type, cand.entity_id.as_str(), p));
                }
            }
            if cand.op_type == OpType::Create
                && (cand.server_seq.is_some()
                    || (cand.sync_blocked_reason.is_none() && !tainted_unpushed.contains(&cand.op_id)))
            {
                entities_with_surviving_create.insert((cand.entity_type, cand.entity_id.as_str()));
            }
        }

        let collapse_retiring_ancestors = |start_parents: &[OpId],
                                           allow_collapse_create: bool|
         -> (Vec<OpId>, BTreeSet<OpId>, bool, bool) {
            let mut frontier: BTreeSet<OpId> = BTreeSet::new();
            let mut collapsed: BTreeSet<OpId> = BTreeSet::new();
            let mut collapsed_create = false;
            let mut hit_unpushable_create = false;
            let mut stack: Vec<OpId> = start_parents.to_vec();
            let mut visited: BTreeSet<OpId> = BTreeSet::new();
            while let Some(pid) = stack.pop() {
                if !visited.insert(pid) {
                    continue;
                }
                if tainted_unpushed.contains(&pid) {
                    if let Some(anc) = unpushed_by_id.get(&pid) {
                        if anc.op_type == OpType::Create && !allow_collapse_create {
                            hit_unpushable_create = true;
                            frontier.insert(pid);
                            continue;
                        }
                        if anc.op_type == OpType::Create {
                            collapsed_create = true;
                        }
                        collapsed.insert(pid);
                        stack.extend(anc.parent_op_ids.iter().copied());
                    } else {
                        frontier.insert(pid);
                    }
                } else {
                    frontier.insert(pid);
                }
            }
            (
                frontier.into_iter().collect(),
                collapsed,
                collapsed_create,
                hit_unpushable_create,
            )
        };

        let mut leaves = Vec::new();
        let mut protected_roots: Vec<OpId> = Vec::new();
        for o in &unpushed {
            if !o.op_type.is_dag_op()
                || referenced_parents.contains(&(o.entity_type, o.entity_id.as_str(), o.op_id))
            {
                continue;
            }
            let self_needs_rekey = needs_rekey_ids.contains(&o.op_id);
            let allow_collapse_create = self_needs_rekey
                || o.op_type != OpType::Delete
                || entities_with_surviving_create.contains(&(o.entity_type, o.entity_id.as_str()));
            let (frontier_parents, collapsed_ancestors, collapsed_create, hit_unpushable_create) =
                collapse_retiring_ancestors(&o.parent_op_ids, allow_collapse_create);
            if hit_unpushable_create || (!self_needs_rekey && collapsed_ancestors.is_empty()) {
                protected_roots.push(o.op_id);
                continue;
            }
            let mut merged: BTreeSet<OpId> = frontier_parents.iter().copied().collect();
            merged.extend(collapsed_ancestors.iter().copied());
            merged.insert(o.op_id);
            leaves.push(OutboxLeafPlan {
                op_id: o.op_id,
                self_needs_rekey,
                frontier_parents,
                merged_parents: merged.into_iter().collect(),
                collapsed_ancestors,
                collapsed_create,
            });
        }

        let mut protected_ancestors: BTreeSet<OpId> = BTreeSet::new();
        let mut p_stack = protected_roots;
        let mut p_visited = BTreeSet::new();
        while let Some(oid) = p_stack.pop() {
            if !p_visited.insert(oid) {
                continue;
            }
            if let Some(u) = unpushed_by_id.get(&oid) {
                protected_ancestors.insert(oid);
                p_stack.extend(u.parent_op_ids.iter().copied());
            }
        }

        let mut blocked_roots: Vec<OpId> = Vec::new();
        for o in self.ops.values() {
            if o.server_seq.is_none()
                && matches!(
                    o.sync_blocked_reason.as_deref(),
                    Some("NEEDS_VAULT_REKEY" | "NEEDS_VAULT_REKEY_ANCESTOR")
                )
            {
                blocked_roots.extend(o.parent_op_ids.iter().copied());
            }
        }
        let mut blocked_rekey_ancestors: BTreeSet<OpId> = BTreeSet::new();
        let mut b_visited = BTreeSet::new();
        while let Some(oid) = blocked_roots.pop() {
            if !b_visited.insert(oid) {
                continue;
            }
            if let Some(u) = unpushed_by_id.get(&oid) {
                if tainted_unpushed.contains(&oid) && !protected_ancestors.contains(&oid) {
                    blocked_rekey_ancestors.insert(oid);
                } else {
                    protected_ancestors.insert(oid);
                }
                blocked_roots.extend(u.parent_op_ids.iter().copied());
            } else if let Some(b) = self.ops.get(&oid) {
                if b.server_seq.is_none() {
                    blocked_roots.extend(b.parent_op_ids.iter().copied());
                }
            }
        }

        let mut stranded_superseded_ops: BTreeSet<OpId> = BTreeSet::new();
        for o in &unpushed {
            if !o.op_type.is_dag_op()
                || o.op_type == OpType::Create
                || !referenced_parents.contains(&(o.entity_type, o.entity_id.as_str(), o.op_id))
                || protected_ancestors.contains(&o.op_id)
                || blocked_rekey_ancestors.contains(&o.op_id)
            {
                continue;
            }
            if tainted_unpushed.contains(&o.op_id) {
                stranded_superseded_ops.insert(o.op_id);
            }
        }

        OutboxReconcilePlan {
            leaves,
            stranded_superseded_ops,
            protected_ancestors,
            blocked_rekey_ancestors,
        }
    }

    /// Collect keys currently referenced by live leaves of any `ACTIVE` block or `ACTIVE` buffer.
    pub(crate) fn active_live_keys(&self) -> BTreeSet<KeyId> {
        let mut live = BTreeSet::new();
        for buf in self.all_buffers() {
            if buf.state == crate::model::BlockState::Active {
                live.insert(buf.key_id);
            }
        }
        for blk in self.all_blocks() {
            if blk.state != crate::model::BlockState::Active {
                continue;
            }
            for leaf in &blk.leaves {
                if !leaf.is_live() {
                    continue;
                }
                if let Some(op) = self.ops.get(&leaf.op_id) {
                    if let Some(kid) = op.key_id {
                        live.insert(kid);
                    }
                }
            }
        }
        live
    }

    /// Build next push batch if bootstrapped and not mid-reconciliation.
    ///
    /// Enforces DO atomic order (`key_records -> cancel_key_ids -> ops -> shred_marks`) and
    /// guarantees (`INV-KEY-LIVENESS` #3):
    /// 1. `pending_shred_marks` are NEVER attached while any pending ops are deferred to a later batch
    ///    (otherwise a deferred `DELETE` (`key_id: None`) or `LOCK`/`UNLOCK` (`key_id: K_new`) could
    ///    allow `K_old`'s shred mark to land on DO before the superseding op!).
    /// 2. `pending_shred_marks` are NEVER attached for a key still referenced by a live leaf of any
    ///    `ACTIVE` block or `ACTIVE` buffer (Update-Wins defense-in-depth).
    pub fn build_pending_push(&self) -> Option<PushRequestDto> {
        if !self.bootstrap_completed || self.reconciling_epoch.is_some() {
            return None;
        }
        let epoch = self.journal_epoch?;

        let mut cancel_set: BTreeSet<KeyId> = self
            .pending_cancel_key_ids
            .iter()
            .copied()
            .filter(|k| !self.keys.is_shredded(k))
            .collect();

        let mut raw_candidates: Vec<&LocalOpRecord> = self
            .ops
            .values()
            .filter(|o| o.server_seq.is_none() && o.sync_blocked_reason.is_none())
            .filter(|o| match self.classify_unpushed_op(o) {
                OutboxKeyAction::PushNormal => true,
                OutboxKeyAction::CancelAndPush => {
                    if let Some(kid) = o.key_id {
                        cancel_set.insert(kid);
                    }
                    true
                }
                OutboxKeyAction::NeedsRekey { .. } => false,
            })
            .collect();
        raw_candidates.sort_by_key(|a| (a.created_at_ms, a.op_id));

        // Topological causal filter: never emit an op ahead of or without an unpushed local parent,
        // preventing orphan Tombstone/Update ops on DO under clock skew or blocked Tier 2 ancestors.
        let candidate_ids: BTreeSet<OpId> = raw_candidates.iter().map(|o| o.op_id).collect();
        let mut pending: Vec<&LocalOpRecord> = Vec::with_capacity(raw_candidates.len());
        let mut ready_ids: BTreeSet<OpId> = BTreeSet::new();
        let mut remaining = raw_candidates;
        while !remaining.is_empty() {
            let mut progressed = false;
            let mut next_remaining = Vec::new();
            for o in remaining {
                let parents_ready = o.parent_op_ids.iter().all(|pid| match self.ops.get(pid) {
                    None => true,
                    Some(p) if p.server_seq.is_some() => true,
                    Some(p) if p.sync_blocked_reason.as_deref() == Some("NEEDS_VAULT_REKEY_ANCESTOR") => true,
                    Some(_) => candidate_ids.contains(pid) && ready_ids.contains(pid),
                });
                if parents_ready {
                    ready_ids.insert(o.op_id);
                    pending.push(o);
                    progressed = true;
                } else {
                    next_remaining.push(o);
                }
            }
            if !progressed {
                break;
            }
            remaining = next_remaining;
        }

        let mut needed_keys = BTreeSet::new();
        let mut ops = Vec::with_capacity(pending.len().min(MAX_PUSH_BATCH_OPS));
        let mut included_op_ids = BTreeSet::new();
        let mut est_json_bytes: usize = 256;

        for o in &pending {
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
            included_op_ids.insert(o.op_id);
            ops.push(PushOpDto {
                op_id: o.op_id,
                device_id: o.device_id.clone(),
                key_id: o.key_id,
                envelope: o.envelope.clone(),
            });
        }

        // Only attach shred marks once ALL non-blocked pending ops fit in this batch (C6).
        // Also exclude any key still referenced by an unpushed blocked/rekey op or an ACTIVE live leaf (C7).
        let mut shred_marks = Vec::new();
        if included_op_ids.len() == pending.len() && !self.pending_shred_marks.is_empty() {
            let mut blocked_entities: BTreeSet<(EntityType, &str)> = BTreeSet::new();
            let mut blocked_keys: BTreeSet<KeyId> = BTreeSet::new();
            for o in self.ops.values() {
                if o.server_seq.is_none() && !included_op_ids.contains(&o.op_id) {
                    blocked_entities.insert((o.entity_type, o.entity_id.as_str()));
                    if let Some(kid) = o.key_id {
                        blocked_keys.insert(kid);
                    }
                }
            }
            let active_live = self.active_live_keys();
            for m in &self.pending_shred_marks {
                if self.keys.is_shredded(&m.key_id)
                    || cancel_set.contains(&m.key_id)
                    || blocked_keys.contains(&m.key_id)
                    || active_live.contains(&m.key_id)
                {
                    continue;
                }
                let belongs_to_blocked_entity = self.ops.values().any(|o| {
                    o.key_id == Some(m.key_id)
                        && blocked_entities.contains(&(o.entity_type, o.entity_id.as_str()))
                });
                if belongs_to_blocked_entity {
                    continue;
                }
                if self.keys.records.contains_key(&m.key_id) {
                    needed_keys.insert(m.key_id);
                    shred_marks.push(m.clone());
                }
            }
        }

        let cancel_key_ids: Vec<KeyId> = cancel_set.into_iter().collect();
        if ops.is_empty() && cancel_key_ids.is_empty() && shred_marks.is_empty() {
            return None;
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
            cancel_key_ids,
            ops,
            shred_marks,
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
                            op.sync_blocked_reason = None;
                        }
                    }
                }
                StoreMutation::MarkOpBlocked { op_id, reason } => {
                    if let Some(op) = self.ops.get_mut(op_id) {
                        op.sync_blocked_reason = Some(reason.clone());
                    }
                }
                StoreMutation::MarkShredMarksAcked {
                    results,
                    cancelled_keys,
                } => {
                    for res in results {
                        let mut acked_marks = Vec::new();
                        self.pending_shred_marks.retain(|pm| {
                            if pm.key_id == res.key_id {
                                let mut updated = pm.clone();
                                if res.state >= updated.state {
                                    updated.state = res.state;
                                }
                                updated.not_before_ms = res.not_before_ms;
                                acked_marks.push(updated);
                                false
                            } else {
                                true
                            }
                        });
                        for am in acked_marks {
                            self.keys.insert_mark(am);
                        }
                        if res.state == ShredMarkState::Executed {
                            self.keys.executed_tombstones.insert(res.key_id);
                            if let Some(rec) = self.keys.records.get_mut(&res.key_id) {
                                rec.key_record = None;
                            }
                        }
                        for existing in self.keys.marks.values_mut() {
                            if existing.key_id == res.key_id
                                && matches!(
                                    existing.state,
                                    ShredMarkState::PendingConfirm | ShredMarkState::Scheduled
                                )
                            {
                                if res.state >= existing.state {
                                    existing.state = res.state;
                                }
                                if res.not_before_ms.is_some() {
                                    existing.not_before_ms = match (existing.not_before_ms, res.not_before_ms)
                                    {
                                        (Some(a), Some(b)) => Some(a.min(b)),
                                        (Some(a), None) | (None, Some(a)) => Some(a),
                                        (None, None) => None,
                                    };
                                }
                            }
                        }
                    }
                    for kid in cancelled_keys {
                        self.pending_cancel_key_ids.remove(kid);
                        self.pending_shred_marks.retain(|pm| pm.key_id != *kid);
                        for existing in self.keys.marks.values_mut() {
                            if existing.key_id == *kid
                                && matches!(
                                    existing.state,
                                    ShredMarkState::PendingConfirm | ShredMarkState::Scheduled
                                )
                            {
                                existing.state = ShredMarkState::Cancelled;
                                existing.cancelled_by = Some(self.device_id.clone());
                            }
                        }
                    }
                }
                StoreMutation::ClearServerSeqsForReconcile { new_epoch } => {
                    // ANTI-WIPE INVARIANT: NEVER delete local ops; only clear old epoch's server_seq!
                    for op in self.ops.values_mut() {
                        op.server_seq = None;
                    }
                    // Demote non-Executed server marks so DO PITR / new-epoch reconciliation re-pushes
                    // active shred marks (G4) and re-asserts cancellations (Update-Wins G1), converging keys_digest.
                    let existing_pending: BTreeSet<crate::ids::MarkId> =
                        self.pending_shred_marks.iter().map(|m| m.mark_id).collect();
                    let mut kept_marks = BTreeMap::new();
                    for (mid, mut m) in std::mem::take(&mut self.keys.marks) {
                        if m.state == ShredMarkState::Executed || self.keys.is_shredded(&m.key_id) {
                            kept_marks.insert(mid, m);
                            continue;
                        }
                        match m.state {
                            ShredMarkState::PendingConfirm | ShredMarkState::Scheduled => {
                                if !existing_pending.contains(&mid) {
                                    m.state = ShredMarkState::PendingConfirm;
                                    m.not_before_ms = None;
                                    m.confirmed_at_ms = None;
                                    self.pending_shred_marks.push(m);
                                }
                            }
                            ShredMarkState::Cancelled => {
                                self.pending_cancel_key_ids.insert(m.key_id);
                            }
                            ShredMarkState::Executed => {}
                        }
                    }
                    self.keys.marks = kept_marks;
                    self.reconciling_epoch = Some(*new_epoch);
                    self.last_seq = 0;
                }
                StoreMutation::UpsertBlockKey(row) => {
                    self.keys.insert_record(row.clone());
                }
                StoreMutation::UpsertShredMark(mark) => {
                    self.pending_shred_marks.retain(|pm| pm.mark_id != mark.mark_id);
                    if matches!(mark.state, ShredMarkState::Cancelled | ShredMarkState::Executed) {
                        self.pending_cancel_key_ids.remove(&mark.key_id);
                    }
                    self.keys.insert_mark(mark.clone());
                }
                StoreMutation::UpsertKeyMaterial { kind, gen, blob, .. } => match kind {
                    KeyMaterialKind::Keyring => self.keys.update_keyring_material(*gen as u32, blob.clone()),
                    KeyMaterialKind::VaultHeader => {
                        self.keys.update_vault_header_material(*gen, blob.clone())
                    }
                    KeyMaterialKind::ClipKey => {
                        // INV-CLIP-ISOLATION: ClipKey never enters note KeyTableState::digest().
                    }
                },
                StoreMutation::ExecuteShred { key_id } => {
                    self.keys.executed_tombstones.insert(*key_id);
                    self.pending_shred_marks.retain(|pm| pm.key_id != *key_id);
                    self.pending_cancel_key_ids.remove(key_id);
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
        shred_results: Vec<ShredResultDto>,
        cancelled_keys: Vec<KeyId>,
        head_seq: i64,
    },
    PushEpochMismatch {
        remote_epoch: JournalEpoch,
    },
    /// Server rejected a push batch due to key/shred concurrency (`SHRED_STALE`, `KEY_PENDING_SHRED`,
    /// `KEY_SHREDDED`): pull latest ops first, then reconcile key table and retry.
    PushKeyRaceError {
        code: ErrorCode,
        key_id: Option<KeyId>,
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
    MarkOpBlocked {
        op_id: OpId,
        reason: String,
    },
    MarkShredMarksAcked {
        results: Vec<ShredResultDto>,
        cancelled_keys: Vec<KeyId>,
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
            // Always pull ops BEFORE syncing the key table so remote DELETE/LOCK ops land
            // prior to evaluating `ExecuteShred` and `classify_unpushed_op` (C3, C11).
            commands.push(SyncCommand::HttpPull {
                since_seq: if state.bootstrap_completed {
                    state.last_seq
                } else {
                    0
                },
                limit: DEFAULT_PULL_LIMIT,
            });
        }

        SyncEvent::WsWake { epoch, head_seq } => {
            let epoch_changed = state.journal_epoch.is_some_and(|e| e != epoch);
            if epoch_changed || head_seq < state.last_seq {
                mutations.push(StoreMutation::ClearServerSeqsForReconcile { new_epoch: epoch });
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
            commands.push(SyncCommand::HttpPull {
                since_seq: 0,
                limit: DEFAULT_PULL_LIMIT,
            });
        }

        SyncEvent::PushKeyRaceError { .. } => {
            // Pull remote ops FIRST so remote DELETE/LOCK/UPDATE ops settle before `PullResponse`
            // triggers `SyncKeyTable` on `keys_digest` diff (C11, §5.7).
            commands.push(SyncCommand::HttpPull {
                since_seq: state.last_seq,
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
            } else if !keys_match {
                // Sync key table AFTER remote ops landed so shred marks & new keys settle cleanly!
                commands.push(SyncCommand::SyncKeyTable(build_key_sync_dto(state)));
            } else {
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
            shred_results,
            cancelled_keys,
            head_seq,
        } => {
            if state.journal_epoch.is_some_and(|e| e != epoch) {
                mutations.push(StoreMutation::ClearServerSeqsForReconcile { new_epoch: epoch });
                commands.push(SyncCommand::HttpPull {
                    since_seq: 0,
                    limit: DEFAULT_PULL_LIMIT,
                });
                return Ok((mutations, commands));
            }
            if !acked.is_empty() {
                mutations.push(StoreMutation::MarkOpsSynced { epoch, acked });
            }
            let executed_shred_keys: BTreeSet<KeyId> = shred_results
                .iter()
                .filter(|r| r.state == ShredMarkState::Executed && !state.keys.is_shredded(&r.key_id))
                .map(|r| r.key_id)
                .collect();
            if !shred_results.is_empty() || !cancelled_keys.is_empty() {
                mutations.push(StoreMutation::MarkShredMarksAcked {
                    results: shred_results,
                    cancelled_keys,
                });
            }
            for key_id in executed_shred_keys {
                mutations.push(StoreMutation::ExecuteShred { key_id });
            }
            let mut next_state = state.clone();
            next_state.apply_mutations(&mutations);
            if head_seq > next_state.last_seq {
                // Pull first to advance `last_seq` before sending Batch 2 so `seen_seq` is fresh (M1).
                commands.push(SyncCommand::HttpPull {
                    since_seq: next_state.last_seq,
                    limit: DEFAULT_PULL_LIMIT,
                });
            } else if let Some(push) = next_state.build_pending_push() {
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
            // HARD INVARIANT (`sync-protocol.md` §5.2):
            // ONLY server-reported `key_record == None` or `mark.state == Executed` triggers
            // local `ExecuteShred` — client local clock NEVER decides expiration.
            let mut exec_shreds = BTreeSet::new();
            for rec in records {
                if rec.key_record.is_none() && !state.keys.is_shredded(&rec.key_id) {
                    exec_shreds.insert(rec.key_id);
                }
                mutations.push(StoreMutation::UpsertBlockKey(rec));
            }
            for mark in marks {
                if mark.state == ShredMarkState::Executed && !state.keys.is_shredded(&mark.key_id) {
                    exec_shreds.insert(mark.key_id);
                }
                mutations.push(StoreMutation::UpsertShredMark(mark));
            }
            for key_id in exec_shreds {
                mutations.push(StoreMutation::ExecuteShred { key_id });
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
            }
            let mut next_state = state.clone();
            next_state.apply_mutations(&mutations);
            if next_state.bootstrap_completed && next_state.reconciling_epoch.is_none() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{BlockId, MarkId, Ulid};
    use crate::model::{ShredMarkRow, ShredMarkState};
    use crate::vault::T_GRACE_DEFAULT_MS;

    fn test_op_id(n: u64) -> OpId {
        OpId::from_ulid(Ulid::from_parts(1_710_000_000_000 + n, [n as u8; 10]))
    }

    fn test_key_id(n: u64) -> KeyId {
        KeyId::from_ulid(Ulid::from_parts(1_710_000_100_000 + n, [n as u8; 10]))
    }

    fn dummy_op(
        op_id: OpId,
        entity_id: &str,
        op_type: OpType,
        parents: Vec<OpId>,
        key_id: Option<KeyId>,
        server_seq: Option<i64>,
        blocked: Option<&str>,
    ) -> LocalOpRecord {
        let dev = DeviceId::from_random_bytes([1; 10]);
        LocalOpRecord {
            op_id,
            server_seq,
            sync_blocked_reason: blocked.map(str::to_string),
            device_id: dev.clone(),
            entity_type: EntityType::Block,
            entity_id: entity_id.to_string(),
            parent_op_ids: parents,
            op_type,
            hlc: Hlc::new(1_710_000_000_000, 0, dev),
            actor: "human".into(),
            key_id,
            smk_kid: SmkKid::from_bytes([2; 16]),
            envelope: vec![0u8; 8],
            created_at_ms: 1_710_000_000_000,
        }
    }

    fn insert_live_key(snap: &mut EngineSnapshot, kid: KeyId) {
        snap.keys.insert_record(KeyRecordRow {
            key_id: kid,
            wrap_gen: 1,
            key_record: Some(vec![1, 2, 3]),
            created_at_ms: 1_710_000_000_000,
        });
    }

    fn schedule_shred(snap: &mut EngineSnapshot, n: u64, kid: KeyId) {
        snap.keys.insert_mark(ShredMarkRow {
            mark_id: MarkId::from_ulid(Ulid::from_parts(1_710_000_200_000 + n, [n as u8; 10])),
            key_id: kid,
            seen_seq: 1,
            requested_by: DeviceId::from_random_bytes([9; 10]),
            requested_at_ms: 1_710_000_200_000,
            grace_ms: T_GRACE_DEFAULT_MS,
            not_before_ms: Some(1_710_000_200_000 + T_GRACE_DEFAULT_MS),
            state: ShredMarkState::Scheduled,
            confirmed_at_ms: None,
            cancelled_by: None,
            executed_at_ms: None,
        });
    }

    #[test]
    fn plan_collapses_tainted_delete_between_retiring_updates_and_keeps_synced_frontier() {
        let dev = DeviceId::from_random_bytes([1; 10]);
        let mut snap = EngineSnapshot::new(dev, 1_710_000_000_000);
        let bid = BlockId::from_ulid(Ulid::from_parts(1_710_000_000_001, [7; 10])).to_string();
        let k0 = test_key_id(1);
        let k1 = test_key_id(2);
        insert_live_key(&mut snap, k0);
        insert_live_key(&mut snap, k1);
        schedule_shred(&mut snap, 1, k1);

        let f_synced = test_op_id(1);
        let f_conflict = test_op_id(2);
        let u1 = test_op_id(3);
        let d = test_op_id(4);
        let leaf = test_op_id(5);

        snap.ops.insert(
            f_synced,
            dummy_op(f_synced, &bid, OpType::Create, vec![], Some(k0), Some(1), None),
        );
        snap.ops.insert(
            f_conflict,
            dummy_op(
                f_conflict,
                &bid,
                OpType::Update,
                vec![f_synced],
                Some(k0),
                Some(2),
                None,
            ),
        );
        snap.ops.insert(
            u1,
            dummy_op(
                u1,
                &bid,
                OpType::Update,
                vec![f_synced, f_conflict],
                Some(k1),
                None,
                None,
            ),
        );
        snap.ops
            .insert(d, dummy_op(d, &bid, OpType::Delete, vec![u1], None, None, None));
        snap.ops.insert(
            leaf,
            dummy_op(leaf, &bid, OpType::Update, vec![d], Some(k1), None, None),
        );

        let plan = snap.plan_outbox_reconciliation();
        assert_eq!(plan.leaves.len(), 1);
        let lp = &plan.leaves[0];
        assert_eq!(lp.op_id, leaf);
        assert!(lp.self_needs_rekey);
        assert_eq!(lp.frontier_parents, vec![f_synced, f_conflict]);
        assert_eq!(lp.collapsed_ancestors, BTreeSet::from([u1, d]));
        assert_eq!(lp.merged_parents, vec![f_synced, f_conflict, u1, d, leaf]);
        assert!(plan.protected_ancestors.is_empty());
        assert!(plan.blocked_rekey_ancestors.is_empty());
    }

    #[test]
    fn plan_collapses_tainted_fresh_intermediate_under_non_rekey_leaf() {
        let dev = DeviceId::from_random_bytes([1; 10]);
        let mut snap = EngineSnapshot::new(dev, 1_710_000_000_000);
        let bid = BlockId::from_ulid(Ulid::from_parts(1_710_000_000_002, [8; 10])).to_string();
        let k0 = test_key_id(10);
        let k1 = test_key_id(11);
        let k2 = test_key_id(12);
        insert_live_key(&mut snap, k0);
        insert_live_key(&mut snap, k1);
        insert_live_key(&mut snap, k2);
        schedule_shred(&mut snap, 2, k1);

        let f_synced = test_op_id(10);
        let u1 = test_op_id(11);
        let u2 = test_op_id(12);
        let del_leaf = test_op_id(13);

        snap.ops.insert(
            f_synced,
            dummy_op(f_synced, &bid, OpType::Create, vec![], Some(k0), Some(1), None),
        );
        snap.ops.insert(
            u1,
            dummy_op(u1, &bid, OpType::Update, vec![f_synced], Some(k1), None, None),
        );
        snap.ops.insert(
            u2,
            dummy_op(u2, &bid, OpType::Update, vec![u1], Some(k2), None, None),
        );
        snap.ops.insert(
            del_leaf,
            dummy_op(del_leaf, &bid, OpType::Delete, vec![u2], None, None, None),
        );

        let plan = snap.plan_outbox_reconciliation();
        assert_eq!(plan.leaves.len(), 1);
        let lp = &plan.leaves[0];
        assert_eq!(lp.op_id, del_leaf);
        assert!(!lp.self_needs_rekey);
        assert!(!lp.collapsed_create);
        assert_eq!(lp.frontier_parents, vec![f_synced]);
        assert_eq!(lp.collapsed_ancestors, BTreeSet::from([u1, u2]));
        assert_eq!(lp.merged_parents, vec![f_synced, u1, u2, del_leaf]);
        assert!(plan.protected_ancestors.is_empty());
    }

    #[test]
    fn plan_handles_create_collapsing_only_when_create_is_unpushable_and_metadata_survives() {
        let dev = DeviceId::from_random_bytes([1; 10]);
        let mut snap = EngineSnapshot::new(dev, 1_710_000_000_000);
        let bid_upd = BlockId::from_ulid(Ulid::from_parts(1_710_000_000_003, [3; 10])).to_string();
        let bid_del = BlockId::from_ulid(Ulid::from_parts(1_710_000_000_004, [4; 10])).to_string();
        let k1 = test_key_id(21);
        let k2 = test_key_id(22);
        insert_live_key(&mut snap, k1);
        insert_live_key(&mut snap, k2);
        schedule_shred(&mut snap, 3, k1);

        // 1. Non-delete leaf on fresh K2 above retiring Create(K1) collapses Create -> promoted to Create
        let c_upd = test_op_id(21);
        let l_upd = test_op_id(22);
        snap.ops.insert(
            c_upd,
            dummy_op(c_upd, &bid_upd, OpType::Create, vec![], Some(k1), None, None),
        );
        snap.ops.insert(
            l_upd,
            dummy_op(l_upd, &bid_upd, OpType::Update, vec![c_upd], Some(k2), None, None),
        );

        // 2. Delete leaf above unpushable Create(K1) with no surviving Create aborts partial collapse
        let c_del = test_op_id(23);
        let u_del = test_op_id(24);
        let l_del = test_op_id(25);
        snap.ops.insert(
            c_del,
            dummy_op(c_del, &bid_del, OpType::Create, vec![], Some(k1), None, None),
        );
        snap.ops.insert(
            u_del,
            dummy_op(u_del, &bid_del, OpType::Update, vec![c_del], Some(k1), None, None),
        );
        snap.ops.insert(
            l_del,
            dummy_op(l_del, &bid_del, OpType::Delete, vec![u_del], None, None, None),
        );

        let plan = snap.plan_outbox_reconciliation();
        assert_eq!(plan.leaves.len(), 1);
        let lp = &plan.leaves[0];
        assert_eq!(lp.op_id, l_upd);
        assert!(!lp.self_needs_rekey);
        assert!(lp.collapsed_create);
        assert!(lp.frontier_parents.is_empty());
        assert_eq!(lp.collapsed_ancestors, BTreeSet::from([c_upd]));
        assert_eq!(lp.merged_parents, vec![c_upd, l_upd]);
        assert_eq!(plan.protected_ancestors, BTreeSet::from([c_del, u_del, l_del]));
        assert!(!plan.stranded_superseded_ops.contains(&u_del));
    }

    #[test]
    fn plan_separates_tainted_ancestors_of_blocked_vault_ops_from_protected_pushable_ancestors() {
        let dev = DeviceId::from_random_bytes([1; 10]);
        let mut snap = EngineSnapshot::new(dev, 1_710_000_000_000);
        let bid = BlockId::from_ulid(Ulid::from_parts(1_710_000_000_005, [5; 10])).to_string();
        let k0 = test_key_id(30);
        let ka = test_key_id(31);
        let kt2 = test_key_id(32);
        insert_live_key(&mut snap, k0);
        insert_live_key(&mut snap, ka);
        insert_live_key(&mut snap, kt2);
        schedule_shred(&mut snap, 4, ka);

        let f_synced = test_op_id(30);
        let anc_a = test_op_id(31);
        let sib_l1 = test_op_id(32);
        let blocked_l2 = test_op_id(33);

        snap.ops.insert(
            f_synced,
            dummy_op(f_synced, &bid, OpType::Create, vec![], Some(k0), Some(1), None),
        );
        snap.ops.insert(
            anc_a,
            dummy_op(anc_a, &bid, OpType::Update, vec![f_synced], Some(ka), None, None),
        );
        snap.ops.insert(
            sib_l1,
            dummy_op(sib_l1, &bid, OpType::Update, vec![anc_a], Some(ka), None, None),
        );
        snap.ops.insert(
            blocked_l2,
            dummy_op(
                blocked_l2,
                &bid,
                OpType::Lock,
                vec![anc_a],
                Some(kt2),
                None,
                Some("NEEDS_VAULT_REKEY"),
            ),
        );

        let plan = snap.plan_outbox_reconciliation();
        assert_eq!(plan.leaves.len(), 1);
        assert_eq!(plan.leaves[0].op_id, sib_l1);
        assert_eq!(plan.leaves[0].merged_parents, vec![f_synced, anc_a, sib_l1]);
        assert!(plan.protected_ancestors.is_empty());
        assert_eq!(plan.blocked_rekey_ancestors, BTreeSet::from([anc_a]));
        assert!(plan.stranded_superseded_ops.is_empty());
    }
}
