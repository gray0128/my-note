//! Deterministic Simulation Testing (`SimCluster`, M1-12 / `docs/eval-framework.md` §2 & §4).
//!
//! Zero system clocks, zero real I/O: every schedule, fault injection, PITR rollback,
//! SMK rotation, and R2 archive recovery is 100% determined by a single `SimSeed(u64)`.

use crate::crypto::{
    decode_mna1, decode_mnks, decrypt_mns1, encode_mna1, encode_mnks, encrypt_mnb1, encrypt_mnr1,
    encrypt_mns1, peek_envelope_kid, seal_mnrs, ArchiveOpsHeaderV1, ArchivedOpRow, KeyRecordV1,
    KeySnapshotBodyV1, KeySnapshotHeaderV1, RecoveryKeypair, RecoveryKeyringV1, VaultHeaderV1, MAGIC_MNS1,
    MNRS_KIND_SMK,
};
use crate::error::{CoreError, ErrorCode};
use crate::fractional_index;
use crate::hlc::HlcClock;
use crate::ids::{
    BlockId, BufferId, DeviceId, JournalEpoch, KeyId, MonotonicUlidGen, OpId, SmkKid, SnapshotId,
};
use crate::keys::{self_check_key_liveness, KeyTableState};
use crate::model::{
    BlockState, EntityType, InnerOpV1, KeyRecordRow, LeafBody, OpBodyV1, OpType, ShredMarkRow, ShredMarkState,
};
use crate::sync::{
    step, AckedOp, EngineSnapshot, LocalOpRecord, PushRequestDto, RemoteEnvelopeRow, ShredResultDto,
    StoreMutation, SyncCommand, SyncEvent,
};
use crate::vault::{SHRED_BATCH_LIMIT_24H, T_GRACE_MIN_MS};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimSeed(pub u64);

/// Deterministic xorshift64* PRNG (zero external RNG dependence, 100% reproducible across OSes).
#[derive(Clone, Debug)]
struct DetRng(u64);

impl DetRng {
    fn new(seed: SimSeed) -> Self {
        Self(if seed.0 == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed.0
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() as usize) % bound
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }

    fn bytes_10(&mut self) -> [u8; 10] {
        let mut b = [0u8; 10];
        self.fill_bytes(&mut b);
        b
    }

    fn bytes_16(&mut self) -> [u8; 16] {
        let mut b = [0u8; 16];
        self.fill_bytes(&mut b);
        b
    }

    fn bytes_24(&mut self) -> [u8; 24] {
        let mut b = [0u8; 24];
        self.fill_bytes(&mut b);
        b
    }

    fn bytes_32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        self.fill_bytes(&mut b);
        b
    }

    fn bytes_4(&mut self) -> [u8; 4] {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        b
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimPushOk {
    pub epoch: JournalEpoch,
    pub acked: Vec<AckedOp>,
    pub shred_results: Vec<ShredResultDto>,
    pub head_seq: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimRelayError {
    pub code: ErrorCode,
    pub key_id: Option<KeyId>,
}

impl SimRelayError {
    fn new(code: ErrorCode, key_id: Option<KeyId>) -> Self {
        Self { code, key_id }
    }
}

#[derive(Clone, Debug)]
pub struct StoredPhoneSnapshot {
    pub epoch: JournalEpoch,
    pub covers_seq: i64,
    pub snapshot_id: SnapshotId,
    pub bytes: Vec<u8>,
}

/// Faithful blind relay server model mirroring `cloud-cf` DO semantics (`F-12`).
#[derive(Clone, Debug)]
pub struct SimRelay {
    pub epoch: JournalEpoch,
    pub ops: Vec<RemoteEnvelopeRow>,
    pub op_index: BTreeMap<OpId, i64>,
    pub keys: KeyTableState,
    pub r2_op_archives: Vec<(String, Vec<u8>)>,
    pub r2_latest_mnks: Option<Vec<u8>>,
    pub last_archived_seq: i64,
    pub t_grace_min_ms: i64,
    pub shred_batch_limit_24h: usize,
    pub migration_exempt_used: bool,
    pub phone_snapshots: Vec<StoredPhoneSnapshot>,
}

impl SimRelay {
    pub fn new(epoch: JournalEpoch) -> Self {
        Self {
            epoch,
            ops: Vec::new(),
            op_index: BTreeMap::new(),
            keys: KeyTableState::default(),
            r2_op_archives: Vec::new(),
            r2_latest_mnks: None,
            last_archived_seq: 0,
            t_grace_min_ms: T_GRACE_MIN_MS,
            shred_batch_limit_24h: SHRED_BATCH_LIMIT_24H,
            migration_exempt_used: false,
            phone_snapshots: Vec::new(),
        }
    }

    pub fn head_seq(&self) -> i64 {
        self.ops.last().map_or(0, |o| o.seq)
    }

    fn rolling_24h_scheduled_count(keys: &KeyTableState, now_ms: i64) -> usize {
        let cutoff = now_ms - 86_400_000;
        let mut distinct = BTreeSet::new();
        for m in keys.marks.values() {
            if m.requested_at_ms > cutoff
                && matches!(m.state, ShredMarkState::Scheduled | ShredMarkState::Executed)
            {
                distinct.insert(m.key_id);
            }
        }
        distinct.len()
    }

    pub fn handle_push(
        &mut self,
        pusher_device_id: &DeviceId,
        req: &PushRequestDto,
        now_ms: i64,
    ) -> Result<SimPushOk, SimRelayError> {
        if req.expected_epoch != self.epoch {
            return Err(SimRelayError::new(ErrorCode::CasMismatch, None));
        }

        // Capture head_seq BEFORE inserting ops in this batch so offline "create + lock/delete"
        // does not self-lock on SHRED_STALE, while concurrent remote ops DO trigger SHRED_STALE!
        let pre_batch_head_seq = self.head_seq();
        let mut staged_keys = self.keys.clone();

        // 1. key_records
        for rec in &req.key_records {
            if let Some(cur) = staged_keys.records.get(&rec.key_id) {
                if cur.key_record.is_none() || staged_keys.is_shredded(&rec.key_id) {
                    return Err(SimRelayError::new(ErrorCode::KeyShredded, Some(rec.key_id)));
                }
                if rec.wrap_gen == cur.wrap_gen && rec.key_record != cur.key_record {
                    return Err(SimRelayError::new(ErrorCode::IntegrityError, Some(rec.key_id)));
                }
            }
            staged_keys.insert_record(rec.clone());
        }

        // 2. cancel_key_ids (Update-Wins revival / trash restore)
        for &kid in &req.cancel_key_ids {
            if staged_keys.is_shredded(&kid) {
                return Err(SimRelayError::new(ErrorCode::KeyShredded, Some(kid)));
            }
            for m in staged_keys.marks.values_mut() {
                if m.key_id == kid
                    && matches!(
                        m.state,
                        ShredMarkState::PendingConfirm | ShredMarkState::Scheduled
                    )
                {
                    m.state = ShredMarkState::Cancelled;
                    m.cancelled_by = Some(pusher_device_id.clone());
                }
            }
        }

        // 3. ops validation against staged_keys (check op_id idempotency FIRST so retries succeed — H10)
        for op in &req.ops {
            if self.op_index.contains_key(&op.op_id) {
                continue;
            }
            if let Some(kid) = op.key_id {
                if staged_keys.is_shredded(&kid) {
                    return Err(SimRelayError::new(ErrorCode::KeyShredded, Some(kid)));
                }
                if !staged_keys.is_key_available(&kid) {
                    return Err(SimRelayError::new(ErrorCode::KeyUnknown, Some(kid)));
                }
                if staged_keys.has_pending_or_scheduled_mark(&kid) {
                    return Err(SimRelayError::new(ErrorCode::KeyPendingShred, Some(kid)));
                }
            }
        }

        // 4. shred_marks validation & scheduling (check mark_id idempotency BEFORE SHRED_STALE — H10)
        let mut shred_results = Vec::with_capacity(req.shred_marks.len());
        let mut rolling_count = Self::rolling_24h_scheduled_count(&staged_keys, now_ms);
        for m in &req.shred_marks {
            if let Some(existing) = staged_keys.marks.get(&m.mark_id) {
                if existing.key_id != m.key_id {
                    return Err(SimRelayError::new(ErrorCode::IntegrityError, Some(m.key_id)));
                }
                shred_results.push(ShredResultDto {
                    key_id: existing.key_id,
                    state: existing.state,
                    not_before_ms: existing.not_before_ms,
                });
                continue;
            }
            if m.grace_ms < self.t_grace_min_ms {
                return Err(SimRelayError::new(ErrorCode::GraceTooShort, Some(m.key_id)));
            }
            if !staged_keys.records.contains_key(&m.key_id) {
                return Err(SimRelayError::new(ErrorCode::KeyUnknown, Some(m.key_id)));
            }
            if staged_keys.is_shredded(&m.key_id) {
                shred_results.push(ShredResultDto {
                    key_id: m.key_id,
                    state: ShredMarkState::Executed,
                    not_before_ms: None,
                });
                continue;
            }
            // SHRED_STALE: check ops committed BEFORE this batch with seq > req.seen_seq
            let stale = self
                .ops
                .iter()
                .any(|o| o.seq > req.seen_seq && o.seq <= pre_batch_head_seq && o.key_id == Some(m.key_id));
            if stale {
                return Err(SimRelayError::new(ErrorCode::ShredStale, Some(m.key_id)));
            }
            let (state, not_before_ms) = if rolling_count >= self.shred_batch_limit_24h {
                (ShredMarkState::PendingConfirm, None)
            } else {
                rolling_count += 1;
                (ShredMarkState::Scheduled, Some(now_ms + m.grace_ms))
            };
            let stored = ShredMarkRow {
                mark_id: m.mark_id,
                key_id: m.key_id,
                seen_seq: req.seen_seq,
                requested_by: m.requested_by.clone(),
                requested_at_ms: now_ms,
                grace_ms: m.grace_ms,
                not_before_ms,
                state,
                confirmed_at_ms: None,
                cancelled_by: None,
                executed_at_ms: None,
            };
            staged_keys.insert_mark(stored);
            shred_results.push(ShredResultDto {
                key_id: m.key_id,
                state,
                not_before_ms,
            });
        }

        // Commit atomically
        self.keys = staged_keys;
        let mut acked = Vec::with_capacity(req.ops.len());
        for op in &req.ops {
            if let Some(&existing_seq) = self.op_index.get(&op.op_id) {
                acked.push(AckedOp {
                    op_id: op.op_id,
                    seq: existing_seq,
                });
                continue;
            }
            let seq = self.head_seq() + 1;
            self.ops.push(RemoteEnvelopeRow {
                seq,
                op_id: op.op_id,
                key_id: op.key_id,
                device_id: op.device_id.clone(),
                created_at: now_ms,
                envelope: op.envelope.clone(),
            });
            self.op_index.insert(op.op_id, seq);
            acked.push(AckedOp { op_id: op.op_id, seq });
        }
        Ok(SimPushOk {
            epoch: self.epoch,
            acked,
            shred_results,
            head_seq: self.head_seq(),
        })
    }

    pub fn handle_keys_shred(
        &mut self,
        seen_seq: i64,
        expedite: bool,
        migration_exempt: bool,
        marks: &[ShredMarkRow],
        now_ms: i64,
    ) -> Result<Vec<ShredResultDto>, SimRelayError> {
        let mut staged = self.keys.clone();
        let mut results = Vec::with_capacity(marks.len());
        let allow_exempt = migration_exempt && !self.migration_exempt_used;
        let mut rolling_count = Self::rolling_24h_scheduled_count(&staged, now_ms);

        for m in marks {
            if m.grace_ms < self.t_grace_min_ms {
                return Err(SimRelayError::new(ErrorCode::GraceTooShort, Some(m.key_id)));
            }
            if !staged.records.contains_key(&m.key_id) {
                return Err(SimRelayError::new(ErrorCode::KeyUnknown, Some(m.key_id)));
            }
            if staged.is_shredded(&m.key_id) {
                return Err(SimRelayError::new(ErrorCode::KeyShredded, Some(m.key_id)));
            }
            let stale = self
                .ops
                .iter()
                .any(|o| o.seq > seen_seq && o.key_id == Some(m.key_id));
            if stale {
                return Err(SimRelayError::new(ErrorCode::ShredStale, Some(m.key_id)));
            }
            if expedite {
                if let Some(existing) = staged
                    .marks
                    .values_mut()
                    .find(|em| em.key_id == m.key_id && em.state == ShredMarkState::Scheduled)
                {
                    let candidate = now_ms + m.grace_ms.max(self.t_grace_min_ms);
                    let floor = existing.requested_at_ms + self.t_grace_min_ms;
                    let bounded = candidate.max(floor);
                    let next_nb = existing.not_before_ms.map_or(bounded, |cur| cur.min(bounded));
                    existing.not_before_ms = Some(next_nb);
                    results.push(ShredResultDto {
                        key_id: m.key_id,
                        state: ShredMarkState::Scheduled,
                        not_before_ms: Some(next_nb),
                    });
                    continue;
                }
            }
            if let Some(existing) = staged.marks.get(&m.mark_id) {
                results.push(ShredResultDto {
                    key_id: existing.key_id,
                    state: existing.state,
                    not_before_ms: existing.not_before_ms,
                });
                continue;
            }
            let (state, not_before_ms) = if !allow_exempt && rolling_count >= self.shred_batch_limit_24h {
                (ShredMarkState::PendingConfirm, None)
            } else {
                if !allow_exempt {
                    rolling_count += 1;
                }
                (ShredMarkState::Scheduled, Some(now_ms + m.grace_ms))
            };
            staged.insert_mark(ShredMarkRow {
                mark_id: m.mark_id,
                key_id: m.key_id,
                seen_seq,
                requested_by: m.requested_by.clone(),
                requested_at_ms: now_ms,
                grace_ms: m.grace_ms,
                not_before_ms,
                state,
                confirmed_at_ms: None,
                cancelled_by: None,
                executed_at_ms: None,
            });
            results.push(ShredResultDto {
                key_id: m.key_id,
                state,
                not_before_ms,
            });
        }
        self.keys = staged;
        if allow_exempt && !marks.is_empty() {
            self.migration_exempt_used = true;
        }
        Ok(results)
    }

    pub fn handle_keys_cancel(
        &mut self,
        device_id: &DeviceId,
        key_ids: &[KeyId],
    ) -> Result<Vec<KeyId>, SimRelayError> {
        let mut staged = self.keys.clone();
        let mut cancelled = Vec::new();
        for &kid in key_ids {
            if staged.is_shredded(&kid) {
                return Err(SimRelayError::new(ErrorCode::KeyShredded, Some(kid)));
            }
            let mut changed = false;
            for m in staged.marks.values_mut() {
                if m.key_id == kid
                    && matches!(
                        m.state,
                        ShredMarkState::PendingConfirm | ShredMarkState::Scheduled
                    )
                {
                    m.state = ShredMarkState::Cancelled;
                    m.cancelled_by = Some(device_id.clone());
                    changed = true;
                }
            }
            if changed {
                cancelled.push(kid);
            }
        }
        self.keys = staged;
        Ok(cancelled)
    }

    pub fn handle_keys_confirm(
        &mut self,
        key_ids: &[KeyId],
        grace_ms: i64,
        now_ms: i64,
    ) -> Result<Vec<ShredResultDto>, SimRelayError> {
        if grace_ms < self.t_grace_min_ms {
            return Err(SimRelayError::new(
                ErrorCode::GraceTooShort,
                key_ids.first().copied(),
            ));
        }
        let mut staged = self.keys.clone();
        let mut results = Vec::new();
        for &kid in key_ids {
            if !staged.records.contains_key(&kid) {
                return Err(SimRelayError::new(ErrorCode::KeyUnknown, Some(kid)));
            }
            if staged.is_shredded(&kid) {
                return Err(SimRelayError::new(ErrorCode::KeyShredded, Some(kid)));
            }
            let nb = now_ms + grace_ms.max(self.t_grace_min_ms);
            for m in staged.marks.values_mut() {
                if m.key_id == kid && m.state == ShredMarkState::PendingConfirm {
                    m.state = ShredMarkState::Scheduled;
                    m.confirmed_at_ms = Some(now_ms);
                    m.not_before_ms = Some(nb);
                    results.push(ShredResultDto {
                        key_id: kid,
                        state: ShredMarkState::Scheduled,
                        not_before_ms: Some(nb),
                    });
                }
            }
        }
        self.keys = staged;
        Ok(results)
    }

    /// Execute all due `Scheduled` shred marks (`not_before_ms <= now_ms`) idempotently.
    pub fn run_shred_alarm(&mut self, now_ms: i64) -> Vec<KeyId> {
        let mut executed = Vec::new();
        for m in self.keys.marks.values_mut() {
            if m.state == ShredMarkState::Scheduled && m.not_before_ms.is_some_and(|nb| nb <= now_ms) {
                m.state = ShredMarkState::Executed;
                m.executed_at_ms = Some(now_ms);
                executed.push(m.key_id);
            }
        }
        for &kid in &executed {
            self.keys.executed_tombstones.insert(kid);
            if let Some(rec) = self.keys.records.get_mut(&kid) {
                rec.key_record = None;
            }
        }
        executed
    }

    pub fn handle_snapshot_put(
        &mut self,
        epoch: JournalEpoch,
        covers_seq: i64,
        snapshot_id: SnapshotId,
        bytes: Vec<u8>,
    ) -> Result<(), SimRelayError> {
        if epoch != self.epoch {
            return Err(SimRelayError::new(ErrorCode::CasMismatch, None));
        }
        if let Some(latest) = self.phone_snapshots.iter().rev().find(|s| s.epoch == epoch) {
            if covers_seq <= latest.covers_seq {
                return Err(SimRelayError::new(ErrorCode::CasMismatch, None));
            }
        }
        self.phone_snapshots.push(StoredPhoneSnapshot {
            epoch,
            covers_seq,
            snapshot_id,
            bytes,
        });
        while self.phone_snapshots.len() > 2 {
            self.phone_snapshots.remove(0);
        }
        Ok(())
    }

    pub fn handle_snapshot_get(&self) -> Option<&StoredPhoneSnapshot> {
        self.phone_snapshots.iter().rev().find(|s| s.epoch == self.epoch)
    }

    pub fn handle_pull(
        &self,
        since_seq: i64,
        limit: usize,
    ) -> (JournalEpoch, Vec<RemoteEnvelopeRow>, String, i64, bool) {
        let matching: Vec<RemoteEnvelopeRow> = self
            .ops
            .iter()
            .filter(|o| o.seq > since_seq)
            .take(limit + 1)
            .cloned()
            .collect();
        let has_more = matching.len() > limit;
        let page = matching.into_iter().take(limit).collect();
        (self.epoch, page, self.keys.digest(), self.head_seq(), has_more)
    }

    pub fn handle_keys_post(
        &mut self,
        records: &[KeyRecordRow],
        keyring: Option<(u32, Vec<u8>)>,
        vault_header: Option<(i64, Vec<u8>)>,
    ) -> Result<(), ErrorCode> {
        let mut staged = self.keys.clone();
        for rec in records {
            if let Some(cur) = staged.records.get(&rec.key_id) {
                if cur.key_record.is_none() {
                    return Err(ErrorCode::KeyShredded);
                }
                if rec.wrap_gen == cur.wrap_gen && rec.key_record != cur.key_record {
                    return Err(ErrorCode::IntegrityError);
                }
            }
            staged.insert_record(rec.clone());
        }
        if let Some((gen, blob)) = keyring {
            if let Some((cur_gen, cur_blob)) = &staged.keyring_material {
                if gen < *cur_gen {
                    return Err(ErrorCode::CasMismatch);
                }
                if gen == *cur_gen && &blob != cur_blob {
                    return Err(ErrorCode::IntegrityError);
                }
            }
            staged.update_keyring_material(gen, blob);
        }
        if let Some((gen, blob)) = vault_header {
            if let Some((cur_gen, cur_blob)) = &staged.vault_header_material {
                if gen < *cur_gen {
                    return Err(ErrorCode::CasMismatch);
                }
                if gen == *cur_gen && &blob != cur_blob {
                    return Err(ErrorCode::IntegrityError);
                }
            }
            staged.update_vault_header_material(gen, blob);
        }
        self.keys = staged;
        Ok(())
    }

    /// Simulate DO PITR rollback to `keep_ops` prefix with a brand new `journal_epoch`.
    pub fn inject_pitr_rollback(&mut self, keep_ops: usize, new_epoch: JournalEpoch) {
        self.ops.truncate(keep_ops);
        self.op_index = self.ops.iter().map(|o| (o.op_id, o.seq)).collect();
        self.epoch = new_epoch;
        self.last_archived_seq = 0;
    }

    /// Simulate DO daily alarm writing permanent `MNA1` op archive + overwritten `latest.mnks`.
    pub fn run_daily_archive_alarm(
        &mut self,
        keyring: &RecoveryKeyringV1,
        now_ms: i64,
    ) -> Result<(), CoreError> {
        let new_rows: Vec<ArchivedOpRow> = self
            .ops
            .iter()
            .filter(|o| o.seq > self.last_archived_seq)
            .map(|o| ArchivedOpRow {
                seq: o.seq,
                op_id: o.op_id,
                key_id: o.key_id,
                device_id: o.device_id.clone(),
                created_at: o.created_at,
                envelope: o.envelope.clone(),
            })
            .collect();
        if !new_rows.is_empty() {
            let from_seq = new_rows.first().unwrap().seq;
            let to_seq = new_rows.last().unwrap().seq;
            let key = format!("archives/ops/{}/{from_seq:012}-{to_seq:012}.mna1", self.epoch);
            if !self.r2_op_archives.iter().any(|(k, _)| k == &key) {
                let hdr = ArchiveOpsHeaderV1 {
                    journal_epoch: self.epoch,
                    from_seq,
                    to_seq,
                    row_count: new_rows.len() as u32,
                    created_at_ms: now_ms,
                };
                let bytes = encode_mna1(&hdr, &new_rows)?;
                self.r2_op_archives.push((key, bytes));
            }
            self.last_archived_seq = to_seq;
        }
        let active_records: Vec<KeyRecordRow> = self
            .keys
            .records
            .values()
            .filter(|r| r.key_record.is_some())
            .cloned()
            .collect();
        let vault_header: Option<VaultHeaderV1> = self
            .keys
            .vault_header_material
            .as_ref()
            .and_then(|(_, blob)| rmp_serde::from_slice(blob).ok());
        let mnks_hdr = KeySnapshotHeaderV1 {
            created_at_ms: now_ms,
            keyring_gen: keyring.keyring_gen,
            record_count: active_records.len() as u32,
        };
        let mnks_body = KeySnapshotBodyV1 {
            keyring: keyring.clone(),
            vault_header,
            records: active_records,
            marks: self.keys.marks.values().cloned().collect(),
        };
        self.r2_latest_mnks = Some(encode_mnks(&mnks_hdr, &mnks_body)?);
        Ok(())
    }
}

struct SimNode {
    engine: EngineSnapshot,
    ulid_gen: MonotonicUlidGen,
    clock_skew_ms: i64,
    partitioned: bool,
    delay_keys: bool,
}

/// Complete deterministic multi-node simulation cluster.
pub struct SimCluster {
    pub seed: SimSeed,
    rng: DetRng,
    now_ms: u64,
    recovery_words: String,
    keyring: RecoveryKeyringV1,
    current_smk: (SmkKid, Zeroizing<[u8; 32]>),
    nodes: Vec<SimNode>,
    pub relay: SimRelay,
    default_buffer: BufferId,
    known_blocks: Vec<BlockId>,
    /// Tracks committed content tags (`tag_i -> (block_id, op_id)`) for `INV-SYNC-2`.
    committed_tags: Vec<(String, BlockId, OpId)>,
}

#[derive(Clone, Debug)]
pub struct SimReport {
    pub seed: SimSeed,
    pub total_ops_committed: usize,
    pub pitr_rollbacks: usize,
    pub smk_rotations: usize,
    pub tamper_rejections: usize,
    pub blocks_restored_offline: usize,
}

impl SimCluster {
    pub fn new(seed: SimSeed) -> Self {
        let mut rng = DetRng::new(seed);
        let now_ms = 1_795_521_600_000u64;
        let entropy = rng.bytes_32();
        let (kp, recovery_words) = RecoveryKeypair::from_entropy(&entropy).expect("valid entropy");

        let mut init_gen = MonotonicUlidGen::new();
        let smk1_kid = SmkKid::from_ulid(init_gen.next(now_ms, rng.bytes_10()));
        let smk1 = Zeroizing::new(rng.bytes_32());
        let sealed1 = seal_mnrs(
            &kp.recovery_pk,
            MNRS_KIND_SMK,
            smk1_kid.as_bytes(),
            &smk1,
            rng.bytes_32(),
            rng.bytes_24(),
        )
        .expect("seal smk1");

        let keyring = RecoveryKeyringV1 {
            v: 1,
            recovery_kid: kp.recovery_kid,
            recovery_pk: kp.recovery_pk,
            keyring_gen: 1,
            current_smk_kid: smk1_kid,
            smk_entries: vec![sealed1],
        };
        let keyring_bytes = rmp_serde::to_vec_named(&keyring).expect("msgpack keyring");

        let epoch = JournalEpoch::from_random_bytes(rng.bytes_16());
        let mut relay = SimRelay::new(epoch);
        relay.keys.update_keyring_material(1, keyring_bytes.clone());

        let device_names = ["dev_mac00001", "dev_lin00002", "dev_box00003"];
        let mut nodes = Vec::new();
        for (idx, name) in device_names.iter().enumerate() {
            let dev = DeviceId::parse(*name).unwrap();
            let mut engine = EngineSnapshot::new(dev, now_ms);
            engine.smks.insert(smk1_kid, smk1.clone());
            engine.keys.update_keyring_material(1, keyring_bytes.clone());
            // Node 0 starts bootstrapped; nodes 1 & 2 bootstrap via sync (tests INV-SYNC-3!)
            if idx == 0 {
                engine.bootstrap_completed = true;
                engine.journal_epoch = Some(epoch);
            }
            // Inject deliberate clock skew on node 2 (+8 minutes) to prove HLC skew tolerance
            let skew = if idx == 2 { 480_000 } else { 0 };
            nodes.push(SimNode {
                engine,
                ulid_gen: MonotonicUlidGen::new(),
                clock_skew_ms: skew,
                partitioned: false,
                delay_keys: false,
            });
        }

        // Create default "scratch" buffer on node 0
        let buf_id = BufferId::from_ulid(nodes[0].ulid_gen.next(now_ms, rng.bytes_10()));
        let mut cluster = Self {
            seed,
            rng,
            now_ms,
            recovery_words,
            keyring,
            current_smk: (smk1_kid, smk1),
            nodes,
            relay,
            default_buffer: buf_id,
            known_blocks: Vec::new(),
            committed_tags: Vec::new(),
        };
        cluster.create_buffer_on_node(0, buf_id, "scratch");
        cluster
    }

    fn node_now(&self, node_idx: usize) -> u64 {
        (self.now_ms as i64 + self.nodes[node_idx].clock_skew_ms).max(1) as u64
    }

    fn create_buffer_on_node(&mut self, node_idx: usize, buf_id: BufferId, name: &str) {
        let now = self.node_now(node_idx);
        let op_id = OpId::from_ulid(self.nodes[node_idx].ulid_gen.next(now, self.rng.bytes_10()));
        let key_id = KeyId::from_ulid(self.nodes[node_idx].ulid_gen.next(now, self.rng.bytes_10()));
        let bdek = self.rng.bytes_32();
        let (smk_kid, smk) = (self.current_smk.0, self.current_smk.1.clone());
        let pos = fractional_index::between(None, None, self.rng.bytes_4()).unwrap();

        let mut clock = HlcClock::from_last(self.nodes[node_idx].engine.hlc.clone());
        let hlc = clock.tick(now);
        self.nodes[node_idx].engine.hlc = hlc.clone();

        let name_mnb1 =
            encrypt_mnb1(buf_id.as_bytes(), op_id, key_id, &bdek, name, self.rng.bytes_24()).unwrap();
        let krec = KeyRecordV1 {
            v: 1,
            key_id,
            block_id: buf_id.0,
            tier: 1,
            created_hlc: hlc.canonical_string(),
            created_by: self.nodes[node_idx].engine.device_id.clone(),
            bdek: bdek.to_vec(),
        };
        let mnr1 = encrypt_mnr1(
            smk_kid,
            &smk,
            self.keyring.keyring_gen,
            &krec,
            self.rng.bytes_24(),
        )
        .unwrap();
        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Buffer,
            entity_id: buf_id.to_string(),
            op_type: OpType::Create,
            parent_op_ids: vec![],
            hlc: hlc.clone(),
            actor: "human".into(),
            body: OpBodyV1::BufferMeta {
                key_id,
                name_mnb1: Some(name_mnb1),
                position: Some(pos),
            },
        };
        let mns1 = encrypt_mns1(
            smk_kid,
            &smk,
            op_id,
            &self.nodes[node_idx].engine.device_id,
            &inner,
            self.rng.bytes_24(),
        )
        .unwrap();

        self.nodes[node_idx].engine.keys.insert_record(KeyRecordRow {
            key_id,
            wrap_gen: self.keyring.keyring_gen,
            key_record: Some(mnr1),
            created_at_ms: now as i64,
        });
        let dev_id = self.nodes[node_idx].engine.device_id.clone();
        self.nodes[node_idx].engine.ops.insert(
            op_id,
            LocalOpRecord {
                op_id,
                server_seq: None,
                sync_blocked_reason: None,
                device_id: dev_id,
                entity_type: EntityType::Buffer,
                entity_id: buf_id.to_string(),
                parent_op_ids: vec![],
                op_type: OpType::Create,
                hlc,
                actor: "human".into(),
                key_id: Some(key_id),
                smk_kid,
                envelope: mns1,
                created_at_ms: now as i64,
            },
        );
    }

    fn create_block_on_node(&mut self, node_idx: usize, tag: &str) -> BlockId {
        let now = self.node_now(node_idx);
        let blk_id = BlockId::from_ulid(self.nodes[node_idx].ulid_gen.next(now, self.rng.bytes_10()));
        let op_id = OpId::from_ulid(self.nodes[node_idx].ulid_gen.next(now, self.rng.bytes_10()));
        let key_id = KeyId::from_ulid(self.nodes[node_idx].ulid_gen.next(now, self.rng.bytes_10()));
        let bdek = self.rng.bytes_32();
        let (smk_kid, smk) = (self.current_smk.0, self.current_smk.1.clone());
        let pos = fractional_index::between(None, None, self.rng.bytes_4()).unwrap();

        let mut clock = HlcClock::from_last(self.nodes[node_idx].engine.hlc.clone());
        let hlc = clock.tick(now);
        self.nodes[node_idx].engine.hlc = hlc.clone();

        let mnb1 = encrypt_mnb1(blk_id.as_bytes(), op_id, key_id, &bdek, tag, self.rng.bytes_24()).unwrap();
        let krec = KeyRecordV1 {
            v: 1,
            key_id,
            block_id: blk_id.0,
            tier: 1,
            created_hlc: hlc.canonical_string(),
            created_by: self.nodes[node_idx].engine.device_id.clone(),
            bdek: bdek.to_vec(),
        };
        let mnr1 = encrypt_mnr1(
            smk_kid,
            &smk,
            self.keyring.keyring_gen,
            &krec,
            self.rng.bytes_24(),
        )
        .unwrap();
        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: blk_id.to_string(),
            op_type: OpType::Create,
            parent_op_ids: vec![],
            hlc: hlc.clone(),
            actor: "human".into(),
            body: OpBodyV1::BlockContent {
                buffer_id: Some(self.default_buffer),
                position: Some(pos),
                lang: Some("markdown".into()),
                public_hint: None,
                tier: 1,
                key_id,
                mnb1,
            },
        };
        let mns1 = encrypt_mns1(
            smk_kid,
            &smk,
            op_id,
            &self.nodes[node_idx].engine.device_id,
            &inner,
            self.rng.bytes_24(),
        )
        .unwrap();

        self.nodes[node_idx].engine.keys.insert_record(KeyRecordRow {
            key_id,
            wrap_gen: self.keyring.keyring_gen,
            key_record: Some(mnr1),
            created_at_ms: now as i64,
        });
        let dev_id = self.nodes[node_idx].engine.device_id.clone();
        self.nodes[node_idx].engine.ops.insert(
            op_id,
            LocalOpRecord {
                op_id,
                server_seq: None,
                sync_blocked_reason: None,
                device_id: dev_id,
                entity_type: EntityType::Block,
                entity_id: blk_id.to_string(),
                parent_op_ids: vec![],
                op_type: OpType::Create,
                hlc,
                actor: "human".into(),
                key_id: Some(key_id),
                smk_kid,
                envelope: mns1,
                created_at_ms: now as i64,
            },
        );
        self.known_blocks.push(blk_id);
        self.committed_tags.push((tag.to_string(), blk_id, op_id));
        blk_id
    }

    fn update_block_on_node(&mut self, node_idx: usize, blk_id: BlockId, tag: &str) -> bool {
        if self.nodes[node_idx]
            .engine
            .check_bootstrap_gate(&blk_id.to_string(), OpType::Update)
            .is_err()
        {
            return false;
        }
        let Some(mat) = self.nodes[node_idx].engine.materialize_block_view(blk_id) else {
            return false;
        };
        if mat.state != BlockState::Active {
            return false;
        }
        let parents = mat.head_op_ids();
        // Reuse existing available key_id for this block
        let existing_key = self.nodes[node_idx]
            .engine
            .ops
            .values()
            .find(|o| o.entity_id == blk_id.to_string() && o.key_id.is_some())
            .and_then(|o| o.key_id);
        let Some(key_id) = existing_key else {
            return false;
        };
        let Some(krec) = self.nodes[node_idx].engine.unwrap_key_record(key_id) else {
            return false;
        };
        if krec.bdek.len() != 32 {
            return false;
        }
        let mut bdek = [0u8; 32];
        bdek.copy_from_slice(&krec.bdek);

        let now = self.node_now(node_idx);
        let op_id = OpId::from_ulid(self.nodes[node_idx].ulid_gen.next(now, self.rng.bytes_10()));
        let (smk_kid, smk) = (self.current_smk.0, self.current_smk.1.clone());
        let mut clock = HlcClock::from_last(self.nodes[node_idx].engine.hlc.clone());
        let hlc = clock.tick(now);
        self.nodes[node_idx].engine.hlc = hlc.clone();

        let mnb1 = encrypt_mnb1(blk_id.as_bytes(), op_id, key_id, &bdek, tag, self.rng.bytes_24()).unwrap();
        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: blk_id.to_string(),
            op_type: OpType::Update,
            parent_op_ids: parents.clone(),
            hlc: hlc.clone(),
            actor: "human".into(),
            body: OpBodyV1::BlockContent {
                buffer_id: None,
                position: None,
                lang: None,
                public_hint: None,
                tier: 1,
                key_id,
                mnb1,
            },
        };
        let mns1 = encrypt_mns1(
            smk_kid,
            &smk,
            op_id,
            &self.nodes[node_idx].engine.device_id,
            &inner,
            self.rng.bytes_24(),
        )
        .unwrap();

        let dev_id = self.nodes[node_idx].engine.device_id.clone();
        self.nodes[node_idx].engine.ops.insert(
            op_id,
            LocalOpRecord {
                op_id,
                server_seq: None,
                sync_blocked_reason: None,
                device_id: dev_id,
                entity_type: EntityType::Block,
                entity_id: blk_id.to_string(),
                parent_op_ids: parents,
                op_type: OpType::Update,
                hlc,
                actor: "human".into(),
                key_id: Some(key_id),
                smk_kid,
                envelope: mns1,
                created_at_ms: now as i64,
            },
        );
        self.committed_tags.push((tag.to_string(), blk_id, op_id));
        true
    }

    fn delete_block_on_node(&mut self, node_idx: usize, blk_id: BlockId) -> bool {
        if self.nodes[node_idx]
            .engine
            .check_bootstrap_gate(&blk_id.to_string(), OpType::Delete)
            .is_err()
        {
            return false;
        }
        let Some(mat) = self.nodes[node_idx].engine.materialize_block_view(blk_id) else {
            return false;
        };
        if mat.state != BlockState::Active {
            return false;
        }
        let parents = mat.head_op_ids();
        let now = self.node_now(node_idx);
        let op_id = OpId::from_ulid(self.nodes[node_idx].ulid_gen.next(now, self.rng.bytes_10()));
        let (smk_kid, smk) = (self.current_smk.0, self.current_smk.1.clone());
        let mut clock = HlcClock::from_last(self.nodes[node_idx].engine.hlc.clone());
        let hlc = clock.tick(now);
        self.nodes[node_idx].engine.hlc = hlc.clone();

        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: blk_id.to_string(),
            op_type: OpType::Delete,
            parent_op_ids: parents.clone(),
            hlc: hlc.clone(),
            actor: "human".into(),
            body: OpBodyV1::Tombstone {
                deleted_at_ms: now as i64,
            },
        };
        // Note: DELETE has outer key_id = None (16 zero bytes only inside MNS1 AAD!)
        let mns1 = encrypt_mns1(
            smk_kid,
            &smk,
            op_id,
            &self.nodes[node_idx].engine.device_id,
            &inner,
            self.rng.bytes_24(),
        )
        .unwrap();

        let dev_id = self.nodes[node_idx].engine.device_id.clone();
        self.nodes[node_idx].engine.ops.insert(
            op_id,
            LocalOpRecord {
                op_id,
                server_seq: None,
                sync_blocked_reason: None,
                device_id: dev_id,
                entity_type: EntityType::Block,
                entity_id: blk_id.to_string(),
                parent_op_ids: parents,
                op_type: OpType::Delete,
                hlc,
                actor: "human".into(),
                key_id: None,
                smk_kid,
                envelope: mns1,
                created_at_ms: now as i64,
            },
        );
        true
    }

    fn rotate_smk(&mut self) {
        let now = self.now_ms;
        let new_kid = SmkKid::from_ulid(self.nodes[0].ulid_gen.next(now, self.rng.bytes_10()));
        let new_smk = Zeroizing::new(self.rng.bytes_32());
        let sealed = seal_mnrs(
            &self.keyring.recovery_pk,
            MNRS_KIND_SMK,
            new_kid.as_bytes(),
            &new_smk,
            self.rng.bytes_32(),
            self.rng.bytes_24(),
        )
        .unwrap();
        self.keyring.keyring_gen += 1;
        self.keyring.current_smk_kid = new_kid;
        self.keyring.smk_entries.push(sealed);
        self.current_smk = (new_kid, new_smk.clone());

        let kr_bytes = rmp_serde::to_vec_named(&self.keyring).unwrap();
        // Distribute new SMK gen while permanently retaining all old SMK generations
        for n in &mut self.nodes {
            n.engine.smks.insert(new_kid, new_smk.clone());
            n.engine
                .keys
                .update_keyring_material(self.keyring.keyring_gen, kr_bytes.clone());
        }
        self.relay
            .keys
            .update_keyring_material(self.keyring.keyring_gen, kr_bytes);
    }

    /// Drive one full sync round for `node_idx` against `self.relay`, respecting partition/delay flags.
    fn sync_node(&mut self, node_idx: usize, tamper_once: &mut bool) -> usize {
        if self.nodes[node_idx].partitioned {
            return 0;
        }
        let mut tamper_alerts = 0usize;
        let mut queue = VecDeque::from([SyncEvent::StartSync]);
        let mut guard = 0usize;

        while let Some(ev) = queue.pop_front() {
            guard += 1;
            if guard > 64 {
                break;
            }
            let (muts, cmds) = step(&self.nodes[node_idx].engine, ev).expect("step ok");
            for m in &muts {
                if matches!(m, StoreMutation::IntegrityAlert { .. }) {
                    tamper_alerts += 1;
                }
            }
            self.nodes[node_idx].engine.apply_mutations(&muts);

            for cmd in cmds {
                match cmd {
                    SyncCommand::HttpPull { since_seq, limit } => {
                        let (epoch, mut page, digest, head_seq, has_more) =
                            self.relay.handle_pull(since_seq, limit as usize);
                        // Optionally inject a 1-bit tamper on a synthetic duplicate to verify INV-SYNC-5
                        if *tamper_once && !page.is_empty() {
                            *tamper_once = false;
                            let mut corrupted = page[0].clone();
                            let flip_pos = corrupted.envelope.len() - 5;
                            corrupted.envelope[flip_pos] ^= 0x01;
                            // Deliver tampered copy first; real copy also present -> tampered rejected, real succeeds
                            page.insert(0, corrupted);
                        }
                        queue.push_back(SyncEvent::PullResponse {
                            now_ms: self.node_now(node_idx),
                            epoch,
                            ops: page,
                            keys_digest: digest,
                            head_seq,
                            has_more,
                        });
                    }
                    SyncCommand::HttpPush(req) => {
                        let dev = self.nodes[node_idx].engine.device_id.clone();
                        let cancelled_keys = req.cancel_key_ids.clone();
                        match self.relay.handle_push(&dev, &req, self.now_ms as i64) {
                            Ok(ok) => {
                                queue.push_back(SyncEvent::PushAcked {
                                    epoch: ok.epoch,
                                    acked: ok.acked,
                                    shred_results: ok.shred_results,
                                    cancelled_keys,
                                    head_seq: ok.head_seq,
                                });
                            }
                            Err(err) if err.code == ErrorCode::CasMismatch => {
                                queue.push_back(SyncEvent::PushEpochMismatch {
                                    remote_epoch: self.relay.epoch,
                                });
                            }
                            Err(err)
                                if matches!(
                                    err.code,
                                    ErrorCode::ShredStale
                                        | ErrorCode::KeyPendingShred
                                        | ErrorCode::KeyShredded
                                ) =>
                            {
                                queue.push_back(SyncEvent::PushKeyRaceError {
                                    code: err.code,
                                    key_id: err.key_id,
                                });
                            }
                            Err(e) => panic!("unexpected relay push error on seed {:?}: {:?}", self.seed, e),
                        }
                    }
                    SyncCommand::SyncKeyTable(dto) => {
                        if self.nodes[node_idx].delay_keys {
                            continue;
                        }
                        for rec in dto.push_records {
                            self.relay.keys.insert_record(rec);
                        }
                        if let Some((gen, blob)) = dto.keyring_material {
                            self.relay.keys.update_keyring_material(gen, blob);
                        }
                        if let Some((gen, blob)) = dto.vault_header_material {
                            self.relay.keys.update_vault_header_material(gen, blob);
                        }
                        queue.push_back(SyncEvent::KeyTableResponse {
                            records: self.relay.keys.records.values().cloned().collect(),
                            marks: self.relay.keys.marks.values().cloned().collect(),
                            keyring: self.relay.keys.keyring_material.clone(),
                            vault_header: self.relay.keys.vault_header_material.clone(),
                            server_now_ms: self.now_ms as i64,
                        });
                    }
                }
            }
        }
        tamper_alerts
    }

    /// Run a full randomized fault-injection workload and assert ALL M1 invariants:
    /// `INV-SYNC-1`, `INV-SYNC-2`, `INV-SYNC-3`, `INV-SYNC-5`, `INV-KEY-LIVENESS`, `INV-RECOVERY`.
    pub fn run_and_verify(&mut self, steps: usize) -> SimReport {
        // First verify INV-SYNC-3 Bootstrap Gate on unbootstrapped node 1 BEFORE first sync
        let seed_blk = self.create_block_on_node(0, "TAG_INIT_0");
        self.sync_node(0, &mut false);
        assert!(
            self.nodes[1]
                .engine
                .check_bootstrap_gate(&seed_blk.to_string(), OpType::Update)
                .is_err(),
            "INV-SYNC-3 violated: unbootstrapped node allowed remote UPDATE!"
        );

        let mut pitr_rollbacks = 0usize;
        let mut smk_rotations = 0usize;
        let mut tamper_rejections = 0usize;
        let mut tamper_once = true;

        for step_i in 0..steps {
            self.now_ms += 100 + (self.rng.next_u64() % 5_000);
            let action = self.rng.next_usize(100);
            let node_idx = self.rng.next_usize(self.nodes.len());

            match action {
                0..=24 => {
                    let tag = format!("TAG_C_{step_i}_{node_idx}");
                    self.create_block_on_node(node_idx, &tag);
                }
                25..=54 if !self.known_blocks.is_empty() => {
                    let b = self.known_blocks[self.rng.next_usize(self.known_blocks.len())];
                    let tag = format!("TAG_U_{step_i}_{node_idx}");
                    self.update_block_on_node(node_idx, b, &tag);
                }
                55..=64 if !self.known_blocks.is_empty() => {
                    let b = self.known_blocks[self.rng.next_usize(self.known_blocks.len())];
                    self.delete_block_on_node(node_idx, b);
                }
                65..=74 => {
                    self.nodes[node_idx].partitioned = !self.nodes[node_idx].partitioned;
                }
                75..=81 => {
                    self.nodes[node_idx].delay_keys = !self.nodes[node_idx].delay_keys;
                }
                82..=85 if !self.relay.ops.is_empty() => {
                    // Inject DO PITR rollback to a random earlier prefix + new epoch!
                    let keep = self.rng.next_usize(self.relay.ops.len());
                    let new_epoch = JournalEpoch::from_random_bytes(self.rng.bytes_16());
                    self.relay.inject_pitr_rollback(keep, new_epoch);
                    pitr_rollbacks += 1;
                }
                86..=88 => {
                    self.rotate_smk();
                    smk_rotations += 1;
                }
                _ => {
                    tamper_rejections += self.sync_node(node_idx, &mut tamper_once);
                }
            }
        }

        // Heal all partitions & key delays, then run two full convergence rounds across all nodes
        for n in &mut self.nodes {
            n.partitioned = false;
            n.delay_keys = false;
        }
        for _ in 0..3 {
            for idx in 0..self.nodes.len() {
                tamper_rejections += self.sync_node(idx, &mut tamper_once);
            }
        }

        // ---- ASSERT INV-SYNC-1 (Strong Eventual Convergence) ----
        let ref_blocks = self.nodes[0].engine.all_blocks();
        let ref_buffers = self.nodes[0].engine.all_buffers();
        let ref_keys_digest = self.nodes[0].engine.keys.digest();

        for idx in 1..self.nodes.len() {
            assert_eq!(
                self.nodes[idx].engine.all_buffers(),
                ref_buffers,
                "INV-SYNC-1 buffer divergence on seed {:?} node {}",
                self.seed,
                idx
            );
            assert_eq!(
                self.nodes[idx].engine.all_blocks(),
                ref_blocks,
                "INV-SYNC-1 block divergence on seed {:?} node {}",
                self.seed,
                idx
            );
            assert_eq!(
                self.nodes[idx].engine.keys.digest(),
                ref_keys_digest,
                "INV-SYNC-1 key table divergence on seed {:?} node {}",
                self.seed,
                idx
            );
        }

        // ---- ASSERT INV-KEY-LIVENESS ----
        for (idx, n) in self.nodes.iter().enumerate() {
            let (ok, missing) = self_check_key_liveness(&n.engine.all_blocks(), &n.engine.keys);
            assert!(
                ok,
                "INV-KEY-LIVENESS failed on seed {:?} node {}: missing {:?}",
                self.seed, idx, missing
            );
        }

        // ---- ASSERT INV-SYNC-2 (Zero Silent Character Evaporation) ----
        // Build global parent set across node 0's complete converged op log
        let all_ops = &self.nodes[0].engine.ops;
        let mut overwritten: BTreeSet<OpId> = BTreeSet::new();
        for op in all_ops.values() {
            for p in &op.parent_op_ids {
                overwritten.insert(*p);
            }
        }
        for (tag, blk_id, op_id) in &self.committed_tags {
            assert!(
                all_ops.contains_key(op_id),
                "INV-SYNC-2 / INV-SYNC-5: committed op {} ({}) vanished after sync/PITR on seed {:?}!",
                op_id,
                tag,
                self.seed
            );
            if !overwritten.contains(op_id) {
                let mat = self.nodes[0]
                    .engine
                    .materialize_block_view(*blk_id)
                    .expect("block must exist");
                let found = mat
                    .leaves
                    .iter()
                    .any(|l| l.op_id == *op_id && matches!(&l.body, LeafBody::Plaintext(s) if s == tag));
                assert!(
                    found,
                    "INV-SYNC-2: non-overwritten tag '{}' (op {}) missing from materialized leaves on seed {:?}!",
                    tag, op_id, self.seed
                );
            }
        }

        // ---- ASSERT INV-RECOVERY (Zero-Device Offline Restore from R2 MNA1 + latest.mnks + 24 Words) ----
        self.relay
            .run_daily_archive_alarm(&self.keyring, self.now_ms as i64)
            .expect("archive alarm ok");
        let restored = offline_restore_from_r2(
            &self.recovery_words,
            &self.relay.r2_op_archives,
            self.relay.r2_latest_mnks.as_ref().expect("latest.mnks present"),
        )
        .expect("INV-RECOVERY offline restore must succeed");
        assert_eq!(
            restored.all_buffers(),
            ref_buffers,
            "INV-RECOVERY buffer mismatch on seed {:?}",
            self.seed
        );
        assert_eq!(
            restored.all_blocks(),
            ref_blocks,
            "INV-RECOVERY block mismatch on seed {:?}",
            self.seed
        );

        SimReport {
            seed: self.seed,
            total_ops_committed: all_ops.len(),
            pitr_rollbacks,
            smk_rotations,
            tamper_rejections,
            blocks_restored_offline: restored.all_blocks().len(),
        }
    }
}

/// Pure offline disaster recovery (`mynote restore --from-archive <local-dir>` core logic, `INV-RECOVERY`).
pub fn offline_restore_from_r2(
    recovery_words: &str,
    mna1_segments: &[(String, Vec<u8>)],
    latest_mnks_bytes: &[u8],
) -> Result<EngineSnapshot, CoreError> {
    let kp = RecoveryKeypair::from_mnemonic_words(recovery_words)?;
    let (_, mnks_body) = decode_mnks(latest_mnks_bytes)?;
    let unsealed_smks = kp.unseal_all_smks(&mnks_body.keyring)?;

    let mut snap = EngineSnapshot::new(DeviceId::parse("dev_restore0001")?, 0);
    snap.bootstrap_completed = true;
    for (kid, smk) in unsealed_smks {
        snap.smks.insert(kid, smk);
    }
    for rec in mnks_body.records {
        snap.keys.insert_record(rec);
    }
    for mark in mnks_body.marks {
        snap.keys.insert_mark(mark);
    }
    let kr_bytes = rmp_serde::to_vec_named(&mnks_body.keyring).map_err(|e| {
        CoreError::new(
            ErrorCode::IntegrityError,
            e.to_string(),
            "Corrupt RecoveryKeyringV1 inside latest.mnks",
        )
    })?;
    snap.keys
        .update_keyring_material(mnks_body.keyring.keyring_gen, kr_bytes);
    if let Some(vh) = mnks_body.vault_header {
        let vh_bytes = rmp_serde::to_vec_named(&vh).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                e.to_string(),
                "Corrupt VaultHeaderV1 inside latest.mnks",
            )
        })?;
        snap.keys.update_vault_header_material(vh.updated_at_ms, vh_bytes);
    }

    for (_, seg_bytes) in mna1_segments {
        let (_, rows) = decode_mna1(seg_bytes)?;
        for row in rows {
            let smk_kid = SmkKid::from_bytes(peek_envelope_kid(MAGIC_MNS1, &row.envelope)?);
            let smk = snap.smks.get(&smk_kid).ok_or_else(|| {
                CoreError::new(
                    ErrorCode::KeyMissing,
                    format!("archived op {} needs unknown SMK {smk_kid}", row.op_id),
                    "Recovery keyring is missing an older SMK generation",
                )
            })?;
            let inner = decrypt_mns1(smk_kid, smk, row.op_id, &row.device_id, row.key_id, &row.envelope)?;
            snap.ops.entry(row.op_id).or_insert(LocalOpRecord {
                op_id: row.op_id,
                server_seq: None,
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
            });
        }
    }

    Ok(snap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::decrypt_mnb1;
    use crate::ids::{MarkId, VkekKid};
    use crate::snapshot::{decode_mnp1, pack_state_snapshot, MobileReadState};
    use crate::sync::OutboxKeyAction;
    use crate::vault::{
        create_vault_header, unlock_vault_with_passphrase, unseal_vault_with_recovery, T_GRACE_DEFAULT_MS,
    };
    use std::path::Path;

    #[test]
    fn replay_all_active_regression_seeds_from_evals() {
        // Read-only replay of evals/seeds/regression_seeds.txt (never modifies evals/)
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let seeds_path = Path::new(manifest_dir).join("../../evals/seeds/regression_seeds.txt");
        let text = std::fs::read_to_string(&seeds_path).expect("regression_seeds.txt readable");
        let mut replayed = 0usize;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let hex_tok = trimmed.split_whitespace().next().unwrap();
            let raw = hex_tok.strip_prefix("0x").unwrap_or(hex_tok);
            let seed_val = u64::from_str_radix(raw, 16).expect("valid hex u64 seed");
            let mut cluster = SimCluster::new(SimSeed(seed_val));
            let report = cluster.run_and_verify(80);
            assert!(report.total_ops_committed > 0);
            assert!(report.tamper_rejections >= 1);
            replayed += 1;
        }
        assert!(
            replayed >= 3,
            "expected at least 3 active regression seeds, got {replayed}"
        );
    }

    #[test]
    fn dst_random_seeds_pass_all_m1_invariants_including_pitr_rotation_and_offline_recovery() {
        let count: u64 = std::env::var("MYNOTE_DST_SEEDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(50);
        for i in 1..=count {
            let seed = SimSeed(0x2026_1124_0000_0000 ^ (i.wrapping_mul(0x9E37_79B9_7F4A_7C15)));
            let mut cluster = SimCluster::new(seed);
            let report = cluster.run_and_verify(60);
            assert!(report.total_ops_committed >= 2);
            assert!(report.tamper_rejections >= 1);
        }
    }

    #[test]
    fn dst_m2_vault_shred_update_wins_and_mobile_snapshot_invariants() {
        let mut cluster = SimCluster::new(SimSeed(0x2026_1125_0000_0002));
        // 1. Initialize VaultHeaderV1 on node 0 with passphrase + unified 24-word recovery_pk
        let vkek_kid = VkekKid::from_ulid(
            cluster.nodes[0]
                .ulid_gen
                .next(cluster.now_ms, cluster.rng.bytes_10()),
        );
        let vkek = cluster.rng.bytes_32();
        let vh = create_vault_header(
            b"m2-dst-vault-passphrase",
            &cluster.keyring.recovery_pk,
            vkek_kid,
            &vkek,
            cluster.rng.bytes_16(),
            cluster.rng.bytes_24(),
            cluster.rng.bytes_32(),
            cluster.rng.bytes_24(),
            cluster.now_ms as i64,
        )
        .unwrap();
        let vh_bytes = rmp_serde::to_vec_named(&vh).unwrap();
        cluster.nodes[0]
            .engine
            .keys
            .update_vault_header_material(vh.updated_at_ms, vh_bytes);
        let unlocked = unlock_vault_with_passphrase(b"m2-dst-vault-passphrase", &vh).unwrap();

        // 2. Create 3 blocks on node 0:
        //    b_shred: will be deleted + alarm-shredded after T_grace
        //    b_revive: deleted by node 0 while node 1 offline-edits -> Update-Wins auto-cancel!
        //    b_lock: locked to Tier 2 by node 0 (old Tier 1 key shredded) while node 1 stays synced
        let b_shred = cluster.create_block_on_node(0, "CANARY_TO_BE_SHREDDED");
        let b_revive = cluster.create_block_on_node(0, "REVIVE_BASE");
        let b_lock = cluster.create_block_on_node(0, "PLAINTEXT_BEFORE_LOCK");

        // Sync node 0 & node 1 so both are bootstrapped and see all 3 blocks
        cluster.sync_node(0, &mut false);
        cluster.sync_node(1, &mut false);
        cluster.sync_node(2, &mut false);

        // Publish an early MNP1 mobile snapshot at seq = relay.head_seq()
        let snap1_id = SnapshotId::from_ulid(
            cluster.nodes[0]
                .ulid_gen
                .next(cluster.now_ms, cluster.rng.bytes_10()),
        );
        let (_, snap1_bytes) = pack_state_snapshot(
            &cluster.nodes[0].engine,
            snap1_id,
            cluster.relay.head_seq(),
            cluster.current_smk.0,
            &cluster.current_smk.1,
            cluster.now_ms as i64,
            cluster.rng.bytes_24(),
            cluster.rng.bytes_24(),
        )
        .unwrap();
        cluster
            .relay
            .handle_snapshot_put(
                cluster.relay.epoch,
                cluster.relay.head_seq(),
                snap1_id,
                snap1_bytes,
            )
            .unwrap();

        // Partition node 1; node 1 offline-edits b_revive!
        cluster.nodes[1].partitioned = true;
        assert!(cluster.update_block_on_node(1, b_revive, "OFFLINE_REVIVED_CONTENT"));

        // Meanwhile node 0 deletes BOTH b_shred and b_revive and queues M2 shred marks
        let dev0_id = cluster.nodes[0].engine.device_id.clone();
        assert!(cluster.delete_block_on_node(0, b_shred));
        for kid in cluster.nodes[0]
            .engine
            .collect_entity_unshredded_keys(EntityType::Block, &b_shred.to_string())
        {
            let mid = MarkId::from_ulid(
                cluster.nodes[0]
                    .ulid_gen
                    .next(cluster.now_ms, cluster.rng.bytes_10()),
            );
            let seen_seq0 = cluster.nodes[0].engine.last_seq;
            cluster.nodes[0].engine.pending_shred_marks.push(ShredMarkRow {
                mark_id: mid,
                key_id: kid,
                seen_seq: seen_seq0,
                requested_by: dev0_id.clone(),
                requested_at_ms: cluster.now_ms as i64,
                grace_ms: T_GRACE_DEFAULT_MS,
                not_before_ms: None,
                state: ShredMarkState::PendingConfirm,
                confirmed_at_ms: None,
                cancelled_by: None,
                executed_at_ms: None,
            });
        }
        assert!(cluster.delete_block_on_node(0, b_revive));
        for kid in cluster.nodes[0]
            .engine
            .collect_entity_unshredded_keys(EntityType::Block, &b_revive.to_string())
        {
            let mid = MarkId::from_ulid(
                cluster.nodes[0]
                    .ulid_gen
                    .next(cluster.now_ms, cluster.rng.bytes_10()),
            );
            let seen_seq0 = cluster.nodes[0].engine.last_seq;
            cluster.nodes[0].engine.pending_shred_marks.push(ShredMarkRow {
                mark_id: mid,
                key_id: kid,
                seen_seq: seen_seq0,
                requested_by: dev0_id.clone(),
                requested_at_ms: cluster.now_ms as i64,
                grace_ms: T_GRACE_DEFAULT_MS,
                not_before_ms: None,
                state: ShredMarkState::PendingConfirm,
                confirmed_at_ms: None,
                cancelled_by: None,
                executed_at_ms: None,
            });
        }

        // Also lock b_lock to Tier 2 on node 0 + schedule shred of old Tier 1 key!
        let old_lock_keys = cluster.nodes[0]
            .engine
            .collect_entity_unshredded_keys(EntityType::Block, &b_lock.to_string());
        assert_eq!(old_lock_keys.len(), 1);
        let old_lock_kid = old_lock_keys[0];
        let lock_parents = cluster.nodes[0]
            .engine
            .materialize_block_view(b_lock)
            .unwrap()
            .head_op_ids();
        let lock_op_id = OpId::from_ulid(
            cluster.nodes[0]
                .ulid_gen
                .next(cluster.now_ms, cluster.rng.bytes_10()),
        );
        let lock_key_id = KeyId::from_ulid(
            cluster.nodes[0]
                .ulid_gen
                .next(cluster.now_ms, cluster.rng.bytes_10()),
        );
        let tier2_bdek = cluster.rng.bytes_32();
        let mnw1 = unlocked
            .wrap_bdek(lock_key_id, b_lock, &tier2_bdek, cluster.rng.bytes_24())
            .unwrap();
        let mnb1 = encrypt_mnb1(
            b_lock.as_bytes(),
            lock_op_id,
            lock_key_id,
            &tier2_bdek,
            "TIER2_SECRET_CANARY",
            cluster.rng.bytes_24(),
        )
        .unwrap();
        let mut clock = HlcClock::from_last(cluster.nodes[0].engine.hlc.clone());
        let lock_hlc = clock.tick(cluster.now_ms);
        cluster.nodes[0].engine.hlc = lock_hlc.clone();
        let lock_krec = KeyRecordV1 {
            v: 1,
            key_id: lock_key_id,
            block_id: b_lock.0,
            tier: 2,
            created_hlc: lock_hlc.canonical_string(),
            created_by: cluster.nodes[0].engine.device_id.clone(),
            bdek: mnw1,
        };
        let lock_mnr1 = encrypt_mnr1(
            cluster.current_smk.0,
            &cluster.current_smk.1,
            cluster.keyring.keyring_gen,
            &lock_krec,
            cluster.rng.bytes_24(),
        )
        .unwrap();
        let lock_inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: b_lock.to_string(),
            op_type: OpType::Lock,
            parent_op_ids: lock_parents.clone(),
            hlc: lock_hlc.clone(),
            actor: "human".into(),
            body: OpBodyV1::BlockContent {
                buffer_id: None,
                position: None,
                lang: None,
                public_hint: Some(Some("prod api secret".into())),
                tier: 2,
                key_id: lock_key_id,
                mnb1,
            },
        };
        let lock_mns1 = encrypt_mns1(
            cluster.current_smk.0,
            &cluster.current_smk.1,
            lock_op_id,
            &cluster.nodes[0].engine.device_id,
            &lock_inner,
            cluster.rng.bytes_24(),
        )
        .unwrap();
        cluster.nodes[0].engine.keys.insert_record(KeyRecordRow {
            key_id: lock_key_id,
            wrap_gen: cluster.keyring.keyring_gen,
            key_record: Some(lock_mnr1),
            created_at_ms: cluster.now_ms as i64,
        });
        let dev0 = cluster.nodes[0].engine.device_id.clone();
        cluster.nodes[0].engine.ops.insert(
            lock_op_id,
            LocalOpRecord {
                op_id: lock_op_id,
                server_seq: None,
                sync_blocked_reason: None,
                device_id: dev0.clone(),
                entity_type: EntityType::Block,
                entity_id: b_lock.to_string(),
                parent_op_ids: lock_parents,
                op_type: OpType::Lock,
                hlc: lock_hlc,
                actor: "human".into(),
                key_id: Some(lock_key_id),
                smk_kid: cluster.current_smk.0,
                envelope: lock_mns1,
                created_at_ms: cluster.now_ms as i64,
            },
        );
        let lock_mid = MarkId::from_ulid(
            cluster.nodes[0]
                .ulid_gen
                .next(cluster.now_ms, cluster.rng.bytes_10()),
        );
        let seen_seq0 = cluster.nodes[0].engine.last_seq;
        cluster.nodes[0].engine.pending_shred_marks.push(ShredMarkRow {
            mark_id: lock_mid,
            key_id: old_lock_kid,
            seen_seq: seen_seq0,
            requested_by: dev0,
            requested_at_ms: cluster.now_ms as i64,
            grace_ms: T_GRACE_DEFAULT_MS,
            not_before_ms: None,
            state: ShredMarkState::PendingConfirm,
            confirmed_at_ms: None,
            cancelled_by: None,
            executed_at_ms: None,
        });

        // Node 0 pushes deletes + LOCK + shred marks
        cluster.sync_node(0, &mut false);
        assert!(cluster.nodes[0].engine.pending_shred_marks.is_empty());

        // Node 1 reconnects! Its offline edit on b_revive MUST classify as CancelAndPush
        // and atomically cancel b_revive's shred mark (Update-Wins revival)!
        cluster.nodes[1].partitioned = false;
        let revive_op = cluster.nodes[1]
            .engine
            .ops
            .values()
            .find(|o| o.server_seq.is_none() && o.entity_id == b_revive.to_string())
            .cloned()
            .unwrap();
        cluster.sync_node(1, &mut false);
        assert!(
            cluster.nodes[1].engine.ops[&revive_op.op_id].server_seq.is_some(),
            "offline edit on trashed block must push via atomic Update-Wins cancel!"
        );

        // Advance virtual time past T_grace (7d + 1s) and fire DO shred alarm
        cluster.now_ms += (T_GRACE_DEFAULT_MS as u64) + 1_000;
        let executed = cluster.relay.run_shred_alarm(cluster.now_ms as i64);
        assert!(
            executed.contains(&old_lock_kid),
            "old Tier 1 key of LOCKed block must shred"
        );
        assert_eq!(
            executed.len(),
            2,
            "exactly b_shred's key and b_lock's old Tier 1 key must shred; b_revive's key MUST survive!"
        );

        // Idempotent second alarm run does nothing
        assert!(cluster.relay.run_shred_alarm(cluster.now_ms as i64).is_empty());

        // Sync all desktop nodes to observe Executed shreds
        for _ in 0..2 {
            for idx in 0..cluster.nodes.len() {
                cluster.sync_node(idx, &mut false);
            }
        }

        // Assert INV-SYNC-1 & INV-KEY-LIVENESS across all desktop nodes
        let ref_blocks = cluster.nodes[0].engine.all_blocks();
        let ref_buffers = cluster.nodes[0].engine.all_buffers();
        for (idx, node) in cluster.nodes.iter().enumerate() {
            assert_eq!(node.engine.all_blocks(), ref_blocks);
            assert_eq!(node.engine.all_buffers(), ref_buffers);
            let (ok, missing) = self_check_key_liveness(&node.engine.all_blocks(), &node.engine.keys);
            assert!(ok, "INV-KEY-LIVENESS failed on node {idx}: {missing:?}");
        }

        // Verify b_shred is SHREDDED, b_revive is ACTIVE with OFFLINE_REVIVED_CONTENT,
        // and b_lock is ACTIVE + is_locked == true with old Tier 1 key shredded!
        let m_shred = cluster.nodes[0].engine.materialize_block_view(b_shred).unwrap();
        assert_eq!(m_shred.state, BlockState::Shredded);

        let m_revive = cluster.nodes[0].engine.materialize_block_view(b_revive).unwrap();
        assert_eq!(m_revive.state, BlockState::Active);
        assert!(m_revive
            .leaves
            .iter()
            .any(|l| matches!(&l.body, LeafBody::Plaintext(s) if s == "OFFLINE_REVIVED_CONTENT")));

        let m_lock = cluster.nodes[0].engine.materialize_block_view(b_lock).unwrap();
        assert_eq!(m_lock.state, BlockState::Active);
        assert!(m_lock.is_locked);
        assert!(cluster.nodes[0].engine.keys.is_shredded(&old_lock_kid));

        // ---- ASSERT INV-SYNC-7: MobileReadState from early MNP1 + tail ops + /v1/keys ----
        let mut mobile = MobileReadState::new();
        let stored_snap = cluster.relay.handle_snapshot_get().unwrap();
        let (hdr, body) = decode_mnp1(&cluster.nodes[0].engine.smks, &stored_snap.bytes).unwrap();
        assert!(mobile.install_snapshot(hdr.clone(), body));
        let (_, tail_ops, _, _, _) = cluster.relay.handle_pull(hdr.covers_seq, 500);
        for row in &tail_ops {
            mobile
                .apply_tail_envelope(row, &cluster.nodes[0].engine.smks)
                .unwrap();
        }
        mobile.merge_key_table(&cluster.relay.keys, &cluster.nodes[0].engine.smks);

        // Mobile must NOT hold shredded block in cache, and MUST match desktop on all non-shredded blocks!
        assert!(!mobile.blocks.contains_key(&b_shred));
        let desktop_non_shred: Vec<_> = ref_blocks
            .iter()
            .filter(|b| b.state != BlockState::Shredded)
            .cloned()
            .collect();
        assert_eq!(
            mobile.all_non_shredded_blocks(&cluster.nodes[0].engine.smks),
            desktop_non_shred,
            "INV-SYNC-7 mobile projection must match desktop byte-for-byte for all non-shredded blocks"
        );

        // Next packed MNP1 snapshot after shred must exclude b_shred completely!
        let snap2_id = SnapshotId::from_ulid(
            cluster.nodes[0]
                .ulid_gen
                .next(cluster.now_ms, cluster.rng.bytes_10()),
        );
        let (_, snap2_bytes) = pack_state_snapshot(
            &cluster.nodes[0].engine,
            snap2_id,
            cluster.relay.head_seq(),
            cluster.current_smk.0,
            &cluster.current_smk.1,
            cluster.now_ms as i64,
            cluster.rng.bytes_24(),
            cluster.rng.bytes_24(),
        )
        .unwrap();
        let (_, snap2_body) = decode_mnp1(&cluster.nodes[0].engine.smks, &snap2_bytes).unwrap();
        assert!(!snap2_body.blocks.iter().any(|b| b.id == b_shred));

        // ---- ASSERT INV-RECOVERY including Tier 2 VKEK recovery via single 24-word bundle ----
        cluster
            .relay
            .run_daily_archive_alarm(&cluster.keyring, cluster.now_ms as i64)
            .unwrap();
        let restored = offline_restore_from_r2(
            &cluster.recovery_words,
            &cluster.relay.r2_op_archives,
            cluster.relay.r2_latest_mnks.as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(restored.all_blocks(), ref_blocks);
        // Unseal VaultHeaderV1 from restored snapshot using ONLY the 24 words (NO passphrase!)
        let (_, vh_raw) = restored
            .keys
            .vault_header_material
            .as_ref()
            .expect("vault_header restored from latest.mnks");
        let restored_vh: VaultHeaderV1 = rmp_serde::from_slice(vh_raw).unwrap();
        let kp = RecoveryKeypair::from_mnemonic_words(&cluster.recovery_words).unwrap();
        let recovered_vault = unseal_vault_with_recovery(&kp, &restored_vh).unwrap();
        // Decrypt Tier 2 locked block leaf using recovered VKEK!
        let restored_lock = restored.materialize_block_view(b_lock).unwrap();
        let LeafBody::Sealed { key_id, mnb1 } = &restored_lock.display_leaf().unwrap().body else {
            panic!("expected Sealed leaf");
        };
        let krec = restored.unwrap_key_record(*key_id).unwrap();
        let recovered_bdek = recovered_vault.unwrap_bdek(*key_id, b_lock, &krec.bdek).unwrap();
        let recovered_pt = decrypt_mnb1(
            b_lock.as_bytes(),
            restored_lock.display_op_id.unwrap(),
            *key_id,
            &recovered_bdek,
            mnb1,
        )
        .unwrap();
        assert_eq!(recovered_pt, "TIER2_SECRET_CANARY");

        // Also confirm classify_unpushed_op distinguishes rekey-intent vs delete-intent
        let dummy_rekey_op = LocalOpRecord {
            op_id: lock_op_id,
            server_seq: None,
            sync_blocked_reason: None,
            device_id: cluster.nodes[0].engine.device_id.clone(),
            entity_type: EntityType::Block,
            entity_id: b_lock.to_string(),
            parent_op_ids: vec![],
            op_type: OpType::Update,
            hlc: cluster.nodes[0].engine.hlc.clone(),
            actor: "human".into(),
            key_id: Some(old_lock_kid),
            smk_kid: cluster.current_smk.0,
            envelope: vec![],
            created_at_ms: 0,
        };
        assert_eq!(
            cluster.nodes[0].engine.classify_unpushed_op(&dummy_rekey_op),
            OutboxKeyAction::NeedsRekey { key_shredded: true }
        );
    }

    #[test]
    fn execute_shared_m1_relay_contract_scenario_on_sim_relay() {
        use base64::Engine;
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = Path::new(manifest_dir).join("../../tests/scenarios/m1_relay_contract.json");
        let raw = std::fs::read_to_string(&path).expect("shared scenario json readable");
        let doc: serde_json::Value = serde_json::from_str(&raw).expect("valid scenario json");

        let mut current_epoch = JournalEpoch::from_random_bytes([0x42; 16]);
        let mut previous_epoch = current_epoch;
        let mut relay = SimRelay::new(current_epoch);
        let b64 = base64::engine::general_purpose::STANDARD;

        for step in doc["steps"].as_array().expect("steps array") {
            let step_id = step["id"].as_str().unwrap();
            match step["action"].as_str().unwrap() {
                "pitr_rollback" => {
                    previous_epoch = current_epoch;
                    let keep = step["keep_seq"].as_u64().unwrap() as usize;
                    let next = JournalEpoch::parse(step["new_epoch"].as_str().unwrap()).unwrap();
                    relay.inject_pitr_rollback(keep, next);
                    current_epoch = next;
                }
                "push" => {
                    let dev = DeviceId::parse(step["as_device"].as_str().unwrap()).unwrap();
                    let expected_epoch = if step["use_epoch"].as_str() == Some("previous") {
                        previous_epoch
                    } else {
                        current_epoch
                    };
                    let key_records: Vec<KeyRecordRow> = step["key_records"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|k| KeyRecordRow {
                            key_id: KeyId::parse(k["key_id"].as_str().unwrap()).unwrap(),
                            wrap_gen: k["wrap_gen"].as_u64().unwrap() as u32,
                            key_record: Some(b64.decode(k["key_record_b64"].as_str().unwrap()).unwrap()),
                            created_at_ms: 1_795_521_600_000,
                        })
                        .collect();
                    let ops: Vec<crate::sync::PushOpDto> = step["ops"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|o| crate::sync::PushOpDto {
                            op_id: OpId::parse(o["op_id"].as_str().unwrap()).unwrap(),
                            device_id: DeviceId::parse(o["device_id"].as_str().unwrap()).unwrap(),
                            key_id: o["key_id"].as_str().map(|s| KeyId::parse(s).unwrap()),
                            envelope: b64.decode(o["envelope_b64"].as_str().unwrap()).unwrap(),
                        })
                        .collect();
                    let req = PushRequestDto {
                        expected_epoch,
                        seen_seq: 0,
                        key_records,
                        cancel_key_ids: Vec::new(),
                        ops,
                        shred_marks: Vec::new(),
                    };
                    let exp = &step["expect"];
                    match relay.handle_push(&dev, &req, 1_795_521_600_000) {
                        Ok(ok) => {
                            assert_eq!(exp["status"].as_u64().unwrap(), 200, "step={step_id}");
                            let got_seqs: Vec<i64> = ok.acked.iter().map(|a| a.seq).collect();
                            let want_seqs: Vec<i64> = exp["acked_seqs"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|v| v.as_i64().unwrap())
                                .collect();
                            assert_eq!(got_seqs, want_seqs, "step={step_id}");
                            assert_eq!(ok.head_seq, exp["head_seq"].as_i64().unwrap(), "step={step_id}");
                        }
                        Err(err) => {
                            assert_ne!(exp["status"].as_u64().unwrap(), 200, "step={step_id}");
                            assert_eq!(
                                err.code.as_str(),
                                exp["error_code"].as_str().unwrap(),
                                "step={step_id}"
                            );
                            if let Some(h) = exp["head_seq"].as_i64() {
                                assert_eq!(relay.head_seq(), h, "step={step_id}");
                            }
                        }
                    }
                }
                "pull" => {
                    let since = step["since"].as_i64().unwrap();
                    let limit = step["limit"].as_u64().unwrap() as usize;
                    let (_, ops, digest, head_seq, has_more) = relay.handle_pull(since, limit);
                    let exp = &step["expect"];
                    let got_ids: Vec<String> = ops.iter().map(|o| o.op_id.to_string()).collect();
                    let want_ids: Vec<String> = exp["op_ids"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_string())
                        .collect();
                    assert_eq!(got_ids, want_ids, "step={step_id}");
                    let got_seqs: Vec<i64> = ops.iter().map(|o| o.seq).collect();
                    let want_seqs: Vec<i64> = exp["seqs"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_i64().unwrap())
                        .collect();
                    assert_eq!(got_seqs, want_seqs, "step={step_id}");
                    if let Some(dev_ids) = exp["device_ids"].as_array() {
                        let got_devs: Vec<String> = ops.iter().map(|o| o.device_id.to_string()).collect();
                        let want_devs: Vec<String> =
                            dev_ids.iter().map(|v| v.as_str().unwrap().to_string()).collect();
                        assert_eq!(got_devs, want_devs, "step={step_id}");
                    }
                    assert_eq!(has_more, exp["has_more"].as_bool().unwrap(), "step={step_id}");
                    assert_eq!(head_seq, exp["head_seq"].as_i64().unwrap(), "step={step_id}");
                    assert!(digest.starts_with("blake3:"), "step={step_id}");
                }
                "keys_post" => {
                    let records: Vec<KeyRecordRow> = step["key_records"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|k| KeyRecordRow {
                            key_id: KeyId::parse(k["key_id"].as_str().unwrap()).unwrap(),
                            wrap_gen: k["wrap_gen"].as_u64().unwrap() as u32,
                            key_record: Some(b64.decode(k["key_record_b64"].as_str().unwrap()).unwrap()),
                            created_at_ms: 1_795_521_600_000,
                        })
                        .collect();
                    let keyring = step.get("keyring").and_then(|kr| {
                        Some((
                            kr["gen"].as_u64()? as u32,
                            b64.decode(kr["blob_b64"].as_str()?).ok()?,
                        ))
                    });
                    let exp = &step["expect"];
                    match relay.handle_keys_post(&records, keyring, None) {
                        Ok(()) => assert_eq!(exp["status"].as_u64().unwrap(), 200, "step={step_id}"),
                        Err(code) => {
                            assert_ne!(exp["status"].as_u64().unwrap(), 200, "step={step_id}");
                            assert_eq!(
                                code.as_str(),
                                exp["error_code"].as_str().unwrap(),
                                "step={step_id}"
                            );
                        }
                    }
                }
                other => panic!("unexpected scenario action: {other}"),
            }
        }
    }

    #[test]
    fn execute_shared_m2_shred_and_snapshot_scenario_on_sim_relay() {
        use base64::Engine;
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = Path::new(manifest_dir).join("../../tests/scenarios/m2_shred_and_snapshot_contract.json");
        let raw = std::fs::read_to_string(&path).expect("m2 scenario json readable");
        let doc: serde_json::Value = serde_json::from_str(&raw).expect("valid m2 scenario json");

        let epoch = JournalEpoch::from_random_bytes([0x55; 16]);
        let mut relay = SimRelay::new(epoch);
        let mut now_ms: i64 = 1_795_521_600_000;
        let b64 = base64::engine::general_purpose::STANDARD;

        for step in doc["steps"].as_array().expect("steps array") {
            let step_id = step["id"].as_str().unwrap();
            let exp = &step["expect"];
            match step["action"].as_str().unwrap() {
                "push" => {
                    let dev = DeviceId::parse(step["as_device"].as_str().unwrap()).unwrap();
                    let key_records: Vec<KeyRecordRow> = step
                        .get("key_records")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .map(|k| KeyRecordRow {
                                    key_id: KeyId::parse(k["key_id"].as_str().unwrap()).unwrap(),
                                    wrap_gen: k["wrap_gen"].as_u64().unwrap() as u32,
                                    key_record: Some(
                                        b64.decode(k["key_record_b64"].as_str().unwrap()).unwrap(),
                                    ),
                                    created_at_ms: now_ms,
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let cancel_key_ids: Vec<KeyId> = step
                        .get("cancel_key_ids")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .map(|k| KeyId::parse(k.as_str().unwrap()).unwrap())
                                .collect()
                        })
                        .unwrap_or_default();
                    let ops: Vec<crate::sync::PushOpDto> = step
                        .get("ops")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .map(|o| crate::sync::PushOpDto {
                                    op_id: OpId::parse(o["op_id"].as_str().unwrap()).unwrap(),
                                    device_id: DeviceId::parse(o["device_id"].as_str().unwrap()).unwrap(),
                                    key_id: o["key_id"].as_str().map(|s| KeyId::parse(s).unwrap()),
                                    envelope: b64.decode(o["envelope_b64"].as_str().unwrap()).unwrap(),
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let shred_marks: Vec<ShredMarkRow> = step
                        .get("shred_marks")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .map(|m| ShredMarkRow {
                                    mark_id: MarkId::parse(m["mark_id"].as_str().unwrap()).unwrap(),
                                    key_id: KeyId::parse(m["key_id"].as_str().unwrap()).unwrap(),
                                    seen_seq: step["seen_seq"].as_i64().unwrap_or(0),
                                    requested_by: DeviceId::parse(m["requested_by"].as_str().unwrap())
                                        .unwrap(),
                                    requested_at_ms: now_ms,
                                    grace_ms: m["grace_ms"].as_i64().unwrap(),
                                    not_before_ms: None,
                                    state: ShredMarkState::PendingConfirm,
                                    confirmed_at_ms: None,
                                    cancelled_by: None,
                                    executed_at_ms: None,
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let req = PushRequestDto {
                        expected_epoch: epoch,
                        seen_seq: step["seen_seq"].as_i64().unwrap_or(0),
                        key_records,
                        cancel_key_ids,
                        ops,
                        shred_marks,
                    };
                    match relay.handle_push(&dev, &req, now_ms) {
                        Ok(ok) => {
                            assert_eq!(exp["status"].as_u64().unwrap(), 200, "step={step_id}");
                            let got_seqs: Vec<i64> = ok.acked.iter().map(|a| a.seq).collect();
                            let want_seqs: Vec<i64> = exp["acked_seqs"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|v| v.as_i64().unwrap())
                                .collect();
                            assert_eq!(got_seqs, want_seqs, "step={step_id}");
                            assert_eq!(ok.head_seq, exp["head_seq"].as_i64().unwrap(), "step={step_id}");
                            if let Some(want_states) = exp.get("shred_states").and_then(|v| v.as_array()) {
                                let got_states: Vec<String> = ok
                                    .shred_results
                                    .iter()
                                    .map(|r| {
                                        serde_json::to_value(r.state)
                                            .unwrap()
                                            .as_str()
                                            .unwrap()
                                            .to_string()
                                    })
                                    .collect();
                                let want: Vec<String> = want_states
                                    .iter()
                                    .map(|v| v.as_str().unwrap().to_string())
                                    .collect();
                                assert_eq!(got_states, want, "step={step_id}");
                            }
                        }
                        Err(err) => {
                            assert_ne!(exp["status"].as_u64().unwrap(), 200, "step={step_id}");
                            assert_eq!(
                                err.code.as_str(),
                                exp["error_code"].as_str().unwrap(),
                                "step={step_id}"
                            );
                        }
                    }
                }
                "keys_shred" => {
                    let seen_seq = step["seen_seq"].as_i64().unwrap_or(0);
                    let expedite = step.get("expedite").and_then(|v| v.as_bool()).unwrap_or(false);
                    let marks: Vec<ShredMarkRow> = step["marks"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|m| ShredMarkRow {
                            mark_id: MarkId::parse(m["mark_id"].as_str().unwrap()).unwrap(),
                            key_id: KeyId::parse(m["key_id"].as_str().unwrap()).unwrap(),
                            seen_seq,
                            requested_by: DeviceId::parse(m["requested_by"].as_str().unwrap()).unwrap(),
                            requested_at_ms: now_ms,
                            grace_ms: m["grace_ms"].as_i64().unwrap(),
                            not_before_ms: None,
                            state: ShredMarkState::PendingConfirm,
                            confirmed_at_ms: None,
                            cancelled_by: None,
                            executed_at_ms: None,
                        })
                        .collect();
                    match relay.handle_keys_shred(seen_seq, expedite, false, &marks, now_ms) {
                        Ok(res) => {
                            assert_eq!(exp["status"].as_u64().unwrap(), 200, "step={step_id}");
                            let got: Vec<String> = res
                                .iter()
                                .map(|r| {
                                    serde_json::to_value(r.state)
                                        .unwrap()
                                        .as_str()
                                        .unwrap()
                                        .to_string()
                                })
                                .collect();
                            let want: Vec<String> = exp["shred_states"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|v| v.as_str().unwrap().to_string())
                                .collect();
                            assert_eq!(got, want, "step={step_id}");
                        }
                        Err(err) => {
                            assert_ne!(exp["status"].as_u64().unwrap(), 200, "step={step_id}");
                            assert_eq!(
                                err.code.as_str(),
                                exp["error_code"].as_str().unwrap(),
                                "step={step_id}"
                            );
                        }
                    }
                }
                "keys_cancel" => {
                    let dev = DeviceId::parse(step["as_device"].as_str().unwrap()).unwrap();
                    let kids: Vec<KeyId> = step["key_ids"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| KeyId::parse(v.as_str().unwrap()).unwrap())
                        .collect();
                    match relay.handle_keys_cancel(&dev, &kids) {
                        Ok(_) => assert_eq!(exp["status"].as_u64().unwrap(), 200, "step={step_id}"),
                        Err(err) => {
                            assert_ne!(exp["status"].as_u64().unwrap(), 200, "step={step_id}");
                            assert_eq!(
                                err.code.as_str(),
                                exp["error_code"].as_str().unwrap(),
                                "step={step_id}"
                            );
                        }
                    }
                }
                "advance_and_alarm" => {
                    now_ms += step["delta_ms"].as_i64().unwrap();
                    relay.run_shred_alarm(now_ms);
                    for k in exp["shredded_keys"].as_array().unwrap() {
                        let kid = KeyId::parse(k.as_str().unwrap()).unwrap();
                        assert!(
                            relay.keys.is_shredded(&kid),
                            "step={step_id} {kid} must be shredded"
                        );
                    }
                    for k in exp["alive_keys"].as_array().unwrap() {
                        let kid = KeyId::parse(k.as_str().unwrap()).unwrap();
                        assert!(
                            relay.keys.is_key_available(&kid),
                            "step={step_id} {kid} must remain alive"
                        );
                    }
                }
                "snapshot_put" => {
                    let covers_seq = step["covers_seq"].as_i64().unwrap();
                    let snap_id = SnapshotId::parse(step["snapshot_id"].as_str().unwrap()).unwrap();
                    let bytes = b64.decode(step["body_b64"].as_str().unwrap()).unwrap();
                    match relay.handle_snapshot_put(epoch, covers_seq, snap_id, bytes) {
                        Ok(()) => assert_eq!(exp["status"].as_u64().unwrap(), 200, "step={step_id}"),
                        Err(err) => {
                            assert_ne!(exp["status"].as_u64().unwrap(), 200, "step={step_id}");
                            assert_eq!(
                                err.code.as_str(),
                                exp["error_code"].as_str().unwrap(),
                                "step={step_id}"
                            );
                        }
                    }
                }
                "snapshot_get" => {
                    let got = relay.handle_snapshot_get().expect("snapshot present");
                    assert_eq!(
                        got.covers_seq,
                        exp["covers_seq"].as_i64().unwrap(),
                        "step={step_id}"
                    );
                    assert_eq!(
                        b64.encode(&got.bytes),
                        exp["body_b64"].as_str().unwrap(),
                        "step={step_id}"
                    );
                }
                other => panic!("unexpected m2 scenario action: {other}"),
            }
        }
    }

    #[test]
    fn c6_c7_c11_h10_sync_push_deferral_live_key_guard_race_order_and_idempotent_replay() {
        let mut cluster = SimCluster::new(SimSeed(0x2026_1125_C6C7_0001));
        let b1 = cluster.create_block_on_node(0, "block-1");
        let b2 = cluster.create_block_on_node(0, "block-2");
        cluster.sync_node(0, &mut false);
        cluster.sync_node(1, &mut false);

        // C7: Even if a stale unacked shred mark exists for an ACTIVE block's live key, build_pending_push() MUST NOT send it!
        let b1_live_kid = cluster.nodes[0]
            .engine
            .all_blocks()
            .into_iter()
            .find(|b| b.id == b1)
            .and_then(|b| b.leaves.into_iter().find_map(|l| l.op_id.into()))
            .and_then(|oid: OpId| cluster.nodes[0].engine.ops.get(&oid).and_then(|o| o.key_id))
            .unwrap();
        let dev0 = cluster.nodes[0].engine.device_id.clone();
        let bogus_mark_id = MarkId::from_ulid(
            cluster.nodes[0]
                .ulid_gen
                .next(cluster.now_ms, cluster.rng.bytes_10()),
        );
        let seen0 = cluster.nodes[0].engine.last_seq;
        cluster.nodes[0].engine.pending_shred_marks.push(ShredMarkRow {
            mark_id: bogus_mark_id,
            key_id: b1_live_kid,
            seen_seq: seen0,
            requested_by: dev0.clone(),
            requested_at_ms: cluster.now_ms as i64,
            grace_ms: T_GRACE_DEFAULT_MS,
            not_before_ms: None,
            state: ShredMarkState::PendingConfirm,
            confirmed_at_ms: None,
            cancelled_by: None,
            executed_at_ms: None,
        });
        assert!(
            cluster.nodes[0].engine.build_pending_push().is_none(),
            "C7: build_pending_push must never attach shred mark for a key still live on an active block"
        );
        cluster.nodes[0].engine.pending_shred_marks.clear();

        // C6: Delete b2 + add 505 ops so push spans >1 batch (>500 ops). Batch 1 MUST defer b2's shred mark!
        let b2_kid = cluster.nodes[0]
            .engine
            .ops
            .values()
            .find(|o| o.entity_id == b2.to_string())
            .and_then(|o| o.key_id)
            .unwrap();
        assert!(cluster.delete_block_on_node(0, b2));
        for i in 0..505usize {
            cluster.create_block_on_node(0, &format!("bulk-{i}"));
        }
        let mark_b2 = MarkId::from_ulid(
            cluster.nodes[0]
                .ulid_gen
                .next(cluster.now_ms, cluster.rng.bytes_10()),
        );
        let seen1 = cluster.nodes[0].engine.last_seq;
        cluster.nodes[0].engine.pending_shred_marks.push(ShredMarkRow {
            mark_id: mark_b2,
            key_id: b2_kid,
            seen_seq: seen1,
            requested_by: dev0.clone(),
            requested_at_ms: cluster.now_ms as i64,
            grace_ms: T_GRACE_DEFAULT_MS,
            not_before_ms: None,
            state: ShredMarkState::PendingConfirm,
            confirmed_at_ms: None,
            cancelled_by: None,
            executed_at_ms: None,
        });
        let batch1 = cluster.nodes[0].engine.build_pending_push().expect("batch 1");
        assert!(
            batch1.shred_marks.is_empty(),
            "C6: multi-batch push MUST defer all shred_marks until the final batch"
        );

        // C11: PushKeyRaceError MUST emit HttpPull FIRST without premature SyncKeyTable!
        let (_, cmds) = step(
            &cluster.nodes[0].engine,
            SyncEvent::PushKeyRaceError {
                code: ErrorCode::KeyPendingShred,
                key_id: Some(b2_kid),
            },
        )
        .unwrap();
        assert_eq!(
            cmds.len(),
            1,
            "C11: PushKeyRaceError must emit only HttpPull so remote ops settle before key table sync (got {cmds:?})"
        );
        assert!(
            matches!(cmds.first(), Some(SyncCommand::HttpPull { .. })),
            "C11: PushKeyRaceError must pull remote ops first (got {cmds:?})"
        );

        // H10: SimRelay idempotent push replay succeeds even when op's key now has a scheduled shred mark
        let mut relay = SimRelay::new(JournalEpoch::from_random_bytes([0x55; 16]));
        let kid = KeyId::from_ulid(cluster.nodes[0].ulid_gen.next(cluster.now_ms, [1; 10]));
        let oid = OpId::from_ulid(cluster.nodes[0].ulid_gen.next(cluster.now_ms, [2; 10]));
        let mid = MarkId::from_ulid(cluster.nodes[0].ulid_gen.next(cluster.now_ms, [3; 10]));
        let req = PushRequestDto {
            expected_epoch: relay.epoch,
            seen_seq: 0,
            key_records: vec![KeyRecordRow {
                key_id: kid,
                wrap_gen: 1,
                key_record: Some(vec![1, 2, 3]),
                created_at_ms: 1000,
            }],
            cancel_key_ids: vec![],
            ops: vec![crate::sync::PushOpDto {
                op_id: oid,
                device_id: dev0.clone(),
                key_id: Some(kid),
                envelope: vec![4, 5, 6],
            }],
            shred_marks: vec![ShredMarkRow {
                mark_id: mid,
                key_id: kid,
                seen_seq: 0,
                requested_by: dev0.clone(),
                requested_at_ms: 1000,
                grace_ms: T_GRACE_DEFAULT_MS,
                not_before_ms: None,
                state: ShredMarkState::PendingConfirm,
                confirmed_at_ms: None,
                cancelled_by: None,
                executed_at_ms: None,
            }],
        };
        let r1 = relay.handle_push(&dev0, &req, 1000).unwrap();
        let r2 = relay.handle_push(&dev0, &req, 1000).unwrap();
        assert_eq!(r1.acked[0].seq, r2.acked[0].seq);
        assert_eq!(r2.shred_results[0].state, ShredMarkState::Scheduled);
    }

    #[test]
    fn dst_m2_multi_seed_random_shred_cancel_pitr_and_mobile_snapshot_convergence() {
        for i in 1..=20u64 {
            let mut cluster = SimCluster::new(SimSeed(
                0x2026_1125_A000_0000 ^ i.wrapping_mul(0x517C_C1B7_2722_0A95),
            ));
            let mut ids = Vec::new();
            for j in 0..4 {
                ids.push(cluster.create_block_on_node((j % 2) as usize, &format!("seed-{i}-blk-{j}")));
            }
            cluster.sync_node(0, &mut false);
            cluster.sync_node(1, &mut false);
            cluster.sync_node(0, &mut false);
            cluster.sync_node(2, &mut false);

            // Partition node 1; node 1 updates ids[0] while node 0 deletes ids[0] and ids[1]
            cluster.nodes[1].partitioned = true;
            assert!(cluster.update_block_on_node(1, ids[0], &format!("revived-{i}")));
            assert!(cluster.delete_block_on_node(0, ids[0]));
            assert!(cluster.delete_block_on_node(0, ids[1]));
            let dev0 = cluster.nodes[0].engine.device_id.clone();
            for target in [ids[0], ids[1]] {
                let kids: BTreeSet<KeyId> = cluster.nodes[0]
                    .engine
                    .ops
                    .values()
                    .filter(|o| o.entity_id == target.to_string())
                    .filter_map(|o| o.key_id)
                    .collect();
                for kid in kids {
                    let mid = MarkId::from_ulid(
                        cluster.nodes[0]
                            .ulid_gen
                            .next(cluster.now_ms, cluster.rng.bytes_10()),
                    );
                    let seen_m2 = cluster.nodes[0].engine.last_seq;
                    cluster.nodes[0].engine.pending_shred_marks.push(ShredMarkRow {
                        mark_id: mid,
                        key_id: kid,
                        seen_seq: seen_m2,
                        requested_by: dev0.clone(),
                        requested_at_ms: cluster.now_ms as i64,
                        grace_ms: T_GRACE_DEFAULT_MS,
                        not_before_ms: None,
                        state: ShredMarkState::PendingConfirm,
                        confirmed_at_ms: None,
                        cancelled_by: None,
                        executed_at_ms: None,
                    });
                }
            }
            cluster.sync_node(0, &mut false);

            // Take MNP1 snapshot while BOTH ids[0] and ids[1] are Trashed (tests C9 across seeds!)
            let snap_id = SnapshotId::from_ulid(
                cluster.nodes[0]
                    .ulid_gen
                    .next(cluster.now_ms, cluster.rng.bytes_10()),
            );
            let (_, snap_bytes) = pack_state_snapshot(
                &cluster.nodes[0].engine,
                snap_id,
                cluster.relay.head_seq(),
                cluster.current_smk.0,
                &cluster.current_smk.1,
                cluster.now_ms as i64,
                cluster.rng.bytes_24(),
                cluster.rng.bytes_24(),
            )
            .unwrap();
            cluster
                .relay
                .handle_snapshot_put(cluster.relay.epoch, cluster.relay.head_seq(), snap_id, snap_bytes)
                .unwrap();

            // Heal node 1 -> Update-Wins auto-cancels ids[0] shred mark before alarm executes!
            cluster.nodes[1].partitioned = false;
            cluster.sync_node(1, &mut false);
            cluster.sync_node(0, &mut false);

            // Advance past T_grace -> alarm shreds ONLY ids[1], keeping ids[0] alive!
            cluster.now_ms += (T_GRACE_DEFAULT_MS + 60_000) as u64;
            cluster.relay.run_shred_alarm(cluster.now_ms as i64);
            cluster.sync_node(0, &mut false);
            cluster.sync_node(1, &mut false);
            cluster.sync_node(2, &mut false);

            // Verify INV-KEY-LIVENESS on all nodes + MobileReadState parity (INV-SYNC-7)
            for n in &cluster.nodes {
                let all_blks = n.engine.all_blocks();
                let (ok, missing) = crate::keys::self_check_key_liveness(&all_blks, &n.engine.keys);
                assert!(ok && missing.is_empty(), "INV-KEY-LIVENESS failed: {missing:?}");
            }
            let ref_blocks: Vec<crate::model::MaterializedBlock> = cluster.nodes[0]
                .engine
                .all_blocks()
                .into_iter()
                .filter(|b| b.state != BlockState::Shredded)
                .collect();
            assert_eq!(
                cluster.nodes[1]
                    .engine
                    .all_blocks()
                    .into_iter()
                    .filter(|b| b.state != BlockState::Shredded)
                    .collect::<Vec<_>>(),
                ref_blocks
            );

            let snap_rec = cluster.relay.handle_snapshot_get().unwrap();
            let (hdr, body) = decode_mnp1(&cluster.nodes[0].engine.smks, &snap_rec.bytes).unwrap();
            let mut mobile = MobileReadState::new();
            mobile.install_snapshot(hdr, body);
            let (_, tail, _, _, _) = cluster.relay.handle_pull(mobile.last_seq, 500);
            for r in &tail {
                mobile
                    .apply_tail_envelope(r, &cluster.nodes[0].engine.smks)
                    .unwrap();
            }
            mobile.merge_key_table(&cluster.relay.keys, &cluster.nodes[0].engine.smks);
            assert_eq!(
                mobile.all_non_shredded_blocks(&cluster.nodes[0].engine.smks),
                ref_blocks,
                "INV-SYNC-7 mobile parity failed on M2 seed {i}"
            );
        }
    }
}
