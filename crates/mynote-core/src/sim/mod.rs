//! Deterministic Simulation Testing (`SimCluster`, M1-12 / `docs/eval-framework.md` §2 & §4).
//!
//! Zero system clocks, zero real I/O: every schedule, fault injection, PITR rollback,
//! SMK rotation, and R2 archive recovery is 100% determined by a single `SimSeed(u64)`.

use crate::crypto::{
    decode_mna1, decode_mnks, decrypt_mns1, encode_mna1, encode_mnks, encrypt_mnb1, encrypt_mnr1,
    encrypt_mns1, peek_envelope_kid, seal_mnrs, ArchiveOpsHeaderV1, ArchivedOpRow, KeyRecordV1,
    KeySnapshotBodyV1, KeySnapshotHeaderV1, RecoveryKeypair, RecoveryKeyringV1, MAGIC_MNS1, MNRS_KIND_SMK,
};
use crate::error::{CoreError, ErrorCode};
use crate::fractional_index;
use crate::hlc::HlcClock;
use crate::ids::{BlockId, BufferId, DeviceId, JournalEpoch, KeyId, MonotonicUlidGen, OpId, SmkKid};
use crate::keys::{self_check_key_liveness, KeyTableState};
use crate::model::{BlockState, EntityType, InnerOpV1, KeyRecordRow, LeafBody, OpBodyV1, OpType};
use crate::sync::{
    step, AckedOp, EngineSnapshot, LocalOpRecord, PushRequestDto, RemoteEnvelopeRow, StoreMutation,
    SyncCommand, SyncEvent,
};
use std::collections::{BTreeMap, BTreeSet};
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
        }
    }

    pub fn head_seq(&self) -> i64 {
        self.ops.last().map_or(0, |o| o.seq)
    }

    pub fn handle_push(
        &mut self,
        _pusher_device_id: &DeviceId,
        req: &PushRequestDto,
        now_ms: i64,
    ) -> Result<(JournalEpoch, Vec<AckedOp>, i64), ErrorCode> {
        if req.expected_epoch != self.epoch {
            return Err(ErrorCode::CasMismatch);
        }
        // Atomic batch order: key_records -> ops (M1 enforces KEY_UNKNOWN)
        let mut staged_keys = self.keys.clone();
        for rec in &req.key_records {
            staged_keys.insert_record(rec.clone());
        }
        for op in &req.ops {
            if let Some(kid) = op.key_id {
                if !staged_keys.is_key_available(&kid) {
                    return Err(ErrorCode::KeyUnknown);
                }
            }
        }
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
        Ok((self.epoch, acked, self.head_seq()))
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
    fn run_daily_archive_alarm(&mut self, keyring: &RecoveryKeyringV1, now_ms: i64) -> Result<(), CoreError> {
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
        let mnks_hdr = KeySnapshotHeaderV1 {
            created_at_ms: now_ms,
            keyring_gen: keyring.keyring_gen,
            record_count: active_records.len() as u32,
        };
        let mnks_body = KeySnapshotBodyV1 {
            keyring: keyring.clone(),
            vault_header: None,
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
        let mut queue = vec![SyncEvent::StartSync];
        let mut guard = 0usize;

        while let Some(ev) = queue.pop() {
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
                        queue.push(SyncEvent::PullResponse {
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
                        match self.relay.handle_push(&dev, &req, self.now_ms as i64) {
                            Ok((epoch, acked, head_seq)) => {
                                queue.push(SyncEvent::PushAcked {
                                    epoch,
                                    acked,
                                    head_seq,
                                });
                            }
                            Err(ErrorCode::CasMismatch) => {
                                queue.push(SyncEvent::PushEpochMismatch {
                                    remote_epoch: self.relay.epoch,
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
                        queue.push(SyncEvent::KeyTableResponse {
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
                        ops,
                    };
                    let exp = &step["expect"];
                    match relay.handle_push(&dev, &req, 1_795_521_600_000) {
                        Ok((_, acked, head_seq)) => {
                            assert_eq!(exp["status"].as_u64().unwrap(), 200, "step={step_id}");
                            let got_seqs: Vec<i64> = acked.iter().map(|a| a.seq).collect();
                            let want_seqs: Vec<i64> = exp["acked_seqs"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|v| v.as_i64().unwrap())
                                .collect();
                            assert_eq!(got_seqs, want_seqs, "step={step_id}");
                            assert_eq!(head_seq, exp["head_seq"].as_i64().unwrap(), "step={step_id}");
                        }
                        Err(code) => {
                            assert_ne!(exp["status"].as_u64().unwrap(), 200, "step={step_id}");
                            assert_eq!(
                                code.as_str(),
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
}
