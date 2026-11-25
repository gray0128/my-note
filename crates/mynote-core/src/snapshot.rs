//! Mobile read-only state snapshot (`MNP1`, `#18 [M2-4]`) and tail-op incremental projection (`INV-SYNC-7`).
//!
//! SSOT references:
//! - `docs/data-structures.md` §3.2 #7, §3.3 (exact `MNP1` AAD), §3.6
//! - `docs/sync-protocol.md` §9
//! - `docs/eval-framework.md` §2 `INV-SYNC-7`

use crate::crypto::{
    compress_zstd, decompress_zstd, decrypt_mnb1, decrypt_mnr1, decrypt_mns1, peek_envelope_kid, KeyRecordV1,
    MAGIC_MNR1, MAGIC_MNS1, WIRE_VERSION,
};
use crate::error::{CoreError, ErrorCode};
use crate::fractional_index;
use crate::hlc::Hlc;
use crate::ids::{BlockId, BufferId, DeviceId, JournalEpoch, KeyId, OpId, SmkKid, SnapshotId};
use crate::keys::KeyTableState;
use crate::model::{
    BlockFieldHlc, BlockLeaf, BlockState, BufferFieldHlc, EntityType, InnerOpV1, LeafBody, MaterializedBlock,
    MaterializedBuffer, OpBodyV1,
};
use crate::sync::{EngineSnapshot, RemoteEnvelopeRow};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub const MAGIC_MNP1: &[u8; 4] = b"MNP1";
const AEAD_TAG_LEN: usize = 16;
// Prefix: magic(4) + ver(1) + smk_kid(16) + snapshot_id(16) + covers_seq(8) + hdr_nonce(24) + hdr_ct_len(4) = 73 B
const MNP1_PREFIX_LEN: usize = 4 + 1 + 16 + 16 + 8 + 24 + 4;

fn integrity_err(msg: impl Into<String>) -> CoreError {
    CoreError::new(
        ErrorCode::IntegrityError,
        msg,
        "State snapshot MNP1 authentication or decoding failed; discard and re-fetch",
    )
}

/// Exact `MNP1` header AAD (`docs/data-structures.md` §3.3):
/// `"MNP1" || ver || smk_kid(16B) || snapshot_id(16B) || covers_seq(i64 LE)`
fn aad_mnp1_header(smk_kid: SmkKid, snapshot_id: SnapshotId, covers_seq: i64) -> [u8; 45] {
    let mut aad = [0u8; 45];
    aad[0..4].copy_from_slice(MAGIC_MNP1);
    aad[4] = WIRE_VERSION;
    aad[5..21].copy_from_slice(smk_kid.as_bytes());
    aad[21..37].copy_from_slice(snapshot_id.as_bytes());
    aad[37..45].copy_from_slice(&covers_seq.to_le_bytes());
    aad
}

/// Exact `MNP1` body AAD (`docs/data-structures.md` §3.3):
/// `"MNP1" || ver || smk_kid(16B) || hdr_blake3(32B)`
fn aad_mnp1_body(smk_kid: SmkKid, hdr_blake3: &[u8; 32]) -> [u8; 53] {
    let mut aad = [0u8; 53];
    aad[0..4].copy_from_slice(MAGIC_MNP1);
    aad[4] = WIRE_VERSION;
    aad[5..21].copy_from_slice(smk_kid.as_bytes());
    aad[21..53].copy_from_slice(hdr_blake3);
    aad
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotHeaderV1 {
    pub v: u8,
    pub journal_epoch: JournalEpoch,
    pub snapshot_id: SnapshotId,
    pub covers_seq: i64,
    pub buffer_count: u32,
    pub block_count: u32,
    pub leaf_count: u32,
    pub created_by: DeviceId,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotBodyV1 {
    pub buffers: Vec<SnapshotBufferV1>,
    pub blocks: Vec<SnapshotBlockV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotBufferLeafV1 {
    pub op_id: OpId,
    pub hlc: Hlc,
    pub is_tombstone: bool,
    pub deleted_at_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotBufferV1 {
    pub id: BufferId,
    pub position: String,
    pub key_id: KeyId,
    pub name_op_id: OpId,
    pub name_mnb1: Vec<u8>,
    pub field_hlc: BufferFieldHlc,
    #[serde(default)]
    pub leaves: Vec<SnapshotBufferLeafV1>,
    #[serde(default)]
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotBlockV1 {
    pub id: BlockId,
    pub buffer_id: BufferId,
    pub position: String,
    pub lang: String,
    pub public_hint: Option<String>,
    pub field_hlc: BlockFieldHlc,
    pub leaves: Vec<SnapshotLeafV1>,
    #[serde(default)]
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotLeafV1 {
    pub op_id: OpId,
    pub hlc: Hlc,
    pub device_id: DeviceId,
    pub actor: String,
    pub body: SnapshotLeafBody,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "k", content = "d")]
pub enum SnapshotLeafBody {
    Content { tier: u8, key_id: KeyId, mnb1: Vec<u8> },
    Tombstone { deleted_at_ms: i64 },
}

/// Encrypt `(SnapshotHeaderV1, SnapshotBodyV1)` into dual-authenticated `MNP1` wire bytes.
pub fn encode_mnp1(
    smk_kid: SmkKid,
    smk: &[u8; 32],
    header: &SnapshotHeaderV1,
    body: &SnapshotBodyV1,
    hdr_nonce: [u8; 24],
    body_nonce: [u8; 24],
) -> Result<Vec<u8>, CoreError> {
    let hdr_raw = rmp_serde::to_vec_named(header).map_err(|e| integrity_err(e.to_string()))?;
    let body_raw = rmp_serde::to_vec_named(body).map_err(|e| integrity_err(e.to_string()))?;
    let body_zstd = compress_zstd(&body_raw);

    let cipher = XChaCha20Poly1305::new(smk.into());
    let hdr_aad = aad_mnp1_header(smk_kid, header.snapshot_id, header.covers_seq);
    let hdr_ct = cipher
        .encrypt(
            &XNonce::from(hdr_nonce),
            Payload {
                msg: &hdr_raw,
                aad: &hdr_aad,
            },
        )
        .map_err(|_| integrity_err("MNP1 header encryption failed"))?;

    let mut out = Vec::with_capacity(MNP1_PREFIX_LEN + hdr_ct.len() + 24 + body_zstd.len() + AEAD_TAG_LEN);
    out.extend_from_slice(MAGIC_MNP1);
    out.push(WIRE_VERSION);
    out.extend_from_slice(smk_kid.as_bytes());
    out.extend_from_slice(header.snapshot_id.as_bytes());
    out.extend_from_slice(&header.covers_seq.to_le_bytes());
    out.extend_from_slice(&hdr_nonce);
    out.extend_from_slice(&(hdr_ct.len() as u32).to_le_bytes());
    out.extend_from_slice(&hdr_ct);

    let hdr_hash = blake3::hash(&out);
    let body_aad = aad_mnp1_body(smk_kid, hdr_hash.as_bytes());
    let body_ct = cipher
        .encrypt(
            &XNonce::from(body_nonce),
            Payload {
                msg: &body_zstd,
                aad: &body_aad,
            },
        )
        .map_err(|_| integrity_err("MNP1 body encryption failed"))?;

    out.extend_from_slice(&body_nonce);
    out.extend_from_slice(&body_ct);
    Ok(out)
}

/// Authenticate and decrypt `MNP1` snapshot bytes using the caller's SMK generation map.
pub fn decode_mnp1(
    smks: &BTreeMap<SmkKid, Zeroizing<[u8; 32]>>,
    raw: &[u8],
) -> Result<(SnapshotHeaderV1, SnapshotBodyV1), CoreError> {
    if raw.len() < MNP1_PREFIX_LEN + AEAD_TAG_LEN + 24 + AEAD_TAG_LEN {
        return Err(integrity_err("MNP1 snapshot truncated"));
    }
    if &raw[0..4] != MAGIC_MNP1 || raw[4] != WIRE_VERSION {
        return Err(integrity_err("MNP1 magic or version mismatch"));
    }
    let mut smk_kid_bytes = [0u8; 16];
    smk_kid_bytes.copy_from_slice(&raw[5..21]);
    let smk_kid = SmkKid::from_bytes(smk_kid_bytes);
    let mut snap_id_bytes = [0u8; 16];
    snap_id_bytes.copy_from_slice(&raw[21..37]);
    let snapshot_id = SnapshotId::from_bytes(snap_id_bytes);
    let covers_seq = i64::from_le_bytes(raw[37..45].try_into().unwrap());
    let mut hdr_nonce = [0u8; 24];
    hdr_nonce.copy_from_slice(&raw[45..69]);
    let hdr_ct_len = u32::from_le_bytes(raw[69..73].try_into().unwrap()) as usize;
    let hdr_end = MNP1_PREFIX_LEN
        .checked_add(hdr_ct_len)
        .filter(|&e| e + 24 + AEAD_TAG_LEN <= raw.len())
        .ok_or_else(|| integrity_err("MNP1 header length out of bounds"))?;

    let smk = smks.get(&smk_kid).ok_or_else(|| {
        CoreError::new(
            ErrorCode::KeyMissing,
            format!("MNP1 requires unknown SMK generation {smk_kid}"),
            "Refresh device keys with 'mynote device refresh' or 'mynote keyring unlock'",
        )
    })?;

    let cipher = XChaCha20Poly1305::new((&**smk).into());
    let hdr_aad = aad_mnp1_header(smk_kid, snapshot_id, covers_seq);
    let hdr_pt = cipher
        .decrypt(
            &XNonce::from(hdr_nonce),
            Payload {
                msg: &raw[MNP1_PREFIX_LEN..hdr_end],
                aad: &hdr_aad,
            },
        )
        .map_err(|_| integrity_err("MNP1 header AEAD verification failed"))?;
    let header: SnapshotHeaderV1 =
        rmp_serde::from_slice(&hdr_pt).map_err(|e| integrity_err(e.to_string()))?;
    if header.v != 1 || header.snapshot_id != snapshot_id || header.covers_seq != covers_seq {
        return Err(integrity_err(
            "MNP1 header fields do not match authenticated prefix",
        ));
    }

    let hdr_hash = blake3::hash(&raw[..hdr_end]);
    let body_aad = aad_mnp1_body(smk_kid, hdr_hash.as_bytes());
    let mut body_nonce = [0u8; 24];
    body_nonce.copy_from_slice(&raw[hdr_end..hdr_end + 24]);
    let body_zstd = cipher
        .decrypt(
            &XNonce::from(body_nonce),
            Payload {
                msg: &raw[hdr_end + 24..],
                aad: &body_aad,
            },
        )
        .map_err(|_| integrity_err("MNP1 body AEAD verification failed"))?;
    let body_raw = decompress_zstd(&body_zstd)?;
    let body: SnapshotBodyV1 = rmp_serde::from_slice(&body_raw).map_err(|e| integrity_err(e.to_string()))?;
    Ok((header, body))
}

/// Build an `MNP1` mobile state snapshot from a bootstrapped desktop `EngineSnapshot`
/// covering all ops with `server_seq <= covers_seq` (`docs/sync-protocol.md` §9.1).
///
/// - Includes BOTH `Active` and `Trashed` non-`Shredded` buffers & blocks so tail Update-Wins
///   revivals and `trash restore` have complete metadata.
/// - Excludes ALL `Shredded` entities.
/// - Contains ZERO keys (leaf payloads stay encrypted as original `MNB1`).
#[allow(clippy::too_many_arguments)]
pub fn pack_state_snapshot(
    engine: &EngineSnapshot,
    snapshot_id: SnapshotId,
    covers_seq: i64,
    smk_kid: SmkKid,
    smk: &[u8; 32],
    now_ms: i64,
    hdr_nonce: [u8; 24],
    body_nonce: [u8; 24],
) -> Result<(SnapshotHeaderV1, Vec<u8>), CoreError> {
    let journal_epoch = engine.journal_epoch.ok_or_else(|| {
        CoreError::new(
            ErrorCode::InvalidArgument,
            "cannot pack state snapshot without journal_epoch",
            "Complete sync bootstrap before publishing a mobile snapshot",
        )
    })?;

    // Restrict to ops with server_seq <= covers_seq so `covers_seq` is exact!
    let mut scoped = engine.clone();
    scoped
        .ops
        .retain(|_, o| o.server_seq.is_some_and(|s| s <= covers_seq));

    // Pre-decode all scoped ops once (grouped by entity)
    let mut buf_ops: BTreeMap<BufferId, Vec<(OpId, DeviceId, InnerOpV1)>> = BTreeMap::new();
    let mut blk_ops: BTreeMap<BlockId, Vec<(OpId, DeviceId, InnerOpV1)>> = BTreeMap::new();
    for rec in scoped.ops.values() {
        let Some(op_smk) = scoped.smks.get(&rec.smk_kid) else {
            continue;
        };
        let Ok(inner) = decrypt_mns1(
            rec.smk_kid,
            op_smk,
            rec.op_id,
            &rec.device_id,
            rec.key_id,
            &rec.envelope,
        ) else {
            continue;
        };
        match inner.entity_type {
            EntityType::Buffer => {
                if let Ok(id) = BufferId::parse(&inner.entity_id) {
                    buf_ops
                        .entry(id)
                        .or_default()
                        .push((rec.op_id, rec.device_id.clone(), inner));
                }
            }
            EntityType::Block => {
                if let Ok(id) = BlockId::parse(&inner.entity_id) {
                    blk_ops
                        .entry(id)
                        .or_default()
                        .push((rec.op_id, rec.device_id.clone(), inner));
                }
            }
        }
    }

    // 1. Pack non-Shredded buffers
    let mut snap_buffers = Vec::new();
    for mat in scoped.all_buffers() {
        if mat.state == BlockState::Shredded {
            continue;
        }
        let Some(ops) = buf_ops.get(&mat.id) else {
            continue;
        };
        let mut referenced: BTreeSet<OpId> = BTreeSet::new();
        for (_, _, inner) in ops {
            for p in &inner.parent_op_ids {
                referenced.insert(*p);
            }
        }
        let mut best_name: Option<(Hlc, OpId, KeyId, Vec<u8>)> = None;
        let mut leaves = Vec::new();
        for (op_id, _, inner) in ops {
            let k = (&inner.hlc, *op_id);
            match &inner.body {
                OpBodyV1::BufferMeta {
                    key_id, name_mnb1, ..
                } => {
                    if let Some(mnb1) = name_mnb1 {
                        if best_name.as_ref().is_none_or(|c| k > (&c.0, c.1)) {
                            best_name = Some((inner.hlc.clone(), *op_id, *key_id, mnb1.clone()));
                        }
                    }
                    if !referenced.contains(op_id) {
                        leaves.push(SnapshotBufferLeafV1 {
                            op_id: *op_id,
                            hlc: inner.hlc.clone(),
                            is_tombstone: false,
                            deleted_at_ms: None,
                        });
                    }
                }
                OpBodyV1::Tombstone { deleted_at_ms } if !referenced.contains(op_id) => {
                    leaves.push(SnapshotBufferLeafV1 {
                        op_id: *op_id,
                        hlc: inner.hlc.clone(),
                        is_tombstone: true,
                        deleted_at_ms: Some(*deleted_at_ms),
                    });
                }
                _ => {}
            }
        }
        let Some((_, name_op_id, name_key_id, name_mnb1)) = best_name else {
            continue;
        };
        let _ = name_key_id;
        snap_buffers.push(SnapshotBufferV1 {
            id: mat.id,
            position: mat.position,
            key_id: mat.key_id,
            name_op_id,
            name_mnb1,
            field_hlc: mat.field_hlc,
            leaves,
            updated_at_ms: mat.updated_at_ms,
        });
    }

    // 2. Pack non-Shredded blocks (BOTH Active AND Trashed!)
    let mut snap_blocks = Vec::new();
    let mut leaf_count = 0u32;
    for mat in scoped.all_blocks() {
        if mat.state == BlockState::Shredded {
            continue;
        }
        let Some(ops) = blk_ops.get(&mat.id) else {
            continue;
        };
        let op_lookup: BTreeMap<OpId, &(OpId, DeviceId, InnerOpV1)> =
            ops.iter().map(|tuple| (tuple.0, tuple)).collect();
        let mut snap_leaves = Vec::with_capacity(mat.leaves.len());
        for leaf in &mat.leaves {
            let Some((_, dev_id, inner)) = op_lookup.get(&leaf.op_id) else {
                continue;
            };
            let body = match &inner.body {
                OpBodyV1::BlockContent {
                    tier, key_id, mnb1, ..
                } => SnapshotLeafBody::Content {
                    tier: *tier,
                    key_id: *key_id,
                    mnb1: mnb1.clone(),
                },
                OpBodyV1::Tombstone { deleted_at_ms } => SnapshotLeafBody::Tombstone {
                    deleted_at_ms: *deleted_at_ms,
                },
                _ => continue,
            };
            snap_leaves.push(SnapshotLeafV1 {
                op_id: leaf.op_id,
                hlc: inner.hlc.clone(),
                device_id: dev_id.clone(),
                actor: inner.actor.clone(),
                body,
            });
        }
        leaf_count = leaf_count.saturating_add(snap_leaves.len() as u32);
        snap_blocks.push(SnapshotBlockV1 {
            id: mat.id,
            buffer_id: mat.buffer_id,
            position: mat.position,
            lang: mat.lang,
            public_hint: mat.public_hint,
            field_hlc: mat.field_hlc,
            leaves: snap_leaves,
            updated_at_ms: mat.updated_at_ms,
        });
    }

    let header = SnapshotHeaderV1 {
        v: 1,
        journal_epoch,
        snapshot_id,
        covers_seq,
        buffer_count: snap_buffers.len() as u32,
        block_count: snap_blocks.len() as u32,
        leaf_count,
        created_by: engine.device_id.clone(),
        created_at_ms: now_ms,
    };
    let body = SnapshotBodyV1 {
        buffers: snap_buffers,
        blocks: snap_blocks,
    };
    let raw = encode_mnp1(smk_kid, smk, &header, &body, hdr_nonce, body_nonce)?;
    Ok((header, raw))
}

/// Mobile read-only state reconstructed from `MNP1(covers_seq = k)` + tail ops `(k, head_seq]`
/// + `/v1/keys` (`docs/sync-protocol.md` §9.2, `INV-SYNC-7`).
///
/// Strictly read-only: holds NO outbox and NEVER generates write ops.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MobileReadState {
    pub journal_epoch: Option<JournalEpoch>,
    pub snapshot_covers_seq: i64,
    pub last_seq: i64,
    pub buffers: BTreeMap<BufferId, SnapshotBufferV1>,
    pub blocks: BTreeMap<BlockId, SnapshotBlockV1>,
    /// Referenced parents seen in tail ops per entity so out-of-order tail ops still converge!
    pub referenced_buffer_parents: BTreeMap<BufferId, BTreeSet<OpId>>,
    pub referenced_block_parents: BTreeMap<BlockId, BTreeSet<OpId>>,
    /// All known `key_id`s seen for each entity (populated from `block_keys` unwrap + snapshot + tail ops).
    pub entity_keys: BTreeMap<String, BTreeSet<KeyId>>,
    pub keys: KeyTableState,
}

impl MobileReadState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all cached entities/cursors on `journal_epoch` change (read-only cache; zero data loss).
    pub fn reset_for_epoch(&mut self, epoch: JournalEpoch) {
        self.journal_epoch = Some(epoch);
        self.snapshot_covers_seq = 0;
        self.last_seq = 0;
        self.buffers.clear();
        self.blocks.clear();
        self.referenced_buffer_parents.clear();
        self.referenced_block_parents.clear();
        self.entity_keys.clear();
    }

    /// Monotonically install a decoded `MNP1` snapshot (`covers_seq` must strictly increase within same epoch).
    /// Returns `true` if installed, `false` if ignored as stale.
    pub fn install_snapshot(&mut self, header: SnapshotHeaderV1, body: SnapshotBodyV1) -> bool {
        if self.journal_epoch == Some(header.journal_epoch) && header.covers_seq <= self.snapshot_covers_seq {
            return false;
        }
        self.reset_for_epoch(header.journal_epoch);
        self.snapshot_covers_seq = header.covers_seq;
        self.last_seq = header.covers_seq;

        for buf in body.buffers {
            self.entity_keys
                .entry(buf.id.to_string())
                .or_default()
                .insert(buf.key_id);
            self.buffers.insert(buf.id, buf);
        }
        for blk in body.blocks {
            let ek = self.entity_keys.entry(blk.id.to_string()).or_default();
            for leaf in &blk.leaves {
                if let SnapshotLeafBody::Content { key_id, .. } = &leaf.body {
                    ek.insert(*key_id);
                }
            }
            self.blocks.insert(blk.id, blk);
        }
        true
    }

    /// Merge synced key table and index unwrapped `(key_id -> entity_id)` mappings using SMK.
    pub fn merge_key_table(
        &mut self,
        remote_keys: &KeyTableState,
        smks: &BTreeMap<SmkKid, Zeroizing<[u8; 32]>>,
    ) {
        self.keys.merge_from(remote_keys);
        for rec in self.keys.records.values() {
            if let Some(mnr1) = &rec.key_record {
                if let Ok(smk_kid_bytes) = peek_envelope_kid(MAGIC_MNR1, mnr1) {
                    let smk_kid = SmkKid::from_bytes(smk_kid_bytes);
                    if let Some(smk) = smks.get(&smk_kid) {
                        if let Ok(kr) = decrypt_mnr1(smk_kid, smk, rec.key_id, rec.wrap_gen, mnr1) {
                            self.entity_keys
                                .entry(kr.block_id.to_string())
                                .or_default()
                                .insert(rec.key_id);
                        }
                    }
                }
            }
        }
        self.prune_shredded_cache();
    }

    /// Remove fully shredded blocks/buffers from mobile read-only cache (`INV-SHRED-BOUND`).
    pub fn prune_shredded_cache(&mut self) {
        let shredded_blocks: Vec<BlockId> = self
            .blocks
            .keys()
            .copied()
            .filter(|id| {
                self.materialize_block(*id, &BTreeMap::new())
                    .is_some_and(|m| m.state == BlockState::Shredded)
            })
            .collect();
        for id in shredded_blocks {
            self.blocks.remove(&id);
        }
        let shredded_bufs: Vec<BufferId> = self
            .buffers
            .keys()
            .copied()
            .filter(|id| {
                self.materialize_buffer(*id, &BTreeMap::new())
                    .is_some_and(|m| m.state == BlockState::Shredded)
            })
            .collect();
        for id in shredded_bufs {
            self.buffers.remove(&id);
        }
    }

    /// Apply a single tail `MNS1` envelope (`sync-protocol.md` §9.2 #3).
    /// Handles out-of-order delivery, Update-Wins revival, and field LWW identically to desktop.
    pub fn apply_tail_envelope(
        &mut self,
        row: &RemoteEnvelopeRow,
        smks: &BTreeMap<SmkKid, Zeroizing<[u8; 32]>>,
    ) -> Result<(), CoreError> {
        let smk_kid = SmkKid::from_bytes(peek_envelope_kid(MAGIC_MNS1, &row.envelope)?);
        let smk = smks.get(&smk_kid).ok_or_else(|| {
            CoreError::new(
                ErrorCode::KeyMissing,
                format!("tail op {} needs unknown SMK {smk_kid}", row.op_id),
                "Refresh device keys with 'mynote device refresh'",
            )
        })?;
        let inner = decrypt_mns1(smk_kid, smk, row.op_id, &row.device_id, row.key_id, &row.envelope)?;
        self.apply_decoded_tail_op(row.op_id, &row.device_id, inner)?;
        self.last_seq = self.last_seq.max(row.seq);
        Ok(())
    }

    /// Apply an already-decrypted tail op into `MobileReadState`.
    pub fn apply_decoded_tail_op(
        &mut self,
        op_id: OpId,
        device_id: &DeviceId,
        inner: InnerOpV1,
    ) -> Result<(), CoreError> {
        if let Some(kid) = inner.key_id() {
            self.entity_keys
                .entry(inner.entity_id.clone())
                .or_default()
                .insert(kid);
        }
        match inner.entity_type {
            EntityType::Buffer => {
                let buf_id = BufferId::parse(&inner.entity_id)?;
                let refs = self.referenced_buffer_parents.entry(buf_id).or_default();
                for p in &inner.parent_op_ids {
                    refs.insert(*p);
                }
                let already_superseded = refs.contains(&op_id);
                let z = zero_hlc();

                match inner.body {
                    OpBodyV1::BufferMeta {
                        key_id,
                        name_mnb1,
                        position,
                    } => {
                        let entry = self.buffers.entry(buf_id).or_insert_with(|| SnapshotBufferV1 {
                            id: buf_id,
                            position: String::new(),
                            key_id,
                            name_op_id: OpId::from_bytes([0u8; 16]),
                            name_mnb1: Vec::new(),
                            field_hlc: BufferFieldHlc {
                                name: z.clone(),
                                position: z.clone(),
                            },
                            leaves: Vec::new(),
                            updated_at_ms: 0,
                        });
                        entry.updated_at_ms = entry.updated_at_ms.max(inner.hlc.wall_ms as i64);
                        if let Some(mnb1) = name_mnb1 {
                            if inner.hlc > entry.field_hlc.name
                                || (inner.hlc == entry.field_hlc.name && op_id > entry.name_op_id)
                            {
                                entry.field_hlc.name = inner.hlc.clone();
                                entry.name_op_id = op_id;
                                entry.name_mnb1 = mnb1;
                                entry.key_id = key_id;
                            }
                        }
                        if let Some(pos) = position {
                            if inner.hlc >= entry.field_hlc.position {
                                entry.field_hlc.position = inner.hlc.clone();
                                entry.position = pos;
                            }
                        }
                        entry.leaves.retain(|l| !refs.contains(&l.op_id));
                        if !already_superseded && !entry.leaves.iter().any(|l| l.op_id == op_id) {
                            entry.leaves.push(SnapshotBufferLeafV1 {
                                op_id,
                                hlc: inner.hlc,
                                is_tombstone: false,
                                deleted_at_ms: None,
                            });
                        }
                    }
                    OpBodyV1::Tombstone { deleted_at_ms } => {
                        let entry = self.buffers.entry(buf_id).or_insert_with(|| SnapshotBufferV1 {
                            id: buf_id,
                            position: String::new(),
                            key_id: KeyId::from_bytes([0u8; 16]),
                            name_op_id: OpId::from_bytes([0u8; 16]),
                            name_mnb1: Vec::new(),
                            field_hlc: BufferFieldHlc {
                                name: z.clone(),
                                position: z.clone(),
                            },
                            leaves: Vec::new(),
                            updated_at_ms: 0,
                        });
                        entry.updated_at_ms = entry.updated_at_ms.max(inner.hlc.wall_ms as i64);
                        entry.leaves.retain(|l| !refs.contains(&l.op_id));
                        if !already_superseded && !entry.leaves.iter().any(|l| l.op_id == op_id) {
                            entry.leaves.push(SnapshotBufferLeafV1 {
                                op_id,
                                hlc: inner.hlc,
                                is_tombstone: true,
                                deleted_at_ms: Some(deleted_at_ms),
                            });
                        }
                    }
                    _ => {}
                }
            }
            EntityType::Block => {
                let blk_id = BlockId::parse(&inner.entity_id)?;
                let refs = self.referenced_block_parents.entry(blk_id).or_default();
                if inner.op_type.is_dag_op() {
                    for p in &inner.parent_op_ids {
                        refs.insert(*p);
                    }
                }
                let already_superseded = refs.contains(&op_id);
                let z = zero_hlc();

                match inner.body {
                    OpBodyV1::BlockContent {
                        buffer_id,
                        position,
                        lang,
                        public_hint,
                        tier,
                        key_id,
                        mnb1,
                    } => {
                        let entry = self.blocks.entry(blk_id).or_insert_with(|| SnapshotBlockV1 {
                            id: blk_id,
                            buffer_id: BufferId::from_bytes([0u8; 16]),
                            position: String::new(),
                            lang: "text".to_string(),
                            public_hint: None,
                            field_hlc: BlockFieldHlc {
                                buffer_id: z.clone(),
                                position: z.clone(),
                                lang: z.clone(),
                                public_hint: z.clone(),
                            },
                            leaves: Vec::new(),
                            updated_at_ms: 0,
                        });
                        entry.updated_at_ms = entry.updated_at_ms.max(inner.hlc.wall_ms as i64);
                        apply_block_field_lww(entry, &inner.hlc, buffer_id, position, lang, public_hint);
                        entry.leaves.retain(|l| !refs.contains(&l.op_id));
                        if !already_superseded && !entry.leaves.iter().any(|l| l.op_id == op_id) {
                            entry.leaves.push(SnapshotLeafV1 {
                                op_id,
                                hlc: inner.hlc,
                                device_id: device_id.clone(),
                                actor: inner.actor,
                                body: SnapshotLeafBody::Content { tier, key_id, mnb1 },
                            });
                        }
                        entry
                            .leaves
                            .sort_by(|a, b| (&b.hlc, b.op_id).cmp(&(&a.hlc, a.op_id)));
                    }
                    OpBodyV1::BlockMeta {
                        buffer_id,
                        position,
                        lang,
                        public_hint,
                    } => {
                        let entry = self.blocks.entry(blk_id).or_insert_with(|| SnapshotBlockV1 {
                            id: blk_id,
                            buffer_id: BufferId::from_bytes([0u8; 16]),
                            position: String::new(),
                            lang: "text".to_string(),
                            public_hint: None,
                            field_hlc: BlockFieldHlc {
                                buffer_id: z.clone(),
                                position: z.clone(),
                                lang: z.clone(),
                                public_hint: z.clone(),
                            },
                            leaves: Vec::new(),
                            updated_at_ms: 0,
                        });
                        entry.updated_at_ms = entry.updated_at_ms.max(inner.hlc.wall_ms as i64);
                        apply_block_field_lww(entry, &inner.hlc, buffer_id, position, lang, public_hint);
                    }
                    OpBodyV1::Tombstone { deleted_at_ms } => {
                        let entry = self.blocks.entry(blk_id).or_insert_with(|| SnapshotBlockV1 {
                            id: blk_id,
                            buffer_id: BufferId::from_bytes([0u8; 16]),
                            position: String::new(),
                            lang: "text".to_string(),
                            public_hint: None,
                            field_hlc: BlockFieldHlc {
                                buffer_id: z.clone(),
                                position: z.clone(),
                                lang: z.clone(),
                                public_hint: z.clone(),
                            },
                            leaves: Vec::new(),
                            updated_at_ms: 0,
                        });
                        entry.updated_at_ms = entry.updated_at_ms.max(inner.hlc.wall_ms as i64);
                        entry.leaves.retain(|l| !refs.contains(&l.op_id));
                        if !already_superseded && !entry.leaves.iter().any(|l| l.op_id == op_id) {
                            entry.leaves.push(SnapshotLeafV1 {
                                op_id,
                                hlc: inner.hlc,
                                device_id: device_id.clone(),
                                actor: inner.actor,
                                body: SnapshotLeafBody::Tombstone { deleted_at_ms },
                            });
                        }
                        entry
                            .leaves
                            .sort_by(|a, b| (&b.hlc, b.op_id).cmp(&(&a.hlc, a.op_id)));
                    }
                    OpBodyV1::BufferMeta { .. } => {}
                }
            }
        }
        Ok(())
    }

    fn unwrap_key_record(
        &self,
        key_id: KeyId,
        smks: &BTreeMap<SmkKid, Zeroizing<[u8; 32]>>,
    ) -> Option<KeyRecordV1> {
        if self.keys.is_shredded(&key_id) {
            return None;
        }
        let row = self.keys.records.get(&key_id)?;
        let mnr1 = row.key_record.as_ref()?;
        let smk_kid = SmkKid::from_bytes(peek_envelope_kid(MAGIC_MNR1, mnr1).ok()?);
        let smk = smks.get(&smk_kid)?;
        decrypt_mnr1(smk_kid, smk, key_id, row.wrap_gen, mnr1).ok()
    }

    fn entity_has_unshredded_key(&self, entity_id: &str) -> bool {
        self.entity_keys
            .get(entity_id)
            .is_some_and(|ks| ks.iter().any(|k| !self.keys.is_shredded(k)))
    }

    pub fn materialize_buffer(
        &self,
        buffer_id: BufferId,
        smks: &BTreeMap<SmkKid, Zeroizing<[u8; 32]>>,
    ) -> Option<MaterializedBuffer> {
        let buf = self.buffers.get(&buffer_id)?;
        let has_unshredded_key =
            !self.keys.is_shredded(&buf.key_id) || self.entity_has_unshredded_key(&buffer_id.to_string());
        let has_live_leaf = if buf.leaves.is_empty() {
            has_unshredded_key
        } else {
            has_unshredded_key && buf.leaves.iter().any(|l| !l.is_tombstone)
        };
        let state = if has_live_leaf {
            BlockState::Active
        } else if has_unshredded_key {
            BlockState::Trashed
        } else {
            BlockState::Shredded
        };
        let name = if state == BlockState::Shredded {
            String::new()
        } else {
            self.unwrap_key_record(buf.key_id, smks)
                .and_then(|kr| {
                    if kr.bdek.len() != 32 {
                        return None;
                    }
                    let mut bdek = Zeroizing::new([0u8; 32]);
                    bdek.copy_from_slice(&kr.bdek);
                    decrypt_mnb1(
                        buffer_id.as_bytes(),
                        buf.name_op_id,
                        buf.key_id,
                        &bdek,
                        &buf.name_mnb1,
                    )
                    .ok()
                })
                .unwrap_or_default()
        };
        let deleted_at_ms = if state == BlockState::Active {
            None
        } else {
            buf.leaves
                .iter()
                .filter_map(|l| l.deleted_at_ms)
                .max()
                .or(Some(buf.updated_at_ms))
        };
        Some(MaterializedBuffer {
            id: buf.id,
            name,
            key_id: buf.key_id,
            position: buf.position.clone(),
            field_hlc: buf.field_hlc.clone(),
            state,
            updated_at_ms: buf.updated_at_ms,
            deleted_at_ms,
        })
    }

    pub fn materialize_block(
        &self,
        block_id: BlockId,
        smks: &BTreeMap<SmkKid, Zeroizing<[u8; 32]>>,
    ) -> Option<MaterializedBlock> {
        let blk = self.blocks.get(&block_id)?;
        let mut leaves = Vec::with_capacity(blk.leaves.len());
        let mut latest_tombstone_ms: Option<i64> = None;

        for leaf in &blk.leaves {
            let (tier, body) = match &leaf.body {
                SnapshotLeafBody::Tombstone { deleted_at_ms } => {
                    latest_tombstone_ms =
                        Some(latest_tombstone_ms.map_or(*deleted_at_ms, |m| m.max(*deleted_at_ms)));
                    (
                        None,
                        LeafBody::Tombstone {
                            deleted_at_ms: *deleted_at_ms,
                        },
                    )
                }
                SnapshotLeafBody::Content { tier, key_id, mnb1 } => {
                    let body = if self.keys.is_shredded(key_id) {
                        LeafBody::KeyUnavailable {
                            key_id: *key_id,
                            shredded: true,
                        }
                    } else if *tier == 2 {
                        LeafBody::Sealed {
                            key_id: *key_id,
                            mnb1: mnb1.clone(),
                        }
                    } else {
                        match self.unwrap_key_record(*key_id, smks) {
                            Some(kr) if kr.tier == 1 && kr.bdek.len() == 32 => {
                                let mut bdek = Zeroizing::new([0u8; 32]);
                                bdek.copy_from_slice(&kr.bdek);
                                match decrypt_mnb1(block_id.as_bytes(), leaf.op_id, *key_id, &bdek, mnb1) {
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
                                key_id: *key_id,
                                shredded: false,
                            },
                        }
                    };
                    (Some(*tier), body)
                }
            };
            leaves.push(BlockLeaf {
                op_id: leaf.op_id,
                hlc: leaf.hlc.clone(),
                device_id: leaf.device_id.clone(),
                actor: leaf.actor.clone(),
                tier,
                body,
            });
        }
        leaves.sort_by(|a, b| (&b.hlc, b.op_id).cmp(&(&a.hlc, a.op_id)));

        let live_leaves: Vec<&BlockLeaf> = leaves.iter().filter(|l| l.is_live()).collect();
        let has_unshredded = self.entity_has_unshredded_key(&block_id.to_string());
        let state = if !live_leaves.is_empty() {
            BlockState::Active
        } else if has_unshredded {
            BlockState::Trashed
        } else {
            BlockState::Shredded
        };

        let has_locked_live = live_leaves.iter().any(|l| l.tier == Some(2));
        let has_unlocked_live = live_leaves.iter().any(|l| l.tier == Some(1));
        let is_locked = has_locked_live;
        let has_unlocked_concurrent_version = has_locked_live && has_unlocked_live;
        let display_op_id = if state == BlockState::Active {
            let candidates = if is_locked {
                live_leaves
                    .iter()
                    .copied()
                    .filter(|l| l.tier == Some(2))
                    .collect::<Vec<_>>()
            } else {
                live_leaves
            };
            candidates
                .into_iter()
                .max_by(|a, b| (&a.hlc, a.op_id).cmp(&(&b.hlc, b.op_id)))
                .map(|l| l.op_id)
        } else {
            None
        };
        let deleted_at_ms = if state == BlockState::Active {
            None
        } else {
            latest_tombstone_ms.or(Some(blk.updated_at_ms))
        };

        let mut field_hlc = blk.field_hlc.clone();
        if field_hlc.public_hint.wall_ms == 0 {
            field_hlc.public_hint = field_hlc.buffer_id.clone();
        }
        if field_hlc.buffer_id.wall_ms == 0 || blk.leaves.is_empty() {
            return None;
        }

        Some(MaterializedBlock {
            id: blk.id,
            buffer_id: blk.buffer_id,
            position: blk.position.clone(),
            lang: blk.lang.clone(),
            public_hint: blk.public_hint.clone(),
            field_hlc,
            state,
            is_locked,
            has_unlocked_concurrent_version,
            display_op_id,
            leaves,
            updated_at_ms: blk.updated_at_ms,
            deleted_at_ms,
        })
    }

    /// Return all non-Shredded blocks in deterministic `(position, id)` order (for `INV-SYNC-7` comparison).
    pub fn all_non_shredded_blocks(
        &self,
        smks: &BTreeMap<SmkKid, Zeroizing<[u8; 32]>>,
    ) -> Vec<MaterializedBlock> {
        let mut out: Vec<MaterializedBlock> = self
            .blocks
            .keys()
            .filter_map(|id| self.materialize_block(*id, smks))
            .filter(|b| b.state != BlockState::Shredded)
            .collect();
        out.sort_by(|a, b| {
            fractional_index::compare_order(&a.position, &a.id.to_string(), &b.position, &b.id.to_string())
        });
        out
    }

    pub fn all_non_shredded_buffers(
        &self,
        smks: &BTreeMap<SmkKid, Zeroizing<[u8; 32]>>,
    ) -> Vec<MaterializedBuffer> {
        let mut out: Vec<MaterializedBuffer> = self
            .buffers
            .keys()
            .filter_map(|id| self.materialize_buffer(*id, smks))
            .filter(|b| b.state != BlockState::Shredded)
            .collect();
        out.sort_by(|a, b| {
            fractional_index::compare_order(&a.position, &a.id.to_string(), &b.position, &b.id.to_string())
        });
        out
    }
}

fn zero_hlc() -> Hlc {
    Hlc::new(0, 0, DeviceId::parse("dev_00000000").expect("valid zero dev id"))
}

fn apply_block_field_lww(
    entry: &mut SnapshotBlockV1,
    hlc: &Hlc,
    buffer_id: Option<BufferId>,
    position: Option<String>,
    lang: Option<String>,
    public_hint: Option<Option<String>>,
) {
    if let Some(v) = buffer_id {
        if hlc >= &entry.field_hlc.buffer_id {
            entry.field_hlc.buffer_id = hlc.clone();
            entry.buffer_id = v;
        }
    }
    if let Some(v) = position {
        if hlc >= &entry.field_hlc.position {
            entry.field_hlc.position = hlc.clone();
            entry.position = v;
        }
    }
    if let Some(v) = lang {
        if hlc >= &entry.field_hlc.lang {
            entry.field_hlc.lang = hlc.clone();
            entry.lang = v;
        }
    }
    if let Some(v) = public_hint {
        if hlc >= &entry.field_hlc.public_hint {
            entry.field_hlc.public_hint = hlc.clone();
            entry.public_hint = v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt_mnb1, encrypt_mnr1, encrypt_mns1, KeyRecordV1};
    use crate::hlc::HlcClock;
    use crate::ids::MonotonicUlidGen;
    use crate::model::{KeyRecordRow, OpType};
    use crate::sync::LocalOpRecord;
    use proptest::prelude::*;

    #[test]
    fn mnp1_roundtrip_tamper_rejection_and_inv_sync_7_with_trash_revival_and_out_of_order_tail() {
        let mut g = MonotonicUlidGen::new();
        let dev_a = DeviceId::parse("dev_mac00001").unwrap();
        let dev_b = DeviceId::parse("dev_lin00002").unwrap();
        let epoch = JournalEpoch::from_random_bytes([0x11; 16]);
        let smk_kid = SmkKid::from_ulid(g.next(1_000, [1; 10]));
        let smk = Zeroizing::new([0x22u8; 32]);

        let mut engine = EngineSnapshot::new(dev_a.clone(), 1_000);
        engine.bootstrap_completed = true;
        engine.journal_epoch = Some(epoch);
        engine.smks.insert(smk_kid, smk.clone());

        let mut clock_a = HlcClock::new(dev_a.clone(), 1_000);
        let mut clock_b = HlcClock::new(dev_b.clone(), 1_000);
        let mut seq = 0i64;

        let mut push_op =
            |eng: &mut EngineSnapshot, dev: &DeviceId, op_id: OpId, inner: InnerOpV1, nonce: u8| {
                seq += 1;
                let env = encrypt_mns1(smk_kid, &smk, op_id, dev, &inner, [nonce; 24]).unwrap();
                let rec = LocalOpRecord {
                    op_id,
                    server_seq: Some(seq),
                    sync_blocked_reason: None,
                    device_id: dev.clone(),
                    entity_type: inner.entity_type,
                    entity_id: inner.entity_id.clone(),
                    parent_op_ids: inner.parent_op_ids.clone(),
                    op_type: inner.op_type,
                    hlc: inner.hlc.clone(),
                    actor: inner.actor.clone(),
                    key_id: inner.key_id(),
                    smk_kid,
                    envelope: env.clone(),
                    created_at_ms: inner.hlc.wall_ms as i64,
                };
                let remote = RemoteEnvelopeRow {
                    seq,
                    op_id,
                    key_id: inner.key_id(),
                    device_id: dev.clone(),
                    created_at: inner.hlc.wall_ms as i64,
                    envelope: env,
                };
                eng.ops.insert(op_id, rec);
                eng.last_seq = seq;
                remote
            };

        let add_key =
            |eng: &mut EngineSnapshot, kid: KeyId, entity: crate::ids::Ulid, bdek: [u8; 32], n: u8| {
                let kr = KeyRecordV1 {
                    v: 1,
                    key_id: kid,
                    block_id: entity,
                    tier: 1,
                    created_hlc: Hlc::new(1_000, 0, dev_a.clone()).canonical_string(),
                    created_by: dev_a.clone(),
                    bdek: bdek.to_vec(),
                };
                let mnr1 = encrypt_mnr1(smk_kid, &smk, 1, &kr, [n; 24]).unwrap();
                eng.keys.insert_record(KeyRecordRow {
                    key_id: kid,
                    wrap_gen: 1,
                    key_record: Some(mnr1),
                    created_at_ms: 1_000,
                });
            };

        // Buffer "scratch"
        let buf_id = BufferId::from_ulid(g.next(1_000, [2; 10]));
        let buf_kid = KeyId::from_ulid(g.next(1_000, [3; 10]));
        let buf_bdek = [0x31u8; 32];
        add_key(&mut engine, buf_kid, buf_id.0, buf_bdek, 1);
        let op_buf = OpId::from_ulid(g.next(1_001, [4; 10]));
        let name_mnb1 =
            encrypt_mnb1(buf_id.as_bytes(), op_buf, buf_kid, &buf_bdek, "scratch", [2; 24]).unwrap();
        push_op(
            &mut engine,
            &dev_a,
            op_buf,
            InnerOpV1 {
                v: 1,
                entity_type: EntityType::Buffer,
                entity_id: buf_id.to_string(),
                op_type: OpType::Create,
                parent_op_ids: vec![],
                hlc: clock_a.tick(1_001),
                actor: "human".into(),
                body: OpBodyV1::BufferMeta {
                    key_id: buf_kid,
                    name_mnb1: Some(name_mnb1),
                    position: Some("V0001".into()),
                },
            },
            3,
        );

        // Block 1: created then trashed BEFORE snapshot k
        let blk1 = BlockId::from_ulid(g.next(1_002, [5; 10]));
        let blk1_kid = KeyId::from_ulid(g.next(1_002, [6; 10]));
        let blk1_bdek = [0x41u8; 32];
        add_key(&mut engine, blk1_kid, blk1.0, blk1_bdek, 4);
        let op1_create = OpId::from_ulid(g.next(1_002, [7; 10]));
        let mnb1_1 = encrypt_mnb1(
            blk1.as_bytes(),
            op1_create,
            blk1_kid,
            &blk1_bdek,
            "hello v1",
            [5; 24],
        )
        .unwrap();
        push_op(
            &mut engine,
            &dev_a,
            op1_create,
            InnerOpV1 {
                v: 1,
                entity_type: EntityType::Block,
                entity_id: blk1.to_string(),
                op_type: OpType::Create,
                parent_op_ids: vec![],
                hlc: clock_a.tick(1_002),
                actor: "human".into(),
                body: OpBodyV1::BlockContent {
                    buffer_id: Some(buf_id),
                    position: Some("V0001".into()),
                    lang: Some("markdown".into()),
                    public_hint: None,
                    tier: 1,
                    key_id: blk1_kid,
                    mnb1: mnb1_1,
                },
            },
            6,
        );
        let op1_del = OpId::from_ulid(g.next(1_003, [8; 10]));
        push_op(
            &mut engine,
            &dev_a,
            op1_del,
            InnerOpV1 {
                v: 1,
                entity_type: EntityType::Block,
                entity_id: blk1.to_string(),
                op_type: OpType::Delete,
                parent_op_ids: vec![op1_create],
                hlc: clock_a.tick(1_003),
                actor: "human".into(),
                body: OpBodyV1::Tombstone { deleted_at_ms: 1_003 },
            },
            7,
        );

        // Export MNP1 snapshot at covers_seq = 3 (blk1 is Trashed!)
        let covers_seq = engine.last_seq;
        let snap_id = SnapshotId::from_ulid(g.next(1_004, [9; 10]));
        let (hdr, raw_mnp1) = pack_state_snapshot(
            &engine, snap_id, covers_seq, smk_kid, &smk, 1_004, [10; 24], [11; 24],
        )
        .unwrap();
        assert_eq!(hdr.covers_seq, 3);
        assert_eq!(hdr.block_count, 1);

        // Tamper detection on MNP1 header & body
        let mut bad_hdr = raw_mnp1.clone();
        bad_hdr[38] ^= 0x01; // flip covers_seq byte in prefix -> AAD mismatch!
        assert!(decode_mnp1(&engine.smks, &bad_hdr).is_err());
        let mut bad_body = raw_mnp1.clone();
        *bad_body.last_mut().unwrap() ^= 0x80;
        assert!(decode_mnp1(&engine.smks, &bad_body).is_err());

        // Tail ops AFTER covers_seq:
        // op_revive (concurrent offline Update-Wins on blk1!) -> then op_merge (resolves both leaves!)
        let op1_revive = OpId::from_ulid(g.next(1_005, [12; 10]));
        let mnb1_rev = encrypt_mnb1(
            blk1.as_bytes(),
            op1_revive,
            blk1_kid,
            &blk1_bdek,
            "offline revive!",
            [12; 24],
        )
        .unwrap();
        let tail1 = push_op(
            &mut engine,
            &dev_b,
            op1_revive,
            InnerOpV1 {
                v: 1,
                entity_type: EntityType::Block,
                entity_id: blk1.to_string(),
                op_type: OpType::Update,
                parent_op_ids: vec![op1_create],
                hlc: clock_b.tick(1_005),
                actor: "human".into(),
                body: OpBodyV1::BlockContent {
                    buffer_id: None,
                    position: None,
                    lang: None,
                    public_hint: None,
                    tier: 1,
                    key_id: blk1_kid,
                    mnb1: mnb1_rev,
                },
            },
            13,
        );
        let op1_merge = OpId::from_ulid(g.next(1_006, [13; 10]));
        let mnb1_merge = encrypt_mnb1(
            blk1.as_bytes(),
            op1_merge,
            blk1_kid,
            &blk1_bdek,
            "revived & merged",
            [14; 24],
        )
        .unwrap();
        let tail2 = push_op(
            &mut engine,
            &dev_a,
            op1_merge,
            InnerOpV1 {
                v: 1,
                entity_type: EntityType::Block,
                entity_id: blk1.to_string(),
                op_type: OpType::Update,
                parent_op_ids: vec![op1_del, op1_revive],
                hlc: clock_a.tick(1_006),
                actor: "human".into(),
                body: OpBodyV1::BlockContent {
                    buffer_id: None,
                    position: None,
                    lang: Some("json".into()),
                    public_hint: None,
                    tier: 1,
                    key_id: blk1_kid,
                    mnb1: mnb1_merge,
                },
            },
            15,
        );

        // Mobile installs MNP1, syncs keys, and applies tail ops OUT OF ORDER (tail2 before tail1)!
        let (dec_hdr, dec_body) = decode_mnp1(&engine.smks, &raw_mnp1).unwrap();
        let mut mobile = MobileReadState::new();
        assert!(mobile.install_snapshot(dec_hdr.clone(), dec_body.clone()));
        // Stale/equal snapshot in same epoch MUST be rejected!
        assert!(!mobile.install_snapshot(dec_hdr, dec_body));
        mobile.merge_key_table(&engine.keys, &engine.smks);
        mobile.apply_tail_envelope(&tail2, &engine.smks).unwrap();
        mobile.apply_tail_envelope(&tail1, &engine.smks).unwrap();

        // INV-SYNC-7: Mobile view MUST equal Desktop full-history view byte-for-byte!
        assert_eq!(
            mobile.all_non_shredded_buffers(&engine.smks),
            engine.all_buffers()
        );
        assert_eq!(mobile.all_non_shredded_blocks(&engine.smks), engine.all_blocks());
    }

    proptest! {
        // INV-SYNC-7 property test: snapshot at ANY cut point k + arbitrary tail order == full replay
        #[test]
        fn inv_sync_7_arbitrary_cut_and_tail_permutation_equals_desktop(
            cut_idx in 1usize..6,
            reverse_tail in any::<bool>(),
            shred_b2 in any::<bool>(),
        ) {
            let mut g = MonotonicUlidGen::new();
            let dev_a = DeviceId::parse("dev_mac00001").unwrap();
            let dev_b = DeviceId::parse("dev_lin00002").unwrap();
            let epoch = JournalEpoch::from_random_bytes([0x55; 16]);
            let smk_kid = SmkKid::from_ulid(g.next(10_000, [1; 10]));
            let smk = Zeroizing::new([0x66u8; 32]);

            let mut engine = EngineSnapshot::new(dev_a.clone(), 10_000);
            engine.bootstrap_completed = true;
            engine.journal_epoch = Some(epoch);
            engine.smks.insert(smk_kid, smk.clone());
            let mut clock_a = HlcClock::new(dev_a.clone(), 10_000);
            let mut clock_b = HlcClock::new(dev_b.clone(), 10_000);

            let buf_id = BufferId::from_ulid(g.next(10_000, [2; 10]));
            let buf_kid = KeyId::from_ulid(g.next(10_000, [3; 10]));
            let buf_bdek = [0x11u8; 32];
            let blk1 = BlockId::from_ulid(g.next(10_000, [4; 10]));
            let k1 = KeyId::from_ulid(g.next(10_000, [5; 10]));
            let bdek1 = [0x22u8; 32];
            let blk2 = BlockId::from_ulid(g.next(10_000, [6; 10]));
            let k2 = KeyId::from_ulid(g.next(10_000, [7; 10]));
            let bdek2 = [0x33u8; 32];

            for (kid, ent, bdek, n) in [
                (buf_kid, buf_id.0, buf_bdek, 1u8),
                (k1, blk1.0, bdek1, 2u8),
                (k2, blk2.0, bdek2, 3u8),
            ] {
                let kr = KeyRecordV1 {
                    v: 1,
                    key_id: kid,
                    block_id: ent,
                    tier: 1,
                    created_hlc: Hlc::new(10_000, 0, dev_a.clone()).canonical_string(),
                    created_by: dev_a.clone(),
                    bdek: bdek.to_vec(),
                };
                engine.keys.insert_record(KeyRecordRow {
                    key_id: kid,
                    wrap_gen: 1,
                    key_record: Some(encrypt_mnr1(smk_kid, &smk, 1, &kr, [n; 24]).unwrap()),
                    created_at_ms: 10_000,
                });
            }

            let op0 = OpId::from_ulid(g.next(10_001, [10; 10]));
            let op1 = OpId::from_ulid(g.next(10_002, [11; 10]));
            let op2 = OpId::from_ulid(g.next(10_003, [12; 10]));
            let op3 = OpId::from_ulid(g.next(10_004, [13; 10]));
            let op4 = OpId::from_ulid(g.next(10_005, [14; 10]));
            let op5 = OpId::from_ulid(g.next(10_006, [15; 10]));
            let op6 = OpId::from_ulid(g.next(10_007, [16; 10]));

            let ops_spec: Vec<(OpId, DeviceId, InnerOpV1, u8)> = vec![
                (op0, dev_a.clone(), InnerOpV1 {
                    v: 1, entity_type: EntityType::Buffer, entity_id: buf_id.to_string(),
                    op_type: OpType::Create, parent_op_ids: vec![], hlc: clock_a.tick(10_001), actor: "human".into(),
                    body: OpBodyV1::BufferMeta {
                        key_id: buf_kid,
                        name_mnb1: Some(encrypt_mnb1(buf_id.as_bytes(), op0, buf_kid, &buf_bdek, "main", [20; 24]).unwrap()),
                        position: Some("V0001".into()),
                    },
                }, 30),
                (op1, dev_a.clone(), InnerOpV1 {
                    v: 1, entity_type: EntityType::Block, entity_id: blk1.to_string(),
                    op_type: OpType::Create, parent_op_ids: vec![], hlc: clock_a.tick(10_002), actor: "human".into(),
                    body: OpBodyV1::BlockContent {
                        buffer_id: Some(buf_id), position: Some("V0001".into()), lang: Some("text".into()), public_hint: None,
                        tier: 1, key_id: k1,
                        mnb1: encrypt_mnb1(blk1.as_bytes(), op1, k1, &bdek1, "b1-v1", [21; 24]).unwrap(),
                    },
                }, 31),
                (op2, dev_a.clone(), InnerOpV1 {
                    v: 1, entity_type: EntityType::Block, entity_id: blk2.to_string(),
                    op_type: OpType::Create, parent_op_ids: vec![], hlc: clock_a.tick(10_003), actor: "human".into(),
                    body: OpBodyV1::BlockContent {
                        buffer_id: Some(buf_id), position: Some("V0002".into()), lang: Some("json".into()), public_hint: None,
                        tier: 1, key_id: k2,
                        mnb1: encrypt_mnb1(blk2.as_bytes(), op2, k2, &bdek2, "{\"a\":1}", [22; 24]).unwrap(),
                    },
                }, 32),
                (op3, dev_a.clone(), InnerOpV1 {
                    v: 1, entity_type: EntityType::Block, entity_id: blk1.to_string(),
                    op_type: OpType::Delete, parent_op_ids: vec![op1], hlc: clock_a.tick(10_004), actor: "human".into(),
                    body: OpBodyV1::Tombstone { deleted_at_ms: 10_004 },
                }, 33),
                (op4, dev_b.clone(), InnerOpV1 {
                    v: 1, entity_type: EntityType::Block, entity_id: blk1.to_string(),
                    op_type: OpType::Update, parent_op_ids: vec![op1], hlc: clock_b.tick(10_005), actor: "human".into(),
                    body: OpBodyV1::BlockContent {
                        buffer_id: None, position: None, lang: None, public_hint: None,
                        tier: 1, key_id: k1,
                        mnb1: encrypt_mnb1(blk1.as_bytes(), op4, k1, &bdek1, "b1-concurrent-revive", [23; 24]).unwrap(),
                    },
                }, 34),
                (op5, dev_a.clone(), InnerOpV1 {
                    v: 1, entity_type: EntityType::Block, entity_id: blk2.to_string(),
                    op_type: OpType::Delete, parent_op_ids: vec![op2], hlc: clock_a.tick(10_006), actor: "human".into(),
                    body: OpBodyV1::Tombstone { deleted_at_ms: 10_006 },
                }, 35),
                (op6, dev_b.clone(), InnerOpV1 {
                    v: 1, entity_type: EntityType::Block, entity_id: blk1.to_string(),
                    op_type: OpType::SetMeta, parent_op_ids: vec![], hlc: clock_b.tick(10_007), actor: "human".into(),
                    body: OpBodyV1::BlockMeta { buffer_id: None, position: None, lang: Some("sql".into()), public_hint: None },
                }, 36),
            ];

            let mut all_remote = Vec::new();
            for (idx, (op_id, dev, inner, nonce)) in ops_spec.into_iter().enumerate() {
                let seq = (idx + 1) as i64;
                let env = encrypt_mns1(smk_kid, &smk, op_id, &dev, &inner, [nonce; 24]).unwrap();
                engine.ops.insert(op_id, LocalOpRecord {
                    op_id, server_seq: Some(seq), sync_blocked_reason: None, device_id: dev.clone(),
                    entity_type: inner.entity_type, entity_id: inner.entity_id.clone(),
                    parent_op_ids: inner.parent_op_ids.clone(), op_type: inner.op_type,
                    hlc: inner.hlc.clone(), actor: inner.actor.clone(), key_id: inner.key_id(),
                    smk_kid, envelope: env.clone(), created_at_ms: inner.hlc.wall_ms as i64,
                });
                engine.last_seq = seq;
                all_remote.push(RemoteEnvelopeRow {
                    seq, op_id, key_id: inner.key_id(), device_id: dev, created_at: inner.hlc.wall_ms as i64, envelope: env,
                });
            }

            let snap_id = SnapshotId::from_ulid(g.next(10_010, [99; 10]));
            let (_, raw_snap) = pack_state_snapshot(&engine, snap_id, cut_idx as i64, smk_kid, &smk, 10_010, [40; 24], [41; 24]).unwrap();

            if shred_b2 {
                engine.keys.executed_tombstones.insert(k2);
                if let Some(r) = engine.keys.records.get_mut(&k2) {
                    r.key_record = None;
                }
            }

            let (dec_hdr, dec_body) = decode_mnp1(&engine.smks, &raw_snap).unwrap();
            let mut mobile = MobileReadState::new();
            mobile.install_snapshot(dec_hdr, dec_body);
            let mut tail: Vec<RemoteEnvelopeRow> = all_remote.into_iter().filter(|r| r.seq > cut_idx as i64).collect();
            if reverse_tail {
                tail.reverse();
            }
            for r in &tail {
                mobile.apply_tail_envelope(r, &engine.smks).unwrap();
            }
            mobile.merge_key_table(&engine.keys, &engine.smks);

            let desktop_non_shredded: Vec<MaterializedBlock> = engine
                .all_blocks()
                .into_iter()
                .filter(|b| b.state != BlockState::Shredded)
                .collect();
            prop_assert_eq!(mobile.all_non_shredded_blocks(&engine.smks), desktop_non_shredded);
            let desktop_bufs: Vec<MaterializedBuffer> = engine
                .all_buffers()
                .into_iter()
                .filter(|b| b.state != BlockState::Shredded)
                .collect();
            prop_assert_eq!(mobile.all_non_shredded_buffers(&engine.smks), desktop_bufs);
        }
    }
}
