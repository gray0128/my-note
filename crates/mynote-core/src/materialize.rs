use crate::hlc::Hlc;
use crate::ids::{BlockId, BufferId, DeviceId, KeyId, OpId};
use crate::model::{
    BlockFieldHlc, BlockLeaf, BlockState, BufferFieldHlc, EntityType, InnerOpV1, LeafBody, MaterializedBlock,
    MaterializedBuffer, OpBodyV1, OpType,
};
use std::collections::{BTreeMap, HashSet};

/// A decoded outer `MNS1` op ready for deterministic projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedOp {
    pub op_id: OpId,
    pub device_id: DeviceId,
    pub created_at_ms: i64,
    pub inner: InnerOpV1,
}

/// Pure Path γ materialization of a single block over the COMPLETE causal graph `G(b)`
/// (`docs/sync-protocol.md` §4.2, §4.3).
///
/// Crucially, `L(b)` is computed on ALL known `MNS1` DAG ops BEFORE checking BDEK availability
/// so that an intermediate shredded BDEK NEVER resurrects older plaintext ancestors.
pub fn materialize_block<F>(
    block_id: BlockId,
    ops: &[DecodedOp],
    block_has_unshredded_key: bool,
    mut resolve_content: F,
) -> Option<MaterializedBlock>
where
    F: FnMut(OpId, KeyId, u8, &[u8]) -> LeafBody,
{
    // Filter ops targeting this block and deduplicate by op_id for idempotency.
    let mut by_id: BTreeMap<OpId, &DecodedOp> = BTreeMap::new();
    let target_id_str = block_id.to_string();
    for op in ops {
        if op.inner.entity_type == EntityType::Block && op.inner.entity_id == target_id_str {
            by_id.entry(op.op_id).or_insert(op);
        }
    }

    let dag_ops: Vec<&DecodedOp> = by_id
        .values()
        .copied()
        .filter(|op| op.inner.op_type.is_dag_op())
        .collect();

    if dag_ops.is_empty() {
        return None;
    }

    // 1. Compute complete referenced parent set across G(b)
    let mut referenced_parents: HashSet<OpId> = HashSet::new();
    for op in &dag_ops {
        for parent in &op.inner.parent_op_ids {
            referenced_parents.insert(*parent);
        }
    }

    // 2. Maximal elements L(b) = ops in G(b) not referenced as a parent by any op in G(b)
    let mut leaves: Vec<BlockLeaf> = Vec::new();
    let mut latest_tombstone_ms: Option<i64> = None;

    for op in &dag_ops {
        if referenced_parents.contains(&op.op_id) {
            continue;
        }
        let (tier, body) = match &op.inner.body {
            OpBodyV1::BlockContent {
                tier, key_id, mnb1, ..
            } => (Some(*tier), resolve_content(op.op_id, *key_id, *tier, mnb1)),
            OpBodyV1::Tombstone { deleted_at_ms } => {
                latest_tombstone_ms =
                    Some(latest_tombstone_ms.map_or(*deleted_at_ms, |m| m.max(*deleted_at_ms)));
                (
                    None,
                    LeafBody::Tombstone {
                        deleted_at_ms: *deleted_at_ms,
                    },
                )
            }
            _ => continue,
        };
        leaves.push(BlockLeaf {
            op_id: op.op_id,
            hlc: op.inner.hlc.clone(),
            device_id: op.device_id.clone(),
            actor: op.inner.actor.clone(),
            tier,
            body,
        });
    }

    // Deterministic descending order by (hlc, op_id)
    leaves.sort_by(|a, b| (&b.hlc, b.op_id).cmp(&(&a.hlc, a.op_id)));

    // 3. Scalar metadata LWW registers independently merged over all ops (CREATE, UPDATE, SET_META, etc.)
    let mut buffer_id: Option<(Hlc, OpId, BufferId)> = None;
    let mut position: Option<(Hlc, OpId, String)> = None;
    let mut lang: Option<(Hlc, OpId, String)> = None;
    let mut public_hint: Option<(Hlc, OpId, Option<String>)> = None;
    let mut updated_at_ms: i64 = 0;

    for op in by_id.values() {
        updated_at_ms = updated_at_ms.max(op.inner.hlc.wall_ms as i64);
        let key = (&op.inner.hlc, op.op_id);
        match &op.inner.body {
            OpBodyV1::BlockContent {
                buffer_id: b,
                position: p,
                lang: l,
                public_hint: h,
                ..
            }
            | OpBodyV1::BlockMeta {
                buffer_id: b,
                position: p,
                lang: l,
                public_hint: h,
            } => {
                if let Some(v) = b {
                    if buffer_id.as_ref().is_none_or(|cur| key > (&cur.0, cur.1)) {
                        buffer_id = Some((op.inner.hlc.clone(), op.op_id, *v));
                    }
                }
                if let Some(v) = p {
                    if position.as_ref().is_none_or(|cur| key > (&cur.0, cur.1)) {
                        position = Some((op.inner.hlc.clone(), op.op_id, v.clone()));
                    }
                }
                if let Some(v) = l {
                    if lang.as_ref().is_none_or(|cur| key > (&cur.0, cur.1)) {
                        lang = Some((op.inner.hlc.clone(), op.op_id, v.clone()));
                    }
                }
                if let Some(v) = h {
                    if public_hint.as_ref().is_none_or(|cur| key > (&cur.0, cur.1)) {
                        public_hint = Some((op.inner.hlc.clone(), op.op_id, v.clone()));
                    }
                }
            }
            _ => {}
        }
    }

    let (buf_hlc, _, buf_val) = buffer_id?;
    let (pos_hlc, _, pos_val) = position?;
    let (lang_hlc, _, lang_val) = lang?;
    let (hint_hlc, hint_val) = match public_hint {
        Some((h, _, v)) => (h, v),
        None => (
            Hlc::new(0, 0, DeviceId::parse("dev_00000000").expect("valid zero dev id")),
            None,
        ),
    };

    // 4. Live leaves, Update-Wins state, locked rendering (no Lock-Wins special case), display_op_id
    let live_leaves: Vec<&BlockLeaf> = leaves.iter().filter(|l| l.is_live()).collect();
    let state = if !live_leaves.is_empty() {
        BlockState::Active
    } else if block_has_unshredded_key {
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
        latest_tombstone_ms.or(Some(updated_at_ms))
    };

    Some(MaterializedBlock {
        id: block_id,
        buffer_id: buf_val,
        position: pos_val,
        lang: lang_val,
        public_hint: hint_val,
        field_hlc: BlockFieldHlc {
            buffer_id: buf_hlc,
            position: pos_hlc,
            lang: lang_hlc,
            public_hint: hint_hlc,
        },
        state,
        is_locked,
        has_unlocked_concurrent_version,
        display_op_id,
        leaves,
        updated_at_ms,
        deleted_at_ms,
    })
}

/// Pure deterministic materialization for a Buffer entity (`docs/data-structures.md` §2.1, §4).
pub fn materialize_buffer<F>(
    buffer_id: BufferId,
    ops: &[DecodedOp],
    buffer_has_unshredded_key: bool,
    mut resolve_name: F,
) -> Option<MaterializedBuffer>
where
    F: FnMut(OpId, KeyId, &[u8]) -> Option<String>,
{
    let mut by_id: BTreeMap<OpId, &DecodedOp> = BTreeMap::new();
    let target_id_str = buffer_id.to_string();
    for op in ops {
        if op.inner.entity_type == EntityType::Buffer && op.inner.entity_id == target_id_str {
            by_id.entry(op.op_id).or_insert(op);
        }
    }
    if by_id.is_empty() {
        return None;
    }

    let mut referenced: HashSet<OpId> = HashSet::new();
    for op in by_id.values() {
        for p in &op.inner.parent_op_ids {
            referenced.insert(*p);
        }
    }

    let mut has_live_leaf = false;
    let mut latest_tombstone_ms: Option<i64> = None;
    let mut name_reg: Option<(Hlc, OpId, String)> = None;
    let mut pos_reg: Option<(Hlc, OpId, String)> = None;
    let mut key_reg: Option<(Hlc, OpId, KeyId)> = None;
    let mut updated_at_ms: i64 = 0;

    for op in by_id.values() {
        updated_at_ms = updated_at_ms.max(op.inner.hlc.wall_ms as i64);
        let is_leaf = !referenced.contains(&op.op_id);
        let k = (&op.inner.hlc, op.op_id);
        match &op.inner.body {
            OpBodyV1::BufferMeta {
                key_id,
                name_mnb1,
                position,
            } => {
                if is_leaf && buffer_has_unshredded_key {
                    has_live_leaf = true;
                }
                if key_reg.as_ref().is_none_or(|cur| k > (&cur.0, cur.1)) {
                    key_reg = Some((op.inner.hlc.clone(), op.op_id, *key_id));
                }
                if let Some(mnb1) = name_mnb1 {
                    if name_reg.as_ref().is_none_or(|cur| k > (&cur.0, cur.1)) {
                        let resolved = resolve_name(op.op_id, *key_id, mnb1).unwrap_or_default();
                        name_reg = Some((op.inner.hlc.clone(), op.op_id, resolved));
                    }
                }
                if let Some(pos) = position {
                    if pos_reg.as_ref().is_none_or(|cur| k > (&cur.0, cur.1)) {
                        pos_reg = Some((op.inner.hlc.clone(), op.op_id, pos.clone()));
                    }
                }
            }
            OpBodyV1::Tombstone { deleted_at_ms } if is_leaf => {
                latest_tombstone_ms =
                    Some(latest_tombstone_ms.map_or(*deleted_at_ms, |m| m.max(*deleted_at_ms)));
            }
            _ => {}
        }
    }

    let (_, _, key_id) = key_reg?;
    let (pos_hlc, _, position) = pos_reg?;
    let (name_hlc, name) = match name_reg {
        Some((h, _, n)) => (h, n),
        None => (pos_hlc.clone(), String::new()),
    };

    let state = if has_live_leaf {
        BlockState::Active
    } else if buffer_has_unshredded_key {
        BlockState::Trashed
    } else {
        BlockState::Shredded
    };

    let final_name = if state == BlockState::Shredded {
        String::new()
    } else {
        name
    };

    let deleted_at_ms = if state == BlockState::Active {
        None
    } else {
        latest_tombstone_ms.or(Some(updated_at_ms))
    };

    Some(MaterializedBuffer {
        id: buffer_id,
        name: final_name,
        key_id,
        position,
        field_hlc: BufferFieldHlc {
            name: name_hlc,
            position: pos_hlc,
        },
        state,
        updated_at_ms,
        deleted_at_ms,
    })
}

/// Helper to check whether an op is a `DELETE` tombstone.
pub fn is_delete_op(op: &DecodedOp) -> bool {
    op.inner.op_type == OpType::Delete
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::MonotonicUlidGen;
    use proptest::prelude::*;

    #[allow(clippy::too_many_arguments)]
    fn mk_op(
        op_id: OpId,
        block_id: BlockId,
        buf_id: BufferId,
        dev: &DeviceId,
        wall: u64,
        op_type: OpType,
        parents: Vec<OpId>,
        tier: u8,
        key_id: KeyId,
        text: &str,
    ) -> DecodedOp {
        let body = match op_type {
            OpType::Delete => OpBodyV1::Tombstone {
                deleted_at_ms: wall as i64,
            },
            OpType::SetMeta => OpBodyV1::BlockMeta {
                buffer_id: None,
                position: None,
                lang: Some(text.to_string()),
                public_hint: None,
            },
            _ => OpBodyV1::BlockContent {
                buffer_id: if parents.is_empty() { Some(buf_id) } else { None },
                position: if parents.is_empty() {
                    Some("V0001".into())
                } else {
                    None
                },
                lang: if parents.is_empty() {
                    Some("markdown".into())
                } else {
                    None
                },
                public_hint: None,
                tier,
                key_id,
                mnb1: text.as_bytes().to_vec(),
            },
        };
        DecodedOp {
            op_id,
            device_id: dev.clone(),
            created_at_ms: wall as i64,
            inner: InnerOpV1 {
                v: 1,
                entity_type: EntityType::Block,
                entity_id: block_id.to_string(),
                op_type,
                parent_op_ids: parents,
                hlc: Hlc::new(wall, 0, dev.clone()),
                actor: "human".into(),
                body,
            },
        }
    }

    #[test]
    fn delete_vs_concurrent_update_triggers_update_wins_and_merge_converges() {
        let mut g = MonotonicUlidGen::new();
        let buf = BufferId::from_ulid(g.next(100, [1; 10]));
        let blk = BlockId::from_ulid(g.next(100, [2; 10]));
        let key = KeyId::from_ulid(g.next(100, [3; 10]));
        let d_mac = DeviceId::parse("dev_mac00001").unwrap();
        let d_lin = DeviceId::parse("dev_lin00002").unwrap();

        let op1 = OpId::from_ulid(g.next(1000, [4; 10]));
        let op_del = OpId::from_ulid(g.next(2000, [5; 10]));
        let op_upd = OpId::from_ulid(g.next(1500, [6; 10]));

        let ops = vec![
            mk_op(op1, blk, buf, &d_mac, 1000, OpType::Create, vec![], 1, key, "v1"),
            mk_op(
                op_del,
                blk,
                buf,
                &d_mac,
                2000,
                OpType::Delete,
                vec![op1],
                1,
                key,
                "",
            ),
            mk_op(
                op_upd,
                blk,
                buf,
                &d_lin,
                1500,
                OpType::Update,
                vec![op1],
                1,
                key,
                "v2-offline",
            ),
        ];

        // Even though DELETE has higher HLC (2000 > 1500), concurrent UPDATE revives the block (Update-Wins!)
        let m = materialize_block(blk, &ops, true, |_, _, _, raw| {
            LeafBody::Plaintext(String::from_utf8_lossy(raw).into_owned())
        })
        .unwrap();
        assert_eq!(m.state, BlockState::Active);
        assert_eq!(m.display_op_id, Some(op_upd));
        assert_eq!(m.leaves.len(), 2);

        // User merges both leaves (parents = [op_del, op_upd]) -> converges to 1 leaf
        let op_merge = OpId::from_ulid(g.next(3000, [7; 10]));
        let mut ops2 = ops;
        ops2.push(mk_op(
            op_merge,
            blk,
            buf,
            &d_mac,
            3000,
            OpType::Update,
            vec![op_del, op_upd],
            1,
            key,
            "merged",
        ));
        let m2 = materialize_block(blk, &ops2, true, |_, _, _, raw| {
            LeafBody::Plaintext(String::from_utf8_lossy(raw).into_owned())
        })
        .unwrap();
        assert_eq!(m2.state, BlockState::Active);
        assert_eq!(m2.leaves.len(), 1);
        assert_eq!(m2.display_op_id, Some(op_merge));
    }

    #[test]
    fn intermediate_shredded_key_never_resurrects_older_plaintext_ancestor() {
        let mut g = MonotonicUlidGen::new();
        let buf = BufferId::from_ulid(g.next(100, [1; 10]));
        let blk = BlockId::from_ulid(g.next(100, [2; 10]));
        let k_old = KeyId::from_ulid(g.next(100, [3; 10]));
        let k_mid = KeyId::from_ulid(g.next(100, [4; 10]));
        let d = DeviceId::parse("dev_mac00001").unwrap();

        let op1 = OpId::from_ulid(g.next(1000, [5; 10]));
        let op2 = OpId::from_ulid(g.next(2000, [6; 10]));
        let op3 = OpId::from_ulid(g.next(3000, [7; 10]));

        // Chain: op1 (k_old, readable) -> op2 (k_mid, SHREDDED!) -> op3 (DELETE)
        let ops = vec![
            mk_op(
                op1,
                blk,
                buf,
                &d,
                1000,
                OpType::Create,
                vec![],
                1,
                k_old,
                "old-secret",
            ),
            mk_op(
                op2,
                blk,
                buf,
                &d,
                2000,
                OpType::Update,
                vec![op1],
                1,
                k_mid,
                "mid",
            ),
            mk_op(op3, blk, buf, &d, 3000, OpType::Delete, vec![op2], 1, k_mid, ""),
        ];

        // Because L(b) is computed on COMPLETE G(b), only op3 (Tombstone) is a leaf; op1 MUST NOT resurrect!
        let m = materialize_block(blk, &ops, true, |_, kid, _, raw| {
            if kid == k_mid {
                LeafBody::KeyUnavailable {
                    key_id: kid,
                    shredded: true,
                }
            } else {
                LeafBody::Plaintext(String::from_utf8_lossy(raw).into_owned())
            }
        })
        .unwrap();
        assert_eq!(m.state, BlockState::Trashed);
        assert_eq!(m.display_op_id, None);
        assert_eq!(m.leaves.len(), 1);
        assert_eq!(m.leaves[0].op_id, op3);
    }

    #[test]
    fn locked_concurrent_leaf_forces_locked_rendering_and_flags_unlocked_version() {
        let mut g = MonotonicUlidGen::new();
        let buf = BufferId::from_ulid(g.next(100, [1; 10]));
        let blk = BlockId::from_ulid(g.next(100, [2; 10]));
        let k1 = KeyId::from_ulid(g.next(100, [3; 10]));
        let k2 = KeyId::from_ulid(g.next(100, [4; 10]));
        let d_mac = DeviceId::parse("dev_mac00001").unwrap();
        let d_lin = DeviceId::parse("dev_lin00002").unwrap();

        let op1 = OpId::from_ulid(g.next(1000, [5; 10]));
        let op_lock = OpId::from_ulid(g.next(2000, [6; 10]));
        let op_plain = OpId::from_ulid(g.next(9000, [7; 10])); // Higher HLC plaintext concurrent edit

        let ops = vec![
            mk_op(op1, blk, buf, &d_mac, 1000, OpType::Create, vec![], 1, k1, "init"),
            mk_op(
                op_lock,
                blk,
                buf,
                &d_mac,
                2000,
                OpType::Lock,
                vec![op1],
                2,
                k2,
                "cipher",
            ),
            mk_op(
                op_plain,
                blk,
                buf,
                &d_lin,
                9000,
                OpType::Update,
                vec![op1],
                1,
                k1,
                "plain-concurrent",
            ),
        ];

        let m = materialize_block(blk, &ops, true, |_, kid, tier, raw| {
            if tier == 2 {
                LeafBody::Sealed {
                    key_id: kid,
                    mnb1: raw.to_vec(),
                }
            } else {
                LeafBody::Plaintext(String::from_utf8_lossy(raw).into_owned())
            }
        })
        .unwrap();

        assert!(m.is_locked);
        assert!(m.has_unlocked_concurrent_version);
        assert_eq!(m.display_op_id, Some(op_lock)); // Locked leaf takes display precedence
        assert!(m.has_conflict());
    }

    proptest! {
        #[test]
        fn arbitrary_order_and_duplicates_converge_identically(
            perm in prop::collection::vec(0usize..6, 6..20)
        ) {
            let mut g = MonotonicUlidGen::new();
            let buf = BufferId::from_ulid(g.next(100, [1; 10]));
            let blk = BlockId::from_ulid(g.next(100, [2; 10]));
            let k1 = KeyId::from_ulid(g.next(100, [3; 10]));
            let d1 = DeviceId::parse("dev_a0000001").unwrap();
            let d2 = DeviceId::parse("dev_b0000002").unwrap();

            let op1 = OpId::from_ulid(g.next(1000, [1; 10]));
            let op2 = OpId::from_ulid(g.next(2000, [2; 10]));
            let op3 = OpId::from_ulid(g.next(2100, [3; 10]));
            let op4 = OpId::from_ulid(g.next(2200, [4; 10]));
            let op5 = OpId::from_ulid(g.next(2300, [5; 10]));
            let op6 = OpId::from_ulid(g.next(2400, [6; 10]));

            let base = vec![
                mk_op(op1, blk, buf, &d1, 1000, OpType::Create, vec![], 1, k1, "init"),
                mk_op(op2, blk, buf, &d1, 2000, OpType::Update, vec![op1], 1, k1, "branch-a"),
                mk_op(op3, blk, buf, &d2, 2100, OpType::Update, vec![op1], 1, k1, "branch-b"),
                mk_op(op4, blk, buf, &d1, 2200, OpType::SetMeta, vec![], 1, k1, "json"),
                mk_op(op5, blk, buf, &d2, 2300, OpType::SetMeta, vec![], 1, k1, "sql"),
                mk_op(op6, blk, buf, &d2, 2400, OpType::Delete, vec![op3], 1, k1, ""),
            ];

            // Include all 6 ops at least once, plus arbitrary duplicates in permuted order
            let mut shuffled = base.clone();
            for idx in perm {
                shuffled.push(base[idx].clone());
            }
            shuffled.reverse();

            let resolve = |_: OpId, _: KeyId, _: u8, raw: &[u8]| {
                LeafBody::Plaintext(String::from_utf8_lossy(raw).into_owned())
            };
            let m_canon = materialize_block(blk, &base, true, resolve).unwrap();
            let m_shuf = materialize_block(blk, &shuffled, true, resolve).unwrap();
            prop_assert_eq!(m_canon, m_shuf);
        }
    }
}
