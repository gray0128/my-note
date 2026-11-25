use crate::ids::{KeyId, MarkId};
use crate::model::{BlockState, KeyRecordRow, LeafBody, MaterializedBlock, ShredMarkRow, ShredMarkState};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Local or remote replica of the independent key table (`block_keys` + `shred_marks` + `key_material`),
/// merged via 2P-Set lattice rules (`docs/data-structures.md` §3.4.4, `docs/sync-protocol.md` §5.2).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyTableState {
    pub records: BTreeMap<KeyId, KeyRecordRow>,
    pub marks: BTreeMap<MarkId, ShredMarkRow>,
    /// Permanent local tombstone set of keys observed as `Executed` from server.
    /// Guarantees executed shreds NEVER resurrect after DO PITR rollback or old backups.
    pub executed_tombstones: BTreeSet<KeyId>,
    pub keyring_material: Option<(u32, Vec<u8>)>,
    pub vault_header_material: Option<(i64, Vec<u8>)>,
}

impl KeyTableState {
    pub fn insert_record(&mut self, row: KeyRecordRow) {
        if row.key_record.is_none() {
            self.executed_tombstones.insert(row.key_id);
        }
        self.records
            .entry(row.key_id)
            .and_modify(|cur| *cur = merge_record(cur, &row))
            .or_insert(row);
    }

    pub fn insert_mark(&mut self, mark: ShredMarkRow) {
        if mark.state == ShredMarkState::Executed {
            self.executed_tombstones.insert(mark.key_id);
            if let Some(rec) = self.records.get_mut(&mark.key_id) {
                rec.key_record = None;
            }
        }
        self.marks
            .entry(mark.mark_id)
            .and_modify(|cur| *cur = merge_mark(cur, &mark))
            .or_insert(mark);
    }

    pub fn update_keyring_material(&mut self, gen: u32, blob: Vec<u8>) {
        if self.keyring_material.as_ref().is_none_or(|(g, _)| gen > *g) {
            self.keyring_material = Some((gen, blob));
        }
    }

    pub fn update_vault_header_material(&mut self, gen: i64, blob: Vec<u8>) {
        if self.vault_header_material.as_ref().is_none_or(|(g, _)| gen > *g) {
            self.vault_header_material = Some((gen, blob));
        }
    }

    /// 2P-Set lattice join: commutative, associative, and idempotent.
    /// Merging NEVER loses an unshredded key; only server-executed shred marks remove keys.
    pub fn merge_from(&mut self, other: &Self) {
        for &kid in &other.executed_tombstones {
            self.executed_tombstones.insert(kid);
        }
        for rec in other.records.values() {
            self.insert_record(rec.clone());
        }
        for mark in other.marks.values() {
            self.insert_mark(mark.clone());
        }
        // Apply tombstones consistently across records
        for &kid in &self.executed_tombstones {
            if let Some(rec) = self.records.get_mut(&kid) {
                rec.key_record = None;
            }
        }
        if let Some((gen, blob)) = &other.keyring_material {
            self.update_keyring_material(*gen, blob.clone());
        }
        if let Some((gen, blob)) = &other.vault_header_material {
            self.update_vault_header_material(*gen, blob.clone());
        }
    }

    pub fn is_shredded(&self, key_id: &KeyId) -> bool {
        if self.executed_tombstones.contains(key_id) {
            return true;
        }
        if let Some(rec) = self.records.get(key_id) {
            if rec.key_record.is_none() {
                return true;
            }
        }
        self.marks
            .values()
            .any(|m| &m.key_id == key_id && m.state == ShredMarkState::Executed)
    }

    /// Available key set `K \ ExecutedShreds` (`docs/data-structures.md` §3.4.4 #4).
    pub fn is_key_available(&self, key_id: &KeyId) -> bool {
        !self.is_shredded(key_id) && self.records.get(key_id).is_some_and(|r| r.key_record.is_some())
    }

    /// Deterministic BLAKE3 digest over `block_keys`, `shred_marks`, and `key_material`
    /// used by `GET /v1/sync/pull` (`keys_digest`) to detect diffs cheaply.
    pub fn digest(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"mynote-keys-digest-v1\0");
        for (kid, rec) in &self.records {
            hasher.update(kid.as_bytes());
            hasher.update(&rec.wrap_gen.to_le_bytes());
            match &rec.key_record {
                Some(bytes) => {
                    hasher.update(&[1u8]);
                    hasher.update(&(bytes.len() as u32).to_le_bytes());
                    hasher.update(bytes);
                }
                None => {
                    hasher.update(&[0u8]);
                }
            }
        }
        hasher.update(b"\0marks\0");
        for (mid, m) in &self.marks {
            hasher.update(mid.as_bytes());
            hasher.update(m.key_id.as_bytes());
            hasher.update(&[state_rank(m.state)]);
            hasher.update(&m.not_before_ms.unwrap_or(-1).to_le_bytes());
        }
        hasher.update(b"\0mat\0");
        if let Some((gen, blob)) = &self.keyring_material {
            hasher.update(&[1u8]);
            hasher.update(&gen.to_le_bytes());
            hasher.update(blob);
        } else {
            hasher.update(&[0u8]);
        }
        if let Some((gen, blob)) = &self.vault_header_material {
            hasher.update(&[1u8]);
            hasher.update(&gen.to_le_bytes());
            hasher.update(blob);
        } else {
            hasher.update(&[0u8]);
        }
        format!("blake3:{}", hasher.finalize().to_hex())
    }
}

fn state_rank(s: ShredMarkState) -> u8 {
    match s {
        ShredMarkState::PendingConfirm => 0,
        ShredMarkState::Scheduled => 1,
        ShredMarkState::Cancelled => 2,
        ShredMarkState::Executed => 3,
    }
}

fn merge_record(a: &KeyRecordRow, b: &KeyRecordRow) -> KeyRecordRow {
    let shredded = a.key_record.is_none() || b.key_record.is_none();
    let (winner, wrap_gen) = if b.wrap_gen > a.wrap_gen {
        (b, b.wrap_gen)
    } else if a.wrap_gen > b.wrap_gen {
        (a, a.wrap_gen)
    } else if b.key_record.as_deref() < a.key_record.as_deref() {
        (b, a.wrap_gen)
    } else {
        (a, a.wrap_gen)
    };
    KeyRecordRow {
        key_id: a.key_id,
        wrap_gen,
        key_record: if shredded { None } else { winner.key_record.clone() },
        created_at_ms: a.created_at_ms.min(b.created_at_ms),
    }
}

fn merge_mark(a: &ShredMarkRow, b: &ShredMarkRow) -> ShredMarkRow {
    let state = if state_rank(b.state) > state_rank(a.state) {
        b.state
    } else {
        a.state
    };
    let opt_max_i64 = |x: Option<i64>, y: Option<i64>| match (x, y) {
        (Some(u), Some(v)) => Some(u.max(v)),
        (Some(u), None) | (None, Some(u)) => Some(u),
        (None, None) => None,
    };
    let opt_min_i64 = |x: Option<i64>, y: Option<i64>| match (x, y) {
        (Some(u), Some(v)) => Some(u.min(v)),
        (Some(u), None) | (None, Some(u)) => Some(u),
        (None, None) => None,
    };
    let cancelled_by = match (&a.cancelled_by, &b.cancelled_by) {
        (Some(u), Some(v)) => Some(if u <= v { u.clone() } else { v.clone() }),
        (Some(u), None) | (None, Some(u)) => Some(u.clone()),
        (None, None) => None,
    };
    ShredMarkRow {
        mark_id: a.mark_id,
        key_id: a.key_id,
        seen_seq: a.seen_seq.max(b.seen_seq),
        requested_by: if a.requested_by <= b.requested_by {
            a.requested_by.clone()
        } else {
            b.requested_by.clone()
        },
        requested_at_ms: a.requested_at_ms.min(b.requested_at_ms),
        grace_ms: a.grace_ms.max(b.grace_ms),
        not_before_ms: opt_max_i64(a.not_before_ms, b.not_before_ms),
        state,
        confirmed_at_ms: opt_min_i64(a.confirmed_at_ms, b.confirmed_at_ms),
        cancelled_by,
        executed_at_ms: opt_min_i64(a.executed_at_ms, b.executed_at_ms),
    }
}

/// Daily INV-KEY-LIVENESS self-check (`docs/sync-protocol.md` §5.6 #8).
/// Returns `(ok, missing_key_ids)` where any missing key for an Active block triggers `KEY_MISSING`
/// and halts shred issuance on this device.
pub fn self_check_key_liveness(blocks: &[MaterializedBlock], keys: &KeyTableState) -> (bool, Vec<KeyId>) {
    let mut missing = BTreeSet::new();
    for block in blocks {
        if block.state != BlockState::Active {
            continue;
        }
        for leaf in &block.leaves {
            if !leaf.is_live() {
                continue;
            }
            match &leaf.body {
                LeafBody::KeyUnavailable {
                    key_id,
                    shredded: false,
                } => {
                    missing.insert(*key_id);
                }
                LeafBody::Sealed { key_id, .. } if !keys.is_key_available(key_id) => {
                    missing.insert(*key_id);
                }
                _ => {}
            }
        }
    }
    (missing.is_empty(), missing.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{DeviceId, MonotonicUlidGen};
    use proptest::prelude::*;

    fn make_rec(kid: KeyId, gen: u32, payload: Option<u8>) -> KeyRecordRow {
        KeyRecordRow {
            key_id: kid,
            wrap_gen: gen,
            key_record: payload.map(|b| vec![b; 16]),
            created_at_ms: 1000,
        }
    }

    fn make_mark(mid: MarkId, kid: KeyId, state: ShredMarkState, nb: Option<i64>) -> ShredMarkRow {
        ShredMarkRow {
            mark_id: mid,
            key_id: kid,
            seen_seq: 1,
            requested_by: DeviceId::parse("dev_mac00001").unwrap(),
            requested_at_ms: 1000,
            grace_ms: 86_400_000,
            not_before_ms: nb,
            state,
            confirmed_at_ms: None,
            cancelled_by: None,
            executed_at_ms: if state == ShredMarkState::Executed {
                Some(90_000_000)
            } else {
                None
            },
        }
    }

    proptest! {
        #[test]
        fn key_table_2p_set_merge_is_commutative_associative_and_idempotent(
            g1 in 1u32..5,
            g2 in 1u32..5,
            shred1 in any::<bool>(),
            shred2 in any::<bool>(),
            nb1 in 100_000i64..500_000i64,
            nb2 in 100_000i64..500_000i64,
        ) {
            let mut gen = MonotonicUlidGen::new();
            let k1 = KeyId::from_ulid(gen.next(100, [1; 10]));
            let k2 = KeyId::from_ulid(gen.next(100, [2; 10]));
            let m1 = MarkId::from_ulid(gen.next(100, [3; 10]));

            let mut a = KeyTableState::default();
            a.insert_record(make_rec(k1, g1, if shred1 { None } else { Some(1) }));
            a.insert_mark(make_mark(m1, k1, if shred1 { ShredMarkState::Executed } else { ShredMarkState::Scheduled }, Some(nb1)));

            let mut b = KeyTableState::default();
            b.insert_record(make_rec(k1, g2, if shred2 { None } else { Some(2) }));
            b.insert_record(make_rec(k2, 1, Some(9)));
            b.insert_mark(make_mark(m1, k1, if shred2 { ShredMarkState::Executed } else { ShredMarkState::Scheduled }, Some(nb2)));

            let mut c = KeyTableState::default();
            c.insert_record(make_rec(k2, 2, Some(8)));

            // Commutativity: merge(a, b) == merge(b, a)
            let mut ab = a.clone();
            ab.merge_from(&b);
            let mut ba = b.clone();
            ba.merge_from(&a);
            prop_assert_eq!(&ab, &ba);
            prop_assert_eq!(ab.digest(), ba.digest());

            // Idempotence: merge(ab, ab) == ab
            let mut ab_idem = ab.clone();
            ab_idem.merge_from(&ab);
            prop_assert_eq!(&ab, &ab_idem);

            // Associativity: merge(merge(a, b), c) == merge(a, merge(b, c))
            let mut ab_c = ab.clone();
            ab_c.merge_from(&c);
            let mut bc = b.clone();
            bc.merge_from(&c);
            let mut a_bc = a.clone();
            a_bc.merge_from(&bc);
            prop_assert_eq!(&ab_c, &a_bc);

            // Unshredded k2 is NEVER lost by merging!
            prop_assert!(ab_c.is_key_available(&k2));
            // Shredded k1 stays permanently shredded!
            if shred1 || shred2 {
                prop_assert!(!ab_c.is_key_available(&k1));
                prop_assert!(ab_c.is_shredded(&k1));
            }
        }
    }
}
