use crate::hlc::Hlc;
use crate::ids::{BlockId, BufferId, DeviceId, JournalEpoch, KeyId, MarkId, OpId, SnapshotId};
use serde::{Deserialize, Serialize};

fn default_actor() -> String {
    "human".to_string()
}

/// Entity kind in `InnerOpV1` (`docs/data-structures.md` §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntityType {
    Buffer,
    Block,
}

/// Operation type (`docs/data-structures.md` §2.1; `Resolve` is accepted as an alias for `Update`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OpType {
    Create,
    Update,
    SetMeta,
    Lock,
    Unlock,
    Resolve,
    Delete,
}

impl OpType {
    /// True if this op participates in the block content causal DAG `G(b)`.
    pub const fn is_dag_op(self) -> bool {
        !matches!(self, Self::SetMeta)
    }
}

/// Decrypted plaintext inside an `MNS1` sync envelope (`docs/data-structures.md` §2.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnerOpV1 {
    pub v: u8,
    pub entity_type: EntityType,
    pub entity_id: String,
    pub op_type: OpType,
    pub parent_op_ids: Vec<OpId>,
    pub hlc: Hlc,
    #[serde(default = "default_actor")]
    pub actor: String,
    pub body: OpBodyV1,
}

impl InnerOpV1 {
    /// Returns the BDEK `key_id` referenced by this op, or `None` for `SET_META` / `DELETE`.
    pub fn key_id(&self) -> Option<KeyId> {
        match &self.body {
            OpBodyV1::BufferMeta { key_id, .. } => Some(*key_id),
            OpBodyV1::BlockContent { key_id, .. } => Some(*key_id),
            OpBodyV1::BlockMeta { .. } | OpBodyV1::Tombstone { .. } => None,
        }
    }
}

/// Tagged op body (`docs/data-structures.md` §2.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "k", content = "d")]
pub enum OpBodyV1 {
    BufferMeta {
        key_id: KeyId,
        name_mnb1: Option<Vec<u8>>,
        position: Option<String>,
    },
    BlockContent {
        buffer_id: Option<BufferId>,
        position: Option<String>,
        lang: Option<String>,
        public_hint: Option<Option<String>>,
        tier: u8,
        key_id: KeyId,
        mnb1: Vec<u8>,
    },
    BlockMeta {
        buffer_id: Option<BufferId>,
        position: Option<String>,
        lang: Option<String>,
        public_hint: Option<Option<String>>,
    },
    Tombstone {
        deleted_at_ms: i64,
    },
}

/// Plaintext payload inside `MNB1` (`docs/data-structures.md` §2.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockPlaintextV1 {
    pub content: String,
}

/// Single leaf body state (`docs/data-structures.md` §2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeafBody {
    Plaintext(String),
    Sealed { key_id: KeyId, mnb1: Vec<u8> },
    Tombstone { deleted_at_ms: i64 },
    KeyUnavailable { key_id: KeyId, shredded: bool },
    DecryptFailed { error_code: String },
}

/// Compile-time anti-empty-UPDATE write token (`docs/sync-protocol.md` §3 #2).
/// Can ONLY be constructed from a verified `BlockBodyState::Plaintext` or fresh user input;
/// `Locked`, `KeyUnavailable`, `DecryptFailed`, and `Unhydrated` have NO way to produce one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WritablePlaintext {
    content: String,
}

impl WritablePlaintext {
    pub fn from_new_user_input(content: String) -> Self {
        Self { content }
    }

    pub fn as_str(&self) -> &str {
        &self.content
    }

    pub fn into_string(self) -> String {
        self.content
    }
}

/// Strongly typed in-memory block body state enforcing compile-time write isolation (`INV-SYNC-2`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockBodyState {
    Plaintext(WritablePlaintext),
    Locked {
        key_id: KeyId,
        public_hint: Option<String>,
        tier2_blob: Vec<u8>,
    },
    KeyUnavailable {
        key_id: KeyId,
        shredded: bool,
    },
    DecryptFailed {
        op_id: OpId,
        reason: String,
    },
    Unhydrated,
}

impl BlockBodyState {
    /// Only `Plaintext` can produce a `WritablePlaintext` handle for constructing an `UPDATE`.
    pub fn as_writable_plaintext(&self) -> Option<&WritablePlaintext> {
        match self {
            Self::Plaintext(p) => Some(p),
            Self::Locked { .. }
            | Self::KeyUnavailable { .. }
            | Self::DecryptFailed { .. }
            | Self::Unhydrated => None,
        }
    }

    /// Derive a new `WritablePlaintext` edit from an already-hydrated plaintext state.
    pub fn edit_plaintext(&self, new_content: String) -> Option<WritablePlaintext> {
        self.as_writable_plaintext()
            .map(|_| WritablePlaintext { content: new_content })
    }
}

/// One leaf version of a block computed on the complete causal graph `G(b)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockLeaf {
    pub op_id: OpId,
    pub hlc: Hlc,
    pub device_id: DeviceId,
    pub actor: String,
    pub tier: Option<u8>,
    pub body: LeafBody,
}

impl BlockLeaf {
    pub fn is_tombstone(&self) -> bool {
        matches!(self.body, LeafBody::Tombstone { .. })
    }

    pub fn is_shredded_key(&self) -> bool {
        matches!(self.body, LeafBody::KeyUnavailable { shredded: true, .. })
    }

    /// A leaf is live iff it is neither a tombstone nor backed by an executed-shredded key.
    /// Note: a leaf waiting for a not-yet-arrived key (`shredded == false`) or `DecryptFailed`
    /// remains live so it is never silently discarded or downgraded to empty.
    pub fn is_live(&self) -> bool {
        !self.is_tombstone() && !self.is_shredded_key()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlockState {
    Active,
    Trashed,
    Shredded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockFieldHlc {
    pub buffer_id: Hlc,
    pub position: Hlc,
    pub lang: Hlc,
    pub public_hint: Hlc,
}

/// Complete materialized view of a single block (`docs/data-structures.md` §2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedBlock {
    pub id: BlockId,
    pub buffer_id: BufferId,
    pub position: String,
    pub lang: String,
    pub public_hint: Option<String>,
    pub field_hlc: BlockFieldHlc,
    pub state: BlockState,
    pub is_locked: bool,
    pub has_unlocked_concurrent_version: bool,
    pub display_op_id: Option<OpId>,
    /// All leaves in `L(b)` sorted by `(hlc, op_id)` descending.
    pub leaves: Vec<BlockLeaf>,
    pub updated_at_ms: i64,
    pub deleted_at_ms: Option<i64>,
}

impl MaterializedBlock {
    pub fn head_op_ids(&self) -> Vec<OpId> {
        self.leaves.iter().map(|l| l.op_id).collect()
    }

    pub fn display_leaf(&self) -> Option<&BlockLeaf> {
        let target = self.display_op_id?;
        self.leaves.iter().find(|l| l.op_id == target)
    }

    pub fn has_conflict(&self) -> bool {
        self.leaves.iter().filter(|l| l.is_live()).count() > 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferFieldHlc {
    pub name: Hlc,
    pub position: Hlc,
}

/// Complete materialized view of a Buffer (`docs/data-structures.md` §4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedBuffer {
    pub id: BufferId,
    pub name: String,
    pub key_id: KeyId,
    pub position: String,
    pub field_hlc: BufferFieldHlc,
    pub state: BlockState,
    pub updated_at_ms: i64,
    pub deleted_at_ms: Option<i64>,
}

/// Shred mark lifecycle (`docs/data-structures.md` §3.4.3, M2 active, M1 schema ready).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShredMarkState {
    PendingConfirm,
    Scheduled,
    Cancelled,
    Executed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecordRow {
    pub key_id: KeyId,
    pub wrap_gen: u32,
    pub key_record: Option<Vec<u8>>,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShredMarkRow {
    pub mark_id: MarkId,
    pub key_id: KeyId,
    pub seen_seq: i64,
    pub requested_by: DeviceId,
    pub requested_at_ms: i64,
    pub grace_ms: i64,
    pub not_before_ms: Option<i64>,
    pub state: ShredMarkState,
    pub confirmed_at_ms: Option<i64>,
    pub cancelled_by: Option<DeviceId>,
    pub executed_at_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyMaterialKind {
    Keyring,
    VaultHeader,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotPointer {
    pub snapshot_id: SnapshotId,
    pub journal_epoch: JournalEpoch,
    pub covers_seq: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::Ulid;

    #[test]
    fn non_plaintext_states_cannot_produce_writable_plaintext() {
        let locked = BlockBodyState::Locked {
            key_id: KeyId::from_ulid(Ulid::ZERO),
            public_hint: Some("hint".into()),
            tier2_blob: vec![1, 2, 3],
        };
        let unavail = BlockBodyState::KeyUnavailable {
            key_id: KeyId::from_ulid(Ulid::ZERO),
            shredded: false,
        };
        let failed = BlockBodyState::DecryptFailed {
            op_id: OpId::from_ulid(Ulid::ZERO),
            reason: "bad tag".into(),
        };
        let unhydrated = BlockBodyState::Unhydrated;

        assert!(locked.as_writable_plaintext().is_none());
        assert!(unavail.as_writable_plaintext().is_none());
        assert!(failed.as_writable_plaintext().is_none());
        assert!(unhydrated.as_writable_plaintext().is_none());
        assert!(failed.edit_plaintext(String::new()).is_none());

        let pt = BlockBodyState::Plaintext(WritablePlaintext::from_new_user_input("hello".into()));
        assert_eq!(pt.as_writable_plaintext().unwrap().as_str(), "hello");
        assert_eq!(pt.edit_plaintext("world".into()).unwrap().as_str(), "world");
    }
}
