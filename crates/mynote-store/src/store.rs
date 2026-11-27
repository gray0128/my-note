//! Local desktop SQLite store (`M1-4`) implementing full M1 wire-format writes,
//! multi-leaf materialization, FTS5 indexing, default read-only Markdown mirror (`F-19`),
//! `VACUUM INTO` backups, Heynote import (`M1-5`), SMK rotation, and offline restore (`INV-RECOVERY`).

use crate::credentials::{
    exclude_from_os_backups, load_device_credentials, save_device_credentials, write_atomic_0600,
    DeviceCredentials,
};
use crate::heynote::{load_heynote_path, ParsedHeynoteBuffer};
use crate::schema::{init_connection, vacuum_into};
use mynote_core::crypto::{
    decrypt_mnb1, decrypt_mnr1, decrypt_mns1, encrypt_mnb1, encrypt_mnr1, encrypt_mns1, peek_envelope_kid,
    seal_mnrs, KeyRecordV1, RecoveryKeypair, RecoveryKeyringV1, SmkGenerationBytes, MAGIC_MNR1, MAGIC_MNS1,
    MNRS_KIND_SMK,
};
use mynote_core::error::{CoreError, ErrorCode};
use mynote_core::fractional_index;
use mynote_core::hlc::{Hlc, HlcClock};
use mynote_core::ids::{
    BlockId, BufferId, DeviceId, JournalEpoch, KeyId, MonotonicUlidGen, OpId, SmkKid, Ulid,
};
use mynote_core::keys::KeyTableState;
use mynote_core::materialize::{materialize_block, materialize_buffer, DecodedOp};
use mynote_core::model::{
    BlockState, EntityType, InnerOpV1, KeyMaterialKind, KeyRecordRow, LeafBody, MaterializedBlock,
    MaterializedBuffer, OpBodyV1, OpType, ShredMarkState,
};
use mynote_core::sim::offline_restore_from_r2;
use mynote_core::sync::{EngineSnapshot, LocalOpRecord, StoreMutation};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub type SmkMap = BTreeMap<SmkKid, Zeroizing<[u8; 32]>>;

/// Parameters for applying a remote block op during sync or conflict/lock simulation.
#[derive(Clone, Debug)]
pub struct RemoteBlockOpParams {
    pub remote_device: DeviceId,
    pub block_id: BlockId,
    pub op_id: OpId,
    pub parents: Vec<OpId>,
    pub op_type: OpType,
    pub hlc: Hlc,
    pub tier: u8,
    pub key_id: KeyId,
    pub new_key_record: Option<(u32, Vec<u8>)>,
    pub mnb1: Vec<u8>,
    pub public_hint: Option<String>,
}

struct BlockSummaryRow {
    id: String,
    buffer_id: String,
    buffer_name: String,
    position: String,
    lang: String,
    is_locked: bool,
    public_hint: Option<String>,
    display_op_id: Option<String>,
    updated_at_ms: i64,
}

struct BlockDetailRow {
    buffer_id: String,
    position: String,
    lang: String,
    public_hint: Option<String>,
    state: String,
    is_locked: bool,
    display_op_id: Option<String>,
    updated_at_ms: i64,
    deleted_at_ms: Option<i64>,
}

struct BlockLeafRow {
    op_id: String,
    hlc: String,
    device_id: String,
    actor: String,
    body_state: String,
    tier: Option<i64>,
    content: Option<String>,
}

struct LeafInsertRow<'a> {
    body_state: &'static str,
    tier: Option<i64>,
    key_id: Option<String>,
    content: Option<&'a str>,
    ciphertext: Option<&'a [u8]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteReceipt {
    pub block_id: String,
    pub op_id: String,
    pub head_op_ids: Vec<String>,
    pub buffer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotent_replay: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteReceipt {
    pub block_id: String,
    pub op_id: String,
    pub head_op_ids: Vec<String>,
    pub buffer_id: String,
    pub in_trash: bool,
    pub shred_not_before_ms: Option<i64>,
    pub shred_state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockSummaryDto {
    pub id: String,
    pub buffer_id: String,
    pub buffer_name: String,
    pub position: String,
    pub lang: String,
    pub is_locked: bool,
    pub redacted: bool,
    pub public_hint: Option<String>,
    pub head_op_ids: Vec<String>,
    pub display_op_id: Option<String>,
    pub has_conflict: bool,
    pub byte_size: Option<usize>,
    pub preview: Option<String>,
    pub actor: String,
    pub updated_at_ms: i64,
}

#[path = "m2_vault_shred.rs"]
mod m2_vault_shred;
pub use m2_vault_shred::{BlockHistoryContentDto, BlockedTier2OpDto, Tier2OpInput, VaultHeaderDto};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockVersionDto {
    pub op_id: String,
    pub hlc: String,
    pub device_id: String,
    pub actor: String,
    pub is_display: bool,
    pub is_locked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnb1_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnw1_b64: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockDetailDto {
    pub id: String,
    pub buffer_id: String,
    pub position: String,
    pub lang: String,
    pub is_locked: bool,
    pub redacted: bool,
    pub has_unlocked_concurrent_version: bool,
    pub public_hint: Option<String>,
    pub head_op_ids: Vec<String>,
    pub display_op_id: Option<String>,
    pub has_conflict: bool,
    pub content: Option<String>,
    pub versions: Vec<BlockVersionDto>,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BufferDto {
    pub id: String,
    pub name: String,
    pub position: String,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrashItemDto {
    pub id: String,
    pub buffer_id: String,
    pub buffer_name: String,
    pub is_locked: bool,
    pub preview: Option<String>,
    pub deleted_at_ms: i64,
    pub deleted_by_device: String,
    pub actor: String,
    pub shred_not_before_ms: Option<i64>,
    pub shred_state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryEntryDto {
    pub op_id: String,
    pub op_type: String,
    pub hlc: String,
    pub device_id: String,
    pub actor: String,
    pub content_available: bool,
    pub has_content: bool,
    pub is_locked: bool,
    pub shredded: bool,
    pub key_id: Option<String>,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug)]
pub struct ResolvedRevertTarget {
    pub detail: BlockDetailDto,
    pub target: HistoryEntryDto,
    pub skipped_actor_ops: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevertPreviewDto {
    pub dry_run: bool,
    pub block_id: String,
    pub current_head_op_id: Option<String>,
    pub target_op_id: String,
    pub target_actor: String,
    pub target_hlc: String,
    pub target_op_type: String,
    pub skipped_actor_ops: usize,
    pub is_locked: bool,
    pub preview: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImportSummaryDto {
    pub dry_run: bool,
    pub buffers_imported: usize,
    pub blocks_imported: usize,
    pub duplicate_sources: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryDrillDto {
    pub ok: bool,
    pub keyring_generations: usize,
    pub includes_vkek: bool,
    pub drilled_at_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestoreSummaryDto {
    pub restored_blocks: usize,
    pub restored_buffers: usize,
    pub skipped_shredded: usize,
    pub archive_segments: usize,
    pub key_snapshot_at_ms: i64,
    pub data_dir: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeySelfCheckDto {
    pub ok: bool,
    pub last_run_ms: i64,
    pub blocks_missing_key: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrashStatusDto {
    pub count: usize,
    pub pending_confirm_count: usize,
    pub next_shred_ms: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncStatusDto {
    pub sync_state: String,
    pub epoch: Option<String>,
    pub last_seq: i64,
    pub pending_ops: usize,
    pub blocked_ops: usize,
    pub clock_skew_ms: i64,
    pub key_self_check: KeySelfCheckDto,
    pub trash: TrashStatusDto,
    pub recovery_drill_due: bool,
    pub last_recovery_drill_ms: Option<i64>,
    pub last_local_backup_ms: Option<i64>,
}

#[derive(Serialize, Deserialize)]
struct LocalSmkFile {
    current_smk_kid: String,
    /// Map of `smk_kid -> hex(32B SMK)` (all historical generations permanently retained).
    generations: BTreeMap<String, String>,
}

pub struct LocalStore {
    data_dir: PathBuf,
    conn: Connection,
    device_id: DeviceId,
    ulid_gen: MonotonicUlidGen,
    hlc_clock: HlcClock,
    current_smk_kid: SmkKid,
    smks: BTreeMap<SmkKid, Zeroizing<[u8; 32]>>,
    /// Present ONLY on the very first initialization call so CLI/UI can show it once.
    pub initial_recovery_words: Option<String>,
}

pub(super) fn op_type_str(op_type: OpType) -> &'static str {
    match op_type {
        OpType::Create => "CREATE",
        OpType::Update => "UPDATE",
        OpType::SetMeta => "SET_META",
        OpType::Lock => "LOCK",
        OpType::Unlock => "UNLOCK",
        OpType::Resolve => "RESOLVE",
        OpType::Delete => "DELETE",
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1)
}

fn rand_bytes<const N: usize>() -> Result<[u8; N], CoreError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| {
        CoreError::new(
            ErrorCode::IntegrityError,
            format!("OS CSPRNG failure: {e}"),
            "Check system entropy source",
        )
    })?;
    Ok(buf)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex_32(s: &str) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    if s.len() != 64 {
        return Err(CoreError::new(
            ErrorCode::IntegrityError,
            "corrupt SMK hex length",
            "Re-unlock keyring with 24-word recovery bundle",
        ));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| {
            CoreError::new(
                ErrorCode::IntegrityError,
                "corrupt SMK hex byte",
                "Re-unlock keyring with 24-word recovery bundle",
            )
        })?;
    }
    Ok(out)
}

fn truncate_preview(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let collected: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{collected}...")
    } else {
        collected
    }
}

fn sanitize_mirror_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "unnamed".to_string()
    } else {
        out
    }
}

fn ensure_private_dir(path: &Path) -> Result<(), CoreError> {
    std::fs::create_dir_all(path).map_err(|e| {
        CoreError::new(
            ErrorCode::InvalidArgument,
            format!("cannot create dir '{}': {e}", path.display()),
            "Check directory permissions",
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("cannot set 0700 on '{}': {e}", path.display()),
                "Check directory ownership and permissions",
            )
        })?;
    }
    Ok(())
}

impl LocalStore {
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self, CoreError> {
        Self::open_with_device_id(data_dir, None)
    }

    pub fn open_with_device_id(
        data_dir: impl AsRef<Path>,
        preset_device_id: Option<DeviceId>,
    ) -> Result<Self, CoreError> {
        let data_dir = data_dir.as_ref().to_path_buf();
        let backups_dir = data_dir.join("backups");
        let mirror_dir = data_dir.join("mirror");
        ensure_private_dir(&data_dir)?;
        ensure_private_dir(&backups_dir)?;
        ensure_private_dir(&mirror_dir)?;

        let db_path = data_dir.join("mynote.db");
        let conn = Connection::open(&db_path).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("cannot open SQLite '{}': {e}", db_path.display()),
                "Verify SQLite file permissions and integrity",
            )
        })?;
        init_connection(&conn, Some(&backups_dir))?;

        let smk_file_path = data_dir.join("smk_keyring.local.json");
        let mut ulid_gen = MonotonicUlidGen::new();

        // Load or initialize device_id + SMK + unified 24-word recovery bundle
        let existing_device: Option<String> = conn
            .query_row("SELECT value FROM local_meta WHERE key = 'device_id'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "DB query failed"))?;

        let (device_id, current_smk_kid, smks, initial_recovery_words, is_fresh) = if let Some(dev_str) =
            existing_device
        {
            let dev = DeviceId::parse(dev_str)?;
            let (cur_kid, map) = Self::load_local_smks(&smk_file_path)?;
            (dev, cur_kid, map, None, false)
        } else {
            let dev = match preset_device_id {
                Some(d) => d,
                None => DeviceId::from_random_bytes(rand_bytes::<10>()?),
            };
            let now = now_ms();
            let entropy = Zeroizing::new(rand_bytes::<32>()?);
            let (kp, words) = RecoveryKeypair::from_entropy(&entropy)?;
            let smk1_kid = SmkKid::from_ulid(ulid_gen.next(now, rand_bytes::<10>()?));
            let smk1 = Zeroizing::new(rand_bytes::<32>()?);
            let sealed1 = seal_mnrs(
                &kp.recovery_pk,
                MNRS_KIND_SMK,
                smk1_kid.as_bytes(),
                &smk1,
                rand_bytes::<32>()?,
                rand_bytes::<24>()?,
            )?;
            let keyring = RecoveryKeyringV1 {
                v: 1,
                recovery_kid: kp.recovery_kid,
                recovery_pk: kp.recovery_pk,
                keyring_gen: 1,
                current_smk_kid: smk1_kid,
                smk_entries: vec![sealed1],
            };
            let kr_blob = rmp_serde::to_vec_named(&keyring)
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode keyring"))?;

            conn.execute(
                "INSERT INTO local_meta (key, value) VALUES ('device_id', ?1)",
                [dev.as_str()],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "save device_id"))?;
            conn.execute(
                "INSERT INTO local_meta (key, value) VALUES ('bootstrap_completed', '0')",
                [],
            )
            .ok();
            conn.execute(
                "INSERT INTO key_material (kind, gen, blob, updated_at_ms) VALUES ('keyring', 1, ?1, ?2)",
                params![kr_blob, now as i64],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "save keyring"))?;

            let mut map = BTreeMap::new();
            map.insert(smk1_kid, smk1);
            Self::save_local_smks(&smk_file_path, smk1_kid, &map)?;
            (dev, smk1_kid, map, Some(words), true)
        };

        let last_hlc_str: Option<String> = conn
            .query_row("SELECT MAX(hlc) FROM sync_ops", [], |r| r.get(0))
            .optional()
            .ok()
            .flatten();
        let hlc_clock = match last_hlc_str.and_then(|s| Hlc::parse(&s).ok()) {
            Some(h) => HlcClock::new(device_id.clone(), h.wall_ms.max(now_ms())),
            None => HlcClock::new(device_id.clone(), now_ms()),
        };

        let mut store = Self {
            data_dir,
            conn,
            device_id,
            ulid_gen,
            hlc_clock,
            current_smk_kid,
            smks,
            initial_recovery_words,
        };

        if is_fresh {
            exclude_from_os_backups(&store.data_dir);
            store.create_buffer("scratch", None, "human")?;
        } else if !store.smks.is_empty() {
            // Read-only fast-path if no placeholder Ulid::ZERO block_keys exist.
            let _ = store.backfill_unknown_block_keys();
        }
        Ok(store)
    }

    fn save_local_smks(
        path: &Path,
        current: SmkKid,
        smks: &BTreeMap<SmkKid, Zeroizing<[u8; 32]>>,
    ) -> Result<(), CoreError> {
        let mut generations = BTreeMap::new();
        for (k, v) in smks {
            generations.insert(k.to_string(), encode_hex(v.as_ref()));
        }
        let file = LocalSmkFile {
            current_smk_kid: current.to_string(),
            generations,
        };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "serialize SMK store"))?;
        write_atomic_0600(path, &bytes)
    }

    fn load_local_smks(path: &Path) -> Result<(SmkKid, SmkMap), CoreError> {
        let bytes = std::fs::read(path).map_err(|e| {
            CoreError::new(
                ErrorCode::KeyMissing,
                format!("missing local SMK keystore '{}': {e}", path.display()),
                "Run 'mynote keyring unlock' with your 24-word recovery bundle",
            )
        })?;
        let file: LocalSmkFile = serde_json::from_slice(&bytes)
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "corrupt SMK keystore"))?;
        let cur = SmkKid::parse(&file.current_smk_kid)?;
        let mut map = BTreeMap::new();
        for (k, v) in file.generations {
            map.insert(SmkKid::parse(&k)?, decode_hex_32(&v)?);
        }
        Ok((cur, map))
    }

    /// Reload SMK generations from disk (e.g. after CLI `keyring rotate` / `keyring unlock` / `device claim`
    /// while the daemon is already running) and backfill any placeholder `Ulid::ZERO` `block_keys`.
    pub fn reload_smks_from_disk(&mut self) -> Result<bool, CoreError> {
        let path = self.data_dir.join("smk_keyring.local.json");
        let (cur, map) = Self::load_local_smks(&path)?;
        let changed = cur != self.current_smk_kid
            || map.len() != self.smks.len()
            || map
                .iter()
                .any(|(k, v)| self.smks.get(k).is_none_or(|old| old.as_ref() != v.as_ref()));
        if changed {
            self.current_smk_kid = cur;
            self.smks = map;
            let _ = self.backfill_unknown_block_keys()?;
        }
        Ok(changed)
    }

    /// Backfill `block_id` and `tier` on any `block_keys` rows that were synced before their SMK
    /// became available locally (stored temporarily with `block_id = Ulid::ZERO`).
    /// Performs ZERO SQLite writes when no placeholder rows exist.
    pub fn backfill_unknown_block_keys(&self) -> Result<usize, CoreError> {
        let zero = Ulid::ZERO.to_string();
        let pending: Vec<(String, i64, Vec<u8>)> = {
            let mut stmt = self
                .conn
                .prepare("SELECT key_id, wrap_gen, key_record FROM block_keys WHERE block_id = ?1 AND key_record IS NOT NULL")
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "scan unknown block_keys"))?;
            let rows: Vec<(String, i64, Vec<u8>)> = stmt
                .query_map([&zero], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map unknown block_keys")
                })?
                .filter_map(Result::ok)
                .collect();
            rows
        };
        if pending.is_empty() {
            return Ok(0);
        }
        let mut updated = 0usize;
        for (kid_s, wrap_gen, mnr1) in pending {
            let Ok(kid) = KeyId::parse(&kid_s) else {
                continue;
            };
            let Some(smk_kid) = peek_envelope_kid(MAGIC_MNR1, &mnr1).ok().map(SmkKid::from_bytes) else {
                continue;
            };
            let Some(smk) = self.smks.get(&smk_kid) else {
                continue;
            };
            if let Ok(kr) = decrypt_mnr1(smk_kid, smk, kid, wrap_gen as u32, &mnr1) {
                self.conn
                    .execute(
                        "UPDATE block_keys SET block_id = ?1, tier = ?2 WHERE key_id = ?3",
                        params![kr.block_id.to_string(), kr.tier as i64, kid_s],
                    )
                    .map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "backfill block_key")
                    })?;
                updated += 1;
            }
        }
        Ok(updated)
    }

    /// Enforce Bootstrap Gate (`AGENTS.md` §3.1, `docs/sync-protocol.md` §3 #1, `INV-SYNC-3`):
    /// Before `bootstrap_completed == 1`, refuse non-CREATE mutations against remote-existing entities.
    fn check_bootstrap_gate(
        &self,
        entity_type: EntityType,
        entity_id: &str,
        op_type: OpType,
    ) -> Result<(), CoreError> {
        if op_type == OpType::Create || self.get_local_meta("bootstrap_completed").as_deref() == Some("1") {
            return Ok(());
        }
        let has_sync_configured = self.get_local_meta("sync_url").is_some();
        let et_s = match entity_type {
            EntityType::Buffer => "buffer",
            EntityType::Block => "block",
        };
        let remote_seq_count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sync_ops WHERE entity_type = ?1 AND entity_id = ?2 AND server_seq IS NOT NULL",
                params![et_s, entity_id],
                |r| r.get(0),
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "bootstrap gate check"))?;
        let foreign_dev_count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sync_ops WHERE entity_type = ?1 AND entity_id = ?2 AND device_id != ?3",
                params![et_s, entity_id, self.device_id.as_str()],
                |r| r.get(0),
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "bootstrap gate check"))?;
        let local_create_count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sync_ops WHERE entity_type = ?1 AND entity_id = ?2 AND op_type = 'CREATE' AND device_id = ?3",
                params![et_s, entity_id, self.device_id.as_str()],
                |r| r.get(0),
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "bootstrap gate check"))?;

        if remote_seq_count > 0 || local_create_count == 0 || (has_sync_configured && foreign_dev_count > 0) {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "Bootstrap Gate blocked {:?} on remote {et_s} '{entity_id}' before initial sync bootstrap completed",
                    op_type
                ),
                "Wait for initial sync bootstrap ('mynote sync pull') before modifying existing remote entities",
            ));
        }
        Ok(())
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    pub fn current_keyring(&self) -> Result<RecoveryKeyringV1, CoreError> {
        let blob: Vec<u8> = self
            .conn
            .query_row("SELECT blob FROM key_material WHERE kind = 'keyring'", [], |r| {
                r.get(0)
            })
            .map_err(|e| CoreError::new(ErrorCode::KeyMissing, e.to_string(), "Recovery keyring missing"))?;
        rmp_serde::from_slice(&blob).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                e.to_string(),
                "Corrupt recovery keyring",
            )
        })
    }

    pub fn pending_op_count(&self) -> usize {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM sync_ops WHERE server_seq IS NULL AND sync_blocked_reason IS NULL",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0) as usize
    }

    pub fn redacted_locked_count(&self) -> usize {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM blocks WHERE state = 'ACTIVE' AND is_locked = 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0) as usize
    }

    pub fn has_any_conflict(&self) -> bool {
        self.conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM block_leaves l
                    JOIN blocks b ON b.id = l.block_id
                    WHERE b.state = 'ACTIVE' AND l.body_state != 'TOMBSTONE'
                    GROUP BY l.block_id HAVING COUNT(*) > 1
                 )",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            != 0
    }

    pub fn sync_state_label(&self) -> &'static str {
        if self.pending_op_count() > 0 {
            "pending_offline"
        } else if self.has_any_conflict() {
            "conflict_present"
        } else {
            let configured: Option<String> = self
                .conn
                .query_row("SELECT value FROM local_meta WHERE key = 'sync_url'", [], |r| {
                    r.get(0)
                })
                .optional()
                .unwrap_or(None);
            if configured.is_some() {
                "synced"
            } else {
                "unconfigured"
            }
        }
    }

    pub fn sync_status(&self) -> Result<SyncStatusDto, CoreError> {
        let meta_str = |k: &str| -> Option<String> {
            self.conn
                .query_row("SELECT value FROM local_meta WHERE key = ?1", [k], |r| r.get(0))
                .optional()
                .unwrap_or(None)
        };
        let meta_i64 = |k: &str| -> Option<i64> { meta_str(k).and_then(|s| s.parse::<i64>().ok()) };

        let pending_ops = self.pending_op_count();
        let blocked_ops: usize = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sync_ops WHERE sync_blocked_reason IS NOT NULL",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0) as usize;
        let trash_count: usize = self
            .conn
            .query_row("SELECT COUNT(*) FROM blocks WHERE state = 'TRASHED'", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap_or(0) as usize;
        let pending_confirm_count: usize = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM shred_marks WHERE state = 'pending_confirm' AND server_acked = 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0) as usize;
        let next_shred_ms: Option<i64> = self
            .conn
            .query_row(
                "SELECT MIN(not_before_ms) FROM shred_marks WHERE state = 'scheduled' AND not_before_ms IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None)
            .flatten();

        let (check_ok, missing) = self.key_self_check()?;
        let now = now_ms() as i64;

        Ok(SyncStatusDto {
            sync_state: self.sync_state_label().to_string(),
            epoch: meta_str("journal_epoch"),
            last_seq: meta_i64("last_seq").unwrap_or(0),
            pending_ops,
            blocked_ops,
            clock_skew_ms: meta_i64("clock_skew_ms").unwrap_or(0),
            key_self_check: KeySelfCheckDto {
                ok: check_ok,
                last_run_ms: now,
                blocks_missing_key: missing.len(),
            },
            trash: TrashStatusDto {
                count: trash_count,
                pending_confirm_count,
                next_shred_ms,
            },
            recovery_drill_due: meta_str("recovery_drill_due").as_deref() == Some("1"),
            last_recovery_drill_ms: meta_i64("last_recovery_drill_ms"),
            last_local_backup_ms: meta_i64("last_local_backup_ms"),
        })
    }

    /// Unseal all SMK generations from synced `RecoveryKeyringV1` using the 24-word recovery bundle
    /// and persist them to local storage (`mynote keyring unlock`).
    pub fn unlock_keyring_with_words(&mut self, words: &str) -> Result<usize, CoreError> {
        let kp = RecoveryKeypair::from_mnemonic_words(words)?;
        let kr = self.current_keyring()?;
        let unsealed = kp.unseal_all_smks(&kr)?;
        for (kid, smk) in &unsealed {
            self.smks.insert(*kid, smk.clone());
        }
        self.current_smk_kid = kr.current_smk_kid;
        Self::save_local_smks(
            &self.data_dir.join("smk_keyring.local.json"),
            self.current_smk_kid,
            &self.smks,
        )?;
        self.backfill_unknown_block_keys()?;
        self.set_local_meta("last_seq", "0")?;
        self.rematerialize_all()?;
        Ok(unsealed.len())
    }

    fn current_smk(&self) -> Result<&Zeroizing<[u8; 32]>, CoreError> {
        self.smks.get(&self.current_smk_kid).ok_or_else(|| {
            CoreError::new(
                ErrorCode::KeyMissing,
                format!("SMK generation {} missing from local store", self.current_smk_kid),
                "Run 'mynote keyring unlock' with your 24-word recovery bundle",
            )
        })
    }

    fn load_key_table(&self) -> Result<KeyTableState, CoreError> {
        let mut kt = KeyTableState::default();
        let mut stmt = self
            .conn
            .prepare("SELECT key_id, wrap_gen, key_record, created_at_ms FROM block_keys")
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query block_keys"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<Vec<u8>>>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map block_keys"))?;
        for row in rows {
            let (kid, wrap_gen, key_record, created_at_ms) =
                row.map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "row block_keys"))?;
            kt.insert_record(KeyRecordRow {
                key_id: KeyId::parse(&kid)?,
                wrap_gen: wrap_gen as u32,
                key_record,
                created_at_ms,
            });
        }
        for mark in self.load_shred_marks(true)? {
            kt.insert_mark(mark);
        }
        if let Ok(mut mstmt) = self.conn.prepare("SELECT kind, gen, blob FROM key_material") {
            if let Ok(mrows) = mstmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            }) {
                for mrow in mrows.flatten() {
                    match mrow.0.as_str() {
                        "keyring" => kt.update_keyring_material(mrow.1 as u32, mrow.2),
                        "vault_header" => kt.update_vault_header_material(mrow.1, mrow.2),
                        _ => {}
                    }
                }
            }
        }
        Ok(kt)
    }

    pub(super) fn unwrap_key_record_full(&self, key_id: KeyId) -> Result<KeyRecordV1, CoreError> {
        let row: Option<(i64, Option<Vec<u8>>)> = self
            .conn
            .query_row(
                "SELECT wrap_gen, key_record FROM block_keys WHERE key_id = ?1",
                [key_id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "lookup key_id"))?;
        let (wrap_gen, maybe_mnr1) = row.ok_or_else(|| {
            CoreError::new(
                ErrorCode::KeyMissing,
                format!("key {key_id} not found"),
                "Run 'mynote sync pull'",
            )
        })?;
        let mnr1 = maybe_mnr1.ok_or_else(|| {
            CoreError::new(
                ErrorCode::KeyShredded,
                format!("key {key_id} has been permanently shredded"),
                "Shredded blocks cannot be recovered after the grace period",
            )
        })?;
        let smk_kid = SmkKid::from_bytes(peek_envelope_kid(MAGIC_MNR1, &mnr1)?);
        let smk = self.smks.get(&smk_kid).ok_or_else(|| {
            CoreError::new(
                ErrorCode::KeyMissing,
                format!("SMK generation {smk_kid} missing locally"),
                "Run 'mynote keyring unlock'",
            )
        })?;
        decrypt_mnr1(smk_kid, smk, key_id, wrap_gen as u32, &mnr1)
    }

    fn unwrap_bdek(&self, key_id: KeyId) -> Result<(u8, Vec<u8>), CoreError> {
        let rec = self.unwrap_key_record_full(key_id)?;
        Ok((rec.tier, rec.bdek))
    }

    /// Unwrap a Tier 1 32-byte BDEK, rejecting Tier 2 Vault keys (`BlockLocked`) and malformed lengths (`IntegrityError`).
    fn unwrap_tier1_bdek(&self, key_id: KeyId) -> Result<Zeroizing<[u8; 32]>, CoreError> {
        let (tier, bdek_vec) = self.unwrap_bdek(key_id)?;
        if tier != 1 {
            return Err(CoreError::new(
                ErrorCode::BlockLocked,
                format!("key {key_id} belongs to Tier {tier} Vault and cannot be unwrapped on Tier 1 path"),
                "Unlock Vault in the desktop UI before editing locked blocks",
            ));
        }
        if bdek_vec.len() != 32 {
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                format!("invalid Tier 1 BDEK length {} for key {key_id}", bdek_vec.len()),
                "Verify key integrity or restore from backup",
            ));
        }
        let mut bdek = Zeroizing::new([0u8; 32]);
        bdek.copy_from_slice(&bdek_vec);
        Ok(bdek)
    }

    fn load_entity_decoded_ops(
        &self,
        entity_type: EntityType,
        entity_id: &str,
    ) -> Result<Vec<DecodedOp>, CoreError> {
        let et = match entity_type {
            EntityType::Buffer => "buffer",
            EntityType::Block => "block",
        };
        let mut stmt = self
            .conn
            .prepare(
                "SELECT op_id, device_id, key_id, smk_kid, envelope, created_at_ms
                 FROM sync_ops WHERE entity_type = ?1 AND entity_id = ?2 ORDER BY hlc ASC",
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query sync_ops"))?;
        let rows = stmt
            .query_map(params![et, entity_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map sync_ops"))?;

        let mut out = Vec::new();
        for row in rows {
            let (op_id_s, dev_s, key_s, smk_s, env, created_at_ms) =
                row.map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "read sync_op"))?;
            let op_id = OpId::parse(&op_id_s)?;
            let device_id = DeviceId::parse(dev_s)?;
            let key_id = key_s.as_deref().map(KeyId::parse).transpose()?;
            let smk_kid = SmkKid::parse(&smk_s)?;
            if let Some(smk) = self.smks.get(&smk_kid) {
                if let Ok(inner) = decrypt_mns1(smk_kid, smk, op_id, &device_id, key_id, &env) {
                    out.push(DecodedOp {
                        op_id,
                        device_id,
                        created_at_ms,
                        inner,
                    });
                }
            }
        }
        Ok(out)
    }

    fn rematerialize_block(&self, block_id: BlockId) -> Result<MaterializedBlock, CoreError> {
        let kt = self.load_key_table()?;
        self.rematerialize_block_with_kt(block_id, &kt)
    }

    fn rematerialize_block_with_kt(
        &self,
        block_id: BlockId,
        kt: &KeyTableState,
    ) -> Result<MaterializedBlock, CoreError> {
        let decoded = self.load_entity_decoded_ops(EntityType::Block, &block_id.to_string())?;
        let has_unshredded_key: bool = decoded
            .iter()
            .filter_map(|d| d.inner.key_id())
            .any(|k| !kt.is_shredded(&k));

        let mat = materialize_block(
            block_id,
            &decoded,
            has_unshredded_key,
            |op_id, kid, tier, mnb1| {
                if kt.is_shredded(&kid) {
                    return LeafBody::KeyUnavailable {
                        key_id: kid,
                        shredded: true,
                    };
                }
                match tier {
                    2 => match self.unwrap_key_record_full(kid) {
                        Ok(rec) if rec.tier == 2 && rec.bdek.len() == 93 => LeafBody::Sealed {
                            key_id: kid,
                            mnb1: mnb1.to_vec(),
                        },
                        Ok(_) => LeafBody::DecryptFailed {
                            error_code: ErrorCode::IntegrityError.as_str().to_string(),
                        },
                        Err(e) if e.code() == ErrorCode::KeyShredded => LeafBody::KeyUnavailable {
                            key_id: kid,
                            shredded: true,
                        },
                        Err(_) => LeafBody::KeyUnavailable {
                            key_id: kid,
                            shredded: false,
                        },
                    },
                    1 => match self.unwrap_bdek(kid) {
                        Ok((1, bdek_vec)) if bdek_vec.len() == 32 => {
                            let mut bdek = Zeroizing::new([0u8; 32]);
                            bdek.copy_from_slice(&bdek_vec);
                            match decrypt_mnb1(block_id.as_bytes(), op_id, kid, &bdek, mnb1) {
                                Ok(pt) => LeafBody::Plaintext(pt),
                                Err(e) => LeafBody::DecryptFailed {
                                    error_code: e.code().as_str().to_string(),
                                },
                            }
                        }
                        Ok(_) => LeafBody::DecryptFailed {
                            error_code: ErrorCode::IntegrityError.as_str().to_string(),
                        },
                        Err(e) if e.code() == ErrorCode::KeyShredded => LeafBody::KeyUnavailable {
                            key_id: kid,
                            shredded: true,
                        },
                        Err(_) => LeafBody::KeyUnavailable {
                            key_id: kid,
                            shredded: false,
                        },
                    },
                    _ => LeafBody::DecryptFailed {
                        error_code: ErrorCode::IntegrityError.as_str().to_string(),
                    },
                }
            },
        )
        .ok_or_else(|| {
            CoreError::new(
                ErrorCode::NotFound,
                format!("block {block_id} not found"),
                "Check block ID",
            )
        })?;

        let state_str = match mat.state {
            BlockState::Active => "ACTIVE",
            BlockState::Trashed => "TRASHED",
            BlockState::Shredded => "SHREDDED",
        };

        self.conn
            .execute_batch("SAVEPOINT mynote_remat_block;")
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "savepoint remat_block"))?;

        let write_res: Result<(), CoreError> = (|| {
            // Remove old FTS entries for this block's leaves BEFORE replacing block_leaves
            self.conn
                .execute(
                    "DELETE FROM blocks_fts WHERE rowid IN (SELECT rowid FROM block_leaves WHERE block_id = ?1)",
                    [block_id.to_string()],
                )
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "cleanup fts"))?;

            self.conn
                .execute(
                    "INSERT INTO blocks (
                        id, buffer_id, position, lang, public_hint,
                        buffer_id_hlc, position_hlc, lang_hlc, public_hint_hlc,
                        state, is_locked, display_op_id, leaf_count, updated_at_ms, deleted_at_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
                     ON CONFLICT(id) DO UPDATE SET
                        buffer_id=excluded.buffer_id, position=excluded.position, lang=excluded.lang,
                        public_hint=excluded.public_hint, buffer_id_hlc=excluded.buffer_id_hlc,
                        position_hlc=excluded.position_hlc, lang_hlc=excluded.lang_hlc,
                        public_hint_hlc=excluded.public_hint_hlc, state=excluded.state,
                        is_locked=excluded.is_locked, display_op_id=excluded.display_op_id,
                        leaf_count=excluded.leaf_count, updated_at_ms=excluded.updated_at_ms,
                        deleted_at_ms=excluded.deleted_at_ms",
                    params![
                        mat.id.to_string(),
                        mat.buffer_id.to_string(),
                        mat.position,
                        mat.lang,
                        mat.public_hint,
                        mat.field_hlc.buffer_id.canonical_string(),
                        mat.field_hlc.position.canonical_string(),
                        mat.field_hlc.lang.canonical_string(),
                        mat.field_hlc.public_hint.canonical_string(),
                        state_str,
                        if mat.is_locked { 1i64 } else { 0i64 },
                        mat.display_op_id.map(|o| o.to_string()),
                        mat.leaves.len() as i64,
                        mat.updated_at_ms,
                        mat.deleted_at_ms,
                    ],
                )
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "upsert blocks"))?;

            self.conn
                .execute(
                    "DELETE FROM block_leaves WHERE block_id = ?1",
                    [block_id.to_string()],
                )
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "clear block_leaves")
                })?;

            for leaf in &mat.leaves {
                let row = match &leaf.body {
                    LeafBody::Plaintext(s) => {
                        let kid = decoded
                            .iter()
                            .find(|d| d.op_id == leaf.op_id)
                            .and_then(|d| d.inner.key_id())
                            .map(|k| k.to_string());
                        LeafInsertRow {
                            body_state: "PLAINTEXT",
                            tier: Some(1),
                            key_id: kid,
                            content: Some(s.as_str()),
                            ciphertext: None,
                        }
                    }
                    LeafBody::Sealed { key_id, mnb1 } => LeafInsertRow {
                        body_state: "SEALED",
                        tier: Some(2),
                        key_id: Some(key_id.to_string()),
                        content: None,
                        ciphertext: Some(mnb1.as_slice()),
                    },
                    LeafBody::Tombstone { .. } => LeafInsertRow {
                        body_state: "TOMBSTONE",
                        tier: None,
                        key_id: None,
                        content: None,
                        ciphertext: None,
                    },
                    LeafBody::KeyUnavailable { key_id, .. } => LeafInsertRow {
                        body_state: "KEY_UNAVAILABLE",
                        tier: leaf.tier.map(i64::from),
                        key_id: Some(key_id.to_string()),
                        content: None,
                        ciphertext: None,
                    },
                    LeafBody::DecryptFailed { .. } => LeafInsertRow {
                        body_state: "DECRYPT_FAILED",
                        tier: leaf.tier.map(i64::from),
                        key_id: None,
                        content: None,
                        ciphertext: None,
                    },
                };

                self.conn
                    .execute(
                        "INSERT INTO block_leaves
                         (block_id, op_id, hlc, device_id, actor, body_state, tier, key_id, content, ciphertext)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        params![
                            mat.id.to_string(),
                            leaf.op_id.to_string(),
                            leaf.hlc.canonical_string(),
                            leaf.device_id.as_str(),
                            leaf.actor,
                            row.body_state,
                            row.tier,
                            row.key_id,
                            row.content,
                            row.ciphertext,
                        ],
                    )
                    .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert block_leaf"))?;

                // FTS5 INVARIANT: ONLY index ACTIVE unlocked PLAINTEXT leaves!
                if mat.state == BlockState::Active && !mat.is_locked {
                    if let LeafBody::Plaintext(pt) = &leaf.body {
                        let rowid = self.conn.last_insert_rowid();
                        self.conn
                            .execute(
                                "INSERT INTO blocks_fts (rowid, content, public_hint) VALUES (?1, ?2, ?3)",
                                params![rowid, pt, mat.public_hint.as_deref().unwrap_or("")],
                            )
                            .map_err(|e| {
                                CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert fts")
                            })?;
                    }
                }
            }
            Ok(())
        })();

        match write_res {
            Ok(()) => {
                self.conn
                    .execute_batch("RELEASE SAVEPOINT mynote_remat_block;")
                    .map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "release savepoint")
                    })?;
                Ok(mat)
            }
            Err(e) => {
                let _ = self.conn.execute_batch(
                    "ROLLBACK TO SAVEPOINT mynote_remat_block; RELEASE SAVEPOINT mynote_remat_block;",
                );
                Err(e)
            }
        }
    }

    fn rematerialize_buffer(&self, buffer_id: BufferId) -> Result<MaterializedBuffer, CoreError> {
        let kt = self.load_key_table()?;
        self.rematerialize_buffer_with_kt(buffer_id, &kt)
    }

    fn rematerialize_buffer_with_kt(
        &self,
        buffer_id: BufferId,
        kt: &KeyTableState,
    ) -> Result<MaterializedBuffer, CoreError> {
        let decoded = self.load_entity_decoded_ops(EntityType::Buffer, &buffer_id.to_string())?;
        let has_unshredded_key = decoded
            .iter()
            .filter_map(|d| d.inner.key_id())
            .any(|k| !kt.is_shredded(&k));

        let mat = materialize_buffer(buffer_id, &decoded, has_unshredded_key, |op_id, kid, mnb1| {
            let (1, bdek_vec) = self.unwrap_bdek(kid).ok()? else {
                return None;
            };
            if bdek_vec.len() != 32 {
                return None;
            }
            let mut bdek = Zeroizing::new([0u8; 32]);
            bdek.copy_from_slice(&bdek_vec);
            decrypt_mnb1(buffer_id.as_bytes(), op_id, kid, &bdek, mnb1).ok()
        })
        .ok_or_else(|| {
            CoreError::new(
                ErrorCode::NotFound,
                format!("buffer {buffer_id} not found"),
                "Check buffer ID",
            )
        })?;

        let state_str = match mat.state {
            BlockState::Active => "ACTIVE",
            BlockState::Trashed => "TRASHED",
            BlockState::Shredded => "SHREDDED",
        };
        self.conn
            .execute(
                "INSERT INTO buffers (id, name, key_id, position, name_hlc, position_hlc, state, updated_at_ms, deleted_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, key_id=excluded.key_id, position=excluded.position,
                    name_hlc=excluded.name_hlc, position_hlc=excluded.position_hlc,
                    state=excluded.state, updated_at_ms=excluded.updated_at_ms,
                    deleted_at_ms=excluded.deleted_at_ms",
                params![
                    mat.id.to_string(),
                    mat.name,
                    mat.key_id.to_string(),
                    mat.position,
                    mat.field_hlc.name.canonical_string(),
                    mat.field_hlc.position.canonical_string(),
                    state_str,
                    mat.updated_at_ms,
                    mat.deleted_at_ms,
                ],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "upsert buffer"))?;
        Ok(mat)
    }

    /// Default-on unidirectional read-only Markdown mirror (`F-19`, `docs/architecture-proposal.md` §0.4).
    /// Atomically projects ACTIVE unlocked blocks to `<data_dir>/mirror/<buffer>.md`;
    /// locked blocks output ONLY a redacted placeholder comment; trashed/deleted items removed.
    pub fn refresh_mirror(&self) -> Result<(), CoreError> {
        let mirror_dir = self.data_dir.join("mirror");
        std::fs::create_dir_all(&mirror_dir).ok();
        let active_buffers = self.list_buffers()?;
        let mut live_filenames = BTreeSet::new();

        for buf in &active_buffers {
            let fname = format!("{}.md", sanitize_mirror_name(&buf.name));
            live_filenames.insert(fname.clone());
            let mut md = format!("# {}\n\n", buf.name);

            let mut stmt = self
                .conn
                .prepare(
                    "SELECT id, lang, is_locked, public_hint, display_op_id
                     FROM blocks
                     WHERE buffer_id = ?1 AND state = 'ACTIVE'
                     ORDER BY position COLLATE BINARY ASC, id ASC",
                )
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "mirror query"))?;
            let rows = stmt
                .query_map([&buf.id], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<String>>(4)?,
                    ))
                })
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "mirror rows"))?;

            for row in rows {
                let (blk_id, lang, is_locked, hint, disp_op) =
                    row.map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "mirror row"))?;
                if is_locked != 0 {
                    let h = hint.as_deref().unwrap_or("locked");
                    md.push_str(&format!("<!-- LOCKED BLOCK: {blk_id} (hint: {h}) -->\n\n"));
                } else if let Some(op_id) = disp_op {
                    let content: Option<String> = self
                        .conn
                        .query_row(
                            "SELECT content FROM block_leaves WHERE block_id = ?1 AND op_id = ?2 AND body_state = 'PLAINTEXT'",
                            params![blk_id, op_id],
                            |r| r.get(0),
                        )
                        .optional()
                        .unwrap_or(None);
                    if let Some(body) = content {
                        md.push_str(&format!("<!-- BLOCK: {blk_id} lang={lang} -->\n"));
                        if lang == "markdown" || lang == "text" {
                            md.push_str(&body);
                            md.push_str("\n\n");
                        } else {
                            md.push_str(&format!("```{lang}\n{body}\n```\n\n"));
                        }
                    }
                }
            }

            let target = mirror_dir.join(&fname);
            let tmp = mirror_dir.join(format!(".{fname}.tmp"));
            std::fs::write(&tmp, md.as_bytes()).map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("mirror write failed: {e}"),
                    "Check disk space",
                )
            })?;
            std::fs::rename(&tmp, &target).map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("mirror rename failed: {e}"),
                    "Check mirror dir",
                )
            })?;
        }

        // Remove stale mirror files for deleted/renamed buffers
        if let Ok(entries) = std::fs::read_dir(&mirror_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().is_some_and(|e| e == "md") {
                    if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                        if !live_filenames.contains(name) {
                            let _ = std::fs::remove_file(p);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn resolve_buffer_id(&self, selector: &str) -> Result<BufferId, CoreError> {
        if let Ok(id) = BufferId::parse(selector) {
            let exists: Option<String> = self
                .conn
                .query_row(
                    "SELECT id FROM buffers WHERE id = ?1 AND state = 'ACTIVE'",
                    [id.to_string()],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "resolve buffer"))?;
            if exists.is_some() {
                return Ok(id);
            }
        }
        let found: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM buffers WHERE name = ?1 AND state = 'ACTIVE' ORDER BY position COLLATE BINARY ASC, id ASC LIMIT 1",
                [selector],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "resolve buffer by name"))?;
        match found {
            Some(id_s) => BufferId::parse(&id_s),
            None => Err(CoreError::new(
                ErrorCode::NotFound,
                format!("buffer '{selector}' not found"),
                "Run 'mynote buf ls' to view active buffers, or create one with 'mynote buf create <name>'",
            )),
        }
    }

    pub fn list_buffers(&self) -> Result<Vec<BufferDto>, CoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, name, position, updated_at_ms FROM buffers
                 WHERE state = 'ACTIVE'
                 ORDER BY position COLLATE BINARY ASC, id ASC",
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "list buffers"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(BufferDto {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    position: r.get(2)?,
                    updated_at_ms: r.get(3)?,
                })
            })
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map buffers"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "read buffer"))?);
        }
        Ok(out)
    }

    pub fn create_buffer(
        &mut self,
        name: &str,
        after_id: Option<&str>,
        actor: &str,
    ) -> Result<BufferDto, CoreError> {
        if name.trim().is_empty() {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "buffer name cannot be empty",
                "Provide a non-empty buffer name",
            ));
        }
        let existing = self.list_buffers()?;
        let (prev, next) = match after_id {
            Some(aid) => {
                let idx = existing
                    .iter()
                    .position(|b| b.id == aid || b.name == aid)
                    .ok_or_else(|| {
                        CoreError::new(
                            ErrorCode::NotFound,
                            format!("buffer '{aid}' not found"),
                            "Check --after ID",
                        )
                    })?;
                (
                    Some(existing[idx].position.as_str()),
                    existing.get(idx + 1).map(|b| b.position.as_str()),
                )
            }
            None => (existing.last().map(|b| b.position.as_str()), None),
        };
        let pos = fractional_index::between(prev, next, rand_bytes::<4>()?)?;
        let now = now_ms();
        let buf_id = BufferId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let op_id = OpId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let key_id = KeyId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let bdek = Zeroizing::new(rand_bytes::<32>()?);
        let hlc = self.hlc_clock.tick(now);
        let keyring_gen = self.current_keyring()?.keyring_gen;
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();

        let name_mnb1 = encrypt_mnb1(buf_id.as_bytes(), op_id, key_id, &bdek, name, rand_bytes::<24>()?)?;
        let krec = KeyRecordV1 {
            v: 1,
            key_id,
            block_id: buf_id.0,
            tier: 1,
            created_hlc: hlc.canonical_string(),
            created_by: self.device_id.clone(),
            bdek: bdek.to_vec(),
        };
        let mnr1 = encrypt_mnr1(smk_kid, &smk, keyring_gen, &krec, rand_bytes::<24>()?)?;
        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Buffer,
            entity_id: buf_id.to_string(),
            op_type: OpType::Create,
            parent_op_ids: vec![],
            hlc: hlc.clone(),
            actor: actor.to_string(),
            body: OpBodyV1::BufferMeta {
                key_id,
                name_mnb1: Some(name_mnb1),
                position: Some(pos),
            },
        };
        let mns1 = encrypt_mns1(smk_kid, &smk, op_id, &self.device_id, &inner, rand_bytes::<24>()?)?;

        self.conn
            .execute(
                "INSERT INTO block_keys (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                 VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, 0)",
                params![
                    key_id.to_string(),
                    buf_id.to_string(),
                    keyring_gen as i64,
                    mnr1,
                    hlc.canonical_string(),
                    now as i64,
                ],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert buffer key"))?;
        self.insert_sync_op(
            op_id,
            None,
            EntityType::Buffer,
            &buf_id.to_string(),
            &[],
            OpType::Create,
            &hlc,
            actor,
            Some(key_id),
            smk_kid,
            &mns1,
            now as i64,
        )?;
        let mat = self.rematerialize_buffer(buf_id)?;
        self.refresh_mirror()?;
        Ok(BufferDto {
            id: mat.id.to_string(),
            name: mat.name,
            position: mat.position,
            updated_at_ms: mat.updated_at_ms,
        })
    }

    pub fn rename_buffer(
        &mut self,
        selector: &str,
        new_name: &str,
        actor: &str,
    ) -> Result<BufferDto, CoreError> {
        let buf_id = self.resolve_buffer_id(selector)?;
        self.check_bootstrap_gate(EntityType::Buffer, &buf_id.to_string(), OpType::Update)?;
        let key_str: String = self
            .conn
            .query_row(
                "SELECT key_id FROM buffers WHERE id = ?1",
                [buf_id.to_string()],
                |r| r.get(0),
            )
            .map_err(|e| CoreError::new(ErrorCode::NotFound, e.to_string(), "Buffer not found"))?;
        let key_id = KeyId::parse(&key_str)?;
        let bdek = self.unwrap_tier1_bdek(key_id)?;

        let now = now_ms();
        let op_id = OpId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let hlc = self.hlc_clock.tick(now);
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();
        let parents = self.current_entity_leaves(EntityType::Buffer, &buf_id.to_string())?;

        let name_mnb1 = encrypt_mnb1(
            buf_id.as_bytes(),
            op_id,
            key_id,
            &bdek,
            new_name,
            rand_bytes::<24>()?,
        )?;
        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Buffer,
            entity_id: buf_id.to_string(),
            op_type: OpType::Update,
            parent_op_ids: parents.clone(),
            hlc: hlc.clone(),
            actor: actor.to_string(),
            body: OpBodyV1::BufferMeta {
                key_id,
                name_mnb1: Some(name_mnb1),
                position: None,
            },
        };
        let mns1 = encrypt_mns1(smk_kid, &smk, op_id, &self.device_id, &inner, rand_bytes::<24>()?)?;
        self.insert_sync_op(
            op_id,
            None,
            EntityType::Buffer,
            &buf_id.to_string(),
            &parents,
            OpType::Update,
            &hlc,
            actor,
            Some(key_id),
            smk_kid,
            &mns1,
            now as i64,
        )?;
        let mat = self.rematerialize_buffer(buf_id)?;
        self.refresh_mirror()?;
        Ok(BufferDto {
            id: mat.id.to_string(),
            name: mat.name,
            position: mat.position,
            updated_at_ms: mat.updated_at_ms,
        })
    }

    pub fn delete_buffer(&mut self, selector: &str, actor: &str) -> Result<BufferDto, CoreError> {
        let buf_id = self.resolve_buffer_id(selector)?;
        self.check_bootstrap_gate(EntityType::Buffer, &buf_id.to_string(), OpType::Delete)?;
        // Also soft-delete all active blocks inside the buffer (`docs/sync-protocol.md` §2.2)
        let child_ids: Vec<String> = {
            let mut stmt = self
                .conn
                .prepare("SELECT id FROM blocks WHERE buffer_id = ?1 AND state = 'ACTIVE'")
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query child blocks")
                })?;
            let rows: Vec<String> = stmt
                .query_map([buf_id.to_string()], |r| r.get(0))
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map child blocks"))?
                .filter_map(Result::ok)
                .collect();
            rows
        };
        for cid in child_ids {
            let _ = self.delete_block(&cid, None, actor);
        }

        let now = now_ms();
        let op_id = OpId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let hlc = self.hlc_clock.tick(now);
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();
        let parents = self.current_entity_leaves(EntityType::Buffer, &buf_id.to_string())?;
        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Buffer,
            entity_id: buf_id.to_string(),
            op_type: OpType::Delete,
            parent_op_ids: parents.clone(),
            hlc: hlc.clone(),
            actor: actor.to_string(),
            body: OpBodyV1::Tombstone {
                deleted_at_ms: now as i64,
            },
        };
        let mns1 = encrypt_mns1(smk_kid, &smk, op_id, &self.device_id, &inner, rand_bytes::<24>()?)?;
        self.insert_sync_op(
            op_id,
            None,
            EntityType::Buffer,
            &buf_id.to_string(),
            &parents,
            OpType::Delete,
            &hlc,
            actor,
            None,
            smk_kid,
            &mns1,
            now as i64,
        )?;
        let mat = self.rematerialize_buffer(buf_id)?;
        if self.key_self_check()?.0 {
            let buf_keys = self.collect_entity_unshredded_key_ids(EntityType::Buffer, &buf_id.to_string())?;
            let _ =
                self.queue_local_shred_marks(&buf_keys, mynote_core::vault::T_GRACE_DEFAULT_MS, now as i64);
        }
        self.refresh_mirror()?;
        Ok(BufferDto {
            id: mat.id.to_string(),
            name: mat.name,
            position: mat.position,
            updated_at_ms: mat.updated_at_ms,
        })
    }

    fn current_entity_leaves(
        &self,
        entity_type: EntityType,
        entity_id: &str,
    ) -> Result<Vec<OpId>, CoreError> {
        let decoded = self.load_entity_decoded_ops(entity_type, entity_id)?;
        let dag: Vec<&DecodedOp> = decoded.iter().filter(|d| d.inner.op_type.is_dag_op()).collect();
        let mut refs = BTreeSet::new();
        for d in &dag {
            for p in &d.inner.parent_op_ids {
                refs.insert(*p);
            }
        }
        Ok(dag
            .iter()
            .filter(|d| !refs.contains(&d.op_id))
            .map(|d| d.op_id)
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_sync_op(
        &self,
        op_id: OpId,
        server_seq: Option<i64>,
        entity_type: EntityType,
        entity_id: &str,
        parents: &[OpId],
        op_type: OpType,
        hlc: &Hlc,
        actor: &str,
        key_id: Option<KeyId>,
        smk_kid: SmkKid,
        envelope: &[u8],
        created_at_ms: i64,
    ) -> Result<(), CoreError> {
        let et = match entity_type {
            EntityType::Buffer => "buffer",
            EntityType::Block => "block",
        };
        let ot = match op_type {
            OpType::Create => "CREATE",
            OpType::Update => "UPDATE",
            OpType::SetMeta => "SET_META",
            OpType::Lock => "LOCK",
            OpType::Unlock => "UNLOCK",
            OpType::Resolve => "RESOLVE",
            OpType::Delete => "DELETE",
        };
        let parents_json = serde_json::to_string(parents).unwrap_or_else(|_| "[]".to_string());
        self.conn
            .execute(
                "INSERT INTO sync_ops
                 (op_id, server_seq, sync_blocked_reason, device_id, entity_type, entity_id,
                  parent_op_ids, op_type, hlc, actor, key_id, smk_kid, envelope, created_at_ms)
                 VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    op_id.to_string(),
                    server_seq,
                    self.device_id.as_str(),
                    et,
                    entity_id,
                    parents_json,
                    ot,
                    hlc.canonical_string(),
                    actor,
                    key_id.map(|k| k.to_string()),
                    smk_kid.to_string(),
                    envelope,
                    created_at_ms,
                ],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert sync_ops"))?;
        Ok(())
    }

    pub fn add_block(
        &mut self,
        buffer_selector: &str,
        content: &str,
        lang: Option<&str>,
        after_id: Option<&str>,
        actor: &str,
        idempotency_key: Option<&str>,
    ) -> Result<WriteReceipt, CoreError> {
        if let Some(ik) = idempotency_key {
            let replay: Option<(String, String)> = self
                .conn
                .query_row(
                    "SELECT entity_id, op_id FROM idempotency_keys WHERE idem_key = ?1",
                    [ik],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "check idem_key"))?;
            if let Some((entity_id, op_id)) = replay {
                let blk_id = BlockId::parse(&entity_id)?;
                let buf_id: String = self
                    .conn
                    .query_row("SELECT buffer_id FROM blocks WHERE id = ?1", [&entity_id], |r| {
                        r.get(0)
                    })
                    .unwrap_or_default();
                let heads = self
                    .current_entity_leaves(EntityType::Block, &entity_id)?
                    .into_iter()
                    .map(|o| o.to_string())
                    .collect();
                return Ok(WriteReceipt {
                    block_id: blk_id.to_string(),
                    op_id,
                    head_op_ids: heads,
                    buffer_id: buf_id,
                    idempotent_replay: Some(true),
                });
            }
        }

        let buf_id = self.resolve_buffer_id(buffer_selector)?;
        let pos = self.compute_block_position(buf_id, after_id, None)?;
        let detected_lang = lang
            .map(str::to_string)
            .unwrap_or_else(|| sniff_language(content));

        let now = now_ms();
        let blk_id = BlockId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let op_id = OpId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let key_id = KeyId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let bdek = Zeroizing::new(rand_bytes::<32>()?);
        let hlc = self.hlc_clock.tick(now);
        let keyring_gen = self.current_keyring()?.keyring_gen;
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();

        let mnb1 = encrypt_mnb1(
            blk_id.as_bytes(),
            op_id,
            key_id,
            &bdek,
            content,
            rand_bytes::<24>()?,
        )?;
        let krec = KeyRecordV1 {
            v: 1,
            key_id,
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
            op_type: OpType::Create,
            parent_op_ids: vec![],
            hlc: hlc.clone(),
            actor: actor.to_string(),
            body: OpBodyV1::BlockContent {
                buffer_id: Some(buf_id),
                position: Some(pos),
                lang: Some(detected_lang),
                public_hint: None,
                tier: 1,
                key_id,
                mnb1,
            },
        };
        let mns1 = encrypt_mns1(smk_kid, &smk, op_id, &self.device_id, &inner, rand_bytes::<24>()?)?;

        self.conn
            .execute(
                "INSERT INTO block_keys (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                 VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, 0)",
                params![
                    key_id.to_string(),
                    blk_id.to_string(),
                    keyring_gen as i64,
                    mnr1,
                    hlc.canonical_string(),
                    now as i64,
                ],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert block_key"))?;

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

        if let Some(ik) = idempotency_key {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO idempotency_keys (idem_key, command, entity_id, op_id, created_at_ms)
                     VALUES (?1, 'add', ?2, ?3, ?4)",
                    params![ik, blk_id.to_string(), op_id.to_string(), now as i64],
                )
                .ok();
        }

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

    fn compute_block_position(
        &self,
        buf_id: BufferId,
        after_id: Option<&str>,
        before_id: Option<&str>,
    ) -> Result<String, CoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, position FROM blocks WHERE buffer_id = ?1 AND state = 'ACTIVE'
                 ORDER BY position COLLATE BINARY ASC, id ASC",
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query positions"))?;
        let rows: Vec<(String, String)> = stmt
            .query_map([buf_id.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map positions"))?
            .filter_map(Result::ok)
            .collect();

        let (prev, next) = if let Some(aid) = after_id {
            let idx = rows.iter().position(|(id, _)| id == aid).ok_or_else(|| {
                CoreError::new(
                    ErrorCode::NotFound,
                    format!("block '{aid}' not found"),
                    "Check --after ID",
                )
            })?;
            (
                Some(rows[idx].1.as_str()),
                rows.get(idx + 1).map(|(_, p)| p.as_str()),
            )
        } else if let Some(bid) = before_id {
            let idx = rows.iter().position(|(id, _)| id == bid).ok_or_else(|| {
                CoreError::new(
                    ErrorCode::NotFound,
                    format!("block '{bid}' not found"),
                    "Check --before ID",
                )
            })?;
            (
                if idx > 0 {
                    Some(rows[idx - 1].1.as_str())
                } else {
                    None
                },
                Some(rows[idx].1.as_str()),
            )
        } else {
            (rows.last().map(|(_, p)| p.as_str()), None)
        };
        fractional_index::between(prev, next, rand_bytes::<4>()?)
    }

    pub fn list_blocks(
        &self,
        buffer_selector: Option<&str>,
        limit: usize,
    ) -> Result<Vec<BlockSummaryDto>, CoreError> {
        let buf_filter = buffer_selector.map(|s| self.resolve_buffer_id(s)).transpose()?;
        let sql = if buf_filter.is_some() {
            "SELECT b.id, b.buffer_id, buf.name, b.position, b.lang, b.is_locked, b.public_hint, b.display_op_id, b.updated_at_ms
             FROM blocks b JOIN buffers buf ON b.buffer_id = buf.id
             WHERE b.state = 'ACTIVE' AND b.buffer_id = ?1
             ORDER BY b.position COLLATE BINARY ASC, b.id ASC
             LIMIT ?2"
        } else {
            "SELECT b.id, b.buffer_id, buf.name, b.position, b.lang, b.is_locked, b.public_hint, b.display_op_id, b.updated_at_ms
             FROM blocks b JOIN buffers buf ON b.buffer_id = buf.id
             WHERE b.state = 'ACTIVE' AND buf.state = 'ACTIVE'
             ORDER BY buf.position COLLATE BINARY ASC, buf.id ASC, b.position COLLATE BINARY ASC, b.id ASC
             LIMIT ?1"
        };

        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "list blocks"))?;
        let map_summary = |r: &rusqlite::Row<'_>| -> rusqlite::Result<BlockSummaryRow> {
            Ok(BlockSummaryRow {
                id: r.get(0)?,
                buffer_id: r.get(1)?,
                buffer_name: r.get(2)?,
                position: r.get(3)?,
                lang: r.get(4)?,
                is_locked: r.get::<_, i64>(5)? != 0,
                public_hint: r.get(6)?,
                display_op_id: r.get(7)?,
                updated_at_ms: r.get(8)?,
            })
        };
        let raw_rows: Vec<BlockSummaryRow> = if let Some(bid) = buf_filter {
            stmt.query_map(params![bid.to_string(), limit as i64], map_summary)
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query blocks"))?
                .filter_map(Result::ok)
                .collect()
        } else {
            stmt.query_map(params![limit as i64], map_summary)
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query blocks"))?
                .filter_map(Result::ok)
                .collect()
        };

        let mut out = Vec::with_capacity(raw_rows.len());
        for row in raw_rows {
            out.push(self.build_summary_dto(
                row.id,
                row.buffer_id,
                row.buffer_name,
                row.position,
                row.lang,
                row.is_locked,
                row.public_hint,
                row.display_op_id,
                row.updated_at_ms,
            )?);
        }
        Ok(out)
    }

    pub fn search_blocks(
        &self,
        query: &str,
        buffer_selector: Option<&str>,
        limit: usize,
    ) -> Result<Vec<BlockSummaryDto>, CoreError> {
        let buf_filter = buffer_selector.map(|s| self.resolve_buffer_id(s)).transpose()?;
        let mut stmt = self
            .conn
            .prepare(
                "SELECT DISTINCT b.id, b.buffer_id, buf.name, b.position, b.lang, b.is_locked, b.public_hint, b.display_op_id, b.updated_at_ms
                 FROM blocks_fts f
                 JOIN block_leaves l ON l.rowid = f.rowid
                 JOIN blocks b ON b.id = l.block_id
                 JOIN buffers buf ON buf.id = b.buffer_id
                 WHERE blocks_fts MATCH ?1 AND b.state = 'ACTIVE' AND b.is_locked = 0
                 ORDER BY bm25(blocks_fts)
                 LIMIT ?2",
            )
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::InvalidArgument,
                    format!("FTS5 search query error: {e}"),
                    "Check search query syntax",
                )
            })?;

        let raw_rows: Vec<BlockSummaryRow> = stmt
            .query_map(params![query, (limit * 2) as i64], |r| {
                Ok(BlockSummaryRow {
                    id: r.get(0)?,
                    buffer_id: r.get(1)?,
                    buffer_name: r.get(2)?,
                    position: r.get(3)?,
                    lang: r.get(4)?,
                    is_locked: r.get::<_, i64>(5)? != 0,
                    public_hint: r.get(6)?,
                    display_op_id: r.get(7)?,
                    updated_at_ms: r.get(8)?,
                })
            })
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::InvalidArgument,
                    format!("FTS5 match failed: {e}"),
                    "Escape special FTS operators with quotes",
                )
            })?
            .filter_map(Result::ok)
            .collect();

        let mut out = Vec::new();
        for row in raw_rows {
            if let Some(bf) = buf_filter {
                if row.buffer_id != bf.to_string() {
                    continue;
                }
            }
            if out.len() >= limit {
                break;
            }
            out.push(self.build_summary_dto(
                row.id,
                row.buffer_id,
                row.buffer_name,
                row.position,
                row.lang,
                row.is_locked,
                row.public_hint,
                row.display_op_id,
                row.updated_at_ms,
            )?);
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_summary_dto(
        &self,
        id: String,
        buffer_id: String,
        buffer_name: String,
        position: String,
        lang: String,
        is_locked: bool,
        public_hint: Option<String>,
        display_op_id: Option<String>,
        updated_at_ms: i64,
    ) -> Result<BlockSummaryDto, CoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT op_id, actor, content, body_state FROM block_leaves WHERE block_id = ?1 ORDER BY hlc DESC, op_id DESC")
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query leaves"))?;
        let leaves: Vec<(String, String, Option<String>, String)> = stmt
            .query_map([&id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map leaves"))?
            .filter_map(Result::ok)
            .collect();

        let head_op_ids: Vec<String> = leaves.iter().map(|(o, _, _, _)| o.clone()).collect();
        let has_conflict = leaves.iter().filter(|(_, _, _, bs)| bs != "TOMBSTONE").count() > 1;
        let display_row = display_op_id
            .as_deref()
            .and_then(|d| leaves.iter().find(|(o, _, _, _)| o == d))
            .or_else(|| leaves.first());
        let actor = display_row
            .map(|(_, a, _, _)| a.clone())
            .unwrap_or_else(|| "human".to_string());

        let (byte_size, preview) = if is_locked {
            (None, None)
        } else if let Some((_, _, Some(text), _)) = display_row {
            (Some(text.len()), Some(truncate_preview(text, 240)))
        } else {
            (Some(0), Some(String::new()))
        };

        Ok(BlockSummaryDto {
            id,
            buffer_id,
            buffer_name,
            position,
            lang,
            is_locked,
            redacted: is_locked,
            public_hint,
            head_op_ids,
            display_op_id,
            has_conflict,
            byte_size,
            preview,
            actor,
            updated_at_ms,
        })
    }

    pub fn get_block(&self, block_id_str: &str) -> Result<BlockDetailDto, CoreError> {
        let blk_id = BlockId::parse(block_id_str)?;
        let row: BlockDetailRow = self
            .conn
            .query_row(
                "SELECT buffer_id, position, lang, public_hint, state, is_locked, display_op_id, updated_at_ms, deleted_at_ms
                 FROM blocks WHERE id = ?1",
                [blk_id.to_string()],
                |r| {
                    Ok(BlockDetailRow {
                        buffer_id: r.get(0)?,
                        position: r.get(1)?,
                        lang: r.get(2)?,
                        public_hint: r.get(3)?,
                        state: r.get(4)?,
                        is_locked: r.get::<_, i64>(5)? != 0,
                        display_op_id: r.get(6)?,
                        updated_at_ms: r.get(7)?,
                        deleted_at_ms: r.get(8)?,
                    })
                },
            )
            .optional()
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query block"))?
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::NotFound,
                    format!("block '{block_id_str}' not found"),
                    "Run 'mynote ls --json' to list active blocks",
                )
            })?;

        if row.state == "TRASHED" {
            let (_, nb_ms) = self.block_trash_shred_status(&blk_id.to_string());
            return Err(CoreError::new(
                ErrorCode::InTrash,
                format!(
                    "block '{block_id_str}' is in the recycle bin (deleted_at_ms={})",
                    row.deleted_at_ms.unwrap_or(0)
                ),
                format!("Run 'mynote trash restore {block_id_str}' to undo the deletion"),
            )
            .with_details(serde_json::json!({
                "deleted_at_ms": row.deleted_at_ms,
                "shred_not_before_ms": nb_ms,
            })));
        }
        if row.state == "SHREDDED" {
            return Err(CoreError::new(
                ErrorCode::KeyShredded,
                format!("block '{block_id_str}' has been shredded"),
                "Shredded blocks cannot be read or recovered",
            ));
        }

        let is_locked = row.is_locked;
        let mut stmt = self
            .conn
            .prepare(
                "SELECT op_id, hlc, device_id, actor, body_state, tier, content
                 FROM block_leaves WHERE block_id = ?1 ORDER BY hlc DESC, op_id DESC",
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query block_leaves"))?;
        let raw_leaves: Vec<BlockLeafRow> = stmt
            .query_map([blk_id.to_string()], |r| {
                Ok(BlockLeafRow {
                    op_id: r.get(0)?,
                    hlc: r.get(1)?,
                    device_id: r.get(2)?,
                    actor: r.get(3)?,
                    body_state: r.get(4)?,
                    tier: r.get(5)?,
                    content: r.get(6)?,
                })
            })
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map block_leaves"))?
            .filter_map(Result::ok)
            .collect();

        let head_op_ids: Vec<String> = raw_leaves.iter().map(|r| r.op_id.clone()).collect();
        let has_unlocked_concurrent_version = is_locked && raw_leaves.iter().any(|r| r.tier == Some(1));

        let mut versions: Vec<BlockVersionDto> = Vec::new();
        let mut display_content: Option<String> = None;

        for leaf in raw_leaves {
            if leaf.body_state == "TOMBSTONE" {
                continue;
            }
            let is_display = row.display_op_id.as_deref() == Some(leaf.op_id.as_str());
            let exposed_content = if is_locked { None } else { leaf.content };
            if is_display {
                display_content = exposed_content.clone();
            }
            versions.push(BlockVersionDto {
                op_id: leaf.op_id,
                hlc: leaf.hlc,
                device_id: leaf.device_id,
                actor: leaf.actor,
                is_display,
                is_locked: leaf.tier == Some(2),
                key_id: None,
                content: exposed_content,
                mnb1_b64: None,
                mnw1_b64: None,
            });
        }

        // Display version ALWAYS first (`docs/interface-contracts.md` §2.2 & §2.6 #5)
        versions.sort_by(|a, b| {
            b.is_display
                .cmp(&a.is_display)
                .then_with(|| (&b.hlc, &b.op_id).cmp(&(&a.hlc, &a.op_id)))
        });

        let has_conflict = versions.len() > 1;

        Ok(BlockDetailDto {
            id: blk_id.to_string(),
            buffer_id: row.buffer_id,
            position: row.position,
            lang: row.lang,
            is_locked,
            redacted: is_locked,
            has_unlocked_concurrent_version,
            public_hint: row.public_hint,
            head_op_ids,
            display_op_id: row.display_op_id,
            has_conflict,
            content: display_content,
            versions,
            updated_at_ms: row.updated_at_ms,
        })
    }

    pub fn update_block(
        &mut self,
        block_id_str: &str,
        new_content: &str,
        expected_heads: &[String],
        force: bool,
        actor: &str,
    ) -> Result<WriteReceipt, CoreError> {
        let detail = self.get_block(block_id_str)?;
        self.check_bootstrap_gate(EntityType::Block, &detail.id, OpType::Update)?;
        if detail.is_locked {
            return Err(CoreError::new(
                ErrorCode::BlockLocked,
                format!("block '{block_id_str}' is locked (Tier 2 Vault)"),
                "Unlock the block interactively in desktop UI or TTY before editing",
            ));
        }
        if !force && detail.versions.iter().any(|v| v.content.is_none()) {
            return Err(CoreError::new(
                ErrorCode::KeyMissing,
                format!(
                    "block '{block_id_str}' has unreadable leaves (KEY_UNAVAILABLE or DECRYPT_FAILED); refusing plaintext overwrite"
                ),
                "Sync missing keys or unlock keyring before editing this block",
            ));
        }
        let actual_set: BTreeSet<String> = detail.head_op_ids.iter().cloned().collect();
        if !force {
            let expected_set: BTreeSet<String> = expected_heads.iter().cloned().collect();
            if expected_set != actual_set {
                return Err(CoreError::new(
                    ErrorCode::HeadMismatch,
                    format!("block {block_id_str} heads changed concurrently"),
                    format!(
                        "Run 'mynote block get {block_id_str} --json' to inspect latest versions, then retry with --expected-head {}",
                        detail.head_op_ids.join(" --expected-head ")
                    ),
                )
                .with_details(serde_json::json!({
                    "expected_heads": expected_heads,
                    "actual_heads": detail.head_op_ids,
                })));
            }
        }

        let blk_id = BlockId::parse(block_id_str)?;
        let key_id = self.find_active_block_key(blk_id)?;
        let bdek = self.unwrap_tier1_bdek(key_id)?;

        let parents: Vec<OpId> = detail
            .head_op_ids
            .iter()
            .map(|s| OpId::parse(s))
            .collect::<Result<_, _>>()?;
        let now = now_ms();
        let op_id = OpId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let hlc = self.hlc_clock.tick(now);
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();

        let mnb1 = encrypt_mnb1(
            blk_id.as_bytes(),
            op_id,
            key_id,
            &bdek,
            new_content,
            rand_bytes::<24>()?,
        )?;
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
                key_id,
                mnb1,
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

    pub fn append_block(
        &mut self,
        block_id_str: &str,
        suffix: &str,
        expected_heads: Option<&[String]>,
        actor: &str,
    ) -> Result<WriteReceipt, CoreError> {
        let detail = self.get_block(block_id_str)?;
        self.check_bootstrap_gate(EntityType::Block, &detail.id, OpType::Update)?;
        if detail.is_locked {
            return Err(CoreError::new(
                ErrorCode::BlockLocked,
                format!("block '{block_id_str}' is locked"),
                "Unlock the block before appending",
            ));
        }
        if detail.has_conflict {
            return Err(CoreError::new(
                ErrorCode::ConflictPresent,
                format!("block '{block_id_str}' has {} concurrent versions", detail.versions.len()),
                format!(
                    "Inspect with 'mynote block get {block_id_str} --json', then merge via 'mynote block update {block_id_str} --expected-head ...'"
                ),
            ));
        }
        let heads = match expected_heads {
            Some(h) if !h.is_empty() => h.to_vec(),
            _ => detail.head_op_ids.clone(),
        };
        let mut combined = detail.content.ok_or_else(|| {
            CoreError::new(
                ErrorCode::KeyMissing,
                format!(
                    "block '{block_id_str}' content is unreadable; refusing to append over unavailable body"
                ),
                "Sync missing keys or unlock keyring before modifying this block",
            )
        })?;
        if !combined.is_empty() && !combined.ends_with('\n') && !suffix.starts_with('\n') {
            combined.push('\n');
        }
        combined.push_str(suffix);
        self.update_block(block_id_str, &combined, &heads, false, actor)
    }

    pub fn move_block(
        &mut self,
        block_id_str: &str,
        to_buf: Option<&str>,
        after_id: Option<&str>,
        before_id: Option<&str>,
        lang: Option<&str>,
        actor: &str,
    ) -> Result<WriteReceipt, CoreError> {
        let detail = self.get_block(block_id_str)?;
        self.check_bootstrap_gate(EntityType::Block, &detail.id, OpType::SetMeta)?;
        let blk_id = BlockId::parse(block_id_str)?;
        let target_buf = match to_buf {
            Some(s) => self.resolve_buffer_id(s)?,
            None => BufferId::parse(&detail.buffer_id)?,
        };
        let new_pos = if after_id.is_some() || before_id.is_some() || to_buf.is_some() {
            Some(self.compute_block_position(target_buf, after_id, before_id)?)
        } else {
            None
        };

        let now = now_ms();
        let op_id = OpId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let hlc = self.hlc_clock.tick(now);
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();

        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: blk_id.to_string(),
            op_type: OpType::SetMeta,
            parent_op_ids: vec![],
            hlc: hlc.clone(),
            actor: actor.to_string(),
            body: OpBodyV1::BlockMeta {
                buffer_id: to_buf.map(|_| target_buf),
                position: new_pos,
                lang: lang.map(str::to_string),
                public_hint: None,
            },
        };
        let mns1 = encrypt_mns1(smk_kid, &smk, op_id, &self.device_id, &inner, rand_bytes::<24>()?)?;
        self.insert_sync_op(
            op_id,
            None,
            EntityType::Block,
            &blk_id.to_string(),
            &[],
            OpType::SetMeta,
            &hlc,
            actor,
            None,
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

    pub fn delete_block(
        &mut self,
        block_id_str: &str,
        expected_heads: Option<&[String]>,
        actor: &str,
    ) -> Result<DeleteReceipt, CoreError> {
        let detail = self.get_block(block_id_str)?;
        self.check_bootstrap_gate(EntityType::Block, &detail.id, OpType::Delete)?;
        if let Some(exp) = expected_heads {
            if !exp.is_empty() {
                let exp_set: BTreeSet<String> = exp.iter().cloned().collect();
                let act_set: BTreeSet<String> = detail.head_op_ids.iter().cloned().collect();
                if exp_set != act_set {
                    return Err(CoreError::new(
                        ErrorCode::HeadMismatch,
                        format!("block {block_id_str} heads changed concurrently"),
                        format!("Run 'mynote block get {block_id_str} --json' and retry"),
                    )
                    .with_details(serde_json::json!({
                        "expected_heads": exp,
                        "actual_heads": detail.head_op_ids,
                    })));
                }
            }
        }
        let blk_id = BlockId::parse(block_id_str)?;
        let parents: Vec<OpId> = detail
            .head_op_ids
            .iter()
            .map(|s| OpId::parse(s))
            .collect::<Result<_, _>>()?;
        let now = now_ms();
        let op_id = OpId::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let hlc = self.hlc_clock.tick(now);
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();

        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: blk_id.to_string(),
            op_type: OpType::Delete,
            parent_op_ids: parents.clone(),
            hlc: hlc.clone(),
            actor: actor.to_string(),
            body: OpBodyV1::Tombstone {
                deleted_at_ms: now as i64,
            },
        };
        let mns1 = encrypt_mns1(smk_kid, &smk, op_id, &self.device_id, &inner, rand_bytes::<24>()?)?;
        self.insert_sync_op(
            op_id,
            None,
            EntityType::Block,
            &blk_id.to_string(),
            &parents,
            OpType::Delete,
            &hlc,
            actor,
            None,
            smk_kid,
            &mns1,
            now as i64,
        )?;
        let mat = self.rematerialize_block(blk_id)?;
        let (shred_state, shred_not_before_ms) = if self.key_self_check()?.0 {
            let keys = self.collect_entity_unshredded_key_ids(EntityType::Block, &blk_id.to_string())?;
            if keys.is_empty() {
                ("unscheduled".to_string(), None)
            } else {
                self.queue_local_shred_marks(&keys, mynote_core::vault::T_GRACE_DEFAULT_MS, now as i64)?;
                ("pending_sync".to_string(), None)
            }
        } else {
            ("withheld_self_check".to_string(), None)
        };
        self.refresh_mirror()?;

        Ok(DeleteReceipt {
            block_id: mat.id.to_string(),
            op_id: op_id.to_string(),
            head_op_ids: mat.head_op_ids().into_iter().map(|o| o.to_string()).collect(),
            buffer_id: mat.buffer_id.to_string(),
            in_trash: true,
            shred_not_before_ms,
            shred_state,
        })
    }

    pub fn list_trash(&self) -> Result<Vec<TrashItemDto>, CoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT b.id, b.buffer_id, buf.name, b.is_locked, COALESCE(b.deleted_at_ms, b.updated_at_ms)
                 FROM blocks b JOIN buffers buf ON b.buffer_id = buf.id
                 WHERE b.state = 'TRASHED'
                 ORDER BY b.deleted_at_ms DESC, b.id ASC",
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query trash"))?;
        let rows: Vec<(String, String, String, i64, i64)> = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map trash"))?
            .filter_map(Result::ok)
            .collect();

        let mut out = Vec::with_capacity(rows.len());
        for (id, buffer_id, buffer_name, is_locked_i, deleted_at_ms) in rows {
            let (dev, actor): (String, String) = self
                .conn
                .query_row(
                    "SELECT device_id, actor FROM block_leaves WHERE block_id = ?1 ORDER BY hlc DESC LIMIT 1",
                    [&id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap_or_else(|_| (self.device_id.to_string(), "human".to_string()));
            // Trashed blocks have no live leaves so blocks.is_locked is 0; inspect latest content op tier.
            let is_locked = if is_locked_i != 0 {
                true
            } else {
                self.conn
                    .query_row(
                        "SELECT op_id, device_id, key_id, smk_kid, envelope
                         FROM sync_ops
                         WHERE entity_type = 'block' AND entity_id = ?1 AND key_id IS NOT NULL
                         ORDER BY hlc DESC LIMIT 1",
                        [&id],
                        |r| {
                            Ok((
                                r.get::<_, String>(0)?,
                                r.get::<_, String>(1)?,
                                r.get::<_, Option<String>>(2)?,
                                r.get::<_, String>(3)?,
                                r.get::<_, Vec<u8>>(4)?,
                            ))
                        },
                    )
                    .optional()
                    .ok()
                    .flatten()
                    .and_then(|(oid_s, dev_s, kid_s, smk_s, env)| {
                        let oid = OpId::parse(&oid_s).ok()?;
                        let d = DeviceId::parse(dev_s).ok()?;
                        let kid = kid_s.as_deref().and_then(|s| KeyId::parse(s).ok());
                        let skid = SmkKid::parse(&smk_s).ok()?;
                        let smk = self.smks.get(&skid)?;
                        let inner = decrypt_mns1(skid, smk, oid, &d, kid, &env).ok()?;
                        match inner.body {
                            OpBodyV1::BlockContent { tier, .. } => Some(tier == 2),
                            _ => None,
                        }
                    })
                    .unwrap_or(false)
            };
            let (shred_state, shred_not_before_ms) = self.block_trash_shred_status(&id);
            out.push(TrashItemDto {
                id,
                buffer_id,
                buffer_name,
                is_locked,
                preview: None,
                deleted_at_ms,
                deleted_by_device: dev,
                actor,
                shred_not_before_ms,
                shred_state,
            });
        }
        // `docs/interface-contracts.md` §2.6 #5: sort by `shred_not_before_ms` ASC NULLS LAST
        out.sort_by(|a, b| match (a.shred_not_before_ms, b.shred_not_before_ms) {
            (Some(x), Some(y)) => x.cmp(&y).then_with(|| a.id.cmp(&b.id)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => b
                .deleted_at_ms
                .cmp(&a.deleted_at_ms)
                .then_with(|| a.id.cmp(&b.id)),
        });
        Ok(out)
    }

    pub fn restore_trash(&mut self, block_id_str: &str, actor: &str) -> Result<WriteReceipt, CoreError> {
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
                    "Run 'mynote trash ls' to inspect blocks in the recycle bin",
                ));
            }
        }

        // Recover pre-deletion content from the latest non-tombstone op in sync_ops
        let decoded = self.load_entity_decoded_ops(EntityType::Block, &blk_id.to_string())?;
        let last_content_op = decoded
            .iter()
            .rev()
            .find(|d| matches!(d.inner.body, OpBodyV1::BlockContent { .. }))
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::KeyShredded,
                    "no recoverable content op found",
                    "Key may be shredded",
                )
            })?;

        let (key_id, mnb1) = match &last_content_op.inner.body {
            OpBodyV1::BlockContent {
                key_id,
                mnb1,
                tier: 1,
                ..
            } => (*key_id, mnb1.as_slice()),
            OpBodyV1::BlockContent { tier: 2, .. } => {
                return Err(CoreError::new(
                    ErrorCode::BlockLocked,
                    "restoring a locked block requires Vault unlock in UI/TTY",
                    "Unlock Vault in desktop UI before restoring this block",
                ));
            }
            _ => {
                return Err(CoreError::new(
                    ErrorCode::IntegrityError,
                    "unsupported or corrupted block content tier in op history",
                    "Inspect block history or restore from backup",
                ));
            }
        };
        if self.is_key_executed(&key_id) {
            return Err(CoreError::new(
                ErrorCode::KeyShredded,
                format!("key {key_id} has already been shredded"),
                "Cannot restore a shredded block",
            ));
        }
        let bdek = self.unwrap_tier1_bdek(key_id)?;
        let restored_pt = decrypt_mnb1(blk_id.as_bytes(), last_content_op.op_id, key_id, &bdek, mnb1)?;

        let receipt = self.with_savepoint("restore_trash", |this| {
            // Cancel active shred marks ONLY for the restored content key_id (M3: never cancel
            // intentionally retired keys from earlier LOCK / purge_block_history!).
            this.cancel_local_shred_marks_for_keys(&[key_id])?;

            let parents = this.current_entity_leaves(EntityType::Block, &blk_id.to_string())?;
            let now = now_ms();
            let op_id = OpId::from_ulid(this.ulid_gen.next(now, rand_bytes::<10>()?));
            let hlc = this.hlc_clock.tick(now);
            let smk_kid = this.current_smk_kid;
            let smk = this.current_smk()?.clone();

            let new_mnb1 = encrypt_mnb1(
                blk_id.as_bytes(),
                op_id,
                key_id,
                &bdek,
                &restored_pt,
                rand_bytes::<24>()?,
            )?;
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
                    key_id,
                    mnb1: new_mnb1,
                },
            };
            let mns1 = encrypt_mns1(smk_kid, &smk, op_id, &this.device_id, &inner, rand_bytes::<24>()?)?;
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
            let mat = this.rematerialize_block(blk_id)?;
            Ok(WriteReceipt {
                block_id: mat.id.to_string(),
                op_id: op_id.to_string(),
                head_op_ids: mat.head_op_ids().into_iter().map(|o| o.to_string()).collect(),
                buffer_id: mat.buffer_id.to_string(),
                idempotent_replay: None,
            })
        })?;
        self.refresh_mirror()?;

        Ok(receipt)
    }

    pub fn block_history(&self, block_id_str: &str, limit: usize) -> Result<Vec<HistoryEntryDto>, CoreError> {
        let blk_id = BlockId::parse(block_id_str)?;
        let mut decoded = self.load_entity_decoded_ops(EntityType::Block, &blk_id.to_string())?;
        if decoded.is_empty() {
            return Err(CoreError::new(
                ErrorCode::NotFound,
                format!("block '{block_id_str}' not found"),
                "Check block ID",
            ));
        }
        decoded.sort_by(|a, b| {
            (b.inner.hlc.canonical_string(), b.op_id).cmp(&(a.inner.hlc.canonical_string(), a.op_id))
        });
        let kt = self.load_key_table()?;
        let out: Vec<HistoryEntryDto> = decoded
            .into_iter()
            .take(limit)
            .map(|d| {
                let (has_content, is_locked, key_id_opt) = match &d.inner.body {
                    OpBodyV1::BlockContent { tier, key_id, .. } => (true, *tier == 2, Some(*key_id)),
                    _ => (false, false, d.inner.key_id()),
                };
                let shredded = key_id_opt.is_some_and(|k| kt.is_shredded(&k) || self.is_key_executed(&k));
                let content_available =
                    has_content && !shredded && key_id_opt.is_some_and(|k| kt.is_key_available(&k));
                HistoryEntryDto {
                    op_id: d.op_id.to_string(),
                    op_type: op_type_str(d.inner.op_type).to_string(),
                    hlc: d.inner.hlc.canonical_string(),
                    device_id: d.device_id.to_string(),
                    actor: d.inner.actor,
                    content_available,
                    has_content,
                    is_locked,
                    shredded,
                    key_id: key_id_opt.map(|k| k.to_string()),
                    created_at_ms: d.created_at_ms,
                }
            })
            .collect();
        Ok(out)
    }

    /// Resolve a revert target op (by explicit `to_op` or `undo_actor`) while enforcing single-leaf
    /// conflict refusal (`CONFLICT_PRESENT`) and strict fail-closed handling of shredded targets
    /// (`KEY_SHREDDED` — never skipping past a shredded predecessor).
    pub fn resolve_revert_target(
        &self,
        block_id_str: &str,
        to_op: Option<&str>,
        undo_actor: Option<&str>,
    ) -> Result<ResolvedRevertTarget, CoreError> {
        if to_op.is_none() && undo_actor.is_none() {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "specify either --to-op <op_id> or --undo-actor <actor>",
                format!("Run 'mynote block history {block_id_str} --json' to list historical ops"),
            ));
        }
        if to_op.is_some() && undo_actor.is_some() {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "specify either --to-op or --undo-actor, not both",
                "Pass only one revert selector",
            ));
        }
        let detail = self.get_block(block_id_str)?;
        if detail.has_conflict {
            return Err(CoreError::new(
                ErrorCode::ConflictPresent,
                format!("block '{block_id_str}' has multiple leaves; merge before reverting"),
                format!("Run 'mynote block get {block_id_str} --json' first"),
            ));
        }
        let history = self.block_history(block_id_str, usize::MAX)?;
        let (target, skipped_actor_ops) = if let Some(op_s) = to_op {
            let target_op_id = OpId::parse(op_s)?;
            let target_str = target_op_id.to_string();
            let entry = history
                .into_iter()
                .find(|e| e.op_id == target_str)
                .ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::NotFound,
                        format!("op '{op_s}' not found in block '{block_id_str}'"),
                        format!("Run 'mynote block history {block_id_str} --json'"),
                    )
                })?;
            if !entry.has_content {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    format!("op '{op_s}' has no block content (op_type={})", entry.op_type),
                    "Choose a CREATE, UPDATE, LOCK, UNLOCK, or RESOLVE op_id",
                ));
            }
            if entry.shredded {
                return Err(CoreError::new(
                    ErrorCode::KeyShredded,
                    format!("op '{op_s}' cannot be restored because its key was permanently shredded"),
                    "Shredded historical versions cannot be recovered",
                ));
            }
            if !entry.content_available {
                return Err(CoreError::new(
                    ErrorCode::KeyMissing,
                    format!("key for op '{op_s}' is not available locally"),
                    "Run 'mynote sync pull' or 'mynote keyring unlock'",
                ));
            }
            (entry, 0usize)
        } else {
            let bad_actor = undo_actor.expect("checked above");
            let mut skipped_actor_ops = 0usize;
            let mut found: Option<HistoryEntryDto> = None;
            for entry in history {
                if !entry.has_content {
                    continue;
                }
                if entry.actor == bad_actor {
                    skipped_actor_ops += 1;
                    continue;
                }
                found = Some(entry);
                break;
            }
            let entry = found.ok_or_else(|| {
                CoreError::new(
                    ErrorCode::NotFound,
                    format!("no earlier version authored outside actor '{bad_actor}'"),
                    format!("Run 'mynote block history {block_id_str} --json' to pick an op_id explicitly"),
                )
            })?;
            if entry.shredded {
                return Err(CoreError::new(
                    ErrorCode::KeyShredded,
                    format!(
                        "target version '{}' (actor '{}') cannot be restored because its key was permanently shredded",
                        entry.op_id, entry.actor
                    ),
                    "Shredded historical versions cannot be recovered",
                ));
            }
            if !entry.content_available {
                return Err(CoreError::new(
                    ErrorCode::KeyMissing,
                    format!(
                        "key for target version '{}' is not available locally",
                        entry.op_id
                    ),
                    "Run 'mynote sync pull' or 'mynote keyring unlock'",
                ));
            }
            (entry, skipped_actor_ops)
        };

        Ok(ResolvedRevertTarget {
            detail,
            target,
            skipped_actor_ops,
        })
    }

    /// Preview a revert operation without mutating SQLite (`--dry-run`).
    /// Never exposes plaintext for locked blocks or Tier 2 historical versions (`SEC-03`).
    pub fn preview_revert_block(
        &self,
        block_id_str: &str,
        to_op: Option<&str>,
        undo_actor: Option<&str>,
    ) -> Result<RevertPreviewDto, CoreError> {
        let resolved = self.resolve_revert_target(block_id_str, to_op, undo_actor)?;
        let is_locked = resolved.target.is_locked || resolved.detail.is_locked;
        let preview = if is_locked {
            None
        } else {
            let hist_op = self.get_block_history_op_for_daemon(block_id_str, &resolved.target.op_id)?;
            hist_op.content.map(|pt| truncate_preview(&pt, 240))
        };
        let current_head_op_id = resolved
            .detail
            .display_op_id
            .clone()
            .or_else(|| resolved.detail.head_op_ids.first().cloned());

        Ok(RevertPreviewDto {
            dry_run: true,
            block_id: resolved.detail.id,
            current_head_op_id,
            target_op_id: resolved.target.op_id,
            target_actor: resolved.target.actor,
            target_hlc: resolved.target.hlc,
            target_op_type: resolved.target.op_type,
            skipped_actor_ops: resolved.skipped_actor_ops,
            is_locked,
            preview,
        })
    }

    pub fn revert_block(
        &mut self,
        block_id_str: &str,
        to_op_id_str: &str,
        actor: &str,
    ) -> Result<WriteReceipt, CoreError> {
        let detail = self.get_block(block_id_str)?;
        self.check_bootstrap_gate(EntityType::Block, &detail.id, OpType::Update)?;
        if detail.has_conflict {
            return Err(CoreError::new(
                ErrorCode::ConflictPresent,
                format!("block '{block_id_str}' has multiple leaves; merge before reverting"),
                format!("Run 'mynote block get {block_id_str} --json' first"),
            ));
        }
        let blk_id = BlockId::parse(block_id_str)?;
        let target_op_id = OpId::parse(to_op_id_str)?;
        let decoded = self.load_entity_decoded_ops(EntityType::Block, &blk_id.to_string())?;
        let target = decoded.iter().find(|d| d.op_id == target_op_id).ok_or_else(|| {
            CoreError::new(
                ErrorCode::NotFound,
                format!("op '{to_op_id_str}' not found in block '{block_id_str}'"),
                format!("Run 'mynote block history {block_id_str} --json'"),
            )
        })?;
        let (tier, key_id, mnb1) = match &target.inner.body {
            OpBodyV1::BlockContent {
                tier, key_id, mnb1, ..
            } => (*tier, *key_id, mnb1.as_slice()),
            _ => {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "target op has no block content",
                    "Choose a CREATE/UPDATE op_id",
                ));
            }
        };
        if self.is_key_executed(&key_id) {
            return Err(CoreError::new(
                ErrorCode::KeyShredded,
                format!("key {key_id} for op '{to_op_id_str}' has been permanently shredded"),
                "Shredded historical versions cannot be recovered",
            ));
        }
        if tier == 2 {
            return Err(CoreError::new(
                ErrorCode::BlockLocked,
                "cannot revert locked op without Vault unlock",
                "Unlock in UI",
            ));
        }
        if tier != 1 {
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                format!("unsupported block content tier {tier} in op '{to_op_id_str}'"),
                "Inspect block history or restore from backup",
            ));
        }
        let bdek = self.unwrap_tier1_bdek(key_id)?;
        let pt = decrypt_mnb1(blk_id.as_bytes(), target_op_id, key_id, &bdek, mnb1)?;
        self.update_block(block_id_str, &pt, &detail.head_op_ids, false, actor)
    }

    fn find_active_block_key(&self, blk_id: BlockId) -> Result<KeyId, CoreError> {
        let key_str: Option<String> = self
            .conn
            .query_row(
                "SELECT key_id FROM block_keys WHERE block_id = ?1 AND tier = 1 AND key_record IS NOT NULL ORDER BY created_at_ms DESC LIMIT 1",
                [blk_id.to_string()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query block key"))?;
        match key_str {
            Some(s) => KeyId::parse(&s),
            None => Err(CoreError::new(
                ErrorCode::KeyMissing,
                format!("no active Tier 1 BDEK found for block {blk_id}"),
                "Run 'mynote sync pull'",
            )),
        }
    }

    /// Import Heynote 1.x / 2.x buffers losslessly (`M1-5`, Issue #6).
    pub fn import_heynote(
        &mut self,
        path: &Path,
        buffer_override: Option<&str>,
        dry_run: bool,
        actor: &str,
    ) -> Result<ImportSummaryDto, CoreError> {
        let parsed: Vec<ParsedHeynoteBuffer> = load_heynote_path(path, buffer_override)?;
        let mut duplicate_sources = Vec::new();
        let mut buffers_imported = 0usize;
        let mut blocks_imported = 0usize;

        for buf in &parsed {
            let meta_key = format!("imported_heynote_hash:{}", buf.source_hash);
            let already: Option<String> = self
                .conn
                .query_row("SELECT value FROM local_meta WHERE key = ?1", [&meta_key], |r| {
                    r.get(0)
                })
                .optional()
                .unwrap_or(None);
            if already.is_some() {
                duplicate_sources.push(buf.buffer_name.clone());
            }

            if dry_run {
                buffers_imported += 1;
                blocks_imported += buf.blocks.len();
                continue;
            }

            let target_buf_id = match self.resolve_buffer_id(&buf.buffer_name) {
                Ok(id) => id.to_string(),
                Err(_) => self.create_buffer(&buf.buffer_name, None, actor)?.id,
            };
            buffers_imported += 1;
            for blk in &buf.blocks {
                self.add_block(&target_buf_id, &blk.content, Some(&blk.lang), None, actor, None)?;
                blocks_imported += 1;
            }
            self.conn
                .execute(
                    "INSERT OR REPLACE INTO local_meta (key, value) VALUES (?1, ?2)",
                    params![meta_key, buf.buffer_name],
                )
                .ok();
        }

        Ok(ImportSummaryDto {
            dry_run,
            buffers_imported,
            blocks_imported,
            duplicate_sources,
        })
    }

    /// Rotate SMK generation by sealing a new SMK via device-stored `recovery_pk` (NO 24 words required!),
    /// re-wrapping all active `block_keys` with `wrap_gen + 1`, and PERMANENTLY retaining old SMK generations (`F-05`).
    /// Fully atomic: decrypts/re-wraps all keys in memory first, persists the new SMK alongside old SMKs
    /// on disk (`0600` + `fsync`), then commits all SQLite updates inside a single `BEGIN IMMEDIATE` transaction.
    pub fn rotate_smk(&mut self) -> Result<(u32, SmkKid), CoreError> {
        let now = now_ms();
        let mut kr = self.current_keyring()?;
        let new_smk_kid = SmkKid::from_ulid(self.ulid_gen.next(now, rand_bytes::<10>()?));
        let new_smk = Zeroizing::new(rand_bytes::<32>()?);
        let sealed = seal_mnrs(
            &kr.recovery_pk,
            MNRS_KIND_SMK,
            new_smk_kid.as_bytes(),
            &new_smk,
            rand_bytes::<32>()?,
            rand_bytes::<24>()?,
        )?;

        kr.keyring_gen += 1;
        kr.current_smk_kid = new_smk_kid;
        kr.smk_entries.push(sealed);

        // Phase 1: Decrypt & re-wrap ALL active keys in memory before mutating disk or SQLite.
        let active_keys: Vec<(String, i64, Vec<u8>)> = {
            let mut stmt = self
                .conn
                .prepare("SELECT key_id, wrap_gen, key_record FROM block_keys WHERE key_record IS NOT NULL")
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "scan keys for rotate")
                })?;
            let rows: Vec<(String, i64, Vec<u8>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map keys for rotate"))?
                .filter_map(Result::ok)
                .collect();
            rows
        };

        let mut rewrapped_rows: Vec<(String, Vec<u8>)> = Vec::with_capacity(active_keys.len());
        for (kid_s, old_gen, mnr1) in active_keys {
            let kid = KeyId::parse(&kid_s)?;
            let old_smk_kid = SmkKid::from_bytes(peek_envelope_kid(MAGIC_MNR1, &mnr1)?);
            let old_smk = self.smks.get(&old_smk_kid).ok_or_else(|| {
                CoreError::new(
                    ErrorCode::KeyMissing,
                    format!("missing old SMK {old_smk_kid}"),
                    "Unlock keyring before rotating SMK",
                )
            })?;
            let rec = decrypt_mnr1(old_smk_kid, old_smk, kid, old_gen as u32, &mnr1)?;
            let rewrapped = encrypt_mnr1(new_smk_kid, &new_smk, kr.keyring_gen, &rec, rand_bytes::<24>()?)?;
            rewrapped_rows.push((kid_s, rewrapped));
        }

        let kr_blob = rmp_serde::to_vec_named(&kr)
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode keyring"))?;

        // Phase 2: Persist new SMK generation (retaining all old generations) BEFORE SQLite commit.
        let smk_path = self.data_dir.join("smk_keyring.local.json");
        let mut next_smks = self.smks.clone();
        next_smks.insert(new_smk_kid, new_smk);
        Self::save_local_smks(&smk_path, new_smk_kid, &next_smks)?;

        // Phase 3: Commit all re-wrapped keys, keyring blob, and drill flag atomically in SQLite.
        let tx_res: Result<(), CoreError> = (|| {
            self.conn
                .execute_batch("BEGIN IMMEDIATE;")
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "begin rotate_smk"))?;
            let body: Result<(), CoreError> = (|| {
                for (kid_s, rewrapped) in &rewrapped_rows {
                    self.conn
                        .execute(
                            "UPDATE block_keys SET wrap_gen = ?1, key_record = ?2, server_acked = 0 WHERE key_id = ?3",
                            params![kr.keyring_gen as i64, rewrapped, kid_s],
                        )
                        .map_err(|e| {
                            CoreError::new(ErrorCode::IntegrityError, e.to_string(), "rewrap block_key")
                        })?;
                }
                self.conn
                    .execute(
                        "INSERT OR REPLACE INTO key_material (kind, gen, blob, updated_at_ms) VALUES ('keyring', ?1, ?2, ?3)",
                        params![kr.keyring_gen as i64, kr_blob, now as i64],
                    )
                    .map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "save rotated keyring")
                    })?;
                self.conn
                    .execute(
                        "INSERT OR REPLACE INTO local_meta (key, value) VALUES ('recovery_drill_due', '1')",
                        [],
                    )
                    .map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "set recovery_drill_due")
                    })?;
                Ok(())
            })();
            match body {
                Ok(()) => self.conn.execute_batch("COMMIT;").map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "commit rotate_smk")
                }),
                Err(e) => {
                    let _ = self.conn.execute_batch("ROLLBACK;");
                    Err(e)
                }
            }
        })();

        if let Err(e) = tx_res {
            // Roll back current_smk_kid pointer on disk while retaining old SMKs intact.
            let _ = Self::save_local_smks(&smk_path, self.current_smk_kid, &self.smks);
            return Err(e);
        }

        self.smks = next_smks;
        self.current_smk_kid = new_smk_kid;
        Ok((kr.keyring_gen, new_smk_kid))
    }

    /// Offline sandbox recovery drill (`mynote recovery drill`, read-only on user notes, updates drill timestamp).
    pub fn recovery_drill(&self, words: &str) -> Result<RecoveryDrillDto, CoreError> {
        let kp = RecoveryKeypair::from_mnemonic_words(words)?;
        let kr = self.current_keyring()?;
        let unsealed = kp.unseal_all_smks(&kr)?;
        if unsealed.len() != kr.smk_entries.len() {
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                "recovery bundle did not unseal all SMK generations",
                "Verify recovery bundle matches this vault",
            ));
        }
        let vh_blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT blob FROM key_material WHERE kind = 'vault_header'",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);
        let has_vault = if let Some(blob) = vh_blob {
            let vh: mynote_core::crypto::VaultHeaderV1 = rmp_serde::from_slice(&blob).map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("corrupt VaultHeaderV1 during recovery drill: {e}"),
                    "Sync the latest VaultHeaderV1",
                )
            })?;
            let _ = mynote_core::vault::unseal_vault_with_recovery(&kp, &vh)?;
            true
        } else {
            false
        };
        let drilled_at_ms = now_ms() as i64;
        let _ = self.set_local_meta("recovery_drill_due", "0");
        let _ = self.set_local_meta("last_recovery_drill_ms", &drilled_at_ms.to_string());
        Ok(RecoveryDrillDto {
            ok: true,
            keyring_generations: unsealed.len(),
            includes_vkek: has_vault,
            drilled_at_ms,
        })
    }

    /// Run daily `VACUUM INTO` automatic backup (`0600`), updating `last_local_backup_ms` and pruning
    /// `auto-*.db` files older than `T_snap` (30 days, `docs/threat-model.md` §2.3, H9).
    pub fn create_auto_backup(&self, label: &str) -> Result<PathBuf, CoreError> {
        if label.is_empty()
            || label.len() > 64
            || label.contains("..")
            || !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid backup label '{label}'"),
                "Backup label must match [A-Za-z0-9._-]{1,64} without '..'",
            ));
        }
        let backups_dir = self.data_dir.join("backups");
        let dest = backups_dir.join(format!("auto-{label}.db"));
        vacuum_into(&self.conn, &dest)?;
        let now = now_ms() as i64;
        self.set_local_meta("last_local_backup_ms", &now.to_string())?;
        // Prune auto-*.db backups older than T_snap (30 days) so shredded data does not linger.
        const T_SNAP_SECS: u64 = 30 * 86_400;
        let now_sys = std::time::SystemTime::now();
        if let Ok(rd) = std::fs::read_dir(&backups_dir) {
            for ent in rd.flatten() {
                let p = ent.path();
                if p == dest {
                    continue;
                }
                if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                    if name.starts_with("auto-") && name.ends_with(".db") {
                        if let Ok(meta) = ent.metadata() {
                            if let Ok(mtime) = meta.modified() {
                                if let Ok(age) = now_sys.duration_since(mtime) {
                                    if age.as_secs() > T_SNAP_SECS {
                                        let _ = std::fs::remove_file(&p);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(dest)
    }

    /// Run read-only key liveness self-check (`INV-KEY-LIVENESS`, H9) with ZERO SQLite writes.
    /// Checks all ACTIVE blocks' live leaves AND ACTIVE buffers:
    /// - Fails if any live key is missing, shredded, pending/scheduled for shred, or fails local MNR1 unwrap;
    /// - Fails if any active leaf is in `DECRYPT_FAILED`;
    /// - Does NOT false-positive on a concurrent leaf whose key was already legitimately shredded on an
    ///   otherwise readable active block (`KEY_UNAVAILABLE` with `kt.is_shredded(&kid)`).
    pub fn key_self_check(&self) -> Result<(bool, Vec<KeyId>), CoreError> {
        let kt = self.load_key_table()?;
        let mut stmt = self
            .conn
            .prepare(
                "SELECT bl.block_id, bl.key_id, bl.body_state
                 FROM block_leaves bl
                 JOIN blocks b ON b.id = bl.block_id
                 WHERE b.state = 'ACTIVE' AND bl.body_state != 'TOMBSTONE'",
            )
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    e.to_string(),
                    "scan active block leaf keys",
                )
            })?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    e.to_string(),
                    "map active block leaf keys",
                )
            })?;
        let mut by_block: BTreeMap<String, Vec<(Option<String>, String)>> = BTreeMap::new();
        for row in rows {
            let (bid, kid_opt, body_state) = row.map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    e.to_string(),
                    "read active block leaf key",
                )
            })?;
            by_block.entry(bid).or_default().push((kid_opt, body_state));
        }
        let mut missing: BTreeSet<KeyId> = BTreeSet::new();
        let mut has_decrypt_failed = false;
        for leaves in by_block.values() {
            let has_readable_live_leaf = leaves.iter().any(|(kid_opt, body_state)| {
                if body_state != "PLAINTEXT" && body_state != "SEALED" {
                    return false;
                }
                match kid_opt.as_deref().and_then(|s| KeyId::parse(s).ok()) {
                    Some(kid) => {
                        kt.is_key_available(&kid)
                            && !kt.has_pending_or_scheduled_mark(&kid)
                            && self.unwrap_bdek(kid).is_ok()
                    }
                    None => false,
                }
            });
            for (kid_opt, body_state) in leaves {
                if body_state == "DECRYPT_FAILED" {
                    has_decrypt_failed = true;
                    if let Some(ref ks) = kid_opt {
                        if let Ok(kid) = KeyId::parse(ks) {
                            missing.insert(kid);
                        }
                    }
                    continue;
                }
                if let Some(kid_s) = kid_opt {
                    if let Ok(kid) = KeyId::parse(kid_s) {
                        if body_state == "KEY_UNAVAILABLE" && kt.is_shredded(&kid) && has_readable_live_leaf {
                            // Legitimately shredded concurrent branch on an otherwise readable active
                            // block; do not permanently wedge shredding on future trashed items.
                            continue;
                        }
                        if body_state == "KEY_UNAVAILABLE"
                            || !kt.is_key_available(&kid)
                            || kt.has_pending_or_scheduled_mark(&kid)
                            || self.unwrap_bdek(kid).is_err()
                        {
                            missing.insert(kid);
                        }
                    }
                }
            }
        }
        // Also check ACTIVE buffers' keys!
        let mut bstmt = self
            .conn
            .prepare("SELECT DISTINCT key_id FROM buffers WHERE state = 'ACTIVE'")
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    e.to_string(),
                    "scan active buffer keys",
                )
            })?;
        let brows = bstmt.query_map([], |r| r.get::<_, String>(0)).map_err(|e| {
            CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map active buffer keys")
        })?;
        for row in brows {
            let kid_s = row.map_err(|e| {
                CoreError::new(ErrorCode::IntegrityError, e.to_string(), "read active buffer key")
            })?;
            if let Ok(kid) = KeyId::parse(&kid_s) {
                if !kt.is_key_available(&kid)
                    || kt.has_pending_or_scheduled_mark(&kid)
                    || self.unwrap_bdek(kid).is_err()
                {
                    missing.insert(kid);
                }
            }
        }
        let missing_vec: Vec<KeyId> = missing.into_iter().collect();
        Ok((missing_vec.is_empty() && !has_decrypt_failed, missing_vec))
    }

    /// Inject a remote concurrent op (e.g. from another device) and re-materialize cleanly.
    /// Useful for sync apply and multi-leaf / locked-block testing (`G09`, `G10`).
    pub fn apply_remote_block_op_for_sync(
        &mut self,
        p: RemoteBlockOpParams,
    ) -> Result<MaterializedBlock, CoreError> {
        let now = now_ms() as i64;
        if let Some((wrap_gen, mnr1)) = p.new_key_record {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO block_keys (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)",
                    params![
                        p.key_id.to_string(),
                        p.block_id.to_string(),
                        p.tier as i64,
                        wrap_gen as i64,
                        mnr1,
                        p.hlc.canonical_string(),
                        now,
                    ],
                )
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert remote key"))?;
        }
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();
        let inner = InnerOpV1 {
            v: 1,
            entity_type: EntityType::Block,
            entity_id: p.block_id.to_string(),
            op_type: p.op_type,
            parent_op_ids: p.parents.clone(),
            hlc: p.hlc.clone(),
            actor: "human".to_string(),
            body: OpBodyV1::BlockContent {
                buffer_id: None,
                position: None,
                lang: None,
                public_hint: p.public_hint.map(Some),
                tier: p.tier,
                key_id: p.key_id,
                mnb1: p.mnb1,
            },
        };
        let mns1 = encrypt_mns1(
            smk_kid,
            &smk,
            p.op_id,
            &p.remote_device,
            &inner,
            rand_bytes::<24>()?,
        )?;
        let parents_json = serde_json::to_string(&p.parents).unwrap_or_else(|_| "[]".to_string());
        let ot = match p.op_type {
            OpType::Create => "CREATE",
            OpType::Update => "UPDATE",
            OpType::Lock => "LOCK",
            OpType::Unlock => "UNLOCK",
            OpType::Resolve => "RESOLVE",
            OpType::Delete => "DELETE",
            OpType::SetMeta => "SET_META",
        };
        self.conn
            .execute(
                "INSERT OR IGNORE INTO sync_ops
                 (op_id, server_seq, sync_blocked_reason, device_id, entity_type, entity_id,
                  parent_op_ids, op_type, hlc, actor, key_id, smk_kid, envelope, created_at_ms)
                 VALUES (?1, 1, NULL, ?2, 'block', ?3, ?4, ?5, ?6, 'human', ?7, ?8, ?9, ?10)",
                params![
                    p.op_id.to_string(),
                    p.remote_device.as_str(),
                    p.block_id.to_string(),
                    parents_json,
                    ot,
                    p.hlc.canonical_string(),
                    p.key_id.to_string(),
                    smk_kid.to_string(),
                    mns1,
                    now,
                ],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert remote op"))?;
        let mat = self.rematerialize_block(p.block_id)?;
        self.refresh_mirror()?;
        Ok(mat)
    }

    /// Pure offline disaster recovery (`mynote restore --from-archive <local-dir> --to <empty-dir>`, `INV-RECOVERY`).
    pub fn restore_from_archive_dir(
        archive_dir: &Path,
        recovery_words: &str,
        target_dir: &Path,
        dry_run: bool,
    ) -> Result<RestoreSummaryDto, CoreError> {
        if !dry_run && target_dir.exists() {
            let mut entries = std::fs::read_dir(target_dir).map_err(|e| {
                CoreError::new(
                    ErrorCode::InvalidArgument,
                    format!("cannot read target dir: {e}"),
                    "Check --to path",
                )
            })?;
            if entries.next().is_some() {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "target directory '{}' is not empty; refusing to overwrite",
                        target_dir.display()
                    ),
                    "Pass an empty or non-existent directory to --to <empty-data-dir>",
                ));
            }
        }

        let latest_path = archive_dir.join("keys").join("latest.mnks");
        let latest_bytes = std::fs::read(&latest_path).map_err(|e| {
            CoreError::new(
                ErrorCode::NotFound,
                format!("missing '{}': {e}", latest_path.display()),
                "Export R2 'archives/' directory containing keys/latest.mnks and ops/*.mna1",
            )
        })?;
        let (mnks_hdr, mnks_body) = mynote_core::crypto::decode_mnks(&latest_bytes)?;

        let mut segments = Vec::new();
        let ops_dir = archive_dir.join("ops");
        if ops_dir.exists() {
            collect_mna1_files(&ops_dir, &mut segments)?;
        }
        segments.sort_by(|a, b| a.0.cmp(&b.0));

        let restored_snap = offline_restore_from_r2(recovery_words, &segments, &latest_bytes)?;
        let all_bufs = restored_snap.all_buffers();
        let all_blks = restored_snap.all_blocks();
        let active_or_trashed = all_blks
            .iter()
            .filter(|b| b.state != BlockState::Shredded)
            .count();
        let skipped_shredded = all_blks
            .iter()
            .filter(|b| b.state == BlockState::Shredded)
            .count();

        if !dry_run {
            let backups_dir = target_dir.join("backups");
            let mirror_dir = target_dir.join("mirror");
            std::fs::create_dir_all(&backups_dir).map_err(|e| {
                CoreError::new(
                    ErrorCode::InvalidArgument,
                    format!("cannot create target dir: {e}"),
                    "Check permissions",
                )
            })?;
            std::fs::create_dir_all(&mirror_dir).ok();
            let conn = Connection::open(target_dir.join("mynote.db"))
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "open restored db"))?;
            init_connection(&conn, Some(&backups_dir))?;

            let dev = DeviceId::from_random_bytes(rand_bytes::<10>()?);
            conn.execute(
                "INSERT INTO local_meta (key, value) VALUES ('device_id', ?1)",
                [dev.as_str()],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert device_id"))?;
            conn.execute(
                "INSERT INTO local_meta (key, value) VALUES ('bootstrap_completed', '1')",
                [],
            )
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    e.to_string(),
                    "insert bootstrap_completed",
                )
            })?;
            let kr_blob = rmp_serde::to_vec_named(&mnks_body.keyring)
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode keyring"))?;
            conn.execute(
                "INSERT INTO key_material (kind, gen, blob, updated_at_ms) VALUES ('keyring', ?1, ?2, ?3)",
                params![
                    mnks_body.keyring.keyring_gen as i64,
                    kr_blob,
                    mnks_hdr.created_at_ms
                ],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert keyring"))?;

            // H6: Restore VaultHeaderV1 so Tier 2 Vault blocks can be unlocked offline after restore!
            if let Some(ref vh) = mnks_body.vault_header {
                let vh_blob = rmp_serde::to_vec_named(vh).map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode vault_header")
                })?;
                conn.execute(
                    "INSERT INTO key_material (kind, gen, blob, updated_at_ms) VALUES ('vault_header', ?1, ?2, ?3)",
                    params![vh.updated_at_ms, vh_blob, vh.updated_at_ms],
                )
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert vault_header")
                })?;
            }

            for rec in &mnks_body.records {
                let (blk_id_s, tier) = if let Some(mnr1) = &rec.key_record {
                    let smk_kid = SmkKid::from_bytes(peek_envelope_kid(MAGIC_MNR1, mnr1)?);
                    if let Some(smk) = restored_snap.smks.get(&smk_kid) {
                        if let Ok(kr) = decrypt_mnr1(smk_kid, smk, rec.key_id, rec.wrap_gen, mnr1) {
                            (kr.block_id.to_string(), kr.tier as i64)
                        } else {
                            (Ulid::ZERO.to_string(), 1)
                        }
                    } else {
                        (Ulid::ZERO.to_string(), 1)
                    }
                } else {
                    (Ulid::ZERO.to_string(), 1)
                };
                conn.execute(
                    "INSERT OR REPLACE INTO block_keys (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                     VALUES (?1, ?2, ?3, ?4, ?5, '', ?6, 1)",
                    params![
                        rec.key_id.to_string(),
                        blk_id_s,
                        tier,
                        rec.wrap_gen as i64,
                        rec.key_record,
                        rec.created_at_ms,
                    ],
                )
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert block_key"))?;
            }

            // H6: Restore all shred_marks (creating NULL block_keys tombstones if absent for FK safety)
            for mark in &mnks_body.marks {
                conn.execute(
                    "INSERT OR IGNORE INTO block_keys
                     (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                     VALUES (?1, ?2, 1, 1, NULL, '', ?3, 1)",
                    params![
                        mark.key_id.to_string(),
                        Ulid::ZERO.to_string(),
                        mark.requested_at_ms,
                    ],
                )
                .map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        e.to_string(),
                        "ensure block_key for mark",
                    )
                })?;
                conn.execute(
                    "INSERT OR REPLACE INTO shred_marks
                     (mark_id, key_id, requested_by, requested_at_ms, seen_seq, grace_ms, not_before_ms,
                      state, confirmed_at_ms, cancelled_by, executed_at_ms, server_acked)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1)",
                    params![
                        mark.mark_id.to_string(),
                        mark.key_id.to_string(),
                        mark.requested_by.as_str(),
                        mark.requested_at_ms,
                        mark.seen_seq,
                        mark.grace_ms,
                        mark.not_before_ms,
                        m2_vault_shred::shred_state_to_str(mark.state),
                        mark.confirmed_at_ms,
                        mark.cancelled_by.as_ref().map(|d| d.as_str()),
                        mark.executed_at_ms,
                    ],
                )
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert shred_mark"))?;
            }

            for op in restored_snap.ops.values() {
                let et = match op.entity_type {
                    EntityType::Buffer => "buffer",
                    EntityType::Block => "block",
                };
                let ot = match op.op_type {
                    OpType::Create => "CREATE",
                    OpType::Update => "UPDATE",
                    OpType::SetMeta => "SET_META",
                    OpType::Lock => "LOCK",
                    OpType::Unlock => "UNLOCK",
                    OpType::Resolve => "RESOLVE",
                    OpType::Delete => "DELETE",
                };
                let parents_json = serde_json::to_string(&op.parent_op_ids).unwrap_or_else(|_| "[]".into());
                conn.execute(
                    "INSERT OR IGNORE INTO sync_ops
                     (op_id, server_seq, sync_blocked_reason, device_id, entity_type, entity_id,
                      parent_op_ids, op_type, hlc, actor, key_id, smk_kid, envelope, created_at_ms)
                     VALUES (?1, NULL, NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    params![
                        op.op_id.to_string(),
                        op.device_id.as_str(),
                        et,
                        op.entity_id,
                        parents_json,
                        ot,
                        op.hlc.canonical_string(),
                        op.actor,
                        op.key_id.map(|k| k.to_string()),
                        op.smk_kid.to_string(),
                        op.envelope,
                        op.created_at_ms,
                    ],
                )
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "insert sync_op"))?;
            }

            Self::save_local_smks(
                &target_dir.join("smk_keyring.local.json"),
                mnks_body.keyring.current_smk_kid,
                &restored_snap.smks,
            )?;
            drop(conn);

            // Re-open restored store and rematerialize every buffer & block + mirror
            let restored_store = Self::open(target_dir)?;
            let kt = restored_store.load_key_table()?;
            for b in &all_bufs {
                let _ = restored_store.rematerialize_buffer_with_kt(b.id, &kt);
            }
            for blk in &all_blks {
                let _ = restored_store.rematerialize_block_with_kt(blk.id, &kt);
            }
            restored_store.refresh_mirror()?;
        }

        Ok(RestoreSummaryDto {
            restored_blocks: active_or_trashed,
            restored_buffers: all_bufs.len(),
            skipped_shredded,
            archive_segments: segments.len(),
            key_snapshot_at_ms: mnks_hdr.created_at_ms,
            data_dir: target_dir.to_string_lossy().into_owned(),
        })
    }

    /// Initialize an empty data directory when joining an existing cloud account via `mynote device claim`
    /// (`kind = "add"`). Installs the claimed `device_id`, SMKs, and sync credentials without creating a
    /// redundant local `"scratch"` buffer or random recovery bundle.
    pub fn open_for_claim(
        data_dir: impl AsRef<Path>,
        device_id: DeviceId,
        smks_in: &[SmkGenerationBytes],
        sync_url: &str,
        device_token: &str,
        scope: &str,
    ) -> Result<Self, CoreError> {
        if smks_in.is_empty() {
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                "pairing payload contains zero SMK generations",
                "Re-generate the pairing code on the existing desktop",
            ));
        }
        let data_dir = data_dir.as_ref().to_path_buf();
        if data_dir.join("mynote.db").exists() || data_dir.join("smk_keyring.local.json").exists() {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "target data directory '{}' is already initialized; refusing to overwrite existing local data",
                    data_dir.display()
                ),
                "Use an empty --data-dir for claiming a new device, or use 'mynote device refresh' for an existing device",
            ));
        }
        let backups_dir = data_dir.join("backups");
        let mirror_dir = data_dir.join("mirror");
        ensure_private_dir(&data_dir)?;
        ensure_private_dir(&backups_dir)?;
        ensure_private_dir(&mirror_dir)?;
        exclude_from_os_backups(&data_dir);

        let conn = Connection::open(data_dir.join("mynote.db")).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("cannot open SQLite: {e}"),
                "Check directory permissions",
            )
        })?;
        init_connection(&conn, Some(&backups_dir))?;

        let mut map = BTreeMap::new();
        let mut latest_kid = smks_in[0].smk_kid;
        for entry in smks_in {
            map.insert(entry.smk_kid, Zeroizing::new(entry.key));
            if entry.smk_kid > latest_kid {
                latest_kid = entry.smk_kid;
            }
        }

        conn.execute(
            "INSERT OR REPLACE INTO local_meta (key, value) VALUES ('device_id', ?1)",
            [device_id.as_str()],
        )
        .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "save device_id"))?;
        conn.execute(
            "INSERT OR REPLACE INTO local_meta (key, value) VALUES ('bootstrap_completed', '0')",
            [],
        )
        .ok();
        conn.execute(
            "INSERT OR REPLACE INTO local_meta (key, value) VALUES ('last_seq', '0')",
            [],
        )
        .ok();
        conn.execute(
            "INSERT OR REPLACE INTO local_meta (key, value) VALUES ('sync_url', ?1)",
            [sync_url],
        )
        .ok();
        conn.execute(
            "INSERT OR REPLACE INTO local_meta (key, value) VALUES ('device_scope', ?1)",
            [scope],
        )
        .ok();

        Self::save_local_smks(&data_dir.join("smk_keyring.local.json"), latest_kid, &map)?;
        save_device_credentials(
            &data_dir,
            &DeviceCredentials {
                sync_url: sync_url.to_string(),
                device_token: device_token.to_string(),
                scope: scope.to_string(),
            },
        )?;
        drop(conn);
        Self::open(&data_dir)
    }

    /// Initialize an empty data directory when recovering an existing cloud account via
    /// `mynote device bootstrap --revoke-existing` (Disaster Recovery Path #1, `docs/sync-protocol.md` §5.3).
    /// Installs the registered `device_id`, remote `keyring` (`gen`, `blob`), sync credentials, and an
    /// empty local SMK store (awaiting `mynote keyring unlock` with the user's 24-word recovery bundle),
    /// WITHOUT generating a conflicting gen=1 keyring or dummy `"scratch"` buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn open_for_recovery_bootstrap(
        data_dir: impl AsRef<Path>,
        device_id: DeviceId,
        sync_url: &str,
        device_token: &str,
        scope: &str,
        keyring_gen: u32,
        keyring_blob: &[u8],
    ) -> Result<Self, CoreError> {
        let data_dir = data_dir.as_ref().to_path_buf();
        if data_dir.join("mynote.db").exists() || data_dir.join("smk_keyring.local.json").exists() {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "target data directory '{}' is already initialized; refusing recovery bootstrap overwrite",
                    data_dir.display()
                ),
                "Use an empty --data-dir for disaster recovery bootstrap",
            ));
        }
        let backups_dir = data_dir.join("backups");
        let mirror_dir = data_dir.join("mirror");
        ensure_private_dir(&data_dir)?;
        ensure_private_dir(&backups_dir)?;
        ensure_private_dir(&mirror_dir)?;
        exclude_from_os_backups(&data_dir);

        let conn = Connection::open(data_dir.join("mynote.db")).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("cannot open SQLite: {e}"),
                "Check directory permissions",
            )
        })?;
        init_connection(&conn, Some(&backups_dir))?;

        let now = now_ms() as i64;
        conn.execute(
            "INSERT OR REPLACE INTO local_meta (key, value) VALUES ('device_id', ?1)",
            [device_id.as_str()],
        )
        .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "save device_id"))?;
        conn.execute(
            "INSERT OR REPLACE INTO local_meta (key, value) VALUES ('bootstrap_completed', '0')",
            [],
        )
        .ok();
        conn.execute(
            "INSERT OR REPLACE INTO local_meta (key, value) VALUES ('last_seq', '0')",
            [],
        )
        .ok();
        conn.execute(
            "INSERT OR REPLACE INTO local_meta (key, value) VALUES ('sync_url', ?1)",
            [sync_url],
        )
        .ok();
        conn.execute(
            "INSERT OR REPLACE INTO local_meta (key, value) VALUES ('device_scope', ?1)",
            [scope],
        )
        .ok();
        conn.execute(
            "INSERT OR REPLACE INTO key_material (kind, gen, blob, updated_at_ms) VALUES ('keyring', ?1, ?2, ?3)",
            params![keyring_gen as i64, keyring_blob, now],
        )
        .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "save remote keyring"))?;

        let empty_smks: SmkMap = BTreeMap::new();
        Self::save_local_smks(
            &data_dir.join("smk_keyring.local.json"),
            SmkKid::from_ulid(Ulid::ZERO),
            &empty_smks,
        )?;
        save_device_credentials(
            &data_dir,
            &DeviceCredentials {
                sync_url: sync_url.to_string(),
                device_token: device_token.to_string(),
                scope: scope.to_string(),
            },
        )?;
        drop(conn);
        Self::open(&data_dir)
    }

    pub fn get_local_meta(&self, key: &str) -> Option<String> {
        self.conn
            .query_row("SELECT value FROM local_meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()
            .unwrap_or(None)
    }

    pub fn set_local_meta(&self, key: &str, value: &str) -> Result<(), CoreError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO local_meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "set local_meta"))?;
        Ok(())
    }

    pub fn load_credentials(&self) -> Result<Option<DeviceCredentials>, CoreError> {
        load_device_credentials(&self.data_dir)
    }

    pub fn save_credentials(&self, creds: &DeviceCredentials) -> Result<(), CoreError> {
        save_device_credentials(&self.data_dir, creds)?;
        self.set_local_meta("sync_url", &creds.sync_url)?;
        self.set_local_meta("device_scope", &creds.scope)?;
        Ok(())
    }

    pub fn current_smks_for_pairing(&self) -> Vec<SmkGenerationBytes> {
        self.smks
            .iter()
            .map(|(kid, k)| SmkGenerationBytes {
                smk_kid: *kid,
                key: **k,
            })
            .collect()
    }

    /// Install refreshed SMK generations received via `mynote device claim` (`kind = "refresh"`).
    /// Permanently retains all prior generations and resets `last_seq` to 0 so any ops previously
    /// skipped under the newer SMK are re-pulled idempotently.
    pub fn install_refreshed_smks(&mut self, smks_in: &[SmkGenerationBytes]) -> Result<usize, CoreError> {
        let mut added = 0usize;
        for entry in smks_in {
            if !self.smks.contains_key(&entry.smk_kid) {
                added += 1;
            }
            self.smks.insert(entry.smk_kid, Zeroizing::new(entry.key));
            if entry.smk_kid > self.current_smk_kid {
                self.current_smk_kid = entry.smk_kid;
            }
        }
        Self::save_local_smks(
            &self.data_dir.join("smk_keyring.local.json"),
            self.current_smk_kid,
            &self.smks,
        )?;
        self.backfill_unknown_block_keys()?;
        self.set_local_meta("last_seq", "0")?;
        self.rematerialize_all()?;
        Ok(added)
    }

    pub fn last_hlc_string(&self) -> Option<String> {
        self.conn
            .query_row("SELECT MAX(hlc) FROM sync_ops", [], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
    }

    /// Full `BlockDetailDto` list for a buffer (used by `GET /v1/local/blocks?buffer_id=...`).
    pub fn list_blocks_detailed(&self, buffer_selector: &str) -> Result<Vec<BlockDetailDto>, CoreError> {
        let buf_id = self.resolve_buffer_id(buffer_selector)?;
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id FROM blocks WHERE state = 'ACTIVE' AND buffer_id = ?1
                 ORDER BY position COLLATE BINARY ASC, id ASC",
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query buffer blocks"))?;
        let ids: Vec<String> = stmt
            .query_map([buf_id.to_string()], |r| r.get(0))
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map block ids"))?
            .filter_map(Result::ok)
            .collect();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(self.get_block(&id)?);
        }
        Ok(out)
    }

    /// Resolve a multi-leaf block by keeping the exact plaintext of `keep_op_id`.
    pub fn resolve_block_keep(
        &mut self,
        block_id_str: &str,
        expected_heads: &[String],
        keep_op_id: &str,
        actor: &str,
    ) -> Result<WriteReceipt, CoreError> {
        let detail = self.get_block(block_id_str)?;
        self.check_bootstrap_gate(EntityType::Block, &detail.id, OpType::Resolve)?;
        if detail.is_locked {
            return Err(CoreError::new(
                ErrorCode::BlockLocked,
                format!(
                    "block '{block_id_str}' is locked; resolve locked blocks in UI after unlocking Vault"
                ),
                "Unlock Vault in the desktop UI before resolving locked conflicts",
            ));
        }
        let chosen = detail
            .versions
            .iter()
            .find(|v| v.op_id == keep_op_id)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::NotFound,
                    format!("leaf op '{keep_op_id}' not found on block '{block_id_str}'"),
                    "Inspect current leaves via 'mynote block get <id> --json'",
                )
            })?;
        let content = chosen.content.as_deref().ok_or_else(|| {
            CoreError::new(
                ErrorCode::KeyMissing,
                format!(
                    "leaf op '{keep_op_id}' on block '{block_id_str}' is unreadable; refusing empty overwrite"
                ),
                "Sync missing keys or choose a readable version to keep",
            )
        })?;
        // Verify expected_heads against current heads before resolving (force=true allows resolving
        // a conflict where another sibling leaf is KEY_UNAVAILABLE while the user explicitly keeps a readable leaf).
        let expected_set: BTreeSet<String> = expected_heads.iter().cloned().collect();
        let actual_set: BTreeSet<String> = detail.head_op_ids.iter().cloned().collect();
        if expected_set != actual_set {
            return Err(CoreError::new(
                ErrorCode::HeadMismatch,
                format!("block {block_id_str} heads changed concurrently"),
                format!("Run 'mynote block get {block_id_str} --json' and retry with latest heads"),
            )
            .with_details(serde_json::json!({
                "expected_heads": expected_heads,
                "actual_heads": detail.head_op_ids,
            })));
        }
        self.update_block(block_id_str, content, expected_heads, true, actor)
    }

    pub fn key_table_state(&self) -> Result<KeyTableState, CoreError> {
        self.load_key_table()
    }

    /// Export complete Sans-I/O `EngineSnapshot` for driving `mynote_core::sync::step()`.
    pub fn export_engine_snapshot(&self) -> Result<EngineSnapshot, CoreError> {
        let mut snap = EngineSnapshot::new(self.device_id.clone(), now_ms());
        snap.bootstrap_completed = self.get_local_meta("bootstrap_completed").as_deref() == Some("1");
        snap.journal_epoch = self
            .get_local_meta("journal_epoch")
            .and_then(|s| JournalEpoch::parse(&s).ok());
        snap.reconciling_epoch = self
            .get_local_meta("reconciling_epoch")
            .and_then(|s| JournalEpoch::parse(&s).ok());
        snap.last_seq = self
            .get_local_meta("last_seq")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        if let Some(h) = self.last_hlc_string().and_then(|s| Hlc::parse(&s).ok()) {
            snap.hlc = h;
        }
        snap.keys = self.load_key_table()?;
        snap.pending_shred_marks = self.load_shred_marks(false)?;
        snap.pending_cancel_key_ids = self.load_pending_cancel_keys();
        snap.smks = self.smks.clone();

        let mut stmt = self
            .conn
            .prepare(
                "SELECT op_id, server_seq, sync_blocked_reason, device_id, entity_type, entity_id,
                        parent_op_ids, op_type, hlc, actor, key_id, smk_kid, envelope, created_at_ms
                 FROM sync_ops ORDER BY created_at_ms ASC, op_id ASC",
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "export sync_ops"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, Option<String>>(10)?,
                    r.get::<_, String>(11)?,
                    r.get::<_, Vec<u8>>(12)?,
                    r.get::<_, i64>(13)?,
                ))
            })
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map sync_ops"))?;

        for row in rows {
            let (
                op_id_s,
                server_seq,
                sync_blocked_reason,
                dev_s,
                et_s,
                entity_id,
                parents_s,
                ot_s,
                hlc_s,
                actor,
                key_s,
                smk_s,
                envelope,
                created_at_ms,
            ) = row.map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "read sync_op"))?;
            let op_id = OpId::parse(&op_id_s)?;
            let device_id = DeviceId::parse(dev_s)?;
            let entity_type = match et_s.as_str() {
                "buffer" => EntityType::Buffer,
                _ => EntityType::Block,
            };
            let op_type = match ot_s.as_str() {
                "CREATE" => OpType::Create,
                "UPDATE" => OpType::Update,
                "SET_META" => OpType::SetMeta,
                "LOCK" => OpType::Lock,
                "UNLOCK" => OpType::Unlock,
                "RESOLVE" => OpType::Resolve,
                "DELETE" => OpType::Delete,
                _ => OpType::Update,
            };
            let parent_op_ids: Vec<OpId> = serde_json::from_str(&parents_s).unwrap_or_default();
            let hlc = Hlc::parse(&hlc_s)?;
            let key_id = key_s.as_deref().map(KeyId::parse).transpose()?;
            let smk_kid = SmkKid::parse(&smk_s)?;
            snap.ops.insert(
                op_id,
                LocalOpRecord {
                    op_id,
                    server_seq,
                    sync_blocked_reason,
                    device_id,
                    entity_type,
                    entity_id,
                    parent_op_ids,
                    op_type,
                    hlc,
                    actor,
                    key_id,
                    smk_kid,
                    envelope,
                    created_at_ms,
                },
            );
        }
        Ok(snap)
    }

    /// Re-materialize every buffer (first, for FK safety) and every block from `sync_ops` + `block_keys`.
    pub fn rematerialize_all(&self) -> Result<(), CoreError> {
        let mut buf_ids: Vec<BufferId> = Vec::new();
        let mut blk_ids: Vec<BlockId> = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT DISTINCT entity_type, entity_id FROM sync_ops")
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "scan entities"))?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map entities"))?;
            for r in rows.flatten() {
                if r.0 == "buffer" {
                    if let Ok(id) = BufferId::parse(&r.1) {
                        buf_ids.push(id);
                    }
                } else if let Ok(id) = BlockId::parse(&r.1) {
                    blk_ids.push(id);
                }
            }
        }
        for id in buf_ids {
            let _ = self.rematerialize_buffer(id);
        }
        for id in blk_ids {
            let _ = self.rematerialize_block(id);
        }
        self.refresh_mirror()?;
        Ok(())
    }

    /// Re-materialize ONLY entities that are currently missing from projection tables or have
    /// `KEY_UNAVAILABLE` / `DECRYPT_FAILED` leaves (e.g. after hot-reloading newly unlocked SMKs).
    /// Returns `(buffers_updated, updated_block_ids)` and avoids rewriting unchanged blocks/mirrors.
    pub fn rematerialize_unavailable(&self) -> Result<(bool, Vec<String>), CoreError> {
        let mut buf_ids: Vec<BufferId> = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT DISTINCT entity_id FROM sync_ops
                     WHERE entity_type = 'buffer'
                       AND entity_id NOT IN (SELECT id FROM buffers)",
                )
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "scan missing buffers")
                })?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(|e| {
                CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map missing buffers")
            })?;
            for r in rows.flatten() {
                if let Ok(id) = BufferId::parse(&r) {
                    buf_ids.push(id);
                }
            }
        }
        let mut blk_ids: BTreeSet<BlockId> = BTreeSet::new();
        {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT DISTINCT entity_id FROM sync_ops
                     WHERE entity_type = 'block'
                       AND entity_id NOT IN (SELECT id FROM blocks)
                     UNION
                     SELECT DISTINCT block_id FROM block_leaves
                     WHERE body_state IN ('KEY_UNAVAILABLE', 'DECRYPT_FAILED')",
                )
                .map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        e.to_string(),
                        "scan unavailable blocks",
                    )
                })?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(|e| {
                CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map unavailable blocks")
            })?;
            for r in rows.flatten() {
                if let Ok(id) = BlockId::parse(&r) {
                    blk_ids.insert(id);
                }
            }
        }
        if buf_ids.is_empty() && blk_ids.is_empty() {
            return Ok((false, Vec::new()));
        }
        let mut buffers_updated = false;
        for id in buf_ids {
            if self.rematerialize_buffer(id).is_ok() {
                buffers_updated = true;
            }
        }
        let mut updated_blocks = Vec::new();
        for id in blk_ids {
            if self.rematerialize_block(id).is_ok() {
                updated_blocks.push(id.to_string());
            }
        }
        if buffers_updated || !updated_blocks.is_empty() {
            self.refresh_mirror()?;
        }
        Ok((buffers_updated, updated_blocks))
    }

    /// Apply Sans-I/O `StoreMutation`s atomically to SQLite and re-materialize affected entities.
    pub fn apply_store_mutations(
        &mut self,
        mutations: &[StoreMutation],
    ) -> Result<SyncApplySummary, CoreError> {
        let mut touched_buffers: BTreeSet<BufferId> = BTreeSet::new();
        let mut touched_blocks: BTreeSet<BlockId> = BTreeSet::new();
        let mut changed_keys: BTreeSet<KeyId> = BTreeSet::new();
        let mut marks_changed = false;
        let mut shred_keys_to_execute: BTreeMap<KeyId, Option<(u32, i64)>> = BTreeMap::new();
        let mut summary = SyncApplySummary::default();

        self.conn
            .execute_batch("BEGIN IMMEDIATE;")
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "begin apply_mutations"))?;

        let mut need_mirror_refresh = false;
        let tx_body: Result<(), CoreError> = (|| {
            for m in mutations {
                match m {
                    StoreMutation::AppendOp(op) => {
                        let et = match op.entity_type {
                            EntityType::Buffer => "buffer",
                            EntityType::Block => "block",
                        };
                        let ot = match op.op_type {
                            OpType::Create => "CREATE",
                            OpType::Update => "UPDATE",
                            OpType::SetMeta => "SET_META",
                            OpType::Lock => "LOCK",
                            OpType::Unlock => "UNLOCK",
                            OpType::Resolve => "RESOLVE",
                            OpType::Delete => "DELETE",
                        };
                        let parents_json =
                            serde_json::to_string(&op.parent_op_ids).unwrap_or_else(|_| "[]".into());
                        self.conn
                            .execute(
                                "INSERT INTO sync_ops
                                 (op_id, server_seq, sync_blocked_reason, device_id, entity_type, entity_id,
                                  parent_op_ids, op_type, hlc, actor, key_id, smk_kid, envelope, created_at_ms)
                                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                                 ON CONFLICT(op_id) DO UPDATE SET
                                   server_seq = COALESCE(excluded.server_seq, sync_ops.server_seq)",
                                params![
                                    op.op_id.to_string(),
                                    op.server_seq,
                                    op.sync_blocked_reason,
                                    op.device_id.as_str(),
                                    et,
                                    op.entity_id,
                                    parents_json,
                                    ot,
                                    op.hlc.canonical_string(),
                                    op.actor,
                                    op.key_id.map(|k| k.to_string()),
                                    op.smk_kid.to_string(),
                                    op.envelope,
                                    op.created_at_ms,
                                ],
                            )
                            .map_err(|e| {
                                CoreError::new(ErrorCode::IntegrityError, e.to_string(), "append sync_op")
                            })?;
                        match op.entity_type {
                            EntityType::Buffer => {
                                if let Ok(id) = BufferId::parse(&op.entity_id) {
                                    touched_buffers.insert(id);
                                }
                            }
                            EntityType::Block => {
                                if let Ok(id) = BlockId::parse(&op.entity_id) {
                                    touched_blocks.insert(id);
                                }
                            }
                        }
                        let _ = self.hlc_clock.receive(now_ms(), &op.hlc);
                    }
                    StoreMutation::MarkOpsSynced { epoch, acked } => {
                        self.set_local_meta("journal_epoch", &epoch.to_string())?;
                        for a in acked {
                            self.conn
                                .execute(
                                    "UPDATE sync_ops SET server_seq = ?1, sync_blocked_reason = NULL WHERE op_id = ?2",
                                    params![a.seq, a.op_id.to_string()],
                                )
                                .map_err(|e| {
                                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "mark op synced")
                                })?;
                        }
                        self.conn
                            .execute(
                                "UPDATE block_keys SET server_acked = 1
                                 WHERE key_id IN (
                                     SELECT key_id FROM sync_ops
                                     WHERE server_seq IS NOT NULL AND key_id IS NOT NULL
                                 )",
                                [],
                            )
                            .ok();
                    }
                    StoreMutation::MarkOpBlocked { op_id, reason } => {
                        self.conn
                            .execute(
                                "UPDATE sync_ops SET sync_blocked_reason = ?1 WHERE op_id = ?2",
                                params![reason, op_id.to_string()],
                            )
                            .map_err(|e| {
                                CoreError::new(ErrorCode::IntegrityError, e.to_string(), "mark op blocked")
                            })?;
                        if reason == "NEEDS_VAULT_REKEY" {
                            // H8: Back up wrapped mnw1 BEFORE any subsequent shred wipes block_keys.key_record!
                            if let Ok(Some(kid_s)) = self.conn.query_row(
                                "SELECT key_id FROM sync_ops WHERE op_id = ?1",
                                [op_id.to_string()],
                                |r| r.get::<_, Option<String>>(0),
                            ) {
                                if let Ok(kid) = KeyId::parse(&kid_s) {
                                    if let Ok((2, mnw1)) = self.unwrap_bdek(kid) {
                                        use base64::Engine as _;
                                        let slot_key = format!("blocked_t2_mnw1:{op_id}");
                                        self.set_local_meta(
                                            &slot_key,
                                            &base64::engine::general_purpose::STANDARD.encode(mnw1),
                                        )?;
                                    }
                                }
                            }
                            summary.needs_vault_rekey.push(op_id.to_string());
                        }
                    }
                    StoreMutation::MarkShredMarksAcked {
                        results,
                        cancelled_keys,
                    } => {
                        self.apply_shred_results_acked(results, cancelled_keys)?;
                        summary.trash_changed = true;
                        for r in results {
                            if r.state == ShredMarkState::PendingConfirm {
                                summary.pending_confirm_count += 1;
                            }
                            // C3 Path C: execute local physical shred when push-ack reports Executed!
                            if r.state == ShredMarkState::Executed {
                                shred_keys_to_execute.entry(r.key_id).or_insert(None);
                            }
                        }
                    }
                    StoreMutation::ClearServerSeqsForReconcile { new_epoch } => {
                        // NEVER delete sync_ops or blocks — only clear server_seq for Set-Union reconciliation!
                        self.conn
                            .execute("UPDATE sync_ops SET server_seq = NULL", [])
                            .map_err(|e| {
                                CoreError::new(ErrorCode::IntegrityError, e.to_string(), "clear server_seq")
                            })?;
                        // Re-queue non-Executed shred marks & cancellations across DO PITR / epoch change
                        let mut cancel_set = self.load_pending_cancel_keys();
                        {
                            let mut cstmt = self
                                .conn
                                .prepare(
                                    "SELECT DISTINCT sm.key_id FROM shred_marks sm
                                     JOIN block_keys bk ON bk.key_id = sm.key_id
                                     WHERE sm.server_acked = 1 AND sm.state = 'cancelled' AND bk.key_record IS NOT NULL",
                                )
                                .map_err(|e| {
                                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "read cancelled marks")
                                })?;
                            let crows = cstmt.query_map([], |r| r.get::<_, String>(0)).map_err(|e| {
                                CoreError::new(
                                    ErrorCode::IntegrityError,
                                    e.to_string(),
                                    "map cancelled marks",
                                )
                            })?;
                            for s in crows.flatten() {
                                if let Ok(kid) = KeyId::parse(&s) {
                                    cancel_set.insert(kid);
                                }
                            }
                        }
                        self.save_pending_cancel_keys(&cancel_set)?;
                        self.conn
                            .execute(
                                "DELETE FROM shred_marks WHERE server_acked = 1 AND state = 'cancelled'",
                                [],
                            )
                            .map_err(|e| {
                                CoreError::new(
                                    ErrorCode::IntegrityError,
                                    e.to_string(),
                                    "clear cancelled marks",
                                )
                            })?;
                        self.conn
                            .execute(
                                "UPDATE shred_marks
                                 SET server_acked = 0, state = 'pending_confirm', not_before_ms = NULL, confirmed_at_ms = NULL
                                 WHERE server_acked = 1 AND state IN ('pending_confirm', 'scheduled')
                                   AND key_id IN (SELECT key_id FROM block_keys WHERE key_record IS NOT NULL)",
                                [],
                            )
                            .map_err(|e| {
                                CoreError::new(ErrorCode::IntegrityError, e.to_string(), "requeue shred marks")
                            })?;
                        marks_changed = true;
                        self.set_local_meta("reconciling_epoch", &new_epoch.to_string())?;
                        self.set_local_meta("last_seq", "0")?;
                    }
                    StoreMutation::UpsertBlockKey(rec) => {
                        if rec.key_record.is_none() {
                            // C2 FIX: If this shredded key has NEVER been seen locally, insert a NULL
                            // tombstone row in `block_keys` immediately so subsequent `UpsertShredMark`
                            // satisfies `FOREIGN KEY(key_id) REFERENCES block_keys(key_id)`!
                            // If a non-NULL row already exists, keep it intact until AFTER rematerialize,
                            // outbox reconciliation, and INV-KEY-LIVENESS check.
                            self.conn
                                .execute(
                                    "INSERT OR IGNORE INTO block_keys
                                     (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                                     VALUES (?1, ?2, 1, ?3, NULL, '', ?4, 1)",
                                    params![
                                        rec.key_id.to_string(),
                                        Ulid::ZERO.to_string(),
                                        rec.wrap_gen as i64,
                                        rec.created_at_ms,
                                    ],
                                )
                                .map_err(|e| {
                                    CoreError::new(
                                        ErrorCode::IntegrityError,
                                        e.to_string(),
                                        "insert unseen shredded block_key tombstone",
                                    )
                                })?;
                            shred_keys_to_execute.insert(rec.key_id, Some((rec.wrap_gen, rec.created_at_ms)));
                            continue;
                        }
                        let zero_id = Ulid::ZERO.to_string();
                        let existing: Option<(String, i64, Option<Vec<u8>>)> = self
                            .conn
                            .query_row(
                                "SELECT block_id, wrap_gen, key_record FROM block_keys WHERE key_id = ?1",
                                [rec.key_id.to_string()],
                                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                            )
                            .optional()
                            .unwrap_or(None);
                        let should_write = match existing {
                            None => true,
                            Some((_, _, None)) => false, // Executed shred is terminal
                            Some((ref bid, g, Some(_))) => (rec.wrap_gen as i64) > g || bid == &zero_id,
                        };
                        if should_write {
                            let (blk_id_s, tier) = if let Some(mnr1) = &rec.key_record {
                                let smk_kid =
                                    peek_envelope_kid(MAGIC_MNR1, mnr1).ok().map(SmkKid::from_bytes);
                                if let Some(sk) =
                                    smk_kid.and_then(|kid| self.smks.get(&kid).map(|k| (kid, k)))
                                {
                                    if let Ok(kr) = decrypt_mnr1(sk.0, sk.1, rec.key_id, rec.wrap_gen, mnr1) {
                                        (kr.block_id.to_string(), kr.tier as i64)
                                    } else {
                                        (zero_id.clone(), 1)
                                    }
                                } else {
                                    (zero_id.clone(), 1)
                                }
                            } else {
                                (zero_id.clone(), 1)
                            };
                            self.conn
                                .execute(
                                    "INSERT INTO block_keys
                                     (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                                     VALUES (?1, ?2, ?3, ?4, ?5, '', ?6, 1)
                                     ON CONFLICT(key_id) DO UPDATE SET
                                       block_id = CASE WHEN excluded.block_id != ?7 THEN excluded.block_id ELSE block_keys.block_id END,
                                       tier = CASE WHEN excluded.block_id != ?7 THEN excluded.tier ELSE block_keys.tier END,
                                       wrap_gen = excluded.wrap_gen,
                                       key_record = excluded.key_record,
                                       server_acked = 1",
                                    params![
                                        rec.key_id.to_string(),
                                        blk_id_s,
                                        tier,
                                        rec.wrap_gen as i64,
                                        rec.key_record,
                                        rec.created_at_ms,
                                        zero_id,
                                    ],
                                )
                                .map_err(|e| {
                                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "upsert block_key")
                                })?;
                            changed_keys.insert(rec.key_id);
                        }
                    }
                    StoreMutation::UpsertShredMark(mark) => {
                        // C2 defense-in-depth: ensure parent block_keys row exists before shred_marks FK insert
                        self.conn
                            .execute(
                                "INSERT OR IGNORE INTO block_keys
                                 (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                                 VALUES (?1, ?2, 1, 1, NULL, '', ?3, 1)",
                                params![
                                    mark.key_id.to_string(),
                                    Ulid::ZERO.to_string(),
                                    mark.requested_at_ms,
                                ],
                            )
                            .map_err(|e| {
                                CoreError::new(
                                    ErrorCode::IntegrityError,
                                    e.to_string(),
                                    "ensure parent block_key for shred_mark",
                                )
                            })?;
                        self.upsert_shred_mark_row(mark, true)?;
                        marks_changed = true;
                        summary.trash_changed = true;
                        if mark.state == ShredMarkState::PendingConfirm {
                            summary.pending_confirm_count += 1;
                        }
                        if mark.state == ShredMarkState::Executed {
                            shred_keys_to_execute.entry(mark.key_id).or_insert(None);
                        }
                    }
                    StoreMutation::ExecuteShred { key_id } => {
                        shred_keys_to_execute.entry(*key_id).or_insert(None);
                    }
                    StoreMutation::UpsertKeyMaterial {
                        kind,
                        gen,
                        blob,
                        updated_at_ms,
                    } => {
                        // Validate remote key_material blob & monotonic SMK retention before persisting!
                        match kind {
                            KeyMaterialKind::Keyring => {
                                let new_kr: RecoveryKeyringV1 = rmp_serde::from_slice(blob).map_err(|e| {
                                    CoreError::new(
                                        ErrorCode::IntegrityError,
                                        format!("invalid remote RecoveryKeyringV1 payload: {e}"),
                                        "Refusing to persist malformed remote keyring",
                                    )
                                })?;
                                if let Ok(existing_kr) = self.current_keyring() {
                                    if new_kr.recovery_pk != existing_kr.recovery_pk {
                                        return Err(CoreError::new(
                                            ErrorCode::IntegrityError,
                                            "remote keyring recovery_pk mismatch",
                                            "Recovery public key cannot change silently across keyring generations",
                                        ));
                                    }
                                    for old_ent in &existing_kr.smk_entries {
                                        if !new_kr.smk_entries.iter().any(|e| e == old_ent) {
                                            return Err(CoreError::new(
                                                ErrorCode::IntegrityError,
                                                format!(
                                                    "remote keyring gen {} truncated existing SMK generation",
                                                    new_kr.keyring_gen
                                                ),
                                                "Old SMK generations must be preserved permanently",
                                            ));
                                        }
                                    }
                                }
                            }
                            KeyMaterialKind::VaultHeader => {
                                let vh: mynote_core::crypto::VaultHeaderV1 = rmp_serde::from_slice(blob)
                                    .map_err(|e| {
                                        CoreError::new(
                                            ErrorCode::IntegrityError,
                                            format!("invalid remote VaultHeaderV1 payload: {e}"),
                                            "Refusing to persist malformed remote vault header",
                                        )
                                    })?;
                                if vh.v != 1 {
                                    return Err(CoreError::new(
                                        ErrorCode::IntegrityError,
                                        format!("unsupported remote VaultHeaderV1 version {}", vh.v),
                                        "Upgrade mynote to handle newer vault header format",
                                    ));
                                }
                            }
                            KeyMaterialKind::ClipKey => {
                                let _ = mynote_core::clip::decode_clip_key_material(blob)?;
                            }
                        }
                        let kind_s = match kind {
                            KeyMaterialKind::Keyring => "keyring",
                            KeyMaterialKind::VaultHeader => "vault_header",
                            KeyMaterialKind::ClipKey => "clip_key",
                        };
                        let cur_gen: Option<i64> = self
                            .conn
                            .query_row("SELECT gen FROM key_material WHERE kind = ?1", [kind_s], |r| {
                                r.get(0)
                            })
                            .optional()
                            .unwrap_or(None);
                        if cur_gen.is_none_or(|g| *gen > g) {
                            self.conn
                                .execute(
                                    "INSERT OR REPLACE INTO key_material (kind, gen, blob, updated_at_ms)
                                     VALUES (?1, ?2, ?3, ?4)",
                                    params![kind_s, gen, blob, updated_at_ms],
                                )
                                .map_err(|e| {
                                    CoreError::new(
                                        ErrorCode::IntegrityError,
                                        e.to_string(),
                                        "upsert key_material",
                                    )
                                })?;
                            if *kind == KeyMaterialKind::VaultHeader {
                                summary.vault_header_changed = true;
                            }
                        }
                    }
                    StoreMutation::SetSyncMeta {
                        bootstrap_completed,
                        journal_epoch,
                        last_seq,
                        reconciling_epoch,
                        hlc,
                    } => {
                        self.set_local_meta(
                            "bootstrap_completed",
                            if *bootstrap_completed { "1" } else { "0" },
                        )?;
                        if let Some(ep) = journal_epoch {
                            self.set_local_meta("journal_epoch", &ep.to_string())?;
                        }
                        self.set_local_meta("last_seq", &last_seq.to_string())?;
                        if let Some(rec_ep) = reconciling_epoch {
                            self.set_local_meta("reconciling_epoch", &rec_ep.to_string())?;
                        } else {
                            self.conn
                                .execute("DELETE FROM local_meta WHERE key = 'reconciling_epoch'", [])
                                .ok();
                        }
                        let _ = self.hlc_clock.receive(now_ms(), hlc);
                    }
                    StoreMutation::IntegrityAlert { op_id, reason } => {
                        summary.integrity_alerts.push((op_id.to_string(), reason.clone()));
                    }
                    StoreMutation::ClockSkewAlert(w) => {
                        self.set_local_meta("clock_skew_ms", &w.skew_ms.to_string())?;
                        summary.clock_skew_ms = Some(w.skew_ms);
                    }
                }
            }

            // Helper: collect all buffers & blocks referencing any key in `keys` so we only
            // rematerialize affected entities (`O(touched)` instead of `O(blocks * keys)`).
            let collect_entities_for_keys =
                |conn: &Connection,
                 keys: &BTreeSet<KeyId>,
                 bufs: &mut BTreeSet<BufferId>,
                 blks: &mut BTreeSet<BlockId>| {
                    for kid in keys {
                        let ks = kid.to_string();
                        if let Ok(mut stmt) = conn
                            .prepare("SELECT DISTINCT entity_type, entity_id FROM sync_ops WHERE key_id = ?1")
                        {
                            if let Ok(rows) = stmt
                                .query_map([&ks], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                            {
                                for (et, eid) in rows.flatten() {
                                    if et == "buffer" {
                                        if let Ok(id) = BufferId::parse(&eid) {
                                            bufs.insert(id);
                                        }
                                    } else if let Ok(id) = BlockId::parse(&eid) {
                                        blks.insert(id);
                                    }
                                }
                            }
                        }
                        if let Ok(mut stmt) =
                            conn.prepare("SELECT DISTINCT block_id FROM block_leaves WHERE key_id = ?1")
                        {
                            if let Ok(rows) = stmt.query_map([&ks], |r| r.get::<_, String>(0)) {
                                for bid in rows.flatten() {
                                    if let Ok(id) = BlockId::parse(&bid) {
                                        blks.insert(id);
                                    }
                                }
                            }
                        }
                        if let Ok(mut stmt) =
                            conn.prepare("SELECT DISTINCT id FROM buffers WHERE key_id = ?1")
                        {
                            if let Ok(rows) = stmt.query_map([&ks], |r| r.get::<_, String>(0)) {
                                for bid in rows.flatten() {
                                    if let Ok(id) = BufferId::parse(&bid) {
                                        bufs.insert(id);
                                    }
                                }
                            }
                        }
                        if let Ok(mut stmt) =
                            conn.prepare("SELECT DISTINCT block_id FROM block_keys WHERE key_id = ?1")
                        {
                            if let Ok(rows) = stmt.query_map([&ks], |r| r.get::<_, String>(0)) {
                                for eid in rows.flatten() {
                                    if let Ok(id) = BlockId::parse(&eid) {
                                        blks.insert(id);
                                    }
                                    if let Ok(id) = BufferId::parse(&eid) {
                                        bufs.insert(id);
                                    }
                                }
                            }
                        }
                    }
                };

            let mut upserted_bufs: BTreeSet<String> = BTreeSet::new();
            let mut deleted_bufs: BTreeSet<String> = BTreeSet::new();
            let mut upserted_blks: BTreeSet<String> = BTreeSet::new();
            let mut deleted_blks: BTreeSet<String> = BTreeSet::new();

            // Step A & B: Rematerialize touched ops + newly synced keys FIRST so `block_leaves` and
            // `blocks.state` reflect newly pulled DELETE/LOCK/UPDATE before outbox reconciliation,
            // unacked-mark pruning (C7), and physical shred execution (C3 Path A)!
            if !changed_keys.is_empty() {
                collect_entities_for_keys(
                    &self.conn,
                    &changed_keys,
                    &mut touched_buffers,
                    &mut touched_blocks,
                );
            }
            if !touched_buffers.is_empty() || !touched_blocks.is_empty() {
                let kt = self.load_key_table()?;
                let had_buffers = !touched_buffers.is_empty();
                for buf_id in &touched_buffers {
                    if let Ok(m) = self.rematerialize_buffer_with_kt(*buf_id, &kt) {
                        if m.state == BlockState::Active {
                            upserted_bufs.insert(buf_id.to_string());
                            deleted_bufs.remove(&buf_id.to_string());
                        } else {
                            deleted_bufs.insert(buf_id.to_string());
                            upserted_bufs.remove(&buf_id.to_string());
                        }
                    }
                }
                if had_buffers {
                    if let Ok(mut stmt) = self.conn.prepare(
                        "SELECT DISTINCT entity_id FROM sync_ops
                         WHERE entity_type = 'block' AND entity_id NOT IN (SELECT id FROM blocks)",
                    ) {
                        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
                            for id_s in rows.flatten() {
                                if let Ok(bid) = BlockId::parse(&id_s) {
                                    touched_blocks.insert(bid);
                                }
                            }
                        }
                    }
                }
                for blk_id in &touched_blocks {
                    if let Ok(m) = self.rematerialize_block_with_kt(*blk_id, &kt) {
                        if m.state == BlockState::Active {
                            upserted_blks.insert(blk_id.to_string());
                            deleted_blks.remove(&blk_id.to_string());
                        } else {
                            deleted_blks.insert(blk_id.to_string());
                            upserted_blks.remove(&blk_id.to_string());
                            summary.trash_changed = true;
                        }
                    }
                }
            }

            // Step C (C7): Prune any local unacked (`server_acked = 0`) shred marks targeting keys
            // now live on ACTIVE blocks/buffers (e.g. offline DELETE revived by remote Update-Wins)!
            let cancelled_unacked = self.cancel_active_unacked_shred_marks_in_tx()?;
            if cancelled_unacked > 0 {
                summary.trash_changed = true;
            }

            // Step D: Reconcile local outbox against newly received shred marks & imminent shreds BEFORE
            // nullifying key_record so offline Tier 1 edits rekey & Tier 2 edits save mnw1!
            if marks_changed || !shred_keys_to_execute.is_empty() {
                let imminent: BTreeSet<KeyId> = shred_keys_to_execute.keys().copied().collect();
                let (rekey_ops, rekeyed_t1) = self.reconcile_outbox_with_imminent_shreds(&imminent)?;
                if !rekey_ops.is_empty() {
                    summary.needs_vault_rekey.extend(rekey_ops);
                }
                summary.rekeyed_tier1_ops += rekeyed_t1;
            }

            // Step E (C3): Execute server-confirmed key shreds with INV-KEY-LIVENESS guard, AND sweep
            // any previously deferred `shred_marks.state = 'executed'` rows whose key is now eligible!
            let mut shredded_now: BTreeSet<KeyId> = BTreeSet::new();
            for (kid, meta) in shred_keys_to_execute {
                if self.execute_shred_in_tx(kid, meta)? {
                    shredded_now.insert(kid);
                }
            }
            for kid in self.sweep_unexecuted_shreds_in_tx()? {
                shredded_now.insert(kid);
            }
            if !shredded_now.is_empty() {
                summary.trash_changed = true;
                for kid in &shredded_now {
                    summary.executed_shreds.push(kid.to_string());
                }
                // Step F: Rematerialize entities referencing freshly shredded keys (O(affected))
                let mut post_bufs = BTreeSet::new();
                let mut post_blks = BTreeSet::new();
                collect_entities_for_keys(&self.conn, &shredded_now, &mut post_bufs, &mut post_blks);
                let kt = self.load_key_table()?;
                for buf_id in post_bufs {
                    if let Ok(m) = self.rematerialize_buffer_with_kt(buf_id, &kt) {
                        if m.state == BlockState::Active {
                            upserted_bufs.insert(buf_id.to_string());
                            deleted_bufs.remove(&buf_id.to_string());
                        } else {
                            deleted_bufs.insert(buf_id.to_string());
                            upserted_bufs.remove(&buf_id.to_string());
                        }
                    }
                }
                for blk_id in post_blks {
                    if let Ok(m) = self.rematerialize_block_with_kt(blk_id, &kt) {
                        if m.state == BlockState::Active {
                            upserted_blks.insert(blk_id.to_string());
                            deleted_blks.remove(&blk_id.to_string());
                        } else {
                            deleted_blks.insert(blk_id.to_string());
                            upserted_blks.remove(&blk_id.to_string());
                        }
                    }
                }
            }

            summary.upserted_buffer_ids = upserted_bufs.into_iter().collect();
            summary.deleted_buffer_ids = deleted_bufs.into_iter().collect();
            summary.upserted_block_ids = upserted_blks.into_iter().collect();
            summary.deleted_block_ids = deleted_blks.into_iter().collect();
            need_mirror_refresh = !summary.upserted_block_ids.is_empty()
                || !summary.deleted_block_ids.is_empty()
                || !summary.upserted_buffer_ids.is_empty()
                || !summary.deleted_buffer_ids.is_empty()
                || !summary.executed_shreds.is_empty();
            Ok(())
        })();

        match tx_body {
            Ok(()) => {
                self.conn.execute_batch("COMMIT;").map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "commit apply_mutations")
                })?;
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK;");
                return Err(e);
            }
        }

        if !summary.executed_shreds.is_empty() {
            // SEC-01 / INV-SHRED-BOUND: scrub FTS5 segments, VACUUM under secure_delete=ON, truncate WAL, refresh mirror!
            self.full_forensic_shred_scrub()?;
        } else if need_mirror_refresh {
            self.refresh_mirror()?;
        }
        Ok(summary)
    }

    /// Re-encrypt a raw remote MNS1 check helper (ensures `MAGIC_MNS1` import stays used cleanly).
    pub fn peek_op_smk_kid(envelope: &[u8]) -> Result<SmkKid, CoreError> {
        Ok(SmkKid::from_bytes(peek_envelope_kid(MAGIC_MNS1, envelope)?))
    }
}

#[derive(Clone, Debug, Default)]
pub struct SyncApplySummary {
    pub upserted_block_ids: Vec<String>,
    pub deleted_block_ids: Vec<String>,
    pub upserted_buffer_ids: Vec<String>,
    pub deleted_buffer_ids: Vec<String>,
    pub trash_changed: bool,
    pub clock_skew_ms: Option<i64>,
    pub integrity_alerts: Vec<(String, String)>,
    pub executed_shreds: Vec<String>,
    pub needs_vault_rekey: Vec<String>,
    pub pending_confirm_count: usize,
    pub vault_header_changed: bool,
    pub rekeyed_tier1_ops: usize,
}

fn collect_mna1_files(dir: &Path, out: &mut Vec<(String, Vec<u8>)>) -> Result<(), CoreError> {
    for entry in std::fs::read_dir(dir)
        .map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("read archive dir: {e}"),
                "Check path",
            )
        })?
        .flatten()
    {
        let p = entry.path();
        if p.is_dir() {
            collect_mna1_files(&p, out)?;
        } else if p.extension().is_some_and(|e| e == "mna1") {
            let bytes = std::fs::read(&p).map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("read '{}': {e}", p.display()),
                    "Check archive file",
                )
            })?;
            out.push((p.to_string_lossy().into_owned(), bytes));
        }
    }
    Ok(())
}

/// Lightweight heuristic language sniffer when `--lang` is omitted (`mynote add`).
pub fn sniff_language(content: &str) -> String {
    let t = content.trim();
    if ((t.starts_with('{') && t.ends_with('}')) || (t.starts_with('[') && t.ends_with(']')))
        && serde_json::from_str::<serde_json::Value>(t).is_ok()
    {
        return "json".to_string();
    }
    let upper = t.to_ascii_uppercase();
    if upper.starts_with("SELECT ") || upper.starts_with("INSERT ") || upper.starts_with("CREATE TABLE") {
        return "sql".to_string();
    }
    if t.starts_with("# ") || t.starts_with("## ") || t.contains("\n```") {
        return "markdown".to_string();
    }
    "text".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mynote_core::crypto::{
        encode_mna1, encode_mnks, ArchiveOpsHeaderV1, ArchivedOpRow, KeySnapshotBodyV1, KeySnapshotHeaderV1,
    };
    use mynote_core::ids::JournalEpoch;

    fn temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("mynote_store_test_{}_{}", tag, now_ms()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn crud_idempotency_optimistic_lock_trash_mirror_fts_and_backup_work_end_to_end() {
        let dir = temp_dir("crud");
        let mut store = LocalStore::open(&dir).unwrap();
        let words = store
            .initial_recovery_words
            .clone()
            .expect("24 words on first init");
        assert_eq!(words.split_whitespace().count(), 24);

        // 1. Add block with idempotency key + replay check
        let r1 = store
            .add_block(
                "scratch",
                "{\"hello\":\"world\"}",
                None,
                None,
                "agent:test",
                Some("idem-1"),
            )
            .unwrap();
        assert_eq!(r1.idempotent_replay, None);
        let r1_replay = store
            .add_block(
                "scratch",
                "{\"hello\":\"world\"}",
                None,
                None,
                "agent:test",
                Some("idem-1"),
            )
            .unwrap();
        assert_eq!(r1_replay.block_id, r1.block_id);
        assert_eq!(r1_replay.op_id, r1.op_id);
        assert_eq!(r1_replay.idempotent_replay, Some(true));

        // 2. Verify FTS search and default read-only Markdown mirror
        let hits = store.search_blocks("hello", None, 20).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].lang, "json");
        let mirror_md = std::fs::read_to_string(dir.join("mirror/scratch.md")).unwrap();
        assert!(mirror_md.contains("\"hello\":\"world\""));

        // 3. Optimistic lock mismatch -> HEAD_MISMATCH with zero side effects
        let bad = store.update_block(
            &r1.block_id,
            "overwritten",
            &["01J00000000000000000000000".into()],
            false,
            "human",
        );
        assert_eq!(bad.unwrap_err().code(), ErrorCode::HeadMismatch);

        // 4. Valid update + delete to trash -> removed from FTS5 & mirror -> restore brings it back!
        let r2 = store
            .update_block(
                &r1.block_id,
                "updated secret canary",
                &r1.head_op_ids,
                false,
                "human",
            )
            .unwrap();
        let del = store
            .delete_block(&r1.block_id, Some(&r2.head_op_ids), "human")
            .unwrap();
        assert!(del.in_trash);
        assert_eq!(del.shred_state, "pending_sync");
        assert!(store.search_blocks("canary", None, 20).unwrap().is_empty());
        let mirror_after_del = std::fs::read_to_string(dir.join("mirror/scratch.md")).unwrap();
        assert!(!mirror_after_del.contains("canary"));
        assert_eq!(
            store.get_block(&r1.block_id).unwrap_err().code(),
            ErrorCode::InTrash
        );
        assert_eq!(store.list_trash().unwrap().len(), 1);

        let restored = store.restore_trash(&r1.block_id, "human").unwrap();
        assert_eq!(restored.block_id, r1.block_id);
        assert_eq!(
            store.get_block(&r1.block_id).unwrap().content.as_deref(),
            Some("updated secret canary")
        );
        assert_eq!(store.search_blocks("canary", None, 20).unwrap().len(), 1);

        // 5. Rotate SMK + verify recovery drill passes with original 24 words!
        let (new_gen, _) = store.rotate_smk().unwrap();
        assert_eq!(new_gen, 2);
        let drill = store.recovery_drill(&words).unwrap();
        assert!(drill.ok);
        assert_eq!(drill.keyring_generations, 2);

        // 6. VACUUM INTO backup produces valid openable SQLite snapshot
        let bak = store.create_auto_backup("2026-11-24").unwrap();
        let bak_conn = Connection::open(&bak).unwrap();
        let cnt: i64 = bak_conn
            .query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cnt, 1);

        // 7. Key liveness self-check passes
        let (ok, missing) = store.key_self_check().unwrap();
        assert!(ok && missing.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn locked_block_has_zero_plaintext_in_fts_and_mirror_and_multi_leaf_merge_works() {
        let dir = temp_dir("locked_and_conflict");
        let mut store = LocalStore::open(&dir).unwrap();
        let r1 = store
            .add_block("scratch", "v1 base", Some("text"), None, "human", None)
            .unwrap();
        let blk_id = BlockId::parse(&r1.block_id).unwrap();
        let p1 = OpId::parse(&r1.op_id).unwrap();

        // Inject concurrent remote Tier 1 leaf -> creates 2 leaves!
        let key_id = store.find_active_block_key(blk_id).unwrap();
        let (_, bdek_vec) = store.unwrap_bdek(key_id).unwrap();
        let mut bdek = [0u8; 32];
        bdek.copy_from_slice(&bdek_vec);
        let remote_dev = DeviceId::parse("dev_remote0001").unwrap();
        let op_remote = OpId::from_ulid(store.ulid_gen.next(now_ms() + 10, rand_bytes::<10>().unwrap()));
        let mnb1_r = encrypt_mnb1(
            blk_id.as_bytes(),
            op_remote,
            key_id,
            &bdek,
            "v2 from omarchy",
            rand_bytes::<24>().unwrap(),
        )
        .unwrap();
        let r2 = store
            .update_block(&r1.block_id, "v2 from mac", &r1.head_op_ids, false, "human")
            .unwrap();
        store
            .apply_remote_block_op_for_sync(RemoteBlockOpParams {
                remote_device: remote_dev.clone(),
                block_id: blk_id,
                op_id: op_remote,
                parents: vec![p1],
                op_type: OpType::Update,
                hlc: Hlc::new(now_ms() + 5000, 0, remote_dev.clone()),
                tier: 1,
                key_id,
                new_key_record: None,
                mnb1: mnb1_r,
                public_hint: None,
            })
            .unwrap();
        // Simulate an already-bootstrapped desktop receiving a concurrent peer edit.
        store.set_local_meta("bootstrap_completed", "1").unwrap();

        let detail = store.get_block(&r1.block_id).unwrap();
        assert!(detail.has_conflict);
        assert_eq!(detail.versions.len(), 2);
        // Append rejects multi-leaf block with CONFLICT_PRESENT
        assert_eq!(
            store
                .append_block(&r1.block_id, "more", None, "human")
                .unwrap_err()
                .code(),
            ErrorCode::ConflictPresent
        );

        // Merge both leaves with expected_heads = all leaves -> converges to 1 leaf!
        let merged = store
            .update_block(&r1.block_id, "merged v2", &detail.head_op_ids, false, "human")
            .unwrap();
        assert_eq!(merged.head_op_ids.len(), 1);
        assert!(!store.get_block(&r1.block_id).unwrap().has_conflict);
        let _ = r2;

        // Inject a Tier 2 locked leaf -> FTS5 and mirror must contain ZERO plaintext!
        let locked_blk = store
            .add_block(
                "scratch",
                "SENSITIVE_CANARY_999",
                Some("text"),
                None,
                "human",
                None,
            )
            .unwrap();
        let l_bid = BlockId::parse(&locked_blk.block_id).unwrap();
        let l_p1 = OpId::parse(&locked_blk.op_id).unwrap();
        let l_op = OpId::from_ulid(store.ulid_gen.next(now_ms() + 100, rand_bytes::<10>().unwrap()));
        let l_key = KeyId::from_ulid(store.ulid_gen.next(now_ms() + 100, rand_bytes::<10>().unwrap()));
        let l_krec = KeyRecordV1 {
            v: 1,
            key_id: l_key,
            block_id: l_bid.0,
            tier: 2,
            created_hlc: Hlc::new(now_ms() + 100, 0, remote_dev.clone()).canonical_string(),
            created_by: remote_dev.clone(),
            bdek: vec![0xAA; 93],
        };
        let smk = store.current_smk().unwrap().clone();
        let l_mnr1 = encrypt_mnr1(
            store.current_smk_kid,
            &smk,
            1,
            &l_krec,
            rand_bytes::<24>().unwrap(),
        )
        .unwrap();
        store
            .apply_remote_block_op_for_sync(RemoteBlockOpParams {
                remote_device: remote_dev.clone(),
                block_id: l_bid,
                op_id: l_op,
                parents: vec![l_p1],
                op_type: OpType::Lock,
                hlc: Hlc::new(now_ms() + 9000, 0, remote_dev),
                tier: 2,
                key_id: l_key,
                new_key_record: Some((1, l_mnr1)),
                mnb1: vec![0xBB; 64],
                public_hint: Some("prod token".into()),
            })
            .unwrap();

        let locked_detail = store.get_block(&locked_blk.block_id).unwrap();
        assert!(locked_detail.is_locked);
        assert!(locked_detail.content.is_none());
        assert!(store
            .search_blocks("SENSITIVE_CANARY_999", None, 20)
            .unwrap()
            .is_empty());
        let mirror_md = std::fs::read_to_string(dir.join("mirror/scratch.md")).unwrap();
        assert!(!mirror_md.contains("SENSITIVE_CANARY_999"));
        assert!(mirror_md.contains(&format!("<!-- LOCKED BLOCK: {}", locked_blk.block_id)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offline_restore_from_archive_directory_rebuilds_database_and_refuses_non_empty_dir() {
        let src_dir = temp_dir("restore_src");
        let arch_dir = temp_dir("restore_arch");
        let dst_dir = temp_dir("restore_dst");

        let mut src = LocalStore::open(&src_dir).unwrap();
        let words = src.initial_recovery_words.clone().unwrap();
        let b1 = src
            .add_block(
                "scratch",
                "archived content #1",
                Some("markdown"),
                None,
                "human",
                None,
            )
            .unwrap();
        src.rotate_smk().unwrap();
        let b2 = src
            .add_block(
                "scratch",
                "archived content #2 after rotation",
                Some("json"),
                None,
                "human",
                None,
            )
            .unwrap();

        // Export MNA1 + latest.mnks to arch_dir simulating R2 download
        std::fs::create_dir_all(arch_dir.join("ops")).unwrap();
        std::fs::create_dir_all(arch_dir.join("keys")).unwrap();
        let mut rows = Vec::new();
        {
            let mut stmt = src
                .conn
                .prepare("SELECT op_id, key_id, device_id, created_at_ms, envelope FROM sync_ops ORDER BY rowid ASC")
                .unwrap();
            for (idx, r) in stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                    ))
                })
                .unwrap()
                .enumerate()
            {
                let (op_s, kid_s, dev_s, ts, env) = r.unwrap();
                rows.push(ArchivedOpRow {
                    seq: (idx + 1) as i64,
                    op_id: OpId::parse(&op_s).unwrap(),
                    key_id: kid_s.as_deref().map(KeyId::parse).transpose().unwrap(),
                    device_id: DeviceId::parse(dev_s).unwrap(),
                    created_at: ts,
                    envelope: env,
                });
            }
        }
        let epoch = JournalEpoch::from_random_bytes([7u8; 16]);
        let mna1 = encode_mna1(
            &ArchiveOpsHeaderV1 {
                journal_epoch: epoch,
                from_seq: 1,
                to_seq: rows.len() as i64,
                row_count: rows.len() as u32,
                created_at_ms: now_ms() as i64,
            },
            &rows,
        )
        .unwrap();
        std::fs::write(arch_dir.join("ops/000000000001-000000000004.mna1"), mna1).unwrap();

        let kr = src.current_keyring().unwrap();
        let kt = src.load_key_table().unwrap();
        let records: Vec<KeyRecordRow> = kt.records.values().cloned().collect();
        let mnks = encode_mnks(
            &KeySnapshotHeaderV1 {
                created_at_ms: now_ms() as i64,
                keyring_gen: kr.keyring_gen,
                record_count: records.len() as u32,
            },
            &KeySnapshotBodyV1 {
                keyring: kr,
                vault_header: None,
                records,
                marks: vec![],
            },
        )
        .unwrap();
        std::fs::write(arch_dir.join("keys/latest.mnks"), mnks).unwrap();

        // Pure offline restore into empty dst_dir
        let summary = LocalStore::restore_from_archive_dir(&arch_dir, &words, &dst_dir, false).unwrap();
        assert_eq!(summary.restored_blocks, 2);
        assert_eq!(summary.archive_segments, 1);

        let restored = LocalStore::open(&dst_dir).unwrap();
        assert_eq!(
            restored.get_block(&b1.block_id).unwrap().content.as_deref(),
            Some("archived content #1")
        );
        assert_eq!(
            restored.get_block(&b2.block_id).unwrap().content.as_deref(),
            Some("archived content #2 after rotation")
        );

        // Non-empty target dir MUST be refused!
        let err = LocalStore::restore_from_archive_dir(&arch_dir, &words, &dst_dir, false).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&arch_dir);
        let _ = std::fs::remove_dir_all(&dst_dir);
    }

    #[test]
    fn regression_rotate_smk_is_atomic_and_rolls_back_on_missing_old_smk() {
        let dir = temp_dir("atomic_rotate_rollback");
        let mut store = LocalStore::open(&dir).unwrap();
        let b1 = store
            .add_block("scratch", "important note", Some("text"), None, "human", None)
            .unwrap();
        let orig_smk_kid = store.current_smk_kid;
        let orig_kr_gen = store.current_keyring().unwrap().keyring_gen;

        // Insert a second active block_key wrapped under an unknown SMK to force rotate_smk failure mid-scan
        let bogus_smk_kid = SmkKid::from_ulid(store.ulid_gen.next(now_ms() + 10, [0x44; 10]));
        let bogus_smk = [0x77u8; 32];
        let bogus_key_id = KeyId::from_ulid(store.ulid_gen.next(now_ms() + 11, [0x55; 10]));
        let bogus_krec = KeyRecordV1 {
            v: 1,
            key_id: bogus_key_id,
            block_id: Ulid::ZERO,
            tier: 1,
            created_hlc: store.hlc_clock.tick(now_ms()).canonical_string(),
            created_by: store.device_id.clone(),
            bdek: vec![0x22; 32],
        };
        let bogus_mnr1 = encrypt_mnr1(bogus_smk_kid, &bogus_smk, 1, &bogus_krec, [0x33; 24]).unwrap();
        store
            .conn
            .execute(
                "INSERT INTO block_keys (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                 VALUES (?1, ?2, 1, 1, ?3, '', 1, 1)",
                params![bogus_key_id.to_string(), Ulid::ZERO.to_string(), bogus_mnr1],
            )
            .unwrap();

        let err = store
            .rotate_smk()
            .expect_err("rotate must fail on missing old SMK");
        assert_eq!(err.code(), ErrorCode::KeyMissing);
        // Existing keys, keyring_gen, and smk_keyring.local.json MUST remain completely untouched!
        assert_eq!(store.current_smk_kid, orig_smk_kid);
        assert_eq!(store.current_keyring().unwrap().keyring_gen, orig_kr_gen);
        let blk_key = store
            .find_active_block_key(BlockId::parse(&b1.block_id).unwrap())
            .unwrap();
        let wrap_gen: i64 = store
            .conn
            .query_row(
                "SELECT wrap_gen FROM block_keys WHERE key_id = ?1",
                [blk_key.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(wrap_gen, 1, "existing key wrap_gen must not be partially mutated");
        assert_eq!(
            store.get_block(&b1.block_id).unwrap().content.as_deref(),
            Some("important note")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn regression_key_self_check_is_strictly_read_only() {
        let dir = temp_dir("readonly_key_self_check");
        let mut store = LocalStore::open(&dir).unwrap();
        store
            .add_block("scratch", "hello readonly", Some("text"), None, "human", None)
            .unwrap();

        // Enforce SQLite query_only=ON: ANY write inside key_self_check() would fail with SQLITE_READONLY!
        store.conn.execute_batch("PRAGMA query_only = ON;").unwrap();
        let (ok, missing) = store
            .key_self_check()
            .expect("key_self_check must perform zero DB writes");
        assert!(ok);
        assert!(missing.is_empty());
        store.conn.execute_batch("PRAGMA query_only = OFF;").unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn regression_bootstrap_gate_unreadable_guard_non_empty_dirs_and_tier1_bdek_checks() {
        let dir = temp_dir("bootstrap_and_guards");
        let mut store = LocalStore::open(&dir).unwrap();
        let local_blk = store
            .add_block("scratch", "local offline note", Some("text"), None, "human", None)
            .unwrap();

        // 1. open_for_claim and open_for_recovery_bootstrap MUST refuse already-initialized directory
        let fake_smk = SmkGenerationBytes {
            smk_kid: store.current_smk_kid,
            key: [1u8; 32],
        };
        assert_eq!(
            LocalStore::open_for_claim(
                &dir,
                DeviceId::from_random_bytes([2u8; 10]),
                &[fake_smk],
                "https://relay.test",
                "tok",
                "read-write"
            )
            .err()
            .unwrap()
            .code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            LocalStore::open_for_recovery_bootstrap(
                &dir,
                DeviceId::from_random_bytes([3u8; 10]),
                "https://relay.test",
                "tok",
                "read-write",
                1,
                b"kr"
            )
            .err()
            .unwrap()
            .code(),
            ErrorCode::InvalidArgument
        );

        // 2. Bootstrap Gate: while bootstrap_completed == 0, local-only block is editable,
        //    but a remote-synced entity (server_seq IS NOT NULL) is strictly blocked!
        store
            .update_block(
                &local_blk.block_id,
                "local edit ok",
                &local_blk.head_op_ids,
                false,
                "human",
            )
            .expect("pure local entity remains editable before bootstrap");

        store
            .conn
            .execute(
                "UPDATE sync_ops SET server_seq = 1 WHERE entity_id = ?1",
                [&local_blk.block_id],
            )
            .unwrap();
        let detail_after = store.get_block(&local_blk.block_id).unwrap();
        assert_eq!(
            store
                .update_block(
                    &local_blk.block_id,
                    "blocked",
                    &detail_after.head_op_ids,
                    false,
                    "human"
                )
                .unwrap_err()
                .code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            store
                .delete_block(&local_blk.block_id, None, "human")
                .unwrap_err()
                .code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            store
                .move_block(&local_blk.block_id, None, None, None, Some("json"), "human")
                .unwrap_err()
                .code(),
            ErrorCode::InvalidArgument
        );

        // Once bootstrap_completed = 1, mutations succeed again
        store.set_local_meta("bootstrap_completed", "1").unwrap();
        let u2 = store
            .update_block(
                &local_blk.block_id,
                "now bootstrapped",
                &detail_after.head_op_ids,
                false,
                "human",
            )
            .unwrap();

        // 3. Unreadable KEY_UNAVAILABLE block refuses append_block, update_block, and resolve_block_keep (zero "" overwrite!)
        let blk_id = BlockId::parse(&local_blk.block_id).unwrap();
        let key_id = store.find_active_block_key(blk_id).unwrap();
        // Temporarily replace key_record with a record wrapped under an unknown SMK so rematerialize produces KEY_UNAVAILABLE
        let missing_smk = SmkKid::from_ulid(store.ulid_gen.next(now_ms() + 20, [0x99; 10]));
        let missing_mnr1 = encrypt_mnr1(
            missing_smk,
            &[0x88; 32],
            2,
            &KeyRecordV1 {
                v: 1,
                key_id,
                block_id: blk_id.0,
                tier: 1,
                created_hlc: store.hlc_clock.tick(now_ms()).canonical_string(),
                created_by: store.device_id.clone(),
                bdek: vec![0x11; 32],
            },
            [0x44; 24],
        )
        .unwrap();
        store
            .conn
            .execute(
                "UPDATE block_keys SET wrap_gen = 2, key_record = ?1 WHERE key_id = ?2",
                params![missing_mnr1, key_id.to_string()],
            )
            .unwrap();
        store.rematerialize_block(blk_id).unwrap();
        let unreadable = store.get_block(&local_blk.block_id).unwrap();
        assert!(!unreadable.is_locked);
        assert!(unreadable.content.is_none());

        assert_eq!(
            store
                .append_block(&local_blk.block_id, "extra", None, "human")
                .unwrap_err()
                .code(),
            ErrorCode::KeyMissing
        );
        assert_eq!(
            store
                .update_block(&local_blk.block_id, "overwrite", &u2.head_op_ids, false, "human")
                .unwrap_err()
                .code(),
            ErrorCode::KeyMissing
        );
        assert_eq!(
            store
                .resolve_block_keep(&local_blk.block_id, &u2.head_op_ids, &u2.op_id, "human")
                .unwrap_err()
                .code(),
            ErrorCode::KeyMissing
        );

        // 4. unwrap_tier1_bdek rejects Tier 2 key with BlockLocked and malformed BDEK with IntegrityError (no panic!)
        let smk = store.current_smk().unwrap().clone();
        let bad_t2_key = KeyId::from_ulid(store.ulid_gen.next(now_ms() + 30, [0xA1; 10]));
        let bad_t2_mnr1 = encrypt_mnr1(
            store.current_smk_kid,
            &smk,
            1,
            &KeyRecordV1 {
                v: 1,
                key_id: bad_t2_key,
                block_id: blk_id.0,
                tier: 2,
                created_hlc: store.hlc_clock.tick(now_ms()).canonical_string(),
                created_by: store.device_id.clone(),
                bdek: vec![0xAA; 93],
            },
            [0x55; 24],
        )
        .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO block_keys (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                 VALUES (?1, ?2, 2, 1, ?3, '', 1, 1)",
                params![bad_t2_key.to_string(), blk_id.to_string(), bad_t2_mnr1],
            )
            .unwrap();
        assert_eq!(
            store.unwrap_tier1_bdek(bad_t2_key).unwrap_err().code(),
            ErrorCode::BlockLocked
        );

        let bad_len_key = KeyId::from_ulid(store.ulid_gen.next(now_ms() + 31, [0xA2; 10]));
        let bad_len_mnr1 = encrypt_mnr1(
            store.current_smk_kid,
            &smk,
            1,
            &KeyRecordV1 {
                v: 1,
                key_id: bad_len_key,
                block_id: blk_id.0,
                tier: 1,
                created_hlc: store.hlc_clock.tick(now_ms()).canonical_string(),
                created_by: store.device_id.clone(),
                bdek: vec![0xBB; 16], // Invalid length (not 32B)
            },
            [0x56; 24],
        )
        .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO block_keys (key_id, block_id, tier, wrap_gen, key_record, created_hlc, created_at_ms, server_acked)
                 VALUES (?1, ?2, 1, 1, ?3, '', 1, 1)",
                params![bad_len_key.to_string(), blk_id.to_string(), bad_len_mnr1],
            )
            .unwrap();
        assert_eq!(
            store.unwrap_tier1_bdek(bad_len_key).unwrap_err().code(),
            ErrorCode::IntegrityError
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn regression_out_of_order_block_op_materializes_when_buffer_arrives_later() {
        let dir_src = temp_dir("ooo_src");
        let dir_dst = temp_dir("ooo_dst");
        let mut src = LocalStore::open(&dir_src).unwrap();
        let buf = src.create_buffer("work", None, "human").unwrap();
        let blk = src
            .add_block("work", "arrived before buffer", Some("text"), None, "human", None)
            .unwrap();

        let snap = src.export_engine_snapshot().unwrap();
        let buf_op = snap
            .ops
            .values()
            .find(|o| o.entity_type == EntityType::Buffer && o.entity_id == buf.id)
            .unwrap()
            .clone();
        let blk_op = snap
            .ops
            .values()
            .find(|o| o.entity_type == EntityType::Block && o.entity_id == blk.block_id)
            .unwrap()
            .clone();
        let buf_krec = snap.keys.records.get(&buf_op.key_id.unwrap()).unwrap().clone();
        let blk_krec = snap.keys.records.get(&blk_op.key_id.unwrap()).unwrap().clone();

        // Destination joins with same SMKs
        let mut dst = LocalStore::open_for_claim(
            &dir_dst,
            DeviceId::from_random_bytes([0xC1; 10]),
            &src.current_smks_for_pairing(),
            "https://relay.test",
            "tok",
            "read-write",
        )
        .unwrap();

        // First install keys
        dst.apply_store_mutations(&[
            StoreMutation::UpsertBlockKey(buf_krec),
            StoreMutation::UpsertBlockKey(blk_krec),
        ])
        .unwrap();
        // Page 1: block op arrives BEFORE its parent buffer op!
        dst.apply_store_mutations(&[StoreMutation::AppendOp(blk_op)])
            .unwrap();
        assert!(dst.get_block(&blk.block_id).is_err());

        // Page 2: parent buffer op arrives -> out-of-order block MUST auto-materialize!
        dst.apply_store_mutations(&[StoreMutation::AppendOp(buf_op)])
            .unwrap();
        assert_eq!(
            dst.get_block(&blk.block_id).unwrap().content.as_deref(),
            Some("arrived before buffer")
        );

        let _ = std::fs::remove_dir_all(&dir_src);
        let _ = std::fs::remove_dir_all(&dir_dst);
    }

    #[test]
    fn sec_01_and_inv_shred_bound_zero_plaintext_in_db_wal_fts_mirror_and_backup() {
        let dir = temp_dir("sec01_shred");
        let mut store = LocalStore::open(&dir).unwrap();
        let canary = "CANARY_SECRET_TOKEN_987654321_XYZ_FORENSIC";
        let blk = store
            .add_block("scratch", canary, Some("text"), None, "human", None)
            .unwrap();
        assert_eq!(store.search_blocks("CANARY_SECRET", None, 10).unwrap().len(), 1);
        let mirror_before = std::fs::read_to_string(dir.join("mirror/scratch.md")).unwrap();
        assert!(mirror_before.contains(canary));

        // 1. Delete block -> enters trash & queues local pending shred mark; mirror & FTS immediately scrubbed
        let del = store.delete_block(&blk.block_id, None, "human").unwrap();
        assert!(del.in_trash);
        assert_eq!(del.shred_state, "pending_sync");
        assert!(store.search_blocks("CANARY_SECRET", None, 10).unwrap().is_empty());

        let snap = store.export_engine_snapshot().unwrap();
        assert_eq!(snap.pending_shred_marks.len(), 1);
        let key_id = snap.pending_shred_marks[0].key_id;

        // 2. Simulate server executing shred after grace period expires
        let mut executed_mark = snap.pending_shred_marks[0].clone();
        executed_mark.state = ShredMarkState::Executed;
        executed_mark.executed_at_ms = Some(now_ms() as i64);
        let summary = store
            .apply_store_mutations(&[
                StoreMutation::UpsertShredMark(executed_mark),
                StoreMutation::ExecuteShred { key_id },
            ])
            .unwrap();
        assert_eq!(summary.executed_shreds, vec![key_id.to_string()]);
        assert_eq!(
            store.get_block(&blk.block_id).unwrap_err().code(),
            ErrorCode::KeyShredded
        );
        assert!(store.list_trash().unwrap().is_empty());

        // 3. Create fresh backup AFTER shred & drop store so WAL/SHM flush cleanly
        let post_shred_backup = store.create_auto_backup("post-shred").unwrap();
        drop(store);

        // 4. Forensic raw-byte scan across mynote.db, .db-wal, .db-shm, mirror, and post-shred backup!
        let needle = canary.as_bytes();
        let mut scan_paths = vec![
            dir.join("mynote.db"),
            dir.join("mynote.db-wal"),
            dir.join("mynote.db-shm"),
            dir.join("mirror/scratch.md"),
            post_shred_backup,
        ];
        for path in scan_paths.drain(..) {
            if path.exists() {
                let bytes = std::fs::read(&path).unwrap();
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle),
                    "SEC-01 / INV-SHRED-BOUND VIOLATION: canary found in {}",
                    path.display()
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vault_tier2_roundtrip_rekey_blocked_op_and_recovery_drill_includes_vkek() {
        use mynote_core::ids::VkekKid;
        use mynote_core::vault::{create_vault_header, unlock_vault_with_passphrase};

        let dir = temp_dir("vault_t2_store");
        let mut store = LocalStore::open(&dir).unwrap();
        let words = store
            .initial_recovery_words
            .clone()
            .expect("24 words on first init");
        let rpk = store.recovery_pk().unwrap();

        // 1. Create VaultHeaderV1 + persist in key_material
        let vkek_kid = VkekKid::from_ulid(Ulid::from_parts(1_700_000_000_000, [0x10; 10]));
        let hdr = create_vault_header(
            b"correct-horse-battery",
            &rpk,
            vkek_kid,
            &[0x22; 32],
            [0x11; 16],
            [0x33; 24],
            [0x44; 32],
            [0x55; 24],
            1_700_000_000_000,
        )
        .unwrap();
        let hdr_bytes = rmp_serde::to_vec_named(&hdr).unwrap();
        store.put_vault_header(1, &hdr_bytes).unwrap();
        let fetched_hdr = store.get_vault_header().unwrap().unwrap();
        assert_eq!(fetched_hdr.gen, 1);

        // 2. Recovery drill MUST verify BOTH SMK keyring AND Vault VKEK!
        let drill = store.recovery_drill(&words).unwrap();
        assert!(drill.ok);
        assert!(drill.includes_vkek);

        // 3. Encrypt Tier 2 block in-memory (simulating WasmVaultSession) -> Daemon/Store NEVER sees plaintext or VKEK
        let unlocked = unlock_vault_with_passphrase(b"correct-horse-battery", &hdr).unwrap();
        let secret_body = "VAULT_SECRET_NEVER_ON_DISK_4242";
        let blk_id = BlockId::from_ulid(Ulid::from_parts(1_700_000_001_000, [0xA1; 10]));
        let op_id = OpId::from_ulid(Ulid::from_parts(1_700_000_001_001, [0xA2; 10]));
        let key_id = KeyId::from_ulid(Ulid::from_parts(1_700_000_001_002, [0xA3; 10]));
        let bdek = Zeroizing::new([0x77; 32]);
        let mnb1 = encrypt_mnb1(blk_id.as_bytes(), op_id, key_id, &bdek, secret_body, [0x88; 24]).unwrap();
        let mnw1 = unlocked.wrap_bdek(key_id, blk_id, &bdek, [0x99; 24]).unwrap();

        let receipt = store
            .add_tier2_block(
                &blk_id.to_string(),
                Tier2OpInput {
                    op_id: &op_id.to_string(),
                    key_id: &key_id.to_string(),
                    mnb1: &mnb1,
                    mnw1: Some(&mnw1),
                },
                "scratch",
                "text",
                None,
                Some("prod api key"),
                "human",
            )
            .unwrap();
        assert_eq!(receipt.op_id, op_id.to_string()); // F-01: Daemon reused exact caller op_id!

        // Daemon view returns ciphertext only, zero plaintext!
        let daemon_blk = store.get_block_for_daemon(&blk_id.to_string()).unwrap();
        assert!(daemon_blk.is_locked);
        assert!(daemon_blk.content.is_none());
        assert_eq!(daemon_blk.public_hint.as_deref(), Some("prod api key"));
        assert!(daemon_blk.versions[0].mnb1_b64.is_some());
        assert!(daemon_blk.versions[0].mnw1_b64.is_some());

        // 4. Simulate remote shred execution while local Tier 2 op is still unpushed -> NEEDS_VAULT_REKEY!
        let exec_mark = mynote_core::model::ShredMarkRow {
            mark_id: mynote_core::ids::MarkId::from_ulid(Ulid::from_parts(1_700_000_002_000, [0xB1; 10])),
            key_id,
            seen_seq: 1,
            requested_by: DeviceId::from_random_bytes([0xCC; 10]),
            requested_at_ms: 1_700_000_002_000,
            grace_ms: mynote_core::vault::T_GRACE_DEFAULT_MS,
            not_before_ms: Some(1_700_000_002_000),
            state: ShredMarkState::Executed,
            confirmed_at_ms: None,
            cancelled_by: None,
            executed_at_ms: Some(1_700_000_002_000),
        };
        let sum = store
            .apply_store_mutations(&[
                StoreMutation::UpsertShredMark(exec_mark),
                StoreMutation::ExecuteShred { key_id },
            ])
            .unwrap();
        assert_eq!(sum.needs_vault_rekey, vec![op_id.to_string()]);
        let blocked = store.list_blocked_tier2_ops().unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].op_id, op_id.to_string());
        assert!(blocked[0].mnw1_b64.is_some()); // Saved mnw1 before shred so UI can rescue it!

        // 5. Rekey blocked Tier 2 op on fresh key -> unblocks and becomes active again!
        let new_op = OpId::from_ulid(Ulid::from_parts(1_700_000_003_000, [0xD1; 10]));
        let new_key = KeyId::from_ulid(Ulid::from_parts(1_700_000_003_001, [0xD2; 10]));
        let new_bdek = Zeroizing::new([0x66; 32]);
        let new_mnb1 = encrypt_mnb1(
            blk_id.as_bytes(),
            new_op,
            new_key,
            &new_bdek,
            secret_body,
            [0x55; 24],
        )
        .unwrap();
        let new_mnw1 = unlocked
            .wrap_bdek(new_key, blk_id, &new_bdek, [0x44; 24])
            .unwrap();
        store
            .rekey_blocked_tier2_op(
                &op_id.to_string(),
                Tier2OpInput {
                    op_id: &new_op.to_string(),
                    key_id: &new_key.to_string(),
                    mnb1: &new_mnb1,
                    mnw1: Some(&new_mnw1),
                },
                "human",
            )
            .unwrap();
        assert!(store.list_blocked_tier2_ops().unwrap().is_empty());

        // 6. Verify ZERO plaintext on disk in SQLite or mirror!
        drop(store);
        let needle = secret_body.as_bytes();
        for rel in ["mynote.db", "mynote.db-wal", "mirror/scratch.md"] {
            let p = dir.join(rel);
            if p.exists() {
                let bytes = std::fs::read(&p).unwrap();
                assert!(!bytes.windows(needle.len()).any(|w| w == needle));
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pr38_store_regressions_c2_c3_c5_c7_c8_h6_h8_h9() {
        use mynote_core::crypto::{
            encode_mna1, encode_mnks, ArchiveOpsHeaderV1, ArchivedOpRow, KeySnapshotBodyV1,
            KeySnapshotHeaderV1,
        };
        use mynote_core::ids::{MarkId, VkekKid};
        use mynote_core::model::{KeyRecordRow, ShredMarkRow};
        use mynote_core::sync::{ShredResultDto, StoreMutation};
        use mynote_core::vault::{create_vault_header, T_GRACE_DEFAULT_MS};

        let dir = temp_dir("pr38_store_regs");
        let mut store = LocalStore::open(&dir).unwrap();
        let words = store.initial_recovery_words.clone().unwrap();
        let rpk = store.recovery_pk().unwrap();

        // --- C2: New device receiving unseen shredded key (key_record: None) + UpsertShredMark must NOT fail FK! ---
        let unseen_kid = KeyId::from_ulid(Ulid::from_parts(1_710_000_000_001, [0xE1; 10]));
        let unseen_mid = MarkId::from_ulid(Ulid::from_parts(1_710_000_000_002, [0xE2; 10]));
        store
            .apply_store_mutations(&[
                StoreMutation::UpsertBlockKey(KeyRecordRow {
                    key_id: unseen_kid,
                    wrap_gen: 1,
                    key_record: None,
                    created_at_ms: 1_710_000_000_000,
                }),
                StoreMutation::UpsertShredMark(ShredMarkRow {
                    mark_id: unseen_mid,
                    key_id: unseen_kid,
                    seen_seq: 1,
                    requested_by: DeviceId::from_random_bytes([0xEE; 10]),
                    requested_at_ms: 1_710_000_000_000,
                    grace_ms: T_GRACE_DEFAULT_MS,
                    not_before_ms: Some(1_710_000_000_000),
                    state: ShredMarkState::Executed,
                    confirmed_at_ms: None,
                    cancelled_by: None,
                    executed_at_ms: Some(1_710_000_000_000),
                }),
            ])
            .expect("C2: unseen shredded key + shred_mark must succeed without FK error");

        // --- C8: collect_trash_action_keys("expedite") MUST ignore ACTIVE blocks and pending_confirm trashed blocks ---
        let active_blk = store
            .add_block("scratch", "still active!", Some("text"), None, "human", None)
            .unwrap();
        let (exp_ids, exp_keys, _) = store
            .collect_trash_action_keys("expedite", Some(std::slice::from_ref(&active_blk.block_id)))
            .unwrap();
        assert!(
            exp_ids.is_empty() && exp_keys.is_empty(),
            "C8: active block must never be expedited"
        );

        // Delete a block and mark its key pending_confirm (server_acked=1) -> expedite MUST exclude it, confirm_pending includes it
        let trash_blk = store
            .add_block("scratch", "pending trash", Some("text"), None, "human", None)
            .unwrap();
        let trash_kid = store
            .collect_entity_unshredded_key_ids(EntityType::Block, &trash_blk.block_id)
            .unwrap()[0];
        let _ = store
            .delete_block(&trash_blk.block_id, Some(&trash_blk.head_op_ids), "human")
            .unwrap();
        store
            .apply_store_mutations(&[StoreMutation::UpsertShredMark(ShredMarkRow {
                mark_id: MarkId::from_ulid(Ulid::from_parts(1_710_000_010_000, [0xA1; 10])),
                key_id: trash_kid,
                seen_seq: 1,
                requested_by: store.device_id().clone(),
                requested_at_ms: 1_710_000_010_000,
                grace_ms: T_GRACE_DEFAULT_MS,
                not_before_ms: None,
                state: ShredMarkState::PendingConfirm,
                confirmed_at_ms: None,
                cancelled_by: None,
                executed_at_ms: None,
            })])
            .unwrap();
        let (_, exp_k2, _) = store
            .collect_trash_action_keys("expedite", Some(std::slice::from_ref(&trash_blk.block_id)))
            .unwrap();
        assert!(
            exp_k2.is_empty(),
            "C8: pending_confirm block must not be expedited"
        );
        let (_, conf_k, _) = store
            .collect_trash_action_keys("confirm_pending", Some(std::slice::from_ref(&trash_blk.block_id)))
            .unwrap();
        assert_eq!(conf_k, vec![trash_kid]);

        // --- C3 Path C: MarkShredMarksAcked(Executed) MUST physically nullify block_keys.key_record on disk! ---
        store
            .apply_store_mutations(&[StoreMutation::MarkShredMarksAcked {
                results: vec![ShredResultDto {
                    key_id: trash_kid,
                    state: ShredMarkState::Executed,
                    not_before_ms: None,
                }],
                cancelled_keys: vec![],
            }])
            .unwrap();
        let raw_krec: Option<Vec<u8>> = store
            .conn
            .query_row(
                "SELECT key_record FROM block_keys WHERE key_id = ?1",
                [trash_kid.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            raw_krec.is_none(),
            "C3 Path C: MarkShredMarksAcked(Executed) must physically wipe key_record"
        );

        // --- C5: purge_block_history MUST reject unreadable blocks (KeyMissing) instead of overwriting with "" ---
        let unread_blk = store
            .add_block("scratch", "about to lose key", Some("text"), None, "human", None)
            .unwrap();
        let unread_kid = store
            .collect_entity_unshredded_key_ids(EntityType::Block, &unread_blk.block_id)
            .unwrap()[0];
        // Remove key row locally to simulate missing/unarrived key on an ACTIVE block (shredded=false)
        store
            .conn
            .execute(
                "DELETE FROM block_keys WHERE key_id = ?1",
                [unread_kid.to_string()],
            )
            .unwrap();
        store
            .rematerialize_block(BlockId::parse(&unread_blk.block_id).unwrap())
            .unwrap();
        // H9: key_self_check MUST now report ok == false with unread_kid!
        let (self_ok, self_missing) = store.key_self_check().unwrap();
        assert!(
            !self_ok && self_missing.contains(&unread_kid),
            "H9: key_self_check must fail on unreadable active block (ok={self_ok}, missing={self_missing:?})"
        );
        let purge_err = store
            .purge_block_history(
                &unread_blk.block_id,
                Some(&unread_blk.head_op_ids),
                None,
                T_GRACE_DEFAULT_MS,
                "human",
            )
            .unwrap_err();
        assert_eq!(
            purge_err.code(),
            ErrorCode::KeyMissing,
            "C5: purge_block_history must refuse unreadable block"
        );

        // --- H9: create_auto_backup updates last_local_backup_ms ---
        let backup_path = store.create_auto_backup("h9-test").unwrap();
        assert!(backup_path.exists());
        assert!(store.sync_status().unwrap().last_local_backup_ms.is_some());

        // --- H8: Multi-op offline retiring chain (Create -> Update) collapses into single rekeyed Create preserving metadata ---
        let chain_blk = store
            .add_block("scratch", "chain v1", Some("json"), None, "human", None)
            .unwrap();
        let chain_upd = store
            .update_block(
                &chain_blk.block_id,
                "chain v2 final",
                &chain_blk.head_op_ids,
                false,
                "human",
            )
            .unwrap();
        let old_chain_kid = store
            .collect_entity_unshredded_key_ids(EntityType::Block, &chain_blk.block_id)
            .unwrap()[0];
        let (_, rekeyed_cnt) = store
            .apply_store_mutations(&[StoreMutation::UpsertShredMark(ShredMarkRow {
                mark_id: MarkId::from_ulid(Ulid::from_parts(1_710_000_020_000, [0xC1; 10])),
                key_id: old_chain_kid,
                seen_seq: 1,
                requested_by: DeviceId::from_random_bytes([0xDD; 10]),
                requested_at_ms: 1_710_000_020_000,
                grace_ms: T_GRACE_DEFAULT_MS,
                not_before_ms: Some(1_710_000_020_000 + T_GRACE_DEFAULT_MS),
                state: ShredMarkState::Scheduled,
                confirmed_at_ms: None,
                cancelled_by: None,
                executed_at_ms: None,
            })])
            .map(|s| (s.needs_vault_rekey, s.rekeyed_tier1_ops))
            .unwrap();
        assert_eq!(
            rekeyed_cnt, 1,
            "H8: multi-op offline chain must collapse into 1 rekeyed Create"
        );
        let after_chain = store.get_block(&chain_blk.block_id).unwrap();
        assert_eq!(after_chain.content.as_deref(), Some("chain v2 final"));
        assert_eq!(after_chain.lang, "json");
        assert_ne!(after_chain.head_op_ids, chain_upd.head_op_ids);

        // --- H6: restore_from_archive_dir restores VaultHeaderV1 and shred_marks ---
        let vkek_kid = VkekKid::from_ulid(Ulid::from_parts(1_710_000_030_000, [0xF1; 10]));
        let vh = create_vault_header(
            b"archive-vault-pass",
            &rpk,
            vkek_kid,
            &[0x33; 32],
            [0x12; 16],
            [0x13; 24],
            [0x14; 32],
            [0x15; 24],
            1_710_000_030_000,
        )
        .unwrap();
        let vh_bytes = rmp_serde::to_vec_named(&vh).unwrap();
        store.put_vault_header(vh.updated_at_ms, &vh_bytes).unwrap();

        let archive_dir = temp_dir("pr38_archive_h6");
        std::fs::create_dir_all(archive_dir.join("ops/ep1")).unwrap();
        std::fs::create_dir_all(archive_dir.join("keys")).unwrap();
        let snap = store.export_engine_snapshot().unwrap();
        let rows: Vec<ArchivedOpRow> = snap
            .ops
            .values()
            .enumerate()
            .map(|(i, o)| ArchivedOpRow {
                seq: (i + 1) as i64,
                op_id: o.op_id,
                key_id: o.key_id,
                device_id: o.device_id.clone(),
                created_at: o.created_at_ms,
                envelope: o.envelope.clone(),
            })
            .collect();
        let mna1 = encode_mna1(
            &ArchiveOpsHeaderV1 {
                journal_epoch: JournalEpoch::from_random_bytes([0xAB; 16]),
                from_seq: 1,
                to_seq: rows.len() as i64,
                row_count: rows.len() as u32,
                created_at_ms: 1_710_000_030_000,
            },
            &rows,
        )
        .unwrap();
        std::fs::write(archive_dir.join("ops/ep1/000000000001-000000000010.mna1"), mna1).unwrap();
        let kr = store.current_keyring().unwrap();
        let recs: Vec<KeyRecordRow> = snap.keys.records.values().cloned().collect();
        let marks: Vec<ShredMarkRow> = snap.keys.marks.values().cloned().collect();
        let mnks = encode_mnks(
            &KeySnapshotHeaderV1 {
                created_at_ms: 1_710_000_030_000,
                keyring_gen: kr.keyring_gen,
                record_count: recs.len() as u32,
            },
            &KeySnapshotBodyV1 {
                keyring: kr,
                vault_header: Some(vh),
                records: recs,
                marks,
            },
        )
        .unwrap();
        std::fs::write(archive_dir.join("keys/latest.mnks"), mnks).unwrap();

        let restore_dir = temp_dir("pr38_restore_h6");
        let _summary =
            LocalStore::restore_from_archive_dir(&archive_dir, &words, &restore_dir, false).unwrap();
        let restored = LocalStore::open(&restore_dir).unwrap();
        assert!(
            restored.get_vault_header().unwrap().is_some(),
            "H6: restored store must contain VaultHeaderV1 from latest.mnks"
        );
        let restored_marks = restored.load_shred_marks(true).unwrap();
        assert!(
            restored_marks.iter().any(|m| m.mark_id == unseen_mid),
            "H6: restored store must contain shred_marks from latest.mnks"
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&archive_dir);
        let _ = std::fs::remove_dir_all(&restore_dir);
    }
}
