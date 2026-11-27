//! Desktop local storage for the independent 100-item text & bitmap clipboard channel
//! (`docs/data-structures.md` §4 & §4.1, `docs/sync-protocol.md` §11, `INV-CLIP-ISOLATION`).
//!
//! Hard invariants:
//! - Strictly isolated from `sync_ops`, `blocks`, `buffers`, `block_keys`, `shred_marks`,
//!   `blocks_fts`, `mirror/`, and `backups/`.
//! - Large images and `> 64 KiB` long-text payloads are NEVER stored in `mynote.db`;
//!   they live as `0600` files inside `<data_dir>/clip_cache/` (`0700`) bounded by LRU
//!   eviction (max 100 files AND max 256 MiB).

use crate::credentials::write_atomic_0600;
use crate::store::{ensure_private_dir, rand_bytes, LocalStore};
use mynote_core::clip::{
    decode_clip_key_material, encode_clip_key_material, unwrap_clip_key_material_with_keyring,
    validate_clip_image_mime, wrap_clip_key_material, CLIP_MAX_ITEMS,
};
use mynote_core::error::{CoreError, ErrorCode};
use mynote_core::ids::{ClipId, ClipKid};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Maximum retained clipboard entries in local SQLite `clip_items`.
pub const CLIP_LOCAL_MAX_ITEMS: usize = CLIP_MAX_ITEMS;
/// Maximum number of cached blob files inside `<data_dir>/clip_cache/`.
pub const CLIP_CACHE_MAX_FILES: usize = 100;
/// Maximum aggregate byte budget of `<data_dir>/clip_cache/` (`256 MiB`).
pub const CLIP_CACHE_MAX_BYTES: u64 = 256 * 1024 * 1024;

const META_CLIP_LAST_ID: &str = "clip_last_id";

/// Local SQLite `clip_items` row (`docs/data-structures.md` §4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipItemRow {
    pub clip_id: String,
    pub clip_kid: String,
    pub device_id: String,
    pub kind: String,
    pub mime: String,
    pub source_mode: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub text_preview: Option<String>,
    pub has_blob: bool,
    pub blob_bytes: Option<i64>,
    pub blob_sha256: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub thumb_mime: Option<String>,
    pub thumb_blob: Option<Vec<u8>>,
    pub local_blob_path: Option<String>,
}

/// Stored `key_material(kind = 'clip_key')` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredClipKeyMaterial {
    pub gen: i64,
    pub blob: Vec<u8>,
    pub updated_at_ms: i64,
}

/// Unwrapped `(ClipKid, ClipKey, generation)` tuple returned from local `key_material`.
pub type UnwrappedClipKey = (ClipKid, Zeroizing<[u8; 32]>, i64);

/// Newly generated `(ClipKid, ClipKey, encoded_ClipKeyMaterialV1)` tuple.
pub type GeneratedClipKey = (ClipKid, Zeroizing<[u8; 32]>, Vec<u8>);

fn validate_cache_rel_name(rel_name: &str) -> Result<&str, CoreError> {
    if rel_name.is_empty()
        || rel_name.starts_with('.')
        || rel_name.contains('/')
        || rel_name.contains('\\')
        || rel_name.contains("..")
        || rel_name.contains('\0')
    {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            format!("unsafe clip_cache file name '{rel_name}'"),
            "Cache filenames must be single non-hidden relative names without path separators",
        ));
    }
    Ok(rel_name)
}

/// Isolated `0700` file cache for decrypted clipboard blobs (`<data_dir>/clip_cache/`),
/// bounded by LRU eviction on BOTH file count (`<= 100`) and total size (`<= 256 MiB`).
#[derive(Clone, Debug)]
pub struct ClipCache {
    root: PathBuf,
}

impl ClipCache {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn path_for(&self, rel_name: &str) -> Result<PathBuf, CoreError> {
        let clean = validate_cache_rel_name(rel_name)?;
        Ok(self.root.join(clean))
    }

    /// Atomically persist decrypted blob bytes (`0600` temp + rename) and enforce default
    /// LRU caps (`100` files / `256 MiB`).
    pub fn write(&self, rel_name: &str, bytes: &[u8]) -> Result<PathBuf, CoreError> {
        self.write_with_limits(rel_name, bytes, CLIP_CACHE_MAX_FILES, CLIP_CACHE_MAX_BYTES)
    }

    /// Atomically persist decrypted blob bytes and enforce explicit `(max_files, max_bytes)` LRU caps.
    pub fn write_with_limits(
        &self,
        rel_name: &str,
        bytes: &[u8],
        max_files: usize,
        max_bytes: u64,
    ) -> Result<PathBuf, CoreError> {
        ensure_private_dir(&self.root)?;
        let path = self.path_for(rel_name)?;
        write_atomic_0600(&path, bytes)?;
        let _ = self.enforce_lru(max_files, max_bytes)?;
        Ok(path)
    }

    /// Read cached blob bytes and touch `mtime` so hot entries stay resident in LRU order.
    pub fn read(&self, rel_name: &str) -> Result<Option<Vec<u8>>, CoreError> {
        let path = self.path_for(rel_name)?;
        if !path.is_file() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("failed reading clip_cache '{}': {e}", path.display()),
                "Verify clip_cache permissions or re-download blob from relay",
            )
        })?;
        // Best-effort LRU mtime bump on read hit.
        if let Ok(file) = std::fs::OpenOptions::new().write(true).open(&path) {
            let _ = file.set_modified(SystemTime::now());
        }
        Ok(Some(bytes))
    }

    pub fn exists(&self, rel_name: &str) -> bool {
        self.path_for(rel_name).is_ok_and(|p| p.is_file())
    }

    pub fn delete(&self, rel_name: &str) -> Result<(), CoreError> {
        let path = self.path_for(rel_name)?;
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        Ok(())
    }

    pub fn clear(&self) -> Result<(), CoreError> {
        if !self.root.exists() {
            return Ok(());
        }
        let rd = std::fs::read_dir(&self.root).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("failed reading clip_cache dir: {e}"),
                "Check clip_cache permissions",
            )
        })?;
        for ent in rd.flatten() {
            let p = ent.path();
            if p.is_file() {
                let _ = std::fs::remove_file(p);
            }
        }
        Ok(())
    }

    /// Evict oldest files (by `mtime`, tie-broken by filename) until BOTH
    /// `file_count <= max_files` AND `total_bytes <= max_bytes`.
    pub fn enforce_lru(&self, max_files: usize, max_bytes: u64) -> Result<Vec<String>, CoreError> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let rd = std::fs::read_dir(&self.root).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("failed scanning clip_cache dir: {e}"),
                "Check clip_cache permissions",
            )
        })?;
        let mut entries: Vec<(u128, String, u64, PathBuf)> = Vec::new();
        let mut total_bytes = 0u64;
        for ent in rd.flatten() {
            let path = ent.path();
            let Some(name) = path.file_name().and_then(|s| s.to_str()).map(ToString::to_string) else {
                continue;
            };
            // Skip transient atomic write temp files.
            if name.starts_with('.') {
                continue;
            }
            let Ok(meta) = ent.metadata() else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let len = meta.len();
            let mtime_ns = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            total_bytes = total_bytes.saturating_add(len);
            entries.push((mtime_ns, name, len, path));
        }

        if entries.len() <= max_files && total_bytes <= max_bytes {
            return Ok(Vec::new());
        }

        // Oldest first.
        entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let mut count = entries.len();
        let mut evicted = Vec::new();
        for (_, name, len, path) in entries {
            if count <= max_files && total_bytes <= max_bytes {
                break;
            }
            let _ = std::fs::remove_file(&path);
            count = count.saturating_sub(1);
            total_bytes = total_bytes.saturating_sub(len);
            evicted.push(name);
        }
        Ok(evicted)
    }

    pub fn stats(&self) -> (usize, u64) {
        let Ok(rd) = std::fs::read_dir(&self.root) else {
            return (0, 0);
        };
        let mut files = 0usize;
        let mut bytes = 0u64;
        for ent in rd.flatten() {
            let p = ent.path();
            if p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| n.starts_with('.'))
            {
                continue;
            }
            if let Ok(m) = ent.metadata() {
                if m.is_file() {
                    files += 1;
                    bytes = bytes.saturating_add(m.len());
                }
            }
        }
        (files, bytes)
    }
}

fn map_clip_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ClipItemRow> {
    let has_blob_i: i64 = r.get(9)?;
    let width_i: Option<i64> = r.get(12)?;
    let height_i: Option<i64> = r.get(13)?;
    Ok(ClipItemRow {
        clip_id: r.get(0)?,
        clip_kid: r.get(1)?,
        device_id: r.get(2)?,
        kind: r.get(3)?,
        mime: r.get(4)?,
        source_mode: r.get(5)?,
        created_at_ms: r.get(6)?,
        expires_at_ms: r.get(7)?,
        text_preview: r.get(8)?,
        has_blob: has_blob_i != 0,
        blob_bytes: r.get(10)?,
        blob_sha256: r.get(11)?,
        width: width_i.and_then(|v| u32::try_from(v).ok()),
        height: height_i.and_then(|v| u32::try_from(v).ok()),
        thumb_mime: r.get(14)?,
        thumb_blob: r.get(15)?,
        local_blob_path: r.get(16)?,
    })
}

const CLIP_SELECT_COLS: &str = "clip_id, clip_kid, device_id, kind, mime, source_mode, \
    created_at_ms, expires_at_ms, text_preview, has_blob, blob_bytes, blob_sha256, \
    width, height, thumb_mime, thumb_blob, local_blob_path";

impl LocalStore {
    /// Return a handle to `<data_dir>/clip_cache/` (strictly separate from `mynote.db`, `mirror/`, `backups/`).
    pub fn clip_cache(&self) -> ClipCache {
        ClipCache::new(self.data_dir.join("clip_cache"))
    }

    pub fn next_clip_id(&mut self, now_ms: u64) -> Result<ClipId, CoreError> {
        Ok(ClipId::from_ulid(self.ulid_gen.next(now_ms, rand_bytes::<10>()?)))
    }

    pub fn upsert_clip_item(&self, item: &ClipItemRow) -> Result<(), CoreError> {
        if item.kind != "text" && item.kind != "image" {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid clip kind '{}'", item.kind),
                "Expected 'text' or 'image'",
            ));
        }
        if item.kind == "image" {
            validate_clip_image_mime(&item.mime)?;
        }
        if let Some(tm) = item.thumb_mime.as_deref() {
            validate_clip_image_mime(tm)?;
        }
        if item.source_mode != "explicit" && item.source_mode != "auto" {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid clip source_mode '{}'", item.source_mode),
                "Expected 'explicit' or 'auto'",
            ));
        }
        if let Some(rel) = item.local_blob_path.as_deref() {
            validate_cache_rel_name(rel)?;
        }

        self.conn
            .execute(
                "INSERT INTO clip_items (
                    clip_id, clip_kid, device_id, kind, mime, source_mode,
                    created_at_ms, expires_at_ms, text_preview, has_blob,
                    blob_bytes, blob_sha256, width, height, thumb_mime, thumb_blob, local_blob_path
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
                 ON CONFLICT(clip_id) DO UPDATE SET
                    clip_kid = excluded.clip_kid,
                    device_id = excluded.device_id,
                    kind = excluded.kind,
                    mime = excluded.mime,
                    source_mode = excluded.source_mode,
                    created_at_ms = excluded.created_at_ms,
                    expires_at_ms = excluded.expires_at_ms,
                    text_preview = excluded.text_preview,
                    has_blob = excluded.has_blob,
                    blob_bytes = excluded.blob_bytes,
                    blob_sha256 = excluded.blob_sha256,
                    width = excluded.width,
                    height = excluded.height,
                    thumb_mime = excluded.thumb_mime,
                    thumb_blob = excluded.thumb_blob,
                    local_blob_path = COALESCE(excluded.local_blob_path, clip_items.local_blob_path)",
                params![
                    item.clip_id,
                    item.clip_kid,
                    item.device_id,
                    item.kind,
                    item.mime,
                    item.source_mode,
                    item.created_at_ms,
                    item.expires_at_ms,
                    item.text_preview,
                    i64::from(item.has_blob),
                    item.blob_bytes,
                    item.blob_sha256,
                    item.width.map(i64::from),
                    item.height.map(i64::from),
                    item.thumb_mime,
                    item.thumb_blob,
                    item.local_blob_path,
                ],
            )
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("upsert clip_item failed: {e}"),
                    "Verify clip_items schema",
                )
            })?;
        Ok(())
    }

    pub fn list_clip_items(
        &self,
        limit: usize,
        kind_filter: Option<&str>,
    ) -> Result<Vec<ClipItemRow>, CoreError> {
        if let Some(k) = kind_filter {
            if k != "text" && k != "image" {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid clip kind filter '{k}'"),
                    "Use --kind text or --kind image",
                ));
            }
        }
        let lim = limit.clamp(1, CLIP_LOCAL_MAX_ITEMS) as i64;
        let mut out = Vec::new();
        if let Some(k) = kind_filter {
            let sql = format!(
                "SELECT {CLIP_SELECT_COLS} FROM clip_items WHERE kind = ?1 \
                 ORDER BY created_at_ms DESC, clip_id DESC LIMIT ?2"
            );
            let mut stmt = self
                .conn
                .prepare(&sql)
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query clip_items"))?;
            let rows = stmt
                .query_map(params![k, lim], map_clip_row)
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map clip_items"))?;
            for r in rows {
                out.push(r.map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "row clip_items")
                })?);
            }
        } else {
            let sql = format!(
                "SELECT {CLIP_SELECT_COLS} FROM clip_items \
                 ORDER BY created_at_ms DESC, clip_id DESC LIMIT ?1"
            );
            let mut stmt = self
                .conn
                .prepare(&sql)
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query clip_items"))?;
            let rows = stmt
                .query_map([lim], map_clip_row)
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map clip_items"))?;
            for r in rows {
                out.push(r.map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "row clip_items")
                })?);
            }
        }
        Ok(out)
    }

    pub fn get_clip_item(&self, clip_id: &str) -> Result<Option<ClipItemRow>, CoreError> {
        let sql = format!("SELECT {CLIP_SELECT_COLS} FROM clip_items WHERE clip_id = ?1");
        self.conn
            .query_row(&sql, [clip_id], map_clip_row)
            .optional()
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "get clip_item"))
    }

    pub fn count_active_clip_items(&self, now_ms: i64) -> Result<usize, CoreError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM clip_items WHERE expires_at_ms > ?1",
                [now_ms],
                |r| r.get(0),
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "count clip_items"))?;
        Ok(count.max(0) as usize)
    }

    pub fn latest_clip_item(&self) -> Result<Option<ClipItemRow>, CoreError> {
        let sql = format!(
            "SELECT {CLIP_SELECT_COLS} FROM clip_items \
             ORDER BY created_at_ms DESC, clip_id DESC LIMIT 1"
        );
        self.conn
            .query_row(&sql, [], map_clip_row)
            .optional()
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "latest clip_item"))
    }

    /// Delete one clip item; returns `(existed, local_blob_path)` so caller can delete any cached blob.
    pub fn delete_clip_item(&self, clip_id: &str) -> Result<(bool, Option<String>), CoreError> {
        let existing: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT local_blob_path FROM clip_items WHERE clip_id = ?1",
                [clip_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "lookup clip_item"))?;
        let Some(blob_path) = existing else {
            return Ok((false, None));
        };
        self.conn
            .execute("DELETE FROM clip_items WHERE clip_id = ?1", [clip_id])
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "delete clip_item"))?;
        Ok((true, blob_path))
    }

    /// Clear all local clip items and reset the incremental `clip_last_id` cursor.
    /// Returns `(deleted_count, evicted_local_blob_paths)`.
    pub fn clear_clip_items(&self) -> Result<(usize, Vec<String>), CoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT local_blob_path FROM clip_items WHERE local_blob_path IS NOT NULL")
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "scan clip_items"))?;
        let paths: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map clip paths"))?
            .filter_map(Result::ok)
            .collect();
        let deleted = self
            .conn
            .execute("DELETE FROM clip_items", [])
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "clear clip_items"))?;
        let _ = self.set_clip_cursor(None);
        Ok((deleted, paths))
    }

    /// Keep at most `max_items` newest clip rows by `(created_at_ms DESC, clip_id DESC)`,
    /// returning evicted `local_blob_path`s for cache cleanup.
    pub fn trim_clip_items(&self, max_items: usize) -> Result<Vec<String>, CoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT clip_id, local_blob_path FROM clip_items
                 ORDER BY created_at_ms DESC, clip_id DESC
                 LIMIT -1 OFFSET ?1",
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "trim clip_items query"))?;
        let overflow: Vec<(String, Option<String>)> = stmt
            .query_map([max_items as i64], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "trim clip_items map"))?
            .filter_map(Result::ok)
            .collect();
        let mut evicted_paths = Vec::new();
        for (cid, path) in overflow {
            self.conn
                .execute("DELETE FROM clip_items WHERE clip_id = ?1", [&cid])
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "delete trimmed clip")
                })?;
            if let Some(p) = path {
                evicted_paths.push(p);
            }
        }
        Ok(evicted_paths)
    }

    /// Delete local clip rows whose `expires_at_ms <= now_ms`, returning evicted `local_blob_path`s.
    pub fn prune_expired_clip_items(&self, now_ms: i64) -> Result<Vec<String>, CoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT clip_id, local_blob_path FROM clip_items WHERE expires_at_ms <= ?1")
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "prune expired clips"))?;
        let expired: Vec<(String, Option<String>)> = stmt
            .query_map([now_ms], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map expired clips"))?
            .filter_map(Result::ok)
            .collect();
        let mut evicted_paths = Vec::new();
        for (cid, path) in expired {
            self.conn
                .execute("DELETE FROM clip_items WHERE clip_id = ?1", [&cid])
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "delete expired clip")
                })?;
            if let Some(p) = path {
                evicted_paths.push(p);
            }
        }
        Ok(evicted_paths)
    }

    pub fn set_clip_local_blob_path(&self, clip_id: &str, rel_path: Option<&str>) -> Result<(), CoreError> {
        if let Some(rel) = rel_path {
            validate_cache_rel_name(rel)?;
        }
        self.conn
            .execute(
                "UPDATE clip_items SET local_blob_path = ?1 WHERE clip_id = ?2",
                params![rel_path, clip_id],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "update clip blob path"))?;
        Ok(())
    }

    pub fn get_clip_key_material(&self) -> Result<Option<StoredClipKeyMaterial>, CoreError> {
        self.conn
            .query_row(
                "SELECT gen, blob, updated_at_ms FROM key_material WHERE kind = 'clip_key'",
                [],
                |r| {
                    Ok(StoredClipKeyMaterial {
                        gen: r.get(0)?,
                        blob: r.get(1)?,
                        updated_at_ms: r.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    e.to_string(),
                    "query clip_key material",
                )
            })
    }

    /// Persist a validated `ClipKeyMaterialV1` into `key_material(kind = 'clip_key')`.
    /// Rejects stale generations (`gen < cur_gen`) with `CasMismatch`; rotation destructively
    /// replaces the previous generation (old `ClipKey` is never retained).
    pub fn upsert_clip_key_material(
        &self,
        gen: i64,
        blob: &[u8],
        updated_at_ms: i64,
    ) -> Result<(), CoreError> {
        let _ = decode_clip_key_material(blob)?;
        if let Some(cur) = self.get_clip_key_material()? {
            if gen < cur.gen {
                return Err(CoreError::new(
                    ErrorCode::CasMismatch,
                    format!("stale clip_key gen {gen} < local gen {}", cur.gen),
                    "Fetch latest clip_key from relay before retrying",
                ));
            }
            if gen == cur.gen && cur.blob != blob {
                return Err(CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("conflicting clip_key payload at gen={gen}"),
                    "Verify relay key_material integrity",
                ));
            }
            if gen == cur.gen {
                return Ok(());
            }
        }
        self.conn
            .execute(
                "INSERT OR REPLACE INTO key_material (kind, gen, blob, updated_at_ms)
                 VALUES ('clip_key', ?1, ?2, ?3)",
                params![gen, blob, updated_at_ms],
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "upsert clip_key"))?;
        Ok(())
    }

    /// Decode and unwrap the locally stored `ClipKey` using the device's SMK keyring.
    pub fn unwrap_local_clip_key(&self) -> Result<Option<UnwrappedClipKey>, CoreError> {
        let Some(stored) = self.get_clip_key_material()? else {
            return Ok(None);
        };
        let mat = decode_clip_key_material(&stored.blob)?;
        let key = unwrap_clip_key_material_with_keyring(&mat, &self.smks)?;
        Ok(Some((mat.clip_kid, key, stored.gen)))
    }

    /// Generate a brand-new random `(ClipKid, ClipKey)` and wrap it under the current active `SMK`
    /// into encoded `ClipKeyMaterialV1` bytes (does not mutate SQLite until persisted).
    pub fn generate_wrapped_clip_key(&mut self, now_ms: u64) -> Result<GeneratedClipKey, CoreError> {
        let smk_kid = self.current_smk_kid;
        let smk = self.current_smk()?.clone();
        let clip_kid = ClipKid::from_ulid(self.ulid_gen.next(now_ms, rand_bytes::<10>()?));
        let clip_key = Zeroizing::new(rand_bytes::<32>()?);
        let nonce = rand_bytes::<24>()?;
        let mat = wrap_clip_key_material(smk_kid, &smk, clip_kid, &clip_key, nonce)?;
        let blob = encode_clip_key_material(&mat)?;
        Ok((clip_kid, clip_key, blob))
    }

    pub fn get_clip_cursor(&self) -> Option<String> {
        self.get_local_meta(META_CLIP_LAST_ID)
            .filter(|s| !s.trim().is_empty())
    }

    pub fn set_clip_cursor(&self, clip_id: Option<&str>) -> Result<(), CoreError> {
        match clip_id {
            Some(id) if !id.trim().is_empty() => self.set_local_meta(META_CLIP_LAST_ID, id),
            _ => {
                self.conn
                    .execute("DELETE FROM local_meta WHERE key = ?1", [META_CLIP_LAST_ID])
                    .map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "clear clip cursor")
                    })?;
                Ok(())
            }
        }
    }
}
