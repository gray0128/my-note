//! Desktop local storage for the independent text & bitmap clipboard archive
//! (`docs/data-structures.md` §4 & §4.1, `docs/sync-protocol.md` §11, `INV-CLIP-ISOLATION`, D8′).
//!
//! Hard invariants:
//! - Strictly isolated from `sync_ops`, `blocks`, `buffers`, `block_keys`, `shred_marks`,
//!   `blocks_fts`, `mirror/`, and `backups/`.
//! - Desktop local `clip_items` and `<data_dir>/clip_cache/` (`0700` dir, `0600` files) retain
//!   synced items indefinitely until the user explicitly deletes or prunes them (no automatic
//!   ring-buffer trim, TTL expiry, or LRU eviction on desktop writes).
//! - Large images and `> 64 KiB` long-text payloads are NEVER stored inside `mynote.db`.

use crate::credentials::write_atomic_0600;
use crate::store::{ensure_private_dir, rand_bytes, LocalStore};
use mynote_core::clip::{
    decode_clip_key_material, encode_clip_key_material, unwrap_clip_key_material_with_keyring,
    validate_clip_image_mime, wrap_clip_key_material, CLIP_CLOUD_MAX_ITEMS,
};
use mynote_core::error::{CoreError, ErrorCode};
use mynote_core::ids::{ClipId, ClipKid};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Cloud rolling window size (`1,000`), retained as a reference constant.
pub const CLIP_LOCAL_MAX_ITEMS: usize = CLIP_CLOUD_MAX_ITEMS;
/// Default page size for local clipboard history queries.
pub const CLIP_LOCAL_DEFAULT_PAGE_LIMIT: usize = 50;
/// Maximum page size for a single local clipboard query.
pub const CLIP_LOCAL_MAX_PAGE_LIMIT: usize = 1000;
/// Legacy optional LRU file count cap (used only when calling `enforce_lru` / `write_with_limits` explicitly).
pub const CLIP_CACHE_MAX_FILES: usize = 100;
/// Legacy optional LRU byte cap (`256 MiB`, used only when calling `enforce_lru` / `write_with_limits` explicitly).
pub const CLIP_CACHE_MAX_BYTES: u64 = 256 * 1024 * 1024;

const META_CLIP_LAST_ID: &str = "clip_last_id";

/// Query options for paginated/searchable local clipboard archive listing.
#[derive(Clone, Debug, Default)]
pub struct ClipListQuery<'a> {
    pub limit: usize,
    pub before_id: Option<&'a str>,
    pub kind: Option<&'a str>,
    pub query: Option<&'a str>,
}

/// Paginated local clipboard listing response.
#[derive(Clone, Debug)]
pub struct ClipListPage {
    pub items: Vec<ClipItemRow>,
    pub has_more: bool,
    pub total_count: usize,
}

/// Filter for explicit manual clipboard pruning (`dry_run = true` previews without mutating).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClipPruneFilter {
    pub before_ms: Option<i64>,
    pub keep_latest: Option<usize>,
    pub kind: Option<String>,
    pub dry_run: bool,
}

/// Result summary for a manual clipboard prune operation.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClipPruneResult {
    pub dry_run: bool,
    pub matched_count: usize,
    pub deleted_count: usize,
    pub freed_bytes: u64,
    pub deleted_ids: Vec<String>,
}

/// Aggregate local desktop clipboard storage statistics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LocalClipStats {
    pub total_items: usize,
    pub text_items: usize,
    pub image_items: usize,
    pub blob_items: usize,
    pub cached_blob_files: usize,
    pub cached_blob_bytes: u64,
    pub uncached_blob_items: usize,
    pub oldest_created_at_ms: Option<i64>,
    pub newest_created_at_ms: Option<i64>,
}

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

    /// Atomically persist decrypted blob bytes (`0600` temp + rename) without automatic LRU eviction.
    /// Desktop local blobs are retained until explicitly deleted or pruned by the user (D8′).
    pub fn write(&self, rel_name: &str, bytes: &[u8]) -> Result<PathBuf, CoreError> {
        ensure_private_dir(&self.root)?;
        let path = self.path_for(rel_name)?;
        write_atomic_0600(&path, bytes)?;
        Ok(path)
    }

    /// File byte size if present on disk (returns `0` when absent).
    pub fn file_size(&self, rel_name: &str) -> u64 {
        self.path_for(rel_name)
            .ok()
            .and_then(|p| std::fs::metadata(p).ok())
            .filter(|m| m.is_file())
            .map(|m| m.len())
            .unwrap_or(0)
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
        let page = self.list_clip_items_page(&ClipListQuery {
            limit,
            before_id: None,
            kind: kind_filter,
            query: None,
        })?;
        Ok(page.items)
    }

    /// Paginated, searchable query over the unbounded local desktop clipboard archive.
    pub fn list_clip_items_page(&self, q: &ClipListQuery<'_>) -> Result<ClipListPage, CoreError> {
        if let Some(k) = q.kind {
            if k != "text" && k != "image" {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid clip kind filter '{k}'"),
                    "Use --kind text or --kind image",
                ));
            }
        }
        let lim = q.limit.clamp(1, CLIP_LOCAL_MAX_PAGE_LIMIT);
        let like_pattern = q.query.map(str::trim).filter(|s| !s.is_empty()).map(|raw| {
            let escaped = raw.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
            format!("%{escaped}%")
        });

        let mut base_clauses: Vec<String> = Vec::new();
        let mut base_vals: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(k) = q.kind {
            base_clauses.push(format!("kind = ?{}", base_vals.len() + 1));
            base_vals.push(rusqlite::types::Value::Text(k.to_string()));
        }
        if let Some(ref pat) = like_pattern {
            let p_idx = base_vals.len() + 1;
            base_clauses.push(format!(
                "(LOWER(COALESCE(text_preview, '')) LIKE LOWER(?{p_idx}) ESCAPE '\\' \
                 OR LOWER(mime) LIKE LOWER(?{p_idx}) ESCAPE '\\' \
                 OR LOWER(clip_id) LIKE LOWER(?{p_idx}) ESCAPE '\\')"
            ));
            base_vals.push(rusqlite::types::Value::Text(pat.clone()));
        }

        let base_where = if base_clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", base_clauses.join(" AND "))
        };

        let count_sql = format!("SELECT COUNT(*) FROM clip_items{base_where}");
        let total_count: usize = self
            .conn
            .query_row(&count_sql, rusqlite::params_from_iter(base_vals.iter()), |r| {
                r.get::<_, i64>(0)
            })
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "count clip_items"))?
            .max(0) as usize;

        let mut page_clauses = base_clauses;
        let mut page_vals = base_vals;
        if let Some(bid) = q.before_id.map(str::trim).filter(|s| !s.is_empty()) {
            let cursor_ts: Option<i64> = self
                .conn
                .query_row(
                    "SELECT created_at_ms FROM clip_items WHERE clip_id = ?1",
                    [bid],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "lookup clip cursor")
                })?;
            if let Some(b_ts) = cursor_ts {
                let ts_idx = page_vals.len() + 1;
                let id_idx = page_vals.len() + 2;
                page_clauses.push(format!(
                    "(created_at_ms < ?{ts_idx} OR (created_at_ms = ?{ts_idx} AND clip_id < ?{id_idx}))"
                ));
                page_vals.push(rusqlite::types::Value::Integer(b_ts));
                page_vals.push(rusqlite::types::Value::Text(bid.to_string()));
            } else {
                let id_idx = page_vals.len() + 1;
                page_clauses.push(format!("clip_id < ?{id_idx}"));
                page_vals.push(rusqlite::types::Value::Text(bid.to_string()));
            }
        }

        let page_where = if page_clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", page_clauses.join(" AND "))
        };
        let lim_idx = page_vals.len() + 1;
        page_vals.push(rusqlite::types::Value::Integer((lim + 1) as i64));

        let page_sql = format!(
            "SELECT {CLIP_SELECT_COLS} FROM clip_items{page_where} \
             ORDER BY created_at_ms DESC, clip_id DESC LIMIT ?{lim_idx}"
        );
        let mut stmt = self
            .conn
            .prepare(&page_sql)
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query clip_items"))?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(page_vals.iter()), map_clip_row)
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map clip_items"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(
                r.map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "row clip_items"))?,
            );
        }
        let has_more = out.len() > lim;
        if has_more {
            out.truncate(lim);
        }
        Ok(ClipListPage {
            items: out,
            has_more,
            total_count,
        })
    }

    pub fn get_clip_item(&self, clip_id: &str) -> Result<Option<ClipItemRow>, CoreError> {
        let sql = format!("SELECT {CLIP_SELECT_COLS} FROM clip_items WHERE clip_id = ?1");
        self.conn
            .query_row(&sql, [clip_id], map_clip_row)
            .optional()
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "get clip_item"))
    }

    /// Count all locally retained desktop clipboard items (ignores cloud `expires_at_ms`).
    pub fn count_all_clip_items(&self) -> Result<usize, CoreError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM clip_items", [], |r| r.get(0))
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "count clip_items"))?;
        Ok(count.max(0) as usize)
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

    /// Return aggregate local desktop clipboard archive stats (SQLite + `clip_cache/`).
    pub fn clip_storage_stats(&self) -> Result<LocalClipStats, CoreError> {
        let cache = self.clip_cache();
        let (cached_blob_files, cached_blob_bytes) = cache.stats();
        let (total_items, text_items, image_items, blob_items, oldest, newest): (
            i64,
            i64,
            i64,
            i64,
            Option<i64>,
            Option<i64>,
        ) = self
            .conn
            .query_row(
                "SELECT COUNT(*), \
                 COALESCE(SUM(CASE WHEN kind = 'text' THEN 1 ELSE 0 END), 0), \
                 COALESCE(SUM(CASE WHEN kind = 'image' THEN 1 ELSE 0 END), 0), \
                 COALESCE(SUM(CASE WHEN has_blob != 0 THEN 1 ELSE 0 END), 0), \
                 MIN(created_at_ms), MAX(created_at_ms) \
                 FROM clip_items",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "clip stats"))?;

        let mut stmt = self
            .conn
            .prepare("SELECT local_blob_path FROM clip_items WHERE has_blob != 0")
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "scan clip blobs"))?;
        let mut uncached_blob_items = 0usize;
        let rows = stmt
            .query_map([], |r| r.get::<_, Option<String>>(0))
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map clip blobs"))?;
        for r in rows.flatten() {
            if !r.as_deref().is_some_and(|p| cache.exists(p)) {
                uncached_blob_items += 1;
            }
        }

        Ok(LocalClipStats {
            total_items: total_items.max(0) as usize,
            text_items: text_items.max(0) as usize,
            image_items: image_items.max(0) as usize,
            blob_items: blob_items.max(0) as usize,
            cached_blob_files,
            cached_blob_bytes,
            uncached_blob_items,
            oldest_created_at_ms: oldest,
            newest_created_at_ms: newest,
        })
    }

    /// List newest-first clip items whose remote R2 blob has not yet expired and is missing locally,
    /// so the desktop Daemon can eagerly persist them to `clip_cache/` before cloud TTL expires.
    pub fn list_uncached_remote_blobs(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<ClipItemRow>, CoreError> {
        let cache = self.clip_cache();
        let sql = format!(
            "SELECT {CLIP_SELECT_COLS} FROM clip_items \
             WHERE has_blob != 0 AND expires_at_ms > ?1 \
             ORDER BY created_at_ms DESC, clip_id DESC"
        );
        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "query uncached blobs"))?;
        let rows = stmt
            .query_map([now_ms], map_clip_row)
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "map uncached blobs"))?;
        let mut out = Vec::new();
        for r in rows {
            let row =
                r.map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "row uncached blob"))?;
            let is_cached = row.local_blob_path.as_deref().is_some_and(|p| cache.exists(p));
            if !is_cached {
                out.push(row);
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Manually prune local clipboard items matching `filter` (matches cloud `POST /v1/clip/prune` semantics).
    pub fn prune_clip_items(&self, filter: &ClipPruneFilter) -> Result<ClipPruneResult, CoreError> {
        if let Some(ref k) = filter.kind {
            if k != "text" && k != "image" {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid clip kind filter '{k}'"),
                    "Use kind 'text' or 'image'",
                ));
            }
        }
        if filter.before_ms.is_none() && filter.keep_latest.is_none() && filter.kind.is_none() {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "at least one of before_ms, keep_latest, or kind is required for clip prune",
                "Specify --before, --keep, or --kind (or use 'clip clear' to wipe all)",
            ));
        }

        let candidates: Vec<(String, i64, Option<String>)> = if let Some(ref k) = filter.kind {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT clip_id, created_at_ms, local_blob_path FROM clip_items \
                     WHERE kind = ?1 ORDER BY created_at_ms DESC, clip_id DESC",
                )
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "prune scan"))?;
            let rows = stmt
                .query_map([k], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "prune map"))?;
            rows.filter_map(Result::ok).collect()
        } else {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT clip_id, created_at_ms, local_blob_path FROM clip_items \
                     ORDER BY created_at_ms DESC, clip_id DESC",
                )
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "prune scan"))?;
            let rows = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "prune map"))?;
            rows.filter_map(Result::ok).collect()
        };

        let cache = self.clip_cache();
        let mut matched: Vec<(String, Option<String>)> = Vec::new();
        let mut freed_bytes = 0u64;
        for (idx, (cid, created_at_ms, local_path)) in candidates.into_iter().enumerate() {
            if filter.keep_latest.is_some_and(|k| idx < k) {
                continue;
            }
            if filter.before_ms.is_some_and(|b| created_at_ms >= b) {
                continue;
            }
            if let Some(ref rel) = local_path {
                freed_bytes = freed_bytes.saturating_add(cache.file_size(rel));
            }
            matched.push((cid, local_path));
        }

        let matched_count = matched.len();
        if filter.dry_run {
            return Ok(ClipPruneResult {
                dry_run: true,
                matched_count,
                deleted_count: 0,
                freed_bytes,
                deleted_ids: Vec::new(),
            });
        }

        let mut deleted_ids = Vec::with_capacity(matched_count);
        for (cid, local_path) in matched {
            self.conn
                .execute("DELETE FROM clip_items WHERE clip_id = ?1", [&cid])
                .map_err(|e| {
                    CoreError::new(ErrorCode::IntegrityError, e.to_string(), "delete pruned clip")
                })?;
            if let Some(rel) = local_path {
                let _ = cache.delete(&rel);
            }
            deleted_ids.push(cid);
        }

        Ok(ClipPruneResult {
            dry_run: false,
            matched_count,
            deleted_count: deleted_ids.len(),
            freed_bytes,
            deleted_ids,
        })
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
