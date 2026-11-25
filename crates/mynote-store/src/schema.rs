//! Desktop SQLite STRICT DDL, PRAGMA initialization, schema version guard, and `VACUUM INTO` backups
//! (`docs/data-structures.md` §4 & §4.1).

use mynote_core::error::{CoreError, ErrorCode};
use rusqlite::Connection;
use std::path::Path;

pub const CURRENT_SCHEMA_VERSION: i64 = 1;
pub const MIN_READER_SCHEMA_VERSION: i64 = 1;

pub const INIT_PRAGMAS: &str = "
PRAGMA busy_timeout = 5000;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA secure_delete = ON;
";

pub const SCHEMA_V1_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS local_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS buffers (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    key_id        TEXT NOT NULL,
    position      TEXT NOT NULL,
    name_hlc      TEXT NOT NULL,
    position_hlc  TEXT NOT NULL,
    state         TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'TRASHED', 'SHREDDED')),
    updated_at_ms INTEGER NOT NULL,
    deleted_at_ms INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS idx_buffers_active_order
    ON buffers (position COLLATE BINARY ASC, id ASC)
    WHERE state = 'ACTIVE';

CREATE TABLE IF NOT EXISTS blocks (
    id                 TEXT PRIMARY KEY,
    buffer_id          TEXT NOT NULL REFERENCES buffers(id),
    position           TEXT NOT NULL,
    lang               TEXT NOT NULL,
    public_hint        TEXT,
    buffer_id_hlc      TEXT NOT NULL,
    position_hlc       TEXT NOT NULL,
    lang_hlc           TEXT NOT NULL,
    public_hint_hlc    TEXT NOT NULL,
    state              TEXT NOT NULL CHECK (state IN ('ACTIVE', 'TRASHED', 'SHREDDED')),
    is_locked          INTEGER NOT NULL CHECK (is_locked IN (0, 1)),
    display_op_id      TEXT,
    leaf_count         INTEGER NOT NULL DEFAULT 1,
    updated_at_ms      INTEGER NOT NULL,
    deleted_at_ms      INTEGER,
    CHECK ((state = 'ACTIVE') = (display_op_id IS NOT NULL))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_blocks_buffer_order
    ON blocks (buffer_id, position COLLATE BINARY ASC, id ASC)
    WHERE state = 'ACTIVE';

CREATE TABLE IF NOT EXISTS block_leaves (
    block_id      TEXT NOT NULL REFERENCES blocks(id) ON DELETE CASCADE,
    op_id         TEXT NOT NULL,
    hlc           TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    actor         TEXT NOT NULL,
    body_state    TEXT NOT NULL CHECK (body_state IN ('PLAINTEXT', 'SEALED', 'TOMBSTONE', 'KEY_UNAVAILABLE', 'DECRYPT_FAILED')),
    tier          INTEGER CHECK (tier IN (1, 2)),
    key_id        TEXT,
    content       TEXT,
    ciphertext    BLOB,
    PRIMARY KEY (block_id, op_id),
    CHECK (
        (body_state = 'PLAINTEXT'       AND tier = 1 AND key_id IS NOT NULL AND content IS NOT NULL AND ciphertext IS NULL)
        OR
        (body_state = 'SEALED'          AND tier = 2 AND key_id IS NOT NULL AND content IS NULL AND ciphertext IS NOT NULL)
        OR
        (body_state = 'TOMBSTONE'       AND tier IS NULL AND key_id IS NULL AND content IS NULL AND ciphertext IS NULL)
        OR
        (body_state IN ('KEY_UNAVAILABLE', 'DECRYPT_FAILED') AND content IS NULL AND ciphertext IS NULL)
    )
) STRICT;

CREATE INDEX IF NOT EXISTS idx_block_leaves_key ON block_leaves (key_id) WHERE key_id IS NOT NULL;

CREATE VIRTUAL TABLE IF NOT EXISTS blocks_fts USING fts5(
    content,
    public_hint,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TABLE IF NOT EXISTS sync_ops (
    op_id                TEXT PRIMARY KEY,
    server_seq           INTEGER,
    sync_blocked_reason  TEXT,
    device_id            TEXT NOT NULL,
    entity_type          TEXT NOT NULL CHECK (entity_type IN ('buffer', 'block')),
    entity_id            TEXT NOT NULL,
    parent_op_ids        TEXT NOT NULL,
    op_type              TEXT NOT NULL CHECK (op_type IN ('CREATE','UPDATE','SET_META','LOCK','UNLOCK','RESOLVE','DELETE')),
    hlc                  TEXT NOT NULL,
    actor                TEXT NOT NULL DEFAULT 'human',
    key_id               TEXT,
    smk_kid              TEXT NOT NULL,
    envelope             BLOB NOT NULL,
    created_at_ms        INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_sync_ops_outbox
    ON sync_ops (created_at_ms ASC, op_id ASC)
    WHERE server_seq IS NULL AND sync_blocked_reason IS NULL;

CREATE INDEX IF NOT EXISTS idx_sync_ops_entity_history
    ON sync_ops (entity_type, entity_id, hlc ASC);

CREATE TABLE IF NOT EXISTS block_keys (
    key_id         TEXT PRIMARY KEY,
    block_id       TEXT NOT NULL,
    tier           INTEGER NOT NULL CHECK (tier IN (1, 2)),
    wrap_gen       INTEGER NOT NULL,
    key_record     BLOB,
    created_hlc    TEXT NOT NULL,
    created_at_ms  INTEGER NOT NULL,
    server_acked   INTEGER NOT NULL DEFAULT 0 CHECK (server_acked IN (0, 1))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_block_keys_block ON block_keys (block_id);

CREATE TABLE IF NOT EXISTS shred_marks (
    mark_id          TEXT PRIMARY KEY,
    key_id           TEXT NOT NULL REFERENCES block_keys(key_id),
    requested_by     TEXT NOT NULL,
    requested_at_ms  INTEGER NOT NULL,
    seen_seq         INTEGER NOT NULL,
    grace_ms         INTEGER NOT NULL,
    not_before_ms    INTEGER,
    state            TEXT NOT NULL CHECK (state IN ('pending_confirm', 'scheduled', 'cancelled', 'executed')),
    confirmed_at_ms  INTEGER,
    cancelled_by     TEXT,
    executed_at_ms   INTEGER,
    server_acked     INTEGER NOT NULL DEFAULT 0 CHECK (server_acked IN (0, 1))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_shred_marks_key ON shred_marks (key_id);

CREATE TABLE IF NOT EXISTS key_material (
    kind           TEXT PRIMARY KEY CHECK (kind IN ('keyring', 'vault_header')),
    gen            INTEGER NOT NULL,
    blob           BLOB NOT NULL,
    updated_at_ms  INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS idempotency_keys (
    idem_key       TEXT PRIMARY KEY,
    command        TEXT NOT NULL,
    entity_id      TEXT NOT NULL,
    op_id          TEXT NOT NULL,
    created_at_ms  INTEGER NOT NULL
) STRICT;
"#;

pub fn init_connection(conn: &Connection, backups_dir: Option<&Path>) -> Result<(), CoreError> {
    // busy_timeout MUST be set BEFORE inspecting or enabling WAL so concurrent opens wait instead of SQLITE_BUSY.
    conn.execute_batch(INIT_PRAGMAS).map_err(|e| {
        CoreError::new(
            ErrorCode::IntegrityError,
            format!("SQLite PRAGMA initialization failed: {e}"),
            "Verify database file permissions and SQLite integrity",
        )
    })?;

    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap_or_default();
    if !journal_mode.eq_ignore_ascii_case("wal") {
        conn.execute_batch("PRAGMA journal_mode = WAL;").map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("SQLite WAL initialization failed: {e}"),
                "Verify database file permissions and SQLite integrity",
            )
        })?;
    }

    let existing_ver: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                e.to_string(),
                "Failed to inspect schema version",
            )
        })?;

    // Check downgrade lock before touching any table
    if existing_ver > 0 {
        let min_reader: Option<i64> = conn
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM local_meta WHERE key = 'min_reader_schema_version'",
                [],
                |r| r.get(0),
            )
            .ok();
        if let Some(min_v) = min_reader {
            if CURRENT_SCHEMA_VERSION < min_v {
                return Err(CoreError::new(
                    ErrorCode::IntegrityError,
                    format!(
                        "SCHEMA_TOO_NEW: database requires reader schema >= {min_v}, binary supports {CURRENT_SCHEMA_VERSION}"
                    ),
                    "Upgrade mynote via your package manager, or restore a pre-migration backup (see 'mynote help upgrade')",
                ));
            }
        }
        // Already at current schema version: avoid acquiring SQLite write locks on read-only opens.
        if existing_ver == CURRENT_SCHEMA_VERSION {
            return Ok(());
        }
        // Pre-migration VACUUM INTO consistency snapshot
        if existing_ver < CURRENT_SCHEMA_VERSION {
            if let Some(dir) = backups_dir {
                std::fs::create_dir_all(dir).map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        e.to_string(),
                        "Cannot create backups directory",
                    )
                })?;
                let snap = dir.join(format!("mynote-pre-schema-v{existing_ver}.db"));
                vacuum_into(conn, &snap)?;
                prune_pre_schema_backups(dir, 2);
            }
        }
    }

    conn.execute_batch(SCHEMA_V1_DDL).map_err(|e| {
        CoreError::new(
            ErrorCode::IntegrityError,
            format!("SQLite schema migration failed: {e}"),
            "Verify SQLite database file is not corrupted",
        )
    })?;

    conn.execute(
        "INSERT OR IGNORE INTO local_meta (key, value) VALUES ('schema_version', ?1)",
        [CURRENT_SCHEMA_VERSION.to_string()],
    )
    .ok();
    conn.execute(
        "INSERT OR IGNORE INTO local_meta (key, value) VALUES ('min_reader_schema_version', ?1)",
        [MIN_READER_SCHEMA_VERSION.to_string()],
    )
    .ok();
    conn.execute_batch(&format!("PRAGMA user_version = {CURRENT_SCHEMA_VERSION};"))
        .map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                e.to_string(),
                "Failed to set user_version",
            )
        })?;

    Ok(())
}

/// Generate a consistent single-file SQLite backup via `VACUUM INTO` (`0600` on Unix).
pub fn vacuum_into(conn: &Connection, dest: &Path) -> Result<(), CoreError> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("cannot create backup parent '{}': {e}", parent.display()),
                "Verify backup directory permissions",
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("failed setting 0700 on '{}': {e}", parent.display()),
                    "Verify backup directory ownership and permissions",
                )
            })?;
        }
    }
    if dest.exists() {
        let _ = std::fs::remove_file(dest);
    }
    let path_str = dest.to_string_lossy().replace('\'', "''");
    conn.execute(&format!("VACUUM INTO '{path_str}'"), [])
        .map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("VACUUM INTO '{}' failed: {e}", dest.display()),
                "Ensure sufficient disk space in the backup directory",
            )
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("failed setting 0600 on backup '{}': {e}", dest.display()),
                "Verify backup directory ownership and permissions",
            )
        })?;
    }
    Ok(())
}

/// Keep at most `keep_latest` `mynote-pre-schema-v*.db` files in `dir` so shredded data does not
/// linger indefinitely in ancient schema-migration backups (`docs/threat-model.md` §2.3, H9).
fn prune_pre_schema_backups(dir: &Path, keep_latest: usize) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<(u64, std::path::PathBuf)> = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if let Some(rest) = name.strip_prefix("mynote-pre-schema-v") {
                if let Some(ver_s) = rest.strip_suffix(".db") {
                    if let Ok(ver) = ver_s.parse::<u64>() {
                        entries.push((ver, p));
                    }
                }
            }
        }
    }
    if entries.len() <= keep_latest {
        return;
    }
    entries.sort_by_key(|a| std::cmp::Reverse(a.0));
    for (_, old_path) in entries.into_iter().skip(keep_latest) {
        let _ = std::fs::remove_file(old_path);
    }
}
