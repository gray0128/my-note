//! Local `0600` Unix Domain Socket NDJSON IPC protocol (`docs/interface-contracts.md` §3.3).
//!
//! When `mynote daemon` is running, CLI write commands route through `apply` frames so SQLite
//! maintains a single writer and connected Web UI clients receive `< 20 ms` live WebSocket updates.

use mynote_core::error::{CoreError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

pub fn socket_path_for(data_dir: &Path) -> PathBuf {
    // Keep socket inside explicit / test data dirs for hermetic multi-instance isolation.
    let s = data_dir.to_string_lossy();
    let is_custom = std::env::var("MYNOTE_DATA_DIR").is_ok() || s.starts_with("/tmp/") || s.contains("/.tmp");
    if !is_custom {
        #[cfg(target_os = "linux")]
        if let Ok(xdg_rt) = std::env::var("XDG_RUNTIME_DIR") {
            if !xdg_rt.trim().is_empty() {
                return PathBuf::from(xdg_rt).join("mynote").join("daemon.sock");
            }
        }
        #[cfg(target_os = "macos")]
        {
            return data_dir.join("run").join("daemon.sock");
        }
    }
    data_dir.join("daemon.sock")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplyMeta {
    pub actor: String,
    pub idempotency_key: Option<String>,
    pub allow_empty: bool,
    pub force: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ApplyRequest {
    AddBlock {
        buffer: String,
        content: String,
        lang: Option<String>,
        after_id: Option<String>,
    },
    UpdateBlock {
        id: String,
        content: String,
        expected_heads: Vec<String>,
    },
    AppendBlock {
        id: String,
        text: String,
        expected_heads: Vec<String>,
    },
    MoveBlock {
        id: String,
        to_buf: Option<String>,
        after_id: Option<String>,
        before_id: Option<String>,
        lang: Option<String>,
    },
    ResolveBlock {
        id: String,
        expected_heads: Vec<String>,
        content: Option<String>,
        keep_op_id: Option<String>,
    },
    RevertBlock {
        id: String,
        to_op: Option<String>,
        undo_actor: Option<String>,
    },
    DeleteBlock {
        id: String,
        expected_heads: Vec<String>,
        dry_run: bool,
    },
    CreateBuffer {
        name: String,
        after: Option<String>,
    },
    RenameBuffer {
        buf: String,
        new_name: String,
    },
    DeleteBuffer {
        buf: String,
    },
    RestoreTrash {
        id: String,
    },
    ImportHeynote {
        path: String,
        buf: Option<String>,
        dry_run: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum UdsRequest {
    Ping,
    OpenTicket,
    Poke { fast_flush: bool },
    SyncNow { wait: bool },
    Apply { meta: ApplyMeta, request: ApplyRequest },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UdsErrorPayload {
    pub code: String,
    pub message: String,
    pub hint: String,
    pub retryable: bool,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UdsResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_seq: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_ops: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<UdsErrorPayload>,
}

impl UdsResponse {
    pub fn from_core_error(err: &CoreError) -> Self {
        Self {
            ok: false,
            version: None,
            pid: None,
            port: None,
            url: None,
            head_seq: None,
            sync_state: None,
            pending_ops: None,
            data: None,
            error: Some(UdsErrorPayload {
                code: err.code().as_str().to_string(),
                message: err.message().to_string(),
                hint: err.hint().to_string(),
                retryable: err.code().retryable(),
                details: err.details().cloned(),
            }),
        }
    }

    pub fn into_core_error(self) -> CoreError {
        if let Some(e) = self.error {
            let code = match e.code.as_str() {
                "INVALID_ARGUMENT" => ErrorCode::InvalidArgument,
                "EMPTY_STDIN_REFUSED" => ErrorCode::EmptyStdinRefused,
                "INTERACTION_REQUIRED" => ErrorCode::InteractionRequired,
                "UI_CONFIRMATION_REQUIRED" => ErrorCode::UiConfirmationRequired,
                "NOT_FOUND" => ErrorCode::NotFound,
                "IN_TRASH" => ErrorCode::InTrash,
                "HEAD_MISMATCH" => ErrorCode::HeadMismatch,
                "CONFLICT_PRESENT" => ErrorCode::ConflictPresent,
                "CAS_MISMATCH" => ErrorCode::CasMismatch,
                "BLOCK_LOCKED" => ErrorCode::BlockLocked,
                "KEY_SHREDDED" => ErrorCode::KeyShredded,
                "KEY_UNKNOWN" => ErrorCode::KeyUnknown,
                "AUTH_REQUIRED" => ErrorCode::AuthRequired,
                "DEVICE_REVOKED" => ErrorCode::DeviceRevoked,
                "TOKEN_SCOPE_FORBIDDEN" => ErrorCode::TokenScopeForbidden,
                "SYNC_OFFLINE" => ErrorCode::SyncOffline,
                "RATE_LIMITED" => ErrorCode::RateLimited,
                "FORMAT_SYNTAX_ERROR" => ErrorCode::FormatSyntaxError,
                "KEY_MISSING" => ErrorCode::KeyMissing,
                _ => ErrorCode::IntegrityError,
            };
            let mut ce = CoreError::new(code, e.message, e.hint);
            if let Some(d) = e.details {
                ce = ce.with_details(d);
            }
            ce
        } else {
            CoreError::new(
                ErrorCode::IntegrityError,
                "daemon returned error response without payload",
                "Check daemon logs",
            )
        }
    }
}

/// Send one NDJSON request to a running local Daemon over `0600 daemon.sock`.
/// Returns `Ok(None)` if no Daemon is currently listening (so CLI falls back to direct SQLite WAL).
#[cfg(unix)]
pub fn try_send_uds(
    data_dir: &Path,
    req: &UdsRequest,
    timeout: Duration,
) -> Result<Option<UdsResponse>, CoreError> {
    let sock_path = socket_path_for(data_dir);
    if !sock_path.exists() {
        return Ok(None);
    }
    let mut stream = match UnixStream::connect(&sock_path) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut line = serde_json::to_string(req)
        .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "serialize UDS request"))?;
    line.push('\n');
    if stream.write_all(line.as_bytes()).is_err() || stream.flush().is_err() {
        return Ok(None);
    }
    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    let n = reader.read_line(&mut resp_line).map_err(|e| {
        CoreError::new(
            ErrorCode::SyncOffline,
            format!("daemon socket read failed: {e}"),
            "Retry or restart 'mynote daemon'",
        )
    })?;
    if n == 0 {
        return Ok(None);
    }
    let resp: UdsResponse = serde_json::from_str(resp_line.trim()).map_err(|e| {
        CoreError::new(
            ErrorCode::IntegrityError,
            format!("invalid NDJSON response from daemon: {e}"),
            "Restart 'mynote daemon'",
        )
    })?;
    Ok(Some(resp))
}

#[cfg(not(unix))]
pub fn try_send_uds(
    _data_dir: &Path,
    _req: &UdsRequest,
    _timeout: Duration,
) -> Result<Option<UdsResponse>, CoreError> {
    Ok(None)
}
