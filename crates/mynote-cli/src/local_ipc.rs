//! Cross-platform `LocalIpc` single-writer NDJSON protocol (`docs/interface-contracts.md` §3.0 & §3.3,
//! `docs/threat-model.md` §10.1, `SEC-WIN-PIPE`, D9).
//!
//! - Unix (`macOS` / `Omarchy Linux`): `0600` Unix Domain Socket (`daemon.sock`) inside `0700`
//!   owner-verified directory, with deterministic SHA-256 fallback under macOS `104 B` `sun_path`.
//! - Windows: Named Pipe `\\.\pipe\mynote-<blake3_16(canonical_data_dir)>` bound with
//!   `first_pipe_instance(true)` on the initial server instance, `reject_remote_clients(true)`,
//!   and explicit `SECURITY_ATTRIBUTES` + SDDL `D:P(A;;GA;;;OW)` (current user `TokenUser` owner,
//!   stripping `Everyone` / `Anonymous` / `Authenticated Users`).

use mynote_core::error::{CoreError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Canonical SDDL specified by D9 / `SEC-WIN-PIPE`: Protected DACL (`D:P`) granting
/// `GENERIC_ALL` (`GA`) exclusively to Owner Rights (`OW`, `S-1-3-4`), stripping inherited
/// and default `Everyone` (`WD`) / `Anonymous` (`AN`) / `Network` (`NU`) ACEs.
pub const PIPE_OWNER_ONLY_SDDL: &str = "D:P(A;;GA;;;OW)";

/// Broad trustees that MUST NOT appear in a hardened local Named Pipe or NTFS DACL.
pub const FORBIDDEN_DACL_TRUSTEES: &[&str] = &[
    "WD",       // Everyone (S-1-1-0)
    "S-1-1-0",  // Everyone numeric SID
    "AN",       // Anonymous Logon (S-1-5-7)
    "S-1-5-7",  // Anonymous numeric SID
    "NU",       // Network (S-1-5-2)
    "S-1-5-2",  // Network numeric SID
    "AU",       // Authenticated Users (S-1-5-11)
    "S-1-5-11", // Authenticated Users numeric SID
    "BU",       // BUILTIN\Users (S-1-5-32-545)
    "S-1-5-32-545",
    "BG", // Built-in Guests (S-1-5-32-546)
    "S-1-5-32-546",
];

#[cfg(unix)]
pub fn current_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    if let Ok(uid_s) = std::env::var("UID") {
        if let Ok(u) = uid_s.parse::<u32>() {
            return u;
        }
    }
    if let Ok(meta) = std::fs::metadata("/proc/self") {
        return meta.uid();
    }
    if let Some(home) = std::env::var_os("HOME") {
        if let Ok(meta) = std::fs::metadata(home) {
            return meta.uid();
        }
    }
    0
}

pub fn socket_path_for(data_dir: &Path) -> PathBuf {
    // Keep socket inside explicit / test data dirs for hermetic multi-instance isolation.
    let s = data_dir.to_string_lossy();
    let is_custom = std::env::var("MYNOTE_DATA_DIR").is_ok()
        || s.starts_with("/tmp/")
        || s.contains("/.tmp")
        || data_dir.starts_with(std::env::temp_dir());
    let candidate = if !is_custom {
        #[cfg(target_os = "linux")]
        {
            if let Ok(xdg_rt) = std::env::var("XDG_RUNTIME_DIR") {
                if !xdg_rt.trim().is_empty() {
                    PathBuf::from(xdg_rt).join("mynote").join("daemon.sock")
                } else {
                    data_dir.join("daemon.sock")
                }
            } else {
                data_dir.join("daemon.sock")
            }
        }
        #[cfg(target_os = "macos")]
        {
            data_dir.join("run").join("daemon.sock")
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            data_dir.join("daemon.sock")
        }
    } else {
        data_dir.join("daemon.sock")
    };

    // macOS sockaddr_un.sun_path is strictly 104 bytes (Linux 108); deterministically hash long paths
    // into a UID-scoped private directory (`0700`) so deep data dirs never hit ENAMETOOLONG or /tmp squatting.
    if candidate.as_os_str().len() >= 96 {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(data_dir.to_string_lossy().as_bytes());
        let digest = h.finalize();
        let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        #[cfg(unix)]
        {
            if let Ok(xdg_rt) = std::env::var("XDG_RUNTIME_DIR") {
                let xdg = xdg_rt.trim();
                if !xdg.is_empty() && xdg.len() < 64 {
                    return PathBuf::from(xdg).join("mn").join(format!("{hex}.sock"));
                }
            }
            return PathBuf::from("/tmp")
                .join(format!("mn-{}", current_uid()))
                .join(format!("{hex}.sock"));
        }
        #[cfg(not(unix))]
        {
            return std::env::temp_dir().join(format!("mn-{hex}.sock"));
        }
    }
    candidate
}

/// Resolve `data_dir` to a normalized canonical string even when `data_dir` itself has not been
/// created yet (resolving 8.3 short paths such as `RUNNER~1` via the nearest existing ancestor).
pub fn canonical_data_dir_key(data_dir: &Path) -> String {
    let abs = if data_dir.is_absolute() {
        data_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(data_dir))
            .unwrap_or_else(|_| data_dir.to_path_buf())
    };

    let resolved = if let Ok(canon) = std::fs::canonicalize(&abs) {
        canon
    } else {
        let mut cur = abs.as_path();
        let mut tail_parts = Vec::new();
        let mut base_canon = None;
        while let Some(parent) = cur.parent() {
            if let Some(name) = cur.file_name() {
                tail_parts.push(name.to_os_string());
            }
            if let Ok(c) = std::fs::canonicalize(parent) {
                base_canon = Some(c);
                break;
            }
            cur = parent;
        }
        if let Some(mut base) = base_canon {
            for part in tail_parts.into_iter().rev() {
                base.push(part);
            }
            base
        } else {
            abs
        }
    };

    let raw = resolved.to_string_lossy();
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    let trimmed = stripped.trim_end_matches(['/', '\\']);
    #[cfg(windows)]
    {
        trimmed.replace('/', "\\").to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        trimmed.to_string()
    }
}

/// Compute the deterministic Windows Named Pipe path `\\.\pipe\mynote-<blake3_16(canonical_data_dir)>`
/// (`docs/interface-contracts.md` §3.3).
pub fn pipe_name_for(data_dir: &Path) -> String {
    let key = canonical_data_dir_key(data_dir);
    let hash = blake3::hash(key.as_bytes());
    format!(r"\\.\pipe\mynote-{}", &hash.to_hex()[..16])
}

/// Parsed view of an SDDL string's DACL section (`D:<dacl_flags>(ace1)(ace2)...`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedDaclSummary {
    pub dacl_flags: String,
    pub is_protected: bool,
    pub aces: Vec<ParsedAce>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedAce {
    pub ace_type: String,
    pub ace_flags: String,
    pub rights: String,
    pub account_sid: String,
}

/// Extract and parse the `D:` DACL section from a full SDDL string (which may begin with `O:...G:...`).
pub fn parse_sddl_dacl(sddl: &str) -> Result<ParsedDaclSummary, String> {
    let d_pos = if sddl.starts_with("D:") {
        0
    } else if let Some(idx) = sddl.find("D:") {
        idx
    } else {
        return Err(format!("SDDL missing 'D:' DACL section: {sddl}"));
    };

    let after_d = &sddl[d_pos + 2..];
    let dacl_body = split_before_top_level_sacl(after_d);
    let first_paren = dacl_body.find('(').unwrap_or(dacl_body.len());
    let dacl_flags = dacl_body[..first_paren].to_string();
    let is_protected = dacl_flags.contains('P');

    let mut aces = Vec::new();
    let mut rest = &dacl_body[first_paren..];
    while !rest.is_empty() {
        if !rest.starts_with('(') {
            return Err(format!("unexpected trailing characters in DACL: {rest}"));
        }
        let close = rest
            .find(')')
            .ok_or_else(|| format!("unclosed ACE parenthesis in SDDL: {sddl}"))?;
        let inner = &rest[1..close];
        let fields: Vec<&str> = inner.split(';').collect();
        if fields.len() != 6 {
            return Err(format!(
                "expected 6 semicolon-separated fields in ACE '({inner})', got {}",
                fields.len()
            ));
        }
        aces.push(ParsedAce {
            ace_type: fields[0].to_string(),
            ace_flags: fields[1].to_string(),
            rights: fields[2].to_string(),
            account_sid: fields[5].to_string(),
        });
        rest = &rest[close + 1..];
    }

    Ok(ParsedDaclSummary {
        dacl_flags,
        is_protected,
        aces,
    })
}

fn split_before_top_level_sacl(s: &str) -> &str {
    let mut depth = 0usize;
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b'S' if depth == 0 && bytes.get(i + 1) == Some(&b':') => return &s[..i],
            _ => {}
        }
    }
    s
}

/// Verify that a kernel-readback SDDL string has a Protected DACL (`D:P`), zero forbidden broad
/// trustees (`WD` / `Everyone`, `AU`, `BU`, `AN`, `NU`, `BG`), and exclusively grants access to
/// one of `allowed_trustees` (e.g. `["OW"]` or `[current_user_sid]`).
pub fn verify_strict_pipe_sddl(sddl: &str, allowed_trustees: &[&str]) -> Result<ParsedDaclSummary, String> {
    let summary = parse_sddl_dacl(sddl)?;
    if !summary.is_protected {
        return Err(format!(
            "DACL is not marked Protected ('P'); flags='{}' in SDDL '{sddl}'",
            summary.dacl_flags
        ));
    }
    if summary.aces.is_empty() {
        return Err(format!("DACL contains zero ACEs in SDDL '{sddl}'"));
    }
    for ace in &summary.aces {
        for forbidden in FORBIDDEN_DACL_TRUSTEES {
            if ace.account_sid.eq_ignore_ascii_case(forbidden) {
                return Err(format!(
                    "forbidden broad trustee '{}' found in DACL of '{sddl}'",
                    ace.account_sid
                ));
            }
        }
        if ace.ace_type == "A"
            && !allowed_trustees
                .iter()
                .any(|allowed| ace.account_sid.eq_ignore_ascii_case(allowed))
        {
            return Err(format!(
                "unexpected allow ACE trustee '{}' (expected only {:?}) in '{sddl}'",
                ace.account_sid, allowed_trustees
            ));
        }
    }
    Ok(summary)
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
    PutVaultHeader {
        gen: i64,
        blob_b64: String,
    },
    LockBlockTier2 {
        id: String,
        op_id: String,
        key_id: String,
        mnb1_b64: String,
        mnw1_b64: String,
        expected_heads: Vec<String>,
        public_hint: Option<String>,
    },
    UnlockBlockTier1 {
        id: String,
        plaintext_content: String,
        expected_heads: Vec<String>,
        shred_old_key: bool,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum LocalIpcRequest {
    Ping,
    OpenTicket,
    Poke {
        fast_flush: bool,
    },
    SyncNow {
        wait: bool,
    },
    Apply {
        meta: ApplyMeta,
        request: ApplyRequest,
    },
    ClipUndo,
    ClipApply {
        clip_id: String,
    },
    ClipPoke {
        clip_id: Option<String>,
        cleared: bool,
    },
    ClipWatchSet {
        paused: Option<bool>,
        enabled: Option<bool>,
        auto_apply_mirror: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalIpcErrorPayload {
    pub code: String,
    pub message: String,
    pub hint: String,
    pub retryable: bool,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalIpcResponse {
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
    pub error: Option<LocalIpcErrorPayload>,
}

impl LocalIpcResponse {
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
            error: Some(LocalIpcErrorPayload {
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
            let code = serde_json::from_value::<ErrorCode>(serde_json::Value::String(e.code))
                .unwrap_or(ErrorCode::IntegrityError);
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

/// Send one NDJSON request to a running local Daemon over `LocalIpc` (`0600 daemon.sock` on Unix,
/// current-user SDDL Named Pipe on Windows).
/// Returns `Ok(None)` if no Daemon is currently listening (so CLI falls back to direct SQLite WAL).
#[cfg(unix)]
pub fn try_send_ipc(
    data_dir: &Path,
    req: &LocalIpcRequest,
    timeout: Duration,
) -> Result<Option<LocalIpcResponse>, CoreError> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

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
        .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "serialize IPC request"))?;
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
        if matches!(req, LocalIpcRequest::Apply { .. }) {
            return Err(CoreError::new(
                ErrorCode::SyncOffline,
                "daemon closed connection after receiving apply request; refusing blind SQLite fallback to prevent duplicate write",
                "Check local state and retry with --idempotency-key if needed",
            ));
        }
        return Ok(None);
    }
    let resp: LocalIpcResponse = serde_json::from_str(resp_line.trim()).map_err(|e| {
        CoreError::new(
            ErrorCode::IntegrityError,
            format!("invalid NDJSON response from daemon: {e}"),
            "Restart 'mynote daemon'",
        )
    })?;
    Ok(Some(resp))
}

#[cfg(windows)]
mod win_imp {
    use super::*;
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ptr;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::{
        GetLastError, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_BUSY,
        ERROR_SUCCESS, HANDLE, HLOCAL,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenOwner, TokenUser, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Pipes::{
        GetNamedPipeInfo, WaitNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_SERVER_END,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct LocalAllocGuard(*mut core::ffi::c_void);

    impl Drop for LocalAllocGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0 as HLOCAL);
                }
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct ProcessTokenSids {
        pub token_user_sid: String,
        pub token_owner_sid: String,
    }

    /// Query both `TokenUser` (`S-1-5-21-...`) and `TokenOwner` (which on UAC-elevated admin
    /// tokens may be `S-1-5-32-544` `BUILTIN\Administrators`) for the current process.
    pub fn query_current_process_sids() -> io::Result<ProcessTokenSids> {
        let mut raw_token: HANDLE = ptr::null_mut();
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
        let token_handle = token.as_raw_handle() as HANDLE;

        let token_user_sid = query_sid_class(token_handle, TokenUser, |buf| {
            let tu = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
            tu.User.Sid
        })?;
        let token_owner_sid = query_sid_class(token_handle, TokenOwner, |buf| {
            let to = unsafe { &*(buf.as_ptr() as *const TOKEN_OWNER) };
            to.Owner
        })?;

        Ok(ProcessTokenSids {
            token_user_sid,
            token_owner_sid,
        })
    }

    fn query_sid_class(
        token_handle: HANDLE,
        class: i32,
        extract: impl FnOnce(&[u8]) -> PSID,
    ) -> io::Result<String> {
        let mut needed = 0u32;
        unsafe {
            GetTokenInformation(token_handle, class, ptr::null_mut(), 0, &mut needed);
        }
        let err = unsafe { GetLastError() };
        if err != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        let mut buf = vec![0u8; needed as usize];
        let ok =
            unsafe { GetTokenInformation(token_handle, class, buf.as_mut_ptr().cast(), needed, &mut needed) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        sid_to_string(extract(&buf))
    }

    fn sid_to_string(sid: PSID) -> io::Result<String> {
        let mut wide_ptr: *mut u16 = ptr::null_mut();
        let ok = unsafe { ConvertSidToStringSidW(sid, &mut wide_ptr) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let _guard = LocalAllocGuard(wide_ptr.cast());
        Ok(unsafe { pwstr_to_string(wide_ptr) })
    }

    unsafe fn pwstr_to_string(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
        String::from_utf16_lossy(slice)
    }

    /// Create a `NamedPipeServer` bound with explicit `sddl`, `first_pipe_instance(first_instance)`,
    /// and `reject_remote_clients(true)`.
    pub fn create_hardened_pipe_server_with_sddl(
        pipe_name: &str,
        sddl: &str,
        first_instance: bool,
    ) -> io::Result<NamedPipeServer> {
        let sddl_utf16: Vec<u16> = sddl.encode_utf16().chain(core::iter::once(0)).collect();
        let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_utf16.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let _sd_guard = LocalAllocGuard(psd);

        let mut sa = SECURITY_ATTRIBUTES {
            nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd,
            bInheritHandle: 0,
        };

        let mut opts = ServerOptions::new();
        opts.first_pipe_instance(first_instance)
            .reject_remote_clients(true);

        unsafe {
            opts.create_with_security_attributes_raw(pipe_name, (&mut sa as *mut SECURITY_ATTRIBUTES).cast())
        }
    }

    /// Create the production `NamedPipeServer` for `pipe_name` using `PIPE_OWNER_ONLY_SDDL`
    /// (`D:P(A;;GA;;;OW)`) anchored to the current `TokenUser` SID as explicit Owner so even
    /// UAC-elevated sessions isolate strictly to the current user SID (`S-Win-1` §3.1).
    pub fn create_hardened_pipe_server(pipe_name: &str, first_instance: bool) -> io::Result<NamedPipeServer> {
        if let Ok(sids) = query_current_process_sids() {
            let user_owned_sddl = format!("O:{}{PIPE_OWNER_ONLY_SDDL}", sids.token_user_sid);
            if let Ok(srv) =
                create_hardened_pipe_server_with_sddl(pipe_name, &user_owned_sddl, first_instance)
            {
                return Ok(srv);
            }
        }
        create_hardened_pipe_server_with_sddl(pipe_name, PIPE_OWNER_ONLY_SDDL, first_instance)
    }

    #[derive(Clone, Debug)]
    pub struct KernelPipeSecurityReport {
        pub owner_and_dacl_sddl: String,
        pub dacl_only_sddl: String,
        pub owner_sid: String,
        pub pipe_flags: u32,
        pub is_server_end: bool,
        pub rejects_remote_clients: bool,
    }

    /// Read the live kernel Security Descriptor and Named Pipe flags back from `server` via
    /// `GetSecurityInfo` + `ConvertSecurityDescriptorToStringSecurityDescriptorW` + `GetNamedPipeInfo`.
    pub fn inspect_pipe_kernel_security(server: &NamedPipeServer) -> io::Result<KernelPipeSecurityReport> {
        let handle = server.as_raw_handle() as HANDLE;
        let mut owner_sid: PSID = ptr::null_mut();
        let mut dacl_ptr = ptr::null_mut();
        let mut sd_out: PSECURITY_DESCRIPTOR = ptr::null_mut();

        let rc = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner_sid,
                ptr::null_mut(),
                &mut dacl_ptr,
                ptr::null_mut(),
                &mut sd_out,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let _sd_guard = LocalAllocGuard(sd_out);

        let owner_sid_str = sid_to_string(owner_sid)?;
        let owner_and_dacl_sddl = sd_to_sddl(sd_out, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)?;
        let dacl_only_sddl = sd_to_sddl(sd_out, DACL_SECURITY_INFORMATION)?;

        let mut pipe_flags = 0u32;
        let info_ok = unsafe {
            GetNamedPipeInfo(
                handle,
                &mut pipe_flags,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if info_ok == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(KernelPipeSecurityReport {
            owner_and_dacl_sddl,
            dacl_only_sddl,
            owner_sid: owner_sid_str,
            pipe_flags,
            is_server_end: (pipe_flags & PIPE_SERVER_END) != 0,
            rejects_remote_clients: (pipe_flags & PIPE_REJECT_REMOTE_CLIENTS) != 0,
        })
    }

    fn sd_to_sddl(sd: PSECURITY_DESCRIPTOR, info_flags: u32) -> io::Result<String> {
        let mut wide_ptr: *mut u16 = ptr::null_mut();
        let mut wide_len = 0u32;
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                info_flags,
                &mut wide_ptr,
                &mut wide_len,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let _guard = LocalAllocGuard(wide_ptr.cast());
        Ok(unsafe { pwstr_to_string(wide_ptr) })
    }

    async fn exchange_pipe_ndjson(
        pipe_name: &str,
        req_line: &[u8],
        is_apply: bool,
    ) -> Result<Option<LocalIpcResponse>, CoreError> {
        let client = loop {
            match ClientOptions::new().open(pipe_name) {
                Ok(c) => break c,
                Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => return Ok(None),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(_) => return Ok(None),
            }
        };

        let (read_half, mut write_half) = tokio::io::split(client);
        if write_half.write_all(req_line).await.is_err() || write_half.flush().await.is_err() {
            return Ok(None);
        }

        let mut reader = BufReader::new(read_half);
        let mut resp_line = String::new();
        let n = reader.read_line(&mut resp_line).await.map_err(|e| {
            CoreError::new(
                ErrorCode::SyncOffline,
                format!("daemon named pipe read failed: {e}"),
                "Retry or restart 'mynote daemon'",
            )
        })?;
        if n == 0 {
            if is_apply {
                return Err(CoreError::new(
                    ErrorCode::SyncOffline,
                    "daemon closed connection after receiving apply request; refusing blind SQLite fallback to prevent duplicate write",
                    "Check local state and retry with --idempotency-key if needed",
                ));
            }
            return Ok(None);
        }

        let resp: LocalIpcResponse = serde_json::from_str(resp_line.trim()).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("invalid NDJSON response from daemon: {e}"),
                "Restart 'mynote daemon'",
            )
        })?;
        Ok(Some(resp))
    }

    pub fn try_send_ipc(
        data_dir: &Path,
        req: &LocalIpcRequest,
        timeout: Duration,
    ) -> Result<Option<LocalIpcResponse>, CoreError> {
        let pipe_name = pipe_name_for(data_dir);
        let pipe_w: Vec<u16> = pipe_name.encode_utf16().chain(core::iter::once(0)).collect();
        let probe_ok = unsafe { WaitNamedPipeW(pipe_w.as_ptr(), 1) };
        if probe_ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
        }

        let mut line = serde_json::to_string(req)
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "serialize IPC request"))?;
        line.push('\n');
        let line_bytes = line.into_bytes();
        let is_apply = matches!(req, LocalIpcRequest::Apply { .. });

        let run_exchange = move || -> Result<Option<LocalIpcResponse>, CoreError> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        format!("IPC tokio runtime failed: {e}"),
                        "Retry command",
                    )
                })?;
            rt.block_on(async move {
                match tokio::time::timeout(timeout, exchange_pipe_ndjson(&pipe_name, &line_bytes, is_apply))
                    .await
                {
                    Ok(res) => res,
                    Err(_) => Err(CoreError::new(
                        ErrorCode::SyncOffline,
                        format!("daemon named pipe timed out after {} ms", timeout.as_millis()),
                        "Retry or restart 'mynote daemon'",
                    )),
                }
            })
        };

        if tokio::runtime::Handle::try_current().is_ok() {
            std::thread::spawn(run_exchange).join().map_err(|_| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    "IPC client worker thread panicked",
                    "Retry command",
                )
            })?
        } else {
            run_exchange()
        }
    }
}

#[cfg(windows)]
pub use win_imp::*;

#[cfg(not(any(unix, windows)))]
pub fn try_send_ipc(
    _data_dir: &Path,
    _req: &LocalIpcRequest,
    _timeout: Duration,
) -> Result<Option<LocalIpcResponse>, CoreError> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_for_hashes_long_paths_under_macos_sun_len() {
        let deep = Path::new(
            "/var/folders/q2/p1t6rgxj5fj32g1dc7dmd49r0000gn/T/mynote_daemon_sync_sec05_1795589174499009000",
        );
        let sock = socket_path_for(deep);
        assert!(sock.as_os_str().len() < 100, "sock too long: {}", sock.display());
        assert_eq!(sock, socket_path_for(deep), "must be deterministic");
    }

    #[test]
    fn pipe_name_for_uses_blake3_16_prefix_and_is_deterministic() {
        let dir = std::env::temp_dir().join("mynote-pipe-hash-check");
        let pipe = pipe_name_for(&dir);
        assert!(
            pipe.starts_with(r"\\.\pipe\mynote-"),
            "unexpected pipe prefix: {pipe}"
        );
        let suffix = pipe.strip_prefix(r"\\.\pipe\mynote-").unwrap();
        assert_eq!(suffix.len(), 16, "expected 16 hex chars, got '{suffix}'");
        assert!(suffix.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(pipe, pipe_name_for(&dir));
    }

    #[test]
    fn pure_sddl_parser_rejects_everyone_and_accepts_owner_only() {
        let ok = verify_strict_pipe_sddl("O:BAD:P(A;;FA;;;OW)", &["OW"]).unwrap();
        assert!(ok.is_protected);
        assert_eq!(ok.aces.len(), 1);
        assert_eq!(ok.aces[0].account_sid, "OW");

        let ok_sid = verify_strict_pipe_sddl(
            "D:P(A;;GA;;;S-1-5-21-111-222-333-1001)",
            &["S-1-5-21-111-222-333-1001"],
        )
        .unwrap();
        assert_eq!(ok_sid.aces[0].account_sid, "S-1-5-21-111-222-333-1001");

        assert!(verify_strict_pipe_sddl("D:(A;;GA;;;OW)", &["OW"]).is_err());
        assert!(verify_strict_pipe_sddl("D:P(A;;GA;;;OW)(A;;GR;;;WD)", &["OW"]).is_err());
        assert!(verify_strict_pipe_sddl("D:P(A;;GA;;;AU)", &["OW"]).is_err());
    }
}
