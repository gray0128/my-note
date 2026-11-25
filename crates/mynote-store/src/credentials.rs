//! Device sync credential & OS Keychain / Secret Service abstraction (`docs/threat-model.md` §2.3, D5′).
//!
//! Because macOS and Omarchy unify on a single `mynote` binary (D5′), only one binary accesses
//! the OS credential store (macOS Keychain via `security` / Linux Secret Service via `secret-tool`).
//! Headless sessions, CI, and isolated custom `--data-dir` instances cleanly use `0600` atomic files.

use mynote_core::error::{CoreError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::{Command, Stdio};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DeviceCredentials {
    pub sync_url: String,
    pub device_token: String,
    pub scope: String,
}

impl std::fmt::Debug for DeviceCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCredentials")
            .field("sync_url", &self.sync_url)
            .field("device_token", &"<redacted>")
            .field("scope", &self.scope)
            .finish()
    }
}

#[cfg(target_os = "linux")]
fn command_in_path(bin: &str) -> bool {
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if std::fs::metadata(&candidate).is_ok_and(|m| m.permissions().mode() & 0o111 != 0) {
                    return true;
                }
            }
            #[cfg(not(unix))]
            {
                return true;
            }
        }
    }
    false
}

fn should_use_os_keychain(data_dir: &Path) -> bool {
    if let Ok(mode) = std::env::var("MYNOTE_KEYCHAIN") {
        return mode.eq_ignore_ascii_case("os");
    }
    // Never touch the host OS keychain for temporary, CI, or explicit test data directories.
    let s = data_dir.to_string_lossy();
    if s.starts_with("/tmp/")
        || s.contains("/.tmp")
        || data_dir.starts_with(std::env::temp_dir())
        || std::env::var("MYNOTE_DATA_DIR").is_ok()
        || std::env::var("CI").is_ok()
    {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        Path::new("/usr/bin/security").exists()
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("DBUS_SESSION_BUS_ADDRESS").is_ok() && command_in_path("secret-tool")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

fn keychain_account(data_dir: &Path) -> String {
    let hash = blake3::hash(data_dir.to_string_lossy().as_bytes());
    format!("mynote-{}", &hash.to_hex()[..16])
}

#[cfg(target_os = "macos")]
fn os_store_secret(service: &str, account: &str, payload: &str) -> bool {
    use std::io::Write;
    // Pass secret via `security -i` stdin with `-X <hex>` so the device token NEVER appears in `ps` argv.
    // Guard against `security -i`'s 4096-byte line buffer cap and unsafe characters in service/account.
    if service.contains(char::is_whitespace) || account.contains(char::is_whitespace) {
        return false;
    }
    let hex_payload: String = payload.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let cmd = format!("add-generic-password -U -s {service} -a {account} -X {hex_payload}\n");
    if cmd.len() >= 3900 {
        return false;
    }
    let Ok(mut child) = Command::new("/usr/bin/security")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(cmd.as_bytes()).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return false;
        }
    }
    child.wait().is_ok_and(|s| s.success())
}

/// Decodes secret output from OS keychain tools; handles macOS `security find-generic-password -w`
/// hex-encoding secrets that contain newlines or non-ASCII bytes.
#[allow(dead_code)]
fn decode_keychain_secret(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed.starts_with('{')
        && trimmed.len().is_multiple_of(2)
        && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
    {
        let mut bytes = Vec::with_capacity(trimmed.len() / 2);
        for chunk in trimmed.as_bytes().as_chunks::<2>().0 {
            let s = std::str::from_utf8(chunk).ok()?;
            bytes.push(u8::from_str_radix(s, 16).ok()?);
        }
        if let Ok(decoded) = String::from_utf8(bytes) {
            return Some(decoded);
        }
    }
    Some(trimmed.to_string())
}

#[cfg(target_os = "macos")]
fn os_load_secret(service: &str, account: &str) -> Option<String> {
    let out = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", service, "-a", account, "-w"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let raw = String::from_utf8(out.stdout).ok()?;
    decode_keychain_secret(&raw)
}

#[cfg(target_os = "linux")]
fn os_store_secret(service: &str, account: &str, payload: &str) -> bool {
    use std::io::Write;
    let Ok(mut child) = Command::new("secret-tool")
        .args([
            "store",
            "--label",
            "my-note sync credentials",
            "service",
            service,
            "account",
            account,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(payload.as_bytes());
    }
    child.wait().is_ok_and(|s| s.success())
}

#[cfg(target_os = "linux")]
fn os_load_secret(service: &str, account: &str) -> Option<String> {
    let out = Command::new("secret-tool")
        .args(["lookup", "service", service, "account", account])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let trimmed = s.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn os_store_secret(_service: &str, _account: &str, _payload: &str) -> bool {
    false
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn os_load_secret(_service: &str, _account: &str) -> Option<String> {
    None
}

/// Atomically create a `0600` secret file (zero world-readable TOCTOU window), fsync, and rename into place.
pub fn write_atomic_0600(path: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(|e| {
        CoreError::new(
            ErrorCode::IntegrityError,
            format!("OS CSPRNG failure creating temp file: {e}"),
            "Check OS entropy source",
        )
    })?;
    let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let base_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "secret".to_string());
    let tmp = parent.join(format!(".{base_name}.{}.{suffix}.tmp", std::process::id()));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp).map_err(|e| {
        CoreError::new(
            ErrorCode::IntegrityError,
            format!("failed creating '{}': {e}", tmp.display()),
            "Verify data directory permissions",
        )
    })?;
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&tmp);
        return Err(CoreError::new(
            ErrorCode::IntegrityError,
            format!("failed writing '{}': {e}", path.display()),
            "Verify disk space and data directory permissions",
        ));
    }
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                format!("failed setting 0600 on '{}': {e}", tmp.display()),
                "Verify data directory permissions",
            ));
        }
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        CoreError::new(
            ErrorCode::IntegrityError,
            format!("failed renaming '{}': {e}", path.display()),
            "Verify data directory permissions",
        )
    })?;
    Ok(())
}

pub fn save_device_credentials(data_dir: &Path, creds: &DeviceCredentials) -> Result<(), CoreError> {
    // Compact single-line JSON avoids macOS `security find-generic-password -w` hex-encoding multiline secrets.
    let json = serde_json::to_string(creds)
        .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "serialize credentials"))?;
    let fallback_path = data_dir.join("device_credentials.local.json");
    if should_use_os_keychain(data_dir) {
        let acct = keychain_account(data_dir);
        if os_store_secret("mynote.device_credentials", &acct, &json) {
            if fallback_path.exists() {
                let _ = std::fs::remove_file(&fallback_path);
            }
            return Ok(());
        }
    }
    write_atomic_0600(&fallback_path, json.as_bytes())
}

pub fn load_device_credentials(data_dir: &Path) -> Result<Option<DeviceCredentials>, CoreError> {
    if should_use_os_keychain(data_dir) {
        let acct = keychain_account(data_dir);
        if let Some(raw) = os_load_secret("mynote.device_credentials", &acct) {
            let parsed: DeviceCredentials = serde_json::from_str(&raw).map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("corrupt OS keychain credentials: {e}"),
                    "Re-bootstrap or re-pair device",
                )
            })?;
            return Ok(Some(parsed));
        }
    }
    let path = data_dir.join("device_credentials.local.json");
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        CoreError::new(
            ErrorCode::IntegrityError,
            format!("cannot read credentials file: {e}"),
            "Check file permissions on device_credentials.local.json",
        )
    })?;
    let parsed: DeviceCredentials = serde_json::from_str(&raw).map_err(|e| {
        CoreError::new(
            ErrorCode::IntegrityError,
            format!("corrupt credentials file: {e}"),
            "Re-bootstrap or re-pair device",
        )
    })?;
    Ok(Some(parsed))
}

/// Best-effort Time Machine exclusion on macOS (`docs/threat-model.md` §3.5).
pub fn exclude_from_os_backups(data_dir: &Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("/usr/bin/tmutil")
            .arg("addexclusion")
            .arg(data_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = data_dir;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_keychain_secret_handles_plain_and_macos_hex_json() {
        let plain =
            r#"{"sync_url":"https://note.example.com","device_token":"mnt_abc","scope":"read-write"}"#;
        assert_eq!(decode_keychain_secret(plain).as_deref(), Some(plain));

        let multiline = "{\n  \"sync_url\": \"https://note.example.com\",\n  \"device_token\": \"mnt_abc\",\n  \"scope\": \"read-write\"\n}";
        let hex_encoded: String = multiline.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(decode_keychain_secret(&hex_encoded).as_deref(), Some(multiline));
    }
}
