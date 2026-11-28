//! Device sync credential, OS Keychain / Secret Service / Windows Credential Manager + DPAPI,
//! and cross-platform private file / NTFS user-only DACL primitives
//! (`docs/threat-model.md` §2.3 & §10.1, `docs/data-structures.md` §4.1, D5′ / D9).
//!
//! - macOS: Keychain via `/usr/bin/security -i` (`0600` atomic fallback for isolated/CI dirs).
//! - Omarchy Linux: Secret Service via `secret-tool` (`0600` atomic fallback for isolated/CI dirs).
//! - Windows: Credential Manager (`CredWriteW` / `CredReadW` / `CredDeleteW`, UTF-16LE blob) when
//!   `should_use_os_keychain` is active, plus user-scoped DPAPI (`CryptProtectData` /
//!   `CryptUnprotectData` with `CRYPTPROTECT_UI_FORBIDDEN`) AND current-user-only protected NTFS
//!   DACL (`SetNamedSecurityInfoW`) on isolated/fallback secret files.

use mynote_core::error::{CoreError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "linux"))]
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

#[cfg(windows)]
#[derive(Serialize, Deserialize)]
struct DpapiEnvelope {
    v: u8,
    dpapi_b64: String,
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
    let lower = s.to_ascii_lowercase();
    let is_ephemeral_or_override = s.starts_with("/tmp/")
        || s.contains("/.tmp")
        || lower.contains("\\appdata\\local\\temp\\")
        || lower.contains("/appdata/local/temp/")
        || data_dir.starts_with(std::env::temp_dir())
        || std::env::var("MYNOTE_DATA_DIR").is_ok()
        || std::env::var("CI").is_ok();
    #[cfg(target_os = "macos")]
    {
        !is_ephemeral_or_override && Path::new("/usr/bin/security").exists()
    }
    #[cfg(target_os = "linux")]
    {
        !is_ephemeral_or_override
            && std::env::var("DBUS_SESSION_BUS_ADDRESS").is_ok()
            && command_in_path("secret-tool")
    }
    #[cfg(windows)]
    {
        !is_ephemeral_or_override
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = is_ephemeral_or_override;
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

#[cfg(windows)]
mod win_sec {
    use super::*;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ptr;
    use windows_sys::Win32::Foundation::{
        GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_FOUND, ERROR_SUCCESS, HANDLE, HLOCAL,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
        CRED_TYPE_GENERIC,
    };
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use zeroize::Zeroizing;

    /// Maximum credential blob size accepted by `CredWriteW` (`CRED_MAX_CREDENTIAL_BLOB_SIZE`).
    const MAX_CRED_BLOB_BYTES: usize = 5 * 512;

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

    struct CredFreeGuard(*mut CREDENTIALW);

    impl Drop for CredFreeGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CredFree(self.0.cast());
                }
            }
        }
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

    /// Query the current process `TokenUser` SID string (`S-1-5-21-...`).
    pub fn query_current_user_sid() -> io::Result<String> {
        let mut raw_token: HANDLE = ptr::null_mut();
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
        let token_handle = token.as_raw_handle() as HANDLE;

        let mut needed = 0u32;
        unsafe {
            GetTokenInformation(token_handle, TokenUser, ptr::null_mut(), 0, &mut needed);
        }
        let err = unsafe { GetLastError() };
        if err != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        let mut buf = vec![0u8; needed as usize];
        let ok2 = unsafe {
            GetTokenInformation(
                token_handle,
                TokenUser,
                buf.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        if ok2 == 0 {
            return Err(io::Error::last_os_error());
        }
        let tu = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
        let mut wide_ptr: *mut u16 = ptr::null_mut();
        let ok_sid = unsafe { ConvertSidToStringSidW(tu.User.Sid, &mut wide_ptr) };
        if ok_sid == 0 {
            return Err(io::Error::last_os_error());
        }
        let _guard = LocalAllocGuard(wide_ptr.cast());
        Ok(unsafe { pwstr_to_string(wide_ptr) })
    }

    /// Apply a Protected NTFS DACL granting Full Access (`FA`) exclusively to the current user
    /// `TokenUser` SID (`D:P(A;OICI;FA;;;<SID>)` on directories, `D:P(A;;FA;;;<SID>)` on files),
    /// stripping inherited `Everyone` / `BUILTIN\Users` / `Authenticated Users` ACEs.
    pub fn apply_windows_private_acl(path: &Path, is_dir: bool) -> Result<(), CoreError> {
        let trustee = query_current_user_sid().unwrap_or_else(|_| "OW".to_string());
        let sddl = if is_dir {
            format!("D:P(A;OICI;FA;;;{trustee})")
        } else {
            format!("D:P(A;;FA;;;{trustee})")
        };
        let sddl_w: Vec<u16> = sddl.encode_utf16().chain(core::iter::once(0)).collect();
        let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let ok_sd = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                ptr::null_mut(),
            )
        };
        if ok_sd == 0 {
            let e = io::Error::last_os_error();
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                format!("ConvertStringSecurityDescriptor('{sddl}') failed: {e}"),
                "Verify Windows security subsystem",
            ));
        }
        let _sd_guard = LocalAllocGuard(psd);

        let mut dacl_present = 0i32;
        let mut dacl_ptr: *mut ACL = ptr::null_mut();
        let mut dacl_defaulted = 0i32;
        let ok_dacl =
            unsafe { GetSecurityDescriptorDacl(psd, &mut dacl_present, &mut dacl_ptr, &mut dacl_defaulted) };
        if ok_dacl == 0 || dacl_present == 0 || dacl_ptr.is_null() {
            let e = io::Error::last_os_error();
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                format!("GetSecurityDescriptorDacl failed: {e}"),
                "Verify Windows security descriptor",
            ));
        }

        let path_w: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(core::iter::once(0))
            .collect();
        let rc = unsafe {
            SetNamedSecurityInfoW(
                path_w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl_ptr,
                ptr::null_mut(),
            )
        };
        if rc != ERROR_SUCCESS {
            let e = io::Error::from_raw_os_error(rc as i32);
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                format!("SetNamedSecurityInfoW('{}') failed: {e}", path.display()),
                "Verify ownership and NTFS ACL support on data directory",
            ));
        }
        Ok(())
    }

    /// Read back the kernel NTFS Owner + DACL SDDL string for `path` via `GetNamedSecurityInfoW`.
    pub fn inspect_windows_file_dacl_sddl(path: &Path) -> Result<String, CoreError> {
        let path_w: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(core::iter::once(0))
            .collect();
        let mut owner_sid: PSID = ptr::null_mut();
        let mut dacl_ptr: *mut ACL = ptr::null_mut();
        let mut sd_out: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let rc = unsafe {
            GetNamedSecurityInfoW(
                path_w.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner_sid,
                ptr::null_mut(),
                &mut dacl_ptr,
                ptr::null_mut(),
                &mut sd_out,
            )
        };
        if rc != ERROR_SUCCESS {
            let e = io::Error::from_raw_os_error(rc as i32);
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                format!("GetNamedSecurityInfoW('{}') failed: {e}", path.display()),
                "Verify file exists and is readable",
            ));
        }
        let _sd_guard = LocalAllocGuard(sd_out);

        let mut wide_ptr: *mut u16 = ptr::null_mut();
        let mut wide_len = 0u32;
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd_out,
                SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut wide_ptr,
                &mut wide_len,
            )
        };
        if ok == 0 {
            let e = io::Error::last_os_error();
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                format!("ConvertSecurityDescriptorToStringSecurityDescriptorW failed: {e}"),
                "Verify security descriptor",
            ));
        }
        let _str_guard = LocalAllocGuard(wide_ptr.cast());
        Ok(unsafe { pwstr_to_string(wide_ptr) })
    }

    fn cred_target_utf16(service: &str, account: &str) -> Vec<u16> {
        format!("{service}:{account}")
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect()
    }

    /// Store a UTF-16LE secret blob in Windows Credential Manager (`CredWriteW`).
    pub fn win_cred_write(service: &str, account: &str, payload: &str) -> bool {
        let mut target_w = cred_target_utf16(service, account);
        let mut user_w: Vec<u16> = account.encode_utf16().chain(core::iter::once(0)).collect();
        let mut utf16_bytes = Zeroizing::new(Vec::with_capacity(payload.len() * 2));
        for unit in payload.encode_utf16() {
            utf16_bytes.extend_from_slice(&unit.to_le_bytes());
        }
        if utf16_bytes.len() > MAX_CRED_BLOB_BYTES {
            return false;
        }

        let cred = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target_w.as_mut_ptr(),
            Comment: ptr::null_mut(),
            LastWritten: Default::default(),
            CredentialBlobSize: utf16_bytes.len() as u32,
            CredentialBlob: utf16_bytes.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: ptr::null_mut(),
            TargetAlias: ptr::null_mut(),
            UserName: user_w.as_mut_ptr(),
        };
        unsafe { CredWriteW(&cred, 0) != 0 }
    }

    /// Read a UTF-16LE secret blob from Windows Credential Manager (`CredReadW`).
    pub fn win_cred_read(service: &str, account: &str) -> Option<Zeroizing<String>> {
        let target_w = cred_target_utf16(service, account);
        let mut cred_ptr: *mut CREDENTIALW = ptr::null_mut();
        let ok = unsafe { CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred_ptr) };
        if ok == 0 || cred_ptr.is_null() {
            return None;
        }
        let _guard = CredFreeGuard(cred_ptr);
        let cred = unsafe { &*cred_ptr };
        if cred.CredentialBlob.is_null() || cred.CredentialBlobSize == 0 {
            return None;
        }
        let raw_slice =
            unsafe { core::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize) };
        if raw_slice.len().is_multiple_of(2) {
            let mut units = Zeroizing::new(Vec::with_capacity(raw_slice.len() / 2));
            for &chunk in raw_slice.as_chunks::<2>().0 {
                units.push(u16::from_le_bytes(chunk));
            }
            if let Ok(s) = String::from_utf16(&units) {
                return Some(Zeroizing::new(s));
            }
        }
        std::str::from_utf8(raw_slice)
            .ok()
            .map(|s| Zeroizing::new(s.to_string()))
    }

    /// Delete a credential from Windows Credential Manager (`CredDeleteW`).
    pub fn win_cred_delete(service: &str, account: &str) -> bool {
        let target_w = cred_target_utf16(service, account);
        let ok = unsafe { CredDeleteW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if ok != 0 {
            return true;
        }
        unsafe { GetLastError() == ERROR_NOT_FOUND }
    }

    /// Protect bytes under the current Windows user's DPAPI key (`CryptProtectData` +
    /// `CRYPTPROTECT_UI_FORBIDDEN`).
    pub fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
        let desc_w: Vec<u16> = "mynote-credentials"
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        let ok = unsafe {
            CryptProtectData(
                &in_blob,
                desc_w.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ok == 0 || out_blob.pbData.is_null() {
            let e = io::Error::last_os_error();
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                format!("CryptProtectData failed: {e}"),
                "Verify Windows user profile DPAPI availability",
            ));
        }
        let _guard = LocalAllocGuard(out_blob.pbData.cast());
        let slice = unsafe { core::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
        Ok(slice.to_vec())
    }

    /// Unprotect bytes previously sealed with `dpapi_protect` (`CryptUnprotectData` +
    /// `CRYPTPROTECT_UI_FORBIDDEN`), zeroizing the Win32 output buffer before `LocalFree`.
    pub fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: ciphertext.len() as u32,
            pbData: ciphertext.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        let ok = unsafe {
            CryptUnprotectData(
                &in_blob,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ok == 0 || out_blob.pbData.is_null() {
            let e = io::Error::last_os_error();
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                format!("CryptUnprotectData failed: {e}"),
                "Re-bootstrap or re-pair device under the current Windows user account",
            ));
        }
        let _guard = LocalAllocGuard(out_blob.pbData.cast());
        let len = out_blob.cbData as usize;
        let mut out = Zeroizing::new(vec![0u8; len]);
        unsafe {
            ptr::copy_nonoverlapping(out_blob.pbData, out.as_mut_ptr(), len);
            for i in 0..len {
                ptr::write_volatile(out_blob.pbData.add(i), 0);
            }
        }
        Ok(out)
    }
}

#[cfg(windows)]
pub use win_sec::*;

#[cfg(windows)]
fn os_store_secret(service: &str, account: &str, payload: &str) -> bool {
    win_cred_write(service, account, payload)
}

#[cfg(windows)]
fn os_load_secret(service: &str, account: &str) -> Option<String> {
    win_cred_read(service, account).map(|z| (*z).clone())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn os_store_secret(_service: &str, _account: &str, _payload: &str) -> bool {
    false
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn os_load_secret(_service: &str, _account: &str) -> Option<String> {
    None
}

/// Atomically create a private secret file (`0600` on Unix, current-user-only NTFS DACL on Windows),
/// fsync, and rename into place.
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
    #[cfg(windows)]
    {
        if let Err(e) = apply_windows_private_acl(&tmp, false) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
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
    let json =
        zeroize::Zeroizing::new(serde_json::to_string(creds).map_err(|e| {
            CoreError::new(ErrorCode::IntegrityError, e.to_string(), "serialize credentials")
        })?);
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
    #[cfg(windows)]
    {
        use base64::Engine;
        if let Ok(sealed) = dpapi_protect(json.as_bytes()) {
            let env = DpapiEnvelope {
                v: 1,
                dpapi_b64: base64::engine::general_purpose::STANDARD.encode(sealed),
            };
            let env_bytes = serde_json::to_vec(&env).map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    e.to_string(),
                    "serialize DPAPI envelope",
                )
            })?;
            return write_atomic_0600(&fallback_path, &env_bytes);
        }
    }
    write_atomic_0600(&fallback_path, json.as_bytes())
}

pub fn load_device_credentials(data_dir: &Path) -> Result<Option<DeviceCredentials>, CoreError> {
    if should_use_os_keychain(data_dir) {
        let acct = keychain_account(data_dir);
        if let Some(raw) = os_load_secret("mynote.device_credentials", &acct) {
            let raw_z = zeroize::Zeroizing::new(raw);
            let parsed: DeviceCredentials = serde_json::from_str(&raw_z).map_err(|e| {
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
    let raw = zeroize::Zeroizing::new(std::fs::read_to_string(&path).map_err(|e| {
        CoreError::new(
            ErrorCode::IntegrityError,
            format!("cannot read credentials file: {e}"),
            "Check file permissions on device_credentials.local.json",
        )
    })?);
    #[cfg(windows)]
    {
        use base64::Engine;
        if let Ok(env) = serde_json::from_str::<DpapiEnvelope>(&raw) {
            let ct = base64::engine::general_purpose::STANDARD
                .decode(&env.dpapi_b64)
                .map_err(|e| {
                    CoreError::new(
                        ErrorCode::IntegrityError,
                        format!("corrupt DPAPI base64 credentials: {e}"),
                        "Re-bootstrap or re-pair device",
                    )
                })?;
            let plain = dpapi_unprotect(&ct)?;
            let parsed: DeviceCredentials = serde_json::from_slice(&plain).map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("corrupt DPAPI credentials payload: {e}"),
                    "Re-bootstrap or re-pair device",
                )
            })?;
            return Ok(Some(parsed));
        }
    }
    let parsed: DeviceCredentials = serde_json::from_str(&raw).map_err(|e| {
        CoreError::new(
            ErrorCode::IntegrityError,
            format!("corrupt credentials file: {e}"),
            "Re-bootstrap or re-pair device",
        )
    })?;
    Ok(Some(parsed))
}

/// Remove stored device credentials from both the OS credential manager and local fallback file.
pub fn delete_device_credentials(data_dir: &Path) {
    if should_use_os_keychain(data_dir) {
        let acct = keychain_account(data_dir);
        #[cfg(windows)]
        {
            let _ = win_cred_delete("mynote.device_credentials", &acct);
        }
        #[cfg(not(windows))]
        {
            let _ = acct;
        }
    }
    let fallback_path = data_dir.join("device_credentials.local.json");
    if fallback_path.exists() {
        let _ = std::fs::remove_file(&fallback_path);
    }
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
