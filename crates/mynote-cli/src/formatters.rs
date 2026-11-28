//! Combined Layer 1 (built-in Rust core) and Layer 2 (`formatters.toml`) external formatter
//! pipeline with strict timeout, zero-byte fuse, Windows minimal environment allowlist,
//! `.bat`/`.cmd` refusal (CVE-2024-24576), and `CREATE_NO_WINDOW | CREATE_SUSPENDED` with
//! Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) process-tree teardown
//! (`docs/interface-contracts.md` §2.4, `docs/threat-model.md` §10.1, `SEC-WIN-PIPE`).

use mynote_core::error::{CoreError, ErrorCode};
use mynote_core::format::format_snippet;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

const DEFAULT_TIMEOUT_MS: u64 = 2_000;

/// Minimal Windows system environment allowlist (`docs/interface-contracts.md` §2.4).
pub const WINDOWS_ENV_ALLOWLIST: &[&str] = &[
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "SYSTEMDRIVE",
    "PATH",
];

/// Forced UTF-8 / non-interactive defaults injected into child environments on Windows.
pub const WINDOWS_FORCED_ENV_DEFAULTS: &[(&str, &str)] = &[
    ("PYTHONUTF8", "1"),
    ("PYTHONIOENCODING", "utf-8"),
    ("POWERSHELL_TELEMETRY_OPTOUT", "1"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubprocessError {
    EmptyExecutable,
    BatchScriptForbidden(String),
    ExecutableNotFound(String),
    Win32Error {
        step: &'static str,
        code: i32,
        message: String,
    },
    TimedOut {
        timeout_ms: u64,
        child_pid: u32,
    },
    InvalidUtf8Output,
}

impl std::fmt::Display for SubprocessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyExecutable => write!(f, "executable path cannot be empty"),
            Self::BatchScriptForbidden(p) => {
                write!(
                    f,
                    "batch script / cmd.exe entry is forbidden (CVE-2024-24576): '{p}'"
                )
            }
            Self::ExecutableNotFound(p) => write!(f, "executable not found: '{p}'"),
            Self::Win32Error { step, code, message } => write!(f, "{step} failed (win32={code}): {message}"),
            Self::TimedOut {
                timeout_ms,
                child_pid,
            } => write!(f, "child pid {child_pid} timed out after {timeout_ms} ms"),
            Self::InvalidUtf8Output => write!(f, "child emitted non-UTF-8 stdout"),
        }
    }
}

impl std::error::Error for SubprocessError {}

/// Validate an executable target string, strictly rejecting `.bat`, `.cmd` (including Windows
/// trailing dots/spaces normalization like `evil.bat. `), and direct `cmd` / `cmd.exe` invocation.
pub fn validate_executable_target(program: &str) -> Result<(), SubprocessError> {
    let trimmed = program.trim().trim_end_matches([' ', '.']);
    if trimmed.is_empty() {
        return Err(SubprocessError::EmptyExecutable);
    }

    let file_name = trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed);
    let lower = file_name.to_ascii_lowercase();

    if lower.ends_with(".bat") || lower.ends_with(".cmd") || lower == "cmd" || lower == "cmd.exe" {
        return Err(SubprocessError::BatchScriptForbidden(program.to_string()));
    }
    Ok(())
}

/// Build the filtered, case-insensitively sorted Windows environment map from an iterator of
/// parent `(key, value)` pairs plus optional explicit `passthrough_keys`.
pub fn filter_windows_environment<'a>(
    parent_env: impl IntoIterator<Item = (String, String)>,
    passthrough_keys: &'a [&'a str],
) -> BTreeMap<String, String> {
    let mut selected: BTreeMap<String, (String, String)> = BTreeMap::new();

    for (k, v) in parent_env {
        if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
            continue;
        }
        let upper = k.to_ascii_uppercase();
        let allowed = WINDOWS_ENV_ALLOWLIST.iter().any(|w| *w == upper)
            || passthrough_keys.iter().any(|p| p.eq_ignore_ascii_case(&k));
        if allowed {
            selected.insert(upper, (k, v));
        }
    }

    for &(k, v) in WINDOWS_FORCED_ENV_DEFAULTS {
        selected.insert(k.to_ascii_uppercase(), (k.to_string(), v.to_string()));
    }

    let mut out = BTreeMap::new();
    for (_upper, (orig_k, val)) in selected {
        out.insert(orig_k, val);
    }
    out
}

/// Encode an environment map into a Win32 `CREATE_UNICODE_ENVIRONMENT` UTF-16 block
/// (`KEY1=VAL1\0KEY2=VAL2\0\0`, sorted case-insensitively by key name).
pub fn encode_unicode_environment_block(env_map: &BTreeMap<String, String>) -> Vec<u16> {
    let mut entries: Vec<(&str, &str)> = env_map.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    entries.sort_by(|(a, _), (b, _)| {
        a.to_ascii_uppercase()
            .cmp(&b.to_ascii_uppercase())
            .then_with(|| a.cmp(b))
    });

    let mut block = Vec::new();
    for (k, v) in entries {
        if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
            continue;
        }
        block.extend(k.encode_utf16());
        block.push(b'=' as u16);
        block.extend(v.encode_utf16());
        block.push(0);
    }
    block.push(0);
    if block.len() == 1 {
        block.push(0);
    }
    block
}

/// Quote a single Windows command-line argument following standard MSVCRT `CommandLineToArgvW` rules.
pub fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '"')) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(ch);
            }
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

/// Build a NUL-terminated mutable UTF-16 command line (`argv[0] argv[1] ...`) for `CreateProcessW`.
pub fn build_windows_command_line_utf16(program: &str, args: &[&str]) -> Vec<u16> {
    let mut line = quote_windows_arg(program);
    for arg in args {
        line.push(' ');
        line.push_str(&quote_windows_arg(arg));
    }
    line.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Normalize Windows `\r\n` (and text-mode CRT doubled `\r\r\n`, `S-Win-1` §3.3) line endings to
/// `\n` without disturbing UTF-8 content.
pub fn normalize_crlf(s: &str) -> String {
    let mut out = s.replace("\r\n", "\n");
    while out.contains("\r\n") {
        out = out.replace("\r\n", "\n");
    }
    out
}

#[derive(Clone, Debug, Deserialize)]
struct FormattersConfig {
    #[serde(default)]
    formatters: BTreeMap<String, ExternalFormatterSpec>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum CmdSpec {
    String(String),
    Array(Vec<String>),
}

#[derive(Clone, Debug, Deserialize)]
struct ExternalFormatterSpec {
    cmd: CmdSpec,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default = "default_timeout")]
    timeout_ms: u64,
    #[serde(default)]
    env_passthrough: Vec<String>,
}

impl ExternalFormatterSpec {
    fn resolve_command(&self) -> Result<(String, Vec<String>), CoreError> {
        let (prog, args) = match &self.cmd {
            CmdSpec::String(s) => (s.trim().to_string(), self.args.clone()),
            CmdSpec::Array(parts) => {
                let Some((first, rest)) = parts.split_first() else {
                    return Err(CoreError::new(
                        ErrorCode::FormatSyntaxError,
                        "external formatter 'cmd' array cannot be empty",
                        "Specify at least the executable in formatters.toml",
                    ));
                };
                let mut combined = rest.to_vec();
                combined.extend(self.args.iter().cloned());
                (first.trim().to_string(), combined)
            }
        };
        if prog.is_empty() {
            return Err(CoreError::new(
                ErrorCode::FormatSyntaxError,
                "external formatter 'cmd' executable cannot be blank",
                "Specify a non-empty command executable in formatters.toml",
            ));
        }
        Ok((prog, args))
    }
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_MS
}

pub fn config_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("MYNOTE_FORMATTERS_CONFIG") {
        if !explicit.trim().is_empty() {
            return Some(PathBuf::from(explicit));
        }
    }
    #[cfg(windows)]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            if !local_app_data.trim().is_empty() {
                return Some(
                    PathBuf::from(local_app_data)
                        .join("mynote")
                        .join("formatters.toml"),
                );
            }
        }
        if let Ok(user_profile) = std::env::var("USERPROFILE") {
            if !user_profile.trim().is_empty() {
                return Some(
                    PathBuf::from(user_profile)
                        .join("AppData")
                        .join("Local")
                        .join("mynote")
                        .join("formatters.toml"),
                );
            }
        }
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.trim().is_empty() {
                return Some(PathBuf::from(xdg).join("mynote").join("formatters.toml"));
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.trim().is_empty() {
                return Some(PathBuf::from(xdg).join("mynote").join("formatters.toml"));
            }
        }
        std::env::var("HOME").ok().map(|h| {
            PathBuf::from(h)
                .join(".config")
                .join("mynote")
                .join("formatters.toml")
        })
    }
}

fn load_external_spec(lang: &str) -> Result<Option<ExternalFormatterSpec>, CoreError> {
    let Some(path) = config_path() else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!("failed to read '{}': {e}", path.display()),
            "Check permissions and TOML syntax of formatters.toml",
        )
    })?;
    let cfg: FormattersConfig = toml::from_str(&raw).map_err(|e| {
        CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!("invalid formatters.toml: {e}"),
            "Fix TOML syntax in formatters.toml",
        )
    })?;
    Ok(cfg
        .formatters
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(lang))
        .map(|(_, v)| v.clone()))
}

/// Format snippet via Layer 1 built-in core, falling back to Layer 2 external formatter
/// ONLY when no `--action` is specified and a matching entry exists in `formatters.toml`.
pub fn format_content(input: &str, lang: &str, action: Option<&str>) -> Result<String, CoreError> {
    if action.is_none() {
        if let Some(spec) = load_external_spec(lang)? {
            return run_external_formatter(&spec, input);
        }
    }
    format_snippet(input, lang, action)
}

#[cfg(not(windows))]
fn run_external_formatter(spec: &ExternalFormatterSpec, input: &str) -> Result<String, CoreError> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    let (prog, args) = spec.resolve_command()?;
    let mut cmd = Command::new(&prog);
    cmd.args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    cmd.env("LC_ALL", "C.UTF-8");
    for key in &spec.env_passthrough {
        if let Ok(val) = std::env::var(key) {
            cmd.env(key, val);
        }
    }

    let mut child = cmd.spawn().map_err(|e| {
        CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!("failed to spawn external formatter '{prog}': {e}"),
            "Verify the formatter binary exists on PATH in ~/.config/mynote/formatters.toml",
        )
    })?;

    if let Some(mut stdin) = child.stdin.take() {
        let bytes = input.as_bytes().to_vec();
        thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
    }

    let mut stdout_pipe = child.stdout.take();
    let stdout_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = stdout_pipe.take() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });

    let mut stderr_pipe = child.stderr.take();
    let stderr_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = stderr_pipe.take() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });

    let deadline = Instant::now() + Duration::from_millis(spec.timeout_ms.max(50));
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CoreError::new(
                        ErrorCode::FormatSyntaxError,
                        format!(
                            "external formatter '{prog}' timed out after {} ms",
                            spec.timeout_ms
                        ),
                        "Original block left untouched; check input or increase timeout_ms",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(CoreError::new(
                    ErrorCode::FormatSyntaxError,
                    format!("error waiting on formatter '{prog}': {e}"),
                    "Original block left untouched",
                ));
            }
        }
    };

    let stdout_bytes = stdout_handle.join().unwrap_or_default();
    let stderr_bytes = stderr_handle.join().unwrap_or_default();

    if !status.success() {
        let stderr_str = String::from_utf8_lossy(&stderr_bytes);
        return Err(CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!(
                "external formatter '{prog}' exited with {status}: {}",
                stderr_str.trim()
            ),
            "Fix input syntax; original block was NOT modified",
        ));
    }

    if !input.is_empty() && stdout_bytes.is_empty() {
        return Err(CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!("external formatter '{prog}' returned 0 bytes for non-empty input"),
            "Refusing to overwrite block with empty output; inspect formatter configuration",
        ));
    }

    String::from_utf8(stdout_bytes).map_err(|_| {
        CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!("external formatter '{prog}' emitted non-UTF-8 output"),
            "Original block left untouched",
        )
    })
}

#[cfg(windows)]
mod win_proc {
    use super::*;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::thread;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, STILL_ACTIVE, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, OpenProcess, ResumeThread, TerminateProcess, WaitForSingleObject,
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, STARTF_USESTDHANDLES, STARTUPINFOW,
    };

    /// Resolve an executable to an explicit `.exe` / `.com` path, refusing `.bat` / `.cmd` even if
    /// an un-extensioned command name would have matched a `.bat` / `.cmd` script on `PATH`.
    pub fn resolve_safe_windows_executable(program: &str) -> Result<PathBuf, SubprocessError> {
        validate_executable_target(program)?;
        let p = Path::new(program);

        if p.components().count() > 1 || p.is_absolute() {
            if p.is_file() {
                validate_resolved_extension(p)?;
                return Ok(p.to_path_buf());
            }
            if p.extension().is_none() {
                let with_exe = p.with_extension("exe");
                if with_exe.is_file() {
                    return Ok(with_exe);
                }
            }
            return Err(SubprocessError::ExecutableNotFound(program.to_string()));
        }

        let path_var = std::env::var_os("PATH").unwrap_or_default();
        for dir in std::env::split_paths(&path_var) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            if p.extension().is_some() {
                let cand = dir.join(p);
                if cand.is_file() {
                    validate_resolved_extension(&cand)?;
                    return Ok(cand);
                }
            } else {
                let exe_cand = dir.join(format!("{program}.exe"));
                if exe_cand.is_file() {
                    return Ok(exe_cand);
                }
                for bad_ext in ["bat", "cmd"] {
                    let bad_cand = dir.join(format!("{program}.{bad_ext}"));
                    if bad_cand.is_file() {
                        return Err(SubprocessError::BatchScriptForbidden(
                            bad_cand.display().to_string(),
                        ));
                    }
                }
            }
        }
        Err(SubprocessError::ExecutableNotFound(program.to_string()))
    }

    fn validate_resolved_extension(path: &Path) -> Result<(), SubprocessError> {
        validate_executable_target(&path.to_string_lossy())?;
        let ext = path
            .extension()
            .and_then(OsStr::to_str)
            .map(|s| s.to_ascii_lowercase());
        match ext.as_deref() {
            Some("exe" | "com") => Ok(()),
            Some("bat" | "cmd") => Err(SubprocessError::BatchScriptForbidden(path.display().to_string())),
            _ => Err(SubprocessError::BatchScriptForbidden(format!(
                "only .exe/.com binaries may be spawned directly on Windows: '{}'",
                path.display()
            ))),
        }
    }

    fn win32_last_err(step: &'static str) -> SubprocessError {
        let err = io::Error::last_os_error();
        SubprocessError::Win32Error {
            step,
            code: err.raw_os_error().unwrap_or(-1),
            message: err.to_string(),
        }
    }

    fn create_stdio_pipe(child_reads: bool) -> Result<(OwnedHandle, OwnedHandle), SubprocessError> {
        let sa = SECURITY_ATTRIBUTES {
            nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: 1,
        };
        let mut r_raw: HANDLE = ptr::null_mut();
        let mut w_raw: HANDLE = ptr::null_mut();
        let ok = unsafe { CreatePipe(&mut r_raw, &mut w_raw, &sa, 0) };
        if ok == 0 {
            return Err(win32_last_err("CreatePipe"));
        }
        let read_h = unsafe { OwnedHandle::from_raw_handle(r_raw) };
        let write_h = unsafe { OwnedHandle::from_raw_handle(w_raw) };

        let parent_raw = if child_reads {
            write_h.as_raw_handle() as HANDLE
        } else {
            read_h.as_raw_handle() as HANDLE
        };
        let ok_inh = unsafe { SetHandleInformation(parent_raw, HANDLE_FLAG_INHERIT, 0) };
        if ok_inh == 0 {
            return Err(win32_last_err("SetHandleInformation(HANDLE_FLAG_INHERIT=0)"));
        }
        Ok((read_h, write_h))
    }

    /// Create a Job Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
    pub fn create_kill_on_close_job() -> Result<OwnedHandle, SubprocessError> {
        let job_raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if job_raw.is_null() {
            return Err(win32_last_err("CreateJobObjectW"));
        }
        let job = unsafe { OwnedHandle::from_raw_handle(job_raw) };

        let info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                ..Default::default()
            },
            ..Default::default()
        };

        let ok = unsafe {
            SetInformationJobObject(
                job.as_raw_handle() as HANDLE,
                JobObjectExtendedLimitInformation,
                ptr::from_ref(&info).cast(),
                core::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(win32_last_err(
                "SetInformationJobObject(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)",
            ));
        }
        Ok(job)
    }

    /// Running hardened child bound to a `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` Job Object.
    /// `job` is declared FIRST so dropping `HardenedChild` closes the Job handle first and
    /// immediately triggers kernel teardown of the entire descendant process tree.
    pub struct HardenedChild {
        pub job: OwnedHandle,
        pub process: OwnedHandle,
        pub pid: u32,
        pub stdin: Option<File>,
        pub stdout: Option<File>,
        pub stderr: Option<File>,
    }

    /// Spawn a Windows child process with:
    /// 1. Strict `.bat` / `.cmd` rejection + `.exe` resolution;
    /// 2. Minimal Windows system environment allowlist + `PYTHONUTF8=1`;
    /// 3. `CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT`;
    /// 4. `AssignProcessToJobObject` BEFORE `ResumeThread` (zero escape race window).
    pub fn spawn_hardened_windows_child(
        program: &str,
        args: &[&str],
        passthrough_env: &[&str],
    ) -> Result<HardenedChild, SubprocessError> {
        let exe_path = resolve_safe_windows_executable(program)?;
        let exe_str = exe_path.to_string_lossy();
        let app_utf16: Vec<u16> = exe_str.encode_utf16().chain(core::iter::once(0)).collect();
        let mut cmdline_utf16 = build_windows_command_line_utf16(&exe_str, args);

        let parent_pairs =
            std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)));
        let filtered_env = filter_windows_environment(parent_pairs, passthrough_env);
        let env_block = encode_unicode_environment_block(&filtered_env);

        let job = create_kill_on_close_job()?;
        let (stdin_r, stdin_w) = create_stdio_pipe(true)?;
        let (stdout_r, stdout_w) = create_stdio_pipe(false)?;
        let (stderr_r, stderr_w) = create_stdio_pipe(false)?;

        let si = STARTUPINFOW {
            cb: core::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: stdin_r.as_raw_handle() as HANDLE,
            hStdOutput: stdout_w.as_raw_handle() as HANDLE,
            hStdError: stderr_w.as_raw_handle() as HANDLE,
            ..Default::default()
        };

        let mut pi = PROCESS_INFORMATION::default();
        let created = unsafe {
            CreateProcessW(
                app_utf16.as_ptr(),
                cmdline_utf16.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                env_block.as_ptr().cast(),
                ptr::null(),
                &si,
                &mut pi,
            )
        };
        if created == 0 {
            return Err(win32_last_err("CreateProcessW"));
        }

        let proc_handle = unsafe { OwnedHandle::from_raw_handle(pi.hProcess) };
        let thread_handle = unsafe { OwnedHandle::from_raw_handle(pi.hThread) };

        drop(stdin_r);
        drop(stdout_w);
        drop(stderr_w);

        let assigned = unsafe {
            AssignProcessToJobObject(
                job.as_raw_handle() as HANDLE,
                proc_handle.as_raw_handle() as HANDLE,
            )
        };
        if assigned == 0 {
            let err = win32_last_err("AssignProcessToJobObject");
            unsafe {
                let _ = TerminateProcess(proc_handle.as_raw_handle() as HANDLE, 1);
            }
            return Err(err);
        }

        let prev_suspend_count = unsafe { ResumeThread(thread_handle.as_raw_handle() as HANDLE) };
        if prev_suspend_count == u32::MAX {
            return Err(win32_last_err("ResumeThread"));
        }
        drop(thread_handle);

        Ok(HardenedChild {
            job,
            process: proc_handle,
            pid: pi.dwProcessId,
            stdin: Some(File::from(stdin_w)),
            stdout: Some(File::from(stdout_r)),
            stderr: Some(File::from(stderr_r)),
        })
    }

    #[derive(Clone, Debug)]
    pub struct SubprocessOutput {
        pub exit_code: u32,
        pub stdout: String,
        pub stderr: String,
        pub elapsed: Duration,
    }

    /// Run a oneshot hardened child to completion with UTF-8 `stdin -> stdout` and strict timeout.
    /// On timeout, drops the Job Object handle (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) to kill the
    /// entire child + grandchild process tree immediately.
    pub fn run_hardened_oneshot(
        program: &str,
        args: &[&str],
        stdin_utf8: &str,
        passthrough_env: &[&str],
        timeout: Duration,
    ) -> Result<SubprocessOutput, SubprocessError> {
        let t0 = Instant::now();
        let mut child = spawn_hardened_windows_child(program, args, passthrough_env)?;
        let pid = child.pid;

        if let Some(mut sin) = child.stdin.take() {
            let input_bytes = stdin_utf8.as_bytes().to_vec();
            thread::spawn(move || {
                let _ = sin.write_all(&input_bytes);
                let _ = sin.flush();
            });
        }

        let mut sout = child.stdout.take().unwrap();
        let out_join = thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = sout.read_to_end(&mut buf);
            buf
        });

        let mut serr = child.stderr.take().unwrap();
        let err_join = thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = serr.read_to_end(&mut buf);
            buf
        });

        let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        let wait_rc = unsafe { WaitForSingleObject(child.process.as_raw_handle() as HANDLE, timeout_ms) };
        if wait_rc == WAIT_TIMEOUT {
            drop(child.job);
            let _ = unsafe { WaitForSingleObject(child.process.as_raw_handle() as HANDLE, 2_000) };
            let _ = out_join.join();
            let _ = err_join.join();
            return Err(SubprocessError::TimedOut {
                timeout_ms: timeout.as_millis() as u64,
                child_pid: pid,
            });
        }
        if wait_rc != WAIT_OBJECT_0 {
            return Err(win32_last_err("WaitForSingleObject"));
        }

        let mut exit_code = 0u32;
        let ok_ec = unsafe { GetExitCodeProcess(child.process.as_raw_handle() as HANDLE, &mut exit_code) };
        if ok_ec == 0 {
            return Err(win32_last_err("GetExitCodeProcess"));
        }

        let stdout_bytes = out_join.join().unwrap_or_default();
        let stderr_bytes = err_join.join().unwrap_or_default();
        let elapsed = t0.elapsed();

        let stdout_raw = String::from_utf8(stdout_bytes).map_err(|_| SubprocessError::InvalidUtf8Output)?;
        let stderr = normalize_crlf(&String::from_utf8_lossy(&stderr_bytes));

        Ok(SubprocessOutput {
            exit_code,
            stdout: normalize_crlf(&stdout_raw),
            stderr,
            elapsed,
        })
    }

    /// Open a synchronization + query handle to `pid` to observe liveness/termination without PID reuse ambiguity.
    pub fn open_process_observer(pid: u32) -> io::Result<OwnedHandle> {
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, 0, pid) };
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(h) })
    }

    pub fn is_process_handle_alive(proc_handle: &OwnedHandle) -> bool {
        let h = proc_handle.as_raw_handle() as HANDLE;
        let wait_rc = unsafe { WaitForSingleObject(h, 0) };
        if wait_rc == WAIT_OBJECT_0 {
            return false;
        }
        let mut code = 0u32;
        let ok = unsafe { GetExitCodeProcess(h, &mut code) };
        ok != 0 && code == (STILL_ACTIVE as u32)
    }

    pub fn wait_process_terminated(proc_handle: &OwnedHandle, timeout: Duration) -> Result<Duration, String> {
        let t0 = Instant::now();
        let ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        let rc = unsafe { WaitForSingleObject(proc_handle.as_raw_handle() as HANDLE, ms) };
        if rc == WAIT_OBJECT_0 {
            Ok(t0.elapsed())
        } else {
            Err(format!("WaitForSingleObject returned {rc} after {ms} ms"))
        }
    }
}

#[cfg(windows)]
pub use win_proc::*;

#[cfg(windows)]
fn run_external_formatter(spec: &ExternalFormatterSpec, input: &str) -> Result<String, CoreError> {
    use std::time::Duration;

    let (prog, args) = spec.resolve_command()?;
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let pass_refs: Vec<&str> = spec.env_passthrough.iter().map(String::as_str).collect();
    let timeout = Duration::from_millis(spec.timeout_ms.max(50));

    let out = run_hardened_oneshot(&prog, &arg_refs, input, &pass_refs, timeout).map_err(|err| match err {
        SubprocessError::BatchScriptForbidden(ref msg) => CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!("refusing unsafe Windows batch formatter '{prog}': {msg}"),
            "Configure a direct .exe binary (such as python.exe, node.exe, or pwsh.exe) in formatters.toml instead of .bat/.cmd",
        ),
        SubprocessError::TimedOut { timeout_ms, .. } => CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!("external formatter '{prog}' timed out after {timeout_ms} ms"),
            "Original block left untouched; check input or increase timeout_ms",
        ),
        SubprocessError::InvalidUtf8Output => CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!("external formatter '{prog}' emitted non-UTF-8 output"),
            "Original block left untouched",
        ),
        other => CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!("failed to run external formatter '{prog}': {other}"),
            "Verify the formatter .exe binary exists on PATH in %LOCALAPPDATA%\\mynote\\formatters.toml",
        ),
    })?;

    if out.exit_code != 0 {
        return Err(CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!(
                "external formatter '{prog}' exited with code {}: {}",
                out.exit_code,
                out.stderr.trim()
            ),
            "Fix input syntax; original block was NOT modified",
        ));
    }

    if !input.is_empty() && out.stdout.is_empty() {
        return Err(CoreError::new(
            ErrorCode::FormatSyntaxError,
            format!("external formatter '{prog}' returned 0 bytes for non-empty input"),
            "Refusing to overwrite block with empty output; inspect formatter configuration",
        ));
    }

    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_script_and_cmd_exe_targets_are_rejected() {
        for bad in [
            "formatter.bat",
            "FORMATTER.CMD",
            r"C:\tools\run.bat",
            "evil.bat. ",
            "evil.cmd...",
            "cmd",
            "cmd.exe",
            r"C:\Windows\System32\cmd.exe",
        ] {
            let err = validate_executable_target(bad).unwrap_err();
            assert!(
                matches!(err, SubprocessError::BatchScriptForbidden(_)),
                "expected BatchScriptForbidden for '{bad}', got {err:?}"
            );
        }

        assert_eq!(
            validate_executable_target("   "),
            Err(SubprocessError::EmptyExecutable)
        );
        assert!(validate_executable_target("python").is_ok());
        assert!(validate_executable_target("python.exe").is_ok());
        assert!(validate_executable_target(r"C:\Program Files\Python312\python.exe").is_ok());
    }

    #[test]
    fn minimal_env_allowlist_strips_secrets_and_injects_utf8_defaults() {
        let parent = vec![
            ("SystemRoot".to_string(), r"C:\Windows".to_string()),
            ("Path".to_string(), r"C:\Windows\System32".to_string()),
            ("PYTHONUTF8".to_string(), "0".to_string()),
            ("MYNOTE_SMK_SECRET".to_string(), "never-leak-me".to_string()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "leaked".to_string()),
            (
                "CUSTOM_PLUGIN_TOKEN".to_string(),
                "allowed-explicitly".to_string(),
            ),
        ];
        let filtered = filter_windows_environment(parent, &["CUSTOM_PLUGIN_TOKEN"]);
        assert_eq!(
            filtered.get("SystemRoot").map(String::as_str),
            Some(r"C:\Windows")
        );
        assert_eq!(
            filtered.get("Path").map(String::as_str),
            Some(r"C:\Windows\System32")
        );
        assert_eq!(filtered.get("PYTHONUTF8").map(String::as_str), Some("1"));
        assert_eq!(
            filtered.get("PYTHONIOENCODING").map(String::as_str),
            Some("utf-8")
        );
        assert_eq!(
            filtered.get("POWERSHELL_TELEMETRY_OPTOUT").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            filtered.get("CUSTOM_PLUGIN_TOKEN").map(String::as_str),
            Some("allowed-explicitly")
        );
        assert!(!filtered.contains_key("MYNOTE_SMK_SECRET"));
        assert!(!filtered.contains_key("AWS_SECRET_ACCESS_KEY"));

        let block = encode_unicode_environment_block(&filtered);
        assert!(block.ends_with(&[0, 0]));
    }

    #[test]
    fn windows_cmdline_quoting_and_crlf_normalization() {
        assert_eq!(quote_windows_arg("plain"), "plain");
        assert_eq!(quote_windows_arg("hello world"), "\"hello world\"");
        assert_eq!(quote_windows_arg(r#"a"b"#), r#""a\"b""#);
        assert_eq!(
            quote_windows_arg(r#"C:\dir with space\"#),
            r#""C:\dir with space\\""#
        );
        assert_eq!(normalize_crlf("a\r\nb\r\r\nc\n"), "a\nb\nc\n");
    }
}
