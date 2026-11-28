//! Windows subprocess hardening primitive (`docs/interface-contracts.md` §2.4,
//! `docs/threat-model.md` §10.1, `SEC-WIN-PIPE`):
//! - `.bat` / `.cmd` / `cmd.exe` batch-script rejection (CVE-2024-24576 / BatBadBut defense);
//! - Minimal Windows environment allowlist (`SYSTEMROOT` etc.) + `PYTHONUTF8=1`;
//! - `CREATE_NO_WINDOW | CREATE_SUSPENDED` -> `CreateJobObjectW` (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`)
//!   -> `AssignProcessToJobObject` -> `ResumeThread`, guaranteeing 0 orphan grandchild processes;
//! - UTF-8 Chinese / Emoji `stdin -> stdout` roundtrip.

use std::collections::BTreeMap;

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
    // Windows Win32 path normalization strips trailing spaces and dots!
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
    // Store keyed by ASCII-uppercase name while preserving canonical key casing in value tuple.
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
        selected
            .entry(k.to_ascii_uppercase())
            .or_insert_with(|| (k.to_string(), v.to_string()));
    }

    // Flatten preserving sorted order by uppercase key (required by Windows CreateProcessW).
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
        // Empty environment block still requires double-NUL `\0\0`.
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

/// Normalize Windows `\r\n` line endings to `\n` without disturbing UTF-8 content.
pub fn normalize_crlf(s: &str) -> String {
    s.replace("\r\n", "\n")
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::{self, BufRead, BufReader, Read, Write};
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
        CreateProcessW, GetExitCodeProcess, OpenProcess, ResumeThread, WaitForSingleObject, CREATE_NO_WINDOW,
        CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, STARTF_USESTDHANDLES, STARTUPINFOW,
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

        // Search PATH strictly for exact match (if `.exe`/`.com`) or `<program>.exe` — never `.bat`/`.cmd`
        // and never the current working directory (`NoDefaultCurrentDirectoryInExePath`).
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
                // Check if a `.bat` or `.cmd` precedes `.exe` in the same directory or exists alone:
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

    /// Create an anonymous pipe where ONLY the child end is inheritable (`HANDLE_FLAG_INHERIT = 0`
    /// on the parent end so child/grandchild processes never hold parent pipe handles open).
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
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
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
    /// Dropping `job` (or `HardenedChild` itself) immediately triggers kernel teardown of the
    /// entire descendant process tree.
    pub struct HardenedChild {
        pub pid: u32,
        pub job: OwnedHandle,
        pub process: OwnedHandle,
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
                1, // bInheritHandles = TRUE (only child pipe ends have HANDLE_FLAG_INHERIT)
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

        // Immediately wrap process & thread handles in RAII so early return closes & kills via job.
        let proc_handle = unsafe { OwnedHandle::from_raw_handle(pi.hProcess) };
        let thread_handle = unsafe { OwnedHandle::from_raw_handle(pi.hThread) };

        // Close child-side pipe handles in the parent immediately.
        drop(stdin_r);
        drop(stdout_w);
        drop(stderr_w);

        // Bind to Job Object WHILE primary thread is still suspended!
        let assigned = unsafe {
            AssignProcessToJobObject(
                job.as_raw_handle() as HANDLE,
                proc_handle.as_raw_handle() as HANDLE,
            )
        };
        if assigned == 0 {
            let err = win32_last_err("AssignProcessToJobObject");
            // Explicitly drop job before returning if assignment failed (terminate process directly).
            unsafe {
                let _ = windows_sys::Win32::System::Threading::TerminateProcess(
                    proc_handle.as_raw_handle() as HANDLE,
                    1,
                );
            }
            return Err(err);
        }

        let prev_suspend_count = unsafe { ResumeThread(thread_handle.as_raw_handle() as HANDLE) };
        if prev_suspend_count == u32::MAX {
            return Err(win32_last_err("ResumeThread"));
        }
        drop(thread_handle);

        let stdin_file = File::from(stdin_w);
        let stdout_file = File::from(stdout_r);
        let stderr_file = File::from(stderr_r);

        Ok(HardenedChild {
            pid: pi.dwProcessId,
            job,
            process: proc_handle,
            stdin: Some(stdin_file),
            stdout: Some(stdout_file),
            stderr: Some(stderr_file),
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
            // Closing the Job Object handle triggers kernel JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE!
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

    /// Open a synchronization + query handle to `pid` so we can verify whether it is alive and wait
    /// on its exact kernel process object without PID-reuse ambiguity.
    pub fn open_process_observer(pid: u32) -> io::Result<OwnedHandle> {
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, 0, pid) };
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(h) })
    }

    /// Check whether an observed `OwnedHandle` process is currently alive (`WAIT_TIMEOUT` and
    /// `GetExitCodeProcess == STILL_ACTIVE`).
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

    /// Wait up to `timeout` for `proc_handle` to terminate and return exact elapsed wait duration.
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

    /// Spawn a `python` or `powershell` child that spawns a long-lived `ping.exe` grandchild,
    /// prove BOTH child and grandchild are alive, close the Job handle, and prove BOTH terminate
    /// immediately (`0` orphans).
    pub fn verify_job_object_kills_grandchild_tree() -> Result<(u32, u32, Duration), String> {
        // Prefer python if on PATH (fast ~40 ms startup), falling back to powershell.exe.
        let use_python = resolve_safe_windows_executable("python").is_ok();
        let mut child = if use_python {
            spawn_hardened_windows_child(
                "python",
                &[
                    "-u",
                    "-c",
                    "import subprocess, sys, time; p = subprocess.Popen(['ping.exe', '-n', '60', '127.0.0.1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); print(f'GRANDCHILD_PID={p.pid}', flush=True); time.sleep(60)",
                ],
                &[],
            )
            .map_err(|e| e.to_string())?
        } else {
            spawn_hardened_windows_child(
                "powershell",
                &[
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "$p = Start-Process -FilePath 'ping.exe' -ArgumentList '-n','60','127.0.0.1' -WindowStyle Hidden -PassThru; [Console]::Out.WriteLine(\"GRANDCHILD_PID=$($p.Id)\"); [Console]::Out.Flush(); Start-Sleep -Seconds 60",
                ],
                &[],
            )
            .map_err(|e| e.to_string())?
        };

        let child_pid = child.pid;
        drop(child.stdin.take());

        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("failed reading GRANDCHILD_PID line: {e}"))?;
        let gc_pid: u32 = line
            .trim()
            .strip_prefix("GRANDCHILD_PID=")
            .ok_or_else(|| format!("unexpected child output line: '{line}'"))?
            .parse()
            .map_err(|e| format!("invalid grandchild PID in '{line}': {e}"))?;

        let gc_observer = open_process_observer(gc_pid)
            .map_err(|e| format!("OpenProcess(grandchild {gc_pid}) failed: {e}"))?;

        assert!(
            is_process_handle_alive(&child.process),
            "child {child_pid} must be alive before Job close"
        );
        assert!(
            is_process_handle_alive(&gc_observer),
            "grandchild {gc_pid} must be alive before Job close"
        );

        // Trigger kernel JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE by closing the Job handle!
        let kill_t0 = Instant::now();
        let HardenedChild {
            job,
            process: child_proc,
            ..
        } = child;
        drop(job);

        let _child_wait = wait_process_terminated(&child_proc, Duration::from_secs(2))?;
        let _gc_wait = wait_process_terminated(&gc_observer, Duration::from_secs(2))?;
        let total_kill_elapsed = kill_t0.elapsed();

        assert!(
            !is_process_handle_alive(&child_proc),
            "child {child_pid} must be dead after Job close"
        );
        assert!(
            !is_process_handle_alive(&gc_observer),
            "grandchild {gc_pid} must be dead after Job close (0 orphans)"
        );

        Ok((child_pid, gc_pid, total_kill_elapsed))
    }
}

#[cfg(windows)]
pub use imp::*;

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
            ("MYNOTE_SMK_SECRET".to_string(), "never-leak-me".to_string()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), " leaked ".to_string()),
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
            filtered.get("CUSTOM_PLUGIN_TOKEN").map(String::as_str),
            Some("allowed-explicitly")
        );
        assert!(!filtered.contains_key("MYNOTE_SMK_SECRET"));
        assert!(!filtered.contains_key("AWS_SECRET_ACCESS_KEY"));

        let block = encode_unicode_environment_block(&filtered);
        assert!(
            block.ends_with(&[0, 0]),
            "unicode env block must end with double NUL"
        );
    }

    #[test]
    fn windows_cmdline_quoting_preserves_spaces_quotes_and_backslashes() {
        assert_eq!(quote_windows_arg("plain"), "plain");
        assert_eq!(quote_windows_arg("hello world"), "\"hello world\"");
        assert_eq!(quote_windows_arg(r#"a"b"#), r#""a\"b""#);
        assert_eq!(
            quote_windows_arg(r#"C:\dir with space\"#),
            r#""C:\dir with space\\""#
        );
    }

    #[cfg(windows)]
    #[test]
    fn win_subprocess_job_object_grandchild_kill_env_and_utf8_roundtrip() {
        // 1. Reject .bat / .cmd even before CreateProcessW, AND reject a real .bat file on disk
        let temp_bat = std::env::temp_dir().join(format!("mynote-spike-{}.bat", std::process::id()));
        std::fs::write(&temp_bat, "@echo off\r\necho pwned\r\n").unwrap();
        let bat_err = run_hardened_oneshot(
            &temp_bat.to_string_lossy(),
            &[],
            "",
            &[],
            std::time::Duration::from_secs(2),
        )
        .expect_err(".bat file must be rejected");
        let _ = std::fs::remove_file(&temp_bat);
        println!("[S-Win-1][PROC] .bat rejection verified: {bat_err}");
        assert!(matches!(bat_err, SubprocessError::BatchScriptForbidden(_)));

        // 2. Grandchild process tree teardown via CreateJobObjectW + JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        let (child_pid, gc_pid, kill_elapsed) =
            verify_job_object_kills_grandchild_tree().expect("Job Object grandchild tree kill must succeed");
        println!(
            "[S-Win-1][PROC] Job Object tree teardown PASS: child_pid={child_pid} grandchild_pid={gc_pid} kill_convergence={:.3}ms (0 orphans)",
            kill_elapsed.as_secs_f64() * 1_000.0
        );

        // Also verify timeout path via run_hardened_oneshot spawning powershell/python grandchild
        let ps_timeout = run_hardened_oneshot(
            "powershell",
            &[
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$p = Start-Process -FilePath 'ping.exe' -ArgumentList '-n','30','127.0.0.1' -WindowStyle Hidden -PassThru; Start-Sleep -Seconds 30",
            ],
            "",
            &[],
            std::time::Duration::from_millis(400),
        )
        .expect_err("long-running powershell must hit timeout and kill job tree");
        println!("[S-Win-1][PROC] Oneshot timeout + Job kill verified: {ps_timeout}");
        assert!(matches!(ps_timeout, SubprocessError::TimedOut { .. }));

        // 3. Minimal env allowlist + UTF-8 Chinese/Emoji stdin -> stdout roundtrip via python.exe
        //    (relies directly on injected PYTHONUTF8=1 + SYSTEMROOT without -X utf8 CLI flag!)
        assert!(
            std::env::var_os("COMPUTERNAME").is_some(),
            "parent Windows process has COMPUTERNAME set (not in allowlist)"
        );
        let utf8_payload =
            "{\"note\":\"你好 Windows 一等桌面 🚀🔒🧪\",\"lines\":[\"第一行\",\"第二行 CJK & Emoji ✨\"]}\n";
        let py_script = concat!(
            "import json, os, sys\n",
            "raw = sys.stdin.read()\n",
            "obj = json.loads(raw)\n",
            "out = {\n",
            "  'echo': obj,\n",
            "  'has_systemroot': bool(os.environ.get('SYSTEMROOT')),\n",
            "  'pythonutf8': os.environ.get('PYTHONUTF8'),\n",
            "  'leaked_computername': os.environ.get('COMPUTERNAME'),\n",
            "}\n",
            "sys.stdout.write(json.dumps(out, ensure_ascii=False) + '\\r\\n')\n",
        );
        let res = run_hardened_oneshot(
            "python",
            &["-c", py_script],
            utf8_payload,
            &[],
            std::time::Duration::from_secs(10),
        )
        .expect("python UTF-8 roundtrip must succeed");

        println!(
            "[S-Win-1][PROC] Python UTF-8 roundtrip: exit={} elapsed={:.2}ms stdout={}",
            res.exit_code,
            res.elapsed.as_secs_f64() * 1_000.0,
            res.stdout.trim()
        );
        assert_eq!(res.exit_code, 0, "stderr={}", res.stderr);
        assert!(!res.stdout.contains('\r'), "CRLF must be normalized to LF");

        let parsed: serde_json::Value = serde_json::from_str(res.stdout.trim()).unwrap();
        let expected_echo: serde_json::Value = serde_json::from_str(utf8_payload).unwrap();
        assert_eq!(parsed["echo"], expected_echo);
        assert_eq!(parsed["has_systemroot"], serde_json::Value::Bool(true));
        assert_eq!(parsed["pythonutf8"], serde_json::Value::String("1".to_string()));
        assert_eq!(
            parsed["leaked_computername"],
            serde_json::Value::Null,
            "non-allowlisted parent env var COMPUTERNAME MUST NOT leak into child process"
        );
    }
}
