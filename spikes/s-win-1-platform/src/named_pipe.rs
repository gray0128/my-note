//! Windows Named Pipe isolation primitive (`SEC-WIN-PIPE`, `docs/interface-contracts.md` §3.3,
//! `docs/threat-model.md` §10.1).

use serde::{Deserialize, Serialize};

/// Canonical SDDL specified by D9 / `SEC-WIN-PIPE`: Protected DACL (`D:P`) granting
/// `GENERIC_ALL` (`GA`) exclusively to Owner Rights (`OW`, `S-1-3-4`), stripping inherited
/// and default `Everyone` (`WD`) / `Anonymous` (`AN`) / `Network` (`NU`) ACEs.
pub const PIPE_OWNER_ONLY_SDDL: &str = "D:P(A;;GA;;;OW)";

/// Broad trustees that MUST NOT appear in a hardened local Named Pipe DACL.
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum SpikeIpcRequest {
    Ping,
    Echo { seq: u64, payload: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpikeIpcResponse {
    pub ok: bool,
    pub seq: u64,
    pub pid: u32,
    pub echo: Option<String>,
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
    // Stop if an `S:` SACL section follows outside parentheses.
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
/// trustees (`WD` / `Everyone`, `AU`, `BU`, `AN`, `NU`), and exclusively grants access to one of
/// `allowed_trustees` (e.g. `["OW"]` or `[current_user_sid]`).
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

/// Generate a unique test pipe name `\\.\pipe\mynote-spike-<pid>-<rand>`.
pub fn unique_spike_pipe_name(tag: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let pid = std::process::id();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!(r"\\.\pipe\mynote-spike-{pid}-{nanos:08x}-{seq}-{tag}")
}

#[derive(Clone, Debug)]
pub struct LatencyDistributionUs {
    pub samples: usize,
    pub min_us: f64,
    pub p50_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
    pub max_us: f64,
}

pub fn summarize_latencies_ns(mut samples_ns: Vec<u128>) -> LatencyDistributionUs {
    assert!(!samples_ns.is_empty(), "latency samples must not be empty");
    samples_ns.sort_unstable();
    let n = samples_ns.len();
    let pct = |p: usize| -> f64 {
        let idx = ((n - 1) * p) / 100;
        samples_ns[idx] as f64 / 1_000.0
    };
    LatencyDistributionUs {
        samples: n,
        min_us: samples_ns[0] as f64 / 1_000.0,
        p50_us: pct(50),
        p95_us: pct(95),
        p99_us: pct(99),
        max_us: samples_ns[n - 1] as f64 / 1_000.0,
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ptr;
    use std::time::Instant;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::{
        GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE, HLOCAL,
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
    use windows_sys::Win32::System::Pipes::{GetNamedPipeInfo, PIPE_SERVER_END};
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

    /// Query both `TokenUser` (`S-1-5-21-...`) and `TokenOwner` (which on elevated UAC admin
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
        let sid = extract(&buf);
        sid_to_string(sid)
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

    /// Create a `NamedPipeServer` bound with explicit SDDL (`D:P(A;;GA;;;OW)` or custom SDDL),
    /// `first_pipe_instance`, and `reject_remote_clients(true)`.
    pub fn create_hardened_pipe_server(
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

    #[derive(Clone, Debug)]
    pub struct KernelPipeSecurityReport {
        pub owner_and_dacl_sddl: String,
        pub dacl_only_sddl: String,
        pub owner_sid: String,
        pub pipe_flags: u32,
        pub is_server_end: bool,
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

    #[derive(Clone, Debug)]
    pub struct PipeBenchResult {
        pub persistent_stream: LatencyDistributionUs,
        pub per_call_connect_roundtrip: LatencyDistributionUs,
    }

    /// Measure NDJSON roundtrip latency over a hardened `D:P(A;;GA;;;OW)` Named Pipe:
    /// 1. Persistent stream roundtrip (in-session request/response over a single connected pipe);
    /// 2. Full CLI-style connect + NDJSON request/response + disconnect cycle (`first_pipe_instance`
    ///    on initial bind, `first_pipe_instance(false)` on subsequent accept instances).
    pub async fn benchmark_ndjson_roundtrip(
        sddl: &str,
        persistent_iters: usize,
        connect_iters: usize,
    ) -> io::Result<PipeBenchResult> {
        let pipe_name = unique_spike_pipe_name("bench");
        let server = create_hardened_pipe_server(&pipe_name, sddl, true)?;
        let pid = std::process::id();

        // Part 1: persistent stream roundtrip
        let server_task = tokio::spawn(async move {
            server.connect().await?;
            let (read_half, mut write_half) = tokio::io::split(server);
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            loop {
                line.clear();
                let n = reader.read_line(&mut line).await?;
                if n == 0 {
                    break;
                }
                let req: SpikeIpcRequest = serde_json::from_str(line.trim_end())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let resp = match req {
                    SpikeIpcRequest::Ping => SpikeIpcResponse {
                        ok: true,
                        seq: 0,
                        pid,
                        echo: None,
                    },
                    SpikeIpcRequest::Echo { seq, payload } => SpikeIpcResponse {
                        ok: true,
                        seq,
                        pid,
                        echo: Some(payload),
                    },
                };
                let mut out =
                    serde_json::to_vec(&resp).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                out.push(b'\n');
                write_half.write_all(&out).await?;
                write_half.flush().await?;
            }
            Ok::<(), io::Error>(())
        });

        let client = ClientOptions::new().open(&pipe_name)?;
        let (c_read, mut c_write) = tokio::io::split(client);
        let mut c_reader = BufReader::new(c_read);
        let payload_str = "mynote-ipc-ndjson-block-update-你好-🚀-0123456789abcdef".to_string();

        // Warmup 20 frames
        let mut resp_line = String::new();
        for seq in 0..20u64 {
            let mut raw = serde_json::to_vec(&SpikeIpcRequest::Echo {
                seq,
                payload: payload_str.clone(),
            })
            .unwrap();
            raw.push(b'\n');
            c_write.write_all(&raw).await?;
            c_write.flush().await?;
            resp_line.clear();
            c_reader.read_line(&mut resp_line).await?;
        }

        let mut persistent_ns = Vec::with_capacity(persistent_iters);
        for i in 0..persistent_iters {
            let seq = i as u64 + 1;
            let mut raw = serde_json::to_vec(&SpikeIpcRequest::Echo {
                seq,
                payload: payload_str.clone(),
            })
            .unwrap();
            raw.push(b'\n');
            let t0 = Instant::now();
            c_write.write_all(&raw).await?;
            c_write.flush().await?;
            resp_line.clear();
            let n = c_reader.read_line(&mut resp_line).await?;
            let elapsed = t0.elapsed().as_nanos();
            assert!(n > 0, "unexpected EOF during persistent pipe benchmark");
            let parsed: SpikeIpcResponse = serde_json::from_str(resp_line.trim_end()).unwrap();
            assert!(parsed.ok && parsed.seq == seq);
            assert_eq!(parsed.echo.as_deref(), Some(payload_str.as_str()));
            persistent_ns.push(elapsed);
        }
        drop(c_write);
        drop(c_reader);
        server_task.await.unwrap()?;

        // Part 2: per-CLI-call connect + NDJSON roundtrip + close
        let pipe_name_2 = unique_spike_pipe_name("bench-conn");
        let pipe_name_srv = pipe_name_2.clone();
        let sddl_srv = sddl.to_string();
        let total_conns = connect_iters + 5; // 5 warmup + N measured
        let mut initial_srv = create_hardened_pipe_server(&pipe_name_srv, &sddl_srv, true)?;

        let accept_loop = tokio::spawn(async move {
            for idx in 0..total_conns {
                initial_srv.connect().await?;
                let next_srv = if idx + 1 < total_conns {
                    Some(create_hardened_pipe_server(&pipe_name_srv, &sddl_srv, false)?)
                } else {
                    None
                };
                let (r_half, mut w_half) = tokio::io::split(initial_srv);
                let mut rdr = BufReader::new(r_half);
                let mut buf = String::new();
                rdr.read_line(&mut buf).await?;
                let req: SpikeIpcRequest = serde_json::from_str(buf.trim_end()).unwrap();
                let seq = match req {
                    SpikeIpcRequest::Ping => 0,
                    SpikeIpcRequest::Echo { seq, .. } => seq,
                };
                let resp = SpikeIpcResponse {
                    ok: true,
                    seq,
                    pid,
                    echo: None,
                };
                let mut out = serde_json::to_vec(&resp).unwrap();
                out.push(b'\n');
                w_half.write_all(&out).await?;
                w_half.flush().await?;
                if let Some(ns) = next_srv {
                    initial_srv = ns;
                } else {
                    break;
                }
            }
            Ok::<(), io::Error>(())
        });

        let mut connect_ns = Vec::with_capacity(connect_iters);
        for idx in 0..total_conns {
            let t0 = Instant::now();
            let cli = ClientOptions::new().open(&pipe_name_2)?;
            let (cr, mut cw) = tokio::io::split(cli);
            let mut cr = BufReader::new(cr);
            let mut raw = serde_json::to_vec(&SpikeIpcRequest::Echo {
                seq: idx as u64,
                payload: "ping".to_string(),
            })
            .unwrap();
            raw.push(b'\n');
            cw.write_all(&raw).await?;
            cw.flush().await?;
            let mut line = String::new();
            let n = cr.read_line(&mut line).await?;
            let elapsed = t0.elapsed().as_nanos();
            assert!(n > 0);
            let resp: SpikeIpcResponse = serde_json::from_str(line.trim_end()).unwrap();
            assert!(resp.ok && resp.seq == idx as u64);
            if idx >= 5 {
                connect_ns.push(elapsed);
            }
        }
        accept_loop.await.unwrap()?;

        Ok(PipeBenchResult {
            persistent_stream: summarize_latencies_ns(persistent_ns),
            per_call_connect_roundtrip: summarize_latencies_ns(connect_ns),
        })
    }
}

#[cfg(windows)]
pub use imp::*;

#[cfg(test)]
mod tests {
    use super::*;

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

        // Unprotected DACL rejected
        assert!(verify_strict_pipe_sddl("D:(A;;GA;;;OW)", &["OW"]).is_err());
        // Everyone (`WD`) rejected
        assert!(verify_strict_pipe_sddl("D:P(A;;GA;;;OW)(A;;GR;;;WD)", &["OW"]).is_err());
        // Authenticated Users (`AU`) rejected
        assert!(verify_strict_pipe_sddl("D:P(A;;GA;;;AU)", &["OW"]).is_err());
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn win_sec_pipe_first_instance_sddl_and_ndjson_roundtrip() {
        use tokio::net::windows::named_pipe::ServerOptions;
        use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

        let sids = query_current_process_sids().expect("query process token SIDs");
        println!(
            "[S-Win-1][PIPE] Current process TokenUser={} TokenOwner={}",
            sids.token_user_sid, sids.token_owner_sid
        );

        // 0. Baseline control: inspect default Tokio NamedPipeServer::create DACL (without SDDL)
        let default_pipe_name = unique_spike_pipe_name("default-baseline");
        let default_srv = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&default_pipe_name)
            .expect("create default baseline pipe");
        let default_sec = inspect_pipe_kernel_security(&default_srv).expect("inspect default pipe security");
        println!(
            "[S-Win-1][PIPE] Default Tokio pipe (no explicit SDDL) kernel SDDL: full='{}' dacl='{}'",
            default_sec.owner_and_dacl_sddl, default_sec.dacl_only_sddl
        );
        drop(default_srv);

        // 1. Bind 1st instance with D:P(A;;GA;;;OW) + first_pipe_instance(true) + reject_remote_clients(true)
        let pipe_name = unique_spike_pipe_name("ow-sddl");
        let srv1 = create_hardened_pipe_server(&pipe_name, PIPE_OWNER_ONLY_SDDL, true)
            .expect("1st hardened pipe bind must succeed");

        // 2. Prove 2nd first_pipe_instance(true) bind on the same pipe fails with ERROR_ACCESS_DENIED (5)
        let dup_err = create_hardened_pipe_server(&pipe_name, PIPE_OWNER_ONLY_SDDL, true)
            .expect_err("2nd first_pipe_instance(true) bind MUST fail");
        println!(
            "[S-Win-1][PIPE] 2nd first_pipe_instance(true) error: kind={:?} raw_os_error={:?} ({dup_err})",
            dup_err.kind(),
            dup_err.raw_os_error()
        );
        assert_eq!(
            dup_err.raw_os_error(),
            Some(ERROR_ACCESS_DENIED as i32),
            "2nd first_pipe_instance(true) must fail with ERROR_ACCESS_DENIED (5)"
        );

        // Also prove default ServerOptions::new().first_pipe_instance(true) squatter fails with ERROR_ACCESS_DENIED
        let dup_default = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)
            .expect_err("2nd default first_pipe_instance(true) bind MUST fail");
        assert_eq!(dup_default.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));

        // 3. Query kernel DACL back and prove Protected DACL + OW only + ZERO WD/Everyone
        let ow_sec = inspect_pipe_kernel_security(&srv1).expect("inspect OW pipe security");
        println!(
            "[S-Win-1][PIPE] Hardened OW pipe kernel SDDL: full='{}' dacl='{}' owner_sid='{}' pipe_flags=0x{:x}",
            ow_sec.owner_and_dacl_sddl, ow_sec.dacl_only_sddl, ow_sec.owner_sid, ow_sec.pipe_flags
        );
        assert!(ow_sec.is_server_end);
        let parsed_ow = verify_strict_pipe_sddl(&ow_sec.owner_and_dacl_sddl, &["OW", &sids.token_user_sid])
            .expect("kernel SDDL must strictly match Protected OW/current-user only with zero Everyone");
        assert_eq!(parsed_ow.aces.len(), 1);
        drop(srv1);

        // 4. Side-by-side check with explicit TokenUser SID SDDL `D:P(A;;GA;;;<TokenUser SID>)`
        //    (important on UAC-elevated processes where TokenOwner == BA `S-1-5-32-544` whereas
        //    TokenUser == `S-1-5-21-...`)
        let explicit_user_sddl = format!("D:P(A;;GA;;;{})", sids.token_user_sid);
        let user_pipe_name = unique_spike_pipe_name("token-user-sddl");
        let srv_user = create_hardened_pipe_server(&user_pipe_name, &explicit_user_sddl, true)
            .expect("explicit TokenUser SID pipe bind must succeed");
        let user_sec = inspect_pipe_kernel_security(&srv_user).expect("inspect TokenUser pipe security");
        println!(
            "[S-Win-1][PIPE] Hardened TokenUser SID pipe kernel SDDL: full='{}' dacl='{}'",
            user_sec.owner_and_dacl_sddl, user_sec.dacl_only_sddl
        );
        let parsed_user = verify_strict_pipe_sddl(&user_sec.owner_and_dacl_sddl, &[&sids.token_user_sid])
            .expect("explicit TokenUser SDDL must contain only TokenUser SID");
        assert_eq!(parsed_user.aces.len(), 1);
        drop(srv_user);

        // 5. Measure NDJSON roundtrip latency across 5 trials (interleaved / repeated for stability)
        let mut trial_stream_p50 = Vec::new();
        let mut trial_conn_p50 = Vec::new();
        for trial in 1..=5 {
            let bench = benchmark_ndjson_roundtrip(PIPE_OWNER_ONLY_SDDL, 500, 100)
                .await
                .expect("NDJSON benchmark must succeed");
            println!(
                "[S-Win-1][PIPE][Trial {trial}/5] persistent_500(min={:.1}us p50={:.1}us p95={:.1}us p99={:.1}us max={:.1}us) | connect+roundtrip_100(min={:.1}us p50={:.1}us p95={:.1}us p99={:.1}us max={:.1}us)",
                bench.persistent_stream.min_us,
                bench.persistent_stream.p50_us,
                bench.persistent_stream.p95_us,
                bench.persistent_stream.p99_us,
                bench.persistent_stream.max_us,
                bench.per_call_connect_roundtrip.min_us,
                bench.per_call_connect_roundtrip.p50_us,
                bench.per_call_connect_roundtrip.p95_us,
                bench.per_call_connect_roundtrip.p99_us,
                bench.per_call_connect_roundtrip.max_us,
            );
            trial_stream_p50.push(bench.persistent_stream.p50_us);
            trial_conn_p50.push(bench.per_call_connect_roundtrip.p50_us);
        }
        trial_stream_p50.sort_by(|a, b| a.partial_cmp(b).unwrap());
        trial_conn_p50.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "[S-Win-1][PIPE][5-Trial Summary] persistent p50 median={:.1}us (range {:.1}..{:.1}us) | connect+roundtrip p50 median={:.1}us (range {:.1}..{:.1}us)",
            trial_stream_p50[2],
            trial_stream_p50[0],
            trial_stream_p50[4],
            trial_conn_p50[2],
            trial_conn_p50[0],
            trial_conn_p50[4],
        );
    }
}
