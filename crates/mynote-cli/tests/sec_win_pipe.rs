//! `SEC-WIN-PIPE` & M5-W1 Windows platform security integration suite
//! (`docs/eval-framework.md` §5 `SEC-WIN-PIPE`, `docs/threat-model.md` §10.1,
//! `docs/interface-contracts.md` §2.4 & §3.3, `docs/spikes/s-win-1-platform.md`).
//!
//! Verifies:
//! 1. Named Pipe `first_pipe_instance(true)` deterministic 2nd-bind rejection (`ERROR_ACCESS_DENIED`);
//! 2. Kernel Security Descriptor readback (`D:P` Protected DACL, `OW` / current `TokenUser` SID only,
//!    zero `Everyone`/`WD`/`AN`/`AU`/`BU`) and `PIPE_REJECT_REMOTE_CLIENTS`;
//! 3. Live `mynote daemon` + `LocalIpc` Named Pipe Chinese/Emoji UTF-8 roundtrip;
//! 4. `.bat` / `.cmd` / `cmd.exe` batch-script refusal (CVE-2024-24576) and Job Object
//!    (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) timeout killing grandchild process trees (`0` orphans);
//! 5. Protected current-user NTFS DACL on `data_dir`, `mynote.db`, `backups/*.db`, and secret files,
//!    plus Windows Credential Manager (`CredWriteW`/`CredReadW`/`CredDeleteW`) & DPAPI roundtrip.

use mynote_cli::formatters::{
    filter_windows_environment, normalize_crlf, validate_executable_target, SubprocessError,
};
use mynote_cli::local_ipc::{pipe_name_for, verify_strict_pipe_sddl, PIPE_OWNER_ONLY_SDDL};
use mynote_cli::runner::suppress_console_echo_mode;

#[test]
fn pure_cross_platform_win_security_invariants() {
    let tmp = std::env::temp_dir().join("mynote_sec_win_pure_check");
    let pipe = pipe_name_for(&tmp);
    assert!(pipe.starts_with(r"\\.\pipe\mynote-"));
    assert_eq!(pipe.strip_prefix(r"\\.\pipe\mynote-").unwrap().len(), 16);
    assert_eq!(pipe, pipe_name_for(&tmp));

    assert!(verify_strict_pipe_sddl(PIPE_OWNER_ONLY_SDDL, &["OW"]).is_ok());
    assert!(verify_strict_pipe_sddl("O:BAD:P(A;;FA;;;OW)", &["OW"]).is_ok());
    assert!(verify_strict_pipe_sddl("D:(A;;FA;;;OW)", &["OW"]).is_err());
    assert!(verify_strict_pipe_sddl("D:P(A;;FA;;;OW)(A;;FR;;;WD)", &["OW"]).is_err());
    assert!(verify_strict_pipe_sddl("D:P(A;;FA;;;S-1-1-0)", &["OW"]).is_err());

    for forbidden in ["evil.bat", "EVIL.CMD", "sneaky.bat. ", "cmd", "cmd.exe"] {
        assert!(matches!(
            validate_executable_target(forbidden),
            Err(SubprocessError::BatchScriptForbidden(_))
        ));
    }

    let env = filter_windows_environment(
        vec![
            ("SYSTEMROOT".into(), r"C:\Windows".into()),
            ("AWS_SECRET_ACCESS_KEY".into(), "top-secret".into()),
        ],
        &[],
    );
    assert_eq!(env.get("SYSTEMROOT").map(String::as_str), Some(r"C:\Windows"));
    assert_eq!(env.get("PYTHONUTF8").map(String::as_str), Some("1"));
    assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));
    assert_eq!(normalize_crlf("你好\r\r\n世界\r\n"), "你好\n世界\n");

    // ENABLE_ECHO_INPUT (0x4) cleared; ENABLE_LINE_INPUT (0x2) | ENABLE_PROCESSED_INPUT (0x1) set
    let masked = suppress_console_echo_mode(0x0007);
    assert_eq!(masked & 0x4, 0);
    assert_eq!(masked & 0x3, 0x3);
}

#[cfg(windows)]
mod windows_live {
    use super::*;
    use mynote_cli::daemon::{start_daemon, DaemonConfig};
    use mynote_cli::formatters::{
        is_process_handle_alive, open_process_observer, resolve_safe_windows_executable,
        run_hardened_oneshot, spawn_hardened_windows_child, wait_process_terminated, HardenedChild,
    };
    use mynote_cli::local_ipc::{
        create_hardened_pipe_server, create_hardened_pipe_server_with_sddl, inspect_pipe_kernel_security,
        query_current_process_sids, try_send_ipc, ApplyMeta, ApplyRequest, LocalIpcRequest,
    };
    use mynote_cli::runner::resolve_data_dir;
    use mynote_store::credentials::{
        delete_device_credentials, dpapi_protect, dpapi_unprotect, inspect_windows_file_dacl_sddl,
        load_device_credentials, save_device_credentials, win_cred_delete, win_cred_read, win_cred_write,
        DeviceCredentials,
    };
    use mynote_store::LocalStore;
    use serde_json::Value;
    use std::io::{BufRead, BufReader, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

    fn bin() -> &'static str {
        env!("CARGO_BIN_EXE_mynote")
    }

    fn temp_dir(tag: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("mynote_sec_win_{tag}_{}_{ts}_{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn unique_pipe_name(tag: &str) -> String {
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        format!(
            r"\\.\pipe\mynote-secwin-{}-{ts:08x}-{n}-{tag}",
            std::process::id()
        )
    }

    fn run_cli_with_env(
        data_dir: &Path,
        args: &[&str],
        stdin_bytes: Option<&[u8]>,
        extra_env: &[(&str, &str)],
    ) -> std::process::Output {
        let mut cmd = Command::new(bin());
        cmd.arg("--data-dir")
            .arg(data_dir)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn mynote.exe");
        if let Some(bytes) = stdin_bytes {
            if let Some(mut sin) = child.stdin.take() {
                sin.write_all(bytes).expect("write stdin");
            }
        } else {
            drop(child.stdin.take());
        }
        child.wait_with_output().expect("wait mynote.exe")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sec_win_pipe_first_instance_sddl_and_daemon_ndjson_chinese_roundtrip() {
        let sids = query_current_process_sids().expect("query process token SIDs");
        println!(
            "[SEC-WIN-PIPE] TokenUser={} TokenOwner={}",
            sids.token_user_sid, sids.token_owner_sid
        );

        // 1. Bind 1st Named Pipe server instance and verify 2nd `first_pipe_instance(true)` fails with ERROR_ACCESS_DENIED (5)
        let pipe_name = unique_pipe_name("first-inst");
        let srv1 =
            create_hardened_pipe_server(&pipe_name, true).expect("1st hardened pipe bind must succeed");

        let dup_hardened = create_hardened_pipe_server(&pipe_name, true)
            .expect_err("2nd first_pipe_instance(true) bind MUST fail");
        assert_eq!(
            dup_hardened.raw_os_error(),
            Some(ERROR_ACCESS_DENIED as i32),
            "expected ERROR_ACCESS_DENIED (5), got {dup_hardened:?}"
        );

        let dup_default = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)
            .expect_err("2nd default ServerOptions first_pipe_instance(true) bind MUST fail");
        assert_eq!(dup_default.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));

        // 2. Inspect live kernel Security Descriptor & pipe flags
        let sec = inspect_pipe_kernel_security(&srv1).expect("inspect pipe kernel security");
        println!(
            "[SEC-WIN-PIPE] Kernel SDDL: full='{}' dacl='{}' owner_sid='{}' pipe_flags=0x{:x} rejects_remote_clients={}",
            sec.owner_and_dacl_sddl,
            sec.dacl_only_sddl,
            sec.owner_sid,
            sec.pipe_flags,
            sec.rejects_remote_clients
        );
        assert!(sec.is_server_end);
        assert!(
            sec.rejects_remote_clients,
            "PIPE_REJECT_REMOTE_CLIENTS must be enabled"
        );
        assert_eq!(
            sec.owner_sid, sids.token_user_sid,
            "Named Pipe owner SID must equal current TokenUser SID even under UAC elevation"
        );

        let mut allowed = vec!["OW", sids.token_user_sid.as_str()];
        if sids.token_user_sid.ends_with("-500") {
            allowed.push("LA");
        }
        let parsed = verify_strict_pipe_sddl(&sec.owner_and_dacl_sddl, &allowed)
            .expect("kernel SDDL must be Protected with zero Everyone/WD/AN/AU/BU");
        assert_eq!(parsed.aces.len(), 1);
        drop(srv1);

        // Also verify direct `PIPE_OWNER_ONLY_SDDL` (`D:P(A;;GA;;;OW)`) helper
        let raw_ow_pipe = unique_pipe_name("raw-ow");
        let srv_ow = create_hardened_pipe_server_with_sddl(&raw_ow_pipe, PIPE_OWNER_ONLY_SDDL, true)
            .expect("bind raw PIPE_OWNER_ONLY_SDDL");
        let ow_sec = inspect_pipe_kernel_security(&srv_ow).unwrap();
        assert!(ow_sec.rejects_remote_clients);
        verify_strict_pipe_sddl(&ow_sec.dacl_only_sddl, &["OW"]).unwrap();
        drop(srv_ow);

        // 3. Start real `mynote daemon`, verify pipe squatting against live daemon pipe is rejected,
        //    and verify UTF-8 Chinese + Emoji NDJSON roundtrip via both `try_send_ipc` and `mynote.exe` CLI!
        let dir = temp_dir("daemon_ipc");
        let daemon = start_daemon(DaemonConfig {
            data_dir: dir.clone(),
            port: 0,
            enable_cloud_sync: false,
        })
        .await
        .expect("start_daemon on Windows");

        let daemon_pipe = pipe_name_for(&dir);
        let squat_err = create_hardened_pipe_server(&daemon_pipe, true)
            .expect_err("squatting on live daemon Named Pipe with first_pipe_instance(true) must fail");
        assert_eq!(squat_err.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));

        let dir_ping = dir.clone();
        let ping = tokio::task::spawn_blocking(move || {
            try_send_ipc(&dir_ping, &LocalIpcRequest::Ping, Duration::from_secs(5))
        })
        .await
        .unwrap()
        .unwrap()
        .expect("daemon Named Pipe Ping reachable");
        assert!(ping.ok);
        assert_eq!(ping.port, Some(daemon.port));

        let chinese_payload =
            "中文 UTF-8 跨进程 Named Pipe 单写入方验证 🚀 零乱码\n第二行：严禁 Everyone 访问";
        let payload_owned = chinese_payload.to_string();
        let dir_apply = dir.clone();
        let apply = tokio::task::spawn_blocking(move || {
            try_send_ipc(
                &dir_apply,
                &LocalIpcRequest::Apply {
                    meta: ApplyMeta {
                        actor: "human".into(),
                        idempotency_key: Some("win-ipc-idem-1".into()),
                        allow_empty: false,
                        force: false,
                    },
                    request: ApplyRequest::AddBlock {
                        buffer: "scratch".into(),
                        content: payload_owned,
                        lang: Some("markdown".into()),
                        after_id: None,
                    },
                },
                Duration::from_secs(5),
            )
        })
        .await
        .unwrap()
        .unwrap()
        .expect("daemon Named Pipe Apply reachable");
        assert!(apply.ok, "Apply failed: {:?}", apply.error);
        let blk_id = apply.data.as_ref().unwrap()["block_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Read back via real `mynote.exe block get --raw` while daemon is running
        let dir_cli = dir.clone();
        let blk_cli = blk_id.clone();
        let raw_out = tokio::task::spawn_blocking(move || {
            run_cli_with_env(&dir_cli, &["block", "get", &blk_cli, "--raw"], None, &[])
        })
        .await
        .unwrap();
        assert_eq!(raw_out.status.code(), Some(0));
        assert_eq!(
            String::from_utf8(raw_out.stdout).unwrap(),
            chinese_payload,
            "Chinese UTF-8 payload must roundtrip byte-for-byte without corruption"
        );

        daemon.shutdown();
        tokio::time::sleep(Duration::from_millis(80)).await;

        // After daemon shutdown, Named Pipe is closed -> `try_send_ipc` returns `Ok(None)`
        let after_stop = try_send_ipc(&dir, &LocalIpcRequest::Ping, Duration::from_secs(2)).unwrap();
        assert!(
            after_stop.is_none(),
            "pipe must close cleanly after daemon shutdown"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sec_win_pipe_job_object_timeout_kills_grandchild_tree_and_refuses_batch_scripts() {
        let dir = temp_dir("job_and_bat");

        // 1. Real `.bat` and `.cmd` files on disk MUST be rejected (zero execution, exit 7 FORMAT_SYNTAX_ERROR)
        let spy_marker = dir.join("bat_was_executed.marker");
        let bat_file = dir.join("evil_formatter.bat");
        let cmd_file = dir.join("evil_formatter.CMD");
        let bat_body = format!(
            "@echo off\r\necho pwned > \"{}\"\r\necho formatted\r\n",
            spy_marker.display()
        );
        std::fs::write(&bat_file, &bat_body).unwrap();
        std::fs::write(&cmd_file, &bat_body).unwrap();

        let direct_bat_err =
            run_hardened_oneshot(&bat_file.to_string_lossy(), &[], "", &[], Duration::from_secs(1))
                .expect_err("direct run_hardened_oneshot must refuse .bat");
        assert!(matches!(direct_bat_err, SubprocessError::BatchScriptForbidden(_)));

        let cfg_path = dir.join("formatters.toml");
        std::fs::write(
            &cfg_path,
            format!(
                "[formatters.batfmt]\ncmd = '{}'\ntimeout_ms = 2000\n\n[formatters.cmdfmt]\ncmd = '{}'\ntimeout_ms = 2000\n\n[formatters.cmdexe]\ncmd = ['cmd.exe', '/c', 'echo', 'hi']\ntimeout_ms = 2000\n",
                bat_file.display(),
                cmd_file.display()
            ),
        )
        .unwrap();
        let cfg_str = cfg_path.to_str().unwrap();

        for lang in ["batfmt", "cmdfmt", "cmdexe"] {
            let out = run_cli_with_env(
                &dir,
                &["format", "--lang", lang, "--json"],
                Some(b"hello"),
                &[("MYNOTE_FORMATTERS_CONFIG", cfg_str)],
            );
            assert_eq!(out.status.code(), Some(7), "{lang} must exit 7");
            let j: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(j["error"]["code"], "FORMAT_SYNTAX_ERROR");
            assert!(
                !spy_marker.exists(),
                "CVE-2024-24576 defense failed: {lang} must NEVER execute"
            );
        }

        // 2. Direct `spawn_hardened_windows_child` + Job Object kills grandchild `ping.exe` (`0` orphans)
        let use_python = resolve_safe_windows_executable("python").is_ok();
        let mut child = if use_python {
            spawn_hardened_windows_child(
                "python",
                &[
                    "-u",
                    "-c",
                    "import subprocess, time; p = subprocess.Popen(['ping.exe', '-n', '60', '127.0.0.1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); print(f'GRANDCHILD_PID={p.pid}', flush=True); time.sleep(60)",
                ],
                &[],
            )
            .expect("spawn python child")
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
            .expect("spawn powershell child")
        };
        drop(child.stdin.take());
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).expect("read GRANDCHILD_PID");
        let gc_pid: u32 = line
            .trim()
            .strip_prefix("GRANDCHILD_PID=")
            .expect("GRANDCHILD_PID prefix")
            .parse()
            .expect("parse grandchild pid");
        let gc_observer = open_process_observer(gc_pid).expect("open grandchild handle");
        assert!(is_process_handle_alive(&child.process));
        assert!(is_process_handle_alive(&gc_observer));

        let HardenedChild {
            job,
            process: child_proc,
            ..
        } = child;
        drop(job);
        let child_elapsed = wait_process_terminated(&child_proc, Duration::from_secs(3)).unwrap();
        let gc_elapsed = wait_process_terminated(&gc_observer, Duration::from_secs(3)).unwrap();
        println!(
            "[SEC-WIN-PIPE] Direct Job Object drop killed child+grandchild ({gc_pid}) in child={:.2}ms gc={:.2}ms (0 orphans)",
            child_elapsed.as_secs_f64() * 1000.0,
            gc_elapsed.as_secs_f64() * 1000.0
        );
        assert!(!is_process_handle_alive(&child_proc));
        assert!(!is_process_handle_alive(&gc_observer));

        // 3. End-to-end CLI `mynote format` timeout kills grandchild process tree (`0` orphans)
        //    AND verifies minimal env allowlist (`SYSTEMROOT` kept, `PYTHONUTF8=1`, secrets stripped) + Chinese UTF-8!
        if use_python {
            let gc_pid_file = dir.join("cli_timeout_gc.pid");
            let gc_pid_posix = gc_pid_file.to_string_lossy().replace('\\', "/");
            let py_cfg_path = dir.join("py_formatters.toml");
            std::fs::write(
                &py_cfg_path,
                format!(
                    r#"
[formatters.py_tree_timeout]
cmd = ["python", "-u", "-c", "import pathlib, subprocess, time; p = subprocess.Popen(['ping.exe', '-n', '60', '127.0.0.1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); pathlib.Path('{gc_pid_posix}').write_text(str(p.pid)); time.sleep(30)"]
timeout_ms = 350

[formatters.py_utf8_env]
cmd = ["python", "-c", "import json, os, sys; data = sys.stdin.read(); sys.stdout.write(json.dumps({{'text': data, 'has_sysroot': bool(os.environ.get('SYSTEMROOT')), 'py_utf8': os.environ.get('PYTHONUTF8'), 'secret': os.environ.get('AWS_SECRET_ACCESS_KEY')}}, ensure_ascii=False) + '\\r\\r\\n')"]
timeout_ms = 5000
"#
                ),
            )
            .unwrap();
            let py_cfg_str = py_cfg_path.to_str().unwrap();

            let timeout_out = run_cli_with_env(
                &dir,
                &["format", "--lang", "py_tree_timeout", "--json"],
                Some(b"slow input"),
                &[("MYNOTE_FORMATTERS_CONFIG", py_cfg_str)],
            );
            assert_eq!(timeout_out.status.code(), Some(7));
            let timeout_j: Value = serde_json::from_slice(&timeout_out.stdout).unwrap();
            assert_eq!(timeout_j["error"]["code"], "FORMAT_SYNTAX_ERROR");

            let cli_gc_pid: u32 = std::fs::read_to_string(&gc_pid_file)
                .expect("formatter wrote grandchild pid before timeout")
                .trim()
                .parse()
                .unwrap();
            if let Ok(obs) = open_process_observer(cli_gc_pid) {
                let _ = wait_process_terminated(&obs, Duration::from_secs(2));
                assert!(
                    !is_process_handle_alive(&obs),
                    "CLI formatter timeout MUST kill grandchild process {cli_gc_pid} (0 orphans)"
                );
            }

            let utf8_input = "你好 Windows 子进程加固 🌟";
            let ok_out = run_cli_with_env(
                &dir,
                &["format", "--lang", "py_utf8_env", "--json"],
                Some(utf8_input.as_bytes()),
                &[
                    ("MYNOTE_FORMATTERS_CONFIG", py_cfg_str),
                    ("AWS_SECRET_ACCESS_KEY", "NEVER_LEAK_THIS_KEY"),
                ],
            );
            assert_eq!(
                ok_out.status.code(),
                Some(0),
                "stderr={}",
                String::from_utf8_lossy(&ok_out.stderr)
            );
            let ok_j: Value = serde_json::from_slice(&ok_out.stdout).unwrap();
            let formatted_str = ok_j["data"]["formatted"].as_str().unwrap();
            assert!(
                !formatted_str.contains('\r'),
                "doubled \\r\\r\\n must be normalized to \\n: {formatted_str:?}"
            );
            let inner: Value = serde_json::from_str(formatted_str.trim()).unwrap();
            assert_eq!(inner["text"], utf8_input);
            assert_eq!(inner["has_sysroot"], true);
            assert_eq!(inner["py_utf8"], "1");
            assert!(inner["secret"].is_null());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sec_win_ntfs_user_dacl_credential_manager_dpapi_and_default_paths() {
        let sids = query_current_process_sids().expect("query process token SIDs");
        let mut allowed = vec!["OW", sids.token_user_sid.as_str()];
        if sids.token_user_sid.ends_with("-500") {
            allowed.push("LA");
        }

        // 1. NTFS Protected user-only DACL on data_dir, mynote.db, backups/*.db, smk_keyring.local.json, and DPAPI credentials
        let dir = temp_dir("ntfs_dacl_dpapi");
        {
            let mut store = LocalStore::open(&dir).expect("open LocalStore on Windows");
            store
                .add_block(
                    "scratch",
                    "windows ntfs acl test",
                    Some("text"),
                    None,
                    "human",
                    None,
                )
                .unwrap();

            let creds = DeviceCredentials {
                sync_url: "https://relay.mynote.test".to_string(),
                device_token: "mnt_win_dpapi_secret_canary_999999".to_string(),
                scope: "read-write".to_string(),
            };
            save_device_credentials(&dir, &creds).expect("save_device_credentials with DPAPI");

            let loaded = load_device_credentials(&dir)
                .expect("load_device_credentials")
                .expect("credentials must exist");
            assert_eq!(loaded, creds);

            let backup_file = store
                .create_auto_backup("win-acl-test")
                .expect("vacuum_into backup");
            for path in [
                dir.as_path(),
                &dir.join("mynote.db"),
                &dir.join("smk_keyring.local.json"),
                &dir.join("device_credentials.local.json"),
                backup_file.as_path(),
            ] {
                let sddl = inspect_windows_file_dacl_sddl(path).expect("inspect NTFS DACL SDDL");
                println!("[SEC-WIN-ACL] path='{}' sddl='{sddl}'", path.display());
                let summary = verify_strict_pipe_sddl(&sddl, &allowed).unwrap_or_else(|e| {
                    panic!(
                        "NTFS DACL check failed on '{}' (sddl='{sddl}'): {e}",
                        path.display()
                    )
                });
                assert_eq!(summary.aces.len(), 1);
                if path.is_dir() {
                    assert!(
                        summary.aces[0].ace_flags.contains("OI") && summary.aces[0].ace_flags.contains("CI"),
                        "directory DACL must carry OICI inheritance flags, got '{}'",
                        summary.aces[0].ace_flags
                    );
                }
            }

            // Verify raw `device_credentials.local.json` on disk is DPAPI-encrypted (zero plaintext token!)
            let raw_cred_file = std::fs::read_to_string(dir.join("device_credentials.local.json")).unwrap();
            assert!(
                raw_cred_file.contains("dpapi_b64"),
                "fallback credentials file on Windows must use DPAPI envelope: {raw_cred_file}"
            );
            assert!(
                !raw_cred_file.contains("mnt_win_dpapi_secret_canary_999999"),
                "plaintext device_token MUST NOT appear on disk when DPAPI is active"
            );

            delete_device_credentials(&dir);
            assert!(load_device_credentials(&dir).unwrap().is_none());
        }

        // 2. Direct DPAPI roundtrip with binary + UTF-8 Chinese secret
        let secret = "DPAPI 密钥保护测试 🔑".as_bytes();
        let sealed = dpapi_protect(secret).expect("dpapi_protect");
        assert_ne!(sealed, secret);
        let unsealed = dpapi_unprotect(&sealed).expect("dpapi_unprotect");
        assert_eq!(unsealed.as_slice(), secret);

        // 3. Windows Credential Manager (`CredWriteW` / `CredReadW` / `CredDeleteW`) live UTF-16LE roundtrip
        let cred_service = "mynote.sec_win_pipe_test";
        let cred_account = format!("test-{}-{}", std::process::id(), unique_pipe_name("cred").len());
        struct CredCleanup<'a>(&'a str, &'a str);
        impl Drop for CredCleanup<'_> {
            fn drop(&mut self) {
                let _ = win_cred_delete(self.0, self.1);
            }
        }
        let _cleanup = CredCleanup(cred_service, &cred_account);
        let cred_payload = r#"{"sync_url":"https://win-cred.example","device_token":"mnt_cred_utf16_你好","scope":"read-write"}"#;
        assert!(
            win_cred_write(cred_service, &cred_account, cred_payload),
            "CredWriteW must succeed"
        );
        let read_back =
            win_cred_read(cred_service, &cred_account).expect("CredReadW must return stored secret");
        assert_eq!(read_back.as_str(), cred_payload);
        assert!(
            win_cred_delete(cred_service, &cred_account),
            "CredDeleteW must succeed"
        );
        assert!(
            win_cred_read(cred_service, &cred_account).is_none(),
            "CredReadW must return None after CredDeleteW"
        );

        // 4. Default Windows data directory resolves to `%LOCALAPPDATA%\mynote` when `MYNOTE_DATA_DIR` is unset
        if let (None, Some(lad)) = (
            std::env::var_os("MYNOTE_DATA_DIR"),
            std::env::var_os("LOCALAPPDATA"),
        ) {
            assert_eq!(resolve_data_dir(None), PathBuf::from(lad).join("mynote"));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
