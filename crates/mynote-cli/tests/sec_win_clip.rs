//! `SEC-WIN-CLIP` & M5-W2 Windows native clipboard, event-driven `WM_CLIPBOARDUPDATE` watcher,
//! privacy format hard-filtering, and `ShellExecuteW` `mynote open` security integration suite
//! (`docs/eval-framework.md` §5 `SEC-WIN-CLIP`, `docs/threat-model.md` §9.2 & §10.1,
//! `docs/architecture-proposal.md` §5.7 & §7, `docs/spikes/s-win-1-platform.md`).
//!
//! Covers:
//! 1. Cross-platform pure invariants (Windows privacy format & DWORD==0 fail-closed classifiers,
//!    `"PNG"` > `CF_DIBV5` > `CF_DIB` > `CF_UNICODETEXT` priority, `CF_DIBV5` & `CF_DIB` lossless
//!    RGBA -> PNG conversion, UTF-16LE <-> UTF-8 surrogate/Chinese roundtrip, SVG rejection, and
//!    `validate_local_open_url` query-string `&` command-injection defense);
//! 2. Live Win32 `SEC-WIN-CLIP` primitive & format-trace audit (`windows-latest`):
//!    - `0` user-payload `GetClipboardData` calls on `ExcludeClipboardContentFromMonitorProcessing`,
//!      `CanIncludeInClipboardHistory == 0`, `CanUploadClipboardDataToCloud == 0`, and
//!      `MyNoteClipEchoMarker` / `dev.mynote.synced-clip`;
//!    - `"PNG"` priority over larger `CF_DIBV5` (`0` reads of `CF_DIBV5`), plus lossless `CF_DIBV5`
//!      and `CF_DIB` fallback to PNG and Chinese + Emoji UTF-16LE roundtrip;
//!    - Sensitive/ephemeral write atomicity (`ExcludeClipboardContentFromMonitorProcessing` +
//!      `CanIncludeInClipboardHistory = 0` + `CanUploadClipboardDataToCloud = 0`) and safe
//!      `current_mynote_blake3()` inspection;
//!    - SVG rejection on both `image/svg+xml` format and spoofed `<svg>` bytes inside `"PNG"`;
//!    - Event-driven `HWND_MESSAGE` + `AddClipboardFormatListener` (`WM_CLIPBOARDUPDATE`) and clean
//!      `PostThreadMessageW(..., WM_QUIT, ...)` / `DestroyWindow` teardown;
//! 3. End-to-end live Windows `Daemon` + `NativeSystemClipboard` + `WM_CLIPBOARDUPDATE` background
//!    watcher + mock cloud relay + `mynote.exe` CLI (`0` outbound HTTP captures on privacy formats,
//!    secrets, SVG, and synced echo writes; lossless auto-sync of Chinese UTF-8, `"PNG"`, and
//!    `CF_DIBV5`; plus `mynote open` URL validation over Named Pipe).

use image::{ImageFormat, ImageReader};
use mynote_cli::clip_watch::{ClipWatchFilter, WatchDecision};
use mynote_cli::clipboard::{
    dib_to_png, rgba_to_dib_bytes, rgba_to_dibv5_bytes, utf16le_clipboard_bytes_to_utf8,
    utf8_to_utf16le_clipboard_bytes, validate_png_clipboard_bytes, windows_is_dword_zero_or_malformed,
    windows_precheck_presence_format, windows_select_source_format, WinSelectedFormat, PNG_MAGIC, WIN_CF_DIB,
    WIN_CF_DIBV5, WIN_CF_UNICODETEXT, WIN_FMT_CAN_INCLUDE_HISTORY, WIN_FMT_CAN_UPLOAD_CLOUD,
    WIN_FMT_EXCLUDE_MONITOR, WIN_FMT_MYNOTE_ECHO_MARKER, WIN_FMT_MYNOTE_SYNCED, WIN_FMT_MYNOTE_VAULT_SECRET,
    WIN_FMT_PNG, WIN_FMT_SVG_MIME,
};
use mynote_cli::runner::validate_local_open_url;
use mynote_core::error::ErrorCode;
use std::io::Cursor;

#[test]
fn pure_cross_platform_win_clip_and_open_url_invariants() {
    // 1. Presence-based privacy & echo-marker prechecks
    for marker in [
        WIN_FMT_MYNOTE_ECHO_MARKER,
        WIN_FMT_MYNOTE_SYNCED,
        WIN_FMT_MYNOTE_VAULT_SECRET,
        "dev.mynote.custom-tag",
        WIN_FMT_EXCLUDE_MONITOR,
    ] {
        assert_eq!(
            windows_precheck_presence_format(&["CF_UNICODETEXT", marker]),
            Some(marker)
        );
        let err = ClipWatchFilter::precheck_windows_formats(
            &[(WIN_CF_UNICODETEXT, "CF_UNICODETEXT"), (49500, marker)],
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err, WatchDecision::SkipSensitive(marker.to_string()));
    }

    // 2. DWORD == 0 and malformed (< 4B) fail-closed privacy checks
    assert!(windows_is_dword_zero_or_malformed(&0u32.to_le_bytes()));
    assert!(windows_is_dword_zero_or_malformed(&[]));
    assert!(windows_is_dword_zero_or_malformed(&[1, 0]));
    assert!(!windows_is_dword_zero_or_malformed(&1u32.to_le_bytes()));

    assert_eq!(
        ClipWatchFilter::precheck_windows_formats(
            &[
                (WIN_CF_UNICODETEXT, "CF_UNICODETEXT"),
                (49501, WIN_FMT_CAN_INCLUDE_HISTORY)
            ],
            Some(&0u32.to_le_bytes()),
            None,
        ),
        Err(WatchDecision::SkipSensitive(
            "CanIncludeInClipboardHistory == 0".to_string()
        ))
    );
    assert_eq!(
        ClipWatchFilter::precheck_windows_formats(
            &[
                (WIN_CF_UNICODETEXT, "CF_UNICODETEXT"),
                (49502, WIN_FMT_CAN_UPLOAD_CLOUD)
            ],
            Some(&1u32.to_le_bytes()),
            Some(&0u32.to_le_bytes()),
        ),
        Err(WatchDecision::SkipSensitive(
            "CanUploadClipboardDataToCloud == 0".to_string()
        ))
    );
    assert_eq!(
        ClipWatchFilter::precheck_windows_formats(
            &[
                (WIN_CF_UNICODETEXT, "CF_UNICODETEXT"),
                (49501, WIN_FMT_CAN_INCLUDE_HISTORY),
                (49502, WIN_FMT_CAN_UPLOAD_CLOUD),
            ],
            Some(&1u32.to_le_bytes()),
            Some(&1u32.to_le_bytes()),
        ),
        Ok(WinSelectedFormat::UnicodeText)
    );

    // 3. Source priority: `"PNG"` > `CF_DIBV5` > `CF_DIB` > `CF_UNICODETEXT`, SVG rejected as image
    assert_eq!(
        windows_select_source_format(&[
            (WIN_CF_DIBV5, "CF_DIBV5"),
            (WIN_CF_DIB, "CF_DIB"),
            (49600, WIN_FMT_PNG),
        ]),
        Some(WinSelectedFormat::Png(49600))
    );
    assert_eq!(
        windows_select_source_format(&[(WIN_CF_DIB, "CF_DIB"), (WIN_CF_DIBV5, "CF_DIBV5")]),
        Some(WinSelectedFormat::DibV5)
    );
    assert_eq!(
        windows_select_source_format(&[(WIN_CF_DIB, "CF_DIB")]),
        Some(WinSelectedFormat::Dib)
    );
    assert_eq!(
        windows_select_source_format(&[(49610, WIN_FMT_SVG_MIME)]),
        Some(WinSelectedFormat::SvgOnlyRejected)
    );
    assert_eq!(
        windows_select_source_format(&[(49610, WIN_FMT_SVG_MIME), (WIN_CF_UNICODETEXT, "CF_UNICODETEXT")]),
        Some(WinSelectedFormat::UnicodeText)
    );

    // 4. Lossless `CF_DIBV5` (translucent RGBA) and `CF_DIB` (32-bpp BI_RGB) -> PNG conversion
    let mut orig_rgba = Vec::with_capacity(5 * 4 * 4);
    for y in 0..4u8 {
        for x in 0..5u8 {
            orig_rgba.extend_from_slice(&[x * 45, y * 70, 220 - x * 25, 65 + y * 60]);
        }
    }
    let dibv5 = rgba_to_dibv5_bytes(5, 4, &orig_rgba);
    let (png_v5, w_v5, h_v5) = dib_to_png(&dibv5).expect("dibv5 -> png");
    assert_eq!((w_v5, h_v5), (5, 4));
    assert!(png_v5.starts_with(&PNG_MAGIC));
    assert_eq!(validate_png_clipboard_bytes(&png_v5).unwrap(), (5, 4));
    let decoded_v5 = ImageReader::with_format(Cursor::new(&png_v5), ImageFormat::Png)
        .decode()
        .unwrap()
        .to_rgba8();
    assert_eq!(decoded_v5.as_raw(), &orig_rgba);

    let mut opaque_rgba = Vec::with_capacity(6 * 3 * 4);
    for i in 0..(6 * 3) {
        opaque_rgba.extend_from_slice(&[(i * 11) as u8, (240 - i * 7) as u8, (i * 19 + 5) as u8, 255]);
    }
    let dib_v1 = rgba_to_dib_bytes(6, 3, &opaque_rgba);
    let (png_v1, w_v1, h_v1) = dib_to_png(&dib_v1).expect("cf_dib -> png");
    assert_eq!((w_v1, h_v1), (6, 3));
    let decoded_v1 = ImageReader::with_format(Cursor::new(&png_v1), ImageFormat::Png)
        .decode()
        .unwrap()
        .to_rgba8();
    assert_eq!(decoded_v1.as_raw(), &opaque_rgba);

    // Reject SVG masquerading as PNG or DIB
    let svg = b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>";
    assert_eq!(
        validate_png_clipboard_bytes(svg).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(dib_to_png(svg).unwrap_err().code(), ErrorCode::InvalidArgument);

    // 5. Lossless UTF-8 <-> UTF-16LE NUL-terminated roundtrip (Chinese + surrogate-pair Emoji + trailing heap zero)
    let sample = "中文剪贴板无损同步 🚀🧪\nLine 2 with tabs\tand symbols & | ;";
    let mut utf16_raw = utf8_to_utf16le_clipboard_bytes(sample);
    utf16_raw.extend_from_slice(&[0xAA, 0xBB, 0x00, 0x00]); // trailing bytes past NUL terminator ignored
    assert_eq!(utf16le_clipboard_bytes_to_utf8(&utf16_raw).unwrap(), sample);

    // 6. `ShellExecuteW` URL validator (`mynote open`): preserves `&` literally and blocks non-localhost / command paths
    let valid_ticket_url = "http://localhost:19876/v1/local/auth/exchange?ticket=t123&probe=calc.exe";
    let utf16_url = validate_local_open_url(valid_ticket_url).expect("localhost ticket URL must pass");
    assert_eq!(*utf16_url.last().unwrap(), 0u16);
    assert_eq!(
        String::from_utf16(&utf16_url[..utf16_url.len() - 1]).unwrap(),
        valid_ticket_url
    );

    for bad_url in [
        "",
        "cmd.exe /c calc.exe",
        r"C:\Windows\System32\calc.exe",
        r"\\192.168.1.1\share\evil.exe",
        "file:///C:/Windows/System32/calc.exe",
        "javascript:alert(1)",
        "http://127.0.0.1:19876/v1/local/auth/exchange?ticket=abc",
        "https://evil.example/phish",
        "http://localhost/no-port",
        "http://localhost:19876/v1/local/auth/exchange?ticket=abc\0evil",
    ] {
        assert_eq!(
            validate_local_open_url(bad_url).unwrap_err().code(),
            ErrorCode::InvalidArgument,
            "expected {bad_url:?} to be rejected"
        );
    }
}

#[cfg(windows)]
mod windows_live {
    use super::*;
    use axum::body::Bytes;
    use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, State};
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, put};
    use axum::{Json, Router};
    use image::codecs::jpeg::JpegEncoder;
    use image::RgbaImage;
    use mynote_cli::clip_watch::Win32ClipboardWatcher;
    use mynote_cli::clipboard::{
        read_win32_clipboard_with_trace, register_win_formats, transcode_to_png, write_raw_win32_clipboard,
        ClipboardPayload, ClipboardWriteOpts, NativeSystemClipboard, ReadClipboardResult, SystemClipboard,
        WinRawClipboardSpec,
    };
    use mynote_cli::daemon::{start_daemon_with_clipboard, DaemonConfig};
    use mynote_cli::sync_client::{ensure_clip_key, RelayClient};
    use mynote_core::clip::CLIP_DEFAULT_TTL_MS;
    use mynote_core::ids::JournalEpoch;
    use mynote_store::{DeviceCredentials, LocalStore};
    use serde::Deserialize;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as TokioMutex;

    /// Session-global mutex serializing all live Win32 clipboard operations within `sec_win_clip`.
    static WIN_CLIPBOARD_LOCK: TokioMutex<()> = TokioMutex::const_new(());

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
        let p = std::env::temp_dir().join(format!(
            "mynote_sec_win_clip_{tag}_{}_{ts}_{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn sha256_hex(s: &str) -> String {
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
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

    #[derive(Clone)]
    struct MockClipRecord {
        clip_id: String,
        clip_kid: String,
        device_id: String,
        kind: String,
        created_at_ms: i64,
        expires_at_ms: i64,
        meta_envelope_b64: String,
        has_blob: bool,
        blob_bytes: Option<i64>,
        blob_envelope: Option<Vec<u8>>,
    }

    struct RelayState {
        epoch: JournalEpoch,
        devices: BTreeMap<String, (String, String)>,
        clip_key_material: Option<(i64, String)>,
        clips: BTreeMap<String, MockClipRecord>,
        total_pushes: Arc<AtomicUsize>,
    }

    impl RelayState {
        fn new() -> Self {
            Self {
                epoch: JournalEpoch::from_random_bytes([0x79; 16]),
                devices: BTreeMap::new(),
                clip_key_material: None,
                clips: BTreeMap::new(),
                total_pushes: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn register_device(&mut self, device_id: &str, token: &str, scope: &str) {
            self.devices
                .insert(sha256_hex(token), (device_id.to_string(), scope.to_string()));
        }

        #[allow(clippy::result_large_err)]
        fn auth(&self, headers: &HeaderMap) -> Result<String, Response> {
            let tok = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .unwrap_or_default();
            if let Some((dev_id, _)) = self.devices.get(&sha256_hex(tok)) {
                Ok(dev_id.clone())
            } else {
                Err((
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "ok": false,
                        "error": { "code": "AUTH_REQUIRED", "message": "unauthorized" }
                    })),
                )
                    .into_response())
            }
        }
    }

    #[derive(Deserialize)]
    struct ClipListQuery {
        since_id: Option<String>,
        limit: Option<usize>,
    }

    async fn start_mock_relay(state: Arc<StdMutex<RelayState>>) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route(
                "/v1/keys",
                get(
                    |State(st): State<Arc<StdMutex<RelayState>>>, headers: HeaderMap| async move {
                        let g = st.lock().unwrap();
                        if let Err(r) = g.auth(&headers) {
                            return r;
                        }
                        let ck = g
                            .clip_key_material
                            .as_ref()
                            .map(|(gen, b64)| serde_json::json!({ "gen": gen, "blob_b64": b64 }));
                        Json(serde_json::json!({
                            "ok": true,
                            "key_records": [],
                            "shred_marks": [],
                            "key_material": {
                                "keyring": Value::Null,
                                "vault_header": Value::Null,
                                "clip_key": ck,
                            }
                        }))
                        .into_response()
                    },
                )
                .post(
                    |State(st): State<Arc<StdMutex<RelayState>>>,
                     headers: HeaderMap,
                     Json(body): Json<Value>| async move {
                        let mut g = st.lock().unwrap();
                        if let Err(r) = g.auth(&headers) {
                            return r;
                        }
                        let mut gen_out = g.clip_key_material.as_ref().map(|(gen, _)| *gen);
                        if let Some(ck) = body["key_material"]["clip_key"].as_object() {
                            let gen = ck["gen"].as_i64().unwrap_or(1);
                            let b64 = ck["blob_b64"].as_str().unwrap_or_default().to_string();
                            g.clip_key_material = Some((gen, b64));
                            gen_out = Some(gen);
                        }
                        Json(serde_json::json!({
                            "ok": true,
                            "key_material_gens": { "clip_key": gen_out }
                        }))
                        .into_response()
                    },
                ),
            )
            .route(
                "/v1/sync/pull",
                get(
                    |State(st): State<Arc<StdMutex<RelayState>>>, headers: HeaderMap| async move {
                        let g = st.lock().unwrap();
                        if let Err(r) = g.auth(&headers) {
                            return r;
                        }
                        Json(serde_json::json!({
                            "ok": true,
                            "epoch": g.epoch.to_string(),
                            "ops": [],
                            "keys_digest": "",
                            "head_seq": 0,
                            "has_more": false,
                        }))
                        .into_response()
                    },
                ),
            )
            .route(
                "/v1/clip",
                get(
                    |State(st): State<Arc<StdMutex<RelayState>>>,
                     headers: HeaderMap,
                     Query(q): Query<ClipListQuery>| async move {
                        let g = st.lock().unwrap();
                        if let Err(r) = g.auth(&headers) {
                            return r;
                        }
                        let lim = q.limit.unwrap_or(100).min(100);
                        let mut items: Vec<Value> = g
                            .clips
                            .values()
                            .filter(|c| q.since_id.as_deref().is_none_or(|s| c.clip_id.as_str() > s))
                            .map(|c| {
                                serde_json::json!({
                                    "clip_id": c.clip_id,
                                    "clip_kid": c.clip_kid,
                                    "device_id": c.device_id,
                                    "kind": c.kind,
                                    "created_at_ms": c.created_at_ms,
                                    "expires_at_ms": c.expires_at_ms,
                                    "meta_envelope_b64": c.meta_envelope_b64,
                                    "has_blob": c.has_blob,
                                    "blob_bytes": c.blob_bytes,
                                })
                            })
                            .collect();
                        items.truncate(lim);
                        Json(serde_json::json!({ "ok": true, "items": items })).into_response()
                    },
                )
                .post(
                    |State(st): State<Arc<StdMutex<RelayState>>>,
                     headers: HeaderMap,
                     Json(body): Json<Value>| async move {
                        let mut g = st.lock().unwrap();
                        let dev_id = match g.auth(&headers) {
                            Ok(d) => d,
                            Err(r) => return r,
                        };
                        g.total_pushes.fetch_add(1, Ordering::SeqCst);
                        let clip_id = body["clip_id"].as_str().unwrap().to_string();
                        let clip_kid = body["clip_kid"].as_str().unwrap().to_string();
                        let kind = body["kind"].as_str().unwrap_or("text").to_string();
                        let env_b64 = body["meta_envelope_b64"].as_str().unwrap().to_string();
                        let created = now_ms();
                        let expires = created + CLIP_DEFAULT_TTL_MS;
                        g.clips.insert(
                            clip_id.clone(),
                            MockClipRecord {
                                clip_id: clip_id.clone(),
                                clip_kid,
                                device_id: dev_id,
                                kind,
                                created_at_ms: created,
                                expires_at_ms: expires,
                                meta_envelope_b64: env_b64,
                                has_blob: false,
                                blob_bytes: None,
                                blob_envelope: None,
                            },
                        );
                        Json(serde_json::json!({
                            "ok": true,
                            "clip_id": clip_id,
                            "created_at_ms": created,
                            "expires_at_ms": expires,
                        }))
                        .into_response()
                    },
                ),
            )
            .route(
                "/v1/clip/blob",
                put(
                    |State(st): State<Arc<StdMutex<RelayState>>>,
                     headers: HeaderMap,
                     body: Bytes| async move {
                        let mut g = st.lock().unwrap();
                        let dev_id = match g.auth(&headers) {
                            Ok(d) => d,
                            Err(r) => return r,
                        };
                        g.total_pushes.fetch_add(1, Ordering::SeqCst);
                        let clip_id = headers.get("x-clip-id").unwrap().to_str().unwrap().to_string();
                        let clip_kid = headers.get("x-clip-kid").unwrap().to_str().unwrap().to_string();
                        let kind = headers.get("x-clip-kind").unwrap().to_str().unwrap().to_string();
                        let meta_b64 = headers.get("x-clip-meta-b64").unwrap().to_str().unwrap().to_string();
                        let created = now_ms();
                        let expires = created + CLIP_DEFAULT_TTL_MS;
                        let blob_len = body.len() as i64;
                        g.clips.insert(
                            clip_id.clone(),
                            MockClipRecord {
                                clip_id: clip_id.clone(),
                                clip_kid,
                                device_id: dev_id,
                                kind,
                                created_at_ms: created,
                                expires_at_ms: expires,
                                meta_envelope_b64: meta_b64,
                                has_blob: true,
                                blob_bytes: Some(blob_len),
                                blob_envelope: Some(body.to_vec()),
                            },
                        );
                        Json(serde_json::json!({
                            "ok": true,
                            "clip_id": clip_id,
                            "created_at_ms": created,
                            "expires_at_ms": expires,
                        }))
                        .into_response()
                    },
                ),
            )
            .route(
                "/v1/clip/{clip_id}/blob",
                get(
                    |State(st): State<Arc<StdMutex<RelayState>>>,
                     headers: HeaderMap,
                     AxumPath(clip_id): AxumPath<String>| async move {
                        let g = st.lock().unwrap();
                        if let Err(r) = g.auth(&headers) {
                            return r;
                        }
                        let Some(rec) = g.clips.get(&clip_id) else {
                            return StatusCode::NOT_FOUND.into_response();
                        };
                        let Some(blob) = rec.blob_envelope.clone() else {
                            return StatusCode::NOT_FOUND.into_response();
                        };
                        let mut resp = Response::new(axum::body::Body::from(blob));
                        resp.headers_mut().insert(
                            "content-type",
                            HeaderValue::from_static("application/octet-stream"),
                        );
                        resp.headers_mut()
                            .insert("x-clip-id", HeaderValue::from_str(&rec.clip_id).unwrap());
                        resp.headers_mut()
                            .insert("x-clip-kid", HeaderValue::from_str(&rec.clip_kid).unwrap());
                        resp.headers_mut().insert(
                            "x-clip-device-id",
                            HeaderValue::from_str(&rec.device_id).unwrap(),
                        );
                        resp
                    },
                ),
            )
            .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
            .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://127.0.0.1:{port}"), handle)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sec_win_clip_native_formats_privacy_trace_watcher_and_svg_rejection() {
        let _guard = WIN_CLIPBOARD_LOCK.lock().await;
        let clip = NativeSystemClipboard;
        let fmts = register_win_formats().expect("register Win32 clipboard formats");

        let mut watcher = Win32ClipboardWatcher::start()
            .await
            .expect("start HWND_MESSAGE + AddClipboardFormatListener watcher");
        while tokio::time::timeout(Duration::from_millis(20), watcher.next_event())
            .await
            .is_ok()
        {}

        // 1. Chinese + Emoji UTF-16LE <-> UTF-8 roundtrip + zero-polling WM_CLIPBOARDUPDATE event
        let chinese_text = "你好 Windows 剪贴板 🚀🔒 — 第一行\n第二行 UTF-16LE 无损往返 & query=1";
        let t0 = Instant::now();
        let receipt_txt = clip
            .write(
                &ClipboardPayload::Text(chinese_text.to_string()),
                ClipboardWriteOpts::default(),
            )
            .expect("write UTF-16LE text");
        assert_eq!(
            receipt_txt.written_blake3,
            *blake3::hash(chinese_text.as_bytes()).as_bytes()
        );

        let ev = tokio::time::timeout(Duration::from_secs(2), watcher.next_event())
            .await
            .expect("WM_CLIPBOARDUPDATE must fire within 2s")
            .expect("watcher channel open");
        let wake_us = t0.elapsed().as_secs_f64() * 1_000_000.0;
        let (read_txt, trace_txt) = read_win32_clipboard_with_trace().expect("read UTF-16LE text");
        println!(
            "[SEC-WIN-CLIP] UTF-16LE roundtrip + WM_CLIPBOARDUPDATE: seq={} wake={:.1}us get_data_calls={:?}",
            ev.sequence_number, wake_us, trace_txt.get_clipboard_data_calls
        );
        assert_eq!(
            read_txt,
            ReadClipboardResult::Payload(ClipboardPayload::Text(chinese_text.to_string()))
        );
        assert!(clip.current_mynote_blake3().is_none());

        // 2. `"PNG"` priority over larger `CF_DIBV5` (`0` reads of `CF_DIBV5`!)
        let small_rgba = vec![
            255, 0, 0, 255, 0, 255, 0, 255, //
            0, 0, 255, 255, 255, 255, 0, 140, //
        ];
        let mut png_2x2 = Vec::new();
        RgbaImage::from_raw(2, 2, small_rgba)
            .unwrap()
            .write_to(&mut Cursor::new(&mut png_2x2), ImageFormat::Png)
            .unwrap();
        let large_dibv5 = rgba_to_dibv5_bytes(16, 16, &[42u8; 16 * 16 * 4]);

        write_raw_win32_clipboard(&WinRawClipboardSpec {
            png_bytes: Some(png_2x2.clone()),
            dibv5_bytes: Some(large_dibv5),
            ..Default::default()
        })
        .expect("write PNG + CF_DIBV5");
        let _ = tokio::time::timeout(Duration::from_secs(2), watcher.next_event())
            .await
            .expect("WM_CLIPBOARDUPDATE for PNG");
        let (read_png, trace_png) = read_win32_clipboard_with_trace().expect("read PNG priority");
        assert_eq!(
            trace_png.get_clipboard_data_calls,
            vec![fmts.png],
            "must read ONLY registered 'PNG' and 0 bytes of CF_DIBV5"
        );
        assert_eq!(
            read_png,
            ReadClipboardResult::Payload(ClipboardPayload::Image {
                mime: "image/png".to_string(),
                bytes: png_2x2,
                width: Some(2),
                height: Some(2),
            })
        );

        // 3. `CF_DIBV5` fallback AND `CF_DIB` fallback -> lossless PNG conversion
        let fallback_rgba: Vec<u8> = (0..(8 * 6))
            .flat_map(|i| [(i * 5) as u8, (250 - i * 3) as u8, (i * 7 + 11) as u8, 255u8])
            .collect();
        write_raw_win32_clipboard(&WinRawClipboardSpec {
            dibv5_bytes: Some(rgba_to_dibv5_bytes(8, 6, &fallback_rgba)),
            ..Default::default()
        })
        .expect("write CF_DIBV5 only");
        match clip.read().expect("read CF_DIBV5 fallback") {
            ReadClipboardResult::Payload(ClipboardPayload::Image {
                mime,
                bytes,
                width,
                height,
            }) => {
                assert_eq!(mime, "image/png");
                assert_eq!((width, height), (Some(8), Some(6)));
                let decoded = ImageReader::with_format(Cursor::new(&bytes), ImageFormat::Png)
                    .decode()
                    .unwrap()
                    .to_rgba8();
                assert_eq!(decoded.as_raw(), &fallback_rgba);
            }
            other => panic!("expected Image from CF_DIBV5 fallback, got {other:?}"),
        }

        write_raw_win32_clipboard(&WinRawClipboardSpec {
            dib_bytes: Some(rgba_to_dib_bytes(8, 6, &fallback_rgba)),
            ..Default::default()
        })
        .expect("write CF_DIB only");
        match clip.read().expect("read CF_DIB fallback") {
            ReadClipboardResult::Payload(ClipboardPayload::Image {
                mime,
                bytes,
                width,
                height,
            }) => {
                assert_eq!(mime, "image/png");
                assert_eq!((width, height), (Some(8), Some(6)));
                let decoded = ImageReader::with_format(Cursor::new(&bytes), ImageFormat::Png)
                    .decode()
                    .unwrap()
                    .to_rgba8();
                assert_eq!(decoded.as_raw(), &fallback_rgba);
            }
            other => panic!("expected Image from CF_DIB fallback, got {other:?}"),
        }

        // 4. Privacy hard-filtering trace audit (0 user-payload reads!)
        write_raw_win32_clipboard(&WinRawClipboardSpec {
            unicode_text: Some("1password-master-secret".to_string()),
            exclude_from_monitor: true,
            ..Default::default()
        })
        .unwrap();
        let (priv1, ptrace1) = read_win32_clipboard_with_trace().unwrap();
        assert_eq!(
            priv1,
            ReadClipboardResult::SkippedSensitive(WIN_FMT_EXCLUDE_MONITOR.to_string())
        );
        assert!(
            ptrace1.get_clipboard_data_calls.is_empty(),
            "ExcludeClipboardContentFromMonitorProcessing must make 0 GetClipboardData calls"
        );

        write_raw_win32_clipboard(&WinRawClipboardSpec {
            unicode_text: Some("bitwarden-totp-secret".to_string()),
            can_include_in_history: Some(0),
            ..Default::default()
        })
        .unwrap();
        let (priv2, ptrace2) = read_win32_clipboard_with_trace().unwrap();
        assert_eq!(
            priv2,
            ReadClipboardResult::SkippedSensitive("CanIncludeInClipboardHistory == 0".to_string())
        );
        assert_eq!(ptrace2.get_clipboard_data_calls, vec![fmts.can_include_history]);

        write_raw_win32_clipboard(&WinRawClipboardSpec {
            unicode_text: Some("cloud-blocked-secret".to_string()),
            can_upload_to_cloud: Some(0),
            ..Default::default()
        })
        .unwrap();
        let (priv3, ptrace3) = read_win32_clipboard_with_trace().unwrap();
        assert_eq!(
            priv3,
            ReadClipboardResult::SkippedSensitive("CanUploadClipboardDataToCloud == 0".to_string())
        );
        assert_eq!(ptrace3.get_clipboard_data_calls, vec![fmts.can_upload_cloud]);

        // Sensitive/ephemeral write sets all 3 Windows privacy formats + echo marker atomically
        let ephem_receipt = clip
            .write(
                &ClipboardPayload::Text("vault-ephemeral-secret".to_string()),
                ClipboardWriteOpts {
                    synced_marker: true,
                    sensitive: true,
                    ephemeral: true,
                },
            )
            .expect("write sensitive ephemeral item");
        assert_eq!(clip.current_mynote_blake3(), Some(ephem_receipt.written_blake3));
        let (ephem_read, ephem_trace) = read_win32_clipboard_with_trace().unwrap();
        assert!(matches!(ephem_read, ReadClipboardResult::SkippedSensitive(_)));
        assert!(ephem_trace.get_clipboard_data_calls.is_empty());
        let enum_ids: Vec<u32> = ephem_trace.enumerated_formats.iter().map(|(id, _)| *id).collect();
        assert!(enum_ids.contains(&fmts.echo_marker));
        assert!(enum_ids.contains(&fmts.exclude_monitor));
        assert!(enum_ids.contains(&fmts.can_include_history));
        assert!(enum_ids.contains(&fmts.can_upload_cloud));

        // 5. SVG rejection on `image/svg+xml`, spoofed `"PNG"`, and `NativeSystemClipboard::write`
        let evil_svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"></svg>".to_vec();
        write_raw_win32_clipboard(&WinRawClipboardSpec {
            svg_xml_bytes: Some(evil_svg.clone()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(clip.read().unwrap_err().code(), ErrorCode::InvalidArgument);

        write_raw_win32_clipboard(&WinRawClipboardSpec {
            png_bytes: Some(evil_svg.clone()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(clip.read().unwrap_err().code(), ErrorCode::InvalidArgument);

        assert_eq!(
            clip.write(
                &ClipboardPayload::Image {
                    mime: "image/svg+xml".to_string(),
                    bytes: evil_svg,
                    width: None,
                    height: None,
                },
                ClipboardWriteOpts::default(),
            )
            .unwrap_err()
            .code(),
            ErrorCode::InvalidArgument
        );

        clip.clear().expect("clear clipboard");
        assert_eq!(clip.read().unwrap(), ReadClipboardResult::Empty);

        // Clean `PostThreadMessageW(..., WM_QUIT, ...)` / `DestroyWindow` shutdown
        watcher.stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sec_win_clip_daemon_e2e_zero_sensitive_outbound_echo_immunity_and_open_ticket() {
        let _guard = WIN_CLIPBOARD_LOCK.lock().await;
        let clip = NativeSystemClipboard;
        clip.clear()
            .expect("clear initial clipboard before daemon watch test");

        let relay_state = Arc::new(StdMutex::new(RelayState::new()));
        let pushes = Arc::clone(&relay_state.lock().unwrap().total_pushes);
        let (relay_url, relay_task) = start_mock_relay(Arc::clone(&relay_state)).await;

        let dir_a = temp_dir("desk_a");
        let dir_b = temp_dir("desk_b");
        let tok_a = "mnt_win_clip_desk_a_token";
        let tok_b = "mnt_win_clip_desk_b_token";
        {
            let mut st_a = LocalStore::open(&dir_a).unwrap();
            let dev_a = st_a.device_id().unwrap().to_string();
            st_a.save_credentials(&DeviceCredentials {
                sync_url: relay_url.clone(),
                device_token: tok_a.to_string(),
                scope: "read-write".to_string(),
            })
            .unwrap();

            let mut st_b = LocalStore::open(&dir_b).unwrap();
            let dev_b = st_b.device_id().unwrap().to_string();
            let smk = st_a.active_smk().unwrap().1;
            let b_gen = st_b.active_smk().unwrap().0 + 1;
            st_b.put_local_smk(b_gen, &smk).unwrap();
            st_b.save_credentials(&DeviceCredentials {
                sync_url: relay_url.clone(),
                device_token: tok_b.to_string(),
                scope: "read-write".to_string(),
            })
            .unwrap();

            {
                let mut g = relay_state.lock().unwrap();
                g.register_device(&dev_a, tok_a, "read-write");
                g.register_device(&dev_b, tok_b, "read-write");
            }

            let client_a = RelayClient::new(&relay_url, tok_a).unwrap();
            let _ = ensure_clip_key(&mut st_a, &client_a).await.unwrap();
            let client_b = RelayClient::new(&relay_url, tok_b).unwrap();
            let _ = ensure_clip_key(&mut st_b, &client_b).await.unwrap();
        }

        // Start live Windows Daemon A backed by real `NativeSystemClipboard`
        let daemon_a = start_daemon_with_clipboard(
            DaemonConfig {
                data_dir: dir_a.clone(),
                port: 0,
                enable_cloud_sync: false,
            },
            Arc::new(NativeSystemClipboard),
        )
        .await
        .expect("start Windows daemon with NativeSystemClipboard");

        // Enable opt-in background WM_CLIPBOARDUPDATE watcher
        daemon_a
            .state
            .update_clip_watch(Some(false), Some(true), Some("auto-apply".to_string()))
            .expect("enable clip watch");
        tokio::time::sleep(Duration::from_millis(80)).await;

        // 1. Privacy formats + AWS secret + SVG -> MUST produce 0 outbound HTTP captures!
        write_raw_win32_clipboard(&WinRawClipboardSpec {
            unicode_text: Some("1password-vault-item".to_string()),
            exclude_from_monitor: true,
            ..Default::default()
        })
        .unwrap();
        tokio::time::sleep(Duration::from_millis(380)).await;

        write_raw_win32_clipboard(&WinRawClipboardSpec {
            unicode_text: Some("no-history-secret".to_string()),
            can_include_in_history: Some(0),
            ..Default::default()
        })
        .unwrap();
        tokio::time::sleep(Duration::from_millis(380)).await;

        write_raw_win32_clipboard(&WinRawClipboardSpec {
            unicode_text: Some("no-cloud-secret".to_string()),
            can_upload_to_cloud: Some(0),
            ..Default::default()
        })
        .unwrap();
        tokio::time::sleep(Duration::from_millis(380)).await;

        write_raw_win32_clipboard(&WinRawClipboardSpec {
            unicode_text: Some("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE".to_string()),
            ..Default::default()
        })
        .unwrap();
        tokio::time::sleep(Duration::from_millis(380)).await;

        write_raw_win32_clipboard(&WinRawClipboardSpec {
            svg_xml_bytes: Some(b"<svg onload='alert(1)'/>".to_vec()),
            ..Default::default()
        })
        .unwrap();
        tokio::time::sleep(Duration::from_millis(380)).await;

        assert_eq!(
            pushes.load(Ordering::SeqCst),
            0,
            "SEC-WIN-CLIP VIOLATION: privacy formats, secrets, and SVG must cause 0 outbound relay pushes"
        );

        // Also verify CLI `mynote clip push` rejects SVG file and SVG clipboard with exit 2 INVALID_ARGUMENT
        let svg_file = dir_a.join("attack.svg");
        std::fs::write(&svg_file, b"<svg xmlns='http://www.w3.org/2000/svg'/>").unwrap();
        let svg_cli_dir = dir_a.clone();
        let svg_path_str = svg_file.to_string_lossy().to_string();
        let svg_cli_out = tokio::task::spawn_blocking(move || {
            run_cli_with_env(
                &svg_cli_dir,
                &["clip", "push", "--file", &svg_path_str, "--json"],
                None,
                &[],
            )
        })
        .await
        .unwrap();
        assert_eq!(svg_cli_out.status.code(), Some(2));
        let svg_cli_json: Value = serde_json::from_slice(&svg_cli_out.stdout).unwrap();
        assert_eq!(svg_cli_json["error"]["code"], "INVALID_ARGUMENT");
        assert_eq!(pushes.load(Ordering::SeqCst), 0);

        // 2. Real user copies Chinese UTF-8, `"PNG"`, and `CF_DIBV5` -> auto-captured via WM_CLIPBOARDUPDATE
        //    and roundtripped losslessly to Desktop B!
        let user_cn = "Windows 后台事件监听自动同步测试 🎯 — 零轮询";
        write_raw_win32_clipboard(&WinRawClipboardSpec {
            unicode_text: Some(user_cn.to_string()),
            ..Default::default()
        })
        .unwrap();
        for _ in 0..30 {
            if pushes.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            pushes.load(Ordering::SeqCst),
            1,
            "Chinese UTF-8 text must auto-upload once"
        );

        let png_rgba = vec![
            12, 34, 56, 255, 78, 90, 123, 200, //
            210, 180, 150, 255, 45, 67, 89, 128, //
        ];
        let mut orig_png = Vec::new();
        RgbaImage::from_raw(2, 2, png_rgba.clone())
            .unwrap()
            .write_to(&mut Cursor::new(&mut orig_png), ImageFormat::Png)
            .unwrap();
        write_raw_win32_clipboard(&WinRawClipboardSpec {
            png_bytes: Some(orig_png.clone()),
            ..Default::default()
        })
        .unwrap();
        for _ in 0..30 {
            if pushes.load(Ordering::SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            pushes.load(Ordering::SeqCst),
            2,
            "PNG image must auto-upload once"
        );

        let dib_rgba: Vec<u8> = (0..(4 * 3))
            .flat_map(|i| [(i * 17) as u8, (200 - i * 11) as u8, (i * 23 + 9) as u8, 255u8])
            .collect();
        write_raw_win32_clipboard(&WinRawClipboardSpec {
            dibv5_bytes: Some(rgba_to_dibv5_bytes(4, 3, &dib_rgba)),
            ..Default::default()
        })
        .unwrap();
        for _ in 0..30 {
            if pushes.load(Ordering::SeqCst) >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            pushes.load(Ordering::SeqCst),
            3,
            "CF_DIBV5 image must auto-upload as PNG once"
        );

        // Verify Desktop B pulls all 3 encrypted clips losslessly
        let dir_b_pull = dir_b.clone();
        let ls_b = tokio::task::spawn_blocking(move || {
            let _ = run_cli_with_env(&dir_b_pull, &["clip", "pull", "--json"], None, &[]);
            run_cli_with_env(&dir_b_pull, &["clip", "ls", "--json"], None, &[])
        })
        .await
        .unwrap();
        assert_eq!(ls_b.status.code(), Some(0));
        let ls_json: Value = serde_json::from_slice(&ls_b.stdout).unwrap();
        let items = ls_json["data"]["items"].as_array().unwrap();
        assert_eq!(items.len(), 3);

        // Newest is CF_DIBV5 -> PNG (4x3), middle is 2x2 PNG, oldest is Chinese UTF-8 text
        let cid_dib = items[0]["clip_id"].as_str().unwrap().to_string();
        let cid_png = items[1]["clip_id"].as_str().unwrap().to_string();
        let cid_txt = items[2]["clip_id"].as_str().unwrap().to_string();

        let dir_b1 = dir_b.clone();
        let out_txt = tokio::task::spawn_blocking(move || {
            run_cli_with_env(&dir_b1, &["clip", "pull", "--id", &cid_txt, "--raw"], None, &[])
        })
        .await
        .unwrap();
        assert_eq!(String::from_utf8(out_txt.stdout).unwrap(), user_cn);

        let dir_b2 = dir_b.clone();
        let out_png = tokio::task::spawn_blocking(move || {
            run_cli_with_env(&dir_b2, &["clip", "pull", "--id", &cid_png, "--raw"], None, &[])
        })
        .await
        .unwrap();
        assert_eq!(out_png.stdout, orig_png);

        let dir_b3 = dir_b.clone();
        let out_dib = tokio::task::spawn_blocking(move || {
            run_cli_with_env(&dir_b3, &["clip", "pull", "--id", &cid_dib, "--raw"], None, &[])
        })
        .await
        .unwrap();
        let decoded_dib = ImageReader::with_format(Cursor::new(&out_dib.stdout), ImageFormat::Png)
            .decode()
            .unwrap()
            .to_rgba8();
        assert_eq!(decoded_dib.as_raw(), &dib_rgba);

        // 3. Dual Echo-Loop Immunity on Windows: Desktop B pushes a JPEG clip -> Desktop A pulls &
        //    auto-applies transcoded PNG + `MyNoteClipEchoMarker` -> 0 echo pushes (even if an external
        //    clipboard history tool re-writes the PNG without `MyNoteClipEchoMarker` within 2,000 ms)!
        let mut jpeg_bytes = Vec::new();
        let rgb_img = image::DynamicImage::ImageRgba8(RgbaImage::from_fn(8, 8, |x, y| {
            image::Rgba([(x * 25) as u8, (y * 25) as u8, 180, 255])
        }))
        .to_rgb8();
        JpegEncoder::new_with_quality(&mut jpeg_bytes, 85)
            .encode_image(&rgb_img)
            .unwrap();
        let (expected_transcoded_png, _, _) = transcode_to_png(&jpeg_bytes).unwrap();
        let jpg_file = dir_b.join("remote.jpg");
        std::fs::write(&jpg_file, &jpeg_bytes).unwrap();
        let jpg_str = jpg_file.to_string_lossy().to_string();
        let dir_b_push = dir_b.clone();
        let push_b_out = tokio::task::spawn_blocking(move || {
            run_cli_with_env(
                &dir_b_push,
                &["clip", "push", "--file", &jpg_str, "--json"],
                None,
                &[],
            )
        })
        .await
        .unwrap();
        assert_eq!(push_b_out.status.code(), Some(0));
        let push_b_json: Value = serde_json::from_slice(&push_b_out.stdout).unwrap();
        let remote_jpg_id = push_b_json["data"]["clip_id"].as_str().unwrap().to_string();
        assert_eq!(pushes.load(Ordering::SeqCst), 4);

        // Pull into Daemon A and apply to Windows clipboard
        let dir_a_pull = dir_a.clone();
        let rid_clone = remote_jpg_id.clone();
        let apply_out = tokio::task::spawn_blocking(move || {
            run_cli_with_env(
                &dir_a_pull,
                &["clip", "pull", "--id", &rid_clone, "--apply", "--json"],
                None,
                &[],
            )
        })
        .await
        .unwrap();
        assert_eq!(apply_out.status.code(), Some(0));
        tokio::time::sleep(Duration::from_millis(380)).await;
        assert_eq!(
            pushes.load(Ordering::SeqCst),
            4,
            "MyNoteClipEchoMarker + EchoGuard must suppress echo upload"
        );

        // Simulate external clipboard manager re-setting PNG WITHOUT MyNoteClipEchoMarker inside 2s window
        write_raw_win32_clipboard(&WinRawClipboardSpec {
            png_bytes: Some(expected_transcoded_png),
            echo_marker: false,
            ..Default::default()
        })
        .unwrap();
        tokio::time::sleep(Duration::from_millis(380)).await;
        assert_eq!(
            pushes.load(Ordering::SeqCst),
            4,
            "Layer-2 BLAKE3 EchoGuard must suppress marker-stripped PNG echo upload"
        );

        // 4. Verify `mynote open` over Windows Named Pipe produces valid `http://localhost:<port>` ticket URL
        let dir_open1 = dir_a.clone();
        let open_json_out =
            tokio::task::spawn_blocking(move || run_cli_with_env(&dir_open1, &["open", "--json"], None, &[]))
                .await
                .unwrap();
        assert_eq!(open_json_out.status.code(), Some(0));
        let open_j: Value = serde_json::from_slice(&open_json_out.stdout).unwrap();
        let ticket_url = open_j["data"]["url"].as_str().unwrap();
        assert!(ticket_url.starts_with(&format!(
            "http://localhost:{}/v1/local/auth/exchange?ticket=",
            daemon_a.port
        )));
        validate_local_open_url(ticket_url).expect("daemon ticket URL must pass ShellExecuteW validator");

        let dir_open2 = dir_a.clone();
        let open_human_out = tokio::task::spawn_blocking(move || {
            run_cli_with_env(&dir_open2, &["open"], None, &[("MYNOTE_NO_BROWSER", "1")])
        })
        .await
        .unwrap();
        assert_eq!(open_human_out.status.code(), Some(0));
        let printed_url = String::from_utf8(open_human_out.stdout).unwrap();
        validate_local_open_url(printed_url.trim())
            .expect("human ticket URL must pass ShellExecuteW validator");

        println!(
            "[SEC-WIN-CLIP] E2E Windows Daemon WM_CLIPBOARDUPDATE + privacy 0-outbound + lossless UTF-8/PNG/CF_DIBV5 + JPEG->PNG echo immunity + mynote open PASS"
        );

        daemon_a.shutdown();
        relay_task.abort();
        let _ = clip.clear();
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }
}
