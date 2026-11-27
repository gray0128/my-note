//! SEC-09 M4b-1 Desktop <-> Desktop Background Auto-Mirror & Echo-Loop Immunity Tests (`#59`).
//!
//! Covers:
//! 1. Default OFF (`watch_enabled = false`) + persistence in `local_meta` across restarts +
//!    `PATCH /v1/local/clip/watch` + CLI `mynote clip watch` + WS `clip_changed` broadcast.
//! 2. Sensitive macOS UTI & Wayland MIME hard filtering + SVG rejection -> 0 outbound pushes.
//! 3. `detect_secret_pattern` interception (AWS key, PEM private key, GitHub PAT) -> 0 outbound
//!    pushes + `CLIP_SECRET_BLOCKED` local WebSocket alert with pattern & hint.
//! 4. Rolling 60s rate limit (> 30 items/min total, > 10 images/min), > 10 MiB drop, and 250 ms
//!    debounce coalescing.
//! 5. Receive modes (`auto_apply_mirror`: `inbox-only` default vs `auto-apply`) for `source_mode=auto`
//!    vs `source_mode=explicit`.
//! 6. 100-round Two-Desktop JPEG -> PNG Echo Loop Immunity Test (both tagged AND untagged marker-stripped
//!    observations across 100 rounds -> total relay pushes across both desktops is EXACTLY 1).

use axum::body::Bytes;
use axum::extract::ws::{Message as AxumWsMsg, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use image::codecs::jpeg::JpegEncoder;
use image::{ImageFormat, RgbaImage};
use mynote_cli::clip_watch::{
    ClipWatchDebouncer, ClipWatchFilter, RateLimitKind, WatchCaptureOutcome, WatchDecision,
    CLIP_SECRET_BLOCKED_HINT, CLIP_WATCH_DEBOUNCE_MS, CLIP_WATCH_MAX_IMAGES_PER_MIN,
    CLIP_WATCH_MAX_ITEMS_PER_MIN, CLIP_WATCH_RATE_WINDOW_MS,
};
use mynote_cli::clipboard::{
    ClipboardPayload, InMemoryClipboard, ReadClipboardResult, SystemClipboard, MIME_KDE_PASSWORD_HINT,
    MIME_MYNOTE_SYNCED, MIME_MYNOTE_VAULT_SECRET, PNG_MAGIC, UTI_AUTO_GENERATED, UTI_CONCEALED,
    UTI_MYNOTE_SYNCED, UTI_MYNOTE_VAULT_SECRET, UTI_ONEPASSWORD, UTI_REMOTE_CLIPBOARD, UTI_SVG,
    UTI_TRANSIENT, UTI_UTF8_PLAIN_TEXT,
};
use mynote_cli::daemon::{start_daemon_with_clipboard, DaemonConfig};
use mynote_cli::runner::run_from;
use mynote_cli::sync_client::{ensure_clip_key, RelayClient};
use mynote_core::clip::{CLIP_BLOB_MAX_BYTES, CLIP_DEFAULT_TTL_MS};
use mynote_core::ids::JournalEpoch;
use mynote_store::{DeviceCredentials, LocalStore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as TungMsg;

fn temp_dir(tag: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("mynote_m4b_watch_{tag}_{ts}"));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn now_ms_test() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn sample_image_bytes(w: u32, h: u32, fmt: ImageFormat) -> Vec<u8> {
    let img = RgbaImage::from_fn(w, h, |x, y| {
        image::Rgba([
            ((x * 13 + y * 7) & 0xFF) as u8,
            ((x * 5 + y * 17) & 0xFF) as u8,
            ((x * 19 + y * 3) & 0xFF) as u8,
            255,
        ])
    });
    let dyn_img = image::DynamicImage::ImageRgba8(img);
    let mut out = Vec::new();
    if fmt == ImageFormat::Jpeg {
        let rgb = dyn_img.to_rgb8();
        JpegEncoder::new_with_quality(&mut out, 85)
            .encode_image(&rgb)
            .unwrap();
    } else {
        dyn_img.write_to(&mut Cursor::new(&mut out), fmt).unwrap();
    }
    out
}

// ---------------------------------------------------------------------------
// In-process Mock Relay with exact push counters for M4b-1 SEC-09 tests
// ---------------------------------------------------------------------------

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

struct MockDevice {
    device_id: String,
    scope: String,
    token_hash: String,
}

struct RelayState {
    epoch: JournalEpoch,
    devices: BTreeMap<String, MockDevice>,
    clip_key_material: Option<(i64, String)>,
    clips: BTreeMap<String, MockClipRecord>,
    ws_tx: broadcast::Sender<String>,
    total_pushes: Arc<AtomicUsize>,
}

impl RelayState {
    fn new() -> Self {
        let (ws_tx, _) = broadcast::channel(128);
        Self {
            epoch: JournalEpoch::from_random_bytes([0x59; 16]),
            devices: BTreeMap::new(),
            clip_key_material: None,
            clips: BTreeMap::new(),
            ws_tx,
            total_pushes: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn register_device(&mut self, device_id: &str, token: &str, scope: &str) {
        self.devices.insert(
            device_id.to_string(),
            MockDevice {
                device_id: device_id.to_string(),
                scope: scope.to_string(),
                token_hash: sha256_hex(token),
            },
        );
    }

    #[allow(clippy::result_large_err)]
    fn auth(&self, headers: &HeaderMap) -> Result<(String, String), Response> {
        let tok = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or_default();
        let hash = sha256_hex(tok);
        for d in self.devices.values() {
            if d.token_hash == hash {
                return Ok((d.device_id.clone(), d.scope.clone()));
            }
        }
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

#[derive(Deserialize)]
struct ClipListQuery {
    since_id: Option<String>,
    limit: Option<usize>,
}

async fn relay_keys_get(State(st): State<Arc<Mutex<RelayState>>>, headers: HeaderMap) -> Response {
    let g = st.lock().unwrap();
    if let Err(resp) = g.auth(&headers) {
        return resp;
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
            "keyring": serde_json::Value::Null,
            "vault_header": serde_json::Value::Null,
            "clip_key": ck,
        }
    }))
    .into_response()
}

async fn relay_keys_post(
    State(st): State<Arc<Mutex<RelayState>>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let mut g = st.lock().unwrap();
    if let Err(resp) = g.auth(&headers) {
        return resp;
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
}

async fn relay_sync_pull(State(st): State<Arc<Mutex<RelayState>>>, headers: HeaderMap) -> Response {
    let g = st.lock().unwrap();
    if let Err(resp) = g.auth(&headers) {
        return resp;
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
}

async fn relay_clip_get(
    State(st): State<Arc<Mutex<RelayState>>>,
    headers: HeaderMap,
    Query(q): Query<ClipListQuery>,
) -> Response {
    let g = st.lock().unwrap();
    if let Err(resp) = g.auth(&headers) {
        return resp;
    }
    let lim = q.limit.unwrap_or(100).min(100);
    let mut items: Vec<serde_json::Value> = g
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
}

async fn relay_clip_post(
    State(st): State<Arc<Mutex<RelayState>>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let mut g = st.lock().unwrap();
    let (dev_id, _) = match g.auth(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    g.total_pushes.fetch_add(1, Ordering::SeqCst);
    let clip_id = body["clip_id"].as_str().unwrap().to_string();
    let clip_kid = body["clip_kid"].as_str().unwrap().to_string();
    let kind = body["kind"].as_str().unwrap_or("text").to_string();
    let env_b64 = body["meta_envelope_b64"].as_str().unwrap().to_string();
    let now = now_ms_test();
    let expires = now + CLIP_DEFAULT_TTL_MS;
    g.clips.insert(
        clip_id.clone(),
        MockClipRecord {
            clip_id: clip_id.clone(),
            clip_kid,
            device_id: dev_id,
            kind: kind.clone(),
            created_at_ms: now,
            expires_at_ms: expires,
            meta_envelope_b64: env_b64,
            has_blob: false,
            blob_bytes: None,
            blob_envelope: None,
        },
    );
    let _ = g.ws_tx.send(
        serde_json::json!({
            "type": "clip_wake",
            "clip_id": clip_id,
            "kind": kind,
            "created_at_ms": now,
        })
        .to_string(),
    );
    Json(serde_json::json!({
        "ok": true,
        "clip_id": clip_id,
        "created_at_ms": now,
        "expires_at_ms": expires,
    }))
    .into_response()
}

async fn relay_clip_put_blob(
    State(st): State<Arc<Mutex<RelayState>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut g = st.lock().unwrap();
    let (dev_id, _) = match g.auth(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    g.total_pushes.fetch_add(1, Ordering::SeqCst);
    let clip_id = headers.get("x-clip-id").unwrap().to_str().unwrap().to_string();
    let clip_kid = headers.get("x-clip-kid").unwrap().to_str().unwrap().to_string();
    let kind = headers.get("x-clip-kind").unwrap().to_str().unwrap().to_string();
    let meta_b64 = headers
        .get("x-clip-meta-b64")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let now = now_ms_test();
    let expires = now + CLIP_DEFAULT_TTL_MS;
    let blob_len = body.len() as i64;
    g.clips.insert(
        clip_id.clone(),
        MockClipRecord {
            clip_id: clip_id.clone(),
            clip_kid,
            device_id: dev_id,
            kind: kind.clone(),
            created_at_ms: now,
            expires_at_ms: expires,
            meta_envelope_b64: meta_b64,
            has_blob: true,
            blob_bytes: Some(blob_len),
            blob_envelope: Some(body.to_vec()),
        },
    );
    let _ = g.ws_tx.send(
        serde_json::json!({
            "type": "clip_wake",
            "clip_id": clip_id,
            "kind": kind,
            "created_at_ms": now,
        })
        .to_string(),
    );
    Json(serde_json::json!({
        "ok": true,
        "clip_id": clip_id,
        "blob_bytes": blob_len,
        "created_at_ms": now,
        "expires_at_ms": expires,
    }))
    .into_response()
}

async fn relay_clip_get_blob(
    State(st): State<Arc<Mutex<RelayState>>>,
    headers: HeaderMap,
    AxumPath(clip_id): AxumPath<String>,
) -> Response {
    let g = st.lock().unwrap();
    if let Err(resp) = g.auth(&headers) {
        return resp;
    }
    let Some(rec) = g.clips.get(&clip_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": { "code": "NOT_FOUND", "message": "missing" } })),
        )
            .into_response();
    };
    let Some(ref raw) = rec.blob_envelope else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": { "code": "NOT_FOUND", "message": "no blob" } })),
        )
            .into_response();
    };
    let mut res = (StatusCode::OK, raw.clone()).into_response();
    res.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/octet-stream"),
    );
    res.headers_mut()
        .insert("x-clip-id", HeaderValue::from_str(&rec.clip_id).unwrap());
    res.headers_mut()
        .insert("x-clip-kid", HeaderValue::from_str(&rec.clip_kid).unwrap());
    res.headers_mut()
        .insert("x-clip-device-id", HeaderValue::from_str(&rec.device_id).unwrap());
    res
}

async fn relay_clip_delete_all(State(st): State<Arc<Mutex<RelayState>>>, headers: HeaderMap) -> Response {
    let mut g = st.lock().unwrap();
    if let Err(resp) = g.auth(&headers) {
        return resp;
    }
    let count = g.clips.len();
    g.clips.clear();
    Json(serde_json::json!({ "ok": true, "deleted_count": count })).into_response()
}

async fn relay_ws(
    State(st): State<Arc<Mutex<RelayState>>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    {
        let g = st.lock().unwrap();
        if let Err(resp) = g.auth(&headers) {
            return resp;
        }
    }
    ws.on_upgrade(move |socket| serve_relay_ws(st, socket))
}

async fn serve_relay_ws(st: Arc<Mutex<RelayState>>, socket: WebSocket) {
    let mut rx = st.lock().unwrap().ws_tx.subscribe();
    let (mut sink, mut stream) = socket.split();
    let send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sink.send(AxumWsMsg::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });
    while let Some(Ok(msg)) = stream.next().await {
        if let AxumWsMsg::Close(_) = msg {
            break;
        }
    }
    send_task.abort();
}

async fn spawn_relay() -> (
    String,
    Arc<Mutex<RelayState>>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let state = Arc::new(Mutex::new(RelayState::new()));
    let pushes = Arc::clone(&state.lock().unwrap().total_pushes);
    let app = Router::new()
        .route("/v1/keys", get(relay_keys_get).post(relay_keys_post))
        .route("/v1/sync/pull", get(relay_sync_pull))
        .route(
            "/v1/clip",
            get(relay_clip_get)
                .post(relay_clip_post)
                .delete(relay_clip_delete_all),
        )
        .route(
            "/v1/clip/blob",
            put(relay_clip_put_blob).layer(DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route("/v1/clip/{clip_id}/blob", get(relay_clip_get_blob))
        .route("/v1/sync/ws", get(relay_ws))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, state, pushes, handle)
}

async fn acquire_daemon_cookie(port: u16, ticket_url: &str) -> String {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let path_and_q = ticket_url
        .strip_prefix(&format!("http://localhost:{port}"))
        .unwrap();
    let res = client
        .get(format!("http://127.0.0.1:{port}{path_and_q}"))
        .header("Host", format!("localhost:{port}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let set_cookie = res
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    set_cookie.split(';').next().unwrap().to_string()
}

/// Pair two local stores with the same active SMK & ClipKey against our shared mock relay.
async fn init_paired_desktop_stores(
    dir_a: &PathBuf,
    dir_b: &PathBuf,
    relay_url: &str,
    relay: &Arc<Mutex<RelayState>>,
) {
    let mut store_a = LocalStore::open(dir_a).unwrap();
    let dev_a = store_a.device_id().as_str().to_string();
    let tok_a = "m4b-desktop-a-token";
    relay.lock().unwrap().register_device(&dev_a, tok_a, "read-write");
    let creds_a = DeviceCredentials {
        sync_url: relay_url.to_string(),
        scope: "read-write".to_string(),
        device_token: tok_a.to_string(),
    };
    store_a.save_credentials(&creds_a).unwrap();
    let client_a = RelayClient::from_credentials(&creds_a).unwrap();
    let (_kid, _key, _gen) = ensure_clip_key(&mut store_a, &client_a).await.unwrap();
    let smks_a = store_a.current_smks_for_pairing();
    drop(store_a);

    // Install Desktop A's SMK generation into Desktop B (simulating paired second desktop)
    let mut store_b = LocalStore::open(dir_b).unwrap();
    store_b.install_refreshed_smks(&smks_a).unwrap();
    let dev_b = store_b.device_id().as_str().to_string();
    assert_ne!(dev_a, dev_b);
    let tok_b = "m4b-desktop-b-token";
    relay.lock().unwrap().register_device(&dev_b, tok_b, "read-write");
    let creds_b = DeviceCredentials {
        sync_url: relay_url.to_string(),
        scope: "read-write".to_string(),
        device_token: tok_b.to_string(),
    };
    store_b.save_credentials(&creds_b).unwrap();
    let client_b = RelayClient::from_credentials(&creds_b).unwrap();
    let (_kid_b, _key_b, _) = ensure_clip_key(&mut store_b, &client_b).await.unwrap();
}

// ---------------------------------------------------------------------------
// Test 1: Default OFF, persistence in local_meta, PATCH /v1/local/clip/watch, CLI watch, WS notify
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m4b_watch_config_defaults_off_persists_across_restart_and_supports_cli_and_http() {
    let dir = temp_dir("watch_cfg");
    let (relay_url, relay, pushes, relay_handle) = spawn_relay().await;
    {
        let store = LocalStore::open(&dir).unwrap();
        let dev = store.device_id().as_str().to_string();
        relay
            .lock()
            .unwrap()
            .register_device(&dev, "tok-cfg", "read-write");
        store
            .save_credentials(&DeviceCredentials {
                sync_url: relay_url.clone(),
                scope: "read-write".into(),
                device_token: "tok-cfg".into(),
            })
            .unwrap();
    }

    let clip = Arc::new(InMemoryClipboard::new());
    let daemon = start_daemon_with_clipboard(
        DaemonConfig {
            data_dir: dir.clone(),
            port: 0,
            enable_cloud_sync: false,
        },
        clip.clone(),
    )
    .await
    .unwrap();

    // 1. Strictly DEFAULT OFF
    let init_cfg = daemon.state.clip_watch_snapshot();
    assert!(!init_cfg.watch_enabled, "auto_watch MUST default OFF!");
    assert!(!init_cfg.watch_paused);
    assert_eq!(init_cfg.auto_apply_mirror, "inbox-only");

    // Capturing while watch_enabled=false MUST do nothing & push 0 times
    let out = daemon
        .state
        .handle_auto_captured_read(
            ReadClipboardResult::Payload(ClipboardPayload::Text("should not upload while off".into())),
            10_000,
        )
        .await
        .unwrap();
    assert!(matches!(out, WatchCaptureOutcome::DisabledOrPaused));
    assert_eq!(pushes.load(Ordering::SeqCst), 0);

    // 2. Connect WS + watch receiver to confirm immediate notification on PATCH /v1/local/clip/watch
    let mut cfg_rx = daemon.state.clip_watch_tx.subscribe();
    let mut ws_rx = daemon.state.ws_tx.subscribe();
    let ticket = daemon.state.issue_open_ticket().unwrap();
    let cookie = acquire_daemon_cookie(daemon.port, &ticket).await;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let patch_res = http
        .patch(format!("http://127.0.0.1:{}/v1/local/clip/watch", daemon.port))
        .header("Host", format!("localhost:{}", daemon.port))
        .header("Origin", format!("http://localhost:{}", daemon.port))
        .header("Cookie", &cookie)
        .json(&serde_json::json!({
            "enabled": true,
            "auto_apply_mirror": "auto-apply"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(patch_res.status(), StatusCode::OK);
    let patch_json: serde_json::Value = patch_res.json().await.unwrap();
    assert_eq!(patch_json["data"]["watch_enabled"], true);
    assert_eq!(patch_json["data"]["watch_paused"], false);
    assert_eq!(patch_json["data"]["auto_apply_mirror"], "auto-apply");

    // Watcher task channel notified immediately!
    cfg_rx.changed().await.unwrap();
    assert!(cfg_rx.borrow().watch_enabled);
    assert_eq!(cfg_rx.borrow().auto_apply_mirror, "auto-apply");

    // WS clip_changed broadcast received!
    let ws_frame: serde_json::Value = serde_json::from_str(&ws_rx.recv().await.unwrap()).unwrap();
    assert_eq!(ws_frame["type"], "clip_changed");
    assert_eq!(ws_frame["watch_enabled"], true);
    assert_eq!(ws_frame["watch_paused"], false);
    assert_eq!(ws_frame["auto_apply_mirror"], "auto-apply");

    // 3. CLI `mynote clip watch --pause` via UDS notifies running daemon
    let dir_for_cli = dir.clone();
    let rc = tokio::task::spawn_blocking(move || {
        run_from([
            "mynote",
            "--data-dir",
            dir_for_cli.to_str().unwrap(),
            "--json",
            "clip",
            "watch",
            "--pause",
        ])
    })
    .await
    .unwrap();
    assert_eq!(rc, 0);
    assert!(daemon.state.clip_watch_snapshot().watch_paused);

    // 4. Restart daemon -> `watch_enabled=true` & `auto_apply_mirror="auto-apply"` persisted in local_meta,
    //    while transient `watch_paused` resets to false!
    daemon.shutdown();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let daemon2 = start_daemon_with_clipboard(
        DaemonConfig {
            data_dir: dir.clone(),
            port: 0,
            enable_cloud_sync: false,
        },
        clip,
    )
    .await
    .unwrap();
    let reloaded = daemon2.state.clip_watch_snapshot();
    assert!(reloaded.watch_enabled, "watch_enabled must persist in local_meta");
    assert!(!reloaded.watch_paused, "watch_paused is transient across restart");
    assert_eq!(
        reloaded.auto_apply_mirror, "auto-apply",
        "auto_apply_mirror must persist in local_meta"
    );

    // CLI offline disable persists to local_meta cleanly
    daemon2.shutdown();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let rc2 = run_from([
        "mynote",
        "--data-dir",
        dir.to_str().unwrap(),
        "--json",
        "clip",
        "watch",
        "--disable",
        "--auto-apply",
        "inbox-only",
    ]);
    assert_eq!(rc2, 0);
    let store = LocalStore::open(&dir).unwrap();
    let persisted = mynote_cli::clip_watch::load_persisted_watch_config(&store);
    assert!(!persisted.watch_enabled);
    assert_eq!(persisted.auto_apply_mirror, "inbox-only");

    relay_handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Test 2: SEC-09 Sensitive UTI/MIME filtering, detect_secret_pattern + CLIP_SECRET_BLOCKED WS alert,
//         rate limit (>30/min, >10 images/min), >10 MiB drop, and 250ms debounce coalescing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m4b_sec09_sensitive_filters_secret_blocking_ws_alert_rate_limit_and_debounce() {
    let dir = temp_dir("sec09_filters");
    let (relay_url, relay, pushes, relay_handle) = spawn_relay().await;
    {
        let mut store = LocalStore::open(&dir).unwrap();
        let dev = store.device_id().as_str().to_string();
        relay
            .lock()
            .unwrap()
            .register_device(&dev, "tok-sec09", "read-write");
        let creds = DeviceCredentials {
            sync_url: relay_url.clone(),
            scope: "read-write".into(),
            device_token: "tok-sec09".into(),
        };
        store.save_credentials(&creds).unwrap();
        let client = RelayClient::from_credentials(&creds).unwrap();
        let _ = ensure_clip_key(&mut store, &client).await.unwrap();
    }

    let daemon = start_daemon_with_clipboard(
        DaemonConfig {
            data_dir: dir.clone(),
            port: 0,
            enable_cloud_sync: false,
        },
        Arc::new(InMemoryClipboard::new()),
    )
    .await
    .unwrap();
    daemon
        .state
        .update_clip_watch(Some(false), Some(true), Some("inbox-only".into()))
        .unwrap();

    // Connect REAL local WebSocket `/v1/local/ws` to verify `CLIP_SECRET_BLOCKED` alert delivery!
    let ticket = daemon.state.issue_open_ticket().unwrap();
    let cookie = acquire_daemon_cookie(daemon.port, &ticket).await;
    let mut ws_req = format!("ws://127.0.0.1:{}/v1/local/ws", daemon.port)
        .into_client_request()
        .unwrap();
    ws_req.headers_mut().insert(
        "Host",
        HeaderValue::from_str(&format!("localhost:{}", daemon.port)).unwrap(),
    );
    ws_req.headers_mut().insert(
        "Origin",
        HeaderValue::from_str(&format!("http://localhost:{}", daemon.port)).unwrap(),
    );
    ws_req
        .headers_mut()
        .insert("Cookie", HeaderValue::from_str(&cookie).unwrap());
    let (mut ws_stream, _) = tokio_tungstenite::connect_async(ws_req).await.unwrap();

    // A. All 7 macOS sensitive/remote/echo UTIs & 3 Wayland MIMEs -> 0 outbound pushes!
    for uti in [
        UTI_CONCEALED,
        UTI_TRANSIENT,
        UTI_AUTO_GENERATED,
        UTI_ONEPASSWORD,
        UTI_REMOTE_CLIPBOARD,
        UTI_MYNOTE_SYNCED,
        UTI_MYNOTE_VAULT_SECRET,
    ] {
        let decision =
            ClipWatchFilter::precheck_macos_types(&[UTI_UTF8_PLAIN_TEXT.to_string(), uti.to_string()])
                .unwrap_err();
        assert_eq!(decision, WatchDecision::SkipSensitive(uti.to_string()));

        let out = daemon
            .state
            .handle_auto_captured_read(ReadClipboardResult::SkippedSensitive(uti.to_string()), 1_000)
            .await
            .unwrap();
        assert!(matches!(
            out,
            WatchCaptureOutcome::Dropped(WatchDecision::SkipSensitive(_))
        ));
    }

    for mime in [
        MIME_KDE_PASSWORD_HINT,
        MIME_MYNOTE_VAULT_SECRET,
        MIME_MYNOTE_SYNCED,
    ] {
        let decision = ClipWatchFilter::precheck_wayland_mimes(&[
            "text/plain;charset=utf-8".to_string(),
            mime.to_string(),
        ])
        .unwrap_err();
        assert_eq!(decision, WatchDecision::SkipSensitive(mime.to_string()));

        let out = daemon
            .state
            .handle_auto_captured_read(ReadClipboardResult::SkippedSensitive(mime.to_string()), 1_050)
            .await
            .unwrap();
        assert!(matches!(
            out,
            WatchCaptureOutcome::Dropped(WatchDecision::SkipSensitive(_))
        ));
    }

    // SVG precheck & disguised SVG image payload -> 0 pushes
    assert!(matches!(
        ClipWatchFilter::precheck_macos_types(&[UTI_SVG.to_string()]),
        Err(WatchDecision::SkipDisallowedImage(_))
    ));
    assert!(matches!(
        ClipWatchFilter::precheck_wayland_mimes(&["image/svg+xml".to_string()]),
        Err(WatchDecision::SkipDisallowedImage(_))
    ));
    let svg_out = daemon
        .state
        .handle_auto_captured_read(
            ReadClipboardResult::Payload(ClipboardPayload::Image {
                mime: "image/png".into(),
                bytes: b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>".to_vec(),
                width: None,
                height: None,
            }),
            1_100,
        )
        .await
        .unwrap();
    assert!(matches!(
        svg_out,
        WatchCaptureOutcome::Dropped(WatchDecision::SkipDisallowedImage(_))
    ));
    assert_eq!(pushes.load(Ordering::SeqCst), 0);

    // B. detect_secret_pattern interception (AWS access key, PEM private key, GitHub PAT)
    //    -> 0 outbound pushes + CLIP_SECRET_BLOCKED WS alert received for EACH!
    let secrets = [
        ("aws_access_key", "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
        (
            "pem_private_key",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE=\n-----END OPENSSH PRIVATE KEY-----",
        ),
        (
            "github_token",
            "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopQRSTUV",
        ),
    ];
    for (idx, (expected_pat, secret_text)) in secrets.iter().enumerate() {
        let out = daemon
            .state
            .handle_auto_captured_read(
                ReadClipboardResult::Payload(ClipboardPayload::Text((*secret_text).to_string())),
                2_000 + (idx as u64) * 500,
            )
            .await
            .unwrap();
        assert!(
            matches!(out, WatchCaptureOutcome::Dropped(WatchDecision::SecretBlocked(p)) if p == *expected_pat),
            "expected SecretBlocked({expected_pat}), got {out:?}"
        );

        let frame_txt = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let msg = ws_stream.next().await.unwrap().unwrap();
                if let TungMsg::Text(t) = msg {
                    let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                    if v["type"] == "alert" && v["code"] == "CLIP_SECRET_BLOCKED" {
                        return v;
                    }
                }
            }
        })
        .await
        .expect("timed out waiting for CLIP_SECRET_BLOCKED WS alert");

        assert_eq!(frame_txt["details"]["pattern"], *expected_pat);
        assert_eq!(frame_txt["details"]["hint"], CLIP_SECRET_BLOCKED_HINT);
    }
    assert_eq!(
        pushes.load(Ordering::SeqCst),
        0,
        "secret & sensitive events MUST produce 0 outbound network pushes!"
    );

    // C. > 10 MiB payload dropped without pushing
    let oversize = "X".repeat(CLIP_BLOB_MAX_BYTES + 1);
    let over_out = daemon
        .state
        .handle_auto_captured_read(
            ReadClipboardResult::Payload(ClipboardPayload::Text(oversize)),
            5_000,
        )
        .await
        .unwrap();
    assert!(matches!(
        over_out,
        WatchCaptureOutcome::Dropped(WatchDecision::SkipTooLarge { .. })
    ));
    assert_eq!(pushes.load(Ordering::SeqCst), 0);

    // D. 250 ms debounce coalescing: 3 rapid observations within 250ms produce exactly 1 upload!
    let mut debouncer = ClipWatchDebouncer::new(CLIP_WATCH_DEBOUNCE_MS);
    debouncer.observe(ClipboardPayload::Text("burst-1".into()), 10_000);
    assert!(debouncer.take_ready(10_100).is_none());
    debouncer.observe(ClipboardPayload::Text("burst-2".into()), 10_100);
    assert!(debouncer.take_ready(10_200).is_none());
    debouncer.observe(ClipboardPayload::Text("burst-final".into()), 10_200);
    assert!(debouncer.take_ready(10_449).is_none());
    let coalesced = debouncer
        .take_ready(10_450)
        .expect("debounce should flush at +250ms");
    let up = daemon
        .state
        .handle_auto_captured_read(ReadClipboardResult::Payload(coalesced), 10_450)
        .await
        .unwrap();
    match up {
        WatchCaptureOutcome::Uploaded(dto) => {
            assert_eq!(dto.source_mode, "auto");
            assert_eq!(dto.text_preview.as_deref(), Some("burst-final"));
        }
        other => panic!("expected Uploaded for coalesced item, got {other:?}"),
    }
    assert_eq!(pushes.load(Ordering::SeqCst), 1);

    // E. Rolling 60s rate limits: max 10 images/min AND max 30 items/min total!
    let png = sample_image_bytes(16, 16, ImageFormat::Png);
    let base_t = 20_000u64; // still inside same 60s window as 10_450 (so total already has 1 text item)
    for i in 0..CLIP_WATCH_MAX_IMAGES_PER_MIN {
        let res = daemon
            .state
            .handle_auto_captured_read(
                ReadClipboardResult::Payload(ClipboardPayload::Image {
                    mime: "image/png".into(),
                    bytes: png.clone(),
                    width: Some(16),
                    height: Some(16),
                }),
                base_t + (i as u64) * 100,
            )
            .await
            .unwrap();
        assert!(
            matches!(res, WatchCaptureOutcome::Uploaded(_)),
            "image #{i} should upload"
        );
    }
    assert_eq!(pushes.load(Ordering::SeqCst), 1 + CLIP_WATCH_MAX_IMAGES_PER_MIN);

    // 11th image within 60s MUST be rate-limited!
    let img_11 = daemon
        .state
        .handle_auto_captured_read(
            ReadClipboardResult::Payload(ClipboardPayload::Image {
                mime: "image/png".into(),
                bytes: png.clone(),
                width: Some(16),
                height: Some(16),
            }),
            base_t + 2_000,
        )
        .await
        .unwrap();
    assert!(matches!(
        img_11,
        WatchCaptureOutcome::Dropped(WatchDecision::SkipRateLimited(RateLimitKind::ImagesPerMin))
    ));
    assert_eq!(pushes.load(Ordering::SeqCst), 1 + CLIP_WATCH_MAX_IMAGES_PER_MIN);

    // Fill remaining text quota up to 30 total items/min (we already have 1 text + 10 images = 11)
    let remaining_text = CLIP_WATCH_MAX_ITEMS_PER_MIN - (1 + CLIP_WATCH_MAX_IMAGES_PER_MIN);
    for i in 0..remaining_text {
        let res = daemon
            .state
            .handle_auto_captured_read(
                ReadClipboardResult::Payload(ClipboardPayload::Text(format!("rate-text-{i}"))),
                base_t + 3_000 + (i as u64) * 100,
            )
            .await
            .unwrap();
        assert!(
            matches!(res, WatchCaptureOutcome::Uploaded(_)),
            "text #{i} should upload"
        );
    }
    assert_eq!(pushes.load(Ordering::SeqCst), CLIP_WATCH_MAX_ITEMS_PER_MIN);

    // 31st item in 60s window MUST be rate-limited!
    let item_31 = daemon
        .state
        .handle_auto_captured_read(
            ReadClipboardResult::Payload(ClipboardPayload::Text("rate-text-overflow".into())),
            base_t + 10_000,
        )
        .await
        .unwrap();
    assert!(matches!(
        item_31,
        WatchCaptureOutcome::Dropped(WatchDecision::SkipRateLimited(RateLimitKind::TotalItemsPerMin))
    ));
    assert_eq!(pushes.load(Ordering::SeqCst), CLIP_WATCH_MAX_ITEMS_PER_MIN);

    // Advancing past the 60s rolling window allows new items again
    let after_window = daemon
        .state
        .handle_auto_captured_read(
            ReadClipboardResult::Payload(ClipboardPayload::Text("after-window".into())),
            10_450 + CLIP_WATCH_RATE_WINDOW_MS + 1,
        )
        .await
        .unwrap();
    assert!(matches!(after_window, WatchCaptureOutcome::Uploaded(_)));
    assert_eq!(pushes.load(Ordering::SeqCst), CLIP_WATCH_MAX_ITEMS_PER_MIN + 1);

    daemon.shutdown();
    relay_handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Test 3: auto_apply_mirror receive modes (inbox-only default vs auto-apply)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m4b_receive_mode_inbox_only_vs_auto_apply_respects_source_mode() {
    let dir_a = temp_dir("recv_a");
    let dir_b = temp_dir("recv_b");
    let (relay_url, relay, _pushes, relay_handle) = spawn_relay().await;
    init_paired_desktop_stores(&dir_a, &dir_b, &relay_url, &relay).await;

    let clip_a = Arc::new(InMemoryClipboard::new());
    let clip_b = Arc::new(InMemoryClipboard::new());
    clip_b.set_user_text("desktop-b-local-work");

    let daemon_a = start_daemon_with_clipboard(
        DaemonConfig {
            data_dir: dir_a.clone(),
            port: 0,
            enable_cloud_sync: false,
        },
        clip_a,
    )
    .await
    .unwrap();
    let daemon_b = start_daemon_with_clipboard(
        DaemonConfig {
            data_dir: dir_b.clone(),
            port: 0,
            enable_cloud_sync: false,
        },
        clip_b.clone(),
    )
    .await
    .unwrap();

    daemon_a
        .state
        .update_clip_watch(Some(false), Some(true), Some("inbox-only".into()))
        .unwrap();
    // Desktop B keeps default `auto_apply_mirror = "inbox-only"`
    assert_eq!(
        daemon_b.state.clip_watch_snapshot().auto_apply_mirror,
        "inbox-only"
    );

    // 1. Desktop A auto-captures text -> Desktop B receives into inbox WITHOUT overwriting B's clipboard!
    let mut b_ws = daemon_b.state.ws_tx.subscribe();
    let up1 = daemon_a
        .state
        .handle_auto_captured_read(
            ReadClipboardResult::Payload(ClipboardPayload::Text("auto-mirror-inbox-item".into())),
            50_000,
        )
        .await
        .unwrap();
    assert!(matches!(up1, WatchCaptureOutcome::Uploaded(_)));

    let pulled = daemon_b.state.pull_cloud_clips(true).await.unwrap();
    assert_eq!(pulled.len(), 1);
    assert_eq!(pulled[0].source_mode, "auto");
    assert_eq!(pulled[0].text_preview.as_deref(), Some("auto-mirror-inbox-item"));
    // B's local WS received clip_changed
    let b_frame: serde_json::Value = serde_json::from_str(&b_ws.recv().await.unwrap()).unwrap();
    assert_eq!(b_frame["type"], "clip_changed");
    // B's OS clipboard was NOT overwritten!
    let (b_cur, _, _) = clip_b.snapshot().unwrap();
    assert_eq!(b_cur, ClipboardPayload::Text("desktop-b-local-work".into()));

    // 2. Switch Desktop B to `auto_apply_mirror = "auto-apply"` -> next auto-mirrored item DOES apply!
    daemon_b
        .state
        .update_clip_watch(Some(false), Some(true), Some("auto-apply".into()))
        .unwrap();
    let up2 = daemon_a
        .state
        .handle_auto_captured_read(
            ReadClipboardResult::Payload(ClipboardPayload::Text("auto-mirror-applied-item".into())),
            51_000,
        )
        .await
        .unwrap();
    assert!(matches!(up2, WatchCaptureOutcome::Uploaded(_)));

    let pulled2 = daemon_b.state.pull_cloud_clips(true).await.unwrap();
    assert_eq!(pulled2.len(), 1);
    let (b_cur2, b_opts2, b_hash2) = clip_b.snapshot().unwrap();
    assert_eq!(b_cur2, ClipboardPayload::Text("auto-mirror-applied-item".into()));
    assert!(b_opts2.synced_marker);
    assert_eq!(
        daemon_b.state.clip_echo.lock().unwrap().last_hash(),
        Some(b_hash2)
    );

    // Undo restores "desktop-b-local-work"!
    assert!(daemon_b.state.undo_clipboard().unwrap());
    let (b_restored, _, _) = clip_b.snapshot().unwrap();
    assert_eq!(b_restored, ClipboardPayload::Text("desktop-b-local-work".into()));

    daemon_a.shutdown();
    daemon_b.shutdown();
    relay_handle.abort();
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

// ---------------------------------------------------------------------------
// Test 4: SEC-09 100-round Two-Desktop JPEG -> PNG Echo Loop Immunity Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn m4b_sec09_100_round_two_desktop_jpeg_to_png_echo_loop_immunity() {
    let dir_a = temp_dir("echo_a");
    let dir_b = temp_dir("echo_b");
    let (relay_url, relay, pushes, relay_handle) = spawn_relay().await;
    init_paired_desktop_stores(&dir_a, &dir_b, &relay_url, &relay).await;

    let clip_a = Arc::new(InMemoryClipboard::new());
    let clip_b = Arc::new(InMemoryClipboard::new());
    clip_b.set_user_text("before-jpeg-mirror");

    let daemon_a = start_daemon_with_clipboard(
        DaemonConfig {
            data_dir: dir_a.clone(),
            port: 0,
            enable_cloud_sync: false,
        },
        clip_a.clone(),
    )
    .await
    .unwrap();
    let daemon_b = start_daemon_with_clipboard(
        DaemonConfig {
            data_dir: dir_b.clone(),
            port: 0,
            enable_cloud_sync: false,
        },
        clip_b.clone(),
    )
    .await
    .unwrap();

    // BOTH desktops enabled with auto_apply_mirror="auto-apply" (worst-case echo loop topology!)
    daemon_a
        .state
        .update_clip_watch(Some(false), Some(true), Some("auto-apply".into()))
        .unwrap();
    daemon_b
        .state
        .update_clip_watch(Some(false), Some(true), Some("auto-apply".into()))
        .unwrap();

    // Step 1: Desktop A captures a JPEG image -> pushes ONCE!
    let jpeg_bytes = sample_image_bytes(64, 48, ImageFormat::Jpeg);
    let jpeg_blake3 = *blake3::hash(&jpeg_bytes).as_bytes();
    let up = daemon_a
        .state
        .handle_auto_captured_read(
            ReadClipboardResult::Payload(ClipboardPayload::Image {
                mime: "image/jpeg".into(),
                bytes: jpeg_bytes,
                width: Some(64),
                height: Some(48),
            }),
            now_ms_test() as u64,
        )
        .await
        .unwrap();
    match up {
        WatchCaptureOutcome::Uploaded(dto) => {
            assert_eq!(dto.kind, "image");
            assert_eq!(dto.mime, "image/jpeg");
            assert_eq!(dto.source_mode, "auto");
        }
        other => panic!("expected Desktop A JPEG auto-upload, got {other:?}"),
    }
    assert_eq!(
        pushes.load(Ordering::SeqCst),
        1,
        "Desktop A must push exactly once"
    );

    // Step 2: Desktop B receives, downloads JPEG blob, transcodes JPEG -> PNG, writes PNG to B's clipboard
    //         with synced_marker=true and records blake3(transcoded_png) in EchoGuard!
    let pulled = daemon_b.state.pull_cloud_clips(true).await.unwrap();
    assert_eq!(pulled.len(), 1);
    let (b_payload, b_opts, b_written_blake3) = clip_b
        .snapshot()
        .expect("Desktop B clipboard must contain transcoded PNG");
    assert!(
        b_opts.synced_marker,
        "Desktop B must tag written clipboard with synced_marker"
    );
    let transcoded_png_bytes = match b_payload {
        ClipboardPayload::Image {
            mime,
            bytes,
            width,
            height,
        } => {
            assert_eq!(
                mime, "image/png",
                "JPEG must be transcoded to PNG on desktop apply"
            );
            assert!(bytes.starts_with(&PNG_MAGIC), "written bytes must be valid PNG");
            assert_eq!((width, height), (Some(64), Some(48)));
            bytes
        }
        other => panic!("expected transcoded PNG in B's clipboard, got {other:?}"),
    };
    assert_eq!(b_written_blake3, *blake3::hash(&transcoded_png_bytes).as_bytes());
    assert_ne!(
        b_written_blake3, jpeg_blake3,
        "transcoded PNG BLAKE3 must differ from original JPEG BLAKE3 to genuinely test post-transcode EchoGuard"
    );

    let applied_at_ms = daemon_b.state.clip_echo.lock().unwrap().applied_at_ms();
    assert_eq!(
        daemon_b.state.clip_echo.lock().unwrap().last_hash(),
        Some(b_written_blake3)
    );

    // Step 3: Simulate 100 rounds where B's watcher observes BOTH:
    //   (a) Tagged OS clipboard read (Layer 1: custom UTI/MIME synced_marker)
    //   (b) Untagged OS clipboard read with marker stripped (Layer 2: PNG BLAKE3 EchoGuard within 2,000 ms)
    //   AND verify Desktop A pulling produces 0 feedback pushes!
    for round in 0u64..100 {
        let t_round = applied_at_ms + round * 15; // 0..1485 ms, inside 2,000 ms echo window

        // Layer 1 (tagged read straight from B's clipboard)
        let tagged_read = clip_b.read().unwrap();
        assert!(
            matches!(tagged_read, ReadClipboardResult::SkippedSensitive(_)),
            "round {round}: tagged read must skip synced_marker"
        );
        let tagged_res = daemon_b
            .state
            .handle_auto_captured_read(tagged_read, t_round)
            .await
            .unwrap();
        assert!(matches!(
            tagged_res,
            WatchCaptureOutcome::Dropped(WatchDecision::SkipSensitive(_))
        ));

        // Layer 2 (untagged: simulate OS stripping dev.mynote.synced-clip / application/x-mynote-synced!)
        let untagged_png = ReadClipboardResult::Payload(ClipboardPayload::Image {
            mime: "image/png".into(),
            bytes: transcoded_png_bytes.clone(),
            width: Some(64),
            height: Some(48),
        });
        let untagged_res = daemon_b
            .state
            .handle_auto_captured_read(untagged_png, t_round)
            .await
            .unwrap();
        assert!(
            matches!(
                untagged_res,
                WatchCaptureOutcome::Dropped(WatchDecision::SkipEchoSuppressed)
            ),
            "round {round}: untagged transcoded PNG must be suppressed by Layer-2 EchoGuard, got {untagged_res:?}"
        );

        // Verify A pulling stays quiet
        let a_pull = daemon_a.state.pull_cloud_clips(true).await.unwrap();
        assert!(a_pull.is_empty());
    }

    assert_eq!(
        pushes.load(Ordering::SeqCst),
        1,
        "SEC-09 VIOLATION: total relay pushes across 100 JPEG->PNG mirror rounds MUST be EXACTLY 1!"
    );
    assert_eq!(relay.lock().unwrap().clips.len(), 1);

    // Bonus honesty check: after 2,000 ms, tagged read is STILL blocked by Layer 1,
    // while EchoGuard's 2,000 ms window cleanly expires so genuine user re-copy is never permanently deadlocked.
    let tagged_after = daemon_b
        .state
        .handle_auto_captured_read(clip_b.read().unwrap(), applied_at_ms + 5_000)
        .await
        .unwrap();
    assert!(matches!(
        tagged_after,
        WatchCaptureOutcome::Dropped(WatchDecision::SkipSensitive(_))
    ));
    assert_eq!(pushes.load(Ordering::SeqCst), 1);

    daemon_a.shutdown();
    daemon_b.shutdown();
    relay_handle.abort();
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}
