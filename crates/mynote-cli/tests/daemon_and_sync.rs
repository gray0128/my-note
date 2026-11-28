//! M1 Daemon (`SEC-05` + UDS single-writer + live WS), Anti-302 defense, and full dual-desktop
//! E2EE HTTP sync E2E tests (bootstrap, pairing, concurrent Path γ conflict merge, SMK rotation
//! recovery via BOTH 24-word unlock and `device refresh`, device revocation, and PITR reconciliation).

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use futures_util::StreamExt;
use mynote_cli::daemon::{start_daemon, DaemonConfig};
use mynote_cli::local_ipc::{try_send_ipc, ApplyMeta, ApplyRequest, LocalIpcRequest};
use mynote_cli::sync_client::{sha256_hex, RelayClient};
use mynote_core::error::ErrorCode;
use mynote_core::ids::{DeviceId, JournalEpoch, KeyId, OpId};
use mynote_core::model::KeyRecordRow;
use mynote_core::sim::SimRelay;
use mynote_core::sync::{PushOpDto, PushRequestDto};
use mynote_store::{DeviceCredentials, LocalStore};
use reqwest::header::{COOKIE, HOST, ORIGIN};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mynote")
}

fn temp_dir(tag: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("mynote_daemon_sync_{tag}_{ts}"));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn raw_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

/// SEC-05 (`docs/interface-contracts.md` §3.1, `docs/threat-model.md` §5.1):
/// - Sole allowed Host: `localhost:<port>` (`127.0.0.1`, `[::1]`, DNS rebind -> 403)
/// - Strict Origin on non-GET HTTP and `/v1/local/ws` (-> 403)
/// - HttpOnly SameSite=Strict session cookie required on `/v1/local/*` & WS (-> 401)
/// - One-time 10s ticket exchange -> 303 + Set-Cookie; replay -> 401
/// - Strict CSP header (no `'unsafe-inline'`) on embedded HTML
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sec05_host_origin_cookie_and_ticket_enforcement() {
    let dir = temp_dir("sec05");
    let daemon = start_daemon(DaemonConfig {
        data_dir: dir.clone(),
        port: 0,
        enable_cloud_sync: false,
    })
    .await
    .expect("start daemon");
    let port = daemon.port;
    let base_ip = format!("http://127.0.0.1:{port}");
    let base_localhost = format!("http://localhost:{port}");
    let client = raw_http_client();

    // 1. Forbidden Host headers -> 403
    for bad_host in [
        format!("127.0.0.1:{port}"),
        format!("[::1]:{port}"),
        format!("evil.rebind:{port}"),
    ] {
        let res = client
            .get(format!("{base_ip}/v1/local/bootstrap"))
            .header(HOST, &bad_host)
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "Host '{bad_host}' must be rejected with 403"
        );
    }

    // 2. Valid Host but missing or forged session cookie -> 401
    let res_no_cookie = client
        .get(format!("{base_ip}/v1/local/bootstrap"))
        .header(HOST, format!("localhost:{port}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res_no_cookie.status(), StatusCode::UNAUTHORIZED);

    let res_forged = client
        .get(format!("{base_ip}/v1/local/bootstrap"))
        .header(HOST, format!("localhost:{port}"))
        .header(COOKIE, "mynote_local_session=forged_token_value")
        .send()
        .await
        .unwrap();
    assert_eq!(res_forged.status(), StatusCode::UNAUTHORIZED);

    // 3. Issue one-time ticket over 0600 UDS, exchange -> 303 + HttpOnly SameSite=Strict cookie
    let dir_uds = dir.clone();
    let ticket_resp = tokio::task::spawn_blocking(move || {
        try_send_ipc(&dir_uds, &LocalIpcRequest::OpenTicket, Duration::from_secs(3))
    })
    .await
    .unwrap()
    .unwrap()
    .expect("daemon UDS reachable");
    assert!(ticket_resp.ok);
    let ticket_url = ticket_resp.url.expect("ticket url");
    assert!(ticket_url.starts_with(&format!("{base_localhost}/v1/local/auth/exchange?ticket=")));
    let ticket_path = ticket_url.strip_prefix(&base_localhost).unwrap();

    let ex_res = client
        .get(format!("{base_ip}{ticket_path}"))
        .header(HOST, format!("localhost:{port}"))
        .send()
        .await
        .unwrap();
    assert_eq!(ex_res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        ex_res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/")
    );
    let set_cookie = ex_res
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("Set-Cookie header")
        .to_string();
    assert!(set_cookie.contains("mynote_local_session="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    let cookie_pair = set_cookie.split(';').next().unwrap().to_string();

    // 4. Replaying the same one-time ticket -> 401
    let replay_res = client
        .get(format!("{base_ip}{ticket_path}"))
        .header(HOST, format!("localhost:{port}"))
        .send()
        .await
        .unwrap();
    assert_eq!(replay_res.status(), StatusCode::UNAUTHORIZED);

    // 5. Embedded HTML served with strict CSP (no 'unsafe-inline')
    let html_res = client
        .get(format!("{base_ip}/"))
        .header(HOST, format!("localhost:{port}"))
        .header(COOKIE, &cookie_pair)
        .send()
        .await
        .unwrap();
    assert_eq!(html_res.status(), StatusCode::OK);
    let csp = html_res
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .expect("CSP header")
        .to_string();
    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("script-src 'self' 'wasm-unsafe-eval'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(!csp.contains("'unsafe-inline'"));
    let html_body = html_res.text().await.unwrap();
    assert!(html_body.contains("id=\"app\""));

    // 6. Valid cookie -> bootstrap succeeds
    let boot_res = client
        .get(format!("{base_ip}/v1/local/bootstrap"))
        .header(HOST, format!("localhost:{port}"))
        .header(COOKIE, &cookie_pair)
        .send()
        .await
        .unwrap();
    assert_eq!(boot_res.status(), StatusCode::OK);
    let boot_json: Value = boot_res.json().await.unwrap();
    assert_eq!(boot_json["ok"], true);
    assert!(!boot_json["data"]["buffers"].as_array().unwrap().is_empty());

    // 7. POST without Origin or with evil Origin -> 403; with exact localhost Origin -> 200
    let post_no_origin = client
        .post(format!("{base_ip}/v1/local/blocks"))
        .header(HOST, format!("localhost:{port}"))
        .header(COOKIE, &cookie_pair)
        .json(&json!({ "buffer_id": "scratch", "content": "x", "lang": "plain" }))
        .send()
        .await
        .unwrap();
    assert_eq!(post_no_origin.status(), StatusCode::FORBIDDEN);

    let post_bad_origin = client
        .post(format!("{base_ip}/v1/local/blocks"))
        .header(HOST, format!("localhost:{port}"))
        .header(ORIGIN, "http://evil.example")
        .header(COOKIE, &cookie_pair)
        .json(&json!({ "buffer_id": "scratch", "content": "x", "lang": "plain" }))
        .send()
        .await
        .unwrap();
    assert_eq!(post_bad_origin.status(), StatusCode::FORBIDDEN);

    let post_ok = client
        .post(format!("{base_ip}/v1/local/blocks"))
        .header(HOST, format!("localhost:{port}"))
        .header(ORIGIN, &base_localhost)
        .header(COOKIE, &cookie_pair)
        .json(&json!({ "buffer_id": "scratch", "content": "created via api", "lang": "plain" }))
        .send()
        .await
        .unwrap();
    assert_eq!(post_ok.status(), StatusCode::OK);
    let post_body: Value = post_ok.json().await.unwrap();
    assert_eq!(post_body["ok"], true);

    // 8. WebSocket rejects bad Origin (403) & missing cookie (401), accepts valid Host+Origin+Cookie (101)
    let mut bad_ws_req = format!("ws://127.0.0.1:{port}/v1/local/ws")
        .into_client_request()
        .unwrap();
    bad_ws_req
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(&format!("localhost:{port}")).unwrap());
    bad_ws_req
        .headers_mut()
        .insert(ORIGIN, HeaderValue::from_static("http://evil.example"));
    bad_ws_req
        .headers_mut()
        .insert(COOKIE, HeaderValue::from_str(&cookie_pair).unwrap());
    assert!(tokio_tungstenite::connect_async(bad_ws_req).await.is_err());

    let mut no_cookie_ws = format!("ws://127.0.0.1:{port}/v1/local/ws")
        .into_client_request()
        .unwrap();
    no_cookie_ws
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(&format!("localhost:{port}")).unwrap());
    no_cookie_ws
        .headers_mut()
        .insert(ORIGIN, HeaderValue::from_str(&base_localhost).unwrap());
    assert!(tokio_tungstenite::connect_async(no_cookie_ws).await.is_err());

    let mut good_ws = format!("ws://127.0.0.1:{port}/v1/local/ws")
        .into_client_request()
        .unwrap();
    good_ws
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(&format!("localhost:{port}")).unwrap());
    good_ws
        .headers_mut()
        .insert(ORIGIN, HeaderValue::from_str(&base_localhost).unwrap());
    good_ws
        .headers_mut()
        .insert(COOKIE, HeaderValue::from_str(&cookie_pair).unwrap());
    let (mut ws_stream, ws_resp) = tokio_tungstenite::connect_async(good_ws)
        .await
        .expect("authenticated WS must upgrade");
    assert_eq!(ws_resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    let _ = ws_stream.close(None).await;

    daemon.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

/// CLI writes route over `0600 daemon.sock` `apply` when Daemon is running (emitting live
/// `/v1/local/ws` `blocks_changed` frame in < 200 ms), and fall back cleanly to direct SQLite WAL
/// after Daemon shuts down (`D5'`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_daemon_uds_live_ws_refresh_and_offline_fallback() {
    let dir = temp_dir("uds_ws");
    let daemon = start_daemon(DaemonConfig {
        data_dir: dir.clone(),
        port: 0,
        enable_cloud_sync: false,
    })
    .await
    .expect("start daemon");
    let port = daemon.port;
    let base_ip = format!("http://127.0.0.1:{port}");
    let base_localhost = format!("http://localhost:{port}");

    // Authenticate session cookie via UDS one-time ticket
    let dir_uds = dir.clone();
    let ticket_url = tokio::task::spawn_blocking(move || {
        try_send_ipc(&dir_uds, &LocalIpcRequest::OpenTicket, Duration::from_secs(3))
    })
    .await
    .unwrap()
    .unwrap()
    .unwrap()
    .url
    .unwrap();
    let ticket_path = ticket_url.strip_prefix(&base_localhost).unwrap();
    let ex_res = raw_http_client()
        .get(format!("{base_ip}{ticket_path}"))
        .header(HOST, format!("localhost:{port}"))
        .send()
        .await
        .unwrap();
    let cookie_pair = ex_res
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // Connect authenticated local WS
    let mut ws_req = format!("ws://127.0.0.1:{port}/v1/local/ws")
        .into_client_request()
        .unwrap();
    ws_req
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(&format!("localhost:{port}")).unwrap());
    ws_req
        .headers_mut()
        .insert(ORIGIN, HeaderValue::from_str(&base_localhost).unwrap());
    ws_req
        .headers_mut()
        .insert(COOKIE, HeaderValue::from_str(&cookie_pair).unwrap());
    let (mut ws_stream, _) = tokio_tungstenite::connect_async(ws_req).await.unwrap();

    // Run real CLI binary `mynote add` against the same data_dir -> routes via UDS `apply`!
    let t0 = Instant::now();
    let dir_clone = dir.clone();
    let cli_handle = tokio::task::spawn_blocking(move || {
        Command::new(bin())
            .arg("--data-dir")
            .arg(&dir_clone)
            .args(["add", "--json", "hello via UDS live refresh"])
            .stdin(Stdio::null())
            .output()
            .expect("run mynote add")
    });

    // Wait for WS `blocks_changed` notification carrying the newly created block
    let ws_frame = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(Ok(msg)) = ws_stream.next().await {
            if let Message::Text(txt) = msg {
                let v: Value = serde_json::from_str(&txt).unwrap();
                if v["type"] == "blocks_changed" {
                    return v;
                }
            }
        }
        panic!("WS closed before receiving blocks_changed");
    })
    .await
    .expect("WS notification timed out");
    let elapsed_ms = t0.elapsed().as_millis();

    let cli_out = cli_handle.await.unwrap();
    assert_eq!(
        cli_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&cli_out.stderr)
    );
    let cli_json: Value = serde_json::from_slice(&cli_out.stdout).unwrap();
    let block_id = cli_json["data"]["block_id"].as_str().unwrap();

    let upserts = ws_frame["upserted"].as_array().unwrap();
    assert!(
        upserts.iter().any(|b| b["id"].as_str() == Some(block_id)
            && b["content"].as_str() == Some("hello via UDS live refresh")),
        "expected WS upsert for block {block_id}, got: {ws_frame}"
    );
    eprintln!("[measured] CLI -> UDS -> SQLite -> WS live UI refresh end-to-end (including process spawn): {elapsed_ms} ms");

    // Shut down daemon and verify CLI seamlessly falls back to direct SQLite WAL write
    let _ = ws_stream.close(None).await;
    daemon.shutdown();
    tokio::time::sleep(Duration::from_millis(80)).await;

    let fallback_out = Command::new(bin())
        .arg("--data-dir")
        .arg(&dir)
        .args(["add", "--json", "direct WAL fallback after daemon stopped"])
        .stdin(Stdio::null())
        .output()
        .expect("run mynote add offline fallback");
    assert_eq!(fallback_out.status.code(), Some(0));
    let fb_json: Value = serde_json::from_slice(&fallback_out.stdout).unwrap();
    assert_eq!(fb_json["ok"], true);

    let store = LocalStore::open(&dir).unwrap();
    let blocks = store.list_blocks(None, 20).unwrap();
    assert_eq!(blocks.len(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Anti-302 captive-portal / CF Access defense (`#14` AC #1, `AGENTS.md` §3.3):
/// A `302 Found -> 200 text/html` login redirect or `200 text/html` response MUST NEVER advance
/// `last_seq` or mark local outbox ops synced.
#[tokio::test]
async fn anti_302_captive_portal_preserves_local_outbox() {
    async fn redirect_to_login() -> Response {
        (StatusCode::FOUND, [("location", "/cf-access-login")]).into_response()
    }
    async fn fake_login_html() -> Response {
        (
            StatusCode::OK,
            [("content-type", "text/html; charset=utf-8")],
            "<html><body>Sign in to Cloudflare Access</body></html>",
        )
            .into_response()
    }

    let app = Router::new()
        .route("/v1/sync/pull", get(redirect_to_login))
        .route("/v1/sync/push", post(redirect_to_login))
        .route("/v1/keys", get(fake_login_html).post(fake_login_html))
        .route("/cf-access-login", get(fake_login_html));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let dir = temp_dir("anti302");
    let mut store = LocalStore::open(&dir).unwrap();
    store
        .add_block(
            "scratch",
            "precious note must never drop",
            Some("plain"),
            None,
            "human",
            None,
        )
        .unwrap();
    let pending_before = store.pending_op_count();
    assert!(pending_before >= 2); // default buffer + block

    let creds = DeviceCredentials {
        sync_url: format!("http://{addr}"),
        device_token: "mnt_test_token_302".into(),
        scope: "read-write".into(),
    };
    let client = RelayClient::from_credentials(&creds).unwrap();
    let err = client
        .run_sync_round(&mut store, false)
        .await
        .expect_err("302 redirect must fail sync round");
    assert_eq!(err.code(), ErrorCode::SyncOffline);
    assert_eq!(
        store.pending_op_count(),
        pending_before,
        "ZERO local ops may be marked synced after 302 redirect"
    );
    assert_eq!(store.sync_status().unwrap().last_seq, 0);

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

// ============================================================================
// In-process Spec-Compliant HTTP Relay (backed by SimRelay) for full M1 E2E
// ============================================================================

struct MockDeviceRow {
    device_id: String,
    scope: String,
    token_hash: String,
    revoked_at_ms: Option<i64>,
}

struct MockPairingRow {
    kind: String,
    scope: String,
    ciphertext_b64: String,
    consumed: bool,
}

struct MockRelayState {
    bootstrap_token: String,
    relay: SimRelay,
    devices: BTreeMap<String, MockDeviceRow>,
    pairings: BTreeMap<String, MockPairingRow>,
}

impl MockRelayState {
    fn authenticate(&self, headers: &HeaderMap) -> Result<&MockDeviceRow, (StatusCode, Value)> {
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    json!({ "ok": false, "error": { "code": "AUTH_REQUIRED", "message": "missing token" } }),
                )
            })?;
        let hash = sha256_hex(auth);
        let dev = self
            .devices
            .values()
            .find(|d| d.token_hash == hash)
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    json!({ "ok": false, "error": { "code": "AUTH_REQUIRED", "message": "unknown token" } }),
                )
            })?;
        if dev.revoked_at_ms.is_some() {
            return Err((
                StatusCode::UNAUTHORIZED,
                json!({ "ok": false, "error": { "code": "DEVICE_REVOKED", "message": "device revoked" } }),
            ));
        }
        Ok(dev)
    }
}

async fn mock_bootstrap(
    State(st): State<Arc<Mutex<MockRelayState>>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let mut g = st.lock().unwrap();
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    if bearer != g.bootstrap_token {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "ok": false, "error": { "code": "AUTH_REQUIRED", "message": "bad bootstrap token" } })),
        )
            .into_response();
    }
    let revoke_existing = body["revoke_existing"].as_bool().unwrap_or(false);
    if revoke_existing {
        for d in g.devices.values_mut() {
            d.revoked_at_ms = Some(1_795_521_700_000);
        }
    }
    let dev_id = body["device_id"].as_str().unwrap().to_string();
    g.devices.insert(
        dev_id.clone(),
        MockDeviceRow {
            device_id: dev_id.clone(),
            scope: "read-write".to_string(),
            token_hash: body["token_sha256_hex"].as_str().unwrap().to_string(),
            revoked_at_ms: None,
        },
    );
    Json(
        json!({ "ok": true, "device_id": dev_id, "scope": "read-write", "epoch": g.relay.epoch.to_string() }),
    )
    .into_response()
}

async fn mock_devices_post(
    State(st): State<Arc<Mutex<MockRelayState>>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let mut g = st.lock().unwrap();
    let dev = match g.authenticate(&headers) {
        Ok(d) => d.scope.clone(),
        Err((s, j)) => return (s, Json(j)).into_response(),
    };
    if dev != "read-write" {
        return (
            StatusCode::FORBIDDEN,
            Json(
                json!({ "ok": false, "error": { "code": "TOKEN_SCOPE_FORBIDDEN", "message": "read-only" } }),
            ),
        )
            .into_response();
    }
    let device_id = body["device_id"].as_str().unwrap().to_string();
    let pair_id = body["pair_id"].as_str().unwrap().to_string();
    let scope = body["scope"].as_str().unwrap_or("read-write").to_string();
    g.devices.insert(
        device_id.clone(),
        MockDeviceRow {
            device_id: device_id.clone(),
            scope: scope.clone(),
            token_hash: body["token_sha256_hex"].as_str().unwrap().to_string(),
            revoked_at_ms: None,
        },
    );
    g.pairings.insert(
        pair_id.clone(),
        MockPairingRow {
            kind: "add".into(),
            scope: scope.clone(),
            ciphertext_b64: body["ciphertext_b64"].as_str().unwrap().to_string(),
            consumed: false,
        },
    );
    Json(json!({ "ok": true, "device_id": device_id, "pair_id": pair_id, "scope": scope, "expires_at_ms": 9_999_999_999_999i64 }))
        .into_response()
}

async fn mock_device_refresh(
    State(st): State<Arc<Mutex<MockRelayState>>>,
    headers: HeaderMap,
    AxumPath(target_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Response {
    let mut g = st.lock().unwrap();
    if let Err((s, j)) = g.authenticate(&headers) {
        return (s, Json(j)).into_response();
    }
    let Some(target) = g.devices.get(&target_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": { "code": "NOT_FOUND", "message": "device not found" } })),
        )
            .into_response();
    };
    let scope = target.scope.clone();
    let pair_id = body["pair_id"].as_str().unwrap().to_string();
    g.pairings.insert(
        pair_id.clone(),
        MockPairingRow {
            kind: "refresh".into(),
            scope,
            ciphertext_b64: body["ciphertext_b64"].as_str().unwrap().to_string(),
            consumed: false,
        },
    );
    Json(json!({ "ok": true, "device_id": target_id, "pair_id": pair_id, "expires_at_ms": 9_999_999_999_999i64 }))
        .into_response()
}

async fn mock_pair_claim(State(st): State<Arc<Mutex<MockRelayState>>>, Json(body): Json<Value>) -> Response {
    let mut g = st.lock().unwrap();
    let pair_id = body["pair_id"].as_str().unwrap_or("");
    let Some(row) = g.pairings.get_mut(pair_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": { "code": "NOT_FOUND", "message": "not found" } })),
        )
            .into_response();
    };
    if row.consumed {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": { "code": "NOT_FOUND", "message": "already claimed" } })),
        )
            .into_response();
    }
    row.consumed = true;
    Json(json!({ "ok": true, "kind": row.kind, "scope": row.scope, "ciphertext_b64": row.ciphertext_b64 }))
        .into_response()
}

async fn mock_device_revoke(
    State(st): State<Arc<Mutex<MockRelayState>>>,
    headers: HeaderMap,
    AxumPath(target_id): AxumPath<String>,
) -> Response {
    let mut g = st.lock().unwrap();
    if let Err((s, j)) = g.authenticate(&headers) {
        return (s, Json(j)).into_response();
    }
    if let Some(d) = g.devices.get_mut(&target_id) {
        d.revoked_at_ms = Some(1_795_521_700_000);
        return Json(json!({ "ok": true, "device_id": target_id, "revoked_at_ms": 1_795_521_700_000i64 }))
            .into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "ok": false, "error": { "code": "NOT_FOUND", "message": "not found" } })),
    )
        .into_response()
}

async fn mock_pull(
    State(st): State<Arc<Mutex<MockRelayState>>>,
    headers: HeaderMap,
    Query(q): Query<BTreeMap<String, String>>,
) -> Response {
    let g = st.lock().unwrap();
    if let Err((s, j)) = g.authenticate(&headers) {
        return (s, Json(j)).into_response();
    }
    let since: i64 = q.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
    let limit: usize = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(500);
    let (epoch, ops, keys_digest, head_seq, has_more) = g.relay.handle_pull(since, limit);
    let b64 = base64::engine::general_purpose::STANDARD;
    let ops_json: Vec<Value> = ops
        .into_iter()
        .map(|o| {
            json!({
                "seq": o.seq,
                "op_id": o.op_id.to_string(),
                "key_id": o.key_id.map(|k| k.to_string()),
                "device_id": o.device_id.as_str(),
                "created_at": o.created_at,
                "envelope_b64": b64.encode(o.envelope),
            })
        })
        .collect();
    Json(json!({
        "ok": true,
        "epoch": epoch.to_string(),
        "ops": ops_json,
        "keys_digest": keys_digest,
        "head_seq": head_seq,
        "has_more": has_more,
    }))
    .into_response()
}

async fn mock_push(
    State(st): State<Arc<Mutex<MockRelayState>>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let mut g = st.lock().unwrap();
    let dev_id = match g.authenticate(&headers) {
        Ok(d) => {
            if d.scope != "read-write" {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({ "ok": false, "error": { "code": "TOKEN_SCOPE_FORBIDDEN", "message": "read-only" } })),
                )
                    .into_response();
            }
            DeviceId::parse(&d.device_id).unwrap()
        }
        Err((s, j)) => return (s, Json(j)).into_response(),
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    let expected_epoch = JournalEpoch::parse(body["expected_epoch"].as_str().unwrap()).unwrap();
    let seen_seq = body["seen_seq"].as_i64().unwrap_or(0);
    let key_records: Vec<KeyRecordRow> = body["key_records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| KeyRecordRow {
            key_id: KeyId::parse(k["key_id"].as_str().unwrap()).unwrap(),
            wrap_gen: k["wrap_gen"].as_u64().unwrap() as u32,
            key_record: Some(b64.decode(k["key_record_b64"].as_str().unwrap()).unwrap()),
            created_at_ms: 1_795_521_600_000,
        })
        .collect();
    let ops: Vec<PushOpDto> = body["ops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| PushOpDto {
            op_id: OpId::parse(o["op_id"].as_str().unwrap()).unwrap(),
            device_id: DeviceId::parse(o["device_id"].as_str().unwrap()).unwrap(),
            key_id: o["key_id"].as_str().map(|s| KeyId::parse(s).unwrap()),
            envelope: b64.decode(o["envelope_b64"].as_str().unwrap()).unwrap(),
        })
        .collect();
    let cancel_key_ids: Vec<KeyId> = body["cancel_key_ids"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().and_then(|s| KeyId::parse(s).ok()))
        .collect();
    let shred_marks: Vec<mynote_core::model::ShredMarkRow> = body["shred_marks"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|m| {
            Some(mynote_core::model::ShredMarkRow {
                mark_id: mynote_core::ids::MarkId::parse(m["mark_id"].as_str()?).ok()?,
                key_id: KeyId::parse(m["key_id"].as_str()?).ok()?,
                seen_seq,
                requested_by: dev_id.clone(),
                requested_at_ms: 1_795_521_600_000,
                grace_ms: m["grace_ms"]
                    .as_i64()
                    .unwrap_or(mynote_core::vault::T_GRACE_DEFAULT_MS),
                not_before_ms: None,
                state: mynote_core::model::ShredMarkState::PendingConfirm,
                confirmed_at_ms: None,
                cancelled_by: None,
                executed_at_ms: None,
            })
        })
        .collect();
    let req = PushRequestDto {
        expected_epoch,
        seen_seq,
        key_records,
        cancel_key_ids,
        ops,
        shred_marks,
    };
    match g.relay.handle_push(&dev_id, &req, 1_795_521_600_000) {
        Ok(ok) => {
            let acked_json: Vec<Value> = ok
                .acked
                .into_iter()
                .map(|a| json!({ "op_id": a.op_id.to_string(), "seq": a.seq }))
                .collect();
            let shred_json: Vec<Value> = ok
                .shred_results
                .into_iter()
                .map(|r| {
                    json!({
                        "key_id": r.key_id.to_string(),
                        "state": match r.state {
                            mynote_core::model::ShredMarkState::PendingConfirm => "pending_confirm",
                            mynote_core::model::ShredMarkState::Scheduled => "scheduled",
                            mynote_core::model::ShredMarkState::Cancelled => "cancelled",
                            mynote_core::model::ShredMarkState::Executed => "executed",
                        },
                        "not_before_ms": r.not_before_ms,
                    })
                })
                .collect();
            Json(json!({
                "ok": true,
                "epoch": ok.epoch.to_string(),
                "acked": acked_json,
                "shred_results": shred_json,
                "head_seq": ok.head_seq,
            }))
            .into_response()
        }
        Err(err) if err.code == ErrorCode::CasMismatch => (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "CAS_MISMATCH",
                    "message": "epoch mismatch",
                    "details": { "remote_epoch": g.relay.epoch.to_string() }
                }
            })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::from_u16(err.code.http_status()).unwrap_or(StatusCode::BAD_REQUEST),
            Json(json!({ "ok": false, "error": { "code": err.code.as_str(), "message": "push error" } })),
        )
            .into_response(),
    }
}

async fn mock_keys_get(State(st): State<Arc<Mutex<MockRelayState>>>, headers: HeaderMap) -> Response {
    let g = st.lock().unwrap();
    if let Err((s, j)) = g.authenticate(&headers) {
        return (s, Json(j)).into_response();
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let recs: Vec<Value> = g
        .relay
        .keys
        .records
        .values()
        .map(|r| {
            json!({
                "key_id": r.key_id.to_string(),
                "wrap_gen": r.wrap_gen,
                "key_record_b64": r.key_record.as_ref().map(|b| b64.encode(b)),
                "created_at_ms": r.created_at_ms,
            })
        })
        .collect();
    let marks: Vec<Value> = g
        .relay
        .keys
        .marks
        .values()
        .map(|m| {
            json!({
                "mark_id": m.mark_id.to_string(),
                "key_id": m.key_id.to_string(),
                "seen_seq": m.seen_seq,
                "requested_by": m.requested_by.as_str(),
                "requested_at_ms": m.requested_at_ms,
                "grace_ms": m.grace_ms,
                "not_before_ms": m.not_before_ms,
                "state": match m.state {
                    mynote_core::model::ShredMarkState::PendingConfirm => "pending_confirm",
                    mynote_core::model::ShredMarkState::Scheduled => "scheduled",
                    mynote_core::model::ShredMarkState::Cancelled => "cancelled",
                    mynote_core::model::ShredMarkState::Executed => "executed",
                },
                "confirmed_at_ms": m.confirmed_at_ms,
                "cancelled_by": m.cancelled_by.as_ref().map(|d| d.as_str()),
                "executed_at_ms": m.executed_at_ms,
            })
        })
        .collect();
    let mut km = serde_json::Map::new();
    if let Some((gen, blob)) = &g.relay.keys.keyring_material {
        km.insert(
            "keyring".into(),
            json!({ "gen": gen, "blob_b64": b64.encode(blob) }),
        );
    }
    if let Some((gen, blob)) = &g.relay.keys.vault_header_material {
        km.insert(
            "vault_header".into(),
            json!({ "gen": gen, "blob_b64": b64.encode(blob) }),
        );
    }
    Json(json!({
        "ok": true,
        "keys_digest": g.relay.keys.digest(),
        "key_records": recs,
        "shred_marks": marks,
        "key_material": km,
    }))
    .into_response()
}

async fn mock_keys_post(
    State(st): State<Arc<Mutex<MockRelayState>>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let mut g = st.lock().unwrap();
    if let Err((s, j)) = g.authenticate(&headers) {
        return (s, Json(j)).into_response();
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let records: Vec<KeyRecordRow> = body["key_records"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|k| KeyRecordRow {
            key_id: KeyId::parse(k["key_id"].as_str().unwrap()).unwrap(),
            wrap_gen: k["wrap_gen"].as_u64().unwrap() as u32,
            key_record: Some(b64.decode(k["key_record_b64"].as_str().unwrap()).unwrap()),
            created_at_ms: 1_795_521_600_000,
        })
        .collect();
    let keyring = body["key_material"]["keyring"].as_object().and_then(|o| {
        let gen = o.get("gen")?.as_u64()? as u32;
        let blob = b64.decode(o.get("blob_b64")?.as_str()?).ok()?;
        Some((gen, blob))
    });
    match g.relay.handle_keys_post(&records, keyring, None) {
        Ok(()) => Json(json!({ "ok": true, "keys_digest": g.relay.keys.digest() })).into_response(),
        Err(code) => (
            StatusCode::CONFLICT,
            Json(json!({ "ok": false, "error": { "code": code.as_str(), "message": "key post rejected" } })),
        )
            .into_response(),
    }
}

/// Full dual-desktop E2E over HTTP:
/// 1. Desktop A bootstraps + creates note -> syncs.
/// 2. Desktop A generates one-time pairing ticket -> Desktop B claims -> pulls identical note.
/// 3. Concurrent offline edits -> Path γ 2-leaf conflict on both -> Desktop A resolves -> convergence.
/// 4. Desktop A rotates SMK (gen 2) + writes note -> Desktop B unlocks via 24 words + pulls -> decrypts.
/// 5. Desktop A rotates SMK (gen 3) + writes note -> Desktop A `device refresh` -> Desktop B claims + pulls -> decrypts.
/// 6. Desktop A revokes Desktop B -> Desktop B immediately gets `DEVICE_REVOKED`.
/// 7. Relay PITR rollback -> Desktop A reconciles cross-epoch set union and re-pushes dropped ops with zero loss!
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_dual_desktop_sync_conflict_rotation_refresh_revoke_and_pitr_e2e() {
    let state = Arc::new(Mutex::new(MockRelayState {
        bootstrap_token: "e2e-bootstrap-secret".into(),
        relay: SimRelay::new(JournalEpoch::from_random_bytes([0x11; 16])),
        devices: BTreeMap::new(),
        pairings: BTreeMap::new(),
    }));

    let app = Router::new()
        .route("/v1/devices/bootstrap", post(mock_bootstrap))
        .route("/v1/devices", post(mock_devices_post))
        .route("/v1/devices/pair-claim", post(mock_pair_claim))
        .route("/v1/devices/{id}/refresh", post(mock_device_refresh))
        .route("/v1/devices/{id}", delete(mock_device_revoke))
        .route("/v1/sync/pull", get(mock_pull))
        .route("/v1/sync/push", post(mock_push))
        .route("/v1/keys", get(mock_keys_get).post(mock_keys_post))
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let dir_a = temp_dir("desktop_a");
    let dir_b = temp_dir("desktop_b");

    // 1. Desktop A initializes, records 24 words, bootstraps, writes initial block, and syncs
    let mut store_a = LocalStore::open(&dir_a).unwrap();
    let words_24 = store_a.initial_recovery_words.clone().expect("24 recovery words");
    RelayClient::bootstrap_device(&relay_url, "e2e-bootstrap-secret", &store_a, "macbook", false)
        .await
        .expect("bootstrap A");
    let creds_a = store_a.load_credentials().unwrap().unwrap();
    let client_a = RelayClient::from_credentials(&creds_a).unwrap();

    let blk1 = store_a
        .add_block(
            "scratch",
            "initial block from desktop A",
            Some("plain"),
            None,
            "human",
            None,
        )
        .unwrap();
    let rep_a1 = client_a.run_sync_round(&mut store_a, false).await.unwrap();
    assert!(rep_a1.pushed_ops >= 2);
    assert_eq!(store_a.pending_op_count(), 0);

    // 2. Desktop A creates one-time pairing ticket -> Desktop B claims -> pulls identical note
    let pair = client_a
        .create_pairing_ticket("omarchy", "read-write", store_a.current_smks_for_pairing(), None)
        .await
        .unwrap();
    let claimed = RelayClient::claim_pairing_code(&pair.pairing_code, &dir_b)
        .await
        .unwrap();
    assert_eq!(claimed.kind, "add");
    // One-time replay MUST fail
    assert!(RelayClient::claim_pairing_code(&pair.pairing_code, &dir_b)
        .await
        .is_err());

    let mut store_b = LocalStore::open(&dir_b).unwrap();
    let creds_b = store_b.load_credentials().unwrap().unwrap();
    let client_b = RelayClient::from_credentials(&creds_b).unwrap();
    client_b.run_sync_round(&mut store_b, false).await.unwrap();

    let b_view = store_b.get_block(&blk1.block_id).unwrap();
    assert_eq!(b_view.content.as_deref(), Some("initial block from desktop A"));
    assert!(!b_view.has_conflict);

    // 3. Concurrent offline edits -> Path γ 2-leaf conflict -> Desktop A manual merge -> convergence
    let shared_heads = b_view.head_op_ids.clone();
    store_a
        .update_block(&blk1.block_id, "edit on macbook", &shared_heads, false, "human")
        .unwrap();
    store_b
        .update_block(&blk1.block_id, "edit on omarchy", &shared_heads, false, "human")
        .unwrap();
    client_a.run_sync_round(&mut store_a, false).await.unwrap();
    client_b.run_sync_round(&mut store_b, false).await.unwrap();
    client_a.run_sync_round(&mut store_a, false).await.unwrap();

    let conflict_a = store_a.get_block(&blk1.block_id).unwrap();
    let conflict_b = store_b.get_block(&blk1.block_id).unwrap();
    assert!(conflict_a.has_conflict && conflict_a.versions.len() == 2);
    assert!(conflict_b.has_conflict && conflict_b.versions.len() == 2);

    store_a
        .update_block(
            &blk1.block_id,
            "merged: macbook + omarchy",
            &conflict_a.head_op_ids,
            false,
            "human",
        )
        .unwrap();
    client_a.run_sync_round(&mut store_a, false).await.unwrap();
    client_b.run_sync_round(&mut store_b, false).await.unwrap();

    let resolved_b = store_b.get_block(&blk1.block_id).unwrap();
    assert!(!resolved_b.has_conflict);
    assert_eq!(resolved_b.content.as_deref(), Some("merged: macbook + omarchy"));

    // 4. Desktop A rotates SMK -> gen 2, writes block under smk_v2 -> Desktop B unlocks with 24 words!
    let (gen2, _kid2) = store_a.rotate_smk().unwrap();
    assert_eq!(gen2, 2);
    assert!(store_a.sync_status().unwrap().recovery_drill_due);
    store_a.recovery_drill(&words_24).unwrap();
    assert!(!store_a.sync_status().unwrap().recovery_drill_due);

    let blk_v2 = store_a
        .add_block(
            "scratch",
            "secret written under smk_v2",
            Some("plain"),
            None,
            "human",
            None,
        )
        .unwrap();
    client_a.run_sync_round(&mut store_a, false).await.unwrap();

    // Desktop B pulls without smk_v2 yet -> block not yet decrypted, keyring synced
    client_b.run_sync_round(&mut store_b, false).await.unwrap();
    assert!(store_b.get_block(&blk_v2.block_id).is_err());

    // Desktop B runs `keyring unlock` with 24 words (resets last_seq=0) + pulls -> decrypts smk_v2!
    let unsealed = store_b.unlock_keyring_with_words(&words_24).unwrap();
    assert_eq!(unsealed, 2);
    client_b.run_sync_round(&mut store_b, false).await.unwrap();
    let b_v2 = store_b.get_block(&blk_v2.block_id).unwrap();
    assert_eq!(b_v2.content.as_deref(), Some("secret written under smk_v2"));
    // BLOCKER #3 regression: block_keys.block_id must be backfilled from Ulid::ZERO so B can edit!
    store_b
        .update_block(
            &blk_v2.block_id,
            "edited smk_v2 on desktop B",
            &b_v2.head_op_ids,
            false,
            "human",
        )
        .expect("Desktop B must be able to edit block decrypted after 24-word unlock");
    client_b.run_sync_round(&mut store_b, false).await.unwrap();
    client_a.run_sync_round(&mut store_a, false).await.unwrap();
    assert_eq!(
        store_a.get_block(&blk_v2.block_id).unwrap().content.as_deref(),
        Some("edited smk_v2 on desktop B")
    );

    // 5. Desktop A rotates SMK -> gen 3, writes block -> Desktop A `device refresh` -> Desktop B claims!
    let (gen3, _kid3) = store_a.rotate_smk().unwrap();
    assert_eq!(gen3, 3);
    let blk_v3 = store_a
        .add_block(
            "scratch",
            "written under smk_v3",
            Some("plain"),
            None,
            "human",
            None,
        )
        .unwrap();
    client_a.run_sync_round(&mut store_a, false).await.unwrap();
    client_b.run_sync_round(&mut store_b, false).await.unwrap();
    assert!(store_b.get_block(&blk_v3.block_id).is_err());

    let refresh = client_a
        .create_refresh_ticket(store_b.device_id().as_str(), store_a.current_smks_for_pairing())
        .await
        .unwrap();
    drop(store_b);
    let ref_claim = RelayClient::claim_pairing_code(&refresh.pairing_code, &dir_b)
        .await
        .unwrap();
    assert_eq!(ref_claim.kind, "refresh");
    assert_eq!(ref_claim.smk_generations, 3);

    let mut store_b = LocalStore::open(&dir_b).unwrap();
    client_b.run_sync_round(&mut store_b, false).await.unwrap();
    let b_v3 = store_b.get_block(&blk_v3.block_id).unwrap();
    assert_eq!(b_v3.content.as_deref(), Some("written under smk_v3"));
    // BLOCKER #3 regression: block_keys.block_id must also be backfilled after `device refresh`!
    store_b
        .update_block(
            &blk_v3.block_id,
            "local edit of smk_v3 on desktop B",
            &b_v3.head_op_ids,
            false,
            "human",
        )
        .expect("Desktop B must be able to edit block decrypted after device refresh");

    // 6. Desktop A revokes Desktop B -> Desktop B immediately receives DEVICE_REVOKED
    client_a
        .revoke_device(store_b.device_id().as_str())
        .await
        .unwrap();
    let rev_err = client_b
        .run_sync_round(&mut store_b, false)
        .await
        .expect_err("revoked device must fail sync");
    assert_eq!(rev_err.code(), ErrorCode::DeviceRevoked);

    // 7. Relay PITR rollback (drops ops after seq 2 and switches epoch) -> Desktop A rescues all ops!
    let total_before_pitr = state.lock().unwrap().relay.head_seq();
    assert!(total_before_pitr >= 5);
    {
        let mut g = state.lock().unwrap();
        g.relay
            .inject_pitr_rollback(2, JournalEpoch::from_random_bytes([0x99; 16]));
    }
    let pitr_rep = client_a.run_sync_round(&mut store_a, false).await.unwrap();
    assert!(pitr_rep.reconciled_epoch_change);
    assert!(
        state.lock().unwrap().relay.head_seq() >= total_before_pitr,
        "Desktop A must rescue all PITR-dropped ops via cross-epoch set union"
    );
    // All local blocks remain intact on Desktop A
    assert_eq!(
        store_a.get_block(&blk_v3.block_id).unwrap().content.as_deref(),
        Some("written under smk_v3")
    );

    server.abort();
    let _ = Path::new(&dir_a)
        .exists()
        .then(|| std::fs::remove_dir_all(&dir_a));
    let _ = Path::new(&dir_b)
        .exists()
        .then(|| std::fs::remove_dir_all(&dir_b));
}

/// Regression suite covering:
/// - BLOCKER #4: Disaster Recovery Path #1 (`bootstrap_register --revoke-existing` -> probe `/v1/keys`
///   -> `open_for_recovery_bootstrap` -> `unlock_keyring_with_words` -> full multi-generation restore).
/// - HIGH #2: `sync_key_table` GET-before-POST strictly-newer diff when peer holds older `keyring_gen`.
/// - HIGH #4: `build_pending_push` 4 MiB JSON byte-budget batching across multi-hundred-KiB blocks.
/// - HIGH #8: Live daemon hot-reloads rotated SMKs on `LocalIpcRequest::Poke` so subsequent writes use new SMK.
/// - HIGH #9: `run_cloud_sync_now` failure always clears `"syncing"` WS state & emits `DEVICE_REVOKED`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn regression_recovery_bootstrap_key_table_diff_large_batch_and_daemon_smk_reload() {
    let state = Arc::new(Mutex::new(MockRelayState {
        bootstrap_token: "rec-bootstrap-secret".into(),
        relay: SimRelay::new(JournalEpoch::from_random_bytes([0x22; 16])),
        devices: BTreeMap::new(),
        pairings: BTreeMap::new(),
    }));

    let app = Router::new()
        .route("/v1/devices/bootstrap", post(mock_bootstrap))
        .route("/v1/devices", post(mock_devices_post))
        .route("/v1/devices/pair-claim", post(mock_pair_claim))
        .route("/v1/devices/{id}/refresh", post(mock_device_refresh))
        .route("/v1/devices/{id}", delete(mock_device_revoke))
        .route("/v1/sync/pull", get(mock_pull))
        .route("/v1/sync/push", post(mock_push))
        .route("/v1/keys", get(mock_keys_get).post(mock_keys_post))
        .layer(axum::extract::DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let dir_a = temp_dir("reg_a");
    let dir_rec = temp_dir("reg_rec");
    let dir_peer = temp_dir("reg_peer");
    let dir_daemon = temp_dir("reg_daemon");

    // === 1. BLOCKER #4: Disaster Recovery Path #1 ===
    let mut store_a = LocalStore::open(&dir_a).unwrap();
    let words_24 = store_a.initial_recovery_words.clone().expect("24 recovery words");
    RelayClient::bootstrap_device(&relay_url, "rec-bootstrap-secret", &store_a, "lost-laptop", false)
        .await
        .unwrap();
    let creds_a = store_a.load_credentials().unwrap().unwrap();
    let client_a = RelayClient::from_credentials(&creds_a).unwrap();

    let note1 = store_a
        .add_block(
            "scratch",
            "gen1 important note",
            Some("plain"),
            None,
            "human",
            None,
        )
        .unwrap();
    let (gen2, _kid2) = store_a.rotate_smk().unwrap();
    assert_eq!(gen2, 2);
    let note2 = store_a
        .add_block(
            "scratch",
            "gen2 important note",
            Some("plain"),
            None,
            "human",
            None,
        )
        .unwrap();
    client_a.run_sync_round(&mut store_a, false).await.unwrap();

    // All old devices lost! Brand-new empty `dir_rec` registers with --revoke-existing, probes
    // GET /v1/keys, initializes in recovery mode without generating a conflicting gen-1 keyring!
    let rec_dev_id = DeviceId::from_random_bytes([0x55; 10]);
    let (_receipt, rec_creds) = RelayClient::bootstrap_register(
        &relay_url,
        "rec-bootstrap-secret",
        &rec_dev_id,
        "replacement-laptop",
        true,
    )
    .await
    .unwrap();
    let client_rec = RelayClient::from_credentials(&rec_creds).unwrap();
    let (_recs, _marks, remote_kr, _vh) = client_rec.fetch_remote_keys().await.unwrap();
    let (kr_gen, kr_blob) = remote_kr.expect("relay must return existing gen-2 keyring");
    assert_eq!(kr_gen, 2);

    // Lost device A must now be revoked by `revoke_existing = true`
    assert_eq!(
        client_a
            .run_sync_round(&mut store_a, false)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::DeviceRevoked
    );

    let mut store_rec = LocalStore::open_for_recovery_bootstrap(
        &dir_rec,
        rec_dev_id,
        &rec_creds.sync_url,
        &rec_creds.device_token,
        &rec_creds.scope,
        kr_gen,
        &kr_blob,
    )
    .unwrap();
    assert_eq!(store_rec.unlock_keyring_with_words(&words_24).unwrap(), 2);
    client_rec.run_sync_round(&mut store_rec, false).await.unwrap();

    let r1 = store_rec.get_block(&note1.block_id).unwrap();
    let r2 = store_rec.get_block(&note2.block_id).unwrap();
    assert_eq!(r1.content.as_deref(), Some("gen1 important note"));
    assert_eq!(r2.content.as_deref(), Some("gen2 important note"));
    // Both recovered blocks must be immediately editable!
    store_rec
        .update_block(
            &note2.block_id,
            "edited after disaster recovery",
            &r2.head_op_ids,
            false,
            "human",
        )
        .unwrap();
    client_rec.run_sync_round(&mut store_rec, false).await.unwrap();

    // === 2. HIGH #2: sync_key_table GET-before-POST when peer holds older keyring_gen ===
    let pair = client_rec
        .create_pairing_ticket(
            "peer-desktop",
            "read-write",
            store_rec.current_smks_for_pairing(),
            None,
        )
        .await
        .unwrap();
    RelayClient::claim_pairing_code(&pair.pairing_code, &dir_peer)
        .await
        .unwrap();
    let mut store_peer = LocalStore::open(&dir_peer).unwrap();
    let creds_peer = store_peer.load_credentials().unwrap().unwrap();
    let client_peer = RelayClient::from_credentials(&creds_peer).unwrap();
    client_peer.run_sync_round(&mut store_peer, false).await.unwrap();

    // `store_rec` rotates to keyring_gen = 3 and syncs to relay
    let (gen3, _kid3) = store_rec.rotate_smk().unwrap();
    assert_eq!(gen3, 3);
    client_rec.run_sync_round(&mut store_rec, false).await.unwrap();

    // `store_peer` still locally holds keyring_gen = 2, writes a brand-new block with a new BDEK,
    // and syncs. GET-before-POST must omit the stale gen-2 keyring and upload ONLY the new BDEK
    // without triggering 409 CAS_MISMATCH!
    let peer_blk = store_peer
        .add_block(
            "scratch",
            "written by peer at older keyring_gen",
            Some("plain"),
            None,
            "human",
            None,
        )
        .unwrap();
    client_peer.run_sync_round(&mut store_peer, false).await.unwrap();
    assert_eq!(store_peer.pending_op_count(), 0);

    client_rec.run_sync_round(&mut store_rec, false).await.unwrap();
    assert_eq!(
        store_rec
            .get_block(&peer_blk.block_id)
            .unwrap()
            .content
            .as_deref(),
        Some("written by peer at older keyring_gen")
    );

    // === 3. HIGH #4: build_pending_push enforces 4 MiB JSON byte budget ===
    // 8 blocks of ~600 KiB incompressible-ish pattern (~4.8 MiB raw -> > 6 MiB base64 JSON).
    // Even with zstd compression inside MNB1, pseudo-random hex ensures compressed envelopes stay large.
    for i in 0..8usize {
        let mut s = String::with_capacity(620_000);
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15 ^ (i as u64 + 1).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        while s.len() < 600_000 {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            let v = x.wrapping_mul(0x2545_f491_4f6c_dd1d);
            s.push_str(&format!("{v:016x}"));
        }
        store_rec
            .add_block("scratch", &s, Some("plain"), None, "human", None)
            .unwrap();
    }
    let snap = store_rec.export_engine_snapshot().unwrap();
    let first_batch = snap.build_pending_push().expect("pending batch");
    assert!(
        first_batch.ops.len() < 8,
        "byte-budget chunking must split 8 x 600 KiB incompressible ops into multiple HTTP batches (got {})",
        first_batch.ops.len()
    );
    client_rec.run_sync_round(&mut store_rec, false).await.unwrap();
    assert_eq!(
        store_rec.pending_op_count(),
        0,
        "multi-batch push must drain all 8 large ops cleanly under 4 MiB limit"
    );

    // === 4. HIGH #8 & HIGH #9: Live daemon SMK hot-reload on Poke + error clears "syncing" ===
    let pair_d = client_rec
        .create_pairing_ticket(
            "daemon-desktop",
            "read-write",
            store_rec.current_smks_for_pairing(),
            None,
        )
        .await
        .unwrap();
    RelayClient::claim_pairing_code(&pair_d.pairing_code, &dir_daemon)
        .await
        .unwrap();

    let daemon = start_daemon(DaemonConfig {
        data_dir: dir_daemon.clone(),
        port: 0,
        enable_cloud_sync: false,
    })
    .await
    .expect("start daemon");

    // Complete initial bootstrap sync on the daemon so `scratch` buffer & remote keys are pulled
    daemon
        .state
        .run_cloud_sync_now()
        .await
        .expect("initial daemon sync");

    // External CLI process rotates SMK on disk while daemon is already running
    let rotated_kid = {
        let mut cli_store = LocalStore::open(&dir_daemon).unwrap();
        let (_g, new_kid) = cli_store.rotate_smk().unwrap();
        new_kid
    };

    // Send LocalIpcRequest::Poke -> daemon MUST hot-reload SMKs from disk
    let dir_d_poke = dir_daemon.clone();
    let poke_resp = tokio::task::spawn_blocking(move || {
        try_send_ipc(
            &dir_d_poke,
            &LocalIpcRequest::Poke { fast_flush: false },
            Duration::from_secs(3),
        )
    })
    .await
    .unwrap()
    .unwrap()
    .expect("daemon IPC reachable");
    assert!(poke_resp.ok);

    // Add a block via daemon LocalIpc Apply -> new op MUST be encrypted with rotated_kid!
    let dir_d_apply = dir_daemon.clone();
    let apply_resp = tokio::task::spawn_blocking(move || {
        try_send_ipc(
            &dir_d_apply,
            &LocalIpcRequest::Apply {
                meta: ApplyMeta {
                    actor: "human".into(),
                    idempotency_key: None,
                    allow_empty: false,
                    force: false,
                },
                request: ApplyRequest::AddBlock {
                    buffer: "scratch".into(),
                    content: "encrypted under hot-reloaded SMK".into(),
                    lang: Some("plain".into()),
                    after_id: None,
                },
            },
            Duration::from_secs(3),
        )
    })
    .await
    .unwrap()
    .unwrap()
    .expect("daemon UDS apply reachable");
    assert!(apply_resp.ok, "apply failed: {:?}", apply_resp.error);

    let last_op_smk = {
        let guard = daemon.state.store.lock().unwrap();
        let d_snap = guard.export_engine_snapshot().unwrap();
        let pending = d_snap.build_pending_push().expect("new pending push batch");
        let last_op = pending.ops.last().expect("new pending op");
        LocalStore::peek_op_smk_kid(&last_op.envelope).unwrap()
    };
    assert_eq!(
        last_op_smk, rotated_kid,
        "daemon must encrypt new ops under the hot-reloaded SMK after LocalIpcRequest::Poke"
    );

    // HIGH #9: Revoke daemon's device on relay, subscribe to daemon WS broadcast, invoke
    // `run_cloud_sync_now()`, verify Err(DeviceRevoked), DEVICE_REVOKED alert, AND final
    // sync_status state is NOT stuck on "syncing"!
    let daemon_dev_id = {
        let guard = daemon.state.store.lock().unwrap();
        guard.device_id().to_string()
    };
    client_rec.revoke_device(&daemon_dev_id).await.unwrap();

    let mut ws_rx = daemon.state.ws_tx.subscribe();
    let sync_err = daemon
        .state
        .run_cloud_sync_now()
        .await
        .expect_err("revoked daemon must return Err");
    assert_eq!(sync_err.code(), ErrorCode::DeviceRevoked);

    let mut seen_syncing = false;
    let mut seen_revoked_alert = false;
    let mut final_sync_state: Option<String> = None;
    while let Ok(raw) = ws_rx.try_recv() {
        let v: Value = serde_json::from_str(&raw).unwrap();
        match v["type"].as_str() {
            Some("sync_status") => {
                let st = v["state"].as_str().unwrap_or("").to_string();
                if st == "syncing" {
                    seen_syncing = true;
                }
                final_sync_state = Some(st);
            }
            Some("alert") if v["code"].as_str() == Some("DEVICE_REVOKED") => {
                seen_revoked_alert = true;
            }
            _ => {}
        }
    }
    assert!(seen_syncing, "expected initial syncing broadcast");
    assert!(seen_revoked_alert, "expected DEVICE_REVOKED alert broadcast");
    assert_ne!(
        final_sync_state.as_deref(),
        Some("syncing"),
        "sync_status must NOT remain stuck in 'syncing' after sync failure (got {:?})",
        final_sync_state
    );

    daemon.shutdown();
    server.abort();
    for d in [&dir_a, &dir_rec, &dir_peer, &dir_daemon] {
        let _ = Path::new(d).exists().then(|| std::fs::remove_dir_all(d));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pr38_cli_daemon_regressions_c1_c8_h16_h17() {
    use axum::body::Bytes;
    use axum::routing::put;
    use mynote_core::crypto::encrypt_mnb1;
    use mynote_core::ids::{BlockId, KeyId, OpId, Ulid, VkekKid};
    use mynote_core::vault::{create_vault_header, unlock_vault_with_passphrase};
    use zeroize::Zeroizing;

    // === 1. C1: RelayClient::put_state_snapshot & get_state_snapshot MUST use X-Journal-Epoch / X-Covers-Seq / X-Snapshot-Id ===
    type SnapEntry = (String, i64, String, Vec<u8>);
    let snap_store: Arc<Mutex<Option<SnapEntry>>> = Arc::new(Mutex::new(None));
    let state = Arc::new(Mutex::new(MockRelayState {
        bootstrap_token: "c1-boot".into(),
        relay: SimRelay::new(JournalEpoch::from_random_bytes([0xC1; 16])),
        devices: BTreeMap::new(),
        pairings: BTreeMap::new(),
    }));
    let snap_put_store = snap_store.clone();
    let snap_get_store = snap_store.clone();
    let app = Router::new()
        .route("/v1/devices/bootstrap", post(mock_bootstrap))
        .route("/v1/sync/pull", get(mock_pull))
        .route("/v1/sync/push", post(mock_push))
        .route("/v1/keys", get(mock_keys_get).post(mock_keys_post))
        .route(
            "/v1/snapshots/state",
            put(move |headers: HeaderMap, body: Bytes| {
                let s = snap_put_store.clone();
                async move {
                    let ep = headers.get("x-journal-epoch").and_then(|v| v.to_str().ok()).map(str::to_string);
                    let seq = headers.get("x-covers-seq").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<i64>().ok());
                    let sid = headers.get("x-snapshot-id").and_then(|v| v.to_str().ok()).map(str::to_string);
                    match (ep, seq, sid) {
                        (Some(e), Some(q), Some(id)) => {
                            *s.lock().unwrap() = Some((e, q, id, body.to_vec()));
                            Json(json!({ "ok": true })).into_response()
                        }
                        _ => (
                            StatusCode::BAD_REQUEST,
                            Json(json!({ "ok": false, "error": { "code": "INVALID_ARGUMENT", "message": "missing C1 headers" } })),
                        )
                            .into_response(),
                    }
                }
            })
            .get(move || {
                let s = snap_get_store.clone();
                async move {
                    let guard = s.lock().unwrap();
                    if let Some((ep, seq, sid, bytes)) = guard.as_ref() {
                        (
                            StatusCode::OK,
                            [
                                ("content-type", "application/octet-stream".to_string()),
                                ("x-journal-epoch", ep.clone()),
                                ("x-covers-seq", seq.to_string()),
                                ("x-snapshot-id", sid.clone()),
                            ],
                            bytes.clone(),
                        )
                            .into_response()
                    } else {
                        StatusCode::NOT_FOUND.into_response()
                    }
                }
            }),
        )
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let dir_c1 = temp_dir("pr38_c1_snap");
    let mut store_c1 = LocalStore::open(&dir_c1).unwrap();
    RelayClient::bootstrap_device(&relay_url, "c1-boot", &store_c1, "c1-mac", false)
        .await
        .unwrap();
    store_c1
        .add_block("scratch", "snapshot canary", Some("text"), None, "human", None)
        .unwrap();
    let creds = store_c1.load_credentials().unwrap().unwrap();
    let relay_client = RelayClient::from_credentials(&creds).unwrap();
    relay_client.run_sync_round(&mut store_c1, false).await.unwrap();
    let (hdr, raw) = store_c1.build_state_snapshot().unwrap();
    relay_client
        .put_state_snapshot(
            &hdr.journal_epoch.to_string(),
            hdr.covers_seq,
            &hdr.snapshot_id.to_string(),
            &raw,
        )
        .await
        .expect("C1: put_state_snapshot must succeed with X-Journal-Epoch/X-Covers-Seq/X-Snapshot-Id");
    let fetched = relay_client
        .get_state_snapshot()
        .await
        .unwrap()
        .expect("C1: get_state_snapshot must return uploaded snapshot");
    assert_eq!(fetched.0, hdr.journal_epoch.to_string());
    assert_eq!(fetched.1, hdr.covers_seq);
    assert_eq!(fetched.2, hdr.snapshot_id.to_string());
    assert_eq!(fetched.3, raw);
    server.abort();

    // === 2. C8 / H16 / H17: Daemon trash action guards + session-bound confirm_nonce + Tier 1 leaf endpoint ===
    let dir_d = temp_dir("pr38_daemon_guards");
    let daemon = start_daemon(DaemonConfig {
        data_dir: dir_d.clone(),
        port: 0,
        enable_cloud_sync: false,
    })
    .await
    .unwrap();
    let port = daemon.port;
    let base_ip = format!("http://127.0.0.1:{port}");
    let base_localhost = format!("http://localhost:{port}");
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Issue TWO independent sessions (Session A & Session B)
    let mut sessions = Vec::new();
    for _ in 0..2 {
        let dd = dir_d.clone();
        let t = tokio::task::spawn_blocking(move || {
            try_send_ipc(&dd, &LocalIpcRequest::OpenTicket, Duration::from_secs(3))
        })
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let path = t.url.unwrap().strip_prefix(&base_localhost).unwrap().to_string();
        let res = http
            .get(format!("{base_ip}{path}"))
            .header(HOST, format!("localhost:{port}"))
            .send()
            .await
            .unwrap();
        let cookie = res
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        sessions.push(cookie);
    }
    let cookie_a = &sessions[0];
    let cookie_b = &sessions[1];

    // Create 2 blocks and trash block 1
    let (b1_id, b2_id) = {
        let mut g = daemon.state.store.lock().unwrap();
        let r1 = g
            .add_block("scratch", "blk1", Some("text"), None, "human", None)
            .unwrap();
        let r2 = g
            .add_block("scratch", "blk2", Some("text"), None, "human", None)
            .unwrap();
        let _ = g
            .delete_block(&r1.block_id, Some(&r1.head_op_ids), "human")
            .unwrap();
        (r1.block_id, r2.block_id)
    };

    // H16: multi-block purge_history MUST be rejected with 400 INVALID_ARGUMENT!
    let multi_purge = http
        .post(format!("{base_ip}/v1/local/trash/actions/prepare"))
        .header(HOST, format!("localhost:{port}"))
        .header(ORIGIN, &base_localhost)
        .header(COOKIE, cookie_a)
        .json(&json!({ "action": "purge_history", "block_ids": [&b1_id, &b2_id] }))
        .send()
        .await
        .unwrap();
    assert_eq!(multi_purge.status(), StatusCode::BAD_REQUEST);

    // H16: confirm_nonce prepared by Session A MUST be rejected when submitted by Session B!
    let prep_res = http
        .post(format!("{base_ip}/v1/local/trash/actions/prepare"))
        .header(HOST, format!("localhost:{port}"))
        .header(ORIGIN, &base_localhost)
        .header(COOKIE, cookie_a)
        .json(&json!({ "action": "expedite", "block_ids": [&b1_id] }))
        .send()
        .await
        .unwrap();
    assert_eq!(prep_res.status(), StatusCode::OK);
    let prep_json: Value = prep_res.json().await.unwrap();
    let nonce = prep_json["data"]["confirm_nonce"].as_str().unwrap().to_string();

    let hijack = http
        .post(format!("{base_ip}/v1/local/trash/actions/commit"))
        .header(HOST, format!("localhost:{port}"))
        .header(ORIGIN, &base_localhost)
        .header(COOKIE, cookie_b)
        .json(&json!({ "confirm_nonce": nonce }))
        .send()
        .await
        .unwrap();
    assert_eq!(hijack.status(), StatusCode::PRECONDITION_REQUIRED);
    let hijack_json: Value = hijack.json().await.unwrap();
    assert_eq!(hijack_json["error"]["code"], "UI_CONFIRMATION_REQUIRED");

    // H17: Locked block with concurrent Tier 1 leaf -> GET /v1/local/blocks redacts Tier 1 leaf,
    // while GET /v1/local/blocks/{id}/tier1-leaf/{op_id} returns its plaintext on demand!
    let (h17_blk_id, t1_op_id) = {
        use mynote_core::hlc::Hlc;
        use mynote_core::ids::DeviceId;
        use mynote_core::model::OpType;
        use mynote_store::store::RemoteBlockOpParams;

        let mut g = daemon.state.store.lock().unwrap();
        let rpk = g.recovery_pk().unwrap();
        let vkid = VkekKid::from_ulid(Ulid::from_parts(1_720_000_000_000, [1; 10]));
        let vh = create_vault_header(
            b"h17-pass",
            &rpk,
            vkid,
            &[0x42; 32],
            [2; 16],
            [3; 24],
            [4; 32],
            [5; 24],
            1_720_000_000_000,
        )
        .unwrap();
        let unlocked = unlock_vault_with_passphrase(b"h17-pass", &vh).unwrap();
        g.put_vault_header(vh.updated_at_ms, &rmp_serde::to_vec_named(&vh).unwrap())
            .unwrap();

        let created = g
            .add_block("scratch", "H17_BASE", Some("text"), None, "human", None)
            .unwrap();
        let t1_edit = g
            .update_block(
                &created.block_id,
                "H17_TIER1_CONCURRENT",
                &created.head_op_ids,
                false,
                "human",
            )
            .unwrap();
        // Concurrent Tier 2 LOCK branching off `created.head_op_ids` from a remote device (sibling to `t1_edit`)!
        let blk_id = BlockId::parse(&created.block_id).unwrap();
        let parent_op = OpId::parse(&created.head_op_ids[0]).unwrap();
        let remote_dev = DeviceId::from_random_bytes([0xAB; 10]);
        let t2_op = OpId::from_ulid(Ulid::from_parts(1_720_000_005_000, [9; 10]));
        let t2_kid = KeyId::from_ulid(Ulid::from_parts(1_720_000_005_001, [10; 10]));
        let t2_bdek = Zeroizing::new([0x55; 32]);
        let mnb1 = encrypt_mnb1(
            blk_id.as_bytes(),
            t2_op,
            t2_kid,
            &t2_bdek,
            "H17_TIER2_SEALED",
            [11; 24],
        )
        .unwrap();
        let mnw1 = unlocked.wrap_bdek(t2_kid, blk_id, &t2_bdek, [12; 24]).unwrap();
        g.apply_remote_block_op_for_sync(RemoteBlockOpParams {
            remote_device: remote_dev.clone(),
            block_id: blk_id,
            op_id: t2_op,
            parents: vec![parent_op],
            op_type: OpType::Lock,
            hlc: Hlc::new(1_720_000_005_000, 0, remote_dev),
            tier: 2,
            key_id: t2_kid,
            new_key_record: Some((1, mnw1)),
            mnb1,
            public_hint: Some("h17 hint".to_string()),
        })
        .unwrap();
        (created.block_id, t1_edit.op_id)
    };

    let list_res = http
        .get(format!("{base_ip}/v1/local/blocks?buffer_id=scratch"))
        .header(HOST, format!("localhost:{port}"))
        .header(COOKIE, cookie_a)
        .send()
        .await
        .unwrap();
    let list_json: Value = list_res.json().await.unwrap();
    let h17_dto = list_json["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["id"] == h17_blk_id)
        .unwrap();
    assert_eq!(h17_dto["is_locked"], true);
    assert_eq!(h17_dto["has_unlocked_concurrent_version"], true);
    assert!(!h17_dto.to_string().contains("H17_TIER1_CONCURRENT"));

    let leaf_res = http
        .get(format!(
            "{base_ip}/v1/local/blocks/{h17_blk_id}/tier1-leaf/{t1_op_id}"
        ))
        .header(HOST, format!("localhost:{port}"))
        .header(COOKIE, cookie_a)
        .send()
        .await
        .unwrap();
    assert_eq!(leaf_res.status(), StatusCode::OK);
    let leaf_json: Value = leaf_res.json().await.unwrap();
    assert_eq!(leaf_json["data"]["content"], "H17_TIER1_CONCURRENT");

    daemon.shutdown();
    for d in [&dir_c1, &dir_d] {
        let _ = Path::new(d).exists().then(|| std::fs::remove_dir_all(d));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m3_daemon_time_travel_tier2_history_revert_and_format_sec03_isolation() {
    use mynote_core::crypto::{decrypt_mnb1, encrypt_mnb1, encrypt_mnr1, KeyRecordV1};
    use mynote_core::hlc::Hlc;
    use mynote_core::ids::{BlockId, MonotonicUlidGen, SmkKid, Ulid, VkekKid};
    use mynote_core::model::OpType;
    use mynote_core::sync::StoreMutation;
    use mynote_core::vault::{create_vault_header, unlock_vault_with_passphrase, T_GRACE_DEFAULT_MS};
    use mynote_store::store::RemoteBlockOpParams;
    use mynote_store::Tier2OpInput;
    use zeroize::Zeroizing;

    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(v) = &self.prev {
                std::env::set_var(self.key, v);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    let dir = temp_dir("m3_daemon_tt_fmt");
    let daemon = start_daemon(DaemonConfig {
        data_dir: dir.clone(),
        port: 0,
        enable_cloud_sync: false,
    })
    .await
    .unwrap();
    let port = daemon.port;
    let base_ip = format!("http://127.0.0.1:{port}");
    let base_localhost = format!("http://localhost:{port}");
    let http = raw_http_client();

    // Acquire authenticated local session cookie
    let dir_uds = dir.clone();
    let ticket = tokio::task::spawn_blocking(move || {
        try_send_ipc(&dir_uds, &LocalIpcRequest::OpenTicket, Duration::from_secs(3))
    })
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let ticket_path = ticket
        .url
        .unwrap()
        .strip_prefix(&base_localhost)
        .unwrap()
        .to_string();
    let ex_res = http
        .get(format!("{base_ip}{ticket_path}"))
        .header(HOST, format!("localhost:{port}"))
        .send()
        .await
        .unwrap();
    let cookie = ex_res
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // Connect local WebSocket to verify live `blocks_changed` broadcast on revert
    let mut ws_req = format!("ws://127.0.0.1:{port}/v1/local/ws")
        .into_client_request()
        .unwrap();
    ws_req
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(&format!("localhost:{port}")).unwrap());
    ws_req
        .headers_mut()
        .insert(ORIGIN, HeaderValue::from_str(&base_localhost).unwrap());
    ws_req
        .headers_mut()
        .insert(COOKIE, HeaderValue::from_str(&cookie).unwrap());
    let (mut ws_stream, _) = tokio_tungstenite::connect_async(ws_req).await.unwrap();

    // 1. Create Tier 1 block with human + SET_META + agent:claude-code edits
    let (blk_id, op1, op2, op3, meta_op) = {
        let mut g = daemon.state.store.lock().unwrap();
        let r1 = g
            .add_block("scratch", "v1 human base", Some("markdown"), None, "human", None)
            .unwrap();
        let r2 = g
            .update_block(&r1.block_id, "v2 human good", &r1.head_op_ids, false, "human")
            .unwrap();
        let m1 = g
            .move_block(&r1.block_id, None, None, None, Some("text"), "human")
            .unwrap();
        let r3 = g
            .update_block(
                &r1.block_id,
                "v3 agent oops",
                &r2.head_op_ids,
                false,
                "agent:claude-code",
            )
            .unwrap();
        (r1.block_id, r1.op_id, r2.op_id, r3.op_id, m1.op_id)
    };

    // GET /v1/local/blocks/{id}/history
    let h_res = http
        .get(format!("{base_ip}/v1/local/blocks/{blk_id}/history"))
        .header(HOST, format!("localhost:{port}"))
        .header(COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(h_res.status(), StatusCode::OK);
    let h_json: Value = h_res.json().await.unwrap();
    assert_eq!(h_json["data"].as_array().unwrap().len(), 4);

    // GET /v1/local/blocks/{id}/history/{op1} -> Tier 1 plaintext
    let op1_res = http
        .get(format!("{base_ip}/v1/local/blocks/{blk_id}/history/{op1}"))
        .header(HOST, format!("localhost:{port}"))
        .header(COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(op1_res.status(), StatusCode::OK);
    let op1_j: Value = op1_res.json().await.unwrap();
    assert_eq!(op1_j["data"]["content"], "v1 human base");
    assert_eq!(op1_j["data"]["is_locked"], false);
    assert!(op1_j["data"]["mnb1_b64"].is_null());
    assert!(op1_j["data"]["mnw1_b64"].is_null());

    // GET /v1/local/blocks/{id}/history/{meta_op} -> 400 INVALID_ARGUMENT
    let meta_res = http
        .get(format!("{base_ip}/v1/local/blocks/{blk_id}/history/{meta_op}"))
        .header(HOST, format!("localhost:{port}"))
        .header(COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(meta_res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        meta_res.json::<Value>().await.unwrap()["error"]["code"],
        "INVALID_ARGUMENT"
    );

    // POST /v1/local/blocks/{id}/revert with stale expected_heads -> 409 HEAD_MISMATCH
    let stale_rev = http
        .post(format!("{base_ip}/v1/local/blocks/{blk_id}/revert"))
        .header(HOST, format!("localhost:{port}"))
        .header(ORIGIN, &base_localhost)
        .header(COOKIE, &cookie)
        .json(&json!({
            "undo_actor": "agent:claude-code",
            "expected_heads": [&op1]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(stale_rev.status(), StatusCode::CONFLICT);
    assert_eq!(
        stale_rev.json::<Value>().await.unwrap()["error"]["code"],
        "HEAD_MISMATCH"
    );

    // POST /v1/local/blocks/{id}/revert with undo_actor -> 200 OK, restores "v2 human good" + WS broadcast!
    let ok_rev = http
        .post(format!("{base_ip}/v1/local/blocks/{blk_id}/revert"))
        .header(HOST, format!("localhost:{port}"))
        .header(ORIGIN, &base_localhost)
        .header(COOKIE, &cookie)
        .json(&json!({
            "undo_actor": "agent:claude-code",
            "expected_heads": [&op3]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok_rev.status(), StatusCode::OK);
    let ok_rev_j: Value = ok_rev.json().await.unwrap();
    assert_eq!(ok_rev_j["data"]["content"], "v2 human good");
    assert_ne!(ok_rev_j["data"]["head_op_ids"][0], op2);

    // Expect a live WS `blocks_changed` frame for the reverted block
    let mut saw_ws_revert = false;
    let ws_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < ws_deadline {
        if let Ok(Some(Ok(Message::Text(txt)))) =
            tokio::time::timeout(Duration::from_millis(500), ws_stream.next()).await
        {
            if let Ok(v) = serde_json::from_str::<Value>(&txt) {
                if v["type"] == "blocks_changed"
                    && v["upserted"].as_array().is_some_and(|arr| {
                        arr.iter()
                            .any(|b| b["id"] == blk_id && b["content"] == "v2 human good")
                    })
                {
                    saw_ws_revert = true;
                    break;
                }
            }
        }
    }
    assert!(saw_ws_revert, "WS must broadcast blocks_changed on POST /revert");

    // 2. Purge history + ExecuteShred -> HTTP 410 KEY_SHREDDED on history op, REST revert, and UDS revert!
    {
        let mut g = daemon.state.store.lock().unwrap();
        let (_rec, old_keys) = g
            .purge_block_history(&blk_id, None, None, T_GRACE_DEFAULT_MS, "human")
            .unwrap();
        let muts: Vec<StoreMutation> = old_keys
            .into_iter()
            .map(|key_id| StoreMutation::ExecuteShred { key_id })
            .collect();
        g.apply_store_mutations(&muts).unwrap();
    }

    let shred_get = http
        .get(format!("{base_ip}/v1/local/blocks/{blk_id}/history/{op1}"))
        .header(HOST, format!("localhost:{port}"))
        .header(COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(shred_get.status(), StatusCode::GONE);
    assert_eq!(
        shred_get.json::<Value>().await.unwrap()["error"]["code"],
        "KEY_SHREDDED"
    );

    let shred_post = http
        .post(format!("{base_ip}/v1/local/blocks/{blk_id}/revert"))
        .header(HOST, format!("localhost:{port}"))
        .header(ORIGIN, &base_localhost)
        .header(COOKIE, &cookie)
        .json(&json!({ "to_op_id": &op1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(shred_post.status(), StatusCode::GONE);
    assert_eq!(
        shred_post.json::<Value>().await.unwrap()["error"]["code"],
        "KEY_SHREDDED"
    );

    // LocalIpc ApplyRequest::RevertBlock shares resolve_revert_target and returns KEY_SHREDDED
    let dir_uds2 = dir.clone();
    let blk_for_uds = blk_id.clone();
    let op1_for_uds = op1.clone();
    let uds_resp = tokio::task::spawn_blocking(move || {
        try_send_ipc(
            &dir_uds2,
            &LocalIpcRequest::Apply {
                meta: ApplyMeta {
                    actor: "human".into(),
                    idempotency_key: None,
                    allow_empty: true,
                    force: false,
                },
                request: ApplyRequest::RevertBlock {
                    id: blk_for_uds,
                    to_op: Some(op1_for_uds),
                    undo_actor: None,
                },
            },
            Duration::from_secs(3),
        )
    })
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert!(!uds_resp.ok);
    assert_eq!(uds_resp.error.as_ref().unwrap().code, "KEY_SHREDDED");

    // 3. Conflict block -> POST /revert returns 409 CONFLICT_PRESENT
    let (conflict_id, conflict_op1) = {
        let mut g = daemon.state.store.lock().unwrap();
        let c1 = g
            .add_block("scratch", "dc-base", Some("text"), None, "human", None)
            .unwrap();
        let _c2 = g
            .update_block(&c1.block_id, "dc-local", &c1.head_op_ids, false, "human")
            .unwrap();
        let kr_json: Value =
            serde_json::from_slice(&std::fs::read(dir.join("smk_keyring.local.json")).unwrap()).unwrap();
        let smk_kid_s = kr_json["current_smk_kid"].as_str().unwrap();
        let smk_hex = kr_json["generations"][smk_kid_s].as_str().unwrap();
        let mut smk = [0u8; 32];
        for i in 0..32 {
            smk[i] = u8::from_str_radix(&smk_hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let smk_kid = SmkKid::parse(smk_kid_s).unwrap();
        let mut gen = MonotonicUlidGen::new();
        let remote_dev = DeviceId::parse("dev_dconf_tt1").unwrap();
        let c_bid = BlockId::parse(&c1.block_id).unwrap();
        let r_op = OpId::from_ulid(gen.next(1_795_800_000_000, [1u8; 10]));
        let r_kid = KeyId::from_ulid(gen.next(1_795_800_000_001, [2u8; 10]));
        let r_bdek = [0x55u8; 32];
        let r_mnb1 = encrypt_mnb1(c_bid.as_bytes(), r_op, r_kid, &r_bdek, "dc-remote", [3u8; 24]).unwrap();
        let r_mnr1 = encrypt_mnr1(
            smk_kid,
            &smk,
            1,
            &KeyRecordV1 {
                v: 1,
                key_id: r_kid,
                block_id: c_bid.0,
                tier: 1,
                created_hlc: Hlc::new(1_795_800_000_000, 0, remote_dev.clone()).canonical_string(),
                created_by: remote_dev.clone(),
                bdek: r_bdek.to_vec(),
            },
            [4u8; 24],
        )
        .unwrap();
        g.apply_remote_block_op_for_sync(RemoteBlockOpParams {
            remote_device: remote_dev.clone(),
            block_id: c_bid,
            op_id: r_op,
            parents: vec![OpId::parse(&c1.op_id).unwrap()],
            op_type: OpType::Update,
            hlc: Hlc::new(1_795_800_000_000, 0, remote_dev),
            tier: 1,
            key_id: r_kid,
            new_key_record: Some((1, r_mnr1)),
            mnb1: r_mnb1,
            public_hint: None,
        })
        .unwrap();
        g.set_local_meta("bootstrap_completed", "1").unwrap();
        (c1.block_id, c1.op_id)
    };
    let conf_rev = http
        .post(format!("{base_ip}/v1/local/blocks/{conflict_id}/revert"))
        .header(HOST, format!("localhost:{port}"))
        .header(ORIGIN, &base_localhost)
        .header(COOKIE, &cookie)
        .json(&json!({ "to_op_id": &conflict_op1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(conf_rev.status(), StatusCode::CONFLICT);
    assert_eq!(
        conf_rev.json::<Value>().await.unwrap()["error"]["code"],
        "CONFLICT_PRESENT"
    );

    // 4. Tier 2 historical op via Daemon GET /history/{op_id} & Tier 2 WASM-encrypted POST /revert (SEC-03!)
    let (t2_blk, t2_kid, t2_op1, t2_op2, unlocked) = {
        let mut g = daemon.state.store.lock().unwrap();
        let rpk = g.recovery_pk().unwrap();
        let vkid = VkekKid::from_ulid(Ulid::from_parts(1_720_000_100_000, [0x31; 10]));
        let vh = create_vault_header(
            b"daemon-m3-pass",
            &rpk,
            vkid,
            &[0x61; 32],
            [0x32; 16],
            [0x33; 24],
            [0x34; 32],
            [0x35; 24],
            1_720_000_100_000,
        )
        .unwrap();
        let unlocked = unlock_vault_with_passphrase(b"daemon-m3-pass", &vh).unwrap();
        g.put_vault_header(vh.updated_at_ms, &rmp_serde::to_vec_named(&vh).unwrap())
            .unwrap();

        let mut ugen = MonotonicUlidGen::new();
        let t2_blk = BlockId::from_ulid(ugen.next(1_795_810_000_000, [0x41; 10]));
        let t2_op1 = OpId::from_ulid(ugen.next(1_795_810_000_001, [0x42; 10]));
        let t2_kid = KeyId::from_ulid(ugen.next(1_795_810_000_002, [0x43; 10]));
        let t2_bdek = Zeroizing::new([0x66; 32]);
        let mnb1_1 = encrypt_mnb1(
            t2_blk.as_bytes(),
            t2_op1,
            t2_kid,
            &t2_bdek,
            "DAEMON_T2_HIST_CANARY_V1",
            [0x44; 24],
        )
        .unwrap();
        let mnw1 = unlocked.wrap_bdek(t2_kid, t2_blk, &t2_bdek, [0x45; 24]).unwrap();
        let r1 = g
            .add_tier2_block(
                &t2_blk.to_string(),
                Tier2OpInput {
                    op_id: &t2_op1.to_string(),
                    key_id: &t2_kid.to_string(),
                    mnb1: &mnb1_1,
                    mnw1: Some(&mnw1),
                },
                "scratch",
                "spy_daemon_sec03",
                None,
                Some("t2 hint"),
                "human",
            )
            .unwrap();
        let t2_op2 = OpId::from_ulid(ugen.next(1_795_810_000_010, [0x46; 10]));
        let mnb1_2 = encrypt_mnb1(
            t2_blk.as_bytes(),
            t2_op2,
            t2_kid,
            &t2_bdek,
            "DAEMON_T2_CURR_CANARY_V2",
            [0x47; 24],
        )
        .unwrap();
        g.update_tier2_block(
            &t2_blk.to_string(),
            Tier2OpInput {
                op_id: &t2_op2.to_string(),
                key_id: &t2_kid.to_string(),
                mnb1: &mnb1_2,
                mnw1: None,
            },
            &r1.head_op_ids,
            None,
            None,
            "human",
        )
        .unwrap();
        (t2_blk, t2_kid, t2_op1, t2_op2, unlocked)
    };

    let t2_hist_res = http
        .get(format!("{base_ip}/v1/local/blocks/{t2_blk}/history/{t2_op1}"))
        .header(HOST, format!("localhost:{port}"))
        .header(COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(t2_hist_res.status(), StatusCode::OK);
    let t2_hist_txt = t2_hist_res.text().await.unwrap();
    assert!(
        !t2_hist_txt.contains("DAEMON_T2_HIST_CANARY_V1"),
        "SEC-03 VIOLATION: Daemon history op response must contain ZERO Tier 2 plaintext"
    );
    let t2_hist_j: Value = serde_json::from_str(&t2_hist_txt).unwrap();
    assert_eq!(t2_hist_j["data"]["is_locked"], true);
    assert!(t2_hist_j["data"]["content"].is_null());
    let b64 = base64::engine::general_purpose::STANDARD;
    let mnb1_bytes = b64
        .decode(t2_hist_j["data"]["mnb1_b64"].as_str().unwrap())
        .unwrap();
    let mnw1_bytes = b64
        .decode(t2_hist_j["data"]["mnw1_b64"].as_str().unwrap())
        .unwrap();
    let dec_bdek = unlocked.unwrap_bdek(t2_kid, t2_blk, &mnw1_bytes).unwrap();
    let pt_v1 = decrypt_mnb1(t2_blk.as_bytes(), t2_op1, t2_kid, &dec_bdek, &mnb1_bytes).unwrap();
    assert_eq!(pt_v1, "DAEMON_T2_HIST_CANARY_V1");

    // Re-encrypt client-side (simulating WasmVaultSession) and POST /v1/local/blocks/{id}/revert
    let t2_op3 = OpId::from_ulid(Ulid::from_parts(1_795_810_000_020, [0x48; 10]));
    let mnb1_3 = encrypt_mnb1(t2_blk.as_bytes(), t2_op3, t2_kid, &dec_bdek, &pt_v1, [0x49; 24]).unwrap();
    let t2_rev = http
        .post(format!("{base_ip}/v1/local/blocks/{t2_blk}/revert"))
        .header(HOST, format!("localhost:{port}"))
        .header(ORIGIN, &base_localhost)
        .header(COOKIE, &cookie)
        .json(&json!({
            "expected_heads": [t2_op2.to_string()],
            "op_id": t2_op3.to_string(),
            "key_id": t2_kid.to_string(),
            "mnb1_b64": b64.encode(&mnb1_3),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(t2_rev.status(), StatusCode::OK);
    let t2_rev_txt = t2_rev.text().await.unwrap();
    assert!(!t2_rev_txt.contains("DAEMON_T2_HIST_CANARY_V1"));
    let t2_rev_j: Value = serde_json::from_str(&t2_rev_txt).unwrap();
    assert_eq!(t2_rev_j["data"]["is_locked"], true);
    assert_eq!(t2_rev_j["data"]["head_op_ids"][0], t2_op3.to_string());

    // 5. Daemon POST /v1/local/format SEC-03 locked-block zero-subprocess guarantee!
    let marker = dir.join("daemon_locked_fmt_spy.marker");
    let cfg_path = dir.join("daemon_formatters.toml");
    #[cfg(not(windows))]
    let spy_toml = format!(
        r#"
[formatters.spy_daemon_sec03]
cmd = ["sh", "-c", "touch '{}'; printf 'FMT:%s' \"$(cat)\""]
timeout_ms = 500
"#,
        marker.display()
    );
    #[cfg(windows)]
    let spy_toml = {
        let marker_posix = marker.to_string_lossy().replace('\\', "/");
        format!(
            r#"
[formatters.spy_daemon_sec03]
cmd = ["python", "-c", "import pathlib, sys; pathlib.Path('{marker_posix}').write_text('x'); sys.stdout.write('FMT:' + sys.stdin.read())"]
timeout_ms = 3000
"#
        )
    };
    std::fs::write(&cfg_path, spy_toml).unwrap();
    let _env_guard = EnvGuard {
        key: "MYNOTE_FORMATTERS_CONFIG",
        prev: std::env::var("MYNOTE_FORMATTERS_CONFIG").ok(),
    };
    std::env::set_var("MYNOTE_FORMATTERS_CONFIG", &cfg_path);

    // Locked block -> 423 BLOCK_LOCKED, spy subprocess MUST NOT run!
    let fmt_locked = http
        .post(format!("{base_ip}/v1/local/format"))
        .header(HOST, format!("localhost:{port}"))
        .header(ORIGIN, &base_localhost)
        .header(COOKIE, &cookie)
        .json(&json!({
            "block_id": t2_blk.to_string(),
            "lang": "spy_daemon_sec03",
            "content": "NEVER_PASS_TO_SUBPROCESS"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(fmt_locked.status(), StatusCode::LOCKED);
    assert_eq!(
        fmt_locked.json::<Value>().await.unwrap()["error"]["code"],
        "BLOCK_LOCKED"
    );
    assert!(
        !marker.exists(),
        "SEC-03 VIOLATION: Daemon /v1/local/format MUST NOT spawn subprocess for locked block_id"
    );

    // Unlocked block -> 200 OK via spawn_blocking external array-cmd formatter!
    let fmt_ok = http
        .post(format!("{base_ip}/v1/local/format"))
        .header(HOST, format!("localhost:{port}"))
        .header(ORIGIN, &base_localhost)
        .header(COOKIE, &cookie)
        .json(&json!({
            "block_id": blk_id,
            "lang": "spy_daemon_sec03",
            "content": "hello_t1"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(fmt_ok.status(), StatusCode::OK);
    assert_eq!(
        fmt_ok.json::<Value>().await.unwrap()["data"]["formatted"],
        "FMT:hello_t1"
    );
    assert!(marker.exists());

    drop(_env_guard);
    daemon.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}
