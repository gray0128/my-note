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
use mynote_cli::sync_client::{sha256_hex, RelayClient};
use mynote_cli::uds::{try_send_uds, ApplyMeta, ApplyRequest, UdsRequest};
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
        try_send_uds(&dir_uds, &UdsRequest::OpenTicket, Duration::from_secs(3))
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
        try_send_uds(&dir_uds, &UdsRequest::OpenTicket, Duration::from_secs(3))
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
    let req = PushRequestDto {
        expected_epoch,
        seen_seq,
        key_records,
        ops,
    };
    match g.relay.handle_push(&dev_id, &req, 1_795_521_600_000) {
        Ok((epoch, acked, head_seq)) => {
            let acked_json: Vec<Value> = acked
                .into_iter()
                .map(|a| json!({ "op_id": a.op_id.to_string(), "seq": a.seq }))
                .collect();
            Json(json!({ "ok": true, "epoch": epoch.to_string(), "acked": acked_json, "head_seq": head_seq }))
                .into_response()
        }
        Err(ErrorCode::CasMismatch) => (
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
        Err(code) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": { "code": code.as_str(), "message": "push error" } })),
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
    let mut km = serde_json::Map::new();
    if let Some((gen, blob)) = &g.relay.keys.keyring_material {
        km.insert(
            "keyring".into(),
            json!({ "gen": gen, "blob_b64": b64.encode(blob) }),
        );
    }
    Json(json!({
        "ok": true,
        "keys_digest": g.relay.keys.digest(),
        "key_records": recs,
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
        .create_pairing_ticket("omarchy", "read-write", store_a.current_smks_for_pairing())
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
/// - HIGH #8: Live daemon hot-reloads rotated SMKs on `UdsRequest::Poke` so subsequent writes use new SMK.
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
        .create_pairing_ticket("peer-desktop", "read-write", store_rec.current_smks_for_pairing())
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

    // Send UdsRequest::Poke -> daemon MUST hot-reload SMKs from disk
    let dir_d_poke = dir_daemon.clone();
    let poke_resp = tokio::task::spawn_blocking(move || {
        try_send_uds(
            &dir_d_poke,
            &UdsRequest::Poke { fast_flush: false },
            Duration::from_secs(3),
        )
    })
    .await
    .unwrap()
    .unwrap()
    .expect("daemon UDS reachable");
    assert!(poke_resp.ok);

    // Add a block via daemon UDS Apply -> new op MUST be encrypted with rotated_kid!
    let dir_d_apply = dir_daemon.clone();
    let apply_resp = tokio::task::spawn_blocking(move || {
        try_send_uds(
            &dir_d_apply,
            &UdsRequest::Apply {
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
        "daemon must encrypt new ops under the hot-reloaded SMK after UdsRequest::Poke"
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
