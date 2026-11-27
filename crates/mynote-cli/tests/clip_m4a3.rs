//! End-to-end integration tests for M4a-3 (`#57`):
//! - Local Daemon 8 `/v1/local/clip*` routes + SEC-05 auth + frozen DTO contract + WS `clip_changed`
//! - 4-state `device add --scope` (`read`, `read+clip`, `clip-write`, `read-write`) isolation
//! - Cloud WS `clip_wake` auto-apply (including JPEG->PNG transcode & EchoGuard),
//!   zero-DB `clip_ephemeral` + safe auto-clear timer, `clip_cleared` + `rotate-key`
//! - `mynote clip <push|pull|history|promote|undo|rotate-key>` CLI subcommands & `device revoke` hint.

use axum::body::Bytes;
use axum::extract::ws::{Message as AxumWsMsg, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use image::codecs::jpeg::JpegEncoder;
use image::{ImageFormat, RgbaImage};
use mynote_cli::clipboard::{ClipboardPayload, InMemoryClipboard};
use mynote_cli::daemon::{start_daemon_with_clipboard, DaemonConfig};
use mynote_cli::runner::run_from;
use mynote_cli::sync_client::{decode_pairing_code, ensure_clip_key, rotate_clip_key, RelayClient};
use mynote_core::clip::{
    clip_sha256_hex, encrypt_mnc1_blob, encrypt_mnc1_meta, ClipBlobMetaV1, ClipKind, ClipMetaV1,
    ClipSourceMode, CLIP_BLOB_MAX_BYTES, CLIP_DEFAULT_TTL_MS,
};
use mynote_core::crypto::decrypt_pairing_ticket;
use mynote_core::error::ErrorCode;
use mynote_core::ids::JournalEpoch;
use mynote_store::LocalStore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

fn temp_dir(tag: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("mynote_clip_m4a3_{tag}_{ts}"));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
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
// In-process Mock Cloud Relay (M4a-2 wire-compatible for /v1/clip*, /v1/keys, /v1/devices, /v1/sync/ws)
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
    device_name: String,
    scope: String,
    token_hash: String,
    revoked_at_ms: Option<i64>,
}

struct MockPairing {
    device_id: String,
    scope: String,
    ciphertext_b64: String,
    claimed: bool,
}

struct ClipRelayState {
    bootstrap_token: String,
    epoch: JournalEpoch,
    devices: BTreeMap<String, MockDevice>,
    pairings: BTreeMap<String, MockPairing>,
    clip_key_material: Option<(i64, String)>,
    clips: BTreeMap<String, MockClipRecord>,
    ws_tx: broadcast::Sender<String>,
    online_desktop_ws: usize,
}

impl ClipRelayState {
    fn new(bootstrap_token: &str) -> Self {
        let (ws_tx, _) = broadcast::channel(128);
        Self {
            bootstrap_token: bootstrap_token.to_string(),
            epoch: JournalEpoch::from_random_bytes([0x42; 16]),
            devices: BTreeMap::new(),
            pairings: BTreeMap::new(),
            clip_key_material: None,
            clips: BTreeMap::new(),
            ws_tx,
            online_desktop_ws: 0,
        }
    }

    fn auth(&self, headers: &HeaderMap) -> Result<(String, String), (StatusCode, Json<serde_json::Value>)> {
        let tok = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or_default();
        let hash = sha256_hex(tok);
        for d in self.devices.values() {
            if d.token_hash == hash {
                if d.revoked_at_ms.is_some() {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({
                            "ok": false,
                            "error": { "code": "DEVICE_REVOKED", "message": "revoked" }
                        })),
                    ));
                }
                return Ok((d.device_id.clone(), d.scope.clone()));
            }
        }
        Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "ok": false,
                "error": { "code": "AUTH_REQUIRED", "message": "unauthorized" }
            })),
        ))
    }
}

fn now_ms_test() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

async fn mock_bootstrap(
    State(st): State<Arc<Mutex<ClipRelayState>>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let mut g = st.lock().unwrap();
    let tok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or_default();
    if tok != g.bootstrap_token {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": { "code": "AUTH_REQUIRED", "message": "bad bootstrap" } })),
        )
            .into_response();
    }
    let dev_id = body["device_id"].as_str().unwrap().to_string();
    let dev_name = body["device_name"].as_str().unwrap_or("dev").to_string();
    let token_hash = body["token_sha256_hex"].as_str().unwrap().to_string();
    g.devices.insert(
        dev_id.clone(),
        MockDevice {
            device_id: dev_id.clone(),
            device_name: dev_name,
            scope: "read-write".to_string(),
            token_hash,
            revoked_at_ms: None,
        },
    );
    Json(serde_json::json!({
        "ok": true,
        "device_id": dev_id,
        "scope": "read-write",
        "epoch": g.epoch.to_string(),
    }))
    .into_response()
}

async fn mock_devices_post(
    State(st): State<Arc<Mutex<ClipRelayState>>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let mut g = st.lock().unwrap();
    let Ok((_, scope)) = g.auth(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": { "code": "AUTH_REQUIRED", "message": "auth" } })),
        )
            .into_response();
    };
    if scope != "read-write" {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": { "code": "TOKEN_SCOPE_FORBIDDEN", "message": "rw required" } })),
        )
            .into_response();
    }
    let dev_id = body["device_id"].as_str().unwrap().to_string();
    let pair_id = body["pair_id"].as_str().unwrap().to_string();
    let dev_name = body["device_name"].as_str().unwrap_or("peer").to_string();
    let new_scope = body["scope"].as_str().unwrap_or("read-write").to_string();
    let token_hash = body["token_sha256_hex"].as_str().unwrap().to_string();
    let ct = body["ciphertext_b64"].as_str().unwrap().to_string();
    g.devices.insert(
        dev_id.clone(),
        MockDevice {
            device_id: dev_id.clone(),
            device_name: dev_name,
            scope: new_scope.clone(),
            token_hash,
            revoked_at_ms: None,
        },
    );
    g.pairings.insert(
        pair_id.clone(),
        MockPairing {
            device_id: dev_id.clone(),
            scope: new_scope,
            ciphertext_b64: ct,
            claimed: false,
        },
    );
    Json(serde_json::json!({
        "ok": true,
        "device_id": dev_id,
        "pair_id": pair_id,
        "expires_at_ms": now_ms_test() + 600_000,
    }))
    .into_response()
}

async fn mock_devices_get(State(st): State<Arc<Mutex<ClipRelayState>>>, headers: HeaderMap) -> Response {
    let g = st.lock().unwrap();
    if let Err(resp) = g.auth(&headers) {
        return resp.into_response();
    }
    let list: Vec<serde_json::Value> = g
        .devices
        .values()
        .map(|d| {
            serde_json::json!({
                "device_id": d.device_id,
                "device_name": d.device_name,
                "scope": d.scope,
                "created_at_ms": 1,
                "last_seen_at_ms": 1,
                "last_pulled_seq": 0,
                "claimed_at_ms": 1,
                "revoked_at_ms": d.revoked_at_ms,
            })
        })
        .collect();
    Json(serde_json::json!({ "ok": true, "devices": list })).into_response()
}

async fn mock_device_revoke(
    State(st): State<Arc<Mutex<ClipRelayState>>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let mut g = st.lock().unwrap();
    if let Err(resp) = g.auth(&headers) {
        return resp.into_response();
    }
    let now = now_ms_test();
    if let Some(d) = g.devices.get_mut(&id) {
        d.revoked_at_ms = Some(now);
        return Json(serde_json::json!({ "ok": true, "revoked_at_ms": now })).into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "ok": false, "error": { "code": "NOT_FOUND", "message": "not found" } })),
    )
        .into_response()
}

async fn mock_pair_claim(
    State(st): State<Arc<Mutex<ClipRelayState>>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let mut g = st.lock().unwrap();
    let pid = body["pair_id"].as_str().unwrap_or_default();
    let Some(p) = g.pairings.get_mut(pid) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": { "code": "NOT_FOUND", "message": "missing pair_id" } })),
        )
            .into_response();
    };
    if p.claimed {
        return (
            StatusCode::GONE,
            Json(serde_json::json!({ "ok": false, "error": { "code": "NOT_FOUND", "message": "already claimed" } })),
        )
            .into_response();
    }
    p.claimed = true;
    Json(serde_json::json!({
        "ok": true,
        "kind": "add",
        "device_id": p.device_id,
        "scope": p.scope,
        "ciphertext_b64": p.ciphertext_b64,
    }))
    .into_response()
}

async fn mock_keys_get(State(st): State<Arc<Mutex<ClipRelayState>>>, headers: HeaderMap) -> Response {
    let g = st.lock().unwrap();
    if let Err(resp) = g.auth(&headers) {
        return resp.into_response();
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

async fn mock_keys_post(
    State(st): State<Arc<Mutex<ClipRelayState>>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let mut g = st.lock().unwrap();
    if let Err(resp) = g.auth(&headers) {
        return resp.into_response();
    }
    let mut ck_gen_out: Option<i64> = g.clip_key_material.as_ref().map(|(gen, _)| *gen);
    if let Some(ck) = body["key_material"]["clip_key"].as_object() {
        let gen = ck["gen"].as_i64().unwrap_or(1);
        let b64 = ck["blob_b64"].as_str().unwrap_or_default().to_string();
        if let Some((cur_gen, _)) = &g.clip_key_material {
            if gen < *cur_gen {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({ "ok": false, "error": { "code": "CAS_MISMATCH", "message": "stale clip_key gen" } })),
                )
                    .into_response();
            }
        }
        g.clip_key_material = Some((gen, b64));
        ck_gen_out = Some(gen);
    }
    if body["clear_clips"].as_bool().unwrap_or(false) {
        g.clips.clear();
        let _ = g.ws_tx.send(
            serde_json::json!({ "type": "clip_cleared", "clip_id": serde_json::Value::Null }).to_string(),
        );
    }
    Json(serde_json::json!({
        "ok": true,
        "key_material_gens": {
            "clip_key": ck_gen_out,
        }
    }))
    .into_response()
}

async fn mock_sync_pull(State(st): State<Arc<Mutex<ClipRelayState>>>, headers: HeaderMap) -> Response {
    let g = st.lock().unwrap();
    if let Err(resp) = g.auth(&headers) {
        return resp.into_response();
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

#[derive(Deserialize)]
struct ClipListQuery {
    since_id: Option<String>,
    limit: Option<usize>,
}

async fn mock_clip_get(
    State(st): State<Arc<Mutex<ClipRelayState>>>,
    headers: HeaderMap,
    Query(q): Query<ClipListQuery>,
) -> Response {
    let g = st.lock().unwrap();
    let Ok((_, scope)) = g.auth(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": { "code": "AUTH_REQUIRED", "message": "auth" } })),
        )
            .into_response();
    };
    if scope == "clip-write" || scope == "read" {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": { "code": "TOKEN_SCOPE_FORBIDDEN", "message": "scope" } })),
        )
            .into_response();
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

async fn mock_clip_post(
    State(st): State<Arc<Mutex<ClipRelayState>>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let mut g = st.lock().unwrap();
    let Ok((dev_id, scope)) = g.auth(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": { "code": "AUTH_REQUIRED", "message": "auth" } })),
        )
            .into_response();
    };
    if scope == "read" {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": { "code": "TOKEN_SCOPE_FORBIDDEN", "message": "scope" } })),
        )
            .into_response();
    }
    let clip_id = body["clip_id"].as_str().unwrap().to_string();
    let clip_kid = body["clip_kid"].as_str().unwrap().to_string();
    let kind = body["kind"].as_str().unwrap_or("text").to_string();
    let ephemeral = body["ephemeral"].as_bool().unwrap_or(false);
    let env_b64 = body["meta_envelope_b64"].as_str().unwrap().to_string();
    if ephemeral {
        if g.online_desktop_ws == 0 {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "ok": false,
                    "error": { "code": "NO_ONLINE_DESKTOP", "message": "no online desktop connected" }
                })),
            )
                .into_response();
        }
        let delivered = g.online_desktop_ws;
        let _ = g.ws_tx.send(
            serde_json::json!({
                "type": "clip_ephemeral",
                "clip_id": clip_id,
                "clip_kid": clip_kid,
                "device_id": dev_id,
                "envelope_b64": env_b64,
            })
            .to_string(),
        );
        return Json(serde_json::json!({
            "ok": true,
            "clip_id": clip_id,
            "delivered_to": delivered,
        }))
        .into_response();
    }

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

async fn mock_clip_put_blob(
    State(st): State<Arc<Mutex<ClipRelayState>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut g = st.lock().unwrap();
    let Ok((dev_id, scope)) = g.auth(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "ok": false, "error": { "code": "AUTH_REQUIRED", "message": "auth" } })),
        )
            .into_response();
    };
    if scope == "read" {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": { "code": "TOKEN_SCOPE_FORBIDDEN", "message": "scope" } })),
        )
            .into_response();
    }
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

async fn mock_clip_get_blob(
    State(st): State<Arc<Mutex<ClipRelayState>>>,
    headers: HeaderMap,
    AxumPath(clip_id): AxumPath<String>,
) -> Response {
    let g = st.lock().unwrap();
    if let Err(resp) = g.auth(&headers) {
        return resp.into_response();
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

async fn mock_clip_delete_all(State(st): State<Arc<Mutex<ClipRelayState>>>, headers: HeaderMap) -> Response {
    let mut g = st.lock().unwrap();
    if let Err(resp) = g.auth(&headers) {
        return resp.into_response();
    }
    let count = g.clips.len();
    g.clips.clear();
    let _ = g
        .ws_tx
        .send(serde_json::json!({ "type": "clip_cleared", "clip_id": serde_json::Value::Null }).to_string());
    Json(serde_json::json!({ "ok": true, "deleted_count": count })).into_response()
}

async fn mock_clip_delete_one(
    State(st): State<Arc<Mutex<ClipRelayState>>>,
    headers: HeaderMap,
    AxumPath(clip_id): AxumPath<String>,
) -> Response {
    let mut g = st.lock().unwrap();
    if let Err(resp) = g.auth(&headers) {
        return resp.into_response();
    }
    let deleted = usize::from(g.clips.remove(&clip_id).is_some());
    if deleted > 0 {
        let _ = g
            .ws_tx
            .send(serde_json::json!({ "type": "clip_cleared", "clip_id": clip_id }).to_string());
    }
    Json(serde_json::json!({ "ok": true, "deleted_count": deleted })).into_response()
}

async fn mock_ws(
    State(st): State<Arc<Mutex<ClipRelayState>>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let scope = {
        let g = st.lock().unwrap();
        match g.auth(&headers) {
            Ok((_, s)) => s,
            Err(resp) => return resp.into_response(),
        }
    };
    ws.on_upgrade(move |socket| serve_mock_ws(st, scope, socket))
}

async fn serve_mock_ws(st: Arc<Mutex<ClipRelayState>>, scope: String, socket: WebSocket) {
    let mut rx = {
        let mut g = st.lock().unwrap();
        if scope == "read-write" {
            g.online_desktop_ws += 1;
        }
        g.ws_tx.subscribe()
    };
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
    let mut g = st.lock().unwrap();
    if scope == "read-write" {
        g.online_desktop_ws = g.online_desktop_ws.saturating_sub(1);
    }
}

async fn spawn_mock_clip_relay(
    token: &str,
) -> (String, Arc<Mutex<ClipRelayState>>, tokio::task::JoinHandle<()>) {
    let state = Arc::new(Mutex::new(ClipRelayState::new(token)));
    let app = Router::new()
        .route("/v1/devices/bootstrap", post(mock_bootstrap))
        .route("/v1/devices", post(mock_devices_post).get(mock_devices_get))
        .route("/v1/devices/pair-claim", post(mock_pair_claim))
        .route("/v1/devices/{id}", delete(mock_device_revoke))
        .route("/v1/keys", get(mock_keys_get).post(mock_keys_post))
        .route("/v1/sync/pull", get(mock_sync_pull))
        .route(
            "/v1/clip",
            get(mock_clip_get)
                .post(mock_clip_post)
                .delete(mock_clip_delete_all),
        )
        .route(
            "/v1/clip/blob",
            put(mock_clip_put_blob).layer(DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route("/v1/clip/{clip_id}", delete(mock_clip_delete_one))
        .route("/v1/clip/{clip_id}/blob", get(mock_clip_get_blob))
        .route("/v1/sync/ws", get(mock_ws))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, state, handle)
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

// ---------------------------------------------------------------------------
// Test 1: All 8 Local Daemon /v1/local/clip* routes + SEC-05 + Frozen DTO + WS + SVG/10MiB guards
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_clip_api_eight_routes_sec05_svg_cap_promote_apply_undo_and_ws() {
    let (relay_url, _relay_st, relay_srv) = spawn_mock_clip_relay("boot-secret").await;
    let dir = temp_dir("daemon_routes");

    // Bootstrap device so daemon pushes/pulls via mock relay
    {
        let store = LocalStore::open(&dir).unwrap();
        RelayClient::bootstrap_device(&relay_url, "boot-secret", &store, "macbook", false)
            .await
            .unwrap();
    }

    let mem_clip = Arc::new(InMemoryClipboard::new());
    mem_clip.set_user_text("user_original_clipboard");

    let daemon = start_daemon_with_clipboard(
        DaemonConfig {
            data_dir: dir.clone(),
            port: 0,
            enable_cloud_sync: false,
        },
        mem_clip.clone(),
    )
    .await
    .unwrap();
    let port = daemon.port;
    let ticket_url = daemon.state.issue_open_ticket().unwrap();
    let cookie = acquire_daemon_cookie(port, &ticket_url).await;
    let origin = format!("http://localhost:{port}");
    let host = format!("localhost:{port}");
    let base = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // SEC-05: missing cookie -> 401; wrong Host -> 403
    let unauth = http
        .get(format!("{base}/v1/local/clip"))
        .header("Host", &host)
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
    let bad_host = http
        .get(format!("{base}/v1/local/clip"))
        .header("Host", format!("127.0.0.1:{port}"))
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_host.status(), StatusCode::FORBIDDEN);

    // Subscribe to local WS `/v1/local/ws` to verify `clip_changed` frames
    let mut ws_rx = daemon.state.ws_tx.subscribe();

    // 1. POST text clip
    let post_txt: serde_json::Value = http
        .post(format!("{base}/v1/local/clip"))
        .header("Host", &host)
        .header("Origin", &origin)
        .header("Cookie", &cookie)
        .json(&serde_json::json!({ "kind": "text", "text": "hello from drawer" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(post_txt["ok"], true);
    assert_eq!(post_txt["data"]["ephemeral"], false);
    let text_clip_id = post_txt["data"]["clip_id"].as_str().unwrap().to_string();
    assert_eq!(post_txt["data"]["item"]["text_preview"], "hello from drawer");
    assert_eq!(post_txt["data"]["item"]["cached_locally"], true);

    // Confirm WS broadcast shape matches frozen contract
    let ws_frame: serde_json::Value = serde_json::from_str(&ws_rx.recv().await.unwrap()).unwrap();
    assert_eq!(ws_frame["type"], "clip_changed");
    assert_eq!(ws_frame["cleared"], false);
    assert_eq!(ws_frame["watch_paused"], false);
    assert_eq!(ws_frame["upserted"][0]["clip_id"], text_clip_id);

    // 2. POST SVG image -> MUST reject 400 INVALID_ARGUMENT (both explicit SVG MIME and smuggled SVG bytes!)
    let b64 = base64::engine::general_purpose::STANDARD;
    let svg_bytes = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>";
    let svg_resp = http
        .post(format!("{base}/v1/local/clip"))
        .header("Host", &host)
        .header("Origin", &origin)
        .header("Cookie", &cookie)
        .json(&serde_json::json!({
            "kind": "image",
            "mime": "image/svg+xml",
            "data_b64": b64.encode(svg_bytes),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(svg_resp.status(), StatusCode::BAD_REQUEST);
    let svg_json: serde_json::Value = svg_resp.json().await.unwrap();
    assert_eq!(svg_json["error"]["code"], "INVALID_ARGUMENT");

    let smuggled_resp = http
        .post(format!("{base}/v1/local/clip"))
        .header("Host", &host)
        .header("Origin", &origin)
        .header("Cookie", &cookie)
        .json(&serde_json::json!({
            "kind": "image",
            "mime": "image/png",
            "data_b64": b64.encode(svg_bytes),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(smuggled_resp.status(), StatusCode::BAD_REQUEST);

    // 3. POST > 10 MiB image -> MUST reject 400 INVALID_ARGUMENT
    let huge = vec![0x89u8; CLIP_BLOB_MAX_BYTES + 128];
    let huge_resp = http
        .post(format!("{base}/v1/local/clip"))
        .header("Host", &host)
        .header("Origin", &origin)
        .header("Cookie", &cookie)
        .json(&serde_json::json!({
            "kind": "image",
            "mime": "image/png",
            "data_b64": b64.encode(&huge),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(huge_resp.status(), StatusCode::BAD_REQUEST);
    let huge_json: serde_json::Value = huge_resp.json().await.unwrap();
    assert_eq!(huge_json["error"]["code"], "INVALID_ARGUMENT");

    // 4. POST valid JPEG image -> auto thumbnail (image/jpeg data URL, never SVG) + cached locally
    let jpg_bytes = sample_image_bytes(64, 48, ImageFormat::Jpeg);
    let post_img: serde_json::Value = http
        .post(format!("{base}/v1/local/clip"))
        .header("Host", &host)
        .header("Origin", &origin)
        .header("Cookie", &cookie)
        .json(&serde_json::json!({
            "kind": "image",
            "mime": "image/jpeg",
            "data_b64": b64.encode(&jpg_bytes),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(post_img["ok"], true);
    let img_clip_id = post_img["data"]["clip_id"].as_str().unwrap().to_string();
    let img_dto = &post_img["data"]["item"];
    assert_eq!(img_dto["kind"], "image");
    assert_eq!(img_dto["mime"], "image/jpeg");
    assert_eq!(img_dto["width"], 64);
    assert_eq!(img_dto["height"], 48);
    assert_eq!(img_dto["has_blob"], true);
    assert_eq!(img_dto["cached_locally"], true);
    assert!(img_dto["thumb_data_url"]
        .as_str()
        .unwrap()
        .starts_with("data:image/jpeg;base64,"));

    // 5. GET /v1/local/clip (and kind filter)
    let list_all: serde_json::Value = http
        .get(format!("{base}/v1/local/clip?limit=100"))
        .header("Host", &host)
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list_all["data"]["items"].as_array().unwrap().len(), 2);
    assert_eq!(list_all["data"]["has_undo"], false);
    assert_eq!(list_all["data"]["watch_enabled"], false);
    assert_eq!(list_all["data"]["watch_paused"], false);
    assert_eq!(list_all["data"]["auto_apply_mirror"], "inbox-only");

    let list_img: serde_json::Value = http
        .get(format!("{base}/v1/local/clip?kind=image"))
        .header("Host", &host)
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list_img["data"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(list_img["data"]["items"][0]["clip_id"], img_clip_id);

    // 6. GET /v1/local/clip/{id}/blob (test BOTH cache hit AND cache-evicted relay re-download!)
    {
        let store = daemon.state.store.lock().unwrap();
        store.clip_cache().clear().unwrap();
    }
    let blob_resp = http
        .get(format!("{base}/v1/local/clip/{img_clip_id}/blob"))
        .header("Host", &host)
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(blob_resp.status(), StatusCode::OK);
    assert_eq!(blob_resp.headers().get("content-type").unwrap(), "image/jpeg");
    assert_eq!(
        blob_resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(blob_resp.headers().get("cache-control").unwrap(), "no-store");
    let fetched_bytes = blob_resp.bytes().await.unwrap();
    assert_eq!(fetched_bytes.as_ref(), jpg_bytes.as_slice());

    // 7. POST /v1/local/clip/{id}/apply (JPEG -> PNG transcode + EchoGuard + UndoSlot) & POST /undo
    let apply_res: serde_json::Value = http
        .post(format!("{base}/v1/local/clip/{img_clip_id}/apply"))
        .header("Host", &host)
        .header("Origin", &origin)
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(apply_res["data"]["applied"], true);
    assert_eq!(apply_res["data"]["has_undo"], true);
    let (applied_payload, applied_opts, applied_hash) = mem_clip.snapshot().unwrap();
    assert!(applied_opts.synced_marker);
    match applied_payload {
        ClipboardPayload::Image { mime, bytes, .. } => {
            assert_eq!(mime, "image/png");
            assert_eq!(&bytes[..8], &mynote_cli::clipboard::PNG_MAGIC);
            assert_eq!(
                daemon.state.clip_echo.lock().unwrap().last_hash(),
                Some(applied_hash)
            );
        }
        other => panic!("expected PNG image in clipboard, got {other:?}"),
    }

    let undo_res: serde_json::Value = http
        .post(format!("{base}/v1/local/clip/undo"))
        .header("Host", &host)
        .header("Origin", &origin)
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(undo_res["data"]["restored"], true);
    assert_eq!(
        mem_clip.snapshot().unwrap().0,
        ClipboardPayload::Text("user_original_clipboard".to_string())
    );

    // 8. POST /v1/local/clip/{id}/promote (text OK -> BlockDto; image -> 400 INVALID_ARGUMENT)
    let promo_img = http
        .post(format!("{base}/v1/local/clip/{img_clip_id}/promote"))
        .header("Host", &host)
        .header("Origin", &origin)
        .header("Cookie", &cookie)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(promo_img.status(), StatusCode::BAD_REQUEST);

    let promo_txt: serde_json::Value = http
        .post(format!("{base}/v1/local/clip/{text_clip_id}/promote"))
        .header("Host", &host)
        .header("Origin", &origin)
        .header("Cookie", &cookie)
        .json(&serde_json::json!({ "buffer_id": "scratch", "lang": "text" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(promo_txt["ok"], true);
    assert_eq!(promo_txt["data"]["block"]["content"], "hello from drawer");

    // 9. PATCH /v1/local/clip/watch
    let watch_res: serde_json::Value = http
        .patch(format!("{base}/v1/local/clip/watch"))
        .header("Host", &host)
        .header("Origin", &origin)
        .header("Cookie", &cookie)
        .json(&serde_json::json!({
            "paused": true,
            "enabled": true,
            "auto_apply_mirror": "auto-apply"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(watch_res["data"]["watch_paused"], true);
    assert_eq!(watch_res["data"]["watch_enabled"], true);
    assert_eq!(watch_res["data"]["auto_apply_mirror"], "auto-apply");

    // 10. DELETE single & DELETE all
    let del_one: serde_json::Value = http
        .delete(format!("{base}/v1/local/clip/{text_clip_id}"))
        .header("Host", &host)
        .header("Origin", &origin)
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(del_one["data"]["deleted_count"], 1);

    let del_all: serde_json::Value = http
        .delete(format!("{base}/v1/local/clip"))
        .header("Host", &host)
        .header("Origin", &origin)
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(del_all["data"]["deleted_count"], 1);

    daemon.shutdown();
    relay_srv.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Test 2: 4-State Pairing Scope Isolation (`clip-write` has ZERO SMKs!) + Cloud WS clip_wake /
//         zero-DB clip_ephemeral auto-clear / clip_cleared / rotate_clip_key
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_scope_isolation_and_cloud_ws_clip_wake_ephemeral_and_rotate_key() {
    std::env::set_var("MYNOTE_CLIP_EPHEMERAL_CLEAR_MS", "150");
    std::env::set_var("MYNOTE_NO_NOTIFY", "1");

    let (relay_url, relay_st, relay_srv) = spawn_mock_clip_relay("ws-secret").await;
    let dir_a = temp_dir("ws_desktop_a");
    let dir_b = temp_dir("ws_desktop_b");

    let mut store_a = LocalStore::open(&dir_a).unwrap();
    RelayClient::bootstrap_device(&relay_url, "ws-secret", &store_a, "macbook-a", false)
        .await
        .unwrap();
    let creds_a = store_a.load_credentials().unwrap().unwrap();
    let client_a = RelayClient::from_credentials(&creds_a).unwrap();
    let (ck, ck_key, ck_gen) = ensure_clip_key(&mut store_a, &client_a).await.unwrap();
    assert_eq!(ck_gen, 1);

    // --- 4-State Device Pairing Scope Verification ---
    // (a) `clip-write`: MUST contain ZERO SMKs and ONLY `(clip_kid, clip_key)`!
    let cw_ticket = client_a
        .create_pairing_ticket(
            "ios-shortcut",
            "clip-write",
            store_a.current_smks_for_pairing(), // even if caller passed SMKs, create_pairing_ticket strips them!
            Some((ck, ck_key.clone())),
        )
        .await
        .unwrap();
    assert_eq!(cw_ticket.scope, "clip-write");
    let (_url, cw_pair_id, cw_k_pair) = decode_pairing_code(&cw_ticket.pairing_code).unwrap();
    let cw_ct_b64 = relay_st
        .lock()
        .unwrap()
        .pairings
        .get(&cw_pair_id)
        .unwrap()
        .ciphertext_b64
        .clone();
    let cw_ct = base64::engine::general_purpose::STANDARD
        .decode(cw_ct_b64)
        .unwrap();
    let cw_payload = decrypt_pairing_ticket(&cw_pair_id, &cw_k_pair, &cw_ct).unwrap();
    assert!(
        cw_payload.smks.is_empty(),
        "HARD INVARIANT: clip-write pairing payload MUST carry ZERO SMKs"
    );
    assert_eq!(cw_payload.clip_kid, Some(ck));
    assert_eq!(cw_payload.clip_key, Some(*ck_key));

    // (b) `read+clip`: MUST carry BOTH SMKs AND `(clip_kid, clip_key)`!
    let rc_ticket = client_a
        .create_pairing_ticket(
            "iphone-pwa",
            "read+clip",
            store_a.current_smks_for_pairing(),
            Some((ck, ck_key.clone())),
        )
        .await
        .unwrap();
    let (_, rc_pid, rc_kp) = decode_pairing_code(&rc_ticket.pairing_code).unwrap();
    let rc_ct = base64::engine::general_purpose::STANDARD
        .decode(
            &relay_st
                .lock()
                .unwrap()
                .pairings
                .get(&rc_pid)
                .unwrap()
                .ciphertext_b64,
        )
        .unwrap();
    let rc_payload = decrypt_pairing_ticket(&rc_pid, &rc_kp, &rc_ct).unwrap();
    assert!(!rc_payload.smks.is_empty());
    assert_eq!(rc_payload.clip_kid, Some(ck));
    assert_eq!(rc_payload.clip_key, Some(*ck_key));

    // (c) `read-write` Desktop B pairing
    let rw_ticket = client_a
        .create_pairing_ticket(
            "omarchy-b",
            "read-write",
            store_a.current_smks_for_pairing(),
            Some((ck, ck_key.clone())),
        )
        .await
        .unwrap();
    RelayClient::claim_pairing_code(&rw_ticket.pairing_code, &dir_b)
        .await
        .unwrap();

    // Ephemeral push BEFORE Desktop B connects -> 409 NO_ONLINE_DESKTOP!
    let eph_id_0 = store_a.next_clip_id(now_ms_test() as u64).unwrap();
    let eph_meta_0 = ClipMetaV1 {
        v: 1,
        kind: ClipKind::Text,
        mime: "text/plain".to_string(),
        source_mode: ClipSourceMode::Explicit,
        created_at_ms: now_ms_test(),
        text: Some("OTP-OFFLINE".to_string()),
        blob: None,
    };
    let eph_env_0 = encrypt_mnc1_meta(
        ck,
        &ck_key,
        eph_id_0,
        store_a.device_id(),
        &eph_meta_0,
        true,
        [0x11; 24],
    )
    .unwrap();
    let err_no_desk = client_a
        .clip_push_meta(&eph_id_0.to_string(), &ck.to_string(), "text", true, &eph_env_0)
        .await
        .unwrap_err();
    assert_eq!(err_no_desk.code(), ErrorCode::NoOnlineDesktop);

    // Start Desktop B daemon with live Cloud WS + InMemoryClipboard
    let clip_b = Arc::new(InMemoryClipboard::new());
    clip_b.set_user_text("b_before_sync");
    let daemon_b = start_daemon_with_clipboard(
        DaemonConfig {
            data_dir: dir_b.clone(),
            port: 0,
            enable_cloud_sync: true,
        },
        clip_b.clone(),
    )
    .await
    .unwrap();

    // Wait for Desktop B WS to register as online
    for _ in 0..50 {
        if relay_st.lock().unwrap().online_desktop_ws >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(relay_st.lock().unwrap().online_desktop_ws >= 1);

    // --- Test `clip_wake`: Desktop A pushes JPEG image -> Desktop B pulls, caches, auto-applies as PNG! ---
    let jpg = sample_image_bytes(32, 24, ImageFormat::Jpeg);
    let sha = clip_sha256_hex(&jpg);
    let img_cid = store_a.next_clip_id(now_ms_test() as u64).unwrap();
    let img_meta = ClipMetaV1 {
        v: 1,
        kind: ClipKind::Image,
        mime: "image/jpeg".to_string(),
        source_mode: ClipSourceMode::Explicit,
        created_at_ms: now_ms_test(),
        text: None,
        blob: Some(ClipBlobMetaV1 {
            byte_size: jpg.len() as u64,
            sha256_hex: sha,
            width: Some(32),
            height: Some(24),
            thumb_mime: None,
            thumb_b64: None,
        }),
    };
    let img_meta_env = encrypt_mnc1_meta(
        ck,
        &ck_key,
        img_cid,
        store_a.device_id(),
        &img_meta,
        false,
        [0x21; 24],
    )
    .unwrap();
    let img_blob_env =
        encrypt_mnc1_blob(ck, &ck_key, img_cid, store_a.device_id(), &jpg, [0x22; 24]).unwrap();
    client_a
        .clip_push_blob(
            &img_cid.to_string(),
            &ck.to_string(),
            "image",
            &img_meta_env,
            &img_blob_env,
        )
        .await
        .unwrap();

    // Wait for Desktop B to auto-apply PNG onto clip_b
    let mut applied_png = false;
    for _ in 0..60 {
        if let Some((ClipboardPayload::Image { mime, .. }, opts, hash)) = clip_b.snapshot() {
            if mime == "image/png" && opts.synced_marker {
                assert_eq!(daemon_b.state.clip_echo.lock().unwrap().last_hash(), Some(hash));
                applied_png = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert!(
        applied_png,
        "Desktop B must auto-apply explicit remote JPEG as PNG"
    );
    // Undo on Desktop B restores `"b_before_sync"`
    assert!(daemon_b.state.undo_clipboard().unwrap());
    assert_eq!(
        clip_b.snapshot().unwrap().0,
        ClipboardPayload::Text("b_before_sync".to_string())
    );

    // --- Test `clip_ephemeral`: zero DB / zero clip_cache + auto-clear timer ---
    let count_b_before = daemon_b
        .state
        .store
        .lock()
        .unwrap()
        .list_clip_items(100, None)
        .unwrap()
        .len();
    let cache_b_before = daemon_b.state.store.lock().unwrap().clip_cache().stats();

    let eph_id = store_a.next_clip_id(now_ms_test() as u64).unwrap();
    let eph_meta = ClipMetaV1 {
        v: 1,
        kind: ClipKind::Text,
        mime: "text/plain".to_string(),
        source_mode: ClipSourceMode::Explicit,
        created_at_ms: now_ms_test(),
        text: Some("OTP-EPHEMERAL-778899".to_string()),
        blob: None,
    };
    let eph_env = encrypt_mnc1_meta(
        ck,
        &ck_key,
        eph_id,
        store_a.device_id(),
        &eph_meta,
        true,
        [0x33; 24],
    )
    .unwrap();
    let eph_rec = client_a
        .clip_push_meta(&eph_id.to_string(), &ck.to_string(), "text", true, &eph_env)
        .await
        .unwrap();
    assert!(eph_rec.delivered_to.unwrap_or(0) >= 1);

    let mut saw_ephemeral = false;
    for _ in 0..40 {
        if let Some((ClipboardPayload::Text(ref t), opts, _)) = clip_b.snapshot() {
            if t == "OTP-EPHEMERAL-778899" {
                assert!(opts.ephemeral && opts.sensitive && opts.synced_marker);
                saw_ephemeral = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    assert!(saw_ephemeral, "Desktop B must apply ephemeral clip immediately");
    // ZERO DB and ZERO clip_cache writes!
    assert_eq!(
        daemon_b
            .state
            .store
            .lock()
            .unwrap()
            .list_clip_items(100, None)
            .unwrap()
            .len(),
        count_b_before
    );
    assert_eq!(
        daemon_b.state.store.lock().unwrap().clip_cache().stats(),
        cache_b_before
    );
    // Auto-clear timer (~150ms) MUST clear clipboard because hash still matches!
    tokio::time::sleep(Duration::from_millis(260)).await;
    assert!(
        clip_b.snapshot().is_none(),
        "ephemeral clipboard must auto-clear after timer expires when untouched"
    );

    // Second ephemeral push: if user overwrites clipboard before timer fires, timer MUST NOT clear user text!
    let eph_id2 = store_a.next_clip_id(now_ms_test() as u64).unwrap();
    let eph_meta2 = ClipMetaV1 {
        v: 1,
        kind: ClipKind::Text,
        mime: "text/plain".to_string(),
        source_mode: ClipSourceMode::Explicit,
        created_at_ms: now_ms_test(),
        text: Some("OTP-SECOND-554433".to_string()),
        blob: None,
    };
    let eph_env2 = encrypt_mnc1_meta(
        ck,
        &ck_key,
        eph_id2,
        store_a.device_id(),
        &eph_meta2,
        true,
        [0x34; 24],
    )
    .unwrap();
    client_a
        .clip_push_meta(&eph_id2.to_string(), &ck.to_string(), "text", true, &eph_env2)
        .await
        .unwrap();
    for _ in 0..40 {
        if let Some((ClipboardPayload::Text(ref t), _, _)) = clip_b.snapshot() {
            if t == "OTP-SECOND-554433" {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    clip_b.set_user_text("user_overwrote_before_clear");
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        clip_b.snapshot().unwrap().0,
        ClipboardPayload::Text("user_overwrote_before_clear".to_string()),
        "ephemeral auto-clear must NEVER clobber user's newer clipboard item"
    );

    // --- Test `rotate_clip_key` -> `clip_cleared` broadcasts to Desktop B & refreshes ClipKey ---
    let (new_ck, new_gen) = rotate_clip_key(&mut store_a, &client_a).await.unwrap();
    assert_eq!(new_gen, 2);
    assert_ne!(new_ck, ck);

    let mut b_cleared_and_rotated = false;
    for _ in 0..50 {
        let done = {
            let store = daemon_b.state.store.lock().unwrap();
            let items = store.list_clip_items(100, None).unwrap();
            let key_gen = store.unwrap_local_clip_key().unwrap().map(|(_, _, g)| g);
            items.is_empty() && key_gen == Some(2)
        };
        if done {
            b_cleared_and_rotated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        b_cleared_and_rotated,
        "Desktop B must wipe local clip_items/cache and pick up rotated ClipKey gen=2 on clip_cleared"
    );

    daemon_b.shutdown();
    relay_srv.abort();
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

// ---------------------------------------------------------------------------
// Test 3: `mynote clip` CLI subcommands (`push`, `pull`, `history`, `promote`, `undo`, `rotate-key`)
//         and `device revoke` hint for `clip-write`
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_clip_subcommands_and_device_revoke_clip_write_hint() {
    let (relay_url, _relay_st, relay_srv) = spawn_mock_clip_relay("cli-secret").await;
    let dir = temp_dir("cli_clip");
    let mock_clip_file = dir.join("mock_clipboard.json");
    let png_path = dir.join("sample.png");
    let svg_path = dir.join("evil.svg");
    let out_png_path = dir.join("pulled.png");

    let png_bytes = sample_image_bytes(24, 24, ImageFormat::Png);
    std::fs::write(&png_path, &png_bytes).unwrap();
    std::fs::write(&svg_path, b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>").unwrap();

    let clip_write_dev_id;
    {
        let mut store = LocalStore::open(&dir).unwrap();
        RelayClient::bootstrap_device(&relay_url, "cli-secret", &store, "cli-host", false)
            .await
            .unwrap();
        let creds = store.load_credentials().unwrap().unwrap();
        let client = RelayClient::from_credentials(&creds).unwrap();
        let (ck, key, _) = ensure_clip_key(&mut store, &client).await.unwrap();
        let cw = client
            .create_pairing_ticket("shortcut-dev", "clip-write", vec![], Some((ck, key)))
            .await
            .unwrap();
        clip_write_dev_id = cw.device_id;
    }

    // Use a separate thread for sync `run_from` calls (which build a local current_thread tokio runtime).
    let dir_s = dir.to_string_lossy().to_string();
    let mock_s = mock_clip_file.to_string_lossy().to_string();
    let png_s = png_path.to_string_lossy().to_string();
    let svg_s = svg_path.to_string_lossy().to_string();
    let out_s = out_png_path.to_string_lossy().to_string();

    tokio::task::spawn_blocking(move || {
        std::env::set_var("MYNOTE_CLIPBOARD_MOCK_FILE", &mock_s);
        std::env::set_var("MYNOTE_NO_NOTIFY", "1");

        // 1. clip push --text
        assert_eq!(
            run_from([
                "mynote",
                "--data-dir",
                &dir_s,
                "--json",
                "clip",
                "push",
                "--text",
                "cli pushed text"
            ]),
            0
        );
        // 2. clip push --file <svg> -> exit 2 INVALID_ARGUMENT
        assert_eq!(
            run_from([
                "mynote",
                "--data-dir",
                &dir_s,
                "--json",
                "clip",
                "push",
                "--file",
                &svg_s
            ]),
            ErrorCode::InvalidArgument.exit_code()
        );
        // 3. clip push --ephemeral when 0 desktops online -> exit 6 NO_ONLINE_DESKTOP
        assert_eq!(
            run_from([
                "mynote",
                "--data-dir",
                &dir_s,
                "--json",
                "clip",
                "push",
                "--ephemeral",
                "--text",
                "ephemeral-no-desktop"
            ]),
            ErrorCode::NoOnlineDesktop.exit_code()
        );
        // 4. clip push --file <png> -> exit 0
        assert_eq!(
            run_from([
                "mynote",
                "--data-dir",
                &dir_s,
                "--json",
                "clip",
                "push",
                "--file",
                &png_s
            ]),
            0
        );
        // 5. clip history --kind image / text -> exit 0
        assert_eq!(
            run_from([
                "mynote",
                "--data-dir",
                &dir_s,
                "--json",
                "clip",
                "history",
                "--kind",
                "image"
            ]),
            0
        );
        // 6. clip pull --out <path> --apply -> writes exact PNG & updates mock clipboard!
        assert_eq!(
            run_from([
                "mynote",
                "--data-dir",
                &dir_s,
                "--json",
                "clip",
                "pull",
                "--out",
                &out_s,
                "--apply"
            ]),
            0
        );
        assert_eq!(std::fs::read(&out_s).unwrap(), png_bytes);
        assert!(PathBuf::from(&mock_s).is_file());

        // 7. clip promote on latest (image) -> exit 2 INVALID_ARGUMENT
        assert_eq!(
            run_from(["mynote", "--data-dir", &dir_s, "--json", "clip", "promote"]),
            ErrorCode::InvalidArgument.exit_code()
        );

        // Find the text clip_id and promote it -> exit 0 & block added!
        let text_id = {
            let store = LocalStore::open(PathBuf::from(&dir_s)).unwrap();
            store
                .list_clip_items(10, Some("text"))
                .unwrap()
                .first()
                .unwrap()
                .clip_id
                .clone()
        };
        assert_eq!(
            run_from([
                "mynote",
                "--data-dir",
                &dir_s,
                "--json",
                "clip",
                "promote",
                &text_id,
                "--buf",
                "scratch"
            ]),
            0
        );
        {
            let store = LocalStore::open(PathBuf::from(&dir_s)).unwrap();
            let blocks = store.list_blocks(Some("scratch"), 10).unwrap();
            assert_eq!(blocks.len(), 1);
            assert_eq!(
                store.get_block(&blocks[0].id).unwrap().content.as_deref(),
                Some("cli pushed text")
            );
        }

        // 8. clip rotate-key --non-interactive -> exit 2 INTERACTION_REQUIRED
        assert_eq!(
            run_from([
                "mynote",
                "--data-dir",
                &dir_s,
                "--non-interactive",
                "--json",
                "clip",
                "rotate-key"
            ]),
            ErrorCode::InteractionRequired.exit_code()
        );

        // 9. device revoke on clip-write device emits hint recommending `mynote clip rotate-key`
        let revoke_out = std::process::Command::new(env!("CARGO_BIN_EXE_mynote"))
            .args([
                "--data-dir",
                &dir_s,
                "--json",
                "device",
                "revoke",
                &clip_write_dev_id,
            ])
            .output()
            .expect("spawn mynote device revoke");
        assert!(revoke_out.status.success());
        let revoke_json: serde_json::Value =
            serde_json::from_slice(&revoke_out.stdout).expect("valid revoke JSON");
        assert_eq!(revoke_json["ok"], true);
        assert!(
            revoke_json["data"]["hint"]
                .as_str()
                .unwrap_or_default()
                .contains("mynote clip rotate-key"),
            "revoking clip-write device must suggest 'mynote clip rotate-key', got: {revoke_json}"
        );

        // 10. clip undo without daemon returns cleanly (exit 0)
        assert_eq!(
            run_from(["mynote", "--data-dir", &dir_s, "--json", "clip", "undo"]),
            0
        );

        std::env::remove_var("MYNOTE_CLIPBOARD_MOCK_FILE");
    })
    .await
    .unwrap();

    relay_srv.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
