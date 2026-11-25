//! Local desktop Daemon (`#8 [M1-7]`): axum HTTP/WS (`localhost:<port>`), `SEC-05` security
//! middleware, `rust-embed` Web UI assets, `0600` UDS NDJSON IPC, and Single-Flight cloud sync.

use crate::formatters::format_content;
use crate::sync_client::{hex_encode, run_cloud_ws_loop, RelayClient};
use crate::uds::{socket_path_for, ApplyMeta, ApplyRequest, UdsRequest, UdsResponse};
use axum::extract::ws::{Message as AxumWsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as AxumPath, Query, Request, State};
use axum::http::header::{CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, HOST, LOCATION, ORIGIN, SET_COOKIE};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use base64::Engine;
use fs2::FileExt;
use futures_util::{SinkExt, StreamExt};
use mynote_core::error::{CoreError, ErrorCode};
use mynote_core::ids::KeyId;
use mynote_core::model::{KeyMaterialKind, KeyRecordRow};
use mynote_core::sync::StoreMutation;
use mynote_store::LocalStore;
use rust_embed::RustEmbed;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, watch, Notify};

#[derive(RustEmbed)]
#[folder = "../../web/dist"]
struct EmbeddedWebAssets;

const SESSION_COOKIE_NAME: &str = "mynote_local_session";
const TICKET_TTL: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub data_dir: PathBuf,
    pub port: u16,
    pub enable_cloud_sync: bool,
}

pub struct DaemonState {
    pub store: Mutex<LocalStore>,
    pub port: u16,
    pub tickets: Mutex<HashMap<String, Instant>>,
    pub sessions: Mutex<HashSet<String>>,
    pub ws_tx: broadcast::Sender<String>,
    pub sync_lock: tokio::sync::Mutex<()>,
    pub sync_notify: Arc<Notify>,
    pub enable_cloud_sync: bool,
    pub version: &'static str,
}

impl DaemonState {
    pub fn issue_open_ticket(&self) -> Result<String, CoreError> {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw)
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, format!("CSPRNG failed: {e}"), "Retry"))?;
        let ticket = hex_encode(&raw);
        let mut guard = self.tickets.lock().unwrap();
        let now = Instant::now();
        guard.retain(|_, issued| now.duration_since(*issued) <= TICKET_TTL);
        guard.insert(ticket.clone(), now);
        Ok(format!(
            "http://localhost:{}/v1/local/auth/exchange?ticket={ticket}",
            self.port
        ))
    }

    pub fn exchange_ticket(&self, ticket: &str) -> Option<String> {
        let mut tguard = self.tickets.lock().unwrap();
        let issued = tguard.remove(ticket)?;
        if Instant::now().duration_since(issued) > TICKET_TTL {
            return None;
        }
        drop(tguard);
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).ok()?;
        let session = hex_encode(&raw);
        self.sessions.lock().unwrap().insert(session.clone());
        Some(session)
    }

    pub fn is_valid_session(&self, token: &str) -> bool {
        self.sessions.lock().unwrap().contains(token)
    }

    fn broadcast_json(&self, val: serde_json::Value) {
        let _ = self.ws_tx.send(val.to_string());
    }

    fn broadcast_block_upserted(&self, block_id: &str) {
        let dto = {
            let store = self.store.lock().unwrap();
            store.get_block(block_id).ok()
        };
        if let Some(b) = dto {
            self.broadcast_json(serde_json::json!({
                "type": "blocks_changed",
                "upserted": [b],
                "deleted_ids": []
            }));
        }
        self.broadcast_sync_and_trash();
    }

    fn broadcast_block_deleted(&self, block_id: &str) {
        self.broadcast_json(serde_json::json!({
            "type": "blocks_changed",
            "upserted": [],
            "deleted_ids": [block_id]
        }));
        self.broadcast_sync_and_trash();
    }

    fn broadcast_buffers_snapshot(&self, deleted_ids: Vec<String>) {
        let bufs = {
            let store = self.store.lock().unwrap();
            store.list_buffers().unwrap_or_default()
        };
        self.broadcast_json(serde_json::json!({
            "type": "buffers_changed",
            "upserted": bufs,
            "deleted_ids": deleted_ids
        }));
        self.broadcast_sync_and_trash();
    }

    fn broadcast_sync_and_trash(&self) {
        let status = {
            let store = self.store.lock().unwrap();
            store.sync_status().ok()
        };
        if let Some(st) = status {
            self.broadcast_json(serde_json::json!({
                "type": "trash_changed",
                "count": st.trash.count,
                "pending_confirm_count": st.trash.pending_confirm_count,
                "next_shred_ms": st.trash.next_shred_ms
            }));
            self.broadcast_json(serde_json::json!({
                "type": "sync_status",
                "state": st.sync_state,
                "last_seq": st.last_seq,
                "pending_ops": st.pending_ops
            }));
            if !st.key_self_check.ok {
                self.broadcast_json(serde_json::json!({
                    "type": "alert",
                    "code": "KEY_MISSING",
                    "details": { "blocks_missing_key": st.key_self_check.blocks_missing_key }
                }));
            }
            if st.clock_skew_ms.abs() > 300_000 {
                self.broadcast_json(serde_json::json!({
                    "type": "alert",
                    "code": "CLOCK_SKEW",
                    "details": { "clock_skew_ms": st.clock_skew_ms }
                }));
            }
            if st.recovery_drill_due {
                self.broadcast_json(serde_json::json!({
                    "type": "alert",
                    "code": "RECOVERY_DRILL_DUE",
                    "details": {}
                }));
            }
        }
    }

    /// Execute Single-Flight cloud sync round against configured relay and push live UI frames.
    pub async fn run_cloud_sync_now(&self) -> Result<(i64, String, usize), CoreError> {
        let _sf = self.sync_lock.lock().await;
        let creds = {
            let store = self.store.lock().unwrap();
            store.load_credentials()?
        };
        let Some(creds) = creds else {
            return Err(CoreError::new(
                ErrorCode::SyncOffline,
                "sync relay is not configured on this device",
                "Run 'mynote device bootstrap --url <https://...>' or 'mynote device claim'",
            ));
        };
        let read_only = creds.scope == "read";
        let client = RelayClient::from_credentials(&creds)?;
        self.broadcast_json(serde_json::json!({
            "type": "sync_status",
            "state": "syncing",
            "last_seq": 0
        }));

        // Run sync round on a short-locked store reference via a fresh handle or locked store:
        // Since LocalStore owns a non-Send rusqlite::Connection, hold it inside `spawn_blocking`?
        // Even better: `store` is behind `std::sync::Mutex<LocalStore>`, and we keep awaits outside the lock
        // by opening a scoped lock only during snapshot export & mutation apply inside `sync_round_locked`.
        let report = run_sync_round_with_mutex(&client, &self.store, read_only).await?;

        // Broadcast any remotely pulled changes immediately over `/v1/local/ws`
        if !report.apply_summary.upserted_buffer_ids.is_empty()
            || !report.apply_summary.deleted_buffer_ids.is_empty()
        {
            self.broadcast_buffers_snapshot(report.apply_summary.deleted_buffer_ids.clone());
        }
        if !report.apply_summary.upserted_block_ids.is_empty()
            || !report.apply_summary.deleted_block_ids.is_empty()
        {
            let upserted: Vec<_> = {
                let store = self.store.lock().unwrap();
                report
                    .apply_summary
                    .upserted_block_ids
                    .iter()
                    .filter_map(|id| store.get_block(id).ok())
                    .collect()
            };
            self.broadcast_json(serde_json::json!({
                "type": "blocks_changed",
                "upserted": upserted,
                "deleted_ids": report.apply_summary.deleted_block_ids
            }));
        }
        self.broadcast_sync_and_trash();

        let (head_seq, sync_state, pending) = {
            let store = self.store.lock().unwrap();
            let st = store.sync_status()?;
            (st.last_seq.max(report.head_seq), st.sync_state, st.pending_ops)
        };
        Ok((head_seq, sync_state, pending))
    }
}

/// Runs `RelayClient::run_sync_round` without holding the `std::sync::Mutex<LocalStore>` across `.await` points!
async fn run_sync_round_with_mutex(
    client: &RelayClient,
    store_mutex: &Mutex<LocalStore>,
    read_only: bool,
) -> Result<crate::sync_client::SyncRoundReport, CoreError> {
    use mynote_core::sync::{step, SyncCommand, SyncEvent};
    let mut report = crate::sync_client::SyncRoundReport::default();

    let mut queue: Vec<SyncCommand> = {
        let mut store = store_mutex.lock().unwrap();
        let snap = store.export_engine_snapshot()?;
        let (muts, cmds) = step(&snap, SyncEvent::StartSync)?;
        let summary = store.apply_store_mutations(&muts)?;
        report.apply_summary = summary;
        cmds
    };

    let mut steps = 0usize;
    while !queue.is_empty() && steps < 64 {
        steps += 1;
        let cmd = queue.remove(0);
        match cmd {
            SyncCommand::HttpPull { since_seq, limit } => {
                // Delegate HTTP pull via temporary LocalStore-free helper on RelayClient
                let (epoch, ops, keys_digest, head_seq, has_more) =
                    client.pull_page_for_daemon(since_seq, limit).await?;
                report.epoch = Some(epoch.to_string());
                report.head_seq = head_seq;
                report.pulled_ops += ops.len();
                let next_cmds = {
                    let mut store = store_mutex.lock().unwrap();
                    let snap = store.export_engine_snapshot()?;
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(1);
                    let (muts, cmds) = step(
                        &snap,
                        SyncEvent::PullResponse {
                            now_ms,
                            epoch,
                            ops,
                            keys_digest,
                            head_seq,
                            has_more,
                        },
                    )?;
                    let sum = store.apply_store_mutations(&muts)?;
                    merge_apply(&mut report.apply_summary, sum);
                    cmds
                };
                for c in next_cmds {
                    if matches!(c, SyncCommand::SyncKeyTable(_)) {
                        queue.insert(0, c);
                    } else {
                        queue.push(c);
                    }
                }
            }
            SyncCommand::SyncKeyTable(dto) => {
                let (records, marks, keyring, vault_header) = client.sync_key_table(&dto, read_only).await?;
                report.keys_synced = true;
                let next_cmds = {
                    let mut store = store_mutex.lock().unwrap();
                    let snap = store.export_engine_snapshot()?;
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(1);
                    let (muts, cmds) = step(
                        &snap,
                        SyncEvent::KeyTableResponse {
                            records,
                            marks,
                            keyring,
                            vault_header,
                            server_now_ms: now_ms,
                        },
                    )?;
                    let sum = store.apply_store_mutations(&muts)?;
                    merge_apply(&mut report.apply_summary, sum);
                    cmds
                };
                queue.extend(next_cmds);
            }
            SyncCommand::HttpPush(push_req) => {
                if read_only {
                    continue;
                }
                match client.push_batch_for_daemon(&push_req).await? {
                    Ok((epoch, acked, head_seq)) => {
                        report.epoch = Some(epoch.to_string());
                        report.head_seq = head_seq;
                        report.pushed_ops += acked.len();
                        let next_cmds = {
                            let mut store = store_mutex.lock().unwrap();
                            let snap = store.export_engine_snapshot()?;
                            let (muts, cmds) = step(
                                &snap,
                                SyncEvent::PushAcked {
                                    epoch,
                                    acked,
                                    head_seq,
                                },
                            )?;
                            let sum = store.apply_store_mutations(&muts)?;
                            merge_apply(&mut report.apply_summary, sum);
                            cmds
                        };
                        queue.extend(next_cmds);
                    }
                    Err(remote_epoch) => {
                        report.reconciled_epoch_change = true;
                        let next_cmds = {
                            let mut store = store_mutex.lock().unwrap();
                            let snap = store.export_engine_snapshot()?;
                            let (muts, cmds) = step(&snap, SyncEvent::PushEpochMismatch { remote_epoch })?;
                            let sum = store.apply_store_mutations(&muts)?;
                            merge_apply(&mut report.apply_summary, sum);
                            cmds
                        };
                        queue.clear();
                        queue.extend(next_cmds);
                    }
                }
            }
        }
    }
    Ok(report)
}

fn merge_apply(dst: &mut mynote_store::store::SyncApplySummary, src: mynote_store::store::SyncApplySummary) {
    dst.upserted_block_ids.extend(src.upserted_block_ids);
    dst.deleted_block_ids.extend(src.deleted_block_ids);
    dst.upserted_buffer_ids.extend(src.upserted_buffer_ids);
    dst.deleted_buffer_ids.extend(src.deleted_buffer_ids);
    dst.trash_changed |= src.trash_changed;
    if src.clock_skew_ms.is_some() {
        dst.clock_skew_ms = src.clock_skew_ms;
    }
    dst.integrity_alerts.extend(src.integrity_alerts);
}

pub struct RunningDaemon {
    pub port: u16,
    pub state: Arc<DaemonState>,
    shutdown_tx: watch::Sender<bool>,
    _lock_file: File,
    sock_path: PathBuf,
}

impl RunningDaemon {
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = std::fs::remove_file(&self.sock_path);
    }
}

/// Acquire single-instance exclusive lock, bind loopback HTTP/WS (`127.0.0.1` + `[::1]`) & `0600` UDS.
pub async fn start_daemon(cfg: DaemonConfig) -> Result<RunningDaemon, CoreError> {
    std::fs::create_dir_all(&cfg.data_dir).map_err(|e| {
        CoreError::new(
            ErrorCode::InvalidArgument,
            format!("cannot create data dir '{}': {e}", cfg.data_dir.display()),
            "Check directory permissions",
        )
    })?;
    let lock_path = cfg.data_dir.join("daemon.lock");
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("cannot open daemon lock '{}': {e}", lock_path.display()),
                "Check permissions",
            )
        })?;
    lock_file.try_lock_exclusive().map_err(|_| {
        CoreError::new(
            ErrorCode::InvalidArgument,
            format!(
                "another mynote daemon instance is already running for '{}'",
                cfg.data_dir.display()
            ),
            "Use 'mynote open' to connect to the running daemon",
        )
    })?;

    let store = LocalStore::open(&cfg.data_dir)?;

    // Bind IPv4 loopback first (resolves actual port if cfg.port == 0), then also IPv6 loopback if available.
    let v4_listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), cfg.port))
        .await
        .map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("cannot bind 127.0.0.1:{}: {e}", cfg.port),
                "Pick another --port or stop the conflicting process",
            )
        })?;
    let actual_port = v4_listener
        .local_addr()
        .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "local_addr"))?
        .port();
    let v6_listener = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), actual_port))
        .await
        .ok();

    let (ws_tx, _) = broadcast::channel::<String>(256);
    let sync_notify = Arc::new(Notify::new());
    let state = Arc::new(DaemonState {
        store: Mutex::new(store),
        port: actual_port,
        tickets: Mutex::new(HashMap::new()),
        sessions: Mutex::new(HashSet::new()),
        ws_tx,
        sync_lock: tokio::sync::Mutex::new(()),
        sync_notify: sync_notify.clone(),
        enable_cloud_sync: cfg.enable_cloud_sync,
        version: env!("CARGO_PKG_VERSION"),
    });

    let app = build_router(state.clone());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn IPv4 server
    {
        let app4 = app.clone();
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let _ = axum::serve(v4_listener, app4)
                .with_graceful_shutdown(async move {
                    let _ = rx.changed().await;
                })
                .await;
        });
    }
    // Spawn IPv6 server if available (so `localhost` resolving to `::1` works seamlessly)
    if let Some(v6) = v6_listener {
        let app6 = app.clone();
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let _ = axum::serve(v6, app6)
                .with_graceful_shutdown(async move {
                    let _ = rx.changed().await;
                })
                .await;
        });
    }

    // Bind `0600` Unix Domain Socket for CLI `apply` / `open_ticket` / `sync_now` / `ping`
    let sock_path = socket_path_for(&cfg.data_dir);
    #[cfg(unix)]
    {
        if let Some(parent) = sock_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::remove_file(&sock_path);
        let uds_listener = tokio::net::UnixListener::bind(&sock_path).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("cannot bind daemon.sock '{}': {e}", sock_path.display()),
                "Check directory permissions",
            )
        })?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600));
        }
        let uds_state = state.clone();
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    accepted = uds_listener.accept() => {
                        if let Ok((stream, _)) = accepted {
                            let st = uds_state.clone();
                            tokio::spawn(async move { handle_uds_client(st, stream).await; });
                        }
                    }
                }
            }
        });
    }

    // Spawn background Single-Flight cloud sync loop + Cloud WS Hibernation wakeup
    if cfg.enable_cloud_sync {
        let sync_state = state.clone();
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut poll = tokio::time::interval(Duration::from_secs(60));
            // Trigger initial sync immediately on startup
            let _ = sync_state.run_cloud_sync_now().await;
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    _ = sync_state.sync_notify.notified() => {
                        let _ = sync_state.run_cloud_sync_now().await;
                    }
                    _ = poll.tick() => {
                        let _ = sync_state.run_cloud_sync_now().await;
                    }
                }
            }
        });

        let maybe_creds = state.store.lock().unwrap().load_credentials().ok().flatten();
        if let Some(creds) = maybe_creds {
            let notify = sync_notify.clone();
            let mut rx = shutdown_rx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = rx.changed() => {}
                    _ = run_cloud_ws_loop(creds, move |_head_seq| {
                        notify.notify_one();
                    }) => {}
                }
            });
        }
    }

    // Consume unused mut warning on shutdown_rx
    let _ = shutdown_rx.borrow();

    Ok(RunningDaemon {
        port: actual_port,
        state,
        shutdown_tx,
        _lock_file: lock_file,
        sock_path,
    })
}

/// Run daemon in foreground until Ctrl+C / SIGTERM (`mynote daemon`).
pub async fn run_daemon_foreground(cfg: DaemonConfig) -> Result<(), CoreError> {
    let running = start_daemon(cfg).await?;
    eprintln!(
        "mynote daemon listening on http://localhost:{} (pid={})",
        running.port,
        std::process::id()
    );
    let _ = tokio::signal::ctrl_c().await;
    running.shutdown();
    Ok(())
}

fn build_router(state: Arc<DaemonState>) -> Router {
    Router::new()
        .route("/v1/local/auth/exchange", get(handle_auth_exchange))
        .route("/v1/local/bootstrap", get(handle_bootstrap))
        .route(
            "/v1/local/buffers",
            get(handle_list_buffers).post(handle_create_buffer),
        )
        .route(
            "/v1/local/buffers/{id}",
            patch(handle_patch_buffer).delete(handle_delete_buffer),
        )
        .route(
            "/v1/local/blocks",
            get(handle_list_blocks).post(handle_create_block),
        )
        .route(
            "/v1/local/blocks/{id}",
            get(handle_get_block)
                .patch(handle_patch_block)
                .delete(handle_delete_block),
        )
        .route("/v1/local/blocks/{id}/resolve", post(handle_resolve_block))
        .route("/v1/local/blocks/{id}/history", get(handle_block_history))
        .route("/v1/local/trash", get(handle_list_trash))
        .route("/v1/local/trash/{id}/restore", post(handle_restore_trash))
        .route("/v1/local/format", post(handle_format))
        .route("/v1/local/keys", get(handle_get_keys).post(handle_post_keys))
        .route("/v1/local/sync/status", get(handle_sync_status))
        .route("/v1/local/sync/now", post(handle_sync_now))
        .route("/v1/local/ws", get(handle_local_ws))
        .fallback(get(handle_static_asset))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            sec05_security_middleware,
        ))
        .with_state(state)
}

fn api_err_response(status: StatusCode, err: &CoreError) -> Response {
    let body = serde_json::json!({
        "ok": false,
        "data": null,
        "error": {
            "code": err.code().as_str(),
            "message": err.message(),
            "hint": err.hint(),
            "retryable": err.code().retryable(),
            "details": err.details(),
        }
    });
    (status, Json(body)).into_response()
}

fn core_err_to_response(err: CoreError) -> Response {
    let status = StatusCode::from_u16(err.code().http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    api_err_response(status, &err)
}

fn ok_json<T: serde::Serialize>(data: T) -> Response {
    Json(serde_json::json!({ "ok": true, "data": data, "error": null })).into_response()
}

fn extract_session_cookie(req: &Request) -> Option<String> {
    let raw = req.headers().get(COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let kv = part.trim();
        if let Some(val) = kv.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")) {
            return Some(val.trim().to_string());
        }
    }
    None
}

/// Strict `SEC-05` middleware (`docs/interface-contracts.md` §3.1, `docs/threat-model.md` §5.1):
/// 1. `Host` MUST equal `localhost:<port>` ONLY (rejects `127.0.0.1:<port>`, `[::1]:<port>`, DNS rebind).
/// 2. `Origin` MUST equal `http://localhost:<port>` on all non-GET HTTP requests AND `/v1/local/ws`.
/// 3. Session Cookie `mynote_local_session` MUST be valid on all `/v1/local/*` (except `/auth/exchange`) & WS.
async fn sec05_security_middleware(
    State(state): State<Arc<DaemonState>>,
    req: Request,
    next: Next,
) -> Response {
    let expected_host = format!("localhost:{}", state.port);
    let expected_origin = format!("http://localhost:{}", state.port);

    // 1. Strict Host whitelist (sole allowed value: `localhost:<port>`)
    let host_ok = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|h| h == expected_host);
    if !host_ok {
        let err = CoreError::new(
            ErrorCode::AuthRequired,
            format!("forbidden Host header; only '{expected_host}' is accepted"),
            format!("Open the UI via '{expected_origin}'"),
        );
        return api_err_response(StatusCode::FORBIDDEN, &err);
    }

    let path = req.uri().path().to_string();
    let is_ws = path == "/v1/local/ws";
    let is_exchange = path == "/v1/local/auth/exchange";
    let is_api = path.starts_with("/v1/local/");

    // 2. Strict Origin whitelist on non-GET HTTP methods and WebSocket handshake
    if req.method() != Method::GET || is_ws {
        let origin_ok = req
            .headers()
            .get(ORIGIN)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|o| o == expected_origin);
        if !origin_ok {
            let err = CoreError::new(
                ErrorCode::AuthRequired,
                format!("forbidden or missing Origin header; expected '{expected_origin}'"),
                format!("Access the API only from '{expected_origin}'"),
            );
            return api_err_response(StatusCode::FORBIDDEN, &err);
        }
    }

    // 3. HttpOnly SameSite=Strict session cookie on all `/v1/local/*` except `/v1/local/auth/exchange`
    if is_api && !is_exchange {
        let valid = extract_session_cookie(&req).is_some_and(|tok| state.is_valid_session(&tok));
        if !valid {
            let err = CoreError::new(
                ErrorCode::AuthRequired,
                "missing or invalid local session cookie",
                "Run 'mynote open' to obtain a fresh one-time login ticket",
            );
            return api_err_response(StatusCode::UNAUTHORIZED, &err);
        }
    }

    next.run(req).await
}

#[derive(Deserialize)]
struct ExchangeQuery {
    ticket: Option<String>,
}

async fn handle_auth_exchange(
    State(state): State<Arc<DaemonState>>,
    Query(q): Query<ExchangeQuery>,
) -> Response {
    let Some(ticket) = q.ticket.as_deref() else {
        return api_err_response(
            StatusCode::UNAUTHORIZED,
            &CoreError::new(
                ErrorCode::AuthRequired,
                "missing ticket parameter",
                "Run 'mynote open'",
            ),
        );
    };
    let Some(session_token) = state.exchange_ticket(ticket) else {
        return api_err_response(
            StatusCode::UNAUTHORIZED,
            &CoreError::new(
                ErrorCode::AuthRequired,
                "ticket invalid, expired, or already consumed",
                "Run 'mynote open' to generate a fresh one-time ticket",
            ),
        );
    };
    let cookie = format!("{SESSION_COOKIE_NAME}={session_token}; HttpOnly; SameSite=Strict; Path=/");
    let mut res = (StatusCode::SEE_OTHER, "").into_response();
    res.headers_mut().insert(LOCATION, HeaderValue::from_static("/"));
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        res.headers_mut().insert(SET_COOKIE, hv);
    }
    res
}

async fn handle_static_asset(State(state): State<Arc<DaemonState>>, req: Request) -> Response {
    let raw_path = req.uri().path().trim_start_matches('/');
    let asset_path = if raw_path.is_empty() {
        "index.html"
    } else {
        raw_path
    };
    let (resolved_path, file) = match EmbeddedWebAssets::get(asset_path) {
        Some(f) => (asset_path, Some(f)),
        None => ("index.html", EmbeddedWebAssets::get("index.html")),
    };
    let Some(content) = file else {
        return (StatusCode::NOT_FOUND, "Embedded Web UI assets not built").into_response();
    };
    let mime = mime_guess::from_path(resolved_path).first_or_octet_stream();
    let (body_bytes, style_src) = if resolved_path == "index.html" {
        let mut nonce_raw = [0u8; 16];
        let _ = getrandom::fill(&mut nonce_raw);
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_raw);
        let html = String::from_utf8_lossy(&content.data);
        let meta = format!("<meta name=\"csp-nonce\" content=\"{nonce}\" />");
        let injected = if html.contains("</head>") {
            html.replacen("</head>", &format!("    {meta}\n  </head>"), 1)
        } else {
            format!("{meta}{html}")
        };
        (injected.into_bytes(), format!("'self' 'nonce-{nonce}'"))
    } else {
        (content.data.into_owned(), "'self'".to_string())
    };
    let csp = format!(
        "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src {style_src}; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' ws://localhost:{}; frame-ancestors 'none'; base-uri 'none'; form-action 'none';",
        state.port
    );
    let mut res = (StatusCode::OK, body_bytes).into_response();
    if let Ok(hv) = HeaderValue::from_str(mime.as_ref()) {
        res.headers_mut().insert(CONTENT_TYPE, hv);
    }
    if let Ok(hv) = HeaderValue::from_str(&csp) {
        res.headers_mut().insert(CONTENT_SECURITY_POLICY, hv);
    }
    res
}

async fn handle_bootstrap(State(state): State<Arc<DaemonState>>) -> Response {
    let res = {
        let store = state.store.lock().unwrap();
        (|| -> Result<serde_json::Value, CoreError> {
            let buffers = store.list_buffers()?;
            let initial_buffer_id = buffers.first().map(|b| b.id.clone());
            let blocks = match &initial_buffer_id {
                Some(bid) => store.list_blocks_detailed(bid)?,
                None => Vec::new(),
            };
            let sync_status = store.sync_status()?;
            let trash_count = sync_status.trash.count;
            Ok(serde_json::json!({
                "buffers": buffers,
                "initial_buffer_id": initial_buffer_id,
                "blocks": blocks,
                "sync_status": sync_status,
                "vault_header": serde_json::Value::Null,
                "trash_count": trash_count,
                "device_id": store.device_id().as_str(),
                "last_hlc": store.last_hlc_string(),
            }))
        })()
    };
    match res {
        Ok(v) => ok_json(v),
        Err(e) => core_err_to_response(e),
    }
}

async fn handle_list_buffers(State(state): State<Arc<DaemonState>>) -> Response {
    let res = state.store.lock().unwrap().list_buffers();
    match res {
        Ok(v) => ok_json(v),
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct BufferWriteBody {
    name: Option<String>,
    after_id: Option<String>,
}

async fn handle_create_buffer(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<BufferWriteBody>,
) -> Response {
    let Some(name) = body.name.filter(|s| !s.trim().is_empty()) else {
        return core_err_to_response(CoreError::new(
            ErrorCode::InvalidArgument,
            "buffer name is required",
            "Pass non-empty name",
        ));
    };
    let res = state
        .store
        .lock()
        .unwrap()
        .create_buffer(&name, body.after_id.as_deref(), "human");
    match res {
        Ok(buf) => {
            state.broadcast_buffers_snapshot(Vec::new());
            state.sync_notify.notify_one();
            ok_json(buf)
        }
        Err(e) => core_err_to_response(e),
    }
}

async fn handle_patch_buffer(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<BufferWriteBody>,
) -> Response {
    let Some(name) = body.name.filter(|s| !s.trim().is_empty()) else {
        return core_err_to_response(CoreError::new(
            ErrorCode::InvalidArgument,
            "new buffer name is required",
            "Pass non-empty name",
        ));
    };
    let res = state.store.lock().unwrap().rename_buffer(&id, &name, "human");
    match res {
        Ok(buf) => {
            state.broadcast_buffers_snapshot(Vec::new());
            state.sync_notify.notify_one();
            ok_json(buf)
        }
        Err(e) => core_err_to_response(e),
    }
}

async fn handle_delete_buffer(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let res = state.store.lock().unwrap().delete_buffer(&id, "human");
    match res {
        Ok(buf) => {
            state.broadcast_buffers_snapshot(vec![buf.id.clone()]);
            state.sync_notify.notify_one();
            ok_json(buf)
        }
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct BlocksQuery {
    buffer_id: Option<String>,
}

async fn handle_list_blocks(State(state): State<Arc<DaemonState>>, Query(q): Query<BlocksQuery>) -> Response {
    let res = {
        let store = state.store.lock().unwrap();
        match q.buffer_id.as_deref() {
            Some(bid) => store.list_blocks_detailed(bid),
            None => {
                let bufs = store.list_buffers();
                match bufs {
                    Ok(list) if !list.is_empty() => store.list_blocks_detailed(&list[0].id),
                    Ok(_) => Ok(Vec::new()),
                    Err(e) => Err(e),
                }
            }
        }
    };
    match res {
        Ok(v) => ok_json(v),
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct CreateBlockBody {
    buffer_id: String,
    lang: Option<String>,
    content: String,
    after_id: Option<String>,
    #[serde(default)]
    fast_sync: bool,
}

async fn handle_create_block(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<CreateBlockBody>,
) -> Response {
    let res = {
        let mut store = state.store.lock().unwrap();
        let receipt = store.add_block(
            &body.buffer_id,
            &body.content,
            body.lang.as_deref(),
            body.after_id.as_deref(),
            "human",
            None,
        );
        receipt.and_then(|r| store.get_block(&r.block_id))
    };
    match res {
        Ok(blk) => {
            state.broadcast_block_upserted(&blk.id);
            if body.fast_sync || state.enable_cloud_sync {
                state.sync_notify.notify_one();
            }
            ok_json(blk)
        }
        Err(e) => core_err_to_response(e),
    }
}

async fn handle_get_block(State(state): State<Arc<DaemonState>>, AxumPath(id): AxumPath<String>) -> Response {
    let res = state.store.lock().unwrap().get_block(&id);
    match res {
        Ok(v) => ok_json(v),
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct PatchBlockBody {
    expected_heads: Option<Vec<String>>,
    content: Option<String>,
    lang: Option<String>,
    after_id: Option<String>,
    before_id: Option<String>,
    buffer_id: Option<String>,
    #[serde(default)]
    fast_sync: bool,
}

async fn handle_patch_block(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<PatchBlockBody>,
) -> Response {
    let res = {
        let mut store = state.store.lock().unwrap();
        let mut op_res: Result<(), CoreError> = Ok(());
        if let Some(content) = &body.content {
            let heads = match &body.expected_heads {
                Some(h) if !h.is_empty() => h,
                _ => {
                    return core_err_to_response(CoreError::new(
                        ErrorCode::InvalidArgument,
                        "expected_heads is required when updating block content",
                        "Pass all current head_op_ids in expected_heads",
                    ));
                }
            };
            op_res = store
                .update_block(&id, content, heads, false, "human")
                .map(|_| ());
        }
        if op_res.is_ok()
            && (body.lang.is_some()
                || body.after_id.is_some()
                || body.before_id.is_some()
                || body.buffer_id.is_some())
        {
            op_res = store
                .move_block(
                    &id,
                    body.buffer_id.as_deref(),
                    body.after_id.as_deref(),
                    body.before_id.as_deref(),
                    body.lang.as_deref(),
                    "human",
                )
                .map(|_| ());
        }
        op_res.and_then(|_| store.get_block(&id))
    };
    match res {
        Ok(blk) => {
            state.broadcast_block_upserted(&blk.id);
            if body.fast_sync || state.enable_cloud_sync {
                state.sync_notify.notify_one();
            }
            ok_json(blk)
        }
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct ResolveBlockBody {
    expected_heads: Vec<String>,
    content: Option<String>,
    keep_op_id: Option<String>,
}

async fn handle_resolve_block(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<ResolveBlockBody>,
) -> Response {
    let res = {
        let mut store = state.store.lock().unwrap();
        let write = if let Some(keep) = body.keep_op_id.as_deref() {
            store.resolve_block_keep(&id, &body.expected_heads, keep, "human")
        } else if let Some(content) = body.content.as_deref() {
            store.update_block(&id, content, &body.expected_heads, false, "human")
        } else {
            Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "provide either keep_op_id or content to resolve",
                "Pass keep_op_id or merged content",
            ))
        };
        write.and_then(|_| store.get_block(&id))
    };
    match res {
        Ok(blk) => {
            state.broadcast_block_upserted(&blk.id);
            state.sync_notify.notify_one();
            ok_json(blk)
        }
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct DeleteBlockBody {
    #[serde(default)]
    expected_heads: Vec<String>,
}

async fn handle_delete_block(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    body: Option<Json<DeleteBlockBody>>,
) -> Response {
    let expected = body.map(|b| b.0.expected_heads).unwrap_or_default();
    let exp_opt = if expected.is_empty() {
        None
    } else {
        Some(expected.as_slice())
    };
    let res = state.store.lock().unwrap().delete_block(&id, exp_opt, "human");
    match res {
        Ok(receipt) => {
            state.broadcast_block_deleted(&id);
            state.sync_notify.notify_one();
            ok_json(receipt)
        }
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct HistoryQuery {
    limit: Option<usize>,
}

async fn handle_block_history(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    let res = state
        .store
        .lock()
        .unwrap()
        .block_history(&id, q.limit.unwrap_or(50));
    match res {
        Ok(v) => ok_json(v),
        Err(e) => core_err_to_response(e),
    }
}

async fn handle_list_trash(State(state): State<Arc<DaemonState>>) -> Response {
    let res = state.store.lock().unwrap().list_trash();
    match res {
        Ok(v) => ok_json(v),
        Err(e) => core_err_to_response(e),
    }
}

async fn handle_restore_trash(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let res = {
        let mut store = state.store.lock().unwrap();
        store
            .restore_trash(&id, "human")
            .and_then(|r| store.get_block(&r.block_id))
    };
    match res {
        Ok(blk) => {
            state.broadcast_block_upserted(&blk.id);
            state.sync_notify.notify_one();
            ok_json(blk)
        }
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct FormatBody {
    content: String,
    lang: String,
    action: Option<String>,
}

async fn handle_format(Json(body): Json<FormatBody>) -> Response {
    match format_content(&body.content, &body.lang, body.action.as_deref()) {
        Ok(formatted) => ok_json(serde_json::json!({ "formatted": formatted })),
        Err(e) => core_err_to_response(e),
    }
}

async fn handle_get_keys(State(state): State<Arc<DaemonState>>) -> Response {
    let res = {
        let store = state.store.lock().unwrap();
        store.key_table_state().map(|kt| {
            let b64 = base64::engine::general_purpose::STANDARD;
            let records: Vec<serde_json::Value> = kt
                .records
                .values()
                .map(|r| {
                    serde_json::json!({
                        "key_id": r.key_id.to_string(),
                        "wrap_gen": r.wrap_gen,
                        "key_record_b64": r.key_record.as_ref().map(|b| b64.encode(b)),
                        "created_at_ms": r.created_at_ms,
                    })
                })
                .collect();
            serde_json::json!({
                "key_records": records,
                "shred_marks": [],
                "digest": kt.digest(),
            })
        })
    };
    match res {
        Ok(v) => ok_json(v),
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct PostKeysBody {
    #[serde(default)]
    key_records: Vec<KeyRecDto>,
    keyring: Option<KeyMatDto>,
}

#[derive(Deserialize)]
struct KeyRecDto {
    key_id: String,
    wrap_gen: u32,
    key_record_b64: String,
}

#[derive(Deserialize)]
struct KeyMatDto {
    gen: i64,
    blob_b64: String,
}

async fn handle_post_keys(State(state): State<Arc<DaemonState>>, Json(body): Json<PostKeysBody>) -> Response {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut muts = Vec::new();
    for rec in &body.key_records {
        let Ok(kid) = KeyId::parse(&rec.key_id) else {
            return core_err_to_response(CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid key_id '{}'", rec.key_id),
                "Provide 26-char ULID",
            ));
        };
        let Ok(bytes) = b64.decode(&rec.key_record_b64) else {
            return core_err_to_response(CoreError::new(
                ErrorCode::InvalidArgument,
                "invalid base64 key_record_b64",
                "Provide valid base64",
            ));
        };
        muts.push(StoreMutation::UpsertBlockKey(KeyRecordRow {
            key_id: kid,
            wrap_gen: rec.wrap_gen,
            key_record: Some(bytes),
            created_at_ms: 0,
        }));
    }
    if let Some(kr) = &body.keyring {
        if let Ok(bytes) = b64.decode(&kr.blob_b64) {
            muts.push(StoreMutation::UpsertKeyMaterial {
                kind: KeyMaterialKind::Keyring,
                gen: kr.gen,
                blob: bytes,
                updated_at_ms: 0,
            });
        }
    }
    let res = state.store.lock().unwrap().apply_store_mutations(&muts);
    match res {
        Ok(_) => {
            state.sync_notify.notify_one();
            ok_json(serde_json::json!({ "accepted": body.key_records.len() }))
        }
        Err(e) => core_err_to_response(e),
    }
}

async fn handle_sync_status(State(state): State<Arc<DaemonState>>) -> Response {
    let res = state.store.lock().unwrap().sync_status();
    match res {
        Ok(st) => ok_json(st),
        Err(e) => core_err_to_response(e),
    }
}

async fn handle_sync_now(State(state): State<Arc<DaemonState>>) -> Response {
    match state.run_cloud_sync_now().await {
        Ok(_) => {
            let st = state.store.lock().unwrap().sync_status();
            match st {
                Ok(s) => ok_json(s),
                Err(e) => core_err_to_response(e),
            }
        }
        Err(e) => core_err_to_response(e),
    }
}

async fn handle_local_ws(State(state): State<Arc<DaemonState>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| serve_local_ws(state, socket))
}

async fn serve_local_ws(state: Arc<DaemonState>, socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.ws_tx.subscribe();
    let send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(AxumWsMessage::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });
    while let Some(Ok(_)) = receiver.next().await {}
    send_task.abort();
}

#[cfg(unix)]
async fn handle_uds_client(state: Arc<DaemonState>, stream: tokio::net::UnixStream) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    while let Ok(n) = reader.read_line(&mut line).await {
        if n == 0 {
            break;
        }
        let resp = match serde_json::from_str::<UdsRequest>(line.trim()) {
            Ok(req) => dispatch_uds_request(&state, req).await,
            Err(e) => UdsResponse::from_core_error(&CoreError::new(
                ErrorCode::InvalidArgument,
                format!("malformed UDS request: {e}"),
                "Send valid NDJSON UdsRequest",
            )),
        };
        if let Ok(mut out) = serde_json::to_string(&resp) {
            out.push('\n');
            if write_half.write_all(out.as_bytes()).await.is_err() {
                break;
            }
            let _ = write_half.flush().await;
        }
        line.clear();
    }
}

async fn dispatch_uds_request(state: &Arc<DaemonState>, req: UdsRequest) -> UdsResponse {
    match req {
        UdsRequest::Ping => UdsResponse {
            ok: true,
            version: Some(state.version.to_string()),
            pid: Some(std::process::id()),
            port: Some(state.port),
            url: None,
            head_seq: None,
            sync_state: None,
            pending_ops: None,
            data: None,
            error: None,
        },
        UdsRequest::OpenTicket => match state.issue_open_ticket() {
            Ok(url) => UdsResponse {
                ok: true,
                version: None,
                pid: None,
                port: Some(state.port),
                url: Some(url),
                head_seq: None,
                sync_state: None,
                pending_ops: None,
                data: None,
                error: None,
            },
            Err(e) => UdsResponse::from_core_error(&e),
        },
        UdsRequest::Poke { fast_flush: _ } => {
            state.sync_notify.notify_one();
            UdsResponse {
                ok: true,
                version: None,
                pid: None,
                port: None,
                url: None,
                head_seq: None,
                sync_state: None,
                pending_ops: None,
                data: None,
                error: None,
            }
        }
        UdsRequest::SyncNow { wait } => {
            if !wait {
                state.sync_notify.notify_one();
                return UdsResponse {
                    ok: true,
                    version: None,
                    pid: None,
                    port: None,
                    url: None,
                    head_seq: None,
                    sync_state: Some("syncing".to_string()),
                    pending_ops: None,
                    data: None,
                    error: None,
                };
            }
            match state.run_cloud_sync_now().await {
                Ok((head_seq, sync_state, pending)) => UdsResponse {
                    ok: true,
                    version: None,
                    pid: None,
                    port: None,
                    url: None,
                    head_seq: Some(head_seq),
                    sync_state: Some(sync_state),
                    pending_ops: Some(pending),
                    data: None,
                    error: None,
                },
                Err(e) => UdsResponse::from_core_error(&e),
            }
        }
        UdsRequest::Apply { meta, request } => execute_uds_apply(state, meta, request),
    }
}

fn execute_uds_apply(state: &Arc<DaemonState>, meta: ApplyMeta, req: ApplyRequest) -> UdsResponse {
    let mut broadcast_block_up: Option<String> = None;
    let mut broadcast_block_del: Option<String> = None;
    let mut broadcast_bufs: Option<Vec<String>> = None;

    let result: Result<(serde_json::Value, String, usize), CoreError> = {
        let mut store = state.store.lock().unwrap();
        let data_res = match req {
            ApplyRequest::AddBlock {
                buffer,
                content,
                lang,
                after_id,
            } => store
                .add_block(
                    &buffer,
                    &content,
                    lang.as_deref(),
                    after_id.as_deref(),
                    &meta.actor,
                    meta.idempotency_key.as_deref(),
                )
                .and_then(|r| {
                    broadcast_block_up = Some(r.block_id.clone());
                    serde_json::to_value(r).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode receipt")
                    })
                }),
            ApplyRequest::UpdateBlock {
                id,
                content,
                expected_heads,
            } => store
                .update_block(&id, &content, &expected_heads, meta.force, &meta.actor)
                .and_then(|r| {
                    broadcast_block_up = Some(r.block_id.clone());
                    serde_json::to_value(r).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode receipt")
                    })
                }),
            ApplyRequest::AppendBlock {
                id,
                text,
                expected_heads,
            } => {
                let exp_opt = if expected_heads.is_empty() {
                    None
                } else {
                    Some(expected_heads.as_slice())
                };
                store
                    .append_block(&id, &text, exp_opt, &meta.actor)
                    .and_then(|r| {
                        broadcast_block_up = Some(r.block_id.clone());
                        serde_json::to_value(r).map_err(|e| {
                            CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode receipt")
                        })
                    })
            }
            ApplyRequest::MoveBlock {
                id,
                to_buf,
                after_id,
                before_id,
                lang,
            } => store
                .move_block(
                    &id,
                    to_buf.as_deref(),
                    after_id.as_deref(),
                    before_id.as_deref(),
                    lang.as_deref(),
                    &meta.actor,
                )
                .and_then(|r| {
                    broadcast_block_up = Some(r.block_id.clone());
                    serde_json::to_value(r).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode receipt")
                    })
                }),
            ApplyRequest::ResolveBlock {
                id,
                expected_heads,
                content,
                keep_op_id,
            } => {
                let wr = if let Some(keep) = keep_op_id.as_deref() {
                    store.resolve_block_keep(&id, &expected_heads, keep, &meta.actor)
                } else {
                    store.update_block(
                        &id,
                        content.as_deref().unwrap_or_default(),
                        &expected_heads,
                        meta.force,
                        &meta.actor,
                    )
                };
                wr.and_then(|r| {
                    broadcast_block_up = Some(r.block_id.clone());
                    serde_json::to_value(r).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode receipt")
                    })
                })
            }
            ApplyRequest::RevertBlock {
                id,
                to_op,
                undo_actor,
            } => {
                let target_op = if let Some(op_s) = to_op {
                    Ok(op_s)
                } else if let Some(uactor) = undo_actor {
                    store.block_history(&id, 500).and_then(|hist| {
                        hist.into_iter()
                            .find(|h| h.actor != uactor && h.content_available)
                            .map(|h| h.op_id)
                            .ok_or_else(|| {
                                CoreError::new(
                                    ErrorCode::NotFound,
                                    format!("no prior version authored by someone other than '{uactor}'"),
                                    "Inspect 'mynote block history <id> --json'",
                                )
                            })
                    })
                } else {
                    Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        "provide either --to-op or --undo-actor",
                        "Run 'mynote block revert --help'",
                    ))
                };
                target_op
                    .and_then(|op_s| store.revert_block(&id, &op_s, &meta.actor))
                    .and_then(|r| {
                        broadcast_block_up = Some(r.block_id.clone());
                        serde_json::to_value(r).map_err(|e| {
                            CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode receipt")
                        })
                    })
            }
            ApplyRequest::DeleteBlock {
                id,
                expected_heads,
                dry_run,
            } => {
                let exp_opt = if expected_heads.is_empty() {
                    None
                } else {
                    Some(expected_heads.as_slice())
                };
                if dry_run {
                    store.get_block(&id).map(|b| {
                        serde_json::json!({
                            "dry_run": true,
                            "block_id": b.id,
                            "buffer_id": b.buffer_id,
                            "in_trash": true,
                            "shred_state": "unscheduled",
                            "shred_not_before_ms": serde_json::Value::Null
                        })
                    })
                } else {
                    store.delete_block(&id, exp_opt, &meta.actor).and_then(|r| {
                        broadcast_block_del = Some(id.clone());
                        serde_json::to_value(r).map_err(|e| {
                            CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode receipt")
                        })
                    })
                }
            }
            ApplyRequest::CreateBuffer { name, after } => store
                .create_buffer(&name, after.as_deref(), &meta.actor)
                .and_then(|b| {
                    broadcast_bufs = Some(Vec::new());
                    serde_json::to_value(b)
                        .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode buf"))
                }),
            ApplyRequest::RenameBuffer { buf, new_name } => {
                store.rename_buffer(&buf, &new_name, &meta.actor).and_then(|b| {
                    broadcast_bufs = Some(Vec::new());
                    serde_json::to_value(b)
                        .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode buf"))
                })
            }
            ApplyRequest::DeleteBuffer { buf } => store.delete_buffer(&buf, &meta.actor).and_then(|b| {
                broadcast_bufs = Some(vec![b.id.clone()]);
                serde_json::to_value(b)
                    .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode buf"))
            }),
            ApplyRequest::RestoreTrash { id } => store.restore_trash(&id, &meta.actor).and_then(|r| {
                broadcast_block_up = Some(r.block_id.clone());
                serde_json::to_value(r)
                    .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode receipt"))
            }),
            ApplyRequest::ImportHeynote { path, buf, dry_run } => store
                .import_heynote(Path::new(&path), buf.as_deref(), dry_run, &meta.actor)
                .and_then(|s| {
                    if !dry_run {
                        broadcast_bufs = Some(Vec::new());
                    }
                    serde_json::to_value(s).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode import")
                    })
                }),
        };
        data_res.map(|v| (v, store.sync_state_label().to_string(), store.pending_op_count()))
    };

    match result {
        Ok((data, sync_state, pending)) => {
            if let Some(id) = broadcast_block_up {
                state.broadcast_block_upserted(&id);
            }
            if let Some(id) = broadcast_block_del {
                state.broadcast_block_deleted(&id);
            }
            if let Some(dels) = broadcast_bufs {
                state.broadcast_buffers_snapshot(dels);
            }
            state.sync_notify.notify_one();
            UdsResponse {
                ok: true,
                version: Some(state.version.to_string()),
                pid: None,
                port: None,
                url: None,
                head_seq: None,
                sync_state: Some(sync_state),
                pending_ops: Some(pending),
                data: Some(data),
                error: None,
            }
        }
        Err(e) => UdsResponse::from_core_error(&e),
    }
}
