//! Local desktop Daemon (`#8 [M1-7]`): axum HTTP/WS (`localhost:<port>`), `SEC-05` security
//! middleware, `rust-embed` Web UI assets, `0600` UDS NDJSON IPC, and Single-Flight cloud sync.

use crate::clip_watch::{load_persisted_watch_config, spawn_clip_watch_supervisor, ClipWatchFilter};
use crate::clipboard::{default_system_clipboard, EchoGuard, SystemClipboard, UndoClipboardSlot};
use crate::formatters::format_content;
use crate::local_ipc::{socket_path_for, ApplyMeta, ApplyRequest, LocalIpcRequest, LocalIpcResponse};
use crate::sync_client::{hex_encode, run_cloud_ws_loop, PushOutcome, RelayClient};
use axum::extract::ws::{Message as AxumWsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, HOST, LOCATION, ORIGIN, REFERRER_POLICY,
    SET_COOKIE, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};

#[path = "daemon_clip.rs"]
mod daemon_clip;
use base64::Engine;
pub use daemon_clip::{
    clip_blob_cache_name, clip_row_to_dto, truncate_clip_preview, ClipItemDto, ClipWatchConfig,
};
use fs2::FileExt;
use futures_util::{SinkExt, StreamExt};
use mynote_core::error::{CoreError, ErrorCode};
use mynote_core::ids::KeyId;
use mynote_core::model::{KeyMaterialKind, KeyRecordRow, ShredMarkRow, ShredMarkState};
use mynote_core::sync::StoreMutation;
use mynote_core::vault::{T_GRACE_DEFAULT_MS, T_GRACE_MIN_MS};
use mynote_store::{LocalStore, Tier2OpInput};
use rust_embed::RustEmbed;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, watch, Notify};

#[derive(RustEmbed)]
#[folder = "../../web/dist"]
struct EmbeddedWebAssets;

const SESSION_COOKIE_NAME: &str = "mynote_local_session";
const TICKET_TTL: Duration = Duration::from_secs(10);
const TRASH_CONFIRM_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct PendingTrashAction {
    pub action: String,
    pub block_ids: Vec<String>,
    pub key_ids: Vec<KeyId>,
    pub grace_ms: i64,
    pub seen_seq: i64,
    pub session_token: String,
    pub created_at: Instant,
}

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
    pub trash_confirm_nonces: Mutex<HashMap<String, PendingTrashAction>>,
    pub ws_tx: broadcast::Sender<String>,
    pub sync_lock: tokio::sync::Mutex<()>,
    pub clip_sync_lock: tokio::sync::Mutex<()>,
    pub clip_prefetch_lock: tokio::sync::Mutex<()>,
    pub cloud_clip_quota: Mutex<Option<crate::sync_client::CloudClipQuota>>,
    pub sync_notify: Arc<Notify>,
    pub creds_tx: watch::Sender<Option<mynote_store::DeviceCredentials>>,
    pub enable_cloud_sync: bool,
    pub version: &'static str,
    pub clipboard: Arc<dyn SystemClipboard>,
    pub clip_undo: Mutex<UndoClipboardSlot>,
    pub clip_echo: Mutex<EchoGuard>,
    pub clip_watch_state: Mutex<ClipWatchConfig>,
    pub clip_watch_tx: watch::Sender<ClipWatchConfig>,
    pub clip_watch_filter: Mutex<ClipWatchFilter>,
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

    pub fn issue_trash_confirm_nonce(&self, pending: PendingTrashAction) -> Result<String, CoreError> {
        let mut raw = [0u8; 24];
        getrandom::fill(&mut raw)
            .map_err(|e| CoreError::new(ErrorCode::IntegrityError, format!("CSPRNG failed: {e}"), "Retry"))?;
        let nonce = hex_encode(&raw);
        let mut guard = self.trash_confirm_nonces.lock().unwrap();
        let now = Instant::now();
        guard.retain(|_, item| now.duration_since(item.created_at) <= TRASH_CONFIRM_TTL);
        guard.insert(nonce.clone(), pending);
        Ok(nonce)
    }

    pub fn consume_trash_confirm_nonce(
        &self,
        nonce: &str,
        session_token: &str,
    ) -> Option<PendingTrashAction> {
        let mut guard = self.trash_confirm_nonces.lock().unwrap();
        let now = Instant::now();
        guard.retain(|_, item| now.duration_since(item.created_at) <= TRASH_CONFIRM_TTL);
        let matches_session = guard.get(nonce).is_some_and(|item| {
            let a = item.session_token.as_bytes();
            let b = session_token.as_bytes();
            a.len() == b.len() && a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
        });
        if !matches_session {
            return None;
        }
        guard.remove(nonce)
    }

    fn broadcast_json(&self, val: serde_json::Value) {
        let _ = self.ws_tx.send(val.to_string());
    }

    fn broadcast_block_upserted(&self, block_id: &str) {
        let dto = {
            let store = self.store.lock().unwrap();
            store.get_block_for_daemon(block_id).ok()
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
        let (status, blocked_count) = {
            let store = self.store.lock().unwrap();
            (
                store.sync_status().ok(),
                store.list_blocked_tier2_ops().map(|v| v.len()).unwrap_or(0),
            )
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
            if st.trash.pending_confirm_count > 0 {
                self.broadcast_json(serde_json::json!({
                    "type": "alert",
                    "code": "SHRED_PENDING_CONFIRM",
                    "details": { "pending_confirm_count": st.trash.pending_confirm_count }
                }));
            }
            if blocked_count > 0 {
                self.broadcast_json(serde_json::json!({
                    "type": "alert",
                    "code": "NEEDS_VAULT_REKEY",
                    "details": { "blocked_count": blocked_count }
                }));
            }
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
        let (creds, cur_last_seq, cur_pending) = {
            let store = self.store.lock().unwrap();
            let c = store.load_credentials()?;
            let last_seq = store
                .get_local_meta("last_seq")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            let pending = store.pending_op_count();
            (c, last_seq, pending)
        };
        let Some(creds) = creds else {
            return Err(CoreError::new(
                ErrorCode::SyncOffline,
                "sync relay is not configured on this device",
                "Run 'mynote device bootstrap --url <https://...>' or 'mynote device claim'",
            ));
        };
        let read_only = creds.scope != "read-write";
        let client = RelayClient::from_credentials(&creds)?;
        self.broadcast_json(serde_json::json!({
            "type": "sync_status",
            "state": "syncing",
            "last_seq": cur_last_seq,
            "pending_ops": cur_pending
        }));

        // Keep awaits outside the std::sync::Mutex<LocalStore> lock; always clear "syncing" on error!
        let report = match run_sync_round_with_mutex(&client, &self.store, read_only).await {
            Ok(r) => r,
            Err(e) => {
                if e.code() == ErrorCode::DeviceRevoked {
                    self.broadcast_json(serde_json::json!({
                        "type": "alert",
                        "code": "DEVICE_REVOKED",
                        "details": { "message": e.message() }
                    }));
                }
                self.broadcast_sync_and_trash();
                return Err(e);
            }
        };

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
                    .filter_map(|id| store.get_block_for_daemon(id).ok())
                    .collect()
            };
            self.broadcast_json(serde_json::json!({
                "type": "blocks_changed",
                "upserted": upserted,
                "deleted_ids": report.apply_summary.deleted_block_ids
            }));
        }
        if report.apply_summary.vault_header_changed {
            let vh = {
                let store = self.store.lock().unwrap();
                store.get_vault_header().ok().flatten()
            };
            if let Some(dto) = vh {
                self.broadcast_json(serde_json::json!({
                    "type": "vault_header_changed",
                    "vault_header": dto
                }));
            }
        }
        self.broadcast_sync_and_trash();

        // Cross-epoch PITR reconciliation (`docs/sync-protocol.md` §11.1 #2):
        // Reset local clip_last_id cursor and re-pull cloud clips without re-pushing old items.
        if report.reconciled_epoch_change {
            {
                let store = self.store.lock().unwrap();
                let _ = store.set_clip_cursor(None);
            }
            let _ = self.pull_cloud_clips(false).await;
        }

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
    const MAX_SYNC_STEPS: usize = 10_000;
    const MAX_STALLED_STEPS: usize = 8;

    let mut report = crate::sync_client::SyncRoundReport::default();
    let mut shred_acks = 0usize;

    let (mut queue, mut prev_progress) = {
        let mut store = store_mutex.lock().unwrap();
        let snap = store.export_engine_snapshot()?;
        let (muts, cmds) = step(&snap, SyncEvent::StartSync)?;
        let summary = store.apply_store_mutations(&muts)?;
        report.apply_summary = summary;
        let prog = (
            store.get_local_meta("last_seq"),
            store.get_local_meta("bootstrap_completed"),
            store.get_local_meta("reconciling_epoch"),
            report.pulled_ops,
            report.pushed_ops,
            report.keys_synced,
            shred_acks,
            report.apply_summary.rekeyed_tier1_ops,
        );
        (cmds, prog)
    };

    let mut steps = 0usize;
    let mut stalled_steps = 0usize;
    while !queue.is_empty() && steps < MAX_SYNC_STEPS {
        steps += 1;
        let cmd = queue.remove(0);
        match cmd {
            SyncCommand::HttpPull { since_seq, limit } => {
                let (epoch, ops, keys_digest, head_seq, has_more) =
                    client.pull_page_for_daemon(since_seq, limit).await?;
                report.epoch = Some(epoch.to_string());
                report.head_seq = head_seq;
                report.pulled_ops += ops.len();
                let (next_cmds, rekeyed_now) = {
                    let mut store = store_mutex.lock().unwrap();
                    let snap = store.export_engine_snapshot()?;
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
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
                    if muts
                        .iter()
                        .any(|m| matches!(m, StoreMutation::ClearServerSeqsForReconcile { .. }))
                    {
                        report.reconciled_epoch_change = true;
                    }
                    let sum = store.apply_store_mutations(&muts)?;
                    let rk = sum.rekeyed_tier1_ops;
                    merge_apply(&mut report.apply_summary, sum);
                    (cmds, rk)
                };
                for c in next_cmds {
                    if matches!(c, SyncCommand::SyncKeyTable(_)) {
                        queue.insert(0, c);
                    } else {
                        queue.push(c);
                    }
                }
                if rekeyed_now > 0
                    && !read_only
                    && !queue.iter().any(|c| matches!(c, SyncCommand::HttpPush(_)))
                {
                    let maybe_push = {
                        let store = store_mutex.lock().unwrap();
                        store.export_engine_snapshot().ok().and_then(|s| {
                            if s.bootstrap_completed && s.reconciling_epoch.is_none() {
                                s.build_pending_push()
                            } else {
                                None
                            }
                        })
                    };
                    if let Some(req) = maybe_push {
                        queue.push(SyncCommand::HttpPush(req));
                    }
                }
            }
            SyncCommand::SyncKeyTable(dto) => {
                let (records, marks, keyring, vault_header) = client.sync_key_table(&dto, read_only).await?;
                report.keys_synced = true;
                let (next_cmds, rekeyed_now) = {
                    let mut store = store_mutex.lock().unwrap();
                    let snap = store.export_engine_snapshot()?;
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
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
                    let rk = sum.rekeyed_tier1_ops;
                    merge_apply(&mut report.apply_summary, sum);
                    (cmds, rk)
                };
                queue.extend(next_cmds);
                if rekeyed_now > 0
                    && !read_only
                    && !queue.iter().any(|c| matches!(c, SyncCommand::HttpPush(_)))
                {
                    let maybe_push = {
                        let store = store_mutex.lock().unwrap();
                        store.export_engine_snapshot().ok().and_then(|s| {
                            if s.bootstrap_completed && s.reconciling_epoch.is_none() {
                                s.build_pending_push()
                            } else {
                                None
                            }
                        })
                    };
                    if let Some(req) = maybe_push {
                        queue.push(SyncCommand::HttpPush(req));
                    }
                }
            }
            SyncCommand::HttpPush(push_req) => {
                if read_only {
                    continue;
                }
                match client.push_batch_for_daemon(&push_req).await? {
                    PushOutcome::Acked {
                        epoch,
                        acked,
                        shred_results,
                        cancelled_keys,
                        head_seq,
                    } => {
                        report.epoch = Some(epoch.to_string());
                        report.head_seq = head_seq;
                        report.pushed_ops += acked.len();
                        shred_acks += shred_results.len() + cancelled_keys.len();
                        let next_cmds = {
                            let mut store = store_mutex.lock().unwrap();
                            let snap = store.export_engine_snapshot()?;
                            let (muts, cmds) = step(
                                &snap,
                                SyncEvent::PushAcked {
                                    epoch,
                                    acked,
                                    shred_results,
                                    cancelled_keys,
                                    head_seq,
                                },
                            )?;
                            let sum = store.apply_store_mutations(&muts)?;
                            merge_apply(&mut report.apply_summary, sum);
                            cmds
                        };
                        queue.extend(next_cmds);
                    }
                    PushOutcome::EpochMismatch(remote_epoch) => {
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
                    PushOutcome::KeyRace { code } => {
                        let next_cmds = {
                            let mut store = store_mutex.lock().unwrap();
                            let snap = store.export_engine_snapshot()?;
                            let (muts, cmds) =
                                step(&snap, SyncEvent::PushKeyRaceError { code, key_id: None })?;
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

        let cur_progress = {
            let store = store_mutex.lock().unwrap();
            (
                store.get_local_meta("last_seq"),
                store.get_local_meta("bootstrap_completed"),
                store.get_local_meta("reconciling_epoch"),
                report.pulled_ops,
                report.pushed_ops,
                report.keys_synced,
                shred_acks,
                report.apply_summary.rekeyed_tier1_ops,
            )
        };
        if cur_progress == prev_progress {
            stalled_steps += 1;
            if stalled_steps >= MAX_STALLED_STEPS && !queue.is_empty() {
                return Err(CoreError::new(
                    ErrorCode::SyncOffline,
                    "daemon sync round stopped making progress (stalled loop detected)",
                    "Inspect relay status and retry sync",
                ));
            }
        } else {
            stalled_steps = 0;
            prev_progress = cur_progress;
        }
    }

    if !queue.is_empty() {
        return Err(CoreError::new(
            ErrorCode::SyncOffline,
            "daemon sync round reached step safety limit before draining queue",
            "Trigger another sync round to continue",
        ));
    }

    // M2 post-sync tasks (without holding std::sync::Mutex across await!)
    if !read_only {
        let mig_req: Option<(i64, Vec<ShredMarkRow>)> = {
            let mut store = store_mutex.lock().unwrap();
            if store.get_local_meta("bootstrap_completed").as_deref() == Some("1") {
                match store.collect_m1_trashed_migration_marks() {
                    Ok((true, marks)) if marks.is_empty() => {
                        let _ = store.mark_m1_trash_migrated();
                        None
                    }
                    Ok((true, marks)) => {
                        let seen_seq = store
                            .get_local_meta("last_seq")
                            .and_then(|s| s.parse::<i64>().ok())
                            .unwrap_or(0);
                        Some((seen_seq, marks))
                    }
                    _ => None,
                }
            } else {
                None
            }
        };
        if let Some((seen_seq, marks)) = mig_req {
            if let Ok(results) = client.post_keys_shred(seen_seq, false, true, &marks).await {
                let mut store = store_mutex.lock().unwrap();
                let _ = store.apply_store_mutations(&[StoreMutation::MarkShredMarksAcked {
                    results,
                    cancelled_keys: Vec::new(),
                }]);
                let _ = store.mark_m1_trash_migrated();
            }
        }

        // Auto-publish mobile MNP1 state snapshot when due or immediately after ExecuteShred (H22)
        let force_snap = !report.apply_summary.executed_shreds.is_empty();
        let snap_to_put = {
            let mut store = store_mutex.lock().unwrap();
            let boot = store.get_local_meta("bootstrap_completed").as_deref() == Some("1");
            let reconciling = store.get_local_meta("reconciling_epoch").is_some();
            let cur_epoch = store.get_local_meta("journal_epoch");
            let last_seq = store
                .get_local_meta("last_seq")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            let same_epoch = cur_epoch.is_some() && store.get_local_meta("last_snapshot_epoch") == cur_epoch;
            let last_snap_seq = if same_epoch {
                store
                    .get_local_meta("last_snapshot_seq")
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(-1)
            } else {
                -1
            };
            let last_snap_at = if same_epoch {
                store
                    .get_local_meta("last_snapshot_at_ms")
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0)
            } else {
                0
            };
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(1);
            let due = boot
                && !reconciling
                && cur_epoch.is_some()
                && last_seq > 0
                && last_seq > last_snap_seq
                && (force_snap
                    || last_snap_seq < 0
                    || last_seq.saturating_sub(last_snap_seq) >= 1000
                    || now.saturating_sub(last_snap_at) >= 86_400_000);
            if due {
                store.build_state_snapshot().ok()
            } else {
                None
            }
        };
        if let Some((hdr, bytes)) = snap_to_put {
            let epoch_s = hdr.journal_epoch.to_string();
            match client
                .put_state_snapshot(&epoch_s, hdr.covers_seq, &hdr.snapshot_id.to_string(), &bytes)
                .await
            {
                Ok(_) => {
                    let store = store_mutex.lock().unwrap();
                    let _ = store.set_local_meta("last_snapshot_epoch", &epoch_s);
                    let _ = store.set_local_meta("last_snapshot_seq", &hdr.covers_seq.to_string());
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(1);
                    let _ = store.set_local_meta("last_snapshot_at_ms", &now.to_string());
                }
                Err(e) if e.code() == ErrorCode::CasMismatch => {
                    let is_epoch_mismatch = e
                        .details()
                        .and_then(|d| d.get("remote_epoch"))
                        .and_then(|v| v.as_str())
                        .is_some_and(|re| re != epoch_s);
                    if !is_epoch_mismatch {
                        let store = store_mutex.lock().unwrap();
                        let _ = store.set_local_meta("last_snapshot_epoch", &epoch_s);
                        let _ = store.set_local_meta("last_snapshot_seq", &hdr.covers_seq.to_string());
                    }
                }
                Err(_) => {}
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
    dst.executed_shreds.extend(src.executed_shreds);
    dst.needs_vault_rekey.extend(src.needs_vault_rekey);
    dst.pending_confirm_count += src.pending_confirm_count;
    dst.vault_header_changed |= src.vault_header_changed;
    dst.rekeyed_tier1_ops += src.rekeyed_tier1_ops;
}

pub struct RunningDaemon {
    pub port: u16,
    pub state: Arc<DaemonState>,
    shutdown_tx: watch::Sender<bool>,
    ipc_accept_task: tokio::task::JoinHandle<()>,
    _lock_file: File,
    sock_path: PathBuf,
}

impl RunningDaemon {
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        self.ipc_accept_task.abort();
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.sock_path);
        #[cfg(not(unix))]
        let _ = &self.sock_path;
    }
}

/// Acquire single-instance exclusive lock, bind loopback HTTP/WS (`127.0.0.1` + `[::1]`) & `0600` UDS.
pub async fn start_daemon(cfg: DaemonConfig) -> Result<RunningDaemon, CoreError> {
    start_daemon_with_clipboard(cfg, default_system_clipboard()).await
}

/// Same as `start_daemon`, injecting a custom `SystemClipboard` (used by hermetic integration tests).
pub async fn start_daemon_with_clipboard(
    cfg: DaemonConfig,
    clipboard: Arc<dyn SystemClipboard>,
) -> Result<RunningDaemon, CoreError> {
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
    let initial_creds = store.load_credentials().ok().flatten();
    let initial_watch_cfg = load_persisted_watch_config(&store);
    let (creds_tx, creds_rx) = watch::channel(initial_creds);
    let (clip_watch_tx, _) = watch::channel(initial_watch_cfg.clone());
    let state = Arc::new(DaemonState {
        store: Mutex::new(store),
        port: actual_port,
        tickets: Mutex::new(HashMap::new()),
        sessions: Mutex::new(HashSet::new()),
        trash_confirm_nonces: Mutex::new(HashMap::new()),
        ws_tx,
        sync_lock: tokio::sync::Mutex::new(()),
        clip_sync_lock: tokio::sync::Mutex::new(()),
        clip_prefetch_lock: tokio::sync::Mutex::new(()),
        cloud_clip_quota: Mutex::new(None),
        sync_notify: sync_notify.clone(),
        creds_tx,
        enable_cloud_sync: cfg.enable_cloud_sync,
        version: env!("CARGO_PKG_VERSION"),
        clipboard,
        clip_undo: Mutex::new(UndoClipboardSlot::default()),
        clip_echo: Mutex::new(EchoGuard::default()),
        clip_watch_state: Mutex::new(initial_watch_cfg),
        clip_watch_tx,
        clip_watch_filter: Mutex::new(ClipWatchFilter::new()),
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

    // Bind cross-platform `LocalIpc` (`0600` UDS on Unix / current-user SDDL Named Pipe on Windows)
    let sock_path = socket_path_for(&cfg.data_dir);
    #[cfg(unix)]
    let ipc_accept_task = {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if let Some(parent) = sock_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("cannot create socket dir '{}': {e}", parent.display()),
                    "Check directory permissions",
                )
            })?;
            let meta = std::fs::symlink_metadata(parent).map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("cannot stat socket dir '{}': {e}", parent.display()),
                    "Check directory permissions",
                )
            })?;
            if meta.file_type().is_symlink() || meta.uid() != crate::local_ipc::current_uid() {
                return Err(CoreError::new(
                    ErrorCode::IntegrityError,
                    format!(
                        "socket directory '{}' is not owned by current user or is a symlink",
                        parent.display()
                    ),
                    "Verify directory ownership and remove untrusted paths",
                ));
            }
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("cannot set 0700 on socket dir '{}': {e}", parent.display()),
                    "Check directory permissions",
                )
            })?;
        }
        let _ = std::fs::remove_file(&sock_path);
        let uds_listener = tokio::net::UnixListener::bind(&sock_path).map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("cannot bind daemon.sock '{}': {e}", sock_path.display()),
                "Check directory permissions",
            )
        })?;
        std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            let _ = std::fs::remove_file(&sock_path);
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("cannot set 0600 on daemon.sock '{}': {e}", sock_path.display()),
                "Check socket directory permissions",
            )
        })?;
        let ipc_state = state.clone();
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    accepted = uds_listener.accept() => {
                        if let Ok((stream, _)) = accepted {
                            let st = ipc_state.clone();
                            tokio::spawn(async move { handle_ipc_client(st, stream).await; });
                        }
                    }
                }
            }
        })
    };

    #[cfg(windows)]
    let ipc_accept_task = {
        let pipe_name = crate::local_ipc::pipe_name_for(&cfg.data_dir);
        let mut pipe_server =
            crate::local_ipc::create_hardened_pipe_server(&pipe_name, true).map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("cannot bind hardened Named Pipe '{pipe_name}': {e}"),
                    "Ensure another process is not squatting on the mynote Named Pipe",
                )
            })?;
        let ipc_state = state.clone();
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    connected = pipe_server.connect() => {
                        let next_server = match crate::local_ipc::create_hardened_pipe_server(&pipe_name, false) {
                            Ok(s) => s,
                            Err(_) => break,
                        };
                        let stream = std::mem::replace(&mut pipe_server, next_server);
                        if connected.is_ok() {
                            let st = ipc_state.clone();
                            tokio::spawn(async move { handle_ipc_client(st, stream).await; });
                        }
                    }
                }
            }
        })
    };

    #[cfg(not(any(unix, windows)))]
    let ipc_accept_task = tokio::spawn(async {});

    // Spawn background Single-Flight cloud sync loop + dynamic Cloud WS Hibernation wakeup watcher
    if cfg.enable_cloud_sync {
        let sync_state = state.clone();
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut poll = tokio::time::interval(Duration::from_secs(60));
            // Trigger initial note sync & non-intrusive clip pull on startup
            let _ = sync_state.run_cloud_sync_now().await;
            let _ = sync_state.pull_cloud_clips(false).await;
            sync_state.spawn_clip_blob_prefetch();
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    _ = sync_state.sync_notify.notified() => {
                        let _ = sync_state.run_cloud_sync_now().await;
                    }
                    _ = poll.tick() => {
                        let _ = sync_state.run_cloud_sync_now().await;
                        let _ = sync_state.pull_cloud_clips(false).await;
                        sync_state.spawn_clip_blob_prefetch();
                    }
                }
            }
        });

        let ws_state = state.clone();
        let mut rx = shutdown_rx.clone();
        let mut creds_watch = creds_rx;
        tokio::spawn(async move {
            let mut ws_task: Option<tokio::task::JoinHandle<()>> = None;
            loop {
                if let Some(handle) = ws_task.take() {
                    handle.abort();
                }
                let current_creds = creds_watch.borrow().clone();
                if let Some(creds) = current_creds {
                    let st = ws_state.clone();
                    ws_task = Some(tokio::spawn(async move {
                        run_cloud_ws_loop(creds, move |ev| {
                            st.handle_cloud_ws_event(ev);
                        })
                        .await;
                    }));
                }
                tokio::select! {
                    _ = rx.changed() => {
                        if let Some(handle) = ws_task.take() {
                            handle.abort();
                        }
                        break;
                    }
                    changed = creds_watch.changed() => {
                        if changed.is_err() {
                            if let Some(handle) = ws_task.take() {
                                handle.abort();
                            }
                            break;
                        }
                    }
                }
            }
        });
    }

    // Spawn M4b-1 opt-in background desktop clipboard watcher supervisor (strictly idle while watch_enabled=false)
    spawn_clip_watch_supervisor(state.clone(), shutdown_rx.clone());

    // Consume unused mut warning on shutdown_rx
    let _ = shutdown_rx.borrow();

    Ok(RunningDaemon {
        port: actual_port,
        state,
        shutdown_tx,
        ipc_accept_task,
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
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
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
        .route(
            "/v1/local/blocks/{id}/history/{op_id}",
            get(handle_block_history_op),
        )
        .route("/v1/local/blocks/{id}/revert", post(handle_revert_block))
        .route(
            "/v1/local/blocks/{id}/tier1-leaf/{op_id}",
            get(handle_get_tier1_leaf_plaintext),
        )
        .route("/v1/local/blocks/{id}/lock", post(handle_lock_block))
        .route("/v1/local/blocks/{id}/unlock", post(handle_unlock_block))
        .route(
            "/v1/local/blocks/{id}/purge-history",
            post(handle_purge_block_history),
        )
        .route("/v1/local/trash", get(handle_list_trash))
        .route("/v1/local/trash/{id}/restore", post(handle_restore_trash))
        .route("/v1/local/trash/{id}/tier2-blob", get(handle_trash_tier2_blob))
        .route(
            "/v1/local/trash/actions/prepare",
            post(handle_trash_actions_prepare),
        )
        .route(
            "/v1/local/trash/actions/commit",
            post(handle_trash_actions_commit),
        )
        .route(
            "/v1/local/vault/header",
            get(handle_get_vault_header).put(handle_put_vault_header),
        )
        .route("/v1/local/blocked-ops", get(handle_list_blocked_ops))
        .route(
            "/v1/local/blocked-ops/{op_id}/rekey",
            post(handle_rekey_blocked_op),
        )
        .route("/v1/local/format", post(handle_format))
        .route("/v1/local/keys", get(handle_get_keys).post(handle_post_keys))
        .route("/v1/local/sync/status", get(handle_sync_status))
        .route("/v1/local/sync/now", post(handle_sync_now))
        .route(
            "/v1/local/clip",
            get(daemon_clip::handle_list_clips)
                .post(daemon_clip::handle_post_clip)
                .delete(daemon_clip::handle_clear_clips)
                .layer(DefaultBodyLimit::max(20 * 1024 * 1024)),
        )
        .route("/v1/local/clip/undo", post(daemon_clip::handle_undo_clip))
        .route("/v1/local/clip/prune", post(daemon_clip::handle_prune_clips))
        .route(
            "/v1/local/clip/watch",
            patch(daemon_clip::handle_patch_clip_watch),
        )
        .route(
            "/v1/local/clip/{clip_id}",
            delete(daemon_clip::handle_delete_clip),
        )
        .route(
            "/v1/local/clip/{clip_id}/blob",
            get(daemon_clip::handle_get_clip_blob),
        )
        .route(
            "/v1/local/clip/{clip_id}/apply",
            post(daemon_clip::handle_apply_clip),
        )
        .route(
            "/v1/local/clip/{clip_id}/promote",
            post(daemon_clip::handle_promote_clip),
        )
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

fn extract_session_cookie_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let kv = part.trim();
        if let Some(val) = kv.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")) {
            return Some(val.trim().to_string());
        }
    }
    None
}

fn extract_session_cookie(req: &Request) -> Option<String> {
    extract_session_cookie_from_headers(req.headers())
}

/// Strict `SEC-05` middleware (`docs/interface-contracts.md` §3.1, `docs/threat-model.md` §5.1):
/// 1. `Host` MUST equal `localhost:<port>` ONLY (rejects `127.0.0.1:<port>`, `[::1]:<port>`, DNS rebind).
/// 2. `Origin` MUST equal `http://localhost:<port>` on all non-GET HTTP requests, `/v1/local/ws`, and any GET that sends `Origin`.
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

    // 2. Strict Origin whitelist on non-GET, WebSocket handshake, and any GET that carries an Origin header
    let origin_hdr = req.headers().get(ORIGIN);
    if req.method() != Method::GET || is_ws || origin_hdr.is_some() {
        let origin_ok = origin_hdr
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

    let mut res = next.run(req).await;
    if is_api {
        res.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res.headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    res.headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    res
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
        if let Err(e) = getrandom::fill(&mut nonce_raw) {
            return api_err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("OS CSPRNG failure generating CSP nonce: {e}"),
                    "Check OS entropy source",
                ),
            );
        }
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
    if resolved_path == "index.html" {
        res.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

fn decode_b64_arg(field: &str, raw: &str) -> Result<Vec<u8>, CoreError> {
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|e| {
            CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid base64 in '{field}': {e}"),
                "Provide valid standard base64",
            )
        })
}

async fn handle_bootstrap(State(state): State<Arc<DaemonState>>) -> Response {
    let res = {
        let store = state.store.lock().unwrap();
        (|| -> Result<serde_json::Value, CoreError> {
            let buffers = store.list_buffers()?;
            let initial_buffer_id = buffers.first().map(|b| b.id.clone());
            let blocks = match &initial_buffer_id {
                Some(bid) => store.list_blocks_for_daemon(bid)?,
                None => Vec::new(),
            };
            let sync_status = store.sync_status()?;
            let trash_count = sync_status.trash.count;
            let clip_count = store.count_all_clip_items().unwrap_or(0);
            let vault_header = store.get_vault_header()?;
            let recovery_pk_b64 = store
                .recovery_pk()
                .ok()
                .map(|pk| base64::engine::general_purpose::STANDARD.encode(pk));
            let blocked_tier2_ops = store.list_blocked_tier2_ops().unwrap_or_default();
            Ok(serde_json::json!({
                "buffers": buffers,
                "initial_buffer_id": initial_buffer_id,
                "blocks": blocks,
                "sync_status": sync_status,
                "vault_header": vault_header,
                "recovery_pk_b64": recovery_pk_b64,
                "blocked_tier2_ops": blocked_tier2_ops,
                "trash_count": trash_count,
                "clip_count": clip_count,
                "daemon_version": env!("CARGO_PKG_VERSION"),
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
            Some(bid) => store.list_blocks_for_daemon(bid),
            None => {
                let bufs = store.list_buffers();
                match bufs {
                    Ok(list) if !list.is_empty() => store.list_blocks_for_daemon(&list[0].id),
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
    content: Option<String>,
    after_id: Option<String>,
    // Tier 2 fields (produced by WasmVaultSession; Daemon NEVER sees plaintext or VKEK)
    block_id: Option<String>,
    op_id: Option<String>,
    key_id: Option<String>,
    mnb1_b64: Option<String>,
    mnw1_b64: Option<String>,
    public_hint: Option<String>,
    #[serde(default)]
    fast_sync: bool,
}

async fn handle_create_block(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<CreateBlockBody>,
) -> Response {
    let res = {
        let mut store = state.store.lock().unwrap();
        let receipt = if let Some(mnb1_b64) = body.mnb1_b64.as_deref() {
            (|| -> Result<mynote_store::WriteReceipt, CoreError> {
                let block_id = body.block_id.as_deref().ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::InvalidArgument,
                        "block_id is required for Tier 2 block creation",
                        "Use WasmVaultSession.encryptNewBlock",
                    )
                })?;
                let op_id = body.op_id.as_deref().ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::InvalidArgument,
                        "op_id is required for Tier 2 block creation",
                        "Use WasmVaultSession.encryptNewBlock",
                    )
                })?;
                let key_id = body.key_id.as_deref().ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::InvalidArgument,
                        "key_id is required for Tier 2 block creation",
                        "Use WasmVaultSession.encryptNewBlock",
                    )
                })?;
                let mnw1_b64 = body.mnw1_b64.as_deref().ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::InvalidArgument,
                        "mnw1_b64 is required for Tier 2 block creation",
                        "Use WasmVaultSession.encryptNewBlock",
                    )
                })?;
                let mnb1 = decode_b64_arg("mnb1_b64", mnb1_b64)?;
                let mnw1 = decode_b64_arg("mnw1_b64", mnw1_b64)?;
                store.add_tier2_block(
                    block_id,
                    Tier2OpInput {
                        op_id,
                        key_id,
                        mnb1: &mnb1,
                        mnw1: Some(&mnw1),
                    },
                    &body.buffer_id,
                    body.lang.as_deref().unwrap_or("text"),
                    body.after_id.as_deref(),
                    body.public_hint.as_deref(),
                    "human",
                )
            })()
        } else {
            let content = body.content.as_deref().unwrap_or("");
            store.add_block(
                &body.buffer_id,
                content,
                body.lang.as_deref(),
                body.after_id.as_deref(),
                "human",
                None,
            )
        };
        receipt.and_then(|r| store.get_block_for_daemon(&r.block_id))
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
    let res = state.store.lock().unwrap().get_block_for_daemon(&id);
    match res {
        Ok(v) => ok_json(v),
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct PatchBlockBody {
    expected_heads: Option<Vec<String>>,
    content: Option<String>,
    // Tier 2 fields (WasmVaultSession encrypted)
    op_id: Option<String>,
    key_id: Option<String>,
    mnb1_b64: Option<String>,
    mnw1_b64: Option<String>,
    public_hint: Option<String>,
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
        if let Some(mnb1_b64) = &body.mnb1_b64 {
            let heads = match &body.expected_heads {
                Some(h) if !h.is_empty() => h,
                _ => {
                    return core_err_to_response(CoreError::new(
                        ErrorCode::InvalidArgument,
                        "expected_heads is required when updating Tier 2 block content",
                        "Pass all current head_op_ids in expected_heads",
                    ));
                }
            };
            op_res = (|| -> Result<(), CoreError> {
                let op_id = body.op_id.as_deref().ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::InvalidArgument,
                        "op_id is required for Tier 2 update",
                        "Use WasmVaultSession.encryptUpdate",
                    )
                })?;
                let key_id = body.key_id.as_deref().ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::InvalidArgument,
                        "key_id is required for Tier 2 update",
                        "Use WasmVaultSession.encryptUpdate",
                    )
                })?;
                let mnb1 = decode_b64_arg("mnb1_b64", mnb1_b64)?;
                let mnw1 = body
                    .mnw1_b64
                    .as_deref()
                    .map(|s| decode_b64_arg("mnw1_b64", s))
                    .transpose()?;
                store
                    .update_tier2_block(
                        &id,
                        Tier2OpInput {
                            op_id,
                            key_id,
                            mnb1: &mnb1,
                            mnw1: mnw1.as_deref(),
                        },
                        heads,
                        body.lang.as_deref(),
                        body.public_hint.as_deref().map(Some),
                        "human",
                    )
                    .map(|_| ())
            })();
        } else if let Some(content) = &body.content {
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
            && body.mnb1_b64.is_none()
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
        op_res.and_then(|_| store.get_block_for_daemon(&id))
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
    // Tier 2 conflict merge fields
    op_id: Option<String>,
    key_id: Option<String>,
    mnb1_b64: Option<String>,
    mnw1_b64: Option<String>,
}

async fn handle_resolve_block(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<ResolveBlockBody>,
) -> Response {
    let res = {
        let mut store = state.store.lock().unwrap();
        let write = if let Some(mnb1_b64) = body.mnb1_b64.as_deref() {
            (|| -> Result<mynote_store::WriteReceipt, CoreError> {
                let op_id = body.op_id.as_deref().ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::InvalidArgument,
                        "op_id required for Tier 2 resolve",
                        "Retry",
                    )
                })?;
                let key_id = body.key_id.as_deref().ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::InvalidArgument,
                        "key_id required for Tier 2 resolve",
                        "Retry",
                    )
                })?;
                let mnb1 = decode_b64_arg("mnb1_b64", mnb1_b64)?;
                let mnw1 = body
                    .mnw1_b64
                    .as_deref()
                    .map(|s| decode_b64_arg("mnw1_b64", s))
                    .transpose()?;
                store.update_tier2_block(
                    &id,
                    Tier2OpInput {
                        op_id,
                        key_id,
                        mnb1: &mnb1,
                        mnw1: mnw1.as_deref(),
                    },
                    &body.expected_heads,
                    None,
                    None,
                    "human",
                )
            })()
        } else if let Some(keep) = body.keep_op_id.as_deref() {
            store.resolve_block_keep(&id, &body.expected_heads, keep, "human")
        } else if let Some(content) = body.content.as_deref() {
            store.update_block(&id, content, &body.expected_heads, false, "human")
        } else {
            Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "provide either keep_op_id, content, or Tier 2 mnb1_b64 to resolve",
                "Pass keep_op_id or merged content",
            ))
        };
        write.and_then(|_| store.get_block_for_daemon(&id))
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

async fn handle_get_tier1_leaf_plaintext(
    State(state): State<Arc<DaemonState>>,
    AxumPath((id, op_id)): AxumPath<(String, String)>,
) -> Response {
    let res = state.store.lock().unwrap().get_tier1_leaf_plaintext(&id, &op_id);
    match res {
        Ok(content) => ok_json(serde_json::json!({
            "block_id": id,
            "op_id": op_id,
            "content": content,
        })),
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct LockBlockBody {
    expected_heads: Vec<String>,
    op_id: String,
    key_id: String,
    mnb1_b64: String,
    mnw1_b64: String,
    public_hint: Option<String>,
}

async fn handle_lock_block(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<LockBlockBody>,
) -> Response {
    if body.expected_heads.is_empty() {
        return core_err_to_response(CoreError::new(
            ErrorCode::InvalidArgument,
            "expected_heads is required when locking a block",
            "Pass current head_op_ids",
        ));
    }
    let res = (|| -> Result<mynote_store::BlockDetailDto, CoreError> {
        let mnb1 = decode_b64_arg("mnb1_b64", &body.mnb1_b64)?;
        let mnw1 = decode_b64_arg("mnw1_b64", &body.mnw1_b64)?;
        let mut store = state.store.lock().unwrap();
        store.lock_block_tier2(
            &id,
            Tier2OpInput {
                op_id: &body.op_id,
                key_id: &body.key_id,
                mnb1: &mnb1,
                mnw1: Some(&mnw1),
            },
            &body.expected_heads,
            None,
            body.public_hint.as_deref(),
            T_GRACE_DEFAULT_MS,
            "human",
        )?;
        store.get_block_for_daemon(&id)
    })();
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
struct UnlockBlockBody {
    expected_heads: Vec<String>,
    content: String,
    lang: Option<String>,
    #[serde(default)]
    shred_old_key: bool,
}

async fn handle_unlock_block(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<UnlockBlockBody>,
) -> Response {
    if body.expected_heads.is_empty() {
        return core_err_to_response(CoreError::new(
            ErrorCode::InvalidArgument,
            "expected_heads is required when unlocking a block",
            "Pass current head_op_ids",
        ));
    }
    let res = {
        let mut store = state.store.lock().unwrap();
        store
            .unlock_block_tier1(
                &id,
                &body.expected_heads,
                &body.content,
                body.lang.as_deref(),
                body.shred_old_key,
                "human",
            )
            .and_then(|_| store.get_block_for_daemon(&id))
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
struct Tier2RekeyJson {
    op_id: String,
    key_id: String,
    mnb1_b64: String,
    mnw1_b64: Option<String>,
}

#[derive(Deserialize)]
struct PurgeHistoryBody {
    confirm_nonce: String,
    #[serde(default)]
    expected_heads: Option<Vec<String>>,
    tier2: Option<Tier2RekeyJson>,
}

async fn handle_purge_block_history(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<PurgeHistoryBody>,
) -> Response {
    let session = extract_session_cookie_from_headers(&headers).unwrap_or_default();
    let Some(pending) = state.consume_trash_confirm_nonce(&body.confirm_nonce, &session) else {
        return core_err_to_response(CoreError::new(
            ErrorCode::UiConfirmationRequired,
            "missing, expired, or already-used confirmation nonce",
            "Call POST /v1/local/trash/actions/prepare and confirm inside the desktop UI",
        ));
    };
    if pending.action != "purge_history" || !pending.block_ids.iter().any(|b| b == &id) {
        return core_err_to_response(CoreError::new(
            ErrorCode::UiConfirmationRequired,
            "confirmation nonce does not match purge_history for this block",
            "Re-open the confirmation modal in the desktop UI",
        ));
    }
    // Always enforce the grace_ms locked in at prepare time (H16: never allow commit override).
    let grace_ms = pending.grace_ms;
    let res = (|| -> Result<serde_json::Value, CoreError> {
        let t2_decoded = match &body.tier2 {
            Some(t) => Some((
                t.op_id.clone(),
                t.key_id.clone(),
                decode_b64_arg("mnb1_b64", &t.mnb1_b64)?,
                t.mnw1_b64
                    .as_deref()
                    .map(|s| decode_b64_arg("mnw1_b64", s))
                    .transpose()?,
            )),
            None => None,
        };
        let mut store = state.store.lock().unwrap();
        let t2_input = t2_decoded.as_ref().map(|(oid, kid, mnb1, mnw1)| Tier2OpInput {
            op_id: oid,
            key_id: kid,
            mnb1,
            mnw1: mnw1.as_deref(),
        });
        let (receipt, old_keys) =
            store.purge_block_history(&id, body.expected_heads.as_deref(), t2_input, grace_ms, "human")?;
        let blk = store.get_block_for_daemon(&id)?;
        Ok(serde_json::json!({
            "block": blk,
            "receipt": receipt,
            "scheduled_old_key_ids": old_keys.into_iter().map(|k| k.to_string()).collect::<Vec<_>>(),
        }))
    })();
    match res {
        Ok(val) => {
            state.broadcast_block_upserted(&id);
            state.sync_notify.notify_one();
            ok_json(val)
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

async fn handle_block_history_op(
    State(state): State<Arc<DaemonState>>,
    AxumPath((id, op_id)): AxumPath<(String, String)>,
) -> Response {
    let res = state
        .store
        .lock()
        .unwrap()
        .get_block_history_op_for_daemon(&id, &op_id);
    match res {
        Ok(dto) => ok_json(dto),
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct RevertBlockBody {
    to_op_id: Option<String>,
    undo_actor: Option<String>,
    expected_heads: Option<Vec<String>>,
    // Tier 2 WASM-encrypted revert fields (Daemon NEVER sees plaintext or VKEK)
    op_id: Option<String>,
    key_id: Option<String>,
    mnb1_b64: Option<String>,
    mnw1_b64: Option<String>,
}

async fn handle_revert_block(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<RevertBlockBody>,
) -> Response {
    let res = {
        let mut store = state.store.lock().unwrap();
        let write = if let Some(mnb1_b64) = body.mnb1_b64.as_deref() {
            (|| -> Result<mynote_store::WriteReceipt, CoreError> {
                let heads = match &body.expected_heads {
                    Some(h) if !h.is_empty() => h,
                    _ => {
                        return Err(CoreError::new(
                            ErrorCode::InvalidArgument,
                            "expected_heads is required for Tier 2 revert",
                            "Pass current head_op_ids in expected_heads",
                        ));
                    }
                };
                let detail = store.get_block(&id)?;
                if detail.has_conflict {
                    return Err(CoreError::new(
                        ErrorCode::ConflictPresent,
                        format!("block '{id}' has multiple leaves; merge before reverting"),
                        "Resolve concurrent versions before reverting",
                    ));
                }
                let op_id = body.op_id.as_deref().ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::InvalidArgument,
                        "op_id is required for Tier 2 revert",
                        "Encrypt reverted plaintext via WasmVaultSession.encryptUpdate",
                    )
                })?;
                let key_id = body.key_id.as_deref().ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::InvalidArgument,
                        "key_id is required for Tier 2 revert",
                        "Encrypt reverted plaintext via WasmVaultSession.encryptUpdate",
                    )
                })?;
                let mnb1 = decode_b64_arg("mnb1_b64", mnb1_b64)?;
                let mnw1 = body
                    .mnw1_b64
                    .as_deref()
                    .map(|s| decode_b64_arg("mnw1_b64", s))
                    .transpose()?;
                store.update_tier2_block(
                    &id,
                    Tier2OpInput {
                        op_id,
                        key_id,
                        mnb1: &mnb1,
                        mnw1: mnw1.as_deref(),
                    },
                    heads,
                    None,
                    None,
                    "human",
                )
            })()
        } else {
            (|| -> Result<mynote_store::WriteReceipt, CoreError> {
                let resolved =
                    store.resolve_revert_target(&id, body.to_op_id.as_deref(), body.undo_actor.as_deref())?;
                if let Some(exp) = body.expected_heads.as_deref() {
                    let exp_set: std::collections::BTreeSet<&String> = exp.iter().collect();
                    let act_set: std::collections::BTreeSet<&String> =
                        resolved.detail.head_op_ids.iter().collect();
                    if exp_set != act_set {
                        return Err(CoreError::new(
                            ErrorCode::HeadMismatch,
                            format!("block {id} heads changed concurrently"),
                            "Refresh block state and retry revert",
                        )
                        .with_details(serde_json::json!({
                            "expected_heads": exp,
                            "actual_heads": resolved.detail.head_op_ids,
                        })));
                    }
                }
                store.revert_block(&id, &resolved.target.op_id, "human")
            })()
        };
        write.and_then(|_| store.get_block_for_daemon(&id))
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

async fn handle_list_trash(State(state): State<Arc<DaemonState>>) -> Response {
    let res = state.store.lock().unwrap().list_trash();
    match res {
        Ok(v) => ok_json(v),
        Err(e) => core_err_to_response(e),
    }
}

async fn handle_trash_tier2_blob(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let res = state.store.lock().unwrap().trashed_tier2_blob(&id);
    match res {
        Ok(Some((op_id, key_id, mnb1_b64, mnw1_b64))) => ok_json(serde_json::json!({
            "op_id": op_id,
            "key_id": key_id,
            "mnb1_b64": mnb1_b64,
            "mnw1_b64": mnw1_b64,
        })),
        Ok(None) => core_err_to_response(CoreError::new(
            ErrorCode::NotFound,
            "no recoverable Tier 2 blob found for this trashed block",
            "Block may be Tier 1 or already shredded",
        )),
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct RestoreTrashBody {
    op_id: Option<String>,
    key_id: Option<String>,
    mnb1_b64: Option<String>,
    mnw1_b64: Option<String>,
}

async fn handle_restore_trash(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    body: Option<Json<RestoreTrashBody>>,
) -> Response {
    let res = {
        let mut store = state.store.lock().unwrap();
        let write = if let Some(Json(b)) = body {
            if let Some(mnb1_b64) = b.mnb1_b64.as_deref() {
                (|| -> Result<mynote_store::WriteReceipt, CoreError> {
                    let op_id = b.op_id.as_deref().ok_or_else(|| {
                        CoreError::new(
                            ErrorCode::InvalidArgument,
                            "op_id required for Tier 2 restore",
                            "Retry",
                        )
                    })?;
                    let key_id = b.key_id.as_deref().ok_or_else(|| {
                        CoreError::new(
                            ErrorCode::InvalidArgument,
                            "key_id required for Tier 2 restore",
                            "Retry",
                        )
                    })?;
                    let mnb1 = decode_b64_arg("mnb1_b64", mnb1_b64)?;
                    let mnw1 = b
                        .mnw1_b64
                        .as_deref()
                        .map(|s| decode_b64_arg("mnw1_b64", s))
                        .transpose()?;
                    store.restore_trash_tier2(
                        &id,
                        Tier2OpInput {
                            op_id,
                            key_id,
                            mnb1: &mnb1,
                            mnw1: mnw1.as_deref(),
                        },
                        "human",
                    )
                })()
            } else {
                store.restore_trash(&id, "human")
            }
        } else {
            store.restore_trash(&id, "human")
        };
        write.and_then(|r| store.get_block_for_daemon(&r.block_id))
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
struct TrashActionPrepareBody {
    action: String,
    block_ids: Option<Vec<String>>,
    grace_ms: Option<i64>,
}

async fn handle_trash_actions_prepare(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<TrashActionPrepareBody>,
) -> Response {
    if !matches!(
        body.action.as_str(),
        "expedite" | "confirm_pending" | "purge_history"
    ) {
        return core_err_to_response(CoreError::new(
            ErrorCode::InvalidArgument,
            format!("unsupported trash action '{}'", body.action),
            "Use 'expedite', 'confirm_pending', or 'purge_history'",
        ));
    }
    if body.action == "purge_history" && body.block_ids.as_ref().is_none_or(|ids| ids.len() != 1) {
        return core_err_to_response(CoreError::new(
            ErrorCode::InvalidArgument,
            "purge_history requires exactly one block_id",
            "Select a single block before purging its history",
        ));
    }
    let grace_ms = body.grace_ms.unwrap_or_else(|| {
        if body.action == "expedite" {
            T_GRACE_MIN_MS
        } else {
            T_GRACE_DEFAULT_MS
        }
    });
    if grace_ms < T_GRACE_MIN_MS {
        return core_err_to_response(CoreError::new(
            ErrorCode::GraceTooShort,
            format!("grace_ms {grace_ms} < minimum {T_GRACE_MIN_MS} (24h)"),
            "Server enforces a mandatory 24-hour minimum grace period",
        ));
    }
    let session_token = extract_session_cookie_from_headers(&headers).unwrap_or_default();
    let collected = {
        let store = state.store.lock().unwrap();
        let seen_seq = store
            .get_local_meta("last_seq")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        store
            .collect_trash_action_keys(&body.action, body.block_ids.as_deref())
            .map(|r| (r, seen_seq))
    };
    match collected {
        Ok(((blocks, key_ids, earliest_nb), seen_seq)) => {
            let block_count = blocks.len();
            let key_count = key_ids.len();
            match state.issue_trash_confirm_nonce(PendingTrashAction {
                action: body.action.clone(),
                block_ids: blocks,
                key_ids,
                grace_ms,
                seen_seq,
                session_token,
                created_at: Instant::now(),
            }) {
                Ok(nonce) => ok_json(serde_json::json!({
                    "confirm_nonce": nonce,
                    "expires_in_ms": TRASH_CONFIRM_TTL.as_millis() as i64,
                    "summary": {
                        "action": body.action,
                        "block_count": block_count,
                        "key_count": key_count,
                        "grace_ms": grace_ms,
                        "earliest_not_before_ms": earliest_nb,
                    }
                })),
                Err(e) => core_err_to_response(e),
            }
        }
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct TrashActionCommitBody {
    confirm_nonce: String,
    #[serde(default)]
    expected_heads: Option<Vec<String>>,
    tier2: Option<Tier2RekeyJson>,
}

async fn handle_trash_actions_commit(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<TrashActionCommitBody>,
) -> Response {
    let session = extract_session_cookie_from_headers(&headers).unwrap_or_default();
    let Some(pending) = state.consume_trash_confirm_nonce(&body.confirm_nonce, &session) else {
        return core_err_to_response(CoreError::new(
            ErrorCode::UiConfirmationRequired,
            "missing, expired, or already-used confirmation nonce",
            "Call POST /v1/local/trash/actions/prepare and confirm inside the desktop UI",
        ));
    };

    if pending.action == "purge_history" {
        if pending.block_ids.len() != 1 {
            return core_err_to_response(CoreError::new(
                ErrorCode::InvalidArgument,
                "purge_history requires exactly one target block_id",
                "Select a single block to purge history",
            ));
        }
        let blk_id = pending.block_ids[0].clone();
        let res = (|| -> Result<serde_json::Value, CoreError> {
            let t2_decoded = match &body.tier2 {
                Some(t) => Some((
                    t.op_id.clone(),
                    t.key_id.clone(),
                    decode_b64_arg("mnb1_b64", &t.mnb1_b64)?,
                    t.mnw1_b64
                        .as_deref()
                        .map(|s| decode_b64_arg("mnw1_b64", s))
                        .transpose()?,
                )),
                None => None,
            };
            let mut store = state.store.lock().unwrap();
            let t2_input = t2_decoded.as_ref().map(|(oid, kid, mnb1, mnw1)| Tier2OpInput {
                op_id: oid,
                key_id: kid,
                mnb1,
                mnw1: mnw1.as_deref(),
            });
            let (receipt, old_keys) = store.purge_block_history(
                &blk_id,
                body.expected_heads.as_deref(),
                t2_input,
                pending.grace_ms,
                "human",
            )?;
            Ok(serde_json::json!({
                "action": "purge_history",
                "receipt": receipt,
                "scheduled_old_key_ids": old_keys.into_iter().map(|k| k.to_string()).collect::<Vec<_>>(),
            }))
        })();
        return match res {
            Ok(v) => {
                state.broadcast_block_upserted(&blk_id);
                state.sync_notify.notify_one();
                ok_json(v)
            }
            Err(e) => core_err_to_response(e),
        };
    }

    // `expedite` and `confirm_pending` MUST pass key_self_check, re-validate eligibility at commit time,
    // and use `pending.seen_seq` captured at prepare time (`sync-protocol.md` §5.2, C8)!
    let commit_prep: Result<
        (
            Option<mynote_store::DeviceCredentials>,
            mynote_core::ids::DeviceId,
            Vec<KeyId>,
        ),
        CoreError,
    > = (|| {
        let store = state.store.lock().unwrap();
        let (self_ok, missing) = store.key_self_check()?;
        if !self_ok {
            return Err(CoreError::new(
                ErrorCode::KeyMissing,
                format!(
                    "key liveness self-check failed ({} missing/unhealthy key(s)); refusing shred action",
                    missing.len()
                ),
                "Resolve key integrity or sync keys before expediting/confirming shreds",
            ));
        }
        let (_, current_eligible, _) =
            store.collect_trash_action_keys(&pending.action, Some(&pending.block_ids))?;
        let current_set: HashSet<KeyId> = current_eligible.into_iter().collect();
        let validated_keys: Vec<KeyId> = pending
            .key_ids
            .iter()
            .copied()
            .filter(|k| current_set.contains(k))
            .collect();
        if validated_keys.is_empty() {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "no eligible trashed keys remain for this shred action",
                "Block may have been restored or already shredded since confirmation began",
            ));
        }
        let c = store.load_credentials()?;
        Ok((c, store.device_id().clone(), validated_keys))
    })();
    let (creds_opt, device_id, validated_keys) = match commit_prep {
        Ok(v) => v,
        Err(e) => return core_err_to_response(e),
    };
    let Some(creds) = creds_opt else {
        return core_err_to_response(CoreError::new(
            ErrorCode::SyncOffline,
            "expedite/confirm requires an online sync relay for authoritative server timestamps",
            "Connect to sync relay first",
        ));
    };
    let client = match RelayClient::from_credentials(&creds) {
        Ok(c) => c,
        Err(e) => return core_err_to_response(e),
    };

    let results_res = if pending.action == "confirm_pending" {
        client
            .post_keys_confirm(&validated_keys, Some(pending.grace_ms))
            .await
    } else {
        // expedite using pending.seen_seq captured at prepare time (C8: preserves server SHRED_STALE protection!)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(1);
        let mut marks = Vec::with_capacity(validated_keys.len());
        for kid in &validated_keys {
            let mut rnd = [0u8; 10];
            let _ = getrandom::fill(&mut rnd);
            let mid =
                mynote_core::ids::MarkId::from_ulid(mynote_core::ids::Ulid::from_parts(now as u64, rnd));
            marks.push(ShredMarkRow {
                mark_id: mid,
                key_id: *kid,
                seen_seq: pending.seen_seq,
                requested_by: device_id.clone(),
                requested_at_ms: now,
                grace_ms: pending.grace_ms,
                not_before_ms: None,
                state: ShredMarkState::PendingConfirm,
                confirmed_at_ms: None,
                cancelled_by: None,
                executed_at_ms: None,
            });
        }
        client
            .post_keys_shred(pending.seen_seq, true, false, &marks)
            .await
    };

    match results_res {
        Ok(results) => {
            let mut store = state.store.lock().unwrap();
            let _ = store.apply_store_mutations(&[StoreMutation::MarkShredMarksAcked {
                results: results.clone(),
                cancelled_keys: Vec::new(),
            }]);
            drop(store);
            state.broadcast_sync_and_trash();
            state.sync_notify.notify_one();
            let out: Vec<serde_json::Value> = results
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "key_id": r.key_id.to_string(),
                        "state": match r.state {
                            ShredMarkState::PendingConfirm => "pending_confirm",
                            ShredMarkState::Scheduled => "scheduled",
                            ShredMarkState::Cancelled => "cancelled",
                            ShredMarkState::Executed => "executed",
                        },
                        "not_before_ms": r.not_before_ms,
                    })
                })
                .collect();
            ok_json(serde_json::json!({
                "action": pending.action,
                "results": out,
            }))
        }
        Err(e) => core_err_to_response(e),
    }
}

async fn handle_get_vault_header(State(state): State<Arc<DaemonState>>) -> Response {
    let res = {
        let store = state.store.lock().unwrap();
        let hdr = store.get_vault_header();
        let rpk = store
            .recovery_pk()
            .ok()
            .map(|pk| base64::engine::general_purpose::STANDARD.encode(pk));
        hdr.map(|h| serde_json::json!({ "vault_header": h, "recovery_pk_b64": rpk }))
    };
    match res {
        Ok(v) => ok_json(v),
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
struct PutVaultHeaderBody {
    gen: i64,
    blob_b64: String,
}

async fn handle_put_vault_header(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<PutVaultHeaderBody>,
) -> Response {
    let res = (|| -> Result<mynote_store::VaultHeaderDto, CoreError> {
        let blob = decode_b64_arg("blob_b64", &body.blob_b64)?;
        state.store.lock().unwrap().put_vault_header(body.gen, &blob)
    })();
    match res {
        Ok(dto) => {
            state.broadcast_json(serde_json::json!({
                "type": "vault_header_changed",
                "vault_header": dto,
            }));
            state.sync_notify.notify_one();
            ok_json(dto)
        }
        Err(e) => core_err_to_response(e),
    }
}

async fn handle_list_blocked_ops(State(state): State<Arc<DaemonState>>) -> Response {
    let res = state.store.lock().unwrap().list_blocked_tier2_ops();
    match res {
        Ok(v) => ok_json(v),
        Err(e) => core_err_to_response(e),
    }
}

async fn handle_rekey_blocked_op(
    State(state): State<Arc<DaemonState>>,
    AxumPath(op_id): AxumPath<String>,
    Json(body): Json<Tier2RekeyJson>,
) -> Response {
    let res = (|| -> Result<mynote_store::BlockDetailDto, CoreError> {
        let mnb1 = decode_b64_arg("mnb1_b64", &body.mnb1_b64)?;
        let mnw1 = body
            .mnw1_b64
            .as_deref()
            .map(|s| decode_b64_arg("mnw1_b64", s))
            .transpose()?;
        let mut store = state.store.lock().unwrap();
        let receipt = store.rekey_blocked_tier2_op(
            &op_id,
            Tier2OpInput {
                op_id: &body.op_id,
                key_id: &body.key_id,
                mnb1: &mnb1,
                mnw1: mnw1.as_deref(),
            },
            "human",
        )?;
        store.get_block_for_daemon(&receipt.block_id)
    })();
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
    #[serde(default)]
    block_id: Option<String>,
}

async fn handle_format(State(state): State<Arc<DaemonState>>, Json(body): Json<FormatBody>) -> Response {
    if let Some(bid) = body.block_id.as_deref() {
        let check = {
            let store = state.store.lock().unwrap();
            store.get_block_for_daemon(bid)
        };
        match check {
            Ok(blk) if blk.is_locked => {
                return core_err_to_response(CoreError::new(
                    ErrorCode::BlockLocked,
                    format!("block '{bid}' is locked; unlocked Tier 2 blocks must be formatted in WASM only"),
                    "Format locked blocks via in-browser WASM Layer 1 formatter without invoking Daemon/Layer 2",
                ));
            }
            Ok(_) => {}
            Err(e) => return core_err_to_response(e),
        }
    }
    let content = body.content;
    let lang = body.lang;
    let action = body.action;
    let formatted = tokio::task::spawn_blocking(move || format_content(&content, &lang, action.as_deref()))
        .await
        .map_err(|e| {
            CoreError::new(
                ErrorCode::IntegrityError,
                format!("formatter worker join error: {e}"),
                "Retry formatting",
            )
        })
        .and_then(|res| res);
    match formatted {
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
            let marks: Vec<serde_json::Value> = kt
                .marks
                .values()
                .map(|m| {
                    serde_json::json!({
                        "mark_id": m.mark_id.to_string(),
                        "key_id": m.key_id.to_string(),
                        "seen_seq": m.seen_seq,
                        "requested_by": m.requested_by.as_str(),
                        "requested_at_ms": m.requested_at_ms,
                        "grace_ms": m.grace_ms,
                        "not_before_ms": m.not_before_ms,
                        "state": match m.state {
                            ShredMarkState::PendingConfirm => "pending_confirm",
                            ShredMarkState::Scheduled => "scheduled",
                            ShredMarkState::Cancelled => "cancelled",
                            ShredMarkState::Executed => "executed",
                        },
                        "confirmed_at_ms": m.confirmed_at_ms,
                        "cancelled_by": m.cancelled_by.as_ref().map(|d| d.as_str()),
                        "executed_at_ms": m.executed_at_ms,
                    })
                })
                .collect();
            serde_json::json!({
                "key_records": records,
                "shred_marks": marks,
                "vault_header": kt.vault_header_material.as_ref().map(|(g, b)| serde_json::json!({
                    "gen": g,
                    "blob_b64": b64.encode(b),
                })),
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

async fn handle_ipc_client<S>(state: Arc<DaemonState>, stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    while let Ok(n) = reader.read_line(&mut line).await {
        if n == 0 {
            break;
        }
        let resp = match serde_json::from_str::<LocalIpcRequest>(line.trim()) {
            Ok(req) => dispatch_ipc_request(&state, req).await,
            Err(e) => LocalIpcResponse::from_core_error(&CoreError::new(
                ErrorCode::InvalidArgument,
                format!("malformed LocalIpc request: {e}"),
                "Send valid NDJSON LocalIpcRequest",
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

async fn dispatch_ipc_request(state: &Arc<DaemonState>, req: LocalIpcRequest) -> LocalIpcResponse {
    match req {
        LocalIpcRequest::Ping => LocalIpcResponse {
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
        LocalIpcRequest::OpenTicket => match state.issue_open_ticket() {
            Ok(url) => LocalIpcResponse {
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
            Err(e) => LocalIpcResponse::from_core_error(&e),
        },
        LocalIpcRequest::Poke { fast_flush: _ } => {
            let (bufs_updated, new_creds, refreshed_blocks) = {
                let mut store = state.store.lock().unwrap();
                let changed = store.reload_smks_from_disk().unwrap_or(false);
                let (bufs_changed, blocks) = if changed {
                    let (bc, updated_ids) = store.rematerialize_unavailable().unwrap_or((false, Vec::new()));
                    let details = updated_ids
                        .into_iter()
                        .filter_map(|id| store.get_block_for_daemon(&id).ok())
                        .collect();
                    (bc, details)
                } else {
                    (false, Vec::new())
                };
                let creds = store.load_credentials().ok().flatten();
                (bufs_changed, creds, blocks)
            };
            if *state.creds_tx.borrow() != new_creds {
                let _ = state.creds_tx.send(new_creds);
            }
            if bufs_updated {
                state.broadcast_buffers_snapshot(Vec::new());
            }
            if !refreshed_blocks.is_empty() {
                state.broadcast_json(serde_json::json!({
                    "type": "blocks_changed",
                    "upserted": refreshed_blocks,
                    "deleted_ids": []
                }));
                state.broadcast_sync_and_trash();
            }
            state.sync_notify.notify_one();
            LocalIpcResponse {
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
        LocalIpcRequest::SyncNow { wait } => {
            if !wait {
                state.sync_notify.notify_one();
                return LocalIpcResponse {
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
                Ok((head_seq, sync_state, pending)) => LocalIpcResponse {
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
                Err(e) => LocalIpcResponse::from_core_error(&e),
            }
        }
        LocalIpcRequest::Apply { meta, request } => execute_ipc_apply(state, meta, request),
        LocalIpcRequest::ClipUndo => daemon_clip::dispatch_ipc_clip_undo(state).await,
        LocalIpcRequest::ClipApply { clip_id } => daemon_clip::dispatch_ipc_clip_apply(state, &clip_id).await,
        LocalIpcRequest::ClipPoke { clip_id, cleared } => {
            daemon_clip::dispatch_ipc_clip_poke(state, clip_id, cleared).await
        }
        LocalIpcRequest::ClipWatchSet {
            paused,
            enabled,
            auto_apply_mirror,
        } => daemon_clip::dispatch_ipc_clip_watch_set(state, paused, enabled, auto_apply_mirror),
    }
}

fn execute_ipc_apply(state: &Arc<DaemonState>, meta: ApplyMeta, req: ApplyRequest) -> LocalIpcResponse {
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
                } else if let Some(merged_content) = content.as_deref() {
                    store.update_block(&id, merged_content, &expected_heads, meta.force, &meta.actor)
                } else {
                    Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        "resolve request requires either keep_op_id or merged content",
                        "Pass --keep-op <op_id> or provide merged content on stdin",
                    ))
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
            } => store
                .resolve_revert_target(&id, to_op.as_deref(), undo_actor.as_deref())
                .and_then(|resolved| store.revert_block(&id, &resolved.target.op_id, &meta.actor))
                .and_then(|r| {
                    broadcast_block_up = Some(r.block_id.clone());
                    serde_json::to_value(r).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode receipt")
                    })
                }),
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
                            "shred_state": "pending_sync",
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
            ApplyRequest::PutVaultHeader { gen, blob_b64 } => decode_b64_arg("blob_b64", &blob_b64)
                .and_then(|blob| store.put_vault_header(gen, &blob))
                .and_then(|dto| {
                    state.broadcast_json(serde_json::json!({
                        "type": "vault_header_changed",
                        "vault_header": dto,
                    }));
                    serde_json::to_value(dto).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode vault header")
                    })
                }),
            ApplyRequest::LockBlockTier2 {
                id,
                op_id,
                key_id,
                mnb1_b64,
                mnw1_b64,
                expected_heads,
                public_hint,
            } => (|| -> Result<serde_json::Value, CoreError> {
                let mnb1 = decode_b64_arg("mnb1_b64", &mnb1_b64)?;
                let mnw1 = decode_b64_arg("mnw1_b64", &mnw1_b64)?;
                let r = store.lock_block_tier2(
                    &id,
                    Tier2OpInput {
                        op_id: &op_id,
                        key_id: &key_id,
                        mnb1: &mnb1,
                        mnw1: Some(&mnw1),
                    },
                    &expected_heads,
                    None,
                    public_hint.as_deref(),
                    T_GRACE_DEFAULT_MS,
                    &meta.actor,
                )?;
                broadcast_block_up = Some(r.block_id.clone());
                serde_json::to_value(r)
                    .map_err(|e| CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode receipt"))
            })(),
            ApplyRequest::UnlockBlockTier1 {
                id,
                plaintext_content,
                expected_heads,
                shred_old_key,
            } => store
                .unlock_block_tier1(
                    &id,
                    &expected_heads,
                    &plaintext_content,
                    None,
                    shred_old_key,
                    &meta.actor,
                )
                .and_then(|r| {
                    broadcast_block_up = Some(r.block_id.clone());
                    serde_json::to_value(r).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "encode receipt")
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
            LocalIpcResponse {
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
        Err(e) => LocalIpcResponse::from_core_error(&e),
    }
}
