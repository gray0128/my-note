//! Local Daemon 100-item text & bitmap clipboard API (`/v1/local/clip*`),
//! Cloud WS clip event handlers (`clip_wake`, `clip_ephemeral`, `clip_cleared`),
//! and UDS clip IPC helpers (`M4a-3`, `docs/interface-contracts.md` §3.2–§3.3).

use super::*;
use crate::clip_watch::{
    persist_watch_config, validate_auto_apply_mirror, WatchCaptureOutcome, WatchDecision,
    CLIP_SECRET_BLOCKED_HINT,
};
use crate::clipboard::{
    detect_image_mime_from_bytes_and_path, inspect_image_dimensions, is_svg_bytes, make_thumbnail,
    send_clip_notification, ClipboardPayload, ClipboardWriteOpts, ReadClipboardResult,
};
use crate::sync_client::{
    ensure_clip_key_with_mutex, refresh_clip_key_from_remote_with_mutex, CloudClipQuota, CloudWsEvent,
    RemoteClipItem,
};
use axum::http::header::CONTENT_TYPE as HTTP_CONTENT_TYPE;
use mynote_core::clip::{
    clip_sha256_hex, decrypt_mnc1_blob, decrypt_mnc1_meta, encrypt_mnc1_blob, encrypt_mnc1_meta,
    validate_clip_image_mime, verify_clip_blob_sha256, ClipBlobMetaV1, ClipKind, ClipMetaV1, ClipSourceMode,
    CLIP_BLOB_MAX_BYTES, CLIP_DEFAULT_TTL_MS, CLIP_EPHEMERAL_MAX_BYTES, CLIP_INLINE_TEXT_MAX_BYTES,
    CLIP_PREVIEW_MAX_CHARS, CLIP_THUMB_MAX_BYTES,
};
use mynote_core::ids::{ClipId, ClipKid, DeviceId};
use mynote_store::{ClipItemRow, ClipListQuery, ClipPruneFilter, CLIP_LOCAL_DEFAULT_PAGE_LIMIT};
use serde::Serialize;

/// Frozen Desktop Web UI <-> Local Daemon DTO (`M4a-3` & `M4a-4` shared contract).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClipItemDto {
    pub clip_id: String,
    pub clip_kid: String,
    pub device_id: String,
    pub kind: String,
    pub mime: String,
    pub source_mode: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub text_preview: Option<String>,
    pub has_blob: bool,
    pub blob_bytes: Option<i64>,
    pub blob_sha256: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub thumb_mime: Option<String>,
    pub thumb_data_url: Option<String>,
    pub cached_locally: bool,
}

/// Local Daemon watch configuration (M4a defaults: watch off, unpaused, `inbox-only`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClipWatchConfig {
    pub watch_enabled: bool,
    pub watch_paused: bool,
    pub auto_apply_mirror: String,
}

impl Default for ClipWatchConfig {
    fn default() -> Self {
        Self {
            watch_enabled: false,
            watch_paused: false,
            auto_apply_mirror: "inbox-only".to_string(),
        }
    }
}

pub fn clip_blob_cache_name(clip_id: &str, mime: &str) -> String {
    let ext = match mime {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/webp" => "webp",
        "image/gif" => "gif",
        _ => "txt",
    };
    format!("{clip_id}.{ext}")
}

pub fn truncate_clip_preview(text: &str) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(CLIP_PREVIEW_MAX_CHARS).collect();
    if chars.next().is_some() {
        format!("{head}...")
    } else {
        head
    }
}

pub fn clip_row_to_dto(row: &ClipItemRow, cache: &mynote_store::ClipCache) -> ClipItemDto {
    let thumb_data_url = match (row.thumb_mime.as_deref(), row.thumb_blob.as_deref()) {
        (Some(tm), Some(bytes)) if validate_clip_image_mime(tm).is_ok() && !is_svg_bytes(bytes) => {
            Some(format!(
                "data:{tm};base64,{}",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            ))
        }
        _ => None,
    };
    let cached_locally = if !row.has_blob {
        true
    } else {
        row.local_blob_path
            .as_deref()
            .is_some_and(|rel| cache.exists(rel))
    };
    ClipItemDto {
        clip_id: row.clip_id.clone(),
        clip_kid: row.clip_kid.clone(),
        device_id: row.device_id.clone(),
        kind: row.kind.clone(),
        mime: row.mime.clone(),
        source_mode: row.source_mode.clone(),
        created_at_ms: row.created_at_ms,
        expires_at_ms: row.expires_at_ms,
        text_preview: row.text_preview.clone(),
        has_blob: row.has_blob,
        blob_bytes: row.blob_bytes,
        blob_sha256: row.blob_sha256.clone(),
        width: row.width,
        height: row.height,
        thumb_mime: row.thumb_mime.clone(),
        thumb_data_url,
        cached_locally,
    }
}

fn now_ms_daemon() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(1)
        .max(1)
}

fn rand_nonce_24() -> Result<[u8; 24], CoreError> {
    let mut n = [0u8; 24];
    getrandom::fill(&mut n).map_err(|e| {
        CoreError::new(
            ErrorCode::IntegrityError,
            format!("OS CSPRNG error: {e}"),
            "Check system entropy",
        )
    })?;
    Ok(n)
}

fn ephemeral_auto_clear_duration() -> Duration {
    if let Ok(ms_s) = std::env::var("MYNOTE_CLIP_EPHEMERAL_CLEAR_MS") {
        if let Ok(ms) = ms_s.trim().parse::<u64>() {
            return Duration::from_millis(ms.max(10));
        }
    }
    if let Ok(sec_s) = std::env::var("MYNOTE_CLIP_EPHEMERAL_CLEAR_SECS") {
        if let Ok(sec) = sec_s.trim().parse::<u64>() {
            return Duration::from_secs(sec.max(1));
        }
    }
    Duration::from_secs(60)
}

impl DaemonState {
    pub fn clip_watch_snapshot(&self) -> ClipWatchConfig {
        self.clip_watch_state.lock().unwrap().clone()
    }

    pub fn cloud_clip_quota_snapshot(&self) -> Option<CloudClipQuota> {
        self.cloud_clip_quota.lock().unwrap().clone()
    }

    pub fn update_cloud_clip_quota(&self, quota: Option<CloudClipQuota>) {
        if let Some(q) = quota {
            *self.cloud_clip_quota.lock().unwrap() = Some(q);
        }
    }

    pub fn broadcast_clip_changed(
        &self,
        upserted: Vec<ClipItemDto>,
        deleted_ids: Vec<String>,
        cleared: bool,
    ) {
        let watch = self.clip_watch_snapshot();
        let quota = self.cloud_clip_quota_snapshot();
        self.broadcast_json(serde_json::json!({
            "type": "clip_changed",
            "upserted": upserted,
            "deleted_ids": deleted_ids,
            "cleared": cleared,
            "watch_enabled": watch.watch_enabled,
            "watch_paused": watch.watch_paused,
            "auto_apply_mirror": watch.auto_apply_mirror,
            "cloud_quota": quota,
        }));
    }

    /// Spawn a single-concurrency background task to eagerly fetch and persist remote blobs
    /// into desktop `clip_cache/` before cloud 30-day TTL expires (D8′).
    pub fn spawn_clip_blob_prefetch(self: &Arc<Self>) {
        let st = Arc::clone(self);
        tokio::spawn(async move {
            st.prefetch_uncached_clip_blobs().await;
        });
    }

    pub async fn prefetch_uncached_clip_blobs(&self) {
        let Ok(_guard) = self.clip_prefetch_lock.try_lock() else {
            return;
        };
        let rows = {
            let store = self.store.lock().unwrap();
            if store.load_credentials().ok().flatten().is_none() {
                return;
            }
            store
                .list_uncached_remote_blobs(now_ms_daemon(), 50)
                .unwrap_or_default()
        };
        for row in rows {
            match self.resolve_clip_payload_bytes(&row).await {
                Ok(_) => {
                    let dto_opt = {
                        let store = self.store.lock().unwrap();
                        let cache = store.clip_cache();
                        store
                            .get_clip_item(&row.clip_id)
                            .ok()
                            .flatten()
                            .map(|r| clip_row_to_dto(&r, &cache))
                    };
                    if let Some(dto) = dto_opt {
                        self.broadcast_clip_changed(vec![dto], Vec::new(), false);
                    }
                }
                Err(e) if e.code() == ErrorCode::SyncOffline => break,
                Err(_) => continue,
            }
        }
    }

    /// Dispatch a Cloud WS frame into the local Daemon state machine.
    pub fn handle_cloud_ws_event(self: &Arc<Self>, ev: CloudWsEvent) {
        match ev {
            CloudWsEvent::Wake { .. } => {
                self.sync_notify.notify_one();
            }
            CloudWsEvent::DeviceRevoked => {
                self.broadcast_json(serde_json::json!({
                    "type": "alert",
                    "code": "DEVICE_REVOKED",
                    "details": { "message": "this device token has been revoked" }
                }));
            }
            CloudWsEvent::ClipWake { .. } => {
                let st = Arc::clone(self);
                tokio::spawn(async move {
                    let _ = st.pull_cloud_clips(true).await;
                    st.spawn_clip_blob_prefetch();
                });
            }
            CloudWsEvent::ClipEphemeral {
                clip_id,
                clip_kid,
                device_id,
                envelope_b64,
            } => {
                let st = Arc::clone(self);
                tokio::spawn(async move {
                    let _ = st
                        .handle_cloud_clip_ephemeral(&clip_id, &clip_kid, &device_id, &envelope_b64)
                        .await;
                });
            }
            CloudWsEvent::ClipCleared { clip_id, scope } => {
                let st = Arc::clone(self);
                tokio::spawn(async move {
                    let _ = st.handle_cloud_clip_cleared(clip_id, scope).await;
                });
            }
        }
    }

    /// Incrementally pull all new clips from the relay's rolling window, decrypt `MNC1` metadata,
    /// upsert into the unbounded local desktop `clip_items` archive, broadcast `clip_changed`,
    /// and optionally auto-apply to OS clipboard.
    pub async fn pull_cloud_clips(&self, auto_apply: bool) -> Result<Vec<ClipItemDto>, CoreError> {
        let _guard = self.clip_sync_lock.lock().await;
        let (creds_opt, local_device_id, cursor) = {
            let store = self.store.lock().unwrap();
            (
                store.load_credentials()?,
                store.device_id().as_str().to_string(),
                store.get_clip_cursor(),
            )
        };
        let Some(creds) = creds_opt else {
            return Ok(Vec::new());
        };
        let client = RelayClient::from_credentials(&creds)?;
        let (mut clip_kid, mut clip_key, _gen) = ensure_clip_key_with_mutex(&self.store, &client).await?;

        let (mut remote_items, quota_opt): (Vec<RemoteClipItem>, Option<CloudClipQuota>) =
            client.clip_list_all_since(cursor.as_deref()).await?;
        self.update_cloud_clip_quota(quota_opt);
        if remote_items.is_empty() {
            return Ok(Vec::new());
        }
        remote_items.sort_by(|a, b| a.clip_id.cmp(&b.clip_id));

        let b64 = base64::engine::general_purpose::STANDARD;
        let mut refreshed_once = false;
        let mut upserted_rows: Vec<ClipItemRow> = Vec::new();
        let mut max_clip_id: Option<String> = cursor;

        for item in &remote_items {
            if max_clip_id
                .as_deref()
                .is_none_or(|cur| item.clip_id.as_str() > cur)
            {
                max_clip_id = Some(item.clip_id.clone());
            }
            if item.clip_kid != clip_kid.to_string() && !refreshed_once {
                refreshed_once = true;
                if let Ok(Some((nkid, nkey, _))) =
                    refresh_clip_key_from_remote_with_mutex(&self.store, &client).await
                {
                    clip_kid = nkid;
                    clip_key = nkey;
                }
            }
            if item.clip_kid != clip_kid.to_string() {
                continue;
            }
            let Ok(cid) = ClipId::parse(&item.clip_id) else {
                continue;
            };
            let Ok(author_dev) = DeviceId::parse(&item.device_id) else {
                continue;
            };
            let Ok(env_bytes) = b64.decode(&item.meta_envelope_b64) else {
                continue;
            };
            let Ok(meta) = decrypt_mnc1_meta(clip_kid, &clip_key, cid, &author_dev, false, &env_bytes) else {
                continue;
            };

            let thumb_blob = meta
                .blob
                .as_ref()
                .and_then(|b| b.thumb_b64.as_deref())
                .and_then(|s| b64.decode(s).ok());
            let row = ClipItemRow {
                clip_id: item.clip_id.clone(),
                clip_kid: item.clip_kid.clone(),
                device_id: item.device_id.clone(),
                kind: meta.kind.as_str().to_string(),
                mime: meta.mime.clone(),
                source_mode: meta.source_mode.as_str().to_string(),
                created_at_ms: item.created_at_ms.max(meta.created_at_ms),
                expires_at_ms: item.expires_at_ms,
                text_preview: meta.text.clone(),
                has_blob: item.has_blob || meta.blob.is_some(),
                blob_bytes: meta.blob.as_ref().map(|b| b.byte_size as i64).or(item.blob_bytes),
                blob_sha256: meta.blob.as_ref().map(|b| b.sha256_hex.clone()),
                width: meta.blob.as_ref().and_then(|b| b.width),
                height: meta.blob.as_ref().and_then(|b| b.height),
                thumb_mime: meta.blob.as_ref().and_then(|b| b.thumb_mime.clone()),
                thumb_blob,
                local_blob_path: None,
            };
            upserted_rows.push(row);
        }

        let (dtos, newest_remote) = {
            let store = self.store.lock().unwrap();
            let cache = store.clip_cache();
            for row in &upserted_rows {
                let _ = store.upsert_clip_item(row);
            }
            if let Some(ref cur) = max_clip_id {
                let _ = store.set_clip_cursor(Some(cur));
            }
            let dtos: Vec<ClipItemDto> = upserted_rows
                .iter()
                .filter_map(|r| store.get_clip_item(&r.clip_id).ok().flatten())
                .map(|r| clip_row_to_dto(&r, &cache))
                .collect();
            let newest = upserted_rows
                .iter()
                .filter(|r| r.device_id != local_device_id)
                .max_by(|a, b| {
                    a.created_at_ms
                        .cmp(&b.created_at_ms)
                        .then_with(|| a.clip_id.cmp(&b.clip_id))
                })
                .and_then(|r| store.get_clip_item(&r.clip_id).ok().flatten());
            (dtos, newest)
        };

        if !dtos.is_empty() {
            self.broadcast_clip_changed(dtos.clone(), Vec::new(), false);
        }

        if auto_apply {
            if let Some(target) = newest_remote {
                let watch_cfg = self.clip_watch_snapshot();
                let should_apply = target.source_mode == "explicit"
                    || (target.source_mode == "auto"
                        && watch_cfg.auto_apply_mirror == "auto-apply"
                        && !watch_cfg.watch_paused);
                if should_apply && self.apply_clip_row_to_clipboard(&target).await.is_ok() {
                    let updated_dto = {
                        let store = self.store.lock().unwrap();
                        let cache = store.clip_cache();
                        store
                            .get_clip_item(&target.clip_id)
                            .ok()
                            .flatten()
                            .map(|r| clip_row_to_dto(&r, &cache))
                    };
                    if let Some(dto) = updated_dto {
                        self.broadcast_clip_changed(vec![dto], Vec::new(), false);
                    }
                    let notif = if target.kind == "image" {
                        format!(
                            "Image copied from another device ({}x{})",
                            target.width.unwrap_or(0),
                            target.height.unwrap_or(0)
                        )
                    } else {
                        "Text copied from another device (run 'mynote clip undo' to revert)".to_string()
                    };
                    send_clip_notification("my-note clipboard", &notif);
                }
            }
        }

        Ok(dtos)
    }

    /// Handle zero-DB pure-memory `clip_ephemeral` WS direct push (`docs/sync-protocol.md` §11.3).
    /// NEVER writes to `clip_items`, `clip_cache/`, or `sync_ops`!
    pub async fn handle_cloud_clip_ephemeral(
        &self,
        clip_id: &str,
        clip_kid_str: &str,
        device_id_str: &str,
        envelope_b64: &str,
    ) -> Result<bool, CoreError> {
        let local_dev = self.store.lock().unwrap().device_id().as_str().to_string();
        if device_id_str == local_dev {
            return Ok(false);
        }
        let cid = ClipId::parse(clip_id)?;
        let ckid = ClipKid::parse(clip_kid_str)?;
        let author_dev = DeviceId::parse(device_id_str)?;
        let env_bytes = decode_b64_arg("envelope_b64", envelope_b64)?;

        let mut key_opt = self.store.lock().unwrap().unwrap_local_clip_key()?;
        if key_opt.as_ref().is_none_or(|(k, _, _)| *k != ckid) {
            let creds_opt = self.store.lock().unwrap().load_credentials()?;
            if let Some(creds) = creds_opt {
                if let Ok(client) = RelayClient::from_credentials(&creds) {
                    if let Ok(refreshed) = refresh_clip_key_from_remote_with_mutex(&self.store, &client).await
                    {
                        key_opt = refreshed;
                    }
                }
            }
        }
        let Some((local_kid, clip_key, _)) = key_opt else {
            return Err(CoreError::new(
                ErrorCode::KeyMissing,
                "ClipKey unavailable for incoming ephemeral clip",
                "Sync ClipKey from relay",
            ));
        };
        if local_kid != ckid {
            return Err(CoreError::new(
                ErrorCode::KeyUnknown,
                format!("ephemeral clip_kid '{clip_kid_str}' does not match active local ClipKey"),
                "Wait for ClipKey sync",
            ));
        }
        let meta = decrypt_mnc1_meta(ckid, &clip_key, cid, &author_dev, true, &env_bytes)?;
        if meta.kind != ClipKind::Text {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "ephemeral clip channel only supports text payloads",
                "Ignore non-text ephemeral frames",
            ));
        }
        let text = meta.text.unwrap_or_default();

        // Capture undo slot, write with sensitive + ephemeral + synced_marker flags, record echo hash.
        {
            let mut undo = self.clip_undo.lock().unwrap();
            undo.capture_from(self.clipboard.as_ref());
        }
        let receipt = self.clipboard.write(
            &ClipboardPayload::Text(text),
            ClipboardWriteOpts {
                synced_marker: true,
                sensitive: true,
                ephemeral: true,
            },
        )?;
        self.clip_echo
            .lock()
            .unwrap()
            .record(receipt.written_blake3, now_ms_daemon() as u64);

        send_clip_notification(
            "my-note ephemeral clip",
            "Sensitive clip copied to clipboard (auto-clears in 60s; zero disk storage)",
        );

        // Spawn safe auto-clear timer: ONLY clears if clipboard still holds our exact BLAKE3 digest!
        let clip_handle = Arc::clone(&self.clipboard);
        let written_hash = receipt.written_blake3;
        let clear_after = ephemeral_auto_clear_duration();
        tokio::spawn(async move {
            tokio::time::sleep(clear_after).await;
            if clip_handle.current_mynote_blake3() == Some(written_hash) {
                let _ = clip_handle.clear();
            }
        });
        Ok(true)
    }

    pub async fn handle_cloud_clip_cleared(
        &self,
        clip_id: Option<String>,
        scope: Option<String>,
    ) -> Result<(), CoreError> {
        if let Some(cid) = clip_id {
            let existed = {
                let store = self.store.lock().unwrap();
                let (existed, blob_path) = store.delete_clip_item(&cid)?;
                if let Some(rel) = blob_path {
                    let _ = store.clip_cache().delete(&rel);
                }
                existed
            };
            if existed {
                self.broadcast_clip_changed(Vec::new(), vec![cid], false);
            }
        } else if scope.as_deref() == Some("all") {
            {
                let store = self.store.lock().unwrap();
                let _ = store.clear_clip_items()?;
                let _ = store.clip_cache().clear();
            }
            // Refresh newly rotated ClipKey and latest cloud quota from relay if configured.
            let creds_opt = self.store.lock().unwrap().load_credentials().ok().flatten();
            if let Some(creds) = creds_opt {
                if let Ok(client) = RelayClient::from_credentials(&creds) {
                    let _ = refresh_clip_key_from_remote_with_mutex(&self.store, &client).await;
                    if let Ok(page) = client.clip_list_page(None, 1).await {
                        self.update_cloud_clip_quota(page.quota);
                    }
                }
            }
            self.broadcast_clip_changed(Vec::new(), Vec::new(), true);
        } else {
            // Cloud-only clear/prune or key rotation (default scope="cloud"):
            // Preserve the desktop local archive untouched; only reset sync cursor, refresh ClipKey & quota.
            {
                let store = self.store.lock().unwrap();
                let _ = store.set_clip_cursor(None);
            }
            let creds_opt = self.store.lock().unwrap().load_credentials().ok().flatten();
            if let Some(creds) = creds_opt {
                if let Ok(client) = RelayClient::from_credentials(&creds) {
                    let _ = refresh_clip_key_from_remote_with_mutex(&self.store, &client).await;
                    if let Ok(page) = client.clip_list_page(None, 1).await {
                        self.update_cloud_clip_quota(page.quota);
                    }
                }
            }
            self.broadcast_clip_changed(Vec::new(), Vec::new(), false);
        }
        Ok(())
    }

    /// Resolve raw plaintext bytes for a stored clip item (hitting `clip_cache/` first, or fetching,
    /// decrypting `MNC1`, verifying `sha256_hex`, and caching locally on miss).
    pub async fn resolve_clip_payload_bytes(
        &self,
        row: &ClipItemRow,
    ) -> Result<(Vec<u8>, String), CoreError> {
        if !row.has_blob {
            if row.kind != "text" {
                return Err(CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("image clip '{}' is missing blob flag", row.clip_id),
                    "Re-pull clip history",
                ));
            }
            let text = row.text_preview.clone().unwrap_or_default();
            return Ok((text.into_bytes(), "text/plain; charset=utf-8".to_string()));
        }

        let content_type = if row.kind == "image" {
            validate_clip_image_mime(&row.mime)?;
            row.mime.clone()
        } else {
            "text/plain; charset=utf-8".to_string()
        };

        let rel_name = row
            .local_blob_path
            .clone()
            .unwrap_or_else(|| clip_blob_cache_name(&row.clip_id, &row.mime));

        // 1. Fast path: local LRU clip_cache hit
        let cached = {
            let store = self.store.lock().unwrap();
            store.clip_cache().read(&rel_name)?
        };
        if let Some(bytes) = cached {
            if let Some(expected_sha) = row.blob_sha256.as_deref() {
                if verify_clip_blob_sha256(&bytes, expected_sha).is_ok() {
                    if row.local_blob_path.is_none() {
                        let _ = self
                            .store
                            .lock()
                            .unwrap()
                            .set_clip_local_blob_path(&row.clip_id, Some(&rel_name));
                    }
                    return Ok((bytes, content_type));
                }
            } else {
                return Ok((bytes, content_type));
            }
        }

        // 2. Cache miss: stream-download from relay, decrypt MNC1, verify sha256_hex, cache 0600
        let creds = self.store.lock().unwrap().load_credentials()?.ok_or_else(|| {
            CoreError::new(
                ErrorCode::SyncOffline,
                format!(
                    "clip blob '{}' is not cached locally and sync relay is unconfigured",
                    row.clip_id
                ),
                "Configure cloud sync or re-push the clip",
            )
        })?;
        let client = RelayClient::from_credentials(&creds)?;
        let remote_blob = client.clip_get_blob(&row.clip_id).await?;

        let cid = ClipId::parse(&row.clip_id)?;
        let ckid = ClipKid::parse(&row.clip_kid)?;
        let author_dev = DeviceId::parse(&row.device_id)?;

        let mut key_opt = self.store.lock().unwrap().unwrap_local_clip_key()?;
        if key_opt.as_ref().is_none_or(|(k, _, _)| *k != ckid) {
            if let Ok(refreshed) = refresh_clip_key_from_remote_with_mutex(&self.store, &client).await {
                key_opt = refreshed;
            }
        }
        let Some((local_kid, clip_key, _)) = key_opt else {
            return Err(CoreError::new(
                ErrorCode::KeyMissing,
                "local ClipKey unavailable to decrypt clip blob",
                "Sync ClipKey from relay",
            ));
        };
        if local_kid != ckid {
            return Err(CoreError::new(
                ErrorCode::KeyUnknown,
                format!(
                    "clip blob '{}' encrypted under rotated/unknown clip_kid",
                    row.clip_id
                ),
                "Refresh clip history",
            ));
        }

        let raw_bytes = decrypt_mnc1_blob(ckid, &clip_key, cid, &author_dev, &remote_blob.envelope)?;
        if let Some(expected_sha) = row.blob_sha256.as_deref() {
            verify_clip_blob_sha256(&raw_bytes, expected_sha)?;
        }
        if row.kind == "image" && is_svg_bytes(&raw_bytes) {
            return Err(CoreError::new(
                ErrorCode::IntegrityError,
                "refusing SVG bytes masquerading as bitmap clip blob",
                "Delete this clip item",
            ));
        }
        {
            let store = self.store.lock().unwrap();
            let _ = store.clip_cache().write(&rel_name, &raw_bytes)?;
            let _ = store.set_clip_local_blob_path(&row.clip_id, Some(&rel_name));
        }
        Ok((raw_bytes, content_type))
    }

    pub async fn apply_clip_row_to_clipboard(&self, row: &ClipItemRow) -> Result<bool, CoreError> {
        let (bytes, _) = self.resolve_clip_payload_bytes(row).await?;
        let payload = if row.kind == "image" {
            validate_clip_image_mime(&row.mime)?;
            ClipboardPayload::Image {
                mime: row.mime.clone(),
                bytes,
                width: row.width,
                height: row.height,
            }
        } else {
            let text = String::from_utf8(bytes).map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("text clip '{}' is not valid UTF-8: {e}", row.clip_id),
                    "Inspect clip payload",
                )
            })?;
            ClipboardPayload::Text(text)
        };

        let has_undo = {
            let mut undo = self.clip_undo.lock().unwrap();
            undo.capture_from(self.clipboard.as_ref());
            undo.has_undo()
        };
        let receipt = self.clipboard.write(
            &payload,
            ClipboardWriteOpts {
                synced_marker: true,
                sensitive: false,
                ephemeral: false,
            },
        )?;
        self.clip_echo
            .lock()
            .unwrap()
            .record(receipt.written_blake3, now_ms_daemon() as u64);
        Ok(has_undo)
    }

    pub async fn apply_clip_by_id(&self, clip_id: &str) -> Result<bool, CoreError> {
        let row = self
            .store
            .lock()
            .unwrap()
            .get_clip_item(clip_id)?
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::NotFound,
                    format!("clip item '{clip_id}' not found"),
                    "Refresh clip history and retry",
                )
            })?;
        self.apply_clip_row_to_clipboard(&row).await
    }

    pub fn undo_clipboard(&self) -> Result<bool, CoreError> {
        let restored_opt = {
            let mut undo = self.clip_undo.lock().unwrap();
            undo.restore(self.clipboard.as_ref())?
        };
        if let Some(receipt) = restored_opt {
            self.clip_echo
                .lock()
                .unwrap()
                .record(receipt.written_blake3, now_ms_daemon() as u64);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn update_clip_watch(
        &self,
        paused: Option<bool>,
        enabled: Option<bool>,
        auto_apply_mirror: Option<String>,
    ) -> Result<ClipWatchConfig, CoreError> {
        if paused.is_none() && enabled.is_none() && auto_apply_mirror.is_none() {
            return Ok(self.clip_watch_snapshot());
        }
        if let Some(ref mode) = auto_apply_mirror {
            validate_auto_apply_mirror(mode)?;
        }
        let cfg = {
            let mut g = self.clip_watch_state.lock().unwrap();
            if let Some(p) = paused {
                g.watch_paused = p;
            }
            if let Some(e) = enabled {
                g.watch_enabled = e;
            }
            if let Some(m) = auto_apply_mirror {
                g.auto_apply_mirror = m;
            }
            g.clone()
        };
        {
            let store = self.store.lock().unwrap();
            persist_watch_config(&store, &cfg)?;
        }
        let _ = self.clip_watch_tx.send(cfg.clone());
        self.broadcast_clip_changed(Vec::new(), Vec::new(), false);
        Ok(cfg)
    }

    /// Process a clipboard observation from the M4b-1 background watch engine (or test harness).
    /// Enforces watch enabled/unpaused state, sensitive/echo/secret/size/rate filters, emits
    /// `CLIP_SECRET_BLOCKED` WS alert on secret hits (0 outbound network calls), and uploads
    /// allowed items with `source_mode = ClipSourceMode::Auto`.
    pub async fn handle_auto_captured_read(
        self: &Arc<Self>,
        read_res: ReadClipboardResult,
        now_ms: u64,
    ) -> Result<WatchCaptureOutcome, CoreError> {
        let cfg = self.clip_watch_snapshot();
        if !cfg.watch_enabled || cfg.watch_paused {
            return Ok(WatchCaptureOutcome::DisabledOrPaused);
        }
        let decision = {
            let mut filter = self.clip_watch_filter.lock().unwrap();
            let echo = self.clip_echo.lock().unwrap();
            filter.evaluate_read(read_res, &echo, now_ms)
        };
        match decision {
            WatchDecision::SecretBlocked(pattern) => {
                self.broadcast_json(serde_json::json!({
                    "type": "alert",
                    "code": "CLIP_SECRET_BLOCKED",
                    "details": {
                        "pattern": pattern,
                        "hint": CLIP_SECRET_BLOCKED_HINT,
                    }
                }));
                Ok(WatchCaptureOutcome::Dropped(WatchDecision::SecretBlocked(
                    pattern,
                )))
            }
            WatchDecision::Allow(payload) => {
                let dto = match payload {
                    ClipboardPayload::Text(text) => {
                        push_text_clip_persisted(self, text, ClipSourceMode::Auto).await?
                    }
                    ClipboardPayload::Image {
                        mime,
                        bytes,
                        width,
                        height,
                    } => {
                        push_image_clip_persisted(
                            self,
                            &mime,
                            bytes,
                            width,
                            height,
                            None,
                            ClipSourceMode::Auto,
                        )
                        .await?
                    }
                };
                Ok(WatchCaptureOutcome::Uploaded(Box::new(dto)))
            }
            other => Ok(WatchCaptureOutcome::Dropped(other)),
        }
    }
}

// ---------------------------------------------------------------------------
// 8 Local Daemon HTTP Route Handlers (all protected by SEC-05 middleware)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct ListClipQuery {
    limit: Option<usize>,
    before_id: Option<String>,
    kind: Option<String>,
    q: Option<String>,
}

/// 1. `GET /v1/local/clip?limit=50&before_id=&kind=text|image&q=`
pub(super) async fn handle_list_clips(
    State(state): State<Arc<DaemonState>>,
    Query(q): Query<ListClipQuery>,
) -> Response {
    let limit = q.limit.unwrap_or(CLIP_LOCAL_DEFAULT_PAGE_LIMIT);
    let res = {
        let store = state.store.lock().unwrap();
        let cache = store.clip_cache();
        let stats = store.clip_storage_stats();
        let page = store.list_clip_items_page(&ClipListQuery {
            limit,
            before_id: q.before_id.as_deref(),
            kind: q.kind.as_deref(),
            query: q.q.as_deref(),
        });
        page.and_then(|p| {
            let st = stats?;
            let dtos = p
                .items
                .iter()
                .map(|r| clip_row_to_dto(r, &cache))
                .collect::<Vec<_>>();
            Ok((dtos, p.has_more, p.total_count, st))
        })
    };
    match res {
        Ok((items, has_more, total_count, stats)) => {
            let has_undo = state.clip_undo.lock().unwrap().has_undo();
            let watch = state.clip_watch_snapshot();
            let cloud_quota = state.cloud_clip_quota_snapshot();
            ok_json(serde_json::json!({
                "items": items,
                "has_more": has_more,
                "total_count": total_count,
                "local_blob_bytes": stats.cached_blob_bytes,
                "local_blob_files": stats.cached_blob_files,
                "uncached_blob_items": stats.uncached_blob_items,
                "cloud_quota": cloud_quota,
                "has_undo": has_undo,
                "watch_enabled": watch.watch_enabled,
                "watch_paused": watch.watch_paused,
                "auto_apply_mirror": watch.auto_apply_mirror,
            }))
        }
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
pub(super) struct PostClipBody {
    kind: String,
    text: Option<String>,
    #[serde(default)]
    ephemeral: bool,
    mime: Option<String>,
    data_b64: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
    thumb_mime: Option<String>,
    thumb_b64: Option<String>,
}

/// 2. `POST /v1/local/clip`
pub(super) async fn handle_post_clip(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<PostClipBody>,
) -> Response {
    match post_clip_inner(&state, body).await {
        Ok(val) => ok_json(val),
        Err(e) => core_err_to_response(e),
    }
}

async fn push_text_clip_persisted(
    state: &Arc<DaemonState>,
    text: String,
    source_mode: ClipSourceMode,
) -> Result<ClipItemDto, CoreError> {
    if text.len() > CLIP_BLOB_MAX_BYTES {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            format!(
                "text clip length ({} bytes) exceeds 10 MiB limit ({CLIP_BLOB_MAX_BYTES} bytes)",
                text.len()
            ),
            "Split large text under 10 MiB",
        ));
    }

    let now = now_ms_daemon();
    let (creds_opt, device_id, clip_id) = {
        let mut store = state.store.lock().unwrap();
        let creds = store.load_credentials()?;
        let dev = store.device_id().clone();
        let cid = store.next_clip_id(now as u64)?;
        (creds, dev, cid)
    };

    let is_blob = text.len() > CLIP_INLINE_TEXT_MAX_BYTES;
    let (clip_kid, clip_key) = ensure_local_or_cloud_clip_key(state, creds_opt.as_ref()).await?;

    let (meta, blob_bytes_opt, sha_opt) = if is_blob {
        let raw = text.as_bytes().to_vec();
        let sha = clip_sha256_hex(&raw);
        let preview = truncate_clip_preview(&text);
        let meta = ClipMetaV1 {
            v: 1,
            kind: ClipKind::Text,
            mime: "text/plain".to_string(),
            source_mode,
            created_at_ms: now,
            text: Some(preview),
            blob: Some(ClipBlobMetaV1 {
                byte_size: raw.len() as u64,
                sha256_hex: sha.clone(),
                width: None,
                height: None,
                thumb_mime: None,
                thumb_b64: None,
            }),
        };
        (meta, Some(raw), Some(sha))
    } else {
        let meta = ClipMetaV1 {
            v: 1,
            kind: ClipKind::Text,
            mime: "text/plain".to_string(),
            source_mode,
            created_at_ms: now,
            text: Some(text),
            blob: None,
        };
        (meta, None, None)
    };

    let meta_env = encrypt_mnc1_meta(
        clip_kid,
        &clip_key,
        clip_id,
        &device_id,
        &meta,
        false,
        rand_nonce_24()?,
    )?;
    let mut created_at_ms = now;
    let mut expires_at_ms = now + CLIP_DEFAULT_TTL_MS;

    if let Some(creds) = creds_opt.as_ref() {
        let client = RelayClient::from_credentials(creds)?;
        if let Some(ref raw) = blob_bytes_opt {
            let blob_env =
                encrypt_mnc1_blob(clip_kid, &clip_key, clip_id, &device_id, raw, rand_nonce_24()?)?;
            let rec = client
                .clip_push_blob(
                    &clip_id.to_string(),
                    &clip_kid.to_string(),
                    "text",
                    &meta_env,
                    &blob_env,
                )
                .await?;
            created_at_ms = rec.created_at_ms;
            if rec.expires_at_ms > 0 {
                expires_at_ms = rec.expires_at_ms;
            }
            state.update_cloud_clip_quota(rec.quota);
        } else {
            let rec = client
                .clip_push_meta(
                    &clip_id.to_string(),
                    &clip_kid.to_string(),
                    "text",
                    false,
                    &meta_env,
                )
                .await?;
            if let Some(c) = rec.created_at_ms {
                created_at_ms = c;
            }
            if let Some(e) = rec.expires_at_ms {
                expires_at_ms = e;
            }
            state.update_cloud_clip_quota(rec.quota);
        }
    }

    persist_and_broadcast_local_clip(
        state,
        ClipItemRow {
            clip_id: clip_id.to_string(),
            clip_kid: clip_kid.to_string(),
            device_id: device_id.as_str().to_string(),
            kind: "text".to_string(),
            mime: "text/plain".to_string(),
            source_mode: source_mode.as_str().to_string(),
            created_at_ms,
            expires_at_ms,
            text_preview: meta.text,
            has_blob: blob_bytes_opt.is_some(),
            blob_bytes: blob_bytes_opt.as_ref().map(|b| b.len() as i64),
            blob_sha256: sha_opt,
            width: None,
            height: None,
            thumb_mime: None,
            thumb_blob: None,
            local_blob_path: None,
        },
        blob_bytes_opt.as_deref(),
    )
}

async fn push_image_clip_persisted(
    state: &Arc<DaemonState>,
    mime: &str,
    raw: Vec<u8>,
    width_hint: Option<u32>,
    height_hint: Option<u32>,
    thumb_override: Option<(String, Vec<u8>)>,
    source_mode: ClipSourceMode,
) -> Result<ClipItemDto, CoreError> {
    let b64 = base64::engine::general_purpose::STANDARD;
    validate_clip_image_mime(mime)?;
    if raw.is_empty() {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "image clip payload cannot be empty",
            "Provide valid bitmap bytes",
        ));
    }
    if raw.len() > CLIP_BLOB_MAX_BYTES {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            format!(
                "image clip payload ({} bytes) exceeds 10 MiB limit ({CLIP_BLOB_MAX_BYTES} bytes)",
                raw.len()
            ),
            "Resize or compress the image under 10 MiB",
        ));
    }
    // Defense-in-depth: sniff bytes to guarantee zero SVG smuggling under a bitmap MIME!
    let _sniffed = detect_image_mime_from_bytes_and_path(&raw, None)?;

    let (width, height) = match (width_hint, height_hint) {
        (Some(w), Some(h)) => (Some(w), Some(h)),
        _ => match inspect_image_dimensions(&raw) {
            Some((w, h)) => (Some(w), Some(h)),
            None => (width_hint, height_hint),
        },
    };

    let (thumb_mime, thumb_bytes) = if let Some((tm, tb)) = thumb_override {
        (Some(tm), Some(tb))
    } else if let Some((tm, tb)) = make_thumbnail(&raw, mime) {
        (Some(tm), Some(tb))
    } else {
        (None, None)
    };

    let now = now_ms_daemon();
    let (creds_opt, device_id, clip_id) = {
        let mut store = state.store.lock().unwrap();
        let creds = store.load_credentials()?;
        let dev = store.device_id().clone();
        let cid = store.next_clip_id(now as u64)?;
        (creds, dev, cid)
    };

    let sha = clip_sha256_hex(&raw);
    let meta = ClipMetaV1 {
        v: 1,
        kind: ClipKind::Image,
        mime: mime.to_string(),
        source_mode,
        created_at_ms: now,
        text: None,
        blob: Some(ClipBlobMetaV1 {
            byte_size: raw.len() as u64,
            sha256_hex: sha.clone(),
            width,
            height,
            thumb_mime: thumb_mime.clone(),
            thumb_b64: thumb_bytes.as_ref().map(|b| b64.encode(b)),
        }),
    };

    let (clip_kid, clip_key) = ensure_local_or_cloud_clip_key(state, creds_opt.as_ref()).await?;
    let meta_env = encrypt_mnc1_meta(
        clip_kid,
        &clip_key,
        clip_id,
        &device_id,
        &meta,
        false,
        rand_nonce_24()?,
    )?;
    let blob_env = encrypt_mnc1_blob(clip_kid, &clip_key, clip_id, &device_id, &raw, rand_nonce_24()?)?;

    let mut created_at_ms = now;
    let mut expires_at_ms = now + CLIP_DEFAULT_TTL_MS;
    if let Some(creds) = creds_opt.as_ref() {
        let client = RelayClient::from_credentials(creds)?;
        let rec = client
            .clip_push_blob(
                &clip_id.to_string(),
                &clip_kid.to_string(),
                "image",
                &meta_env,
                &blob_env,
            )
            .await?;
        created_at_ms = rec.created_at_ms;
        if rec.expires_at_ms > 0 {
            expires_at_ms = rec.expires_at_ms;
        }
        state.update_cloud_clip_quota(rec.quota);
    }

    persist_and_broadcast_local_clip(
        state,
        ClipItemRow {
            clip_id: clip_id.to_string(),
            clip_kid: clip_kid.to_string(),
            device_id: device_id.as_str().to_string(),
            kind: "image".to_string(),
            mime: mime.to_string(),
            source_mode: source_mode.as_str().to_string(),
            created_at_ms,
            expires_at_ms,
            text_preview: None,
            has_blob: true,
            blob_bytes: Some(raw.len() as i64),
            blob_sha256: Some(sha),
            width,
            height,
            thumb_mime,
            thumb_blob: thumb_bytes,
            local_blob_path: None,
        },
        Some(&raw),
    )
}

async fn post_clip_inner(
    state: &Arc<DaemonState>,
    body: PostClipBody,
) -> Result<serde_json::Value, CoreError> {
    match body.kind.as_str() {
        "text" => {
            let text = body.text.ok_or_else(|| {
                CoreError::new(
                    ErrorCode::InvalidArgument,
                    "missing required 'text' field for text clip",
                    "Provide { kind: \"text\", text: \"...\" }",
                )
            })?;
            if body.ephemeral {
                if text.len() > CLIP_EPHEMERAL_MAX_BYTES {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        format!(
                            "ephemeral clip text ({} bytes) exceeds 256 KiB limit ({CLIP_EPHEMERAL_MAX_BYTES} bytes)",
                            text.len()
                        ),
                        "Keep ephemeral pushes <= 256 KiB",
                    ));
                }
                let now = now_ms_daemon();
                let (creds_opt, device_id, clip_id) = {
                    let mut store = state.store.lock().unwrap();
                    let creds = store.load_credentials()?;
                    let dev = store.device_id().clone();
                    let cid = store.next_clip_id(now as u64)?;
                    (creds, dev, cid)
                };
                let creds = creds_opt.ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::SyncOffline,
                        "ephemeral clip push requires a configured cloud sync relay",
                        "Configure sync via 'mynote device bootstrap' first",
                    )
                })?;
                let client = RelayClient::from_credentials(&creds)?;
                let (clip_kid, clip_key, _gen) = ensure_clip_key_with_mutex(&state.store, &client).await?;
                let meta = ClipMetaV1 {
                    v: 1,
                    kind: ClipKind::Text,
                    mime: "text/plain".to_string(),
                    source_mode: ClipSourceMode::Explicit,
                    created_at_ms: now,
                    text: Some(text),
                    blob: None,
                };
                let env = encrypt_mnc1_meta(
                    clip_kid,
                    &clip_key,
                    clip_id,
                    &device_id,
                    &meta,
                    true,
                    rand_nonce_24()?,
                )?;
                let receipt = client
                    .clip_push_meta(&clip_id.to_string(), &clip_kid.to_string(), "text", true, &env)
                    .await?;
                return Ok(serde_json::json!({
                    "clip_id": receipt.clip_id,
                    "ephemeral": true,
                    "delivered_to": receipt.delivered_to.unwrap_or(0),
                    "item": serde_json::Value::Null,
                }));
            }

            let dto = push_text_clip_persisted(state, text, ClipSourceMode::Explicit).await?;
            Ok(serde_json::json!({
                "clip_id": dto.clip_id,
                "ephemeral": false,
                "item": dto,
            }))
        }
        "image" => {
            if body.ephemeral {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "ephemeral channel only supports text clips (<= 256 KiB)",
                    "Omit ephemeral: true for bitmap image clips",
                ));
            }
            let mime = body.mime.as_deref().ok_or_else(|| {
                CoreError::new(
                    ErrorCode::InvalidArgument,
                    "missing required 'mime' for image clip",
                    "Specify one of image/png, image/jpeg, image/webp, image/gif",
                )
            })?;
            validate_clip_image_mime(mime)?;

            let data_b64 = body.data_b64.as_deref().ok_or_else(|| {
                CoreError::new(
                    ErrorCode::InvalidArgument,
                    "missing required 'data_b64' for image clip",
                    "Provide standard base64 encoded bitmap image bytes",
                )
            })?;
            let raw = decode_b64_arg("data_b64", data_b64)?;

            let thumb_override = if let Some(tb64) = body.thumb_b64.as_deref() {
                let tm = body.thumb_mime.as_deref().ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::InvalidArgument,
                        "thumb_b64 requires thumb_mime",
                        "Provide thumb_mime (image/jpeg, image/png, image/webp, or image/gif)",
                    )
                })?;
                validate_clip_image_mime(tm)?;
                let tb = decode_b64_arg("thumb_b64", tb64)?;
                if tb.len() > CLIP_THUMB_MAX_BYTES {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        format!(
                            "thumbnail ({} bytes) exceeds 16 KiB limit ({CLIP_THUMB_MAX_BYTES} bytes)",
                            tb.len()
                        ),
                        "Provide a smaller thumbnail or omit thumb_b64 to auto-generate",
                    ));
                }
                if is_svg_bytes(&tb) {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        "SVG thumbnail is strictly forbidden",
                        "Provide a JPEG/PNG/WebP/GIF thumbnail",
                    ));
                }
                Some((tm.to_string(), tb))
            } else {
                None
            };

            let dto = push_image_clip_persisted(
                state,
                mime,
                raw,
                body.width,
                body.height,
                thumb_override,
                ClipSourceMode::Explicit,
            )
            .await?;

            Ok(serde_json::json!({
                "clip_id": dto.clip_id,
                "ephemeral": false,
                "item": dto,
            }))
        }
        other => Err(CoreError::new(
            ErrorCode::InvalidArgument,
            format!("invalid clip kind '{other}'"),
            "Use kind 'text' or 'image'",
        )),
    }
}

async fn ensure_local_or_cloud_clip_key(
    state: &Arc<DaemonState>,
    creds_opt: Option<&mynote_store::DeviceCredentials>,
) -> Result<(ClipKid, zeroize::Zeroizing<[u8; 32]>), CoreError> {
    if let Some(creds) = creds_opt {
        let client = RelayClient::from_credentials(creds)?;
        let (kid, key, _) = ensure_clip_key_with_mutex(&state.store, &client).await?;
        return Ok((kid, key));
    }
    let mut store = state.store.lock().unwrap();
    if let Some((kid, key, _)) = store.unwrap_local_clip_key()? {
        return Ok((kid, key));
    }
    let now = now_ms_daemon() as u64;
    let (kid, key, blob) = store.generate_wrapped_clip_key(now)?;
    store.upsert_clip_key_material(1, &blob, now as i64)?;
    Ok((kid, key))
}

fn persist_and_broadcast_local_clip(
    state: &Arc<DaemonState>,
    mut row: ClipItemRow,
    blob_bytes: Option<&[u8]>,
) -> Result<ClipItemDto, CoreError> {
    let dto = {
        let store = state.store.lock().unwrap();
        let cache = store.clip_cache();
        if let Some(raw) = blob_bytes {
            let rel = clip_blob_cache_name(&row.clip_id, &row.mime);
            let _ = cache.write(&rel, raw)?;
            row.local_blob_path = Some(rel);
        }
        store.upsert_clip_item(&row)?;
        let cur = store.get_clip_cursor();
        if cur.as_deref().is_none_or(|c| row.clip_id.as_str() > c) {
            let _ = store.set_clip_cursor(Some(&row.clip_id));
        }
        clip_row_to_dto(&row, &cache)
    };
    state.broadcast_clip_changed(vec![dto.clone()], Vec::new(), false);
    Ok(dto)
}

/// 3. `GET /v1/local/clip/{clip_id}/blob`
pub(super) async fn handle_get_clip_blob(
    State(state): State<Arc<DaemonState>>,
    AxumPath(clip_id): AxumPath<String>,
) -> Response {
    let row_opt = match state.store.lock().unwrap().get_clip_item(&clip_id) {
        Ok(r) => r,
        Err(e) => return core_err_to_response(e),
    };
    let Some(row) = row_opt else {
        return core_err_to_response(CoreError::new(
            ErrorCode::NotFound,
            format!("clip item '{clip_id}' not found"),
            "Refresh clip history",
        ));
    };
    match state.resolve_clip_payload_bytes(&row).await {
        Ok((bytes, content_type)) => {
            let mut res = (StatusCode::OK, bytes).into_response();
            if let Ok(hv) = HeaderValue::from_str(&content_type) {
                res.headers_mut().insert(HTTP_CONTENT_TYPE, hv);
            }
            res.headers_mut()
                .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
            res.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            res
        }
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize, Default)]
pub(super) struct ClearClipQuery {
    scope: Option<String>,
}

/// 4a. `DELETE /v1/local/clip?scope=local|cloud|all` (defaults to `"all"` when omitted for backwards compatibility)
pub(super) async fn handle_clear_clips(
    State(state): State<Arc<DaemonState>>,
    Query(q): Query<ClearClipQuery>,
) -> Response {
    let scope = q.scope.as_deref().unwrap_or("all");
    if scope != "local" && scope != "cloud" && scope != "all" {
        return core_err_to_response(CoreError::new(
            ErrorCode::InvalidArgument,
            format!("invalid clip clear scope '{scope}'"),
            "Use scope 'local', 'cloud', or 'all'",
        ));
    }

    let mut cloud_deleted = 0usize;
    let mut cloud_freed = 0u64;
    if scope == "cloud" || scope == "all" {
        let creds_opt = match state.store.lock().unwrap().load_credentials() {
            Ok(c) => c,
            Err(e) => return core_err_to_response(e),
        };
        if let Some(creds) = creds_opt {
            let client = match RelayClient::from_credentials(&creds) {
                Ok(c) => c,
                Err(e) => return core_err_to_response(e),
            };
            let relay_scope = if scope == "all" { "all" } else { "cloud" };
            match client.clip_delete_scoped(None, Some(relay_scope)).await {
                Ok(rec) => {
                    cloud_deleted = rec.deleted_count;
                    cloud_freed = rec.freed_bytes;
                    state.update_cloud_clip_quota(rec.quota);
                }
                Err(e) => return core_err_to_response(e),
            }
            if scope == "cloud" {
                let _ = state.store.lock().unwrap().set_clip_cursor(None);
            }
        }
    }

    let mut local_deleted = 0usize;
    let mut local_freed = 0u64;
    if scope == "local" || scope == "all" {
        let store = state.store.lock().unwrap();
        let (_, bytes_before) = store.clip_cache().stats();
        match store.clear_clip_items() {
            Ok((n, _)) => {
                let _ = store.clip_cache().clear();
                local_deleted = n;
                local_freed = bytes_before;
            }
            Err(e) => return core_err_to_response(e),
        }
    }

    state.broadcast_clip_changed(Vec::new(), Vec::new(), scope != "cloud");
    ok_json(serde_json::json!({
        "scope": scope,
        "deleted_count": cloud_deleted.max(local_deleted),
        "local_deleted": local_deleted,
        "cloud_deleted": cloud_deleted,
        "freed_bytes": local_freed.max(cloud_freed),
        "cloud_quota": state.cloud_clip_quota_snapshot(),
    }))
}

#[derive(Deserialize, Default)]
pub(super) struct PruneClipsBody {
    scope: Option<String>,
    before_days: Option<u64>,
    before_ms: Option<i64>,
    keep_latest: Option<usize>,
    kind: Option<String>,
    #[serde(default)]
    dry_run: bool,
}

/// 4c. `POST /v1/local/clip/prune`
pub(super) async fn handle_prune_clips(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<PruneClipsBody>,
) -> Response {
    let scope = body.scope.as_deref().unwrap_or("local");
    if scope != "local" && scope != "cloud" && scope != "all" {
        return core_err_to_response(CoreError::new(
            ErrorCode::InvalidArgument,
            format!("invalid prune scope '{scope}'"),
            "Use scope 'local', 'cloud', or 'all'",
        ));
    }
    if let Some(ref k) = body.kind {
        if k != "text" && k != "image" {
            return core_err_to_response(CoreError::new(
                ErrorCode::InvalidArgument,
                format!("invalid prune kind '{k}'"),
                "Use kind 'text' or 'image'",
            ));
        }
    }
    let effective_before_ms = match (body.before_ms, body.before_days) {
        (Some(ms), _) => Some(ms),
        (None, Some(days)) => {
            if days == 0 {
                return core_err_to_response(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "before_days must be >= 1",
                    "Pass before_days >= 1 or use DELETE /v1/local/clip to clear all",
                ));
            }
            Some(now_ms_daemon().saturating_sub((days as i64).saturating_mul(86_400_000)))
        }
        (None, None) => None,
    };
    if effective_before_ms.is_none() && body.keep_latest.is_none() && body.kind.is_none() {
        return core_err_to_response(CoreError::new(
            ErrorCode::InvalidArgument,
            "at least one of before_days, before_ms, keep_latest, or kind is required",
            "Specify a prune criterion or use DELETE /v1/local/clip to clear all",
        ));
    }

    let mut local_res = None;
    let mut local_deleted_ids = Vec::new();
    if scope == "local" || scope == "all" {
        let filter = ClipPruneFilter {
            before_ms: effective_before_ms,
            keep_latest: body.keep_latest,
            kind: body.kind.clone(),
            dry_run: body.dry_run,
        };
        match state.store.lock().unwrap().prune_clip_items(&filter) {
            Ok(r) => {
                local_deleted_ids = r.deleted_ids.clone();
                local_res = Some(r);
            }
            Err(e) => return core_err_to_response(e),
        }
    }

    let mut cloud_res = None;
    if scope == "cloud" || scope == "all" {
        let creds_opt = match state.store.lock().unwrap().load_credentials() {
            Ok(c) => c,
            Err(e) => return core_err_to_response(e),
        };
        if let Some(creds) = creds_opt {
            let client = match RelayClient::from_credentials(&creds) {
                Ok(c) => c,
                Err(e) => return core_err_to_response(e),
            };
            match client
                .clip_prune(
                    effective_before_ms,
                    body.keep_latest,
                    body.kind.as_deref(),
                    body.dry_run,
                )
                .await
            {
                Ok(rec) => {
                    state.update_cloud_clip_quota(rec.quota.clone());
                    cloud_res = Some(rec);
                }
                Err(e) => return core_err_to_response(e),
            }
        } else if scope == "cloud" {
            return core_err_to_response(CoreError::new(
                ErrorCode::SyncOffline,
                "cloud sync relay is not configured",
                "Configure cloud sync or prune local scope instead",
            ));
        }
    }

    if !body.dry_run
        && (!local_deleted_ids.is_empty() || cloud_res.as_ref().is_some_and(|c| c.deleted_count > 0))
    {
        state.broadcast_clip_changed(Vec::new(), local_deleted_ids, false);
    }

    let matched_count = local_res
        .as_ref()
        .map(|r| r.matched_count)
        .unwrap_or(0)
        .max(cloud_res.as_ref().map(|r| r.matched_count).unwrap_or(0));
    let deleted_count = local_res
        .as_ref()
        .map(|r| r.deleted_count)
        .unwrap_or(0)
        .max(cloud_res.as_ref().map(|r| r.deleted_count).unwrap_or(0));
    let freed_bytes = local_res
        .as_ref()
        .map(|r| r.freed_bytes)
        .unwrap_or(0)
        .max(cloud_res.as_ref().map(|r| r.freed_bytes).unwrap_or(0));

    ok_json(serde_json::json!({
        "dry_run": body.dry_run,
        "scope": scope,
        "matched_count": matched_count,
        "deleted_count": deleted_count,
        "freed_bytes": freed_bytes,
        "local": local_res,
        "cloud": cloud_res,
        "cloud_quota": state.cloud_clip_quota_snapshot(),
    }))
}

/// 4b. `DELETE /v1/local/clip/{clip_id}`
pub(super) async fn handle_delete_clip(
    State(state): State<Arc<DaemonState>>,
    AxumPath(clip_id): AxumPath<String>,
) -> Response {
    let creds_opt = match state.store.lock().unwrap().load_credentials() {
        Ok(c) => c,
        Err(e) => return core_err_to_response(e),
    };
    let mut cloud_deleted = 0usize;
    if let Some(creds) = creds_opt {
        let client = match RelayClient::from_credentials(&creds) {
            Ok(c) => c,
            Err(e) => return core_err_to_response(e),
        };
        match client.clip_delete_scoped(Some(&clip_id), None).await {
            Ok(rec) => {
                cloud_deleted = rec.deleted_count;
                state.update_cloud_clip_quota(rec.quota);
            }
            Err(e) => return core_err_to_response(e),
        }
    }
    let local_existed = {
        let store = state.store.lock().unwrap();
        match store.delete_clip_item(&clip_id) {
            Ok((existed, blob_path)) => {
                if let Some(rel) = blob_path {
                    let _ = store.clip_cache().delete(&rel);
                }
                existed
            }
            Err(e) => return core_err_to_response(e),
        }
    };
    let deleted_count = cloud_deleted.max(usize::from(local_existed));
    if deleted_count > 0 {
        state.broadcast_clip_changed(Vec::new(), vec![clip_id], false);
    }
    ok_json(serde_json::json!({ "deleted_count": deleted_count }))
}

/// 5. `POST /v1/local/clip/{clip_id}/apply`
pub(super) async fn handle_apply_clip(
    State(state): State<Arc<DaemonState>>,
    AxumPath(clip_id): AxumPath<String>,
) -> Response {
    match state.apply_clip_by_id(&clip_id).await {
        Ok(has_undo) => ok_json(serde_json::json!({
            "applied": true,
            "clip_id": clip_id,
            "has_undo": has_undo,
        })),
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize, Default)]
pub(super) struct PromoteClipBody {
    buffer_id: Option<String>,
    lang: Option<String>,
}

/// 6. `POST /v1/local/clip/{clip_id}/promote`
pub(super) async fn handle_promote_clip(
    State(state): State<Arc<DaemonState>>,
    AxumPath(clip_id): AxumPath<String>,
    body: Option<Json<PromoteClipBody>>,
) -> Response {
    let opts = body.map(|b| b.0).unwrap_or_default();
    let row_opt = match state.store.lock().unwrap().get_clip_item(&clip_id) {
        Ok(r) => r,
        Err(e) => return core_err_to_response(e),
    };
    let Some(row) = row_opt else {
        return core_err_to_response(CoreError::new(
            ErrorCode::NotFound,
            format!("clip item '{clip_id}' not found"),
            "Refresh clip history and retry",
        ));
    };
    if row.kind != "text" {
        return core_err_to_response(CoreError::new(
            ErrorCode::InvalidArgument,
            format!("cannot promote image clip '{clip_id}' to a text note block"),
            format!("Download or export images instead (e.g. 'mynote clip pull {clip_id} --out <path>')"),
        ));
    }
    let (bytes, _) = match state.resolve_clip_payload_bytes(&row).await {
        Ok(v) => v,
        Err(e) => return core_err_to_response(e),
    };
    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(e) => {
            return core_err_to_response(CoreError::new(
                ErrorCode::IntegrityError,
                format!("clip text is not valid UTF-8: {e}"),
                "Inspect clip payload",
            ));
        }
    };
    let target_buf = opts
        .buffer_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("scratch");
    let effective_lang = opts
        .lang
        .clone()
        .unwrap_or_else(|| mynote_store::store::sniff_language(&text));
    let res = {
        let mut store = state.store.lock().unwrap();
        store
            .add_block(target_buf, &text, Some(&effective_lang), None, "human", None)
            .and_then(|r| store.get_block_for_daemon(&r.block_id))
    };
    match res {
        Ok(block) => {
            state.broadcast_block_upserted(&block.id);
            state.sync_notify.notify_one();
            ok_json(serde_json::json!({ "block": block }))
        }
        Err(e) => core_err_to_response(e),
    }
}

/// 7. `POST /v1/local/clip/undo`
pub(super) async fn handle_undo_clip(State(state): State<Arc<DaemonState>>) -> Response {
    match state.undo_clipboard() {
        Ok(restored) => ok_json(serde_json::json!({ "restored": restored })),
        Err(e) => core_err_to_response(e),
    }
}

#[derive(Deserialize)]
pub(super) struct PatchClipWatchBody {
    paused: Option<bool>,
    enabled: Option<bool>,
    auto_apply_mirror: Option<String>,
}

/// 8. `PATCH /v1/local/clip/watch`
pub(super) async fn handle_patch_clip_watch(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<PatchClipWatchBody>,
) -> Response {
    match state.update_clip_watch(body.paused, body.enabled, body.auto_apply_mirror) {
        Ok(cfg) => ok_json(cfg),
        Err(e) => core_err_to_response(e),
    }
}

// ---------------------------------------------------------------------------
// UDS Clip Dispatch Helpers
// ---------------------------------------------------------------------------

pub(super) async fn dispatch_uds_clip_undo(state: &Arc<DaemonState>) -> UdsResponse {
    match state.undo_clipboard() {
        Ok(restored) => UdsResponse {
            ok: true,
            version: Some(state.version.to_string()),
            pid: None,
            port: None,
            url: None,
            head_seq: None,
            sync_state: None,
            pending_ops: None,
            data: Some(serde_json::json!({ "restored": restored })),
            error: None,
        },
        Err(e) => UdsResponse::from_core_error(&e),
    }
}

pub(super) async fn dispatch_uds_clip_apply(state: &Arc<DaemonState>, clip_id: &str) -> UdsResponse {
    match state.apply_clip_by_id(clip_id).await {
        Ok(has_undo) => UdsResponse {
            ok: true,
            version: Some(state.version.to_string()),
            pid: None,
            port: None,
            url: None,
            head_seq: None,
            sync_state: None,
            pending_ops: None,
            data: Some(serde_json::json!({
                "applied": true,
                "clip_id": clip_id,
                "has_undo": has_undo,
            })),
            error: None,
        },
        Err(e) => UdsResponse::from_core_error(&e),
    }
}

pub(super) async fn dispatch_uds_clip_poke(
    state: &Arc<DaemonState>,
    clip_id: Option<String>,
    cleared: bool,
) -> UdsResponse {
    if cleared {
        state.broadcast_clip_changed(Vec::new(), Vec::new(), true);
    } else if let Some(cid) = clip_id {
        let dto_opt = {
            let store = state.store.lock().unwrap();
            let cache = store.clip_cache();
            store
                .get_clip_item(&cid)
                .ok()
                .flatten()
                .map(|r| clip_row_to_dto(&r, &cache))
        };
        if let Some(dto) = dto_opt {
            state.broadcast_clip_changed(vec![dto], Vec::new(), false);
        }
    } else {
        let st = Arc::clone(state);
        tokio::spawn(async move {
            let _ = st.pull_cloud_clips(false).await;
            st.spawn_clip_blob_prefetch();
        });
    }
    UdsResponse {
        ok: true,
        version: Some(state.version.to_string()),
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

pub(super) fn dispatch_uds_clip_watch_set(
    state: &Arc<DaemonState>,
    paused: Option<bool>,
    enabled: Option<bool>,
    auto_apply_mirror: Option<String>,
) -> UdsResponse {
    match state.update_clip_watch(paused, enabled, auto_apply_mirror) {
        Ok(cfg) => UdsResponse {
            ok: true,
            version: Some(state.version.to_string()),
            pid: None,
            port: None,
            url: None,
            head_seq: None,
            sync_state: None,
            pending_ops: None,
            data: serde_json::to_value(cfg).ok(),
            error: None,
        },
        Err(e) => UdsResponse::from_core_error(&e),
    }
}
