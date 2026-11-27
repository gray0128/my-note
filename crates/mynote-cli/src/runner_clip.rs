//! CLI `mynote clip` subcommand execution (`docs/interface-contracts.md` §2.3, `M4a-3`).

use super::*;
use crate::cli::ClipCommand;
use crate::clip_watch::{load_persisted_watch_config, persist_watch_config, validate_auto_apply_mirror};
use crate::clipboard::{
    default_system_clipboard, detect_image_mime_from_bytes_and_path, inspect_image_dimensions, is_svg_bytes,
    make_thumbnail, ClipboardPayload, ClipboardWriteOpts, ReadClipboardResult,
};
use crate::daemon::{clip_blob_cache_name, truncate_clip_preview};
use crate::sync_client::{ensure_clip_key, refresh_clip_key_from_remote, rotate_clip_key, RemoteClipItem};
use mynote_core::clip::{
    clip_sha256_hex, decrypt_mnc1_blob, decrypt_mnc1_meta, encrypt_mnc1_blob, encrypt_mnc1_meta,
    validate_clip_image_mime, verify_clip_blob_sha256, ClipBlobMetaV1, ClipKind, ClipMetaV1, ClipSourceMode,
    CLIP_BLOB_MAX_BYTES, CLIP_DEFAULT_TTL_MS, CLIP_EPHEMERAL_MAX_BYTES, CLIP_INLINE_TEXT_MAX_BYTES,
};
use mynote_core::ids::{ClipId, ClipKid};
use mynote_store::{ClipItemRow, CLIP_LOCAL_MAX_ITEMS};
use serde::Serialize;

#[derive(Serialize)]
struct ClipHistorySummaryDto {
    clip_id: String,
    clip_kid: String,
    device_id: String,
    kind: String,
    mime: String,
    source_mode: String,
    created_at_ms: i64,
    expires_at_ms: i64,
    text_preview: Option<String>,
    has_blob: bool,
    blob_bytes: Option<i64>,
    width: Option<u32>,
    height: Option<u32>,
    has_thumb: bool,
    cached_locally: bool,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_clip(
    store: &mut LocalStore,
    action: ClipCommand,
    actor: &str,
    non_interactive: bool,
    mode: OutputMode,
    started: Instant,
    quiet: bool,
) -> Result<i32, CoreError> {
    match action {
        #[cfg(target_os = "linux")]
        ClipCommand::ServeWayland => unreachable!("handled prior to opening store"),

        ClipCommand::Push {
            stdin,
            text,
            file,
            ephemeral,
            wait_sync: _,
        } => {
            let source_count = usize::from(stdin) + usize::from(text.is_some()) + usize::from(file.is_some());
            if source_count > 1 {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "specify at most one of --stdin, --text, or --file",
                    "Omit all three to read from the system clipboard, or pass exactly one input flag",
                ));
            }
            if ephemeral && file.is_some() {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "--ephemeral only supports inline UTF-8 text (<= 256 KiB), not --file images",
                    "Omit --ephemeral to push bitmap image files",
                ));
            }

            let payload = if stdin {
                let mut s = String::new();
                io::stdin().read_to_string(&mut s).map_err(|e| {
                    CoreError::new(
                        ErrorCode::InvalidArgument,
                        format!("failed reading UTF-8 text from stdin: {e}"),
                        "Pipe valid UTF-8 text into 'mynote clip push --stdin'",
                    )
                })?;
                ClipboardPayload::Text(s)
            } else if let Some(s) = text {
                ClipboardPayload::Text(s)
            } else if let Some(path) = file {
                let bytes = std::fs::read(&path).map_err(|e| {
                    CoreError::new(
                        ErrorCode::InvalidArgument,
                        format!("cannot read clip image '{}': {e}", path.display()),
                        "Verify the file path and permissions",
                    )
                })?;
                if bytes.is_empty() {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        format!("clip image '{}' is empty", path.display()),
                        "Provide a valid PNG, JPEG, WebP, or GIF image",
                    ));
                }
                if bytes.len() > CLIP_BLOB_MAX_BYTES {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        format!(
                            "clip image '{}' ({} bytes) exceeds 10 MiB limit ({CLIP_BLOB_MAX_BYTES} bytes)",
                            path.display(),
                            bytes.len()
                        ),
                        "Resize or compress the image under 10 MiB",
                    ));
                }
                let mime = detect_image_mime_from_bytes_and_path(&bytes, Some(&path))?;
                let dims = inspect_image_dimensions(&bytes);
                ClipboardPayload::Image {
                    mime: mime.to_string(),
                    bytes,
                    width: dims.map(|d| d.0),
                    height: dims.map(|d| d.1),
                }
            } else {
                let clip = default_system_clipboard();
                match clip.read()? {
                    ReadClipboardResult::Payload(p) => p,
                    ReadClipboardResult::Empty => {
                        return Err(CoreError::new(
                            ErrorCode::InvalidArgument,
                            "system clipboard is empty",
                            "Copy text or a bitmap image first, or pass --text / --stdin / --file",
                        ));
                    }
                    ReadClipboardResult::SkippedSensitive(reason) => {
                        return Err(CoreError::new(
                            ErrorCode::InvalidArgument,
                            format!("refusing to push sensitive or already-synced clipboard item ({reason})"),
                            "Use --text or --stdin explicitly if you intend to share this text",
                        ));
                    }
                }
            };

            let Some(creds) = store.load_credentials()? else {
                return Err(CoreError::new(
                    ErrorCode::SyncOffline,
                    "sync relay is offline or not configured on this device",
                    "Configure Cloudflare relay via 'mynote device bootstrap --url <https://...>' before using 'mynote clip push'",
                ));
            };
            let client = RelayClient::from_credentials(&creds)?;
            let (clip_kid, clip_key, _gen) = run_async(ensure_clip_key(store, &client))?;
            let now = now_ms_cli();
            let clip_id = store.next_clip_id(now)?;
            let device_id = store.device_id().clone();

            if ephemeral {
                let ClipboardPayload::Text(s) = payload else {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        "--ephemeral only supports text payloads (<= 256 KiB)",
                        "Omit --ephemeral when pushing images",
                    ));
                };
                if s.len() > CLIP_EPHEMERAL_MAX_BYTES {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        format!(
                            "ephemeral text ({} bytes) exceeds 256 KiB limit ({CLIP_EPHEMERAL_MAX_BYTES} bytes)",
                            s.len()
                        ),
                        "Keep --ephemeral payloads <= 256 KiB",
                    ));
                }
                let meta = ClipMetaV1 {
                    v: 1,
                    kind: ClipKind::Text,
                    mime: "text/plain".to_string(),
                    source_mode: ClipSourceMode::Explicit,
                    created_at_ms: now as i64,
                    text: Some(s),
                    blob: None,
                };
                let env = encrypt_mnc1_meta(
                    clip_kid,
                    &clip_key,
                    clip_id,
                    &device_id,
                    &meta,
                    true,
                    rand_bytes_cli::<24>()?,
                )?;
                let rec = run_async(client.clip_push_meta(
                    &clip_id.to_string(),
                    &clip_kid.to_string(),
                    "text",
                    true,
                    &env,
                ))?;
                // ZERO local DB and ZERO clip_cache writes for ephemeral pushes!
                let out = serde_json::json!({
                    "clip_id": rec.clip_id,
                    "clip_kid": clip_kid.to_string(),
                    "kind": "text",
                    "ephemeral": true,
                    "delivered_to": rec.delivered_to.unwrap_or(0),
                });
                match mode {
                    OutputMode::Json | OutputMode::Jsonl => {
                        emit_json(out, store_meta(store, started, None));
                    }
                    OutputMode::Human => println!(
                        "pushed ephemeral clip {} (delivered_to={}, zero disk storage)",
                        rec.clip_id,
                        rec.delivered_to.unwrap_or(0)
                    ),
                }
                return Ok(0);
            }

            let b64 = base64::engine::general_purpose::STANDARD;
            let (row, raw_blob_opt) = match payload {
                ClipboardPayload::Text(s) => {
                    if s.len() > CLIP_BLOB_MAX_BYTES {
                        return Err(CoreError::new(
                            ErrorCode::InvalidArgument,
                            format!(
                                "text clip ({} bytes) exceeds 10 MiB limit ({CLIP_BLOB_MAX_BYTES} bytes)",
                                s.len()
                            ),
                            "Split text under 10 MiB",
                        ));
                    }
                    let is_blob = s.len() > CLIP_INLINE_TEXT_MAX_BYTES;
                    let (meta, raw_opt, sha_opt) = if is_blob {
                        let raw = s.as_bytes().to_vec();
                        let sha = clip_sha256_hex(&raw);
                        let preview = truncate_clip_preview(&s);
                        let meta = ClipMetaV1 {
                            v: 1,
                            kind: ClipKind::Text,
                            mime: "text/plain".to_string(),
                            source_mode: ClipSourceMode::Explicit,
                            created_at_ms: now as i64,
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
                            source_mode: ClipSourceMode::Explicit,
                            created_at_ms: now as i64,
                            text: Some(s),
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
                        rand_bytes_cli::<24>()?,
                    )?;
                    let (created_at_ms, expires_at_ms) = if let Some(ref raw) = raw_opt {
                        let blob_env = encrypt_mnc1_blob(
                            clip_kid,
                            &clip_key,
                            clip_id,
                            &device_id,
                            raw,
                            rand_bytes_cli::<24>()?,
                        )?;
                        let rec = run_async(client.clip_push_blob(
                            &clip_id.to_string(),
                            &clip_kid.to_string(),
                            "text",
                            &meta_env,
                            &blob_env,
                        ))?;
                        (
                            rec.created_at_ms,
                            if rec.expires_at_ms > 0 {
                                rec.expires_at_ms
                            } else {
                                rec.created_at_ms + CLIP_DEFAULT_TTL_MS
                            },
                        )
                    } else {
                        let rec = run_async(client.clip_push_meta(
                            &clip_id.to_string(),
                            &clip_kid.to_string(),
                            "text",
                            false,
                            &meta_env,
                        ))?;
                        let created = rec.created_at_ms.unwrap_or(now as i64);
                        let expires = rec.expires_at_ms.unwrap_or(created + CLIP_DEFAULT_TTL_MS);
                        (created, expires)
                    };
                    let row = ClipItemRow {
                        clip_id: clip_id.to_string(),
                        clip_kid: clip_kid.to_string(),
                        device_id: device_id.as_str().to_string(),
                        kind: "text".to_string(),
                        mime: "text/plain".to_string(),
                        source_mode: "explicit".to_string(),
                        created_at_ms,
                        expires_at_ms,
                        text_preview: meta.text,
                        has_blob: raw_opt.is_some(),
                        blob_bytes: raw_opt.as_ref().map(|b| b.len() as i64),
                        blob_sha256: sha_opt,
                        width: None,
                        height: None,
                        thumb_mime: None,
                        thumb_blob: None,
                        local_blob_path: None,
                    };
                    (row, raw_opt)
                }
                ClipboardPayload::Image {
                    mime,
                    bytes,
                    width,
                    height,
                } => {
                    validate_clip_image_mime(&mime)?;
                    if bytes.is_empty() || bytes.len() > CLIP_BLOB_MAX_BYTES {
                        return Err(CoreError::new(
                            ErrorCode::InvalidArgument,
                            format!(
                                "image payload ({} bytes) must be in 1..={CLIP_BLOB_MAX_BYTES}",
                                bytes.len()
                            ),
                            "Provide a valid bitmap image <= 10 MiB",
                        ));
                    }
                    if is_svg_bytes(&bytes) {
                        return Err(CoreError::new(
                            ErrorCode::InvalidArgument,
                            "disallowed image/svg+xml payload",
                            "Sync SVG as plain text via --stdin or --text",
                        ));
                    }
                    let (w, h) = match (width, height) {
                        (Some(w), Some(h)) => (Some(w), Some(h)),
                        _ => match inspect_image_dimensions(&bytes) {
                            Some((w, h)) => (Some(w), Some(h)),
                            None => (width, height),
                        },
                    };
                    let (thumb_mime, thumb_bytes) = match make_thumbnail(&bytes, &mime) {
                        Some((tm, tb)) => (Some(tm), Some(tb)),
                        None => (None, None),
                    };
                    let sha = clip_sha256_hex(&bytes);
                    let meta = ClipMetaV1 {
                        v: 1,
                        kind: ClipKind::Image,
                        mime: mime.clone(),
                        source_mode: ClipSourceMode::Explicit,
                        created_at_ms: now as i64,
                        text: None,
                        blob: Some(ClipBlobMetaV1 {
                            byte_size: bytes.len() as u64,
                            sha256_hex: sha.clone(),
                            width: w,
                            height: h,
                            thumb_mime: thumb_mime.clone(),
                            thumb_b64: thumb_bytes.as_ref().map(|b| b64.encode(b)),
                        }),
                    };
                    let meta_env = encrypt_mnc1_meta(
                        clip_kid,
                        &clip_key,
                        clip_id,
                        &device_id,
                        &meta,
                        false,
                        rand_bytes_cli::<24>()?,
                    )?;
                    let blob_env = encrypt_mnc1_blob(
                        clip_kid,
                        &clip_key,
                        clip_id,
                        &device_id,
                        &bytes,
                        rand_bytes_cli::<24>()?,
                    )?;
                    let rec = run_async(client.clip_push_blob(
                        &clip_id.to_string(),
                        &clip_kid.to_string(),
                        "image",
                        &meta_env,
                        &blob_env,
                    ))?;
                    let expires = if rec.expires_at_ms > 0 {
                        rec.expires_at_ms
                    } else {
                        rec.created_at_ms + CLIP_DEFAULT_TTL_MS
                    };
                    let row = ClipItemRow {
                        clip_id: clip_id.to_string(),
                        clip_kid: clip_kid.to_string(),
                        device_id: device_id.as_str().to_string(),
                        kind: "image".to_string(),
                        mime,
                        source_mode: "explicit".to_string(),
                        created_at_ms: rec.created_at_ms,
                        expires_at_ms: expires,
                        text_preview: None,
                        has_blob: true,
                        blob_bytes: Some(bytes.len() as i64),
                        blob_sha256: Some(sha),
                        width: w,
                        height: h,
                        thumb_mime,
                        thumb_blob: thumb_bytes,
                        local_blob_path: None,
                    };
                    (row, Some(bytes))
                }
            };

            let mut stored_row = row;
            let cache = store.clip_cache();
            if let Some(ref raw) = raw_blob_opt {
                let rel = clip_blob_cache_name(&stored_row.clip_id, &stored_row.mime);
                let _ = cache.write(&rel, raw)?;
                stored_row.local_blob_path = Some(rel);
            }
            store.upsert_clip_item(&stored_row)?;
            let cur = store.get_clip_cursor();
            if cur.as_deref().is_none_or(|c| stored_row.clip_id.as_str() > c) {
                let _ = store.set_clip_cursor(Some(&stored_row.clip_id));
            }
            for evicted in store.trim_clip_items(CLIP_LOCAL_MAX_ITEMS)? {
                let _ = cache.delete(&evicted);
            }
            let _ = try_send_uds(
                store.data_dir(),
                &UdsRequest::ClipPoke {
                    clip_id: Some(stored_row.clip_id.clone()),
                    cleared: false,
                },
                Duration::from_secs(2),
            );

            let out = serde_json::json!({
                "clip_id": stored_row.clip_id,
                "clip_kid": stored_row.clip_kid,
                "kind": stored_row.kind,
                "mime": stored_row.mime,
                "has_blob": stored_row.has_blob,
                "blob_bytes": stored_row.blob_bytes,
                "width": stored_row.width,
                "height": stored_row.height,
                "created_at_ms": stored_row.created_at_ms,
                "expires_at_ms": stored_row.expires_at_ms,
                "ephemeral": false,
            });
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(out, store_meta(store, started, None));
                }
                OutputMode::Human => println!(
                    "pushed clip {} ({}, {}{})",
                    stored_row.clip_id,
                    stored_row.kind,
                    stored_row.mime,
                    stored_row
                        .blob_bytes
                        .map(|n| format!(", {n} bytes"))
                        .unwrap_or_default()
                ),
            }
            Ok(0)
        }

        ClipCommand::Pull {
            clip_id,
            apply,
            raw,
            out,
        } => {
            let Some(creds) = store.load_credentials()? else {
                return Err(CoreError::new(
                    ErrorCode::SyncOffline,
                    "sync relay is offline or not configured on this device",
                    "Configure Cloudflare relay via 'mynote device bootstrap' before using 'mynote clip pull'",
                ));
            };
            let client = RelayClient::from_credentials(&creds)?;
            let _ = run_async(sync_cloud_clips_cli(store, &client))?;

            let row = match clip_id.as_deref() {
                Some(id) => store.get_clip_item(id)?,
                None => store.latest_clip_item()?,
            }
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::NotFound,
                    match clip_id {
                        Some(ref id) => format!("clip item '{id}' not found"),
                        None => "no clipboard items available".to_string(),
                    },
                    "Push a clip first with 'mynote clip push'",
                )
            })?;

            let payload_bytes = resolve_clip_bytes_cli(store, Some(&client), &row)?;

            if let Some(ref out_path) = out {
                std::fs::write(out_path, &payload_bytes).map_err(|e| {
                    CoreError::new(
                        ErrorCode::InvalidArgument,
                        format!("cannot write clip output '{}': {e}", out_path.display()),
                        "Verify destination path and permissions",
                    )
                })?;
            }

            if apply {
                let mut applied_via_daemon = false;
                if let Some(resp) = try_send_uds(
                    store.data_dir(),
                    &UdsRequest::ClipApply {
                        clip_id: row.clip_id.clone(),
                    },
                    Duration::from_secs(5),
                )? {
                    if !resp.ok {
                        return Err(resp.into_core_error());
                    }
                    applied_via_daemon = true;
                }
                if !applied_via_daemon {
                    let clip_payload = if row.kind == "image" {
                        validate_clip_image_mime(&row.mime)?;
                        ClipboardPayload::Image {
                            mime: row.mime.clone(),
                            bytes: payload_bytes.clone(),
                            width: row.width,
                            height: row.height,
                        }
                    } else {
                        let s = String::from_utf8(payload_bytes.clone()).map_err(|e| {
                            CoreError::new(
                                ErrorCode::IntegrityError,
                                format!("clip text is not valid UTF-8: {e}"),
                                "Inspect clip payload",
                            )
                        })?;
                        ClipboardPayload::Text(s)
                    };
                    let opts = ClipboardWriteOpts {
                        synced_marker: true,
                        sensitive: false,
                        ephemeral: false,
                    };
                    #[cfg(target_os = "linux")]
                    {
                        if std::env::var("MYNOTE_CLIPBOARD_MOCK_FILE")
                            .ok()
                            .filter(|s| !s.trim().is_empty())
                            .is_some()
                        {
                            default_system_clipboard().write(&clip_payload, opts)?;
                        } else {
                            crate::clipboard::write_detached_for_standalone_cli(&clip_payload, opts)?;
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        default_system_clipboard().write(&clip_payload, opts)?;
                    }
                }
            }

            if raw {
                let mut stdout = io::stdout().lock();
                let _ = stdout.write_all(&payload_bytes);
                let _ = stdout.flush();
                return Ok(0);
            }

            let text_val = if row.kind == "text" {
                String::from_utf8(payload_bytes.clone()).ok()
            } else {
                None
            };
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(
                        serde_json::json!({
                            "clip_id": row.clip_id,
                            "clip_kid": row.clip_kid,
                            "device_id": row.device_id,
                            "kind": row.kind,
                            "mime": row.mime,
                            "source_mode": row.source_mode,
                            "created_at_ms": row.created_at_ms,
                            "expires_at_ms": row.expires_at_ms,
                            "byte_size": payload_bytes.len(),
                            "width": row.width,
                            "height": row.height,
                            "applied": apply,
                            "out_path": out.as_ref().map(|p| p.display().to_string()),
                            "text": text_val,
                        }),
                        store_meta(store, started, None),
                    );
                }
                OutputMode::Human => {
                    if let Some(ref s) = text_val {
                        if !apply && out.is_none() {
                            println!("{s}");
                        } else {
                            println!(
                                "pulled clip {} (text, {} bytes{}{})",
                                row.clip_id,
                                payload_bytes.len(),
                                if apply { ", applied to clipboard" } else { "" },
                                out.as_ref()
                                    .map(|p| format!(", saved to {}", p.display()))
                                    .unwrap_or_default()
                            );
                        }
                    } else {
                        println!(
                            "pulled clip {} ({}, {} bytes{}{})",
                            row.clip_id,
                            row.mime,
                            payload_bytes.len(),
                            if apply { ", applied to clipboard" } else { "" },
                            out.as_ref()
                                .map(|p| format!(", saved to {}", p.display()))
                                .unwrap_or_default()
                        );
                    }
                }
            }
            Ok(0)
        }

        ClipCommand::History { limit, kind } => {
            let cache = store.clip_cache();
            for expired in store.prune_expired_clip_items(now_ms_cli() as i64)? {
                let _ = cache.delete(&expired);
            }
            let rows = store.list_clip_items(limit, kind.as_deref())?;
            let summaries: Vec<ClipHistorySummaryDto> = rows
                .iter()
                .map(|r| ClipHistorySummaryDto {
                    clip_id: r.clip_id.clone(),
                    clip_kid: r.clip_kid.clone(),
                    device_id: r.device_id.clone(),
                    kind: r.kind.clone(),
                    mime: r.mime.clone(),
                    source_mode: r.source_mode.clone(),
                    created_at_ms: r.created_at_ms,
                    expires_at_ms: r.expires_at_ms,
                    text_preview: r.text_preview.as_deref().map(truncate_clip_preview),
                    has_blob: r.has_blob,
                    blob_bytes: r.blob_bytes,
                    width: r.width,
                    height: r.height,
                    has_thumb: r.thumb_blob.is_some(),
                    cached_locally: if !r.has_blob {
                        true
                    } else {
                        r.local_blob_path.as_deref().is_some_and(|p| cache.exists(p))
                    },
                })
                .collect();
            match mode {
                OutputMode::Json => emit_json(&summaries, store_meta(store, started, None)),
                OutputMode::Jsonl => emit_jsonl(&summaries),
                OutputMode::Human => {
                    if summaries.is_empty() {
                        println!("(no clip history items)");
                    } else {
                        for item in &summaries {
                            let detail = if item.kind == "image" {
                                format!(
                                    "{} {}x{} ({} bytes)",
                                    item.mime,
                                    item.width.unwrap_or(0),
                                    item.height.unwrap_or(0),
                                    item.blob_bytes.unwrap_or(0)
                                )
                            } else {
                                item.text_preview.as_deref().unwrap_or("").replace('\n', " ")
                            };
                            println!(
                                "{}  {:5}  {:8}  {}",
                                item.clip_id, item.kind, item.source_mode, detail
                            );
                        }
                    }
                }
            }
            Ok(0)
        }

        ClipCommand::Promote { clip_id, buf, lang } => {
            let mut row_opt = match clip_id.as_deref() {
                Some(id) => store.get_clip_item(id)?,
                None => store.latest_clip_item()?,
            };
            let client_opt = store
                .load_credentials()?
                .map(|c| RelayClient::from_credentials(&c))
                .transpose()?;
            if row_opt.is_none() {
                if let Some(ref client) = client_opt {
                    let _ = run_async(sync_cloud_clips_cli(store, client))?;
                    row_opt = match clip_id.as_deref() {
                        Some(id) => store.get_clip_item(id)?,
                        None => store.latest_clip_item()?,
                    };
                }
            }
            let row = row_opt.ok_or_else(|| {
                CoreError::new(
                    ErrorCode::NotFound,
                    match clip_id {
                        Some(ref id) => format!("clip item '{id}' not found"),
                        None => "no clipboard items available to promote".to_string(),
                    },
                    "Run 'mynote clip history' to list available clip IDs",
                )
            })?;
            if row.kind != "text" {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    format!("cannot promote image clip '{}' to a text note block", row.clip_id),
                    format!(
                        "Export image clips to a file instead: mynote clip pull {} --out <path>",
                        row.clip_id
                    ),
                ));
            }
            let bytes = resolve_clip_bytes_cli(store, client_opt.as_ref(), &row)?;
            let content = String::from_utf8(bytes).map_err(|e| {
                CoreError::new(
                    ErrorCode::IntegrityError,
                    format!("clip text is not valid UTF-8: {e}"),
                    "Inspect clip payload",
                )
            })?;
            let effective_lang = lang.unwrap_or_else(|| mynote_store::store::sniff_language(&content));

            if let Some(resp) = try_daemon_apply(
                store.data_dir(),
                ApplyMeta {
                    actor: actor.to_string(),
                    idempotency_key: None,
                    allow_empty: true,
                    force: false,
                },
                ApplyRequest::AddBlock {
                    buffer: buf.clone(),
                    content: content.clone(),
                    lang: Some(effective_lang.clone()),
                    after_id: None,
                },
                quiet,
            )? {
                if let Some(data) = resp.data {
                    let receipt: WriteReceipt = serde_json::from_value(data).map_err(|e| {
                        CoreError::new(ErrorCode::IntegrityError, e.to_string(), "decode daemon receipt")
                    })?;
                    emit_write_receipt(&receipt, store, mode, started);
                    return Ok(0);
                }
            }
            let receipt = store.add_block(&buf, &content, Some(&effective_lang), None, actor, None)?;
            emit_write_receipt(&receipt, store, mode, started);
            Ok(0)
        }

        ClipCommand::Undo => {
            let restored = if let Some(resp) =
                try_send_uds(store.data_dir(), &UdsRequest::ClipUndo, Duration::from_secs(3))?
            {
                if !resp.ok {
                    return Err(resp.into_core_error());
                }
                resp.data
                    .as_ref()
                    .and_then(|d| d.get("restored"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            } else {
                false
            };
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(
                        serde_json::json!({ "restored": restored }),
                        store_meta(store, started, None),
                    );
                }
                OutputMode::Human => {
                    if restored {
                        println!("restored previous desktop clipboard");
                    } else {
                        println!("nothing to undo (undo slot empty or daemon not running)");
                    }
                }
            }
            Ok(0)
        }

        ClipCommand::RotateKey => {
            require_tty(non_interactive, "clip rotate-key")?;
            let Some(creds) = store.load_credentials()? else {
                return Err(CoreError::new(
                    ErrorCode::SyncOffline,
                    "clip rotate-key requires a configured sync relay",
                    "Configure cloud sync via 'mynote device bootstrap' first",
                ));
            };
            let client = RelayClient::from_credentials(&creds)?;
            let (new_kid, new_gen) = run_async(rotate_clip_key(store, &client))?;
            let _ = try_send_uds(
                store.data_dir(),
                &UdsRequest::ClipPoke {
                    clip_id: None,
                    cleared: true,
                },
                Duration::from_secs(2),
            );
            let data = serde_json::json!({
                "ok": true,
                "clip_kid": new_kid.to_string(),
                "gen": new_gen,
                "cleared": true,
            });
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(data, store_meta(store, started, None));
                }
                OutputMode::Human => println!(
                    "rotated ClipKey to {new_kid} (gen={new_gen}); cloud & local clip history cleared"
                ),
            }
            Ok(0)
        }

        ClipCommand::Watch {
            enable,
            disable,
            pause,
            resume,
            auto_apply,
        } => {
            if let Some(ref m) = auto_apply {
                validate_auto_apply_mirror(m)?;
            }
            let enabled_opt = if enable {
                Some(true)
            } else if disable {
                Some(false)
            } else {
                None
            };
            let paused_opt = if pause {
                Some(true)
            } else if resume {
                Some(false)
            } else {
                None
            };

            let (cfg, daemon_notified) = if let Some(resp) = try_send_uds(
                store.data_dir(),
                &UdsRequest::ClipWatchSet {
                    paused: paused_opt,
                    enabled: enabled_opt,
                    auto_apply_mirror: auto_apply.clone(),
                },
                Duration::from_secs(3),
            )? {
                if !resp.ok {
                    return Err(resp.into_core_error());
                }
                let data = resp.data.unwrap_or_default();
                let cfg = crate::daemon::ClipWatchConfig {
                    watch_enabled: data
                        .get("watch_enabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    watch_paused: data
                        .get("watch_paused")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    auto_apply_mirror: data
                        .get("auto_apply_mirror")
                        .and_then(|v| v.as_str())
                        .unwrap_or("inbox-only")
                        .to_string(),
                };
                (cfg, true)
            } else {
                let mut cfg = load_persisted_watch_config(store);
                let persist_needed = enabled_opt.is_some() || auto_apply.is_some();
                if let Some(e) = enabled_opt {
                    cfg.watch_enabled = e;
                }
                if let Some(m) = auto_apply {
                    cfg.auto_apply_mirror = m;
                }
                if let Some(p) = paused_opt {
                    cfg.watch_paused = p;
                }
                if persist_needed {
                    persist_watch_config(store, &cfg)?;
                }
                (cfg, false)
            };

            let out = serde_json::json!({
                "watch_enabled": cfg.watch_enabled,
                "watch_paused": cfg.watch_paused,
                "auto_apply_mirror": cfg.auto_apply_mirror,
                "daemon_notified": daemon_notified,
            });
            match mode {
                OutputMode::Json | OutputMode::Jsonl => {
                    emit_json(out, store_meta(store, started, None));
                }
                OutputMode::Human => println!(
                    "clip watch: enabled={} paused={} auto_apply_mirror={} (daemon_notified={})",
                    cfg.watch_enabled, cfg.watch_paused, cfg.auto_apply_mirror, daemon_notified
                ),
            }
            Ok(0)
        }
    }
}

async fn sync_cloud_clips_cli(store: &mut LocalStore, client: &RelayClient) -> Result<usize, CoreError> {
    let (mut clip_kid, mut clip_key, _gen) = ensure_clip_key(store, client).await?;
    let cursor = store.get_clip_cursor();
    let mut remote: Vec<RemoteClipItem> = client.clip_list(cursor.as_deref(), CLIP_LOCAL_MAX_ITEMS).await?;
    if remote.is_empty() {
        return Ok(0);
    }
    remote.sort_by(|a, b| a.clip_id.cmp(&b.clip_id));

    let b64 = base64::engine::general_purpose::STANDARD;
    let mut refreshed_once = false;
    let mut upserted = 0usize;
    let mut max_clip_id = cursor;

    for item in &remote {
        if max_clip_id
            .as_deref()
            .is_none_or(|cur| item.clip_id.as_str() > cur)
        {
            max_clip_id = Some(item.clip_id.clone());
        }
        if item.clip_kid != clip_kid.to_string() && !refreshed_once {
            refreshed_once = true;
            if let Ok(Some((nkid, nkey, _))) = refresh_clip_key_from_remote(store, client).await {
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
            mime: meta.mime,
            source_mode: meta.source_mode.as_str().to_string(),
            created_at_ms: item.created_at_ms.max(meta.created_at_ms),
            expires_at_ms: item.expires_at_ms,
            text_preview: meta.text,
            has_blob: item.has_blob || meta.blob.is_some(),
            blob_bytes: meta.blob.as_ref().map(|b| b.byte_size as i64).or(item.blob_bytes),
            blob_sha256: meta.blob.as_ref().map(|b| b.sha256_hex.clone()),
            width: meta.blob.as_ref().and_then(|b| b.width),
            height: meta.blob.as_ref().and_then(|b| b.height),
            thumb_mime: meta.blob.as_ref().and_then(|b| b.thumb_mime.clone()),
            thumb_blob,
            local_blob_path: None,
        };
        store.upsert_clip_item(&row)?;
        upserted += 1;
    }

    if let Some(ref cur) = max_clip_id {
        let _ = store.set_clip_cursor(Some(cur));
    }
    let cache = store.clip_cache();
    for evicted in store.trim_clip_items(CLIP_LOCAL_MAX_ITEMS)? {
        let _ = cache.delete(&evicted);
    }
    for expired in store.prune_expired_clip_items(now_ms_cli() as i64)? {
        let _ = cache.delete(&expired);
    }
    Ok(upserted)
}

fn resolve_clip_bytes_cli(
    store: &mut LocalStore,
    client_opt: Option<&RelayClient>,
    row: &ClipItemRow,
) -> Result<Vec<u8>, CoreError> {
    if !row.has_blob {
        return Ok(row.text_preview.clone().unwrap_or_default().into_bytes());
    }
    let cache = store.clip_cache();
    let rel_name = row
        .local_blob_path
        .clone()
        .unwrap_or_else(|| clip_blob_cache_name(&row.clip_id, &row.mime));
    if let Some(bytes) = cache.read(&rel_name)? {
        if let Some(expected_sha) = row.blob_sha256.as_deref() {
            if verify_clip_blob_sha256(&bytes, expected_sha).is_ok() {
                if row.local_blob_path.is_none() {
                    let _ = store.set_clip_local_blob_path(&row.clip_id, Some(&rel_name));
                }
                return Ok(bytes);
            }
        } else {
            return Ok(bytes);
        }
    }
    let client = client_opt.ok_or_else(|| {
        CoreError::new(
            ErrorCode::SyncOffline,
            format!(
                "clip blob '{}' is not cached locally and relay is unconfigured",
                row.clip_id
            ),
            "Configure sync relay and run 'mynote clip pull'",
        )
    })?;
    let remote_blob = run_async(client.clip_get_blob(&row.clip_id))?;
    let cid = ClipId::parse(&row.clip_id)?;
    let ckid = ClipKid::parse(&row.clip_kid)?;
    let author_dev = DeviceId::parse(&row.device_id)?;
    let mut key_opt = store.unwrap_local_clip_key()?;
    if key_opt.as_ref().is_none_or(|(k, _, _)| *k != ckid) {
        if let Ok(refreshed) = run_async(refresh_clip_key_from_remote(store, client)) {
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
            format!("clip '{}' encrypted under rotated/unknown clip_kid", row.clip_id),
            "Refresh clip history",
        ));
    }
    let raw = decrypt_mnc1_blob(ckid, &clip_key, cid, &author_dev, &remote_blob.envelope)?;
    if let Some(expected_sha) = row.blob_sha256.as_deref() {
        verify_clip_blob_sha256(&raw, expected_sha)?;
    }
    if row.kind == "image" && is_svg_bytes(&raw) {
        return Err(CoreError::new(
            ErrorCode::IntegrityError,
            "refusing SVG bytes masquerading as bitmap image blob",
            "Delete this clip item",
        ));
    }
    let _ = cache.write(&rel_name, &raw)?;
    let _ = store.set_clip_local_blob_path(&row.clip_id, Some(&rel_name));
    Ok(raw)
}
