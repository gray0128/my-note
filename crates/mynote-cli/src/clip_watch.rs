//! M4b-1 Desktop <-> Desktop background auto-mirror watch engine
//! (`docs/sync-protocol.md` §11.3, `docs/threat-model.md` §9.2,
//! `docs/spikes/s-clip-3-macos-pasteboard.md`, `docs/spikes/s-clip-4-hyprland-wayland.md`).
//!
//! Strictly DEFAULT OFF (`watch_enabled = false`, opt-in only):
//! - Zero background polling/threads while disabled or paused.
//! - Hard-filters sensitive/remote/echo macOS UTIs and Wayland MIMEs before reading payloads.
//! - Intercepts high-risk credentials via `mynote_core::vault::detect_secret_pattern` with 0
//!   outbound network pushes and emits `CLIP_SECRET_BLOCKED` WS alert.
//! - Enforces 250 ms debounce, 10 MiB payload ceiling, rolling 60s rate limit (30 items/min total,
//!   10 images/min), and dual Echo Loop suppression (source marker + 2,000 ms BLAKE3 window).

use crate::clipboard::{
    is_svg_bytes, macos_precheck_sensitive_uti, macos_select_source_uti, wayland_classify_mimes,
    ClipboardPayload, EchoGuard, MacosSelectedUti, ReadClipboardResult, WaylandOfferChoice,
    CLIP_ECHO_WINDOW_MS,
};
use crate::daemon::{ClipItemDto, ClipWatchConfig, DaemonState};
use mynote_core::clip::{validate_clip_image_mime, CLIP_BLOB_MAX_BYTES};
use mynote_core::error::{CoreError, ErrorCode};
use mynote_core::vault::detect_secret_pattern;
use mynote_store::LocalStore;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

/// Persisted `local_meta` key for opt-in background auto-watch (`"1"` = enabled, default OFF).
pub const META_CLIP_WATCH_ENABLED: &str = "clip_watch_enabled";
/// Persisted `local_meta` key for M4b receive mode (`"inbox-only"` default or `"auto-apply"`).
pub const META_CLIP_AUTO_APPLY_MIRROR: &str = "clip_auto_apply_mirror";

/// Debounce interval (milliseconds) to coalesce rapid clipboard updates.
pub const CLIP_WATCH_DEBOUNCE_MS: u64 = 250;
/// Rolling rate-limit window duration (milliseconds).
pub const CLIP_WATCH_RATE_WINDOW_MS: u64 = 60_000;
/// Maximum auto-captured items allowed per rolling 60s window.
pub const CLIP_WATCH_MAX_ITEMS_PER_MIN: usize = 30;
/// Maximum auto-captured image items allowed per rolling 60s window.
pub const CLIP_WATCH_MAX_IMAGES_PER_MIN: usize = 10;

/// Actionable user hint broadcast in `CLIP_SECRET_BLOCKED` local WebSocket alerts.
pub const CLIP_SECRET_BLOCKED_HINT: &str =
    "Secret detected in clipboard; auto-upload blocked. Use 'mynote clip push --ephemeral' if intentional.";

/// Validate `auto_apply_mirror` mode string (`"inbox-only"` or `"auto-apply"`).
pub fn validate_auto_apply_mirror(mode: &str) -> Result<(), CoreError> {
    if mode == "inbox-only" || mode == "auto-apply" {
        Ok(())
    } else {
        Err(CoreError::new(
            ErrorCode::InvalidArgument,
            format!("invalid auto_apply_mirror '{mode}'"),
            "Use 'inbox-only' or 'auto-apply'",
        ))
    }
}

/// Load persisted watch config from SQLite `local_meta` (strictly default OFF, unpaused, `inbox-only`).
pub fn load_persisted_watch_config(store: &LocalStore) -> ClipWatchConfig {
    let watch_enabled = store.get_local_meta(META_CLIP_WATCH_ENABLED).as_deref() == Some("1");
    let auto_apply_mirror = match store.get_local_meta(META_CLIP_AUTO_APPLY_MIRROR).as_deref() {
        Some("auto-apply") => "auto-apply".to_string(),
        _ => "inbox-only".to_string(),
    };
    ClipWatchConfig {
        watch_enabled,
        watch_paused: false,
        auto_apply_mirror,
    }
}

/// Persist `watch_enabled` and `auto_apply_mirror` to SQLite `local_meta`.
/// (`watch_paused` is intentionally transient runtime state.)
pub fn persist_watch_config(store: &LocalStore, cfg: &ClipWatchConfig) -> Result<(), CoreError> {
    validate_auto_apply_mirror(&cfg.auto_apply_mirror)?;
    store.set_local_meta(META_CLIP_WATCH_ENABLED, if cfg.watch_enabled { "1" } else { "0" })?;
    store.set_local_meta(META_CLIP_AUTO_APPLY_MIRROR, &cfg.auto_apply_mirror)?;
    Ok(())
}

/// Which rate-limit bucket rejected an auto-captured clipboard event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitKind {
    TotalItemsPerMin,
    ImagesPerMin,
}

/// Rolling 60-second rate limiter enforcing max 30 items/min total AND max 10 images/min.
#[derive(Clone, Debug, Default)]
pub struct ClipWatchRateLimiter {
    all_items: VecDeque<u64>,
    image_items: VecDeque<u64>,
}

impl ClipWatchRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    fn prune(&mut self, now_ms: u64) {
        while let Some(&ts) = self.all_items.front() {
            if now_ms.saturating_sub(ts) >= CLIP_WATCH_RATE_WINDOW_MS {
                self.all_items.pop_front();
            } else {
                break;
            }
        }
        while let Some(&ts) = self.image_items.front() {
            if now_ms.saturating_sub(ts) >= CLIP_WATCH_RATE_WINDOW_MS {
                self.image_items.pop_front();
            } else {
                break;
            }
        }
    }

    /// Check whether another auto-captured item is allowed at `now_ms`, and if so record it.
    pub fn check_and_record(&mut self, is_image: bool, now_ms: u64) -> Result<(), RateLimitKind> {
        self.prune(now_ms);
        if self.all_items.len() >= CLIP_WATCH_MAX_ITEMS_PER_MIN {
            return Err(RateLimitKind::TotalItemsPerMin);
        }
        if is_image && self.image_items.len() >= CLIP_WATCH_MAX_IMAGES_PER_MIN {
            return Err(RateLimitKind::ImagesPerMin);
        }
        self.all_items.push_back(now_ms);
        if is_image {
            self.image_items.push_back(now_ms);
        }
        Ok(())
    }

    pub fn counts_at(&mut self, now_ms: u64) -> (usize, usize) {
        self.prune(now_ms);
        (self.all_items.len(), self.image_items.len())
    }
}

/// Deterministic 250 ms coalescing debouncer for rapid clipboard bursts.
#[derive(Clone, Debug)]
pub struct ClipWatchDebouncer<T> {
    debounce_ms: u64,
    pending: Option<(T, u64)>,
}

impl<T> Default for ClipWatchDebouncer<T> {
    fn default() -> Self {
        Self::new(CLIP_WATCH_DEBOUNCE_MS)
    }
}

impl<T> ClipWatchDebouncer<T> {
    pub fn new(debounce_ms: u64) -> Self {
        Self {
            debounce_ms,
            pending: None,
        }
    }

    /// Record a new candidate observation at `now_ms`, replacing any un-flushed earlier event.
    pub fn observe(&mut self, item: T, now_ms: u64) {
        self.pending = Some((item, now_ms));
    }

    /// Cancel any pending candidate (e.g., clipboard cleared or overwritten by sensitive content).
    pub fn cancel(&mut self) {
        self.pending = None;
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Flush and return the latest pending candidate once `debounce_ms` has elapsed since its observation.
    pub fn take_ready(&mut self, now_ms: u64) -> Option<T> {
        let (_, observed_ms) = self.pending.as_ref()?;
        if now_ms.saturating_sub(*observed_ms) >= self.debounce_ms {
            self.pending.take().map(|(item, _)| item)
        } else {
            None
        }
    }
}

/// Pure decision returned by `ClipWatchFilter` before any outbound network push.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchDecision {
    Allow(ClipboardPayload),
    SkipEmpty,
    SkipSensitive(String),
    SkipEchoSuppressed,
    SkipTooLarge { byte_size: usize, max_bytes: usize },
    SkipDisallowedImage(String),
    SkipRateLimited(RateLimitKind),
    SecretBlocked(&'static str),
}

/// Core testable filter for M4b-1 background clipboard watching:
/// sensitive UTI/MIME prechecks, 10 MiB cap, SVG rejection, `EchoGuard`, `detect_secret_pattern`,
/// and rolling 60s rate limits.
#[derive(Clone, Debug, Default)]
pub struct ClipWatchFilter {
    rate_limiter: ClipWatchRateLimiter,
}

impl ClipWatchFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pure macOS `NSPasteboard.types()` precheck executed BEFORE any payload read.
    pub fn precheck_macos_types(types: &[String]) -> Result<MacosSelectedUti, WatchDecision> {
        if types.is_empty() {
            return Err(WatchDecision::SkipEmpty);
        }
        if let Some(reason) = macos_precheck_sensitive_uti(types) {
            return Err(WatchDecision::SkipSensitive(reason.to_string()));
        }
        match macos_select_source_uti(types) {
            None => Err(WatchDecision::SkipEmpty),
            Some(MacosSelectedUti::SvgOnlyRejected) => {
                Err(WatchDecision::SkipDisallowedImage("public.svg-image".to_string()))
            }
            Some(selected) => Ok(selected),
        }
    }

    /// Pure Wayland offer MIME list precheck executed BEFORE opening any pipe.
    pub fn precheck_wayland_mimes(mimes: &[String]) -> Result<WaylandOfferChoice, WatchDecision> {
        match wayland_classify_mimes(mimes) {
            WaylandOfferChoice::Empty => Err(WatchDecision::SkipEmpty),
            WaylandOfferChoice::SkipSensitive(reason) => {
                Err(WatchDecision::SkipSensitive(reason.to_string()))
            }
            WaylandOfferChoice::SvgOnlyRejected => {
                Err(WatchDecision::SkipDisallowedImage("image/svg+xml".to_string()))
            }
            choice @ (WaylandOfferChoice::ReadImage(_) | WaylandOfferChoice::ReadText(_)) => Ok(choice),
        }
    }

    /// Evaluate a `ReadClipboardResult` from `SystemClipboard::read()`.
    pub fn evaluate_read(
        &mut self,
        read_res: ReadClipboardResult,
        echo: &EchoGuard,
        now_ms: u64,
    ) -> WatchDecision {
        match read_res {
            ReadClipboardResult::Empty => WatchDecision::SkipEmpty,
            ReadClipboardResult::SkippedSensitive(reason) => WatchDecision::SkipSensitive(reason),
            ReadClipboardResult::Payload(payload) => self.evaluate_payload(payload, echo, now_ms),
        }
    }

    /// Evaluate a candidate clipboard payload against size cap, SVG defense, `EchoGuard`,
    /// `detect_secret_pattern`, and rolling 60s rate limits.
    pub fn evaluate_payload(
        &mut self,
        payload: ClipboardPayload,
        echo: &EchoGuard,
        now_ms: u64,
    ) -> WatchDecision {
        let is_image = match &payload {
            ClipboardPayload::Text(text) => {
                if text.is_empty() {
                    return WatchDecision::SkipEmpty;
                }
                if text.len() > CLIP_BLOB_MAX_BYTES {
                    return WatchDecision::SkipTooLarge {
                        byte_size: text.len(),
                        max_bytes: CLIP_BLOB_MAX_BYTES,
                    };
                }
                let hash = *blake3::hash(text.as_bytes()).as_bytes();
                if echo.is_suppressed(&hash, now_ms, CLIP_ECHO_WINDOW_MS) {
                    return WatchDecision::SkipEchoSuppressed;
                }
                if let Some(pattern) = detect_secret_pattern(text) {
                    return WatchDecision::SecretBlocked(pattern);
                }
                false
            }
            ClipboardPayload::Image { mime, bytes, .. } => {
                if bytes.is_empty() {
                    return WatchDecision::SkipEmpty;
                }
                if bytes.len() > CLIP_BLOB_MAX_BYTES {
                    return WatchDecision::SkipTooLarge {
                        byte_size: bytes.len(),
                        max_bytes: CLIP_BLOB_MAX_BYTES,
                    };
                }
                if validate_clip_image_mime(mime).is_err() || is_svg_bytes(bytes) {
                    return WatchDecision::SkipDisallowedImage(mime.clone());
                }
                // Layer-2 Echo Loop prevention: compare BLAKE3 of actual OS clipboard image bytes
                // (transcoded PNG bytes written by `SystemClipboard::write`) against EchoGuard.
                let hash = *blake3::hash(bytes).as_bytes();
                if echo.is_suppressed(&hash, now_ms, CLIP_ECHO_WINDOW_MS) {
                    return WatchDecision::SkipEchoSuppressed;
                }
                true
            }
        };

        if let Err(kind) = self.rate_limiter.check_and_record(is_image, now_ms) {
            return WatchDecision::SkipRateLimited(kind);
        }

        WatchDecision::Allow(payload)
    }

    pub fn rate_counts_at(&mut self, now_ms: u64) -> (usize, usize) {
        self.rate_limiter.counts_at(now_ms)
    }
}

/// Outcome of submitting a watched clipboard capture through `DaemonState`.
#[derive(Clone, Debug)]
pub enum WatchCaptureOutcome {
    DisabledOrPaused,
    Uploaded(Box<ClipItemDto>),
    Dropped(WatchDecision),
}

fn now_ms_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1)
        .max(1)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn is_watch_active(cfg: &ClipWatchConfig) -> bool {
    cfg.watch_enabled && !cfg.watch_paused
}

/// Spawn the M4b-1 background clipboard watcher supervisor.
///
/// - Does NOTHING (0 timers, 0 OS threads, 0 clipboard reads) when `clipboard.is_native() == false`
///   or while `watch_enabled == false` (default) or `watch_paused == true`.
/// - Wakes immediately on `PATCH /v1/local/clip/watch`, CLI `mynote clip watch`, or Daemon shutdown.
pub fn spawn_clip_watch_supervisor(state: Arc<DaemonState>, shutdown_rx: watch::Receiver<bool>) {
    if !state.clipboard.is_native() {
        return;
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let mut cfg_rx = state.clip_watch_tx.subscribe();
        let mut shutdown_rx = shutdown_rx;
        tokio::spawn(async move {
            loop {
                if *shutdown_rx.borrow() {
                    break;
                }
                let cfg = cfg_rx.borrow_and_update().clone();
                if !is_watch_active(&cfg) {
                    tokio::select! {
                        changed = shutdown_rx.changed() => {
                            if changed.is_err() || *shutdown_rx.borrow() {
                                break;
                            }
                        }
                        changed = cfg_rx.changed() => {
                            if changed.is_err() {
                                break;
                            }
                        }
                    }
                    continue;
                }

                #[cfg(target_os = "macos")]
                run_macos_watch_session(&state, &mut cfg_rx, &mut shutdown_rx).await;

                #[cfg(target_os = "linux")]
                run_linux_watch_session(&state, &mut cfg_rx, &mut shutdown_rx).await;
            }
        });
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (state, shutdown_rx);
    }
}

#[cfg(target_os = "macos")]
async fn run_macos_watch_session(
    state: &Arc<DaemonState>,
    cfg_rx: &mut watch::Receiver<ClipWatchConfig>,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    use crate::clipboard::macos_change_count;
    use std::time::Duration;

    // Record initial changeCount on activation so the startup clipboard snapshot is NEVER auto-uploaded!
    let mut last_cc = match tokio::task::spawn_blocking(macos_change_count).await {
        Ok(cc) => cc,
        Err(_) => return,
    };

    let mut poll = tokio::time::interval(Duration::from_millis(CLIP_WATCH_DEBOUNCE_MS));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Consume the immediate first tick so we wait a full interval before polling.
    poll.tick().await;

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    return;
                }
            }
            changed = cfg_rx.changed() => {
                if changed.is_err() || !is_watch_active(&cfg_rx.borrow_and_update()) {
                    return;
                }
            }
            _ = poll.tick() => {
                if *shutdown_rx.borrow() || !is_watch_active(&cfg_rx.borrow()) {
                    return;
                }
                let cur_cc = match tokio::task::spawn_blocking(macos_change_count).await {
                    Ok(cc) => cc,
                    Err(_) => continue,
                };
                if cur_cc == last_cc {
                    continue;
                }

                // 250 ms debounce: wait for changeCount to settle before reading any clipboard data.
                let mut settled_cc = cur_cc;
                for _ in 0..8 {
                    tokio::select! {
                        changed = shutdown_rx.changed() => {
                            if changed.is_err() || *shutdown_rx.borrow() {
                                return;
                            }
                        }
                        changed = cfg_rx.changed() => {
                            if changed.is_err() || !is_watch_active(&cfg_rx.borrow_and_update()) {
                                return;
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_millis(CLIP_WATCH_DEBOUNCE_MS)) => {}
                    }
                    let next_cc = match tokio::task::spawn_blocking(macos_change_count).await {
                        Ok(cc) => cc,
                        Err(_) => break,
                    };
                    if next_cc == settled_cc {
                        break;
                    }
                    settled_cc = next_cc;
                }
                last_cc = settled_cc;

                if *shutdown_rx.borrow() || !is_watch_active(&cfg_rx.borrow()) {
                    return;
                }

                let clip = Arc::clone(&state.clipboard);
                let read_res = match tokio::task::spawn_blocking(move || clip.read()).await {
                    Ok(Ok(r)) => r,
                    _ => continue,
                };
                let _ = state.handle_auto_captured_read(read_res, now_ms_u64()).await;
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn run_linux_watch_session(
    state: &Arc<DaemonState>,
    cfg_rx: &mut watch::Receiver<ClipWatchConfig>,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    use crate::clipboard::inspect_image_dimensions;
    use std::io::Read;
    use std::time::Duration;
    use tokio::sync::{mpsc, oneshot};
    use wl_clipboard_rs::paste::Seat;
    use wl_clipboard_rs::watch::{ClipboardEvent, ClipboardType as WatchClipboardType, Watcher};

    enum WaylandWatchMsg {
        Candidate(ClipboardPayload),
        ClearPending,
    }

    let (tx, mut rx) = mpsc::channel::<WaylandWatchMsg>(32);
    let (cancel_tx, cancel_rx) = oneshot::channel();

    let spawn_res = std::thread::Builder::new()
        .name("mynote-wl-watch".to_string())
        .spawn(move || {
            let mut watcher = match Watcher::new(WatchClipboardType::Regular, Seat::Unspecified) {
                Ok(w) => w,
                Err(_) => {
                    let _ = cancel_tx.send(None);
                    return;
                }
            };
            let cancel = watcher.cancel_handle();
            if cancel_tx.send(Some(cancel)).is_err() {
                return;
            }

            let mut saw_initial = false;
            loop {
                match watcher.next_event() {
                    Ok(None) | Err(_) => break,
                    Ok(Some(ClipboardEvent::Cleared { .. })) => {
                        if !saw_initial {
                            saw_initial = true;
                            continue;
                        }
                        if tx.blocking_send(WaylandWatchMsg::ClearPending).is_err() {
                            break;
                        }
                    }
                    Ok(Some(ClipboardEvent::Changed {
                        mime_types,
                        mut offer,
                        ..
                    })) => {
                        // Skip startup clipboard snapshot without opening any pipe!
                        if !saw_initial {
                            saw_initial = true;
                            drop(offer);
                            continue;
                        }

                        // Strictly inspect MIME list BEFORE opening any Wayland pipe.
                        let choice = match ClipWatchFilter::precheck_wayland_mimes(&mime_types) {
                            Ok(c) => c,
                            Err(_) => {
                                drop(offer);
                                if tx.blocking_send(WaylandWatchMsg::ClearPending).is_err() {
                                    break;
                                }
                                continue;
                            }
                        };

                        let payload_opt = match choice {
                            WaylandOfferChoice::ReadImage(mime) => {
                                if let Ok(pipe) = offer.receive(mime) {
                                    let mut bytes = Vec::new();
                                    if pipe
                                        .take((CLIP_BLOB_MAX_BYTES as u64) + 1)
                                        .read_to_end(&mut bytes)
                                        .is_ok()
                                        && !bytes.is_empty()
                                        && bytes.len() <= CLIP_BLOB_MAX_BYTES
                                        && !is_svg_bytes(&bytes)
                                    {
                                        let dims = inspect_image_dimensions(&bytes);
                                        Some(ClipboardPayload::Image {
                                            mime: mime.to_string(),
                                            bytes,
                                            width: dims.map(|d| d.0),
                                            height: dims.map(|d| d.1),
                                        })
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            }
                            WaylandOfferChoice::ReadText(mime) => {
                                if let Ok(pipe) = offer.receive(mime) {
                                    let mut bytes = Vec::new();
                                    if pipe
                                        .take((CLIP_BLOB_MAX_BYTES as u64) + 1)
                                        .read_to_end(&mut bytes)
                                        .is_ok()
                                        && !bytes.is_empty()
                                        && bytes.len() <= CLIP_BLOB_MAX_BYTES
                                    {
                                        String::from_utf8(bytes).ok().map(ClipboardPayload::Text)
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        };

                        let msg = match payload_opt {
                            Some(p) => WaylandWatchMsg::Candidate(p),
                            None => WaylandWatchMsg::ClearPending,
                        };
                        if tx.blocking_send(msg).is_err() {
                            break;
                        }
                    }
                }
            }
        });

    let Ok(join_handle) = spawn_res else {
        return;
    };

    let cancel = match cancel_rx.await {
        Ok(Some(c)) => c,
        _ => {
            // Wayland data-control unavailable (e.g., headless server): back off until config/shutdown changes.
            let _ = join_handle.join();
            tokio::select! {
                _ = shutdown_rx.changed() => {}
                _ = cfg_rx.changed() => {}
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
            return;
        }
    };

    let mut pending: Option<ClipboardPayload> = None;
    let debounce_sleep = tokio::time::sleep(Duration::from_millis(CLIP_WATCH_DEBOUNCE_MS));
    tokio::pin!(debounce_sleep);

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            changed = cfg_rx.changed() => {
                if changed.is_err() || !is_watch_active(&cfg_rx.borrow_and_update()) {
                    break;
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(WaylandWatchMsg::Candidate(payload)) => {
                        pending = Some(payload);
                        debounce_sleep
                            .as_mut()
                            .reset(tokio::time::Instant::now() + Duration::from_millis(CLIP_WATCH_DEBOUNCE_MS));
                    }
                    Some(WaylandWatchMsg::ClearPending) => {
                        pending = None;
                    }
                    None => break,
                }
            }
            _ = &mut debounce_sleep, if pending.is_some() => {
                if let Some(payload) = pending.take() {
                    if *shutdown_rx.borrow() || !is_watch_active(&cfg_rx.borrow()) {
                        break;
                    }
                    let _ = state
                        .handle_auto_captured_read(ReadClipboardResult::Payload(payload), now_ms_u64())
                        .await;
                }
            }
        }
    }

    cancel.cancel();
    drop(rx);
    let _ = tokio::task::spawn_blocking(move || {
        let _ = join_handle.join();
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::{
        MIME_KDE_PASSWORD_HINT, MIME_MYNOTE_SYNCED, MIME_MYNOTE_VAULT_SECRET, UTI_AUTO_GENERATED,
        UTI_CONCEALED, UTI_MYNOTE_SYNCED, UTI_MYNOTE_VAULT_SECRET, UTI_ONEPASSWORD, UTI_PNG,
        UTI_REMOTE_CLIPBOARD, UTI_SVG, UTI_TRANSIENT, UTI_UTF8_PLAIN_TEXT,
    };

    #[test]
    fn rate_limiter_enforces_30_total_and_10_images_per_rolling_60s_window() {
        let mut rl = ClipWatchRateLimiter::new();
        let t0 = 100_000u64;

        // 10 images succeed; 11th image rejected even though total < 30
        for i in 0..CLIP_WATCH_MAX_IMAGES_PER_MIN {
            assert_eq!(rl.check_and_record(true, t0 + (i as u64) * 100), Ok(()));
        }
        assert_eq!(
            rl.check_and_record(true, t0 + 2_000),
            Err(RateLimitKind::ImagesPerMin)
        );

        // 20 more text items succeed (reaching 30 total); 31st rejected
        for i in 0..(CLIP_WATCH_MAX_ITEMS_PER_MIN - CLIP_WATCH_MAX_IMAGES_PER_MIN) {
            assert_eq!(rl.check_and_record(false, t0 + 3_000 + (i as u64) * 100), Ok(()));
        }
        assert_eq!(
            rl.check_and_record(false, t0 + 10_000),
            Err(RateLimitKind::TotalItemsPerMin)
        );

        // After rolling 60s window expires for first image at t0, 1 image slot reopens
        assert_eq!(rl.check_and_record(true, t0 + CLIP_WATCH_RATE_WINDOW_MS), Ok(()));
    }

    #[test]
    fn debouncer_coalesces_rapid_bursts_within_250ms_and_honors_cancel() {
        let mut deb = ClipWatchDebouncer::default();
        deb.observe("first", 1_000);
        assert_eq!(deb.take_ready(1_249), None);
        deb.observe("second", 1_150);
        assert_eq!(deb.take_ready(1_399), None);
        assert_eq!(deb.take_ready(1_400), Some("second"));
        assert!(!deb.has_pending());

        deb.observe("will-be-cancelled", 2_000);
        deb.cancel();
        assert_eq!(deb.take_ready(3_000), None);
    }

    #[test]
    fn filter_blocks_sensitive_utis_mimes_secrets_svg_oversize_and_echo() {
        for uti in [
            UTI_CONCEALED,
            UTI_TRANSIENT,
            UTI_AUTO_GENERATED,
            UTI_ONEPASSWORD,
            UTI_REMOTE_CLIPBOARD,
            UTI_MYNOTE_SYNCED,
            UTI_MYNOTE_VAULT_SECRET,
        ] {
            let err =
                ClipWatchFilter::precheck_macos_types(&[UTI_UTF8_PLAIN_TEXT.to_string(), uti.to_string()])
                    .unwrap_err();
            assert_eq!(err, WatchDecision::SkipSensitive(uti.to_string()));
        }
        assert_eq!(
            ClipWatchFilter::precheck_macos_types(&[UTI_SVG.to_string()]).unwrap_err(),
            WatchDecision::SkipDisallowedImage("public.svg-image".to_string())
        );
        assert_eq!(
            ClipWatchFilter::precheck_macos_types(&[UTI_PNG.to_string()]).unwrap(),
            MacosSelectedUti::Png
        );

        for mime in [
            MIME_KDE_PASSWORD_HINT,
            MIME_MYNOTE_VAULT_SECRET,
            MIME_MYNOTE_SYNCED,
        ] {
            let err = ClipWatchFilter::precheck_wayland_mimes(&[
                "text/plain;charset=utf-8".to_string(),
                mime.to_string(),
            ])
            .unwrap_err();
            assert_eq!(err, WatchDecision::SkipSensitive(mime.to_string()));
        }
        assert_eq!(
            ClipWatchFilter::precheck_wayland_mimes(&["image/svg+xml".to_string()]).unwrap_err(),
            WatchDecision::SkipDisallowedImage("image/svg+xml".to_string())
        );

        let mut filter = ClipWatchFilter::new();
        let mut echo = EchoGuard::default();

        // High-risk secret patterns blocked before rate limiter
        assert_eq!(
            filter.evaluate_payload(
                ClipboardPayload::Text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE".into()),
                &echo,
                5_000,
            ),
            WatchDecision::SecretBlocked("aws_access_key")
        );
        assert_eq!(filter.rate_counts_at(5_000), (0, 0));

        // > 10 MiB dropped
        let huge = "a".repeat(CLIP_BLOB_MAX_BYTES + 1);
        assert!(matches!(
            filter.evaluate_payload(ClipboardPayload::Text(huge), &echo, 5_100),
            WatchDecision::SkipTooLarge { .. }
        ));

        // SVG masquerading as image/png dropped
        assert!(matches!(
            filter.evaluate_payload(
                ClipboardPayload::Image {
                    mime: "image/png".into(),
                    bytes: b"<svg onload='alert(1)'/>".to_vec(),
                    width: None,
                    height: None,
                },
                &echo,
                5_200,
            ),
            WatchDecision::SkipDisallowedImage(_)
        ));

        // EchoGuard suppresses identical bytes within 2,000 ms
        let echoed_png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3];
        echo.record(*blake3::hash(&echoed_png).as_bytes(), 10_000);
        assert_eq!(
            filter.evaluate_payload(
                ClipboardPayload::Image {
                    mime: "image/png".into(),
                    bytes: echoed_png.clone(),
                    width: Some(1),
                    height: Some(1),
                },
                &echo,
                11_999,
            ),
            WatchDecision::SkipEchoSuppressed
        );
        assert!(matches!(
            filter.evaluate_payload(
                ClipboardPayload::Image {
                    mime: "image/png".into(),
                    bytes: echoed_png,
                    width: Some(1),
                    height: Some(1),
                },
                &echo,
                12_001,
            ),
            WatchDecision::Allow(ClipboardPayload::Image { .. })
        ));
    }
}
