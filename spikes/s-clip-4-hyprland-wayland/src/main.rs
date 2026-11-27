use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::wl_registry::WlRegistry;
use wayland_client::{Connection, Dispatch, QueueHandle};
use wl_clipboard_rs::copy::{
    ClipboardType as CopyClipboardType, MimeSource, MimeType as CopyMimeType, Options,
    ServeRequests, Source,
};
use wl_clipboard_rs::paste::Seat;
use wl_clipboard_rs::utils::{is_primary_selection_supported, PASSWORD_MANAGER_HINT_MIME_TYPE};
use wl_clipboard_rs::watch::{ClipboardEvent, ClipboardType as WatchClipboardType, Watcher};
use x11rb::connection::Connection as X11Connection;
use x11rb::protocol::xproto::{
    AtomEnum, ConnectionExt, CreateWindowAux, EventMask, PropMode, SelectionNotifyEvent,
    WindowClass,
};
use x11rb::protocol::Event as X11Event;
use x11rb::wrapper::ConnectionExt as WrapperConnectionExt;
use x11rb::COPY_DEPTH_FROM_PARENT;

const MIME_MYNOTE_SYNCED: &str = "application/x-mynote-synced";
const MIME_MYNOTE_VAULT_SECRET: &str = "application/x-mynote-vault-secret";
const PNG_MAGIC: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const MAX_CLIP_BYTES: u64 = 10 * 1024 * 1024;

const BITMAP_MIME_WHITELIST: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
];

const TEXT_MIME_PREFERENCE: &[&str] = &[
    "text/plain;charset=utf-8",
    "UTF8_STRING",
    "text/plain",
    "STRING",
    "TEXT",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum OfferDecision {
    Skip { reason: &'static str },
    ReadImage { mime: String },
    ReadText { mime: String },
}

fn decide_offer(mime_types: &[String]) -> OfferDecision {
    // Hard skip rules BEFORE opening any Wayland pipe (docs/threat-model.md §9.2,
    // docs/sync-protocol.md §11.3).
    if mime_types
        .iter()
        .any(|m| m == PASSWORD_MANAGER_HINT_MIME_TYPE)
    {
        return OfferDecision::Skip {
            reason: "sensitive_mime_hint",
        };
    }
    if mime_types.iter().any(|m| m == MIME_MYNOTE_VAULT_SECRET) {
        return OfferDecision::Skip {
            reason: "mynote_vault_secret",
        };
    }
    if mime_types.iter().any(|m| m == MIME_MYNOTE_SYNCED) {
        return OfferDecision::Skip {
            reason: "mynote_synced_echo_guard",
        };
    }

    // Bitmap whitelist only — explicitly excludes image/svg+xml from image channel (SEC-06).
    for preferred in BITMAP_MIME_WHITELIST {
        if mime_types.iter().any(|m| m == preferred) {
            return OfferDecision::ReadImage {
                mime: (*preferred).to_string(),
            };
        }
    }

    // Plain text fallback (also handles SVG if offered with a text MIME, or skips SVG-only).
    for preferred in TEXT_MIME_PREFERENCE {
        if mime_types.iter().any(|m| m == preferred) {
            return OfferDecision::ReadText {
                mime: (*preferred).to_string(),
            };
        }
    }

    if mime_types.iter().any(|m| m == "image/svg+xml") {
        return OfferDecision::Skip {
            reason: "svg_rejected_no_plain_text",
        };
    }

    OfferDecision::Skip {
        reason: "no_supported_mime",
    }
}

struct RegistryProbeState;

impl Dispatch<WlRegistry, GlobalListContents> for RegistryProbeState {
    fn event(
        _state: &mut Self,
        _proxy: &WlRegistry,
        _event: <WlRegistry as wayland_client::Proxy>::Event,
        _data: &GlobalListContents,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

#[derive(Serialize)]
struct GlobalInfo {
    name: u32,
    interface: String,
    version: u32,
}

#[derive(Serialize)]
struct ProtocolProbeReport {
    wayland_display: Option<String>,
    xdg_runtime_dir: Option<String>,
    ext_data_control_v1: Option<u32>,
    zwlr_data_control_v1: Option<u32>,
    wl_data_device_manager: Option<u32>,
    wl_clipboard_rs_selected_protocol: &'static str,
    primary_selection_supported: String,
    relevant_globals: Vec<GlobalInfo>,
}

fn cmd_probe_protocols() -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::connect_to_env()?;
    let (globals, _queue) = registry_queue_init::<RegistryProbeState>(&conn)?;

    let mut ext_ver = None;
    let mut wlr_ver = None;
    let mut wl_ddm_ver = None;
    let mut relevant = Vec::new();

    globals.contents().with_list(|list| {
        for g in list {
            if g.interface == "ext_data_control_manager_v1" {
                ext_ver = Some(g.version);
            } else if g.interface == "zwlr_data_control_manager_v1" {
                wlr_ver = Some(g.version);
            } else if g.interface == "wl_data_device_manager" {
                wl_ddm_ver = Some(g.version);
            }
            if g.interface.contains("data_control")
                || g.interface.contains("data_device")
                || g.interface.contains("selection")
                || g.interface == "wl_seat"
            {
                relevant.push(GlobalInfo {
                    name: g.name,
                    interface: g.interface.clone(),
                    version: g.version,
                });
            }
        }
    });

    // Matches wl-clipboard-rs 0.9.5 src/common.rs: ext_manager.or_else(wlr_manager)
    let selected = if ext_ver.is_some() {
        "ext_data_control_manager_v1"
    } else if wlr_ver.is_some() {
        "zwlr_data_control_manager_v1"
    } else {
        "none"
    };

    let primary = match is_primary_selection_supported() {
        Ok(b) => b.to_string(),
        Err(e) => format!("err:{e}"),
    };

    let report = ProtocolProbeReport {
        wayland_display: env::var("WAYLAND_DISPLAY").ok(),
        xdg_runtime_dir: env::var("XDG_RUNTIME_DIR").ok(),
        ext_data_control_v1: ext_ver,
        zwlr_data_control_v1: wlr_ver,
        wl_data_device_manager: wl_ddm_ver,
        wl_clipboard_rs_selected_protocol: selected,
        primary_selection_supported: primary,
        relevant_globals: relevant,
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[derive(Serialize)]
struct WatchEventRecord {
    event_index: usize,
    elapsed_ms: u128,
    kind: &'static str,
    mime_types: Vec<String>,
    decision: OfferDecision,
    pipe_opened: bool,
    bytes: Option<usize>,
    blake3_hex: Option<String>,
    png_magic_valid: Option<bool>,
    text_preview: Option<String>,
    read_error: Option<String>,
}

#[derive(Serialize)]
struct WatchSummary {
    summary: bool,
    total_events: usize,
    pipe_reads_executed: usize,
    skipped_without_read: usize,
    cleared_events: usize,
    exited_via_cancel_handle: bool,
}

fn cmd_watch(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut duration_secs: u64 = 15;
    let mut max_events: Option<usize> = None;
    let mut skip_initial = false;
    let mut ready_marker = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--duration-secs" => {
                i += 1;
                duration_secs = args.get(i).ok_or("missing --duration-secs value")?.parse()?;
            }
            "--max-events" => {
                i += 1;
                max_events = Some(args.get(i).ok_or("missing --max-events value")?.parse()?);
            }
            "--skip-initial" => skip_initial = true,
            "--ready-marker" => ready_marker = true,
            other => return Err(format!("unknown watch flag: {other}").into()),
        }
        i += 1;
    }

    // Strictly read-only observer: wl_clipboard_rs::watch::Watcher NEVER calls set_selection.
    let mut watcher = Watcher::new(WatchClipboardType::Regular, Seat::Unspecified)?;
    let cancel = watcher.cancel_handle();

    let timer_cancel = cancel.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(duration_secs));
        timer_cancel.cancel();
    });

    if ready_marker {
        println!("READY");
        io::stdout().flush()?;
    }

    let start = Instant::now();
    let mut raw_seen = 0usize;
    let mut total_events = 0usize;
    let mut pipe_reads_executed = 0usize;
    let mut skipped_without_read = 0usize;
    let mut cleared_events = 0usize;
    let mut exited_via_cancel = false;

    loop {
        match watcher.next_event()? {
            None => {
                exited_via_cancel = true;
                break;
            }
            Some(ClipboardEvent::Cleared { .. }) => {
                raw_seen += 1;
                if skip_initial && raw_seen == 1 {
                    continue;
                }
                total_events += 1;
                cleared_events += 1;
                let rec = WatchEventRecord {
                    event_index: total_events,
                    elapsed_ms: start.elapsed().as_millis(),
                    kind: "cleared",
                    mime_types: vec![],
                    decision: OfferDecision::Skip { reason: "cleared" },
                    pipe_opened: false,
                    bytes: None,
                    blake3_hex: None,
                    png_magic_valid: None,
                    text_preview: None,
                    read_error: None,
                };
                println!("{}", serde_json::to_string(&rec)?);
                io::stdout().flush()?;
            }
            Some(ClipboardEvent::Changed {
                mime_types,
                mut offer,
                ..
            }) => {
                raw_seen += 1;
                if skip_initial && raw_seen == 1 {
                    // Drop offer without calling offer.receive()!
                    drop(offer);
                    continue;
                }
                total_events += 1;
                let decision = decide_offer(&mime_types);
                let mut pipe_opened = false;
                let mut bytes = None;
                let mut blake3_hex = None;
                let mut png_magic_valid = None;
                let mut text_preview = None;
                let mut read_error = None;

                match &decision {
                    OfferDecision::Skip { .. } => {
                        // Drop offer BEFORE opening any pipe!
                        drop(offer);
                        skipped_without_read += 1;
                    }
                    OfferDecision::ReadImage { mime } | OfferDecision::ReadText { mime } => {
                        pipe_opened = true;
                        pipe_reads_executed += 1;
                        match offer.receive(mime) {
                            Ok(pipe_reader) => {
                                let mut buf = Vec::new();
                                match pipe_reader.take(MAX_CLIP_BYTES + 1).read_to_end(&mut buf) {
                                    Ok(_) => {
                                        if buf.len() as u64 > MAX_CLIP_BYTES {
                                            read_error = Some("exceeded_10mib_cap".to_string());
                                        } else {
                                            bytes = Some(buf.len());
                                            blake3_hex = Some(blake3::hash(&buf).to_hex().to_string());
                                            if matches!(decision, OfferDecision::ReadImage { .. }) {
                                                if mime == "image/png" {
                                                    png_magic_valid = Some(buf.starts_with(PNG_MAGIC));
                                                }
                                            } else {
                                                let s = String::from_utf8_lossy(&buf);
                                                let preview: String = s.chars().take(64).collect();
                                                text_preview = Some(preview);
                                            }
                                        }
                                    }
                                    Err(e) => read_error = Some(format!("pipe_read:{e}")),
                                }
                            }
                            Err(e) => read_error = Some(format!("offer_receive:{e}")),
                        }
                    }
                }

                let rec = WatchEventRecord {
                    event_index: total_events,
                    elapsed_ms: start.elapsed().as_millis(),
                    kind: "changed",
                    mime_types,
                    decision,
                    pipe_opened,
                    bytes,
                    blake3_hex,
                    png_magic_valid,
                    text_preview,
                    read_error,
                };
                println!("{}", serde_json::to_string(&rec)?);
                io::stdout().flush()?;
            }
        }

        if let Some(limit) = max_events {
            if total_events >= limit {
                cancel.cancel();
                // Drain cancel confirmation on next loop or exit directly.
                break;
            }
        }
    }

    let summary = WatchSummary {
        summary: true,
        total_events,
        pipe_reads_executed,
        skipped_without_read,
        cleared_events,
        exited_via_cancel_handle: exited_via_cancel,
    };
    println!("{}", serde_json::to_string(&summary)?);
    io::stdout().flush()?;
    Ok(())
}

fn cmd_copy_multi(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut text: Option<String> = None;
    let mut png_path: Option<String> = None;
    let mut raw_mime: Option<(String, String)> = None;
    let mut synced = false;
    let mut vault_secret = false;
    let mut sensitive = false;
    let mut serve_requests = ServeRequests::Unlimited;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--text" => {
                i += 1;
                text = Some(args.get(i).ok_or("missing --text value")?.clone());
            }
            "--png" => {
                i += 1;
                png_path = Some(args.get(i).ok_or("missing --png value")?.clone());
            }
            "--raw-mime" => {
                i += 1;
                let mime = args.get(i).ok_or("missing --raw-mime mime")?.clone();
                i += 1;
                let data = args.get(i).ok_or("missing --raw-mime data")?.clone();
                raw_mime = Some((mime, data));
            }
            "--synced" => synced = true,
            "--vault-secret" => vault_secret = true,
            "--sensitive" => sensitive = true,
            "--serve-requests" => {
                i += 1;
                let n: usize = args.get(i).ok_or("missing --serve-requests value")?.parse()?;
                serve_requests = ServeRequests::Only(n);
            }
            other => return Err(format!("unknown copy-multi flag: {other}").into()),
        }
        i += 1;
    }

    let mut sources: Vec<MimeSource> = Vec::new();
    if let Some(t) = text {
        sources.push(MimeSource {
            source: Source::Bytes(t.into_bytes().into_boxed_slice()),
            mime_type: CopyMimeType::Text,
        });
    } else if let Some(path) = png_path {
        let bytes = fs::read(&path)?;
        sources.push(MimeSource {
            source: Source::Bytes(bytes.into_boxed_slice()),
            mime_type: CopyMimeType::Specific("image/png".to_string()),
        });
    } else if let Some((mime, data)) = raw_mime {
        sources.push(MimeSource {
            source: Source::Bytes(data.into_bytes().into_boxed_slice()),
            mime_type: CopyMimeType::Specific(mime),
        });
    } else {
        return Err("copy-multi requires --text, --png, or --raw-mime".into());
    }

    if synced {
        sources.push(MimeSource {
            source: Source::Bytes(b"1".to_vec().into_boxed_slice()),
            mime_type: CopyMimeType::Specific(MIME_MYNOTE_SYNCED.to_string()),
        });
    }
    if vault_secret {
        sources.push(MimeSource {
            source: Source::Bytes(b"1".to_vec().into_boxed_slice()),
            mime_type: CopyMimeType::Specific(MIME_MYNOTE_VAULT_SECRET.to_string()),
        });
    }

    let mut opts = Options::new();
    opts.clipboard(CopyClipboardType::Regular)
        .foreground(true)
        .serve_requests(serve_requests)
        .sensitive(sensitive);

    let prepared = opts.prepare_copy_multi(sources)?;
    println!("READY");
    io::stdout().flush()?;

    prepared.serve()?;
    println!("SERVE_EXITED");
    io::stdout().flush()?;
    Ok(())
}

#[derive(Serialize)]
struct X11ReadReport {
    display: Option<String>,
    target: String,
    ok: bool,
    incr_used: bool,
    targets: Option<Vec<String>>,
    bytes: Option<usize>,
    blake3_hex: Option<String>,
    png_magic_valid: Option<bool>,
    text_preview: Option<String>,
    error: Option<String>,
}

fn cmd_x11_read(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut target_name = "UTF8_STRING".to_string();
    let mut timeout_ms: u64 = 3000;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                i += 1;
                target_name = args.get(i).ok_or("missing --target value")?.clone();
            }
            "--timeout-ms" => {
                i += 1;
                timeout_ms = args.get(i).ok_or("missing --timeout-ms value")?.parse()?;
            }
            other => return Err(format!("unknown x11-read flag: {other}").into()),
        }
        i += 1;
    }

    let (conn, screen_num) = x11rb::connect(None)?;
    let screen = &conn.setup().roots[screen_num];
    let win = conn.generate_id()?;
    conn.create_window(
        COPY_DEPTH_FROM_PARENT,
        win,
        screen.root,
        0,
        0,
        1,
        1,
        0,
        WindowClass::INPUT_ONLY,
        0,
        &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
    )?;

    let clipboard_atom = conn.intern_atom(false, b"CLIPBOARD")?.reply()?.atom;
    let target_atom = conn.intern_atom(false, target_name.as_bytes())?.reply()?.atom;
    let prop_atom = conn.intern_atom(false, b"S_CLIP_4_PROP")?.reply()?.atom;
    let incr_atom = conn.intern_atom(false, b"INCR")?.reply()?.atom;

    conn.convert_selection(win, clipboard_atom, target_atom, prop_atom, x11rb::CURRENT_TIME)?;
    conn.flush()?;

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut incr_mode = false;
    let mut incr_used = false;
    let mut data: Vec<u8> = Vec::new();
    let mut prop_type: u32 = 0;
    let mut finished = false;
    let mut error = None;

    while Instant::now() < deadline && !finished {
        if let Some(ev) = conn.poll_for_event()? {
            match ev {
                X11Event::SelectionNotify(sn) => {
                    if sn.property == x11rb::NONE {
                        error = Some("selection_conversion_refused".to_string());
                        finished = true;
                    } else {
                        let reply = conn
                            .get_property(true, win, prop_atom, AtomEnum::ANY, 0, u32::MAX / 4)?
                            .reply()?;
                        if reply.type_ == incr_atom {
                            incr_mode = true;
                            incr_used = true;
                        } else {
                            prop_type = reply.type_;
                            data = reply.value;
                            finished = true;
                        }
                    }
                }
                X11Event::PropertyNotify(pn) if incr_mode && pn.atom == prop_atom && pn.state == x11rb::protocol::xproto::Property::NEW_VALUE => {
                    let reply = conn
                        .get_property(true, win, prop_atom, AtomEnum::ANY, 0, u32::MAX / 4)?
                        .reply()?;
                    if reply.value.is_empty() {
                        finished = true;
                    } else {
                        prop_type = reply.type_;
                        data.extend_from_slice(&reply.value);
                    }
                }
                _ => {}
            }
        } else {
            thread::sleep(Duration::from_millis(5));
        }
    }

    if !finished {
        error = Some("timeout".to_string());
    }

    let mut targets = None;
    let mut bytes = None;
    let mut blake3_hex = None;
    let mut png_magic_valid = None;
    let mut text_preview = None;

    if error.is_none() {
        if target_name == "TARGETS" && prop_type == u32::from(AtomEnum::ATOM) {
            let mut names = Vec::new();
            for chunk in data.chunks_exact(4) {
                let atom = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                if let Ok(name_reply) = conn.get_atom_name(atom)?.reply() {
                    names.push(String::from_utf8_lossy(&name_reply.name).to_string());
                }
            }
            targets = Some(names);
        } else {
            bytes = Some(data.len());
            blake3_hex = Some(blake3::hash(&data).to_hex().to_string());
            if target_name == "image/png" {
                png_magic_valid = Some(data.starts_with(PNG_MAGIC));
            } else if target_name == "UTF8_STRING" || target_name.starts_with("text/") {
                let s = String::from_utf8_lossy(&data);
                text_preview = Some(s.chars().take(64).collect());
            }
        }
    }

    let report = X11ReadReport {
        display: env::var("DISPLAY").ok(),
        target: target_name,
        ok: error.is_none(),
        incr_used,
        targets,
        bytes,
        blake3_hex,
        png_magic_valid,
        text_preview,
        error,
    };
    println!("{}", serde_json::to_string(&report)?);
    if report.ok {
        Ok(())
    } else {
        Err("x11-read failed".into())
    }
}

fn cmd_x11_copy(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut text = String::new();
    let mut timeout_secs: u64 = 10;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--text" => {
                i += 1;
                text = args.get(i).ok_or("missing --text value")?.clone();
            }
            "--timeout-secs" => {
                i += 1;
                timeout_secs = args.get(i).ok_or("missing --timeout-secs value")?.parse()?;
            }
            other => return Err(format!("unknown x11-copy flag: {other}").into()),
        }
        i += 1;
    }

    let (conn, screen_num) = x11rb::connect(None)?;
    let screen = &conn.setup().roots[screen_num];
    let win = conn.generate_id()?;
    conn.create_window(
        COPY_DEPTH_FROM_PARENT,
        win,
        screen.root,
        0,
        0,
        1,
        1,
        0,
        WindowClass::INPUT_ONLY,
        0,
        &CreateWindowAux::new(),
    )?;

    let clipboard_atom = conn.intern_atom(false, b"CLIPBOARD")?.reply()?.atom;
    let targets_atom = conn.intern_atom(false, b"TARGETS")?.reply()?.atom;
    let utf8_atom = conn.intern_atom(false, b"UTF8_STRING")?.reply()?.atom;
    let text_utf8_atom = conn
        .intern_atom(false, b"text/plain;charset=utf-8")?
        .reply()?
        .atom;
    let string_atom = u32::from(AtomEnum::STRING);

    conn.set_selection_owner(win, clipboard_atom, x11rb::CURRENT_TIME)?;
    let owner = conn.get_selection_owner(clipboard_atom)?.reply()?.owner;
    if owner != win {
        return Err("failed to acquire X11 CLIPBOARD ownership".into());
    }

    println!("READY");
    io::stdout().flush()?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut served_requests = 0usize;
    let mut cleared = false;

    while Instant::now() < deadline {
        if let Some(ev) = conn.poll_for_event()? {
            match ev {
                X11Event::SelectionRequest(req) => {
                    let prop = if req.property == x11rb::NONE {
                        req.target
                    } else {
                        req.property
                    };
                    let mut notify_prop = x11rb::NONE;

                    if req.target == targets_atom {
                        let supported = [targets_atom, utf8_atom, text_utf8_atom, string_atom];
                        conn.change_property32(
                            PropMode::REPLACE,
                            req.requestor,
                            prop,
                            AtomEnum::ATOM,
                            &supported,
                        )?;
                        notify_prop = prop;
                        served_requests += 1;
                    } else if req.target == utf8_atom
                        || req.target == text_utf8_atom
                        || req.target == string_atom
                    {
                        conn.change_property8(
                            PropMode::REPLACE,
                            req.requestor,
                            prop,
                            req.target,
                            text.as_bytes(),
                        )?;
                        notify_prop = prop;
                        served_requests += 1;
                    }

                    let notify = SelectionNotifyEvent {
                        response_type: x11rb::protocol::xproto::SELECTION_NOTIFY_EVENT,
                        sequence: 0,
                        time: req.time,
                        requestor: req.requestor,
                        selection: req.selection,
                        target: req.target,
                        property: notify_prop,
                    };
                    conn.send_event(false, req.requestor, EventMask::NO_EVENT, notify)?;
                    conn.flush()?;
                }
                X11Event::SelectionClear(_) => {
                    cleared = true;
                    break;
                }
                _ => {}
            }
        } else {
            thread::sleep(Duration::from_millis(5));
        }
    }

    println!(
        "{}",
        serde_json::json!({
            "x11_copy_done": true,
            "served_requests": served_requests,
            "cleared_by_new_owner": cleared,
        })
    );
    io::stdout().flush()?;
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage: {} <probe-protocols|watch|copy-multi|x11-read|x11-copy> [args...]",
            args[0]
        );
        return ExitCode::from(2);
    }

    let res = match args[1].as_str() {
        "probe-protocols" => cmd_probe_protocols(),
        "watch" => cmd_watch(&args[2..]),
        "copy-multi" => cmd_copy_multi(&args[2..]),
        "x11-read" => cmd_x11_read(&args[2..]),
        "x11-copy" => cmd_x11_copy(&args[2..]),
        other => Err(format!("unknown subcommand: {other}").into()),
    };

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mimes(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn skips_password_manager_hint_before_reading() {
        assert_eq!(
            decide_offer(&mimes(&[
                "text/plain;charset=utf-8",
                "x-kde-passwordManagerHint",
            ])),
            OfferDecision::Skip {
                reason: "sensitive_mime_hint"
            }
        );
    }

    #[test]
    fn skips_mynote_vault_secret_and_synced_markers() {
        assert_eq!(
            decide_offer(&mimes(&["image/png", "application/x-mynote-synced"])),
            OfferDecision::Skip {
                reason: "mynote_synced_echo_guard"
            }
        );
        assert_eq!(
            decide_offer(&mimes(&[
                "text/plain;charset=utf-8",
                "application/x-mynote-vault-secret",
            ])),
            OfferDecision::Skip {
                reason: "mynote_vault_secret"
            }
        );
    }

    #[test]
    fn rejects_svg_from_image_channel() {
        assert_eq!(
            decide_offer(&mimes(&["image/svg+xml"])),
            OfferDecision::Skip {
                reason: "svg_rejected_no_plain_text"
            }
        );
        assert_eq!(
            decide_offer(&mimes(&["image/svg+xml", "text/plain;charset=utf-8"])),
            OfferDecision::ReadText {
                mime: "text/plain;charset=utf-8".to_string()
            }
        );
    }

    #[test]
    fn prefers_png_bitmap_and_utf8_text() {
        assert_eq!(
            decide_offer(&mimes(&["image/jpeg", "image/png", "text/plain"])),
            OfferDecision::ReadImage {
                mime: "image/png".to_string()
            }
        );
        assert_eq!(
            decide_offer(&mimes(&["STRING", "text/plain;charset=utf-8"])),
            OfferDecision::ReadText {
                mime: "text/plain;charset=utf-8".to_string()
            }
        );
    }
}
