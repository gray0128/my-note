#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{Emitter, Manager};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

struct LatencyLog(Mutex<Vec<f64>>);

fn now_ms() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
        * 1000.0
}

#[tauri::command]
fn record_focus_latency(hotkey_ms: f64, visible_ms: f64, state: tauri::State<LatencyLog>) {
    let focused_ms = now_ms();
    let total = focused_ms - hotkey_ms;
    let vis = visible_ms - hotkey_ms;
    let mut log = state.0.lock().unwrap();
    log.push(total);
    let mut sorted = log.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = sorted[sorted.len() / 2];
    let p95 = sorted[((sorted.len() as f64) * 0.95).floor().min((sorted.len() - 1) as f64) as usize];
    let max = *sorted.last().unwrap();
    println!(
        "[S0-2 trial #{:02}] hotkey->visible={:.2}ms | hotkey->focused={:.2}ms | P50={:.2}ms P95={:.2}ms Max={:.2}ms",
        log.len(),
        vis,
        total,
        p50,
        p95,
        max
    );
}

#[tauri::command]
fn hide_window(window: tauri::WebviewWindow) {
    let _ = window.hide();
}

/// Tiny loopback mock daemon on localhost:19876 testing Scheme A (Host=localhost:19876 + SameSite=Strict Cookie).
fn spawn_mock_daemon() {
    std::thread::spawn(|| {
        let listener = TcpListener::bind("127.0.0.1:19876").expect("bind 127.0.0.1:19876");
        let html = include_str!("../frontend/index.html");
        for stream in listener.incoming().flatten() {
            let mut s = stream;
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let first = req.lines().next().unwrap_or("");
            let has_cookie = req.contains("mynote_local_session=spike_session_ok");

            let resp = if first.starts_with("GET /v1/local/auth/exchange") {
                "HTTP/1.1 303 See Other\r\nLocation: /\r\nSet-Cookie: mynote_local_session=spike_session_ok; HttpOnly; SameSite=Strict; Path=/\r\nContent-Length: 0\r\n\r\n".to_string()
            } else if first.starts_with("POST /v1/local/ping") {
                if has_cookie {
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 19\r\n\r\n{\"cookie_auth\":true}".to_string()
                } else {
                    "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"cookie_auth\":false}".to_string()
                }
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                    html.len(),
                    html
                )
            };
            let _ = s.write_all(resp.as_bytes());
        }
    });
}

fn main() {
    spawn_mock_daemon();
    let use_scheme_b = std::env::var("MYNOTE_SPIKE_SCHEME").unwrap_or_else(|_| "A".into()) == "B";
    let shortcut = Shortcut::new(Some(Modifiers::SUPER | Modifiers::SHIFT), Code::KeyM);

    tauri::Builder::default()
        .manage(LatencyLog(Mutex::new(Vec::new())))
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(move |app, sc, event| {
                    if sc == &shortcut && event.state() == ShortcutState::Pressed {
                        let t0 = now_ms();
                        if let Some(win) = app.get_webview_window("main") {
                            let _ = win.show();
                            let _ = win.set_focus();
                            let t_vis = now_ms();
                            let _ = win.emit("spike://hotkey-pressed", (t0, t_vis));
                        }
                    }
                })
                .build(),
        )
        .setup(move |app| {
            app.global_shortcut().register(shortcut)?;
            if !use_scheme_b {
                if let Some(win) = app.get_webview_window("main") {
                    let url = tauri::Url::parse("http://localhost:19876/v1/local/auth/exchange?ticket=spike").unwrap();
                    let _ = win.navigate(url);
                }
            }
            println!(
                "[S0-2] Ready (Scheme {}). Press Cmd+Shift+M from another app to measure latency; press Esc to hide.",
                if use_scheme_b { "B (tauri://localhost)" } else { "A (http://localhost:19876)" }
            );
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![record_focus_latency, hide_window])
        .run(tauri::generate_context!())
        .expect("error running S0-2 tauri spike");
}
