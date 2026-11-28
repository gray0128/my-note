# `MyNote.app` — Optional Pure Swift macOS Native Shell

Lightweight optional macOS wrapper (`AppKit` + `WebKit` + `Carbon` + `CryptoKit`) with **zero third-party dependencies** and **zero Keychain access**. It connects to the local `mynote daemon` over `0600 daemon.sock` and hosts the embedded `http://localhost:<port>` desktop Web UI in a dedicated `WKWebView` window.

## Capabilities

- **Zero-friction UDS authentication**: Sends `{"cmd":"open_ticket"}` to `daemon.sock` and lets `WKWebView` complete the `303` `HttpOnly; SameSite=Strict` session cookie exchange.
- **Daemon restart self-healing**: Checks `daemon.pid` via `ping` on window wake and re-authenticates automatically after daemon restarts or upgrades.
- **Global Hotkey (no Accessibility permission required)**: Carbon `RegisterEventHotKey` with menu-bar switchable presets (`⌃⌥Space` default, `⌥Space`, `⌥⌘N`, `⌃⌥N`), restoring focus to the previous app when hidden.
- **Menu bar & Dock mode**: Left-click status icon toggles window; right-click opens menu (Reload & Re-auth, Global Hotkey, Menu Bar Only mode, Quit). `Cmd+W` and the close button hide the window instead of quitting.
- **WebKit compatibility & security**:
  - Strict origin guard allowing only `http://localhost:<daemon_port>/*`; external `http(s)/mailto` links (including `target="_blank"`) open in the system browser.
  - Standard macOS `Edit` menu (`Cmd+Z/X/C/V/A`) without hijacking web shortcuts (`Cmd+F/P/L/E/\/Enter/...`).
  - `WKUIDelegate` handlers for `window.prompt` (Buffer rename), `alert`/`confirm`, and `<input type="file">` (M4 clipboard image upload).

## Build, Verify & Install

```bash
# Build apps/macos/build/MyNote.app (reads version from Cargo.toml)
./apps/macos/build.sh

# Run isolated automated verification against a temporary MYNOTE_DATA_DIR
./apps/macos/verify.sh

# Install locally
cp -R apps/macos/build/MyNote.app /Applications/
```

When downloading `MyNote-aarch64-apple-darwin.zip` from GitHub Releases (ad-hoc signed without an Apple Developer ID), clear the macOS quarantine attribute once before opening:

```bash
xattr -dr com.apple.quarantine /Applications/MyNote.app
open /Applications/MyNote.app
```
