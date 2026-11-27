#!/usr/bin/env python3
"""
M4 Full Real-Browser Playwright Chromium & WebKit E2E Gate (SEC-08 ext + SEC-09 + M4b-1 Watch).

Runs against REAL `wrangler dev --local` (M4a-2 Worker + `web/dist-pwa`), REAL Desktop `mynote daemon`
(with `MYNOTE_NO_NOTIFY=1` and `MYNOTE_CLIPBOARD_MOCK_FILE`), and REAL Playwright Chromium + WebKit:

1. Desktop Chromium & WebKit audit (`http://localhost:<port>`):
   - Zero `console.error`, zero `pageerror`, zero CSP violations, zero horizontal overflow
     (`scrollWidth <= innerWidth`), zero `.sr-only` leaks at `1440x900` & `900x700` (EN & zh-CN).
   - Open Clipboard drawer (`clip-inbox-btn`), send text item & real valid PNG image -> both appear
     in `clip-list` with bitmap thumbnail (no `image/svg+xml`).
   - Attempt uploading a crafted `image/svg+xml` file (`<svg onload="alert(1)"/>`) -> rejected with
     visible `clip-error`, 0 `<svg>` injected, 0 upload!
   - Full preview on PNG item -> `blob:` image loads with `naturalWidth > 0` & revokes `blob:` URL on close.
   - Apply + Undo against hermetic mock clipboard; Promote text item -> verified in SQLite (`mynote ls --json`).
   - Toggle Auto-Watch (`PATCH /v1/local/clip/watch`) & verify persisted state across local API + CLI.
2. Mobile PWA WebKit audit (`390x844`, `read+clip` + `SEC-08` ext + `SEC-09`):
   - Issue real `mynote device add --name iPhoneClip --scope read+clip`, pair in Playwright WebKit.
   - Notes tab strictly read-only (0 editable inputs in `.ro-block`), zero horizontal overflow (EN & zh-CN).
   - Switch to Clipboard tab (`pwa-tab-clip`), verify Desktop's text & PNG arrived and decrypted in RAM.
   - Send text canary (`PWA_CLIP_TEXT_CANARY_999`) & real PNG image from PWA (`WasmClipCodec` +
     `PUT /v1/clip/blob`); refuse crafted `image/svg+xml`; verify Desktop `mynote clip history --json`
     receives BOTH items from PWA!
   - Android `share_target` handoff cleanup: seed `mynote-share-handoff` cache with `/__share-handoff/latest`
     containing `SHARE_HANDOFF_CANARY_777`, navigate to `/?clip_share=1`, assert upload completes and
     `caches.has("mynote-share-handoff") === false`!
   - SEC-08 Forensic Storage Audit: dump ALL 7 IndexedDB stores (`block_keys`, `blocks`, `buffers`,
     `clip_items`, `device_keystore`, `meta`, `vault_header`), `localStorage`, `sessionStorage`, and
     `Cache Storage` -> assert exact 7 stores, `device_wrap_key.extractable === false`, 0 `/v1/` cached,
     0 `mynote-share-handoff` residue, and ZERO occurrences of any clip/share/note canary in persistent storage!
3. Cross-check `clip-write` token isolation (`SEC-09` + iOS Scriptable interop):
   - Issue `mynote device add --name ShortcutsTest --scope clip-write`, claim via real
     `deploy/ios-shortcuts/mynote-clip-push.js` crypto -> prove HTTP `GET /v1/clip` & `GET /v1/sync/pull`
     return `403 TOKEN_SCOPE_FORBIDDEN` while `POST /v1/clip` succeeds and Desktop decrypts it!
"""

from __future__ import annotations

import base64
import json
import os
import pty
import re
import select
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zlib
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
CLOUD_DIR = ROOT / "cloud-cf"
SCRIPTABLE_JS = ROOT / "deploy" / "ios-shortcuts" / "mynote-clip-push.js"


def resolve_mynote_bin() -> Path:
    if env_bin := os.environ.get("MYNOTE_BIN"):
        return Path(env_bin)
    if target_dir := os.environ.get("CARGO_TARGET_DIR"):
        cand = Path(target_dir) / "debug" / "mynote"
        if cand.exists():
            return cand
    return ROOT / "target" / "debug" / "mynote"


BIN = resolve_mynote_bin()

GEOMETRY_AUDIT_JS = """() => {
  const docEl = document.documentElement;
  const scrollWidth = docEl.scrollWidth;
  const innerWidth = window.innerWidth;

  const srLeaks = [];
  for (const el of document.querySelectorAll('.sr-only')) {
    const cs = window.getComputedStyle(el);
    if (cs.display === 'none') continue;
    if (el.offsetParent === document.body) {
      srLeaks.push(el.textContent?.trim() || el.tagName);
    }
  }

  return {
    scrollWidth,
    innerWidth,
    overflowPx: scrollWidth - innerWidth,
    srLeaks,
  };
}"""

INIT_AUDIT_HOOKS_JS = """(() => {
  window.__cspViolations = [];
  window.addEventListener('securitypolicyviolation', (e) => {
    window.__cspViolations.push({ directive: e.violatedDirective, blocked: e.blockedURI });
  });
  window.__revokedBlobUrls = [];
  const origRevoke = URL.revokeObjectURL.bind(URL);
  URL.revokeObjectURL = (url) => {
    window.__revokedBlobUrls.push(String(url));
    return origRevoke(url);
  };
})();"""


def make_valid_png(width: int, height: int, r: int, g: int, b: int) -> bytes:
    """Create a valid RGBA PNG using only Python stdlib (struct + zlib)."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    raw_rows = bytearray()
    for y in range(height):
        raw_rows.append(0)  # filter type 0
        for x in range(width):
            raw_rows.extend(((r + x * 5) & 0xFF, (g + y * 7) & 0xFF, b & 0xFF, 255))
    idat = zlib.compress(bytes(raw_rows), level=6)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", idat)
        + chunk(b"IEND", b"")
    )


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def write_mock_clipboard_text(path: Path, text: str) -> None:
    payload = {
        "kind": "text",
        "mime": "text/plain",
        "data_b64": base64.b64encode(text.encode("utf-8")).decode("ascii"),
        "synced_marker": False,
        "sensitive": False,
        "ephemeral": False,
        "written_blake3_hex": "0" * 64,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def read_mock_clipboard(path: Path) -> dict:
    st = json.loads(path.read_text(encoding="utf-8"))
    st["decoded_bytes"] = base64.b64decode(st["data_b64"])
    return st


def run_cli(
    data_dir: Path,
    args: list[str],
    *,
    env_extra: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["MYNOTE_NO_NOTIFY"] = "1"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [str(BIN), "--data-dir", str(data_dir), *args],
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        env=env,
        check=check,
        timeout=25,
    )


def run_pty_cmd(
    data_dir: Path,
    args: list[str],
    prompts_and_answers: list[tuple[str, str]],
    *,
    env_extra: dict[str, str] | None = None,
    timeout_s: float = 25.0,
) -> tuple[int, str]:
    master_fd, slave_fd = pty.openpty()
    env = os.environ.copy()
    env["MYNOTE_NO_NOTIFY"] = "1"
    if env_extra:
        env.update(env_extra)
    proc = subprocess.Popen(
        [str(BIN), "--data-dir", str(data_dir), *args],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        start_new_session=True,
        close_fds=True,
        env=env,
    )
    os.close(slave_fd)
    buf = b""
    idx = 0
    deadline = time.monotonic() + timeout_s
    try:
        while time.monotonic() < deadline:
            r, _, _ = select.select([master_fd], [], [], 0.1)
            if master_fd in r:
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                decoded = buf.decode("utf-8", errors="replace")
                while idx < len(prompts_and_answers):
                    needle, answer = prompts_and_answers[idx]
                    if needle in decoded:
                        time.sleep(0.05)
                        os.write(master_fd, (answer + "\n").encode("utf-8"))
                        idx += 1
                    else:
                        break
            if proc.poll() is not None:
                while True:
                    r2, _, _ = select.select([master_fd], [], [], 0.05)
                    if master_fd not in r2:
                        break
                    try:
                        c2 = os.read(master_fd, 4096)
                    except OSError:
                        break
                    if not c2:
                        break
                    buf += c2
                break
        rc = proc.wait(timeout=5)
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass
    return rc, buf.decode("utf-8", errors="replace")


def wait_for_wrangler(url: str, proc: subprocess.Popen[str], timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out, err = proc.communicate()
            raise RuntimeError(f"wrangler dev exited early ({proc.returncode}):\n{out}\n{err}")
        try:
            with urllib.request.urlopen(url, timeout=1.5) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(0.25)
    raise RuntimeError(f"timed out waiting for wrangler dev at {url}")


def wait_for_open_url(data_dir: Path, env_extra: dict[str, str], timeout_s: float = 15.0) -> tuple[str, int]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        proc = run_cli(data_dir, ["--json", "open"], env_extra=env_extra, check=False)
        if proc.returncode == 0:
            j = json.loads(proc.stdout)
            return j["data"]["url"], int(j["data"]["port"])
        time.sleep(0.15)
    raise RuntimeError("timed out waiting for mynote daemon UDS OpenTicket")


def assert_geometry(page, label: str) -> None:
    g = page.evaluate(GEOMETRY_AUDIT_JS)
    assert g["overflowPx"] <= 0, (
        f"[{label}] horizontal viewport overflow: scrollWidth={g['scrollWidth']} > innerWidth={g['innerWidth']}"
    )
    assert g["srLeaks"] == [], f"[{label}] .sr-only leaked to document.body: {g['srLeaks']}"


def wait_for_desktop_clip_history(
    data_dir: Path,
    env_extra: dict[str, str],
    predicate,
    description: str,
    timeout_s: float = 20.0,
) -> list[dict]:
    deadline = time.monotonic() + timeout_s
    last_items: list[dict] = []
    while time.monotonic() < deadline:
        # Pull gently in case WS wake was still in flight, then inspect local clip history
        run_cli(data_dir, ["--json", "clip", "pull"], env_extra=env_extra, check=False)
        proc = run_cli(data_dir, ["--json", "clip", "history", "--limit", "50"], env_extra=env_extra)
        last_items = json.loads(proc.stdout)["data"]
        if predicate(last_items):
            return last_items
        time.sleep(0.3)
    raise AssertionError(f"timed out waiting for desktop clip history condition ({description}); got: {last_items}")


def http_json_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict | None = None,
) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    hdrs = {"X-Mynote-Protocol": "1"}
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {"raw": raw}
        return err.code, parsed


def verify_clip_write_token_isolation(
    tmp_desktop: Path,
    base_url: str,
    env_extra: dict[str, str],
) -> None:
    """Issue a real `clip-write` device, claim via real Scriptable JS crypto, prove 403 on GET & 200 on POST."""
    rc, pair_out = run_pty_cmd(
        tmp_desktop,
        ["device", "add", "--name", "ShortcutsTest", "--scope", "clip-write"],
        [],
        env_extra=env_extra,
    )
    assert rc == 0, f"clip-write device add failed ({rc}): {pair_out}"
    m = re.search(r"(mynote-pair:v1:[A-Za-z0-9_-]+)", pair_out)
    assert m, f"could not extract clip-write pairing code from:\n{pair_out}"
    pair_code = m.group(1)

    node_script = """
    const clipPush = require(process.argv[1]);
    const pairCode = process.argv[2];
    const canary = process.argv[3];
    (async () => {
      const parsed = clipPush.parsePairingCode(pairCode);
      const claimResp = await fetch(parsed.sync_url + '/v1/devices/pair-claim', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Mynote-Protocol': '1' },
        body: JSON.stringify({ pair_id: parsed.pair_id }),
      });
      const claimJson = await claimResp.json();
      if (!claimResp.ok || !claimJson.ok) {
        throw new Error('pair-claim failed: ' + JSON.stringify(claimJson));
      }
      if (claimJson.scope !== 'clip-write') {
        throw new Error('expected clip-write scope, got ' + claimJson.scope);
      }
      const ct = clipPush.base64ToBytes(claimJson.ciphertext_b64);
      const creds = clipPush.decryptPairingTicket(parsed.pair_id, parsed.k_pair_b64u, ct);
      if (!creds.device_token || !creds.clip_kid || !creds.clip_key_b64) {
        throw new Error('missing clip-write ticket fields: ' + JSON.stringify(creds));
      }
      const upload = clipPush.prepareClipUpload({
        clipKey: clipPush.base64ToBytes(creds.clip_key_b64),
        clipKid: creds.clip_kid,
        deviceId: creds.device_id,
        kind: 'text',
        mime: 'text/plain',
        text: canary,
        ephemeral: false,
      });
      console.log(JSON.stringify({
        device_id: creds.device_id,
        device_token: creds.device_token,
        upload_body: upload.jsonBody,
      }));
    })().catch((e) => { console.error(e); process.exit(1); });
    """
    shortcuts_canary = "SHORTCUTS_CLIP_WRITE_CANARY_555"
    res = subprocess.run(
        ["node", "-e", node_script, str(SCRIPTABLE_JS), pair_code, shortcuts_canary],
        text=True,
        capture_output=True,
        check=True,
        timeout=20,
    )
    claimed = json.loads(res.stdout)
    auth_hdr = {"Authorization": f"Bearer {claimed['device_token']}"}

    # 1. GET /v1/clip -> MUST return 403 TOKEN_SCOPE_FORBIDDEN
    st_clip_get, body_clip_get = http_json_request("GET", f"{base_url}/v1/clip", headers=auth_hdr)
    assert st_clip_get == 403, f"Expected 403 for clip-write GET /v1/clip, got {st_clip_get}: {body_clip_get}"
    assert body_clip_get.get("error", {}).get("code") == "TOKEN_SCOPE_FORBIDDEN", (
        f"Expected TOKEN_SCOPE_FORBIDDEN, got: {body_clip_get}"
    )

    # 2. GET /v1/sync/pull -> MUST return 403 TOKEN_SCOPE_FORBIDDEN
    st_pull_get, body_pull_get = http_json_request("GET", f"{base_url}/v1/sync/pull?since_seq=0", headers=auth_hdr)
    assert st_pull_get == 403, f"Expected 403 for clip-write GET /v1/sync/pull, got {st_pull_get}: {body_pull_get}"
    assert body_pull_get.get("error", {}).get("code") == "TOKEN_SCOPE_FORBIDDEN", (
        f"Expected TOKEN_SCOPE_FORBIDDEN, got: {body_pull_get}"
    )

    # 3. POST /v1/clip -> MUST succeed (HTTP 200, ok: true) & Desktop decrypts it!
    st_clip_post, body_clip_post = http_json_request(
        "POST",
        f"{base_url}/v1/clip",
        headers=auth_hdr,
        body=claimed["upload_body"],
    )
    assert st_clip_post == 200 and body_clip_post.get("ok") is True, (
        f"Expected 200 ok for clip-write POST /v1/clip, got {st_clip_post}: {body_clip_post}"
    )

    wait_for_desktop_clip_history(
        tmp_desktop,
        env_extra,
        lambda items: any(
            it.get("device_id") == claimed["device_id"]
            and shortcuts_canary in (it.get("text_preview") or "")
            for it in items
        ),
        "Desktop receives & decrypts Shortcuts clip-write item",
    )
    print("[m4-e2e] 6. clip-write token isolation (GET /v1/clip & /v1/sync/pull -> 403 TOKEN_SCOPE_FORBIDDEN, POST /v1/clip -> 200 + Desktop decrypt): PASS!")


def main() -> None:
    assert BIN.exists(), f"mynote binary missing at {BIN}; run `cargo build --bin mynote`"
    assert (ROOT / "web" / "dist-pwa" / "index.html").exists(), "web/dist-pwa missing; run `pnpm --dir web build:pwa`"
    assert SCRIPTABLE_JS.exists(), f"Scriptable template missing at {SCRIPTABLE_JS}"

    wrangler_bin = CLOUD_DIR / "node_modules" / ".bin" / "wrangler"
    assert wrangler_bin.exists(), f"wrangler missing at {wrangler_bin}"

    cf_port = pick_free_port()
    base_url = f"http://127.0.0.1:{cf_port}"
    boot_token = "e2e-m4-clip-bootstrap-secret-token"
    tmp_desktop = Path(tempfile.mkdtemp(prefix="mynote-m4-e2e-desk-"))
    tmp_wrangler = Path(tempfile.mkdtemp(prefix="mynote-m4-e2e-cf-"))
    mock_clip_file = tmp_desktop / "mock_clipboard.json"
    env_extra = {
        "MYNOTE_NO_NOTIFY": "1",
        "MYNOTE_CLIPBOARD_MOCK_FILE": str(mock_clip_file),
    }

    note_seed_canary = "M4_NOTE_SEED_CANARY_101"
    desktop_clip_text = "DESKTOP_CLIP_TEXT_CANARY_404"
    pwa_clip_text = "PWA_CLIP_TEXT_CANARY_999"
    share_handoff_canary = "SHARE_HANDOFF_CANARY_777"
    orig_mock_clip = "ORIGINAL_MOCK_CLIPBOARD_BEFORE_APPLY"

    desktop_png = make_valid_png(24, 24, 42, 160, 220)
    pwa_png = make_valid_png(20, 20, 210, 90, 50)
    evil_svg = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>window.__xss=1</script></svg>'

    wrangler = subprocess.Popen(
        [
            str(wrangler_bin),
            "dev",
            "--local",
            "--ip",
            "127.0.0.1",
            "--port",
            str(cf_port),
            "--persist-to",
            str(tmp_wrangler),
            "--var",
            f"BOOTSTRAP_TOKEN:{boot_token}",
            "--show-interactive-dev-session=false",
        ],
        cwd=str(CLOUD_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "CI": "1"},
    )
    daemon: subprocess.Popen[str] | None = None
    try:
        wait_for_wrangler(base_url, wrangler)
        print(f"[m4-e2e] 1. Real wrangler dev ready at {base_url}")

        # Bootstrap Desktop against real local Worker, add seed note, push initial sync + MNP1 snapshot
        rc, out = run_pty_cmd(
            tmp_desktop,
            ["device", "bootstrap", "--url", base_url],
            [],
            env_extra={**env_extra, "MYNOTE_BOOTSTRAP_TOKEN": boot_token},
        )
        assert rc == 0, f"desktop bootstrap failed ({rc}): {out}"
        run_cli(tmp_desktop, ["--json", "add", note_seed_canary], env_extra=env_extra)
        run_cli(tmp_desktop, ["--json", "sync", "push"], env_extra=env_extra)

        # Start real Desktop mynote daemon (cloud sync enabled, hermetic clipboard mock, no OS popups)
        daemon_env = {**os.environ, **env_extra}
        daemon = subprocess.Popen(
            [str(BIN), "--data-dir", str(tmp_desktop), "daemon", "--port", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=daemon_env,
        )
        desk_open_url, desk_port = wait_for_open_url(tmp_desktop, env_extra)
        print(f"[m4-e2e] 2. Real Desktop mynote daemon ready on http://localhost:{desk_port}")

        with sync_playwright() as p:
            # =====================================================================
            # PART A: DESKTOP CHROMIUM AUDIT
            # =====================================================================
            chrom = p.chromium.launch()
            c_ctx = chrom.new_context(viewport={"width": 1440, "height": 900}, locale="en-US")
            c_page = c_ctx.new_page()
            c_errors: list[str] = []
            c_page.on("pageerror", lambda err: c_errors.append(f"pageerror: {err}"))
            c_page.on("console", lambda msg: c_errors.append(f"console.error: {msg.text}") if msg.type == "error" else None)
            c_page.add_init_script(INIT_AUDIT_HOOKS_JS)

            c_page.goto(desk_open_url, wait_until="networkidle")
            c_page.wait_for_selector(".block-card", timeout=15000)

            # Viewport geometry (1440x900 & 900x700, EN & zh-CN)
            assert_geometry(c_page, "desk-chrom-1440-en")
            c_page.click('[data-testid="lang-opt-zh-CN"]')
            assert_geometry(c_page, "desk-chrom-1440-zh")
            c_page.set_viewport_size({"width": 900, "height": 700})
            assert_geometry(c_page, "desk-chrom-900-zh")
            c_page.click('[data-testid="lang-opt-en"]')
            assert_geometry(c_page, "desk-chrom-900-en")
            c_page.set_viewport_size({"width": 1440, "height": 900})

            # Open Clipboard drawer
            c_page.click('[data-testid="clip-inbox-btn"]')
            c_page.wait_for_selector('[data-testid="clip-drawer"]:not(.hidden)', timeout=5000)
            assert_geometry(c_page, "desk-chrom-1440-drawer-open")

            # Send text item
            c_page.fill('[data-testid="clip-send-text"]', desktop_clip_text)
            with c_page.expect_response(lambda r: "/v1/local/clip" in r.url and r.request.method == "POST" and r.status == 200):
                c_page.click('[data-testid="clip-send-submit"]')
            c_page.wait_for_function(
                f"() => document.querySelector('[data-testid=\"clip-list\"]')?.innerText?.includes('{desktop_clip_text}')",
                timeout=10000,
            )

            # Send real valid 24x24 PNG image
            with c_page.expect_response(lambda r: "/v1/local/clip" in r.url and r.request.method == "POST" and r.status == 200):
                c_page.set_input_files(
                    '[data-testid="clip-send-image"]',
                    {"name": "sample.png", "mimeType": "image/png", "buffer": desktop_png},
                )
            c_page.wait_for_selector('[data-testid="clip-list"] img.clip-thumb-img', timeout=10000)
            thumb_src = c_page.get_attribute('[data-testid="clip-list"] img.clip-thumb-img', "src") or ""
            assert thumb_src.startswith("data:image/") and "svg" not in thumb_src.lower(), (
                f"Expected safe bitmap thumbnail data URL, got: {thumb_src[:80]}"
            )

            # Reject crafted image/svg+xml -> visible clip-error, 0 <svg> injected, 0 upload!
            svg_uploads: list[str] = []
            c_page.on(
                "request",
                lambda req: svg_uploads.append(req.url) if "/v1/local/clip" in req.url and req.method == "POST" else None,
            )
            c_page.set_input_files(
                '[data-testid="clip-send-image"]',
                {"name": "evil.svg", "mimeType": "image/svg+xml", "buffer": evil_svg},
            )
            c_page.wait_for_selector('[data-testid="clip-error"]:not(.hidden)', timeout=5000)
            assert svg_uploads == [], f"SVG upload must NOT hit network: {svg_uploads}"
            injected_svg = c_page.evaluate(
                """() => ({
                    evilCount: document.querySelectorAll('[data-testid="clip-list"] svg[onload], [data-testid="clip-list"] img[src*="svg"], [data-testid="clip-list"] .clip-image-body svg').length,
                    itemCount: document.querySelectorAll('[data-testid="clip-list"] .clip-item').length,
                    xssGlobal: Boolean(window.__xss),
                })"""
            )
            assert injected_svg["evilCount"] == 0 and not injected_svg["xssGlobal"], f"SVG XSS leak: {injected_svg}"
            assert injected_svg["itemCount"] == 2, f"Expected exactly 2 clip items (text+png), got {injected_svg}"

            # Extract clip IDs from DOM
            clip_ids = c_page.evaluate(
                """() => Array.from(document.querySelectorAll('[data-testid="clip-list"] .clip-item')).map(el => ({
                    id: el.dataset.clipId,
                    kind: el.dataset.clipKind,
                }))"""
            )
            png_clip_id = [x["id"] for x in clip_ids if x["kind"] == "image"][0]
            text_clip_id = [x["id"] for x in clip_ids if x["kind"] == "text"][0]

            # Full preview on PNG item -> blob: URL with naturalWidth === 24 & revokes on close!
            c_page.click(f'[data-testid="clip-preview-{png_clip_id}"]')
            c_page.wait_for_function(
                """() => {
                    const img = document.querySelector('[data-testid="clip-preview-modal"] img.clip-preview-img');
                    return img && img.src.startsWith('blob:') && img.complete && img.naturalWidth === 24 && img.naturalHeight === 24;
                }""",
                timeout=10000,
            )
            preview_blob_url = c_page.get_attribute('[data-testid="clip-preview-modal"] img.clip-preview-img', "src")
            assert preview_blob_url and preview_blob_url.startswith("blob:")
            c_page.click('[data-testid="clip-preview-close"]')
            c_page.wait_for_selector('[data-testid="clip-preview-modal"]', state="hidden", timeout=5000)
            revoked = c_page.evaluate("() => window.__revokedBlobUrls || []")
            assert preview_blob_url in revoked, f"Expected preview blob URL {preview_blob_url} revoked on close; got {revoked}"

            # Apply + Undo against hermetic MYNOTE_CLIPBOARD_MOCK_FILE
            write_mock_clipboard_text(mock_clip_file, orig_mock_clip)
            with c_page.expect_response(lambda r: f"/v1/local/clip/{text_clip_id}/apply" in r.url and r.status == 200):
                c_page.click(f'[data-testid="clip-apply-{text_clip_id}"]')
            applied_state = read_mock_clipboard(mock_clip_file)
            assert applied_state["decoded_bytes"].decode("utf-8") == desktop_clip_text
            assert applied_state["synced_marker"] is True

            with c_page.expect_response(lambda r: "/v1/local/clip/undo" in r.url and r.status == 200):
                c_page.click('[data-testid="clip-undo-btn"]')
            undone_state = read_mock_clipboard(mock_clip_file)
            assert undone_state["decoded_bytes"].decode("utf-8") == orig_mock_clip

            # Promote text clip -> verify new note block appears in SQLite (`mynote ls --json`)!
            with c_page.expect_response(lambda r: f"/v1/local/clip/{text_clip_id}/promote" in r.url and r.status == 200):
                c_page.click(f'[data-testid="clip-promote-{text_clip_id}"]')
            ls_blocks = json.loads(run_cli(tmp_desktop, ["--json", "ls", "--limit", "50"], env_extra=env_extra).stdout)["data"]
            assert any(desktop_clip_text in (b.get("preview") or "") for b in ls_blocks), (
                f"Promoted clip block missing from SQLite `mynote ls`: {ls_blocks}"
            )

            # Toggle Auto-Watch (UI pause toggle + persisted enabled/auto_apply_mirror via PATCH /v1/local/clip/watch)
            with c_page.expect_response(lambda r: "/v1/local/clip/watch" in r.url and r.request.method == "PATCH" and r.status == 200):
                c_page.click('[data-testid="clip-watch-toggle"]')
            assert c_page.get_attribute('[data-testid="clip-watch-toggle"]', "aria-pressed") == "true"
            with c_page.expect_response(lambda r: "/v1/local/clip/watch" in r.url and r.request.method == "PATCH" and r.status == 200):
                c_page.click('[data-testid="clip-watch-toggle"]')
            assert c_page.get_attribute('[data-testid="clip-watch-toggle"]', "aria-pressed") == "false"

            watch_patch = c_page.evaluate(
                """async () => {
                    const res = await fetch('/v1/local/clip/watch', {
                        method: 'PATCH',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ enabled: true, auto_apply_mirror: 'auto-apply' }),
                        credentials: 'same-origin',
                    });
                    return { status: res.status, json: await res.json() };
                }"""
            )
            assert watch_patch["status"] == 200 and watch_patch["json"]["ok"] is True
            assert watch_patch["json"]["data"]["watch_enabled"] is True
            assert watch_patch["json"]["data"]["auto_apply_mirror"] == "auto-apply"

            cli_watch = json.loads(run_cli(tmp_desktop, ["--json", "clip", "watch"], env_extra=env_extra).stdout)["data"]
            assert cli_watch["watch_enabled"] is True
            assert cli_watch["auto_apply_mirror"] == "auto-apply"

            # Reset watch back to default OFF (`enabled: false, auto_apply_mirror: inbox-only`)
            run_cli(
                tmp_desktop,
                ["--json", "clip", "watch", "--disable", "--auto-apply", "inbox-only"],
                env_extra=env_extra,
            )
            cli_watch_off = json.loads(run_cli(tmp_desktop, ["--json", "clip", "watch"], env_extra=env_extra).stdout)["data"]
            assert cli_watch_off["watch_enabled"] is False
            assert cli_watch_off["auto_apply_mirror"] == "inbox-only"

            c_csp = c_page.evaluate("() => window.__cspViolations || []")
            assert c_csp == [], f"Desktop Chromium CSP violations: {c_csp}"
            assert c_errors == [], f"Desktop Chromium errors: {c_errors}"
            chrom.close()
            print("[m4-e2e] 3. Desktop Chromium audit (geometry, text+PNG send, SVG reject, blob preview+revoke, apply+undo, promote, watch persist): PASS!")

            # =====================================================================
            # PART B: DESKTOP WEBKIT AUDIT
            # =====================================================================
            wk_open_url, _ = wait_for_open_url(tmp_desktop, env_extra)
            webkit = p.webkit.launch()
            dw_ctx = webkit.new_context(viewport={"width": 1440, "height": 900}, locale="en-US")
            dw_page = dw_ctx.new_page()
            dw_errors: list[str] = []
            dw_page.on("pageerror", lambda err: dw_errors.append(f"pageerror: {err}"))
            dw_page.on("console", lambda msg: dw_errors.append(f"console.error: {msg.text}") if msg.type == "error" else None)
            dw_page.add_init_script(INIT_AUDIT_HOOKS_JS)

            dw_page.goto(wk_open_url, wait_until="networkidle")
            dw_page.wait_for_selector(".block-card", timeout=15000)
            assert_geometry(dw_page, "desk-webkit-1440-en")
            dw_page.click('[data-testid="lang-opt-zh-CN"]')
            dw_page.set_viewport_size({"width": 900, "height": 700})
            assert_geometry(dw_page, "desk-webkit-900-zh")
            dw_page.click('[data-testid="lang-opt-en"]')
            dw_page.set_viewport_size({"width": 1440, "height": 900})

            dw_page.click('[data-testid="clip-inbox-btn"]')
            dw_page.wait_for_selector('[data-testid="clip-list"] img.clip-thumb-img', timeout=10000)
            dw_page.click(f'[data-testid="clip-preview-{png_clip_id}"]')
            dw_page.wait_for_function(
                """() => {
                    const img = document.querySelector('[data-testid="clip-preview-modal"] img.clip-preview-img');
                    return img && img.src.startsWith('blob:') && img.complete && img.naturalWidth === 24;
                }""",
                timeout=10000,
            )
            dw_blob = dw_page.get_attribute('[data-testid="clip-preview-modal"] img.clip-preview-img', "src")
            dw_page.click('[data-testid="clip-preview-close"]')
            dw_page.wait_for_selector('[data-testid="clip-preview-modal"]', state="hidden", timeout=5000)
            assert dw_blob in dw_page.evaluate("() => window.__revokedBlobUrls || []")
            assert dw_page.evaluate("() => window.__cspViolations || []") == []
            assert dw_errors == [], f"Desktop WebKit errors: {dw_errors}"
            dw_ctx.close()
            print("[m4-e2e] 4. Desktop WebKit audit (geometry EN/zh-CN, drawer render, PNG blob preview+revoke, 0 errors): PASS!")

            # =====================================================================
            # PART C: MOBILE PWA WEBKIT AUDIT (read+clip + SEC-08 ext + SEC-09)
            # =====================================================================
            rc, pair_out = run_pty_cmd(
                tmp_desktop,
                ["device", "add", "--name", "iPhoneClip", "--scope", "read+clip"],
                [],
                env_extra=env_extra,
            )
            assert rc == 0, f"read+clip device add failed ({rc}): {pair_out}"
            m = re.search(r"(mynote-pair:v1:[A-Za-z0-9_-]+)", pair_out)
            assert m, f"could not extract read+clip pairing code from:\n{pair_out}"
            pwa_pair_code = m.group(1)

            m_ctx = webkit.new_context(viewport={"width": 390, "height": 844}, locale="en-US")
            m_page = m_ctx.new_page()
            m_errors: list[str] = []
            m_page.on("pageerror", lambda err: m_errors.append(f"pageerror: {err}"))
            m_page.on(
                "console",
                lambda msg: m_errors.append(f"console.error: {msg.text}")
                if msg.type == "error" and "status of 404" not in msg.text and "Failed to load resource" not in msg.text
                else None,
            )
            m_page.add_init_script(INIT_AUDIT_HOOKS_JS)

            res = m_page.goto(base_url, wait_until="networkidle")
            assert res is not None and res.status == 200
            csp = res.headers.get("content-security-policy", "")
            assert "default-src 'none'" in csp and "script-src 'self' 'wasm-unsafe-eval'" in csp

            m_page.wait_for_selector('[data-testid="pwa-pair-input"]', timeout=15000)
            m_page.fill('[data-testid="pwa-pair-input"]', pwa_pair_code)
            m_page.click('[data-testid="pwa-pair-submit"]')

            # Wait for seed note on Notes tab -> strictly read-only & zero overflow in EN & zh-CN
            m_page.wait_for_function(
                f"() => document.body.innerText.includes('{note_seed_canary}')",
                timeout=20000,
            )
            editable_notes = m_page.evaluate(
                "() => document.querySelectorAll('.ro-block textarea, .ro-block [contenteditable]').length"
            )
            assert editable_notes == 0, f"PWA Notes tab must be strictly read-only, found {editable_notes}"
            assert_geometry(m_page, "pwa-390-notes-en")
            m_page.click('[data-testid="pwa-lang-opt-zh-CN"]')
            assert_geometry(m_page, "pwa-390-notes-zh")
            m_page.click('[data-testid="pwa-lang-opt-en"]')

            # Switch to Clipboard tab -> Desktop's text & PNG arrived & decrypted in memory!
            m_page.click('[data-testid="pwa-tab-clip"]')
            m_page.wait_for_selector('[data-testid="pwa-clip-view"]', timeout=10000)
            m_page.wait_for_function(
                f"""() => {{
                    const list = document.querySelector('[data-testid="pwa-clip-list"]');
                    const img = list?.querySelector('img.pwa-clip-thumb-img');
                    return Boolean(list && list.innerText.includes('{desktop_clip_text}') && img && img.src.startsWith('data:image/'));
                }}""",
                timeout=20000,
            )
            assert_geometry(m_page, "pwa-390-clip-en")
            m_page.click('[data-testid="pwa-lang-opt-zh-CN"]')
            assert_geometry(m_page, "pwa-390-clip-zh")
            m_page.click('[data-testid="pwa-lang-opt-en"]')

            # Send text canary from PWA (`WasmClipCodec` -> POST /v1/clip)
            m_page.fill('[data-testid="pwa-clip-textarea"]', pwa_clip_text)
            with m_page.expect_response(lambda r: r.url.endswith("/v1/clip") and r.request.method == "POST" and r.status == 200):
                m_page.click('[data-testid="pwa-clip-send"]')
            m_page.wait_for_function(
                f"() => document.querySelector('[data-testid=\"pwa-clip-list\"]')?.innerText?.includes('{pwa_clip_text}')",
                timeout=10000,
            )

            # Send real 20x20 PNG image from PWA (`WasmClipCodec` -> PUT /v1/clip/blob)
            with m_page.expect_response(lambda r: "/v1/clip/blob" in r.url and r.request.method == "PUT" and r.status == 200):
                m_page.set_input_files(
                    '[data-testid="pwa-clip-file"]',
                    {"name": "mobile.png", "mimeType": "image/png", "buffer": pwa_png},
                )
            m_page.wait_for_function(
                "() => document.querySelectorAll('[data-testid=\"pwa-clip-list\"] img.pwa-clip-thumb-img').length >= 2",
                timeout=15000,
            )

            # Refuse crafted image/svg+xml in PWA -> visible pwa-clip-error & 0 SVG upload
            pwa_svg_reqs: list[str] = []
            m_page.on(
                "request",
                lambda req: pwa_svg_reqs.append(req.url) if "/v1/clip/blob" in req.url and req.method == "PUT" else None,
            )
            m_page.set_input_files(
                '[data-testid="pwa-clip-file"]',
                {"name": "evil.svg", "mimeType": "image/svg+xml", "buffer": evil_svg},
            )
            m_page.wait_for_selector('[data-testid="pwa-clip-error"]:not(.hidden)', timeout=5000)
            assert pwa_svg_reqs == [], f"PWA must not upload SVG blob: {pwa_svg_reqs}"

            # Verify Desktop `mynote clip history --json` receives BOTH text & PNG from PWA!
            desk_items = wait_for_desktop_clip_history(
                tmp_desktop,
                env_extra,
                lambda items: (
                    any(pwa_clip_text in (it.get("text_preview") or "") for it in items)
                    and any(it.get("kind") == "image" and it.get("width") == 20 and it.get("height") == 20 for it in items)
                ),
                "Desktop receives PWA text canary and 20x20 PNG image",
            )
            assert len(desk_items) >= 4

            # Android `share_target` handoff cleanup (`SEC-08`):
            # Seed `mynote-share-handoff` cache -> navigate to `/?clip_share=1` -> uploaded & cache DELETED!
            seeded = m_page.evaluate(
                """async (canary) => {
                    if (!('caches' in window)) return { supported: false };
                    const cache = await caches.open('mynote-share-handoff');
                    await cache.put(
                        '/__share-handoff/latest',
                        new Response(JSON.stringify({ kind: 'text', text: canary }), {
                            headers: {
                                'content-type': 'application/json; charset=utf-8',
                                'x-share-kind': 'text',
                            },
                        }),
                    );
                    return { supported: true, seeded: await caches.has('mynote-share-handoff') };
                }""",
                share_handoff_canary,
            )
            assert seeded.get("supported") is True and seeded.get("seeded") is True, (
                f"Expected CacheStorage available to seed share handoff: {seeded}"
            )

            m_page.goto(f"{base_url}/?clip_share=1", wait_until="networkidle")
            m_page.wait_for_function(
                f"() => document.querySelector('[data-testid=\"pwa-clip-list\"]')?.innerText?.includes('{share_handoff_canary}')",
                timeout=20000,
            )
            handoff_still_exists = m_page.evaluate("async () => await caches.has('mynote-share-handoff')")
            assert handoff_still_exists is False, (
                "SEC-08 VIOLATION: transient 'mynote-share-handoff' cache still exists after consumption!"
            )

            wait_for_desktop_clip_history(
                tmp_desktop,
                env_extra,
                lambda items: any(share_handoff_canary in (it.get("text_preview") or "") for it in items),
                "Desktop receives Android share_target handoff canary",
            )

            # SEC-08 FORENSIC STORAGE AUDIT (7 IDB stores + non-extractable CryptoKey + 0 plaintext + 0 cache residue)
            audit = m_page.evaluate(
                """async () => {
                    const ls = Object.entries(localStorage);
                    const ss = Object.entries(sessionStorage);
                    const cacheNames = 'caches' in window ? await caches.keys() : [];
                    const cacheEntries = [];
                    if ('caches' in window) {
                        for (const name of cacheNames) {
                            const c = await caches.open(name);
                            for (const req of await c.keys()) {
                                const resp = await c.match(req);
                                const body = resp ? await resp.clone().text().catch(() => '') : '';
                                cacheEntries.push({ cache: name, url: req.url, body });
                            }
                        }
                    }

                    const db = await new Promise((resolve, reject) => {
                        const r = indexedDB.open('mynote_pwa_v1');
                        r.onsuccess = () => resolve(r.result);
                        r.onerror = () => reject(r.error);
                    });
                    const storeNames = [...db.objectStoreNames].sort();
                    const encodeVal = (v) => {
                        if (v instanceof CryptoKey) {
                            return { __cryptoKey: true, type: v.type, extractable: v.extractable, algorithm: v.algorithm };
                        }
                        if (v instanceof ArrayBuffer) {
                            const u = new Uint8Array(v);
                            return { __bytesUtf8: new TextDecoder('utf-8', { fatal: false }).decode(u), __len: u.length };
                        }
                        if (ArrayBuffer.isView(v)) {
                            const u = new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
                            return { __bytesUtf8: new TextDecoder('utf-8', { fatal: false }).decode(u), __len: u.length };
                        }
                        if (Array.isArray(v)) {
                            const allBytes = v.length > 0 && v.every(x => typeof x === 'number' && x >= 0 && x <= 255);
                            if (allBytes) {
                                return { __numBytesUtf8: new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(v)), __len: v.length };
                            }
                            return v.map(encodeVal);
                        }
                        if (v && typeof v === 'object') {
                            const out = {};
                            for (const [k, val] of Object.entries(v)) out[k] = encodeVal(val);
                            return out;
                        }
                        return v;
                    };

                    const stores = {};
                    let wrapKeyExtractable = null;
                    for (const name of storeNames) {
                        const tx = db.transaction(name, 'readonly');
                        const st = tx.objectStore(name);
                        const keys = await new Promise((res, rej) => { const r = st.getAllKeys(); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
                        const vals = await new Promise((res, rej) => { const r = st.getAll(); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
                        stores[name] = keys.map((k, i) => {
                            if (name === 'device_keystore' && k === 'device_wrap_key' && vals[i] instanceof CryptoKey) {
                                wrapKeyExtractable = vals[i].extractable;
                            }
                            return { key: k, value: encodeVal(vals[i]) };
                        });
                    }
                    db.close();
                    return { ls, ss, cacheNames, cacheEntries, storeNames, wrapKeyExtractable, stores };
                }"""
            )

            expected_stores = sorted(
                ["block_keys", "blocks", "buffers", "clip_items", "device_keystore", "meta", "vault_header"]
            )
            assert audit["storeNames"] == expected_stores, (
                f"Expected exact 7 IDB stores {expected_stores}, got {audit['storeNames']}"
            )
            assert audit["wrapKeyExtractable"] is False, (
                f"SEC-08 VIOLATION: device_wrap_key.extractable={audit['wrapKeyExtractable']}"
            )
            allowed_ls_keys = {"mynote.locale", "mynote.theme"}
            unexpected_ls = [(k, v) for k, v in audit["ls"] if k not in allowed_ls_keys]
            assert unexpected_ls == [], f"SEC-08 VIOLATION: unexpected localStorage entries: {unexpected_ls}"
            assert len(audit["ss"]) == 0, f"SEC-08 VIOLATION: sessionStorage non-empty: {audit['ss']}"
            assert "mynote-share-handoff" not in audit["cacheNames"], (
                f"SEC-08 VIOLATION: share handoff cache residue found: {audit['cacheNames']}"
            )
            for ce in audit["cacheEntries"]:
                assert "/v1/" not in ce["url"], f"SEC-08 VIOLATION: /v1/ API cached: {ce['url']}"

            assert len(audit["stores"]["clip_items"]) >= 5, (
                f"Expected >= 5 ciphertext clip_items in IDB, got {len(audit['stores']['clip_items'])}"
            )
            full_dump = json.dumps(audit)
            for canary in (pwa_clip_text, share_handoff_canary, desktop_clip_text, note_seed_canary):
                assert canary not in full_dump, (
                    f"SEC-08 FORENSIC VIOLATION: plaintext canary '{canary}' found in persistent WebKit storage!"
                )

            assert m_page.evaluate("() => window.__cspViolations || []") == []
            assert m_errors == [], f"Mobile PWA WebKit errors: {m_errors}"
            m_ctx.close()
            webkit.close()
            print("[m4-e2e] 5. Mobile PWA WebKit audit (read+clip, text+PNG sync, SVG reject, share_target wipe, 7-store SEC-08 forensic audit): PASS!")

        # =====================================================================
        # PART D: clip-write TOKEN ISOLATION CROSS-CHECK (SEC-09)
        # =====================================================================
        verify_clip_write_token_isolation(tmp_desktop, base_url, env_extra)

        print("ALL M4 CLIPBOARD CHROMIUM + WEBKIT SEC-08 / SEC-09 E2E AUDITS PASSED!")
    finally:
        if daemon is not None and daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
        if wrangler.poll() is None:
            wrangler.terminate()
            try:
                wrangler.wait(timeout=5)
            except subprocess.TimeoutExpired:
                wrangler.kill()
        shutil.rmtree(tmp_desktop, ignore_errors=True)
        shutil.rmtree(tmp_wrangler, ignore_errors=True)


if __name__ == "__main__":
    main()
