#!/usr/bin/env python3
"""
Prototype C Real-Browser CDP Runtime Geometry, Console Error & SQLite Equivalence Gate.

Implements `eval-harness` Prototype C 5-point headless browser checks + escaped v0.2.0 -> v0.2.1
defect regression checks against REAL `mynote daemon`, REAL `wrangler dev --local`, and REAL
Playwright Chromium + WebKit:
  1. Zero `console.error` (`page.on("console")`) and zero uncaught `pageerror` across all flows.
  2. Multi-viewport zero horizontal overflow (`scrollWidth <= innerWidth`) on Desktop (`1440x900`,
     `900x700` in both EN & zh-CN) and Mobile Read-Only PWA (`390x844` in both EN & zh-CN), plus
     `.sr-only` containing-block confinement (`offsetParent !== document.body`).
  3. Single-line topbar status badges (no vertical wrapping) & mobile primary tap-target geometry.
  4. Escaped defect ratchet:
     - Live WebSocket `/v1/local/ws` + Buffer Switcher (`Mod+P` -> create `"sprint-log"`): zero
       duplicate `.buf-tab` race, and DOM tab order === `mynote buf ls --json`.
     - Focus-only `.block-header` visibility + `Mod+Alt+ArrowDown` focus navigation +
       `Mod+Alt+Shift+ArrowUp` block reorder persisted to SQLite (`mynote ls --json` === DOM order).
  5. High-frequency live WS burst: 25 rapid CLI/UDS writes + buffer roundtrip converge to exact
     SQLite snapshot with zero duplicate `[data-block-id]` nodes and bounded DOM card count.
"""

from __future__ import annotations

import json
import os
import pty
import re
import select
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "target" / "debug" / "mynote"
CLOUD_DIR = ROOT / "cloud-cf"
MOD_KEY = "ControlOrMeta"

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

  const badgeWrapViolations = [];
  for (const sel of ['[data-testid="sync-pill"]', '.ro-pill']) {
    for (const el of document.querySelectorAll(sel)) {
      const cs = window.getComputedStyle(el);
      if (cs.display === 'none' || cs.visibility === 'hidden') continue;
      const rect = el.getBoundingClientRect();
      const lh = parseFloat(cs.lineHeight) || 18;
      if (rect.height > lh * 2.2) {
        badgeWrapViolations.push({ sel, height: rect.height, lineHeight: lh });
      }
    }
  }

  return {
    scrollWidth,
    innerWidth,
    overflowPx: scrollWidth - innerWidth,
    srLeaks,
    badgeWrapViolations,
  };
}"""


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_cli(
    data_dir: Path,
    args: list[str],
    *,
    stdin_text: str | None = None,
    env_extra: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    kwargs = {
        "text": True,
        "capture_output": True,
        "env": env,
        "check": check,
        "timeout": 25,
    }
    if stdin_text is None:
        kwargs["stdin"] = subprocess.DEVNULL
    else:
        kwargs["input"] = stdin_text
    return subprocess.run([str(BIN), "--data-dir", str(data_dir), *args], **kwargs)


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


def wait_for_open_url(data_dir: Path, timeout_s: float = 15.0) -> tuple[str, int]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        proc = run_cli(data_dir, ["--json", "open"], check=False)
        if proc.returncode == 0:
            j = json.loads(proc.stdout)
            return j["data"]["url"], int(j["data"]["port"])
        time.sleep(0.15)
    raise RuntimeError("timed out waiting for mynote daemon UDS OpenTicket")


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


def assert_geometry_invariants(page, label: str) -> None:
    g = page.evaluate(GEOMETRY_AUDIT_JS)
    assert g["overflowPx"] <= 0, (
        f"[{label}] horizontal viewport overflow: scrollWidth={g['scrollWidth']} > innerWidth={g['innerWidth']}"
    )
    assert g["srLeaks"] == [], f"[{label}] .sr-only leaked to document.body containing block: {g['srLeaks']}"
    assert g["badgeWrapViolations"] == [], f"[{label}] single-line badge wrapped vertically: {g['badgeWrapViolations']}"


def verify_desktop_cdp_equivalence(p) -> None:
    tmp = Path(tempfile.mkdtemp(prefix="mynote-cdp-desk-"))
    daemon = subprocess.Popen(
        [str(BIN), "--data-dir", str(tmp), "daemon", "--port", "0", "--no-cloud-sync"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        open_url, port = wait_for_open_url(tmp)
        print(f"[cdp-ui] 1. Desktop daemon listening on http://localhost:{port}")

        # Seed 2 initial blocks in default `scratch` buffer
        run_cli(tmp, ["--json", "add", "--buf", "scratch", "--lang", "json"], stdin_text='{"seed": 1}')
        run_cli(tmp, ["--json", "add", "--buf", "scratch", "--lang", "markdown"], stdin_text="# Heading\n\nBody line")

        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 900}, locale="en-US")
        page = context.new_page()

        console_errors: list[str] = []
        page_errors: list[str] = []
        page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda err: page_errors.append(str(err)))

        page.goto(open_url, wait_until="networkidle")
        page.wait_for_selector(".block-card", timeout=15000)

        # 1. Geometry & zero-overflow check at 1440x900 (EN & zh-CN) + narrow 900x700
        assert_geometry_invariants(page, "desktop-1440-en")
        page.click('[data-testid="lang-opt-zh-CN"]')
        assert_geometry_invariants(page, "desktop-1440-zh")
        page.set_viewport_size({"width": 900, "height": 700})
        assert_geometry_invariants(page, "desktop-900-zh")
        page.click('[data-testid="lang-opt-en"]')
        page.set_viewport_size({"width": 1440, "height": 900})
        assert_geometry_invariants(page, "desktop-1440-restored")
        print("[cdp-ui] 2. Desktop geometry (1440x900 & 900x700, EN & zh-CN): 0 overflow, 0 .sr-only leaks, 0 badge wrap")

        # 2. Escaped v0.2.0 defect ratchet: create buffer via Mod+P while live /v1/local/ws is open -> ZERO duplicate tabs!
        page.keyboard.press(f"{MOD_KEY}+p")
        page.wait_for_selector('[data-testid="buffer-filter-input"]', timeout=5000)
        page.fill('[data-testid="buffer-filter-input"]', "sprint-log")
        with page.expect_response(lambda r: "/v1/local/buffers" in r.url and r.request.method == "POST" and r.status == 200):
            page.keyboard.press("Enter")
        time.sleep(0.25)

        dom_buf_names = page.evaluate(
            """() => Array.from(document.querySelectorAll('.buf-tab')).map(el => el.textContent?.trim() || '')"""
        )
        cli_bufs = json.loads(run_cli(tmp, ["--json", "buf", "ls"]).stdout)["data"]
        cli_buf_names = [b["name"] for b in cli_bufs]
        assert dom_buf_names.count("sprint-log") == 1, f"Duplicate buffer tab regression: {dom_buf_names}"
        assert dom_buf_names == cli_buf_names, f"DOM buffer tabs {dom_buf_names} != SQLite buffers {cli_buf_names}"
        print("[cdp-ui] 3. Live WS buffer creation dedup & SQLite buffer order equivalence PASS")

        # 3. Focus-only .block-header + Mod+Alt+ArrowDown navigation + Mod+Alt+Shift+ArrowUp reorder -> SQLite equivalence!
        b_alpha = json.loads(run_cli(tmp, ["--json", "add", "--buf", "sprint-log", "alpha-first"]).stdout)["data"]["block_id"]
        b_beta = json.loads(run_cli(tmp, ["--json", "add", "--buf", "sprint-log", "beta-second"]).stdout)["data"]["block_id"]
        page.wait_for_selector(f'[data-block-id="{b_beta}"]', timeout=10000)

        page.locator(f'[data-block-id="{b_alpha}"] .cm-content').click()
        hdr_vis = page.evaluate(
            """([id1, id2]) => ({
                focusedDisplay: getComputedStyle(document.querySelector(`[data-block-id="${id1}"] .block-header`)).display,
                unfocusedDisplay: getComputedStyle(document.querySelector(`[data-block-id="${id2}"] .block-header`)).display,
            })""",
            [b_alpha, b_beta],
        )
        assert hdr_vis["focusedDisplay"] != "none", f"Focused block header hidden: {hdr_vis}"
        assert hdr_vis["unfocusedDisplay"] == "none", f"Unfocused block header not hidden: {hdr_vis}"

        # Navigate focus down to b_beta via Mod+Alt+ArrowDown, then move b_beta BEFORE b_alpha via Mod+Alt+Shift+ArrowUp!
        page.keyboard.press(f"{MOD_KEY}+Alt+ArrowDown")
        page.wait_for_selector(f'[data-block-id="{b_beta}"].focused', timeout=5000)
        with page.expect_response(lambda r: f"/v1/local/blocks/{b_beta}" in r.url and r.request.method == "PATCH" and r.status == 200):
            page.keyboard.press(f"{MOD_KEY}+Alt+Shift+ArrowUp")
        page.wait_for_function(
            f"""() => {{
                const ids = Array.from(document.querySelectorAll('.block-card')).map(el => el.dataset.blockId);
                return ids.indexOf('{b_beta}') >= 0 && ids.indexOf('{b_beta}') < ids.indexOf('{b_alpha}');
            }}""",
            timeout=5000,
        )
        sql_sprint_ids = [b["id"] for b in json.loads(run_cli(tmp, ["--json", "ls", "--buf", "sprint-log", "--limit", "50"]).stdout)["data"]]
        dom_sprint_ids = page.evaluate(
            """() => Array.from(document.querySelectorAll('.block-card')).map(el => el.dataset.blockId)"""
        )
        assert dom_sprint_ids == sql_sprint_ids, f"DOM block order {dom_sprint_ids} != SQLite order {sql_sprint_ids}"
        assert sql_sprint_ids.index(b_beta) < sql_sprint_ids.index(b_alpha)
        print("[cdp-ui] 4. Focus-only header, Mod+Alt+Arrow nav & Mod+Alt+Shift+Arrow reorder === SQLite PASS")

        # 4. High-frequency live WS stream burst (25 rapid CLI writes + updates) + buffer switch roundtrip
        burst_target = b_alpha
        for i in range(15):
            run_cli(tmp, ["--json", "add", "--buf", "sprint-log", f"burst-item-{i:02d}"])
        for rev in range(10):
            cur = json.loads(run_cli(tmp, ["--json", "block", "get", burst_target]).stdout)["data"]
            cmd = ["--json", "block", "update", burst_target, f"alpha-rev-{rev}"]
            for h in cur["head_op_ids"]:
                cmd.extend(["--expected-head", h])
            run_cli(tmp, cmd)

        expected_sql = json.loads(run_cli(tmp, ["--json", "ls", "--buf", "sprint-log", "--limit", "100"]).stdout)["data"]
        expected_ids = [b["id"] for b in expected_sql]
        page.wait_for_function(
            f"() => document.querySelectorAll('.block-card').length === {len(expected_ids)}",
            timeout=10000,
        )
        # Switch to scratch and back to sprint-log -> ensure zero stale WS overwrite or leaked duplicate DOM nodes
        page.locator(".buf-tab", has_text="scratch").click()
        page.wait_for_function("() => document.querySelectorAll('.block-card').length === 2", timeout=5000)
        page.locator(".buf-tab", has_text="sprint-log").click()
        page.wait_for_function(
            f"() => document.querySelectorAll('.block-card').length === {len(expected_ids)}",
            timeout=5000,
        )

        dom_after_burst = page.evaluate(
            """() => Array.from(document.querySelectorAll('.block-card')).map(el => ({
                id: el.dataset.blockId,
                text: el.querySelector('.cm-content')?.innerText?.trim() || '',
            }))"""
        )
        dom_ids_after = [x["id"] for x in dom_after_burst]
        assert len(set(dom_ids_after)) == len(dom_ids_after), f"Duplicate block-card DOM nodes: {dom_ids_after}"
        assert dom_ids_after == expected_ids, f"Post-burst DOM IDs {dom_ids_after} != SQLite IDs {expected_ids}"
        alpha_dom = [x["text"] for x in dom_after_burst if x["id"] == burst_target][0]
        assert alpha_dom == "alpha-rev-9", f"Expected latest burst update 'alpha-rev-9', got {alpha_dom!r}"
        assert_geometry_invariants(page, "desktop-post-burst")

        assert console_errors == [], f"Unexpected console.error in Desktop Chromium: {console_errors}"
        assert page_errors == [], f"Unexpected pageerror in Desktop Chromium: {page_errors}"
        print(f"[cdp-ui] 5. High-frequency 25-op WS burst + buffer roundtrip === SQLite ({len(expected_ids)} blocks, 0 console.error) PASS")
        browser.close()
    finally:
        if daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
        shutil.rmtree(tmp, ignore_errors=True)


def verify_mobile_pwa_webkit_geometry(p) -> None:
    assert (ROOT / "web" / "dist-pwa" / "index.html").exists(), "web/dist-pwa missing; run `pnpm --dir web build:pwa`"
    wrangler_bin = CLOUD_DIR / "node_modules" / ".bin" / "wrangler"
    assert wrangler_bin.exists(), f"wrangler missing at {wrangler_bin}"

    port = pick_free_port()
    base_url = f"http://127.0.0.1:{port}"
    boot_token = "cdp-pwa-webkit-bootstrap-token"
    tmp_desk = Path(tempfile.mkdtemp(prefix="mynote-cdp-pwa-desk-"))
    tmp_cf = Path(tempfile.mkdtemp(prefix="mynote-cdp-pwa-cf-"))

    wrangler = subprocess.Popen(
        [
            str(wrangler_bin),
            "dev",
            "--local",
            "--ip",
            "127.0.0.1",
            "--port",
            str(port),
            "--persist-to",
            str(tmp_cf),
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
    try:
        wait_for_wrangler(base_url, wrangler)
        rc, out = run_pty_cmd(
            tmp_desk,
            ["device", "bootstrap", "--url", base_url],
            [],
            env_extra={"MYNOTE_BOOTSTRAP_TOKEN": boot_token},
        )
        assert rc == 0, f"bootstrap failed ({rc}): {out}"

        long_unbroken = "https://example.com/" + ("very_long_segment_" * 8)
        run_cli(tmp_desk, ["--json", "add", f"Mobile overflow stress: {long_unbroken}"])
        run_cli(tmp_desk, ["--json", "sync", "push"])

        rc, pair_out = run_pty_cmd(tmp_desk, ["device", "add", "--name", "iPhoneCDP", "--scope", "read"], [])
        assert rc == 0, f"device add failed ({rc}): {pair_out}"
        m = re.search(r"(mynote-pair:v1:[A-Za-z0-9_-]+)", pair_out)
        assert m, f"pairing code missing:\n{pair_out}"
        pair_code = m.group(1)

        browser = p.webkit.launch()
        context = browser.new_context(viewport={"width": 390, "height": 844}, locale="en-US")
        page = context.new_page()

        console_errors: list[str] = []
        page_errors: list[str] = []
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
        page.on("pageerror", lambda err: page_errors.append(str(err)))

        page.goto(base_url, wait_until="networkidle")
        page.wait_for_selector('[data-testid="pwa-pair-input"]', timeout=15000)

        # Check Onboarding geometry in EN & zh-CN at 390x844 + primary button bounds
        assert_geometry_invariants(page, "pwa-390-onboard-en")
        qr_box = page.locator('[data-testid="pwa-scan-qr-btn"]').bounding_box()
        assert qr_box is not None and qr_box["width"] >= 44 and qr_box["x"] >= 0 and (qr_box["x"] + qr_box["width"]) <= 390, (
            f"PWA Scan QR button clipped or undersized on 390px viewport: {qr_box}"
        )
        page.click('[data-testid="pwa-lang-opt-zh-CN"]')
        assert_geometry_invariants(page, "pwa-390-onboard-zh")
        page.click('[data-testid="pwa-lang-opt-en"]')

        # Pair and check Paired state geometry with long unbroken URL string at 390x844
        page.fill('[data-testid="pwa-pair-input"]', pair_code)
        page.click('[data-testid="pwa-pair-submit"]')
        page.wait_for_function("() => document.body.innerText.includes('Mobile overflow stress:')", timeout=20000)
        assert_geometry_invariants(page, "pwa-390-paired-en")
        page.click('[data-testid="pwa-lang-opt-zh-CN"]')
        assert_geometry_invariants(page, "pwa-390-paired-zh")

        assert console_errors == [], f"Unexpected console.error in Mobile WebKit PWA: {console_errors}"
        assert page_errors == [], f"Unexpected pageerror in Mobile WebKit PWA: {page_errors}"
        print("[cdp-ui] 6. Mobile WebKit PWA 390x844 geometry (Onboard & Paired, EN & zh-CN, long URL wrap, 0 console.error) PASS")
        browser.close()
    finally:
        wrangler.terminate()
        try:
            wrangler.wait(timeout=5)
        except subprocess.TimeoutExpired:
            wrangler.kill()
        shutil.rmtree(tmp_desk, ignore_errors=True)
        shutil.rmtree(tmp_cf, ignore_errors=True)


def main() -> None:
    assert BIN.exists(), f"mynote binary missing at {BIN}; run `cargo build --bin mynote` first"
    with sync_playwright() as p:
        verify_desktop_cdp_equivalence(p)
        verify_mobile_pwa_webkit_geometry(p)
    print("ALL PROTOTYPE-C CDP VIEWPORT GEOMETRY, CONSOLE ERROR & SQLITE EQUIVALENCE GATES PASSED!")


if __name__ == "__main__":
    main()
