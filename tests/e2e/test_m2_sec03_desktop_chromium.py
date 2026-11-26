#!/usr/bin/env python3
"""
SEC-03 Real Desktop Daemon + Embedded Web UI + Playwright Chromium E2E Audit.

Verifies against real `mynote daemon --port 0 --no-cloud-sync` and real Chromium:
1. Real ticket exchange (`mynote open --json`) establishes HttpOnly session on `http://localhost:<port>`.
2. Initialize Tier 2 Vault in browser WASM via UI modal (real Argon2id).
3. Create JSON block, lock into Tier 2 Vault, edit to a Tier-2-only canary, and click `Format`.
4. Assert ZERO HTTP requests to `/v1/local/format` for unlocked Tier 2 blocks (`SEC-03`).
5. Assert ZERO HTTP request/response bodies carry Tier-2-only canary or Vault passphrase.
6. Assert direct `GET /v1/local/blocks` returns `content: null` + ciphertext only.
7. Assert forensic raw byte scan of `.db`, `.db-wal`, `.db-shm`, and `mirror/` finds ZERO hits
   of the Tier-2-only canary and Vault passphrase.
8. Trigger `visibilitychange` -> `"hidden"` and assert Vault immediately zeroizes & scrubs DOM.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "target" / "debug" / "mynote"


def wait_for_open_url(data_dir: Path, timeout_s: float = 15.0) -> tuple[str, int]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        proc = subprocess.run(
            [str(BIN), "--data-dir", str(data_dir), "--json", "open"],
            text=True,
            capture_output=True,
        )
        if proc.returncode == 0:
            j = json.loads(proc.stdout)
            return j["data"]["url"], int(j["data"]["port"])
        time.sleep(0.15)
    raise RuntimeError("timed out waiting for mynote daemon UDS OpenTicket")


def scan_dir_bytes(data_dir: Path, needles: list[bytes]) -> list[tuple[str, str]]:
    hits = []
    for p in data_dir.rglob("*"):
        if p.is_file():
            data = p.read_bytes()
            for n in needles:
                if n in data:
                    hits.append((str(p.relative_to(data_dir)), n.decode("utf-8", errors="replace")))
    return hits


def main():
    assert BIN.exists(), f"mynote binary missing at {BIN}"
    tmp = Path(tempfile.mkdtemp(prefix="mynote-m2-sec03-"))
    daemon = subprocess.Popen(
        [str(BIN), "--data-dir", str(tmp), "daemon", "--port", "0", "--no-cloud-sync"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        open_url, port = wait_for_open_url(tmp)
        print(f"[sec-03] Daemon listening on http://localhost:{port}")

        # Pre-seed an empty JSON block via CLI so we know its exact block_id
        add = subprocess.run(
            [str(BIN), "--data-dir", str(tmp), "--json", "add", '{"initial":true}', "--lang", "json"],
            text=True,
            capture_output=True,
            check=True,
        )
        blk_id = json.loads(add.stdout)["data"]["block_id"]

        passphrase = "SEC03-Desktop-Vault-Passphrase!"
        t2_canary = "SEC03_TIER2_ONLY_CANARY_777999"
        format_urls: list[str] = []
        observed_http_bodies: list[tuple[str, str]] = []
        console_errors: list[str] = []

        with sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context()
            page = context.new_page()
            page.on("pageerror", lambda err: console_errors.append(str(err)))

            def on_request(req):
                if "/v1/local/format" in req.url:
                    format_urls.append(req.url)
                body = req.post_data or ""
                if body:
                    observed_http_bodies.append((f"REQ {req.method} {req.url}", body))

            def on_response(res):
                if "/v1/local/" in res.url:
                    try:
                        txt = res.text()
                        observed_http_bodies.append((f"RES {res.status} {res.url}", txt))
                    except Exception:
                        pass

            page.on("request", on_request)
            page.on("response", on_response)

            # 1. Authenticate via one-time ticket exchange -> redirects to http://localhost:<port>/
            page.goto(open_url, wait_until="networkidle")
            page.wait_for_selector(f'[data-block-id="{blk_id}"]', timeout=15000)

            # 2. Initialize Vault in browser WASM UI
            page.click('[data-testid="vault-btn"]')
            page.fill('[data-testid="vault-passphrase-input"]', passphrase)
            page.fill('[data-testid="vault-passphrase-confirm"]', passphrase)
            page.click('[data-testid="vault-submit-btn"]')
            page.wait_for_function(
                '() => document.querySelector(\'[data-testid="vault-btn"]\')?.textContent?.includes("Unlocked")',
                timeout=15000,
            )
            print("[sec-03] 1. Vault initialized & unlocked in real Chromium WASM OK")

            # 3. Lock the JSON block into Tier 2 Vault (focus block to reveal focus-only header, then open overflow popover)
            card = page.locator(f'[data-block-id="{blk_id}"]')
            card.locator(".cm-content").click()
            page.click(f'[data-testid="more-btn-{blk_id}"]')
            page.click(f'[data-testid="lock-btn-{blk_id}"]')
            page.fill('[data-testid="lock-hint-input"]', "SEC03 Vault Hint")
            page.click('[data-testid="lock-confirm-btn"]')
            page.wait_for_selector(f'[data-block-id="{blk_id}"][data-locked="true"]', timeout=10000)
            print("[sec-03] 2. Block locked into Tier 2 Vault OK")

            # 4. Edit locked Tier 2 block in CM6 to unformatted JSON containing Tier-2-only canary, then click Format!
            cm_content = card.locator(".cm-content")
            cm_content.click()
            page.keyboard.press("ControlOrMeta+a")
            page.keyboard.type(f'{{"secret":"{t2_canary}","n":1}}')
            # Click Format -> MUST run purely in browser WASM with ZERO /v1/local/format HTTP calls!
            card.hover()
            page.click(f'[data-testid="format-btn-{blk_id}"]')
            try:
                page.wait_for_function(
                    f"""() => {{
                        const el = document.querySelector('[data-block-id="{blk_id}"] .cm-content');
                        return el && el.innerText.includes('{t2_canary}') && el.querySelectorAll('.cm-line').length >= 3;
                    }}""",
                    timeout=6000,
                )
            except Exception:
                diag = page.evaluate(
                    f"""() => ({{
                        toast: document.querySelector('.toast')?.textContent,
                        cmText: document.querySelector('[data-block-id="{blk_id}"] .cm-content')?.innerText,
                        lines: document.querySelectorAll('[data-block-id="{blk_id}"] .cm-line').length,
                        locked: document.querySelector('[data-block-id="{blk_id}"]')?.dataset.locked,
                    }})"""
                )
                print("[sec-03] DIAG:", diag, "HTTP:", [(t, b[:200]) for t, b in observed_http_bodies[-6:]], "ERRS:", console_errors)
                raise
            time.sleep(0.4)
            print("[sec-03] 3. Unlocked Tier 2 block edited & formatted cleanly in browser WASM OK")

            # 5. Assert ZERO /v1/local/format calls and ZERO plaintext/passphrase in ANY HTTP request/response!
            assert len(format_urls) == 0, f"SEC-03 VIOLATION: /v1/local/format was called for locked block: {format_urls}"
            for tag, body in observed_http_bodies:
                assert t2_canary not in body, f"SEC-03 VIOLATION: Tier 2 canary leaked over HTTP in {tag}!"
                assert passphrase not in body, f"SEC-03 VIOLATION: passphrase leaked over HTTP in {tag}!"
            print(f"[sec-03] 4. Audited {len(observed_http_bodies)} HTTP payloads: 0 /v1/local/format calls, 0 leaks OK")

            # 6. Concurrent GET /v1/local/blocks via browser cookies returns content: null (zero Tier 2 plaintext!)
            api_blocks = page.evaluate(
                """async () => {
                    const boot = await (await fetch('/v1/local/bootstrap')).json();
                    const bid = boot.data.initial_buffer_id;
                    const res = await (await fetch('/v1/local/blocks?buffer_id=' + encodeURIComponent(bid))).json();
                    return res.data;
                }"""
            )
            target_api_blk = [b for b in api_blocks if b["id"] == blk_id][0]
            assert target_api_blk["is_locked"] is True
            assert target_api_blk["content"] is None, f"SEC-03 VIOLATION: daemon returned content={target_api_blk['content']!r}"
            assert t2_canary not in json.dumps(target_api_blk), "SEC-03 VIOLATION: canary in /v1/local/blocks!"
            print("[sec-03] 5. Daemon /v1/local/blocks returns content:null + ciphertext only OK")

            # 7. Trigger visibilitychange -> hidden => Vault immediately zeroizes & scrubs DOM!
            page.evaluate(
                """() => {
                    Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
                    document.dispatchEvent(new Event('visibilitychange'));
                }"""
            )
            page.wait_for_selector(f'[data-block-id="{blk_id}"] .locked-card', timeout=5000)
            dom_text = page.evaluate("() => document.body.innerText")
            assert t2_canary not in dom_text, "SEC-03 VIOLATION: Tier 2 canary remained in DOM after visibilitychange hidden!"
            assert "SEC03 Vault Hint" in dom_text, "Expected public_hint on locked card!"
            # Restore visibility, re-unlock Vault, and verify formatted Tier 2 canary is intact (C4 anti-empty-overwrite check)
            page.evaluate(
                """() => {
                    delete document.visibilityState;
                    document.dispatchEvent(new Event('visibilitychange'));
                }"""
            )
            page.click('[data-testid="vault-btn"]')
            page.fill('[data-testid="vault-passphrase-input"]', passphrase)
            page.click('[data-testid="vault-submit-btn"]')
            page.wait_for_function(
                f"() => document.querySelector('[data-block-id=\"{blk_id}\"] .cm-content')?.innerText?.includes('{t2_canary}')",
                timeout=15000,
            )
            print("[sec-03] 6. visibilitychange hidden locked Vault, scrubbed DOM, and re-unlock preserved content (C4) OK")

            assert not console_errors, f"Unexpected page errors in Chromium: {console_errors}"
            browser.close()

        # 8. Forensic raw disk byte scan of .db, .db-wal, .db-shm, mirror/ -> ZERO Tier-2-only canary or passphrase hits!
        daemon.terminate()
        daemon.wait(timeout=5)
        disk_hits = scan_dir_bytes(tmp, [t2_canary.encode("utf-8"), passphrase.encode("utf-8")])
        assert len(disk_hits) == 0, f"SEC-03 FORENSIC DISK VIOLATION: found plaintext bytes on disk: {disk_hits}"
        print("[sec-03] 7. Forensic disk scan (.db/.db-wal/.db-shm/mirror): 0 plaintext/passphrase hits OK")
        print("SEC-03 CHROMIUM DESKTOP AUDIT PASSED!")
    finally:
        if daemon.poll() is None:
            daemon.kill()
            daemon.wait(timeout=5)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
