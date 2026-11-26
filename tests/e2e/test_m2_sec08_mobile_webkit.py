#!/usr/bin/env python3
"""
SEC-08 Mobile Read-Only PWA + Real Cloudflare Worker (`wrangler dev --local`) + Playwright WebKit E2E Audit.

Verifies the full Desktop -> Cloud Relay (`MNP1` snapshot + keys + tail ops + WS wake) -> Mobile WebKit PWA pipeline:
1. Starts real `wrangler dev --local` in `cloud-cf/` serving BOTH `/v1/*` Durable Object + R2 AND `web/dist-pwa/`.
2. Bootstraps real Desktop `mynote` against the local Worker, creates Tier 1 & Tier 2 Vault blocks,
   and syncs (pushing ops, keys, VaultHeaderV1, and `MNP1` mobile state snapshot).
3. Issues a real read-only pairing code via `mynote device add --name iPhoneWebKit --scope read`.
4. Opens Mobile PWA in real Playwright **WebKit** (Safari engine):
   - Verifies strict CSP & zero editable inputs on notes.
   - Pairs with `mynote-pair:v1:...` code, bootstraps from `MNP1` snapshot, displays Tier 1 canary.
   - Unlocks Mobile Vault via real Argon2id in WebKit WASM, verifies Tier 2 canary, clicks Copy.
   - Triggers `visibilitychange` -> `"hidden"`, verifies Vault immediately locks & scrubs DOM.
   - Desktop adds a live Tier 1 block & pushes -> WebKit receives WS `"wake"` and displays it without reload!
   - **SEC-08 Forensic Storage Audit**: dumps 100% of ALL 6 IndexedDB stores (`mynote_pwa_v1`),
     `localStorage`, `sessionStorage`, and Cache Storage -> asserts:
       * Exact 6 IndexedDB stores present
       * `device_keystore.device_wrap_key` is a non-extractable `CryptoKey` (`extractable === false`)
       * `localStorage.length === 0`, `sessionStorage.length === 0`
       * Cache Storage has ZERO `/v1/` entries
       * ZERO occurrences of ANY Tier 1 canary, Tier 2 canary, live wake canary, or passphrase!
   - Deletes IndexedDB (simulating iOS/Safari eviction), reloads -> clean unpaired recovery screen!
   - Attempts to re-claim the already-claimed pairing code -> displays `pwa-snatch-warning`!
"""

import json
import os
import pty
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "target" / "debug" / "mynote"
CLOUD_DIR = ROOT / "cloud-cf"


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_pty_cmd(data_dir: Path, args: list[str], prompts_and_answers: list[tuple[str, str]], env_extra: dict[str, str] | None = None, timeout_s: float = 25.0):
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


def wait_for_wrangler(url: str, proc: subprocess.Popen, timeout_s: float = 30.0) -> None:
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


def main():
    assert BIN.exists(), f"mynote binary missing at {BIN}"
    assert (ROOT / "web" / "dist-pwa" / "index.html").exists(), "web/dist-pwa missing; run `pnpm --dir web build:pwa`"

    port = pick_free_port()
    base_url = f"http://127.0.0.1:{port}"
    boot_token = "e2e-sec08-bootstrap-secret-token"
    tmp_desktop = Path(tempfile.mkdtemp(prefix="mynote-m2-sec08-desk-"))
    tmp_wrangler = Path(tempfile.mkdtemp(prefix="mynote-m2-sec08-cf-"))

    wrangler_bin = CLOUD_DIR / "node_modules" / ".bin" / "wrangler"
    assert wrangler_bin.exists(), f"wrangler missing at {wrangler_bin}"
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
    try:
        wait_for_wrangler(base_url, wrangler)
        print(f"[sec-08] 1. Real wrangler dev ready at {base_url}")

        # 2. Desktop bootstrap + Tier 1 block + Vault init + Tier 2 locked block + sync (uploads MNP1 snapshot!)
        rc, out = run_pty_cmd(
            tmp_desktop,
            ["device", "bootstrap", "--url", base_url],
            [],
            env_extra={"MYNOTE_BOOTSTRAP_TOKEN": boot_token},
        )
        assert rc == 0, f"desktop bootstrap failed ({rc}): {out}"

        t1_canary = "PWA_T1_CANARY_111_ALPHA"
        t2_canary = "PWA_T2_CANARY_222_OMEGA"
        live_canary = "PWA_LIVE_WAKE_333_GAMMA"
        vault_pass = "MobileWebKitVault#2026"

        subprocess.run([str(BIN), "--data-dir", str(tmp_desktop), "add", t1_canary], check=True, capture_output=True)
        add_t2 = subprocess.run(
            [str(BIN), "--data-dir", str(tmp_desktop), "--json", "add", t2_canary],
            text=True,
            capture_output=True,
            check=True,
        )
        t2_blk_id = json.loads(add_t2.stdout)["data"]["block_id"]

        rc, out = run_pty_cmd(
            tmp_desktop,
            ["vault", "init"],
            [("Set new Vault passphrase:", vault_pass), ("Confirm Vault passphrase:", vault_pass)],
        )
        assert rc == 0, f"vault init failed ({rc}): {out}"

        rc, out = run_pty_cmd(
            tmp_desktop,
            ["vault", "lock", t2_blk_id, "--hint", "Mobile Secret"],
            [("Enter Vault passphrase:", vault_pass)],
        )
        assert rc == 0, f"vault lock failed ({rc}): {out}"

        sync_push = subprocess.run(
            [str(BIN), "--data-dir", str(tmp_desktop), "--json", "sync", "push"],
            text=True,
            capture_output=True,
            check=True,
        )
        assert json.loads(sync_push.stdout)["ok"] is True

        # Issue read-only mobile pairing code
        rc, pair_out = run_pty_cmd(tmp_desktop, ["device", "add", "--name", "iPhoneWebKit", "--scope", "read"], [])
        assert rc == 0, f"device add failed ({rc}): {pair_out}"
        m = re.search(r"(mynote-pair:v1:[A-Za-z0-9_-]+)", pair_out)
        assert m, f"could not extract pairing code from:\n{pair_out}"
        pair_code = m.group(1)
        print("[sec-08] 2. Desktop bootstrapped, synced (Tier 1 + Tier 2 + MNP1 snapshot), and issued read-only pairing code OK")

        # 3. Real Playwright WebKit audit!
        page_errors: list[str] = []
        snapshot_responses: list[tuple[int, str]] = []
        with sync_playwright() as p:
            browser = p.webkit.launch()
            context = browser.new_context(viewport={"width": 390, "height": 844})
            page = context.new_page()
            page.on("pageerror", lambda err: page_errors.append(str(err)))
            page.on(
                "response",
                lambda r: snapshot_responses.append((r.status, r.headers.get("x-covers-seq", "")))
                if "/v1/snapshots/state" in r.url
                else None,
            )
            page.add_init_script(
                """() => {
                    window.__cspViolations = [];
                    window.addEventListener('securitypolicyviolation', (e) => {
                        window.__cspViolations.push({ directive: e.violatedDirective, blocked: e.blockedURI });
                    });
                }"""
            )

            res = page.goto(base_url, wait_until="networkidle")
            assert res is not None and res.status == 200
            csp = res.headers.get("content-security-policy", "")
            assert "default-src 'none'" in csp, f"Missing default-src 'none' in PWA CSP: {csp}"
            assert "script-src 'self' 'wasm-unsafe-eval'" in csp, f"Missing wasm-unsafe-eval in PWA CSP: {csp}"
            assert "style-src 'self'" in csp and "'unsafe-inline'" not in csp, f"Weak style-src in PWA CSP: {csp}"
            assert "form-action 'none'" in csp, f"Missing form-action 'none' in PWA CSP: {csp}"
            assert " wss: " not in f"{csp} " and " https: " not in f"{csp} ", f"Over-broad wildcard in PWA CSP: {csp}"
            assert res.headers.get("x-frame-options") == "DENY"

            # Pair using the real pairing code
            page.wait_for_selector('[data-testid="pwa-pair-input"]', timeout=15000)
            page.fill('[data-testid="pwa-pair-input"]', pair_code)
            page.click('[data-testid="pwa-pair-submit"]')

            # Wait for Tier 1 canary to appear in strictly read-only <pre>
            page.wait_for_function(
                f"() => document.body.innerText.includes('{t1_canary}')",
                timeout=20000,
            )
            # C1 end-to-end verification: Desktop MUST have uploaded MNP1 snapshot with matching headers so mobile gets HTTP 200!
            assert any(st == 200 and int(seq or "0") > 0 for st, seq in snapshot_responses), (
                f"Expected HTTP 200 MNP1 snapshot with x-covers-seq > 0, got: {snapshot_responses}"
            )
            # Strictly read-only: ZERO <textarea> or [contenteditable] on note cards!
            editable_count = page.evaluate("() => document.querySelectorAll('.ro-block textarea, .ro-block [contenteditable]').length")
            assert editable_count == 0, f"Mobile PWA must be strictly read-only, found {editable_count} editable note elements!"
            # Tier 2 block MUST be locked initially (hint visible, secret NOT in DOM!)
            dom_before_unlock = page.evaluate("() => document.body.innerText")
            assert "Mobile Secret" in dom_before_unlock
            assert t2_canary not in dom_before_unlock, "Tier 2 secret visible before Mobile Vault unlock!"
            print("[sec-08] 3. WebKit paired, synced MNP1 (HTTP 200) + keys + ops, rendered Tier 1 read-only & Tier 2 locked OK")

            # Unlock Mobile Vault in WebKit WASM with real Argon2id
            page.click('[data-testid="pwa-vault-unlock-btn"]')
            page.fill('[data-testid="pwa-vault-passphrase"]', vault_pass)
            page.click('[data-testid="pwa-vault-unlock-submit"]')
            page.wait_for_function(
                f"() => document.body.innerText.includes('{t2_canary}')",
                timeout=20000,
            )
            # Click one-tap Copy button on unlocked Tier 2 block
            page.click(f'[data-testid="copy-{t2_blk_id}"]')
            csp_violations = page.evaluate("() => window.__cspViolations || []")
            assert len(csp_violations) == 0, f"Unexpected CSP violations in Mobile PWA: {csp_violations}"
            print("[sec-08] 4. WebKit Mobile Vault unlocked via real Argon2id WASM, decrypted Tier 2, Copy clicked & 0 CSP violations OK")

            # Trigger visibilitychange -> hidden => Vault immediately zeroizes & scrubs DOM!
            page.evaluate(
                """() => {
                    Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
                    document.dispatchEvent(new Event('visibilitychange'));
                }"""
            )
            page.wait_for_function(
                f"() => !document.body.innerText.includes('{t2_canary}')",
                timeout=5000,
            )
            # Restore native visibilityState getter so live WS wake and page unload see genuine visibility state
            page.evaluate(
                """() => {
                    delete document.visibilityState;
                    document.dispatchEvent(new Event('visibilitychange'));
                }"""
            )
            print("[sec-08] 5. WebKit visibilitychange hidden zeroized VKEK & scrubbed Tier 2 DOM OK")

            # Live WebSocket wake: Desktop pushes a brand-new Tier 1 block -> WebKit updates without reload!
            subprocess.run([str(BIN), "--data-dir", str(tmp_desktop), "add", live_canary], check=True, capture_output=True)
            subprocess.run([str(BIN), "--data-dir", str(tmp_desktop), "sync", "push"], check=True, capture_output=True)
            page.wait_for_function(
                f"() => document.body.innerText.includes('{live_canary}') && document.querySelector('[data-testid=\"pwa-sync-btn\"]')?.textContent?.includes('Synced')",
                timeout=15000,
            )
            print("[sec-08] 6. WebKit received live WS wake & decrypted new tail op OK")

            # SEC-08 FORENSIC STORAGE AUDIT: dump ALL 6 IndexedDB stores, localStorage, sessionStorage, Cache Storage!
            audit = page.evaluate(
                """async () => {
                    const ls = Object.entries(localStorage);
                    const ss = Object.entries(sessionStorage);
                    const cacheEntries = [];
                    if ('caches' in window) {
                        for (const name of await caches.keys()) {
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
                            // Also decode raw byte arrays (e.g. serde Vec<u8>) as UTF-8 to prove no plaintext hides in integer arrays!
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
                    return { ls, ss, cacheEntries, storeNames, wrapKeyExtractable, stores };
                }"""
            )

            expected_stores = sorted(["device_keystore", "meta", "buffers", "blocks", "block_keys", "vault_header"])
            assert audit["storeNames"] == expected_stores, f"Expected exact 6 IDB stores {expected_stores}, got {audit['storeNames']}"
            assert audit["wrapKeyExtractable"] is False, f"SEC-08 VIOLATION: device_wrap_key extractable={audit['wrapKeyExtractable']}"
            assert len(audit["ls"]) == 0, f"SEC-08 VIOLATION: localStorage non-empty: {audit['ls']}"
            assert len(audit["ss"]) == 0, f"SEC-08 VIOLATION: sessionStorage non-empty: {audit['ss']}"
            for ce in audit["cacheEntries"]:
                assert "/v1/" not in ce["url"], f"SEC-08 VIOLATION: /v1/ API cached in Service Worker: {ce['url']}"

            full_dump = json.dumps(audit)
            for secret_str in (t1_canary, t2_canary, live_canary, vault_pass):
                assert secret_str not in full_dump, f"SEC-08 FORENSIC VIOLATION: '{secret_str}' found in persistent WebKit storage!"
            assert len(audit["stores"]["blocks"]) >= 3, f"Expected >= 3 ciphertext blocks in IDB, got {len(audit['stores']['blocks'])}"
            assert len(audit["stores"]["block_keys"]) >= 3, f"Expected >= 3 ciphertext keys in IDB, got {len(audit['stores']['block_keys'])}"
            assert len(audit["stores"]["vault_header"]) == 1, "Expected ciphertext vault_header in IDB"
            print("[sec-08] 7. WebKit Forensic Storage Audit (6 IDB stores + non-extractable CryptoKey + 0 LS/SS/Cache leaks + 0 plaintext): PASS!")

            # Eviction resilience: delete IndexedDB & reload -> clean onboarding prompt without errors!
            page.evaluate(
                """() => new Promise((res, rej) => {
                    const r = indexedDB.deleteDatabase('mynote_pwa_v1');
                    r.onsuccess = () => res(true);
                    r.onerror = () => rej(r.error);
                    r.onblocked = () => res(true);
                })"""
            )
            page.reload(wait_until="networkidle")
            page.wait_for_selector('[data-testid="pwa-pair-input"]', timeout=10000)

            # Snatch-risk warning: re-submitting already-claimed ticket triggers prominent warning!
            page.fill('[data-testid="pwa-pair-input"]', pair_code)
            page.click('[data-testid="pwa-pair-submit"]')
            page.wait_for_selector('[data-testid="pwa-snatch-warning"]', timeout=10000)
            print("[sec-08] 8. IndexedDB eviction recovery & 404 pairing snatch-risk warning OK")

            assert not page_errors, f"Unexpected WebKit page errors: {page_errors}"
            browser.close()

        print("SEC-08 PLAYWRIGHT WEBKIT + WRANGLER DEV FULL AUDIT PASSED!")
    finally:
        wrangler.terminate()
        try:
            wrangler.wait(timeout=5)
        except subprocess.TimeoutExpired:
            wrangler.kill()
        shutil.rmtree(tmp_desktop, ignore_errors=True)
        shutil.rmtree(tmp_wrangler, ignore_errors=True)


if __name__ == "__main__":
    main()
