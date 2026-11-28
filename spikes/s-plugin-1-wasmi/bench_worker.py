#!/usr/bin/env python3
"""
S-Plugin-1 (Issue #76): Playwright headless Chromium (V8) & WebKit (JSC) benchmark
for zero-import Core WASM 3-Export ABI inside a dedicated `'self'` Web Worker under
production CSP (`default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'`).

Run via:
  uv run --with playwright python3 spikes/s-plugin-1-wasmi/bench_worker.py
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import subprocess
import threading
from pathlib import Path
from playwright.sync_api import sync_playwright

SPIKE_DIR = Path(__file__).resolve().parent

STRICT_CSP = (
    "default-src 'none'; "
    "script-src 'self' 'wasm-unsafe-eval'; "
    "worker-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data: blob:; "
    "connect-src 'self';"
)


class WorkerBenchHandler(http.server.BaseHTTPRequestHandler):
    serve_root: Path

    def log_message(self, format: str, *args) -> None:
        pass

    def _send_bytes(self, status: int, content_type: str, data: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", STRICT_CSP)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in ("/", "/bench_worker.html"):
            self._send_bytes(
                200,
                "text/html; charset=utf-8",
                (self.serve_root / "bench_worker.html").read_bytes(),
            )
            return
        if path in ("/bench_main.js", "/plugin_worker.js"):
            self._send_bytes(
                200,
                "application/javascript; charset=utf-8",
                (self.serve_root / path.lstrip("/")).read_bytes(),
            )
            return
        if path.startswith("/fixtures/"):
            rel = path[len("/fixtures/") :]
            if "/" in rel or "\\" in rel or ".." in rel:
                self._send_bytes(403, "text/plain", b"forbidden")
                return
            fp = self.serve_root / "fixtures" / rel
            if not fp.is_file():
                self._send_bytes(404, "text/plain", b"not found")
                return
            self._send_bytes(200, "application/wasm", fp.read_bytes())
            return
        self._send_bytes(404, "text/plain", b"not found")


def start_server(serve_root: Path):
    class Handler(WorkerBenchHandler):
        pass

    Handler.serve_root = serve_root
    # Bind 127.0.0.1 and access via localhost:<port> to mirror production origin rules
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port


def run_browser(p, browser_name: str, url: str, runs: int) -> dict:
    launcher = getattr(p, browser_name)
    browser = launcher.launch(headless=True)
    version = browser.version
    context = browser.new_context(viewport={"width": 1280, "height": 800})
    page = context.new_page()

    page_errors: list[str] = []
    console_errors: list[str] = []
    page.on("pageerror", lambda err: page_errors.append(str(err)))
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)

    page.goto(url, wait_until="domcontentloaded", timeout=15000)
    page.wait_for_function("() => window.__sPlugin1Ready === true", timeout=15000)

    res = page.evaluate("(runs) => window.__sPlugin1.runSuite(runs)", runs)

    assert res["cspViolations"] == [], f"[{browser_name}] CSP violations: {res['cspViolations']}"
    assert not page_errors, f"[{browser_name}] uncaught page errors: {page_errors}"

    gates = res["gates"]
    assert (
        gates["evilRejected"] and gates["evilRejected"]["code"] == "PLUGIN_INVALID_MANIFEST"
    ), f"[{browser_name}] evil_import.wasm not rejected: {gates['evilRejected']}"
    assert (
        gates["oomGrowClampedRejected"]
        and gates["oomGrowClampedRejected"]["code"] == "PLUGIN_RESOURCE_EXCEEDED"
    ), f"[{browser_name}] oom_grow_bomb.wasm not rejected: {gates['oomGrowClampedRejected']}"
    assert (
        gates["unguardedOomControlMemoryBytes"] > 16 * 1024 * 1024
    ), f"[{browser_name}] expected unguarded control to exceed 16 MiB: {gates['unguardedOomControlMemoryBytes']}"
    assert (
        gates["oomInitRejected"] and gates["oomInitRejected"]["code"] == "PLUGIN_RESOURCE_EXCEEDED"
    ), f"[{browser_name}] oom_init_bomb.wasm not rejected: {gates['oomInitRejected']}"
    assert (
        gates["infiniteLoopTerminated"]
        and gates["infiniteLoopTerminated"]["code"] == "PLUGIN_RESOURCE_EXCEEDED"
        and gates["infiniteLoopTerminated"].get("terminated") is True
    ), f"[{browser_name}] infinite_loop.wasm not terminated: {gates['infiniteLoopTerminated']}"

    sanity = gates["postTerminateSanity"]
    assert sanity["kind"] == "gutter" and len(sanity["annotations"]) == 5
    assert sanity["annotations"][3]["copy"] == "84.77"

    browser.close()
    return {
        "browser": browser_name,
        "version": version,
        "pageErrors": page_errors,
        "consoleErrors": console_errors,
        **res,
    }


def ensure_fixtures() -> None:
    if not (SPIKE_DIR / "fixtures" / "guest_calc.wasm").is_file():
        subprocess.run(
            [
                "cargo",
                "run",
                "--manifest-path",
                str(SPIKE_DIR / "Cargo.toml"),
                "--release",
                "--",
                "--runs",
                "5",
            ],
            check=True,
            env={
                **os.environ,
                "CARGO_TARGET_DIR": os.environ.get(
                    "CARGO_TARGET_DIR", "/tmp/mynote-s-plugin-1-target"
                ),
            },
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run S-Plugin-1 Playwright Worker benchmarks.")
    parser.add_argument("--runs", type=int, default=100, help="Iterations per benchmark")
    parser.add_argument("--json-out", help="Optional path to save JSON output")
    args = parser.parse_args()

    ensure_fixtures()
    httpd, port = start_server(SPIKE_DIR)
    url = f"http://localhost:{port}/bench_worker.html"
    try:
        with sync_playwright() as p:
            out = {
                "chromium": run_browser(p, "chromium", url, args.runs),
                "webkit": run_browser(p, "webkit", url, args.runs),
            }
    finally:
        httpd.shutdown()

    pretty = json.dumps(out, indent=2)
    if args.json_out:
        Path(args.json_out).write_text(pretty, encoding="utf-8")
    print(pretty)


if __name__ == "__main__":
    main()
