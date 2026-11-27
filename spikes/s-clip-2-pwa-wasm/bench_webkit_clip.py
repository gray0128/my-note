#!/usr/bin/env python3
"""
S-Clip-2 (Issue #50): Real-browser Playwright WebKit (JSC) & Chromium (V8) benchmark for:
  1. WasmClipCodec (`MNC1`) 1 MiB / 5 MiB / 10 MiB encryption + decryption (median of 3 runs),
     byte-for-byte round-trip verification, tamper & SVG rejection, and WASM linear memory peak.
  2. Synchronous click-handler `navigator.clipboard.write([new ClipboardItem({ 'image/png': pngBlobPromise })])`
     where `pngBlobPromise` fetches MNC1 ciphertext over local HTTP -> decrypts in WASM -> decodes JPEG
     -> converts via offscreen `<canvas>.toBlob('image/png')` -> resolves PNG Blob (`89 50 4E 47 0D 0A 1A 0A`).

Run via:
  uv run --with playwright python3 spikes/s-clip-2-pwa-wasm/bench_webkit_clip.py
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from playwright.sync_api import sync_playwright

SPIKE_DIR = Path(__file__).resolve().parent
PNG_MAGIC_HEX = "89 50 4e 47 0d 0a 1a 0a"


class SpikeHandler(http.server.BaseHTTPRequestHandler):
    serve_root: Path
    pkg_dir: Path
    blob_store: dict[str, bytes]

    def log_message(self, format: str, *args) -> None:
        pass

    def _send_bytes(self, status: int, content_type: str, data: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in ("/", "/bench.html"):
            self._send_bytes(200, "text/html; charset=utf-8", (self.serve_root / "bench.html").read_bytes())
            return
        if path == "/blob.mnc1":
            data = self.blob_store.get("blob.mnc1")
            if data is None:
                self._send_bytes(404, "text/plain", b"not uploaded yet")
                return
            self._send_bytes(200, "application/octet-stream", data)
            return
        if path.startswith("/pkg/"):
            rel = path[len("/pkg/"):]
            if "/" in rel or "\\" in rel or ".." in rel:
                self._send_bytes(403, "text/plain", b"forbidden")
                return
            fp = self.pkg_dir / rel
            if not fp.is_file():
                self._send_bytes(404, "text/plain", b"not found")
                return
            ctype = "application/wasm" if fp.suffix == ".wasm" else "application/javascript; charset=utf-8"
            self._send_bytes(200, ctype, fp.read_bytes())
            return
        self._send_bytes(404, "text/plain", b"not found")

    def do_POST(self) -> None:
        if self.path == "/upload-blob":
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            self.blob_store["blob.mnc1"] = body
            self._send_bytes(200, "application/json", json.dumps({"ok": True, "bytes": len(body)}).encode())
            return
        self._send_bytes(404, "text/plain", b"not found")


def start_server(pkg_dir: Path):
    blob_store: dict[str, bytes] = {}

    class Handler(SpikeHandler):
        pass

    Handler.serve_root = SPIKE_DIR
    Handler.pkg_dir = pkg_dir
    Handler.blob_store = blob_store

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port


def run_browser_suite(p, browser_name: str, url: str, runs: int) -> dict:
    launcher = getattr(p, browser_name)
    browser = launcher.launch(headless=True)
    browser_version = browser.version
    context = browser.new_context(viewport={"width": 1280, "height": 800})
    if browser_name == "chromium":
        context.grant_permissions(["clipboard-read", "clipboard-write"], origin=url.rsplit("/", 1)[0])

    page = context.new_page()
    page_errors: list[str] = []
    console_errors: list[str] = []
    page.on("pageerror", lambda err: page_errors.append(str(err)))
    page.on(
        "console",
        lambda m: console_errors.append(m.text) if m.type == "error" else None,
    )

    page.goto(url, wait_until="domcontentloaded", timeout=15000)
    page.wait_for_function("() => window.__sClip2Ready === true || Boolean(window.__sClip2Error)", timeout=20000)
    init_err = page.evaluate("() => window.__sClip2Error || null")
    if init_err:
        raise RuntimeError(f"[{browser_name}] init error: {init_err}")

    # 1. WASM 1 MiB / 5 MiB / 10 MiB benchmark
    wasm_res = page.evaluate("(runs) => window.__sClip2.runWasmBench(runs)", runs)

    # Assert strict correctness on all sizes
    assert wasm_res["metaRoundTripOk"], f"[{browser_name}] metaRoundTripOk failed"
    assert wasm_res["svgRejected"], f"[{browser_name}] SVG MIME was not rejected"
    assert wasm_res["crossChannelRejected"], f"[{browser_name}] cross-channel AAD was not rejected"
    for row in wasm_res["benchmarks"]:
        assert row["roundTripExactMatch"], f"[{browser_name}] {row['sizeMiB']} MiB byte-for-byte mismatch"
        assert row["tamperRejected"], f"[{browser_name}] {row['sizeMiB']} MiB tamper not rejected"

    # 2. Prepare 1920x1080 JPEG encrypted fixture -> upload ciphertext to local HTTP server
    fixture = page.evaluate("() => window.__sClip2.prepareEncryptedJpegFixture(1920, 1080)")

    # 3. Verify ClipboardItem({ 'image/png': pngBlobPromise }) construction + canvas PNG resolution
    page.evaluate("() => { window.__lastClipboardItemResult = null; }")
    page.click("#btn-check-item")
    page.wait_for_function("() => window.__lastClipboardItemResult !== null", timeout=15000)
    item_res = page.evaluate("() => window.__lastClipboardItemResult")
    assert item_res["ok"], f"[{browser_name}] ClipboardItem Promise resolution failed: {item_res}"
    assert item_res["pngMagicHex"] == PNG_MAGIC_HEX, f"[{browser_name}] bad PNG magic: {item_res}"
    assert item_res["metrics"]["width"] == 1920 and item_res["metrics"]["height"] == 1080

    # 4. Trigger real synchronous click-handler navigator.clipboard.write([new ClipboardItem({ 'image/png': pngBlobPromise })])
    page.evaluate("() => { window.__lastClipboardWriteResult = null; }")
    page.click("#btn-copy-png")
    page.wait_for_function("() => window.__lastClipboardWriteResult !== null", timeout=15000)
    write_res = page.evaluate("() => window.__lastClipboardWriteResult")

    readback_res = None
    if browser_name == "chromium":
        assert write_res["ok"], f"[chromium] navigator.clipboard.write failed: {write_res}"
        assert write_res["metrics"]["pngMagicHex"] == PNG_MAGIC_HEX
        readback_res = page.evaluate("() => window.__sClip2.readClipboardPng()")
        assert readback_res["found"], f"[chromium] clipboard readback did not find image/png: {readback_res}"
        assert readback_res["pngMagicHex"] == PNG_MAGIC_HEX, f"[chromium] readback PNG magic mismatch: {readback_res}"

    assert not page_errors, f"[{browser_name}] uncaught page errors: {page_errors}"
    browser.close()

    return {
        "browser": browser_name,
        "version": browser_version,
        "wasm": wasm_res,
        "jpegFixture": fixture,
        "clipboardItemPromiseCheck": item_res,
        "clipboardWriteClickCheck": write_res,
        "clipboardReadbackCheck": readback_res,
        "pageErrors": page_errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run S-Clip-2 Playwright WebKit & Chromium benchmarks.")
    parser.add_argument("--pkg-dir", help="Prebuilt +WasmClipCodec wasm-bindgen pkg dir (skips rebuild)")
    parser.add_argument("--runs", type=int, default=3, help="Runs per payload size (default: 3)")
    parser.add_argument("--json-out", help="Optional path to write full JSON output")
    args = parser.parse_args()

    tmp_pkg_dir: Path | None = None
    try:
        if args.pkg_dir:
            pkg_dir = Path(args.pkg_dir).resolve()
        else:
            tmp_pkg_dir = Path(tempfile.mkdtemp(prefix="mynote-s-clip-2-pkg-"))
            subprocess.run(
                [str(SPIKE_DIR / "measure_wasm_clip.sh"), "--out-pkg", str(tmp_pkg_dir)],
                check=True,
                env={**os.environ, "CARGO_TARGET_DIR": os.environ.get("CARGO_TARGET_DIR", "/tmp/mynote-s-clip-2")},
            )
            pkg_dir = tmp_pkg_dir

        httpd, port = start_server(pkg_dir)
        url = f"http://127.0.0.1:{port}/bench.html"
        results = {}
        try:
            with sync_playwright() as p:
                for name in ("chromium", "webkit"):
                    results[name] = run_browser_suite(p, name, url, args.runs)
        finally:
            httpd.shutdown()

        output = json.dumps(results, indent=2)
        if args.json_out:
            Path(args.json_out).write_text(output + "\n", encoding="utf-8")
        print(output)
    finally:
        if tmp_pkg_dir and tmp_pkg_dir.exists():
            shutil.rmtree(tmp_pkg_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
