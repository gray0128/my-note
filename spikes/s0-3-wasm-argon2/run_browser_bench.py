#!/usr/bin/env python3
"""Run S0-3 Argon2id WASM benchmark in headless Playwright Chromium (V8) and WebKit (JSC)."""
import functools
import http.server
import json
import os
import threading
from playwright.sync_api import sync_playwright

SPIKE_DIR = os.path.dirname(os.path.abspath(__file__))


def start_server():
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=SPIKE_DIR)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port


def main():
    httpd, port = start_server()
    url = f"http://127.0.0.1:{port}/bench.html"
    all_out = {}
    try:
        with sync_playwright() as p:
            for name, launcher in [("chromium", p.chromium), ("webkit", p.webkit)]:
                browser = launcher.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until="networkidle")
                res = page.evaluate("() => window.runBenchmark('./dist/4-desktop-ruzstd-rw.opt.wasm', 3)")
                all_out[name] = res
                browser.close()
    finally:
        httpd.shutdown()

    print(json.dumps(all_out, indent=2))


if __name__ == "__main__":
    main()
