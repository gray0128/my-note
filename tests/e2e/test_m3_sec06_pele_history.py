#!/usr/bin/env python3
"""
M3 Comprehensive Real-Browser E2E Audit:
  - SEC-06 XSS & External-Image Anti-Exfiltration (Desktop Chromium + WebKit & Mobile PWA WebKit)
  - Obsidian Pele Lazy SVG Chunk + ViewBox Pan/Zoom + Taint-Free Copy PNG (Chromium + WebKit) + Split Error Recovery
  - Granular Markdown Copy (Copy Rich / Copy Code / Copy TSV / Copy MD) + Desktop Task Checkbox Writeback
  - Desktop History (Time Travel) Drawer + Actor Badges + Diff + Revert + Tier 2 Vault History Scrub (SEC-03)
  - Mobile Read-Only PWA M3 Preview Default + Disabled Checkboxes + Copy PNG + SEC-06 + SEC-08 (WebKit + wrangler dev)
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
import urllib.parse
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "target" / "debug" / "mynote"
CLOUD_DIR = ROOT / "cloud-cf"
XSS_FIXTURE = ROOT / "tests" / "fixtures" / "xss_vectors.json"
PNG_MAGIC = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
MOD_KEY = "ControlOrMeta"

INIT_HARNESS_JS = """(() => {
  window.__xssExecuted = false;
  const tripXss = () => { window.__xssExecuted = true; };
  try { window.alert = tripXss; } catch {}
  try { window.confirm = tripXss; } catch {}
  try { window.prompt = tripXss; } catch {}

  window.__cspViolations = [];
  const onCsp = (e) => {
    const tgt = e.target;
    window.__cspViolations.push({
      directive: e.violatedDirective,
      effective: e.effectiveDirective,
      blocked: e.blockedURI,
      sourceFile: e.sourceFile || "",
      line: e.lineNumber || 0,
      col: e.columnNumber || 0,
      sample: e.sample || "",
      target: tgt && tgt.tagName ? `${tgt.tagName}.${tgt.className || ""}` : "",
    });
  };
  document.addEventListener("securitypolicyviolation", onCsp);

  window.__clipboardWrites = [];
  const clipboardStub = {
    async write(items) {
      const entry = { kind: "write", items: [] };
      for (const item of items) {
        const record = {};
        for (const type of item.types) {
          const blob = await item.getType(type);
          if (type.startsWith("text/")) {
            record[type] = await blob.text();
          } else {
            const bytes = new Uint8Array(await blob.arrayBuffer());
            record[type] = Array.from(bytes);
          }
        }
        entry.items.push(record);
      }
      window.__clipboardWrites.push(entry);
    },
    async writeText(text) {
      window.__clipboardWrites.push({ kind: "writeText", text: String(text) });
    },
  };
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: clipboardStub,
  });
})();"""

DOM_SEC06_AUDIT_JS = """(selectors) => {
  const forbiddenTags = new Set([
    "script", "iframe", "object", "embed", "form", "foreignobject", "style", "img"
  ]);
  const findings = [];
  for (const sel of selectors) {
    for (const root of document.querySelectorAll(sel)) {
      const all = [root, ...root.querySelectorAll("*")];
      for (const el of all) {
        const tag = el.localName.toLowerCase();
        if (forbiddenTags.has(tag)) {
          findings.push({ kind: "tag", sel, tag });
        }
        for (const attr of Array.from(el.attributes)) {
          const name = attr.name.toLowerCase();
          if (name.startsWith("on")) {
            findings.push({ kind: "event_attr", sel, tag, attr: attr.name });
          }
          if (name === "style") {
            findings.push({ kind: "inline_style", sel, tag, value: attr.value.slice(0, 80) });
          }
          if (name === "href" || name === "src" || name === "xlink:href") {
            if (/^\\s*(?:javascript|vbscript|data):/i.test(attr.value)) {
              findings.push({ kind: "unsafe_uri", sel, tag, attr: attr.name, value: attr.value.slice(0, 80) });
            }
          }
        }
      }
    }
  }
  return findings;
}"""


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_cli(
    data_dir: Path,
    args: list[str],
    *,
    env_extra: dict[str, str] | None = None,
    stdin_text: str | None = None,
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
        "timeout": 30,
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


def add_block(data_dir: Path, content: str, lang: str, buf: str = "scratch", env_extra: dict[str, str] | None = None) -> str:
    proc = run_cli(
        data_dir,
        ["--json", "add", "--buf", buf, "--lang", lang],
        stdin_text=content,
        env_extra=env_extra,
    )
    return json.loads(proc.stdout)["data"]["block_id"]


def check_non_loopback_request(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme in ("http", "https", "ws", "wss"):
        host = (parsed.hostname or "").lower()
        return host not in LOOPBACK_HOSTS
    return False


def assert_png_bytes(raw: list[int], label: str) -> None:
    assert len(raw) > 500, f"{label}: PNG too small ({len(raw)} bytes)"
    assert raw[:8] == PNG_MAGIC, f"{label}: invalid PNG magic bytes {raw[:8]!r}"


def run_check1_and_check2_desktop(p, browser_name: str, data_dir: Path, vectors: dict) -> None:
    """
    Check 1 (SEC-06 XSS & Anti-Exfiltration) + Check 2 (Pele Lazy SVG + Pan/Zoom + Taint-Free Copy PNG + Split Recovery)
    executed in BOTH real Chromium AND real WebKit.
    """
    open_url, _ = wait_for_open_url(data_dir)
    browser_type = getattr(p, browser_name)
    browser = browser_type.launch()
    context = browser.new_context(viewport={"width": 1280, "height": 900}, locale="en-US")
    page = context.new_page()
    page.add_init_script(INIT_HARNESS_JS)

    page_errors: list[str] = []
    outbound_urls: list[str] = []
    all_request_urls: list[str] = []

    def on_request(req) -> None:
        all_request_urls.append(req.url)
        if check_non_loopback_request(req.url):
            outbound_urls.append(req.url)

    page.on("pageerror", lambda err: page_errors.append(str(err)))
    page.on(
        "console",
        lambda m: page_errors.append(f"console.error: {m.text}")
        if m.type == "error" and "Failed to load resource" not in m.text
        else None,
    )
    page.on("request", on_request)

    # Initial page load (all blocks start in source mode -> pele-*.js MUST NOT load!)
    page.goto(open_url, wait_until="networkidle")
    page.wait_for_selector(".block-card", timeout=15000)

    pele_initial = [u for u in all_request_urls if re.search(r"/pele-[^/]+\.js", u)]
    assert len(pele_initial) == 0, f"[{browser_name}] pele chunk loaded eagerly on initial page load: {pele_initial}"
    print(f"[m3:{browser_name}] Lazy Pele verified: 0 pele-*.js requests before first diagram preview")

    # ---- Check 2: Render all 4 Mermaid diagram types via Pele + Pan/Zoom + Taint-Free Copy PNG ----
    diagram_ids = vectors["diagram_ids"]
    for idx, (kind, blk_id) in enumerate(diagram_ids):
        page.locator(f'[data-block-id="{blk_id}"] .cm-content').click()
        page.click(f'[data-testid="mode-preview-{blk_id}"]')
        svg_sel = f'[data-block-id="{blk_id}"] .diagram-viewport svg'
        page.wait_for_selector(svg_sel, timeout=15000)
        diag_info = page.evaluate(
            """(sel) => {
                const svg = document.querySelector(sel);
                const rect = svg.getBoundingClientRect();
                return {
                    foreignObjects: svg.querySelectorAll('foreignObject, foreignobject').length,
                    width: rect.width,
                    height: rect.height,
                    viewBox: svg.getAttribute('viewBox'),
                };
            }""",
            svg_sel,
        )
        assert diag_info["foreignObjects"] == 0, f"[{browser_name}] {kind} SVG contains <foreignObject>!"
        assert diag_info["width"] > 20 and diag_info["height"] > 20, (
            f"[{browser_name}] {kind} SVG bounding box too small: {diag_info}"
        )

        # Pan/Zoom + Copy PNG on the flowchart diagram
        if idx == 0:
            pele_after = [u for u in all_request_urls if re.search(r"/pele-[^/]+\.js", u)]
            assert len(pele_after) >= 1, f"[{browser_name}] expected lazy pele-*.js fetch after previewing mermaid"

            card = page.locator(f'[data-block-id="{blk_id}"]')
            vb0 = diag_info["viewBox"]
            assert vb0, f"[{browser_name}] missing viewBox on flowchart SVG"

            card.locator('button[aria-label="Zoom in"]').click()
            vb_in = page.locator(svg_sel).get_attribute("viewBox")
            assert vb_in != vb0, f"[{browser_name}] Zoom in did not update viewBox ({vb0} == {vb_in})"

            card.locator('button[aria-label="Zoom out"]').click()
            card.locator('button[aria-label="Zoom out"]').click()
            vb_out = page.locator(svg_sel).get_attribute("viewBox")
            assert vb_out != vb_in, f"[{browser_name}] Zoom out did not update viewBox ({vb_in} == {vb_out})"

            card.locator(".diagram-toolbar button", has_text="Reset").click()
            vb_reset = page.locator(svg_sel).get_attribute("viewBox")
            assert vb_reset == vb0, f"[{browser_name}] Reset did not restore viewBox: got {vb_reset!r}, expected {vb0!r}"

            # Taint-free Copy PNG in real Chromium / real WebKit (via collapsed Copy menu)
            page.evaluate("() => { window.__clipboardWrites = []; }")
            card.locator(".diagram-copy-trigger").click()
            card.locator(".diagram-copy-png").click()
            page.wait_for_function(
                """() => window.__clipboardWrites.some(w => w.kind === 'write' && w.items.some(it => 'image/png' in it))""",
                timeout=10000,
            )
            png_bytes = page.evaluate(
                """() => {
                    const hit = window.__clipboardWrites.find(w => w.kind === 'write' && w.items.some(it => 'image/png' in it));
                    return hit.items.find(it => 'image/png' in it)['image/png'];
                }"""
            )
            assert_png_bytes(png_bytes, f"{browser_name} Desktop Copy PNG")
            failed_attr = card.locator(".diagram-copy-trigger").get_attribute("data-failed")
            assert failed_attr is None, f"[{browser_name}] Copy PNG set data-failed"
            print(
                f"[m3:{browser_name}] Pele flowchart Pan/Zoom + Taint-Free Copy PNG PASS ({len(png_bytes)} bytes)"
            )

    # Split mode invalid syntax recovery: keep previous valid <svg> mounted (zero white flash) + show .diagram-syntax-hint
    split_id = vectors["split_diagram_id"]
    page.locator(f'[data-block-id="{split_id}"] .cm-content').click()
    page.click(f'[data-testid="mode-split-{split_id}"]')
    split_svg_sel = f'[data-block-id="{split_id}"] .diagram-viewport svg'
    page.wait_for_selector(split_svg_sel, timeout=15000)
    page.evaluate(
        "(sel) => { window.__prevValidSvg = document.querySelector(sel); }",
        split_svg_sel,
    )
    split_card = page.locator(f'[data-block-id="{split_id}"]')
    split_card.locator(".cm-content").click()
    page.keyboard.press(f"{MOD_KEY}+a")
    page.keyboard.type("flowchart LR\n  BROKEN --> --> {{{{{ INVALID_SYNTAX")
    page.wait_for_selector(f'[data-block-id="{split_id}"] .diagram-syntax-hint:not(.hidden)', timeout=10000)
    still_mounted = page.evaluate(
        """(sel) => {
            const cur = document.querySelector(sel);
            return Boolean(cur && window.__prevValidSvg && cur === window.__prevValidSvg && document.contains(cur));
        }""",
        split_svg_sel,
    )
    assert still_mounted, f"[{browser_name}] Previous valid SVG was unmounted on invalid split syntax (white flash!)"
    hint_text = split_card.locator(".diagram-syntax-hint").inner_text().strip()
    assert len(hint_text) > 0, f"[{browser_name}] .diagram-syntax-hint empty on syntax error"
    # Restore valid syntax so second browser run sees clean state
    split_card.locator(".cm-content").click()
    page.keyboard.press(f"{MOD_KEY}+a")
    page.keyboard.type("flowchart LR\n  Start --> End")
    page.wait_for_selector(f'[data-block-id="{split_id}"] .diagram-syntax-hint.hidden', state="attached", timeout=10000)
    page.keyboard.press(f"{MOD_KEY}+s")
    time.sleep(0.3)
    print(f"[m3:{browser_name}] Pele 4 diagram types + Split invalid-syntax no-white-flash recovery PASS")

    # ---- Check 1: SEC-06 XSS & External-Image Anti-Exfiltration across ALL xss_vectors.json ----
    page.locator(".buf-tab", has_text="sec06").click()
    page.wait_for_selector(f'[data-block-id="{vectors["md_xss_id"]}"]', timeout=15000)

    for blk_id in [vectors["md_xss_id"], vectors["ext_img_id"], *vectors["mermaid_xss_ids"]]:
        page.locator(f'[data-block-id="{blk_id}"] .cm-content').click()
        page.click(f'[data-testid="mode-preview-{blk_id}"]')

    page.wait_for_selector(f'[data-block-id="{vectors["md_xss_id"]}"] .md-preview', timeout=10000)
    page.wait_for_selector(f'[data-block-id="{vectors["ext_img_id"]}"] .md-preview', timeout=10000)
    for mid in vectors["mermaid_xss_ids"]:
        page.wait_for_function(
            f"""() => {{
                const card = document.querySelector('[data-block-id="{mid}"]');
                return card && (
                    card.querySelector('.diagram-viewport svg') !== null ||
                    card.querySelector('.diagram-syntax-hint:not(.hidden)') !== null
                );
            }}""",
            timeout=15000,
        )
    time.sleep(0.5)

    xss_executed = page.evaluate("() => Boolean(window.__xssExecuted)")
    assert not xss_executed, f"[{browser_name}] SEC-06 VIOLATION: window.__xssExecuted became true!"

    dom_findings = page.evaluate(DOM_SEC06_AUDIT_JS, [".md-preview", ".diagram-viewport"])
    assert len(dom_findings) == 0, f"[{browser_name}] SEC-06 DOM VIOLATIONS: {dom_findings}"

    assert len(outbound_urls) == 0, f"[{browser_name}] SEC-06 EXFILTRATION VIOLATION: outbound requests {outbound_urls}"

    csp_violations = page.evaluate("() => window.__cspViolations || []")
    assert len(csp_violations) == 0, f"[{browser_name}] CSP VIOLATIONS: {csp_violations}"
    assert len(page_errors) == 0, f"[{browser_name}] Unexpected page errors: {page_errors}"

    print(
        f"[m3:{browser_name}] SEC-06 Desktop Audit PASS (0 XSS, 0 forbidden tags/attrs/styles, 0 outbound reqs, 0 CSP violations)"
    )
    browser.close()


def run_check3_and_check4_desktop_chromium(p, data_dir: Path) -> None:
    """
    Check 3: Granular Copy (Copy Rich / Copy Code / Copy TSV / Copy MD) + Desktop Task Checkbox Writeback
    Check 4: Desktop History (Time Travel) Drawer + Actor Badges + Diff + Revert + Tier 2 Vault History Scrub (SEC-03)
    """
    run_cli(data_dir, ["buf", "create", "m3-copy-hist"])

    md_content = "\n".join(
        [
            "# M3 Release Checklist",
            "",
            "```python",
            'print("hi")',
            "```",
            "",
            "| Feature | Status |",
            "| --- | --- |",
            "| Pele | Ready |",
            "| History | Ready |",
            "",
            "- [ ] Ship M3",
            "- [x] Ship M2",
        ]
    )
    md_blk_id = add_block(data_dir, md_content, "markdown", buf="m3-copy-hist")

    # History test block: created by human, then updated twice by agent:claude-code
    human_v1 = "Human original line 1\nShared baseline line 2"
    hist_blk_id = add_block(data_dir, human_v1, "text", buf="m3-copy-hist", env_extra={"MYNOTE_ACTOR": "human"})
    for idx, agent_text in enumerate(
        [
            "Agent edit 1\nShared baseline line 2",
            "Agent edit 2\nShared baseline line 2\nAgent extra line 3",
        ],
        start=1,
    ):
        cur_json = json.loads(run_cli(data_dir, ["--json", "block", "get", hist_blk_id]).stdout)
        heads = cur_json["data"]["head_op_ids"]
        cmd = ["--json", "block", "update", hist_blk_id, agent_text]
        for h in heads:
            cmd.extend(["--expected-head", h])
        run_cli(data_dir, cmd, env_extra={"MYNOTE_ACTOR": "agent:claude-code"})

    # Tier 2 history scrub target block
    t2_hist_blk_id = add_block(data_dir, "tier1-seed-before-lock", "markdown", buf="m3-copy-hist")

    open_url, _ = wait_for_open_url(data_dir)
    browser = p.chromium.launch()
    context = browser.new_context(viewport={"width": 1280, "height": 900}, locale="en-US")
    page = context.new_page()
    page.add_init_script(INIT_HARNESS_JS)

    page_errors: list[str] = []
    http_bodies: list[tuple[str, str]] = []
    page.on("pageerror", lambda err: page_errors.append(str(err)))

    def on_request(req) -> None:
        if "/v1/local/" in req.url and req.post_data:
            http_bodies.append((f"REQ {req.method} {req.url}", req.post_data))

    def on_response(res) -> None:
        if "/v1/local/" in res.url:
            try:
                http_bodies.append((f"RES {res.status} {res.url}", res.text()))
            except Exception:
                pass

    page.on("request", on_request)
    page.on("response", on_response)

    page.goto(open_url, wait_until="networkidle")
    page.locator(".buf-tab", has_text="m3-copy-hist").click()
    page.wait_for_selector(f'[data-block-id="{md_blk_id}"]', timeout=15000)

    # ---- Check 3: Granular Copy & Task Checkbox Writeback ----
    md_card = page.locator(f'[data-block-id="{md_blk_id}"]')
    md_card.locator(".cm-content").click()
    page.keyboard.press(f"{MOD_KEY}+e")
    page.wait_for_selector(f'[data-block-id="{md_blk_id}"][data-view-mode="preview"] .md-preview', timeout=10000)

    # 3a. Copy Rich (via block overflow popover)
    page.evaluate("() => { window.__clipboardWrites = []; }")
    md_card.hover()
    page.click(f'[data-testid="more-btn-{md_blk_id}"]')
    page.click(f'[data-testid="copy-rich-{md_blk_id}"]')
    page.wait_for_function("() => window.__clipboardWrites.length >= 1", timeout=5000)
    rich_write = page.evaluate("() => window.__clipboardWrites[0]")
    assert rich_write["kind"] == "write" and len(rich_write["items"]) == 1, f"Unexpected Copy Rich payload: {rich_write}"
    rich_item = rich_write["items"][0]
    assert "text/html" in rich_item and "text/plain" in rich_item, f"Copy Rich missing dual formats: {rich_item.keys()}"
    assert "<table>" in rich_item["text/html"] and "<code" in rich_item["text/html"], (
        f"Copy Rich HTML missing table/code: {rich_item['text/html']}"
    )
    for ui_noise in ("Copy Code", "Copy TSV", "Copy MD", "Copy Rich"):
        assert ui_noise not in rich_item["text/html"], f"UI button text '{ui_noise}' leaked into Copy Rich HTML"
        assert ui_noise not in rich_item["text/plain"], f"UI button text '{ui_noise}' leaked into Copy Rich text"

    # 3b. Copy Code
    page.evaluate("() => { window.__clipboardWrites = []; }")
    md_card.locator(".md-copy-code").click()
    page.wait_for_function("() => window.__clipboardWrites.length >= 1", timeout=5000)
    code_write = page.evaluate("() => window.__clipboardWrites[0]")
    assert code_write["kind"] == "writeText"
    assert code_write["text"] == 'print("hi")', f"Copy Code mismatch: {code_write['text']!r}"
    assert "```" not in code_write["text"]

    # 3c. Copy TSV (hover table wrap to reveal floating table toolbar)
    page.evaluate("() => { window.__clipboardWrites = []; }")
    md_card.locator(".md-table-wrap").hover()
    md_card.locator(".md-copy-tsv").click()
    page.wait_for_function("() => window.__clipboardWrites.length >= 1", timeout=5000)
    tsv_text = page.evaluate("() => window.__clipboardWrites[0].text")
    assert tsv_text == "Feature\tStatus\nPele\tReady\nHistory\tReady", f"Copy TSV mismatch: {tsv_text!r}"
    assert "|" not in tsv_text

    # 3d. Copy MD
    page.evaluate("() => { window.__clipboardWrites = []; }")
    md_card.locator(".md-table-wrap").hover()
    md_card.locator(".md-copy-md").click()
    page.wait_for_function("() => window.__clipboardWrites.length >= 1", timeout=5000)
    md_table_text = page.evaluate("() => window.__clipboardWrites[0].text")
    assert "| Feature | Status |" in md_table_text and "| --- | --- |" in md_table_text and "| Pele | Ready |" in md_table_text, (
        f"Copy MD mismatch: {md_table_text!r}"
    )

    # 3e. Desktop Task Checkbox Writeback -> persists to SQLite!
    first_cb = md_card.locator('.md-preview input[type="checkbox"]').nth(0)
    assert not first_cb.is_disabled(), "Desktop preview task checkbox must be interactive!"
    assert not first_cb.is_checked(), "First task checkbox should start unchecked"
    with page.expect_response(lambda r: f"/v1/local/blocks/{md_blk_id}" in r.url and r.request.method == "PATCH" and r.status == 200):
        first_cb.click()
    raw_after_toggle = run_cli(data_dir, ["block", "get", md_blk_id, "--raw"]).stdout
    assert "- [x] Ship M3" in raw_after_toggle and "- [x] Ship M2" in raw_after_toggle, (
        f"Checkbox writeback did not persist to SQLite:\n{raw_after_toggle}"
    )
    print("[m3:chromium] Check 3 (Copy Rich / Code / TSV / MD + Task Checkbox SQLite writeback) PASS")

    # ---- Check 4A: Desktop History (Time Travel) Drawer + Actor Badge + Diff + Revert ----
    page.locator(f'[data-block-id="{hist_blk_id}"] .cm-content').click()
    page.click(f'[data-testid="more-btn-{hist_blk_id}"]')
    page.click(f'[data-testid="history-btn-{hist_blk_id}"]')
    page.wait_for_selector('[data-testid="history-drawer"]:not(.hidden)', timeout=10000)
    page.wait_for_selector(".history-item", timeout=10000)

    drawer = page.locator('[data-testid="history-drawer"]')
    assert drawer.locator(".actor-badge-agent", has_text="agent:claude-code").count() >= 2, (
        "Expected agent:claude-code badges in History drawer"
    )
    assert drawer.locator('[data-testid="history-undo-actor-btn"]').is_visible(), (
        "Expected 'Undo agent:claude-code batch' button in History drawer"
    )

    # Select the original human CREATE entry (only non-human actors carry an agent badge)
    human_item = drawer.locator(".history-item:not(:has(.actor-badge-agent))").last
    human_item.click()
    page.wait_for_selector('[data-testid="history-diff-view"] .diff-add', timeout=10000)
    page.wait_for_selector('[data-testid="history-diff-view"] .diff-del', timeout=10000)
    diff_text = drawer.locator('[data-testid="history-diff-view"]').inner_text()
    assert "Human original line 1" in diff_text and "Agent edit 2" in diff_text, (
        f"Expected original & current lines in diff view, got:\n{diff_text}"
    )

    # Click Revert -> restores original human content in DOM AND SQLite
    with page.expect_response(lambda r: f"/v1/local/blocks/{hist_blk_id}/revert" in r.url and r.status == 200):
        page.click('[data-testid="history-revert-btn"]')

    page.wait_for_function(
        f"""() => {{
            const card = document.querySelector('[data-block-id="{hist_blk_id}"]');
            return card && card.innerText.includes('Human original line 1') && !card.innerText.includes('Agent edit 2');
        }}""",
        timeout=10000,
    )
    reverted_raw = run_cli(data_dir, ["block", "get", hist_blk_id, "--raw"]).stdout
    assert reverted_raw == human_v1, f"SQLite revert mismatch: got {reverted_raw!r}, expected {human_v1!r}"
    page.click('[data-testid="history-close-btn"]')
    print("[m3:chromium] Check 4A (History drawer + agent badge + diff + Revert to human v1) PASS")

    # ---- Check 4B: Tier 2 Vault History (WASM-only decryption, 0 HTTP leaks) + visibilitychange Scrub (SEC-03) ----
    vault_pass = "M3-Tier2-History-Vault#2026"
    t2_v1 = "T2_HIST_V1_SECRET_ALPHA_9191"
    t2_v2 = "T2_HIST_V2_SECRET_BETA_8282"

    page.click('[data-testid="vault-btn"]')
    page.fill('[data-testid="vault-passphrase-input"]', vault_pass)
    page.fill('[data-testid="vault-passphrase-confirm"]', vault_pass)
    page.click('[data-testid="vault-submit-btn"]')
    page.wait_for_function(
        '() => document.querySelector(\'[data-testid="vault-btn"]\')?.textContent?.includes("Unlocked")',
        timeout=15000,
    )

    t2_card = page.locator(f'[data-block-id="{t2_hist_blk_id}"]')
    t2_card.locator(".cm-content").click()
    page.click(f'[data-testid="more-btn-{t2_hist_blk_id}"]')
    page.click(f'[data-testid="lock-btn-{t2_hist_blk_id}"]')
    page.fill('[data-testid="lock-hint-input"]', "M3 Tier 2 History Hint")
    page.click('[data-testid="lock-confirm-btn"]')
    page.wait_for_selector(f'[data-block-id="{t2_hist_blk_id}"][data-locked="true"]', timeout=10000)

    # Edit twice strictly inside Tier 2 WASM (v1 -> save -> v2 -> save)
    for ver_text in (f"# Vault Note\n\n{t2_v1}", f"# Vault Note\n\n{t2_v2}"):
        t2_card.locator(".cm-content").click()
        page.keyboard.press(f"{MOD_KEY}+a")
        page.keyboard.press("Backspace")
        page.keyboard.type(ver_text)
        with page.expect_response(
            lambda r: f"/v1/local/blocks/{t2_hist_blk_id}" in r.url and r.request.method == "PATCH" and r.status == 200
        ):
            page.keyboard.press(f"{MOD_KEY}+s")
        time.sleep(0.15)

    # Switch Tier 2 Markdown block to Preview mode so Preview DOM contains Tier 2 plaintext
    page.click(f'[data-testid="mode-preview-{t2_hist_blk_id}"]')
    page.wait_for_function(
        f"""() => document.querySelector('[data-block-id="{t2_hist_blk_id}"] .md-preview')?.innerText?.includes('{t2_v2}')""",
        timeout=10000,
    )

    # Open History drawer on Tier 2 block & inspect the v1 Tier 2 revision (decrypted strictly in WASM RAM!)
    t2_card.hover()
    page.click(f'[data-testid="more-btn-{t2_hist_blk_id}"]')
    page.click(f'[data-testid="history-btn-{t2_hist_blk_id}"]')
    page.wait_for_selector('[data-testid="history-drawer"]:not(.hidden) .history-item', timeout=10000)
    # Entries are newest-first: [0] is v2 (current), [1] is v1 (both UPDATE with locked badge)
    t2_items = drawer.locator(".history-item")
    assert t2_items.count() >= 3, f"Expected >= 3 history items for Tier 2 block, got {t2_items.count()}"
    t2_items.nth(1).click()
    page.wait_for_function(
        f"""() => {{
            const dv = document.querySelector('[data-testid="history-diff-view"]');
            return dv && dv.innerText.includes('{t2_v1}') && dv.innerText.includes('{t2_v2}');
        }}""",
        timeout=10000,
    )

    # Audit ALL observed /v1/local/ HTTP request & response payloads -> ZERO Tier 2 plaintext or passphrase!
    for tag, body in http_bodies:
        assert t2_v1 not in body, f"SEC-03 VIOLATION: {t2_v1} leaked in HTTP {tag}!"
        assert t2_v2 not in body, f"SEC-03 VIOLATION: {t2_v2} leaked in HTTP {tag}!"
        assert vault_pass not in body, f"SEC-03 VIOLATION: passphrase leaked in HTTP {tag}!"

    # Trigger visibilitychange -> hidden => History drawer AND Tier 2 Preview DOM MUST be wiped immediately!
    page.evaluate(
        """() => {
            Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
            document.dispatchEvent(new Event('visibilitychange'));
        }"""
    )
    page.wait_for_selector(f'[data-block-id="{t2_hist_blk_id}"] .locked-card', timeout=5000)
    scrub_state = page.evaluate(
        """(id) => ({
            drawerHidden: document.querySelector('[data-testid="history-drawer"]')?.classList.contains('hidden'),
            drawerHtmlLen: document.querySelector('[data-testid="history-drawer"] .history-diff-pane')?.innerHTML.length ?? -1,
            previewCount: document.querySelectorAll(`[data-block-id="${id}"] .md-preview`).length,
            bodyText: document.body.innerText,
        })""",
        t2_hist_blk_id,
    )
    assert scrub_state["drawerHidden"] is True, f"SEC-03 VIOLATION: History drawer stayed open on hidden: {scrub_state}"
    assert scrub_state["drawerHtmlLen"] == 0, f"SEC-03 VIOLATION: History diff pane not wiped: {scrub_state}"
    assert scrub_state["previewCount"] == 0, f"SEC-03 VIOLATION: Tier 2 preview remained mounted: {scrub_state}"
    assert t2_v1 not in scrub_state["bodyText"] and t2_v2 not in scrub_state["bodyText"], (
        "SEC-03 VIOLATION: Tier 2 secret remained in DOM after visibilitychange hidden!"
    )

    csp_violations = page.evaluate("() => window.__cspViolations || []")
    assert len(csp_violations) == 0, f"Unexpected CSP violations in Check 3/4: {csp_violations}"
    assert len(page_errors) == 0, f"Unexpected page errors in Check 3/4: {page_errors}"
    print("[m3:chromium] Check 4B (Tier 2 WASM History + 0 HTTP plaintext + visibilitychange immediate scrub) PASS")
    browser.close()


def run_check5_mobile_pwa_webkit(p, raw_vectors: dict) -> None:
    """
    Check 5: Mobile Read-Only PWA M3 Audit (REAL WebKit + REAL wrangler dev --local):
      - Markdown & Mermaid default to Preview mode + Source toggle works
      - Task checkboxes strictly disabled (read-only)
      - SEC-06: 0 XSS, 0 external requests, 0 forbidden tags/attrs/styles, 0 CSP violations
      - Copy PNG in WebKit produces valid PNG magic bytes (> 500 bytes), 0 Tainted Canvas error
      - SEC-08: 6 IDB stores ciphertext-only, non-extractable CryptoKey, 0 LS/SS/Cache leaks
    """
    assert (ROOT / "web" / "dist-pwa" / "index.html").exists(), "web/dist-pwa missing"
    wrangler_bin = CLOUD_DIR / "node_modules" / ".bin" / "wrangler"
    assert wrangler_bin.exists(), f"wrangler missing at {wrangler_bin}"

    port = pick_free_port()
    base_url = f"http://127.0.0.1:{port}"
    boot_token = "e2e-m3-pwa-bootstrap-token"
    tmp_desktop = Path(tempfile.mkdtemp(prefix="mynote-m3-pwa-desk-"))
    tmp_wrangler = Path(tempfile.mkdtemp(prefix="mynote-m3-pwa-cf-"))

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
        rc, out = run_pty_cmd(
            tmp_desktop,
            ["device", "bootstrap", "--url", base_url],
            [],
            env_extra={"MYNOTE_BOOTSTRAP_TOKEN": boot_token},
        )
        assert rc == 0, f"desktop bootstrap failed ({rc}): {out}"

        md_canary = "PWA_M3_MD_CANARY_888111"
        mermaid_canary = "PWA_M3_MERMAID_CANARY_999222"

        pwa_md_body = "\n\n".join(
            [
                f"# Mobile M3 {md_canary}",
                "- [ ] Mobile unchecked task\n- [x] Mobile checked task",
                "| Engine | Mode |\n| --- | --- |\n| WebKit | ReadOnly |",
                *raw_vectors["markdown_xss"],
                *raw_vectors["external_images"],
            ]
        )
        md_blk_id = add_block(tmp_desktop, pwa_md_body, "markdown")
        mermaid_blk_id = add_block(
            tmp_desktop,
            f"flowchart LR\n  Phone[\"{mermaid_canary}\"] --> Relay[\"Cloudflare\"]",
            "mermaid",
        )
        mermaid_xss_ids = [add_block(tmp_desktop, vec, "mermaid") for vec in raw_vectors["mermaid_xss"]]

        push_out = run_cli(tmp_desktop, ["--json", "sync", "push"]).stdout
        assert json.loads(push_out)["ok"] is True

        rc, pair_out = run_pty_cmd(tmp_desktop, ["device", "add", "--name", "iPhoneWebKitM3", "--scope", "read"], [])
        assert rc == 0, f"device add failed ({rc}): {pair_out}"
        m = re.search(r"(mynote-pair:v1:[A-Za-z0-9_-]+)", pair_out)
        assert m, f"pairing code missing:\n{pair_out}"
        pair_code = m.group(1)

        browser = p.webkit.launch()
        context = browser.new_context(viewport={"width": 390, "height": 844})
        page = context.new_page()
        page.add_init_script(INIT_HARNESS_JS)

        page_errors: list[str] = []
        outbound_urls: list[str] = []
        page.on("pageerror", lambda err: page_errors.append(str(err)))
        page.on("request", lambda req: outbound_urls.append(req.url) if check_non_loopback_request(req.url) else None)

        res = page.goto(base_url, wait_until="networkidle")
        assert res is not None and res.status == 200
        csp = res.headers.get("content-security-policy", "")
        assert "style-src 'self'" in csp and "'unsafe-inline'" not in csp, f"Weak PWA CSP: {csp}"
        assert "img-src 'self' data: blob:" in csp, f"Missing data:/blob: img-src in PWA CSP: {csp}"

        page.wait_for_selector('[data-testid="pwa-pair-input"]', timeout=15000)
        page.fill('[data-testid="pwa-pair-input"]', pair_code)
        page.click('[data-testid="pwa-pair-submit"]')

        # Wait for Markdown preview AND Mermaid SVG preview to render BY DEFAULT (not raw <pre>!)
        page.wait_for_selector(f'[data-block-id="{md_blk_id}"][data-view-mode="preview"] .md-preview', timeout=20000)
        page.wait_for_selector(
            f'[data-block-id="{mermaid_blk_id}"][data-view-mode="preview"] .diagram-viewport svg',
            timeout=20000,
        )
        for mx_id in mermaid_xss_ids:
            page.wait_for_function(
                f"""() => {{
                    const card = document.querySelector('[data-block-id="{mx_id}"]');
                    return card && (
                        card.querySelector('.diagram-viewport svg') !== null ||
                        card.querySelector('.diagram-syntax-hint:not(.hidden)') !== null
                    );
                }}""",
                timeout=15000,
            )
        time.sleep(0.5)

        # Verify task checkboxes strictly disabled in Mobile PWA
        cb_states = page.evaluate(
            f"""() => Array.from(document.querySelectorAll('[data-block-id="{md_blk_id}"] .md-preview input[type="checkbox"]'))
                .map(el => ({{ disabled: el.disabled, checked: el.checked }}))"""
        )
        assert len(cb_states) >= 2, f"Expected >= 2 checkboxes in PWA preview, got {cb_states}"
        assert all(st["disabled"] for st in cb_states), f"Mobile PWA checkboxes MUST be disabled: {cb_states}"

        # Verify Source toggle button switches preview -> raw <pre> -> preview
        page.click(f'[data-testid="pwa-toggle-mode-{md_blk_id}"]')
        page.wait_for_selector(f'[data-block-id="{md_blk_id}"][data-view-mode="source"] pre.ro-pre', timeout=5000)
        page.click(f'[data-testid="pwa-toggle-mode-{md_blk_id}"]')
        page.wait_for_selector(f'[data-block-id="{md_blk_id}"][data-view-mode="preview"] .md-preview', timeout=5000)

        # SEC-06 Audit on Mobile WebKit PWA
        assert not page.evaluate("() => Boolean(window.__xssExecuted)"), "SEC-06 VIOLATION in Mobile WebKit PWA!"
        dom_findings = page.evaluate(DOM_SEC06_AUDIT_JS, [".md-preview", ".diagram-viewport"])
        assert len(dom_findings) == 0, f"SEC-06 Mobile WebKit DOM VIOLATIONS: {dom_findings}"
        assert len(outbound_urls) == 0, f"SEC-06 Mobile WebKit EXFILTRATION: {outbound_urls}"

        # Taint-Free Copy PNG in Mobile WebKit PWA (via collapsed Copy menu)
        page.evaluate("() => { window.__clipboardWrites = []; }")
        mermaid_card = page.locator(f'[data-block-id="{mermaid_blk_id}"]')
        mermaid_card.locator(".diagram-copy-trigger").click()
        mermaid_card.locator(".diagram-copy-png").click()
        page.wait_for_function(
            """() => window.__clipboardWrites.some(w => w.kind === 'write' && w.items.some(it => 'image/png' in it))""",
            timeout=10000,
        )
        pwa_png_bytes = page.evaluate(
            """() => {
                const hit = window.__clipboardWrites.find(w => w.kind === 'write' && w.items.some(it => 'image/png' in it));
                return hit.items.find(it => 'image/png' in it)['image/png'];
            }"""
        )
        assert_png_bytes(pwa_png_bytes, "Mobile WebKit PWA Copy PNG")

        csp_violations = page.evaluate("() => window.__cspViolations || []")
        assert len(csp_violations) == 0, f"Mobile WebKit PWA CSP VIOLATIONS: {csp_violations}"

        # SEC-08 Forensic Storage Audit
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
                    if (v instanceof CryptoKey) return { __cryptoKey: true, extractable: v.extractable };
                    if (v instanceof ArrayBuffer) return { __utf8: new TextDecoder().decode(new Uint8Array(v)) };
                    if (ArrayBuffer.isView(v)) return { __utf8: new TextDecoder().decode(new Uint8Array(v.buffer, v.byteOffset, v.byteLength)) };
                    if (Array.isArray(v)) {
                        if (v.length > 0 && v.every(x => typeof x === 'number' && x >= 0 && x <= 255)) {
                            return { __numUtf8: new TextDecoder().decode(new Uint8Array(v)) };
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
        assert audit["storeNames"] == expected_stores, f"Unexpected IDB stores: {audit['storeNames']}"
        assert audit["wrapKeyExtractable"] is False, f"SEC-08 VIOLATION: extractable wrap key!"
        assert len(audit["ls"]) == 0 and len(audit["ss"]) == 0, f"SEC-08 VIOLATION: LS/SS non-empty!"
        for ce in audit["cacheEntries"]:
            assert "/v1/" not in ce["url"], f"SEC-08 VIOLATION: /v1/ cached: {ce['url']}"
        full_dump = json.dumps(audit)
        for canary in (md_canary, mermaid_canary):
            assert canary not in full_dump, f"SEC-08 FORENSIC VIOLATION: '{canary}' found in WebKit storage!"

        assert len(page_errors) == 0, f"Unexpected WebKit PWA page errors: {page_errors}"
        print(
            f"[m3:webkit-pwa] Check 5 PASS (Preview default + Source toggle + disabled checkboxes + Copy PNG {len(pwa_png_bytes)}B + SEC-06 + SEC-08)"
        )
        browser.close()
    finally:
        wrangler.terminate()
        try:
            wrangler.wait(timeout=5)
        except subprocess.TimeoutExpired:
            wrangler.kill()
        shutil.rmtree(tmp_desktop, ignore_errors=True)
        shutil.rmtree(tmp_wrangler, ignore_errors=True)


def main() -> None:
    assert BIN.exists(), f"mynote binary missing at {BIN}"
    assert XSS_FIXTURE.exists(), f"XSS fixture missing at {XSS_FIXTURE}"
    raw_vectors = json.loads(XSS_FIXTURE.read_text(encoding="utf-8"))

    tmp_desk = Path(tempfile.mkdtemp(prefix="mynote-m3-desk-"))
    daemon = subprocess.Popen(
        [str(BIN), "--data-dir", str(tmp_desk), "daemon", "--port", "0", "--no-cloud-sync"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _, port = wait_for_open_url(tmp_desk)
        print(f"[m3] Real mynote daemon listening on http://localhost:{port}")

        # Seed 4 Mermaid diagram types + 1 Split-recovery diagram in default `scratch` buffer
        diagram_samples = [
            ("flowchart", "flowchart TD\n  Client[Desktop UI] --> Daemon[mynote daemon]\n  Daemon --> DB[(SQLite WAL)]"),
            ("sequenceDiagram", "sequenceDiagram\n  Desktop->>Relay: Push Op\n  Relay-->>Mobile: WS Wake"),
            ("erDiagram", "erDiagram\n  BUFFER ||--o{ BLOCK : contains\n  BLOCK ||--o{ OP : history"),
            ("classDiagram", "classDiagram\n  class SyncEngine {\n    +applyOp()\n    +materialize()\n  }"),
        ]
        diagram_ids = [(kind, add_block(tmp_desk, src, "mermaid", buf="scratch")) for kind, src in diagram_samples]
        split_diagram_id = add_block(tmp_desk, "flowchart LR\n  Start --> End", "mermaid", buf="scratch")

        # Seed ALL SEC-06 XSS & external-image vectors into `sec06` buffer
        run_cli(tmp_desk, ["buf", "create", "sec06"])
        md_xss_id = add_block(tmp_desk, "\n\n".join(raw_vectors["markdown_xss"]), "markdown", buf="sec06")
        ext_img_id = add_block(tmp_desk, "\n\n".join(raw_vectors["external_images"]), "markdown", buf="sec06")
        mermaid_xss_ids = [add_block(tmp_desk, vec, "mermaid", buf="sec06") for vec in raw_vectors["mermaid_xss"]]

        seeded = {
            "diagram_ids": diagram_ids,
            "split_diagram_id": split_diagram_id,
            "md_xss_id": md_xss_id,
            "ext_img_id": ext_img_id,
            "mermaid_xss_ids": mermaid_xss_ids,
        }

        with sync_playwright() as p:
            # Checks 1 & 2 in BOTH real Chromium AND real WebKit
            run_check1_and_check2_desktop(p, "chromium", tmp_desk, seeded)
            run_check1_and_check2_desktop(p, "webkit", tmp_desk, seeded)

            # Checks 3 & 4 in real Chromium
            run_check3_and_check4_desktop_chromium(p, tmp_desk)

            # Check 5: Mobile Read-Only PWA in real WebKit + real wrangler dev
            run_check5_mobile_pwa_webkit(p, raw_vectors)

        print("ALL M3 REAL-BROWSER E2E AUDITS (CHROMIUM + WEBKIT + WRANGLER DEV) PASSED!")
    finally:
        if daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
        shutil.rmtree(tmp_desk, ignore_errors=True)


if __name__ == "__main__":
    main()
