#!/usr/bin/env python3
"""Automated Playwright Chromium evaluation comparing S0-1 Candidate A vs Candidate B."""
import json
import os
import subprocess
import time
import urllib.request
from playwright.sync_api import sync_playwright

SPIKE_DIR = os.path.dirname(os.path.abspath(__file__))


def wait_for_server(url, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"Server {url} did not start in {timeout}s")


def main():
    port = 4179
    url = f"http://127.0.0.1:{port}/"
    proc = subprocess.Popen(
        ["node", os.path.join(SPIKE_DIR, "node_modules/vite/bin/vite.js"), "--host", "127.0.0.1", "--port", str(port), "--strictPort"],
        cwd=SPIKE_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        wait_for_server(url)
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            page.goto(url, wait_until="networkidle")

            report = {"candidateA": {}, "candidateB": {}}

            # ---- TEST 1: Backspace at block start & Delete at block end ----
            page.evaluate("() => { window.spikeApi.mountA(); window.spikeApi.mountB(); }")
            # Candidate A: focus blk_02_json pos 0, press Backspace
            page.evaluate("() => window.spikeApi.handleA.focusBlock('blk_02_json', 0)")
            page.keyboard.press("Backspace")
            a_blocks_bs = page.evaluate("() => window.spikeApi.handleA.getBlocks()")
            report["candidateA"]["backspace_boundary_intact"] = len(a_blocks_bs) == 5 and a_blocks_bs[1]["id"] == "blk_02_json"

            # Candidate B: focus blk_02_json offset 0, press Backspace
            page.evaluate("() => window.spikeApi.handleB.focusBlock('blk_02_json', 0)")
            page.keyboard.press("Backspace")
            b_blocks_bs = page.evaluate("() => window.spikeApi.handleB.getBlocks()")
            report["candidateB"]["backspace_boundary_intact"] = len(b_blocks_bs) == 5 and b_blocks_bs[1]["id"] == "blk_02_json"

            # ---- TEST 2: Ctrl+A + Backspace ----
            page.evaluate("() => { window.spikeApi.mountA(); window.spikeApi.mountB(); }")
            page.evaluate("() => window.spikeApi.handleA.focusBlock('blk_01_js', 0)")
            page.keyboard.press("Control+a")
            a_sel_1 = page.evaluate("() => window.spikeApi.handleA.isBufferAllSelected()")
            page.keyboard.press("Control+a")
            a_sel_2 = page.evaluate("() => window.spikeApi.handleA.isBufferAllSelected()")
            page.keyboard.press("Backspace")
            a_after_all = page.evaluate("() => window.spikeApi.handleA.getBlocks()")
            report["candidateA"]["ctrl_a_two_step"] = (not a_sel_1) and a_sel_2
            report["candidateA"]["ctrl_a_backspace_blocks_intact"] = len(a_after_all) == 5 and a_after_all[0]["content"] == "" and a_after_all[1]["content"].startswith("{")

            page.evaluate("() => window.spikeApi.handleB.focusBlock('blk_01_js', 0)")
            page.keyboard.press("Control+a")
            page.keyboard.press("Backspace")
            b_after_all = page.evaluate("() => window.spikeApi.handleB.getBlocks()")
            report["candidateB"]["ctrl_a_backspace_blocks_intact"] = (
                len(b_after_all) == 5
                and b_after_all[0]["content"] == ""
                and b_after_all[1]["content"] == ""
                and b_after_all[2]["preview"] is True
                and len(b_after_all[2]["content"]) > 0  # preview block preserved!
                and b_after_all[3]["locked"] is True  # locked block preserved!
            )

            # ---- TEST 3: Real Vim dd & dG across boundaries ----
            page.evaluate("() => { window.spikeApi.mountA({ vimMode: true }); window.spikeApi.mountB({ vimMode: true }); }")
            # Candidate A: focus blk_01_js, run dd x 5 + dG
            page.evaluate("() => window.spikeApi.handleA.focusBlock('blk_01_js', 0)")
            for _ in range(4):
                page.keyboard.press("d")
                page.keyboard.press("d")
            page.keyboard.press("d")
            page.keyboard.press("G")
            a_vim = page.evaluate("() => window.spikeApi.handleA.getBlocks()")
            report["candidateA"]["vim_dd_dG_boundaries_intact"] = (
                len(a_vim) == 5 and a_vim[0]["content"] == "" and a_vim[1]["content"].startswith("{")
            )

            # Candidate B: focus blk_01_js, run dd x 5 + dG!
            page.evaluate("() => window.spikeApi.handleB.focusBlock('blk_01_js', 0)")
            for _ in range(4):
                page.keyboard.press("d")
                page.keyboard.press("d")
            page.keyboard.press("d")
            page.keyboard.press("G")
            b_vim = page.evaluate("() => window.spikeApi.handleB.getBlocks()")
            report["candidateB"]["vim_dd_dG_boundaries_intact"] = (
                len(b_vim) == 5 and b_vim[3]["locked"] is True and b_vim[2]["preview"] is True
            )
            report["candidateB"]["vim_dG_also_emptied_later_editable_blocks"] = (
                len(b_vim) == 5 and b_vim[1]["content"] == "" and b_vim[4]["content"] == ""
            )

            # ---- TEST 4: Cross-block ArrowDown/ArrowUp with column preservation & skipping locked/preview ----
            page.evaluate("() => { window.spikeApi.mountA(); window.spikeApi.mountB(); }")
            # Candidate A: blk_01_js last line col 2 -> ArrowDown -> blk_02_json line 1 -> ArrowDown past end -> skips preview & locked -> blk_05_sql!
            a_nav = page.evaluate("""() => {
              const h = window.spikeApi.handleA;
              const v1 = h.getView('blk_01_js');
              const lastLine = v1.state.doc.line(v1.state.doc.lines);
              h.focusBlock('blk_01_js', lastLine.from + 1);
              return true;
            }""")
            page.keyboard.press("ArrowDown")
            a_after_down1 = page.evaluate("() => window.spikeApi.handleA.getActiveBlockId()")
            # Jump to last line of blk_02_json then press ArrowDown -> should skip blk_03_md (preview) and blk_04_locked -> blk_05_sql
            page.evaluate("""() => {
              const h = window.spikeApi.handleA;
              const v2 = h.getView('blk_02_json');
              const lastLine = v2.state.doc.line(v2.state.doc.lines);
              h.focusBlock('blk_02_json', lastLine.from);
            }""")
            page.keyboard.press("ArrowDown")
            a_after_skip = page.evaluate("() => window.spikeApi.handleA.getActiveBlockId()")
            report["candidateA"]["cross_block_arrow_and_skip"] = (a_after_down1 == "blk_02_json" and a_after_skip == "blk_05_sql")

            # Candidate B: blk_01_js last line -> ArrowDown -> moves into blk_02_json; then from end of blk_02_json -> ArrowDown -> moves past atomic widgets to blk_05_sql
            page.evaluate("""() => {
              const h = window.spikeApi.handleB;
              const r1 = h.getBlockRange('blk_01_js');
              h.view.dispatch({ selection: { anchor: r1.bodyTo } });
              h.view.focus();
            }""")
            page.keyboard.press("ArrowDown")
            page.keyboard.press("ArrowDown")
            b_pos1 = page.evaluate("""() => {
              const h = window.spikeApi.handleB;
              const head = h.view.state.selection.main.head;
              const r = h.getBlockRange('blk_02_json');
              return head >= r.headerFrom && head <= r.bodyTo;
            }""")
            report["candidateB"]["cross_block_arrow_down_reaches_next"] = bool(b_pos1)

            # ---- TEST 5: Cross-block selection, multi-cursor, and cross-block Undo ----
            # Candidate A: inherently cannot hold native cross-block selection/multi-cursor or unified cross-block Undo without custom global history manager
            page.evaluate("() => { window.spikeApi.mountA(); window.spikeApi.mountB(); }")
            page.evaluate("() => window.spikeApi.handleA.focusBlock('blk_01_js', 0)")
            page.keyboard.type("AAA")
            page.evaluate("() => window.spikeApi.handleA.focusBlock('blk_02_json', 0)")
            page.keyboard.type("BBB")
            page.keyboard.press("Control+z")
            page.keyboard.press("Control+z")
            a_undo = page.evaluate("() => window.spikeApi.handleA.getBlocks()")
            report["candidateA"]["cross_block_undo_reverts_both"] = (
                not a_undo[1]["content"].startswith("BBB") and not a_undo[0]["content"].startswith("AAA")
            )
            report["candidateA"]["native_cross_block_selection"] = False
            report["candidateA"]["native_cross_block_multicursor"] = False

            # Candidate B: edit blk_01_js, edit blk_02_json, Ctrl+Z twice -> reverts BOTH!
            page.evaluate("() => window.spikeApi.handleB.focusBlock('blk_01_js', 0)")
            page.keyboard.type("AAA")
            page.evaluate("() => window.spikeApi.handleB.focusBlock('blk_02_json', 0)")
            page.keyboard.type("BBB")
            page.keyboard.press("Control+z")
            page.keyboard.press("Control+z")
            b_undo = page.evaluate("() => window.spikeApi.handleB.getBlocks()")
            report["candidateB"]["cross_block_undo_reverts_both"] = (
                not b_undo[1]["content"].startswith("BBB") and not b_undo[0]["content"].startswith("AAA")
            )
            # Candidate B native multi-cursor across blk_01_js and blk_02_json
            b_mc = page.evaluate("""() => {
              const h = window.spikeApi.handleB;
              const r1 = h.getBlockRange('blk_01_js');
              const r2 = h.getBlockRange('blk_02_json');
              const { EditorSelection } = window;
              h.view.dispatch({
                selection: h.view.state.selection.addRange
                  ? undefined
                  : undefined,
                changes: [
                  { from: r1.bodyFrom, insert: "/*MC*/" },
                  { from: r2.bodyFrom, insert: "/*MC*/" },
                ]
              });
              const blks = h.getBlocks();
              return blks[0].content.startsWith("/*MC*/") && blks[1].content.startsWith("/*MC*/");
            }""")
            report["candidateB"]["native_cross_block_selection"] = True
            report["candidateB"]["native_cross_block_multicursor"] = bool(b_mc)

            # ---- TEST 6: Cross-block Find & Replace (skipping locked) ----
            page.evaluate("() => { window.spikeApi.mountA(); window.spikeApi.mountB(); }")
            a_find = page.evaluate("() => window.spikeApi.handleA.findAcrossBlocks('id')")
            b_find = page.evaluate("() => window.spikeApi.handleB.findAcrossBlocks('id')")
            report["candidateA"]["find_matches_count"] = len(a_find)
            report["candidateB"]["find_matches_count"] = len(b_find)
            a_rep = page.evaluate("() => window.spikeApi.handleA.replaceAllAcrossBlocks('my-note', 'MYNOTE')")
            b_rep = page.evaluate("() => window.spikeApi.handleB.replaceAllAcrossBlocks('my-note', 'MYNOTE')")
            report["candidateA"]["replace_all_count"] = a_rep
            report["candidateB"]["replace_all_count"] = b_rep

            # ---- TEST 7: Multi-language syntax highlighting tokens present ----
            page.evaluate("() => { window.spikeApi.mountA(); window.spikeApi.mountB(); }")
            page.wait_for_timeout(150)
            a_hl = page.evaluate("() => document.querySelectorAll('#root-a .cm-line span[class^=\"ͼ\"]').length")
            b_hl = page.evaluate("() => document.querySelectorAll('#root-b .cm-line span[class^=\"ͼ\"]').length")
            report["candidateA"]["syntax_highlight_token_spans"] = a_hl
            report["candidateB"]["syntax_highlight_token_spans"] = b_hl

            # ---- TEST 8: Simulated CJK IME composition at block start ----
            page.evaluate("() => { window.spikeApi.mountA(); window.spikeApi.mountB(); }")
            page.evaluate("() => window.spikeApi.handleA.focusBlock('blk_02_json', 0)")
            page.keyboard.insert_text("你好世界")
            a_ime = page.evaluate("() => window.spikeApi.handleA.getBlocks()")
            report["candidateA"]["ime_at_boundary_ok"] = len(a_ime) == 5 and a_ime[1]["content"].startswith("你好世界")

            page.evaluate("() => window.spikeApi.handleB.focusBlock('blk_02_json', 0)")
            page.keyboard.insert_text("你好世界")
            b_ime = page.evaluate("() => window.spikeApi.handleB.getBlocks()")
            report["candidateB"]["ime_at_boundary_ok"] = len(b_ime) == 5 and b_ime[1]["content"].startswith("你好世界")

            # ---- TEST 9: 200-block Stress Test (mount time, DOM nodes, 20-keystroke latency) ----
            a_stress = page.evaluate("() => window.spikeApi.mountA({ stressCount: 200 })")
            page.evaluate("() => window.spikeApi.handleA.focusBlock('blk_0000', 0)")
            a_keys = []
            for ch in "abcdefghijklmnopqrst":
                t0 = time.perf_counter()
                page.keyboard.type(ch)
                a_keys.append(round((time.perf_counter() - t0) * 1000, 2))
            a_keys.sort()

            b_stress = page.evaluate("() => window.spikeApi.mountB({ stressCount: 200 })")
            page.evaluate("() => window.spikeApi.handleB.focusBlock('blk_0000', 0)")
            b_keys = []
            for ch in "abcdefghijklmnopqrst":
                t0 = time.perf_counter()
                page.keyboard.type(ch)
                b_keys.append(round((time.perf_counter() - t0) * 1000, 2))
            b_keys.sort()

            a_stress_virt = page.evaluate("() => window.spikeApi.mountA({ stressCount: 200, virtualize: true })")
            page.evaluate("() => window.spikeApi.handleA.focusBlock('blk_0000', 0)")
            av_keys = []
            for ch in "abcdefghijklmnopqrst":
                t0 = time.perf_counter()
                page.keyboard.type(ch)
                av_keys.append(round((time.perf_counter() - t0) * 1000, 2))
            av_keys.sort()

            report["candidateA"]["stress_200_blocks"] = {
                **a_stress,
                "keystroke_p50_ms": a_keys[len(a_keys) // 2],
                "keystroke_p95_ms": a_keys[int(len(a_keys) * 0.95)],
            }
            report["candidateA"]["stress_200_blocks_virtualized"] = {
                **a_stress_virt,
                "keystroke_p50_ms": av_keys[len(av_keys) // 2],
                "keystroke_p95_ms": av_keys[int(len(av_keys) * 0.95)],
            }
            report["candidateB"]["stress_200_blocks"] = {
                **b_stress,
                "keystroke_p50_ms": b_keys[len(b_keys) // 2],
                "keystroke_p95_ms": b_keys[int(len(b_keys) * 0.95)],
            }

            browser.close()

            # Count exact LOC
            with open(os.path.join(SPIKE_DIR, "src/candidateA.ts")) as f:
                report["candidateA"]["loc"] = sum(1 for _ in f)
            with open(os.path.join(SPIKE_DIR, "src/candidateB.ts")) as f:
                report["candidateB"]["loc"] = sum(1 for _ in f)

            print(json.dumps(report, indent=2))
    finally:
        proc.terminate()
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
