#!/usr/bin/env python3
"""Tier 0 static architecture, complexity budget, and security hygiene guard for my-note.

Zero external dependencies (Python 3.10+ standard library).
Includes `--selftest` mutant verification (`ARCH-01`..`ARCH-08`) per `eval-harness` Law 3.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_CORE_DEPS = {
    "tokio",
    "rusqlite",
    "reqwest",
    "axum",
    "web-sys",
    "js-sys",
    "wasm-bindgen",
    "fs2",
    "tokio-tungstenite",
}

FORBIDDEN_CORE_STD_PATTERNS = [
    (re.compile(r"\bstd::fs\b"), "std::fs"),
    (re.compile(r"\bstd::net\b"), "std::net"),
    (re.compile(r"\bstd::process\b"), "std::process"),
    (re.compile(r"\bSystemTime::now\b"), "SystemTime::now"),
    (re.compile(r"\bInstant::now\b"), "Instant::now"),
]

FORBIDDEN_UI_EMOJIS = ("🔒", "🔓", "⚡", "⚠", "🖼")

SYNC_CORE_FILES = (
    "sync.rs",
    "materialize.rs",
    "keys.rs",
    "hlc.rs",
    "fractional_index.rs",
)

CLOUD_CF_MAX_LOC = 950
SYNC_CORE_MAX_LOC = 3000


def strip_rust_cfg_test_tail(source: str) -> str:
    """Return production prefix before a top-level `#[cfg(test)]` module."""
    m = re.search(r"(?m)^#\[cfg\(test\)\]", source)
    return source[: m.start()] if m else source


def parse_cargo_workspace_version(cargo_toml: str) -> str | None:
    in_ws_pkg = False
    for raw in cargo_toml.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_ws_pkg = line == "[workspace.package]"
            continue
        if in_ws_pkg:
            m = re.match(r'^version\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    return None


def parse_cargo_dep_keys(cargo_toml: str) -> set[str]:
    deps: set[str] = set()
    in_deps = False
    subtable_rx = re.compile(r"^\[(?:target\.[^\]]+\.)?(?:build-)?dependencies\.([A-Za-z0-9_-]+)\]$")
    section_rx = re.compile(r"^\[(?:target\.[^\]]+\.)?(?:build-)?dependencies\]$")
    for raw in cargo_toml.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            m_sub = subtable_rx.match(line)
            if m_sub:
                deps.add(m_sub.group(1))
                in_deps = False
            else:
                in_deps = bool(section_rx.match(line))
            continue
        if in_deps and "=" in line:
            key = line.split("=", 1)[0].strip().strip('"')
            if key:
                deps.add(key)
    return deps


def audit_repo(repo: Path) -> list[tuple[str, str]]:
    """Run ARCH-01..ARCH-08 checks against `repo`; return list of `(code, detail)` failures."""
    failures: list[tuple[str, str]] = []

    # ARCH-01: mynote-core Cargo.toml zero I/O or host runtime dependencies
    core_toml_path = repo / "crates" / "mynote-core" / "Cargo.toml"
    if not core_toml_path.exists():
        failures.append(("ARCH-01", f"missing {core_toml_path}"))
    else:
        dep_keys = parse_cargo_dep_keys(core_toml_path.read_text(encoding="utf-8"))
        bad = sorted(dep_keys & FORBIDDEN_CORE_DEPS)
        if bad:
            failures.append(("ARCH-01", f"mynote-core/Cargo.toml contains forbidden I/O deps: {bad}"))

    # ARCH-02: mynote-core non-test, non-sim production code is strictly Sans-I/O & deterministic
    core_src = repo / "crates" / "mynote-core" / "src"
    if core_src.is_dir():
        for rs in sorted(core_src.rglob("*.rs")):
            rel = rs.relative_to(repo).as_posix()
            if "/sim/" in rel:
                continue
            prod = strip_rust_cfg_test_tail(rs.read_text(encoding="utf-8"))
            for rx, label in FORBIDDEN_CORE_STD_PATTERNS:
                if rx.search(prod):
                    failures.append(("ARCH-02", f"{rel} uses forbidden non-deterministic/I/O API `{label}`"))

    # ARCH-03: Spike isolation (root `spikes/` never imported or referenced; `docs/spikes/` reports allowed)
    spike_rx = re.compile(r"(?<!docs)(?:^|[\"'/\\])spikes/")
    for sub in ("crates", "web/src", "cloud-cf/src", "evals", "tests"):
        base = repo / sub
        if not base.exists():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file() or p.suffix in {".md", ".png", ".wasm"} or "__pycache__" in p.parts:
                continue
            rel = p.relative_to(repo).as_posix()
            if rel.startswith("evals/archive/"):
                continue
            txt = p.read_text(encoding="utf-8", errors="ignore")
            if spike_rx.search(txt):
                failures.append(("ARCH-03", f"{rel} references isolated `spikes/` directory"))

    # ARCH-04: Complexity LOC budgets (`AGENTS.md` §1 C1)
    cf_src = repo / "cloud-cf" / "src"
    if cf_src.is_dir():
        cf_loc = sum(
            len(p.read_text(encoding="utf-8").splitlines())
            for p in cf_src.rglob("*")
            if p.is_file() and p.suffix in {".ts", ".mts", ".js", ".mjs"}
        )
        if cf_loc > CLOUD_CF_MAX_LOC:
            failures.append(("ARCH-04", f"cloud-cf/src/ LOC={cf_loc} exceeds <= {CLOUD_CF_MAX_LOC} budget"))

    if core_src.is_dir():
        sync_loc = 0
        for fname in SYNC_CORE_FILES:
            fp = core_src / fname
            if fp.is_file():
                sync_loc += len(strip_rust_cfg_test_tail(fp.read_text(encoding="utf-8")).splitlines())
        if sync_loc >= SYNC_CORE_MAX_LOC:
            failures.append(
                ("ARCH-04", f"mynote-core sync core non-test LOC={sync_loc} exceeds < {SYNC_CORE_MAX_LOC} budget")
            )

    # ARCH-05: Anti-302 captive-portal / CF-Access silent-drop guard (`AGENTS.md` §3.3)
    rust_sync_client = repo / "crates" / "mynote-cli" / "src" / "sync_client.rs"
    pwa_cloud_api = repo / "web" / "src" / "pwa" / "cloudApi.ts"
    if not rust_sync_client.is_file() or "Policy::none()" not in rust_sync_client.read_text(encoding="utf-8"):
        failures.append(("ARCH-05", "crates/mynote-cli/src/sync_client.rs missing reqwest redirect::Policy::none()"))
    if not pwa_cloud_api.is_file():
        failures.append(("ARCH-05", "web/src/pwa/cloudApi.ts missing"))
    else:
        api_txt = pwa_cloud_api.read_text(encoding="utf-8")
        fetch_calls = len(re.findall(r"\bfetch\s*\(", api_txt))
        manual_redirects = len(re.findall(r'redirect\s*:\s*["\']manual["\']', api_txt))
        if fetch_calls == 0 or manual_redirects < fetch_calls:
            failures.append(
                (
                    "ARCH-05",
                    f"web/src/pwa/cloudApi.ts has {fetch_calls} fetch() calls but only {manual_redirects} `redirect: \"manual\"` guards",
                )
            )

    # ARCH-06: Web CSP (zero inline <script> body, identical theme-init.js) & zero forbidden UI emojis
    for html_name in ("index.html", "pwa.html"):
        hp = repo / "web" / html_name
        if not hp.is_file():
            failures.append(("ARCH-06", f"missing web/{html_name}"))
            continue
        htxt = hp.read_text(encoding="utf-8")
        for m in re.finditer(r"<script\b([^>]*)>([\s\S]*?)</script>", htxt, re.I):
            attrs, body = m.group(1), m.group(2)
            if "src=" not in attrs.lower() or body.strip():
                failures.append(("ARCH-06", f"web/{html_name} contains inline <script> violating CSP"))
    t_desk = repo / "web" / "public" / "theme-init.js"
    t_pwa = repo / "web" / "public-pwa" / "theme-init.js"
    if not t_desk.is_file() or not t_pwa.is_file() or t_desk.read_bytes() != t_pwa.read_bytes():
        failures.append(("ARCH-06", "web/public/theme-init.js and web/public-pwa/theme-init.js diverged"))

    web_src = repo / "web" / "src"
    if web_src.is_dir():
        for wp in sorted(web_src.rglob("*")):
            if wp.is_file() and wp.suffix in {".ts", ".tsx", ".css"}:
                wtxt = wp.read_text(encoding="utf-8")
                for emo in FORBIDDEN_UI_EMOJIS:
                    if emo in wtxt:
                        failures.append(
                            ("ARCH-06", f"{wp.relative_to(repo).as_posix()} contains forbidden UI emoji {emo}")
                        )

    # ARCH-07: Version parity across Cargo.toml, web/package.json, cloud-cf/package.json
    root_toml = repo / "Cargo.toml"
    web_pkg = repo / "web" / "package.json"
    cf_pkg = repo / "cloud-cf" / "package.json"
    if root_toml.is_file() and web_pkg.is_file() and cf_pkg.is_file():
        v_cargo = parse_cargo_workspace_version(root_toml.read_text(encoding="utf-8"))
        v_web = json.loads(web_pkg.read_text(encoding="utf-8")).get("version")
        v_cf = json.loads(cf_pkg.read_text(encoding="utf-8")).get("version")
        if not v_cargo or len({v_cargo, v_web, v_cf}) != 1:
            failures.append(
                ("ARCH-07", f"version drift across manifests: Cargo={v_cargo}, web={v_web}, cloud-cf={v_cf}")
            )
    else:
        failures.append(("ARCH-07", "missing root Cargo.toml, web/package.json, or cloud-cf/package.json"))

    # ARCH-08: CI Immutable Verifier Guard gates downstream jobs and pins evals/
    ci_yml = repo / ".github" / "workflows" / "ci.yml"
    if not ci_yml.is_file():
        failures.append(("ARCH-08", "missing .github/workflows/ci.yml"))
    else:
        citxt = ci_yml.read_text(encoding="utf-8")
        if "immutable-verifier-guard:" not in citxt:
            failures.append(("ARCH-08", "ci.yml missing immutable-verifier-guard job"))
        if not re.search(r"web-checks:[\s\S]{0,260}?needs:\s*\[[^\]]*immutable-verifier-guard", citxt):
            failures.append(("ARCH-08", "ci.yml web-checks must declare `needs: [immutable-verifier-guard]`"))
        if "rm -rf evals/ && git checkout" not in citxt:
            failures.append(("ARCH-08", "ci.yml missing `rm -rf evals/ && git checkout ... -- evals/` pin"))

    return failures


def copy_minimal_fixture(src_repo: Path, dst: Path) -> None:
    rel_files = [
        "Cargo.toml",
        "crates/mynote-core/Cargo.toml",
        "crates/mynote-core/src/lib.rs",
        "crates/mynote-core/src/sync.rs",
        "crates/mynote-core/src/materialize.rs",
        "crates/mynote-core/src/keys.rs",
        "crates/mynote-core/src/hlc.rs",
        "crates/mynote-core/src/fractional_index.rs",
        "crates/mynote-cli/src/sync_client.rs",
        "cloud-cf/package.json",
        "cloud-cf/src/index.ts",
        "cloud-cf/src/wire.ts",
        "web/package.json",
        "web/index.html",
        "web/pwa.html",
        "web/public/theme-init.js",
        "web/public-pwa/theme-init.js",
        "web/src/pwa/cloudApi.ts",
        "web/src/i18n.ts",
        ".github/workflows/ci.yml",
    ]
    for rel in rel_files:
        sp = src_repo / rel
        if sp.is_file():
            dp = dst / rel
            dp.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(sp, dp)


def run_selftest(src_repo: Path) -> int:
    """Mutant-first verification: construct 8 broken repo states and prove ARCH-01..ARCH-08 all fail."""
    base_tmp = Path(tempfile.mkdtemp(prefix="mynote-arch-selftest-"))
    try:
        clean = base_tmp / "clean"
        copy_minimal_fixture(src_repo, clean)
        clean_failures = audit_repo(clean)
        if clean_failures:
            print(f"[arch-selftest] FAIL: baseline fixture unexpectedly failed: {clean_failures}", file=sys.stderr)
            return 1

        mutants = [
            (
                "ARCH-01",
                lambda r: (r / "crates/mynote-core/Cargo.toml").write_text(
                    (r / "crates/mynote-core/Cargo.toml")
                    .read_text(encoding="utf-8")
                    .replace("[dependencies]", '[dependencies]\ntokio = "1"', 1),
                    encoding="utf-8",
                ),
            ),
            (
                "ARCH-02",
                lambda r: (r / "crates/mynote-core/src/lib.rs").write_text(
                    "pub fn bad() { let _ = std::time::SystemTime::now(); }\n",
                    encoding="utf-8",
                ),
            ),
            (
                "ARCH-03",
                lambda r: (r / "web/src/i18n.ts").write_text(
                    'import "../../spikes/s0-1";\n',
                    encoding="utf-8",
                ),
            ),
            (
                "ARCH-04",
                lambda r: (r / "cloud-cf/src/bloat.ts").write_text("export const x = 1;\n" * 955, encoding="utf-8"),
            ),
            (
                "ARCH-05",
                lambda r: (r / "web/src/pwa/cloudApi.ts").write_text(
                    'export async function bad(u: string) { return fetch(u); }\n',
                    encoding="utf-8",
                ),
            ),
            (
                "ARCH-06",
                lambda r: (r / "web/index.html").write_text(
                    "<html><body><script>window.evil=1;</script></body></html>",
                    encoding="utf-8",
                ),
            ),
            (
                "ARCH-07",
                lambda r: (r / "web/package.json").write_text('{"name":"x","version":"9.9.9"}\n', encoding="utf-8"),
            ),
            (
                "ARCH-08",
                lambda r: (r / ".github/workflows/ci.yml").write_text(
                    "jobs:\n  web-checks:\n    runs-on: ubuntu-latest\n",
                    encoding="utf-8",
                ),
            ),
        ]

        for idx, (expected_code, mutate) in enumerate(mutants, start=1):
            mdir = base_tmp / f"mutant_{idx}_{expected_code}"
            shutil.copytree(clean, mdir)
            mutate(mdir)
            got = [code for code, _ in audit_repo(mdir)]
            if expected_code not in got:
                print(
                    f"[arch-selftest] FAIL: mutant {expected_code} escaped! got={got}",
                    file=sys.stderr,
                )
                return 1

        print("[arch] selftest: ARCH-01..ARCH-08 planted mutants 100% caught PASS")
        return 0
    finally:
        shutil.rmtree(base_tmp, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Tier 0 static architecture & budget checks.")
    parser.add_argument("--repo", default=str(ROOT), help="Path to repository root")
    parser.add_argument("--selftest", action="store_true", help="Run ARCH-01..ARCH-08 mutant self-tests")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    if args.selftest:
        return run_selftest(repo)

    failures = audit_repo(repo)
    if failures:
        for code, msg in failures:
            print(f"[arch] FAIL {code}: {msg}", file=sys.stderr)
        return 1

    cf_loc = sum(
        len(p.read_text(encoding="utf-8").splitlines())
        for p in (repo / "cloud-cf" / "src").rglob("*")
        if p.is_file() and p.suffix in {".ts", ".mts", ".js", ".mjs"}
    )
    sync_loc = sum(
        len(strip_rust_cfg_test_tail((repo / "crates" / "mynote-core" / "src" / f).read_text(encoding="utf-8")).splitlines())
        for f in SYNC_CORE_FILES
    )
    print(
        f"[arch] PASS ARCH-01..ARCH-08 (cloud-cf/src={cf_loc}/{CLOUD_CF_MAX_LOC} LOC, "
        f"mynote-core sync={sync_loc}/{SYNC_CORE_MAX_LOC} non-test LOC)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
