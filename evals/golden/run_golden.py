#!/usr/bin/env python3
"""
Deterministic CLI Golden Test Harness (`evals/golden/`, scenarios G01-G11 + static checks).

Implements `docs/eval-framework.md` §7 and `docs/interface-contracts.md` §2.6:
- Runs each scenario in an isolated temporary directory (HOME / XDG_* / MYNOTE_DATA_DIR redirected, zero external network).
- Enforces stream discipline (`--json` single-object stdout ending with '\\n'; `--raw` exact bytes).
- Normalizes volatile values (ULIDs, device_id, HLC, *_ms timestamps, duration_ms, error message/hint)
  while verifying semantic invariants and comparing normalized outputs against frozen snapshots in
  `evals/golden/snapshots/G01.json` .. `G11.json`.
- Verifies SQLite DB end-state (zero side effects on refused commands, exact op counts, trash state).
- Runs static checks: L1/L2/L3 `--help` non-empty & `skill/SKILL.md` strictly `< 250 tokens`.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
import pty
import re
import select
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT_DIR = Path(__file__).resolve().parent / "snapshots"

ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
DEVICE_ID_RE = re.compile(r"^dev_[0-9a-zA-Z]+$")
HLC_RE = re.compile(r"^[0-9]{15,16}-[0-9]{4,5}-dev_[0-9a-zA-Z]+$")
MS_KEYS = {
    "duration_ms",
    "created_at_ms",
    "updated_at_ms",
    "deleted_at_ms",
    "shred_not_before_ms",
    "last_run_ms",
    "last_recovery_drill_ms",
    "last_local_backup_ms",
    "next_shred_ms",
    "confirmed_at_ms",
    "executed_at_ms",
    "requested_at_ms",
    "expires_at_ms",
    "drilled_at_ms",
}


def resolve_binary(cli_arg: str | None) -> Path:
    if cli_arg:
        p = Path(cli_arg).resolve()
        if not p.exists():
            raise SystemExit(f"ERROR: mynote binary not found at {p}")
        return p
    env_bin = os.environ.get("MYNOTE_BIN")
    if env_bin:
        p = Path(env_bin).resolve()
        if not p.exists():
            raise SystemExit(f"ERROR: MYNOTE_BIN not found at {p}")
        return p
    for candidate in (
        ROOT / "target" / "debug" / "mynote",
        ROOT / "target" / "release" / "mynote",
    ):
        if candidate.exists():
            return candidate
    raise SystemExit(
        "ERROR: compiled mynote binary not found under target/{debug,release}/mynote; "
        "build with `cargo build --bin mynote` or pass `--bin <path>`."
    )


def isolated_env(sandbox_dir: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    data_dir = sandbox_dir / "data"
    config_dir = sandbox_dir / "config"
    cache_dir = sandbox_dir / "cache"
    home_dir = sandbox_dir / "home"
    for d in (data_dir, config_dir, cache_dir, home_dir):
        d.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": str(home_dir),
        "XDG_DATA_HOME": str(data_dir),
        "XDG_CONFIG_HOME": str(config_dir),
        "XDG_CACHE_HOME": str(cache_dir),
        "MYNOTE_DATA_DIR": str(data_dir / "mynote"),
        "NO_PROXY": "*",
        "no_proxy": "*",
    }
    if extra:
        env.update(extra)
    return env


def run_cli(
    bin_path: Path,
    sandbox_dir: Path,
    args: list[str],
    *,
    stdin_bytes: bytes | None = None,
    extra_env: dict[str, str] | None = None,
    timeout: float = 20.0,
) -> subprocess.CompletedProcess[bytes]:
    env = isolated_env(sandbox_dir, extra_env)
    kwargs: dict[str, Any] = {
        "capture_output": True,
        "env": env,
        "timeout": timeout,
    }
    if stdin_bytes is None:
        kwargs["stdin"] = subprocess.DEVNULL
    else:
        kwargs["input"] = stdin_bytes
    return subprocess.run([str(bin_path), *args], **kwargs)


def run_pty(
    bin_path: Path,
    sandbox_dir: Path,
    args: list[str],
    prompts_and_answers: list[tuple[str, str]],
    *,
    extra_env: dict[str, str] | None = None,
    timeout_s: float = 25.0,
) -> tuple[int, str]:
    env = isolated_env(sandbox_dir, extra_env)
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        [str(bin_path), *args],
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


def parse_json_envelope(proc: subprocess.CompletedProcess[bytes], label: str) -> dict[str, Any]:
    raw = proc.stdout.decode("utf-8")
    assert raw.endswith("\n"), f"{label}: --json stdout must end with '\\n', got {raw!r}"
    trimmed = raw[:-1]
    assert "\n" not in trimmed, f"{label}: --json stdout must be a single line JSON object:\n{raw}"
    obj = json.loads(trimmed)
    assert isinstance(obj, dict), f"{label}: top-level JSON must be an object"
    assert set(obj.keys()) == {"ok", "data", "error", "meta"}, f"{label}: unexpected top-level keys {set(obj.keys())}"
    assert isinstance(obj["ok"], bool), f"{label}: ok must be bool"
    assert isinstance(obj["meta"], dict), f"{label}: meta must be object"
    if obj["ok"]:
        assert obj["error"] is None, f"{label}: ok=true must have error=null"
    else:
        assert obj["data"] is None, f"{label}: ok=false must have data=null"
        err = obj["error"]
        assert isinstance(err, dict), f"{label}: error must be object"
        for k in ("code", "message", "hint", "retryable"):
            assert k in err, f"{label}: error missing key {k}"
        assert isinstance(err["code"], str) and err["code"], f"{label}: invalid error.code"
        assert isinstance(err["message"], str) and err["message"], f"{label}: invalid error.message"
        assert isinstance(err["hint"], str) and err["hint"], f"{label}: invalid error.hint"
        assert isinstance(err["retryable"], bool), f"{label}: invalid error.retryable"
    return obj


def normalize_value(val: Any, key: str | None = None) -> Any:
    if val is None or isinstance(val, bool):
        return val
    if isinstance(val, int):
        if key in MS_KEYS:
            return "<MS>"
        return val
    if isinstance(val, str):
        if key == "position":
            assert val, "position must be non-empty FractionalIndex"
            return "<POSITION>"
        if key in ("message", "hint"):
            return f"<{key.upper()}>"
        if HLC_RE.match(val):
            return "<HLC>"
        if DEVICE_ID_RE.match(val):
            return "<DEVICE_ID>"
        if ULID_RE.match(val):
            return "<ULID>"
        return val
    if isinstance(val, list):
        return [normalize_value(item) for item in val]
    if isinstance(val, dict):
        out: dict[str, Any] = {}
        for k in sorted(val.keys()):
            if k == "error" and isinstance(val[k], dict):
                err = val[k]
                norm_err: dict[str, Any] = {}
                for ek in sorted(err.keys()):
                    if ek == "message":
                        norm_err[ek] = "<MESSAGE>"
                    elif ek == "hint":
                        norm_err[ek] = "<HINT>"
                    else:
                        norm_err[ek] = normalize_value(err[ek], ek)
                out[k] = norm_err
            else:
                out[k] = normalize_value(val[k], k)
        return out
    return val


def db_query_scalar(sandbox_dir: Path, sql: str, params: tuple[Any, ...] = ()) -> Any:
    db_path = sandbox_dir / "data" / "mynote" / "mynote.db"
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        row = conn.execute(sql, params).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


class LoopbackBlindRelay:
    """Minimal zero-dependency loopback blind relay used ONLY for G09 multi-leaf conflict setup."""

    def __init__(self) -> None:
        self.epoch = "00000000-0000-4000-8000-000000000001"
        self.lock = threading.Lock()
        self.ops: list[dict[str, Any]] = []
        self.op_ids: dict[str, int] = {}
        self.key_records: dict[str, dict[str, Any]] = {}
        self.key_material: dict[str, Any] = {}
        self.pairing: dict[str, dict[str, Any]] = {}
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.url: str = ""

    def _keys_digest(self) -> str:
        payload = json.dumps(
            {
                "records": [self.key_records[k] for k in sorted(self.key_records.keys())],
                "material": self.key_material,
            },
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def start(self) -> str:
        relay = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                return

            def _send(self, code: int, obj: dict[str, Any]) -> None:
                body = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read_json(self) -> dict[str, Any]:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length > 0 else b"{}"
                return json.loads(raw.decode("utf-8"))

            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                with relay.lock:
                    if parsed.path == "/v1/keys":
                        self._send(
                            200,
                            {
                                "ok": True,
                                "key_records": list(relay.key_records.values()),
                                "shred_marks": [],
                                "key_material": relay.key_material,
                            },
                        )
                        return
                    if parsed.path == "/v1/sync/pull":
                        qs = parse_qs(parsed.query)
                        since = int(qs.get("since", ["0"])[0])
                        limit = int(qs.get("limit", ["200"])[0])
                        page = [o for o in relay.ops if o["seq"] > since][:limit]
                        head_seq = relay.ops[-1]["seq"] if relay.ops else 0
                        has_more = bool(page and page[-1]["seq"] < head_seq)
                        self._send(
                            200,
                            {
                                "ok": True,
                                "epoch": relay.epoch,
                                "head_seq": head_seq,
                                "has_more": has_more,
                                "keys_digest": relay._keys_digest(),
                                "ops": page,
                            },
                        )
                        return
                    if parsed.path == "/v1/snapshots/state":
                        self._send(404, {"ok": False, "error": {"code": "NOT_FOUND", "message": "none"}})
                        return
                self._send(404, {"ok": False, "error": {"code": "NOT_FOUND", "message": parsed.path}})

            def do_PUT(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 0:
                    self.rfile.read(length)
                self._send(200, {"ok": True})

            def do_POST(self) -> None:
                parsed = urlparse(self.path)
                body = self._read_json()
                now_ms = int(time.time() * 1000)
                with relay.lock:
                    if parsed.path == "/v1/devices/bootstrap":
                        self._send(
                            200,
                            {
                                "ok": True,
                                "device_id": body["device_id"],
                                "scope": "read-write",
                                "epoch": relay.epoch,
                            },
                        )
                        return
                    if parsed.path == "/v1/devices":
                        pair_id = body["pair_id"]
                        relay.pairing[pair_id] = {
                            "kind": "add",
                            "scope": body.get("scope", "read-write"),
                            "ciphertext_b64": body["ciphertext_b64"],
                        }
                        self._send(200, {"ok": True, "expires_at_ms": now_ms + 600_000})
                        return
                    if parsed.path == "/v1/devices/pair-claim":
                        ticket = relay.pairing.pop(body["pair_id"], None)
                        if ticket is None:
                            self._send(404, {"ok": False, "error": {"code": "NOT_FOUND", "message": "missing"}})
                            return
                        self._send(200, {"ok": True, **ticket})
                        return
                    if parsed.path == "/v1/keys":
                        for kr in body.get("key_records", []):
                            kid = kr["key_id"]
                            prev = relay.key_records.get(kid)
                            if prev is None or kr.get("wrap_gen", 1) > prev.get("wrap_gen", 0):
                                relay.key_records[kid] = {
                                    "key_id": kid,
                                    "wrap_gen": kr.get("wrap_gen", 1),
                                    "key_record_b64": kr["key_record_b64"],
                                    "created_at_ms": now_ms,
                                }
                        for mk, mv in body.get("key_material", {}).items():
                            prev = relay.key_material.get(mk)
                            if prev is None or mv.get("gen", 0) > prev.get("gen", 0):
                                relay.key_material[mk] = mv
                        self._send(200, {"ok": True})
                        return
                    if parsed.path == "/v1/sync/push":
                        for kr in body.get("key_records", []):
                            kid = kr["key_id"]
                            prev = relay.key_records.get(kid)
                            if prev is None or kr.get("wrap_gen", 1) > prev.get("wrap_gen", 0):
                                relay.key_records[kid] = {
                                    "key_id": kid,
                                    "wrap_gen": kr.get("wrap_gen", 1),
                                    "key_record_b64": kr["key_record_b64"],
                                    "created_at_ms": now_ms,
                                }
                        acked = []
                        for op in body.get("ops", []):
                            oid = op["op_id"]
                            if oid in relay.op_ids:
                                seq = relay.op_ids[oid]
                            else:
                                seq = len(relay.ops) + 1
                                relay.op_ids[oid] = seq
                                relay.ops.append(
                                    {
                                        "seq": seq,
                                        "op_id": oid,
                                        "key_id": op.get("key_id"),
                                        "device_id": op["device_id"],
                                        "created_at": now_ms,
                                        "envelope_b64": op["envelope_b64"],
                                    }
                                )
                            acked.append({"op_id": oid, "seq": seq})
                        head_seq = relay.ops[-1]["seq"] if relay.ops else 0
                        self._send(
                            200,
                            {
                                "ok": True,
                                "epoch": relay.epoch,
                                "head_seq": head_seq,
                                "acked": acked,
                                "shred_results": [],
                            },
                        )
                        return
                self._send(404, {"ok": False, "error": {"code": "NOT_FOUND", "message": parsed.path}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.url

    def stop(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


# ---------------------------------------------------------------------------
# Static Checks (`docs/eval-framework.md` §7)
# ---------------------------------------------------------------------------

def run_static_checks(bin_path: Path, tmp_root: Path) -> None:
    sandbox = tmp_root / "static"
    top = run_cli(bin_path, sandbox, ["--help"])
    assert top.returncode == 0, f"mynote --help exited {top.returncode}"
    help_text = top.stdout.decode("utf-8")
    lines = help_text.splitlines()
    assert 25 <= len(lines) <= 38, f"L1 --help expected 25..38 lines, got {len(lines)}"
    assert "--help-json" not in help_text, "deferred --help-json must not be advertised"
    assert "\n  clip " not in help_text, "removed clip command must not be advertised"

    subcommands = [
        ["add"],
        ["ls"],
        ["search"],
        ["block"],
        ["block", "get"],
        ["block", "update"],
        ["block", "append"],
        ["block", "move"],
        ["block", "resolve"],
        ["block", "history"],
        ["block", "revert"],
        ["block", "delete"],
        ["buf"],
        ["buf", "ls"],
        ["buf", "create"],
        ["buf", "rename"],
        ["buf", "delete"],
        ["trash"],
        ["trash", "ls"],
        ["trash", "restore"],
        ["trash", "empty"],
        ["trash", "expedite"],
        ["trash", "confirm"],
        ["format"],
        ["import"],
        ["import", "heynote"],
        ["sync"],
        ["sync", "status"],
        ["sync", "push"],
        ["sync", "pull"],
        ["vault"],
        ["vault", "init"],
        ["vault", "lock"],
        ["vault", "unlock"],
        ["vault", "passwd"],
        ["device"],
        ["device", "bootstrap"],
        ["device", "add"],
        ["device", "refresh"],
        ["device", "claim"],
        ["device", "ls"],
        ["device", "revoke"],
        ["keyring"],
        ["keyring", "rotate"],
        ["keyring", "unlock"],
        ["recovery"],
        ["recovery", "show"],
        ["recovery", "drill"],
        ["restore"],
        ["daemon"],
        ["open"],
        ["help"],
    ]
    for sub in subcommands:
        out = run_cli(bin_path, sandbox, [*sub, "--help"])
        assert out.returncode == 0, f"'mynote {' '.join(sub)} --help' failed ({out.returncode})"
        assert out.stdout.decode("utf-8").strip(), f"empty --help for {' '.join(sub)}"

    for topic in ("agent", "formatting", "conflict", "locking", "upgrade"):
        out = run_cli(bin_path, sandbox, ["help", topic])
        assert out.returncode == 0, f"'mynote help {topic}' failed ({out.returncode})"
        assert out.stdout.decode("utf-8").strip(), f"empty help topic {topic}"

    skill_path = ROOT / "skill" / "SKILL.md"
    assert skill_path.exists(), f"missing {skill_path}"
    skill_text = skill_path.read_text(encoding="utf-8")
    words = len(skill_text.split())
    bpe_est = math.ceil(words * 1.35)
    char_est = math.ceil(len(skill_text.encode("utf-8")) / 4)
    assert bpe_est < 250 and char_est < 250, (
        f"skill/SKILL.md exceeds <250 token budget: words={words}, bpe_est={bpe_est}, bytes/4={char_est}"
    )


# ---------------------------------------------------------------------------
# Scenarios G01 - G11
# ---------------------------------------------------------------------------

def scenario_g01(bin_path: Path, sandbox: Path) -> dict[str, Any]:
    p1 = run_cli(
        bin_path,
        sandbox,
        ["add", "hello from arg", "--buf", "scratch", "--idempotency-key", "g01-key-1", "--json"],
    )
    assert p1.returncode == 0
    j1 = parse_json_envelope(p1, "G01.add_arg")
    assert j1["ok"] is True
    assert ULID_RE.match(j1["data"]["block_id"])
    assert ULID_RE.match(j1["data"]["op_id"])

    p1_dup = run_cli(
        bin_path,
        sandbox,
        ["add", "hello from arg", "--buf", "scratch", "--idempotency-key", "g01-key-1", "--json"],
    )
    assert p1_dup.returncode == 0
    j1_dup = parse_json_envelope(p1_dup, "G01.add_idempotent_replay")
    assert j1_dup["data"]["block_id"] == j1["data"]["block_id"]
    assert j1_dup["data"]["op_id"] == j1["data"]["op_id"]
    assert j1_dup["data"]["idempotent_replay"] is True
    assert j1_dup["meta"]["local_op_count_pending"] == j1["meta"]["local_op_count_pending"]

    p2 = run_cli(
        bin_path,
        sandbox,
        ["add", "--buf", "scratch", "--json"],
        stdin_bytes=b'{"golden":true,"n":1}',
    )
    assert p2.returncode == 0
    j2 = parse_json_envelope(p2, "G01.add_stdin")
    assert j2["data"]["block_id"] != j1["data"]["block_id"]
    assert j2["meta"]["local_op_count_pending"] == j1["meta"]["local_op_count_pending"] + 1
    assert db_query_scalar(sandbox, "SELECT COUNT(*) FROM blocks WHERE state = 'ACTIVE'") == 2

    return {
        "scenario": "G01",
        "steps": [
            {"name": "add_arg", "exit_code": p1.returncode, "json": normalize_value(j1)},
            {"name": "add_idempotent_replay", "exit_code": p1_dup.returncode, "json": normalize_value(j1_dup)},
            {"name": "add_stdin", "exit_code": p2.returncode, "json": normalize_value(j2)},
        ],
        "db_active_blocks": 2,
    }


def scenario_g02(bin_path: Path, sandbox: Path) -> dict[str, Any]:
    p_plain = run_cli(bin_path, sandbox, ["add", "searchable alpha token", "--lang", "text", "--json"])
    assert p_plain.returncode == 0
    p_json = run_cli(bin_path, sandbox, ["add", '{"alpha": 1}', "--json"])
    assert p_json.returncode == 0
    p_secret = run_cli(bin_path, sandbox, ["add", "LOCKED_G02_CANARY_ALPHA", "--lang", "text", "--json"])
    assert p_secret.returncode == 0
    secret_id = parse_json_envelope(p_secret, "G02.add_secret")["data"]["block_id"]

    # Lock the third block via real PTY Vault so search must never return its plaintext
    rc, _ = run_pty(
        bin_path,
        sandbox,
        ["vault", "init"],
        [("Set new Vault passphrase:", "GoldenPass#2026"), ("Confirm Vault passphrase:", "GoldenPass#2026")],
    )
    assert rc == 0, f"G02 vault init failed: {rc}"
    rc, _ = run_pty(
        bin_path,
        sandbox,
        ["vault", "lock", secret_id, "--hint", "g02 secret"],
        [("Enter Vault passphrase:", "GoldenPass#2026")],
    )
    assert rc == 0, f"G02 vault lock failed: {rc}"

    p_ls = run_cli(bin_path, sandbox, ["ls", "--limit", "20", "--json"])
    assert p_ls.returncode == 0
    j_ls = parse_json_envelope(p_ls, "G02.ls")
    assert "LOCKED_G02_CANARY_ALPHA" not in p_ls.stdout.decode("utf-8")
    positions = [row["position"] for row in j_ls["data"]]
    assert positions == sorted(positions) and len(set(positions)) == 3, (
        f"G02 ls must be strictly sorted by FractionalIndex position: {positions}"
    )

    p_search_alpha = run_cli(bin_path, sandbox, ["search", "alpha", "--json"])
    assert p_search_alpha.returncode == 0
    j_search_alpha = parse_json_envelope(p_search_alpha, "G02.search_alpha")
    assert "LOCKED_G02_CANARY_ALPHA" not in p_search_alpha.stdout.decode("utf-8")

    p_search_secret = run_cli(bin_path, sandbox, ["search", "LOCKED_G02_CANARY_ALPHA", "--json"])
    assert p_search_secret.returncode == 0
    j_search_secret = parse_json_envelope(p_search_secret, "G02.search_locked_canary")
    assert j_search_secret["data"] == []

    p_jsonl = run_cli(bin_path, sandbox, ["ls", "--jsonl"])
    assert p_jsonl.returncode == 0
    jsonl_rows = [json.loads(line) for line in p_jsonl.stdout.decode("utf-8").splitlines()]
    assert len(jsonl_rows) == 3

    return {
        "scenario": "G02",
        "steps": [
            {"name": "ls_json", "exit_code": p_ls.returncode, "json": normalize_value(j_ls)},
            {"name": "ls_jsonl", "exit_code": p_jsonl.returncode, "rows": normalize_value(jsonl_rows)},
            {"name": "search_alpha", "exit_code": p_search_alpha.returncode, "json": normalize_value(j_search_alpha)},
            {
                "name": "search_locked_canary",
                "exit_code": p_search_secret.returncode,
                "json": normalize_value(j_search_secret),
            },
        ],
    }


def scenario_g03(bin_path: Path, sandbox: Path) -> dict[str, Any]:
    payload = '{"k":"v","emoji":"🚀","lines":"a\\nb"}'
    p_add = run_cli(bin_path, sandbox, ["add", "--buf", "scratch", "--json"], stdin_bytes=payload.encode("utf-8"))
    assert p_add.returncode == 0
    blk_id = parse_json_envelope(p_add, "G03.add")["data"]["block_id"]

    p_raw = run_cli(bin_path, sandbox, ["block", "get", blk_id, "--raw"])
    assert p_raw.returncode == 0
    assert p_raw.stdout == payload.encode("utf-8"), f"G03 raw mismatch: {p_raw.stdout!r}"
    assert p_raw.stderr == b""

    p_json = run_cli(bin_path, sandbox, ["block", "get", blk_id, "--json"])
    assert p_json.returncode == 0
    j_get = parse_json_envelope(p_json, "G03.get_json")

    return {
        "scenario": "G03",
        "steps": [
            {
                "name": "get_raw",
                "exit_code": p_raw.returncode,
                "exact_bytes_utf8": p_raw.stdout.decode("utf-8"),
                "stderr_empty": p_raw.stderr == b"",
            },
            {"name": "get_json", "exit_code": p_json.returncode, "json": normalize_value(j_get)},
        ],
    }


def scenario_g04(bin_path: Path, sandbox: Path) -> dict[str, Any]:
    p_add = run_cli(bin_path, sandbox, ["add", "original precious note", "--json"])
    assert p_add.returncode == 0
    j_add = parse_json_envelope(p_add, "G04.add")
    blk_id = j_add["data"]["block_id"]
    head1 = j_add["data"]["op_id"]
    ops_before = db_query_scalar(sandbox, "SELECT COUNT(*) FROM sync_ops")

    p_stale = run_cli(
        bin_path,
        sandbox,
        [
            "block",
            "update",
            blk_id,
            "clobber attempt",
            "--expected-head",
            "01J00000000000000000000000",
            "--json",
        ],
    )
    assert p_stale.returncode == 4
    j_stale = parse_json_envelope(p_stale, "G04.stale_update")
    assert j_stale["error"]["code"] == "HEAD_MISMATCH"
    assert j_stale["error"]["details"]["actual_heads"] == [head1]

    ops_after = db_query_scalar(sandbox, "SELECT COUNT(*) FROM sync_ops")
    assert ops_after == ops_before, "HEAD_MISMATCH must not write any op"
    p_raw = run_cli(bin_path, sandbox, ["block", "get", blk_id, "--raw"])
    assert p_raw.stdout == b"original precious note"

    return {
        "scenario": "G04",
        "steps": [
            {"name": "stale_update", "exit_code": p_stale.returncode, "json": normalize_value(j_stale)},
            {"name": "content_unchanged", "raw": p_raw.stdout.decode("utf-8"), "ops_delta": ops_after - ops_before},
        ],
    }


def scenario_g05(bin_path: Path, sandbox: Path) -> dict[str, Any]:
    p_add = run_cli(bin_path, sandbox, ["add", "non-empty content", "--json"])
    assert p_add.returncode == 0
    j_add = parse_json_envelope(p_add, "G05.add")
    blk_id = j_add["data"]["block_id"]
    head1 = j_add["data"]["op_id"]
    ops_before = db_query_scalar(sandbox, "SELECT COUNT(*) FROM sync_ops")

    p_empty = run_cli(
        bin_path,
        sandbox,
        ["block", "update", blk_id, "--expected-head", head1, "--json"],
        stdin_bytes=b"",
    )
    assert p_empty.returncode == 2
    j_empty = parse_json_envelope(p_empty, "G05.empty_stdin_refused")
    assert j_empty["error"]["code"] == "EMPTY_STDIN_REFUSED"
    ops_after = db_query_scalar(sandbox, "SELECT COUNT(*) FROM sync_ops")
    assert ops_after == ops_before
    assert run_cli(bin_path, sandbox, ["block", "get", blk_id, "--raw"]).stdout == b"non-empty content"

    p_allow = run_cli(
        bin_path,
        sandbox,
        ["block", "update", blk_id, "--expected-head", head1, "--allow-empty", "--json"],
        stdin_bytes=b"",
    )
    assert p_allow.returncode == 0
    j_allow = parse_json_envelope(p_allow, "G05.allow_empty")
    assert run_cli(bin_path, sandbox, ["block", "get", blk_id, "--raw"]).stdout == b""

    return {
        "scenario": "G05",
        "steps": [
            {"name": "empty_stdin_refused", "exit_code": p_empty.returncode, "json": normalize_value(j_empty)},
            {"name": "ops_delta_on_refusal", "ops_delta": ops_after - ops_before},
            {"name": "allow_empty_update", "exit_code": p_allow.returncode, "json": normalize_value(j_allow)},
        ],
    }


def scenario_g06(bin_path: Path, sandbox: Path) -> dict[str, Any]:
    # Seed store once so we measure exact +1 op delta on offline add without counting initial buffer creation
    p_seed = run_cli(bin_path, sandbox, ["add", "seed", "--json"])
    assert p_seed.returncode == 0
    ops_before = db_query_scalar(sandbox, "SELECT COUNT(*) FROM sync_ops")
    pending_before = parse_json_envelope(p_seed, "G06.seed")["meta"]["local_op_count_pending"]

    # Bind a local TCP trap socket as HTTP_PROXY/HTTPS_PROXY to assert zero outbound attempts
    trap = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    trap.bind(("127.0.0.1", 0))
    trap.listen(5)
    trap_port = trap.getsockname()[1]
    trap_hits = 0

    def watch_trap() -> None:
        nonlocal trap_hits
        trap.settimeout(0.2)
        try:
            while True:
                try:
                    conn, _ = trap.accept()
                    trap_hits += 1
                    conn.close()
                except TimeoutError:
                    if stop_evt.is_set():
                        break
        except OSError:
            pass

    stop_evt = threading.Event()
    t = threading.Thread(target=watch_trap, daemon=True)
    t.start()
    try:
        proxy_url = f"http://127.0.0.1:{trap_port}"
        p_add = run_cli(
            bin_path,
            sandbox,
            ["add", "offline note without daemon", "--json"],
            extra_env={"HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url, "NO_PROXY": "", "no_proxy": ""},
        )
    finally:
        stop_evt.set()
        t.join(timeout=2)
        trap.close()

    assert p_add.returncode == 0
    j_add = parse_json_envelope(p_add, "G06.offline_add")
    ops_after = db_query_scalar(sandbox, "SELECT COUNT(*) FROM sync_ops")
    assert j_add["meta"]["sync_state"] == "pending_offline"
    assert j_add["meta"]["local_op_count_pending"] == pending_before + 1
    assert ops_after == ops_before + 1
    assert trap_hits == 0, f"G06 offline add must not issue any outbound network connections, saw {trap_hits}"

    return {
        "scenario": "G06",
        "steps": [
            {"name": "offline_add", "exit_code": p_add.returncode, "json": normalize_value(j_add)},
            {"name": "invariants", "ops_delta": ops_after - ops_before, "outbound_proxy_hits": trap_hits},
        ],
    }


def scenario_g07(bin_path: Path, sandbox: Path) -> dict[str, Any]:
    p_add = run_cli(bin_path, sandbox, ["add", "pending local note", "--json"])
    assert p_add.returncode == 0

    p_push = run_cli(bin_path, sandbox, ["sync", "push", "--json"])
    assert p_push.returncode == 6
    j_push = parse_json_envelope(p_push, "G07.sync_push")
    assert j_push["error"]["code"] == "SYNC_OFFLINE"
    assert j_push["error"]["retryable"] is True

    p_pull = run_cli(bin_path, sandbox, ["sync", "pull", "--json"])
    assert p_pull.returncode == 6
    j_pull = parse_json_envelope(p_pull, "G07.sync_pull")
    assert j_pull["error"]["code"] == "SYNC_OFFLINE"
    assert j_pull["error"]["retryable"] is True

    p_status = run_cli(bin_path, sandbox, ["sync", "status", "--json"])
    assert p_status.returncode == 0
    j_status = parse_json_envelope(p_status, "G07.sync_status")

    return {
        "scenario": "G07",
        "steps": [
            {"name": "sync_push_offline", "exit_code": p_push.returncode, "json": normalize_value(j_push)},
            {"name": "sync_pull_offline", "exit_code": p_pull.returncode, "json": normalize_value(j_pull)},
            {"name": "sync_status", "exit_code": p_status.returncode, "json": normalize_value(j_status)},
        ],
    }


def scenario_g08(bin_path: Path, sandbox: Path) -> dict[str, Any]:
    p_add = run_cli(bin_path, sandbox, ["add", "trashable note", "--json"])
    assert p_add.returncode == 0
    j_add = parse_json_envelope(p_add, "G08.add")
    blk_id = j_add["data"]["block_id"]
    head = j_add["data"]["op_id"]

    p_del = run_cli(bin_path, sandbox, ["block", "delete", blk_id, "--expected-head", head, "--json"])
    assert p_del.returncode == 0
    j_del = parse_json_envelope(p_del, "G08.delete")
    assert j_del["data"]["in_trash"] is True
    assert j_del["data"]["shred_not_before_ms"] is None

    p_get_trashed = run_cli(bin_path, sandbox, ["block", "get", blk_id, "--json"])
    assert p_get_trashed.returncode == 3
    j_get_trashed = parse_json_envelope(p_get_trashed, "G08.get_in_trash")
    assert j_get_trashed["error"]["code"] == "IN_TRASH"

    p_trash_before = run_cli(bin_path, sandbox, ["trash", "ls", "--json"])
    assert p_trash_before.returncode == 0
    j_trash_before = parse_json_envelope(p_trash_before, "G08.trash_ls")
    assert len(j_trash_before["data"]) == 1

    refused_steps = []
    for action in ("empty", "expedite", "confirm"):
        p_ref = run_cli(bin_path, sandbox, ["trash", action, "--json"])
        assert p_ref.returncode == 2
        j_ref = parse_json_envelope(p_ref, f"G08.trash_{action}")
        assert j_ref["error"]["code"] == "UI_CONFIRMATION_REQUIRED"
        refused_steps.append(
            {"name": f"trash_{action}_refused", "exit_code": p_ref.returncode, "json": normalize_value(j_ref)}
        )

    # Verify TTY also refuses trash empty with exit 2 (UI_CONFIRMATION_REQUIRED)
    rc_tty, tty_out = run_pty(bin_path, sandbox, ["trash", "empty", "--json"], [])
    assert rc_tty == 2, f"G08 PTY trash empty must exit 2, got {rc_tty}: {tty_out}"

    p_trash_after = run_cli(bin_path, sandbox, ["trash", "ls", "--json"])
    assert len(parse_json_envelope(p_trash_after, "G08.trash_ls_after")["data"]) == 1

    p_restore = run_cli(bin_path, sandbox, ["trash", "restore", blk_id, "--json"])
    assert p_restore.returncode == 0
    j_restore = parse_json_envelope(p_restore, "G08.trash_restore")
    assert run_cli(bin_path, sandbox, ["block", "get", blk_id, "--raw"]).stdout == b"trashable note"

    return {
        "scenario": "G08",
        "steps": [
            {"name": "block_delete", "exit_code": p_del.returncode, "json": normalize_value(j_del)},
            {"name": "get_in_trash", "exit_code": p_get_trashed.returncode, "json": normalize_value(j_get_trashed)},
            {"name": "trash_ls", "exit_code": p_trash_before.returncode, "json": normalize_value(j_trash_before)},
            *refused_steps,
            {"name": "trash_empty_tty_exit_code", "exit_code": rc_tty},
            {"name": "trash_restore", "exit_code": p_restore.returncode, "json": normalize_value(j_restore)},
        ],
    }


def scenario_g09(bin_path: Path, sandbox: Path) -> dict[str, Any]:
    dev_a = sandbox / "dev_a"
    dev_b = sandbox / "dev_b"
    relay = LoopbackBlindRelay()
    relay_url = relay.start()
    try:
        # 1. Bootstrap Device A against local loopback relay, add base block, push
        rc, out = run_pty(
            bin_path,
            dev_a,
            ["device", "bootstrap", "--url", relay_url],
            [],
            extra_env={"MYNOTE_BOOTSTRAP_TOKEN": "golden-bootstrap-secret"},
        )
        assert rc == 0, f"G09 bootstrap dev_a failed ({rc}): {out}"

        p_base = run_cli(bin_path, dev_a, ["add", "base version", "--lang", "text", "--json"])
        assert p_base.returncode == 0
        j_base = parse_json_envelope(p_base, "G09.add_base")
        blk_id = j_base["data"]["block_id"]
        base_op = j_base["data"]["op_id"]
        p_push_a1 = run_cli(bin_path, dev_a, ["sync", "push", "--json"])
        assert p_push_a1.returncode == 0, f"G09 push a1 failed: {p_push_a1.stdout!r} {p_push_a1.stderr!r}"

        # 2. Pair Device B via real `device add` + `device claim`
        rc, out_add = run_pty(bin_path, dev_a, ["device", "add", "--name", "dev-b", "--scope", "read-write"], [])
        assert rc == 0, f"G09 device add failed ({rc}): {out_add}"
        m = re.search(r"(mynote-pair:v1:[A-Za-z0-9_-]+)", out_add)
        assert m, f"G09 failed to extract pairing code from:\n{out_add}"
        pair_code = m.group(1)

        rc, out_claim = run_pty(
            bin_path,
            dev_b,
            ["device", "claim"],
            [("Paste pairing/refresh code", pair_code)],
        )
        assert rc == 0, f"G09 device claim failed ({rc}): {out_claim}"
        assert run_cli(bin_path, dev_b, ["block", "get", blk_id, "--raw"]).stdout == b"base version"

        # 3. Concurrent edits on Device A (earlier HLC) and Device B (later HLC -> deterministic display version)
        p_upd_a = run_cli(
            bin_path,
            dev_a,
            ["block", "update", blk_id, "mac edit", "--expected-head", base_op, "--json"],
        )
        assert p_upd_a.returncode == 0
        time.sleep(0.02)
        p_upd_b = run_cli(
            bin_path,
            dev_b,
            ["block", "update", blk_id, "omarchy concurrent edit", "--expected-head", base_op, "--json"],
        )
        assert p_upd_b.returncode == 0

        # 4. Sync both pushes and pull onto Device A -> genuine 2-leaf conflict
        p_push_a1 = run_cli(bin_path, dev_a, ["sync", "push", "--json"])
        assert p_push_a1.returncode == 0, f"G09 push a1 failed: {p_push_a1.stdout!r} {p_push_a1.stderr!r}"
        assert run_cli(bin_path, dev_b, ["sync", "push", "--json"]).returncode == 0
        assert run_cli(bin_path, dev_a, ["sync", "pull", "--json"]).returncode == 0
    finally:
        relay.stop()

    # 5. Offline golden assertions on Device A's 2-leaf conflict block
    p_get = run_cli(bin_path, dev_a, ["block", "get", blk_id, "--json"])
    assert p_get.returncode == 0
    j_get = parse_json_envelope(p_get, "G09.get_conflict")
    assert j_get["data"]["has_conflict"] is True
    heads = j_get["data"]["head_op_ids"]
    assert len(heads) == 2
    assert len(j_get["data"]["versions"]) == 2
    assert j_get["data"]["versions"][0]["is_display"] is True
    assert j_get["data"]["versions"][0]["op_id"] == j_get["data"]["display_op_id"]

    p_raw = run_cli(bin_path, dev_a, ["block", "get", blk_id, "--raw"])
    assert p_raw.returncode == 0
    assert p_raw.stdout == b"omarchy concurrent edit"
    assert "block has 2 versions" in p_raw.stderr.decode("utf-8")

    p_append = run_cli(bin_path, dev_a, ["block", "append", blk_id, "tail", "--json"])
    assert p_append.returncode == 4
    j_append = parse_json_envelope(p_append, "G09.append_conflict")
    assert j_append["error"]["code"] == "CONFLICT_PRESENT"

    p_merge = run_cli(
        bin_path,
        dev_a,
        [
            "block",
            "update",
            blk_id,
            "merged final content",
            "--expected-head",
            heads[0],
            "--expected-head",
            heads[1],
            "--json",
        ],
    )
    assert p_merge.returncode == 0
    j_merge = parse_json_envelope(p_merge, "G09.merge_update")
    assert len(j_merge["data"]["head_op_ids"]) == 1

    p_after = run_cli(bin_path, dev_a, ["block", "get", blk_id, "--json"])
    assert p_after.returncode == 0
    j_after = parse_json_envelope(p_after, "G09.get_after_merge")
    assert j_after["data"]["has_conflict"] is False
    assert j_after["data"]["content"] == "merged final content"
    assert len(j_after["data"]["head_op_ids"]) == 1

    return {
        "scenario": "G09",
        "steps": [
            {"name": "get_conflict", "exit_code": p_get.returncode, "json": normalize_value(j_get)},
            {
                "name": "get_conflict_raw",
                "exit_code": p_raw.returncode,
                "raw": p_raw.stdout.decode("utf-8"),
                "stderr_mentions_2_versions": "block has 2 versions" in p_raw.stderr.decode("utf-8"),
            },
            {"name": "append_conflict", "exit_code": p_append.returncode, "json": normalize_value(j_append)},
            {"name": "merge_update", "exit_code": p_merge.returncode, "json": normalize_value(j_merge)},
            {"name": "get_after_merge", "exit_code": p_after.returncode, "json": normalize_value(j_after)},
        ],
    }


def scenario_g10(bin_path: Path, sandbox: Path) -> dict[str, Any]:
    canary = "TOP_SECRET_G10_CANARY_98765"
    p_add = run_cli(bin_path, sandbox, ["add", canary, "--lang", "text", "--json"])
    assert p_add.returncode == 0
    blk_id = parse_json_envelope(p_add, "G10.add")["data"]["block_id"]

    rc, _ = run_pty(
        bin_path,
        sandbox,
        ["vault", "init"],
        [("Set new Vault passphrase:", "VaultPass#G10"), ("Confirm Vault passphrase:", "VaultPass#G10")],
    )
    assert rc == 0, f"G10 vault init failed: {rc}"

    rc, _ = run_pty(
        bin_path,
        sandbox,
        ["vault", "lock", blk_id, "--hint", "api key"],
        [("Enter Vault passphrase:", "VaultPass#G10")],
    )
    assert rc == 0, f"G10 vault lock failed: {rc}"

    p_raw = run_cli(bin_path, sandbox, ["block", "get", blk_id, "--raw"])
    assert p_raw.returncode == 5
    assert p_raw.stdout == b""
    assert canary not in p_raw.stderr.decode("utf-8", errors="replace")

    p_dec = run_cli(bin_path, sandbox, ["block", "get", blk_id, "--decrypt", "--json"])
    assert p_dec.returncode == 5
    j_dec = parse_json_envelope(p_dec, "G10.decrypt_non_tty")
    assert j_dec["error"]["code"] == "BLOCK_LOCKED"
    assert canary not in p_dec.stdout.decode("utf-8")
    assert canary not in p_dec.stderr.decode("utf-8", errors="replace")

    p_meta = run_cli(bin_path, sandbox, ["block", "get", blk_id, "--json"])
    assert p_meta.returncode == 0
    j_meta = parse_json_envelope(p_meta, "G10.get_meta")
    assert j_meta["data"]["is_locked"] is True
    assert j_meta["data"]["redacted"] is True
    assert j_meta["data"]["content"] is None
    assert canary not in p_meta.stdout.decode("utf-8")

    p_search = run_cli(bin_path, sandbox, ["search", canary, "--json"])
    assert p_search.returncode == 0
    j_search = parse_json_envelope(p_search, "G10.search_canary")
    assert j_search["data"] == []

    return {
        "scenario": "G10",
        "steps": [
            {
                "name": "get_raw_locked",
                "exit_code": p_raw.returncode,
                "stdout_empty": p_raw.stdout == b"",
                "zero_canary": canary not in p_raw.stderr.decode("utf-8", errors="replace"),
            },
            {"name": "get_decrypt_non_tty", "exit_code": p_dec.returncode, "json": normalize_value(j_dec)},
            {"name": "get_meta_redacted", "exit_code": p_meta.returncode, "json": normalize_value(j_meta)},
            {"name": "search_canary", "exit_code": p_search.returncode, "json": normalize_value(j_search)},
        ],
    }


def scenario_g11(bin_path: Path, sandbox: Path) -> dict[str, Any]:
    p_stdin = run_cli(
        bin_path,
        sandbox,
        ["format", "--lang", "json", "--json"],
        stdin_bytes=b'{"unterminated": [1, 2',
    )
    assert p_stdin.returncode == 7
    j_stdin = parse_json_envelope(p_stdin, "G11.format_stdin_broken")
    assert j_stdin["error"]["code"] == "FORMAT_SYNTAX_ERROR"

    p_add = run_cli(bin_path, sandbox, ["add", '{"broken": ', "--lang", "json", "--json"])
    assert p_add.returncode == 0
    j_add = parse_json_envelope(p_add, "G11.add_broken")
    blk_id = j_add["data"]["block_id"]
    head = j_add["data"]["op_id"]
    ops_before = db_query_scalar(sandbox, "SELECT COUNT(*) FROM sync_ops")

    p_inplace = run_cli(
        bin_path,
        sandbox,
        ["format", blk_id, "--expected-head", head, "--json"],
    )
    assert p_inplace.returncode == 7
    j_inplace = parse_json_envelope(p_inplace, "G11.format_inplace_broken")
    assert j_inplace["error"]["code"] == "FORMAT_SYNTAX_ERROR"

    ops_after = db_query_scalar(sandbox, "SELECT COUNT(*) FROM sync_ops")
    assert ops_after == ops_before
    p_check = run_cli(bin_path, sandbox, ["block", "get", blk_id, "--json"])
    j_check = parse_json_envelope(p_check, "G11.check_unchanged")
    assert j_check["data"]["head_op_ids"] == [head]
    assert j_check["data"]["content"] == '{"broken": '

    return {
        "scenario": "G11",
        "steps": [
            {"name": "format_stdin_broken", "exit_code": p_stdin.returncode, "json": normalize_value(j_stdin)},
            {"name": "format_inplace_broken", "exit_code": p_inplace.returncode, "json": normalize_value(j_inplace)},
            {"name": "block_unchanged", "ops_delta": ops_after - ops_before, "json": normalize_value(j_check)},
        ],
    }


SCENARIOS = [
    ("G01", scenario_g01),
    ("G02", scenario_g02),
    ("G03", scenario_g03),
    ("G04", scenario_g04),
    ("G05", scenario_g05),
    ("G06", scenario_g06),
    ("G07", scenario_g07),
    ("G08", scenario_g08),
    ("G09", scenario_g09),
    ("G10", scenario_g10),
    ("G11", scenario_g11),
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run mynote CLI golden tests (G01-G11 + static checks).")
    parser.add_argument("--bin", dest="bin_path", help="Path to compiled mynote binary")
    parser.add_argument(
        "--write-snapshots",
        action="store_true",
        help="Write/overwrite frozen snapshots under evals/golden/snapshots/ (for [eval-only] PR updates only)",
    )
    args = parser.parse_args()

    bin_path = resolve_binary(args.bin_path)
    tmp_root = Path(tempfile.mkdtemp(prefix="mynote-golden-"))
    failures: list[str] = []
    try:
        run_static_checks(bin_path, tmp_root)
        print("[golden] static: --help (L1/L2/L3) & skill/SKILL.md (<250 tokens) PASS")

        SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)

        def run_one(item: tuple[str, Any]) -> tuple[str, dict[str, Any]]:
            name, fn = item
            sandbox = tmp_root / name
            sandbox.mkdir(parents=True, exist_ok=True)
            return name, fn(bin_path, sandbox)

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(run_one, SCENARIOS))

        for name, actual in results:
            snap_file = SNAPSHOT_DIR / f"{name}.json"
            rendered = json.dumps(actual, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
            if args.write_snapshots:
                snap_file.write_text(rendered, encoding="utf-8")
                print(f"[golden] {name}: WROTE snapshot {snap_file.relative_to(ROOT)}")
            else:
                if not snap_file.exists():
                    failures.append(f"{name}: missing snapshot {snap_file}")
                    continue
                expected_text = snap_file.read_text(encoding="utf-8")
                if rendered != expected_text:
                    failures.append(
                        f"{name}: normalized output drifted from {snap_file.relative_to(ROOT)}\n"
                        f"--- expected ---\n{expected_text}\n--- actual ---\n{rendered}"
                    )
                else:
                    print(f"[golden] {name}: PASS")
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    if failures:
        for f in failures:
            print(f"[golden] FAIL {f}", file=sys.stderr)
        return 1
    print(f"[golden] ALL {len(SCENARIOS)} SCENARIOS + STATIC CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
