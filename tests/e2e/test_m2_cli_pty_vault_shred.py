#!/usr/bin/env python3
"""
M2 CLI PTY (/dev/tty) Vault & Shred Guard E2E test.

Verifies against the real compiled `mynote` binary:
1. First-run `recovery show` inside a real PTY prints 24 BIP39 recovery words.
2. `vault init` reads passphrase twice from `/dev/tty` with echo suppressed.
3. `vault lock <id> --hint ...` encrypts a Tier 1 block into Tier 2 (`MNB1` + `MNW1`).
4. Non-TTY `block get <id> --decrypt` fails fast with exit 5 (`BLOCK_LOCKED`) & ZERO plaintext.
5. Real PTY `block get <id> --decrypt --raw` outputs the exact secret.
6. Real PTY `vault passwd` rotates passphrase (old fails, new succeeds).
7. Real PTY `vault passwd --recover` recovers VKEK with the 24 recovery words and sets a new passphrase.
8. Real PTY `vault unlock <id> --shred-old-key` downgrades back to Tier 1.
9. `trash empty`, `trash expedite`, `trash confirm` ALL fail with exit 2 (`UI_CONFIRMATION_REQUIRED`) EVEN in a real TTY.
"""

import json
import os
import pty
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "target" / "debug" / "mynote"


def run_cli(data_dir: Path, args: list[str], stdin_text: str | None = None, env_extra: dict[str, str] | None = None):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    kwargs = {
        "text": True,
        "capture_output": True,
        "env": env,
        "timeout": 30,
    }
    if stdin_text is None:
        kwargs["stdin"] = subprocess.DEVNULL
    else:
        kwargs["input"] = stdin_text
    proc = subprocess.run([str(BIN), "--data-dir", str(data_dir), *args], **kwargs)
    return proc


def run_pty_cmd(data_dir: Path, args: list[str], prompts_and_answers: list[tuple[str, str]], timeout_s: float = 25.0):
    """Spawn `mynote` inside a real Unix PTY (`setsid` + controlling `/dev/tty`) and answer prompts."""
    master_fd, slave_fd = pty.openpty()
    cmd = [str(BIN), "--data-dir", str(data_dir), *args]
    proc = subprocess.Popen(
        cmd,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        start_new_session=True,
        close_fds=True,
        env=os.environ.copy(),
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
                # drain remaining output
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
    text = buf.decode("utf-8", errors="replace")
    return rc, text


def main():
    assert BIN.exists(), f"mynote binary missing at {BIN}; run `cargo build --bin mynote` first"
    tmp = Path(tempfile.mkdtemp(prefix="mynote-m2-cli-pty-"))
    try:
        # 1. First-run `recovery show` in real PTY -> capture 24 BIP39 recovery words
        rc, out = run_pty_cmd(tmp, ["recovery", "show"], [])
        assert rc == 0, f"recovery show failed ({rc}): {out}"
        m = re.search(r"record offline now\):\s*\r?\n\s*([a-z ]+)", out)
        assert m, f"could not parse 24 recovery words from:\n{out}"
        words = " ".join(m.group(1).strip().split())
        assert len(words.split()) == 24, f"expected 24 words, got {len(words.split())}: {words}"
        print("[cli-pty] 1. Captured 24-word recovery bundle OK")

        # 2. Initialize Tier 2 Vault in real PTY (verify passphrase echo is suppressed!)
        pass1 = "VaultPass#One123"
        rc, out = run_pty_cmd(
            tmp,
            ["vault", "init"],
            [("Set new Vault passphrase:", pass1), ("Confirm Vault passphrase:", pass1)],
        )
        assert rc == 0, f"vault init failed ({rc}): {out}"
        assert pass1 not in out, f"SECURITY VIOLATION: passphrase echoed in PTY output:\n{out}"
        print("[cli-pty] 2. vault init with echo-suppressed /dev/tty OK")

        # 3. Add a Tier 1 block, then lock it into Tier 2 Vault
        secret = "CLI_PTY_TIER2_SECRET_CANARY_4242"
        add = run_cli(tmp, ["--json", "add", secret, "--lang", "text"])
        assert add.returncode == 0, f"add failed: {add.stderr}"
        blk_id = json.loads(add.stdout)["data"]["block_id"]

        rc, out = run_pty_cmd(
            tmp,
            ["vault", "lock", blk_id, "--hint", "Prod DB Password"],
            [("Enter Vault passphrase:", pass1)],
        )
        assert rc == 0, f"vault lock failed ({rc}): {out}"
        assert pass1 not in out, "passphrase echoed during vault lock!"
        print(f"[cli-pty] 3. vault lock {blk_id} OK")

        # 4. Non-TTY block get --decrypt MUST fail fast with exit 5 (BLOCK_LOCKED) and zero secret!
        nontty = run_cli(tmp, ["--json", "block", "get", blk_id, "--decrypt"])
        assert nontty.returncode == 5, f"expected exit 5 BLOCK_LOCKED non-TTY, got {nontty.returncode}: {nontty.stdout} {nontty.stderr}"
        assert secret not in nontty.stdout and secret not in nontty.stderr, "secret leaked in non-TTY output!"
        nontty_json = json.loads(nontty.stdout)
        assert nontty_json["error"]["code"] == "BLOCK_LOCKED", f"unexpected error code: {nontty_json}"
        print("[cli-pty] 4. Non-TTY block get --decrypt fast-fail exit 5 (BLOCK_LOCKED) OK")

        # 5. Real PTY block get --decrypt --raw returns exact secret
        rc, out = run_pty_cmd(
            tmp,
            ["block", "get", blk_id, "--decrypt", "--raw"],
            [("Enter Vault passphrase:", pass1)],
        )
        assert rc == 0, f"PTY block get --decrypt failed ({rc}): {out}"
        assert secret in out, f"secret missing from PTY decrypted output:\n{out}"
        assert pass1 not in out, "passphrase echoed during block get --decrypt!"
        print("[cli-pty] 5. PTY block get --decrypt --raw OK")

        # 6. Change passphrase via `vault passwd`
        pass2 = "VaultPass#Two456"
        rc, out = run_pty_cmd(
            tmp,
            ["vault", "passwd"],
            [
                ("Enter current Vault passphrase:", pass1),
                ("Enter new Vault passphrase:", pass2),
                ("Confirm new Vault passphrase:", pass2),
            ],
        )
        assert rc == 0, f"vault passwd failed ({rc}): {out}"
        # Old passphrase must fail
        rc_old, _ = run_pty_cmd(tmp, ["block", "get", blk_id, "--decrypt", "--raw"], [("Enter Vault passphrase:", pass1)])
        assert rc_old != 0, "old passphrase unexpectedly still worked after vault passwd!"
        # New passphrase must succeed
        rc_new, out_new = run_pty_cmd(
            tmp, ["block", "get", blk_id, "--decrypt", "--raw"], [("Enter Vault passphrase:", pass2)]
        )
        assert rc_new == 0 and secret in out_new, f"new passphrase failed: rc={rc_new} out={out_new}"
        print("[cli-pty] 6. vault passwd rotation verified OK")

        # 7. Recover Vault with 24 words (`vault passwd --recover`)
        pass3 = "VaultPass#Recovered789"
        rc, out = run_pty_cmd(
            tmp,
            ["vault", "passwd", "--recover"],
            [
                ("Enter 24-word recovery bundle:", words),
                ("Enter new Vault passphrase:", pass3),
                ("Confirm new Vault passphrase:", pass3),
            ],
        )
        assert rc == 0, f"vault passwd --recover failed ({rc}): {out}"
        rc_rec, out_rec = run_pty_cmd(
            tmp, ["block", "get", blk_id, "--decrypt", "--raw"], [("Enter Vault passphrase:", pass3)]
        )
        assert rc_rec == 0 and secret in out_rec, f"recovered passphrase decrypt failed: rc={rc_rec} out={out_rec}"
        print("[cli-pty] 7. vault passwd --recover (24 words) verified OK")

        # 8. Downgrade back to Tier 1 via `vault unlock <id> --shred-old-key`
        rc, out = run_pty_cmd(
            tmp,
            ["vault", "unlock", blk_id, "--shred-old-key"],
            [("Enter Vault passphrase:", pass3)],
        )
        assert rc == 0, f"vault unlock failed ({rc}): {out}"
        plain_get = run_cli(tmp, ["block", "get", blk_id, "--raw"])
        assert plain_get.returncode == 0 and plain_get.stdout == secret, f"downgraded get mismatch: {plain_get.stdout!r}"
        print("[cli-pty] 8. vault unlock --shred-old-key downgrade to Tier 1 OK")

        # 9. Trash shred commands ALWAYS exit 2 (UI_CONFIRMATION_REQUIRED) EVEN inside a real TTY!
        for sub in (["trash", "empty"], ["trash", "expedite"], ["trash", "confirm"]):
            rc_t, out_t = run_pty_cmd(tmp, ["--json", *sub], [])
            assert rc_t == 2, f"expected exit 2 for {sub} in TTY, got {rc_t}: {out_t}"
            assert "UI_CONFIRMATION_REQUIRED" in out_t, f"expected UI_CONFIRMATION_REQUIRED for {sub}: {out_t}"
        print("[cli-pty] 9. trash empty/expedite/confirm exit 2 (UI_CONFIRMATION_REQUIRED) even in real TTY OK")

        print("ALL CLI PTY VAULT & SHRED CHECKS PASSED!")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
