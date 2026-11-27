#!/usr/bin/env bash
set -euo pipefail

export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/1000}"
export WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-wayland-1}"
export DISPLAY="${DISPLAY:-:0}"

BIN="${1:?usage: $0 <path-to-s-clip-4-binary>}"
WORK_DIR="$(mktemp -d /tmp/s-clip-4-run.XXXXXX)"
BACKUP_DIR="/tmp/s-clip-4-backup"

PIDS_TO_KILL=()
cleanup() {
  for p in "${PIDS_TO_KILL[@]}"; do
    kill "$p" 2>/dev/null || true
    wait "$p" 2>/dev/null || true
  done
  if [[ -f "$BACKUP_DIR/orig.bin" && -s "$BACKUP_DIR/orig.bin" ]]; then
    wl-copy < "$BACKUP_DIR/orig.bin" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

wait_for_ready() {
  local log_file="$1"
  local label="$2"
  for _ in $(seq 1 100); do
    if grep -qx "READY" "$log_file" 2>/dev/null; then
      return 0
    fi
    sleep 0.05
  done
  echo "FAIL: $label did not emit READY" >&2
  cat "$log_file" >&2 || true
  exit 1
}

echo "=== 0. PRE-RUN OMARCHY WATCHER PIDS ==="
PRE_WATCHERS="$(ps -eo pid,ppid,args | grep -E 'wl-paste .*omarchy/shell/plugins/clipboard/capture\.sh' | grep -v grep | sort)"
echo "$PRE_WATCHERS"

echo "=== 1. WAYLAND PROTOCOL PROBE ==="
"$BIN" probe-protocols

echo "=== 2. GENERATE REAL TEST PNGS (77B 2x2 + ~18KiB 128x128) ==="
python3 - "$WORK_DIR" <<'PY'
import hashlib, os, struct, sys, zlib

out_dir = sys.argv[1]
def chunk(t, d):
    return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)

def make_png(w, h, salt):
    rows = bytearray()
    for y in range(h):
        rows.append(0)
        for x in range(w):
            rows.extend(((x * 3 + salt) & 255, (y * 5 + salt) & 255, ((x ^ y) * 7 + salt) & 255, 255))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(rows), 6))
        + chunk(b"IEND", b"")
    )

for name, w, h, salt in [("small.png", 2, 2, 11), ("screenshot.png", 128, 128, 37), ("secret.png", 4, 4, 99)]:
    data = make_png(w, h, salt)
    p = os.path.join(out_dir, name)
    with open(p, "wb") as f:
        f.write(data)
    print(f"{name}: {len(data)} bytes sha256={hashlib.sha256(data).hexdigest()}")
PY

OMARCHY_IMG_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/omarchy/clipboard-images"
SECRET_PNG_SHA="$(sha256sum "$WORK_DIR/secret.png" | awk '{print $1}')"
echo "secret.png expected sha256 (must NOT appear in $OMARCHY_IMG_DIR): $SECRET_PNG_SHA"

echo "=== 3. START READ-ONLY WATCHER (COEXISTING WITH OMARCHY WATCHERS) ==="
WATCH_LOG="$WORK_DIR/watch.log"
"$BIN" watch --duration-secs 12 --skip-initial --ready-marker > "$WATCH_LOG" 2>"$WORK_DIR/watch.err" &
WATCH_PID=$!
PIDS_TO_KILL+=("$WATCH_PID")
wait_for_ready "$WATCH_LOG" "read-only watcher"
echo "Read-only watcher started (PID=$WATCH_PID)"

# Case A: Normal text via wl-copy -> Wayland paste + XWayland paste + Watcher observed
echo "=== CASE A: NORMAL TEXT (wl-copy) ==="
printf "s-clip-4-case-a-normal-text" | wl-copy
sleep 0.25
echo "wl-paste: $(wl-paste --no-newline)"
echo "x11-read TARGETS: $("$BIN" x11-read --target TARGETS)"
echo "x11-read UTF8_STRING: $("$BIN" x11-read --target UTF8_STRING)"

# Case B: Normal PNG via wl-copy --type image/png -> Wayland paste + XWayland paste + Watcher observed
echo "=== CASE B: NORMAL PNG (wl-copy --type image/png, 128x128) ==="
wl-copy --type image/png < "$WORK_DIR/screenshot.png"
sleep 0.3
echo "wl-paste png sha256: $(wl-paste --type image/png | sha256sum)"
echo "x11-read TARGETS: $("$BIN" x11-read --target TARGETS)"
echo "x11-read image/png: $("$BIN" x11-read --target image/png)"

# Case C: Multi-MIME synced text via wl-clipboard-rs (text + application/x-mynote-synced)
echo "=== CASE C: MULTI-MIME SYNCED TEXT (wl-clipboard-rs) ==="
COPY_C_LOG="$WORK_DIR/copy_c.log"
"$BIN" copy-multi --text "s-clip-4-case-c-synced-text" --synced > "$COPY_C_LOG" 2>"$WORK_DIR/copy_c.err" &
COPY_C_PID=$!
PIDS_TO_KILL+=("$COPY_C_PID")
wait_for_ready "$COPY_C_LOG" "copy-multi C"
sleep 0.2
echo "wl-paste --list-types:"
wl-paste --list-types
echo "wl-paste text: $(wl-paste --no-newline)"
echo "wl-paste synced marker: $(wl-paste --type application/x-mynote-synced --no-newline)"
echo "x11-read UTF8_STRING: $("$BIN" x11-read --target UTF8_STRING)"

# Case D: Multi-MIME synced PNG via wl-clipboard-rs (image/png + application/x-mynote-synced)
echo "=== CASE D: MULTI-MIME SYNCED PNG (wl-clipboard-rs) ==="
COPY_D_LOG="$WORK_DIR/copy_d.log"
"$BIN" copy-multi --png "$WORK_DIR/small.png" --synced > "$COPY_D_LOG" 2>"$WORK_DIR/copy_d.err" &
COPY_D_PID=$!
PIDS_TO_KILL+=("$COPY_D_PID")
wait_for_ready "$COPY_D_LOG" "copy-multi D"
sleep 0.25
echo "Previous copy-multi C log (verifying clean exit on supersede):"
cat "$COPY_C_LOG"
echo "wl-paste --list-types:"
wl-paste --list-types
echo "wl-paste image/png sha256: $(wl-paste --type image/png | sha256sum)"
echo "wl-paste synced marker: $(wl-paste --type application/x-mynote-synced --no-newline)"
echo "x11-read TARGETS: $("$BIN" x11-read --target TARGETS)"
echo "x11-read image/png: $("$BIN" x11-read --target image/png)"

# Case E: Sensitive text (--sensitive + --vault-secret) via wl-clipboard-rs
echo "=== CASE E: SENSITIVE VAULT TEXT (x-kde-passwordManagerHint + x-mynote-vault-secret) ==="
COPY_E_LOG="$WORK_DIR/copy_e.log"
"$BIN" copy-multi --text "s-clip-4-case-e-vault-secret" --sensitive --vault-secret > "$COPY_E_LOG" 2>"$WORK_DIR/copy_e.err" &
COPY_E_PID=$!
PIDS_TO_KILL+=("$COPY_E_PID")
wait_for_ready "$COPY_E_LOG" "copy-multi E"
sleep 0.25
echo "wl-paste --list-types:"
wl-paste --list-types
echo "wl-paste hint: $(wl-paste --type x-kde-passwordManagerHint --no-newline)"
echo "wl-paste text still readable for user paste: $(wl-paste --no-newline)"
echo "x11-read UTF8_STRING still readable for XWayland paste: $("$BIN" x11-read --target UTF8_STRING)"

# Case F: Sensitive PNG (--sensitive + --synced) via wl-clipboard-rs
echo "=== CASE F: SENSITIVE PNG (image/png + x-kde-passwordManagerHint + x-mynote-synced) ==="
COPY_F_LOG="$WORK_DIR/copy_f.log"
"$BIN" copy-multi --png "$WORK_DIR/secret.png" --sensitive --synced > "$COPY_F_LOG" 2>"$WORK_DIR/copy_f.err" &
COPY_F_PID=$!
PIDS_TO_KILL+=("$COPY_F_PID")
wait_for_ready "$COPY_F_LOG" "copy-multi F"
sleep 0.35
echo "wl-paste --list-types:"
wl-paste --list-types
echo "wl-paste image/png sha256: $(wl-paste --type image/png | sha256sum)"
echo "x11-read image/png: $("$BIN" x11-read --target image/png)"
if [[ -e "$OMARCHY_IMG_DIR/$SECRET_PNG_SHA.png" ]]; then
  echo "FAIL: Omarchy capture.sh saved sensitive secret.png!" >&2
  exit 1
else
  echo "OK: Omarchy capture.sh did NOT persist sensitive secret.png ($SECRET_PNG_SHA.png absent)"
fi

# Case G: SVG-only offer -> must NOT be read as image (XSS guard)
echo "=== CASE G: SVG-ONLY OFFER (image/svg+xml rejected as image) ==="
COPY_G_LOG="$WORK_DIR/copy_g.log"
"$BIN" copy-multi --raw-mime "image/svg+xml" "<svg onload=alert(1)/>" > "$COPY_G_LOG" 2>"$WORK_DIR/copy_g.err" &
COPY_G_PID=$!
PIDS_TO_KILL+=("$COPY_G_PID")
wait_for_ready "$COPY_G_LOG" "copy-multi G"
sleep 0.25

# Case H: Real XWayland client owns CLIPBOARD -> Wayland wl-paste + Watcher receive cleanly
echo "=== CASE H: XWAYLAND -> WAYLAND COPY (x11-copy on Xwayland :0) ==="
X11_COPY_LOG="$WORK_DIR/x11_copy.log"
"$BIN" x11-copy --text "s-clip-4-case-h-from-xwayland" --timeout-secs 4 > "$X11_COPY_LOG" 2>"$WORK_DIR/x11_copy.err" &
X11_COPY_PID=$!
PIDS_TO_KILL+=("$X11_COPY_PID")
wait_for_ready "$X11_COPY_LOG" "x11-copy H"
sleep 0.3
echo "wl-paste from XWayland owner (1st read): $(wl-paste --no-newline)"
sleep 0.2
echo "wl-paste from XWayland owner (2nd read, proving NOT wiped): $(wl-paste --no-newline)"
echo "Previous copy-multi G log (verifying clean exit on XWayland supersede):"
cat "$COPY_G_LOG"

# Wait for watcher to finish via CancelHandle or send SIGINT? Let's let x11-copy finish & wait for watcher clean cancel?
# Actually wait for x11-copy to finish or overwrite with a clean normal copy and let timer cancel watcher.
echo "Waiting for x11-copy log and watcher cancel_handle exit..."
wait "$X11_COPY_PID" || true
cat "$X11_COPY_LOG"

# Stop watcher early if still waiting? No, wait for timer so we prove CancelHandle cleanly exits!
# Wait: 25s is a bit long; let's check elapsed time and wait.
wait "$WATCH_PID" || true

echo "=== 4. READ-ONLY WATCHER EVENT LOG ==="
cat "$WATCH_LOG"
if [[ -s "$WORK_DIR/watch.err" ]]; then
  echo "=== WATCHER STDERR ==="
  cat "$WORK_DIR/watch.err"
fi

echo "=== 5. POST-RUN OMARCHY WATCHER PIDS (MUST BE IDENTICAL) ==="
POST_WATCHERS="$(ps -eo pid,ppid,args | grep -E 'wl-paste .*omarchy/shell/plugins/clipboard/capture\.sh' | grep -v grep | sort)"
echo "$POST_WATCHERS"
if [[ "$PRE_WATCHERS" != "$POST_WATCHERS" ]]; then
  echo "FAIL: Omarchy watcher PIDs changed!" >&2
  exit 1
fi
echo "OK: Omarchy watcher PIDs identical and healthy!"
