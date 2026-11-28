#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$ROOT/build/MyNote.app"
SKIP_BUILD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build)
      SKIP_BUILD=1
      shift
      ;;
    --app)
      APP_DIR="$2"
      shift 2
      ;;
    *)
      echo "Usage: $0 [--no-build] [--app PATH/TO/MyNote.app]" >&2
      exit 2
      ;;
  esac
done

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  "$ROOT/build.sh"
fi

APP_BIN="$APP_DIR/Contents/MacOS/MyNote"
if [[ ! -x "$APP_BIN" ]]; then
  echo "ERROR: executable not found at $APP_BIN" >&2
  exit 1
fi

MYNOTE_BIN="${MYNOTE_BIN:-$(command -v mynote || true)}"
if [[ -z "$MYNOTE_BIN" ]]; then
  echo "ERROR: mynote binary not found in PATH (set MYNOTE_BIN=/path/to/mynote)" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d /tmp/mynote-macos-verify.XXXXXX)"
DAEMON_PID=""
cleanup() {
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"

export MYNOTE_DATA_DIR="$TMP_DIR"
"$MYNOTE_BIN" daemon --port "$PORT" >"$TMP_DIR/daemon.log" 2>&1 &
DAEMON_PID=$!

SOCK="$TMP_DIR/daemon.sock"
for _ in $(seq 1 150); do
  if [[ -S "$SOCK" ]]; then
    break
  fi
  if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "ERROR: isolated daemon exited early" >&2
    cat "$TMP_DIR/daemon.log" >&2 || true
    exit 1
  fi
  sleep 0.1
done
if [[ ! -S "$SOCK" ]]; then
  echo "ERROR: isolated daemon failed to create $SOCK" >&2
  cat "$TMP_DIR/daemon.log" >&2 || true
  exit 1
fi

echo "=== Verifying $APP_BIN against $MYNOTE_BIN (port $PORT, data_dir $TMP_DIR) ==="
"$APP_BIN" --self-test
