#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SPIKE_DIR="$ROOT_DIR/spikes/s-clip-1-ios-shortcuts"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/mynote-s-clip-1}"
JSC_BIN="/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc"

export CARGO_TARGET_DIR="$TARGET_DIR"
mkdir -p "$TARGET_DIR"

echo "=== 0. Environment ==="
uname -a
sw_vers 2>/dev/null || true
sysctl -n machdep.cpu.brand_string hw.ncpu hw.memsize 2>/dev/null || true
uptime
node -v
rustc -V
cargo -V

echo ""
echo "=== 1. Bundle Size & Minified Verification ==="
node "$SPIKE_DIR/measure_size.js" "$TARGET_DIR/mnc1_sync.min.js"

echo ""
echo "=== 2. Rust Unit Tests + Build Release Interop Binary ==="
cargo test --manifest-path "$SPIKE_DIR/rust-interop/Cargo.toml"
cargo build --release --manifest-path "$SPIKE_DIR/rust-interop/Cargo.toml"

echo ""
echo "=== 3. Bidirectional Byte-Level Interop (Node V8 + macOS JSC + Minified JSC + Rust) ==="
node "$SPIKE_DIR/verify_interop.js" "$SPIKE_DIR/golden_vectors.json" --emit-js-vectors "$TARGET_DIR/js_generated.json"
if [ -x "$JSC_BIN" ]; then
  "$JSC_BIN" "$SPIKE_DIR/verify_interop.js" -- "$SPIKE_DIR/mnc1_sync.js" "$SPIKE_DIR/golden_vectors.json"
  "$JSC_BIN" "$SPIKE_DIR/verify_interop.js" -- "$TARGET_DIR/mnc1_sync.min.js" "$SPIKE_DIR/golden_vectors.json"
fi
"$TARGET_DIR/release/s-clip-1-rust-interop" verify "$SPIKE_DIR/golden_vectors.json"
"$TARGET_DIR/release/s-clip-1-rust-interop" verify "$TARGET_DIR/js_generated.json"

echo ""
echo "=== 4. Warm Benchmarks (7 runs after 5 warmups) ==="
echo "--- Node V8 ---"
node "$SPIKE_DIR/bench.js"
if [ -x "$JSC_BIN" ]; then
  echo "--- macOS JSC (JIT) ---"
  "$JSC_BIN" "$SPIKE_DIR/bench.js" -- "$SPIKE_DIR/mnc1_sync.js"
  echo "--- macOS JSC (NO-JIT / LLInt) ---"
  "$JSC_BIN" --useJIT=false "$SPIKE_DIR/bench.js" -- "$SPIKE_DIR/mnc1_sync.js"
fi

echo ""
echo "=== 5. Limiter Breakdown (1.5 MiB: ChaCha20 vs Poly1305) ==="
node "$SPIKE_DIR/bench.js" --breakdown
if [ -x "$JSC_BIN" ]; then
  "$JSC_BIN" "$SPIKE_DIR/bench.js" -- "$SPIKE_DIR/mnc1_sync.js" --breakdown
  "$JSC_BIN" --useJIT=false "$SPIKE_DIR/bench.js" -- "$SPIKE_DIR/mnc1_sync.js" --breakdown
fi

echo ""
echo "=== 6. Uncontaminated Cold Benchmarks (5 fresh processes per case, interleaved) ==="
COLD_LOG="$TARGET_DIR/cold_runs.jsonl"
: > "$COLD_LOG"
for c in text 500k 15m; do
  for i in 1 2 3 4 5; do
    node "$SPIKE_DIR/bench.js" --cold-case "$c" | tee -a "$COLD_LOG" >/dev/null
    if [ -x "$JSC_BIN" ]; then
      "$JSC_BIN" "$SPIKE_DIR/bench.js" -- "$SPIKE_DIR/mnc1_sync.js" --cold-case "$c" \
        | node -e 'const o=JSON.parse(require("fs").readFileSync(0,"utf8")); o.engine="macOS JSC (JIT)"; console.log(JSON.stringify(o));' \
        >> "$COLD_LOG"
      "$JSC_BIN" --useJIT=false "$SPIKE_DIR/bench.js" -- "$SPIKE_DIR/mnc1_sync.js" --cold-case "$c" \
        | node -e 'const o=JSON.parse(require("fs").readFileSync(0,"utf8")); o.engine="macOS JSC (NO-JIT LLInt)"; console.log(JSON.stringify(o));' \
        >> "$COLD_LOG"
    fi
  done
done

node -e '
const fs = require("fs");
const lines = fs.readFileSync(process.argv[1], "utf8").trim().split("\n").map(JSON.parse);
const groups = {};
for (const r of lines) {
  const k = r.engine + " | " + r.case;
  (groups[k] = groups[k] || []).push(r.ms);
}
const out = {};
for (const [k, arr] of Object.entries(groups)) {
  const s = arr.slice().sort((a, b) => a - b);
  out[k] = { runs: s.length, median_ms: s[s.length >> 1], min_ms: s[0], max_ms: s[s.length - 1], samples: arr };
}
console.log(JSON.stringify(out, null, 2));
' "$COLD_LOG"
