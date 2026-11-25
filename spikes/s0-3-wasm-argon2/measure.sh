#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
OUT_DIR="dist"
mkdir -p "$OUT_DIR"

echo "Config | Raw (.wasm) | wasm-opt -Oz | gzip -9 | Status"
echo "---|---:|---:|---:|---"

run_cfg() {
  local name="$1"
  shift
  local feat_args=("$@")
  local target_wasm="target/wasm32-unknown-unknown/release/s0_3_wasm_argon2.wasm"

  if cargo build --target wasm32-unknown-unknown --release "${feat_args[@]}" >/tmp/s03_"$name".log 2>&1; then
    local raw_bytes
    raw_bytes=$(wc -c < "$target_wasm")
    cp "$target_wasm" "$OUT_DIR/${name}.raw.wasm"
    wasm-opt -Oz --enable-bulk-memory --enable-sign-ext --enable-mutable-globals --enable-nontrapping-float-to-int "$OUT_DIR/${name}.raw.wasm" -o "$OUT_DIR/${name}.opt.wasm"
    local opt_bytes
    opt_bytes=$(wc -c < "$OUT_DIR/${name}.opt.wasm")
    gzip -9 -c "$OUT_DIR/${name}.opt.wasm" > "$OUT_DIR/${name}.opt.wasm.gz"
    local gz_bytes
    gz_bytes=$(wc -c < "$OUT_DIR/${name}.opt.wasm.gz")
    printf "%s | %.1f KiB (%d B) | %.1f KiB (%d B) | **%.1f KiB** (%d B) | OK\n" \
      "$name" \
      "$(awk "BEGIN {print $raw_bytes/1024}")" "$raw_bytes" \
      "$(awk "BEGIN {print $opt_bytes/1024}")" "$opt_bytes" \
      "$(awk "BEGIN {print $gz_bytes/1024}")" "$gz_bytes"
  else
    local err_line
    err_line=$(tail -n 5 /tmp/s03_"$name".log | tr '\n' ' ' | sed 's/|/ /g')
    printf "%s | — | — | — | FAILED: %s\n" "$name" "${err_line:0:120}"
  fi
}

run_cfg "1-crypto-only" --no-default-features
run_cfg "2-crypto-x25519-precomp" --no-default-features --features x25519-precomp
run_cfg "3-mobile-ruzstd-decode" --no-default-features --features comp-ruzstd-decode
run_cfg "4-desktop-ruzstd-rw" --no-default-features --features comp-ruzstd-rw
run_cfg "5-desktop-miniz-rw" --no-default-features --features comp-miniz-rw
run_cfg "6-desktop-ruzstd-layer1" --no-default-features --features comp-ruzstd-rw,fmt-layer1
run_cfg "7-desktop-zstd-c" --no-default-features --features comp-zstd-c
