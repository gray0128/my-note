#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

wasm_opt_supports_externref() {
  if ! command -v wasm-opt >/dev/null 2>&1; then
    return 1
  fi
  local ver
  ver="$(wasm-opt --version 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+(\.[0-9]+)*$/) {split($i, a, "."); print a[1]; exit}}')"
  # Binaryen < 117 (including Ubuntu 24.04 apt binaryen v108) corrupts wasm-bindgen externref tables.
  [ -n "$ver" ] && [ "$ver" -ge 117 ]
}

build_target() {
  local label="$1"
  local features="$2"
  local out_dir="$3"
  local target_dir="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
  mkdir -p "$out_dir"

  echo "[build-wasm] Compiling mynote-wasm ($label: --no-default-features --features $features)..."
  cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p mynote-wasm \
    --target wasm32-unknown-unknown --profile wasm-release \
    --no-default-features --features "$features"

  local wasm_in="$target_dir/wasm32-unknown-unknown/wasm-release/mynote_wasm.wasm"
  wasm-bindgen "$wasm_in" --target web --out-dir "$out_dir" --out-name mynote_wasm

  local wasm_out="$out_dir/mynote_wasm_bg.wasm"
  if wasm_opt_supports_externref; then
    wasm-opt -Oz --enable-reference-types --enable-bulk-memory --enable-nontrapping-float-to-int \
      --enable-sign-ext --enable-mutable-globals \
      "$wasm_out" -o "${wasm_out}.opt"
    mv "${wasm_out}.opt" "$wasm_out"
  else
    echo "[build-wasm] [$label] skipping wasm-opt (not installed or version < 117)"
  fi

  # Runtime instantiation smoke check (catches externref table corruption immediately)
  node --input-type=module -e '
    import fs from "node:fs";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const [outDir, wasmOut] = process.argv.slice(1);
    const mod = await import(pathToFileURL(path.join(outDir, "mynote_wasm.js")).href);
    mod.initSync({ module: fs.readFileSync(wasmOut) });
  ' "$out_dir" "$wasm_out"

  local raw_bytes gzip_bytes gzip_kib
  raw_bytes=$(wc -c < "$wasm_out")
  gzip_bytes=$(gzip -9 -c "$wasm_out" | wc -c)
  gzip_kib=$(( (gzip_bytes + 1023) / 1024 ))
  echo "[build-wasm] [$label] $wasm_out (${raw_bytes} B raw, ${gzip_bytes} B / ${gzip_kib} KiB gzip)"
  if [ "$label" = "pwa" ] && [ "$gzip_bytes" -gt 358400 ]; then
    echo "[build-wasm] WARNING: [$label] gzip size ${gzip_kib} KiB exceeds 350 KiB target!" >&2
  fi
}

build_target "desktop" "desktop" "$ROOT_DIR/web/src/wasm/pkg"
build_target "pwa" "pwa" "$ROOT_DIR/web/src/wasm/pkg-pwa"
