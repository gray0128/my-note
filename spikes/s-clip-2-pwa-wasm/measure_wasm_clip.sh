#!/usr/bin/env bash
set -euo pipefail

# S-Clip-2 (Issue #50): Apples-to-apples measurement of `mynote-wasm` (`pwa` feature)
# baseline vs `+WasmClipCodec` (`MNC1`), strictly isolated in `/tmp/mynote-s-clip-2-work`
# with `CARGO_TARGET_DIR=/tmp/mynote-s-clip-2`. NEVER touches repo `crates/` or `web/`.

SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SPIKE_DIR/../.." && pwd)"
WORK_DIR="${WORK_DIR:-/tmp/mynote-s-clip-2-work}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/mynote-s-clip-2}"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

OUT_PKG=""
KEEP_WORK=0
JSON_OUT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --out-pkg)
      OUT_PKG="$2"
      shift 2
      ;;
    --json-out)
      JSON_OUT="$2"
      shift 2
      ;;
    --keep-work)
      KEEP_WORK=1
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

cleanup() {
  if [ "$KEEP_WORK" -eq 0 ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

wasm_opt_supports_externref() {
  if ! command -v wasm-opt >/dev/null 2>&1; then
    return 1
  fi
  local ver
  ver="$(wasm-opt --version 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+(\.[0-9]+)*$/) {split($i, a, "."); print a[1]; exit}}')"
  [ -n "$ver" ] && [ "$ver" -ge 117 ]
}

measure_wasm() {
  local path="$1"
  local raw gz
  raw=$(wc -c < "$path" | tr -d ' ')
  gz=$(gzip -9 -c "$path" | wc -c | tr -d ' ')
  echo "${raw} ${gz}"
}

verify_node_instantiation() {
  local out_dir="$1"
  local wasm_out="$2"
  local mode="$3"
  node --input-type=module -e '
    import fs from "node:fs";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const [outDir, wasmOut, mode] = process.argv.slice(1);
    const mod = await import(pathToFileURL(path.join(outDir, "mynote_wasm.js")).href);
    mod.initSync({ module: fs.readFileSync(wasmOut) });
    if (mode === "clip") {
      if (typeof mod.WasmClipCodec !== "function") {
        throw new Error("WasmClipCodec export missing");
      }
      const key = new Uint8Array(32).fill(0x5a);
      const codec = new mod.WasmClipCodec(
        "dev_nodecheck001",
        "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
        key
      );
      const clipId = "01JDF8Z9X4K7M2N5P8Q1R3S6TA";
      const metaIn = JSON.stringify({
        v: 1,
        kind: "text",
        mime: "text/plain",
        source_mode: "explicit",
        created_at_ms: 1795600000001,
        text: "hello mnc1 node smoke",
        blob: null
      });
      const metaCt = codec.encryptMeta(clipId, metaIn, false);
      const metaPt = codec.decryptMeta(clipId, "dev_nodecheck001", metaCt, false);
      if (metaPt !== metaIn) throw new Error("meta roundtrip mismatch");

      const ephCt = codec.encryptMeta(clipId, metaIn, true);
      const ephPt = codec.decryptMeta(clipId, "dev_nodecheck001", ephCt, true);
      if (ephPt !== metaIn) throw new Error("ephemeral meta roundtrip mismatch");
      let crossFailed = false;
      try { codec.decryptMeta(clipId, "dev_nodecheck001", ephCt, false); } catch { crossFailed = true; }
      if (!crossFailed) throw new Error("expected cross-channel AAD failure");

      const raw = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4]);
      const blobCt = codec.encryptBlob(clipId, raw);
      if (blobCt.length !== 45 + raw.length + 16) throw new Error("unexpected MNC1 blob size");
      const blobPt = codec.decryptBlob(clipId, "dev_nodecheck001", blobCt);
      if (blobPt.length !== raw.length || blobPt.some((b, i) => b !== raw[i])) {
        throw new Error("blob roundtrip mismatch");
      }

      codec.zeroize();
      let afterZeroizeFailed = false;
      try { codec.encryptBlob(clipId, raw); } catch { afterZeroizeFailed = true; }
      if (!afterZeroizeFailed) throw new Error("expected error after zeroize()");
      codec.free();
    }
  ' "$out_dir" "$wasm_out" "$mode"
}

run_bindgen_variant() {
  local wasm_in="$1"
  local out_dir="$2"
  local mode="$3"
  local extra_flag="$4"

  rm -rf "$out_dir"
  mkdir -p "$out_dir"

  if [ -n "$extra_flag" ]; then
    wasm-bindgen "$wasm_in" --target web --out-dir "$out_dir" --out-name mynote_wasm "$extra_flag"
  else
    wasm-bindgen "$wasm_in" --target web --out-dir "$out_dir" --out-name mynote_wasm
  fi

  local wasm_out="$out_dir/mynote_wasm_bg.wasm"
  if wasm_opt_supports_externref; then
    wasm-opt -Oz --enable-reference-types --enable-bulk-memory --enable-nontrapping-float-to-int \
      --enable-sign-ext --enable-mutable-globals \
      "$wasm_out" -o "${wasm_out}.opt"
    mv "${wasm_out}.opt" "$wasm_out"
  fi

  verify_node_instantiation "$out_dir" "$wasm_out" "$mode"
  measure_wasm "$wasm_out"
}

echo "[s-clip-2] Toolchain:"
echo "  rustc:        $(rustc --version)"
echo "  wasm-bindgen: $(wasm-bindgen --version)"
if wasm_opt_supports_externref; then
  echo "  wasm-opt:     $(wasm-opt --version)"
  WASM_OPT_USED="true"
else
  echo "  wasm-opt:     NOT INSTALLED (or < 117) -> skipped (same as CI & scripts/build-wasm.sh)"
  WASM_OPT_USED="false"
fi
echo "  node:         $(node --version)"
echo "  target_dir:   $CARGO_TARGET_DIR"

COMMITTED_WASM="$ROOT_DIR/web/src/wasm/pkg-pwa/mynote_wasm_bg.wasm"
read -r COMMITTED_RAW COMMITTED_GZ <<< "$(measure_wasm "$COMMITTED_WASM")"
COMMITTED_GZ_KIB=$(awk -v b="$COMMITTED_GZ" 'BEGIN { printf "%.2f", b / 1024.0 }')
echo "[s-clip-2] Committed baseline ($COMMITTED_WASM): ${COMMITTED_RAW} B raw, ${COMMITTED_GZ} B (${COMMITTED_GZ_KIB} KiB) gzip -9"

# 1. Prepare isolated workspace copy in /tmp/mynote-s-clip-2-work
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cp "$ROOT_DIR/Cargo.toml" "$ROOT_DIR/Cargo.lock" "$WORK_DIR/"
cp -R "$ROOT_DIR/crates" "$WORK_DIR/crates"
# Strip exclude lines pointing to spikes/ so cargo does not complain about missing spike dirs in /tmp copy
python3 - "$WORK_DIR/Cargo.toml" <<'PY'
import re, sys
p = sys.argv[1]
txt = open(p, encoding="utf-8").read()
txt = re.sub(r'(?ms)^exclude\s*=\s*\[[^\]]*\]\n?', '', txt)
open(p, "w", encoding="utf-8").write(txt)
PY

# 2. Build UNMODIFIED baseline (pwa feature)
echo "[s-clip-2] Building UNMODIFIED baseline (mynote-wasm --no-default-features --features pwa)..."
cargo build --manifest-path "$WORK_DIR/Cargo.toml" -p mynote-wasm \
  --target wasm32-unknown-unknown --profile wasm-release \
  --no-default-features --features pwa

WASM_IN="$CARGO_TARGET_DIR/wasm32-unknown-unknown/wasm-release/mynote_wasm.wasm"
read -r BASE_DEF_RAW BASE_DEF_GZ <<< "$(run_bindgen_variant "$WASM_IN" "$WORK_DIR/pkg-base-default" "base" "")"
read -r BASE_NONAME_RAW BASE_NONAME_GZ <<< "$(run_bindgen_variant "$WASM_IN" "$WORK_DIR/pkg-base-noname" "base" "--remove-name-section")"

# 3. Patch temp copy with mynote_core::clip + WasmClipCodec
cp "$SPIKE_DIR/clip_core_patch.rs" "$WORK_DIR/crates/mynote-core/src/clip.rs"
cp "$SPIKE_DIR/wasm_clip_patch.rs" "$WORK_DIR/crates/mynote-wasm/src/wasm_clip_patch.rs"

python3 - "$WORK_DIR/crates/mynote-core/src/lib.rs" "$WORK_DIR/crates/mynote-wasm/src/lib.rs" <<'PY'
import sys

core_lib = sys.argv[1]
txt = open(core_lib, encoding="utf-8").read()
if "pub mod clip;" not in txt:
    txt = "pub mod clip;\n" + txt
open(core_lib, "w", encoding="utf-8").write(txt)

wasm_lib = sys.argv[2]
wtxt = open(wasm_lib, encoding="utf-8").read()

old_extern = '''#[cfg(all(target_arch = "wasm32", feature = "desktop"))]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["globalThis", "crypto"], js_name = getRandomValues)]
    fn js_get_random_values(buf: &mut [u8]);

    #[wasm_bindgen(js_namespace = Date, js_name = now)]
    fn js_date_now() -> f64;
}

#[cfg(feature = "desktop")]
fn fill_random<const N: usize>() -> Result<[u8; N], CoreError> {'''

new_extern = '''#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["globalThis", "crypto"], js_name = getRandomValues)]
    fn js_get_random_values(buf: &mut [u8]);

    #[cfg(feature = "desktop")]
    #[wasm_bindgen(js_namespace = Date, js_name = now)]
    fn js_date_now() -> f64;
}

fn fill_random<const N: usize>() -> Result<[u8; N], CoreError> {'''

assert old_extern in wtxt, "expected extern/fill_random block not found in mynote-wasm/src/lib.rs"
wtxt = wtxt.replace(old_extern, new_extern, 1)

marker = '#[cfg(all(test, feature = "desktop", feature = "pwa"))]'
assert marker in wtxt, "expected test marker not found in mynote-wasm/src/lib.rs"
wtxt = wtxt.replace(marker, 'include!("wasm_clip_patch.rs");\n\n' + marker, 1)
open(wasm_lib, "w", encoding="utf-8").write(wtxt)
PY

echo "[s-clip-2] Running native unit tests for mynote-core::clip..."
cargo test --manifest-path "$WORK_DIR/Cargo.toml" -p mynote-core --no-default-features clip::tests

echo "[s-clip-2] Building +WasmClipCodec (mynote-wasm --no-default-features --features pwa)..."
cargo build --manifest-path "$WORK_DIR/Cargo.toml" -p mynote-wasm \
  --target wasm32-unknown-unknown --profile wasm-release \
  --no-default-features --features pwa

read -r CLIP_DEF_RAW CLIP_DEF_GZ <<< "$(run_bindgen_variant "$WASM_IN" "$WORK_DIR/pkg-clip-default" "clip" "")"
read -r CLIP_NONAME_RAW CLIP_NONAME_GZ <<< "$(run_bindgen_variant "$WASM_IN" "$WORK_DIR/pkg-clip-noname" "clip" "--remove-name-section")"

if [ -n "$OUT_PKG" ]; then
  rm -rf "$OUT_PKG"
  mkdir -p "$OUT_PKG"
  cp -R "$WORK_DIR/pkg-clip-noname/"* "$OUT_PKG/"
  echo "[s-clip-2] Copied +WasmClipCodec pkg (--remove-name-section) to $OUT_PKG"
fi

python3 - "$COMMITTED_RAW" "$COMMITTED_GZ" \
  "$BASE_DEF_RAW" "$BASE_DEF_GZ" "$CLIP_DEF_RAW" "$CLIP_DEF_GZ" \
  "$BASE_NONAME_RAW" "$BASE_NONAME_GZ" "$CLIP_NONAME_RAW" "$CLIP_NONAME_GZ" \
  "$WASM_OPT_USED" "$JSON_OUT" <<'PY'
import json, sys

(
    c_raw, c_gz,
    bd_raw, bd_gz, cd_raw, cd_gz,
    bn_raw, bn_gz, cn_raw, cn_gz,
    wasm_opt_used, json_out,
) = sys.argv[1:]

vals = [int(x) for x in (c_raw, c_gz, bd_raw, bd_gz, cd_raw, cd_gz, bn_raw, bn_gz, cn_raw, cn_gz)]
c_raw, c_gz, bd_raw, bd_gz, cd_raw, cd_gz, bn_raw, bn_gz, cn_raw, cn_gz = vals

def kib(b): return b / 1024.0

print("\n=== S-Clip-2 pkg-pwa WASM Size Delta Summary ===")
print(f"Committed web/src/wasm/pkg-pwa:          raw={c_raw:>10,d} B ({kib(c_raw):7.2f} KiB) | gzip-9={c_gz:>7,d} B ({kib(c_gz):6.2f} KiB)")
print(f"Local baseline (build-wasm.sh default):  raw={bd_raw:>10,d} B ({kib(bd_raw):7.2f} KiB) | gzip-9={bd_gz:>7,d} B ({kib(bd_gz):6.2f} KiB)")
print(f"Local +WasmClipCodec (default):          raw={cd_raw:>10,d} B ({kib(cd_raw):7.2f} KiB) | gzip-9={cd_gz:>7,d} B ({kib(cd_gz):6.2f} KiB)")
print(f"  -> Delta (default):                    raw={cd_raw-bd_raw:>+10,d} B ({kib(cd_raw-bd_raw):+7.2f} KiB) | gzip-9={cd_gz-bd_gz:>+7,d} B ({kib(cd_gz-bd_gz):+6.2f} KiB)")
print(f"Local baseline (--remove-name-section):  raw={bn_raw:>10,d} B ({kib(bn_raw):7.2f} KiB) | gzip-9={bn_gz:>7,d} B ({kib(bn_gz):6.2f} KiB)")
print(f"Local +WasmClipCodec (--remove-name):    raw={cn_raw:>10,d} B ({kib(cn_raw):7.2f} KiB) | gzip-9={cn_gz:>7,d} B ({kib(cn_gz):6.2f} KiB)")
print(f"  -> Delta (--remove-name-section):      raw={cn_raw-bn_raw:>+10,d} B ({kib(cn_raw-bn_raw):+7.2f} KiB) | gzip-9={cn_gz-bn_gz:>+7,d} B ({kib(cn_gz-bn_gz):+6.2f} KiB)")
print(f"  -> Saved by --remove-name-section:     raw={cd_raw-cn_raw:>10,d} B ({kib(cd_raw-cn_raw):7.2f} KiB) | gzip-9={cd_gz-cn_gz:>7,d} B ({kib(cd_gz-cn_gz):6.2f} KiB)")
print(f"  -> Under 350 KiB (358,400 B) budget?   default={cd_gz <= 358400} | --remove-name-section={cn_gz <= 358400} (headroom {358400 - cn_gz:,d} B / {kib(358400 - cn_gz):.2f} KiB)")

if json_out:
    summary = {
        "wasm_opt_used": wasm_opt_used == "true",
        "budget_bytes": 358400,
        "committed_baseline": {"raw_bytes": c_raw, "gzip_bytes": c_gz},
        "default_flags": {
            "baseline": {"raw_bytes": bd_raw, "gzip_bytes": bd_gz},
            "with_clip_codec": {"raw_bytes": cd_raw, "gzip_bytes": cd_gz},
            "delta_raw_bytes": cd_raw - bd_raw,
            "delta_gzip_bytes": cd_gz - bd_gz,
            "within_350kib_budget": cd_gz <= 358400,
        },
        "remove_name_section": {
            "baseline": {"raw_bytes": bn_raw, "gzip_bytes": bn_gz},
            "with_clip_codec": {"raw_bytes": cn_raw, "gzip_bytes": cn_gz},
            "delta_raw_bytes": cn_raw - bn_raw,
            "delta_gzip_bytes": cn_gz - bn_gz,
            "within_350kib_budget": cn_gz <= 358400,
            "headroom_bytes": 358400 - cn_gz,
        },
    }
    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
PY
