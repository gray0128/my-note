#!/usr/bin/env bash
set -euo pipefail

# Reproducible apples-to-apples measurement harness for Spike S-Clip-3.
# Measures strictly `--bin s-clip-3-macos-pasteboard` (no test harness skew)
# under `[profile.release]` (`lto = "thin"`, `strip = true`, matching root Cargo.toml).
# Uses ONLY /tmp/mynote-s-clip-3 so parallel agents never collide.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_TARGET="${CARGO_TARGET_DIR:-/tmp/mynote-s-clip-3}"
mkdir -p "$BASE_TARGET"

echo "=== Environment ==="
sw_vers
uname -m
sysctl -n machdep.cpu.brand_string
rustc --version
cargo --version
echo ""

# Pre-fetch all crates into ~/.cargo cache so clean compile timing measures pure compilation.
CARGO_TARGET_DIR="$BASE_TARGET/fetch" cargo fetch --manifest-path "$SCRIPT_DIR/Cargo.toml"

BASELINE_BYTES=0

measure_profile() {
    local label="$1"
    shift
    local tdir="$BASE_TARGET/bench-$label"
    rm -rf "$tdir"

    local crate_count
    crate_count=$(CARGO_TARGET_DIR="$BASE_TARGET/fetch" cargo tree \
        --manifest-path "$SCRIPT_DIR/Cargo.toml" "$@" -e normal --prefix none \
        | awk '{print $1, $2}' | sort -u | wc -l | tr -d ' ')

    local start_ns end_ns elapsed_ms bin_bytes
    start_ns=$(python3 -c 'import time; print(time.perf_counter_ns())')
    CARGO_TARGET_DIR="$tdir" cargo build --release --offline \
        --manifest-path "$SCRIPT_DIR/Cargo.toml" \
        --bin s-clip-3-macos-pasteboard "$@" >/dev/null 2>&1
    end_ns=$(python3 -c 'import time; print(time.perf_counter_ns())')

    elapsed_ms=$(python3 -c "print(f'{($end_ns - $start_ns)/1e6:.1f}')")
    bin_bytes=$(stat -f%z "$tdir/release/s-clip-3-macos-pasteboard")
    if [ "$BASELINE_BYTES" -eq 0 ]; then
        BASELINE_BYTES="$bin_bytes"
    fi
    local delta_bytes=$((bin_bytes - BASELINE_BYTES))
    local bin_kib delta_kib bin_mib delta_mib
    bin_kib=$(python3 -c "print(f'{$bin_bytes/1024:.1f}')")
    bin_mib=$(python3 -c "print(f'{$bin_bytes/(1024*1024):.2f}')")
    delta_kib=$(python3 -c "print(f'{$delta_bytes/1024:+.1f}')")
    delta_mib=$(python3 -c "print(f'{$delta_bytes/(1024*1024):+.2f}')")

    printf "%-28s | %3s | %9s ms | %9s B | %7s KiB (%4s MiB) | %9s KiB (%6s MiB)\n" \
        "$label" "$crate_count" "$elapsed_ms" "$bin_bytes" "$bin_kib" "$bin_mib" "$delta_kib" "$delta_mib"
}

echo "=== Clean Release Build Time & Stripped Binary Size (--bin s-clip-3-macos-pasteboard, lto=thin, strip=true) ==="
printf "%-28s | %3s | %12s | %11s | %-21s | %s\n" \
    "Profile" "Dep" "Clean Build" "Size (B)" "Total Size" "Delta vs Baseline"
printf "%-28s-+-%3s-+-%12s-+-%11s-+-%-21s-+-%s\n" \
    "----------------------------" "---" "------------" "-----------" "---------------------" "-----------------------"

measure_profile "0-baseline"              --no-default-features
measure_profile "1-objc2-raw"             --no-default-features --features backend-objc2-raw
measure_profile "2-objc2-typed-surgical"  --no-default-features --features backend-objc2-typed
measure_profile "3-objc2-appkit-default"  --no-default-features --features backend-objc2-appkit-default
measure_profile "4-typed+img-png-tiff"    --no-default-features --features backend-objc2-typed,img-png-tiff
measure_profile "5-raw+img-full"          --no-default-features --features backend-objc2-raw,img-full
measure_profile "6-typed+img-full"        --no-default-features --features backend-objc2-typed,img-full
