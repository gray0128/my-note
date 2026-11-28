#!/usr/bin/env bash
# S-Plugin-1 (Issue #76): Measure exact stripped release `mynote` binary size delta
# and no-plugin CLI cold-start latency delta in an isolated `/tmp/mynote-s-plugin-1-size-work`
# copy, then delete `/tmp/mynote-s-plugin-1-size-work` on exit so workspace `crates/` stays 100% untouched.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK_DIR="/tmp/mynote-s-plugin-1-size-work"
TARGET_DIR="/tmp/mynote-s-plugin-1-size-target"
OUT_JSON="${1:-/tmp/s-plugin-1-size-report.json}"
GUEST_WASM="$REPO_ROOT/spikes/s-plugin-1-wasmi/fixtures/guest_calc.wasm"
LOOP_WASM="$REPO_ROOT/spikes/s-plugin-1-wasmi/fixtures/infinite_loop.wasm"

cleanup() {
  rm -rf "$WORK_DIR" "$TARGET_DIR"
}
trap cleanup EXIT

rm -rf "$WORK_DIR" "$TARGET_DIR"
mkdir -p "$WORK_DIR"

echo "[size] Copying clean workspace to $WORK_DIR ..."
rsync -a \
  --exclude='.git' \
  --exclude='target' \
  --exclude='spikes' \
  --exclude='web/node_modules' \
  --exclude='cloud-cf/node_modules' \
  "$REPO_ROOT/" "$WORK_DIR/"

echo "[size] Building mynote-wasm + production web/dist for RustEmbed ..."
pnpm --dir "$WORK_DIR/web" install --frozen-lockfile --prefer-offline >/dev/null
CARGO_TARGET_DIR="$TARGET_DIR" "$WORK_DIR/scripts/build-wasm.sh" >/dev/null
pnpm --dir "$WORK_DIR/web" build >/dev/null

cp "$WORK_DIR/Cargo.toml" "$WORK_DIR/Cargo.root.orig"
cp "$WORK_DIR/crates/mynote-cli/Cargo.toml" "$WORK_DIR/Cargo.cli.orig"
cp "$WORK_DIR/crates/mynote-cli/src/main.rs" "$WORK_DIR/main.rs.orig"

write_main_probe() {
  local mode="$1" # "safe" or "unchecked"
  if [[ "$mode" == "safe" ]]; then
    cat > "$WORK_DIR/crates/mynote-cli/src/main.rs" <<'EOF'
fn probe_wasmi_3export(wasm_path: &str) -> i32 {
    let bytes = std::fs::read(wasm_path).expect("read wasm");
    let mut cfg = wasmi::Config::default();
    cfg.consume_fuel(true);
    cfg.wasm_multi_memory(false);
    let engine = wasmi::Engine::new(&cfg);
    let module = wasmi::Module::new(&engine, &bytes).expect("validate wasm");
    assert_eq!(module.imports().len(), 0, "INV-PLUGIN-ZERO-IMPORT");
    let limits = wasmi::StoreLimitsBuilder::new()
        .memory_size(16 * 1024 * 1024)
        .memories(1)
        .trap_on_grow_failure(true)
        .build();
    let mut store = wasmi::Store::new(&engine, limits);
    store.limiter(|lim| lim);
    store.set_fuel(50_000_000).expect("set fuel");
    let instance = wasmi::Instance::new(&mut store, &module, &[]).expect("instantiate");
    let mem = instance.get_memory(&store, "memory").expect("memory");
    let abi = instance
        .get_typed_func::<(), u32>(&store, "mynote_abi_version")
        .expect("abi")
        .call(&mut store, ())
        .expect("call abi");
    assert_eq!(abi, 1);
    let req = br#"{"action":"eval_lines","content":"6*7"}"#;
    let ptr = instance
        .get_typed_func::<u32, u32>(&store, "mynote_alloc")
        .expect("alloc")
        .call(&mut store, req.len() as u32)
        .expect("call alloc");
    mem.write(&mut store, ptr as usize, req).expect("mem write");
    let packed = instance
        .get_typed_func::<(u32, u32), u64>(&store, "mynote_invoke")
        .expect("invoke")
        .call(&mut store, (ptr, req.len() as u32));
    match packed {
        Ok(v) => {
            let rptr = (v >> 32) as usize;
            let rlen = (v & 0xffff_ffff) as usize;
            let out = std::str::from_utf8(&mem.data(&store)[rptr..rptr + rlen]).expect("utf8");
            assert!(out.contains("42"), "unexpected output: {out}");
            if let Ok(dealloc) = instance.get_typed_func::<(u32, u32), ()>(&store, "mynote_dealloc") {
                let _ = dealloc.call(&mut store, (ptr, req.len() as u32));
                let _ = dealloc.call(&mut store, (rptr as u32, rlen as u32));
            }
            0
        }
        Err(e) => {
            if matches!(e.as_trap_code(), Some(wasmi::TrapCode::OutOfFuel)) {
                42
            } else {
                1
            }
        }
    }
}

fn main() {
    let mut args = std::env::args();
    let _bin = args.next();
    if let Some(first) = args.next() {
        if first == "--__spike-wasm-probe" {
            let p = args.next().expect("wasm path");
            std::process::exit(probe_wasmi_3export(&p));
        }
    }
    let code = mynote_cli::run();
    std::process::exit(code);
}
EOF
  else
    cat > "$WORK_DIR/crates/mynote-cli/src/main.rs" <<'EOF'
fn probe_wasmi_3export(wasm_path: &str) -> i32 {
    let bytes = std::fs::read(wasm_path).expect("read wasm");
    let mut cfg = wasmi::Config::default();
    cfg.consume_fuel(true);
    let engine = wasmi::Engine::new(&cfg);
    // Note: without feature = "validate", `Module::new` is absent; only `unsafe Module::new_unchecked` exists!
    let module = unsafe { wasmi::Module::new_unchecked(&engine, &bytes) }.expect("parse unchecked");
    assert_eq!(module.imports().len(), 0, "INV-PLUGIN-ZERO-IMPORT");
    let limits = wasmi::StoreLimitsBuilder::new()
        .memory_size(16 * 1024 * 1024)
        .memories(1)
        .trap_on_grow_failure(true)
        .build();
    let mut store = wasmi::Store::new(&engine, limits);
    store.limiter(|lim| lim);
    store.set_fuel(50_000_000).expect("set fuel");
    let instance = wasmi::Instance::new(&mut store, &module, &[]).expect("instantiate");
    let mem = instance.get_memory(&store, "memory").expect("memory");
    let abi = instance
        .get_typed_func::<(), u32>(&store, "mynote_abi_version")
        .expect("abi")
        .call(&mut store, ())
        .expect("call abi");
    assert_eq!(abi, 1);
    let req = br#"{"action":"eval_lines","content":"6*7"}"#;
    let ptr = instance
        .get_typed_func::<u32, u32>(&store, "mynote_alloc")
        .expect("alloc")
        .call(&mut store, req.len() as u32)
        .expect("call alloc");
    mem.write(&mut store, ptr as usize, req).expect("mem write");
    let packed = instance
        .get_typed_func::<(u32, u32), u64>(&store, "mynote_invoke")
        .expect("invoke")
        .call(&mut store, (ptr, req.len() as u32))
        .expect("call invoke");
    let rptr = (packed >> 32) as usize;
    let rlen = (packed & 0xffff_ffff) as usize;
    let out = std::str::from_utf8(&mem.data(&store)[rptr..rptr + rlen]).expect("utf8");
    assert!(out.contains("42"), "unexpected output: {out}");
    0
}

fn main() {
    let mut args = std::env::args();
    let _bin = args.next();
    if let Some(first) = args.next() {
        if first == "--__spike-wasm-probe" {
            let p = args.next().expect("wasm path");
            std::process::exit(probe_wasmi_3export(&p));
        }
    }
    let code = mynote_cli::run();
    std::process::exit(code);
}
EOF
  fi
}

build_variant() {
  local label="$1"
  local dep_line="$2"
  local probe_mode="$3" # "none" | "unchecked" | "safe"
  local opt_z="${4:-0}"

  cp "$WORK_DIR/Cargo.root.orig" "$WORK_DIR/Cargo.toml"
  cp "$WORK_DIR/Cargo.cli.orig" "$WORK_DIR/crates/mynote-cli/Cargo.toml"
  cp "$WORK_DIR/main.rs.orig" "$WORK_DIR/crates/mynote-cli/src/main.rs"

  if [[ "$opt_z" == "1" ]]; then
    python3 - "$WORK_DIR/Cargo.toml" <<'PY'
import sys
p = sys.argv[1]
txt = open(p, encoding="utf-8").read()
txt = txt.replace('[profile.release]\nlto = "thin"\nstrip = true', '[profile.release]\nopt-level = "z"\nlto = true\ncodegen-units = 1\nstrip = true', 1)
open(p, "w", encoding="utf-8").write(txt)
PY
  fi

  if [[ -n "$dep_line" ]]; then
    python3 - "$WORK_DIR/crates/mynote-cli/Cargo.toml" "$dep_line" <<'PY'
import sys
p, dep = sys.argv[1], sys.argv[2]
txt = open(p, encoding="utf-8").read()
txt = txt.replace("[dependencies]\n", f"[dependencies]\n{dep}\n", 1)
open(p, "w", encoding="utf-8").write(txt)
PY
  fi

  if [[ "$probe_mode" != "none" ]]; then
    write_main_probe "$probe_mode"
  fi

  echo "[size] Building variant: $label ..." >&2
  local t0
  t0=$(python3 -c 'import time; print(time.perf_counter())')
  CARGO_TARGET_DIR="$TARGET_DIR" cargo build --manifest-path "$WORK_DIR/Cargo.toml" --release --bin mynote >/dev/null 2>&1
  local elapsed
  elapsed=$(python3 -c "import time; print(round(time.perf_counter() - $t0, 3))")

  local bin="$TARGET_DIR/release/mynote"
  cp "$bin" "$WORK_DIR/mynote-$label"
  local bytes
  bytes=$(wc -c < "$WORK_DIR/mynote-$label" | tr -d ' ')

  local loop_probe_status="n/a"
  if [[ "$probe_mode" != "none" && -f "$GUEST_WASM" ]]; then
    "$WORK_DIR/mynote-$label" --__spike-wasm-probe "$GUEST_WASM"
    if [[ "$probe_mode" == "safe" && -f "$LOOP_WASM" ]]; then
      set +e
      "$WORK_DIR/mynote-$label" --__spike-wasm-probe "$LOOP_WASM" >/dev/null 2>&1
      local rc=$?
      set -e
      if [[ "$rc" -eq 42 ]]; then
        loop_probe_status="OutOfFuel_clean_trap"
      else
        loop_probe_status="exit_${rc}_crash"
      fi
    fi
  fi

  echo "$label|$bytes|$elapsed|$loop_probe_status"
}

R0=$(build_variant "0-baseline" "" "none")
R1=$(build_variant "1-std-unreferenced" 'wasmi = { version = "2.0.3", default-features = false, features = ["std"] }' "none")
R2=$(build_variant "2-std-linked-unchecked" 'wasmi = { version = "2.0.3", default-features = false, features = ["std"] }' "unchecked")
R3=$(build_variant "3-std-validate-tail-linked" 'wasmi = { version = "2.0.3", default-features = false, features = ["std", "validate"] }' "safe")
R4=$(build_variant "4-std-validate-portable-linked" 'wasmi = { version = "2.0.3", default-features = false, features = ["std", "validate", "portable-dispatch"] }' "safe")
R5=$(build_variant "5-default-features-linked" 'wasmi = "2.0.3"' "safe")
R6=$(build_variant "6-std-validate-portable-optz" 'wasmi = { version = "2.0.3", default-features = false, features = ["std", "validate", "portable-dispatch"] }' "safe" "1")

echo "[size] Benchmarking interleaved no-plugin CLI cold-start latency (50 pairs) ..."
python3 - "$WORK_DIR" "$OUT_JSON" "$R0" "$R1" "$R2" "$R3" "$R4" "$R5" "$R6" <<'PY'
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

work_dir = Path(sys.argv[1])
out_json = Path(sys.argv[2])
raw_rows = sys.argv[3:]

BUDGET_BYTES = 15 * 1024 * 1024  # 15 MiB

variants = []
base_bytes = None
for r in raw_rows:
    label, b_str, sec_str, loop_status = r.split("|")
    b = int(b_str)
    if base_bytes is None:
        base_bytes = b
    delta = b - base_bytes
    variants.append({
        "label": label,
        "bytes": b,
        "kib": round(b / 1024.0, 2),
        "mib": round(b / (1024.0 * 1024.0), 3),
        "delta_bytes": delta,
        "delta_kib": round(delta / 1024.0, 2),
        "delta_mib": round(delta / (1024.0 * 1024.0), 3),
        "under_15_mib": b < BUDGET_BYTES,
        "headroom_bytes": BUDGET_BYTES - b,
        "headroom_mib": round((BUDGET_BYTES - b) / (1024.0 * 1024.0), 3),
        "incremental_build_s": float(sec_str),
        "infinite_loop_50m_fuel_probe": loop_status,
    })

bin_base = str(work_dir / "mynote-0-baseline")
bin_wasmi = str(work_dir / "mynote-4-std-validate-portable-linked")

def summarize_ms(samples):
    s = sorted(samples)
    n = len(s)
    p50 = s[n // 2] if n % 2 == 1 else (s[n // 2 - 1] + s[n // 2]) / 2.0
    p95 = s[min(n - 1, max(0, int(n * 0.95 + 0.9999) - 1))]
    return {
        "runs": n,
        "min_ms": round(s[0], 3),
        "p50_ms": round(p50, 3),
        "p95_ms": round(p95, 3),
        "max_ms": round(s[-1], 3),
    }

with tempfile.TemporaryDirectory(prefix="mynote-coldstart-") as tmpd:
    env_a = {**os.environ, "HOME": tmpd, "XDG_DATA_HOME": f"{tmpd}/data_a", "XDG_CONFIG_HOME": f"{tmpd}/cfg_a"}
    env_b = {**os.environ, "HOME": tmpd, "XDG_DATA_HOME": f"{tmpd}/data_b", "XDG_CONFIG_HOME": f"{tmpd}/cfg_b"}
    # Seed 1 block in each isolated SQLite WAL store so `ls --json` touches real SQLite
    subprocess.run([bin_base, "add", "seed block", "--json"], env=env_a, check=True, stdout=subprocess.DEVNULL)
    subprocess.run([bin_wasmi, "add", "seed block", "--json"], env=env_b, check=True, stdout=subprocess.DEVNULL)

    # Warmup
    for _ in range(5):
        subprocess.run([bin_base, "ls", "--json"], env=env_a, check=True, stdout=subprocess.DEVNULL)
        subprocess.run([bin_wasmi, "ls", "--json"], env=env_b, check=True, stdout=subprocess.DEVNULL)

    ver_a, ver_b = [], []
    ls_a, ls_b = [], []
    for i in range(50):
        if i % 2 == 0:
            t0 = time.perf_counter(); subprocess.run([bin_base, "--version"], env=env_a, check=True, stdout=subprocess.DEVNULL); ver_a.append((time.perf_counter() - t0) * 1000.0)
            t0 = time.perf_counter(); subprocess.run([bin_wasmi, "--version"], env=env_b, check=True, stdout=subprocess.DEVNULL); ver_b.append((time.perf_counter() - t0) * 1000.0)
            t0 = time.perf_counter(); subprocess.run([bin_base, "ls", "--json"], env=env_a, check=True, stdout=subprocess.DEVNULL); ls_a.append((time.perf_counter() - t0) * 1000.0)
            t0 = time.perf_counter(); subprocess.run([bin_wasmi, "ls", "--json"], env=env_b, check=True, stdout=subprocess.DEVNULL); ls_b.append((time.perf_counter() - t0) * 1000.0)
        else:
            t0 = time.perf_counter(); subprocess.run([bin_wasmi, "--version"], env=env_b, check=True, stdout=subprocess.DEVNULL); ver_b.append((time.perf_counter() - t0) * 1000.0)
            t0 = time.perf_counter(); subprocess.run([bin_base, "--version"], env=env_a, check=True, stdout=subprocess.DEVNULL); ver_a.append((time.perf_counter() - t0) * 1000.0)
            t0 = time.perf_counter(); subprocess.run([bin_wasmi, "ls", "--json"], env=env_b, check=True, stdout=subprocess.DEVNULL); ls_b.append((time.perf_counter() - t0) * 1000.0)
            t0 = time.perf_counter(); subprocess.run([bin_base, "ls", "--json"], env=env_a, check=True, stdout=subprocess.DEVNULL); ls_a.append((time.perf_counter() - t0) * 1000.0)

sa_ver, sb_ver = summarize_ms(ver_a), summarize_ms(ver_b)
sa_ls, sb_ls = summarize_ms(ls_a), summarize_ms(ls_b)

report = {
    "budget_bytes": BUDGET_BYTES,
    "variants": variants,
    "cold_start_no_plugin": {
        "version_baseline": sa_ver,
        "version_plus_wasmi": sb_ver,
        "version_delta_p50_ms": round(sb_ver["p50_ms"] - sa_ver["p50_ms"], 3),
        "ls_json_baseline": sa_ls,
        "ls_json_plus_wasmi": sb_ls,
        "ls_json_delta_p50_ms": round(sb_ls["p50_ms"] - sa_ls["p50_ms"], 3),
        "under_1ms_target": (sb_ls["p50_ms"] - sa_ls["p50_ms"]) < 1.0,
    },
}

out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report, indent=2))
PY
