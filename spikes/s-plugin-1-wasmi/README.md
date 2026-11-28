# S-Plugin-1 Prototype (`wasmi 2.0.3` + `'self'` Web Worker Zero-Import 3-Export ABI)

Isolated M5 Phase 0 Spike prototype for Issue #76. Excluded from the root Cargo workspace (`Cargo.toml` `exclude`), with zero changes to `crates/`, `cloud-cf/`, `web/`, or `evals/`.

## Contents

- `guest-calc/`: `#![no_std]` + `alloc` Core WASM `cdylib` (`34,099 B` / `33.30 KiB`, zero `wasm-bindgen`, zero imports) exporting `mynote_abi_version`, `mynote_alloc`, `mynote_invoke`, and `mynote_dealloc`. Implements scratchpad expression evaluation (`PluginResult::Gutter` / `ReplaceContent`) and RFC 8259 JSON canonicalization.
- `src/main.rs`: `wasmi = "2.0.3"` (`std`, `validate`, `portable-dispatch`) host runner, deterministic binary adversarial `.wasm` builders (`evil_import.wasm`, `infinite_loop.wasm`, `oom_grow_bomb.wasm`, `oom_init_bomb.wasm`, `multi_memory_bomb.wasm`), security gate assertions (`INV-PLUGIN-ZERO-IMPORT`, `INV-PLUGIN-RESOURCE-BOUND`), and 100-run cold/warm latency benchmarks.
- `plugin_worker.js` / `bench_main.js` / `bench_worker.html` / `bench_worker.py`: Playwright headless Chromium & WebKit `'self'` Web Worker harness under production CSP (`default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'`), including Section-5 linear memory clamping and `worker.terminate()` hard timeout recovery.
- `measure_binary_size.sh`: Copies the clean workspace to `/tmp/mynote-s-plugin-1-size-work`, builds `mynote-wasm` + `web/dist`, measures exact stripped release `mynote` binary size and interleaved 50-pair cold-start latency across 6 `wasmi` feature profiles, and deletes `/tmp/mynote-s-plugin-1-size-work` on exit.

## Reproduction Commands

```bash
# 1. Build guest-calc + adversarial fixtures, verify gates, and benchmark wasmi 2.0.3 (100 runs)
CARGO_TARGET_DIR=/tmp/mynote-s-plugin-1-target cargo run --manifest-path spikes/s-plugin-1-wasmi/Cargo.toml --release -- --runs 100
CARGO_TARGET_DIR=/tmp/mynote-s-plugin-1-target cargo test --manifest-path spikes/s-plugin-1-wasmi/Cargo.toml --release

# 2. Run Playwright headless Chromium & WebKit 'self' Web Worker suite (100 runs)
uv run --with playwright python3 spikes/s-plugin-1-wasmi/bench_worker.py --runs 100

# 3. Measure exact stripped release mynote binary size & cold-start delta in /tmp
./spikes/s-plugin-1-wasmi/measure_binary_size.sh
```
