//! S-Plugin-1 (`wasmi 2.0.3`) Host Runner, Security Gate Verifier, and Latency Benchmark.
//!
//! Verifies:
//! 1. `INV-PLUGIN-ZERO-IMPORT`: `module.imports().len() == 0` enforced BEFORE instantiation;
//!    non-empty import modules (`env.evil` + `wasi_snapshot_preview1.fd_write`) are 100% rejected
//!    with `PLUGIN_INVALID_MANIFEST` and zero instantiations.
//! 2. `INV-PLUGIN-RESOURCE-BOUND`:
//!    - Fuel limit (`50_000_000`) deterministically aborts infinite loop (`TrapCode::OutOfFuel`)
//!      with `PLUGIN_RESOURCE_EXCEEDED`;
//!    - `StoreLimitsBuilder::new().memory_size(16 * 1024 * 1024).memories(1).trap_on_grow_failure(true)`
//!      deterministically aborts `> 16 MiB` `memory.grow` bombs, initial-memory bombs, and
//!      multi-memory bypass attempts with `PLUGIN_RESOURCE_EXCEEDED`;
//!    - Subsequent clean plugin calls on the same `Engine` / `Module` succeed unaffected.
//! 3. Cold compile (`Module::new`, `LazyTranslation` vs `Eager`) + cached warm invoke latency
//!    (min / median / p95 / max across 100 runs) on real scratchpad math (`~260 B`) and JSON (`~16 KiB`) payloads.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use wasmi::{
    CompilationMode, Config, Engine, Error as WasmiError, Instance, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder, TrapCode,
};

pub const DEFAULT_FUEL_LIMIT: u64 = 50_000_000;
pub const DEFAULT_MEMORY_LIMIT_BYTES: usize = 16 * 1024 * 1024; // 16 MiB (256 pages)
pub const EXPECTED_ABI_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginHostError {
    pub code: &'static str,
    pub detail: String,
}

impl PluginHostError {
    fn invalid_manifest(detail: impl Into<String>) -> Self {
        Self {
            code: "PLUGIN_INVALID_MANIFEST",
            detail: detail.into(),
        }
    }

    fn resource_exceeded(detail: impl Into<String>) -> Self {
        Self {
            code: "PLUGIN_RESOURCE_EXCEEDED",
            detail: detail.into(),
        }
    }

    fn execution_failed(detail: impl Into<String>) -> Self {
        Self {
            code: "PLUGIN_EXECUTION_FAILED",
            detail: detail.into(),
        }
    }
}

struct StoreState {
    limits: StoreLimits,
}

pub struct WasmPluginHost {
    engine: Engine,
    fuel_limit: u64,
    memory_limit_bytes: usize,
    instantiation_count: AtomicUsize,
}

pub struct ValidatedPluginModule {
    module: Module,
}

#[derive(Debug, Clone, Serialize)]
pub struct InvokeOutcome {
    pub response_json: String,
    pub fuel_consumed: u64,
    pub final_memory_bytes: usize,
}

impl WasmPluginHost {
    pub fn new(compilation_mode: CompilationMode) -> Self {
        let mut config = Config::default();
        config.consume_fuel(true);
        config.wasm_multi_memory(false);
        config.compilation_mode(compilation_mode);
        let engine = Engine::new(&config);
        Self {
            engine,
            fuel_limit: DEFAULT_FUEL_LIMIT,
            memory_limit_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
            instantiation_count: AtomicUsize::new(0),
        }
    }

    pub fn instantiation_count(&self) -> usize {
        self.instantiation_count.load(Ordering::SeqCst)
    }

    /// Compiles and validates a Core WASM binary, enforcing `INV-PLUGIN-ZERO-IMPORT`
    /// (`module.imports().len() == 0`) BEFORE any `Store` or `Instance` can be created.
    pub fn load_and_verify_zero_import(
        &self,
        wasm_bytes: &[u8],
    ) -> Result<ValidatedPluginModule, PluginHostError> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| PluginHostError::invalid_manifest(format!("WASM validation failed: {e}")))?;

        let import_count = module.imports().len();
        if import_count != 0 {
            let names: Vec<String> = module
                .imports()
                .take(8)
                .map(|imp| format!("{}::{}", imp.module(), imp.name()))
                .collect();
            return Err(PluginHostError::invalid_manifest(format!(
                "INV-PLUGIN-ZERO-IMPORT violated: module declares {import_count} import(s): [{}]",
                names.join(", ")
            )));
        }

        Ok(ValidatedPluginModule { module })
    }

    fn new_bounded_store(&self) -> Result<Store<StoreState>, PluginHostError> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.memory_limit_bytes)
            .memories(1)
            .tables(2)
            .table_elements(4_096)
            .instances(1)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(&self.engine, StoreState { limits });
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.fuel_limit)
            .map_err(|e| PluginHostError::execution_failed(format!("set_fuel failed: {e}")))?;
        Ok(store)
    }

    /// Executes a single isolated plugin call with a fresh bounded `Store` + `Instance`.
    pub fn invoke_fresh_instance(
        &self,
        validated: &ValidatedPluginModule,
        request_json: &[u8],
    ) -> Result<InvokeOutcome, PluginHostError> {
        let mut store = self.new_bounded_store()?;
        self.instantiation_count.fetch_add(1, Ordering::SeqCst);
        let instance = Instance::new(&mut store, &validated.module, &[])
            .map_err(|e| classify_wasmi_error("instantiation", e))?;
        self.invoke_on_instance(&mut store, &instance, request_json)
    }

    fn invoke_on_instance(
        &self,
        store: &mut Store<StoreState>,
        instance: &Instance,
        request_json: &[u8],
    ) -> Result<InvokeOutcome, PluginHostError> {
        store
            .set_fuel(self.fuel_limit)
            .map_err(|e| PluginHostError::execution_failed(format!("set_fuel failed: {e}")))?;

        let memory: Memory = instance
            .get_memory(&*store, "memory")
            .ok_or_else(|| PluginHostError::invalid_manifest("missing exported `memory`"))?;

        let fn_abi = instance
            .get_typed_func::<(), u32>(&*store, "mynote_abi_version")
            .map_err(|e| {
                PluginHostError::invalid_manifest(format!(
                    "missing or invalid `mynote_abi_version() -> u32`: {e}"
                ))
            })?;
        let fn_alloc = instance
            .get_typed_func::<u32, u32>(&*store, "mynote_alloc")
            .map_err(|e| {
                PluginHostError::invalid_manifest(format!(
                    "missing or invalid `mynote_alloc(u32) -> u32`: {e}"
                ))
            })?;
        let fn_invoke = instance
            .get_typed_func::<(u32, u32), u64>(&*store, "mynote_invoke")
            .map_err(|e| {
                PluginHostError::invalid_manifest(format!(
                    "missing or invalid `mynote_invoke(u32, u32) -> u64`: {e}"
                ))
            })?;
        let fn_dealloc = instance
            .get_typed_func::<(u32, u32), ()>(&*store, "mynote_dealloc")
            .ok();

        let abi_ver = fn_abi
            .call(&mut *store, ())
            .map_err(|e| classify_wasmi_error("mynote_abi_version", e))?;
        if abi_ver != EXPECTED_ABI_VERSION {
            return Err(PluginHostError::invalid_manifest(format!(
                "ABI version mismatch: expected {EXPECTED_ABI_VERSION}, got {abi_ver}"
            )));
        }

        let req_len = u32::try_from(request_json.len())
            .map_err(|_| PluginHostError::execution_failed("request exceeds u32::MAX"))?;
        let req_ptr = fn_alloc
            .call(&mut *store, req_len)
            .map_err(|e| classify_wasmi_error("mynote_alloc", e))?;
        if req_len > 0 && req_ptr == 0 {
            return Err(PluginHostError::resource_exceeded(
                "mynote_alloc returned null (0) for non-empty request",
            ));
        }

        if req_len > 0 {
            memory
                .write(&mut *store, req_ptr as usize, request_json)
                .map_err(|e| {
                    PluginHostError::execution_failed(format!("request memory write out of bounds: {e}"))
                })?;
        }

        let packed = fn_invoke
            .call(&mut *store, (req_ptr, req_len))
            .map_err(|e| classify_wasmi_error("mynote_invoke", e))?;

        let resp_ptr = (packed >> 32) as usize;
        let resp_len = (packed & 0xffff_ffff) as usize;

        let mem_slice = memory.data(&*store);
        let resp_end = resp_ptr
            .checked_add(resp_len)
            .ok_or_else(|| PluginHostError::execution_failed("response pointer overflow"))?;
        if resp_end > mem_slice.len() {
            return Err(PluginHostError::execution_failed(format!(
                "response slice {resp_ptr}..{resp_end} exceeds linear memory ({} B)",
                mem_slice.len()
            )));
        }
        let resp_bytes = mem_slice[resp_ptr..resp_end].to_vec();

        if let Some(dealloc) = &fn_dealloc {
            if req_len > 0 {
                let _ = dealloc.call(&mut *store, (req_ptr, req_len));
            }
            if resp_len > 0 {
                let _ = dealloc.call(&mut *store, (resp_ptr as u32, resp_len as u32));
            }
        }

        let response_json = String::from_utf8(resp_bytes)
            .map_err(|_| PluginHostError::execution_failed("plugin returned invalid UTF-8 response"))?;
        let remaining_fuel = store.get_fuel().unwrap_or(self.fuel_limit);
        let fuel_consumed = self.fuel_limit.saturating_sub(remaining_fuel);
        let final_memory_bytes = memory.data_size(&*store);

        Ok(InvokeOutcome {
            response_json,
            fuel_consumed,
            final_memory_bytes,
        })
    }
}

fn classify_wasmi_error(stage: &str, err: WasmiError) -> PluginHostError {
    if let Some(trap_code) = err.as_trap_code() {
        if matches!(trap_code, TrapCode::OutOfFuel) {
            return PluginHostError::resource_exceeded(format!(
                "{stage} trapped with TrapCode::OutOfFuel: {err}"
            ));
        }
    }
    let msg = err.to_string();
    let lower = msg.to_ascii_lowercase();
    if lower.contains("fuel")
        || lower.contains("limiter")
        || lower.contains("memory")
        || lower.contains("grow")
        || lower.contains("allocation")
    {
        return PluginHostError::resource_exceeded(format!("{stage} hit resource bound: {msg}"));
    }
    PluginHostError::execution_failed(format!("{stage} failed: {msg}"))
}

// --- Deterministic binary `.wasm` adversarial fixture builders (zero external `wat` dep) ---

fn push_leb_u32(buf: &mut Vec<u8>, mut val: u32) {
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}

fn push_wasm_name(buf: &mut Vec<u8>, s: &str) {
    push_leb_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

fn push_section(wasm: &mut Vec<u8>, section_id: u8, payload: &[u8]) {
    wasm.push(section_id);
    push_leb_u32(wasm, payload.len() as u32);
    wasm.extend_from_slice(payload);
}

/// Adversarial Fixture (a): Non-empty imports (`(import "env" "evil" ...)` + WASI `fd_write`).
pub fn build_evil_import_wasm() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\x00\x00\x00".to_vec();

    // Section 1: Type — 0: (i32) -> (), 1: (i32,i32,i32,i32) -> i32, 2: () -> i32
    let mut ty = Vec::new();
    push_leb_u32(&mut ty, 3);
    ty.extend_from_slice(&[0x60, 0x01, 0x7f, 0x00]);
    ty.extend_from_slice(&[0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f]);
    ty.extend_from_slice(&[0x60, 0x00, 0x01, 0x7f]);
    push_section(&mut wasm, 1, &ty);

    // Section 2: Import — `env.evil` + `wasi_snapshot_preview1.fd_write`
    let mut imp = Vec::new();
    push_leb_u32(&mut imp, 2);
    push_wasm_name(&mut imp, "env");
    push_wasm_name(&mut imp, "evil");
    imp.extend_from_slice(&[0x00, 0x00]); // func type 0
    push_wasm_name(&mut imp, "wasi_snapshot_preview1");
    push_wasm_name(&mut imp, "fd_write");
    imp.extend_from_slice(&[0x00, 0x01]); // func type 1
    push_section(&mut wasm, 2, &imp);

    // Section 3: Function — internal func idx 2 (`mynote_abi_version`) has type 2
    push_section(&mut wasm, 3, &[0x01, 0x02]);

    // Section 5: Memory — 1 memory, initial=1 page
    push_section(&mut wasm, 5, &[0x01, 0x00, 0x01]);

    // Section 7: Export — `memory` (mem 0) + `mynote_abi_version` (func 2)
    let mut exp = Vec::new();
    push_leb_u32(&mut exp, 2);
    push_wasm_name(&mut exp, "memory");
    exp.extend_from_slice(&[0x02, 0x00]);
    push_wasm_name(&mut exp, "mynote_abi_version");
    exp.extend_from_slice(&[0x00, 0x02]);
    push_section(&mut wasm, 7, &exp);

    // Section 10: Code — `i32.const 1; end`
    push_section(&mut wasm, 10, &[0x01, 0x04, 0x00, 0x41, 0x01, 0x0b]);

    wasm
}

fn build_3export_shell_wasm(mem_limits_bytes: &[u8], invoke_body_opcodes: &[u8]) -> Vec<u8> {
    let mut wasm = b"\0asm\x01\x00\x00\x00".to_vec();

    // Section 1: Types
    // 0: () -> i32 (`mynote_abi_version`)
    // 1: (i32) -> i32 (`mynote_alloc`)
    // 2: (i32, i32) -> i64 (`mynote_invoke`)
    // 3: (i32, i32) -> () (`mynote_dealloc`)
    let mut ty = Vec::new();
    push_leb_u32(&mut ty, 4);
    ty.extend_from_slice(&[0x60, 0x00, 0x01, 0x7f]);
    ty.extend_from_slice(&[0x60, 0x01, 0x7f, 0x01, 0x7f]);
    ty.extend_from_slice(&[0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e]);
    ty.extend_from_slice(&[0x60, 0x02, 0x7f, 0x7f, 0x00]);
    push_section(&mut wasm, 1, &ty);

    // Section 3: Functions [0, 1, 2, 3]
    push_section(&mut wasm, 3, &[0x04, 0x00, 0x01, 0x02, 0x03]);

    // Section 5: Memory
    push_section(&mut wasm, 5, mem_limits_bytes);

    // Section 7: Exports
    let mut exp = Vec::new();
    push_leb_u32(&mut exp, 5);
    push_wasm_name(&mut exp, "memory");
    exp.extend_from_slice(&[0x02, 0x00]);
    push_wasm_name(&mut exp, "mynote_abi_version");
    exp.extend_from_slice(&[0x00, 0x00]);
    push_wasm_name(&mut exp, "mynote_alloc");
    exp.extend_from_slice(&[0x00, 0x01]);
    push_wasm_name(&mut exp, "mynote_invoke");
    exp.extend_from_slice(&[0x00, 0x02]);
    push_wasm_name(&mut exp, "mynote_dealloc");
    exp.extend_from_slice(&[0x00, 0x03]);
    push_section(&mut wasm, 7, &exp);

    // Section 10: Code
    let mut code = Vec::new();
    push_leb_u32(&mut code, 4);
    // func 0: () -> 1
    code.extend_from_slice(&[0x04, 0x00, 0x41, 0x01, 0x0b]);
    // func 1: (len) -> 1024
    code.extend_from_slice(&[0x05, 0x00, 0x41, 0x80, 0x08, 0x0b]);
    // func 2: invoke body (0 locals + opcodes + end)
    let mut f2 = Vec::with_capacity(2 + invoke_body_opcodes.len());
    f2.push(0x00); // 0 locals
    f2.extend_from_slice(invoke_body_opcodes);
    f2.push(0x0b); // end func
    push_leb_u32(&mut code, f2.len() as u32);
    code.extend_from_slice(&f2);
    // func 3: dealloc nop
    code.extend_from_slice(&[0x02, 0x00, 0x0b]);
    push_section(&mut wasm, 10, &code);

    wasm
}

/// Adversarial Fixture (b1): Zero-import infinite loop `(loop (result i64) (br 0))`.
pub fn build_infinite_loop_wasm() -> Vec<u8> {
    // Memory: 1 memory, flags=0x01 (has max), min=1, max=256 (0x80, 0x02)
    let mem = [0x01, 0x01, 0x01, 0x80, 0x02];
    // `(loop (result i64) (br 0))` -> 0x03, 0x7e, 0x0c, 0x00, 0x0b
    let body = [0x03, 0x7e, 0x0c, 0x00, 0x0b];
    build_3export_shell_wasm(&mem, &body)
}

/// Adversarial Fixture (b2): Zero-import OOM `memory.grow(300)` (`18.75 MiB > 16 MiB`) bomb.
/// Declares unbounded `(memory 1)` (`flags=0x00, min=1`).
/// If host allows `memory.grow(300)`, writes `42` at `18 MiB` and returns `0`; if denied (`-1`), traps.
pub fn build_oom_grow_bomb_wasm() -> Vec<u8> {
    let mem = [0x01, 0x00, 0x01]; // 1 memory, unbounded max, initial=1 page
    let body = [
        0x41, 0xac, 0x02, // i32.const 300 (18.75 MiB)
        0x40, 0x00, // memory.grow 0
        0x41, 0x00, // i32.const 0
        0x48, // i32.lt_s
        0x04, 0x40, // if (empty)
        0x00, // unreachable
        0x0b, // end if
        0x41, 0x80, 0x80, 0x80, 0x09, // i32.const 18874368 (18 MiB)
        0x41, 0x2a, // i32.const 42
        0x3a, 0x00, 0x00, // i32.store8 align=0 offset=0
        0x42, 0x00, // i64.const 0
    ];
    build_3export_shell_wasm(&mem, &body)
}

/// Adversarial Fixture (b3): Initial memory > 16 MiB (`257` pages = `16.0625 MiB`).
pub fn build_oom_init_bomb_wasm() -> Vec<u8> {
    // 257 in unsigned LEB128 = [0x81, 0x02]
    let mem = [0x01, 0x00, 0x81, 0x02];
    let body = [0x42, 0x00]; // i64.const 0
    build_3export_shell_wasm(&mem, &body)
}

/// Adversarial Fixture (b4): Multi-memory bypass (`2` memories of `192` pages = `12 MiB` each -> `24 MiB` total).
pub fn build_multi_memory_bomb_wasm() -> Vec<u8> {
    // 2 memories, each initial=192 pages (`0xc0, 0x01` = 12 MiB <= 16 MiB individually, 24 MiB combined)
    let mem = [0x02, 0x00, 0xc0, 0x01, 0x00, 0xc0, 0x01];
    let body = [0x42, 0x00];
    build_3export_shell_wasm(&mem, &body)
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencySummaryUs {
    pub runs: usize,
    pub min_us: f64,
    pub p50_us: f64,
    pub p95_us: f64,
    pub max_us: f64,
    pub mean_us: f64,
}

fn summarize_samples_ns(mut samples_ns: Vec<u128>) -> LatencySummaryUs {
    samples_ns.sort_unstable();
    let n = samples_ns.len();
    let to_us = |ns: u128| (ns as f64) / 1_000.0;
    let p50_ns = if n % 2 == 1 {
        samples_ns[n / 2] as f64
    } else {
        (samples_ns[n / 2 - 1] as f64 + samples_ns[n / 2] as f64) / 2.0
    };
    let p95_idx = ((n as f64 * 0.95).ceil() as usize).saturating_sub(1).min(n - 1);
    let sum_ns: u128 = samples_ns.iter().copied().sum();
    LatencySummaryUs {
        runs: n,
        min_us: to_us(samples_ns[0]),
        p50_us: p50_ns / 1_000.0,
        p95_us: to_us(samples_ns[p95_idx]),
        max_us: to_us(samples_ns[n - 1]),
        mean_us: (sum_ns as f64) / (n as f64) / 1_000.0,
    }
}

#[derive(Debug, Deserialize)]
struct GutterResponseCheck {
    kind: String,
    annotations: Vec<GutterItemCheck>,
}

#[derive(Debug, Deserialize)]
struct GutterItemCheck {
    line: u32,
    text: String,
    copy: String,
}

#[derive(Debug, Deserialize)]
struct ReplaceResponseCheck {
    kind: String,
    content: String,
    lang: String,
}

#[derive(Debug, Serialize)]
struct FullSpikeReport {
    guest_wasm_bytes: usize,
    guest_wasm_kib: f64,
    guest_under_50_kib: bool,
    evil_import_wasm_bytes: usize,
    infinite_loop_wasm_bytes: usize,
    oom_grow_bomb_wasm_bytes: usize,
    security_gates: SecurityGateResults,
    benchmarks: BenchmarkMatrix,
}

#[derive(Debug, Serialize)]
struct SecurityGateResults {
    evil_import_rejected_before_instantiation: bool,
    evil_import_error_code: &'static str,
    evil_import_error_detail: String,
    evil_import_instantiation_count: usize,
    infinite_loop_trapped: bool,
    infinite_loop_error_code: &'static str,
    infinite_loop_error_detail: String,
    infinite_loop_abort_ms: f64,
    oom_grow_bomb_trapped: bool,
    oom_grow_bomb_error_code: &'static str,
    oom_grow_bomb_error_detail: String,
    oom_grow_bomb_abort_us: f64,
    oom_init_bomb_rejected: bool,
    oom_init_bomb_error_code: &'static str,
    multi_memory_bomb_rejected: bool,
    post_trap_clean_recovery_ok: bool,
}

#[derive(Debug, Serialize)]
struct BenchmarkMatrix {
    small_math_payload_bytes: usize,
    medium_json_payload_bytes: usize,
    cold_compile_only_lazy: LatencySummaryUs,
    cold_compile_only_eager: LatencySummaryUs,
    cold_compile_plus_first_invoke_lazy: LatencySummaryUs,
    cold_compile_plus_first_invoke_eager: LatencySummaryUs,
    warm_cached_module_fresh_store_math: WarmBenchEntry,
    warm_cached_module_fresh_store_json16k: WarmBenchEntry,
    warm_reused_instance_math: WarmBenchEntry,
    warm_reused_instance_json16k: WarmBenchEntry,
}

#[derive(Debug, Serialize)]
struct WarmBenchEntry {
    latency: LatencySummaryUs,
    fuel_consumed: u64,
    final_memory_bytes: usize,
    output_bytes: usize,
}

fn ensure_guest_wasm_and_fixtures(spike_dir: &Path) -> (Vec<u8>, PathBuf) {
    let fixtures_dir = spike_dir.join("fixtures");
    fs::create_dir_all(&fixtures_dir).expect("create fixtures dir");

    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/mynote-s-plugin-1-target"))
        .join("guest-wasm");

    let status = Command::new("cargo")
        .args([
            "build",
            "--manifest-path",
            spike_dir.join("guest-calc/Cargo.toml").to_str().unwrap(),
            "--target",
            "wasm32-unknown-unknown",
            "--release",
        ])
        .env("CARGO_TARGET_DIR", &target_dir)
        .status()
        .expect("spawn cargo build for guest-calc");
    assert!(status.success(), "guest-calc wasm32 build failed");

    let built_wasm = target_dir.join("wasm32-unknown-unknown/release/mynote_s_plugin_1_guest_calc.wasm");
    let guest_bytes = fs::read(&built_wasm).expect("read compiled guest wasm");

    let guest_fixture_path = fixtures_dir.join("guest_calc.wasm");
    fs::write(&guest_fixture_path, &guest_bytes).expect("write fixtures/guest_calc.wasm");
    fs::write(fixtures_dir.join("evil_import.wasm"), build_evil_import_wasm())
        .expect("write fixtures/evil_import.wasm");
    fs::write(
        fixtures_dir.join("infinite_loop.wasm"),
        build_infinite_loop_wasm(),
    )
    .expect("write fixtures/infinite_loop.wasm");
    fs::write(
        fixtures_dir.join("oom_grow_bomb.wasm"),
        build_oom_grow_bomb_wasm(),
    )
    .expect("write fixtures/oom_grow_bomb.wasm");
    fs::write(
        fixtures_dir.join("oom_init_bomb.wasm"),
        build_oom_init_bomb_wasm(),
    )
    .expect("write fixtures/oom_init_bomb.wasm");
    fs::write(
        fixtures_dir.join("multi_memory_bomb.wasm"),
        build_multi_memory_bomb_wasm(),
    )
    .expect("write fixtures/multi_memory_bomb.wasm");

    (guest_bytes, fixtures_dir)
}

fn build_16k_json_request() -> Vec<u8> {
    let mut inner_entries = Vec::new();
    for i in (0..180).rev() {
        inner_entries.push(format!(
            "\"key_{i:03}\":{{\"seq\":{i},\"active\":{},\"tag\":\"block_item_{i:03}\",\"ratio\":{}.{}}}",
            if i % 2 == 0 { "true" } else { "false" },
            i % 17,
            (i * 7) % 100
        ));
    }
    let messy_json = format!(
        "{{\"zeta\":[1,2,3],{},\"alpha\":\"first\"}}",
        inner_entries.join(",")
    );
    serde_json::to_vec(&serde_json::json!({
        "slot": "transform",
        "action": "json_canonicalize",
        "content": messy_json,
    }))
    .expect("serialize 16k json request")
}

fn run_full_suite(runs: usize) -> FullSpikeReport {
    let spike_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let (guest_bytes, _fixtures_dir) = ensure_guest_wasm_and_fixtures(&spike_dir);
    assert!(
        guest_bytes.len() < 50 * 1024,
        "guest_calc.wasm ({} B) exceeds < 50 KiB hard target!",
        guest_bytes.len()
    );

    let evil_import = build_evil_import_wasm();
    let infinite_loop = build_infinite_loop_wasm();
    let oom_grow_bomb = build_oom_grow_bomb_wasm();
    let oom_init_bomb = build_oom_init_bomb_wasm();
    let multi_mem_bomb = build_multi_memory_bomb_wasm();

    // 1. Security Gate Verification
    let gate_host = WasmPluginHost::new(CompilationMode::LazyTranslation);
    let import_err = gate_host
        .load_and_verify_zero_import(&evil_import)
        .err()
        .expect("evil_import.wasm MUST be rejected before instantiation");
    assert_eq!(import_err.code, "PLUGIN_INVALID_MANIFEST");
    let evil_inst_count = gate_host.instantiation_count();
    assert_eq!(evil_inst_count, 0);

    let loop_mod = gate_host
        .load_and_verify_zero_import(&infinite_loop)
        .expect("infinite_loop.wasm has zero imports");
    let t_loop = Instant::now();
    let loop_err = gate_host
        .invoke_fresh_instance(&loop_mod, br#"{"action":"eval_lines","content":"1+1"}"#)
        .expect_err("infinite_loop.wasm MUST trap on fuel exhaustion");
    let loop_abort_ms = t_loop.elapsed().as_secs_f64() * 1_000.0;
    assert_eq!(loop_err.code, "PLUGIN_RESOURCE_EXCEEDED");

    let oom_mod = gate_host
        .load_and_verify_zero_import(&oom_grow_bomb)
        .expect("oom_grow_bomb.wasm has zero imports");
    let t_oom = Instant::now();
    let oom_err = gate_host
        .invoke_fresh_instance(&oom_mod, br#"{"action":"eval_lines","content":"1+1"}"#)
        .expect_err("oom_grow_bomb.wasm MUST trap on >16 MiB StoreLimits");
    let oom_abort_us = t_oom.elapsed().as_secs_f64() * 1_000_000.0;
    assert_eq!(oom_err.code, "PLUGIN_RESOURCE_EXCEEDED");

    let oom_init_mod = gate_host
        .load_and_verify_zero_import(&oom_init_bomb)
        .expect("oom_init_bomb.wasm has zero imports");
    let oom_init_err = gate_host
        .invoke_fresh_instance(&oom_init_mod, b"{}")
        .expect_err("oom_init_bomb.wasm MUST fail instantiation >16 MiB");
    assert_eq!(oom_init_err.code, "PLUGIN_RESOURCE_EXCEEDED");

    let multi_mem_rejected = gate_host.load_and_verify_zero_import(&multi_mem_bomb).is_err();
    assert!(multi_mem_rejected, "multi_memory_bomb.wasm MUST be rejected");

    // Verify clean recovery on the exact same host right after traps
    let valid_mod = gate_host
        .load_and_verify_zero_import(&guest_bytes)
        .expect("guest_calc.wasm must validate cleanly");

    let math_req = serde_json::to_vec(&serde_json::json!({
        "slot": "inspector",
        "action": "eval_lines",
        "content": "unit_price = 19.99 * 3\ntax = round(unit_price * 8) / 100\nshipping = sqrt(144) + 2^3\ntotal = unit_price + tax + shipping\nmargin_pct = round((total - 45) / total * 1000) / 10"
    }))
    .unwrap();

    let recovery_out = gate_host
        .invoke_fresh_instance(&valid_mod, &math_req)
        .expect("clean plugin call after traps must succeed");
    let parsed_gutter: GutterResponseCheck =
        serde_json::from_str(&recovery_out.response_json).expect("valid Gutter PluginResult JSON");
    assert_eq!(parsed_gutter.kind, "gutter");
    assert_eq!(parsed_gutter.annotations.len(), 5);
    assert_eq!(parsed_gutter.annotations[0].line, 1);
    assert_eq!(parsed_gutter.annotations[0].copy, "59.97");
    assert_eq!(parsed_gutter.annotations[0].text, "= 59.97");
    assert_eq!(parsed_gutter.annotations[2].copy, "20");
    assert_eq!(parsed_gutter.annotations[3].copy, "84.77");

    let json16k_req = build_16k_json_request();
    let json16k_check = gate_host
        .invoke_fresh_instance(&valid_mod, &json16k_req)
        .expect("16 KiB JSON canonicalization must succeed");
    let parsed_replace: ReplaceResponseCheck =
        serde_json::from_str(&json16k_check.response_json).expect("valid ReplaceContent JSON");
    assert_eq!(parsed_replace.kind, "replace_content");
    assert_eq!(parsed_replace.lang, "json");
    assert!(
        parsed_replace
            .content
            .starts_with("{\n  \"alpha\": \"first\",\n  \"key_000\":"),
        "keys must be sorted lexicographically: got prefix {:?}",
        &parsed_replace.content[..60.min(parsed_replace.content.len())]
    );

    // 2. Cold compile & first-invoke benchmarks (`runs` iterations, interleaved LazyTranslation vs Eager)
    let mut cold_compile_lazy_ns = Vec::with_capacity(runs);
    let mut cold_compile_eager_ns = Vec::with_capacity(runs);
    let mut cold_total_lazy_ns = Vec::with_capacity(runs);
    let mut cold_total_eager_ns = Vec::with_capacity(runs);

    for _ in 0..runs {
        let host_lazy = WasmPluginHost::new(CompilationMode::LazyTranslation);
        let t0 = Instant::now();
        let m_lazy = host_lazy.load_and_verify_zero_import(&guest_bytes).unwrap();
        let compile_ns = t0.elapsed().as_nanos();
        let out_lazy = host_lazy.invoke_fresh_instance(&m_lazy, &math_req).unwrap();
        let total_ns = t0.elapsed().as_nanos();
        assert!(out_lazy.response_json.contains("\"59.97\""));
        cold_compile_lazy_ns.push(compile_ns);
        cold_total_lazy_ns.push(total_ns);

        let host_eager = WasmPluginHost::new(CompilationMode::Eager);
        let t1 = Instant::now();
        let m_eager = host_eager.load_and_verify_zero_import(&guest_bytes).unwrap();
        let compile_e_ns = t1.elapsed().as_nanos();
        let out_eager = host_eager.invoke_fresh_instance(&m_eager, &math_req).unwrap();
        let total_e_ns = t1.elapsed().as_nanos();
        assert!(out_eager.response_json.contains("\"59.97\""));
        cold_compile_eager_ns.push(compile_e_ns);
        cold_total_eager_ns.push(total_e_ns);
    }

    // 3. Cached Module + Fresh Bounded Store per Call (`runs` iterations after 5 warmup calls)
    let warm_host = WasmPluginHost::new(CompilationMode::Eager);
    let cached_mod = warm_host.load_and_verify_zero_import(&guest_bytes).unwrap();
    for _ in 0..5 {
        let _ = warm_host.invoke_fresh_instance(&cached_mod, &math_req).unwrap();
        let _ = warm_host
            .invoke_fresh_instance(&cached_mod, &json16k_req)
            .unwrap();
    }

    let mut fresh_store_math_ns = Vec::with_capacity(runs);
    let mut last_math_out = None;
    for _ in 0..runs {
        let t = Instant::now();
        let out = warm_host.invoke_fresh_instance(&cached_mod, &math_req).unwrap();
        fresh_store_math_ns.push(t.elapsed().as_nanos());
        assert!(out.response_json.contains("\"84.77\""));
        last_math_out = Some(out);
    }
    let last_math_out = last_math_out.unwrap();

    let mut fresh_store_json_ns = Vec::with_capacity(runs);
    let mut last_json_out = None;
    for _ in 0..runs {
        let t = Instant::now();
        let out = warm_host
            .invoke_fresh_instance(&cached_mod, &json16k_req)
            .unwrap();
        fresh_store_json_ns.push(t.elapsed().as_nanos());
        assert!(out.response_json.contains("\\\"alpha\\\": \\\"first\\\""));
        last_json_out = Some(out);
    }
    let last_json_out = last_json_out.unwrap();

    // 4. Cached Module + Warm Reused Instance (verifying zero memory leak across 100 calls)
    let mut reused_store = warm_host.new_bounded_store().unwrap();
    let reused_instance = Instance::new(&mut reused_store, &cached_mod.module, &[]).unwrap();
    let _warmup_reused = warm_host
        .invoke_on_instance(&mut reused_store, &reused_instance, &math_req)
        .unwrap();
    let baseline_mem_math = warm_host
        .invoke_on_instance(&mut reused_store, &reused_instance, &math_req)
        .unwrap()
        .final_memory_bytes;

    let mut reused_math_ns = Vec::with_capacity(runs);
    let mut last_reused_math = None;
    for _ in 0..runs {
        let t = Instant::now();
        let out = warm_host
            .invoke_on_instance(&mut reused_store, &reused_instance, &math_req)
            .unwrap();
        reused_math_ns.push(t.elapsed().as_nanos());
        assert_eq!(
            out.final_memory_bytes, baseline_mem_math,
            "warm reused instance leaked linear memory pages on math workload"
        );
        last_reused_math = Some(out);
    }
    let last_reused_math = last_reused_math.unwrap();

    let baseline_mem_json = warm_host
        .invoke_on_instance(&mut reused_store, &reused_instance, &json16k_req)
        .unwrap()
        .final_memory_bytes;
    let mut reused_json_ns = Vec::with_capacity(runs);
    let mut last_reused_json = None;
    for _ in 0..runs {
        let t = Instant::now();
        let out = warm_host
            .invoke_on_instance(&mut reused_store, &reused_instance, &json16k_req)
            .unwrap();
        reused_json_ns.push(t.elapsed().as_nanos());
        assert_eq!(
            out.final_memory_bytes, baseline_mem_json,
            "warm reused instance leaked linear memory pages on 16 KiB JSON workload"
        );
        last_reused_json = Some(out);
    }
    let last_reused_json = last_reused_json.unwrap();

    FullSpikeReport {
        guest_wasm_bytes: guest_bytes.len(),
        guest_wasm_kib: (guest_bytes.len() as f64) / 1024.0,
        guest_under_50_kib: guest_bytes.len() < 50 * 1024,
        evil_import_wasm_bytes: evil_import.len(),
        infinite_loop_wasm_bytes: infinite_loop.len(),
        oom_grow_bomb_wasm_bytes: oom_grow_bomb.len(),
        security_gates: SecurityGateResults {
            evil_import_rejected_before_instantiation: true,
            evil_import_error_code: import_err.code,
            evil_import_error_detail: import_err.detail,
            evil_import_instantiation_count: evil_inst_count,
            infinite_loop_trapped: true,
            infinite_loop_error_code: loop_err.code,
            infinite_loop_error_detail: loop_err.detail,
            infinite_loop_abort_ms: loop_abort_ms,
            oom_grow_bomb_trapped: true,
            oom_grow_bomb_error_code: oom_err.code,
            oom_grow_bomb_error_detail: oom_err.detail,
            oom_grow_bomb_abort_us: oom_abort_us,
            oom_init_bomb_rejected: true,
            oom_init_bomb_error_code: oom_init_err.code,
            multi_memory_bomb_rejected: true,
            post_trap_clean_recovery_ok: true,
        },
        benchmarks: BenchmarkMatrix {
            small_math_payload_bytes: math_req.len(),
            medium_json_payload_bytes: json16k_req.len(),
            cold_compile_only_lazy: summarize_samples_ns(cold_compile_lazy_ns),
            cold_compile_only_eager: summarize_samples_ns(cold_compile_eager_ns),
            cold_compile_plus_first_invoke_lazy: summarize_samples_ns(cold_total_lazy_ns),
            cold_compile_plus_first_invoke_eager: summarize_samples_ns(cold_total_eager_ns),
            warm_cached_module_fresh_store_math: WarmBenchEntry {
                latency: summarize_samples_ns(fresh_store_math_ns),
                fuel_consumed: last_math_out.fuel_consumed,
                final_memory_bytes: last_math_out.final_memory_bytes,
                output_bytes: last_math_out.response_json.len(),
            },
            warm_cached_module_fresh_store_json16k: WarmBenchEntry {
                latency: summarize_samples_ns(fresh_store_json_ns),
                fuel_consumed: last_json_out.fuel_consumed,
                final_memory_bytes: last_json_out.final_memory_bytes,
                output_bytes: last_json_out.response_json.len(),
            },
            warm_reused_instance_math: WarmBenchEntry {
                latency: summarize_samples_ns(reused_math_ns),
                fuel_consumed: last_reused_math.fuel_consumed,
                final_memory_bytes: last_reused_math.final_memory_bytes,
                output_bytes: last_reused_math.response_json.len(),
            },
            warm_reused_instance_json16k: WarmBenchEntry {
                latency: summarize_samples_ns(reused_json_ns),
                fuel_consumed: last_reused_json.fuel_consumed,
                final_memory_bytes: last_reused_json.final_memory_bytes,
                output_bytes: last_reused_json.response_json.len(),
            },
        },
    }
}

fn main() {
    let mut runs = 100usize;
    let mut json_out: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--runs" => {
                runs = args
                    .next()
                    .expect("--runs requires integer")
                    .parse()
                    .expect("valid usize");
            }
            "--json-out" => {
                json_out = Some(PathBuf::from(args.next().expect("--json-out requires path")));
            }
            other => panic!("unknown argument: {other}"),
        }
    }

    let report = run_full_suite(runs);
    let pretty = serde_json::to_string_pretty(&report).expect("serialize report");
    if let Some(path) = json_out {
        fs::write(&path, &pretty).expect("write json report");
    }
    println!("{pretty}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inv_plugin_zero_import_and_resource_bounds_hold() {
        let report = run_full_suite(10);
        assert!(report.guest_under_50_kib);
        assert!(report.security_gates.evil_import_rejected_before_instantiation);
        assert_eq!(report.security_gates.evil_import_instantiation_count, 0);
        assert!(report.security_gates.infinite_loop_trapped);
        assert!(report.security_gates.oom_grow_bomb_trapped);
        assert!(report.security_gates.oom_init_bomb_rejected);
        assert!(report.security_gates.multi_memory_bomb_rejected);
        assert!(report.security_gates.post_trap_clean_recovery_ok);
    }
}
