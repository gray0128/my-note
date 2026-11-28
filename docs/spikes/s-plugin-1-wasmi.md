# S-Plugin-1 实测报告：`wasmi 2.0.3` 二进制体积增量与零导入 3-Export 双宿主基准（Issue #76）

- **状态**：**PASS（macOS `arm64` 真机 `wasmi 2.0.3` + Playwright Chromium `159` / WebKit `27.2` `'self'` Web Worker 全部验证通过；Linux / Windows Release 体积待对应 CI 补记）**
- **核心结论（支撑启动 `M5-P1..P4`）**：
  1. **揭露既有单二进制超预算根因，测准 `wasmi 2.0.3` 真实增量与 `< 15 MiB` 收敛路径**：
     - 未修改 `origin/main`（`v0.3.3`，`lto = "thin", strip = true`，含 `RustEmbed` 前端）实测已达 **`18,807,456 B`（`17.936 MiB`）** `[已测]`，在接入插件前已超出 `< 15 MiB`（`15,728,640 B`）`[目标]` 达 `+2.936 MiB`（源于 M3 内嵌未压缩 `web/dist` `3.127 MiB` 与 M4 `image` 编解码器）。
     - 按 Issue 字面最小配置 `wasmi = { version = "2.0.3", default-features = false, features = ["std"] }` 实装 3-Export 宿主链路后为 **`19,714,080 B`（`18.801 MiB`）** `[已测]`，净增 **`+906,624 B`（`+885.38 KiB` / `+0.865 MiB`）** `[已测]`；M5-P2 生产安全配置 `features = ["std", "validate", "portable-dispatch"]` 实测为 **`20,183,648 B`（`19.249 MiB`）** `[已测]`，净增 **`+1,376,192 B`（`+1,343.94 KiB` / `+1.312 MiB`）** `[已测]`，比默认全特性 `wasmi = "2.0.3"`（`+1.978 MiB` `[已测]`）节省 **`681.33 KiB`** `[已测]`。
     - **零新依赖回归 `< 15 MiB` 路径**：仅将根 `Cargo.toml` 的 `[profile.release]` 调整为 `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `strip = true`，含完整 `wasmi`（`std + validate + portable-dispatch`）的剥离后单二进制即骤降至 **`10,924,320 B`（`10.418 MiB`）** `[已测]`（较 `15 MiB` 留出 **`4.582 MiB`** 余量）；若再对 `RustEmbed` 的 `web/dist`（原始 `3.127 MiB` → `gzip -9` `1.070 MiB` `[已测]`）启用预压缩直出，总体积进一步降至 **`8,744,736 B`（`8.340 MiB`）** `[已测]`。
     - **无插件 CLI 冷启零感知**：50 对奇偶交替实测，`mynote ls --json` 中位耗时由 `4.798 ms` 变为 `4.819 ms`（增量 **`+0.021 ms`** `[已测]`，远低于 `< 1 ms` `[目标]`）。
  2. **捕获两处会引发 UB 或宿主要命崩溃的 `wasmi 2.0.3` 陷阱**：
     - **陷阱 A（缺少 `"validate"` 导致 UB）**：`wasmi 2.0.3` 将安全构造函数 `Module::new` 门控在 `#[cfg(feature = "validate")]` 下；若仅开 `features = ["std"]`，只能调用 `unsafe fn Module::new_unchecked`，加载未校验的第三方 `.wasm` 直接构成未定义行为。生产配置必须显式包含 `"validate"`。
     - **陷阱 B（`lto = "thin"` 下默认尾调用分发栈溢出杀死宿主）**：`wasmi 2.0.3` 在未开启 `"portable-dispatch"` 时（无论默认 `auto-dispatch` 还是裸 `std + validate`）于 `aarch64` Release 下选用递归尾调用处理器 `backend/tail.rs`（9 参数 `Handler`）。实测在 `lto = "thin"` 下运行 `15.25 KiB` JSON 插件负载（`23.36M` fuel）时，部分指令未完成 LLVM 尾调用消去，直接耗尽主线程栈触发 **`fatal runtime error: stack overflow, aborting`（`SIGABRT`，退出码 `134`）** `[已测]`。显式启用 `"portable-dispatch"`（仅增 `+15.92 KiB` `[已测]`）切换至 `backend/loop.rs` 后，宿主 C 栈帧恒为 `O(1)`，100 轮全量压测与 `50,000,000` fuel 死循环 100% 平稳拦截。
  3. **零导入样板插件与双宿主安全门禁、性能全部达标**：纯 Rust `#![no_std] + alloc` 构建的 `guest_calc.wasm` 仅 **`34,099 B`（`33.30 KiB`）** `[已测]`（`< 50 KiB` `[目标]`）；同一 `.wasm` 在 `wasmi` 与浏览器 `'self'` Web Worker（严格 CSP 零违规 `[已测]`）上热调用中位耗时分别为 **`0.229 ms`** 与 **`0.035–0.300 ms`**（231 B 算式）`[已测]`，`INV-PLUGIN-ZERO-IMPORT` 与 `INV-PLUGIN-RESOURCE-BOUND` 双端全部通过。

---

## 1. 测试环境与复现路径

| 项目 | 实测环境 |
| --- | --- |
| 宿主机 | macOS `27.2.1`（Build `26B131`），`arm64`（Apple M4，`16 GiB` RAM） |
| Rust 工具链 | `rustc 1.92.0 (ded5c06cf 2025-12-08)`，`cargo 1.92.0`，目标 `aarch64-apple-darwin` 与 `wasm32-unknown-unknown` |
| WASM 宿主与浏览器 | `wasmi 2.0.3`（`wasmparser 0.228.0`）；Playwright `1.65.2` 无头 **Chromium `159.0.8154.6`（V8）** 与 **WebKit `27.2`（JSC）** |
| 物理隔离验证 | 原型代码隔离于 [`spikes/s-plugin-1-wasmi/`](../../spikes/s-plugin-1-wasmi/)，`crates/`、`cloud-cf/`、`web/`、`evals/` 改动为 `0 LOC` `[保证]` |

```bash
# 1. 构建 33.30 KiB guest_calc.wasm 与对抗样本，执行 wasmi 门禁与 100 轮延迟基准
CARGO_TARGET_DIR=/tmp/mynote-s-plugin-1-target cargo run --manifest-path spikes/s-plugin-1-wasmi/Cargo.toml --release -- --runs 100
CARGO_TARGET_DIR=/tmp/mynote-s-plugin-1-target cargo test --manifest-path spikes/s-plugin-1-wasmi/Cargo.toml --release

# 2. 执行 Playwright Chromium + WebKit 独立 'self' Web Worker 门禁与 100 轮延迟基准
uv run --with playwright python3 spikes/s-plugin-1-wasmi/bench_worker.py --runs 100

# 3. 在 /tmp/mynote-s-plugin-1-size-work 副本实测 Release 体积与冷启增量（退出自动清理 /tmp）
./spikes/s-plugin-1-wasmi/measure_binary_size.sh
```

---

## 2. `mynote` Release 二进制体积与无插件冷启增量实测

在 `/tmp/mynote-s-plugin-1-size-work` 独立副本中先运行 `scripts/build-wasm.sh` 与 `pnpm --dir web build` 生成真实内嵌前端（`web/dist` 共 `19` 个文件，原始 `3,278,612 B` / `3.127 MiB`，`gzip -9` 后 `1,121,639 B` / `1.070 MiB` `[已测]`），对所有链接变体注入真实 3-Export 执行入口并以 `guest_calc.wasm` 实跑验真，防止 LTO 死代码消除制造虚假 `0 B` 增量：

| 构建变体（macOS `arm64` stripped） | Stripped 字节数 | 体积（MiB） | 相对基线增量 | `< 15 MiB`（`15,728,640 B`） | 工程判定 |
| --- | ---: | ---: | ---: | :---: | --- |
| `0-baseline`（`origin/main` `v0.3.3`，`lto="thin"`） | `18,807,456 B` `[已测]` | `17.936 MiB` `[已测]` | 基准 | FAIL（既有超 `+2.936 MiB`） | M3/M4 累积体积已超 M1 初始目标 |
| `1-std-unreferenced`（仅写 `Cargo.toml` 未调用） | `18,807,472 B` `[已测]` | `17.936 MiB` `[已测]` | `+16 B`（`+0.02 KiB`）`[已测]` | FAIL | 证实未接线依赖会被 `-dead_strip` 剔除 |
| `2-std-linked-unchecked`（`features=["std"]`） | `19,714,080 B` `[已测]` | `18.801 MiB` `[已测]` | **`+906,624 B`（`+885.38 KiB` / `+0.865 MiB`）** `[已测]` | FAIL | 缺 `Module::new`，仅 `unsafe new_unchecked`，不可用于生产 |
| `3-std-validate-tail`（`["std","validate"]`） | `20,167,344 B` `[已测]` | `19.233 MiB` `[已测]` | `+1,359,888 B`（`+1,328.02 KiB` / `+1.297 MiB`）`[已测]` | FAIL | `tail.rs` 在 `lto="thin"` 长负载下触发宿主栈溢出（`SIGABRT`） |
| **`4-std-validate-portable`（M5-P2 推荐特性）** | **`20,183,648 B`** `[已测]` | **`19.249 MiB`** `[已测]` | **`+1,376,192 B`（`+1,343.94 KiB` / `+1.312 MiB`）** `[已测]` | FAIL（随基线超限） | 安全校验 + 循环分发零栈溢出，较默认省 `681.33 KiB` |
| `5-default-features`（`wasmi = "2.0.3"` 默认全开） | `20,881,328 B` `[已测]` | `19.914 MiB` `[已测]` | `+2,073,872 B`（`+2,025.27 KiB` / `+1.978 MiB`）`[已测]` | FAIL | 拖入无用 `wat` 文本解析器与 `memory64` |
| **`6-std-validate-portable-optz`（推荐特性 + `opt-level="z", lto=true, cgu=1`）** | **`10,924,320 B`** `[已测]` | **`10.418 MiB`** `[已测]` | **`-7,883,136 B`（`-7.518 MiB`）** `[已测]` | **PASS（余量 `4.582 MiB`）** | **零功能裁剪一步回到 `< 15 MiB` 预算内**（若再预压缩 `web/dist` 可至 **`8.340 MiB`** `[已测]`） |

- **无插件 CLI 冷启延迟对比（50 对奇偶交替进程调用，惰性不初始化 `wasmi::Engine`）**：
  - `mynote --version`：基线 `p50 = 3.927 ms`（`p95 = 4.113 ms`）vs `+wasmi` `p50 = 3.913 ms`（`p95 = 4.137 ms`），差值 **`-0.014 ms`** `[已测]`（在系统调度噪声内）；
  - `mynote ls --json`（真实 SQLite WAL 单块库）：基线 `p50 = 4.798 ms`（`p95 = 5.405 ms`）vs `+wasmi` `p50 = 4.819 ms`（`p95 = 5.060 ms`），差值 **`+0.021 ms`** `[已测]`，满足 `< 1 ms` `[目标]`。

---

## 3. 零导入样板 `.wasm` 体积与双宿主安全门禁实测

### 3.1 Guest 样板体积对比（纯 Core WASM `cdylib`，零 `wasm-bindgen`）

- 对照实验：使用标准库 `std` + `format!("{f:.10}")` 编译同一算式与 JSON 插件时，因拖入 `core::fmt::float`（`flt2dec`）、`dec2flt` 与 `std::panicking`，产物达 **`95,705 B`（`93.46 KiB`）** `[已测]`（其中 `code = 73,578 B`、`data = 21,555 B`），超出 `< 50 KiB` `[目标]`。
- 正式样板（[`spikes/s-plugin-1-wasmi/guest-calc/`](../../spikes/s-plugin-1-wasmi/guest-calc/)）：改用 `#![no_std] + alloc`、60 行 `O(1)` 2 幂分级空闲链表分配器与定点数十进制编解码，完整实现多行变量算式求值（`PluginResult::Gutter` / `ReplaceContent`）与 RFC 8259 JSON 键排序美化，并附加 `-C link-arg=--max-memory=16777216`，最终产物仅 **`34,099 B`（`33.30 KiB`）** `[已测]`，低于 `< 50 KiB` `[目标]`。

### 3.2 对抗样本门禁矩阵（`INV-PLUGIN-ZERO-IMPORT` & `INV-PLUGIN-RESOURCE-BOUND`）

| 对抗样本 / 检查项 | `wasmi 2.0.3`（`portable-dispatch`） | Chromium `159` `'self'` Worker | WebKit `27.2` `'self'` Worker |
| --- | --- | --- | --- |
| `evil_import.wasm`（`125 B`，含 `env::evil` + `wasi_snapshot_preview1::fd_write`） | **PASS**：实例化前拒收（`instantiations = 0`），返 `PLUGIN_INVALID_MANIFEST` `[已测]` | **PASS**：`WebAssembly.Module.imports(mod).length === 2` 实例化前拒收，返 `PLUGIN_INVALID_MANIFEST` `[已测]` | **PASS**：实例化前拒收，返 `PLUGIN_INVALID_MANIFEST` `[已测]` |
| `infinite_loop.wasm`（`151 B`，`(loop (result i64) (br 0))`） | **PASS**：`50,000,000` fuel 耗尽确定性捕获 `TrapCode::OutOfFuel`（耗时 **`89.81 ms`** `[已测]`），返 `PLUGIN_RESOURCE_EXCEEDED` | **PASS**：`60 ms` 硬超时调用 `worker.terminate()` 销毁线程（耗时 **`63.1 ms`** `[已测]`）并自动重建新 Worker，返 `PLUGIN_RESOURCE_EXCEEDED` | **PASS**：`worker.terminate()` 销毁线程（耗时 **`62.0 ms`** `[已测]`）并自动重建新 Worker，返 `PLUGIN_RESOURCE_EXCEEDED` |
| `oom_grow_bomb.wasm`（`168 B`，无上限内存声明 + `memory.grow(300)` 申请 `18.75 MiB`） | **PASS**：`StoreLimits`（`16 MiB` + `trap_on_grow_failure(true)`）在 **`131.7 µs`** 内拦截 `[已测]`，返 `PLUGIN_RESOURCE_EXCEEDED` | **PASS**：Section-5 预钳制（`max=256` 页）使 V8 原生拒绝扩容并 trap，返 `PLUGIN_RESOURCE_EXCEEDED`（未钳制阳性对照实测会扩至 **`19,726,336 B` / `18.81 MiB`** `[已测]`） | **PASS**：Section-5 预钳制使 JSC 原生拒绝扩容并 trap，返 `PLUGIN_RESOURCE_EXCEEDED`（未钳制对照扩至 **`18.81 MiB`** `[已测]`） |
| `oom_init_bomb.wasm`（初始声明 `257` 页 = `16.06 MiB`）& `multi_memory_bomb.wasm`（双内存 `2×12 MiB`） | **PASS**：`wasm_multi_memory(false)` + `memories(1)` + `memory_size(16 MiB)` 全数在加载/实例化期拒收 `[已测]` | **PASS**：Section-5 解析器在 `WebAssembly.compile` 前直接拒收 `[已测]` | **PASS**：Section-5 解析器在 `WebAssembly.compile` 前直接拒收 `[已测]` |
| 熔断后即时恢复与桌面严格 CSP（`worker-src 'self'`） | **PASS**：陷阱后同 `Engine` 立即调用 `guest_calc.wasm` 输出精确匹配（`84.77`）`[已测]` | **PASS**：重建 Worker 后首调即成功，`cspViolations = 0`、`pageErrors = 0` `[已测]` | **PASS**：重建 Worker 后首调即成功，`cspViolations = 0`、`pageErrors = 0` `[已测]` |

---

## 4. 双宿主冷编译与热调用延迟基准（100 轮实测）

测试载荷：① **轻量算式块（`231 B` 请求 → `236 B` 5 行 `Gutter` JSON）**；② **中等 JSON 块（`15,252 B` 乱序嵌套 JSON → `21,917 B` 递归键排序美化 `ReplaceContent` JSON）**。浏览器端单次 `performance.now()` 受非跨域隔离下 Spectre 计时粒度限制（Chromium `0.1 ms`、WebKit `1.0 ms`），故同步采集 `20` 次串行往返批均摊微秒值（`25` 批共 `500` 次）：

| 宿主与调用模式（100 轮） | 载荷 | `p50`（中位数） | `p95` | 消耗 Fuel | 峰值线性内存 |
| --- | --- | ---: | ---: | ---: | ---: |
| `wasmi 2.0.3` 冷编译 `Module::new`（`LazyTranslation` / `Eager`） | `33.30 KiB` `.wasm` | **`0.178 ms`** / `0.458 ms` `[已测]` | `0.366 ms` / `1.077 ms` `[已测]` | — | — |
| `wasmi 2.0.3` 冷编译 + 首次实例化调用（`Lazy` / `Eager`） | `231 B` 算式 | `0.758 ms` / **`0.702 ms`** `[已测]` | `1.452 ms` / `1.479 ms` `[已测]` | `314,705` `[已测]` | `1.06 MiB`（`17` 页）`[已测]` |
| `wasmi 2.0.3` 缓存 `Module` + 每调新建隔离 `Store` | `231 B` 算式 | **`0.229 ms`**（`228.7 µs`）`[已测]` | `0.369 ms` `[已测]` | `314,705` `[已测]` | `1.06 MiB` `[已测]` |
| `wasmi 2.0.3` 缓存 `Module` + 复用热 `Instance`（100 轮零涨页） | `231 B` 算式 | **`0.191 ms`**（`190.7 µs`）`[已测]` | `0.206 ms` `[已测]` | `314,705` `[已测]` | `1.06 MiB`（恒定）`[已测]` |
| `wasmi 2.0.3` 缓存 `Module` + 每调新建隔离 `Store` | `15.25 KiB` JSON | **`10.572 ms`** `[已测]` | `12.081 ms` `[已测]` | `23,362,019` `[已测]` | `1.44 MiB`（`23` 页）`[已测]` |
| **Chromium `159`（V8）`'self'` Worker** 冷往返 / 缓存模块每调新实例 | `231 B` 算式 | **`0.20 ms`** / **`35.0 µs`**（单次 `0.0 ms`）`[已测]` | `0.20 ms` / `130.0 µs` `[已测]` | N/A（JIT） | `1.06 MiB` `[已测]` |
| **Chromium `159`（V8）`'self'` Worker** 缓存模块每调新实例 | `15.25 KiB` JSON | **`0.40 ms`**（均摊 **`375.0 µs`**）`[已测]` | `0.50 ms`（`555.0 µs`）`[已测]` | N/A（JIT） | `1.44 MiB` `[已测]` |
| **WebKit `27.2`（JSC）`'self'` Worker** 冷往返 / 缓存模块每调新实例 | `231 B` 算式 | **`1.0 ms`** / **`300.0 µs`**（单次 `0 ms`）`[已测]` | `2.0 ms` / `300.0 µs` `[已测]` | N/A（JIT） | `1.06 MiB` `[已测]` |
| **WebKit `27.2`（JSC）`'self'` Worker** 缓存模块每调新实例 | `15.25 KiB` JSON | **`1.0 ms`**（均摊 **`550.0 µs`**）`[已测]` | `1.0 ms`（`550.0 µs`）`[已测]` | N/A（JIT） | `1.44 MiB` `[已测]` |

---

## 5. 给 M5-P2 / M5-P3 正式实现的工程守则与待补测项

1. **锁定 `wasmi` 依赖特性集**：`crates/mynote-cli/Cargo.toml` 必须采用 `wasmi = { version = "2.0.3", default-features = false, features = ["std", "validate", "portable-dispatch"] }`，严禁省略 `"validate"`（防 `new_unchecked` UB）或省略 `"portable-dispatch"`（防 `lto = "thin"` 下尾调用失效栈溢出杀死 Daemon），并同步在根 `Cargo.toml` 评估启用 `opt-level = "z", lto = true, codegen-units = 1` 将单二进制拉回 `10.42 MiB`（`< 15 MiB`）。
2. **`StoreLimits` 四联防与单次调用新 `Store`**：`StoreLimitsBuilder::new().memory_size(limit).memories(1).tables(2).table_elements(4096).instances(1).trap_on_grow_failure(true)` 配合 `config.wasm_multi_memory(false)`，既堵住多线性内存配额绕过（`10,000 × 16 MiB` 默认上限漏洞），又确保忽略 `memory.grow == -1` 的恶意外挂当场 trap；由于缓存 `Module` 后每次新建 `Store + Instance` 仅增加 **`~38 µs`**（`228.7 µs` vs `190.7 µs` `[已测]`），M5-P2 应采用**缓存 `Module`（按文件 `(mtime, size, blake3)` 索引）+ 每次调用新建 `Store`**，彻底杜绝跨块内存残留。
3. **浏览器 `'self'` Web Worker 必须前置执行 Section-5 线性内存钳制**：原生 `WebAssembly.instantiate(mod, {})` 对模块内部自行定义并导出的无上限 `(memory 1)` 不设 `16 MiB` 护栏（实测 `oom_grow_bomb.wasm` 在未钳制 V8/JSC 中直接扩至 `18.81 MiB` `[已测]`）。`web/src/plugins/worker.ts` 必须在 `WebAssembly.compile` 前解析 Section 5：拒绝 `memory_count > 1` 或 `initial > max_pages`，并将未声明或超限的 `maximum` 覆写为 `max_pages`（默认 `256` 页 = `16 MiB`）。
4. **0 字节分配与释放边界契约**：Rust `GlobalAlloc::alloc` 传入 `size == 0` 属未定义行为，官方参考插件模板的 `mynote_alloc(0)` 必须返回非零哨兵指针（如 `1`）且 `mynote_dealloc` 对 `len == 0` 直接跳过；宿主在 `req_len == 0` 时不写内存、直接传 `(sentinel_ptr, 0)`。
5. **Fuel 预算与大块分级**：纯解释器 `wasmi` 处理 `15.25 KiB` 复杂 JSON AST 重排消耗约 `23.36M` fuel（`10.57 ms` `[已测]`），默认 `fuel_limit = 50,000,000` 可覆盖约 `32 KiB` 结构化转换；`M5-P2` 宿主上限建议定为 `200,000,000`（约 `350 ms`），供重度 `transform` 插件在 `plugin.toml` 中按需声明。
6. **跨平台待补记项**：Linux `x86_64-unknown-linux-gnu` 与 Windows `x86_64-pc-windows-msvc` 的 Release 二进制体积增量列为 `[待 M5-W1 / M5-P2 三平台 CI 实测补记]`。
