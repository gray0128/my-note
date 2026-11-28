# S-Clip-2 实测报告：PWA WASM `WasmClipCodec`（`MNC1`）体积增量、10 MiB 加密基准与同步 Promise 图片剪贴板（Issue #50）

- **结论（本地 WASM 与 Playwright Chromium / WebKit 全部验证通过；物理 iPhone 真机待补测，`status = partial_pending_iphone`）**：
  1. **揭露既有 `pkg-pwa` 体积隐患并给出零依赖根治**：仓库已提交基线 `web/src/wasm/pkg-pwa/mynote_wasm_bg.wasm` 实测为 `1,527,996 B` raw / **`378,603 B`（`369.73 KiB`）`gzip -9`** `[已测]`——**在加入剪贴板之前已超出 `350 KiB`（`358,400 B`）预算 `+19.73 KiB`**（`research/converted/2026-11-27-clipboard-sync-research.md` §3.5 所引 `346 KiB` 已滞后）。根因是 `Cargo.toml` 中 `[profile.wasm-release] strip = false`、`scripts/build-wasm.sh` 调用 `wasm-bindgen` 未传 `--remove-name-section`，且本机与 GitHub Actions CI（`ci.yml` / `deploy-cloud.yml`）均未安装 `wasm-opt >= 117`，导致高达 **`412,920 B`（`403.24 KiB`）的调试 `custom name` 段**直接被打入生产 PWA WASM。
  2. **`+WasmClipCodec`（`MNC1`）精确增量与达标路径**：在完全相同的本机工具链（`rustc 1.92.0`、`wasm-bindgen 0.2.130`、无 `wasm-opt`）下同口径实测，接入完整 `WasmClipCodec`（`encryptMeta` / `decryptMeta` / `encryptBlob` / `decryptBlob` / `zeroize` + `ClipMetaV1` 位图 MIME 白名单拒 `image/svg+xml` + `AeadInOut` 单遍加解密）：
     - 沿用现有 `scripts/build-wasm.sh` 默认参数（保留 `custom name` 段）：`369.58 KiB` → **`381.82 KiB`** `[已测]`（增量 **`+12,534 B` / `+12.24 KiB` `gzip -9`**），超 `350 KiB` 预算；
     - **`wasm-bindgen` 增加 `--remove-name-section`（零新依赖，本机与 CI 即刻可用）**：基线骤降至 `281.72 KiB` `[已测]`，`+WasmClipCodec` 仅 **`298,301 B`（`291.31 KiB`）`gzip -9`** `[已测]`（增量 **`+9,816 B` / `+9.59 KiB` `gzip -9`**），单此一项立省 **`92,680 B`（`90.51 KiB`）`gzip -9`**，距离 `350 KiB` 预算留出 **`58.69 KiB`（`60,099 B`）充足余量**。
  3. **5 MiB / 10 MiB WASM 加密性能与内存峰值**：Apple M4 macOS 真浏览器实测（3 次中位数），`WasmClipCodec.encryptBlob` / `decryptBlob` 均稳定跑在 **`120–128 MiB/s`** `[已测]`：
     - **WebKit 27.2（JSC）**：5 MiB 加密 **`40.0 ms`** / 解密 **`39.0 ms`** `[已测]`；10 MiB 加密 **`80.0 ms`** / 解密 **`79.0 ms`** `[已测]`；峰值 WASM 线性内存 **`24.00 MiB`** `[已测]`，零 OOM / 崩溃，字节级往返 100% 一致；
     - **Chromium 159（V8）**：5 MiB 加密 **`41.3 ms`** / 解密 **`41.1 ms`** `[已测]`；10 MiB 加密 **`83.4 ms`** / 解密 **`82.5 ms`** `[已测]`；峰值 WASM 线性内存 **`23.75 MiB`** `[已测]`。
  4. **同步 Promise `ClipboardItem({ 'image/png': pngBlobPromise })` + 离屏 `<canvas>` JPEG→PNG 转换**：在本地安全上下文 `http://127.0.0.1:<port>` 下，真实 `click` 回调内同步构造 `pngBlobPromise`（`fetch('/blob.mnc1', { redirect: 'manual' })` → `WasmClipCodec.decryptBlob` → `createImageBitmap` → 离屏 `<canvas>` `1920×1080` → `canvas.toBlob('image/png')`）并同步传入 `navigator.clipboard.write([new ClipboardItem({ 'image/png': pngBlobPromise })])`，**Chromium 159 与 WebKit 27.2 均零 `NotAllowedError` / `TypeError` 返回成功** `[已测]`，且转换产出严格符合 PNG 魔数 `89 50 4E 47 0D 0A 1A 0A` `[已测]`（Chromium 另通过真实 `navigator.clipboard.read()` 回读验真）。
  5. **未完成项（需真机）**：当前环境未连接物理 iPhone，**iOS 主屏独立 PWA（Standalone）的实机 WASM 耗时、Jetsam 内存边界及点击复制后跨 App 粘贴到微信 / Apple 备忘录的真实行为仍为 `[待 iPhone 真机补测]`**。待物理 iPhone 补测闭环后方可协同其余 `S-Clip` Spike 升级 `ADR-11`。
- **复现路径**：[`spikes/s-clip-2-pwa-wasm/`](../../spikes/s-clip-2-pwa-wasm/)（`CARGO_TARGET_DIR=/tmp/mynote-s-clip-2 spikes/s-clip-2-pwa-wasm/measure_wasm_clip.sh`、`uv run --with playwright python3 spikes/s-clip-2-pwa-wasm/bench_webkit_clip.py`、`bench.html`）。

---

## 1. 测试环境与工具链声明

| 项目 | 实测环境 |
| --- | --- |
| 宿主机 | macOS `27.2.1`（Build `26B131`），`arm64`（Apple M4） |
| Rust 工具链 | `rustc 1.92.0 (ded5c06cf 2025-12-08)`，目标 `wasm32-unknown-unknown`，Profile `wasm-release`（`opt-level = "z"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = false`） |
| WASM 打包工具 | `wasm-bindgen 0.2.130`（`--target web`）；`wasm-opt` **未安装**（本机与 GitHub Actions CI `ci.yml` / `deploy-cloud.yml` 均跳过 `wasm-opt`，本次对比严格同口径） |
| 运行时与浏览器 | Node.js `v26.13.1`；Playwright `1.65.2` 驱动无头 **Chromium `159.0.8154.6` (V8)** 与 **WebKit `27.2` (JSC)** |
| 隔离与零污染 | 所有 Rust 构建均在独立临时副本 `/tmp/mynote-s-clip-2-work/` 与 `CARGO_TARGET_DIR=/tmp/mynote-s-clip-2` 中完成，未修改正式仓库任何业务文件 |

---

## 2. `mynote-wasm`（`pwa` feature）体积增量实测

### 2.1 已提交基线拆解（发现既有超预算根因）

对当前仓库 `web/src/wasm/pkg-pwa/mynote_wasm_bg.wasm` 做 WASM Section 解析 `[已测]`：

| WASM Section | 字节数 | 占比 | 说明 |
| --- | ---: | ---: | --- |
| `code` | `1,040,397 B` | 68.1% | 密码学 + `ruzstd` + `serde` / `rmp_serde` / `serde_json` + `WasmSyncEngine` |
| **`custom "name"`** | **`412,920 B`** | **27.0%** | **调试符号表——因 `strip = false` 且缺 `wasm-opt` / `--remove-name-section` 残留在生产产物中** |
| `data` | `67,267 B` | 4.4% | 静态表与字符串常量 |
| 其他段（`type` / `func` / `export` / `elem` / `producers` 等） | `7,412 B` | 0.5% | 元数据与表 |
| **合计（已提交 `pkg-pwa`）** | **`1,527,996 B`** | 100% | **`gzip -9 = 378,603 B`（`369.73 KiB`）`[已测]`，已超出 `350 KiB` 目标 `+19.73 KiB`** |

### 2.2 同口径对比：未修改基线 vs `+WasmClipCodec`

`WasmClipCodec` 在临时工作副本中复用 `mynote-core` 已有 `chacha20poly1305`（`XChaCha20-Poly1305`，`AeadInOut` 单遍加解密）、`pad256` / `unpad256`、`serde_json` 与 `zeroize`，完整实现 `MNC1` AAD（`docs/data-structures.md` §3.3）、`flags` 保留位校验、`ClipMetaV1` 位图白名单（拒绝 `image/svg+xml`）、`10 MiB` 上限检查及 `globalThis.crypto.getRandomValues` Nonce 生成。每个构建产物均经 Node `initSync` 实例化与全套功能冒烟校验通过 `[已测]`：

| 构建变体（`--profile wasm-release --no-default-features --features pwa`） | Raw `.wasm` | `gzip -9` | 相对基线增量（Raw / `gzip -9`） | 是否 ≤ `350 KiB`（`358,400 B`） |
| --- | ---: | ---: | ---: | :---: |
| 仓库已提交 `web/src/wasm/pkg-pwa/mynote_wasm_bg.wasm` | `1,527,996 B` (`1492.18 KiB`) | `378,603 B` (**`369.73 KiB`**) `[已测]` | — | ❌（既有已超 `+19.73 KiB`） |
| 本机未修改基线（`build-wasm.sh` 默认参数） | `1,525,750 B` (`1489.99 KiB`) | `378,447 B` (**`369.58 KiB`**) `[已测]` | 基准 | ❌ |
| 本机 `+WasmClipCodec`（`build-wasm.sh` 默认参数） | `1,565,309 B` (`1528.62 KiB`) | `390,981 B` (**`381.82 KiB`**) `[已测]` | `+39,559 B` (`+38.63 KiB`) / **`+12,534 B` (`+12.24 KiB`)** `[已测]` | ❌（含 `409.95 KiB` 符号段） |
| 本机未修改基线（`wasm-bindgen --remove-name-section`） | `1,114,167 B` (`1088.05 KiB`) | `288,485 B` (**`281.72 KiB`**) `[已测]` | 基准（无 `name` 段） | ✅（余量 `68.28 KiB`） |
| **本机 `+WasmClipCodec`（`wasm-bindgen --remove-name-section`）** | **`1,145,523 B` (`1118.67 KiB`)** | **`298,301 B` (`291.31 KiB`)** `[已测]` | **`+31,356 B` (`+30.62 KiB`) / `+9,816 B` (`+9.59 KiB`)** `[已测]` | **✅（余量 `58.69 KiB` / `60,099 B`）** |

- **增量略高于提案估算（`+9.59 KiB` `[已测]` vs `+3–6 KiB` `[估算]`）的原因分析**：
  1. 原 `pwa` 构建严格只读（`WasmSyncEngine` 仅调用 `decrypt_*` 与 `unpad256`），本次首次在 `pwa` 侧引入 `XChaCha20-Poly1305` 加密路径（`AeadInOut::encrypt_inout_detached`）、`pad256` 及 `globalThis.crypto.getRandomValues` FFI；
  2. 为贴近真实 M4 交付，原型完整保留了 `ClipMetaV1` / `ClipBlobMetaV1` 的 `serde` 反序列化与位图白名单校验（拒绝 `image/svg+xml`），未做「空壳裁剪」虚压体积；
  3. 仅需在 `scripts/build-wasm.sh` 的 `wasm-bindgen` 命令增加 `--remove-name-section`，即可零依赖削减 **`92,680 B`（`90.51 KiB`）`gzip -9`**，使最终 `+WasmClipCodec` 落点为 **`291.31 KiB`** `[已测]`，远低于 `350 KiB` 红线（若 CI 再补装 `binaryen >= 117` 运行 `wasm-opt -Oz`，还可进一步缩减）。

---

## 3. 真浏览器 WASM 1 / 5 / 10 MiB 加密与解密基准

在本地 `http://127.0.0.1:<port>` 安全上下文中加载 `+WasmClipCodec` WASM（`--remove-name-section` 产物），每档连续执行 3 次完整 `encryptBlob` + `decryptBlob`（含全字节逐位比对、1-bit 密文篡改拒收、`image/svg+xml` 拒收、常规/瞬态 `ephemeral` 跨通道 AAD 隔离校验），记录 3 次原始采样与中位数：

| 浏览器引擎（macOS arm64 Apple M4） | 载荷大小 | `encryptBlob` 中位 / 3 次采样 | 加密吞吐 | `decryptBlob` 中位 / 3 次采样 | 解密吞吐 | 逐字节校验 & 篡改拒收 | 峰值 WASM 线性内存 |
| --- | ---: | --- | ---: | --- | ---: | :---: | ---: |
| **Chromium `159.0.8154.6` (V8)** | `1 MiB` | **`8.3 ms`** `[9.5, 8.3, 8.2]` `[已测]` | `120.5 MiB/s` | **`8.2 ms`** `[8.9, 8.1, 8.2]` `[已测]` | `122.0 MiB/s` | ✅ 100% / ✅ | `3.56 MiB` |
| **Chromium `159.0.8154.6` (V8)** | `5 MiB` | **`41.3 ms`** `[41.6, 41.1, 41.3]` `[已测]` | `121.1 MiB/s` | **`41.1 ms`** `[41.1, 41.2, 41.0]` `[已测]` | `121.7 MiB/s` | ✅ 100% / ✅ | `13.69 MiB` |
| **Chromium `159.0.8154.6` (V8)** | `10 MiB` | **`83.4 ms`** `[83.4, 82.4, 85.8]` `[已测]` | `119.9 MiB/s` | **`82.5 ms`** `[82.5, 82.7, 82.2]` `[已测]` | `121.2 MiB/s` | ✅ 100% / ✅ | **`23.75 MiB`** `[已测]` |
| **WebKit `27.2` (JSC)** | `1 MiB` | **`8.0 ms`** `[8, 8, 8]` `[已测]` | `125.0 MiB/s` | **`8.0 ms`** `[8, 8, 8]` `[已测]` | `125.0 MiB/s` | ✅ 100% / ✅ | `3.81 MiB` |
| **WebKit `27.2` (JSC)** | `5 MiB` | **`40.0 ms`** `[41, 39, 40]` `[已测]` | `125.0 MiB/s` | **`39.0 ms`** `[39, 39, 39]` `[已测]` | `128.2 MiB/s` | ✅ 100% / ✅ | `13.94 MiB` |
| **WebKit `27.2` (JSC)** | `10 MiB` | **`80.0 ms`** `[80, 78, 80]` `[已测]` | `125.0 MiB/s` | **`79.0 ms`** `[79, 80, 79]` `[已测]` | `126.6 MiB/s` | ✅ 100% / ✅ | **`24.00 MiB`** `[已测]` |

> 注：WebKit 出于 Spectre 缓解将 `performance.now()` 量化为 `1 ms` 步进，故采样均为整数毫秒。

- **内存与性能关键观察**：
  1. 吞吐在 1 / 5 / 10 MiB 三档呈严格线性（`~120–128 MiB/s`），无 GC 抖动或 WASM 页反复扩缩卡顿；
  2. 采用 `AeadInOut::encrypt_inout_detached` / `decrypt_inout_detached` 单遍直写输出缓冲区，消除了 `Aead::encrypt` 带来的额外 `10 MiB` 临时拷贝，10 MiB 满载往返的 WASM 线性内存峰值仅 **`23.75–24.00 MiB`** `[已测]`（远低于 S0-3 已在物理 iPhone 主屏 PWA 实测零 OOM 通过的 `65.19 MiB` Argon2id 峰值）。

---

## 4. 同步 Promise `ClipboardItem({ 'image/png': pngBlobPromise })` 与离屏 `<canvas>` JPEG→PNG 实测

测试链路完整模拟桌面发 JPEG 截图 → 移动端 PWA 点击「复制图片」写入 PNG 剪贴板的全路径：

1. 预先生成一张 `1920×1080` 多色渐变 + 几何色块 + 文字 JPEG 图片，经 `WasmClipCodec.encryptBlob` 加密后托管于本地 `http://127.0.0.1:<port>/blob.mnc1`；
2. 由 Playwright 触发真实可信点击（`page.click("#btn-copy-png")`），**在 `click` 事件回调内同步构造 `pngBlobPromise`**（内部依次执行 `fetch("/blob.mnc1", { redirect: "manual" })` → `WasmClipCodec.decryptBlob` → `createImageBitmap(jpegBlob)` → 离屏 `<canvas>` 绘制 → `canvas.toBlob("image/png")`）并**同步传给 `navigator.clipboard.write([new ClipboardItem({ "image/png": pngBlobPromise })])`**；
3. 同时验证 `ClipboardItem.getType("image/png")` 独立解析与 PNG 魔数 `89 50 4E 47 0D 0A 1A 0A`。

| 验证项 | Chromium `159.0.8154.6`（授 `clipboard-read/write` 权限） | WebKit `27.2`（macOS 无头 Playwright） |
| --- | --- | --- |
| 加密 JPEG 样本（`1920×1080`） | `105,345 B` JPEG / `105,406 B` `MNC1`（加密 `0.8 ms`）`[已测]` | `223,359 B` JPEG / `223,420 B` `MNC1`（加密 `2 ms`）`[已测]` |
| `new ClipboardItem({ 'image/png': pngBlobPromise })` 构造与 `getType('image/png')` | ✅ 通过；`1,183,729 B` PNG，魔数 `89 50 4e 47 0d 0a 1a 0a`（`fetch 109.1 ms` + `decrypt 2.7 ms` + `canvas JPEG→PNG 462.9 ms` = `574.7 ms`）`[已测]` | ✅ 通过；`1,112,080 B` PNG，魔数 `89 50 4e 47 0d 0a 1a 0a`（`fetch 2 ms` + `decrypt 1 ms` + `canvas JPEG→PNG 42 ms` = `45 ms`）`[已测]` |
| 可信点击同步 `navigator.clipboard.write([item])` | ✅ **通过，零 `NotAllowedError` / `TypeError`**（总计 `536.9 ms`，`canvas JPEG→PNG 447.6 ms`）`[已测]` | ✅ **通过，零 `NotAllowedError` / `TypeError`**（总计 `42 ms`，`fetch 2 ms` + `decrypt 2 ms` + `canvas JPEG→PNG 38 ms`）`[已测]` |
| 真实剪贴板回读（`navigator.clipboard.read()`） | ✅ 命中 `image/png`，`1,019,198 B`（Skia 重编码），魔数 `89 50 4e 47 0d 0a 1a 0a` `[已测]` | N/A（无头 WebKit 无法免交互调用 `clipboard.read()`，需物理 iPhone 真机跨 App 粘贴验证） |
| 未捕获页面错误（`pageerror`） | `0` `[已测]` | `0` `[已测]` |

---

## 5. `[待 iPhone 真机补测]` 清单（物理 iPhone 主屏独立 PWA）

当前环境未连接物理 iPhone，依据 `AGENTS.md` §5（F-16）严格不外推桌面模拟结论，以下 4 项必须在真实 iPhone（**经 Safari「添加到主屏幕」后的 Standalone PWA**，经 HTTPS / Tailscale 托管 [`spikes/s-clip-2-pwa-wasm/bench.html`](../../spikes/s-clip-2-pwa-wasm/bench.html)）补测后再将 `ADR-11` 升为 `Accepted`：

| # | 物理 iPhone 真机验证项 | 实测记录栏 | 准出标准 |
| --- | --- | --- | --- |
| 1 | `WasmClipCodec.encryptBlob` / `decryptBlob` `5 MiB` 与 `10 MiB` 真机 3 次中位耗时与峰值内存 | `[待 iPhone 真机补测]`（参考估算：`5 MiB` ~`80–120 ms`、`10 MiB` ~`160–240 ms` `[估算]`） | 零 Jetsam 闪退，10 MiB 加密 `< 1,000 ms` `[目标]` |
| 2 | 主屏独立 PWA（Standalone）点击 **Copy Encrypted JPEG as PNG (Sync Promise)** 是否触发 `NotAllowedError` / `TypeError` | `[待 iPhone 真机补测]` | `Copy PNG PASS`，零异常 |
| 3 | 点击复制后立即切到 **微信（WeChat）** 与 **Apple 备忘录（Notes）** 长按粘贴 | `[待 iPhone 真机补测]` | 完整粘贴出 `1920×1080` 清晰图片（非空白、非降级为文字） |
| 4 | 弱网延迟模拟（如 `fetch` 耗时 `2–4 s` 才返回 `pngBlobPromise`）下，iOS Safari 是否仍保持该次点击的瞬态粘贴板写入授权不超时 | `[待 iPhone 真机补测]` | 若 iOS 对慢网 `pngBlobPromise` 存在超时窗口，M4 UI 须先点击下载至内存缓存、再提供即时「复制 PNG」二次轻点兜底 |

---

## 6. 给 M4 正式实现的工程建议

1. **立刻修复 `scripts/build-wasm.sh` 调试段膨胀（立省 `90.51 KiB` gzip）**：在 `wasm-bindgen` 命令中追加 `--remove-name-section`（零新依赖，桌面与 PWA 均受益，使 `pkg-pwa` 含 `WasmClipCodec` 后仅 `291.31 KiB` gzip-9，稳守 `< 350 KiB` 预算）；并可在 `.github/workflows/ci.yml` / `deploy-cloud.yml` 按需补装 `binaryen >= 117` 运行 `wasm-opt -Oz` 进一步压低体积。
2. **修正 `docs/interface-contracts.md` §5 中 `WasmClipCodec.decryptMeta` 签名**：`docs/data-structures.md` §3.3 已将 `flags`（含 `bit 0 = ephemeral`）绑定进 `MNC1` AAD，但 §5 的 `decryptMeta(clipId, authorDeviceId, envelope)` 漏掉了 `ephemeral: boolean` 参数。M4 应显式传入 `ephemeral: boolean`（常规队列 `GET /v1/clip` 传 `false`，瞬态帧 `clip_ephemeral` 传 `true`），防止恶意中继跨通道重放。
3. **坚持 `AeadInOut` 单遍加解密**：`mynote_core::clip` 应使用 `AeadInOut::encrypt_inout_detached` / `decrypt_inout_detached` 直接写入目标 `Vec<u8>`，将 10 MiB 图片往返的 WASM 线性内存峰值压在 `~24 MiB`（省去额外的 `10 MiB` 临时拷贝），显著降低 iOS WebKit Jetsam 压力。
4. **放开 `mynote-wasm` 的 `pwa` CSPRNG 绑定**：将 `crates/mynote-wasm/src/lib.rs` 中 `js_get_random_values` 与 `fill_random` 的 `#[cfg(feature = "desktop")]` 门控改为全 feature 启用，供 `WasmClipCodec` 生成 24 字节随机 Nonce。
5. **Safari `image/png` 转换与大图兜底**：当图片原始 MIME 已是 `image/png` 时，直接解析 `new Blob([rawBytes], { type: 'image/png' })` 跳过 `<canvas>` 重编码以省去数十至数百毫秒耗时与内存；仅当原始 MIME 为 `image/jpeg` / `image/webp` / `image/gif` 时走离屏 `<canvas>.toBlob('image/png')` 转换。
