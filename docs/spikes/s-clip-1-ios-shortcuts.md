# S-Clip-1 实测报告：纯同步 JS `XChaCha20-Poly1305` `MNC1` ↔ Rust 字节级互通与 V8 / JSC 性能基线（Issue #49）

- **当前状态**：**`partial_pending_iphone` — 纯同步 JS `MNC1` 编解码器（零依赖、零 `crypto.subtle`、零 `BigInt`）与 Rust `chacha20poly1305 0.11.0` 双向字节级互通、负例拦截及 Apple M4 上的 V8 / macOS JavaScriptCore（JIT 与无 JIT LLInt 双模式）基准测试全部通过 `[已测]`；因当前未连接物理 iPhone，iOS Shortcuts + Scriptable 真机耗时、Jetsam 内存峰值、`Data.fromBytes` 桥接行为与 `Allow Paste` 弹窗核验标记为 `[待 iPhone 真机补测]`**。`ADR-11` 保持 `Proposed`，待物理 iPhone 补测与其余 `S-Clip` 验证项全部闭环后再决定是否升级为 `Accepted`。
- **核心结论**：
  1. **双向字节级 100% 互通 `[已测]`**：[`mnc1_sync.js`](../../spikes/s-clip-1-ios-shortcuts/mnc1_sync.js) 在 Node.js v26.13.1（V8）与 macOS 原生 JavaScriptCore（`jsc` 原始版及压缩版）下全部通过 RFC 8439 §2.5.2 Poly1305、draft-irtf-cfrg-xchacha §2.2.1 HChaCha20、§A.3.1 XChaCha20-Poly1305、Poly1305 模 $2^{130}-5$ 边界用例，以及 Rust 生成的 `5` 条正例与 `13` 条负例；Rust `chacha20poly1305 0.11.0` 亦成功解密并字节级一致复现 JS 生成的 `16` 条正例（覆盖 `0 B` 至 `512 KiB` 及 `ClipMetaV1` 文本/图片/瞬态结构）并拒绝全部 `13` 条负例。
  2. **热态与冷态吞吐远超预期，无 JIT 解释器（LLInt）是最关键的 iOS 风险基线 `[已测]`**：
     - **macOS JSC（JIT 开启，Apple M4）**：`256 B` 文本热态 **`0.004 ms`** / 冷态 **`0.607 ms`**；`500 KiB` 二进制热态 **`2.418 ms`**（`201.94 MiB/s`）/ 冷态 **`12.151 ms`**；`1.5 MiB` 二进制热态 **`7.388 ms`**（`203.03 MiB/s`）/ 冷态 **`18.707 ms`**。
     - **macOS JSC（`--useJIT=false` LLInt 纯解释器，模拟 iOS App Extension 禁用 JIT 最坏路径）**：通过消除 ChaCha20 与 Poly1305 热循环内的全部 JS 函数调用（~240 万次/1.5 MiB），将 `1.5 MiB` 加密耗时从 `408.09 ms` 降至 **`230.43 ms`**（冷态 **`235.81 ms`**，`6.51 MiB/s`），`500 KiB` 降至 **`74.24 ms`**（冷态 **`76.64 ms`**），`256 B` 文本仅 **`0.112 ms`**（冷态 **`0.578 ms`**）。
  3. **提前暴露 4 个 M4 工程实坑**：① 裸 JSC（`jsc` 与 Scriptable 类似环境）默认无 `TextEncoder`、`TextDecoder` 与 `crypto.getRandomValues` `[已测]`；② `MNC1` 的 `flags` 仅参与 AAD 认证而不在 45 B 头部明文携带，需为 `WasmClipCodec.decryptMeta` 显式补齐 `ephemeral: boolean` 参数；③ `ClipMetaV1.blob.sha256_hex` 要求 Scriptable 侧同时具备 SHA-256 能力；④ Scriptable `Data.fromBytes` 若要求普通 JS `Array` 而非 `Uint8Array`，对 `1.5 MiB` 图片可能触发额外数组装箱内存峰值，必须在真机核验。
- **复现路径**：[`spikes/s-clip-1-ios-shortcuts/`](../../spikes/s-clip-1-ios-shortcuts/)（一键复现：`bash spikes/s-clip-1-ios-shortcuts/run_all.sh`；独立 Rust 校验仓需在主仓 `Cargo.toml` 排除 `spikes/s-clip-1-ios-shortcuts/rust-interop`）。

---

## 1. 线格式一致性与双向互通实测（`[已测]`）

严格对齐 [`docs/data-structures.md`](../data-structures.md) §3.1 / §3.3 / §3.8 与 [`crates/mynote-core/src/crypto.rs`](../../crates/mynote-core/src/crypto.rs)、[`crates/mynote-core/src/ids.rs`](../../crates/mynote-core/src/ids.rs)：

- **45 字节标准信封头**：`"MNC1" (4B) || 0x01 (1B) || clip_kid (16B ULID) || nonce (24B) || XChaCha20-Poly1305 ciphertext (含 16B Tag)`。
- **唯一 AAD**：`"MNC1" || 0x01 || clip_kid (16B) || clip_id (16B) || utf8(device_id) || flags (1B)`。
- **`flags` 字节**：`bit 0 (0x01)` = `ephemeral`；`bit 1 (0x02)` = `payload_type`（`0` = `pad256(utf8_json(ClipMetaV1))`，`1` = 原始二进制流，无填充无 JSON 包装无 Base64）；`bits 2..7` 必须为 `0`，非零保留位强制报 `INTEGRITY_ERROR`。
- **`pad256` / `unpad256`**：`pad_zeros = (256 - ((len + 1) % 256)) % 256`，尾部严格校验全零填充与长度整除 `256`。

### 1.1 黄金向量与双向校验结果

固定向量文件：[`spikes/s-clip-1-ios-shortcuts/golden_vectors.json`](../../spikes/s-clip-1-ios-shortcuts/golden_vectors.json)（由 Rust `chacha20poly1305 0.11.0` 确定性生成）。

| 校验维度 | 测试范围 | Node.js v26.13.1 (V8) | macOS JSC (`jsc` 原始 & 压缩版) | Rust `chacha20poly1305 0.11.0` |
| --- | --- | :---: | :---: | :---: |
| 密码学原语向量 | RFC 8439 §2.5.2 Poly1305、draft-xchacha §2.2.1 HChaCha20、§A.3.1 XChaCha20-Poly1305、Poly1305 模 $2^{130}-5$ 回绕边界 | ✅ 通过 `[已测]` | ✅ 通过 `[已测]` | 依赖上游已认证实现 |
| ULID & `pad256` & UTF-8 | 4 组 ULID 边界（含 `0000...`、`7ZZZ...`）+ 8 组非法 ULID 拒绝 + 8 组 `pad256` 边界（`0..512 B`）+ CJK / Emoji / 非法 UTF-8 | ✅ 通过 `[已测]` | ✅ 通过 `[已测]` | ✅ 通过 `[已测]` |
| Rust → JS 正例（`5` 条） | `(a)` 常规文本 `ClipMetaV1`（`0x00`）；`(b)` 瞬态文本（`0x01`）；`(c1)` 67 B PNG 二进制流（`0x02`）；`(c2)` 1029 B 多块二进制流（`0x02`）；`(c3)` 255 B `pad256` 零填充边界（`0x00`） | ✅ 解密通过且重加密逐字节一致 `[已测]` | ✅ 解密通过且重加密逐字节一致 `[已测]` | ✅ 自检通过 `[已测]` |
| JS → Rust 正例（`16` 条） | `mnc1_sync.js` 生成 `0, 1, 15, 16, 17, 63, 64, 65, 255, 256, 257, 4097, 65537, 524288 B` 二进制流 + 图片 `ClipMetaV1` + 瞬态中文文本 | ✅ 生成完成 `[已测]` | — | ✅ 全部解密通过且 Rust 重加密逐字节一致 `[已测]` |
| 负例拒绝（`13` 条） | 篡改 `clip_id` / `device_id` / `ephemeral` / `payload_type`、密文与 Tag 单比特翻转、错误魔数/版本、截断信封、合法 AEAD 下的保留位 `0x04` 与 `0x82`、合法 AEAD 下的非零填充字节与未填充 `payload_type=0` | ✅ `13/13` 拒绝 `[已测]` | ✅ `13/13` 拒绝 `[已测]` | ✅ `13/13` 拒绝 `[已测]` |

---

## 2. 体积与性能基准实测（`[已测]`）

### 2.1 测试环境与方法学

- **宿主机**：Mac mini（Apple M4，10 核 arm64，16 GiB RAM，macOS `27.2.1` / Build `26B131`，内核 Darwin `27.2.0`），测试期间系统 `load average = 1.52`。
- **运行时**：`Node.js v26.13.1`（V8）、macOS 系统原生 `/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc`（同时实测默认 JIT 模式与 `--useJIT=false` LLInt 纯解释器模式）、`rustc 1.92.0`。
- **防失真措施**：热态为 `5` 轮预热后交替采样 `7` 轮取中位数与最小/最大区间（`256 B` 文本单轮迭代 `200` 次均摊时钟精度）；冷态为每个载荷在独立全新进程中交替跑 `5` 次（无预热、无跨用例 JIT 污染）；每次计时均校验往返解密正确性并累积防 DCE 校验和（`errors = 0`）。

### 2.2 `mnc1_sync.js` 代码体积（`[已测]`）

| 工件口径 | 行数 | 原始体积 | 去注释/空白压缩体积（未混淆变量名） | `gzip -9` 体积 | 说明 |
| --- | ---: | ---: | ---: | ---: | --- |
| 完整双向编解码器（`mnc1_sync.js`，内联零调用热循环） | `405` `[已测]` | `20,724 B` (`20.24 KiB`) `[已测]` | `14,098 B` (`13.77 KiB`) `[已测]` | `4,825 B` (`4.71 KiB`) `[已测]` | 含完整加解密、严格 UTF-8、ULID、`pad256`/`unpad256` 及 RFC 原语导出 |
| 对照：辅助函数循环版（`qr()` 调用，未采用） | `354` `[已测]` | `16,880 B` (`16.48 KiB`) `[已测]` | `11,854 B` (`11.58 KiB`) `[已测]` | `4,203 B` (`4.10 KiB`) `[已测]` | 仅省 `2.2 KiB` 未混淆源码，但 JSC 无 JIT 慢 `1.77×`（`408 ms` vs `230 ms`） |
| M4a Scriptable 单向发送构建（剔除解密 + `esbuild --minify`） | — | — | 约 `5–6 KiB` `[估算]` | 约 `2.5–3 KiB` `[估算]` | `clip-write` 令牌不可读，生产脚本可仅嵌入加密子集并开启标识符压缩 |

### 2.3 热态加密/解密耗时与吞吐（7 轮中位数，`[已测]`）

| 载荷与路径 | Node.js v26.13.1 (V8 JIT) | macOS JSC (JIT) | macOS JSC (`--useJIT=false` LLInt) |
| --- | --- | --- | --- |
| `256 B` 文本 `encryptMnc1Meta`（输出 `573 B` 信封） | **`0.005 ms`** (`0.005–0.006`) `[已测]` | **`0.004 ms`** (`0.004–0.015`) `[已测]` | **`0.112 ms`** (`0.110–0.114`) `[已测]` |
| `256 B` 文本 `decryptMnc1Meta` | **`0.007 ms`** (`0.006–0.009`) `[已测]` | **`0.006 ms`** (`0.006–0.011`) `[已测]` | **`0.116 ms`** (`0.114–0.120`) `[已测]` |
| `500 KiB` 二进制 `encryptMnc1Blob` | **`2.595 ms`** (`2.570–2.625`, `188.2 MiB/s`) `[已测]` | **`2.418 ms`** (`2.394–3.219`, `201.9 MiB/s`) `[已测]` | **`74.242 ms`** (`73.158–77.729`, `6.58 MiB/s`) `[已测]` |
| `500 KiB` 二进制 `decryptMnc1Blob` | **`2.585 ms`** (`2.570–2.600`, `188.9 MiB/s`) `[已测]` | **`2.418 ms`** (`2.394–3.210`, `201.9 MiB/s`) `[已测]` | **`75.167 ms`** (`74.355–81.037`, `6.50 MiB/s`) `[已测]` |
| `1.5 MiB` 二进制 `encryptMnc1Blob` | **`7.985 ms`** (`7.870–8.076`, `187.9 MiB/s`) `[已测]` | **`7.388 ms`** (`7.360–10.129`, `203.0 MiB/s`) `[已测]` | **`230.432 ms`** (`226.993–235.619`, `6.51 MiB/s`) `[已测]` |
| `1.5 MiB` 二进制 `decryptMnc1Blob` | **`8.003 ms`** (`7.885–8.035`, `187.4 MiB/s`) `[已测]` | **`7.402 ms`** (`7.387–10.048`, `202.7 MiB/s`) `[已测]` | **`231.079 ms`** (`229.669–236.838`, `6.49 MiB/s`) `[已测]` |

### 2.4 独立冷态单次加密耗时（模拟 Shortcuts 每次冷启进程，5 次独立进程中位数，`[已测]`）

| 载荷 | Node.js v26.13.1 (V8 JIT) | macOS JSC (JIT) | macOS JSC (`--useJIT=false` LLInt) |
| --- | --- | --- | --- |
| `256 B` 文本（`encryptMnc1Meta`） | **`0.499 ms`** (`0.489–0.512`) `[已测]` | **`0.607 ms`** (`0.599–0.616`) `[已测]` | **`0.578 ms`** (`0.561–0.584`) `[已测]` |
| `500 KiB` 二进制（`encryptMnc1Blob`） | **`6.130 ms`** (`6.076–6.258`) `[已测]` | **`12.151 ms`** (`12.103–12.164`) `[已测]` | **`76.641 ms`** (`76.311–78.122`) `[已测]` |
| `1.5 MiB` 二进制（`encryptMnc1Blob`） | **`11.048 ms`** (`10.913–11.361`) `[已测]` | **`18.707 ms`** (`18.657–20.085`) `[已测]` | **`235.814 ms`** (`234.644–244.644`) `[已测]` |

### 2.5 瓶颈拆解（`1.5 MiB` 热态分项耗时，`[已测]`）

| 运行时 | ChaCha20 耗时（占比） | Poly1305 耗时（占比） | 主要瓶颈 |
| --- | ---: | ---: | --- |
| Node.js v26.13.1 (V8 JIT) | `2.527 ms` (`32.2%`) `[已测]` | **`5.314 ms` (`67.8%`)** `[已测]` | Poly1305 5×26-bit 浮点双分裂乘加（无 BigInt 精确 53-bit 算术） |
| macOS JSC (JIT) | `2.391 ms` (`33.0%`) `[已测]` | **`4.863 ms` (`67.0%`)** `[已测]` | 同上；JIT 将 ChaCha20 32-bit 整数运算压至 ~627 MiB/s |
| macOS JSC (`--useJIT=false` LLInt) | **`139.076 ms` (`60.5%`)** `[已测]` | `90.847 ms` (`39.5%`) `[已测]` | LLInt 字节码逐指令解释 20 轮 32-bit 移位异或；取消 `qr()` 调用后从 `267.6 ms` 降至 `139.1 ms` |

- **内存占用观测**：Node.js 冷态单次加密 `1.5 MiB` 进程常驻内存（RSS）约 `27 MiB` `[已测]`；加密路径仅分配 1 份输出 `Uint8Array(N + 61)`（无 Base64、无中间拼接拷贝），相对原图净增量约 `1×` 载荷大小（`1.5 MiB` 约 `+1.5 MiB` 堆内存 `[保证]`）。
- **对 iPhone 真机的理性推演（不替代真机测量）**：iOS Shortcuts 后台扩展通常无法启用 JSC JIT，因此应以 **LLInt 基线（`235.8 ms` @ 1.5 MiB / `76.6 ms` @ 500 KiB）** 作为参考下界。若 iPhone 真机在后台扩展效率核上为 M4 LLInt 的 `2–4×` 耗时，`1.5 MiB` 预计约 `470–950 ms` `[估算]`（低于 `1.5 s` 准出红线），`500 KiB` 预计约 `150–310 ms` `[估算]`；最终是否维持 `1.5 MiB` 上限或收紧至 `512 KiB`，严格以物理 iPhone 实测为准。

---

## 3. Scriptable Keychain 与 iOS Shortcuts 集成说明（反哺 M4a）

1. **零明文落入 `.shortcut` 文件（原生 Keychain 托管）**：
   - 初始化脚本通过 `Keychain.set` 写入 5 项：`mynote_sync_url`、`mynote_device_id`、`mynote_clip_token`（严格限定 `scope = "clip-write"`，严禁存放 `SMK` 或 `read-write` 令牌）、`mynote_clip_kid`（26 字符 ULID）与 `mynote_clip_key_hex`（32 B `ClipKey`）。
   - Shortcuts 动作流中不保存任何令牌或密钥，仅将选中文本或经过原生 `Resize Image`（长边 `≤ 1920 px`）+ `Convert Image`（JPEG 80% / PNG）处理后的文件传给 Scriptable `Run Inline Script` / `Run Script`。
2. **协议与端点对齐（[`interface-contracts.md`](../interface-contracts.md) §4.2(7)）**：
   - 公共头：`Authorization: Bearer <clip_token>`、`X-Mynote-Protocol: 1`。
   - 小文本（`≤ 64 KiB`）：`POST /v1/clip`，JSON 体 `{ clip_id, clip_kid, kind: "text", ephemeral, meta_envelope_b64 }`（仅对小元数据信封做 Base64，零大对象膨胀）。
   - 图片（`≤ 1.5 MiB`）：`PUT /v1/clip/blob`，请求体为原始 `MNC1`（`payload_type = 1`）二进制字节流（`Content-Type: application/octet-stream`），元数据放 `X-Clip-Id`、`X-Clip-Kid`、`X-Clip-Kind: image`、`X-Clip-Meta-B64`；校验 `req.response.statusCode === 200` 且返回 JSON 中 `body.ok === true`（防 `302` 代理静默丢数）。
3. **本 Spike 提前发现的 3 项 Scriptable 运行时前置依赖**：
   - **CSPRNG 来源**：macOS 裸 `jsc` 实测 `typeof crypto === "undefined"` `[已测]`。`mnc1_sync.js` 严格禁止回退至 `Math.random()`；M4a 落地前必须在真机 Scriptable 确认 `crypto.getRandomValues` 是否可用，若不可用则改由两次 `UUID.string()`（底层为 iOS `NSUUID` / `SecRandomCopyBytes`，共 244 bit 熵）经 SHA-256 / 拼接提取 24 B Nonce 与 10 B ULID 随机位。
   - **图片 `sha256_hex`**：[`data-structures.md`](../data-structures.md) §3.8 要求图片 `ClipMetaV1.blob.sha256_hex` 供解密端强校验。建议在 Shortcuts 动作流中用原生 `Generate Hash (SHA256)` 算好后作为参数传给 Scriptable（硬件加速、零 JS 代码增量），或在 `mnc1_sync.js` 旁附带 ~1.2 KB 纯同步 JS SHA-256 兜底。
   - **`Data.fromBytes` 内存桥接**：若 Scriptable 的 `Data.fromBytes` 只接受普通 JS `Array` 而不直接接受 `Uint8Array`，`Array.from(u8)` 对 `1.5 MiB` 会额外分配约 `12–24 MiB` 装箱数组，极易逼近 Shortcuts 后台扩展 Jetsam 红线；真机测试时需优先验证 `Data.fromBytes(u8)` 直接传 `Uint8Array` 或改写临时文件后 `Data.fromFile(tmpPath)` 传给 `Request.body`（完后立即删除临时文件）。
4. **对 `interface-contracts.md` §5 `WasmClipCodec` 的建议修正**：
   - `flags`（含 `ephemeral` 位）仅存在于 AAD 而不存于 45 B 信封头，建议在 M4a 实现时将 `WasmClipCodec.decryptMeta(clipId, authorDeviceId, envelope)` 补充为 `decryptMeta(clipId, authorDeviceId, ephemeral, envelope)`，与 `mnc1_sync.js` 及 `mynote-core` 保持严格一致。

---

## 4. `[待 iPhone 真机补测]` 清单

以下项目无法在无物理 iPhone 的 Mac mini 上伪造或推断，待连接真机后逐项回填实测数据，再最终拍板 Shortcuts 图片压缩上限与 `ADR-11` 状态：

- [ ] **Scriptable 运行时能力探针** `[待 iPhone 真机补测]`：在真机 Scriptable 前台与 Shortcuts 后台扩展内分别检测 `typeof crypto?.getRandomValues`、`typeof TextEncoder`、`Data.fromBytes(new Uint8Array([1,2,3]))` 是否直接接受 `Uint8Array`，以及是否启用了 JSC JIT。
- [ ] **真机 `mnc1_sync.js` 加密耗时与 Jetsam 稳定性** `[待 iPhone 真机补测]`：在真机 iPhone（Share Sheet 后台扩展 + Action Button / 控制中心）分别执行 `256 B` 文本、`500 KiB` 压缩截图、`1.5 MiB` 压缩照片各 5 次，记录单次耗时、是否触发 Jetsam 强杀或 Shortcuts 超时，以及 `Data.fromBytes` vs `Data.fromFile` 路径稳定性。
- [ ] **iOS 剪贴板 `Allow Paste` 弹窗行为** `[待 iPhone 真机补测]`：分别验证 ① Share Sheet 传选中文本/相册图是否确为 `0` 次 `Allow Paste` 弹窗；② Action Button / 控制中心调用 `Get Clipboard` 在系统「设置 → 快捷指令 → 高级」授权后的实际弹窗频次。
- [ ] **真机端到端闭环联调** `[待 iPhone 真机补测]`：iPhone Scriptable 加密推送文本与压缩图至测试中继（或本地回环），由 macOS Rust `s-clip-1-rust-interop` / `mynote-core` 原样解开并校验字节与 `sha256_hex` 一致。
- [ ] **Shortcuts 压缩上限最终拍板** `[待 iPhone 真机补测]`：若真机 `1.5 MiB` 稳定 `< 1.5 s` 且零 Jetsam，维持 `1.5 MiB` 上限；若超时或 OOM，按预案收紧为 `512 KiB` 快速截图上限（大图走 PWA `mynote-wasm`）。

---

## 5. 可复现命令

```bash
# 一键运行全套体积测量、Rust 单测、Node V8 / macOS JSC / Rust 双向互通与热/冷态基准
bash spikes/s-clip-1-ios-shortcuts/run_all.sh

# 单独重新生成冻结黄金向量（确认与仓库文件一致）
CARGO_TARGET_DIR=/tmp/mynote-s-clip-1 cargo run --release \
  --manifest-path spikes/s-clip-1-ios-shortcuts/rust-interop/Cargo.toml -- \
  generate spikes/s-clip-1-ios-shortcuts/golden_vectors.json
```
