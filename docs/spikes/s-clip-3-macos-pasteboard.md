# S-Clip-3 实测报告：macOS 原生 `NSPasteboard` 图文读写、UTI 敏感过滤与依赖体积评估（Issue #51）

- **状态**：**✅ PASS（macOS 桌面真机 5/5 必测项 + AppKit 懒承诺验证 + SVG XSS 拦截全部通过）**
- **实测环境**：`macOS 27.2.1 (Build 26B131)` / `arm64`（Apple M4, 10 核, 16 GiB RAM）/ `rustc 1.92.0` / `cargo 1.92.0`
- **复现路径**：[`spikes/s-clip-3-macos-pasteboard/`](../../spikes/s-clip-3-macos-pasteboard/)
  - 实机验证：`CARGO_TARGET_DIR=/tmp/mynote-s-clip-3 cargo run --release --bin run-tests` 与 `CARGO_TARGET_DIR=/tmp/mynote-s-clip-3 cargo test`
  - 体积与编译耗时复现：`CARGO_TARGET_DIR=/tmp/mynote-s-clip-3 ./measure.sh`
- **核心结论（支撑 `ADR-11` 的 macOS 原生剪贴板部分进入 M4a-3 / M4b-1）**：
  1. **依赖选型拍板**：M4a-3 生产推荐采用 **`objc2 0.6.5` + `objc2-foundation 0.3.2` + `objc2-app-kit 0.3.2`（强制 `default-features = false` 精准按类启用）+ `image 0.25.10`（`default-features = false, features = ["png", "jpeg", "webp", "gif", "tiff"]`）**。
     - 纯剪贴板层（`objc2-typed-surgical`）相比零依赖基线仅增 **`+20.0 KiB`** `[已测]`（仅比手写 `unsafe` `msg_send!` 的 `objc2-raw` 多 **`+1.7 KiB`** `[已测]`），全量读写代码 **`0` 处 `unsafe`**，且比默认全开 `objc2-app-kit` **快 `5.6×`**（净编译 `2.74 s` vs `15.41 s` `[已测]`，少拉 `10` 个无关 Apple 框架 crate）。
     - 叠加跨平台纯 Rust 5 格式 `image` 后，完整剪贴板 + 图片归一化模块总 stripped 体积增量（匹配根 `Cargo.toml` 的 `lto = "thin", strip = true`）为 **`+2,074.5 KiB`（`+2.03 MiB`）** `[已测]`，干净编译耗时 **`10.71 s`** `[已测]`。
  2. **真机语义全部达标**：在真实 `NSPasteboard.generalPasteboard()` 上完成文本往返、`public.png` 优先避读 `public.tiff`、`public.tiff` 独占回退转码 PNG（1080p ~8.1 MiB TIFF → PNG 仅 **`13.7–16.6 ms`** `[已测]`）、7 类敏感/远端/回环 UTI 零读负载预检，以及 `dev.mynote.synced-clip` / `TransientType` / `ConcealedType` / `CurrentHostOnly` 原子写入验证。
  3. **三项关键真机发现（直接指导 M4a-3 / M4b-1 实现）**：
     - **发现 A（macOS 自动合成 `public.tiff`）**：实测仅向 `NSPasteboard` 写入 `public.png` + `dev.mynote.synced-clip` 后，macOS `pboard` 自动向外暴露 `["public.png", "Apple PNG pasteboard type", "dev.mynote.synced-clip", "public.tiff", "NeXT TIFF v4.0 pasteboard type"]` `[已测]`。这从根源证实了「优先检 `public.png`、绝不先读 `public.tiff`」是强约束而非防御过度。
     - **发现 B（AppKit 懒承诺与后台线程告警）**：通过真实 `NSPasteboardItemDataProvider` 证明仅检 `pb.types()` 时 macOS **`0` 次**触发 `pasteboard:item:provideDataForType:`（阳性对照显式读取精确触发 `1` 次）`[已测]`；但在后台线程对承诺项同步调用 `stringForType:` 时，AppKit 输出警告 `NSPasteboard: synchronous promise fulfillment requested from a background thread!`。因此 M4a/M4b 写入必须始终写**即刻数据（eager data）**，且后台轮询跳过 `com.apple.is-remote-clipboard` 可完全避开承诺兑现。
     - **发现 C（macOS 27.2.1 权限行为）**：非沙箱 CLI/二进制调用 `generalPasteboard().accessBehavior()` 实测返回 `2`（`NSPasteboardAccessBehavior::AlwaysAllow`）`[已测]`，读写与类型预检均零系统弹窗；但该 API 为 macOS 15.4+ 新增，生产代码若兼容旧版 macOS 不应无条件调用。

---

## 1. 依赖选型与二进制体积 / 编译耗时实测

所有配置均严格编译同一生产等价入口 `--bin s-clip-3-macos-pasteboard`（`backend-objc2-raw` 与 `backend-objc2-typed` 执行完全对称的读写与 5 格式编解码路径，排除测试桩或 LTO 死代码消除偏差），复用根 `Cargo.toml` 的 `[profile.release]`（`lto = "thin"`, `strip = true`），离线清空独立 `CARGO_TARGET_DIR` 实测纯 Rust 编译时间：

| 配置 Profile | 正常依赖 Crate 数 | 干净 Release 编译耗时 | Stripped 二进制总大小 | 相对 Baseline 增量 | 评估结论 |
| --- | ---: | ---: | ---: | ---: | --- |
| `0-baseline`（零依赖空 CLI） | `1` | `1.51 s` `[已测]` | `343.5 KiB` (`351,696 B` / `0.34 MiB`) `[已测]` | `+0.0 KiB` | Rust stdlib macOS arm64 基线 |
| `1-objc2-raw`（仅 `objc2 0.6.5` + 手写 `msg_send!`） | `3` | `2.13 s` `[已测]` | `361.7 KiB` (`370,400 B` / `0.35 MiB`) `[已测]` | `+18.3 KiB` (`+0.02 MiB`) | 需手写十余处 `unsafe` + 裸指针/引用计数，维护风险高 |
| **`2-objc2-typed-surgical`**（`objc2` + `objc2-foundation` 5 特性 + `objc2-app-kit` 2 特性） | **`6`** | **`2.74 s`** `[已测]` | **`363.4 KiB`** (`372,160 B` / `0.35 MiB`) `[已测]` | **`+20.0 KiB` (`+0.02 MiB`)** | **✅ 剪贴板层最优**：比 raw 仅多 **`+1.7 KiB`**，零 `unsafe` |
| `3-objc2-appkit-default`（对照：未关 `default-features`） | `16` | **`15.41 s`** `[已测]` | `363.4 KiB` (`372,144 B` / `0.35 MiB`) `[已测]` | `+20.0 KiB` (`+0.02 MiB`) | ❌ 拖入 10 个无关 Apple 框架，干净编译慢 **`5.6×`** |
| `4-typed+img-png-tiff`（`2` + `image` 仅 `png, tiff`） | `34` | `8.80 s` `[已测]` | `1,378.0 KiB` (`1,411,024 B` / `1.35 MiB`) `[已测]` | `+1,034.5 KiB` (`+1.01 MiB`) | 缺少 JPEG/WebP/GIF 解码，无法支撑 iPhone 上传图归一化 |
| `5-raw+img-full`（`1` + `image` 5 格式） | `35` | `10.35 s` `[已测]` | `2,400.1 KiB` (`2,457,696 B` / `2.34 MiB`) `[已测]` | `+2,056.6 KiB` (`+2.01 MiB`) | 较 typed 仅省 `17.9 KiB`（`< 0.8%`），不值得引入手写 `unsafe` |
| **`6-typed+img-full`**（**M4a-3 推荐组合**：`2` + `image` `png, jpeg, webp, gif, tiff`） | **`37`** | **`10.71 s`** `[已测]` | **`2,418.0 KiB`** (`2,476,016 B` / `2.36 MiB`) `[已测]` | **`+2,074.5 KiB` (`+2.03 MiB`)** | **✅ M4a-3 最终选型**：纯 Rust、零 C 依赖、双桌面共享 `image` |

**体积归因拆解**：
- `objc2` 类型安全剪贴板绑定本体仅占 **`+20.0 KiB`** `[已测]`（不到总增量的 `1%`），相比手写 `unsafe` `msg_send!` 的差异可忽略不计（`+1.7 KiB` 纯剪贴板 / `+17.9 KiB` 含完整图像）。
- 约 **`+2.01 MiB`** `[已测]` 增量来自跨平台纯 Rust `image 0.25.10`（`png 0.18.1`、`tiff 0.11.3`、`zune-jpeg 0.5.15`、`image-webp 0.2.4`、`gif 0.14.2` 及颜色管理 `moxcms`）；该依赖在 Omarchy Linux 端同样用于 JPEG/WebP → PNG 剪贴板写入归一化与缩略图生成，属于双桌面共享必要成本（已关闭 `rayon`、`avif`、`exr`、`hdr` 等重型默认特性）。

---

## 2. 真机 `NSPasteboard.generalPasteboard()` 实测结果（5/5 必测项 + 附加安全项）

所有测试运行前由 RAII `ClipboardRestoreGuard` 捕获当前剪贴板（预检避免触发敏感或远端拉取），退出或 panic 时自动恢复原状。以下均为本机 MacMini（Apple M4 / macOS 27.2.1）真实执行结果 `[已测]`：

| 测试项 | 验证场景 | 实测观测数据 `[已测]` | 结果 |
| --- | --- | --- | :---: |
| **Test 1：UTF-8 文本往返与 `changeCount`** | 写入含 ASCII / CJK / Emoji / 换行的 45 B UTF-8 字符串并读回 | `changeCount` 精确递增 `+1`（`93 -> 94`）；读回字节 100% 一致；`types_queries = 1`，`stringForType = ["public.utf8-plain-text"]`，`dataForType = []` | **✅ PASS** |
| **Test 2：PNG + 更大 TIFF 同项优先读 PNG** | 同一 `NSPasteboardItem` 同时放入 `public.tiff`（128×128，**`65,750 B`**，刻意排前）与 `public.png`（16×16，**`668 B`**）；另做 `NSPasteboardItemDataProvider` 懒承诺 `public.tiff` 对照 | `pb.types()` 同时暴露两 UTI；读取器仅调用 `dataForType(["public.png"])`（**0 次**读 `public.tiff`），返回字节与 668 B 原 PNG 逐字节一致；AppKit 懒承诺 `public.tiff` 回调次数 = **`0`** | **✅ PASS** |
| **Test 3：仅 `public.tiff` 回退转码 PNG** | 向剪贴板仅写入 `public.tiff`（64×48 RGBA，`12,502 B`），另压测 1920×1080 未压缩 RGBA TIFF（`8,100 KiB`） | `pb.types()` 不含 `public.png`；读取器回退读 `public.tiff` 并转码为合法 PNG（`6,686 B`，含完整 8 字节魔数 `89 50 4E 47 0D 0A 1A 0A`，反解码像素与原图 100% 相等，耗时 **`0.24–0.31 ms`**）；1080p 8.1 MiB TIFF → 4.3 MiB PNG 耗时 **`13.7–16.6 ms`** | **✅ PASS** |
| **Test 4：7 类敏感 / 远端 / 回环 UTI 零读预检** | 逐一将 `org.nspasteboard.ConcealedType`、`TransientType`、`AutoGeneratedType`、`com.agilebits.onepassword`、`com.apple.is-remote-clipboard`、`dev.mynote.synced-clip`、`dev.mynote.vault-secret`（0 字节标记）与文本绑定写入；另对 `com.apple.is-remote-clipboard` 做真实 AppKit 懒承诺验证 | **7/7** 全部在 `types()` 阶段返回对应 `Skipped(reason)`，**`dataForType` = 0 次、`stringForType` = 0 次**；AppKit 懒承诺 `pasteboard:item:provideDataForType:` 在默认跳过模式下调用 **`0` 次**，在阳性对照（`ignore_universal_clipboard = false`）下精确调用 **`1` 次**并读出载荷 | **✅ PASS** |
| **Test 5：原子写入标记与独立读验证** | ① 普通同步文本（`+ dev.mynote.synced-clip`）；② 瞬态敏感文本（`+ synced-clip + TransientType + ConcealedType` + `CurrentHostOnly`）；③ 同步 PNG（`+ synced-clip`） | 独立 `pb.types()` 实测均完整包含全部预期 UTI（0 字节 `NSData::with_bytes(&[])` 被 `pboard` 完整保留）：<br>• 普通文本：`["public.utf8-plain-text", "NSStringPboardType", "dev.mynote.synced-clip"]`<br>• 瞬态敏感：`["public.utf8-plain-text", "NSStringPboardType", "dev.mynote.synced-clip", "org.nspasteboard.TransientType", "org.nspasteboard.ConcealedType"]`<br>• 同步 PNG：`["public.png", "Apple PNG pasteboard type", "dev.mynote.synced-clip", "public.tiff", "NeXT TIFF v4.0 pasteboard type"]`<br>且本机监听读均准确识别 `SyncedByMynote` 跳过（回环防护生效） | **✅ PASS** |
| **Bonus：SVG XSS 防护** | 仅写入 `public.svg-image`（含 `<script>` 载荷） | 在 `types()` 阶段被归为 `UnsupportedTypes` 跳过（`0` 次 `dataForType`）；图片归一化层显式拒绝 `image/svg+xml` | **✅ PASS** |

> **实测诚实边界（F-16）**：本机实测已通过真实 AppKit `NSPasteboardItemDataProvider` 懒承诺证明「仅读 `pb.types()` 不会触发 macOS 懒数据兑现」；但本机未连接同一 Apple ID 下开启 Handoff 的实体 iPhone，**跨物理 iPhone ↔ Mac 的真实 BLE + AWDL Universal Clipboard 端到端静默观测**记为 `[待 iPhone 真机补测]`（机制同源，预期零拉取）。

---

## 3. 给 M4a-3 与 M4b-1 的生产落地建议

### 3.1 `Cargo.toml` 精确依赖配置（`crates/mynote-cli/Cargo.toml`）

```toml
# 仅在 macOS 目标启用，零 Linux/WASM 依赖污染
[target.'cfg(target_os = "macos")'.dependencies]
objc2 = { version = "0.6.5", default-features = false, features = ["std"] }
objc2-foundation = { version = "0.3.2", default-features = false, features = ["std", "NSArray", "NSData", "NSEnumerator", "NSString"] }
objc2-app-kit = { version = "0.3.2", default-features = false, features = ["std", "NSPasteboard", "NSPasteboardItem"] }

# 双桌面共享（macOS TIFF 回退 + 双桌面 JPEG/WebP->PNG 归一化与缩略图）
[dependencies]
image = { version = "0.25.10", default-features = false, features = ["png", "jpeg", "webp", "gif", "tiff"] }
```

- **红线**：严禁移除 `objc2-app-kit` / `objc2-foundation` 的 `default-features = false`（否则单此一项就会拖慢干净构建 `+12.7 s` 并引入 `objc2-cloud-kit` 等 10 个无关框架）。

### 3.2 必须保留的 5 条 macOS 工程实践

1. **全程包裹 `objc2::rc::autoreleasepool`**：Daemon 后台轮询线程没有 AppKit `NSRunLoop`，每次 `changeCount()` / `types()` / 读写都必须置于 `autoreleasepool(|_| ...)` 内部，防止 `NSArray`/`NSString`/`NSData` 永久泄漏。
2. **单 `NSPasteboardItem` + `writeObjects:` 原子提交**：绝不要先 `setString_forType` 再分步 `setData_forType` 贴标记，以免 Maccy/1Password 或其他监听器在两条调用之间竞态读到无 `ConcealedType` / `TransientType` 的裸文本；用单个 `NSPasteboardItem` 一次性挂齐正文与全部标记 UTI 后 `writeObjects(&[item])` 原子落盘，且始终写入**即刻数据（eager data）**而非懒承诺。
3. **瞬态项启用 `NSPasteboardContentsOptions::CurrentHostOnly`**：写入 `--ephemeral` 敏感剪贴板或 Vault 复制内容时，用 `pb.prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly)` 替代 `pb.clearContents()`，在系统层阻断 Apple Universal Clipboard 将敏感短串广播到附近其他 Apple 设备（同时保留 `TransientType` + `ConcealedType` 防本机历史管理器落盘）。
4. **严格的 UTI 预检与读取优先级**：
   - 先读 `pb.types()` → 命中任何敏感/瞬态/回环/默认忽略的 `com.apple.is-remote-clipboard` UTI 时**立即返回跳过**，零 `dataForType` / `stringForType` 调用；
   - 图片按 `public.png` → `public.jpeg` → `org.webmproject.webp` → `com.compuserve.gif` → `public.tiff`（仅作兜底并在本机转 PNG，超 `10 MiB` 拒绝）顺序选择，绝不优先读 macOS 自动合成的 `public.tiff`；
   - 严禁将 `public.svg-image` 当作位图图片读取或渲染（守住 T4 / `SEC-06`）。
5. **M4b-1 后台轮询调度细节**：
   - 以 `changeCount()` 做廉价 `O(1)` 轮询门槛（推荐 `250–300 ms` 间隔，仅在 `changeCount` 变化时才读 `types()`），减少不必要的 `pboard` IPC；
   - 遵循本机实测的回环双重防护：`dev.mynote.synced-clip` UTI 预检 + 转码后实际写入系统剪贴板的 PNG 字节 `BLAKE3` 哈希（`2,000 ms` 抑制窗）；
   - 不要在生产路径无条件调用 macOS 15.4+ 新增的 `accessBehavior()`，如需诊断请先判断版本或用 `respondsToSelector:` 防在 macOS 13/14 上崩溃。
