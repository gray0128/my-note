# S-Clip-4 实测报告：Omarchy / Hyprland Wayland 图文剪贴板与只读监听共存（Issue #52）

- **当前状态**：**✅ 真实 Omarchy（Arch + Hyprland + XWayland）实测全部通过**，支撑 `ADR-11` 的 Linux/Wayland 侧技术拍板。
- **核心结论**：
  1. **实测推翻「M4a 直接调 `wl-copy` 写多 MIME」假设**：Omarchy 实装的 `wl-clipboard 2.3.0` 的 `wl-copy` **不支持同时提供多个 `--type`**（重复传入 `-t` 时后者直接覆盖前者，`wl-copy --type image/png --type application/x-mynote-synced` 最终只剩 `application/x-mynote-synced`，普通软件彻底无法粘贴图片）；`--sensitive` 也仅支持硬编码附加 `x-kde-passwordManagerHint=secret`，无法附加自定义回环标记 `application/x-mynote-synced` 或 `application/x-mynote-vault-secret`。
  2. **M4a 与 M4b 统一采用纯 Rust `wl-clipboard-rs 0.9.5`（默认纯 Rust `wayland-backend`，零 C `libwayland-client` 依赖、零外部 `wl-copy`/`wl-paste` 依赖）**：在真实 `Hyprland 0.56.2` 上自动优先绑定官方 staging 协议 **`ext_data_control_manager_v1` v1**（旧合成器自动回退 `zwlr_data_control_manager_v1` v2）；`copy::Options::prepare_copy_multi` / `copy_multi` 原生支持任意多 MIME 组合写入，`foreground(false)` 底层为 `std::thread::spawn`（**零 `fork()`**，可安全运行于多线程 Tokio Daemon）；`watch::Watcher` **零 `set_selection` 调用**，严格先检查 offer MIME 列表再决定是否开启 pipe。
  3. **与 Omarchy 内置双 `wl-paste --watch` 监听器并发零冲突**：实测在 Omarchy 真实常驻监听器（`quickshell` 托管的 `wl-paste --type text --watch .../capture.sh text` 与 `wl-paste --type image/png --watch .../capture.sh image/png`）+ 额外 `wl-paste --watch`（模拟 `cliphist`）+ 本项目 Rust `Watcher` **共 4 个 data-control 观察者同时运行**下，突发 12 次读写全部 `12/12` 准确送达、所有含 `application/x-mynote-synced` / `x-kde-passwordManagerHint` / `application/x-mynote-vault-secret` 的条目均在读取 pipe 前跳过（`pipe_opened = false`）、Omarchy 自身 `capture.sh` 亦未落盘敏感 PNG、两个 Omarchy 监听进程 PID 全程保持一致、零剪贴板清空、零所有权竞争。
- **复现路径**：[`spikes/s-clip-4-hyprland-wayland/`](../../spikes/s-clip-4-hyprland-wayland/)（在 Omarchy 执行 `CARGO_TARGET_DIR=/tmp/s-clip-4-target cargo test && cargo build --release && ./run_omarchy_eval.sh /tmp/s-clip-4-target/release/s-clip-4-hyprland-wayland`）。

---

## 1. 真实测试环境（`tailscale-omarchy`）

| 维度 | 实测环境信息 `[已测]` |
| --- | --- |
| 主机与内核 | `Linux omarchy 7.2.15-1-omarchy #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux` |
| 合成器 | `Hyprland 0.56.2`（Arch 包 `hyprland 0.56.2-4`，`WAYLAND_DISPLAY=wayland-1`，`XDG_RUNTIME_DIR=/run/user/1000`） |
| XWayland | `xorg-xwayland 24.1.14-1`（`Xwayland :0 -rootless -core ... -wm 89`，`DISPLAY=:0`） |
| Wayland CLI | `wl-clipboard 1:2.3.0-1`（`wl-copy` / `wl-paste` 2.3.0） |
| 宿主内置剪贴板监听 | Omarchy Quickshell 插件（`/usr/share/omarchy/shell/plugins/clipboard/capture.sh`），常驻两条 `wl-paste --watch` 进程：<br>- PID `2309006`：`wl-paste --type text --watch /usr/share/omarchy/shell/plugins/clipboard/capture.sh text`<br>- PID `2309007`：`wl-paste --type image/png --watch /usr/share/omarchy/shell/plugins/clipboard/capture.sh image/png`<br>（注：该 Omarchy 主机未安装 `cliphist` 与 `wl-clip-persist`，但 Omarchy 插件使用与 `wl-paste --watch cliphist store` 完全相同的 `wl-paste --watch` data-control 订阅机制） |
| Rust 工具链与 Crate | `rustc 1.99.1` / `cargo 1.99.1`；`wl-clipboard-rs 0.9.5`、`wayland-client 0.31.15`、`wayland-protocols 0.32.13`、`wayland-protocols-wlr 0.3.12`、`blake3 1.8.8`、`x11rb 0.14.0` |

---

## 2. Wayland 协议探测与 `wl-copy` CLI 限制实测

### 2.1 Hyprland 0.56.2 暴露的剪贴板相关 Global（`probe-protocols`，`[已测]`）

| Wayland Global Interface | 实测版本 | 说明 |
| --- | :---: | --- |
| `ext_data_control_manager_v1` | **v1** `[已测]` | 官方 Wayland staging 协议；**`wl-clipboard-rs 0.9.5` 优先绑定此协议** |
| `zwlr_data_control_manager_v1` | **v2** `[已测]` | wlroots 兼容协议（支持 Primary Selection）；旧版合成器自动回退 |
| `wl_data_device_manager` | v3 `[已测]` | 常规窗口剪贴板与拖拽协议 |
| `zwp_primary_selection_device_manager_v1` | v1 `[已测]` | 中键选择协议；`is_primary_selection_supported() == true` `[已测]` |
| `wl_seat` | v9 `[已测]` | 输入席位 |

### 2.2 `wl-copy 2.3.0` CLI vs `wl-clipboard-rs 0.9.5` 多 MIME 对比（`[已测]`）

| 测试命令 / 方式 | `wl-paste --list-types` 实测输出 | 结论 |
| --- | --- | :---: |
| `printf "..." \| wl-copy` | `text/plain`, `text/plain;charset=utf-8`, `TEXT`, `STRING`, `UTF8_STRING` | ✅ 常规文本正常 |
| `printf "..." \| wl-copy --sensitive` | 上述文本类型 + `x-kde-passwordManagerHint`（值 `secret`） | ⚠️ 仅支持硬编码敏感标记 |
| `wl-copy --type image/png < test.png` | `image/png`（`77 B` SHA-256 无损往返） | ✅ 单 MIME 图片正常 |
| `wl-copy --type image/png --sensitive < test.png` | `image/png`, `x-kde-passwordManagerHint` | ⚠️ 仍无法附加自定义 MIME |
| `wl-copy -t "text/plain;charset=utf-8" -t "application/x-mynote-synced"` | **仅 `application/x-mynote-synced`** `[已测]` | ❌ **后者覆盖前者，文本丢失** |
| `wl-copy --type image/png --type application/x-mynote-synced < test.png` | **仅 `application/x-mynote-synced`** `[已测]` | ❌ **后者覆盖前者，图片丢失** |
| `wl-clipboard-rs` `prepare_copy_multi`（`MimeType::Text` + `application/x-mynote-synced`） | `application/x-mynote-synced`, `text/plain;charset=utf-8`, `UTF8_STRING`, `text/plain`, `STRING`, `TEXT` `[已测]` | ✅ **6 个 MIME 完整共存** |
| `wl-clipboard-rs` `prepare_copy_multi`（`image/png` + `application/x-mynote-synced`） | `application/x-mynote-synced`, `image/png` `[已测]` | ✅ **图片 + 防回环标记共存** |
| `wl-clipboard-rs` `prepare_copy_multi`（`image/png` + `--sensitive` + `application/x-mynote-synced`） | `application/x-mynote-synced`, `image/png`, `x-kde-passwordManagerHint` `[已测]` | ✅ **三者共存且 `wl-paste --type image/png` 字节一致** |

---

## 3. 只读观察者与 Omarchy 监听器共存实测矩阵（全部 `[已测]`）

### 3.1 功能矩阵（Cases A–G，Rust `Watcher` 与 Omarchy 双 `wl-paste --watch` 同跑）

| 用例 | 触发方式与负载 | `Watcher` 判定与 `pipe_opened` | Wayland `wl-paste` 核验 | 关键安全 / 生命周期核验 |
| --- | --- | --- | --- | --- |
| **A. 普通文本** | `wl-copy`（`27 B`） | `read_text`（`text/plain;charset=utf-8`），`pipe_opened=true`，`27 B`，BLAKE3 一致 | 原样读出 `27 B` | 正常捕获 |
| **B. 普通 PNG** | `wl-copy --type image/png`（`128×128`，`52,136 B`） | `read_image`（`image/png`），`pipe_opened=true`，`52,136 B`，`png_magic_valid=true` | SHA-256 `e734c890...` 完全一致 | 大于单页 pipe 缓冲无损读完 |
| **C. 多 MIME 已同步文本** | `wl-clipboard-rs`（文本 + `application/x-mynote-synced`） | **`skip`（`mynote_synced_echo_guard`），`pipe_opened=false`** | 文本与标记 `1` 均可正常读出 | **零 pipe 读取，防回环生效** |
| **D. 多 MIME 已同步 PNG** | `wl-clipboard-rs`（`83 B` PNG + `application/x-mynote-synced`） | **`skip`（`mynote_synced_echo_guard`），`pipe_opened=false`** | PNG SHA-256 `1f1875ad...` 与标记 `1` 均一致 | 前一 owner（用例 C）立即打印 `SERVE_EXITED` 退出，**零线程泄漏** |
| **E. 敏感 Vault 文本** | `wl-clipboard-rs`（文本 + `x-kde-passwordManagerHint=secret` + `application/x-mynote-vault-secret`） | **`skip`（`sensitive_mime_hint`），`pipe_opened=false`** | 用户仍可正常粘贴明文，`hint=secret` | **零 pipe 读取** |
| **F. 敏感已同步 PNG** | `wl-clipboard-rs`（`114 B` `secret.png` + `x-kde-passwordManagerHint` + `application/x-mynote-synced`） | **`skip`（`sensitive_mime_hint`），`pipe_opened=false`** | PNG SHA-256 `29317b5c...` 一致 | **Omarchy 自身 `capture.sh` 亦跳过**：`~/.local/state/omarchy/clipboard-images/29317b5c...png` 未生成 |
| **G. SVG 载荷（XSS 防护）** | `wl-clipboard-rs`（`image/svg+xml` `<svg onload=alert(1)/>`） | **`read_text`（`text/plain;charset=utf-8`），拒绝按图片处理** | `22 B` 原始文本 | 实测发现 `wl-clipboard-rs` 默认对 `*+xml` 附加 `text/plain`；位图白名单拒绝 `image/svg+xml` 进入图片通道，符合 `SEC-06` |

- **汇总与退出**：`total_events=7`，`pipe_reads_executed=3`，`skipped_without_read=4`，`cleared_events=0`，`exited_via_cancel_handle=true` `[已测]`。
- **Omarchy 监听器健康度**：测试前后 `ps` 输出完全一致，仍为 PID `2309006` 与 PID `2309007`，零重启、零异常退出 `[已测]`。

### 3.2 4 路并发观察者压力、重复粘贴、大 PNG 耗时与所有权生命周期（`[已测]`）

| 专项验证 | 实测结果 `[已测]` |
| --- | --- |
| **4 路并发 data-control 观察者突发 12 次读写**（Omarchy 2 路 + 额外 `wl-paste --type text --watch` 模拟 `cliphist` + Rust `Watcher`） | Rust `Watcher` 捕获 **`12/12`**（`pipe_reads_executed=5`，`skipped_without_read=7`，`cleared_events=0`，`exited_via_cancel_handle=true`）；额外 `wl-paste --watch` 捕获全部 11 次文本变更 + 初始 26 B 快照（`0` 丢包）；Omarchy PID `2309006`/`2309007` 不变 |
| **单 `wl-clipboard-rs` owner 连续 5 次粘贴**（`ServeRequests::Unlimited`） | 连续 5 次 `wl-paste` 全部返回 `multi-paste-persist-check`，未被消费清空 |
| **owner 进程退出后剪贴板行为** | 终止 `copy-multi` 进程后 150 ms，`wl-paste --list-types` 返回 `Nothing is copied`（exit `1`）——证实 Wayland 选区强绑定 owner 存活期 |
| **`1 MiB` PNG 多 MIME 往返耗时**（`1,010,153 B`，含 `--sensitive` + `--synced`） | `prepare_copy_multi` 就绪（含进程启动 + Wayland 建连与 roundtrip）：**`23 ms`**；`wl-paste --type image/png` 完整读出并算 SHA-256：**`5 ms`**，`sha_match=true` |
| **Rust 单元测试**（`cargo test`） | `4/4` 通过（敏感提示跳过、Vault/Synced 标记跳过、SVG 拒入图片通道、PNG/UTF-8 优先级）；`cargo build --release` 零警告 |

---

## 4. XWayland（`Xwayland :0`）交互边界实测说明（诚实记录）

- **已验证 `[已测]`**：
  - `wl-clipboard-rs` 写入文本时通过 `MimeType::Text` 自动同时宣告 `UTF8_STRING`、`STRING`、`TEXT`、`text/plain;charset=utf-8`、`text/plain` 全部 5 类 XWayland 标准文本 atom，写入图片时宣告标准 `image/png`，且与 Omarchy 的 Wayland 监听器共存无任何 `set_selection` 冲突。
- **无焦点后台 X11 探针边界 `[已测]`**：
  - 本次经 SSH 无人值守测试期间，桌面活动窗口为原生 Wayland `my-note - Chromium`（`hyprctl clients` 显示 `xwayland clients: []`，即无任何 XWayland 窗口打开/获焦）；此时 `DISPLAY=:0` 的 `CLIPBOARD` 所有者为 Hyprland XWayland 桥接代理窗口 `0x200002`。
  - 未获焦的隐藏 `INPUT_ONLY` X11 探针调用 `ConvertSelection` 时，XWayland 按 Wayland 焦点隔离安全策略返回 `property = NONE`（`selection_conversion_refused`），且后台未获焦 `x11-copy` 虽收到 XWayland 代理发出的 `3` 次 `SelectionRequest`（`TARGETS` 探查），但未获准覆盖 Wayland 剪贴板。
  - 为不劫持用户桌面窗口焦点，本次未强制在用户桌面上拉起前景 XWayland GUI 窗口；**有焦点 XWayland 应用（如 X11 窗口内 `Ctrl+V` / `Ctrl+C`）的人工粘贴冒烟**应纳入 M4a 桌面联调清单核验。

---

## 5. 反哺 M4a 与 M4b 的 Wayland 实现拍板建议

| 阶段 | 推荐方案（Linux / Wayland，`#[cfg(target_os = "linux")]`） | 关键设计原因（基于本次实测） |
| --- | --- | --- |
| **统一依赖** | 在 `crates/mynote-cli` 引入 **`wl-clipboard-rs = "0.9.5"`**（保持默认特性，使用纯 Rust `wayland-backend`，不启 `native_lib`） | `#![deny(unsafe_code)]`，零 C `libwayland-client` 动态库链接与外部 `wl-copy`/`wl-paste` 依赖；自动优先 `ext_data_control_manager_v1` 并回退 `zwlr_data_control_manager_v1` |
| **M4a 显式读** | `wl_clipboard_rs::paste::{get_mime_types, get_contents}` | 读取 pipe 前先校验 MIME 列表：硬过滤 `x-kde-passwordManagerHint` / `application/x-mynote-vault-secret`；图片仅放行位图白名单（`image/png`、`image/jpeg`、`image/webp`、`image/gif`，**拒 `image/svg+xml` 进图片通道**）；读取流 `Read::take(10 MiB + 1)` 硬限流 |
| **M4a 显式写（Daemon 在线）** | `wl_clipboard_rs::copy::Options::new().foreground(false).sensitive(is_secret).copy_multi(sources)` | 实测确认 `foreground(false)` 使用 `std::thread::spawn`（`src/copy.rs:1050`），**零 `fork()`，100% 兼容多线程 Tokio Daemon**；单次写即可同时提供正文 MIME + `application/x-mynote-synced`（Vault/ephemeral 附加 `application/x-mynote-vault-secret` + `.sensitive(true)`）；被新复制覆盖后线程自动退出无泄漏 |
| **M4a 显式写（Daemon 离线时 CLI 直跑）** | CLI 检测到 `daemon.sock` 不可达时，派生独立后台子进程（如 `mynote clip __serve-wayland`）运行 `wl-clipboard-rs` `foreground(true)` 直至被覆盖退出（不退回单 MIME `wl-copy`） | 实测证实 owner 进程退出后 Hyprland 立即清空剪贴板；派生自托管短服务子进程可同时保留多 MIME 与零外部 `wl-copy` 依赖 |
| **M4b 后台只读监听（默认关闭 opt-in）** | 在 Daemon 独立 `std::thread::spawn` 运行 `wl_clipboard_rs::watch::Watcher::new(ClipboardType::Regular, Seat::Unspecified)`，保存 `CancelHandle` 供 UI 一键暂停/恢复与优雅停机 | 源码与实测双重确认零 `set_selection` 调用，与 Omarchy `capture.sh` / `cliphist` 零冲突；启动首条事件做跳过或仅记哈希防重启重推；先检 `mime_types` 命中敏感或 `application/x-mynote-synced` 直接 `drop(offer)`（零 pipe 读取）；再配合 `250 ms` 防抖、`2,000 ms` `blake3` 双重防回环窗与文本 `detect_secret_pattern` 拦截 |
| **Cargo Workspace 隔离** | 在根 `Cargo.toml` 的 `[workspace].exclude` 中追加 `"spikes/s-clip-4-hyprland-wayland"` | 保持 S-Clip 脚手架与正式 workspace 完全隔离 |
