# S0-2: macOS Tauri v2 Thin Shell + Global Hotkey (< 100ms) + Keychain ACL Spike

> 本目录是 Issue #33（`S0-2`）的 macOS 真机实测脚手架。因 CI 与云端开发机为 Linux，需在真实 macOS（Apple Silicon）上执行以下两项 5 分钟实测并将数据回填至 [`docs/spikes/s0-2-macos-tauri-shell.md`](../../docs/spikes/s0-2-macos-tauri-shell.md)。

## 前置依赖（macOS）
- Xcode Command Line Tools（`xcode-select --install`）
- Rust toolchain（`rustup`）与 `cargo install tauri-cli --version "^2"`

## 实验 1：全局热键唤出延迟（目标 `< 100 ms`）与 Scheme A / B 验证

```bash
cd spikes/s0-2-macos-tauri-spike/shell-app
# Scheme A（首选：WKWebView 直接导航 http://localhost:19876，复用 SameSite=Strict Cookie）
cargo tauri dev
# 或测 Release 性能（更贴近真实日常体验）：
cargo tauri build --no-bundle && ./target/release/s0-2-tauri-shell
```

操作步骤：
1. 应用启动后会拉起本地模拟 Daemon（`http://localhost:19876`）并隐藏预热的 `WKWebView` 窗口。
2. 切到其他应用（如终端或浏览器），按 `Cmd+Shift+M` 唤出窗口、输入 1 个字符、按 `Esc` 隐藏；重复 **20 次**。
3. 观察终端输出的 `hotkey->visible` 与 `hotkey->editor_focused` 的 **P50 / P95 / Max (ms)**，同时确认：
   - 系统是否弹出「辅助功能（Accessibility）」权限请求；
   - 页面 Cookie `mynote_local_session` 在 `SameSite=Strict` 下是否正确随 `fetch('/v1/local/ping')` 发送（页面顶部显示 `COOKIE_AUTH: OK`）。
4. 可选对比 Scheme B：`MYNOTE_SPIKE_SCHEME=B ./target/release/s0-2-tauri-shell`。

## 实验 2：macOS Keychain 跨二进制代码签名 ACL 弹窗实测

```bash
cd spikes/s0-2-macos-tauri-spike
./scripts/test-keychain-acl.sh
```

脚本会分别编译两个独立二进制（模拟 Tauri `.app` 与 Homebrew `mynote` CLI），使用 ad-hoc 签名（`codesign -s -`），由二进制 A 写入 `service="dev.mynote.s02-spike"` 条目，再由二进制 B 读取该条目，观测 macOS 是否弹出钥匙串授权密码框（记录是否反复弹窗、点击「始终允许」后重编译二进制 B 是否再次弹窗）。
