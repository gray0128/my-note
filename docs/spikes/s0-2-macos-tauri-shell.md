# S0-2 实测报告与 macOS 真机验证清单：Tauri 薄壳、全局热键与 Keychain ACL（Issue #33）

- **当前状态**：**脚手架已就绪，待 macOS 真机实测**（本阶段在 Linux `x86_64` 环境推进，无法原生运行 `WKWebView`、Carbon 全局热键或 macOS Security Keychain）。`ADR-06` 保持 **`Proposed`**，待真机回填下表数据后升级为 `Accepted`。
- **可运行脚手架**：[`spikes/s0-2-macos-tauri-spike/`](../../spikes/s0-2-macos-tauri-spike/)（含 Tauri v2 热键延迟探针 + 模拟 Daemon Cookie 验证 + macOS Keychain 跨二进制 ad-hoc 签名 ACL 脚本）。

---

## 1. 架构预研结论（待真机实测确认）

| 决策项 | 推荐首选方案 | 理由与待验证风险 |
| --- | --- | --- |
| **全局热键注册** | `tauri-plugin-global-shortcut`（macOS 底层走 Carbon `RegisterEventHotKey`） | 不需要「辅助功能（Accessibility）」系统权限；窗口常驻隐藏，热键只做 `win.show()` + `win.set_focus()` + 聚焦编辑器，无页面重载，预期 `< 30–60 ms` [估算]，满足 `< 100 ms` [目标]。 |
| **壳与 Daemon 进程模型** | **独立 `mynote daemon`（`launchd` LaunchAgent 托管）+ Tauri 薄壳只做窗口与热键** | 关闭或重启 Tauri 壳绝不影响 CLI 与后台同步；严格维持 SQLite 单写入方（`daemon.lock` + `0600 daemon.sock`）；也天然规避「壳退出导致后台同步中断」问题。 |
| **WebView Origin 方案** | **方案 A（首选）：`WKWebView` 启动时导航 `http://localhost:<port>/v1/local/auth/exchange?ticket=...`** | 与 Omarchy Chromium webapp 共享 100% 相同的 Origin 与 `HttpOnly; SameSite=Strict` Session Cookie，无需 CORS 与额外 Bearer 分支；方案 B（`tauri://localhost` + UDS Bearer）留作 fallback。 |
| **macOS Keychain 跨二进制 ACL** | **建议仅由 `mynote`（Daemon/CLI 同一二进制）唯一读写 Keychain；Tauri 壳不直接触碰 Keychain** | macOS 传统 login Keychain 按代码签名身份（`designated requirement`）维护 ACL：ad-hoc 签名（未付 Apple Developer 证书）下，不同二进制或 `brew upgrade` 重编后的二进制访问同一条目极易反复弹窗。把 Keychain 访问收口到**单一** `mynote` 二进制（且 Daemon 运行时 CLI 写请求经 `daemon.sock` 转交 Daemon，无需再读 Keychain）可从根本上消除跨二进制 ACL 冲突。 |
| **自启与未公证 Gatekeeper** | `~/Library/LaunchAgents/dev.mynote.daemon.plist` + Tauri 登录项；个人自用未公证时运行 `xattr -dr com.apple.quarantine /Applications/my-note.app` | 个人自用无需 \$99/年公证，但须在安装文档中写明 `quarantine` 解除步骤；若采用自签名证书固定签名身份，亦可减少更新后 Keychain 弹窗。 |

---

## 2. macOS 真机实测回填表（执行 `spikes/s0-2-macos-tauri-spike/README.md` 后填写）

| 验证项 | 目标 / 预期 | 实测结果（待真机填写） | 结论 |
| --- | --- | --- | :---: |
| 全局热键唤出至编辑器可输入延迟（20 次） | P95 `< 100 ms` [目标] | P50 = `___ ms` / P95 = `___ ms` / Max = `___ ms` `[待测]` | ⏳ |
| 是否弹出「辅助功能」权限请求 | 否 | `___` `[待测]` | ⏳ |
| 方案 A `WKWebView` `http://localhost:<port>` `SameSite=Strict` Cookie | `COOKIE_AUTH: OK` | `___` `[待测]` | ⏳ |
| 跨二进制 ad-hoc 签名访问同 Keychain 条目（`test-keychain-acl.sh`） | 记录 Step 2 / Step 3 是否弹窗 | Step 2: `___` / Step 3: `___` `[待测]` | ⏳ |
| 登录自启与 Gatekeeper 记录 | 步骤可复现 | `___` `[待测]` | ⏳ |
