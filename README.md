# my-note

> 2026-11-28 修订：依据 [第一性原理审查 §9](./review/2026-11-24-first-principles-review.md) 与 [多租户及设备管理专项审查](./review/2026-11-28-controlled-multi-tenant-and-device-review.md) 的决策 D1–D11（含 D1′、D5′/D5″ 去 Tauri 壳并新增零依赖纯 Swift 可选薄壳 `apps/macos/`、S0-3 iPhone Argon2id 定值 `(32768, 2, 1)`、2026-11-27/28 独立图文剪贴板与分层留存 D8/D8′、2026-11-28 Windows 一等桌面平台 D9、`wasmi` 优先双宿主插件体系 D10，以及 M6 受控无账号多租户与设备生命周期管理 D11）更新。

一款面向开发者的**轻量、简洁、多端可靠同步、支持块级加密、Markdown/Mermaid 渲染与 CLI + Skill（Agent 友好）**的临时笔记 / Scratchpad 软件。

## 快速开始（交给本地 Agent 自举安装 / 更新）

将下面这一句直接发送给你的本地 AI Coding Agent（Claude Code / Codex / Antigravity / OpenCode 等），即可自动完成预编译包下载校验、二进制安装或升级、守护配置模板部署、`skill/SKILL.md` 注册以及可用性核验：

```text
请帮我安装或更新 gray0128/my-note：按本机系统与架构从 https://github.com/gray0128/my-note/releases/latest 下载对应的发布包（macOS / Linux 下载 mynote-<target>.tar.gz，Windows x86_64 下载 mynote-x86_64-pc-windows-msvc.zip）与 SHA256SUMS.txt 并校验 SHA-256（若为 macOS Apple Silicon 且需要原生菜单栏与全局热键窗口，同步下载并校验 MyNote-aarch64-apple-darwin.zip，用 ditto -x -k 解压至 /Applications/MyNote.app 并执行 xattr -dr com.apple.quarantine /Applications/MyNote.app；若无对应架构预编译包则克隆仓库源码构建）；将 mynote（Windows 为 mynote.exe）安装到系统 PATH（Unix 优先 /opt/homebrew/bin 或 /usr/local/bin，Windows 优先 %LOCALAPPDATA%\Programs\mynote，覆盖前先执行 powershell -NoProfile -ExecutionPolicy Bypass -File deploy/windows/uninstall-daemon-task.ps1 -StopOnly 停止运行中的守护进程并释放文件句柄锁；升级时保留现有 ~/.local/share/mynote 或 %LOCALAPPDATA%\mynote 数据），安装或更新守护配置（macOS 写入 ~/Library/LaunchAgents/com.mynote.daemon.plist 并替换 __HOME__ 与实际二进制路径，Linux 写入 ~/.config/systemd/user/mynote-daemon.service 并修正 ExecStart，检测到 Hyprland 时一并提示接入 deploy/hyprland/mynote.conf，Windows 执行 powershell -NoProfile -ExecutionPolicy Bypass -File deploy/windows/install-daemon-task.ps1，未提权终端自动注册 HKCU Run 自启、提权终端注册 Job Object 计划任务），并将包内 skill/SKILL.md 安装到我当前 Agent 实际生效的 Skills 目录（遵循本机既有 Skills 管理方式，不覆盖无关 Skill）；接着按本地是否已初始化分流：若 ~/.local/share/mynote/mynote.db 或 %LOCALAPPDATA%\mynote\mynote.db 已存在（升级场景），直接重启/加载后台 Daemon 并执行 mynote --version 与 mynote sync status --json 核验；若 mynote.db 尚不存在（全新设备），只保留守护配置而不提前启动 Daemon，也不要执行 sync status 等会触发建库的命令（避免抢先生成孤立本地库阻断 device claim / 云端恢复或漏抄首次 24 词），仅执行 mynote --version 与 mynote --help 核验，最后简明告诉我如何完成首次云同步/设备配对、拉起守护并执行 mynote open（或启动 /Applications/MyNote.app）开始使用。
```

### 发布包与启用速查

- **GitHub Release 预编译目标**（由 [`.github/workflows/release.yml`](./.github/workflows/release.yml) 在 `v*` tag 构建并附带 `SHA256SUMS.txt`）：
  - `mynote-aarch64-apple-darwin.tar.gz`（macOS Apple Silicon CLI + Daemon + 内嵌 Web UI）
  - `MyNote-aarch64-apple-darwin.zip`（macOS Apple Silicon 可选原生纯 Swift `WKWebView` 薄壳 `MyNote.app`，支持菜单栏与全局热键 `⌃⌥Space`，零第三方依赖、不碰 Keychain；首次运行前执行 `xattr -dr com.apple.quarantine /Applications/MyNote.app`）
  - `mynote-x86_64-unknown-linux-gnu.tar.gz`（Linux x86_64 / Omarchy）
  - `mynote-aarch64-unknown-linux-gnu.tar.gz`（Linux ARM64）
  - `mynote-x86_64-pc-windows-msvc.zip`（Windows 10/11 x86_64 CLI + Daemon + 内嵌 Web UI，详见 [`deploy/windows/README.md`](./deploy/windows/README.md)）
  - 每个桌面压缩包均内含剥离后的单体 `mynote` / `mynote.exe`（已内嵌桌面 Web UI）、`skill/SKILL.md` 与对应平台的 `deploy/` 托管模板（Unix 含 `launchd`/`systemd`/`hyprland`/`ios-shortcuts`，Windows 含 `windows`/`ios-shortcuts`）。
- **源码构建回退**：`./scripts/build-wasm.sh && pnpm --dir web install --frozen-lockfile && pnpm --dir web build && cargo build --release --locked --bin mynote`（macOS 可选构建原生薄壳：`./apps/macos/build.sh`）
- **全新设备启用顺序（先配对/接入，再拉起守护）**：
  1. **首台桌面接入云端**：`mynote device bootstrap --url <你的-worker-url>`（妥善离线抄录首次输出的 24 词恢复包，或引导会话内运行 `mynote recovery show`）；**第二台或第三台桌面配对**：在已接入桌面运行 `mynote device add --name <设备名> --scope read-write`，目标桌面运行 `mynote device claim`（纯离线试用可执行 `mynote buf ls` 初始化本地库）
  2. **拉起后台守护**：macOS 执行 `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.mynote.daemon.plist`；Linux 执行 `systemctl --user daemon-reload && systemctl --user enable --now mynote-daemon.service`；Windows 执行 `powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy\windows\install-daemon-task.ps1`（若安装时尚未建库，配对完成后再次执行该脚本即可在未提权或提权模式下启动守护，详见 [`deploy/windows/`](./deploy/windows/README.md)）
  3. **打开桌面 UI / 接入手机只读 PWA**：三桌面统一执行 `mynote open`（仅放行 `http://localhost:19876`，Windows 经 `ShellExecuteW` 直开默认浏览器），或在 macOS 启动可选的 `/Applications/MyNote.app`（默认全局热键 `⌃⌥Space`）；手机接入在桌面执行 `mynote device add --name iphone --scope read+clip`（或纯只读 `--scope read`），iPhone Safari 打开 Worker URL 扫码或粘贴配对码

## 状态

**M1（替换 Heynote + iCloud）、M2（手机只读 PWA + Tier 2 Vault + 受控加密碎纸）、M3（Markdown 双模 / `SEC-06` + 懒加载 `Pele` 纯 SVG 与跨端 `Copy PNG` + 块级历史时间旅行 + Layer 2 外部格式化熔断）、M4（D8 / D8′ 独立图文跨端剪贴板同步：云端 `1,000 条 / 30 天 / 5 GiB` 硬护栏 + 桌面无限归档与 Eager Prefetch + M4b 后台自动镜像 opt-in）、macOS 可选纯 Swift `WKWebView` 原生薄壳（[`apps/macos/`](./apps/macos/README.md)，`D5″`），以及 M5 Phase 0（`S-Plugin-1` + `S-Win-1`）与 Phase 1 Windows 一等桌面平台基座（`M5-W1..W3`，`D9`）已落地并合入主干（当前已发布版本 `v0.3.3`）**；`evals/golden/` CLI `G01–G11` 冻结快照门禁、macOS `MyNote.app` 隔离 `WKWebView` 自检（`140 KiB` zip、`5–8 ms` 唤出 `[已测]`）、Windows `SEC-WIN-PIPE`（`4/4`）与 `SEC-WIN-CLIP`（`3/3`）及 Release ZIP / PowerShell 后台托管端到端自检门禁，以及全部 6 套真机/Playwright（Chromium + WebKit）安全与功能 E2E 审计已在 `ubuntu-latest`、`macos-latest` 与 `windows-latest` 三平台 CI 自动化绿灯 `[已测]`；生产 Cloudflare Sync Relay（`cloud-cf/src/` `1,025/1,050` LOC TS `[已测]`，M5 `0 LOC` 改动 `[保证]`）、PWA WASM（`304,412 B` gzip -9 < `350 KiB` `[已测]`，M5 `0 B` 增量 `[保证]`）与 R2 `mynote-archive` 由 CI-only 最小权限 Scoped Token 部署。`ADR-01`、`ADR-05`、`ADR-06`、`ADR-07`、`ADR-08`、`ADR-10`、`ADR-12` 已升级为 **Accepted**，`ADR-11`、`ADR-13`、`ADR-14` 与其余长期观测 ADR 诚实保持 **Proposed**。开发与 Agent 协作红线见 [`AGENTS.md`](./AGENTS.md)。路线图与全量指标见 [`docs/architecture-proposal.md`](./docs/architecture-proposal.md) 与 [review §9.11](./review/2026-11-24-first-principles-review.md)。

## 背景

源自长期使用 [Heynote](https://heynote.com/) + iCloud 同步过程中多次遭遇「内容被无故清空」的痛点，目标是在保留 Heynote「多语言分块、随手即记、即时格式化」核心体验的基础上，重构底层数据模型、同步协议、安全边界与 Agent 交互能力，覆盖 **macOS**、**Omarchy（Arch + Hyprland）**、**Windows（M5 升为一等桌面平台，D9）** 三台桌面，以及**手机只读访问与独立图文剪贴板同步**（iOS / Android PWA + iOS Shortcuts）。

## 已拍板的决策（D1–D11，摘要）

| # | 决策 | 要点 |
| --- | --- | --- |
| D1′ | 手机笔记只读 + 独立剪贴板通道（2026-11-27 局部修订 D1） | 手机对笔记、密钥与碎纸严格保持只读（所有笔记写请求一律 `403`）；笔记引导仍用「当前状态快照 + 尾部 op」；M4 起新增 `read+clip`（手机 PWA）与 `clip-write`（快捷指令单向只写）令牌范围，仅放行物理隔离的 `/v1/clip*` 通道 |
| D2′ | 删除优先、有界时延、不牺牲可靠性 | 每块数据密钥（BDEK）+ 独立密钥表（M1 线格式）；回收站 + 服务端强制宽限期 + 加密碎纸；密文归档永久保留，彻底不可恢复上界约 37 天 [目标]（不含代码管不到的 OS 级备份等副本） |
| D3 | 两版本并列、手动合并（路径 γ） | 全量载荷 op + 多叶子并列；HLC 只决定展示顺序；不引入 Loro、不做 `SPAN_PATCH` |
| D4 | Cloudflare Workers Paid（约 \$5/月） | 单 DO 10 GB，不做 DO GC / 多代快照 CAS；配置支出告警 |
| D5′ / D5″ | 双桌面统一纯 CLI + Daemon + HTML 底座 + macOS 可选纯 Swift 薄壳（2026-11-25 去 Tauri；2026-11-28 补充 `apps/macos/`） | 永久移除 macOS Tauri 薄壳；macOS 与 Omarchy 底座统一为单一 `mynote` 二进制提供 `http://localhost:<port>`；macOS 另可选零第三方依赖纯 Swift `WKWebView` 薄壳 [`apps/macos/MyNote.app`](./apps/macos/README.md)（仅连 `0600 daemon.sock`、不碰 Keychain、提供菜单栏与 Carbon 全局热键 `⌃⌥Space`） |
| D6 | 评测只为质量保障 | 保留确定性门禁（属性测试、DST、真实 Worker 契约测试、CLI 黄金测试等）；Plane B 与自动爬山推迟 |
| D7 | 手机可解锁 Vault | Argon2id（WASM）+ 单套 KDF 参数 `(32768, 2, 1)`（iPhone 主屏 PWA 实测 `1553 ms` [已测]），VKEK 仅在内存；手机 PWA 代码由 Cloudflare 下发是新的信任边界 |
| D8 / D8′ | 独立图文跨端剪贴板同步与分层留存（M4，2026-11-27 / 2026-11-28 拍板） | 与笔记 `ops` 物理隔离：云端 DO 存最近 `1,000 条` 轻索引（`30 天` TTL、≤ `64 KiB` 小文本内联 + ≤ `16 KiB` 缩略图），图片与长文本（单条上限 `10 MiB`）流式存 R2 `clip/blobs/`（`5 GiB` 硬容量护栏触顶返 `507 CLIP_QUOTA_EXCEEDED`、`31 天` 孤儿生命周期，0 DO PITR）；桌面本地无限归档 + 单并发后台 Eager Prefetch + 手动 `prune`/`clear`（云端清理与默认 `rotate-key` 均保留桌面本地归档）；手机 PWA `200 条` 增量缓存；统一 `MNC1` + 独立可轮换 `ClipKey` + 可选 `≤ 256 KiB` 零写库 `--ephemeral` WS 直推；移动端 → 桌面由 PWA（Android `share_target` + iOS 无损大图 `mynote-wasm`）与 iOS Shortcuts/Scriptable 分流 |
| D9 | Windows 升为一等桌面平台（M5，2026-11-28 拍板） | 与 macOS、Omarchy 并列：跨平台 `LocalIpc`（Unix `0600` UDS / Windows 用户 SID SDDL Named Pipe，防抢注与禁 SMB）、Credential Manager / DPAPI 与 NTFS 用户专属 ACL、`CONIN$` 无回显口令、Win32 原生剪贴板监听与隐私过滤、加固外部子进程（`SYSTEMROOT` 白名单 + `CREATE_NO_WINDOW` + Job Object + `PYTHONUTF8=1` + 禁 `.bat`/`.cmd`）、`windows-latest` CI 与 Release 预编译包（`ADR-12`） |
| D10 | 路线 B `wasmi` 优先双宿主插件体系（M5，2026-11-28 拍板） | 纯计算 `transform` / `inspector` 插件统一为 Core WASM 零导入 3-Export ABI（`module.imports().is_empty()`），同一 `.wasm` 在 Tier 1 跑 Rust `wasmi`、在桌面解锁态 Tier 2 跑独立 `'self'` Web Worker（守住 Daemon 零 Tier 2 明文与现有 CSP）；外部工具链 / 网络类 Tier 1 插件走 Level 1 `exec`（`oneshot`/`worker` 双模式，禁 Tier 2）；前端仅开放 6 种声明式 `PluginResult` 安全原语（严禁主 DOM/JS 注入与云同步分发插件）；全程 `cloud-cf` `0 LOC` 改动、手机 PWA WASM `0 B` 增量（`ADR-13`） |
| D11 | 受控无账号多租户与设备生命周期管理（M6，2026-11-28 拍板，排在 M5 之后） | 零 KV/D1，每个受邀空间映射独立 `SyncJournalDO`（`primary` 保持兼容）；单一 `SPACE_MASTER_SECRET` 派生边缘自路由 MAC 与离线邀请码（`cloud-cf/scripts/issue-invite.ts`），未激活 DO 零写库零 Alarm；R2 类别前置隔离（受邀默认 `12` 设备、`ops=256 MiB`、`clip=512 MiB / 500 条 / 14 天`，共享桶 `clip/blobs/` 维持 31 天规则）+ `INV-MT-IDLE-ALARM`；24 词派生 Ed25519 公钥 + DO 纯内存挑战 Map 支持全设备丢失自救；桌面 UI 设备管理（`confirm_nonce` + 本地 SVG 二维码）+ `INV-MT-NO-SELF-LOCKOUT` 防删最后桌面 + `UnclaimedFresh` 首次启动 `VACUUM INTO` 热切换；被移除桌面保留本地库并停 60s 轮询，被移除手机 PWA 自动清空 IndexedDB；M6 预算 `cloud-cf/src/ <= 1,250` 行、手机 PWA WASM `0 B` 增量（`ADR-14`） |

## 架构基线

- **本地核心**：Rust Sans-I/O 核心（`mynote-core`）+ 单体二进制（Daemon + CLI + SQLite + 内嵌前端），核心逻辑编译为 WASM 供桌面 Web UI 与手机只读 PWA 复用。
- **桌面交付**：macOS、Omarchy 与 Windows 三桌面底座 100% 统一为纯 **CLI + 本地 Daemon + 内嵌 HTML**，本地 UI 唯一入口为 `http://localhost:<port>`（不引入 Tauri 壳）；macOS 另提供可选的零依赖纯 Swift `WKWebView` 薄壳 [`apps/macos/MyNote.app`](./apps/macos/README.md)（`140 KiB` zip `[已测]`，不碰 Keychain、复用 `daemon.sock` 自动换票鉴权），Windows 通过 [`deploy/windows/`](./deploy/windows/README.md) 无窗口计划任务驻留并通过 `mynote open`（`ShellExecuteW`）直达。
- **同步与云端**：三台桌面经 Cloudflare Worker + SQLite Durable Object 端到端加密同步（盲服务端：幂等追加、seq、epoch、令牌范围、WebSocket 唤醒、密钥表与碎纸标记、每日归档）；R2 保存 op 密文归档与密钥表快照。
- **加密**：Tier 1 同步盲信封 + Tier 2 Vault（口令解锁）；一份统一恢复包（24 词）覆盖全部密钥。
- **Agent 集成**：不做 MCP，通过 CLI（`--json`、稳定退出码与错误码，Daemon 未起亦可用）+ 极轻 `SKILL.md`。
- **分发**：GitHub Releases 预编译包（附 `SHA256SUMS.txt`、`skill/SKILL.md` 与 `deploy/` 模板）/ Homebrew tap / AUR / `cargo install`，不做自升级。

## 文档索引（按性质物理分类）

本仓库严格分离**正式方案（`docs/`）**、**技术 Spike 实测报告（`docs/spikes/`）**、**调研报告（`research/`）**与**方案审查记录（`review/`）**。**调研与审查文档仅作分析与决策追溯，严禁直接作为开发实施依据；只有转化为 `docs/` 正式方案正文后方可实施。**

### 正式方案与工程规范（[`docs/`](./docs/README.md)，唯一实施依据）

- [系统架构与演进方案 (`docs/architecture-proposal.md`)](./docs/architecture-proposal.md) — 根因复盘、整体架构、ADR-01～ADR-14 与 S0 → M6 路线图
- [核心数据结构、存储 Schema 与二进制线格式规范 (`docs/data-structures.md`)](./docs/data-structures.md) — 线格式、AAD、op 信封（带 `key_id`）、独立密钥表、M6 自路由标识与离线邀请码、M5 插件契约与 Core WASM 3-Export ABI、全端表结构的单一事实来源
- [全链路接口与跨边界契约规范 (`docs/interface-contracts.md`)](./docs/interface-contracts.md) — 错误码注册表、CLI 子命令与 `--json` 契约、本地 Daemon REST / WS / 跨平台 `LocalIpc`、云端 Sync / Space / Device API、WASM / Tier 2 插件 Worker 边界
- [同步协议与确定性物化规范 (`docs/sync-protocol.md`)](./docs/sync-protocol.md) — 路径 γ 多叶子并列与手动合并、epoch 对账、密钥表 2P-Set 同步、碎纸与宽限期协议、手机状态快照、独立剪贴板通道、M6 首次引导与移除停机协议
- [安全架构与威胁模型规范 (`docs/threat-model.md`)](./docs/threat-model.md) — 敌手模型与诚实承诺（T1–T10）、删除优先与时间上界、代码管不到的副本、只读令牌、手机 PWA 信任边界、剪贴板、Windows / 双宿主插件与受控多租户安全边界
- [Cloudflare 技术栈云端架构专项评估 (`docs/cloudflare-cloud-architecture.md`)](./docs/cloudflare-cloud-architecture.md) — Workers Paid 配额、单空间单 DO / R2 类别前置实现、alarm 碎纸、归档生命周期、支出告警（M5 云端 `0 LOC` 改动，M6 受控多租户 `<= 1,250` 行）
- [质量门禁与评测框架 (`docs/eval-framework.md`)](./docs/eval-framework.md)（配 [`evals/`](./evals/)） — Plane A 确定性门禁（S0 → M6）；Plane B 与自动爬山资产已归档至 [`evals/archive/`](./evals/archive/)

### 独立调研报告（[`research/`](./research/README.md)，严禁直接实施）

- 已转化为正式方案（`research/converted/`）：
  - [跨端剪贴板同步可行性深度调研](./research/converted/2026-11-27-clipboard-sync-research.md)（已转化为 D8 / M4，`ADR-11`）
  - [插件化可行性与跨平台架构深度调研（含 macOS / Linux / Windows）](./research/converted/2026-11-28-plugin-architecture-analysis.md)（已转化为 D9 / D10 / M5，`ADR-12` / `ADR-13`）
  - [受控无账号多租户（路线 B）与设备生命周期管理方案调研](./research/converted/2026-11-28-controlled-multi-tenant-and-device-management.md)（已转化为 D11 / M6，`ADR-14`）
- 待转化探索调研（`research/pending/`，禁止直接实施）：
  - [`v0.3.2` 基建能力外延：10 个发散方向深度调研](./research/pending/2026-11-28-10-directions-infra-analysis.md)

### 方案审查与决策追溯（[`review/`](./review/README.md)）

- [2026-11-24 第一性原理审查与 §9 决策记录（D1–D11）](./review/2026-11-24-first-principles-review.md)（已同步转化为 `docs/` 正文）
- [2026-11-28 受控无账号多租户与设备生命周期管理审查及拍板记录（D11）](./review/2026-11-28-controlled-multi-tenant-and-device-review.md)（已同步转化为 `docs/` 正文）

## 已移除 / 推迟的机制（2026-11-24 / 2026-11-27 / 2026-11-28 修订）

以下机制不再出现在基线中，理由见 [review §9.7 / §9.8 / §9.12](./review/2026-11-24-first-principles-review.md)：

- 手机编辑 / 追加笔记块、笔记 outbox、移动端冲突合并 UI 与 CM6、Layer 3 移动端格式化（D1′）；旧版写入 DO SQLite 的 `ephemeral_clips` 表（F-06，已由 D8 物理隔离的 100 条图文通道取代）。
- `purge_op_ids`、`MNK1`、`key_seq`、可变 `vault_keys`、多槽位 `vault_key_slots`、Vault 第二套恢复码（D2′、F-05）。
- `SPAN_PATCH` / delta 链、HLC 漂移拒收、Lock-Wins 特例、分数索引重平衡（D3）。
- DO 滑动窗口 GC、R2 多代快照 + CAS、「\$0/月免费额度」约束（D4）。
- macOS Tauri 薄壳（`shell-macos/`）、Scheme B Bearer 鉴权分支与单端 GPUI 重写（D5′ / D5″；macOS 全局热键窗口改由零依赖可选纯 Swift `WKWebView` 薄壳 `apps/macos/` 承担）。
- Obsidian 式主 DOM / 任意 JS 注入插件、WASI Preview 2 / WIT 破坏浏览器原生零依赖直跑、捆绑 Node.js / Python 运行时、经云同步自动分发可执行插件代码、`exec` 子进程接触 Tier 2 明文、以及向外部进程暴露高频按键 `onKeystroke`（D10）。
- Plane B 统计评测、自动爬山（D6）；`mynote update` 自升级（F-14）。
