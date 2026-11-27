# my-note

> 2026-11-27 修订：依据 [第一性原理审查 §9](./review/2026-11-24-first-principles-review.md) 的决策 D1–D8（含 D1′、D5′ 去 Tauri 薄壳、S0-3 iPhone Argon2id 定值 `(32768, 2, 1)` 与 2026-11-27 独立 100 条图文剪贴板同步拍板 D8）更新。

一款面向开发者的**轻量、简洁、多端可靠同步、支持块级加密、Markdown/Mermaid 渲染与 CLI + Skill（Agent 友好）**的临时笔记 / Scratchpad 软件。

## 快速开始（交给本地 Agent 自举安装 / 更新）

将下面这一句直接发送给你的本地 AI Coding Agent（Claude Code / Codex / Antigravity / OpenCode 等），即可自动完成预编译包下载校验、二进制安装或升级、守护配置模板部署、`skill/SKILL.md` 注册以及可用性核验：

```text
请帮我安装或更新 gray0128/my-note：按本机系统与架构从 https://github.com/gray0128/my-note/releases/latest 下载对应的 mynote-<target>.tar.gz 与 SHA256SUMS.txt 并校验 SHA-256（若无对应架构预编译包则克隆仓库源码构建）；将 mynote 安装到系统 PATH（优先 /opt/homebrew/bin 或 /usr/local/bin，升级时保留现有 ~/.local/share/mynote 数据），安装或更新守护配置文件（macOS 写入 ~/Library/LaunchAgents/com.mynote.daemon.plist 并替换 __HOME__ 与实际二进制路径，Linux 写入 ~/.config/systemd/user/mynote-daemon.service 并修正 ExecStart，检测到 Hyprland 时一并提示接入 deploy/hyprland/mynote.conf），并将包内 skill/SKILL.md 安装到我当前 Agent 实际生效的 Skills 目录（遵循本机既有 Skills 管理方式，不覆盖无关 Skill）；接着按本地是否已初始化分流：若 ~/.local/share/mynote/mynote.db 已存在（升级场景），直接重启/加载后台 Daemon 并执行 mynote --version 与 mynote sync status --json 核验；若 mynote.db 尚不存在（全新设备），只保留守护配置文件，不要提前启动 Daemon 也不要执行 sync status 等会触发建库的命令（避免抢先生成孤立本地库阻断 device claim / 云端恢复或漏抄首次 24 词），仅执行 mynote --version 与 mynote --help 核验，最后简明告诉我如何完成首次云同步/设备配对、拉起守护并打开桌面 UI 开始使用。
```

### 发布包与启用速查

- **GitHub Release 预编译目标**（由 [`.github/workflows/release.yml`](./.github/workflows/release.yml) 在 `v*` tag 构建并附带 `SHA256SUMS.txt`）：
  - `mynote-aarch64-apple-darwin.tar.gz`（macOS Apple Silicon）
  - `mynote-x86_64-unknown-linux-gnu.tar.gz`（Linux x86_64 / Omarchy）
  - `mynote-aarch64-unknown-linux-gnu.tar.gz`（Linux ARM64）
  - 每个压缩包均内含剥离后的单体 `mynote`（已内嵌桌面 Web UI）、`skill/SKILL.md` 与 `deploy/{launchd,systemd,hyprland}` 模板。
- **源码构建回退**：`./scripts/build-wasm.sh && pnpm --dir web install --frozen-lockfile && pnpm --dir web build && cargo build --release --locked --bin mynote`
- **全新设备启用顺序（先配对/接入，再拉起守护）**：
  1. **首台桌面接入云端**：`mynote device bootstrap --url <你的-worker-url>`（妥善离线抄录首次输出的 24 词恢复包，或引导会话内运行 `mynote recovery show`）；**第二台桌面配对**：在已接入桌面运行 `mynote device add --name <设备名> --scope read-write`，目标桌面运行 `mynote device claim`（纯离线试用可跳过本步）
  2. **拉起后台守护**：macOS 执行 `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.mynote.daemon.plist`；Linux 执行 `systemctl --user daemon-reload && systemctl --user enable --now mynote-daemon.service`
  3. **打开桌面 UI / 接入手机只读 PWA**：桌面执行 `mynote open`（仅放行 `http://localhost:19876`）；手机接入在桌面执行 `mynote device add --name iphone --scope read`，iPhone Safari 打开 Worker URL 扫码或粘贴配对码

## 状态

**M1（替换 Heynote + iCloud）、M2（手机只读 PWA + Tier 2 Vault + 受控加密碎纸）、M3（Markdown 双模 / `SEC-06` + 懒加载 `Pele` 纯 SVG 与跨端 `Copy PNG` + 块级历史时间旅行 + Layer 2 外部格式化熔断）与 M4（D8 独立 100 条图文跨端剪贴板同步：M4a 显式双向 + 移动端 PWA `share_target` / iOS Scriptable 模板 + M4b 桌面后台自动镜像 opt-in）全部工程实现与 Plane A 确定性门禁均已合入 `main` 并接入跨平台 CI（`v0.3.0`）**；`evals/golden/` CLI `G01–G11` 冻结快照门禁与全部 6 套真机/Playwright（Chromium + WebKit）安全与功能 E2E 审计（含 `INV-CLIP-ISOLATION`、`SEC-08` 7 表取证与 `SEC-09` 四态越权/防回环）已在 `ubuntu-latest` 与 `macos-latest` 双平台自动化绿灯 `[已测]`；生产 Cloudflare Sync Relay（`cloud-cf/src/` `929/950` LOC TS `[已测]`）、PWA WASM（`304,412 B` gzip -9 < `350 KiB` `[已测]`）与 R2 `mynote-archive`（`archives/keys/history/` 30 天 + `clip/blobs/` 8 天前缀生命周期 `[已测]`）由 CI-only 最小权限 Scoped Token 部署。`ADR-01`、`ADR-05`、`ADR-06`、`ADR-07` 已升级为 **Accepted**，`ADR-11` 与其余真机 iPhone / 双桌面长期观察相关 ADR 诚实保持 **Proposed**。开发与 Agent 协作红线见 [`AGENTS.md`](./AGENTS.md)。路线图与全量指标见 [`docs/architecture-proposal.md`](./docs/architecture-proposal.md) 与 [review §9.11](./review/2026-11-24-first-principles-review.md)。

## 背景

源自长期使用 [Heynote](https://heynote.com/) + iCloud 同步过程中多次遭遇「内容被无故清空」的痛点，目标是在保留 Heynote「多语言分块、随手即记、即时格式化」核心体验的基础上，重构底层数据模型、同步协议、安全边界与 Agent 交互能力，覆盖 **macOS**、**Omarchy（Arch + Hyprland）** 两台桌面，以及**手机只读访问**（iOS / Android PWA）。

## 已拍板的决策（D1–D8，摘要）

| # | 决策 | 要点 |
| --- | --- | --- |
| D1′ | 手机笔记只读 + 独立剪贴板通道（2026-11-27 局部修订 D1） | 手机对笔记、密钥与碎纸严格保持只读（所有笔记写请求一律 `403`）；笔记引导仍用「当前状态快照 + 尾部 op」；M4 起新增 `read+clip`（手机 PWA）与 `clip-write`（快捷指令单向只写）令牌范围，仅放行物理隔离的 `/v1/clip*` 通道 |
| D2′ | 删除优先、有界时延、不牺牲可靠性 | 每块数据密钥（BDEK）+ 独立密钥表（M1 线格式）；回收站 + 服务端强制宽限期 + 加密碎纸；密文归档永久保留，彻底不可恢复上界约 37 天 [目标]（不含代码管不到的 OS 级备份等副本） |
| D3 | 两版本并列、手动合并（路径 γ） | 全量载荷 op + 多叶子并列；HLC 只决定展示顺序；不引入 Loro、不做 `SPAN_PATCH` |
| D4 | Cloudflare Workers Paid（约 \$5/月） | 单 DO 10 GB，不做 DO GC / 多代快照 CAS；配置支出告警 |
| D5′ | 双桌面统一纯 CLI + Daemon + HTML（取代 D5） | 移除 macOS Tauri 薄壳；macOS 与 Omarchy 均通过单一 `mynote` 二进制提供 `http://localhost:<port>`（Omarchy 用 Hyprland 绑定 Chromium webapp；macOS 用浏览器 / Web App + 外部快捷键工具或 `mynote open`） |
| D6 | 评测只为质量保障 | 保留确定性门禁（属性测试、DST、真实 Worker 契约测试、CLI 黄金测试等）；Plane B 与自动爬山推迟 |
| D7 | 手机可解锁 Vault | Argon2id（WASM）+ 单套 KDF 参数 `(32768, 2, 1)`（iPhone 主屏 PWA 实测 `1553 ms` [已测]），VKEK 仅在内存；手机 PWA 代码由 Cloudflare 下发是新的信任边界 |
| D8 | 独立 100 条图文跨端剪贴板同步（M4，2026-11-27 拍板） | 与笔记 `ops` 物理隔离：DO 存最近 100 条轻索引（7 天 TTL、≤ `64 KiB` 小文本内联 + ≤ `16 KiB` 缩略图），图片与长文本（上限 `10 MiB`）流式存 R2 `clip/blobs/`（8 天生命周期，0 DO PITR）；统一 `MNC1` + 独立可轮换 `ClipKey` + 可选 `≤ 256 KiB` 零写库 `--ephemeral` WS 直推；移动端 → 桌面由 PWA（Android `share_target` + iOS 无损大图 `mynote-wasm`）与 iOS Shortcuts/Scriptable 分流；先 `S-Clip` → `M4a`（显式）再 `M4b`（桌面后台自动镜像 opt-in） |

## 架构基线

- **本地核心**：Rust Sans-I/O 核心（`mynote-core`）+ 单体二进制（Daemon + CLI + SQLite + 内嵌前端），核心逻辑编译为 WASM 供桌面 Web UI 与手机只读 PWA 复用。
- **桌面交付**：macOS 与 Omarchy 100% 统一为纯 **CLI + 本地 Daemon + 内嵌 HTML**，本地 UI 唯一入口为 `http://localhost:<port>`（不引入原生 GUI / Tauri 壳）。
- **同步与云端**：两台桌面经 Cloudflare Worker + SQLite Durable Object 端到端加密同步（盲服务端：幂等追加、seq、epoch、令牌范围、WebSocket 唤醒、密钥表与碎纸标记、每日归档）；R2 保存 op 密文归档与密钥表快照。
- **加密**：Tier 1 同步盲信封 + Tier 2 Vault（口令解锁）；一份统一恢复包（24 词）覆盖全部密钥。
- **Agent 集成**：不做 MCP，通过 CLI（`--json`、稳定退出码与错误码，Daemon 未起亦可用）+ 极轻 `SKILL.md`。
- **分发**：GitHub Releases 预编译包（附 `SHA256SUMS.txt`、`skill/SKILL.md` 与 `deploy/` 模板）/ Homebrew tap / AUR / `cargo install`，不做自升级。

## 文档索引

- [调研报告与系统架构设计方案 (`docs/architecture-proposal.md`)](./docs/architecture-proposal.md) — 根因复盘、竞品调研、整体架构、ADR（Proposed）与 S0 → M3 路线图
- [核心数据结构、存储 Schema 与二进制线格式规范 (`docs/data-structures.md`)](./docs/data-structures.md) — 线格式、AAD、op 信封（带 `key_id`）、独立密钥表、本地 / DO / PWA 表结构的单一事实来源
- [全链路接口与跨边界契约规范 (`docs/interface-contracts.md`)](./docs/interface-contracts.md) — 错误码注册表、CLI 子命令与 `--json` 契约、本地 Daemon API、云端请求响应 Schema、WASM FFI
- [同步协议与确定性物化规范 (`docs/sync-protocol.md`)](./docs/sync-protocol.md) — 路径 γ 多叶子并列与手动合并、epoch 对账、密钥表 2P-Set 同步、碎纸与宽限期协议、手机状态快照
- [安全架构与威胁模型规范 (`docs/threat-model.md`)](./docs/threat-model.md) — 敌手模型与诚实承诺、删除优先与时间上界、代码管不到的副本、只读令牌、手机 PWA 代码下发信任边界
- [Cloudflare 技术栈云端架构专项评估 (`docs/cloudflare-cloud-architecture.md`)](./docs/cloudflare-cloud-architecture.md) — Workers Paid 配额、DO / R2 实现、alarm 碎纸、归档生命周期、支出告警
- [质量门禁与评测框架 (`docs/eval-framework.md`)](./docs/eval-framework.md)（配 [`evals/`](./evals/)） — Plane A 确定性门禁；Plane B 与自动爬山资产已归档至 [`evals/archive/`](./evals/archive/)
- [跨端剪贴板同步可行性调研与决策归档 (`docs/clipboard-sync-proposal.md`)](./docs/clipboard-sync-proposal.md)（`Decided`，D8） — 100 条图文跨端剪贴板同步调研证据、移动端三梯队交互与 Q1–Q6 拍板记录（正式契约已同步至上述 SSOT 规范）
- [方案审查记录 (`review/`)](./review/) — [2026-11-24 第一性原理审查](./review/2026-11-24-first-principles-review.md)（§9 为决策记录 D1–D8，与其他文档冲突时以 §9 为准）

## 已移除 / 推迟的机制（2026-11-24 / 2026-11-27 修订）

以下机制不再出现在基线中，理由见 [review §9.7 / §9.12](./review/2026-11-24-first-principles-review.md)：

- 手机编辑 / 追加笔记块、笔记 outbox、移动端冲突合并 UI 与 CM6、Layer 3 移动端格式化（D1′）；旧版写入 DO SQLite 的 `ephemeral_clips` 表（F-06，已由 D8 物理隔离的 100 条图文通道取代）。
- `purge_op_ids`、`MNK1`、`key_seq`、可变 `vault_keys`、多槽位 `vault_key_slots`、Vault 第二套恢复码（D2′、F-05）。
- `SPAN_PATCH` / delta 链、HLC 漂移拒收、Lock-Wins 特例、分数索引重平衡（D3）。
- DO 滑动窗口 GC、R2 多代快照 + CAS、「\$0/月免费额度」约束（D4）。
- macOS Tauri 薄壳（`shell-macos/`）与内置全局热键窗口（D5′，2026-11-25 拍板双桌面统一纯 CLI + Daemon + HTML）。
- Plane B 统计评测、自动爬山（D6）；`mynote update` 自升级（F-14）。
