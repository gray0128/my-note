# my-note

> 2026-11-25 修订：依据 [第一性原理审查 §9](./review/2026-11-24-first-principles-review.md) 的决策 D1–D7 及 2026-11-25 真机实测拍板（D5′ 去 Tauri 薄壳 + S0-3 iPhone Argon2id 定值 `(32768, 2, 1)`）更新。

一款面向开发者的**轻量、简洁、多端可靠同步、支持块级加密、Markdown/Mermaid 渲染与 CLI + Skill（Agent 友好）**的临时笔记 / Scratchpad 软件。

## 状态

**S0 技术 Spike（除真实 CF Paid 账号控制台核验外均已真机闭环）与 M1 纯领域核 / 本地存储 / Agent CLI 已落地**。`ADR-01`（Rust Sans-I/O 核 + `ruzstd` WASM）、`ADR-06`（双桌面纯 CLI + Daemon + 内嵌 HTML + 手机只读 PWA，iPhone Argon2id 定值 `(32768, 2, 1)`）与 `ADR-07`（CodeMirror 6 候选 A 按块虚拟化）均已获实测证据转为 **Accepted**，其余云端/联调相关 ADR 诚实保持 **Proposed**（详见 [`docs/spikes/`](./docs/spikes/)）。Rust Workspace（`mynote-core`、`mynote-wasm`、`mynote-store`、`mynote-cli`）、`skill/SKILL.md`、200 种子 DST、CLI 合约测试与双平台 CI 均已就绪；开发与 Agent 协作红线见 [`AGENTS.md`](./AGENTS.md)。路线图：S0 spike → M1 替换 Heynote + iCloud → M2 手机只读 + Vault + 碎纸 → M3 渲染与打磨（详见 [`docs/architecture-proposal.md`](./docs/architecture-proposal.md) 与 [review §9.11](./review/2026-11-24-first-principles-review.md)）。

## 背景

源自长期使用 [Heynote](https://heynote.com/) + iCloud 同步过程中多次遭遇「内容被无故清空」的痛点，目标是在保留 Heynote「多语言分块、随手即记、即时格式化」核心体验的基础上，重构底层数据模型、同步协议、安全边界与 Agent 交互能力，覆盖 **macOS**、**Omarchy（Arch + Hyprland）** 两台桌面，以及**手机只读访问**（iOS / Android PWA）。

## 已拍板的决策（D1–D7，摘要）

| # | 决策 | 要点 |
| --- | --- | --- |
| D1 | 手机只读 + 复制 | 只读 PWA + 只读设备令牌；引导用「当前状态快照 + 尾部 op」；复制按钮取代瞬态剪贴板 |
| D2′ | 删除优先、有界时延、不牺牲可靠性 | 每块数据密钥（BDEK）+ 独立密钥表（M1 线格式）；回收站 + 服务端强制宽限期 + 加密碎纸；密文归档永久保留，彻底不可恢复上界约 37 天 [目标]（不含代码管不到的 OS 级备份等副本） |
| D3 | 两版本并列、手动合并（路径 γ） | 全量载荷 op + 多叶子并列；HLC 只决定展示顺序；不引入 Loro、不做 `SPAN_PATCH` |
| D4 | Cloudflare Workers Paid（约 \$5/月） | 单 DO 10 GB，不做 DO GC / 多代快照 CAS；配置支出告警 |
| D5′ | 双桌面统一纯 CLI + Daemon + HTML（取代 D5） | 移除 macOS Tauri 薄壳；macOS 与 Omarchy 均通过单一 `mynote` 二进制提供 `http://localhost:<port>`（Omarchy 用 Hyprland 绑定 Chromium webapp；macOS 用浏览器 / Web App + 外部快捷键工具或 `mynote open`） |
| D6 | 评测只为质量保障 | 保留确定性门禁（属性测试、DST、真实 Worker 契约测试、CLI 黄金测试等）；Plane B 与自动爬山推迟 |
| D7 | 手机可解锁 Vault | Argon2id（WASM）+ 单套 KDF 参数 `(32768, 2, 1)`（iPhone 主屏 PWA 实测 `1553 ms` [已测]），VKEK 仅在内存；手机 PWA 代码由 Cloudflare 下发是新的信任边界 |

## 架构基线

- **本地核心**：Rust Sans-I/O 核心（`mynote-core`）+ 单体二进制（Daemon + CLI + SQLite + 内嵌前端），核心逻辑编译为 WASM 供桌面 Web UI 与手机只读 PWA 复用。
- **桌面交付**：macOS 与 Omarchy 100% 统一为纯 **CLI + 本地 Daemon + 内嵌 HTML**，本地 UI 唯一入口为 `http://localhost:<port>`（不引入原生 GUI / Tauri 壳）。
- **同步与云端**：两台桌面经 Cloudflare Worker + SQLite Durable Object 端到端加密同步（盲服务端：幂等追加、seq、epoch、令牌范围、WebSocket 唤醒、密钥表与碎纸标记、每日归档）；R2 保存 op 密文归档与密钥表快照。
- **加密**：Tier 1 同步盲信封 + Tier 2 Vault（口令解锁）；一份统一恢复包（24 词）覆盖全部密钥。
- **Agent 集成**：不做 MCP，通过 CLI（`--json`、稳定退出码与错误码，Daemon 未起亦可用）+ 极轻 `SKILL.md`。
- **分发**：Homebrew tap / AUR / `cargo install`，不做自升级。

## 文档索引

- [调研报告与系统架构设计方案 (`docs/architecture-proposal.md`)](./docs/architecture-proposal.md) — 根因复盘、竞品调研、整体架构、ADR（Proposed）与 S0 → M3 路线图
- [核心数据结构、存储 Schema 与二进制线格式规范 (`docs/data-structures.md`)](./docs/data-structures.md) — 线格式、AAD、op 信封（带 `key_id`）、独立密钥表、本地 / DO / PWA 表结构的单一事实来源
- [全链路接口与跨边界契约规范 (`docs/interface-contracts.md`)](./docs/interface-contracts.md) — 错误码注册表、CLI 子命令与 `--json` 契约、本地 Daemon API、云端请求响应 Schema、WASM FFI
- [同步协议与确定性物化规范 (`docs/sync-protocol.md`)](./docs/sync-protocol.md) — 路径 γ 多叶子并列与手动合并、epoch 对账、密钥表 2P-Set 同步、碎纸与宽限期协议、手机状态快照
- [安全架构与威胁模型规范 (`docs/threat-model.md`)](./docs/threat-model.md) — 敌手模型与诚实承诺、删除优先与时间上界、代码管不到的副本、只读令牌、手机 PWA 代码下发信任边界
- [Cloudflare 技术栈云端架构专项评估 (`docs/cloudflare-cloud-architecture.md`)](./docs/cloudflare-cloud-architecture.md) — Workers Paid 配额、DO / R2 实现、alarm 碎纸、归档生命周期、支出告警
- [质量门禁与评测框架 (`docs/eval-framework.md`)](./docs/eval-framework.md)（配 [`evals/`](./evals/)） — Plane A 确定性门禁；Plane B 与自动爬山资产已归档至 [`evals/archive/`](./evals/archive/)
- [方案审查记录 (`review/`)](./review/) — [2026-11-24 第一性原理审查](./review/2026-11-24-first-principles-review.md)（§9 为决策记录 D1–D7，与其他文档冲突时以 §9 为准）

## 已移除 / 推迟的机制（2026-11-24）

以下机制不再出现在基线中，理由见 [review §9.7](./review/2026-11-24-first-principles-review.md)：

- 手机编辑 / 追加、outbox、移动端冲突合并 UI 与 CM6、Layer 3 移动端格式化、瞬态加密剪贴板（D1）。
- `purge_op_ids`、`MNK1`、`key_seq`、可变 `vault_keys`、多槽位 `vault_key_slots`、Vault 第二套恢复码（D2′、F-05）。
- `SPAN_PATCH` / delta 链、HLC 漂移拒收、Lock-Wins 特例、分数索引重平衡（D3）。
- DO 滑动窗口 GC、R2 多代快照 + CAS、「\$0/月免费额度」约束（D4）。
- macOS Tauri 薄壳（`shell-macos/`）与内置全局热键窗口（D5′，2026-11-25 拍板双桌面统一纯 CLI + Daemon + HTML）。
- Plane B 统计评测、自动爬山（D6）；`mynote update` 自升级（F-14）。
