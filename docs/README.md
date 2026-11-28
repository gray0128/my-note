# 正式方案与工程规范目录（`docs/`）

本目录是 `my-note` 唯一允许直接指导开发、测试与发布的**正式方案与单一事实来源（SSOT）文档目录**。

## 仓库四类文档边界

| 目录 | 文档性质 | 是否可直接作为实施依据 | 维护规则 |
| --- | --- | :---: | --- |
| **`docs/`**（本目录） | 正式架构方案、数据结构、接口契约、同步协议、威胁模型、云端规范与质量门禁 | **是（唯一依据）** | 每个概念只在归属 SSOT 文档中定义一次，其余文档只做链接 |
| **`docs/spikes/`** | 限时技术验证（Spike）实测证据报告 | 否（仅作实测证据） | 支撑 [`architecture-proposal.md`](./architecture-proposal.md) §8 的 ADR 从 `Proposed` 升级为 `Accepted` |
| **[`research/`](../research/README.md)** | 调研报告、行业对比与发散探索（物理分 `pending/` 与 `converted/`） | **严禁直接实施** | 必须先经明确拍板并转化为本目录正式规范正文后方可实施 |
| **[`review/`](../review/README.md)** | 方案独立审查报告与决策追溯台账 | 否（须先转化至 `docs/`） | 审查结论与拍板决策须同步写入本目录正式规范后方可实施 |

## 正式方案索引（SSOT）

| 规范文档 | 权威覆盖范围 |
| --- | --- |
| [`architecture-proposal.md`](./architecture-proposal.md) | 目标、约束、非目标、整体架构蓝图、Monorepo 布局、路线图（S0 → M6）与 ADR-01～ADR-14 状态 |
| [`data-structures.md`](./data-structures.md) | ULID、定长 HLC、FractionalIndex、M6 自路由标识与离线邀请码、`InnerOpV1`、插件领域类型与 Core WASM 3-Export ABI、二进制信封与**唯一 AAD 定义（§3.3）**、全端 DDL |
| [`interface-contracts.md`](./interface-contracts.md) | 全局 `ErrorCode` 与退出码表、CLI `--json` 契约、本地 Daemon REST / WS / 跨平台 `LocalIpc` 协议、云端 Sync / Space / Device API、`mynote-wasm` 与 Tier 2 插件 Worker 边界 |
| [`sync-protocol.md`](./sync-protocol.md) | 路径 γ 多叶子并列与手动合并、完整因果图 `G(b)`、密钥表 2P-Set、碎纸宽限期、跨 `epoch` 并集对账、手机状态快照、独立剪贴板同步语义、M6 首次引导与移除设备停机协议 |
| [`threat-model.md`](./threat-model.md) | 敌手矩阵 T1–T10、分层密钥存放、约 37 天删除上界、同 UID 诚实边界、CSP、手机 PWA 信任边界、剪贴板安全边界、双宿主插件 / Windows 及受控无账号多租户安全边界 |
| [`cloudflare-cloud-architecture.md`](./cloudflare-cloud-architecture.md) | Cloudflare Workers Paid 极薄盲中继职责、单空间单 DO 惰性初始化 / Alarm / WS Hibernation、R2 类别前置布局与生命周期、Spend Management 与 10 条防坑红线 |
| [`eval-framework.md`](./eval-framework.md) | Plane A 确定性质量门禁（`proptest`、DST、真实 `workerd` 契约、`INV-RECOVERY`、`SEC-01`–`SEC-10`、`SEC-WIN-*`、`SEC-MT-*`、CLI 黄金测试）与里程碑门禁矩阵（S0 → M6） |

## 技术 Spike 实测报告（`docs/spikes/`）

- S0 阶段：[`s0-1-editor-architecture.md`](./spikes/s0-1-editor-architecture.md)、[`s0-2-macos-tauri-shell.md`](./spikes/s0-2-macos-tauri-shell.md)、[`s0-3-wasm-argon2.md`](./spikes/s0-3-wasm-argon2.md)、[`s0-4-cloudflare-relay.md`](./spikes/s0-4-cloudflare-relay.md)
- S-Clip 阶段：[`s-clip-1-ios-shortcuts.md`](./spikes/s-clip-1-ios-shortcuts.md)、[`s-clip-2-pwa-wasm-image.md`](./spikes/s-clip-2-pwa-wasm-image.md)、[`s-clip-3-macos-pasteboard.md`](./spikes/s-clip-3-macos-pasteboard.md)、[`s-clip-4-hyprland-wayland.md`](./spikes/s-clip-4-hyprland-wayland.md)、[`s-clip-5-cf-r2-streaming.md`](./spikes/s-clip-5-cf-r2-streaming.md)
- M5 阶段：[`s-plugin-1-wasmi.md`](./spikes/s-plugin-1-wasmi.md)（`wasmi` 2.0.3 体积与双宿主门禁实测）、[`s-win-1-platform.md`](./spikes/s-win-1-platform.md)（Windows Named Pipe SDDL、Job Object 与 Win32 剪贴板 `windows-latest` 实测）
- M6 规划阶段（待执行）：`s-mt-1-multi-tenant.md`（`workerd` 原生 `Ed25519` ↔ Rust 互通与惰性 DO 零写库零 Alarm 实测）
