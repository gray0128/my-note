# 调研报告目录（`research/`）

本目录集中保存 `my-note` 项目的可行性调研、行业对比、技术选型分析与发散探索报告，与正式方案规范（[`docs/`](../docs/README.md)）和方案审查记录（[`review/`](../review/README.md)）物理分离。

## 强制纪律

> [!IMPORTANT]
> 1. **调研报告严禁直接作为开发、原型或实施依据**。任何调研报告仅作背景分析、风险揭示与选项对比参考。
> 2. 只有经过项目负责人明确拍板，并将确定的结论、数据结构、接口契约、安全边界与测试门禁**完整转化为 `docs/` 正式方案文档正文**后，方可进入编码实施。
> 3. 按转化状态物理分目录保存：
>    - `research/pending/`：待决策或未转化为正式方案的调研报告（禁止直接实施）。
>    - `research/converted/`：已明确拍板并完成正式方案转化的调研报告（仅留档追溯；若与 `docs/` 正文存在差异，一律以 `docs/` 为准）。

## 调研台账

| 日期 | 调研报告 | 状态 | 转化落位（正式方案 / 决策编号） | 摘要 |
| --- | --- | :---: | --- | --- |
| 2026-11-27 | [跨端剪贴板同步可行性深度调研](./converted/2026-11-27-clipboard-sync-research.md) | `Converted` | **D8**（[review §9](../review/2026-11-24-first-principles-review.md)）、[`architecture-proposal.md`](../docs/architecture-proposal.md) `ADR-11` 及 [`data-structures.md`](../docs/data-structures.md) / [`sync-protocol.md`](../docs/sync-protocol.md) / [`interface-contracts.md`](../docs/interface-contracts.md) / [`threat-model.md`](../docs/threat-model.md) / [`cloudflare-cloud-architecture.md`](../docs/cloudflare-cloud-architecture.md) / [`eval-framework.md`](../docs/eval-framework.md) | 独立 100 条图文跨端剪贴板通道：DO 轻索引 + R2 流式加密原图、四态令牌、独立 `ClipKey`、移动端三梯队交互（原 `docs/clipboard-sync-proposal.md` 归类迁入） |
| 2026-11-28 | [插件化可行性与跨平台架构深度调研（含 macOS / Linux / Windows）](./converted/2026-11-28-plugin-architecture-analysis.md) | `Converted` | **D9 / D10**（[review §9](../review/2026-11-24-first-principles-review.md)）、[`architecture-proposal.md`](../docs/architecture-proposal.md) `ADR-12` / `ADR-13` 及配套 `docs/` 正式规范（M5） | 对比 7 类成熟产品插件机制并审计 Windows 7 项源码缺口；已拍板 Windows 升为一等桌面平台（D9）及路线 B `wasmi` 零依赖优先双宿主插件体系（D10） |
| 2026-11-28 | [`v0.3.2` 基建能力外延：10 个发散方向深度调研](./pending/2026-11-28-10-directions-infra-analysis.md) | `Pending` | 尚未转化为正式方案（严禁直接实施） | 基于 `v0.3.2` 现有 E2EE / `MNC1` / `--ephemeral` / Rust-WASM 基建发散探索 10 个潜在方向与资源约束边界；其中 8 个方向已于插件调研中归类为未来插件场景 |
| 2026-11-28 | [受控无账号多租户（路线 B）与设备生命周期管理方案调研](./converted/2026-11-28-controlled-multi-tenant-and-device-management.md) | `Converted` | **D11**（[专项审查与拍板记录](../review/2026-11-28-controlled-multi-tenant-and-device-review.md)、[review §9](../review/2026-11-24-first-principles-review.md)）、[`architecture-proposal.md`](../docs/architecture-proposal.md) `ADR-14`（`M6`）及全部配套 `docs/` 正式规范 | 面向 5–50 名受邀亲友的邀请制无账号多租户与桌面 UI 设备查看/防自锁远程移除闭环；经源码级审查修正 `F-MT-01`..`F-MT-07` 并拍板 Q1–Q6 后已完整转化为 `docs/` 正式方案（与原调研存在差异处一律以 `docs/` 与 D11 为准） |
