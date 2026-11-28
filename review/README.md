# 方案审查与决策追溯记录（`review/`）

本目录归档对 `my-note` 设计方案的独立审查报告与拍板决策追溯记录，与正式方案目录（[`docs/`](../docs/README.md)）及调研目录（[`research/`](../research/README.md)）物理分离。每份报告注明审查对象的提交哈希与转化状态，便于审计追踪。

> [!IMPORTANT]
> **审查纪律**：本目录文档仅作评审决策与审计留痕，**不得跳过正式文档直接作为开发实施依据**；所有已确认的审查结论与拍板决策必须完整转化为 `docs/` 对应 SSOT 规范正文后方可实施。为兼容 [`evals/`](../evals/README.md) 不可变验证器中的既有引用路径，已转化报告保留原文件名并在下表标注处理状态。

| 日期 | 报告 | 审查对象 | 处理状态 | 摘要 |
| --- | --- | --- | :---: | --- |
| 2026-11-24 | [第一性原理审查与决策记录（§9 D1–D11）](./2026-11-24-first-principles-review.md) | `main` @ `31931a2`（后续追加 D8/D8′、D5″、D9、D10、D11） | `已转化至 docs/` | 7 项 P0 缺陷审查与约 15 项机制裁剪；§9 连续记录拍板决策 **D1–D11**（含 2026-11-27/28 D8/D8′ 独立图文剪贴板与分层留存、2026-11-28 D5″ 纯 Swift macOS 可选薄壳、D9 Windows 一等桌面平台、D10 `wasmi` 优先双宿主插件体系，以及 D11 M6 受控无账号多租户与设备生命周期管理），对应规范已全部转化为 `docs/` 正式正文 |
| 2026-11-28 | [受控无账号多租户（路线 B）与设备生命周期管理审查及拍板记录（D11）](./2026-11-28-controlled-multi-tenant-and-device-review.md) | [`2026-11-28-controlled-multi-tenant-and-device-management.md`](../research/converted/2026-11-28-controlled-multi-tenant-and-device-management.md) & `v0.3.2` 源码 | `已转化至 docs/` | 源码级核查揭示 7 项实现死锁与基线失真（`F-MT-01`..`F-MT-07`：首次启动 UI 引导死锁、离线建库 `owner_pk` 派生、`pair_id` 跨空间防伪、被移除桌面轮询熔断、`wire.ts` 行数漏算与 D8′ 31 天 R2 兼容、`INV-MT-IDLE-ALARM`、纯内存挑战与单一 `SPACE_MASTER_SECRET`），记录 Q1–Q6 拍板结论 **D11**（排入 `M6`、`<= 1,250` 行预算、受邀空间默认 `512 MiB / 500 条 / 14 天` 剪贴板配额、PWA 被移除自动清缓存）并完成 `docs/` 全量转化 |
