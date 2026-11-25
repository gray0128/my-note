# S0 Technical Spikes (`spikes/`)

本目录存放 **S0 里程碑（GitHub Milestone #1）** 的限时技术验证脚手架，与正式业务目录（`crates/`、`web/`、`cloud-cf/`）完全隔离，**不被正式 Cargo Workspace 或发行构建依赖**。实测结论与 ADR 升级记录见 [`docs/spikes/`](../docs/spikes/)。

| Spike | 对应 Issue | 目录 | 本地复现命令 | 状态 |
| --- | --- | --- | --- | --- |
| **S0-1** CM6 单文档 vs 按块挂载 | #32 | `s0-1-cm6-editor/` | `pnpm install && pnpm exec tsc --noEmit && python3 run_editor_eval.py` | ✅ 已完成并拍板 `ADR-07`（选候选 A） |
| **S0-2** macOS 平台形态评估（D5′） | #33 | *(已随决策删除)* | — | ✅ 2026-11-25 拍板移除 macOS Tauri 薄壳，双桌面统一纯 CLI + Daemon + HTML（见 [`s0-2-macos-tauri-shell.md`](../docs/spikes/s0-2-macos-tauri-shell.md)） |
| **S0-3** `mynote-wasm` 体积 & iPhone Argon2id | #34 | `s0-3-wasm-argon2/` | `./measure.sh && cargo test --features comp-ruzstd-rw,comp-zstd-c && python3 run_browser_bench.py` | ✅ 体积基线（`ADR-01`）与 iPhone 主屏 PWA 真机实测均闭环，拍板 `(32768, 2, 1)` = `1553 ms` 并升级 `ADR-06` |
| **S0-4** CF Paid Echo Relay / DO Alarm / R2 | #35 | `s0-4-cf-echo-relay/` | `pnpm install && pnpm typecheck && pnpm test` | ✅ `workerd` 3/3 绿灯（297 LOC）；⏳ 真账号 Spend Management & R2 生命周期见报告清单 |
