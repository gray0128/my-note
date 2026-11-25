# S0 Technical Spikes (`spikes/`)

本目录存放 **S0 里程碑（GitHub Milestone #1）** 的 4 项限时技术验证脚手架，与正式业务目录（`crates/`、`web/`、`cloud-cf/`、`shell-macos/`）完全隔离，**不被正式 Cargo Workspace 或发行构建依赖**。实测结论与 ADR 升级记录见 [`docs/spikes/`](../docs/spikes/)。

| Spike | 对应 Issue | 目录 | 本地复现命令 | 状态 |
| --- | --- | --- | --- | --- |
| **S0-1** CM6 单文档 vs 按块挂载 | #32 | `s0-1-cm6-editor/` | `pnpm install && pnpm exec tsc --noEmit && python3 run_editor_eval.py` | ✅ 已完成并拍板 `ADR-07`（选候选 A） |
| **S0-2** macOS Tauri 热键 & Keychain ACL | #33 | `s0-2-macos-tauri-spike/` | 需 macOS 真机，见 [`s0-2-macos-tauri-spike/README.md`](./s0-2-macos-tauri-spike/README.md) | ⏳ 脚手架就绪，待 macOS 真机实测 |
| **S0-3** `mynote-wasm` 体积 & Argon2id | #34 | `s0-3-wasm-argon2/` | `./measure.sh && cargo test --features comp-ruzstd-rw,comp-zstd-c && python3 run_browser_bench.py` | ✅ 体积基线与 `ruzstd` 互通完成（拍板 `ADR-01`）；⏳ iPhone 真机打开 `bench.html` 待补测 |
| **S0-4** CF Paid Echo Relay / DO Alarm / R2 | #35 | `s0-4-cf-echo-relay/` | `pnpm install && pnpm typecheck && pnpm test` | ✅ `workerd` 3/3 绿灯（297 LOC）；⏳ 真账号 Spend Management & R2 生命周期见报告清单 |
