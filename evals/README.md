# `my-note` Evaluation & Verification Harness (`evals/`)

> 2026-11-24 修订：依据 [第一性原理审查 §9](../review/2026-11-24-first-principles-review.md) 的决策 D1–D7 更新。评测只为保障实现质量（D6）：保留 Plane A 确定性门禁，Plane B 统计评测与自动爬山资产已移入 [`archive/`](./archive/)。

> **IMMUTABLE VERIFIER RULE (MANDATORY)**:
> Feature and bugfix PRs **MUST NOT** modify any file inside `evals/`.
> During CI, `immutable-verifier-guard` blocks downstream jobs if a non-`[eval-only]` PR touches `evals/`, and every job resets `evals/` to the PR base commit before running checks (`rm -rf evals/ && git checkout <base-sha> -- evals/`).
> To add or revise evaluation cases, snapshots, or regression seeds, open a dedicated **`[eval-only]`** PR touching only `evals/` and [`docs/eval-framework.md`](../docs/eval-framework.md) (on `[eval-only]` PRs, CI verifies the diff touches no other paths and runs the PR's `evals/`).

## Directory Layout

### 现行资产（Plane A，进 CI 门禁）

- [`seeds/regression_seeds.txt`](./seeds/regression_seeds.txt) — Shrunk deterministic `SimCluster` `u64` seeds replayed on every commit (Tier 0/1)。同步核心 DST 与针对 workerd / miniflare 真实 Worker 的契约测试共用场景语料（F-12）；依赖已移除机制的种子以 `# RETIRED` 注释保留、不再回放。
- `fixtures/` — Dirty Heynote `∞∞∞` migration samples and XSS / `<foreignObject>` payload vectors（供导入差分、格式化幂等与渲染安全测试使用）。
- [`golden/`](./golden/) — 11 个 CLI 黄金测试场景（`G01`–`G11`）、植错自检门禁（`--selftest`，`MG-01`–`MG-07`）及冻结规范化快照（[`snapshots/`](./golden/snapshots/)）与统一运行脚本 [`run_golden.sh`](./golden/run_golden.sh)：在隔离 `HOME`/`XDG_*`/`MYNOTE_DATA_DIR` 环境中断言 `--json` 输出结构、退出码、错误码、数据库终态、L1–L3 `--help` 非空与 `skill/SKILL.md < 250 tokens` 预算；取代 Plane B「Agent 能否正确使用 CLI」的目标。运行方式：`./evals/golden/run_golden.sh --selftest`（毫秒级判分器自检）或 `cargo build --bin mynote && ./evals/golden/run_golden.sh`。
- `reports/` — Archived milestone gate results.

门禁的完整清单（属性测试、DST、真实 Worker 契约测试、INV-RECOVERY、INV-KEY-LIVENESS / INV-SHRED-BOUND / INV-GRACE、SEC 取证、格式化幂等、CLI 黄金测试、可选信封 fuzz、macOS + Linux CI）以 [`docs/eval-framework.md`](../docs/eval-framework.md) 为单一事实来源，此处不重复定义。

### 归档资产（[`archive/`](./archive/)，推迟，不进 CI）

`archive/` 保存 Plane B 统计评测与自动爬山的历史资产，保持原相对目录结构，仅作设计参考：**CI 不读取、不回放、不作为门禁**，新功能也不应依赖其中的格式。

- [`archive/climb-spec.toml`](./archive/climb-spec.toml) — 自动爬山（`mynote-eval climb`）的靶标白名单、约束、分集隔离与卡壳复盘策略。
- [`archive/schemas/eval-case.v1.schema.json`](./archive/schemas/eval-case.v1.schema.json) — Plane B Agent & Retrieval 评测用例 Schema（B1–B5 套件、dev / test / canary 分集）。
- [`archive/schemas/scorecard.v1.schema.json`](./archive/schemas/scorecard.v1.schema.json) — 四数发布计分卡与配对 McNemar 对比报告 Schema（四项指标中三项依赖 Plane B：`pass^3`、Cohen's Kappa、McNemar）。
- [`archive/cases/dev/`](./archive/cases/dev/) — Plane B 开发集用例（`B2-001-…`、`B5-001-…`）。原规划中的 `cases/test/`、`cases/retrieval/`、`calibration/` 从未创建，随 Plane B 一并推迟。

**恢复条件**：只有当「CLI 黄金测试全部通过，但仍观察到 Agent 系统性用错 CLI」时，才重新评估 Agent 使用 CLI 的统计评测（见 [review §9.9](../review/2026-11-24-first-principles-review.md) 与 §9.11「按数据触发的待办」，以及 [`docs/eval-framework.md`](../docs/eval-framework.md)）。自动爬山与跨模型评委已从待办中移除，不设恢复条件。

## 已移除 / 推迟的机制（2026-11-24）

- Plane B 统计评测（45/55/25 分集、Cohen's Kappa、`pass^3`、McNemar）：推迟，由 CLI 黄金测试替代，见 [review §9.9](../review/2026-11-24-first-principles-review.md)。
- 自动爬山（`climb-spec.toml`）与跨模型家族评委：移出路线图，见 [review §9.9 / §9.11](../review/2026-11-24-first-principles-review.md)。
- 以 LLM 评分为门禁的任何测试：删除，见 [review §9.9](../review/2026-11-24-first-principles-review.md)。
- 回归种子 INV-SYNC-4（`LOCK` + `vault_key_records`）与 INV-SYNC-5（R2 K 代快照回退）：所依赖的机制已删除，见 [review §9.3 / §9.7](../review/2026-11-24-first-principles-review.md)。
