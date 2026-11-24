# `my-note` Evaluation & Verification Harness (`evals/`)

> **IMMUTABLE VERIFIER RULE (MANDATORY)**:
> Feature, bugfix, and hill-climbing PRs **MUST NOT** modify any file inside `evals/`.
> During CI, `evals/` is always checked out directly from `origin/main` before running checks (`git checkout origin/main -- evals/`).
> To add or revise evaluation cases, schemas, or regression seeds, open a dedicated **`[eval-only]`** PR touching only `evals/` and [`docs/eval-framework.md`](../docs/eval-framework.md).

## Directory Layout

- [`climb-spec.toml`](./climb-spec.toml) — Declarative target allowlist, hard constraints, split isolation, and stall-reflection policy for automated hill-climbing (`mynote-eval climb`).
- [`schemas/eval-case.v1.schema.json`](./schemas/eval-case.v1.schema.json) — JSON Schema (Draft 2020-12) for Plane B Agent & Retrieval evaluation cases.
- [`schemas/scorecard.v1.schema.json`](./schemas/scorecard.v1.schema.json) — JSON Schema for the 4-Number Release Scorecard & paired McNemar comparison reports.
- [`seeds/regression_seeds.txt`](./seeds/regression_seeds.txt) — Shrunk deterministic `SimCluster` `u64` seeds replayed on every commit (Tier 0/1).
- [`cases/dev/`](./cases/dev/) — Development / Hill-Climb training cases (each ships with a runnable `reference_solution` proving `100%` solvability).
- `cases/test/` — Frozen reporting split (hill-climbing agents receive aggregate metrics only; raw case files and per-case transcripts are unreadable to the climber).
- `cases/retrieval/` — Stage-isolated SQLite FTS5 `Recall@5` / `MRR@5` benchmark cases (Suite A4).
- `fixtures/` — Dirty Heynote `∞∞∞` migration samples and XSS / `<foreignObject>` / Prompt Injection payload vectors.
- `calibration/` — Human-labeled gold traces and Cohen's Kappa ($\kappa \ge 0.60$ gate / $\ge 0.80$ autonomous) calibration logs for Tier 2 binary claim judges.
- `reports/` — Archived milestone and release scorecards.

See [`docs/eval-framework.md`](../docs/eval-framework.md) for the full dual-plane architecture, statistical methodology, and 4-tier execution governance SOP.
