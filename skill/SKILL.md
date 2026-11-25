---
name: mynote
description: Local-first block scratchpad with E2EE sync & offline formatting.
---

# mynote

Local-first multi-language block scratchpad. Invoke CLI directly (no MCP).

## Discovery
- `mynote --help` — command overview
- `mynote <cmd> --help` — flags, IO & exit codes
- `mynote help agent` — full agent contract & conflict recipes

## Golden Rules
1. Always pass `--json` (`{ok, data, error, meta}`; offline writes exit `0` with `pending_offline`).
2. Always pass `--expected-head <op>` (all leaves) on updates; retry with `error.details.actual_heads` on exit `4`.
3. Never decrypt locked blocks (`redacted: true`, exit `5`).
4. Bound queries with `--limit` (default `20`). `block delete` trashes only; permanent actions require desktop UI.

## Top Commands
- `mynote add --buf scratch --json`
- `mynote ls --limit 20 --json` | `mynote search "<q>" --json`
- `mynote block get <id> --json` | `mynote block update <id> --expected-head <op> --json`
