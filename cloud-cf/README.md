# `cloud-cf` — M1 Thin Blind Sync Relay (Cloudflare Workers Paid)

Single-tenant zero-knowledge blind sync relay implementing `docs/cloudflare-cloud-architecture.md` and `docs/interface-contracts.md` §4.

## Architecture & Guarantees

- **Zero plaintext**: DO SQLite (`SyncJournalDO`) and R2 (`ARCHIVE_BUCKET`) store only opaque AEAD envelopes (`MNS1`), wrapped key records (`MNR1`), and encrypted pairing payloads (`MNPR`).
- **Zero `/v1/archive/*` or `/v1/blobs/*` HTTP routes**: R2 archives (`archives/ops/<epoch>/<from>-<to>.mna1`, `archives/keys/latest.mnks`, `archives/keys/history/<yyyy-mm-dd>.mnks`) are written solely by the DO daily `alarm()`. Extreme dual-loss recovery downloads `archives/` via CF dashboard / `wrangler` / `rclone` and runs offline `mynote restore --from-archive <local-dir>`.
- **M1 safety boundary**: No `shred_marks` table and no physical key deletion during M1. Op ciphertexts are append-only forever.
- **DO platform invariants**: Single-row SQL loops inside `ctx.storage.transactionSync` (respecting the 100 bind-parameter limit); WebSocket Hibernation (`ctx.acceptWebSocket` + `setWebSocketAutoResponse("ping", "pong")` + `serializeAttachment`); single multiplexed `alarm()`.

## Deployment Policy (Mandatory)

Per `docs/threat-model.md` §4 & `AGENTS.md` §6:
- **Do NOT run manual `wrangler deploy` against production from a workstation.**
- Deploy exclusively from GitHub Actions (`.github/workflows/deploy-cloud.yml`) using a minimal-scope Cloudflare API Token stored in GitHub Secrets, with FIDO2 hardware 2FA enabled on the Cloudflare account.
- Set the deployment secret once in Cloudflare / CI:
  ```bash
  wrangler secret put BOOTSTRAP_TOKEN
  ```

## Cloudflare Account Configuration Checklist

1. **Custom Domain**: Bind a personal custom domain (e.g. `note.example.com`) rather than `*.workers.dev`.
2. **Spend Management Alerts (D4)**: Configure monthly billing alerts (e.g. \$5 / \$20) in Cloudflare Spend Management. **Prefer alert-only or a generous cap** — triggering a hard DO spend cap halts SQL writes and `alarm()` archiving.
3. **R2 Lifecycle Rule**: Create a 30-day (`T_snap`) object expiration rule scoped strictly to prefix `archives/keys/history/`. Leave `archives/keys/latest.mnks` and `archives/ops/` without expiration rules.

## Local Verification

```bash
pnpm --dir cloud-cf install
pnpm --dir cloud-cf typecheck
pnpm --dir cloud-cf test
```
