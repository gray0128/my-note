# S0-4 实测报告：Cloudflare Paid 最小回声中继、DO Alarm 与 R2 生命周期（Issue #35）

- **当前状态**：**本地 `workerd` 实测全部通过（3/3 绿灯，`297 LOC` TS [已测]）；2026-11-26 已在真实个人 Cloudflare Paid 账号完成全套前置与首次 CI-only 生产部署实测——含 `mynote-archive` 桶、`archives/keys/history/` 30 天前缀生命周期、`archives/ops/` 前缀 Bucket Lock 兼容、最小权限单 Worker `Workers: Editor` Scoped Token 经 GitHub Actions（`deploy-cloud.yml`）首次生产部署（Worker `83.11 KiB` / `19.53 KiB` gzip + SQLite DO `v1` 迁移 + Mobile PWA 严格 CSP + 非 302 `401 AUTH_REQUIRED` 全部在线实测通过 `[已测]`）；仅剩首台设备 `device bootstrap` 后的真实边缘 5 分钟 WS Hibernation 计费核验与控制台 Spend Management 核对**。`ADR-05` 已升级为 `Accepted`，`ADR-02` 保持 `Proposed`（待 5 分钟边缘 Hibernation 计费回填）。
- **复现路径**：[`spikes/s0-4-cf-echo-relay/`](../../spikes/s0-4-cf-echo-relay/)（`pnpm typecheck && pnpm test` 运行于真实 `workerd 1.20260815.1` + Vitest 4.1）。

---

## 1. 真实 `workerd` 验证结果（全部为 `[已测]`）

| 验证项 | 验证手段（`test/relay.test.ts`） | 结果 |
| --- | --- | :---: |
| 令牌范围校验（`read` vs `read-write`） | `read` 令牌可 `GET /v1/sync/pull`、连 `/v1/sync/ws`；调 `push` / `shred` 返回 `403 TOKEN_SCOPE_FORBIDDEN` | ✅ 通过 |
| DO SQLite 单语句 ≤ 100 绑定参数约束 | 单批推送 **150 条 op**，在 `ctx.storage.transactionSync` 内单行循环写入 + 幂等重放 | ✅ 通过（`head_seq = 150`） |
| WebSocket Hibernation + 边缘零唤醒心跳 | `ctx.acceptWebSocket` + `setWebSocketAutoResponse("ping", "pong")` + `serializeAttachment/deserializeAttachment` 元数据存活 + `push` 仅发 `{ type: "wake", epoch, head_seq }` 不泄露密文 | ✅ 通过 |
| DO 单一 Alarm 复用 + `T_grace_min` 强制 | `grace_ms < 24h` 返回 `422 GRACE_TOO_SHORT`；提前触发 Alarm **不置空密钥**；虚拟时钟 `+25h` 后触发 Alarm 置空到期密钥、标记 `executed`、清理超时未认领 `pairing_tickets` 及幽灵设备行 | ✅ 通过 |
| R2 永久归档 + 双轨密钥快照幂等 | Alarm 写入 `archives/ops/<epoch>/<from>-<to>.mna1`（重复触发零重复对象）、覆写 `archives/keys/latest.mnks`（已碎纸密钥立即消失）并写入 `archives/keys/history/<day>.mnks` | ✅ 通过 |
| 代码量预算核验 | `wc -l src/index.ts` = **`297 LOC`** [已测]（含调试与时钟注入端点），验证 M1 业务中继 `< 500 LOC` [目标] 可行 | ✅ 达标 |

---

## 2. Spike 提前捕获的 4 个 Cloudflare / `workerd` 工程实坑（直接反哺 M1-10）

1. **测试插件已更名**：`@cloudflare/vitest-pool-workers` 已弃用并更名为 **`@cloudflare/vitest-plugin`**；Vitest 4.1+ 使用 `plugins: [cloudflareTest(...)]` 而非旧版 `defineWorkersConfig`。M1-10（`cloud-cf/`）应直接采用 `@cloudflare/vitest-plugin`。
2. **早期 `403` 必须排空请求体**：在 `workerd` 中，对带 JSON Body 的 `POST` 直接返回 `403` 而不消费 `req.body` 会触发 `TypeError: Can't read from request stream after response has been sent`。M1-10 鉴权/范围拒绝路径需 `if (req.body) await req.arrayBuffer()`（或 `req.body.cancel()`）。
3. **过去时间戳的 `setAlarm` 会立即触发**：测试中若向 `setAlarm` 传过去时间戳，alarm 会在 `runDurableObjectAlarm` 调用前即刻执行。M1-10 契约测试应通过可注入虚拟时钟偏移 + `Math.max(Date.now() + 1000, nextAt)` 调度未来 alarm，再用 `runDurableObjectAlarm` 精确驱动。
4. **SQLite DO 在同文件测试用例间共享存储**：`cloud-cf` 契约测试中每个场景应使用独立 DO 实例名（如 `env.SYNC_DO.idFromName(scenarioId)`）实现完全隔离。

---

## 3. 真实 Cloudflare Paid 账号验证清单（2026-11-26 实测回填）

```bash
# 生产 R2 归档桶（与 cloud-cf/wrangler.jsonc 一致）及仅针对 archives/keys/history/ 的 30 天生命周期规则
cf r2 buckets create-by-name mynote-archive
cf r2 buckets lifecycle update mynote-archive --rules @lifecycle.json -f
cf r2 buckets lifecycle get mynote-archive
# 在临时探针桶实测 archives/ops/ 前缀 Bucket Lock 不阻断 archives/keys/latest.mnks 每日覆写，测完即销毁
cf r2 buckets locks update mynote-s0-4-lock-probe --rules @lock.json -f
cf r2 objects put archives/keys/latest.mnks --bucket-name mynote-s0-4-lock-probe --file v1.bin
cf r2 objects put archives/keys/latest.mnks --bucket-name mynote-s0-4-lock-probe --file v2.bin
```

| 真账号核验项 | 配置要求 | 实测结论（2026-11-26 真实 CF Paid 账号） |
| --- | --- | --- |
| 订阅基线（Workers Paid + R2 Paid） | 核验 `workers_paid`（含 SQLite DO）与 `r2_paid` 订阅激活 | ✅ `[已测]` `cf accounts subscriptions get` 确认 `workers_paid`（\$5/月，`Paid`，含 `worker_durable_objects_*` / `worker_durable_objects_srs_*`）与 `r2_paid`（PAYGO，`Paid`）均有效 |
| 账单预算告警 / Spend Management | Workers & DO **仅开告警**，不设过紧硬拦截以防停摆 DO Alarm | ⚠️ `[部分已测]` `cf alerting policies list` 确认账户已启用 2 条纯通知 `billing_budget_alert` 邮件告警（\$1 与 \$10 阈值，无硬拦截）；`cf` CLI 未暴露 Dashboard → Billing → Spend Management 面板，需在控制台人工确认未设过紧 DO 硬上限 |
| R2 前缀生命周期规则 | `archives/keys/history/` 30 天过期；核验 `archives/keys/latest.mnks` 与 `archives/ops/` 无过期规则 | ✅ `[已测]` 已创建生产桶 `mynote-archive`（`APAC` / `Standard`）并写入规则 `expire-key-history-30d`（`conditions.prefix: "archives/keys/history/"`，`deleteObjectsTransition: { type: "Age", maxAge: 2592000 }`），与默认 7 天分片中止规则并存；`cf r2 buckets lifecycle get mynote-archive` 回读确认 `archives/keys/latest.mnks` 与 `archives/ops/` 均无过期规则 |
| R2 Bucket Lock 可用性 | 确认能否对 `archives/ops/` 前缀设置保留锁而不影响 `archives/keys/latest.mnks` 每日覆写 | ✅ `[已测]` 在临时探针桶实测 `cf r2 buckets locks update` 成功设置 `prefix: "archives/ops/"`（`Age: 86400s`）并回读确认；锁生效期间连续两次上传覆写 `archives/keys/latest.mnks`（`2 B` → `14 B`）及删除均正常成功，探针桶已清理 |
| CI-only 单 Worker 最小权限生产部署 | 仅授予单个已存在 Worker `mynote-sync-relay` 的新版 `Workers: Editor` 角色（无 R2 / 无 Zone / 无账户级删建权），经 `.github/workflows/deploy-cloud.yml` 部署 | ✅ `[已测]` `wrangler 4.167.0` 一次性成功部署（Worker `83.11 KiB` / `19.53 KiB` gzip + 7 个 Mobile PWA 静态资产），自动完成 SQLite DO `SyncJournalDO` `v1` 迁移并绑定 `ARCHIVE_BUCKET (mynote-archive)` 与 `ASSETS`，且原 Secret `BOOTSTRAP_TOKEN` 完整保留；在线 HTTPS 实测 `/` 返回严格 CSP（无 `'unsafe-inline'`）、`/v1/sync/pull` 与 `/v1/devices/bootstrap`（错令牌）均返回非 302 的 `401 AUTH_REQUIRED` JSON |
| 真实边缘 WS Hibernation | 首台桌面完成 `device bootstrap` 后保持连接静置 5 分钟发 `"ping"` 收 `"pong"`，核验 DO Metrics 无持续 Duration 计费 | ⏳ `[待补测]` 生产 `mynote-sync-relay` 与 `BOOTSTRAP_TOKEN` 已在线就绪；待用户本机 TTY 执 `mynote device bootstrap` 接入首台桌面后完成 5 分钟静置与 DO Metrics 核验 |
