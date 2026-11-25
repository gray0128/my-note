# S0-4 实测报告：Cloudflare Paid 最小回声中继、DO Alarm 与 R2 生命周期（Issue #35）

- **当前状态**：**本地 `workerd` 实测全部通过（3/3 绿灯，`297 LOC` TS [已测]）；真实 Cloudflare Paid 控制台项（Spend Management 告警、R2 前缀 30 天生命周期、R2 Bucket Lock）已备好部署脚本，待在个人 CF 账号执行一次并回填**。`ADR-02` / `ADR-05` 保持 `Proposed (workerd 已测，待真账号补测)`。
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

## 3. 真实 Cloudflare Paid 账号验证清单（5 分钟部署执行后回填）

```bash
cd spikes/s0-4-cf-echo-relay
npx wrangler r2 bucket create mynote-s0-4-spike-archive
# 配置仅针对 archives/keys/history/ 前缀的 30 天自动删除规则（验证不影响 latest.mnks 与 archives/ops/）
npx wrangler r2 bucket lifecycle add mynote-s0-4-spike-archive \
  --id "expire-key-history-30d" --prefix "archives/keys/history/" --expire-days 30
npx wrangler r2 bucket lifecycle list mynote-s0-4-spike-archive
# 检查 R2 Bucket Lock（防删锁）可用性
npx wrangler r2 bucket lock list mynote-s0-4-spike-archive
# 临时部署回声 Worker 验证真实边缘 Hibernation（验证完后 wrangler delete 清理）
npx wrangler secret put BOOTSTRAP_TOKEN
npx wrangler deploy
```

| 真账号核验项 | 配置要求 | 实测结论（待个人 CF 账号填写） |
| --- | --- | :---: |
| Spend Management 支出告警 | Cloudflare 控制台 → Billing → Spend Management：Workers & DO **仅开告警**（如超额 \$5 / \$20 通知），不设过紧拦截上限以防停摆 DO Alarm | ⏳ `[待实测]` |
| R2 前缀生命周期规则 | `archives/keys/history/` 30 天过期；核验 `archives/keys/latest.mnks` 与 `archives/ops/` 无过期规则 | ⏳ `[待实测]` |
| R2 Bucket Lock 可用性 | 确认能否对 `archives/ops/` 前缀设置保留锁而不影响 `archives/keys/latest.mnks` 每日覆写 | ⏳ `[待实测]` |
| 真实边缘 WS Hibernation | 保持连接静置 5 分钟发 `"ping"` 收到 `"pong"`，查看 DO Metrics 无持续 Duration 计费 | ⏳ `[待实测]` |
