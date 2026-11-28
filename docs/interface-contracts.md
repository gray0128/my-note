# 全链路接口与跨边界契约规范 (`interface-contracts.md`)

> 2026-11-28 修订：依据 [第一性原理审查 §9](../review/2026-11-24-first-principles-review.md) 的决策 D1–D10（含 2026-11-27 剪贴板同步拍板 D8 / D1′，以及 2026-11-28 Windows 一等桌面平台 D9 与 `wasmi` 优先双宿主插件体系 D10）更新。

> 本文档与 [数据结构规范 (`data-structures.md`)](./data-structures.md)、[同步协议规范 (`sync-protocol.md`)](./sync-protocol.md)、[威胁模型规范 (`threat-model.md`)](./threat-model.md) 共同构成编码级契约基准，精确定义 **统一错误码表、Agent-Native CLI 契约、本地 Daemon REST / WS / 跨平台 `LocalIpc` 契约、Cloudflare 云端同步 API 契约，以及 `mynote-wasm` / 桌面插件 Web Worker 边界接口**。
>
> **单一事实来源**：本文档是**本地 API / CLI** 的唯一定义处。线格式、信封与 AAD 只在 [`data-structures.md`](./data-structures.md) 定义；合并规则、密钥表 2P-Set、碎纸与宽限期语义只在 [`sync-protocol.md`](./sync-protocol.md) 定义；安全承诺只在 [`threat-model.md`](./threat-model.md) 定义；测试门禁只在 [`eval-framework.md`](./eval-framework.md) 定义。本文只引用这些概念，不重复定义。

---

## 目录

1. [全局错误码注册表与跨层映射契约](#1-全局错误码注册表与跨层映射契约)
2. [Agent-Native CLI 命令、JSON 信封与外部格式化契约](#2-agent-native-cli-命令json-信封与外部格式化契约)
3. [本地桌面 Daemon 契约（HTTP + WebSocket + 跨平台 `LocalIpc`）](#3-本地桌面-daemon-契约http--websocket--跨平台-localipc)
4. [Cloudflare 云端盲同步中继契约（HTTP + R2 + WebSocket Hibernation）](#4-cloudflare-云端盲同步中继契约http--r2--websocket-hibernation)
5. [`mynote-wasm` TypeScript ↔ Rust WASM 边界契约](#5-mynote-wasm-typescript--rust-wasm-边界契约)
6. [已移除 / 推迟的机制（2026-11-24）](#6-已移除--推迟的机制2026-11-24)

---

## 0. 贯穿全文的约定

- **`op_id` 由执行正文加密的 core 实例生成（修正 F-01）**：每个 op 的 `op_id` 由**执行正文加密的那个 `mynote-core` 实例**在加密之前生成，写入 `MNB1` 与 `MNS1` AAD（唯一定义见 [`data-structures.md`](./data-structures.md) §3.3）。
  - 明文 / Tier 1 写入：Daemon（或离线直写的 CLI 进程）内的 core 生成，CLI 与本地 REST 调用方不传 `op_id`。
  - Tier 2 写入：桌面前端 `WasmVaultSession` 只持有 `VKEK`（不持有 `SMK`），在 WASM 内生成 `(op_id, key_id)` 并产出 `mnb1`（及新建/换钥时的 `mnw1`），在本地 REST/UDS 请求中**显式传入 `{ op_id, key_id, mnb1_b64, mnw1_b64? }`**；Daemon **原样采用该 `op_id`**，用 `SMK` 封装外层 `MNS1` 与 `MNR1`，绝不重新生成。
- **多版本（路径 γ）**：一个块可能同时有多个叶子版本。`head_op_ids` 是当前全部叶子；`display_op_id` 是 `(hlc, op_id)` 最大的存活叶子。任何写正文的请求都必须声明它看到的**全部叶子**（`--expected-head` / `expected_heads`），声明集合即新 op 的 `parents`；叶子数 > 1 时，这次写入就是一次**合并**。规则详见 [`sync-protocol.md`](./sync-protocol.md)。
- **删除 = 回收站（M1 纯软删，M2 启用 `shred_marks` 与到期碎纸）**：删除把块放进回收站。M1 只写 `DELETE` 墓碑 op（`shred_state = "unscheduled"`，随时可恢复，物理上无删钥路径）；M2 上线 `shred_marks` 状态机、服务端强制最短宽限期 `T_grace_min` = 24 小时 [保证]、批量阈值 N = 20 块/天及 DO alarm 执行器（并对 M1 回收站存量块一次性豁免阈值补建 `T_grace` = 7 天标记）。语义见 [`sync-protocol.md`](./sync-protocol.md)，时间上界见 [`threat-model.md`](./threat-model.md)。
- **本地入口唯一**：`http://localhost:<port>`（修正 F-15）。

---

## 1. 全局错误码注册表与跨层映射契约

所有子系统共享同一套机器可读错误码枚举（`ErrorCode`），确保 CLI、本地 Daemon 与云端 Worker 的错误处理、重试判定与 Agent 自愈提示（`hint`）完全一致：

| 稳定错误码 `error.code` | CLI 退出码 | HTTP 状态码 | `retryable` | 触发条件与强制 `hint` 模板规范 |
| --- | :---: | :---: | :---: | --- |
| *(成功)* | `0` | `200 / 201` | — | 含断网/无 Daemon 时本地落盘成功的常规写命令（`meta.sync_state = "pending_offline"`）；`block delete` 成功即进入回收站（M2 起即使碎纸标记因离线未同步或超批量阈值暂停，也返回 `0`，见 `data.shred_state`） |
| `INVALID_ARGUMENT` | `2` | `400` | `false` | 参数缺失/格式非法、未知子命令；提示运行 `mynote <cmd> --help` |
| `EMPTY_STDIN_REFUSED` | `2` | `400` | `false` | 非交互 `stdin` 为 0 字节但目标块非空；`hint: "Pass --allow-empty to clear content, or use 'mynote block delete <id>' (moves it to trash)"` |
| `INTERACTION_REQUIRED` | `2` | `400` | `false` | 非 TTY / `--non-interactive` 下请求了必须人工在终端确认的操作（`--force`、`vault *`、`device bootstrap/add/refresh/claim`、`keyring rotate/unlock`、`recovery show/drill`、`restore --from-archive`） |
| `UI_CONFIRMATION_REQUIRED` | `2` | `428` | `false` | 请求了**只能在桌面 UI 中交互确认**的操作：清空回收站、缩短宽限期、确认超出批量阈值的碎纸。CLI 的 `trash empty` / `trash expedite` / `trash confirm` **无论是否 TTY 都固定返回此码**（Agent 可以驱动伪终端，所以 TTY 不能证明是本人操作）；本地 API 的 `trash/actions/commit` 缺少有效 `confirm_nonce` 时也返回此码。由本地 Daemon 强制。`hint: "Open the desktop UI ('mynote open') and confirm there"` |
| `NOT_FOUND` | `3` | `404` | `false` | 指定 `BufferId`、`BlockId`、`op_id`、`key_id` 不存在 |
| `IN_TRASH` | `3` | `404` | `false` | 目标块在回收站中；`details: { deleted_at_ms, shred_not_before_ms }`；`hint: "Run 'mynote trash restore <id>' to undo the deletion"` |
| `HEAD_MISMATCH` | `4` | `409` | `true` | `--expected-head` 集合与当前全部叶子 `head_op_ids` 不一致；`details: { expected_heads, actual_heads }`；提示先 `block get --json` 再重试 |
| `CONFLICT_PRESENT` | `4` | `409` | `false` | 只能作用于单一版本的命令（`block append`、`format <id>`、`block revert`）遇到多叶子块；`hint: "Block has N versions; inspect with 'mynote block get <id> --json', then merge via 'mynote block update <id> --expected-head <h1> --expected-head <h2> ...'"` |
| `CAS_MISMATCH` | `4` | `409` | `true` | 云端 `expected_epoch` 与远端 epoch 不一致（如 DO PITR 回滚后）；或上传的手机状态快照在同一 `epoch` 内 `covers_seq` 未递增（客户端丢弃该快照即可） |
| `BLOCK_LOCKED` | `5` | `423` | `false` | 未解锁访问加锁块（任一叶子加锁即整块按加锁处理），或非 TTY 请求解密 |
| `KEY_SHREDDED` | `5` | `410` | `false` | 目标版本的 `key_id` 已过宽限期并被碎纸，内容永久不可恢复（如超期后 `trash restore`、撤销已执行标记、读取「换钥」前的历史版本） |
| `KEY_UNKNOWN` | `5` | `409` | `false` | 云端拒收引用服务端不认识的 `key_id` 的 op（密钥记录未随批提交或从未创建）。正常客户端不会触发，出现即说明有 bug |
| `KEY_PENDING_SHRED` | `4` | `409` | `true` | 云端拒收引用已有 `pending_confirm` / `scheduled` 碎纸标记的 `key_id` 的新 op，且同批未先撤销该标记。core 自动按 Update-Wins 规则（[`sync-protocol.md`](./sync-protocol.md) §5.7）撤销或换钥后重试 |
| `SHRED_STALE` | `4` | `409` | `true` | 云端拒收碎纸标记：本批之前该 `key_id` 下已存在请求方未见过的远端 op（`seq > seen_seq`）。core 自动 pull、重新评估后再提交 |
| `GRACE_TOO_SHORT` | `5` | `422` | `false` | 云端拒收 `grace_ms < T_grace_min`（或缩短后早于 `requested_at_ms + T_grace_min`）的碎纸请求。正常客户端不会触发，出现即说明有 bug 或滥用 |
| `AUTH_REQUIRED` / `DEVICE_REVOKED` / `TOKEN_SCOPE_FORBIDDEN` | `5` | `401 / 403` | `false` | 本地 Cookie / Origin 校验失败；云端 `device_token` 无效/未认领/已吊销；或 `scope=read` 令牌尝试写操作 |
| `SYNC_OFFLINE` | `6` | `502 / 503` | `true` | **仅用于显式联网阻塞命令**（`sync push/pull`、`clip push --wait-sync`、`clip pull`、`clip prune/clear --scope cloud\|all`、`clip rotate-key`、`keyring rotate`、`device bootstrap/add/refresh/claim`）无法连通远端 |
| `NO_ONLINE_DESKTOP` | `6` | `409` | `true` | **（M4，D8）**`POST /v1/clip` 传入 `ephemeral: true`（零写库纯内存直推）时当前无任何在线 `read-write` 桌面 WebSocket 可交付，服务端拒绝悄悄写库；`hint: "Bring a desktop daemon online and retry, or omit --ephemeral to send via the encrypted clip queue"` |
| `CLIP_QUOTA_EXCEEDED` | `6` | `507` | `false` | **（M4，D8′）**`PUT /v1/clip/blob` 写入后云端 R2 活跃剪贴板大对象总占用将超过 `5 GiB` 硬护栏；`details: { used_bytes, limit_bytes, incoming_bytes }`；不阻塞 `≤ 64 KiB` 内联文本与 `--ephemeral`；`hint: "Run 'mynote clip prune --scope cloud --kind image --before-days 7' or 'mynote clip clear --scope cloud' to free cloud space (desktop local archive is preserved)"` |
| `RATE_LIMITED` | `6` | `429` | `true` | 云端限流；按 `Retry-After` 退避 |
| `FORMAT_SYNTAX_ERROR` | `7` | `422` | `false` | Layer 1/2 格式化输入语法错误或外部命令返回 0 字节/超时；原块保持未修改 |
| `PLUGIN_INVALID_MANIFEST` | `2` | `400` | `false` | **（M5，D10）**`plugin.toml` 校验失败、`exec` 声明 `tier2_capable = true`、路径穿越或 `.bat`/`.cmd` 入口、或 `.wasm` 含非空 `imports` / ABI 版本不匹配 |
| `PLUGIN_RESOURCE_EXCEEDED` | `7` | `422` | `false` | **（M5，D10）**WASM 插件命中 `fuel_limit` / `16 MiB` `StoreLimits` / Worker `terminate()` 超时，或 `exec` 插件超时（击杀整棵进程树）或触发 `reactor` 速率上限；原块保持未修改 |
| `PLUGIN_EXECUTION_FAILED` | `7` | `422` | `false` | **（M5，D10）**插件 trap、非零退出、输出非合法 `PluginResult` JSON 或触发零字节熔断；原块保持未修改 |
| `KEY_MISSING` | `8` | `500` | `false` | 活跃块（未进入碎纸流程）找不到可用密钥，违反 INV-KEY-LIVENESS；本设备随即停止发起碎纸（见 §2.3 `sync status`）；`hint: "Run 'mynote sync pull'; if it persists, do not delete anything and report"` |
| `INTEGRITY_ERROR` | `8` | `422 / 500` | `false` | AEAD 解密失败、请求字段与密文 AAD 不符、手机状态快照 `BLAKE3` 失配，或本地库 `min_reader_schema_version` 高于当前二进制（`SCHEMA_TOO_NEW`） |

---

## 2. Agent-Native CLI 命令、JSON 信封与外部格式化契约

### 2.1 统一 JSON 输出信封（`--json`）

所有命令在传入 `--json` 时，`stdout` **必须且只能输出单条合法 UTF-8 JSON 对象**（进度/告警一律走 `stderr`）：

```typescript
interface CliEnvelope<T> {
  ok: boolean;
  data: T | null;
  error: {
    code: ErrorCode;
    message: string;
    hint: string;
    retryable: boolean;
    details?: Record<string, unknown>; // 如 HEAD_MISMATCH 时附带 { expected_heads, actual_heads }
  } | null;
  meta: {
    local_op_count_pending: number;
    sync_state: "synced" | "syncing" | "pending_offline" | "unconfigured" | "conflict_present";
    redacted_locked_count?: number;
    duration_ms: number;
  };
}
```

写命令（`add`、`block update/append/move/revert/delete`、`trash restore`）的 `data` 至少包含：`{ block_id, op_id, head_op_ids, buffer_id }`。其中 `op_id` 是 core 生成后**返回**的值，不是输入。

### 2.2 核心 DTO 结构契约

1. **列表与搜索摘要项（`mynote ls --json` / `mynote search <q> --json`，默认 `--limit 20`；不含回收站中的块）**：
   ```json
   {
     "id": "01JDF8Z9X4K7M2N5P8Q1R3S6T9",
     "buffer_id": "01JDF8Y0000000000000000001",
     "buffer_name": "scratch",
     "position": "a08xK2",
     "lang": "json",
     "is_locked": false,
     "redacted": false,
     "public_hint": null,
     "head_op_ids": ["01JDF910A2B3C4D5E6F7G8H9J0"],
     "display_op_id": "01JDF910A2B3C4D5E6F7G8H9J0",
     "has_conflict": false,
     "byte_size": 18420,
     "preview": "{\n  \"status\": 200,\n  \"items\": [ ... (truncated to 240 chars)",
     "actor": "human",
     "updated_at_ms": 1795521600123
   }
   ```
   - `has_conflict` ⇔ `head_op_ids.length > 1`；`preview`、`byte_size`、`lang` 取自 `display_op_id` 对应的版本。
   - *若 `is_locked == true`（任一存活叶子加锁即为真）：强制返回 `"redacted": true, "byte_size": null, "preview": null`，仅保留 `id`、`buffer_id`、`position`、`is_locked`、`public_hint`、`head_op_ids`、`has_conflict` 与 `updated_at_ms`。*

2. **单块完整读取（`mynote block get <id> --json`）**：
   - 未加锁块返回 `content: string`（展示版本的正文）与 `versions: Array<{ op_id, hlc, device_id, actor, is_display, is_locked, content: string | null }>`。`versions` 包含全部存活叶子：展示版本排第一，其余按 `(hlc, op_id)` 降序；非展示版本在 UI 中标为「另一台设备的版本」。
   - 加锁块（任一存活叶子加锁）：`content: null`，`versions[*].content` 全部为 `null`（包括未加锁的并发版本），并附带 `has_unlocked_concurrent_version: boolean`。这类块的合并只能在 UI 解锁后完成。
   - `mynote block get <id> --raw`（不带 `--json`）直接向 `stdout` 写出展示版本无尾随装饰的原始 `content` 字节，便于 `mynote block get <id> --raw | jq .` 管道直连。若存在多个版本，`stderr` 提示 `"block has N versions"`，退出码仍为 `0`。若目标块已加锁，则 `stdout` 为空、退出码 `5`。
   - 目标块在回收站中：退出码 `3`（`IN_TRASH`）。

### 2.3 全子命令矩阵与关键参数契约

| 命令 | 核心参数与管道契约 | 幂等与乐观锁要求 | 里程碑 |
| --- | --- | --- | --- |
| `mynote add [text]` | 无位置参数时读 `stdin`；`--buf <name\|id>`（默认 `"scratch"`）、`--lang <lang>`（默认自动嗅探 JSON/SQL/Markdown 或 `"text"`）、`--format`、`--after <block_id>`。从剪贴板新建：`pbpaste \| mynote add` / `wl-paste \| mynote add` | 支持 `--idempotency-key <key>`（重放返回同一 `block_id` / `op_id`，并带 `data.idempotent_replay: true`） | M1 |
| `mynote ls` / `mynote search <q>` | `--buf <name\|id>`、`--limit <N>`（默认 `20`）；不返回回收站中的块 | 只读 | M1 |
| `mynote block get <id>` | `--raw`（纯正文流）、`--max-chars <N>`、`--decrypt`（仅允许真实 `/dev/tty` 交互口令） | 只读 | M1（`--decrypt` M2） |
| `mynote block update <id> [text]` | 读参数或 `stdin`；非 TTY 空输入默认报 `EMPTY_STDIN_REFUSED`（除非 `--allow-empty`）。**提交合并**也用本命令：`--expected-head` 列出全部叶子即可 | **强制要求** `--expected-head <op_id>`（可重复；集合必须**等于**当前全部叶子，否则 `HEAD_MISMATCH`）；人工终端可传 `--force`（以写入时刻的全部叶子为 `parents`；非 TTY 下拒绝） | M1 |
| `mynote block append <id> [text]` | 在展示版本末尾追加文本，生成新的全量载荷 op | 支持 `--expected-head <op_id>`；多叶子块返回 `CONFLICT_PRESENT` | M1 |
| `mynote block move <id>` | `--to-buf <buf>`、`--after <id>` / `--before <id>`（仅发 `SET_META`） | 字段 LWW 幂等，不需要 `--expected-head` | M1 |
| `mynote block resolve <id>` | **`block update` 的别名**（`RESOLVE` 不是独立 op 类型）：从 `stdin` 读入合并后的全文；或 `--keep <op_id>` 以某个版本的正文作为合并结果（core 重新生成全量载荷 op；加锁版本只能在 UI 中操作） | 同 `block update`：`--expected-head` 必须列出全部叶子 | M1 |
| `mynote block history <id>` / `block revert <id>` | `history` 列出版本元数据；`revert --to-op <op_id>` 或 `--undo-actor <actor>`，把选中版本的正文写成新 op。密钥已碎纸的版本返回 `KEY_SHREDDED` | 生成新 `UPDATE`，不篡改历史；多叶子块返回 `CONFLICT_PRESENT` | M1 |
| `mynote block delete <id>` | **只把块放进回收站**：写墓碑 op（M2 起同时对该块全部未碎纸密钥登记碎纸标记，`grace_ms = T_grace`）；支持 `--dry-run`。**无** `--purge` / `--now` / `--grace` 选项。响应 `data` 额外包含 `in_trash: true`、`shred_not_before_ms` 与 `shred_state`：M1 固定为 `"unscheduled"`（`shred_not_before_ms: null`）；M2 起离线未同步为 `"pending_sync"`（`null`），服务端确认后为 `"scheduled"`（带服务端 `shred_not_before_ms`）或超 20 块/天阈值的 `"pending_confirm"`（`null`），本机自检失败不发标记为 `"withheld_self_check"`。退出码均返回 `0` | 支持 `--expected-head <op_id>`（全部叶子） | M1（`shred_marks` 随 M2） |
| `mynote trash ls` | 列出所有设备删除、尚未碎纸的块：`{ id, buffer_id, buffer_name, is_locked, preview \| null, deleted_at_ms, deleted_by_device, actor, shred_not_before_ms \| null, shred_state }`，按 `shred_not_before_ms` 升序（`null` 排最后，再按 `deleted_at_ms` 降序） | 只读 | M1 |
| `mynote trash restore <id>` | **撤销删除**：（M2 起同时撤销碎纸标记）生成一个恢复 op 让块回到原 buffer。宽限期已过则返回 `KEY_SHREDDED`；支持 `--dry-run` | 天然幂等（对未在回收站的块返回 `NOT_FOUND`） | M1 |
| `mynote trash <empty\|expedite\|confirm>` | **仅 UI 操作的存根**：清空回收站、缩短宽限期、确认超阈值的碎纸。这三个子命令存在，只是为了给出明确的拒绝：**无论是否 TTY**，一律返回 `UI_CONFIRMATION_REQUIRED`（退出码 `2`），零副作用。由本地 Daemon / CLI 强制，这样 Agent（唯一入口是 CLI）就做不到加速删除。真正的操作在桌面 UI 中交互确认（§3.2 `trash/actions`），下限仍是服务端强制的 `T_grace_min` | — | M1（UI 侧 M2） |
| `mynote format [id]` | 传 `<id>` 原地格式化该块（需 `--expected-head`；多叶子块返回 `CONFLICT_PRESENT`）；不传 `<id>` 作为纯流过滤器格式化 `stdin -> stdout`（`--lang`、`--action unescape-json\|to-yaml\|...`）；M5-P2 起自动发现匹配语言的 `transform` WASM 插件（优先级低于内置 Layer 1、高于外部 `formatters.toml`） | 语法错误退出码 `7` 且零副作用 | M1（WASM 插件随 M5-P2） |
| `mynote vault <init\|lock\|unlock\|passwd>` | 全部要求 TTY。`init`：生成 VKEK 并追加进密钥环，**并入统一恢复包，不生成第二套恢复码**；KDF 参数与盐写入 Vault 头部（单套参数，按 iPhone 定）。`lock <id> [--hint "..."]`：**换钥**，即用新的 VKEK 包裹 DEK 重新加密当前版本，写一个带新 `key_id` 的 `LOCK` op，同批在 op 之后（或确认后）对旧 Tier 1 `key_id` 登记碎纸标记（`T_grace`；缩短到 `T_grace_min` 只能在 UI 中操作）。`unlock <id> [--shred-old-key]`：换回新的 Tier 1 BDEK，旧 Tier 2 密钥默认保留，带该参数则对其登记碎纸标记。`passwd`：用新口令重新包裹 VKEK | 客户端短进程内存执行；`lock` / `unlock` 支持 `--expected-head` | M2 |
| `mynote keyring <rotate\|unlock>` | 只允许 TTY。`rotate`（原 `sync rotate-smk`）：向密钥环追加新 SMK 代际，重新包裹全部 Tier 1 `MNR1` 并连同新 `RecoveryKeyringV1` 推送；旧 SMK 代际**永久保留**；轮换后**不需要重新抄写 24 词**，提示运行 `mynote recovery drill`（未演练前 `sync status` 报 `recovery_drill_due: true`）。`unlock`：在未丢失的存留桌面上输入一次 24 词恢复包，从已同步的 `RecoveryKeyringV1` 解封本机缺失的 SMK 代际写入 Keychain（异地单机兜底） | `rotate` 断网返回退出码 `6` | M1 |
| `mynote recovery <show\|drill>` | `show`：在 TTY 中经交互确认后显示统一恢复包（24 词，仅初次生成或本机仍在引导会话内可用）。`drill`：恢复演练，在 TTY 中输入恢复包，验证它能解封当前密钥环（含最新 SMK 代际与 VKEK），**不写入任何数据**；响应 `data`：`{ ok, keyring_generations, includes_vkek, drilled_at_ms }`。两者都只允许 TTY，恢复包内容永不写入 `--json` 输出 | 只读 | M1 |
| `mynote sync <status\|push\|pull>` | 显式触发同步对账。`status --json` 的 `data`：`{ sync_state, epoch, last_seq, pending_ops, blocked_ops, clock_skew_ms, key_self_check: { ok, last_run_ms, blocks_missing_key }, trash: { count, pending_confirm_count, next_shred_ms }, recovery_drill_due, last_recovery_drill_ms, last_local_backup_ms }`。时钟偏差过大**只提示、不拒收** | `push/pull` 断网返回退出码 `6` | M1 |
| `mynote device <bootstrap\|add\|refresh\|claim\|ls\|revoke>` | `bootstrap --url <server> [--revoke-existing]`：首台桌面引导（或全设备丢失后重连健在的 DO），从 TTY 读 `BOOTSTRAP_TOKEN` 注册本机生成的 `device_token`。`add --name <label> [--scope read\|read+clip\|clip-write\|read-write]`：桌面自行生成新 `device_token` 与一次性密钥 `K_pair`，把 `SHA-256(token)` 与 `K_pair` 加密的凭据暂存服务端（TTL 10 分钟，首次领取即删；`clip-write` 仅封装 `{ device_token, device_id, sync_url, clip_kid, clip_key }`，不含 `SMK`）。`refresh <device_id>`：SMK 轮换后为既有存活设备生成 10 分钟一次性密钥刷新码（免翻 24 词）。`claim`：在目标桌面读取配对码 / 刷新码完成接入或刷新。`bootstrap/add/refresh/claim` 只允许 TTY，配对码永不写入 `--json` 输出。`ls` 列出设备；`revoke <device_id>` 成功后 `hint` 建议执行 `mynote keyring rotate`（若吊销 `clip-write` 设备则建议 `mynote clip rotate-key`） | 联网管理鉴权，断网返回 `6` | M1（`read` 随 M2；`read+clip`/`clip-write` 随 M4） |
| `mynote clip <push\|pull\|history\|stats\|prune\|clear\|promote\|undo\|rotate-key>` | **（M4，D8 / D8′）**独立图文剪贴板命令（云端 `1,000 条 / 30 天 / 5 GiB` 硬护栏 + 桌面本地无限归档）：`push [--stdin \| --text <str> \| --file <image-path>] [--ephemeral] [--wait-sync]`（默认读取本机系统剪贴板文本或位图图片：macOS 经原生 `NSPasteboard` 优先读 `public.png`、Omarchy 经 `wl-paste`；位图白名单拒 `image/svg+xml`，上限 `10 MiB`；大对象超云端 `5 GiB` 返退出码 `6` `CLIP_QUOTA_EXCEEDED`；`--ephemeral` 限 `≤ 256 KiB` 零写库直推，无在线桌面返退出码 `6` `NO_ONLINE_DESKTOP`）；`pull [clip_id] [--apply \| --raw \| --out <path>]`（拉取最新或指定项，`--apply` 写入本机系统剪贴板并记录防回环哈希，`--out` 保存图片文件）；`history [--limit <N>] [--before-id <ulid>] [--kind text\|image] [--query <str>]`（游标分页与全文搜索）；`stats`（输出本地归档条数/磁盘占用与云端 5 GiB 配额）；`prune [--before-days <N>] [--keep-latest <N>] [--kind text\|image] [--scope local\|cloud\|all] [--dry-run]`（按规则预览或回收空间）；`clear [--scope local\|cloud\|all]`（按作用域清空；默认 `cloud` 保留桌面本地归档）；`promote [clip_id] [--buf <name>] [--lang <lang>]`（将文本项转存为标准笔记块；图片项提示改用 `--out`）；`undo`（恢复上次覆写前的桌面剪贴板）；`rotate-key [--wipe-local]`（TTY 确认，轮换 `ClipKey` 并清空云端 `clip_items` 与 `clip/blobs/*`；默认 `scope=cloud` 保留桌面本地归档，传 `--wipe-local` 则同步清空本地与对端桌面） | 显式联网命令断网返回 `6`；`push` / `pull` 按 `clip_id` 幂等 | M4 |
| `mynote import heynote <path>` | `--buf <name>`、`--dry-run` | 文件哈希防重复提示 | M1 |
| `mynote restore --from-archive <local-dir>` | **纯离线灾难恢复**（INV-RECOVERY）：从本地目录（从 R2 下载的 `archives/ops/` + `archives/keys/latest.mnks`）配合 TTY 输入的 24 词恢复包，重建全部已归档且**未删除**数据。`--to <empty-data-dir>`（**永不覆盖**非空数据目录）、`--key-snapshot <path\|latest>`、`--dry-run`。零网络请求，不为极端场景维护云端归档 API。响应 `data`：`{ restored_blocks, skipped_shredded, archive_segments, key_snapshot_at_ms, data_dir }` | 非 TTY 返回 `INTERACTION_REQUIRED` | M1 |
| `mynote open` | 打开本地 UI：macOS、Omarchy 与 Windows（M5-W2 起经 `ShellExecuteW`）统一经 `LocalIpc` 申请一次性 ticket（见 §3.1）并用系统默认浏览器 / Web App 打开 `http://localhost:<port>` | — | M1（Windows 随 M5-W2） |
| `mynote watch [--buf <name\|id>] [--clip] --jsonl` | **（M5-P1，D10）**经跨平台 `LocalIpc` 只读 `Subscribe` 帧持续输出 NDJSON 事件流（`block.saved` / `clip.received` / `clip.ephemeral`，每条事件携带 `actor` 以便外部脚本防回环）；仅覆盖 Tier 1 普通块与剪贴板，加锁块仅发元数据摘要不发正文 | 只读；Daemon 未运行时返回明确错误提示 | M5-P1 |
| `mynote ext <ls\|run <plugin_id>>` | **（M5-P2/P4，D10）**`ls` 列出已发现的 `plugin.toml`（含 `id`、`runtime`、`slots`、`tier2_capable` 与校验状态）；`run <plugin_id> [--block <id>] [--command <cmd_id>] [--arg <k=v>]` 显式调用插件（`wasmi` 或 `exec`），写结果经单写入方 `LocalIpc` 提交并强制标注 `actor = "plugin:<plugin_id>"`；`exec` 插件访问加锁块返回退出码 `5`（`BLOCK_LOCKED`） | 写块自动附带 `expected_heads` 与零字节熔断 | M5-P2（`exec` 随 M5-P4） |

### 2.4 帮助体系、Layer 2 `formatters.toml` 与 M5 `plugin.toml` 子进程加固契约

- **L0–L3 渐进帮助保留**：L0 `SKILL.md` → L1 `mynote --help` → L2 `mynote <cmd> --help` → L3 `mynote help <topic>`（体系说明见 [`architecture-proposal.md`](./architecture-proposal.md)）。帮助文案中的退出码与错误码必须与 §1 一致。
- **`--help-json` 推迟**：M1 由 CLI 黄金测试（§2.6）守护机读契约；只有当出现需要严格 Schema 的自动化消费方时，才按原结构 `{ command, about, args, stdin_mode, exit_codes, response_schema }` 引入。
- **跨平台外部子进程加固契约（`formatters.toml` 与 M5 `exec_host` 共用，D9 / D10）**：
  - `formatters.toml`（Unix `~/.config/mynote/formatters.toml`；Windows `%LOCALAPPDATA%\mynote\formatters.toml`）保持 100% 向下兼容，M5 内部统一编译为 `Slot: Transform`（`runtime = "exec"`, `mode = "oneshot"`）条目；
  - **环境变量隔离（修复 Windows `SYSTEMROOT` 崩溃）**：Unix 维持 `env_clear()` + `PATH` / `LC_ALL`；Windows 强制保留最小系统白名单（`SYSTEMROOT`、`WINDIR`、`COMSPEC`、`PATHEXT`、`TEMP`、`TMP`、`USERPROFILE`、`LOCALAPPDATA`、`APPDATA`、`SystemDrive`、`PATH`）并自动注入 `PYTHONUTF8=1`、`PYTHONIOENCODING=utf-8`、`POWERSHELL_TELEMETRY_OPTOUT=1`，仅额外放行 `plugin.toml` 显式声明的 `env_passthrough`；
  - **进程树回收与零黑框闪屏**：Unix 使用 `setsid` / PGID 击杀；Windows 使用 `CREATE_NO_WINDOW | CREATE_SUSPENDED` → 绑定 Windows Job Object（`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`）→ `ResumeThread`，超时或 Daemon 崩溃时由内核原子清理整棵子进程树；
  - **防命令注入（BatBadBut / CVE-2024-24576）**：严禁经 `cmd.exe` 启动或执行 `.bat`/`.cmd` 入口；跨平台脚本通过 `launcher = "python" | "node" | "pwsh" | "native"` 由宿主直调真实可执行文件，100% 业务载荷经 UTF-8 `stdin` JSON 传递并归一化 `\r\n`；
  - **熔断条件**：`exit_code != 0`、超时杀死、输出非合法 UTF-8，或对 `transform` 出现 **`input.len() > 0 && stdout.is_empty()`** 时一律返回 `FORMAT_SYNTAX_ERROR` / `PLUGIN_EXECUTION_FAILED` / `PLUGIN_RESOURCE_EXCEEDED`（退出码 `7`），绝不写回数据库。

### 2.5 分发、升级与 Schema 迁移

- **分发交给包管理器与 GitHub Releases（F-14，D9）**：Homebrew tap（macOS）、AUR（Omarchy）、GitHub Releases 预编译包（含 M5-W3 新增的 Windows `x86_64-pc-windows-msvc` ZIP 包，是否同步打 `aarch64-pc-windows-msvc` 待确认；附 `SHA256SUMS.txt`、`skill/SKILL.md` 与 `deploy/` 模板），开发期可用 `cargo install`。`mynote` **不内置自升级**，也**绝不在后台联网检查更新或上报遥测**。
- **安装位置与 F-07**：Linux 经 AUR 安装到用户不可写的 `/usr/bin`；Windows 推荐由管理员安装至 `Program Files` 或受控目录。Tier 2 对同 UID 攻击者的真实边界见 [`threat-model.md`](./threat-model.md)。
- **Schema 迁移前自动备份（保留）**：新版本首次打开数据库、需要升级 `PRAGMA user_version` 时，必须在独占写事务**之前**通过 `VACUUM INTO` 生成单文件快照（Unix `0600` / Windows 当前用户专属 NTFS DACL，路径 `<data_dir>/backups/mynote-pre-schema-v<old>.db`），再执行迁移。
- **降级**：旧二进制打开较新的库时返回 `INTEGRITY_ERROR`（`SCHEMA_TOO_NEW`，退出码 `8`），不做任何写入。回退步骤是用包管理器装回旧版本，再手动换回上面的迁移前备份（步骤写进 `mynote help upgrade`）。
- **升级后的 Daemon 重启**：交给系统托管方（macOS `launchd` / `brew services`，Omarchy `systemctl --user`，Windows `deploy/windows/` Task Scheduler / Startup 静默托管模板）。前端在 `/v1/local/ws` 断开后按指数退避重连。CLI 通过 `LocalIpc` `ping` 发现 Daemon 版本与自身不一致时，只在 `stderr` 告警。

### 2.6 CLI 黄金测试需稳定的输出契约

[`eval-framework.md`](./eval-framework.md) 中约 10 个 CLI 黄金测试断言的就是下列契约。修改其中任何一项都属于**破坏性变更**；新增字段不算。

1. **流纪律**：`--json` 时 `stdout` 恰好一个 JSON 对象（以单个 `\n` 结尾），告警与进度只走 `stderr`；`--raw` 时 `stdout` 是展示版本正文的精确字节，无尾随换行。
2. **信封**：顶层键 `ok`、`data`、`error`、`meta`。`ok == false` ⇔ `data == null` 且 `error != null`。`error` 含 `code`、`message`、`hint`、`retryable`。
3. **错误码集合与退出码映射**：§1 全表，包括 `code → exit`、`code → retryable`。黄金测试比较 `error.code`、退出码与 `details` 的键名，**不比较 `message` / `hint` 文案**。
4. **DTO 字段名与类型**：§2.1 写命令 `data`、§2.2 列表项与 `block get`（含 `versions` 的排序规则）、§2.3 `block delete` / `trash ls` / `sync status` / `restore` 的 `data`。ID 一律为 ULID 字符串，时间一律为毫秒整数（`*_ms`）。
5. **排序**：`ls` 按 `(buffer 顺序, position, id)`；`versions` 展示版本在前，其余按 `(hlc, op_id)` 降序；`trash ls` 按 `shred_not_before_ms` 升序（`null` 排最后）。
6. **离线语义**：普通写命令离线返回 `0`，并带 `meta.sync_state = "pending_offline"`；显式联网命令离线返回 `6`（`restore --from-archive <local-dir>` 为纯本地命令，离线返回 `0`）。
7. **拒绝行为零副作用**：`EMPTY_STDIN_REFUSED`、`HEAD_MISMATCH`、`CONFLICT_PRESENT`、`FORMAT_SYNTAX_ERROR`、`INTERACTION_REQUIRED`、`UI_CONFIRMATION_REQUIRED` 发生后，数据库状态（叶子集、回收站、密钥表、碎纸标记）保持不变。
8. **删除边界**：
   - `block delete` 之后，`ls` 不再返回该块，`trash ls` 返回它（M1 离线黄金测试中 `shred_state == "unscheduled"`、`shred_not_before_ms == null`；M2 联机契约测试中校验 `shred_state == "scheduled"` 时 `shred_not_before_ms ≥ deleted_at_ms + T_grace_min`，第 21 块起为 `"pending_confirm"` 且 `shred_not_before_ms == null`）。
   - `trash restore` 之后状态复原。
   - `trash empty` / `trash expedite` / `trash confirm` 无论是否 TTY 都返回 `UI_CONFIRMATION_REQUIRED`（退出码 `2`），对应黄金测试 G08。
9. **TTY 门槛**：`--force`、`vault *`、`device bootstrap/add/refresh/claim`、`keyring rotate/unlock`、`recovery *`、`restore --from-archive` 在非 TTY 下返回 `INTERACTION_REQUIRED`；`block get --decrypt` 在非 TTY 下返回 `BLOCK_LOCKED`。
10. **幂等**：同一 `--idempotency-key` 的 `add` 重放，返回相同的 `block_id` / `op_id`，且不新增 op。

黄金测试对非确定值（ID、时间戳、`duration_ms`、`hlc`）做归一化后再比较。

---

## 3. 本地桌面 Daemon 契约（HTTP + WebSocket + 跨平台 `LocalIpc`）

### 3.0 进程模型：Daemon 与 CLI

- **三桌面统一底座 + macOS 可选纯 Swift 薄壳（D5′ / D5″ / D9）**：macOS、Omarchy Linux 与 Windows（M5）均运行同一个 `mynote` 单体二进制（CLI + 内嵌 Web UI 的 Daemon），不引入 Tauri 壳或额外本地鉴权通道。Omarchy 由 `systemd --user` 托管 Daemon、通过 Hyprland 键绑定唤出 Chromium webapp 加载 `http://localhost:<port>`；macOS 由 `launchd` LaunchAgent（或 `brew services`）托管 Daemon，既可通过浏览器 / Web App 访问 `http://localhost:<port>`，也可安装可选的零依赖纯 Swift `WKWebView` 薄壳 [`apps/macos/MyNote.app`](../apps/macos/README.md)（复用既有 `LocalIpc` 的 `ping` 与 `open_ticket` 帧换取 `HttpOnly` Cookie，不直连 SQLite，不访问 Keychain，不新增 Daemon 路由）；Windows（M5）由 Task Scheduler / Startup 静默托管 Daemon，通过 `mynote open`（`ShellExecuteW`）经浏览器 / Web App 访问 `http://localhost:<port>`（交互式终端口令读取在 Unix 走 `/dev/tty` + `termios`，在 Windows 走 `CreateFileW("CONIN$")` + `SetConsoleMode(& ~ENABLE_ECHO_INPUT)`）。
- 核心运行契约：
  1. **CLI 在 UI 未打开时独立工作**：关闭浏览器窗口不影响 CLI 读写。CLI 离线写入成功返回 `0`（`pending_offline`），之后由 Daemon 补推。
  2. **SQLite 单写入方**：任一时刻最多一个 Daemon 实例（`<data_dir>/daemon.lock` 独占文件锁），第二个实例启动即退出并提示。CLI 与插件写入路径：**Daemon 运行时**，写命令经跨平台 `LocalIpc`（Unix `0600` UDS / Windows 用户 SID SDDL Named Pipe）的 `apply` 帧转交 Daemon 执行（载荷与 §3.2 的 REST DTO 相同，由 Daemon 生成 `op_id` 与 HLC；插件写入强制标注 `actor = "plugin:<plugin_id>"`）；**Daemon 未运行时**，CLI 以短事务直接写本地 SQLite，此时它就是唯一写入方（协议见 [`sync-protocol.md`](./sync-protocol.md) §7）。
  3. 读路径始终可以由 CLI 直接打开 SQLite（WAL 并发读）完成。

### 3.1 安全握手中介层契约（`localhost:<port>`）

1. **Host / Origin 白名单（请求头强拦截）**：
   - Daemon 只监听回环地址（`127.0.0.1` 与 `::1`，因为 `localhost` 可能先解析到 IPv6）。但 **`Host` 白名单只有一项：`localhost:<port>`**。其他任何 `Host`，包括 `127.0.0.1:<port>`、`[::1]:<port>` 以及 DNS 重绑定域名，**一律 `403`**，`hint` 指向 `http://localhost:<port>`。统一入口是为了让 Cookie 只有一个作用域，并为将来的 WebAuthn RP ID 留出可能（F-15）。
   - **`Origin` 白名单只有一项：`http://localhost:<port>`**（覆盖 macOS 与 Omarchy 的浏览器 / Web App）；其他任何 `Origin`（含 `http://127.0.0.1:<port>`、`null`）一律 `403`，无需开启跨站 CORS 或 Bearer 分支。
   - 除首次 `GET /v1/local/auth/exchange` 外，所有 `/v1/local/*` 请求与 WebSocket 握手必须携带 `Cookie: mynote_local_session=<64hex>`，且所有非 `GET` 请求及 `/v1/local/ws` 必须携带 `Origin: http://localhost:<port>`。
2. **一次性会话置换**：
   - `mynote open` 生成单次有效（有效期 10 秒）的随机 `ticket` 写入 Daemon 内存表，拉起浏览器访问 `http://localhost:<port>/v1/local/auth/exchange?ticket=<ticket>`；
   - Daemon 校验并立即销毁 `ticket`，返回 `303 See Other`、`Location: /` 与 `Set-Cookie: mynote_local_session=<session_token>; HttpOnly; SameSite=Strict; Path=/`。

### 3.2 本地 REST API 端点契约（Daemon 对 Tier 2 严格零明文！）

- **明文 / Tier 1 写入**：请求体**不传 `op_id`**（由 Daemon 内的 core 在加密前生成，§0）。
- **Tier 2 写入**：前端 `WasmVaultSession` 只持有 `VKEK`（不持有 `SMK`），在 WASM 内生成 `(op_id, key_id)` 并产出内层块正文密文 `mnb1_b64` 与（新建密钥或换钥时的）内层包裹密钥 `mnw1_b64`（字节布局与 AAD 见 [`data-structures.md`](./data-structures.md) §3.3 / §3.5）。请求体显式传入 `{ op_id, key_id, mnb1_b64, mnw1_b64? }`；Daemon 必须校验 `mnb1_b64` 45B 头部中的 `key_id` 与请求一致、既有密钥的 `key_id` 已在本地 `block_keys`（或随本次请求提供了头部 `key_id` 一致的 `mnw1_b64`），随后**原样复用该 `op_id`**，用 `SMK` 封装外层 `MNR1`（`block_id + tier=Tier2Vault + mnw1`）与 `MNS1`（`InnerOpV1`），否则返回 `INTEGRITY_ERROR`。

| 方法与路径 | 请求体 / 参数 | 响应体与关键安全不变量 |
| --- | --- | --- |
| `GET /v1/local/bootstrap` | 无 | `{ buffers, initial_buffer_id, blocks, sync_status, vault_header, trash_count, device_id, last_hlc }`（一步完成首屏渲染；`device_id` / `last_hlc` 供 WASM core 构造 op） |
| `POST / PATCH / DELETE /v1/local/buffers[/:id]` | `{ name?, after_id?, before_id? }` | 返回更新后的 `BufferDto` |
| `GET /v1/local/blocks?buffer_id=<id>` | 查询参数 | 返回按 `(position, id)` 排好序的 `BlockDto[]`：`{ id, buffer_id, position, lang, is_locked, has_unlocked_concurrent_version, public_hint, head_op_ids, display_op_id, versions: [{ op_id, hlc, device_id, actor, is_display, is_locked, key_id, content \| null, mnb1_b64 \| null, mnw1_b64 \| null }] }`。加锁版本 `content: null`，由 Daemon 用 `SMK` 解开外层 `MNR1` 后下发 `mnb1_b64` 与 `mnw1_b64` 供前端 `WasmVaultSession` 解密（Daemon 无 `VKEK`，解不开内层密文）。不含回收站中的块 |
| `POST /v1/local/blocks` | 明文块：`{ buffer_id, lang, content, after_id? }`（Daemon core 生成 `block_id`、`op_id`，新建由 SMK 包裹的 BDEK 与 `MNR1` 密钥记录）<br>直接新建加密块：`{ block_id, op_id, key_id, buffer_id, lang, after_id?, public_hint?, mnb1_b64, mnw1_b64 }` | 原子写库（op + 密钥记录同一事务）并异步触发同步，返回 `BlockDto` 与 `op_id` |
| `PATCH /v1/local/blocks/:id` | `{ expected_heads?, content?, lang?, after_id?, before_id?, buffer_id?, op_id?, key_id?, mnb1_b64?, mnw1_b64? }` | 写正文（`content` 或 `mnb1_b64`）时 `expected_heads` 必填，且必须**等于**当前全部叶子，否则返回 `409 HEAD_MISMATCH`（`details.actual_heads`）；叶子数 > 1 时即为合并。只改 `lang` / 位置 / `buffer_id` 走字段 LWW，不需要 `expected_heads`。**Daemon 从不接收加密块的明文或 `VKEK`** |
| `POST /v1/local/blocks/:id/resolve` | `{ expected_heads, content? \| keep_op_id? \| (op_id + key_id + mnb1_b64 + mnw1_b64?) }` | `PATCH` 的别名（`RESOLVE` 不是独立 op 类型）。`keep_op_id` 仅对未加锁版本有效：由 Daemon core 用该版本正文生成新的全量 op；加锁版本须由前端解锁后提交 `{ op_id, key_id, mnb1_b64, mnw1_b64? }` |
| `POST /v1/local/blocks/:id/lock` | `{ expected_heads, op_id, key_id, lang?, public_hint?, mnb1_b64, mnw1_b64, grace?: "default" \| "min", confirm_nonce? }` | **换钥加锁（M2）**：同一事务写入 `LOCK` op（新 `key_id`，`mnw1` 经 `SMK` 封装为 `MNR1`）与新密钥记录，立即从物化表与 FTS5 中移除该块明文。待服务端确认新 op 与新密钥记录后，再对该块旧的全部未碎纸 `key_id` 登记碎纸标记：默认 `grace_ms = T_grace`；`grace: "min"`（`grace_ms = T_grace_min`）需要有效的 `confirm_nonce`。到期后的本地清理（`secure_delete` + WAL checkpoint）见 [`sync-protocol.md`](./sync-protocol.md) |
| `POST /v1/local/blocks/:id/unlock` | `{ expected_heads, plaintext_content, lang, shred_old_key: boolean }` | 用户在前端 WASM 解密后显式解除锁定时调用。换钥到新的 Tier 1 BDEK（Daemon core 生成新 op 与 `op_id`）；`shred_old_key` 为真时，待新 op 确认后对旧 Tier 2 `key_id` 登记碎纸标记（`grace_ms = T_grace`） |
| `DELETE /v1/local/blocks/:id` | `{ expected_heads }` | 移入回收站：写 `DELETE` 墓碑 op。M1 仅做软删除，返回 `{ in_trash: true, shred_not_before_ms: null, shred_state: "unscheduled" }`；M2 起同时对该块全部未碎纸 `key_id` 登记碎纸标记（`grace_ms = T_grace`），返回 `{ in_trash: true, shred_not_before_ms, shred_state }`，取值同 CLI |
| `GET /v1/local/blocks/:id/history` | `?limit=50` | 返回历史版本元数据（每个 op 都是全量载荷，任一版本可直接读取）；`key_id` 已碎纸的版本标 `content_available: false` |
| `GET /v1/local/trash` | 无 | 回收站列表，字段同 `mynote trash ls`（包含其他设备发起的删除） |
| `POST /v1/local/trash/:id/restore` | 无 | M1 写复活 `UPDATE` op；M2 先撤销该块未执行碎纸标记并恢复块，宽限期已过返回 `410 KEY_SHREDDED` |
| `POST /v1/local/trash/actions/prepare` | `{ action: "expedite" \| "confirm_pending" \| "purge_history", block_ids: string[] \| "all" }` | **仅限 UI（M2）**：返回 `{ confirm_nonce, expires_at_ms, summary }`（单次有效、60 秒过期）。UI 必须把 `summary`（块数、最早不可恢复时间）放进模态确认框展示给用户 |
| `POST /v1/local/trash/actions/commit` | `{ confirm_nonce }` | **执行已确认动作（M2）**。`expedite` = 清空回收站或缩短宽限期，向云端 `/v1/keys/shred` 提交 `{ grace_ms: T_grace_min, expedite: true }` 把到期日收敛到 `now + T_grace_min`（服务端另行强制下限）；`confirm_pending` = 确认 `pending_confirm` 的碎纸，向 `/v1/keys/confirm` 提交 `{ key_ids, grace_ms }` 从确认时刻开始计时；`purge_history` = 「清除历史」，即换钥当前版本并对旧 `key_id` 登记碎纸标记。nonce 缺失或失效返回 `428 UI_CONFIRMATION_REQUIRED` |
| `POST /v1/local/format` | `{ content, lang, action? }` | 调用内置 Layer 1 或外部 Layer 2 管线，返回 `{ formatted }`（**严禁把处于解锁态的加密块发给外部 CLI 子进程！加密块格式化仅允许在前端 `mynote-wasm` Layer 1 内纯内存完成**） |
| `GET /v1/local/keys?block_id=<id>` / `POST /v1/local/keys` | `GET` 读取密钥表记录与碎纸标记；`POST` 追加新的密钥记录（只创建、不修改） | 仅传递包裹后的密文字节（对 Tier 2 记录可由 Daemon 用 `SMK` 剥离外层 `MNR1` 后返回内层 `mnw1_b64`）；表结构见 [`data-structures.md`](./data-structures.md) |
| `GET / PUT /v1/local/vault/header` | Vault 头部：`gen` + `VaultHeaderV1`（KDF 参数、盐、口令包裹槽与恢复公钥封装槽） | `PUT` 仅用于 `vault init` / `passwd`（递增 `gen` 并同步至云端 `key_material`）；仅传递密文 |
| `GET / POST / DELETE /v1/local/clip[/:clip_id]` | **（M4，D8 / D8′）**`GET` 支持游标分页与搜索（`?limit=<1..1000>&before_id=<ulid>&kind=text\|image&q=<str>`），返回 `{ items, has_more, next_before_id, total_count, stats, cloud_quota }`；`POST` 从桌面 UI 发送文本或位图图片（`multipart/form-data` 或 JSON，`≤ 10 MiB`；云端触达 `5 GiB` 时透传 `507 CLIP_QUOTA_EXCEEDED`）；`DELETE /v1/local/clip/:clip_id` 全端删单条；`DELETE /v1/local/clip?scope=local\|cloud\|all` 按作用域清空 | 校验位图 MIME 白名单（拒 `image/svg+xml`），同步推送云端 `/v1/clip` 或 `/v1/clip/blob`；桌面本地无限归档，Daemon 单并发后台 Eager Prefetch 远端大对象 |
| `POST /v1/local/clip/prune` | **（M4，D8′）**`{ scope?: "local" \| "cloud" \| "all", before_ms?, keep_latest?, kind?, dry_run? }` | 按与云端一致的过滤规则预览（`dry_run: true`）或回收本地 / 云端 / 全端剪贴板历史与大对象磁盘空间，返回 `{ local_deleted, local_freed_bytes, cloud_deleted, cloud_freed_bytes, cloud_quota }` |
| `GET /v1/local/clip/:clip_id/blob` | **（M4，D8 / D8′）**查询单条图片/大文本明文二进制流 | 优先命中本地无限归档目录 `clip_cache/`，未命中时向云端流式下载并解密校验 `sha256_hex` 后持久落盘并返回（附 `Content-Type` 仅限安全位图或 `text/plain`） |
| `POST /v1/local/clip/:clip_id/apply` / `promote` / `POST /v1/local/clip/undo` / `PATCH /v1/local/clip/watch` | **（M4，D8）**`apply` 将指定项写入本机系统剪贴板（附防回环标记）；`promote` 将文本项转为正式笔记块；`undo` 恢复被覆写前的桌面剪贴板；`watch` 临时暂停/恢复 M4b 后台自动监听 | 均校验 `Host` + `Origin` + `HttpOnly` Cookie |
| `GET /v1/local/plugins` | **（M5-P2/P3，D10）**无 | 返回惰性扫描到的合法插件清单摘要（`id`、`name`、`version`、`runtime`、`tier2_capable`、`slots`、`contributes`、`options` 表单定义，不含 `secret` 值）与加载错误诊断 |
| `POST /v1/local/plugins/:id/invoke` | **（M5-P2/P4，D10）**`{ slot, action_or_command_id, block_id?, expected_heads?, args? }` | 仅用于 **Tier 1 普通块或非块动作**：Daemon 侧按 `runtime` 路由至 `WasmHost`（`wasmi`）或 `ExecHost`（`oneshot`/`worker`）；遇 `is_locked == true` 的块一律返回 `423 BLOCK_LOCKED`（零外发）；若 `PluginResult` 为 `replace_content` / `insert_block`，经单写入方提交并强制写入 `actor = "plugin:<id>"`；若为 `view` / `gutter` / `toast`，原样返回纯 JSON 供主前端声明式安全渲染 |
| `GET /v1/local/plugins/:id/module.wasm` | **（M5-P3，D10）**无 | 仅对声明 `runtime = "wasm"` 且 `tier2_capable = true`、通过 `module.imports().is_empty()` 校验的插件返回原始 `.wasm` 字节流（`Content-Type: application/wasm`），供桌面前端独立 `'self'` Web Worker 在解锁态 Tier 2 块上纯内存执行；Daemon 永不接收 Tier 2 明文 |

> [!NOTE]
> `trash/actions` 的 `confirm_nonce` 防的是 **Agent 经 CLI 误用或被注入**：CLI 没有对应命令，也拿不到 UI 的 `HttpOnly` 会话。它**不防**能篡改执行环境的恶意同 UID 进程（见 [`threat-model.md`](./threat-model.md) T5）。「无法立即删除」的硬保证来自服务端强制的 `T_grace_min` 与批量阈值。

### 3.3 本地 WebSocket（`/v1/local/ws`）与跨平台 `LocalIpc` 协议

- **`/v1/local/ws` 服务端推送帧（JSON）**：
  - `{ "type": "blocks_changed", "upserted": BlockDto[], "deleted_ids": string[] }`
  - `{ "type": "buffers_changed", "upserted": BufferDto[], "deleted_ids": string[] }`
  - `{ "type": "trash_changed", "count": number, "pending_confirm_count": number, "next_shred_ms": number | null }`
  - `{ "type": "sync_status", "state": "synced" | "syncing" | "pending_offline" | "conflict_present", "last_seq": number }`
  - `{ "type": "clip_changed", "upserted": ClipItemDto[], "deleted_ids": string[], "cleared": boolean, "watch_paused": boolean, "cloud_quota"?: CloudClipQuota }`（M4，D8 / D8′：桌面 UI 剪贴板抽屉与配额条实时刷新）
  - `{ "type": "alert", "code": "KEY_MISSING" | "SHRED_PENDING_CONFIRM" | "NEEDS_VAULT_REKEY" | "CLOCK_SKEW" | "RECOVERY_DRILL_DUE" | "CLIP_SECRET_BLOCKED", "details": object }`（UI 常驻提示；`NEEDS_VAULT_REKEY` 表示离线缓存的 Tier 2 op 遇到旧钥待碎纸/已碎纸而挂起，需解锁 Vault 完成换钥重签，不阻塞其他普通 op 同步；`CLOCK_SKEW` 只提示、不影响接收；`CLIP_SECRET_BLOCKED` 表示 M4b 后台监听命中高危凭据特征已拦截上传）
- **跨平台 `LocalIpc`（Unix `0600` UDS / Windows 用户 SID SDDL Named Pipe，NDJSON 单行帧）**：
  - **传输层与权限约束**：
    - macOS / Linux：权限 `0600` 的 Unix Domain Socket（`<runtime_dir>/daemon.sock`）；
    - Windows（M5-W1，D9）：`tokio::net::windows::named_pipe`，管道名 `\\.\pipe\mynote-<blake3_16(canonical_data_dir)>`；首个实例强制 `first_pipe_instance(true)` 防管道抢注，显式传入 `SECURITY_ATTRIBUTES` + SDDL `D:P(A;;GA;;;OW)`（仅当前用户 SID，彻底关闭默认 `Everyone`），强制 `reject_remote_clients(true)` 阻断 SMB 远程连接；
  - CLI 写命令转交（Daemon 运行时）：`{"cmd":"apply","meta":{"actor":"...","idempotency_key":"...","allow_empty":false,"force":false},"request":<§3.2 REST DTO>}\n` → `{"ok":true,"data":...}\n` 或 `{"ok":false,"error":{...}}\n`（错误码同 §1）；
  - Daemon 未运行时 CLI 直写 SQLite 后，Daemon 启动扫描补推，无需通知；`poke`（`{"cmd":"poke","fast_flush":false}\n` → `{"ok":true}\n`）仅用于 `sync` 以外的唤醒场景；
  - CLI 显式等待同步（`sync push`）：`{"cmd":"sync_now","wait":true}\n` → Daemon 完成本轮 HTTP `push/pull` 后返回 `{"ok":true,"head_seq":120}\n` 或 `{"ok":false,"code":"SYNC_OFFLINE"}\n`；
  - CLI 健康探针：`{"cmd":"ping"}\n` → `{"ok":true,"version":"0.2.0","pid":4821}\n`（版本与 CLI 不一致时 CLI 在 `stderr` 告警）；
  - 壳 / `mynote open` 申请会话票据：`{"cmd":"open_ticket"}\n` → `{"ok":true,"url":"http://localhost:<port>/v1/local/auth/exchange?ticket=..."}\n`；
  - **只读事件订阅（M5-P1，D10，供 `mynote watch` 与 `reactor`）**：`{"cmd":"subscribe","filters":{"buffer_id":null,"include_clip":true}}\n` → 持续推送单行 NDJSON 事件帧 `{"event":"block.saved"|"clip.received"|"clip.ephemeral","actor":"...","payload":{...}}\n`（严禁携带任何 Tier 2 加密块正文）。

---

## 4. Cloudflare 云端盲同步中继契约（HTTP + R2 + WebSocket Hibernation）

> 本节只定义 HTTP / WS 的**请求与响应形状**。服务端职责保持极薄（幂等追加、分配 seq、按 seq 分页、epoch、令牌范围、WS 唤醒、密钥表 / `key_material` / 碎纸标记存储及校验、alarm 置空、每日归档）。合并语义、宽限期与批量阈值规则见 [`sync-protocol.md`](./sync-protocol.md)，DO / R2 / alarm 实现见 [`cloudflare-cloud-architecture.md`](./cloudflare-cloud-architecture.md)。
>
> **单一事实来源划分**：云端 HTTP / WS 的**请求与响应形状**以本节为准；端点的实现（DO 表、事务、alarm、R2 布局）以 [`cloudflare-cloud-architecture.md`](./cloudflare-cloud-architecture.md) 为准；字段的线格式与 AAD 以 [`data-structures.md`](./data-structures.md) 为准。

### 4.1 公共请求约定
- **鉴权头**：`Authorization: Bearer <device_token>`（除静态资源 `/, /assets/*`、配对认领 `/v1/devices/pair-claim` 以及凭部署期 Secret `BOOTSTRAP_TOKEN` 鉴权的首台/零设备引导 `/v1/devices/bootstrap` 外全部强制校验）。令牌带四态范围 `scope`（D1′、D8）：`read`（纯只读手机）、`read+clip`（手机 PWA 读笔记 + 读写 `/v1/clip*`）、`clip-write`（快捷指令仅单向写 `/v1/clip` 与 `/v1/clip/blob`，连 `GET /v1/clip*` 与一切笔记接口均返回 `403`）、`read-write`（桌面）。所有非 `read-write` 令牌调用笔记写端点（push、密钥记录与 `key_material`、碎纸标记、状态快照上传、设备管理）一律返回 `403 TOKEN_SCOPE_FORBIDDEN`；
- **协议版本头**：`X-Mynote-Protocol: 1`；
- **客户端强制防丢规则**：`fetch` 必须设置 `redirect: "manual"`，校验 `status === 200`、`Content-Type` 为 `application/json` 且 `body.ok === true` 后方可推进游标。

### 4.2 核心同步与密钥端点精确 Schema

端点分组：`/v1/sync/*`（op 日志与唤醒）、`/v1/keys*`（密钥表、`key_material` 与碎纸标记）、`/v1/snapshots/state`（手机状态快照）、`/v1/devices*`（设备引导、配对与刷新）、`/v1/clip*`（M4 独立图文剪贴板通道，D8 / D8′）。**不存在任何删除 op 的接口，也不暴露任何 `/v1/archive/*` 云端归档读取/枚举接口**（极端双重灾难恢复直接从 R2 下载 `archives/` 目录到本地执行离线 `mynote restore --from-archive <local-dir>`）。

#### (1) `POST /v1/sync/push` — 幂等追加盲操作日志（`read-write`）

```json
// Request (单次上限: ops <= 500 条, 总请求体 <= 4 MiB)
{
  "expected_epoch": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "seen_seq": 104,                                  // 本机已拉取到的最大 seq（M2 碎纸标记竞态校验用）
  "key_records": [ { "key_id": "...", "wrap_gen": 1, "key_record_b64": "..." } ],  // 可选
  "cancel_key_ids": [ "..." ],                      // 可选（M2）：撤销碎纸标记（Update-Wins 复活）
  "ops": [
    { "op_id": "01JDF910...", "key_id": "...", "envelope_b64": "..." }, // BlockContent / BufferMeta 携带明文 key_id
    { "op_id": "01JDF911...", "key_id": null,  "envelope_b64": "..." }  // 无 BDEK 的 op（SetBlockMeta / Delete / DeleteBuffer）传 null（16 零字节仅用于 MNS1 内部 AAD）
  ],
  "shred_marks": [ { "mark_id": "...", "key_id": "...", "grace_ms": 604800000, "requested_by": "dev_..." } ] // 可选（M2；not_before_ms 由服务端按服务端时钟计算）
}

// Response 200 OK (当 expected_epoch 匹配时)
{
  "ok": true,
  "epoch": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "acked": [ { "op_id": "01JDF910...", "seq": 105 }, { "op_id": "01JDF911...", "seq": 106 } ],
  "shred_results": [ { "key_id": "...", "state": "scheduled", "not_before_ms": 1796126400123 } ], // 仅当请求含 shred_marks 时返回
  "head_seq": 106
}

// Response 409 Conflict (当 expected_epoch 不匹配，例如刚执行过 PITR 回滚时)
{
  "ok": false,
  "error": {
    "code": "CAS_MISMATCH",
    "message": "Journal epoch changed; run Set-Union reconciliation before pushing",
    "details": { "remote_epoch": "9c8b7a65-...", "head_seq": 88 }
  }
}
```

- `op_id` 字段与 `MNS1` AAD 绑定的 `op_id` 必须一致（由 core 生成，§0）。重复 `op_id` 幂等返回原 `seq`。
- **同批原子提交，顺序固定为「`key_records` → `cancel_key_ids` → `ops` → `shred_marks`」**：服务端在一个 DO 事务内按此顺序校验并写入，任一项失败则整批回滚、不分配 `seq`。将 `ops` 置于 `shred_marks` 之前，使离线「新建块随后立即换钥加锁 / 删入回收站」可在同一批内先落盘旧 `CREATE` op 再登记旧钥碎纸标记而不自锁，同时对本批事务前已存在的 `seq > seen_seq` 远端并发更新照常拦截 `SHRED_STALE`。
- **服务端竞态校验**（M1 仅校验 `KEY_UNKNOWN`；M2 启用全套碎纸竞态校验，规则见 [`sync-protocol.md`](./sync-protocol.md) §5.6）。失败时整批回滚，`error.details` 带出问题 `key_id`：
  - `KEY_UNKNOWN`（`409`）：op 引用服务端不认识且同批未携带的 `key_id`；
  - `KEY_SHREDDED`（`410`）：op 引用已执行碎纸（`executed`）的 `key_id`，或 `cancel_key_ids` 试图撤销已执行碎纸的标记；
  - `KEY_PENDING_SHRED`（`409`）：op 引用的 `key_id` 有 `pending_confirm` / `scheduled` 标记，且同批未在 `cancel_key_ids` 中先撤销；
  - `SHRED_STALE`（`409`）：新标记的 `key_id` 在本批事务之前已存在 `seq > seen_seq` 的远端 op，客户端须先 pull、重新评估；
  - `GRACE_TOO_SHORT`（`422`）：任一 `grace_ms < T_grace_min`。
- 单独的 `/v1/keys*` 端点（(3)）用于不伴随 op 的密钥、`key_material` 与标记操作，校验规则相同。

#### (2) `GET /v1/sync/pull?since=<seq>&limit=<1..500>` — 增量拉取与水位推进
```json
// 200 OK
{
  "ok": true,
  "epoch": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "ops": [
    {
      "seq": 105,
      "op_id": "01JDF910...",
      "key_id": "...",
      "device_id": "dev_01jdf8...",
      "created_at": 1795521600123,
      "envelope_b64": "..."
    }
  ],
  "keys_digest": "blake3:...",
  "head_seq": 105,
  "has_more": false
}
```
- 无 GC，任意 `since` 都可从头分页拉取，`envelope_b64` 永不为 `null`（op 密文永不删除）；
- `keys_digest` 同时覆盖 `block_keys`、`key_material`（`keyring` + `vault_header`）与 `shred_marks`；与本地摘要不同时，客户端调用 `GET /v1/keys` 全量比对。

#### (3) `/v1/keys*` — 密钥表、`key_material` 与碎纸标记
| 方法与路径 | 范围 | 请求 → 响应 |
| --- | --- | --- |
| `GET /v1/keys` | `read` / `read+clip` | → `{ ok, key_material: { keyring: { gen, blob_b64 } \| null, vault_header: { gen, blob_b64 } \| null, clip_key: { gen, blob_b64 } \| null }, key_records: [{ key_id, wrap_gen, key_record_b64 \| null, created_at_ms }], shred_marks: [{ mark_id, key_id, grace_ms, not_before_ms \| null, requested_by, state, confirmed_at_ms \| null }], digest }`（体量 ≈ 块数 × 250 B + `< 2 KB` `key_material` [估算]）。`block_id` 与 `tier` 只在 `MNR1` 密文（`key_record_b64`）内，**服务端不可见**。已执行碎纸的记录 `key_record_b64 = null`，客户端据此且仅据此触发本地 `ExecuteShred`。合并规则（2P-Set + `min` 到期日收敛）见 [`sync-protocol.md`](./sync-protocol.md) |
| `POST /v1/keys` | `read-write` | `{ key_records?: [...], key_material?: { keyring?: { gen, blob_b64 }, vault_header?: { gen, blob_b64 }, clip_key?: { gen, blob_b64 } }, clear_clips?: boolean, clear_clips_scope?: "cloud" \| "all" }` → `{ ok, acked_key_ids, key_material_gens }`。`key_records` 只创建或以更大 `wrap_gen` 重包（同 `key_id` 同 `wrap_gen` 内容不同返回 `INTEGRITY_ERROR`，相同则幂等）；`key_material` 按各自 `gen` 严格单调递增接受（小于当前 `gen` 返回 `409 CAS_MISMATCH`，相等且字节相同幂等；更新 `clip_key` 且 `clear_clips: true` 时同步清空云端 `clip_items` 与 `clip/blobs/*` 并按 `clear_clips_scope`（默认 `"cloud"` 保留桌面本地归档，`"all"` 通知全端清空）广播 `clip_cleared` + `key_rotated: true`） |
| `POST /v1/keys/shred` | `read-write` | **（M2）** `{ seen_seq, expedite?: boolean, marks: [{ mark_id, key_id, grace_ms, requested_by }] }` → `{ ok, results: [{ key_id, state: "scheduled" \| "pending_confirm", not_before_ms \| null }] }`。任一 `grace_ms < T_grace_min` → 整个请求 `422 GRACE_TOO_SHORT`（不落库）。服务端以自身时钟算 `candidate_ms = now_ms + grace_ms`：新建时超出滚动 24 小时批量阈值（20 块）的部分置 `state = "pending_confirm", not_before_ms = null`（不计时）；对已有 `scheduled` 标记且 `expedite = true` 时更新为 `min(existing.not_before_ms, candidate_ms)`（不重复计入配额）。视图过期 → `409 SHRED_STALE` |
| `POST /v1/keys/cancel` | `read-write` | **（M2）** `{ key_ids }` → `{ ok, cancelled }`。用于 `trash restore` 和 Update-Wins 复活；已到期置空的 `key_id` → `410 KEY_SHREDDED` |
| `POST /v1/keys/confirm` | `read-write` | **（M2）** `{ key_ids, grace_ms }` → `{ ok, results: [{ key_id, state: "scheduled", not_before_ms }] }`。把 `pending_confirm` 转为 `scheduled`，服务端记录 `confirmed_at_ms = now_ms` 并计算 `not_before_ms = confirmed_at_ms + max(grace_ms, T_grace_min)`。只由桌面 UI 的 `trash/actions/commit` 发起，见 §3.2 |

#### (4) `/v1/snapshots/state` — 手机状态快照（M2）
- **`PUT /v1/snapshots/state`**（`read-write`，由任一桌面发布）：
  - 请求头：`Content-Type: application/octet-stream`、`X-Journal-Epoch`、`X-Covers-Seq`；请求体为加密的状态快照 `MNSS`（含 `Active` 与 `Trashed` 块，不含 `Shredded`，格式见 [`data-structures.md`](./data-structures.md) §3.7）；
  - 服务端在同一 `X-Journal-Epoch` 内只接受 `covers_seq` 大于当前最新快照的上传（`epoch` 与当前 DO 不符或同 `epoch` 下 `covers_seq` 未递增均返回 `409 CAS_MISMATCH`，客户端丢弃即可；DO `epoch` 切换后的首份新快照允许从较小 `covers_seq` 起步），R2 只保留最近 2 份。无 `prev_snapshot_id` CAS。
- **`GET /v1/snapshots/state`**（`read`）：返回最新快照字节，元数据在响应头 `X-Journal-Epoch` 与 `X-Covers-Seq`；手机校验 `X-Journal-Epoch` 与后续 (2) 返回的 `epoch` 一致后，从 `covers_seq` 起拉取尾部 op。

#### (5) `/v1/devices*` — 首台引导、设备管理与一次性领取配对 / 刷新
- **`POST /v1/devices/bootstrap`**（凭 `Authorization: Bearer <BOOTSTRAP_TOKEN>` 鉴权，常量时间比对）：`{ "device_name": "MacBook", "token_sha256_hex": "...", "revoke_existing"?: false }` → `{ ok, device_id, scope: "read-write" }`。
  - 用于 Day-1 注册第一台桌面，或所有客户端设备同时丢失但云端 DO 仍健在时重新接入一台新桌面（客户端自行生成随机 256-bit `device_token`，只把 `SHA-256` 传给服务端）。
- **`POST /v1/devices`**（`read-write`）：`{ "device_name": "iPhone", "scope": "read", "token_sha256_hex": "...", "ciphertext_b64": "..." }` → `{ ok, device_id, pair_id, expires_at_ms }`。
  - 发起配对的桌面在本地生成新设备的随机 `device_token` 与一次性包裹密钥 `K_pair`；服务端仅写入未激活设备行（`token_sha256_hex`、`claimed_at_ms = NULL`）并暂存 `ciphertext_b64`（内含全部历史+当前 `SMK` 代际与明文 `device_token`，用 `K_pair` 加密，格式见 [`data-structures.md`](./data-structures.md) §3.5），**TTL 10 分钟** [保证：到期删除]。**服务端全程不接触明文 `device_token` 或 `K_pair`**。
- **`POST /v1/devices/:id/refresh`**（`read-write`）：`{ "ciphertext_b64": "..." }` → `{ ok, device_id, pair_id, expires_at_ms }`。
  - 在 `mynote keyring rotate` 后为既有存活设备（尤其是只读手机）安全下发新 `SMK` 代际：不新建设备、不更换 `device_id` 与既有 `device_token`，仅生成一张 `kind = "refresh"` 的 10 分钟一次性领取票据。
- **配对码**（由 `mynote device add` / `mynote device refresh` 在终端输出，粘贴或扫码）只包含 `mynote-pair:v1:<base64url(server_url || pair_id || K_pair)>`（格式见 [`threat-model.md`](./threat-model.md) §2.4）。
- **`POST /v1/devices/pair-claim`**（无需鉴权，凭 128 位随机 `pair_id`）：`{ "pair_id": "..." }` → `{ ok, kind: "add" | "refresh", device_id, scope, ciphertext_b64 }`。**首次领取即原子删除票据**（若 `kind = "add"` 同时置 `devices.claimed_at_ms = now` 激活令牌），再次领取或过期返回 `404 NOT_FOUND`。新设备或被刷新设备在本地用 `K_pair` 解开密文获得密钥环（及首次配对时的 `device_token`）。
- **`GET /v1/devices`** / **`DELETE /v1/devices/:id`**（`read-write`）：列出 / 吊销设备。`read` 令牌不能发起配对或刷新（`403 TOKEN_SCOPE_FORBIDDEN`）。
- **领取失败的处理**：合法设备领取时若得到 `404`（可能已被他人抢先领取），提示用户在桌面执行 `mynote device ls` 核对并 `mynote device revoke` 可疑设备，然后重新配对（残余风险见 [`threat-model.md`](./threat-model.md)）。

#### (6) `GET /v1/sync/ws`（WebSocket Hibernation 帧）
- 客户端应用层心跳文本帧：`"ping"` → Cloudflare 边缘自动零唤醒回复 `"pong"`；
- 服务端只发唤醒通知，**不携带 op**：`{ "type": "wake", "epoch": "...", "head_seq": 110 }`，客户端发现 `head_seq > local_seq` 即调用 (2)；密钥表或 `key_material` 变化由 pull 响应中的 `keys_digest` 发现；
- 设备被吊销通知：`{ "type": "device_revoked" }`（随即服务端以 Close Code `4401` 断开连接）；
- **剪贴板唤醒与瞬态帧（M4，D8 / D8′）**：
  - `{ "type": "clip_wake", "clip_id": "01J...", "kind": "text" | "image", "created_at_ms": 1795600000000 }`（常规云端滚动队列通知，不含大对象正文）；
  - `{ "type": "clip_ephemeral", "clip_id": "01J...", "clip_kid": "01J...", "device_id": "dev_...", "envelope_b64": "..." }`（仅发往在线 `read-write` 桌面，零写库零 R2）；
  - `{ "type": "clip_cleared", "clip_id": "01J..." | null, "scope": "cloud" | "all", "key_rotated"?: boolean }`（单条删除固定 `scope: "all"`；云端批量清理/清空与默认 `rotate-key` 为 `scope: "cloud"`，桌面保留本地归档）。

#### (7) `/v1/clip*` — 独立图文剪贴板云端滚动中继通道（M4，D8 / D8′：`1,000 条 / 30 天 / 5 GiB`）

| 方法与路径 | 允许 `scope` | 请求 → 响应与硬约束 |
| --- | :---: | --- |
| `POST /v1/clip` | `read-write`, `read+clip`, `clip-write` | `{ clip_id, clip_kid, kind: "text", ephemeral?: boolean, meta_envelope_b64 }` → 常规模式返回 `{ ok: true, clip_id, created_at_ms, expires_at_ms, quota }`；`ephemeral: true`（上限 `≤ 256 KiB`，零 SQLite / R2 写入）返回 `{ ok: true, clip_id, delivered_to }`，若 `delivered_to === 0` 返回 `409 NO_ONLINE_DESKTOP`。常规模式幂等写入 DO `clip_items`（`meta_envelope_b64` 上限 `≤ 96 KiB`，**不受 R2 5 GiB 大对象配额阻塞**），裁剪超出最近 **1,000 条**的旧行并分批 `R2.delete(keys[])` 清理旧大对象，默认 `expires_at_ms = now + 30 天`，广播 `clip_wake` |
| `PUT /v1/clip/blob` | `read-write`, `read+clip`, `clip-write` | **流式上传图片或 `> 64 KiB` 长文本密文**：请求体为原始二进制 `MNC1`（`payload_type=1`）密文流（`Content-Type: application/octet-stream`，单条上限 `10.5 MiB`），请求头携带 `X-Clip-Id`、`X-Clip-Kid`、`X-Clip-Kind: image\|text` 与 `X-Clip-Meta-B64`（`≤ 32 KiB` 的加密 `ClipMetaV1` 含缩略图）。执行 **两段 `5 GiB` 硬配额检查**（写入 R2 前预检 + DO 事务内复检，超限回滚并立即删除 R2 对象，返回 **`507 CLIP_QUOTA_EXCEEDED`** 附 `{ used_bytes, limit_bytes, incoming_bytes }`）。通过后零缓冲流式写入 R2 `clip/blobs/<clip_id>.mnc1`、在 DO 事务登记 `clip_items` 并裁剪超 1,000 条旧项，返回 `{ ok: true, clip_id, blob_bytes, created_at_ms, expires_at_ms, quota }` 并广播 `clip_wake` |
| `GET /v1/clip?since_id=<ulid>&limit=<1..100>` | `read-write`, `read+clip`, `read` | 分页返回未过期剪贴板轻元数据（单页最多 100 条）：`{ ok: true, items: [{ clip_id, clip_kid, device_id, kind, created_at_ms, expires_at_ms, meta_envelope_b64, has_blob, blob_bytes \| null }], has_more, next_since_id, quota: { used_bytes, limit_bytes, item_count, max_items } }`（按 `clip_id ASC`）；`clip-write` 返回 `403 TOKEN_SCOPE_FORBIDDEN` |
| `GET /v1/clip/:clip_id/blob` | `read-write`, `read+clip`, `read` | 经 DO 校验未过期后直接流式返回 R2 加密二进制本体（`Content-Type: application/octet-stream`、`X-Clip-Id`、`X-Clip-Kid`、`X-Clip-Device-Id`）；不存在或过期返回 `404 NOT_FOUND`；`clip-write` 返回 `403` |
| `POST /v1/clip/prune` | `read-write`, `read+clip` | **按规则回收云端空间（D8′）**：`{ before_ms?, keep_latest?, kind?: "text" \| "image", dry_run?: boolean }`（至少提供一项过滤条件）。按 `(created_at_ms DESC, clip_id DESC)` 跳过最新 `keep_latest` 条后删除满足条件的行并分批 `R2.delete(keys[])`，返回 `{ ok: true, dry_run, deleted_count, freed_bytes, quota }`；非 `dry_run` 且有删除时广播 `{ type: "clip_cleared", clip_id: null, scope: "cloud" }`（桌面保留本地归档）；`read` / `clip-write` 返回 `403` |
| `DELETE /v1/clip[/:clip_id]` | `read-write`, `read+clip` | 单条 `DELETE /v1/clip/:clip_id` 固定广播 `scope: "all"`（全端同步删除）；批量清空 `DELETE /v1/clip[?scope=cloud\|all]` 默认 `scope = "cloud"`（仅清空云端，桌面保留本地归档；显式 `?scope=all` 才通知全端清空）；分批 `R2.delete(keys[])` 并返回 `{ ok: true, deleted_count, freed_bytes, scope, quota }` |

---

## 5. `mynote-wasm` TypeScript ↔ Rust WASM 边界契约

由于 JavaScript GC 堆中的字符串与普通对象无法确定性清零内存，`crates/mynote-wasm` 采用 **不透明会话句柄（Opaque Session Handle）** 将解锁后的敏感主密钥 `VKEK` 严格锁在 Rust WASM 线性内存的 `Zeroizing<[u8; 32]>` 结构内。桌面 UI 与手机 PWA 共用同一会话 API（D7）；VKEK 永不写入 IndexedDB / Cache Storage。

Tier 2 写入时，`op_id` 与新 `key_id` 由 `WasmVaultSession` 内的 core 在加密前生成并绑定进 `MNB1` AAD（§0，唯一定义见 [`data-structures.md`](./data-structures.md) §3.3）。因为 `WasmVaultSession` 只持有 `VKEK` 而不持有 `SMK`，它只产出内层密文 `mnb1` 与（新建/换钥时的）内层包裹密钥 `mnw1`；桌面 Daemon 随后原样复用 `opId` 用 `SMK` 封装外层 `MNS1` 与 `MNR1`。解密时，桌面由 Daemon（手机由 `WasmSyncEngine`）先用 `SMK` 解开外层 `MNR1` 取出 `mnw1`，再交由 `WasmVaultSession.decryptBlock` 解密并校验 `MNB1` AAD。

```typescript
// web/src/wasm/mynote_wasm.d.ts (wasm-bindgen 导出契约)

/** 构造 op 所需的上下文（来自 /v1/local/bootstrap 与当前 BlockDto） */
interface OpContextJson {
  block_id?: string;      // 新建块时省略，由 core 生成
  buffer_id: string;
  parents: string[];      // = 当前全部叶子（expected_heads）；新建块为空
  device_id: string;
  last_hlc: string;
}

/** Tier 2 WASM 加密输出：Daemon 原样采用 opId / keyId，用 SMK 封装外层 MNS1 与 MNR1 */
interface Tier2EncryptedOp {
  opId: string;           // 由 WASM core 生成，绑定于 MNB1 AAD，提交给 Daemon 时原样传递
  blockId: string;
  keyId: string;          // 16B 随机密钥 ID（32 hex）
  mnb1: Uint8Array;       // MNB1 块正文密文（45B 头 magic||ver||key_id||nonce + AEAD 密文）
  mnw1?: Uint8Array;      // MNW1 VKEK 包裹的 BDEK（新建加密块或换钥加锁时返回）
}

/**
 * 驻留于 WASM 线性内存的 Tier 2 保险库解锁会话。
 * JS 层仅持有指针句柄，永远拿不到裸 VKEK 字节；调用 lockAndZeroize() 或释放时由 Rust Drop 执行确定性 zeroize。
 */
export class WasmVaultSession {
  /** 通过 Vault 口令 + Argon2id（单套参数，读自 VaultHeaderV1）解开 VKEK 创建会话 */
  static unlockWithPassphrase(passphrase: string, vaultHeaderBytes: Uint8Array): WasmVaultSession;

  /** 新建加密块：随机生成 BDEK 并用 VKEK 包裹为 mnw1，生成 op_id 后加密为 mnb1 */
  encryptNewBlock(ctxJson: string, content: string, lang: string): Tier2EncryptedOp;

  /** 更新 / 合并已有加密块：用 VKEK 解开 mnw1 取出 BDEK，生成新 op_id 与随机 Nonce 重新加密全量载荷 mnb1 */
  encryptUpdate(ctxJson: string, keyId: string, mnw1: Uint8Array, content: string, lang: string): Tier2EncryptedOp;

  /** 换钥加锁：为明文块生成新的 VKEK 包裹 BDEK (mnw1) 并产出 LOCK 载荷 mnb1（旧钥碎纸由 Daemon 在服务端确认后登记） */
  rekeyToVault(ctxJson: string, content: string, lang: string): Tier2EncryptedOp;

  /** 解密：校验 MNB1 头部与 AAD（绑定 entityId / opId / keyId），仅返回渲染所需的明文结果 */
  decryptBlock(entityId: string, opId: string, keyId: string, mnb1: Uint8Array, mnw1: Uint8Array): DecryptedBlockPayload;

  /** 立即触发 Rust Zeroize 擦除 WASM 线性内存中的 VKEK 并使句柄失效（闲置 N 分钟或 visibilitychange 必调） */
  lockAndZeroize(): void;
  free(): void;
}

/**
 * 供移动端只读 PWA 使用的 Sans-I/O 同步与 Tier 1 解密桥接器（D1：只读，不产生任何写 op）
 */
export class WasmSyncEngine {
  constructor(deviceId: string, smkKeyring: Uint8Array);

  /** 执行状态机单步演进：输入当前轻量索引与事件 JSON，返回 { storeMutations, syncCommands }（syncCommands 只含 pull / 拉密钥表 / 拉快照；对 Tier 2 密钥自动用 SMK 剥离外层 MNR1 产出 mnw1 供解锁时使用） */
  step(engineStateJson: string, syncEventJson: string): StepOutput;

  /** 解包手机状态快照 MNSS（非 Shredded 块的全部叶子版本 + 字段 LWW 结果 + journal_epoch + covers_seq） */
  unpackStateSnapshot(snapshotBytes: Uint8Array): UnpackedStateSnapshot;

  /** 显式清零 WASM 内存中的 SMK 密钥环 */
  zeroizeSmk(): void;
  free(): void;
}

/** Layer 1 毫秒级纯离线格式化与结构转换（桌面加密块格式化亦必须走此函数，严禁外发 CLI 子进程！） */
export function formatSnippet(content: string, lang: string, action?: string): string;

/** 本地粘贴内容高危凭据特征快速扫描（返回命中的特征类型如 "aws_access_key" | "pem_private_key" | null） */
export function detectSecretPattern(pastedText: string): string | null;

/**
 * （M4，D8）独立剪贴板通道 MNC1 加解密桥接（桌面与手机 PWA 共用，使用独立可轮换 ClipKey）。
 * 严禁将裸 ClipKey 暴露到持久化明文；释放时执行确定性 zeroize。
 */
export class WasmClipCodec {
  constructor(deviceId: string, clipKid: string, clipKeyBytes: Uint8Array);
  /** 封装 ClipMetaV1（小文本内联或图片元数据+缩略图，pad256 + XChaCha20-Poly1305） */
  encryptMeta(clipId: string, metaJson: string, ephemeral: boolean): Uint8Array;
  /** 解密并校验 AAD（含 ephemeral 位防跨通道重放），返回 ClipMetaV1 JSON */
  decryptMeta(clipId: string, authorDeviceId: string, ephemeral: boolean, envelope: Uint8Array): string;
  /** 封装图片或长文本原始二进制流为 MNC1 (payload_type=1)，零 Base64 膨胀 */
  encryptBlob(clipId: string, rawBytes: Uint8Array): Uint8Array;
  /** 解密并校验 AAD，返回原始位图或 UTF-8 字节 */
  decryptBlob(clipId: string, authorDeviceId: string, envelope: Uint8Array): Uint8Array;
  zeroize(): void;
  free(): void;
}
```

### 5.1 桌面专属 Tier 2 插件 Web Worker 边界契约（M5-P3，D10）

为守住「常驻 Daemon 零 Tier 2 明文」与「手机 PWA WASM `0 B` 增量」两条铁律，解锁态 Tier 2 块运行 `tier2_capable = true` 的 `.wasm` 插件仅存在于**桌面专属前端**（`web/src/plugins/worker.ts`，绝不编入 `web/src/wasm/pkg-pwa/`）：

- **输入隔离**：主页面先从 `GET /v1/local/plugins/:id/module.wasm` 拉取原始 `.wasm` 字节，再由独立同源 `'self'` `Web Worker` 调用 `WebAssembly.compile(bytes)` → 硬断言 **`WebAssembly.Module.imports(mod).length === 0`** → `WebAssembly.instantiate(mod, {})`，随后仅向 Worker 发送「当前单块已解密明文 + 请求参数 JSON」，**绝不传递 `VKEK`、`WasmVaultSession` 句柄、其他块内容或会话 Cookie**；
- **执行与硬超时**：按 [`data-structures.md`](./data-structures.md) §2.3 的 Core WASM 3-Export ABI 调用 `mynote_abi_version` / `mynote_alloc` / `mynote_invoke`；超过单次超时阈值直接 `worker.terminate()` 销毁整线程并返回 `PLUGIN_RESOURCE_EXCEEDED`；
- **结果回写**：Worker 仅返回纯 JSON `PluginResult`。若为 `view` / `gutter` / `toast`，交由桌面主前端 6 种声明式安全组件渲染；若为 `replace_content`（修改当前加密块），由主页面 `WasmVaultSession.encryptUpdate` 在内存重加密后，按 §3.2 既有 Tier 2 密文通道提交 Daemon（Daemon 全程零明文）。

---

## 6. 已移除 / 推迟的机制（2026-11-24）

依据 [第一性原理审查](../review/2026-11-24-first-principles-review.md) 及 PR #31 审阅补充决议：

- **`mynote update` / `self-update` 自升级子系统**（Provenance Guard、Ed25519 签名清单、防降级、原子替换、`update --rollback`、Daemon 热交接 `prepare_restart` / `daemon_restarting`、错误码 `PACKAGE_MANAGER_MANAGED`）：已移除，分发交给包管理器，只保留迁移前 `VACUUM INTO`（F-14、§9.6、§9.11）。
- **`vault shred` 与 `POST /blocks/:id/shred`、错误码 `VAULT_KEY_SHREDDED`**：已移除，由通用的「回收站 + 受控碎纸 + 换钥」取代，错误码改为 `KEY_SHREDDED`（§9.3、§9.7）。
- **加锁时的 `purge_op_ids` 与本地明文历史即时擦除**：已移除，op 密文永不删除，历史通过换钥加碎纸、在宽限期后变得不可读（§9.3）。
- **`vault_keys` / `vault_key_slots` keystore 端点、`key_mutations`、`MNK1`、`key_seq` / `key_since`**：已移除，由只创建的密钥表 + `key_material` + 碎纸标记（2P-Set）全量比对取代（§9.3）。
- **`/v1/archive/*` 云端归档 HTTP 路由与恢复专用挑战-应答鉴权**：已移除。所有客户端设备丢失而云端 DO 仍在时凭部署级 `BOOTSTRAP_TOKEN` + 24 词直接从 DO 零丢失拉回；客户端与 DO 同时损毁时从 CF 控制台 / `wrangler` / `rclone` 下载 R2 `archives/` 到本地执行纯离线 `mynote restore --from-archive <local-dir>`（§9.12）。
- **`/v1/blobs/:sha256` 与 R2 `blobs/` 加密附件端点**：已推迟至「按数据触发的待办」（届时每个附件使用独立随机 `BlobKey` 存入 `BlockPlaintextV1`，避免块换钥时重传附件）（§9.12）。
- **旧版写入 DO SQLite 的 `/v1/sync/ephemeral-clip` 瞬态剪贴板**：已永久废弃（F-06）；2026-11-27 拍板 **D8**（2026-11-28 **D8′** 修订）以物理隔离的 `/v1/clip*`（云端 `1,000 条 / 30 天 / 5 GiB` 硬护栏 + R2 流式大对象 + 桌面无限归档 + 零写库 `--ephemeral` WS 直推）与 `mynote clip` 子命令重新纳入 M4（见 §2.3、§3.2、§4.2(7)）。
- **快照 `prev_snapshot_id` CAS、K=5 多代快照、`requires_snapshot_bootstrap` / DO 滑动窗口**：已移除，无 GC，只保留给手机读的状态快照（§9.2、§9.5）。
- **WebSocket 携带 op 的「顺风车」推送**：已推迟，WS 只发唤醒通知（§9.11 按数据触发的待办）。
- **`SPAN_PATCH` 完整性校验、`head_op_id` 单值、`conflict_siblings`**：已移除，改为全量载荷、`head_op_ids` 与 `versions`（D3，§9.4）。
- **`RESOLVE` 独立语义**：降为 `block update` / `PATCH` 的别名（§9.4）。
- **HLC 漂移拒收**：已移除，只提示 `CLOCK_SKEW`（§9.4）。
- **Lock-Wins 特例**：已移除，任一叶子加锁即整块按加锁渲染（§9.4）。
- **`--help-json` 机读反射**：已推迟，由 CLI 黄金测试守护机读契约（§9.9）。
- **WebAuthn PRF 解锁与槽位注册（`unlockWithPrf`、`enrollPrfSlot`）**：已推迟，口令是唯一主路径（§9.10）。
- **WASM `packSnapshot` 与手机写路径**：已移除，手机只读（D1，§9.2）。
- **`127.0.0.1:<port>` 入口**：已移除，统一使用 `http://localhost:<port>`（F-15）。
- **重命名**：`block restore` → `block revert`（避免与 `trash restore`、`restore --from-archive` 混淆）；`sync rotate-smk` → `keyring rotate`（F-05）。
- **轮换后重新抄写恢复码 / Vault 第二套 24 词恢复码**：已移除，改为一份统一恢复包（公钥封装），轮换后只需 `recovery drill`（F-05）。
