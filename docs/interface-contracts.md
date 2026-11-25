# 全链路接口与跨边界契约规范 (`interface-contracts.md`)

> 2026-11-24 修订：依据 [第一性原理审查 §9](../review/2026-11-24-first-principles-review.md) 的决策 D1–D7 更新。

> 本文档与 [数据结构规范 (`data-structures.md`)](./data-structures.md)、[同步协议规范 (`sync-protocol.md`)](./sync-protocol.md)、[威胁模型规范 (`threat-model.md`)](./threat-model.md) 共同构成编码级契约基准，精确定义 **统一错误码表、Agent-Native CLI 契约、本地 Daemon REST/WS/UDS 契约、Cloudflare 云端同步 API 契约，以及 `mynote-wasm` 前后端 FFI 接口**。
>
> **单一事实来源**：本文档是**本地 API / CLI** 的唯一定义处。线格式、信封与 AAD 只在 [`data-structures.md`](./data-structures.md) 定义；合并规则、密钥表 2P-Set、碎纸与宽限期语义只在 [`sync-protocol.md`](./sync-protocol.md) 定义；安全承诺只在 [`threat-model.md`](./threat-model.md) 定义；测试门禁只在 [`eval-framework.md`](./eval-framework.md) 定义。本文只引用这些概念，不重复定义。

---

## 目录

1. [全局错误码注册表与跨层映射契约](#1-全局错误码注册表与跨层映射契约)
2. [Agent-Native CLI 命令、JSON 信封与外部格式化契约](#2-agent-native-cli-命令json-信封与外部格式化契约)
3. [本地桌面 Daemon 契约（HTTP + WebSocket + Unix Socket IPC）](#3-本地桌面-daemon-契约http--websocket--unix-socket-ipc)
4. [Cloudflare 云端盲同步中继契约（HTTP + R2 + WebSocket Hibernation）](#4-cloudflare-云端盲同步中继契约http--r2--websocket-hibernation)
5. [`mynote-wasm` TypeScript ↔ Rust WASM 边界契约](#5-mynote-wasm-typescript--rust-wasm-边界契约)
6. [已移除 / 推迟的机制（2026-11-24）](#6-已移除--推迟的机制2026-11-24)

---

## 0. 贯穿全文的约定

- **`op_id` 由 core 生成（修正 F-01）**：每个 op 的 `op_id` 由**执行加密的那个 `mynote-core` 实例**在加密之前生成，并写入信封头部（AAD 绑定 `block_id`、`op_id`、`key_id` 与格式版本，定义见 [`data-structures.md`](./data-structures.md)）。
  - 明文 / Tier 1 写入：Daemon（或 CLI 进程）内的 core 生成。
  - Tier 2 写入：前端 `mynote-wasm` 内的 core 生成，并封装进 `sealed_op`。Daemon 从信封头读取 `op_id` 并**原样使用，绝不重新生成**。
  - 因此，本地 REST 请求体与 CLI 参数中**都没有 `op_id` 输入字段**；写命令只在响应中**返回** `op_id`。
- **多版本（路径 γ）**：一个块可能同时有多个叶子版本。`head_op_ids` 是当前全部叶子；`display_op_id` 是 `(hlc, op_id)` 最大的叶子。任何写正文的请求都必须声明它看到的**全部叶子**（`--expected-head` / `expected_heads`），声明集合即新 op 的 `parents`；叶子数 > 1 时，这次写入就是一次**合并**。规则详见 [`sync-protocol.md`](./sync-protocol.md)。
- **删除 = 回收站**：删除只把块放进回收站，并登记一个碎纸标记，`not_before = now + T_grace`。宽限期内可撤销；到期后由碎纸执行器删除密钥。参数：`T_grace` = 7 天，服务端强制下限 `T_grace_min` = 24 小时 [保证：服务端拒收更短的标记]，批量阈值 N = 20 块/天。语义见 [`sync-protocol.md`](./sync-protocol.md)，时间上界见 [`threat-model.md`](./threat-model.md)。
  - M1 只有回收站和撤销；碎纸执行器在 M2 上线，届时对 M1 期间登记的标记追溯执行（[review §9.11](../review/2026-11-24-first-principles-review.md)）。
- **本地入口唯一**：`http://localhost:<port>`（修正 F-15）。

---

## 1. 全局错误码注册表与跨层映射契约

所有子系统共享同一套机器可读错误码枚举（`ErrorCode`），确保 CLI、本地 Daemon 与云端 Worker 的错误处理、重试判定与 Agent 自愈提示（`hint`）完全一致：

| 稳定错误码 `error.code` | CLI 退出码 | HTTP 状态码 | `retryable` | 触发条件与强制 `hint` 模板规范 |
| --- | :---: | :---: | :---: | --- |
| *(成功)* | `0` | `200 / 201` | — | 含断网/无 Daemon 时本地落盘成功的常规写命令（`meta.sync_state = "pending_offline"`）；`block delete` 成功即进入回收站（即使碎纸标记因批量阈值被暂停，也返回 `0`，见 `data.shred_state`） |
| `INVALID_ARGUMENT` | `2` | `400` | `false` | 参数缺失/格式非法、未知子命令；提示运行 `mynote <cmd> --help` |
| `EMPTY_STDIN_REFUSED` | `2` | `400` | `false` | 非交互 `stdin` 为 0 字节但目标块非空；`hint: "Pass --allow-empty to clear content, or use 'mynote block delete <id>' (moves it to trash)"` |
| `INTERACTION_REQUIRED` | `2` | `400` | `false` | 非 TTY / `--non-interactive` 下请求了必须人工在终端确认的操作（`--force`、`vault *`、`device add`、`keyring rotate`、`recovery show`、`recovery drill`、`restore --from-archive`） |
| `UI_CONFIRMATION_REQUIRED` | `2` | `428` | `false` | 请求了**只能在桌面 UI 中交互确认**的操作：清空回收站、缩短宽限期、确认超出批量阈值的碎纸。CLI 的 `trash empty` / `trash expedite` / `trash confirm` **无论是否 TTY 都固定返回此码**（Agent 可以驱动伪终端，所以 TTY 不能证明是本人操作）；本地 API 的 `trash/actions/commit` 缺少有效 `confirm_nonce` 时也返回此码。由本地 Daemon 强制。`hint: "Open the desktop UI ('mynote open') and confirm there"` |
| `NOT_FOUND` | `3` | `404` | `false` | 指定 `BufferId`、`BlockId`、`op_id`、`key_id` 不存在 |
| `IN_TRASH` | `3` | `404` | `false` | 目标块在回收站中；`details: { deleted_at_ms, shred_not_before_ms }`；`hint: "Run 'mynote trash restore <id>' to undo the deletion"` |
| `HEAD_MISMATCH` | `4` | `409` | `true` | `--expected-head` 集合与当前全部叶子 `head_op_ids` 不一致；`details: { expected_heads, actual_heads }`；提示先 `block get --json` 再重试 |
| `CONFLICT_PRESENT` | `4` | `409` | `false` | 只能作用于单一版本的命令（`block append`、`format <id>`、`block revert`）遇到多叶子块；`hint: "Block has N versions; inspect with 'mynote block get <id> --json', then merge via 'mynote block update <id> --expected-head <h1> --expected-head <h2> ...'"` |
| `CAS_MISMATCH` | `4` | `409` | `true` | 云端 `expected_epoch` 与远端 epoch 不一致（如 DO PITR 回滚后）；或上传的手机状态快照 `covers_seq` 未递增（客户端丢弃该快照即可） |
| `BLOCK_LOCKED` | `5` | `423` | `false` | 未解锁访问加锁块（任一叶子加锁即整块按加锁处理），或非 TTY 请求解密 |
| `KEY_SHREDDED` | `5` | `410` | `false` | 目标版本的 `key_id` 已过宽限期并被碎纸，内容永久不可恢复（如超期后 `trash restore`、读取「换钥」前的历史版本） |
| `KEY_UNKNOWN` | `5` | `409` | `false` | 云端拒收引用服务端不认识的 `key_id` 的 op（密钥记录未随批提交或从未创建）。正常客户端不会触发，出现即说明有 bug |
| `KEY_PENDING_SHRED` | `4` | `409` | `true` | 云端拒收引用已有 `pending_confirm` / `scheduled` 碎纸标记的 `key_id` 的新 op，且同批未先撤销该标记。core 自动按 Update-Wins 规则（[`sync-protocol.md`](./sync-protocol.md) §5.7）撤销或换钥后重试 |
| `SHRED_STALE` | `4` | `409` | `true` | 云端拒收碎纸标记：该 `key_id` 下存在请求方未见过的 op（`seq > seen_seq`）。core 自动 pull、重新评估后再提交 |
| `GRACE_TOO_SHORT` | `5` | `422` | `false` | 云端拒收 `not_before < now + T_grace_min` 的碎纸标记。正常客户端不会触发，出现即说明有 bug 或滥用 |
| `AUTH_REQUIRED` / `DEVICE_REVOKED` / `TOKEN_SCOPE_FORBIDDEN` | `5` | `401 / 403` | `false` | 本地 Cookie / Origin 校验失败；云端 `device_token` 无效/已吊销；或 `scope=read` 令牌尝试 push、创建密钥记录、提交碎纸标记 |
| `SYNC_OFFLINE` | `6` | `502 / 503` | `true` | **仅用于显式联网阻塞命令**（`sync push/pull`、`keyring rotate`、`restore --from-archive`）无法连通远端 |
| `RATE_LIMITED` | `6` | `429` | `true` | 云端限流；按 `Retry-After` 退避 |
| `FORMAT_SYNTAX_ERROR` | `7` | `422` | `false` | Layer 1/2 格式化输入语法错误或外部命令返回 0 字节/超时；原块保持未修改 |
| `KEY_MISSING` | `8` | `500` | `false` | 活跃块（未进入碎纸流程）找不到可用密钥，违反 INV-KEY-LIVENESS；本设备随即停止发起碎纸（见 §2.3 `sync status`）；`hint: "Run 'mynote sync pull'; if it persists, do not delete anything and report"` |
| `INTEGRITY_ERROR` | `8` | `422 / 500` | `false` | AEAD 解密失败、信封头与请求不符（`block_id` / `parents` 不匹配）、手机状态快照 `BLAKE3` 失配，或本地库 `min_reader_schema_version` 高于当前二进制（`SCHEMA_TOO_NEW`） |

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
   - *若 `is_locked == true`（任一叶子加锁即为真）：强制返回 `"redacted": true, "byte_size": null, "preview": null`，仅保留 `id`、`buffer_id`、`position`、`is_locked`、`public_hint`、`head_op_ids`、`has_conflict` 与 `updated_at_ms`。*

2. **单块完整读取（`mynote block get <id> --json`）**：
   - 未加锁块返回 `content: string`（展示版本的正文）与 `versions: Array<{ op_id, hlc, device_id, actor, is_display, is_locked, content: string | null }>`。`versions` 包含全部叶子：展示版本排第一，其余按 `(hlc, op_id)` 降序；非展示版本在 UI 中标为「另一台设备的版本」。
   - 加锁块（任一叶子加锁）：`content: null`，`versions[*].content` 全部为 `null`（包括未加锁的并发版本），并附带 `has_unlocked_concurrent_version: boolean`。这类块的合并只能在 UI 解锁后完成。
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
| `mynote block delete <id>` | **只把块放进回收站**：写墓碑 op，登记碎纸标记 `not_before = now + T_grace`；支持 `--dry-run`。**无** `--purge` / `--now` / `--grace` 之类选项。响应 `data` 额外包含 `in_trash: true`、`shred_not_before_ms`（`pending_confirm` 时为 `null`）与 `shred_state`。`shred_state` 取值：`"scheduled"` 表示宽限期计时中；`"pending_confirm"` 表示当日已超过批量阈值 20 块，块照常进回收站，但彻底删除的计时暂停，需在桌面 UI 中确认后才开始；`"withheld_self_check"` 表示本设备自检失败，不发碎纸标记，块仍在回收站。超阈值时 `stderr` 另有告警，退出码仍为 `0` | 支持 `--expected-head <op_id>`（全部叶子） | M1（碎纸执行 M2） |
| `mynote trash ls` | 列出所有设备删除、尚未碎纸的块：`{ id, buffer_id, buffer_name, is_locked, preview \| null, deleted_at_ms, deleted_by_device, actor, shred_not_before_ms \| null, shred_state }`，按 `shred_not_before_ms` 升序（`null` 排最后） | 只读 | M1 |
| `mynote trash restore <id>` | **撤销删除**：撤销碎纸标记，并生成一个恢复 op 让块回到原 buffer。宽限期已过则返回 `KEY_SHREDDED`；支持 `--dry-run` | 天然幂等（对未在回收站的块返回 `NOT_FOUND`） | M1 |
| `mynote trash <empty\|expedite\|confirm>` | **仅 UI 操作的存根**：清空回收站、缩短宽限期、确认超阈值的碎纸。这三个子命令存在，只是为了给出明确的拒绝：**无论是否 TTY**，一律返回 `UI_CONFIRMATION_REQUIRED`（退出码 `2`），零副作用。由本地 Daemon / CLI 强制，这样 Agent（唯一入口是 CLI）就做不到加速删除。真正的操作在桌面 UI 中交互确认（§3.2 `trash/actions`），下限仍是服务端强制的 `T_grace_min` | — | M1（UI 侧 M2） |
| `mynote format [id]` | 传 `<id>` 原地格式化该块（需 `--expected-head`；多叶子块返回 `CONFLICT_PRESENT`）；不传 `<id>` 作为纯流过滤器格式化 `stdin -> stdout`（`--lang`、`--action unescape-json\|to-yaml\|...`） | 语法错误退出码 `7` 且零副作用 | M1 |
| `mynote vault <init\|lock\|unlock\|passwd>` | 全部要求 TTY。`init`：生成 VKEK 并追加进密钥环，**并入统一恢复包，不生成第二套恢复码**；KDF 参数与盐写入 Vault 头部（单套参数，按 iPhone 定）。`lock <id> [--hint "..."]`：**换钥**，即用新的 VKEK 包裹 DEK 重新加密当前版本，写一个带新 `key_id` 的 `LOCK` op，等服务端确认新 op 与新密钥记录后，再对旧 Tier 1 `key_id` 登记碎纸标记（`T_grace`；缩短到 `T_grace_min` 只能在 UI 中操作）。`unlock <id> [--shred-old-key]`：换回新的 Tier 1 BDEK，旧 Tier 2 密钥默认保留，带该参数则对其登记碎纸标记。`passwd`：用新口令重新包裹 VKEK | 客户端短进程内存执行；`lock` / `unlock` 支持 `--expected-head` | M2 |
| `mynote keyring rotate` | 密钥环轮换（原 `sync rotate-smk`）：向密钥环追加新 SMK 代际，用它重新包裹密钥表中全部 Tier 1 密钥记录并推送；旧 SMK 代际**永久保留**在恢复密钥环中（op 归档永久保存，仍需旧代际解密）。恢复包采用公钥封装，轮换后**不需要重新抄写 24 词**。完成后在 `stderr` 和 `hint` 中提示运行 `mynote recovery drill`，未演练前 `sync status` 报告 `recovery_drill_due: true`。只允许 TTY | 断网返回退出码 `6` | M1 |
| `mynote recovery <show\|drill>` | `show`：在 TTY 中经交互确认后显示统一恢复包（24 词）。`drill`：恢复演练，在 TTY 中输入恢复包，验证它能解封当前密钥环（含最新 SMK 代际与 VKEK），**不写入任何数据**；响应 `data`：`{ ok, keyring_generations, includes_vkek, drilled_at_ms }`。两者都只允许 TTY，恢复包内容永不写入 `--json` 输出。恢复包格式见 [`threat-model.md`](./threat-model.md) / [`data-structures.md`](./data-structures.md) | 只读 | M1 |
| `mynote sync <status\|push\|pull>` | 显式触发同步对账。`status --json` 的 `data`：`{ sync_state, epoch, last_seq, pending_ops, clock_skew_ms, key_self_check: { ok, last_run_ms, blocks_missing_key }, trash: { count, pending_confirm_count, next_shred_ms }, recovery_drill_due, last_recovery_drill_ms, last_local_backup_ms }`。时钟偏差过大**只提示、不拒收** | `push/pull` 断网返回退出码 `6` | M1 |
| `mynote device <add\|ls\|revoke>` | `add --name <label> [--scope read\|read-write]`：默认 `read-write`（桌面），手机配对用 `--scope read`。采用**一次性领取**：桌面用随机一次性包裹密钥 `K_pair` 加密 SMK 密钥环，交给服务端暂存（连同新令牌，TTL 10 分钟，首次领取即删除，见 §4.2 (6)）；终端输出的配对码只含 `{ server_url, pair_id, K_pair }`，可粘贴（iOS 主流程）或以二维码形式在 PWA 内用 `getUserMedia` 扫描。`add` 只允许 TTY，配对码**永不进入 `--json` 输出**（`--json` 时 `data` 只含 `{ device_id, scope, expires_at_ms }`，配对码写到 `/dev/tty`）。`ls` 列出 `{ device_id, name, scope, created_at_ms, last_seen_ms }`。`revoke <device_id>` 成功后 `hint` 建议执行 `mynote keyring rotate` | 管理鉴权 | M1（`read` 范围 M2） |
| `mynote import heynote <path>` | `--buf <name>`、`--dry-run` | 文件哈希防重复提示 | M1 |
| `mynote restore --from-archive <source>` | 灾难恢复：从 R2 op 密文归档加最新密钥表快照，重建全部**未删除**数据（INV-RECOVERY）。`<source>` 为云端只读归档端点 `/v1/archive/*`（§4.2 (5)；零设备场景下的访问凭据见 [`cloudflare-cloud-architecture.md`](./cloudflare-cloud-architecture.md)）或已下载的本地目录。`--to <empty-data-dir>`（**永不覆盖**非空数据目录）、`--key-snapshot <id\|latest>`、`--dry-run`。统一恢复包只从 TTY 读取。响应 `data`：`{ restored_blocks, skipped_shredded, archive_days, key_snapshot_at_ms, data_dir }` | 非 TTY 返回 `INTERACTION_REQUIRED`；断网返回 `6` | M1 |
| `mynote open` | 打开本地 UI：Omarchy 上用浏览器打开 `http://localhost:<port>`（一次性 ticket，见 §3.1）；macOS 上显示并聚焦 Tauri 壳窗口 | — | M1 |

### 2.4 帮助体系与 Layer 2 `formatters.toml` 规范

- **L0–L3 渐进帮助保留**：L0 `SKILL.md` → L1 `mynote --help` → L2 `mynote <cmd> --help` → L3 `mynote help <topic>`（体系说明见 [`architecture-proposal.md`](./architecture-proposal.md)）。帮助文案中的退出码与错误码必须与 §1 一致。
- **`--help-json` 推迟**：M1 由 CLI 黄金测试（§2.6）守护机读契约；只有当出现需要严格 Schema 的自动化消费方时，才按原结构 `{ command, about, args, stdin_mode, exit_codes, response_schema }` 引入。
- `~/.config/mynote/formatters.toml` 契约：
  - 子进程在无网络/受限环境变量下通过 `stdin` 喂入原块 UTF-8 字节，在 `timeout_ms`（默认 `2000 ms`）内等待退出；
  - **熔断条件**：`exit_code != 0`、超时杀死、输出非合法 UTF-8，或 **`input.len() > 0 && stdout.is_empty()`** 时一律返回 `FORMAT_SYNTAX_ERROR`（退出码 `7`），绝不写回数据库。

### 2.5 分发、升级与 Schema 迁移

- **分发交给包管理器（F-14）**：Homebrew tap（macOS）、AUR（Omarchy），开发期可用 `cargo install`。完整性校验、升级与回滚都由包管理器负责。`mynote` **不内置自升级**，也**绝不在后台联网检查更新或上报遥测**。
- **安装位置与 F-07**：Homebrew / AUR 把二进制装到用户不可写的位置，这也是 T5 缓解措施之一。`cargo install` 装在用户可写的 `~/.cargo/bin`，只建议开发期使用。Tier 2 对同 UID 攻击者的真实边界见 [`threat-model.md`](./threat-model.md)。
- **Schema 迁移前自动备份（保留）**：新版本首次打开数据库、需要升级 `PRAGMA user_version` 时，必须在独占写事务**之前**通过 `VACUUM INTO` 生成权限 `0600` 的快照 `~/.local/share/mynote/backups/mynote-pre-schema-v<old>.db`，再执行迁移。
- **降级**：旧二进制打开较新的库时返回 `INTEGRITY_ERROR`（`SCHEMA_TOO_NEW`，退出码 `8`），不做任何写入。回退步骤是用包管理器装回旧版本，再手动换回上面的迁移前备份（步骤写进 `mynote help upgrade`）。
- **升级后的 Daemon 重启**：交给托管方（`brew services` / `systemctl --user` / Tauri 壳）。前端在 `/v1/local/ws` 断开后按指数退避重连。CLI 通过 UDS `ping` 发现 Daemon 版本与自身不一致时，只在 `stderr` 告警。

### 2.6 CLI 黄金测试需稳定的输出契约

[`eval-framework.md`](./eval-framework.md) 中约 10 个 CLI 黄金测试断言的就是下列契约。修改其中任何一项都属于**破坏性变更**；新增字段不算。

1. **流纪律**：`--json` 时 `stdout` 恰好一个 JSON 对象（以单个 `\n` 结尾），告警与进度只走 `stderr`；`--raw` 时 `stdout` 是展示版本正文的精确字节，无尾随换行。
2. **信封**：顶层键 `ok`、`data`、`error`、`meta`。`ok == false` ⇔ `data == null` 且 `error != null`。`error` 含 `code`、`message`、`hint`、`retryable`。
3. **错误码集合与退出码映射**：§1 全表，包括 `code → exit`、`code → retryable`。黄金测试比较 `error.code`、退出码与 `details` 的键名，**不比较 `message` / `hint` 文案**。
4. **DTO 字段名与类型**：§2.1 写命令 `data`、§2.2 列表项与 `block get`（含 `versions` 的排序规则）、§2.3 `block delete` / `trash ls` / `sync status` / `restore` 的 `data`。ID 一律为 ULID 字符串，时间一律为毫秒整数（`*_ms`）。
5. **排序**：`ls` 按 `(buffer 顺序, position, id)`；`versions` 展示版本在前，其余按 `(hlc, op_id)` 降序；`trash ls` 按 `shred_not_before_ms` 升序。
6. **离线语义**：普通写命令离线返回 `0`，并带 `meta.sync_state = "pending_offline"`；显式联网命令离线返回 `6`。
7. **拒绝行为零副作用**：`EMPTY_STDIN_REFUSED`、`HEAD_MISMATCH`、`CONFLICT_PRESENT`、`FORMAT_SYNTAX_ERROR`、`INTERACTION_REQUIRED`、`UI_CONFIRMATION_REQUIRED` 发生后，数据库状态（叶子集、回收站、密钥表、碎纸标记）保持不变。
8. **删除边界**：
   - `block delete` 之后，`ls` 不再返回该块，`trash ls` 返回它；`shred_state == "scheduled"` 时，`shred_not_before_ms ≥ deleted_at_ms + T_grace_min`。
   - 当日第 21 块起，`shred_state == "pending_confirm"` 且 `shred_not_before_ms == null`，退出码 `0`。
   - `trash restore` 之后状态复原。
   - `trash empty` / `trash expedite` / `trash confirm` 无论是否 TTY 都返回 `UI_CONFIRMATION_REQUIRED`（退出码 `2`），对应黄金测试 G08。
9. **TTY 门槛**：`--force`、`vault *`、`device add`、`keyring rotate`、`recovery *`、`restore --from-archive` 在非 TTY 下返回 `INTERACTION_REQUIRED`；`block get --decrypt` 在非 TTY 下返回 `BLOCK_LOCKED`。
10. **幂等**：同一 `--idempotency-key` 的 `add` 重放，返回相同的 `block_id` / `op_id`，且不新增 op。

黄金测试对非确定值（ID、时间戳、`duration_ms`、`hlc`）做归一化后再比较。

---

## 3. 本地桌面 Daemon 契约（HTTP + WebSocket + Unix Socket IPC）

### 3.0 进程模型：Daemon、macOS Tauri 壳与 CLI

- **两端共用一份前端**：macOS 用 Tauri 壳（WKWebView）加载 `http://localhost:<port>`，窗口常驻隐藏，全局热键只做「显示 + 聚焦」，目标 < 100 ms [目标]。Omarchy 用 Hyprland 键绑定唤出或聚焦加载同一地址的 Chromium webapp。
- **壳与 Daemon 的关系待 S0 决定**：壳内嵌 Daemon（单进程）、壳拉起独立 Daemon、或由 launchd / systemd 托管 Daemon，三选一（[review §9.8](../review/2026-11-24-first-principles-review.md)）。无论选哪种，下列契约不变：
  1. **CLI 在 UI 未打开时独立工作**：关闭窗口或退出壳不影响 CLI 读写。CLI 离线写入成功返回 `0`（`pending_offline`），之后由 Daemon 补推。
  2. **SQLite 单写入方**：任一时刻最多一个 Daemon 实例（`<data_dir>/daemon.lock` 独占文件锁），第二个实例启动即退出并提示。CLI 写入路径：**Daemon 运行时**，写命令经 UDS 的 `apply` 帧转交 Daemon 执行（载荷与 §3.2 的 REST DTO 相同，由 Daemon 生成 `op_id` 与 HLC）；**Daemon 未运行时**，CLI 以短事务直接写本地 SQLite，此时它就是唯一写入方（协议见 [`sync-protocol.md`](./sync-protocol.md) §7）。
  3. 读路径始终可以由 CLI 直接打开 SQLite（WAL 并发读）完成。

### 3.1 安全握手中介层契约（`localhost:<port>`）

1. **Host / Origin 白名单（请求头强拦截）**：
   - Daemon 只监听回环地址（`127.0.0.1` 与 `::1`，因为 `localhost` 可能先解析到 IPv6）。但 **`Host` 白名单只有一项：`localhost:<port>`**。其他任何 `Host`，包括 `127.0.0.1:<port>`、`[::1]:<port>` 以及 DNS 重绑定域名，**一律 `403`**，`hint` 指向 `http://localhost:<port>`。统一入口是为了让 Cookie 只有一个作用域，并为将来的 WebAuthn RP ID 留出可能（F-15）。
   - **`Origin` 白名单**：
     - `http://localhost:<port>`：Omarchy Chromium webapp、浏览器，以及采用方案 A 的 Tauri 壳。
     - `tauri://localhost`：仅当 S0 选定方案 B 时加入。
     - 其他 `Origin`（含 `http://127.0.0.1:<port>`、`null`）一律 `403`。
   - **Tauri 壳的 Origin**（S0 二选一）：
     - **方案 A（首选）**：WKWebView 直接导航到 `http://localhost:<port>`，Origin 与浏览器完全相同，沿用下文的 Cookie 会话，无需 CORS。
     - **方案 B**：前端资源经自定义协议加载（macOS 上为 `tauri://localhost`），对 Daemon 是跨站请求，`SameSite=Strict` Cookie 不会随请求发送。因此：白名单加入该 Origin；CORS 只对它返回 `Access-Control-Allow-Origin: tauri://localhost`（不用 `*`）；鉴权改为壳经 UDS `open_ticket` 换取的 `Authorization: Bearer <session_token>`，只存在壳进程内存中。
   - 除首次 `GET /v1/local/auth/exchange` 外，所有 `/v1/local/*` 请求与 WebSocket 握手必须携带 `Cookie: mynote_local_session=<64hex>`（方案 B 的壳用上述 Bearer 会话），且所有非 `GET` 请求及 `/v1/local/ws` 必须携带白名单内的 `Origin`。
2. **一次性会话置换**：
   - `mynote open`（或 Tauri 壳启动时经 UDS `open_ticket` 申请）生成单次有效（有效期 10 秒）的随机 `ticket` 写入 Daemon 内存表，拉起浏览器 / 壳窗口访问 `http://localhost:<port>/v1/local/auth/exchange?ticket=<ticket>`；
   - Daemon 校验并立即销毁 `ticket`，返回 `303 See Other`、`Location: /` 与 `Set-Cookie: mynote_local_session=<session_token>; HttpOnly; SameSite=Strict; Path=/`。

### 3.2 本地 REST API 端点契约（Daemon 对 Tier 2 严格零明文！）

所有请求体中**都没有 `op_id` 输入字段**（§0）。Tier 2 写入携带由前端 WASM core 生成的 `sealed_op_b64`（格式见 [`data-structures.md`](./data-structures.md)）。Daemon 必须校验信封头中的 `block_id` 与路径一致、`parents` 与 `expected_heads` 一致、`key_id` 存在于密钥表，否则返回 `INTEGRITY_ERROR`。

| 方法与路径 | 请求体 / 参数 | 响应体与关键安全不变量 |
| --- | --- | --- |
| `GET /v1/local/bootstrap` | 无 | `{ buffers, initial_buffer_id, blocks, sync_status, vault_header, trash_count, device_id, last_hlc }`（一步完成首屏渲染；`device_id` / `last_hlc` 供 WASM core 构造 op） |
| `POST / PATCH / DELETE /v1/local/buffers[/:id]` | `{ name?, after_id?, before_id? }` | 返回更新后的 `BufferDto` |
| `GET /v1/local/blocks?buffer_id=<id>` | 查询参数 | 返回按 `(position, id)` 排好序的 `BlockDto[]`：`{ id, buffer_id, position, lang, is_locked, has_unlocked_concurrent_version, public_hint, head_op_ids, display_op_id, versions: [{ op_id, hlc, device_id, actor, is_display, is_locked, key_id, content \| null, sealed_op_b64 \| null }] }`。加锁版本 `content: null`，并携带 `sealed_op_b64` 供前端解密。不含回收站中的块 |
| `POST /v1/local/blocks` | 明文块：`{ buffer_id, lang, content, after_id? }`（Daemon core 生成 `block_id`、`op_id`，新建由 SMK 包裹的 BDEK 与密钥记录）<br>直接新建加密块：`{ buffer_id, after_id?, public_hint?, sealed_op_b64, block_key_record }` | 原子写库（op + 密钥记录同一事务）并异步触发同步，返回 `BlockDto` 与 `op_id` |
| `PATCH /v1/local/blocks/:id` | `{ expected_heads?, content?, lang?, after_id?, before_id?, buffer_id?, sealed_op_b64? }` | 写正文（`content` 或 `sealed_op_b64`）时 `expected_heads` 必填，且必须**等于**当前全部叶子，否则返回 `409 HEAD_MISMATCH`（`details.actual_heads`）；叶子数 > 1 时即为合并。只改 `lang` / 位置 / `buffer_id` 走字段 LWW，不需要 `expected_heads`。**Daemon 从不接收加密块的明文或 `VKEK`** |
| `POST /v1/local/blocks/:id/resolve` | `{ expected_heads, content? \| keep_op_id? \| sealed_op_b64? }` | `PATCH` 的别名（`RESOLVE` 不是独立 op 类型）。`keep_op_id` 仅对未加锁版本有效：由 Daemon core 用该版本正文生成新的全量 op；加锁版本须由前端解锁后提交 `sealed_op_b64` |
| `POST /v1/local/blocks/:id/lock` | `{ expected_heads, public_hint?, sealed_op_b64, block_key_record, grace?: "default" \| "min", confirm_nonce? }` | **换钥加锁**：同一事务写入 `LOCK` op（新 `key_id`，DEK 由 VKEK 包裹）与新密钥记录，立即从物化表与 FTS5 中移除该块明文。待服务端确认新 op 与新密钥记录后，再对旧 Tier 1 `key_id` 登记碎纸标记：默认 `T_grace`；`grace: "min"`（缩短到 `T_grace_min`）需要有效的 `confirm_nonce`。到期后的本地清理（`secure_delete` + WAL checkpoint）见 [`sync-protocol.md`](./sync-protocol.md) |
| `POST /v1/local/blocks/:id/unlock` | `{ expected_heads, plaintext_content, lang, shred_old_key: boolean }` | 用户在前端 WASM 解密后显式解除锁定时调用。换钥到新的 Tier 1 BDEK（Daemon core 生成新 op 与 `op_id`）；`shred_old_key` 为真时，对旧 Tier 2 `key_id` 登记碎纸标记（`T_grace`） |
| `DELETE /v1/local/blocks/:id` | `{ expected_heads }` | 移入回收站：写墓碑 op 并登记碎纸标记 `not_before = now + T_grace`。响应 `{ in_trash: true, shred_not_before_ms, shred_state }`，取值同 CLI |
| `GET /v1/local/blocks/:id/history` | `?limit=50` | 返回历史版本元数据（每个 op 都是全量载荷，任一版本可直接读取）；`key_id` 已碎纸的版本标 `content_available: false` |
| `GET /v1/local/trash` | 无 | 回收站列表，字段同 `mynote trash ls`（包含其他设备发起的删除） |
| `POST /v1/local/trash/:id/restore` | 无 | 撤销碎纸标记并恢复块；宽限期已过返回 `410 KEY_SHREDDED` |
| `POST /v1/local/trash/actions/prepare` | `{ action: "expedite" \| "confirm_pending" \| "purge_history", block_ids: string[] \| "all" }` | **仅限 UI**：返回 `{ confirm_nonce, expires_at_ms, summary }`（单次有效、60 秒过期）。UI 必须把 `summary`（块数、最早不可恢复时间）放进模态确认框展示给用户 |
| `POST /v1/local/trash/actions/commit` | `{ confirm_nonce }` | 执行已确认的动作。`expedite` = 清空回收站或缩短宽限期，把 `not_before` 提前到 `now + T_grace_min`，不能更早（服务端另行强制），云端调用 `/v1/keys/shred`；`confirm_pending` = 确认 `pending_confirm` 的碎纸，从确认时刻开始计时，云端调用 `/v1/keys/confirm`；`purge_history` = 「清除历史」，即换钥当前版本并对旧 `key_id` 登记碎纸标记。nonce 缺失或失效返回 `428 UI_CONFIRMATION_REQUIRED` |
| `POST /v1/local/format` | `{ content, lang, action? }` | 调用内置 Layer 1 或外部 Layer 2 管线，返回 `{ formatted }`（**严禁把处于解锁态的加密块发给外部 CLI 子进程！加密块格式化仅允许在前端 `mynote-wasm` Layer 1 内纯内存完成**） |
| `GET /v1/local/keys?block_id=<id>` / `POST /v1/local/keys` | `GET` 读取密钥表记录与碎纸标记；`POST` 追加新的密钥记录（只创建、不修改） | 仅传递包裹后的密文字节；表结构见 [`data-structures.md`](./data-structures.md) |
| `GET / PUT /v1/local/vault/header` | Vault 头部：KDF 参数、盐，以及口令派生密钥包裹的 VKEK | `PUT` 仅用于 `vault init` / `passwd`；仅传递密文 |

> [!NOTE]
> `trash/actions` 的 `confirm_nonce` 防的是 **Agent 经 CLI 误用或被注入**：CLI 没有对应命令，也拿不到 UI 的 `HttpOnly` 会话。它**不防**能篡改执行环境的恶意同 UID 进程（见 [`threat-model.md`](./threat-model.md) T5）。「无法立即删除」的硬保证来自服务端强制的 `T_grace_min` 与批量阈值。

### 3.3 本地 WebSocket（`/v1/local/ws`）与 Unix Socket（`daemon.sock`）协议

- **`/v1/local/ws` 服务端推送帧（JSON）**：
  - `{ "type": "blocks_changed", "upserted": BlockDto[], "deleted_ids": string[] }`
  - `{ "type": "buffers_changed", "upserted": BufferDto[], "deleted_ids": string[] }`
  - `{ "type": "trash_changed", "count": number, "pending_confirm_count": number, "next_shred_ms": number | null }`
  - `{ "type": "sync_status", "state": "synced" | "syncing" | "pending_offline" | "conflict_present", "last_seq": number }`
  - `{ "type": "alert", "code": "KEY_MISSING" | "SHRED_PENDING_CONFIRM" | "CLOCK_SKEW" | "RECOVERY_DRILL_DUE", "details": object }`（UI 常驻提示；`CLOCK_SKEW` 只提示、不影响接收）
- **Unix Domain Socket（`0600`，NDJSON 单行请求-响应）**：
  - CLI 写命令转交（Daemon 运行时）：`{"cmd":"apply","request":<§3.2 REST DTO>}\n` → `{"ok":true,"data":...}\n` 或 `{"ok":false,"error":{...}}\n`（错误码同 §1）；
  - Daemon 未运行时 CLI 直写 SQLite 后，Daemon 启动扫描补推，无需通知；`poke`（`{"cmd":"poke","fast_flush":false}\n` → `{"ok":true}\n`）仅用于 `sync` 以外的唤醒场景；
  - CLI 显式等待同步（`sync push`）：`{"cmd":"sync_now","wait":true}\n` → Daemon 完成本轮 HTTP `push/pull` 后返回 `{"ok":true,"head_seq":120}\n` 或 `{"ok":false,"code":"SYNC_OFFLINE"}\n`；
  - CLI 健康探针：`{"cmd":"ping"}\n` → `{"ok":true,"version":"0.2.0","pid":4821}\n`（版本与 CLI 不一致时 CLI 在 `stderr` 告警）；
  - 壳 / `mynote open` 申请会话票据：`{"cmd":"open_ticket"}\n` → `{"ok":true,"url":"http://localhost:<port>/v1/local/auth/exchange?ticket=..."}\n`。

---

## 4. Cloudflare 云端盲同步中继契约（HTTP + R2 + WebSocket Hibernation）

> 本节只定义 HTTP / WS 的**请求与响应形状**。服务端职责保持极薄（幂等追加、分配 seq、按 seq 分页、epoch、令牌范围、WS 唤醒、密钥表与碎纸标记存储及校验、alarm 置空、每日归档）。合并语义、宽限期与批量阈值规则见 [`sync-protocol.md`](./sync-protocol.md)，DO / R2 / alarm 实现见 [`cloudflare-cloud-architecture.md`](./cloudflare-cloud-architecture.md)。
>
> **单一事实来源划分**：云端 HTTP / WS 的**请求与响应形状**以本节为准；端点的实现（DO 表、事务、alarm、R2 布局）以 [`cloudflare-cloud-architecture.md`](./cloudflare-cloud-architecture.md) 为准；字段的线格式与 AAD 以 [`data-structures.md`](./data-structures.md) 为准。

### 4.1 公共请求约定
- **鉴权头**：`Authorization: Bearer <device_token>`（除静态资源 `/, /assets/*` 与配对认领接口外全部强制校验）。令牌带范围 `scope`：`read`（手机）或 `read-write`（桌面）。`read` 令牌调用任何写端点（push、密钥记录、碎纸标记、状态快照上传）一律返回 `403 TOKEN_SCOPE_FORBIDDEN`；
- **协议版本头**：`X-Mynote-Protocol: 1`；
- **客户端强制防丢规则**：`fetch` 必须设置 `redirect: "manual"`，校验 `status === 200`、`Content-Type` 为 `application/json` 且 `body.ok === true` 后方可推进游标。

### 4.2 核心同步与密钥端点精确 Schema

端点分组：`/v1/sync/*`（op 日志与唤醒）、`/v1/keys*`（密钥表与碎纸标记）、`/v1/snapshots/state`（手机状态快照）、`/v1/archive/*`（只读归档）、`/v1/devices*`（设备与配对）。**不存在任何删除 op 或归档的接口。**

#### (1) `POST /v1/sync/push` — 幂等追加盲操作日志（`read-write`）

```json
// Request (单次上限: ops <= 500 条, 总请求体 <= 4 MiB)
{
  "expected_epoch": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "seen_seq": 104,                                  // 本机已拉取到的最大 seq（碎纸标记竞态校验用）
  "key_records": [ { "key_id": "...", "wrap_gen": 1, "key_record_b64": "..." } ],  // 可选
  "cancel_key_ids": [ "..." ],                      // 可选：撤销碎纸标记（Update-Wins 复活）
  "shred_marks": [ { "mark_id": "...", "key_id": "...", "not_before_ms": 1796126400000, "requested_by": "dev_..." } ],  // 可选
  "ops": [
    { "op_id": "01JDF910...", "key_id": "...", "envelope_b64": "..." }  // key_id 明文；无 BDEK 的 op 为 16 个零字节
  ]
}

// Response 200 OK (当 expected_epoch 匹配时)
{
  "ok": true,
  "epoch": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "acked": [ { "op_id": "01JDF910...", "seq": 105 } ],
  "head_seq": 105
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

- `op_id` 字段与信封头中的 `op_id` 必须一致（由 core 生成，§0）。重复 `op_id` 幂等返回原 `seq`。
- **同批原子提交，顺序固定为「密钥记录 → 撤销 → 碎纸标记 → op」**：服务端在一个 DO 事务内按此顺序校验并写入，任一项失败则整批回滚、不分配 `seq`。因此同批新建的密钥可被同批 op 引用，任何拉到该 op 的设备都必然能在 `/v1/keys` 中找到对应密钥。
- **服务端竞态校验**（规则见 [`sync-protocol.md`](./sync-protocol.md) §5.6）。失败时整批返回 `409`，`error.details` 带出问题 `key_id`：
  - `SHRED_STALE`：新标记的 `key_id` 下存在 `seq > seen_seq` 的 op，客户端须先 pull、重新评估；
  - `KEY_PENDING_SHRED`：op 引用的 `key_id` 有 `pending_confirm` / `scheduled` 标记，且同批未先撤销；
  - `KEY_SHREDDED` / `KEY_UNKNOWN`：op 引用已执行碎纸或服务端不认识的 `key_id`（`KEY_SHREDDED` 返回 `410`）。
- 单独的 `/v1/keys*` 端点（(3)）用于不伴随 op 的密钥与标记操作，校验规则相同。

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
- `keys_digest` 与本地密钥表摘要不同时，客户端调用 `GET /v1/keys` 全量比对。

#### (3) `/v1/keys*` — 密钥表与碎纸标记
| 方法与路径 | 范围 | 请求 → 响应 |
| --- | --- | --- |
| `GET /v1/keys` | `read` | → `{ ok, key_records: [{ key_id, wrap_gen, key_record_b64 \| null, created_at_ms }], shred_marks: [{ mark_id, key_id, not_before_ms \| null, requested_by, state, confirmed_at_ms \| null }], digest }`（体量 ≈ 块数 × 250 B [估算]）。`block_id` 与 `tier` 只在 `MNR1` 密文（`key_record_b64`）内，**服务端不可见**。已执行碎纸的记录 `key_record_b64 = null`，客户端据此删除本地密钥与物化明文。合并规则（2P-Set）见 [`sync-protocol.md`](./sync-protocol.md) |
| `POST /v1/keys` | `read-write` | `{ key_records: [...] }` → `{ ok, acked_key_ids }`。只创建、不修改：同一 `key_id` 内容不同的重复提交返回 `INTEGRITY_ERROR`，内容相同则幂等 |
| `POST /v1/keys/shred` | `read-write` | `{ seen_seq, marks: [{ mark_id, key_id, not_before_ms, requested_by }] }` → `{ ok, results: [{ key_id, state: "scheduled" \| "pending_confirm", not_before_ms \| null }] }`。任一 `not_before_ms < now + T_grace_min` → 整个请求 `422 GRACE_TOO_SHORT`（不落库）。当日超出批量阈值（20 块）的部分 `state = "pending_confirm"`，不计时。视图过期 → `409 SHRED_STALE` |
| `POST /v1/keys/cancel` | `read-write` | `{ key_ids }` → `{ ok, cancelled }`。用于 `trash restore` 和 Update-Wins 复活；已到期置空的 `key_id` → `410 KEY_SHREDDED` |
| `POST /v1/keys/confirm` | `read-write` | `{ key_ids, not_before_ms }` → `{ ok, results }`。把 `pending_confirm` 转为 `scheduled`，从确认时刻开始计时（同样受 `T_grace_min` 约束）。只由桌面 UI 的 `trash/actions/commit` 发起，见 §3.2 |

#### (4) `/v1/snapshots/state` — 手机状态快照
- **`PUT /v1/snapshots/state`**（`read-write`，由任一桌面发布）：
  - 请求头：`Content-Type: application/octet-stream`、`X-Journal-Epoch`、`X-Covers-Seq`；请求体为加密的状态快照（格式见 [`data-structures.md`](./data-structures.md)）；
  - 服务端只接受 `covers_seq` 大于当前最新快照的上传（否则返回 `409 CAS_MISMATCH`，客户端丢弃），R2 只保留最近 2 份。无 `prev_snapshot_id` CAS。
- **`GET /v1/snapshots/state`**（`read`）：返回最新快照字节，元数据在响应头 `X-Covers-Seq`；手机随后从 `covers_seq` 起调用 (2) 拉取尾部 op。

#### (5) `/v1/archive/*` — 只读归档（供 `mynote restore --from-archive`）
- `GET /v1/archive/index` → `{ ok, op_days: ["2026-11-24", ...], key_snapshots: [{ id, taken_at_ms }] }`；
- `GET /v1/archive/ops/:day` → 当日 op 密文归档（只追加，永久保留）；
- `GET /v1/archive/keys/:id|latest` → 密钥表快照（由 R2 生命周期规则在 `T_snap` = 30 天后删除）。
- 只有 `GET`，没有任何写或删除接口（归档由 DO alarm 每日写入，见 [`cloudflare-cloud-architecture.md`](./cloudflare-cloud-architecture.md)）。零设备时的访问凭据也在该文档定义。

#### (6) `/v1/devices*` — 设备与一次性领取配对
- **`POST /v1/devices`**（`read-write`）：`{ "device_name": "iPhone", "scope": "read", "sealed_keyring_b64": "..." }` → `{ ok, device_id, pair_id, expires_at_ms }`。
  - `sealed_keyring_b64` 是桌面用一次性包裹密钥 `K_pair` 加密的 SMK 密钥环。
  - 服务端暂存「加密密钥环 + 新签发的 `device_token`」，**TTL 10 分钟** [保证：到期删除]。
- **配对码**（由 `mynote device add` 在终端输出，粘贴或扫码）只包含 `{ server_url, pair_id, K_pair }`。服务端从不接触 `K_pair`，所以 **SMK 对服务端零知识**。配对码格式见 [`threat-model.md`](./threat-model.md)。
- **`POST /v1/devices/pair-claim`**（无需鉴权，凭 128 位随机 `pair_id`）：`{ "pair_id": "..." }` → `{ ok, device_id, device_token, scope, sealed_keyring_b64 }`。**首次领取即删除**暂存记录，再次领取或过期返回 `404 NOT_FOUND`。手机在 PWA 本地用 `K_pair` 解开密钥环。
- **`GET /v1/devices`** / **`DELETE /v1/devices/:id`**（`read-write`）：列出 / 吊销设备。`read` 令牌不能发起配对（`403 TOKEN_SCOPE_FORBIDDEN`）。
- **领取失败的处理**：合法设备领取时若得到 `404`（可能已被他人抢先领取），PWA 提示用户在桌面执行 `mynote device ls` 核对并 `mynote device revoke` 可疑设备，然后重新配对（残余风险见 [`threat-model.md`](./threat-model.md)）。

#### (7) `GET /v1/sync/ws`（WebSocket Hibernation 帧）
- 客户端应用层心跳文本帧：`"ping"` → Cloudflare 边缘自动零唤醒回复 `"pong"`；
- 服务端只发唤醒通知，**不携带 op**：`{ "type": "wake", "epoch": "...", "head_seq": 110 }`，客户端发现 `head_seq > local_seq` 即调用 (2)；密钥表变化由 pull 响应中的 `keys_digest` 发现；
- 设备被吊销通知：`{ "type": "device_revoked" }`（随即服务端以 Close Code `4401` 断开连接）。

---

## 5. `mynote-wasm` TypeScript ↔ Rust WASM 边界契约

由于 JavaScript GC 堆中的字符串与普通对象无法确定性清零内存，`crates/mynote-wasm` 采用 **不透明会话句柄（Opaque Session Handle）** 将解锁后的敏感主密钥 `VKEK` 严格锁在 Rust WASM 线性内存的 `Zeroizing<[u8; 32]>` 结构内。桌面 UI 与手机 PWA 共用同一会话 API（D7）；VKEK 永不写入 IndexedDB / Cache Storage。

`op_id` 由 WASM 内的 core 在加密前生成并封装进 `sealedOp`（§0）。所有函数都**不接受** `opId` 参数，AAD 的构造与校验完全在 Rust 内部完成（唯一定义见 [`data-structures.md`](./data-structures.md)）。

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

/** sealedOp：完整 op 信封字节（头部含 op_id / block_id / key_id / parents），可直接作为 sealed_op_b64 提交 */
interface SealedOpBundle {
  sealedOp: Uint8Array;
  opId: string;           // 仅供展示与日志，提交时不单独传
  blockId: string;
  keyId: string;
  blockKeyRecordJson?: string; // 新建 DEK 时返回，需随请求提交
}

/**
 * 驻留于 WASM 线性内存的 Tier 2 保险库解锁会话。
 * JS 层仅持有指针句柄，永远拿不到裸 VKEK 字节；调用 lock() 或释放时由 Rust Drop 执行确定性 zeroize。
 */
export class WasmVaultSession {
  /** 通过 Vault 口令 + Argon2id（单套参数，读自 Vault 头部）解开 VKEK 创建会话 */
  static unlockWithPassphrase(passphrase: string, vaultHeaderJson: string): WasmVaultSession;

  /** 新建加密块：随机生成 DEK 并用 VKEK 包裹，生成 op_id 后加密 */
  encryptNewBlock(ctxJson: string, content: string, lang: string): SealedOpBundle;

  /** 更新 / 合并已有加密块：解包该块 DEK，生成 op_id，用新随机 Nonce 重新加密为全量载荷 op */
  encryptUpdate(ctxJson: string, blockKeyRecordJson: string, content: string, lang: string): SealedOpBundle;

  /** 换钥加锁：为明文块生成新的 VKEK 包裹 DEK 并产出 LOCK op（旧 Tier 1 key 的碎纸由 Daemon 在服务端确认后登记） */
  rekeyToVault(ctxJson: string, content: string, lang: string): SealedOpBundle;

  /** 解密：op_id / block_id / key_id 从信封头读取并参与 AAD 校验；仅返回渲染所需的明文结果 */
  decryptBlock(sealedOp: Uint8Array, blockKeyRecordJson: string): DecryptedBlockPayload;

  /** 立即触发 Rust Zeroize 擦除 WASM 线性内存中的 VKEK 并使句柄失效（闲置 N 分钟或 visibilitychange 必调） */
  lockAndZeroize(): void;
  free(): void;
}

/**
 * 供移动端只读 PWA 使用的 Sans-I/O 同步与 Tier 1 解密桥接器（D1：只读，不产生任何写 op）
 */
export class WasmSyncEngine {
  constructor(deviceId: string, smkKeyring: Uint8Array);

  /** 执行状态机单步演进：输入当前轻量索引与事件 JSON，返回 { storeMutations, syncCommands }（syncCommands 只含 pull / 拉密钥表 / 拉快照） */
  step(engineStateJson: string, syncEventJson: string): StepOutput;

  /** 解包手机状态快照（每块全部叶子版本 + 字段 LWW 结果 + covers_seq） */
  unpackStateSnapshot(snapshotBytes: Uint8Array): UnpackedStateSnapshot;

  /** 显式清零 WASM 内存中的 SMK 密钥环 */
  zeroizeSmk(): void;
  free(): void;
}

/** Layer 1 毫秒级纯离线格式化与结构转换（桌面加密块格式化亦必须走此函数，严禁外发 CLI 子进程！） */
export function formatSnippet(content: string, lang: string, action?: string): string;

/** 本地粘贴内容高危凭据特征快速扫描（返回命中的特征类型如 "aws_access_key" | "pem_private_key" | null） */
export function detectSecretPattern(pastedText: string): string | null;
```

---

## 6. 已移除 / 推迟的机制（2026-11-24）

依据 [第一性原理审查](../review/2026-11-24-first-principles-review.md)：

- **`mynote update` / `self-update` 自升级子系统**（Provenance Guard、Ed25519 签名清单、防降级、原子替换、`update --rollback`、Daemon 热交接 `prepare_restart` / `daemon_restarting`、错误码 `PACKAGE_MANAGER_MANAGED`）：已移除，分发交给包管理器，只保留迁移前 `VACUUM INTO`（F-14、§9.6、§9.11）。
- **`vault shred` 与 `POST /blocks/:id/shred`、错误码 `VAULT_KEY_SHREDDED`**：已移除，由通用的「回收站 + 受控碎纸 + 换钥」取代，错误码改为 `KEY_SHREDDED`（§9.3、§9.7）。
- **加锁时的 `purge_op_ids` 与本地明文历史即时擦除**：已移除，op 密文永不删除，历史通过换钥加碎纸、在宽限期后变得不可读（§9.3）。
- **`vault_keys` / `vault_key_slots` keystore 端点、`key_mutations`、`MNK1`、`key_seq` / `key_since`**：已移除，由只创建的密钥表 + 碎纸标记（2P-Set）全量比对取代（§9.3）。
- **`clip push/pull` 与 `/v1/sync/ephemeral-clip` 瞬态加密剪贴板**：已移除，由手机端复制按钮取代（D1，§9.2）。
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
