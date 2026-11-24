# 全链路接口与跨边界契约规范 (`interface-contracts.md`)

> 本文档与 [数据结构规范 (`data-structures.md`)](./data-structures.md)、[同步协议规范 (`sync-protocol.md`)](./sync-protocol.md)、[威胁模型规范 (`threat-model.md`)](./threat-model.md) 共同构成编码级契约基准，精确定义 **统一错误码表、Agent-Native CLI 契约、本地 Daemon REST/WS/UDS 契约、Cloudflare 云端同步 API 契约，以及 `mynote-wasm` 前后端 FFI 接口**。

---

## 目录

1. [全局错误码注册表与跨层映射契约](#1-全局错误码注册表与跨层映射契约)
2. [Agent-Native CLI 命令、JSON 信封与外部格式化契约](#2-agent-native-cli-命令json-信封与外部格式化契约)
3. [本地桌面 Daemon 契约（HTTP + WebSocket + Unix Socket IPC）](#3-本地桌面-daemon-契约http--websocket--unix-socket-ipc)
4. [Cloudflare 云端盲同步中继契约（HTTP + R2 + WebSocket Hibernation）](#4-cloudflare-云端盲同步中继契约http--r2--websocket-hibernation)
5. [`mynote-wasm` TypeScript ↔ Rust WASM 边界契约](#5-mynote-wasm-typescript--rust-wasm-边界契约)

---

## 1. 全局错误码注册表与跨层映射契约

所有子系统共享同一套机器可读错误码枚举（`ErrorCode`），确保 CLI、本地 Daemon 与云端 Worker 的错误处理、重试判定与 Agent 自愈提示（`hint`）完全一致：

| 稳定错误码 `error.code` | CLI 退出码 | HTTP 状态码 | `retryable` | 触发条件与强制 `hint` 模板规范 |
| --- | :---: | :---: | :---: | --- |
| *(成功)* | `0` | `200 / 201` | — | 含断网/无 Daemon 时本地落盘成功的常规写命令（`meta.sync_state = "pending_offline"`） |
| `INVALID_ARGUMENT` | `2` | `400` | `false` | 参数缺失/格式非法；提示运行 `mynote <cmd> --help` |
| `EMPTY_STDIN_REFUSED` | `2` | `400` | `false` | 非交互 `stdin` 为 0 字节但目标块非空；`hint: "Pass --allow-empty to clear content, or use 'mynote block delete <id>'"` |
| `INTERACTION_REQUIRED` | `2` | `400` | `false` | 非 TTY / `--non-interactive` 下请求了需人工确认的操作（如未带 `--yes` 执行 `mynote update`） |
| `PACKAGE_MANAGER_MANAGED` | `2` | `400` | `false` | 当前二进制由系统包管理器托管；`hint` 按探测渠道精确给出 `'brew upgrade mynote'` 或 `'paru -Syu mynote-bin'` |
| `NOT_FOUND` | `3` | `404` | `false` | 指定 `BufferId`、`BlockId`、`SnapshotId`、目标发布版本号或本地可回滚备份 `mynote.prev` 不存在 |
| `HEAD_MISMATCH` | `4` | `409` | `true` | `--expected-head` 与当前 `head_op_id` 不一致；响应 `details.actual_head` 并提示先 `block get` 再重试 |
| `CAS_MISMATCH` | `4` | `409` | `true` | 上传快照 `prev_snapshot_id` 过期或 `covers_seq` 未递增；拉取最新元数据后重试 |
| `BLOCK_LOCKED` | `5` | `423` | `false` | 未解锁访问 `is_locked = 1` 的加密块或非 TTY 请求解锁 |
| `VAULT_KEY_SHREDDED` | `5` | `410` | `false` | 目标加密块的 `kid` 已被物理销毁（Crypto-Shredded），永久不可恢复 |
| `AUTH_REQUIRED` / `DEVICE_REVOKED` | `5` | `401 / 403` | `false` | 本地 Cookie / Origin 校验失败，或云端 `device_token` 无效/已被吊销 |
| `SYNC_OFFLINE` | `6` | `502 / 503` | `true` | **仅用于显式联网阻塞命令**（`sync push/pull`、`clip push --wait-sync`、`update`）无法连通远端 |
| `RATE_LIMITED` | `6` | `429` | `true` | 云端或发布源限流；按 `Retry-After` 退避 |
| `FORMAT_SYNTAX_ERROR` | `7` | `422` | `false` | Layer 1/2 格式化输入语法错误或外部命令返回 0 字节/超时；原块保持未修改 |
| `INTEGRITY_ERROR` | `8` | `422 / 500` | `false` | AEAD 解密失败、快照/`SPAN_PATCH` `BLAKE3` 失配、`update` 发布包 Ed25519 签名/哈希/防降级校验失败，或本地库 `min_reader_schema_version` 高于旧版二进制（`SCHEMA_TOO_NEW`） |

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
    details?: Record<string, unknown>; // 如 HEAD_MISMATCH 时附带 { expected_head, actual_head }
  } | null;
  meta: {
    local_op_count_pending: number;
    sync_state: "synced" | "syncing" | "pending_offline" | "unconfigured" | "conflict_present";
    redacted_locked_count?: number;
    duration_ms: number;
  };
}
```

### 2.2 核心 DTO 结构契约

1. **列表与搜索摘要项（`mynote ls --json` / `mynote search <q> --json`，默认 `--limit 20`）**：
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
     "head_op_id": "01JDF910A2B3C4D5E6F7G8H9J0",
     "has_conflict": false,
     "byte_size": 18420,
     "preview": "{\n  \"status\": 200,\n  \"items\": [ ... (truncated to 240 chars)",
     "actor": "human",
     "updated_at_ms": 1795521600123
   }
   ```
   *若 `is_locked == true`：强制返回 `"redacted": true, "byte_size": null, "preview": null`，仅保留 `id`、`buffer_id`、`position`、`is_locked`、`public_hint` 与 `updated_at_ms`。*

2. **单块完整读取（`mynote block get <id> --json`）**：
   - 未加锁块返回完整 `content: string` 与 `conflict_siblings: Array<{ head_op_id, hlc, device_id, actor, content }>`；
   - `mynote block get <id> --raw`（不带 `--json`）直接向 `stdout` 写出无尾随装饰的原始 `content` 字节，便于 `mynote block get <id> --raw | jq .` 管道直连；若目标块已加锁则 `stdout` 为空、退出码 `5`。

### 2.3 全子命令矩阵与关键参数契约

| 命令 | 核心参数与管道契约 | 幂等与乐观锁要求 |
| --- | --- | --- |
| `mynote add [text]` | 无位置参数时读 `stdin`；`--buf <name\|id>`（默认 `"scratch"`）、`--lang <lang>`（默认自动嗅探 JSON/SQL/Markdown 或 `"text"`）、`--format`、`--after <block_id>` | 支持 `--idempotency-key <key>` |
| `mynote block get <id>` | `--raw`（纯正文流）、`--max-chars <N>`、`--decrypt`（仅允许真实 `/dev/tty` 交互口令） | 只读 |
| `mynote block update <id> [text]` | 读参数或 `stdin`；非 TTY 空输入默认报 `EMPTY_STDIN_REFUSED`（除非 `--allow-empty`） | **强制要求** `--expected-head <op_id>`（人工终端可传 `--force`） |
| `mynote block append <id> [text]` | 在原块末尾追加文本并生成新 `op` | 支持 `--expected-head <op_id>` |
| `mynote block move <id>` | `--to-buf <buf>`、`--after <id>` / `--before <id>`（仅发 `SET_META`） | LWW 幂等 |
| `mynote block resolve <id>` | `--keep <head_op_id>` 或从 `stdin` 读入合并全文收敛全部并发叶子 | 校验当前并发叶子集合 |
| `mynote block history <id>` / `restore <id>` | `--to-op <op_id>` 或 `--undo-actor <actor>` | 生成新 `UPDATE` 操作，不篡改历史 |
| `mynote block delete <id>` | 软删除墓碑；支持 `--dry-run` | 支持 `--expected-head <op_id>` |
| `mynote clip push` / `clip pull` | `push` 默认读系统剪贴板或 `stdin`，支持 `--lock`、`--ephemeral`、`--ttl <sec>`、`--wait-sync` | `push --wait-sync` 离线返回 `6` |
| `mynote format [id]` | 传 `<id>` 原地格式化该块（需 `--expected-head`）；不传 `<id>` 作为纯流过滤器格式化 `stdin -> stdout`（`--lang`、`--action unescape-json\|to-yaml\|...`） | 语法错误退出码 `7` 且零副作用 |
| `mynote vault <init\|lock\|unlock\|shred\|passwd>` | `lock <id> [--hint "..."]` 触发本地 WAL 截断与云端 `purge_op_ids`；`shred <id> --yes` 物理删除 `kid` | 客户端短进程内存执行 |
| `mynote sync <status\|push\|pull\|rotate-smk>` | 显式触发同步对账或轮换 `SMK` | 断网返回退出码 `6` |
| `mynote device <add\|ls\|revoke>` | `add --name <label>` 终端输出 60 秒 `#pair=` 二维码 | 管理鉴权 |
| `mynote import heynote <path>` | `--buf <name>`、`--dry-run` | 文件哈希防重复提示 |
| `mynote update`（别名 `self-update`） | `--check`（纯只读查询）、`--version <semver>`、`--rollback`（秒级回退上一版）、`--yes`、`--no-restart-daemon`、`--dry-run`（生产构建**严禁暴露自定义 `--url` 参数**防注入劫持） | 离线签名校验 + 同文件系统原子 `rename`；包管理器托管环境返回 `2`（`PACKAGE_MANAGER_MANAGED`） |

### 2.4 `--help-json` 机读反射契约与 Layer 2 `formatters.toml` 规范

- `mynote <subcommand> --help-json` 输出固定结构：`{ command, about, args: [{ name, flag, value_type, required, default, enum_values, description }], stdin_mode, exit_codes: Record<number, string>, response_schema }`。
- `~/.config/mynote/formatters.toml` 契约：
  - 子进程在无网络/受限环境变量下通过 `stdin` 喂入原块 UTF-8 字节，在 `timeout_ms`（默认 `2000 ms`）内等待退出；
  - **熔断条件**：`exit_code != 0`、超时杀死、输出非合法 UTF-8，或 **`input.len() > 0 && stdout.is_empty()`** 时一律返回 `FORMAT_SYNTAX_ERROR`（退出码 `7`），绝不写回数据库。

### 2.5 CLI 自升级、包管理器探测与原子回滚协议（`mynote update`）

为保证日常 CLI 命令维持 `< 15 ms` 零网络开销，**`mynote` 绝不在后台静默联网检查更新或上报遥测**，仅在用户显式运行 `mynote update`（或 `mynote self-update`）时按以下严格契约执行：

1. **安装渠道自动探测与包管理器防冲突护栏（Provenance Guard）**：
   - 启动时解析 `std::env::current_exe()?.canonicalize()` 并结合编译期注入常量 `MYNOTE_BUILD_CHANNEL`（`"standalone" | "homebrew" | "aur" | "nix"`）：
     - **`homebrew`**（路径位于 `/opt/homebrew/Cellar/` 或 `/usr/local/Cellar/`）：`--check` 正常展示远端新版本；执行升级时拒绝覆盖只读 Cellar 文件，返回退出码 `2`（`PACKAGE_MANAGER_MANAGED`），`hint: "Installed via Homebrew; run 'brew upgrade mynote'"`；
     - **`aur` / `pacman`**（Omarchy / Arch 下路径位于 `/usr/bin/mynote` 或系统 `root` 属主目录）：拒绝提权或破坏 `pacman -Qkk` 校验库，返回退出码 `2`，`hint: "Installed via pacman/AUR; run 'paru -Syu mynote-bin' or 'yay -Syu mynote-bin'"`；
     - **`nix`**（路径位于 `/nix/store/`）：返回退出码 `2`，`hint: "Installed via Nix; run 'nix profile upgrade mynote' or update your flake"`；
     - **`standalone`**（用户态可写独立二进制，如 `~/.local/bin/mynote`）：无需 `sudo`，执行原生离线签名验证与原子自替换。

2. **离线公钥签名清单（`release-manifest.json` + `.sig`）契约**：
   - 官方 GitHub Releases 每次发版同步产出 `release-manifest.json` 与脱离 CI 在线的维护者硬件密钥签名文件 `release-manifest.json.sig`（`Ed25519` 原始 64B 签名，签名域前缀 `"mynote-release-v1\0" || canonical_manifest_bytes`）：
     ```json
     {
       "schema_version": 1,
       "version": "0.2.0",
       "published_at_ms": 1798000000000,
       "min_downgrade_version": "0.1.0",
       "min_reader_schema_version": 1,
       "targets": {
         "aarch64-apple-darwin": {
           "url": "https://github.com/gray0128/my-note/releases/download/v0.2.0/mynote-v0.2.0-aarch64-apple-darwin.tar.zst",
           "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
           "blake3": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
           "byte_size": 9437184
         },
         "x86_64-unknown-linux-musl": { "...": "..." },
         "aarch64-unknown-linux-musl": { "...": "..." }
       }
     }
     ```
   - **先验签哈希、后解压自检原则（防解压器内存漏洞与降级攻击）**：
     1. 用编译期焊死在二进制 `.rodata` 段的 `Ed25519` 公钥验证 `release-manifest.json.sig`；
     2. 默认强制校验 `manifest.version > current_version` 且 `published_at_ms >= COMPILED_BUILD_TIMESTAMP_MS`（若已经是最新版则退出码 `0` 返回 `up_to_date: true`；若显式指定旧版 `--version` 但未传 `--allow-downgrade`，返回退出码 `8` `INTEGRITY_ERROR` 防中间人冻结/降级投毒）；
     3. 通过 `rustls`（仅允许硬编码发布域名白名单，上限 `32 MiB`）流式下载归档至与目标可执行文件**同一挂载分区**的临时文件 `<exe_dir>/.mynote.stage.<pid>.<rand>`，**在调用 `zstd` 解压前**强制比对精确 `byte_size`、`SHA-256` 与 `BLAKE3`；
     4. 解包提取单文件二进制后赋予 `0755`，在清空环境变量的受限子进程内执行 `<stage_bin> --version --json`（超时 `2000 ms`），确认新二进制在当前宿主机 CPU/内核上可正常冷启动且输出版本号与清单严格一致。

3. **同文件系统 POSIX 原子替换、一键 `--rollback` 与守护进程热交接**：
   - **备份上一已知完好版本**：将当前可执行文件硬链接/原子拷贝至 `~/.local/share/mynote/bin/mynote.prev`，同步写入元数据 `mynote.prev.json`（含 `version`、`blake3`、升级前 SQLite `user_version`）；
   - **跨 Schema 迁移前自动数据库快照**：若新版本包含 SQLite `PRAGMA user_version` 升级，新进程首次打开数据库执行迁移前，必须在独占写事务前通过 `VACUUM INTO` 生成权限 `0600` 的只读快照 `~/.local/share/mynote/backups/mynote-pre-schema-v<old>.db`；
   - **POSIX 原子替换**：`fsync(stage_bin)` → `rename(stage_bin_path, current_exe_path)` → `fsync(exe_parent_dir)`（Linux/macOS 下 `rename(2)` 原子替换目录项而不破坏旧 `mynote daemon` 正在映射执行的 inode，彻底杜绝 `ETXTBSY`）；
   - **本地 Daemon 优雅排空重启**：若检测到 `daemon.sock` 存活且未传 `--no-restart-daemon`，发送 `prepare_restart` 指令排空出站队列并通知前端 WebSocket 平滑重连，随后按托管方式触发重启（Linux `systemctl --user restart mynote` / macOS `launchctl kickstart -k gui/$UID/com.mynote.daemon` / 独立守护进程自 `execv`）；
   - **秒级回滚（`mynote update --rollback`）**：校验 `mynote.prev` 的 `BLAKE3` 与当前数据库 `local_meta.min_reader_schema_version` 兼容性后原子换回旧二进制并重启 Daemon（若回滚跨越了不向后兼容的数据库 Schema 升级，唯有确认升级后无未同步新笔记或已将新库另存为 `.post-rollback-saved.db` 后才恢复升级前数据库备份，保证**回滚零丢数**）。
   - **`mynote update [--check|--rollback] --json` 响应 `data` 结构**：
     ```json
     {
       "action": "check" | "upgrade" | "rollback" | "noop_up_to_date",
       "current_version": "0.1.0",
       "target_version": "0.2.0",
       "install_method": "standalone" | "homebrew" | "aur" | "nix",
       "binary_path": "/home/dev/.local/bin/mynote",
       "rollback_available": true,
       "daemon_restarted": true
     }
     ```

---

## 3. 本地桌面 Daemon 契约（HTTP + WebSocket + Unix Socket IPC）

### 3.1 安全握手中介层契约（`127.0.0.1:<port>`）

1. **请求头强拦截**：
   - `Host` 必须精确匹配 `127.0.0.1:<port>` 或 `localhost:<port>`（否则 `403`）；
   - 除首次 `GET /v1/local/auth/exchange` 外，所有 `/v1/local/*` 请求与 WebSocket 握手必须携带 `Cookie: mynote_local_session=<64hex>`，且所有非 `GET` 请求及 `/v1/local/ws` 必须携带匹配的 `Origin: http://127.0.0.1:<port>`（或 `localhost`）。
2. **一次性会话置换**：
   - `mynote open` 生成单次有效（有效期 10 秒）的随机 `ticket` 写入 Daemon 内存表，拉起浏览器访问 `http://127.0.0.1:<port>/v1/local/auth/exchange?ticket=<ticket>`；
   - Daemon 校验并立即销毁 `ticket`，返回 `303 See Other`、`Location: /` 与 `Set-Cookie: mynote_local_session=<session_token>; HttpOnly; SameSite=Strict; Path=/`。

### 3.2 本地 REST API 端点契约（Daemon 对 Tier 2 严格零明文！）

| 方法与路径 | 请求体 / 参数 | 响应体与关键安全不变量 |
| --- | --- | --- |
| `GET /v1/local/bootstrap` | 无 | `{ buffers, initial_buffer_id, blocks, sync_status, vault_slots }`（一步完成首屏渲染） |
| `POST / PATCH / DELETE /v1/local/buffers[/:id]` | `{ name?, after_id?, before_id? }` | 返回更新后的 `BufferDto` |
| `GET /v1/local/blocks?buffer_id=<id>` | 查询参数 | 返回按 `(position, id)` 排好序的 `BlockDto[]`（含 `conflict_siblings`；加锁块仅含 `kid`、`public_hint`、`tier2_envelope_b64`，`content: null`） |
| `POST /v1/local/blocks` | 明文块：`{ buffer_id, lang, content, after_id? }`<br>直接新建加密块：`{ buffer_id, after_id?, locked: { kid, public_hint?, tier2_envelope_b64, vault_key_record } }` | 原子写库并异步触发同步，返回 `BlockDto` |
| `PATCH /v1/local/blocks/:id` | `{ expected_head, content?, lang?, after_id?, before_id?, buffer_id?, locked_update?: { kid, public_hint?, tier2_envelope_b64 } }` | 若 `expected_head` 失配返回 `409 HEAD_MISMATCH`；**Daemon 从不接收加密块的明文或 `VKEK`** |
| `POST /v1/local/blocks/:id/lock` | `{ expected_head, kid, public_hint?, tier2_envelope_b64, vault_key_record }` | **触发事后加锁擦除协议**：同事务擦除本地明文历史、merge FTS5、执行 `wal_checkpoint(TRUNCATE)`，并将该块历史 `op_id` 列入下次云端 `push.purge_op_ids` |
| `POST /v1/local/blocks/:id/unlock` | `{ expected_head, plaintext_content, lang, shred_old_kid: boolean }` | 用户在前端 WASM 解密后显式解除锁定时调用 |
| `POST /v1/local/blocks/:id/shred` | `{ kid }` | 软删除块、物理置 `vault_keys` 为 `SHREDDED`（抹空 `wrapped_dek`）并同步上云 |
| `POST /v1/local/blocks/:id/resolve` | `{ parent_heads: string[], content?: string, tier2_envelope_b64?: string }` | 生成多父节点 `RESOLVE` 收敛冲突分支 |
| `GET /v1/local/blocks/:id/history` | `?limit=50` | 返回历史版本元数据及可重建快照列表 |
| `POST /v1/local/format` | `{ content, lang, action? }` | 调用内置 Layer 1 或外部 Layer 2 管线，返回 `{ formatted }`（**严禁把处于解锁态的加密块发给外部 CLI 子进程！加密块格式化仅允许在前端 `mynote-wasm` Layer 1 内纯内存完成**） |
| `GET / PUT /v1/local/vault/keystore` | 读取或更新 `vault_key_slots` 与 `vault_keys` 密文包裹记录 | 仅传递包裹后的密文字节 |

### 3.3 本地 WebSocket（`/v1/local/ws`）与 Unix Socket（`daemon.sock`）协议

- **`/v1/local/ws` 服务端推送帧（JSON）**：
  - `{ "type": "blocks_changed", "upserted": BlockDto[], "deleted_ids": string[] }`
  - `{ "type": "buffers_changed", "upserted": BufferDto[], "deleted_ids": string[] }`
  - `{ "type": "sync_status", "state": "synced" | "syncing" | "pending_offline" | "conflict_present", "last_seq": number }`
  - `{ "type": "daemon_restarting", "new_version": string }`（`mynote update` 热交接前广播，前端保持未保存编辑状态并执行无抖动指数退避重连与静态资源刷新）
- **Unix Domain Socket（`0600`，NDJSON 单行请求-响应）**：
  - CLI 写入后非阻塞通知：`{"cmd":"poke","fast_flush":false}\n` → Daemon 立即返回 `{"ok":true}\n`；
  - CLI 显式等待同步（`sync push` / `clip push --wait-sync`）：`{"cmd":"sync_now","wait":true}\n` → Daemon 完成本轮 HTTP `push/pull` 后返回 `{"ok":true,"head_seq":120}\n` 或 `{"ok":false,"code":"SYNC_OFFLINE"}\n`；
  - CLI 升级/健康探针：`{"cmd":"ping"}\n` → `{"ok":true,"version":"0.2.0","pid":4821}\n`；
  - CLI 自升级排空准备：`{"cmd":"prepare_restart","new_version":"0.2.0","drain_timeout_ms":3000}\n` → Daemon 广播 `daemon_restarting`、刷完在途同步批并执行 `PRAGMA wal_checkpoint(PASSIVE)` 后返回 `{"ok":true,"supervisor":"systemd"|"launchd"|"self"}\n`。

---

## 4. Cloudflare 云端盲同步中继契约（HTTP + R2 + WebSocket Hibernation）

### 4.1 公共请求约定
- **鉴权头**：`Authorization: Bearer <device_token>`（除静态资源 `/, /assets/*` 与配对认领接口外全部强制校验）；
- **协议版本头**：`X-Mynote-Protocol: 1`；
- **客户端强制防丢规则**：`fetch` 必须设置 `redirect: "manual"`，校验 `status === 200`、`Content-Type` 为 `application/json` 且 `body.ok === true` 后方可推进游标。

### 4.2 核心同步与密钥端点精确 Schema

#### (1) `POST /v1/sync/push` — 原子追加盲操作日志、同步可变密钥与事后墓碑擦除
将 `ops`、`vault_key_records` 变更与 `purge_op_ids` 放在同一个 DO `transactionSync` 事务内提交，**从协议上根除「另一端拉到了 `LOCK` 操作却还没拉到对应 `kid` 包裹密钥」的竞态窗口**：

```json
// Request (单次上限: ops <= 500 条, 总请求体 <= 4 MiB)
{
  "expected_epoch": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "ops": [
    { "op_id": "01JDF910...", "envelope_b64": "TU5TMQE..." }
  ],
  "purge_op_ids": ["01JDF899..."],
  "key_mutations": [
    {
      "record_id": "key:01JDF90Z...",
      "state": "ACTIVE",
      "mnk1_envelope_b64": "TU5LMQE..."
    }
  ]
}

// Response 200 OK (当 expected_epoch 匹配时)
{
  "ok": true,
  "epoch": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "acked": [
    { "op_id": "01JDF910...", "seq": 105 }
  ],
  "acked_keys": [
    { "record_id": "key:01JDF90Z...", "key_seq": 12 }
  ],
  "head_seq": 105,
  "head_key_seq": 12
}

// Response 409 Conflict (当 expected_epoch 不匹配，例如刚执行过 PITR 回滚时)
{
  "ok": false,
  "error": {
    "code": "CAS_MISMATCH",
    "message": "Journal epoch changed; run Set-Union reconciliation before pushing",
    "details": { "remote_epoch": "9c8b7a65-...", "head_seq": 88, "head_key_seq": 10 }
  }
}
```

#### (2) `GET /v1/sync/pull?since=<seq>&key_since=<key_seq>&limit=<1..500>` — 增量拉取与水位推进
```json
// 正常增量响应 200 OK
{
  "ok": true,
  "epoch": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "requires_snapshot_bootstrap": false,
  "ops": [
    {
      "seq": 105,
      "op_id": "01JDF910...",
      "device_id": "dev_01jdf8...",
      "created_at": 1795521600123,
      "envelope_b64": "TU5TMQE..." // 若已被事后加锁擦除则为 null
    }
  ],
  "key_changes": [
    {
      "key_seq": 13,
      "record_id": "key:01JDF800...",
      "state": "SHREDDED",
      "mnk1_envelope_b64": null,   // 客户端收到 SHREDDED 后立即从本地库物理删除该 kid！
      "updated_at_ms": 1795521700000
    }
  ],
  "head_seq": 105,
  "head_key_seq": 13,
  "has_more": false
}

// 慢设备游标低于 DO 30 天滑动窗口保留下限时的引导响应 200 OK
{
  "ok": true,
  "epoch": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "requires_snapshot_bootstrap": true,
  "min_retained_seq": 4500,
  "latest_snapshot": {
    "snapshot_id": "01JDFA00...",
    "covers_seq": 6000,
    "covers_key_seq": 18,
    "byte_size": 312480
  },
  "head_seq": 6120,
  "head_key_seq": 19
}
```

#### (3) 快照、瞬态剪贴板、设备配对与 WebSocket Hibernation 帧契约
- **`PUT /v1/sync/snapshots`**：
  - 请求头：`Content-Type: application/octet-stream`、`X-Journal-Epoch`、`X-Snapshot-Id`、`X-Prev-Snapshot-Id`（首次为空）、`X-Covers-Seq`、`X-Covers-Key-Seq`；请求体为 `MNP1` 二进制流；
  - 服务端先校验 `snapshot_meta` CAS，写入 R2 后提交 DO 元数据并异步删除早于最近 `K=5` 代的旧 R2 快照对象。
- **`GET /v1/sync/snapshots/:snapshot_id`**：流式返回 `MNP1` 二进制字节（支持失败时客户端改拉上一代列表 `GET /v1/sync/snapshots`）。
- **`PUT / GET / DELETE /v1/sync/ephemeral-clip`**：
  - `PUT`：`{ "ttl_sec": 300, "consume_once": true, "cipher_envelope_b64": "..." }`；
  - `GET`：若 `consume_once == true`，DO 在 `transactionSync` 内读取并立即删除该行，确保阅后即焚。
- **`POST /v1/devices` & `POST /v1/devices/pair-claim` & `DELETE /v1/devices/:id`**：
  - 主设备调用 `POST /v1/devices { "device_name": "iPhone" }` → 返回 `{ device_id, device_token, pair_id, expires_at_ms }`；
  - 主设备拼装二维码：`https://<domain>/#pair=<base64url(JSON({ pair_id, device_id, device_token, smk_kid, smk_b64 }))>`；
  - 手机扫码在浏览器本地解析 `#pair`，调用 `POST /v1/devices/pair-claim { "pair_id": "..." }`（带 `Authorization: Bearer <device_token>`）激活设备并销毁单次票据，**全程 `smk_b64` 零字节上云**。
- **`GET /v1/sync/ws`（WebSocket Hibernation 帧）**：
  - 客户端应用层心跳文本帧：`"ping"` → Cloudflare 边缘自动零唤醒回复 `"pong"`；
  - 服务端顺风车推送（当单条 `op` 编码后 `<= 16 KiB` 且无 `key_mutations` 时）：
    `{ "type": "op", "epoch": "...", "seq": 106, "head_key_seq": 13, "op": { ... } }`；
  - 服务端轻量唤醒通知（批量推送、`> 16 KiB` 大包或含密钥变更时）：
    `{ "type": "sync_wakeup", "epoch": "...", "head_seq": 110, "head_key_seq": 14 }`；
  - 设备被吊销通知：`{ "type": "device_revoked" }`（随即服务端以 Close Code `4401` 断开连接）。

---

## 5. `mynote-wasm` TypeScript ↔ Rust WASM 边界契约

由于 JavaScript GC 堆中的字符串与普通对象无法确定性清零内存，`crates/mynote-wasm` 采用 **不透明会话句柄（Opaque Session Handle）** 将解锁后的敏感主密钥 `VKEK` 严格锁在 Rust WASM 线性内存的 `Zeroizing<[u8; 32]>` 结构内：

```typescript
// web/src/wasm/mynote_wasm.d.ts (wasm-bindgen 导出契约)

/**
 * 驻留于 WASM 线性内存的 Tier 2 保险库解锁会话。
 * JS 层仅持有指针句柄，永远拿不到裸 VKEK 字节；调用 lock() 或释放时由 Rust Drop 执行确定性 zeroize。
 */
export class WasmVaultSession {
  /** 通过 Vault 主口令解封 Slot 0 创建会话 */
  static unlockWithPassphrase(passphrase: string, slotJson: string): WasmVaultSession;

  /** 通过浏览器 WebAuthn PRF 扩展返回的 32 字节输出解封对应槽位 */
  static unlockWithPrf(prfOutput32: Uint8Array, slotJson: string): WasmVaultSession;

  /** 用当前已解锁的 VKEK 注册新的本机/本域名 WebAuthn PRF 槽位（返回待持久化的 VaultKeySlot JSON） */
  enrollPrfSlot(rpId: string, credentialId: Uint8Array, prfSalt32: Uint8Array, prfOutput32: Uint8Array, label: string): string;

  /** 新建加密块：随机生成 BDEK，返回 { kid, vaultKeyRecordJson, tier2Envelope: Uint8Array } */
  encryptNewBlock(blockId: string, opId: string, content: string, lang: string): EncryptedBlockBundle;

  /** 更新已有加密块：解包对应 kid 的 BDEK 并用新随机 Nonce 重新加密 */
  encryptExistingBlock(blockId: string, opId: string, vaultKeyRecordJson: string, content: string, lang: string): Uint8Array;

  /** 解密加密块：仅返回渲染所需的明文结果 */
  decryptBlock(blockId: string, opId: string, vaultKeyRecordJson: string, tier2Envelope: Uint8Array): DecryptedBlockPayload;

  /** 立即触发 Rust Zeroize 擦除 WASM 线性内存中的 VKEK 并使句柄失效（5 分钟空闲或 visibilitychange 必调） */
  lockAndZeroize(): void;
  free(): void;
}

/**
 * 供移动端 PWA 使用的 Sans-I/O 同步与 Tier 1 加解密桥接器
 */
export class WasmSyncEngine {
  constructor(deviceId: string, smkKid: string, rawSmk32: Uint8Array);

  /** 执行状态机单步演进：输入当前轻量索引快照与事件 JSON，返回 { storeMutations, syncCommands } */
  step(engineStateJson: string, syncEventJson: string): StepOutput;

  /** 解包或打包 MNP1 全量快照 */
  unpackSnapshot(mnp1Bytes: Uint8Array): UnpackedSnapshot;
  packSnapshot(headerMetaJson: string, snapshotBodyJson: string): Uint8Array;

  /** 显式清零 WASM 内存中的 SMK */
  zeroizeSmk(): void;
  free(): void;
}

/** Layer 1 毫秒级纯离线格式化与结构转换（桌面加密块格式化亦必须走此函数，严禁外发 CLI 子进程！） */
export function formatSnippet(content: string, lang: string, action?: string): string;

/** 本地粘贴内容高危凭据特征快速扫描（返回命中的特征类型如 "aws_access_key" | "pem_private_key" | null） */
export function detectSecretPattern(pastedText: string): string | null;
```
