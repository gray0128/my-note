# 核心数据结构、存储 Schema 与二进制线格式规范 (`data-structures.md`)

> 本文档是 [总架构设计方案 (`architecture-proposal.md`)](./architecture-proposal.md)、[同步协议规范 (`sync-protocol.md`)](./sync-protocol.md) 与 [威胁模型规范 (`threat-model.md`)](./threat-model.md) 的底层数据结构基准，定义全端统一的标识符编码、`mynote-core` Rust 类型定义、精确到字节偏移的二进制信封格式，以及桌面 SQLite、云端 Durable Object SQLite 与移动端 IndexedDB 的完整 Schema。

---

## 目录

1. [基础标识符、时钟与分数索引编码规范](#1-基础标识符时钟与分数索引编码规范)
2. [`mynote-core` Sans-I/O 领域模型与状态机类型定义](#2-mynote-core-sans-io-领域模型与状态机类型定义)
3. [密码学信封、快照与归档包字节布局（Wire Layout v1）](#3-密码学信封快照与归档包字节布局wire-layout-v1)
4. [桌面端本地 SQLite 完整 DDL Schema（`mynote-store`）](#4-桌面端本地-sqlite-完整-ddl-schemamynote-store)
5. [云端 Cloudflare DO SQLite 完整 DDL Schema（`cloud-cf`）](#5-云端-cloudflare-do-sqlite-完整-ddl-schemacloud-cf)
6. [移动端 PWA IndexedDB 存储结构规范（`web`）](#6-移动端-pwa-indexeddb-存储结构规范web)

---

## 1. 基础标识符、时钟与分数索引编码规范

### 1.1 强类型标识符（Newtype IDs）

所有跨端同步实体主键统一采用 **ULID（128-bit，Crockford Base32 大写 26 字符文本表示，如 `01JDF8Z9X4K7M2N5P8Q1R3S6T9`）**，同一毫秒内使用单调递增随机低位生成器（Monotonic ULID），兼具全局唯一性与字典序时间可排性：

| Rust Newtype | 文本格式 / 长度 | 二进制表示 | 适用对象 |
| --- | --- | --- | --- |
| `BufferId` | 26 字符大写 ULID | `[u8; 16]` | 笔记工作区 Buffer 主键（默认初始 Buffer 名称为 `"scratch"`，ID 同样为随机生成 ULID） |
| `BlockId` | 26 字符大写 ULID | `[u8; 16]` | 单个笔记块主键，兼作分数索引平局决胜键（Tie-breaker） |
| `OpId` | 26 字符大写 ULID | `[u8; 16]` | 不可变同步操作唯一幂等 ID |
| `KeyId` (`kid`) | 26 字符大写 ULID | `[u8; 16]` | Tier 2 单个加密块的 `BDEK` 密钥记录 ID 或 Tier 1 `SMK` 世代 ID（`smk_kid`） |
| `DeviceId` | `dev_` + 16 字符小写 Base32 | UTF-8 `String` | 设备唯一标识（注册时生成，只含 `[a-z0-9_]`，严禁包含连字符 `-` 以免干扰 HLC 解析） |
| `SnapshotId` | 26 字符大写 ULID | `[u8; 16]` | R2 压缩快照世代标识 |
| `JournalEpoch` | 标准 36 字符 UUIDv4 | `[u8; 16]` | 云端 DO 日志纪元标识（PITR 回滚或迁移新同步服时变更） |

### 1.2 混合逻辑时钟（`Hlc`）规范化编码

为确保 SQLite `TEXT` 索引、IndexedDB 键排序与 Rust 内存比较三者 **100% 字节序等价（Lexicographical == Causal Order）**，`Hlc` 采用固定宽度大端十六进制/十进制零填充格式：

- **内存结构**：
  ```rust
  #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
  pub struct Hlc {
      pub wall_ms: u64,       // Unix epoch 毫秒时间戳 (48-bit 有效范围)
      pub counter: u16,       // 同毫秒单调逻辑计数器 (0..=65535；溢出则推迟 1ms 或返回 ClockOverflow)
      pub device_id: String,  // 例如 "dev_01jdf8z9x4k7m2n5"
  }
  ```
- **标准定长可排序字符串格式（Canonical String）**：
  `"{wall_ms:015}-{counter:05}-{device_id}"`
  示例：`001795521600123-00001-dev_01jdf8z9x4k7m2n5`
  > **为什么不用 ISO-8601 字符串做存储排序键？** ISO-8601 带可变小数位或时区后缀时容易导致字典序与数值序不一致；15 位零填充毫秒 + 5 位零填充计数器在 `COLLATE BINARY` 下与 `(wall_ms, counter, device_id)` 元组比较 **100% 同构**。
- **漂移钳制常量**：`MAX_FORWARD_DRIFT_MS = 300_000`（5 分钟）。本地 `receive(now_ms, remote_hlc)` 若发现 `remote_hlc.wall_ms > now_ms + MAX_FORWARD_DRIFT_MS`，返回 `ProtocolError::ClockDriftExceeded`。

### 1.3 分数索引（`FractionalIndex`）编码约束

**Buffer 列表排序与 Block 块流排序统一采用同一套 `FractionalIndex`**（修正早期草图中 Buffer 用整数 `sort_order` 导致多端新建/拖拽重排冲突的问题）：

- **字母表（严守 ASCII 字节递增序）**：
  `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`（Base62，共 62 字符，`'0' < '9' < 'A' < 'Z' < 'a' < 'z'`）。
- **生成规则**：在左界 `prev: Option<&str>` 与右界 `next: Option<&str>` 之间计算字典序中点前缀后，追加 **4 字符 CSPRNG 随机 Base62 抖动后缀**（仅在离线/本地新插入时追加，降低多端同时在末尾或同一缝隙插入时的碰撞率至 $62^{-4} \approx 6.7 \times 10^{-8}$）。
- **确定性全序 SQL / 内存比较器**：`(a.position.as_bytes(), a.id.as_bytes()).cmp(&(b.position.as_bytes(), b.id.as_bytes()))`。
- **局部重平衡阈值**：`MAX_POSITION_BYTES = 64`。任一块或 Buffer 更新后若 `position.len() > 64`，触发以其为中心前后各 8 项（最多 17 项）的均匀重分配，发出一组 `SET_META` 操作。

---

## 2. `mynote-core` Sans-I/O 领域模型与状态机类型定义

`crates/mynote-core` 不依赖 `tokio`、`rusqlite` 或 `web-sys`，所有内部业务结构通过 `serde` 支持确定性序列化：

```rust
/// 编译期防空 UPDATE 门禁：仅 Plaintext 分支可提取正文构造 UPDATE
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockBodyState {
    Plaintext(String),
    Locked {
        kid: KeyId,
        public_hint: Option<String>,
        tier2_envelope: Vec<u8>,
    },
    DecryptFailed {
        op_id: OpId,
        error_code: String,
    },
    Unhydrated,
}

/// 未收敛并发正文分支的物化投影（纯函数计算得出，不产生独立 CREATE 操作）
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictBranch {
    pub head_op_id: OpId,
    pub hlc: Hlc,
    pub device_id: DeviceId,
    pub actor: String,
    pub is_locked: bool,
    pub kid: Option<KeyId>,
    pub content: Option<String>,       // is_locked == false 时存在
    pub tier2_envelope: Option<Vec<u8>>, // is_locked == true 时存在
}

/// 物化后的单块完整视图
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedBlock {
    pub id: BlockId,
    pub buffer_id: BufferId,
    pub position: String,
    pub lang: String,
    pub is_locked: bool,
    pub body: BlockBodyState,
    pub head_op_id: OpId,
    pub conflict_siblings: Vec<ConflictBranch>, // 空表示无冲突；非空按 (hlc, op_id) 降序排列
    pub hlc: Hlc,
    pub updated_at_ms: i64,
    pub deleted_at_ms: Option<i64>,
}
```

### 2.1 加密信封内部操作结构（`InnerOpV1`）

使用 **具名字段 MessagePack（`rmp_serde::to_vec_named`）** 序列化，兼顾二进制 `Vec<u8>` 零 Base64 膨胀与后续版本新增 `#[serde(default)]` 可选字段的前向兼容性：

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnerOpV1 {
    pub v: u8,                         // 固定为 1
    pub entity_type: EntityType,       // Buffer | Block
    pub entity_id: String,             // BufferId 或 BlockId (26B ULID)
    pub op_type: OpType,               // Create | Update | SetMeta | Lock | Unlock | Resolve | Delete
    pub parent_op_ids: Vec<OpId>,      // Create 为 []; Update 为 [expected_head]; Resolve 为 [leaf_a, leaf_b, ...]
    pub hlc: String,                   // Canonical HLC 字符串
    #[serde(default = "default_actor")]
    pub actor: String,                 // 默认为 "human"，Agent 调用为自我声明标签如 "agent:claude-code"
    pub body: OpBodyV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "k", content = "d")]
pub enum OpBodyV1 {
    /// 创建或更新 Buffer 元数据（按字段 LWW）
    BufferMeta {
        name: Option<String>,
        position: Option<String>,
    },
    /// 创建或全量更新明文块（正文经 zstd 压缩，100% 自包含）
    BlockFullZstd {
        buffer_id: Option<BufferId>,   // Create 时必填
        position: Option<String>,      // Create 时必填
        lang: Option<String>,          // Create 时必填
        zstd_content: Vec<u8>,
        content_blake3: [u8; 32],
    },
    /// >= 4 KB 明文块连续编辑精确字节区间补丁（距最近 BlockFullZstd < 20 步）
    BlockSpanPatch {
        zstd_patch: Vec<u8>,           // 解压后为 SpanPatchV1 的 MessagePack 字节
    },
    /// 独立更新块标量元数据（不触碰正文因果链）
    BlockMeta {
        buffer_id: Option<BufferId>,
        position: Option<String>,
        lang: Option<String>,
        public_hint: Option<Option<String>>,
    },
    /// 块级保险库锁定态写入或更新（绝不含 wrapped_dek！）
    BlockLocked {
        buffer_id: Option<BufferId>,   // 直接以锁定态 Create 时填写
        position: Option<String>,
        kid: KeyId,
        public_hint: Option<String>,
        tier2_envelope: Vec<u8>,       // 见 §3.2 Tier 2 密文布局
    },
    /// 软删除墓碑
    Tombstone {
        deleted_at_ms: i64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanPatchV1 {
    pub base_op_id: OpId,
    pub base_blake3: [u8; 32],
    pub edits: Vec<SpanEdit>,          // 按原文本 byte_start 严格递增且不重叠
    pub post_blake3: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanEdit {
    pub byte_start: u32,
    pub byte_end: u32,
    pub insert_utf8: String,
}
```

### 2.2 Sans-I/O 状态机输入事件与输出副作用契约

```rust
#[derive(Clone, Debug)]
pub enum SyncEvent {
    LocalMutation(LocalIntent),
    PullResponse {
        epoch: JournalEpoch,
        ops: Vec<RemoteEnvelopeRow>,
        key_changes: Vec<RemoteVaultKeyChange>,
        head_seq: i64,
        head_key_seq: i64,
        has_more: bool,
        requires_snapshot_bootstrap: bool,
        latest_snapshot: Option<SnapshotPointer>,
    },
    PushAcked {
        epoch: JournalEpoch,
        acked: Vec<AckedOp>,
        head_seq: i64,
        head_key_seq: i64,
    },
    WsFastPathOp {
        epoch: JournalEpoch,
        seq: i64,
        op: RemoteEnvelopeRow,
    },
    SnapshotDownloaded {
        pointer: SnapshotPointer,
        raw_bytes: Vec<u8>,
    },
}

#[derive(Clone, Debug)]
pub enum StoreMutation {
    UpsertBuffer(MaterializedBuffer),
    UpsertBlock(MaterializedBlock),    // 同步替换关联 block_conflicts 行与 blocks_fts 索引
    AppendLocalOp(LocalOpRecord),
    MarkOpsSynced { epoch: JournalEpoch, acked: Vec<AckedOp> },
    ClearServerSeqsForReconcile { new_epoch: JournalEpoch },
    ScrubBlockPlaintextHistory { block_id: BlockId, purged_op_ids: Vec<OpId> }, // 触发 FTS5 merge + WAL TRUNCATE
    UpsertVaultKeySlot(VaultKeySlotRecord),
    UpsertVaultKey(VaultKeyRecord),
    ShredVaultKey { kid: KeyId, key_seq: Option<i64> },
    SetSyncMeta { bootstrap_completed: bool, journal_epoch: Option<JournalEpoch>, last_seq: i64, last_key_seq: i64 },
}

#[derive(Clone, Debug)]
pub enum SyncCommand {
    HttpPush(PushRequestDto),
    HttpPull { since_seq: i64, since_key_seq: i64, limit: u16 },
    FetchSnapshot(SnapshotPointer),
    UploadSnapshot { prev_snapshot_id: Option<SnapshotId>, covers_seq: i64, bytes: Vec<u8> },
}
```

---

## 3. 密码学信封、快照与归档包字节布局（Wire Layout v1）

所有多字节整数在二进制线格式中统一采用 **小端序（Little-Endian）**。

### 3.1 确定性 256 字节阶梯填充算法（Bijective 256B Bucket Padding）

对任意长度 $L \ge 0$ 的明文字节串 `raw`：
1. 计算需补零字节数：$\text{pad\_zeros} = (256 - ((L + 1) \bmod 256)) \bmod 256$（取值恒在 `0..=255`，恰好可由单字节 `u8` 表达）；
2. 构造填充帧：`padded = raw || [0x00; pad_zeros] || [pad_zeros as u8]`，总长度恒为 `256` 的正整数倍（最小 `256 B`）；
3. **严格解包校验**：验证 `padded.len() >= 256 && padded.len() % 256 == 0`，读取末字节 `p = padded[padded.len() - 1] as usize`，验证末尾前 `p` 个字节全为 `0x00`（拒绝非规范填充），截取前 `padded.len() - 1 - p` 字节还原 `raw`。

### 3.2 四类核心二进制信封字节布局

#### (1) Tier 1 同步盲信封（`MNS1`，存于 `ops.envelope`）
| 偏移（Bytes） | 字段名 | 长度 | 说明 |
| --- | --- | :---: | --- |
| `0..4` | `magic` | `4 B` | 固定 ASCII `"MNS1"` |
| `4..5` | `version` | `1 B` | `0x01` |
| `5..21` | `smk_kid` | `16 B` | 当前 `Sync Master Key` ULID 二进制字节 |
| `21..45` | `nonce` | `24 B` | CSPRNG 随机 `XChaCha20` Nonce |
| `45..` | `ciphertext` | $256k + 16\text{ B}$ | `XChaCha20-Poly1305` 加密 `pad256(msgpack(InnerOpV1))` 所得密文与 16B Poly1305 Tag |

- **强制绑定 AAD**：`"MNS1" || [0x01] || smk_kid (16B) || op_id_bytes (16B) || device_id.as_bytes()`。

#### (2) Tier 2 块级保险库内层密文（`MNV1`，存于 `blocks.ciphertext` 与 `BlockLocked.tier2_envelope`）
| 偏移（Bytes） | 字段名 | 长度 | 说明 |
| --- | --- | :---: | --- |
| `0..4` | `magic` | `4 B` | 固定 ASCII `"MNV1"` |
| `4..5` | `version` | `1 B` | `0x01` |
| `5..21` | `kid` | `16 B` | 对应 `vault_keys.kid` 的 16B ULID（**不含 `wrapped_dek`**） |
| `21..45` | `nonce` | `24 B` | CSPRNG 随机 Nonce |
| `45..` | `ciphertext` | $256k + 16\text{ B}$ | 以 `BDEK` 加密 `pad256(zstd(msgpack(VaultPlaintextV1 { content, lang, tags })))` |

- **强制绑定 AAD**：`"MNV1" || [0x01] || block_id_bytes (16B) || op_id_bytes (16B) || kid (16B)`。

#### (3) 云端可变密钥同步外层信封（`MNK1`，用于同步 `vault_keys` 与 `vault_key_slots`）
- 布局：`magic "MNK1" (4B) || version (1B) || smk_kid (16B) || nonce (24B) || aead_ct`
- AAD：`"MNK1" || [0x01] || smk_kid (16B) || record_id.as_bytes()`，确保云端无法伪造或回放槽位及密钥记录。

#### (4) R2 多世代全量加密快照（`MNP1`，头体分离双段认证结构）
采用「独立认证头 + 独立认证压缩体」设计，允许客户端先解密 200 字节头部检查 `covers_seq`、`block_count` 与 `state_blake3`，再解密主体：
```text
+-------------------+-------------+--------------+-------------------+------------------+--------------------+
| "MNP1" + ver (5B) | smk_kid(16B)| hdr_nonce(24)| hdr_ct_len(u32_le)| hdr_ct (AEAD)    | body_nonce(24)+ct  |
+-------------------+-------------+--------------+-------------------+------------------+--------------------+
```
- `SnapshotHeaderV1`（MessagePack）：`{ journal_epoch, snapshot_id, prev_snapshot_id, covers_seq, covers_key_seq, buffer_count, block_count, rolling_op_hash: [u8; 32], state_blake3: [u8; 32], created_at_ms }`；
- `SnapshotBodyV1`（`zstd` 压缩后加密）：`{ buffers: Vec<MaterializedBuffer>, blocks: Vec<MaterializedBlock>, vault_key_slots: Vec<VaultKeySlotRecord>, vault_keys: Vec<VaultKeyRecord> }`；
- Body AAD 绑定 `hdr_blake3 (32B)`，杜绝将旧快照头与新快照体拼接攻击。

---

## 4. 桌面端本地 SQLite 完整 DDL Schema（`mynote-store`）

全部业务表启用 SQLite `STRICT` 强类型检查，并通过数据库级 `CHECK` 约束在物理层锁死「加锁块 `content` 必须为 `NULL`」不变量：

```sql
-- 连接打开时必须执行的 PRAGMA 序列：
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;
PRAGMA secure_delete = ON;

-- 1. 本地键值元数据（device_id, journal_epoch, bootstrap_completed, last_synced_seq, last_key_seq 等）
CREATE TABLE IF NOT EXISTS local_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

-- 2. 工作区 Buffer 表（使用 Fractional Index 排序）
CREATE TABLE IF NOT EXISTS buffers (
    id            TEXT PRIMARY KEY,          -- 26B ULID
    name          TEXT NOT NULL,
    position      TEXT NOT NULL,             -- Base62 分数索引
    hlc           TEXT NOT NULL,             -- 定长 Canonical HLC
    updated_at_ms INTEGER NOT NULL,
    deleted_at_ms INTEGER                    -- NULL = 存活
) STRICT;

CREATE INDEX IF NOT EXISTS idx_buffers_active_order
    ON buffers (position COLLATE BINARY ASC, id ASC)
    WHERE deleted_at_ms IS NULL;

-- 3. 核心块物化主表（注意：保留内置整数 rowid 以 O(log N) 极速联动 blocks_fts！）
CREATE TABLE IF NOT EXISTS blocks (
    id                 TEXT PRIMARY KEY,     -- 26B ULID
    buffer_id          TEXT NOT NULL REFERENCES buffers(id),
    position           TEXT NOT NULL,        -- Base62 分数索引
    lang               TEXT NOT NULL,        -- 'markdown' | 'json' | 'sql' | 'mermaid' | ...
    is_locked          INTEGER NOT NULL CHECK (is_locked IN (0, 1)),
    kid                TEXT,                 -- is_locked = 1 时关联 vault_keys.kid
    public_hint        TEXT,
    content            TEXT,                 -- 明文正文；硬约束保证加锁时恒为 NULL
    ciphertext         BLOB,                 -- MNV1 密文体；硬约束保证加锁时非空
    head_op_id         TEXT NOT NULL,        -- 当前主分支极大元 OpId
    meta_hlc           TEXT NOT NULL,        -- 标量元数据最新 HLC
    content_hlc        TEXT NOT NULL,        -- 正文主分支最新 HLC
    conflict_count     INTEGER NOT NULL DEFAULT 0,
    updated_at_ms      INTEGER NOT NULL,
    deleted_at_ms      INTEGER,
    CHECK (
        (is_locked = 0 AND content IS NOT NULL AND ciphertext IS NULL AND kid IS NULL)
        OR
        (is_locked = 1 AND content IS NULL AND ciphertext IS NOT NULL AND kid IS NOT NULL)
    )
) STRICT;

CREATE INDEX IF NOT EXISTS idx_blocks_buffer_order
    ON blocks (buffer_id, position COLLATE BINARY ASC, id ASC)
    WHERE deleted_at_ms IS NULL;

-- 4. 并发冲突兄弟分支物化表（毫秒级直读渲染，无需每次查询重放历史补丁链）
CREATE TABLE IF NOT EXISTS block_conflicts (
    block_id      TEXT NOT NULL REFERENCES blocks(id) ON DELETE CASCADE,
    head_op_id    TEXT NOT NULL,
    hlc           TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    actor         TEXT NOT NULL,
    is_locked     INTEGER NOT NULL CHECK (is_locked IN (0, 1)),
    kid           TEXT,
    content       TEXT,
    ciphertext    BLOB,
    PRIMARY KEY (block_id, head_op_id),
    CHECK (
        (is_locked = 0 AND content IS NOT NULL AND ciphertext IS NULL)
        OR
        (is_locked = 1 AND content IS NULL AND ciphertext IS NOT NULL)
    )
) STRICT;

-- 5. 全文搜索倒排索引（rowid 直接对齐 blocks.rowid；仅在 Rust 写事务内对 is_locked=0 存活块同步更新）
CREATE VIRTUAL TABLE IF NOT EXISTS blocks_fts USING fts5(
    content,
    public_hint,
    tokenize = 'unicode61 remove_diacritics 2'
);

-- 6. 本地操作日志与待同步出站队列（server_seq IS NULL 即为待推 Outbox）
CREATE TABLE IF NOT EXISTS sync_ops (
    op_id            TEXT PRIMARY KEY,       -- 26B ULID
    server_seq       INTEGER,                -- 当前 journal_epoch 下的云端序号；未推送为 NULL
    device_id        TEXT NOT NULL,
    entity_type      TEXT NOT NULL CHECK (entity_type IN ('buffer', 'block')),
    entity_id        TEXT NOT NULL,
    parent_op_ids    TEXT NOT NULL,          -- JSON 数组字符串，如 '["01J..."]'
    op_type          TEXT NOT NULL CHECK (op_type IN ('CREATE','UPDATE','SET_META','LOCK','UNLOCK','RESOLVE','DELETE')),
    hlc              TEXT NOT NULL,
    actor            TEXT NOT NULL DEFAULT 'human',
    payload_encoding TEXT CHECK (payload_encoding IN ('NONE','META','FULL_ZSTD','SPAN_PATCH','LOCKED')),
    payload          BLOB,                   -- 事后加锁触发本地历史擦除后置为 NULL
    is_purged        INTEGER NOT NULL DEFAULT 0 CHECK (is_purged IN (0, 1)),
    created_at_ms    INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_sync_ops_outbox
    ON sync_ops (created_at_ms ASC, op_id ASC)
    WHERE server_seq IS NULL;

CREATE INDEX IF NOT EXISTS idx_sync_ops_entity_history
    ON sync_ops (entity_type, entity_id, hlc ASC);

-- 7. LUKS 式多槽位主保险库密钥包裹表（含 Argon2id / WebAuthn PRF 完整解包参数）
CREATE TABLE IF NOT EXISTS vault_key_slots (
    slot_id        TEXT PRIMARY KEY,         -- 'passphrase' | 'recovery' | 'prf:<sha256_prefix>'
    slot_kind      TEXT NOT NULL CHECK (slot_kind IN ('passphrase', 'recovery', 'webauthn_prf')),
    vk_epoch       INTEGER NOT NULL,
    label          TEXT NOT NULL,            -- 例如 'MacBook Touch ID (localhost)'
    kdf_params     TEXT NOT NULL,            -- JSON: Argon2id{salt_b64,m_kib,t,p} 或 Prf{rp_id,cred_id_b64,prf_salt_b64}
    nonce          BLOB NOT NULL,            -- 24B XChaCha20 Nonce
    wrapped_vkek   BLOB NOT NULL,            -- 32B VKEK + 16B Poly1305 Tag = 48B
    is_local_only  INTEGER NOT NULL DEFAULT 0 CHECK (is_local_only IN (0, 1)), -- localhost PRF 槽位无需上云
    updated_at_ms  INTEGER NOT NULL,
    deleted_at_ms  INTEGER
) STRICT;

-- 8. 可变块密钥表（支持物理清除 wrapped_dek 实现 Crypto-Shredding）
CREATE TABLE IF NOT EXISTS vault_keys (
    kid            TEXT PRIMARY KEY,         -- 26B ULID
    key_seq        INTEGER,                  -- 云端密钥水位序号
    state          TEXT NOT NULL CHECK (state IN ('ACTIVE', 'SHREDDED')),
    vk_epoch       INTEGER NOT NULL,
    nonce          BLOB,                     -- SHREDDED 时置 NULL
    wrapped_dek    BLOB,                     -- SHREDDED 时置 NULL（零密钥材料残留）
    updated_at_ms  INTEGER NOT NULL,
    is_dirty       INTEGER NOT NULL DEFAULT 0 CHECK (is_dirty IN (0, 1)),
    CHECK (
        (state = 'ACTIVE' AND nonce IS NOT NULL AND wrapped_dek IS NOT NULL)
        OR
        (state = 'SHREDDED' AND nonce IS NULL AND wrapped_dek IS NULL)
    )
) STRICT;

-- 9. CLI 幂等键防重表（保留最近 7 天）
CREATE TABLE IF NOT EXISTS idempotency_keys (
    idem_key       TEXT PRIMARY KEY,
    command        TEXT NOT NULL,
    entity_id      TEXT NOT NULL,
    op_id          TEXT NOT NULL,
    created_at_ms  INTEGER NOT NULL
) STRICT;
```

### 4.1 本地升级快照、回滚备份与 Schema 前向兼容保护（`mynote update` 配套存储）

为支撑 `mynote update` 与 `mynote update --rollback` 在升级/回退二进制时绝不损坏本地 SQLite WAL 数据，桌面数据目录（Linux: `~/.local/share/mynote/`；macOS: `~/Library/Application Support/mynote/`）维护以下受控结构：

- **`local_meta` 强制版本锁键**：
  - `schema_version`（同步写入 `PRAGMA user_version`）：当前库已应用的最新迁移号；
  - `min_reader_schema_version`：允许安全读写当前库的最低二进制可识别 Schema 版本号。若旧版二进制（如回滚后）发现自身支持的最高 Schema 版本 `< min_reader_schema_version`，立即以退出码 `8`（`INTEGRITY_ERROR: SCHEMA_TOO_NEW`）拒绝写入，防止旧代码误毁新表结构。
- **二进制回滚槽位（`bin/mynote.prev` + `bin/mynote.prev.json`）**：
  - 每次 `mynote update` 原子替换前保存上一版已知完好可执行文件，元数据记录 `{ version, blake3_hex, pre_upgrade_schema_version, backed_up_at_ms }`（仅保留最近 1 代，占用 `< 15 MiB`）。
- **跨 Schema 升级前自动一致性快照（`backups/mynote-pre-schema-v<N>.db`）**：
  - 仅在版本升级触发 `PRAGMA user_version` 递增前自动通过 `VACUUM INTO` 生成单文件快照（权限 `0600`，最多保留最近 2 代），为跨大版本回滚提供零丢失兜底。

---

## 5. 云端 Cloudflare DO SQLite 完整 DDL Schema（`cloud-cf`）

为解决「设备 A 在本地销毁了某块 `kid`，离线设备 B 重连后如何同步销毁本地 `vault_keys` 中的 `kid`」以及「`LOCK` 操作与对应 `kid` 原子可见性」问题，云端 DO 为可变密钥表引入轻量单调游标 `key_seq`，并保持主表 `ops` 严格 **5 列 + 单唯一索引（2 rows written/op）**：

```sql
-- 1. DO 全局元数据（journal_epoch, next_key_seq, min_retained_seq, last_archive_seq）
CREATE TABLE IF NOT EXISTS journal_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- 2. 注册设备、令牌哈希与同步水位表
CREATE TABLE IF NOT EXISTS devices (
    device_id        TEXT PRIMARY KEY,
    device_name      TEXT NOT NULL,
    token_sha256_hex TEXT NOT NULL UNIQUE,
    last_pulled_seq  INTEGER NOT NULL DEFAULT 0,
    last_seen_at_ms  INTEGER NOT NULL,
    created_at_ms    INTEGER NOT NULL,
    revoked_at_ms    INTEGER                 -- 非 NULL 时立即拒绝一切 HTTP/WS 请求
);

-- 3. 一次性 60 秒扫码配对票据表（绝对不含 SMK！SMK 仅走客户端 URL #fragment）
CREATE TABLE IF NOT EXISTS pairing_tickets (
    pair_id          TEXT PRIMARY KEY,
    device_id        TEXT NOT NULL REFERENCES devices(device_id),
    expires_at_ms    INTEGER NOT NULL,
    claimed_at_ms    INTEGER
);

-- 4. 核心盲操作日志表（seq 映射内置 rowid；仅 UNIQUE(op_id) 1 个二级索引 = 严格 2 rows written/op）
CREATE TABLE IF NOT EXISTS ops (
    seq        INTEGER PRIMARY KEY,
    op_id      TEXT NOT NULL UNIQUE,
    device_id  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    envelope   BLOB                          -- MNS1 密文；经 purge_op_ids 墓碑擦除后为 NULL
);

-- 5. R2 多世代快照指针链（仅保留最近 K=5 代，CAS 校验 prev_snapshot_id）
CREATE TABLE IF NOT EXISTS snapshot_meta (
    snapshot_id      TEXT PRIMARY KEY,
    prev_snapshot_id TEXT,
    covers_seq       INTEGER NOT NULL,
    covers_key_seq   INTEGER NOT NULL,
    r2_object_key    TEXT NOT NULL,
    byte_size        INTEGER NOT NULL,
    created_at_ms    INTEGER NOT NULL
);

-- 6. 云端可变密钥与槽位同步表（通过单调 key_seq 向所有离线设备广播 ACTIVE 与 SHREDDED 销毁墓碑）
CREATE TABLE IF NOT EXISTS vault_key_records (
    record_id       TEXT PRIMARY KEY,        -- 'key:<kid>' 或 'slot:<slot_id>'
    key_seq         INTEGER NOT NULL UNIQUE, -- 单调递增版本号，供客户端 key_since 增量拉取
    state           TEXT NOT NULL CHECK (state IN ('ACTIVE', 'SHREDDED')),
    mnk1_envelope   BLOB,                    -- ACTIVE 时为 MNK1 认证密文；SHREDDED 销毁时强制置 NULL！
    updated_at_ms   INTEGER NOT NULL
);

-- 7. 独立短 TTL 瞬态加密剪贴板（不入 ops、不入快照、每日 R2 冷备任务严格跳过）
CREATE TABLE IF NOT EXISTS ephemeral_clips (
    clip_slot       TEXT PRIMARY KEY,        -- 默认固定单槽 'default'（最新覆盖）或命名槽位
    sender_device   TEXT NOT NULL,
    consume_once    INTEGER NOT NULL DEFAULT 1,
    expires_at_ms   INTEGER NOT NULL,
    cipher_envelope BLOB NOT NULL
);
```

---

## 6. 移动端 PWA IndexedDB 存储结构规范（`web`）

数据库名称：`mynote_pwa_v1`（Schema Version `1`），共设 **6 个极简 Object Stores**，与桌面端逻辑模型一一对应，零 SQL 解析开销：

| Object Store 名称 | `keyPath` | 二级索引（Indexes） | 存储内容说明 |
| --- | --- | --- | --- |
| `device_keystore` | `"id"` | 无 | 存 `{ id: "wrapping_key", cryptoKey: CryptoKey(AES-GCM, extractable=false) }` 及被其包裹的 `{ id: "credentials", iv, wrapped_smk, smk_kid, wrapped_token, device_id, sync_url, journal_epoch, last_seq, last_key_seq, bootstrap_completed }` |
| `buffers` | `"id"` | `by_position`: `["position", "id"]` | 存活与软删除 `MaterializedBuffer` 对象 |
| `blocks` | `"id"` | `by_buffer_pos`: `["buffer_id", "position", "id"]` | `MaterializedBlock`（`is_locked: true` 时仅存 `tier2_envelope: Uint8Array`，`content: null`） |
| `block_conflicts` | `["block_id", "head_op_id"]` | `by_block`: `"block_id"` | 并发冲突分支列表 |
| `sync_ops` | `"op_id"` | `by_unsynced`: `"unsynced_order"`（仅未推送项含此数值键）<br>`by_entity`: `["entity_id", "hlc"]` | 本地历史与待同步 Outbox 队列 |
| `vault_store` | `"record_id"` | 无 | 同步下来的 `vault_key_slots` 与非 `SHREDDED` 的 `vault_keys` 密文记录（收到 `SHREDDED` 立即 `store.delete(record_id)` 物理移除） |
