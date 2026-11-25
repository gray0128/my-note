# 核心数据结构、存储 Schema 与二进制线格式规范 (`data-structures.md`)

> 2026-11-24 修订：依据 [第一性原理审查 §9](../review/2026-11-24-first-principles-review.md) 的决策 D1–D7 更新。

> 本文档是 [总架构设计方案 (`architecture-proposal.md`)](./architecture-proposal.md)、[同步协议规范 (`sync-protocol.md`)](./sync-protocol.md) 与 [威胁模型规范 (`threat-model.md`)](./threat-model.md) 的底层数据结构基准，定义全端统一的标识符编码、`mynote-core` Rust 类型定义、精确到字节偏移的二进制信封格式、**AAD 的唯一权威定义**、密钥表 / 密钥环 / 恢复包结构，以及桌面 SQLite、云端 Durable Object SQLite 与移动端 IndexedDB 的完整 Schema。
>
> **单一事实来源**：线格式、AAD、表结构只在本文档定义。其他文档涉及这些细节时只做一句话概述并链接到这里；若出现不一致，以本文档为准。

---

## 目录

1. [基础标识符、时钟与分数索引编码规范](#1-基础标识符时钟与分数索引编码规范)
2. [`mynote-core` Sans-I/O 领域模型与状态机类型定义](#2-mynote-core-sans-io-领域模型与状态机类型定义)
3. [密码学信封、密钥结构、快照与归档包字节布局（Wire Layout v1）](#3-密码学信封密钥结构快照与归档包字节布局wire-layout-v1)
4. [桌面端本地 SQLite 完整 DDL Schema（`mynote-store`）](#4-桌面端本地-sqlite-完整-ddl-schemamynote-store)
5. [云端 Cloudflare DO SQLite 完整 DDL Schema（`cloud-cf`）](#5-云端-cloudflare-do-sqlite-完整-ddl-schemacloud-cf)
6. [移动端 PWA IndexedDB 存储结构规范（`web`，只读缓存）](#6-移动端-pwa-indexeddb-存储结构规范web只读缓存)
7. [已移除 / 推迟的机制（2026-11-24）](#7-已移除--推迟的机制2026-11-24)

---

## 1. 基础标识符、时钟与分数索引编码规范

### 1.1 强类型标识符（Newtype IDs）

所有跨端同步实体主键统一采用 **ULID（128-bit，Crockford Base32 大写 26 字符文本表示，如 `01JDF8Z9X4K7M2N5P8Q1R3S6T9`）**，同一毫秒内使用单调递增随机低位生成器（Monotonic ULID），兼具全局唯一性与字典序时间可排性：

| Rust Newtype | 文本格式 / 长度 | 二进制表示 | 适用对象 |
| --- | --- | --- | --- |
| `BufferId` | 26 字符大写 ULID | `[u8; 16]` | 笔记工作区 Buffer 主键（默认初始 Buffer 名称为 `"scratch"`，ID 同样为随机生成 ULID） |
| `BlockId` | 26 字符大写 ULID | `[u8; 16]` | 单个笔记块主键，兼作分数索引平局决胜键（Tie-breaker） |
| `OpId` | 26 字符大写 ULID | `[u8; 16]` | 不可变同步操作唯一幂等 ID。**由执行加密的 `mynote-core` 在加密前生成**（见 §3.3）：Tier 1 由 Daemon/CLI 生成；Tier 2 由前端 `WasmVaultSession` 生成并随本地请求显式交给 Daemon 封装 `MNS1` |
| `KeyId` (`key_id`) | 26 字符大写 ULID | `[u8; 16]` | 单把实体数据密钥 **BDEK** 的记录 ID（Block 与 Buffer 通用、Tier 1 与 Tier 2 通用，见 §3.4） |
| `SmkKid` (`smk_kid`) / `VkekKid` (`vkek_kid`) | 26 字符大写 ULID | `[u8; 16]` | 密钥环中某一代 `SMK` / `VKEK` 的 ID（见 §3.5） |
| `MarkId` | 26 字符大写 ULID | `[u8; 16]` | 碎纸标记 ID（见 §3.4） |
| `DeviceId` | `dev_` + 16 字符小写 Base32 | UTF-8 `String` | 设备唯一标识（注册时生成，只含 `[a-z0-9_]`，严禁包含连字符 `-` 以免干扰 HLC 解析） |
| `SnapshotId` | 26 字符大写 ULID | `[u8; 16]` | R2 上「手机用当前状态快照」的标识（见 §3.6） |
| `JournalEpoch` | 标准 36 字符 UUIDv4 | `[u8; 16]` | 云端 DO 日志纪元标识（PITR 回滚或迁移新同步服时变更） |

### 1.2 混合逻辑时钟（`Hlc`）规范化编码

为确保 SQLite `TEXT` 索引、IndexedDB 键排序与 Rust 内存比较三者**字节序等价（Lexicographical == `(wall_ms, counter, device_id)` 元组序）[保证]**，`Hlc` 采用固定宽度大端十六进制/十进制零填充格式：

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
  > **为什么不用 ISO-8601 字符串做存储排序键？** ISO-8601 带可变小数位或时区后缀时容易导致字典序与数值序不一致；15 位零填充毫秒 + 5 位零填充计数器在 `COLLATE BINARY` 下与 `(wall_ms, counter, device_id)` 元组比较同构（定长前缀，构造性成立）。
- **HLC 的用途（路径 γ）**：只用于两件事——(1) 多叶子之间「先展示哪个版本」的排序键 `(hlc, op_id)`；(2) 字段 LWW（`position` / `lang` / `buffer_id` / `public_hint`，以及 Buffer 的 `name` / `position`）。**HLC 不决定是否接受某个 op**。
- **时钟偏差只提示、不拒收、不钳制**：`receive(now_ms, remote_hlc)` 按标准 HLC 算法把远端时钟合并进本地时钟；若 `remote_hlc.wall_ms > now_ms + CLOCK_SKEW_WARN_MS`（`300_000`，5 分钟），只在本地 UI 提示「某设备时钟偏差过大」，**不返回错误、不丢弃 op、不卡住游标**。

### 1.3 分数索引（`FractionalIndex`）编码约束

**Buffer 列表排序与 Block 块流排序统一采用同一套 `FractionalIndex`**（修正早期草图中 Buffer 用整数 `sort_order` 导致多端新建/拖拽重排冲突的问题）：

- **字母表（严守 ASCII 字节递增序）**：
  `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`（Base62，共 62 字符，`'0' < '9' < 'A' < 'Z' < 'a' < 'z'`）。
- **生成规则**：在左界 `prev: Option<&str>` 与右界 `next: Option<&str>` 之间计算字典序中点前缀后，追加 **4 字符 CSPRNG 随机 Base62 抖动后缀**（仅在离线/本地新插入时追加，降低多端同时在末尾或同一缝隙插入时的碰撞率至 $62^{-4} \approx 6.7 \times 10^{-8}$）。
- **确定性全序 SQL / 内存比较器**：`(a.position.as_bytes(), a.id.as_bytes()).cmp(&(b.position.as_bytes(), b.id.as_bytes()))`。
- **不做重平衡**：索引键允许无限变长。在个人规模下键长增长极慢 [估算]；即使两个键完全相同，也由 `id` 决胜，顺序仍确定。

---

## 2. `mynote-core` Sans-I/O 领域模型与状态机类型定义

`crates/mynote-core` 不依赖 `tokio`、`rusqlite` 或 `web-sys`，所有内部业务结构通过 `serde` 支持确定性序列化。

**路径 γ 的数据模型**：一个块的正文是一个因果 DAG，每个 op 都携带**全量**正文；**冲突 = 同一块有多个叶子**。物化视图保存块的**全部叶子**，展示版本 = 非墓碑叶子中 `(hlc, op_id)` 最大者；其余叶子标记为「另一台设备的版本」。合并规则与展示语义的完整定义见 [`sync-protocol.md`](./sync-protocol.md)。

```rust
/// 单个叶子的正文状态（编译期防空 UPDATE 门禁：仅 Plaintext 可提取正文构造 UPDATE）
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeafBody {
    /// Tier 1 叶子，BDEK 可用，已解密
    Plaintext(String),
    /// Tier 2 叶子：只持有 MNB1 密文，需 Vault 会话解密
    Sealed { key_id: KeyId, mnb1: Vec<u8> },
    /// 墓碑叶子（DELETE）
    Tombstone { deleted_at_ms: i64 },
    /// 引用的 key_id 本地不可用：密钥记录尚未同步到达，或已被碎纸
    KeyUnavailable { key_id: KeyId, shredded: bool },
    /// 解密 / 解析失败（AAD 不符、Tag 校验失败、填充非规范等）
    DecryptFailed { error_code: String },
}

/// 一个叶子版本（纯函数在完整 MNS1 因果 DAG 上计算得出；中间祖先的 BDEK 碎纸不改变叶子拓扑）
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockLeaf {
    pub op_id: OpId,
    pub hlc: Hlc,
    pub device_id: DeviceId,
    pub actor: String,
    pub tier: Option<u8>,           // 1 | 2；墓碑为 None
    pub body: LeafBody,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockState {
    Active,    // 至少一个非墓碑且密钥未碎纸的叶子（Update-Wins）
    Trashed,   // 全部叶子均为墓碑（或已碎纸），但该块在 block_keys 中仍有未碎纸的 BDEK：在回收站中，宽限期内可撤销
    Shredded,  // 全部叶子均为墓碑（或已碎纸），且该块的全部 BDEK 均已碎纸：不再物化任何正文
}

/// 物化后的单块完整视图
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedBlock {
    pub id: BlockId,
    pub buffer_id: BufferId,
    pub position: String,
    pub lang: String,
    pub public_hint: Option<String>,
    pub field_hlc: BlockFieldHlc,       // 字段 LWW 的各字段 HLC
    pub state: BlockState,
    pub is_locked: bool,                // 任一叶子 tier == 2 即为 true（整块按加锁渲染）
    pub display_op_id: Option<OpId>,    // 非墓碑叶子中 (hlc, op_id) 最大者；Trashed/Shredded 为 None
    pub leaves: Vec<BlockLeaf>,         // 全部叶子，按 (hlc, op_id) 降序；len() > 1 即存在并发版本
    pub updated_at_ms: i64,
    pub deleted_at_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFieldHlc {
    pub buffer_id: Hlc,
    pub position: Hlc,
    pub lang: Hlc,
    pub public_hint: Hlc,
}
```

### 2.1 加密信封内部操作结构（`InnerOpV1`）

使用 **具名字段 MessagePack（`rmp_serde::to_vec_named`）** 序列化，兼顾二进制 `Vec<u8>` 零 Base64 膨胀与后续版本新增 `#[serde(default)]` 可选字段的前向兼容性。`InnerOpV1` 是 `MNS1` 信封（§3.2 (1)）的明文；**块正文不直接出现在 `InnerOpV1` 中**，而是以 BDEK 加密后的 `MNB1` 密文（§3.2 (2)）嵌入，信封只带 `key_id`，**不带任何密钥或 `wrapped_dek`**。

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnerOpV1 {
    pub v: u8,                         // 固定为 1
    pub entity_type: EntityType,       // Buffer | Block
    pub entity_id: String,             // BufferId 或 BlockId (26B ULID)
    pub op_type: OpType,               // Create | Update | SetMeta | Lock | Unlock | Resolve | Delete
    pub parent_op_ids: Vec<OpId>,      // Create 为 []；其余为提交时本地已知的该块全部叶子
    pub hlc: String,                   // Canonical HLC 字符串
    #[serde(default = "default_actor")]
    pub actor: String,                 // 默认为 "human"，Agent 调用为自我声明标签如 "agent:claude-code"
    pub body: OpBodyV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "k", content = "d")]
pub enum OpBodyV1 {
    /// 创建或更新 Buffer 元数据（按字段 LWW）。「一个实体一把密钥」：Buffer 在 CREATE 时新建自己的
    /// Tier 1 BDEK，名称以该 BDEK 加密；删除 Buffer 时对该 key_id 走与块相同的碎纸流程（§3.4）
    BufferMeta {
        key_id: KeyId,                 // Buffer 自己的 BDEK（只能是 Tier 1）
        name_mnb1: Option<Vec<u8>>,    // Buffer 名称的 MNB1 密文（明文 = BlockPlaintextV1{content: name}），AAD 绑定本 op 的 op_id
        position: Option<String>,      // 排序键不含用户内容，留在 MNS1 内即可
    },
    /// 块正文（全量、自包含）：CREATE / UPDATE / LOCK / UNLOCK / RESOLVE 共用
    BlockContent {
        buffer_id: Option<BufferId>,   // CREATE 必填；换钥复活（§3.4.4）时也必须填写
        position: Option<String>,      // 同上
        lang: Option<String>,          // 同上
        public_hint: Option<Option<String>>,
        tier: u8,                      // 1 | 2；必须与 key_id 对应密钥记录的 tier 一致，否则视为 DecryptFailed
        key_id: KeyId,                 // 加密本 op 正文所用的 BDEK
        mnb1: Vec<u8>,                 // §3.2 (2)，AAD 绑定本 op 的 op_id
    },
    /// 独立更新块标量元数据（字段 LWW，不触碰正文 DAG）
    BlockMeta {
        buffer_id: Option<BufferId>,
        position: Option<String>,
        lang: Option<String>,
        public_hint: Option<Option<String>>,
    },
    /// 软删除墓碑（块进入回收站；碎纸标记在密钥表中另行写入，见 §3.4）
    Tombstone {
        deleted_at_ms: i64,
    },
}

/// MNB1 的明文（zstd 压缩、256B 填充后以 BDEK 加密）
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockPlaintextV1 {
    pub content: String,
}
```

**`op_type` 与载荷对应关系**（op 类型集合不变；`LOCK` 与「换钥」**不新增类型**）：

| `op_type` | 适用实体 | `body` | 约束 |
| --- | --- | --- | --- |
| `CREATE` | `buffer` / `block` | `BufferMeta` / `BlockContent` | `parent_op_ids = []`；块可直接以 `tier = 2` 创建 |
| `UPDATE` | `buffer` / `block` | `BufferMeta` / `BlockContent` | `parent_op_ids` = 本地已知的全部叶子。`key_id` 可与上一版相同，也可是新建的 BDEK′（即「换钥」）。用户合并多叶子 = 提交 `UPDATE`；从回收站恢复 = 以墓碑叶子为父的 `UPDATE` |
| `SET_META` | `block` | `BlockMeta` | 不进入正文 DAG |
| `LOCK` | `block` | `BlockContent`，`tier = 2` | 实现上就是换钥：新建 VKEK 包裹的 BDEK 并重新加密当前版本；随后对旧 Tier 1 密钥发碎纸标记（§3.4） |
| `UNLOCK` | `block` | `BlockContent`，`tier = 1` | 新建 Tier 1 BDEK 重新加密；旧 Tier 2 密钥是否碎纸由用户选择 |
| `RESOLVE` | `block` | `BlockContent` | **`UPDATE` 的别名**：读取端必须接受；写入端应写 `UPDATE` |
| `DELETE` | `buffer` / `block` | `Tombstone` | 携带当前已知全部叶子为 `parent_op_ids` |

载荷编码只有全量一种（`BlockContent` 内的 `zstd` 正文）；不存在依赖历史的增量载荷，因此任何单条 op 都能独立还原该版本 [保证]。

### 2.2 Sans-I/O 状态机输入事件与输出副作用契约

```rust
#[derive(Clone, Debug)]
pub enum SyncEvent {
    LocalMutation(LocalIntent),        // 不含 op_id：op_id 由 core 在此步内生成
    PullResponse {
        epoch: JournalEpoch,
        ops: Vec<RemoteEnvelopeRow>,
        head_seq: i64,
        has_more: bool,
    },
    PushAcked {
        epoch: JournalEpoch,
        acked: Vec<AckedOp>,
        head_seq: i64,
    },
    /// 密钥表与密钥材料全量比对结果（体量 ≈ 块数 × 约 250 B [估算]，见 §3.4、§3.5）
    KeyTableResponse {
        records: Vec<KeyRecordRow>,
        marks: Vec<ShredMarkRow>,
        keyring: Option<(u32, Vec<u8>)>,       // (keyring_gen, msgpack(RecoveryKeyringV1))
        vault_header: Option<(i64, Vec<u8>)>,  // (updated_at_ms, msgpack(VaultHeaderV1))
        server_now_ms: i64,
    },
    /// WebSocket 只做唤醒：只携带 head_seq，不携带 op
    WsWake {
        epoch: JournalEpoch,
        head_seq: i64,
    },
    /// 仅手机：下载到的当前状态快照（§3.6）
    SnapshotDownloaded {
        pointer: SnapshotPointer,
        raw_bytes: Vec<u8>,
    },
}

#[derive(Clone, Debug)]
pub enum StoreMutation {
    UpsertBuffer(MaterializedBuffer),
    UpsertBlock(MaterializedBlock),    // 同步替换该块的 block_leaves 行与 blocks_fts 条目
    AppendOp(LocalOpRecord),           // 含 MNS1 信封原文
    MarkOpsSynced { epoch: JournalEpoch, acked: Vec<AckedOp> },
    MarkOpBlocked { op_id: OpId, reason: String }, // 离线 Tier 2 遇旧钥退役且 Vault 未解锁时暂存，不阻塞其他 op
    ClearServerSeqsForReconcile { new_epoch: JournalEpoch },
    UpsertBlockKey(KeyRecordRow),
    UpsertShredMark(ShredMarkRow),
    UpsertKeyMaterial { kind: KeyMaterialKind, gen: i64, blob: Vec<u8>, updated_at_ms: i64 },
    /// 碎纸到期：删除本地密钥记录、该密钥对应的全部物化明文与 FTS 条目，随后执行 WAL checkpoint(TRUNCATE)
    ExecuteShred { key_id: KeyId },
    SetSyncMeta { bootstrap_completed: bool, journal_epoch: Option<JournalEpoch>, last_seq: i64 },
}

#[derive(Clone, Debug)]
pub enum SyncCommand {
    HttpPush(PushRequestDto),
    HttpPull { since_seq: i64, limit: u16 },
    SyncKeyTable(KeyTableSyncDto),     // 上送本地新建的密钥记录、密钥材料（keyring/vault_header）、碎纸标记与撤销，取回全量
    FetchSnapshot(SnapshotPointer),    // 仅手机
    UploadSnapshot { epoch: JournalEpoch, covers_seq: i64, bytes: Vec<u8> }, // 仅桌面；无 prev 指针、无 CAS
}
```

---

## 3. 密码学信封、密钥结构、快照与归档包字节布局（Wire Layout v1）

所有多字节整数在二进制线格式中统一采用 **小端序（Little-Endian）**。所有 AEAD 均为 `XChaCha20-Poly1305`（24 B 随机 Nonce + 16 B Tag）。

### 3.1 确定性 256 字节阶梯填充算法（Bijective 256B Bucket Padding）

对任意长度 $L \ge 0$ 的明文字节串 `raw`：
1. 计算需补零字节数：$\text{pad\_zeros} = (256 - ((L + 1) \bmod 256)) \bmod 256$（取值恒在 `0..=255`，恰好可由单字节 `u8` 表达）；
2. 构造填充帧：`padded = raw || [0x00; pad_zeros] || [pad_zeros as u8]`，总长度恒为 `256` 的正整数倍（最小 `256 B`）；
3. **严格解包校验**：验证 `padded.len() >= 256 && padded.len() % 256 == 0`，读取末字节 `p = padded[padded.len() - 1] as usize`，验证末尾前 `p` 个字节全为 `0x00`（拒绝非规范填充），截取前 `padded.len() - 1 - p` 字节还原 `raw`。

### 3.2 二进制信封字节布局

所有信封共用同一种外层头：`magic (4B ASCII) || version (1B = 0x01) || kid (16B) || nonce (24B) || aead_ciphertext (含 16B Tag)`，头部长度固定 `45 B`。`kid` 指明解密所用密钥。各信封的 AAD **只在 §3.3 定义**。

| 信封 | `kid` 字段含义 | 明文 | 存放位置 |
| --- | --- | --- | --- |
| (1) `MNS1` op 信封 | `smk_kid` | `pad256(msgpack(InnerOpV1))` | DO `ops.envelope`、本地 `sync_ops.envelope`、R2 op 归档 |
| (2) `MNB1` 块正文密文 | `key_id`（BDEK） | `pad256(zstd(msgpack(BlockPlaintextV1)))` | 嵌在 `BlockContent.mnb1` 中；本地 `block_leaves.ciphertext`（Tier 2）；手机快照与缓存 |
| (3) `MNR1` 密钥记录 | `smk_kid` | `msgpack(KeyRecordV1)`（§3.4） | DO / 本地 `block_keys.key_record`、R2 密钥表快照 |
| (4) `MNW1` VKEK 包裹的 BDEK | `vkek_kid` | 32 B BDEK | 只出现在 Tier 2 的 `KeyRecordV1.bdek` 内 |
| (5) `MNRS` 恢复公钥封装（sealed box，头部格式见 §3.5） | `recovery_kid` | 32 B SMK / VKEK | `RecoveryKeyringV1.smk_entries`、`VaultHeaderV1.sealed_vkek`（§3.5） |
| (6) `MNVH` Vault 头部内的 VKEK 包裹 | `vkek_kid` | 32 B VKEK | `VaultHeaderV1.wrapped_vkek`（§3.5） |
| (7) `MNP1` 手机状态快照 | `smk_kid` | 头 / 体两段（§3.6） | R2 |

- `MNB1` 两层填充：外层 `MNS1` 已填充，`MNB1` 再填充一次是为了让 Tier 2 正文长度对持有 SMK 的一方同样只按 256 B 档位可见；代价每 op ≤ 255 B [估算]。
- `zstd` 解压在手机端需要 WASM 实现（或日后改用浏览器原生 `DecompressionStream` 支持的格式，届时升 `version`）。

### 3.3 AAD 权威定义（全项目唯一）

> [!IMPORTANT]
> 本表是 AAD 的**唯一**定义。其他文档不得另写 AAD，只能链接本节。`||` 为字节拼接；ID 一律取 16 B 二进制；`magic` 为 4 B ASCII；`ver` 为 1 B `0x01`。

| 信封 | AAD |
| --- | --- |
| `MNS1` | `"MNS1" \|\| ver \|\| smk_kid \|\| op_id \|\| device_id.as_bytes() \|\| key_id`（不涉及 BDEK 的 op 在 AAD 中取 16 B 全零；外层 JSON / SQL 列传 `null`） |
| `MNB1` | `"MNB1" \|\| ver \|\| entity_id \|\| op_id \|\| key_id`（块正文取 `block_id`，`BufferMeta.name_mnb1` 取 `buffer_id`） |
| `MNR1` | `"MNR1" \|\| ver \|\| smk_kid \|\| key_id \|\| wrap_gen (u32 LE)` |
| `MNW1` | `"MNW1" \|\| ver \|\| vkek_kid \|\| key_id \|\| block_id` |
| `MNRS` | `"MNRS" \|\| ver \|\| recovery_kid \|\| kind \|\| kid` |
| `MNVH` | `"MNVH" \|\| ver \|\| vkek_kid \|\| msgpack(KdfParamsV1)` |
| `MNP1` 头 | `"MNP1" \|\| ver \|\| smk_kid \|\| snapshot_id \|\| covers_seq (i64 LE)` |
| `MNP1` 体 | `"MNP1" \|\| ver \|\| smk_kid \|\| hdr_blake3 (32B)` |

**`op_id` 的生成方与本地 Tier 2 封装分工（修正 F-01）**：

- `op_id` 由**执行正文加密的 `mynote-core` 实例**在加密之前生成（Monotonic ULID），同一个值同时写入 `MNB1` AAD、`MNS1` AAD 和 DO `ops.op_id` 列。
- **Tier 1 / 元数据写入**：本地 REST API 与 CLI 调用方不传入 `op_id`，由桌面 Daemon（或离线直写的 CLI 进程）内的 core 生成并封装 `MNS1` / `MNR1`。
- **Tier 2 写入**：桌面前端 `WasmVaultSession` 只持有 `VKEK`（不持有 `SMK`），因此它在 WASM 内生成 `(op_id, key_id)`、加密 `MNB1`（用 BDEK）并包裹 `MNW1`（用 `VKEK`，新建或换钥时），随本地 REST/UDS 请求**显式传递 `{ op_id, key_id, mnb1_b64, mnw1_b64? }`**；常驻 Daemon **原样采用该 `op_id`**，用 `SMK` 将 `MNW1` 封入 `MNR1`、将 `InnerOpV1` 封入 `MNS1`，绝不重新生成 `op_id`。
- 由于 `MNB1` 绑定 `op_id`，**同一份密文不能被另一个 op 复用**：任何产生新 op 的路径（合并、换钥、从回收站恢复、`UNLOCK`）都必须先取得明文再重新加密。对 Tier 2 块，这意味着这些操作必须在 Vault 解锁会话内完成。
- `MNB1` 同时绑定 `entity_id` 与 `key_id`：密文不能被搬到另一个实体，也不能被伪装成由另一把密钥加密。
- **`key_id` 在 op 外层明文可见**：`BlockContent` 与 `BufferMeta` 均携带非空明文 `key_id`；不涉及 BDEK 的 op（`SET_META`、`DELETE`）在外层 JSON 与 SQL `key_id` 列中统一为 **`null`**（仅在拼装 `MNS1` AAD 字节串时填入 16 B 全零），避免服务端把全零 ID 误判为 `KEY_UNKNOWN`。DO 存入 `ops.key_id` 并建部分索引，用于服务端的密钥竞态校验（见 [`sync-protocol.md`](./sync-protocol.md)）。由于 `key_id` 进入 `MNS1` AAD，服务端篡改该字段会让客户端解密失败而被发现。

### 3.4 实体数据密钥（BDEK）与独立密钥表（`block_keys` + `shred_marks`）

**这是 M1 线格式，不可推迟**：M1 写入的 op 会进入永久归档，必须从第一天起就用每块（及每 Buffer）独立的 BDEK 加密内容，日后才能单独删除某一实体（审查 [§9.3](../review/2026-11-24-first-principles-review.md)；`shred_marks` 状态机与到期执行器在 M2 上线）。

#### 3.4.1 BDEK

- 每块（及每 Buffer）至少一把 32 B 随机 BDEK；同一实体的各个版本默认共用同一把。**换钥**（「清除历史」、`LOCK`、`UNLOCK`、碎纸后复活）会新建 BDEK′，因此一个实体在密钥表中可能对应多条记录。
- Tier 1 BDEK：由 SMK 保护（即 `MNR1` 记录的封装本身）。Tier 2 BDEK（仅块）：先由 VKEK 包裹为 `MNW1`，再放进 `MNR1` 记录。

#### 3.4.2 密钥记录（只创建、不修改逻辑内容）

```rust
/// MNR1 的明文
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRecordV1 {
    pub v: u8,                     // 1
    pub key_id: KeyId,
    pub block_id: BlockId,         // 归属实体 ID：Block 填 BlockId，Buffer 填 BufferId（同为 16B ULID）
    pub tier: u8,                  // 1 | 2（Buffer 恒为 1）
    pub created_hlc: String,
    pub created_by: DeviceId,
    pub bdek: Vec<u8>,             // tier 1：32 B 原始 BDEK；tier 2：MNW1 信封（45 + 32 + 16 = 93 B）
}

/// 线上 / 表中的一行（服务端可见部分 + 密文）
pub struct KeyRecordRow {
    pub key_id: KeyId,
    pub wrap_gen: u32,             // 密钥环代际：轮换时重新封装记录，代际 +1
    pub key_record: Option<Vec<u8>>, // MNR1；None = 已碎纸（终态）
    pub created_at_ms: i64,        // 服务端接收时间
}
```

- **逻辑内容不可变**：`key_id → (block_id, tier, BDEK)` 一旦创建永不修改。唯一允许的「替换」是密钥环轮换时用更新的 `wrap_gen` 重新封装同一内容（§3.5）。
- 单条约 250 B [估算]；1 万块约 2.5 MB [估算]，每次同步连同 `key_material` 全量比对。
- 服务端可见的元数据：`key_id`、创建时间、`wrap_gen`、碎纸请求的时间与数量。**服务端看不到某把密钥属于哪个块、属于哪一层**（`block_id` 与 `tier` 在 `MNR1` 密文内）。但 `ops.key_id` 暴露了哪些 op 共用同一把密钥，且「新建密钥 + 对旧密钥发 24 小时碎纸」的时序可能暴露「某个块被换钥/加锁了」，只是看不出是哪一块（F-18 的诚实表述）。

#### 3.4.3 碎纸标记（M2 启用）

```rust
pub enum ShredMarkState {
    PendingConfirm, // 超出每日批量阈值 N：不计时，需桌面 UI 确认
    Scheduled,      // 计时中，not_before 前可撤销
    Cancelled,      // 终态：已撤销
    Executed,       // 终态：DO alarm 已置空密钥
}

pub struct ShredMarkRow {
    pub mark_id: MarkId,
    pub key_id: KeyId,                 // 只引用 key_id，不含 block_id / tier
    pub seen_seq: i64,                 // 请求方发出标记时已见到的最大 seq（竞态校验用）
    pub requested_by: DeviceId,
    pub requested_at_ms: i64,
    pub grace_ms: i64,                 // 请求的宽限时长（默认 T_grace = 7 天；>= T_grace_min）
    pub not_before_ms: Option<i64>,    // PendingConfirm 时为 None；Scheduled 时 = 服务端接收时刻 + max(grace_ms, T_grace_min)；
                                       // 由 PendingConfirm 确认时设为 confirmed_at_ms + max(grace_ms, T_grace_min)；
                                       // UI 缩短宽限期（expedite）时更新为 min(原值, 缩短请求时刻 + T_grace_min) 且 >= requested_at_ms + T_grace_min
    pub state: ShredMarkState,
    pub confirmed_at_ms: Option<i64>,  // PendingConfirm → Scheduled 的确认时刻
    pub cancelled_by: Option<DeviceId>,
    pub executed_at_ms: Option<i64>,
}
```

- 参数（审查 Q7–Q9，已拍板）：`T_grace` = 7 天；`T_grace_min` = 24 小时（「先写后锁」或清空回收站在 UI 中可缩短到此下限）；批量阈值 N = 20 个/天。
- **服务端只强制三件事**：`grace_ms ≥ T_grace_min`（及任何 `not_before_ms ≥ requested_at_ms + T_grace_min`）、每日批量阈值（超出部分进入 `PendingConfirm`）、令牌范围（`read` 令牌一律 `403`）。已到期置空后（`state = Executed`）的撤销返回 `410 KEY_SHREDDED`。
- 「缩短宽限期、清空回收站、确认 `PendingConfirm` 只能在 UI 交互确认」由**本地 Daemon** 强制：服务端无法区分 UI 与 CLI。CLI 只能把块删进回收站（M2 起以默认 `T_grace` 写碎纸标记）。
- 新建标记必须携带 `seen_seq`（请求方已见到的最大 `seq`）。同批 push 按「密钥记录 → 撤销 → op → 碎纸标记」顺序在单事务内执行，服务端做三项竞态校验并返回对应错误码：本批之前该 `key_id` 已存在 `seq > seen_seq` 的其他 op → `SHRED_STALE`；对已存在 `PendingConfirm` / `Scheduled` 标记的 `key_id` 推送新 op、且同批未先撤销 → `KEY_PENDING_SHRED`；op 引用已执行碎纸或未知的 `key_id` → `KEY_SHREDDED` / `KEY_UNKNOWN`。错误码到 CLI 的映射见 [`interface-contracts.md`](./interface-contracts.md)。
- 端点（`/v1/keys`、`/v1/keys/shred`、`/v1/keys/cancel`、`/v1/keys/confirm`）与 alarm 实现见 [`cloudflare-cloud-architecture.md`](./cloudflare-cloud-architecture.md)；请求流程见 [`sync-protocol.md`](./sync-protocol.md)。

#### 3.4.4 合并规则（2P-Set）

记密钥记录集合为 $K$，碎纸标记集合为 $M$。各副本（每台桌面、DO、手机缓存）独立保存，合并为逐元素取上确界：

1. **记录**：按 `key_id` 取并集；同一 `key_id` 取 `wrap_gen` 最大者；`key_record = None`（已碎纸）为终态，优先于任何代际。
2. **标记**：按 `mark_id` 取并集；`state` 按 `PendingConfirm < Scheduled < {Cancelled, Executed}` 取较大者（两个终态互斥，由服务端唯一裁定，客户端以服务端为准）；`Scheduled` 状态下的 `not_before_ms` 取非空值中的 `min`（缩短宽限期只会将到期日提前，且受服务端 `requested_at_ms + T_grace_min` 下界约束）。
3. **生效（服务端唯一裁判）**：标记 $m$ 生效 ⇔ `state = Executed`（仅由 DO alarm 在服务端时间越过 `not_before_ms` 后写入；**客户端本地时钟绝不参与生效判定**，防止本机时钟快偏或离线期间远端已撤销而误删本地密钥）。`PendingConfirm` 不计时、不生效。
4. **可用密钥** $= \{ k \in K \mid k.\text{key\_record} \neq \text{None} \land \nexists\, m \in M: m.\text{key\_id} = k \land m.\text{state} = \text{Executed} \}$。
5. **撤销只在执行前有效**：DO alarm 置为 `Executed` 之后到达的撤销返回 `410 KEY_SHREDDED`。因此一个标记一旦执行，结果对所有副本都是永久的。
6. 合并本身不会让任何密钥消失；只有服务端已置为 `Executed` 的碎纸标记会触发各端执行本地 `ExecuteShred` 并将 `key_id` 记入本地已碎纸墓碑集合。

**不变量**（门禁见 [`eval-framework.md`](./eval-framework.md)）：

- **INV-KEY-LIVENESS**：未进入碎纸流程的块，其所有非墓碑叶子引用的 `key_id` 在全部副本中始终属于「可用密钥」。每日自检若发现违反，告警并禁止该设备继续发碎纸请求。
- 引用某 `key_id` 的 op 被推送之前，对应密钥记录必须已被服务端确认或在同一批次中排在前面提交（顺序规则见 [`sync-protocol.md`](./sync-protocol.md)）。
- 换钥后对旧密钥发碎纸之前，必须确认服务端已确认新 op 与新密钥记录（或在同一批次中置于 op 之后原子提交）。
- 已碎纸的 `key_id` 永不重新创建；复活一律使用新 `key_id`。离线设备对已碎纸块的编辑，用新 BDEK 重新加密为新版本，`BlockContent` 中必须填写 `buffer_id` / `position` / `lang`（作为该 op HLC 下的字段 LWW 赋值），以便只读快照之外的设备也能重建该块。

### 3.5 统一恢复包、恢复密钥环与 Vault 头部

只有**一份**恢复材料（修正 F-05）。恢复包派生一对 X25519「恢复密钥对」：设备上**只存恢复公钥**，任何设备都能随时把新的 SMK 代际 / VKEK 封装（sealed box）进来，无需输入 24 词；只有解封需要 24 词。

```text
统一恢复包（24 词，BIP39 英文词表，256-bit 熵）
   └─ HKDF-SHA256(ikm = entropy, salt = "mynote-recovery-v1", info = "seed") → Root Seed (32 B)
        └─ HKDF-SHA256(Root Seed, info = "x25519-recovery") → recovery_sk（X25519 clamp）
             └─ recovery_pk = X25519(recovery_sk, base)        ← 设备与 DO 只保存这一项
恢复密钥环 RecoveryKeyringV1 = [ MNRS(smk_v1), MNRS(smk_v2), …, MNRS(smk_vN) ]（只追加）
Vault 头部 VaultHeaderV1 = { MNVH(口令派生密钥 → VKEK), MNRS(recovery_pk → VKEK) }
   SMK_i → 解开 MNS1 / MNR1 / MNP1        VKEK → 解开 MNW1（Tier 2 BDEK）
```

```rust
/// 恢复密钥环：SMK 各代际的恢复公钥封装（只追加）
pub struct RecoveryKeyringV1 {
    pub v: u8,                         // 1
    pub recovery_kid: [u8; 16],        // = BLAKE3(recovery_pk)[..16]，打印在恢复包上供核对
    pub recovery_pk: [u8; 32],
    pub keyring_gen: u32,              // 每次轮换（SMK 或 VKEK）+1；KeyRecordRow.wrap_gen 的取值来源
    pub current_smk_kid: SmkKid,
    pub smk_entries: Vec<Vec<u8>>,     // MNRS 信封（kind = SMK），全部代际，只追加
}

/// Vault 头部：解锁 VKEK 的全部材料（单套 KDF 参数，按 iPhone 定）
pub struct VaultHeaderV1 {
    pub v: u8,                         // 1
    pub vkek_kid: VkekKid,
    pub kdf: KdfParamsV1,
    pub wrapped_vkek: Vec<u8>,         // MNVH：口令派生密钥包裹（45 + 32 + 16 = 93 B）
    pub sealed_vkek: Vec<u8>,          // MNRS（kind = VKEK）：恢复公钥封装，忘记口令时用恢复包取回
    pub retired: Vec<RetiredVkekV1>,   // VKEK 轮换后的旧代际，退役满 T_snap 后移除
    pub updated_at_ms: i64,
}
pub struct RetiredVkekV1 { pub vkek_kid: VkekKid, pub wrapped_vkek: Vec<u8>, pub sealed_vkek: Vec<u8>, pub retired_at_ms: i64 }

pub struct KdfParamsV1 {
    pub alg: String,                   // "argon2id"
    pub m_kib: u32,                    // 内存参数：32_768 (32 MiB，S0-3 iPhone 主屏 PWA 实测 1553 ms 定值 [已测])
    pub t: u32,                        // 迭代次数：2 [已测]
    pub p: u32,                        // 并行度：1 [已测]
    pub salt: [u8; 16],
}
```

**`MNRS` 封装信封**（sealed box；头部比通用格式多出类型、被封装密钥 ID 与临时公钥）：

| 偏移（Bytes） | 字段 | 长度 | 说明 |
| --- | --- | :---: | --- |
| `0..4` | `magic` | `4 B` | `"MNRS"` |
| `4..5` | `version` | `1 B` | `0x01` |
| `5..21` | `recovery_kid` | `16 B` | 所用恢复公钥的指纹 |
| `21..22` | `kind` | `1 B` | `0x01` = SMK，`0x02` = VKEK |
| `22..38` | `kid` | `16 B` | 被封装的 `smk_kid` / `vkek_kid` |
| `38..70` | `eph_pk` | `32 B` | 一次性 X25519 公钥 |
| `70..94` | `nonce` | `24 B` | 随机 Nonce |
| `94..` | `ciphertext` | `32 + 16 B` | AEAD 密钥 = `HKDF-SHA256(ikm = X25519(eph_sk, recovery_pk), salt = eph_pk ‖ recovery_pk, info = "mynote-seal-v1")`（实现必须拒绝全零 X25519 共享秘密以排除低阶点），明文为 32 B 密钥 |

- **日常密钥存放**：桌面 Daemon（OS Keychain / Secret Service）**只持有 Tier 1 的 SMK 代际**与恢复公钥；VKEK 只以 `wrapped_vkek`（口令）与 `sealed_vkek`（恢复公钥）两种形式存在于 Vault 头部，**Daemon 不持有任何能解开 VKEK 的材料**（Tier 2 解密只在解锁后的 Vault 会话内存中进行，信任边界见 [`threat-model.md`](./threat-model.md)）。Root Seed 与 `recovery_sk` 只在恢复或本地解锁新 SMK 代际时由用户输入 24 词临时派生，用后清零。
- **SMK 代际永久保留**：R2 op 归档永久保留且其中的 `MNS1` 由当时的 SMK 加密，删除旧 SMK 等于让归档不可读，因此 `smk_entries` 只追加，设备 Keychain 中的 SMK 代际也不删除。所谓「旧代际保留 `T_snap`」只适用于**用旧代际封装的历史密钥表快照**（R2 `archives/keys/history/`、本地自动备份）：轮换时全部 `MNR1` 以新 `wrap_gen` 重新封装，旧封装副本随 `T_snap` 生命周期自然淘汰。VKEK 只用于包裹 BDEK，因此退役的 VKEK 可在 `T_snap` 后移除。
- **轮换与存留设备密钥刷新** = 生成新 SMK（或 VKEK）→ 用恢复公钥封装后追加（VKEK 则写入新 Vault 头部，旧的移入 `retired`）→ `keyring_gen + 1` → 以新代际重新封装全部 `MNR1`（VKEK 轮换需在 Vault 会话内重新包裹 Tier 2 的 `MNW1`）并随 `/v1/keys` 上传更新 `key_material`。**不需要重新抄写 24 词**，轮换后运行 `mynote recovery drill` 确认恢复包有效。其他未吊销的存留设备通过两条低复杂度路径之一获取新 `SMK` 代际（不引入设备级长期公钥树）：(1) 在已轮换桌面上执行 `mynote device refresh <device_id>` 生成复用 `pairing_tickets` 的 10 分钟一次性刷新码，在存留设备上 `claim` 领取；(2) 单机/异地时直接在存留桌面上执行 `mynote keyring unlock` 输入一次 24 词解封 `RecoveryKeyringV1`。
- **Vault 口令变更**只重新生成 `salt` 与 `wrapped_vkek`，VKEK 不变，不触碰密钥表。Vault 不再有第二套 24 词恢复码：忘记口令时用统一恢复包解开 `sealed_vkek`，再设新口令。
- KDF 参数只有一套，按最弱设备（iPhone）定，参数和盐存于 Vault 头部；S0-3 iPhone 主屏 PWA 真机已实测定型为 `(m_kib=32768, t=2, p=1)`（中位 `1553 ms` [已测]，稳落 `1–2 s` 目标区间，详见 [`s0-3-wasm-argon2.md`](./spikes/s0-3-wasm-argon2.md)）。
- 服务端可以截断或替换 `smk_entries` 列表（单条封装本身有 AEAD 认证，伪造的条目只会解封失败）。缓解：每台桌面在本地 `key_material` 保留完整副本并在同步时比对条目数，R2 密钥表快照中也有副本；INV-RECOVERY 演练覆盖。
- `RecoveryKeyringV1` 与 `VaultHeaderV1` 存放在 DO `key_material`、本地 `key_material`，随 `/v1/keys` 同步（仅接受更大的 `gen`；其中 `keyring` 的 `gen = keyring_gen`，`vault_header` 的 `gen = updated_at_ms` 单调毫秒时间戳），并随每日密钥表快照进入 R2。手机只缓存 `VaultHeaderV1`。

### 3.6 手机用当前状态快照（`MNP1`，头体分离双段认证结构）

由**任一桌面**每日或在尾部 op 超过阈值时发布到 R2，**只给手机引导用**；桌面之间的同步与因果判定永远基于完整历史，快照不参与。按 `covers_seq` 单调接受（DO 只接受比现有最大值更大的 `covers_seq`），R2 保留最近 2 份；无 `prev` 指针、无 CAS。

```text
+-------------------+-------------+-----------------+-------------------+--------------+-------------------+---------------+-------------------+
| "MNP1" + ver (5B) | smk_kid(16B)| snapshot_id(16B)| covers_seq(8B LE) | hdr_nonce(24)| hdr_ct_len(u32_le)| hdr_ct (AEAD) | body_nonce(24)+ct |
+-------------------+-------------+-----------------+-------------------+--------------+-------------------+---------------+-------------------+
|<-------------------------------------------- 73 B 定长认证前缀 -------------------------------------------->|
```

```rust
pub struct SnapshotHeaderV1 {
    pub v: u8,
    pub journal_epoch: JournalEpoch,
    pub snapshot_id: SnapshotId,
    pub covers_seq: i64,               // 快照已反映 seq <= covers_seq 的全部 op
    pub buffer_count: u32,
    pub block_count: u32,
    pub leaf_count: u32,
    pub created_by: DeviceId,
    pub created_at_ms: i64,
}

/// zstd 压缩后加密
pub struct SnapshotBodyV1 {
    pub buffers: Vec<SnapshotBufferV1>,
    pub blocks: Vec<SnapshotBlockV1>,  // 不含 Shredded 状态的块；Trashed 块只含墓碑叶子
}

pub struct SnapshotBufferV1 {
    pub id: BufferId,
    pub position: String,
    pub key_id: KeyId,                 // Buffer 自己的 BDEK
    pub name_op_id: OpId,              // 名称 LWW 胜出的 op（MNB1 AAD 依赖它）
    pub name_mnb1: Vec<u8>,            // 原样复制，仍由 Buffer 的 BDEK 加密
    pub field_hlc: BufferFieldHlc,
}

pub struct SnapshotBlockV1 {
    pub id: BlockId,
    pub buffer_id: BufferId,
    pub position: String,
    pub lang: String,
    pub public_hint: Option<String>,
    pub field_hlc: BlockFieldHlc,      // 字段 LWW 结果及其 HLC
    pub leaves: Vec<SnapshotLeafV1>,   // 每块的全部叶子
}

pub struct SnapshotLeafV1 {
    pub op_id: OpId,                   // 原 op 的 op_id（MNB1 AAD 依赖它）
    pub hlc: String,
    pub device_id: DeviceId,
    pub actor: String,
    pub body: SnapshotLeafBody,
}

pub enum SnapshotLeafBody {
    Content { tier: u8, key_id: KeyId, mnb1: Vec<u8> }, // 原样复制 op 中的 MNB1，仍由各自 BDEK 加密
    Tombstone { deleted_at_ms: i64 },
}
```

- 快照**不含任何密钥**：手机另行同步密钥表（§3.4）。块被碎纸后，快照里残留的 `MNB1` 也无法解密；下一份快照不再包含该块。
- 桌面构造快照时，叶子的 `mnb1` 从本地 `sync_ops.envelope` 中解出，不需要重新加密。
- 手机应用尾部 op 的唯一规则：把该 op 加入所属块的叶子集，并从叶子集中移除它的 `parent_op_ids`；`BlockMeta` / `BufferMeta` 按字段 LWW 合并。
- 快照出错的后果只限于手机显示不对，重新拉取即可，不会写回任何数据。

### 3.7 R2 归档与密钥表快照（服务端生成的容器）

两类对象都由 DO 的每日任务生成。容器本身不再加密（内容已是密文），只做完整性校验。Worker 不对外暴露归档 HTTP 路由。

| 对象 | R2 键 | 内容 | 保留 |
| --- | --- | --- | --- |
| op 密文归档 `MNA1` | `archives/ops/<journal_epoch>/<from_seq:012>-<to_seq:012>.mna1` | 头 `"MNA1" \|\| ver \|\| msgpack({ journal_epoch, from_seq, to_seq, row_count, created_at_ms })`，体 = `msgpack(Vec<{ seq, op_id, key_id, device_id, created_at, envelope }>)`，尾 = 前文 `blake3 (32B)` | **永久、只追加** |
| 最新密钥表快照 `MNKS` | `archives/keys/latest.mnks` | 头 `"MNKS" \|\| ver \|\| msgpack({ created_at_ms, keyring_gen, record_count })`，体 = `msgpack({ keyring: RecoveryKeyringV1, vault_header: Option<VaultHeaderV1>, records: Vec<KeyRecordRow>（仅可用密钥）, marks: Vec<ShredMarkRow> })`，尾 = `blake3` | **每日覆写、不挂生命周期删除**（碎纸次日即被覆盖移除，停写超 30 天也不会归零） |
| 历史密钥表快照 `MNKS` | `archives/keys/history/<yyyy-mm-dd>.mnks` | 同上 | R2 生命周期规则删除，`T_snap` = 30 天 |

- 极端双重灾难恢复（`mynote restore --from-archive <local-dir>`，契约见 [`interface-contracts.md`](./interface-contracts.md)）= 本地导出的全部 `MNA1` + `latest.mnks` + 统一恢复包。若仅客户端设备全失而 DO 仍健在，直接凭 `BOOTSTRAP_TOKEN` + 24 词从 DO 全量拉回即可。
- 彻底不可恢复的上界（`T_grace + max(DO PITR 30 天, T_snap)` ≈ 37 天）的推导与承诺见 [`threat-model.md`](./threat-model.md)。

---

## 4. 桌面端本地 SQLite 完整 DDL Schema（`mynote-store`）

全部业务表启用 SQLite `STRICT` 强类型检查，并通过数据库级 `CHECK` 约束在物理层锁死「Tier 2 叶子 `content` 必须为 `NULL`」不变量。桌面保存**完整** op 历史（`sync_ops` 不截断）。

```sql
-- 连接打开时必须执行的 PRAGMA 序列：
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;
PRAGMA secure_delete = ON;

-- 1. 本地键值元数据（device_id, journal_epoch, bootstrap_completed, last_synced_seq,
--    schema_version, min_reader_schema_version, last_self_check_at_ms 等）
CREATE TABLE IF NOT EXISTS local_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

-- 2. 工作区 Buffer 表（使用 Fractional Index 排序；字段 LWW）
--    ExecuteShred 执行时保留行主键（避免旗下仍有存活/待确认块时触发 blocks.buffer_id 外键报错），清空 name 并置 state = 'SHREDDED'
CREATE TABLE IF NOT EXISTS buffers (
    id            TEXT PRIMARY KEY,          -- 26B ULID
    name          TEXT NOT NULL,             -- 本地物化明文；state = 'SHREDDED' 时置为 ''
    key_id        TEXT NOT NULL,             -- Buffer 自己的 BDEK（Tier 1）
    position      TEXT NOT NULL,             -- Base62 分数索引
    name_hlc      TEXT NOT NULL,             -- 定长 Canonical HLC
    position_hlc  TEXT NOT NULL,
    state         TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'TRASHED', 'SHREDDED')),
    updated_at_ms INTEGER NOT NULL,
    deleted_at_ms INTEGER                    -- NULL = 存活
) STRICT;

CREATE INDEX IF NOT EXISTS idx_buffers_active_order
    ON buffers (position COLLATE BINARY ASC, id ASC)
    WHERE state = 'ACTIVE';

-- 3. 块物化主表：字段 LWW 结果 + 状态；正文在 block_leaves
CREATE TABLE IF NOT EXISTS blocks (
    id                 TEXT PRIMARY KEY,     -- 26B ULID
    buffer_id          TEXT NOT NULL REFERENCES buffers(id),
    position           TEXT NOT NULL,        -- Base62 分数索引
    lang               TEXT NOT NULL,        -- 'markdown' | 'json' | 'sql' | 'mermaid' | ...
    public_hint        TEXT,
    buffer_id_hlc      TEXT NOT NULL,
    position_hlc       TEXT NOT NULL,
    lang_hlc           TEXT NOT NULL,
    public_hint_hlc    TEXT NOT NULL,
    state              TEXT NOT NULL CHECK (state IN ('ACTIVE', 'TRASHED', 'SHREDDED')),
    is_locked          INTEGER NOT NULL CHECK (is_locked IN (0, 1)), -- 任一存活叶子 tier = 2
    display_op_id      TEXT,                 -- 存活叶子中 (hlc, op_id) 最大者
    leaf_count         INTEGER NOT NULL DEFAULT 1,
    updated_at_ms      INTEGER NOT NULL,
    deleted_at_ms      INTEGER,              -- 进入回收站的时间
    CHECK ((state = 'ACTIVE') = (display_op_id IS NOT NULL))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_blocks_buffer_order
    ON blocks (buffer_id, position COLLATE BINARY ASC, id ASC)
    WHERE state = 'ACTIVE';

-- 4. 叶子物化表（取代 block_conflicts）：每块的全部叶子，毫秒级直读渲染
--    块进入回收站时只剩墓碑叶子，物化明文随之删除；预览从 sync_ops 按需解密
CREATE TABLE IF NOT EXISTS block_leaves (
    block_id      TEXT NOT NULL REFERENCES blocks(id) ON DELETE CASCADE,
    op_id         TEXT NOT NULL,
    hlc           TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    actor         TEXT NOT NULL,
    body_state    TEXT NOT NULL CHECK (body_state IN ('PLAINTEXT', 'SEALED', 'TOMBSTONE', 'KEY_UNAVAILABLE', 'DECRYPT_FAILED')),
    tier          INTEGER CHECK (tier IN (1, 2)),
    key_id        TEXT,
    content       TEXT,                      -- 仅 Tier 1 明文
    ciphertext    BLOB,                      -- 仅 Tier 2 的 MNB1
    PRIMARY KEY (block_id, op_id),
    CHECK (
        (body_state = 'PLAINTEXT'       AND tier = 1 AND key_id IS NOT NULL AND content IS NOT NULL AND ciphertext IS NULL)
        OR
        (body_state = 'SEALED'          AND tier = 2 AND key_id IS NOT NULL AND content IS NULL AND ciphertext IS NOT NULL)
        OR
        (body_state = 'TOMBSTONE'       AND tier IS NULL AND key_id IS NULL AND content IS NULL AND ciphertext IS NULL)
        OR
        (body_state IN ('KEY_UNAVAILABLE', 'DECRYPT_FAILED') AND content IS NULL AND ciphertext IS NULL)
    )
) STRICT;

CREATE INDEX IF NOT EXISTS idx_block_leaves_key ON block_leaves (key_id) WHERE key_id IS NOT NULL;

-- 5. 全文搜索倒排索引（rowid 对齐 block_leaves.rowid；仅索引 is_locked = 0 的 ACTIVE 块中的 PLAINTEXT 叶子，
--    在 Rust 写事务内同步维护；块删除或加锁时立即移除对应条目）
CREATE VIRTUAL TABLE IF NOT EXISTS blocks_fts USING fts5(
    content,
    public_hint,
    tokenize = 'unicode61 remove_diacritics 2'
);

-- 6. 本地完整操作日志与待同步出站队列（server_seq IS NULL AND sync_blocked_reason IS NULL 即为待推 Outbox；永久保留，不截断）
--    envelope 为 MNS1 原文；块正文只以 MNB1 密文存在其中，碎纸其 BDEK 即令该段历史不可读
CREATE TABLE IF NOT EXISTS sync_ops (
    op_id                TEXT PRIMARY KEY,       -- 26B ULID
    server_seq           INTEGER,                -- 当前 journal_epoch 下的云端序号；未推送为 NULL
    sync_blocked_reason  TEXT,                   -- 如 'NEEDS_VAULT_REKEY'（离线 Tier 2 遇旧钥退役待解锁重加密，不阻塞其他 op）
    device_id            TEXT NOT NULL,
    entity_type          TEXT NOT NULL CHECK (entity_type IN ('buffer', 'block')),
    entity_id            TEXT NOT NULL,
    parent_op_ids        TEXT NOT NULL,          -- JSON 数组字符串，如 '["01J..."]'
    op_type              TEXT NOT NULL CHECK (op_type IN ('CREATE','UPDATE','SET_META','LOCK','UNLOCK','RESOLVE','DELETE')),
    hlc                  TEXT NOT NULL,
    actor                TEXT NOT NULL DEFAULT 'human',
    key_id               TEXT,                   -- BlockContent 与 BufferMeta 所用 BDEK；SET_META / DELETE 为 NULL
    smk_kid              TEXT NOT NULL,
    envelope             BLOB NOT NULL,          -- MNS1 原文
    created_at_ms        INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_sync_ops_outbox
    ON sync_ops (created_at_ms ASC, op_id ASC)
    WHERE server_seq IS NULL AND sync_blocked_reason IS NULL;

CREATE INDEX IF NOT EXISTS idx_sync_ops_entity_history
    ON sync_ops (entity_type, entity_id, hlc ASC);

-- 7. 实体数据密钥表（§3.4.2；与 DO 侧逐行对应，同步时全量比对）
CREATE TABLE IF NOT EXISTS block_keys (
    key_id         TEXT PRIMARY KEY,         -- 26B ULID
    block_id       TEXT NOT NULL,            -- 本地解密 MNR1 后填写归属 BlockId / BufferId，便于自检与 ExecuteShred
    tier           INTEGER NOT NULL CHECK (tier IN (1, 2)),
    wrap_gen       INTEGER NOT NULL,
    key_record     BLOB,                     -- MNR1；碎纸执行后置 NULL（终态）
    created_hlc    TEXT NOT NULL,
    created_at_ms  INTEGER NOT NULL,
    server_acked   INTEGER NOT NULL DEFAULT 0 CHECK (server_acked IN (0, 1))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_block_keys_block ON block_keys (block_id);

-- 8. 碎纸标记（§3.4.3，M2 启用；2P-Set 合并规则见 §3.4.4；另存本地已碎纸 key_id 永久墓碑集合于 local_meta 或本表 executed 行）
CREATE TABLE IF NOT EXISTS shred_marks (
    mark_id          TEXT PRIMARY KEY,
    key_id           TEXT NOT NULL REFERENCES block_keys(key_id),
    requested_by     TEXT NOT NULL,
    requested_at_ms  INTEGER NOT NULL,
    seen_seq         INTEGER NOT NULL,
    grace_ms         INTEGER NOT NULL,
    not_before_ms    INTEGER,                -- 服务端赋值；pending_confirm 时为 NULL
    state            TEXT NOT NULL CHECK (state IN ('pending_confirm', 'scheduled', 'cancelled', 'executed')),
    confirmed_at_ms  INTEGER,
    cancelled_by     TEXT,
    executed_at_ms   INTEGER,
    server_acked     INTEGER NOT NULL DEFAULT 0 CHECK (server_acked IN (0, 1))
) STRICT;

CREATE INDEX IF NOT EXISTS idx_shred_marks_key ON shred_marks (key_id);

-- 9. 密钥环与 Vault 头部的本地副本（§3.5；SMK 明文代际存于 OS Keychain / Secret Service，不在此表）
CREATE TABLE IF NOT EXISTS key_material (
    kind           TEXT PRIMARY KEY CHECK (kind IN ('keyring', 'vault_header')),
    gen            INTEGER NOT NULL,         -- keyring_gen；vault_header 用 updated_at_ms 单调值
    blob           BLOB NOT NULL,            -- msgpack(RecoveryKeyringV1) / msgpack(VaultHeaderV1)
    updated_at_ms  INTEGER NOT NULL
) STRICT;

-- 10. CLI 幂等键防重表（保留最近 7 天）
CREATE TABLE IF NOT EXISTS idempotency_keys (
    idem_key       TEXT PRIMARY KEY,
    command        TEXT NOT NULL,
    entity_id      TEXT NOT NULL,
    op_id          TEXT NOT NULL,
    created_at_ms  INTEGER NOT NULL
) STRICT;
```

**删除与碎纸对本地存储的作用**（流程见 [`sync-protocol.md`](./sync-protocol.md)）：

- `DELETE`：块 `state → 'TRASHED'`，`block_leaves` 只剩墓碑叶子，FTS 条目立即删除；`sync_ops` 中的密文原样保留，宽限期内可据此恢复。
- `ExecuteShred { key_id }`（仅在收到服务端 `state = 'executed'` 时执行）：`block_keys.key_record = NULL`；引用该 `key_id` 的叶子转为 `KEY_UNAVAILABLE`；若该块全部叶子均为墓碑/已碎纸且已无任何可用密钥则 `state → 'SHREDDED'`（若目标为 Buffer，则 `buffers.name = ''` 且 `state → 'SHREDDED'`，若其下仍有存活块则在 UI 归入「已删除工作区遗留块」视图）；随后 `PRAGMA wal_checkpoint(TRUNCATE)`（`secure_delete` 已开启）。门禁 INV-SHRED-BOUND 断言此后本地数据库、WAL、FTS、本地备份中都找不到该密钥与对应明文。

### 4.1 本地数据目录、备份与 Schema 版本保护

桌面数据目录（Linux: `~/.local/share/mynote/`；macOS: `~/Library/Application Support/mynote/`）默认排除出 Time Machine（`tmutil addexclusion`）与 Omarchy 文件系统快照，维护以下受控结构：

- **`local_meta` 强制版本锁键**：
  - `schema_version`（同步写入 `PRAGMA user_version`）：当前库已应用的最新迁移号；
  - `min_reader_schema_version`：允许安全读写当前库的最低二进制可识别 Schema 版本号。若旧版二进制（例如经包管理器降级后）发现自身支持的最高 Schema 版本 `< min_reader_schema_version`，立即以退出码 `8`（`INTEGRITY_ERROR: SCHEMA_TOO_NEW`）拒绝写入，防止旧代码误毁新表结构。
- **跨 Schema 升级前自动一致性快照（`backups/mynote-pre-schema-v<N>.db`）**：
  - 仅在版本升级触发 `PRAGMA user_version` 递增前自动通过 `VACUUM INTO` 生成单文件快照（权限 `0600`，最多保留最近 2 代）。
- **每日自动备份（`backups/auto-<yyyy-mm-dd>.db`）**：`VACUUM INTO` 生成，权限 `0600`，按 `T_snap`（30 天）轮换删除，使碎纸后的残留副本在有界时间内消失。
- **只读 Markdown 镜像（`mirror/`）**：只含 `ACTIVE` 且未加锁块的展示版本，块删除时同步删除对应文件。

---

## 5. 云端 Cloudflare DO SQLite 完整 DDL Schema（`cloud-cf`）

服务端保持极薄：幂等追加、分配 `seq`、按 `seq` 分页、`epoch`、令牌范围、WebSocket 唤醒、密钥表 / 密钥材料存储、M2 起的碎纸标记校验与 alarm 置空、每日归档。基于 Workers Paid（单 SQLite DO 10 GB），**不做 GC**。

> [!NOTE]
> INV-SYNC-6「每 op 恰好 2 行写入」已放宽：Paid 套餐内含每月 5,000 万行写，本项目约每月 3 万行写 [估算]，占比约 0.06%。`ops` 表仍保持最小列以减少元数据暴露；确有需要时可以加二级索引。批量推送仍须遵守 DO SQL **单语句最多 100 个绑定参数**的平台限制（逐行预编译语句循环执行）。

```sql
-- 1. DO 全局元数据（journal_epoch, last_archive_seq, last_key_snapshot_day 等）
CREATE TABLE IF NOT EXISTS journal_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- 2. 注册设备、令牌哈希、令牌范围与同步水位表
--    未认领配对票据预注册的设备 claimed_at_ms 为 NULL（尚未激活鉴权），票据超时未领时级联删除该幽灵行
CREATE TABLE IF NOT EXISTS devices (
    device_id        TEXT PRIMARY KEY,
    device_name      TEXT NOT NULL,
    token_sha256_hex TEXT NOT NULL UNIQUE,
    scope            TEXT NOT NULL CHECK (scope IN ('read', 'read-write')), -- 手机为 'read'：push / 碎纸 / 撤销 / 快照上传一律 403
    last_pulled_seq  INTEGER NOT NULL DEFAULT 0,
    last_seen_at_ms  INTEGER NOT NULL,
    created_at_ms    INTEGER NOT NULL,
    claimed_at_ms    INTEGER,                -- bootstrap 直接填激活时间；配对预注册为 NULL，首次 pair-claim 时填激活时间
    revoked_at_ms    INTEGER                 -- 非 NULL 时立即拒绝一切 HTTP/WS 请求
);

-- 3. 一次性领取配对 / 密钥刷新票据表（粘贴配对码 / PWA 内扫码）。
--    配对码只含 pair_id + 一次性包裹密钥 K_pair（256 bit）+ 服务端地址；发起桌面生成新 device_token（仅哈希入 devices），
--    把「Tier 1 SMK 代际 + 新设备令牌（kind='pair'）或仅新 SMK 代际（kind='refresh'）」用 K_pair 加密后暂存于此。
--    服务端从不接触明文 device_token 或 K_pair。TTL 10 分钟；首次领取即删除整行；超时由 alarm 删除（若 kind='pair' 同步清理未激活的 devices 行）。
CREATE TABLE IF NOT EXISTS pairing_tickets (
    pair_id          TEXT PRIMARY KEY,
    kind             TEXT NOT NULL DEFAULT 'pair' CHECK (kind IN ('pair', 'refresh')),
    device_id        TEXT NOT NULL REFERENCES devices(device_id),
    scope            TEXT NOT NULL CHECK (scope IN ('read', 'read-write')),
    ciphertext       BLOB NOT NULL,          -- XChaCha20-Poly1305(K_pair, msgpack({ smks, device_token?, device_id, sync_url }))
    created_by       TEXT NOT NULL,
    expires_at_ms    INTEGER NOT NULL        -- created + 10 分钟
);

-- 4. 核心盲操作日志表（seq 映射内置 rowid；op 密文永不删除、永不置空）
CREATE TABLE IF NOT EXISTS ops (
    seq        INTEGER PRIMARY KEY,
    op_id      TEXT NOT NULL UNIQUE,
    device_id  TEXT NOT NULL,
    created_at INTEGER NOT NULL,             -- 服务端接收毫秒时间戳（仅用于归档分段）
    key_id     TEXT,                         -- 明文 key_id（进入 MNS1 AAD）；SET_META / DELETE 为 NULL
    envelope   BLOB NOT NULL                 -- MNS1 密文
);

CREATE INDEX IF NOT EXISTS idx_ops_key ON ops (key_id, seq) WHERE key_id IS NOT NULL;

-- 5. 实体数据密钥表（§3.4.2）。服务端看不到 block_id 与 tier
CREATE TABLE IF NOT EXISTS block_keys (
    key_id             TEXT PRIMARY KEY,
    wrap_gen           INTEGER NOT NULL,     -- 仅接受更大的 wrap_gen 替换 key_record
    key_record         BLOB,                 -- MNR1；alarm 执行碎纸后置 NULL（终态）
    created_by_device  TEXT NOT NULL,
    created_at_ms      INTEGER NOT NULL,
    shredded_at_ms     INTEGER
);

-- 6. 碎纸标记（§3.4.3，M2 启用）。服务端强制 grace_ms >= T_grace_min；超出每日批量阈值 N 的进入 pending_confirm
CREATE TABLE IF NOT EXISTS shred_marks (
    mark_id          TEXT PRIMARY KEY,
    key_id           TEXT NOT NULL REFERENCES block_keys(key_id),
    seen_seq         INTEGER NOT NULL,       -- 竞态校验：本批之前该 key_id 存在 seq > seen_seq 的 op 时拒绝（SHRED_STALE）
    requested_by     TEXT NOT NULL,
    requested_at_ms  INTEGER NOT NULL,
    grace_ms         INTEGER NOT NULL,
    not_before_ms    INTEGER,                -- pending_confirm 时为 NULL；确认后 = confirmed_at_ms + max(grace_ms, T_grace_min)
    state            TEXT NOT NULL CHECK (state IN ('pending_confirm', 'scheduled', 'cancelled', 'executed')),
    confirmed_by     TEXT,
    confirmed_at_ms  INTEGER,
    cancelled_by     TEXT,
    cancelled_at_ms  INTEGER,
    executed_at_ms   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_shred_marks_due
    ON shred_marks (not_before_ms)
    WHERE state = 'scheduled';

-- 7. 密钥环与 Vault 头部（§3.5；服务端只存密文，随 /v1/keys 读写，仅接受更大的 gen 替换）
CREATE TABLE IF NOT EXISTS key_material (
    kind           TEXT PRIMARY KEY CHECK (kind IN ('keyring', 'vault_header')),
    gen            INTEGER NOT NULL,
    blob           BLOB NOT NULL,
    updated_at_ms  INTEGER NOT NULL
);

-- 8. 手机状态快照指针（§3.6，M2 启用；同一 journal_epoch 内按 covers_seq 单调接受，只保留最近 2 份）
CREATE TABLE IF NOT EXISTS phone_snapshots (
    snapshot_id        TEXT PRIMARY KEY,
    journal_epoch      TEXT NOT NULL,
    covers_seq         INTEGER NOT NULL,
    r2_object_key      TEXT NOT NULL,
    byte_size          INTEGER NOT NULL,
    created_by_device  TEXT NOT NULL,
    created_at_ms      INTEGER NOT NULL,
    UNIQUE (journal_epoch, covers_seq)
);
```

各表的端点、校验与 alarm 实现见 [`cloudflare-cloud-architecture.md`](./cloudflare-cloud-architecture.md) 与 [`interface-contracts.md`](./interface-contracts.md)。

---

## 6. 移动端 PWA IndexedDB 存储结构规范（`web`，只读缓存）

手机是只读客户端（D1）：IndexedDB 只是一份**可随时丢弃的缓存**，被 iOS 驱逐的后果只是下次打开时重新下载「最新快照 + 尾部 op」。**无 outbox、无本地 op 日志写路径、无冲突合并数据**。

数据库名称：`mynote_pwa_v1`（Schema Version `1`），共 **6 个 Object Stores**：

| Object Store 名称 | `keyPath` | 二级索引（Indexes） | 存储内容说明 |
| --- | --- | --- | --- |
| `device_keystore` | `"id"` | 无 | 存 `{ id: "wrapping_key", cryptoKey: CryptoKey(AES-GCM, extractable=false) }` 及被其包裹的 `{ id: "credentials", iv, wrapped_smks (当前及历史 SMK 代际), wrapped_token (scope = read), device_id, sync_url }` |
| `meta` | `"key"` | 无 | `journal_epoch`、`snapshot_covers_seq`、`last_seq`、PWA 版本号等非机密游标 |
| `buffers` | `"id"` | `by_position`: `["position", "id"]` | `SnapshotBufferV1` 形状：名称保持 `MNB1` 密文，渲染时于内存中解密 |
| `blocks` | `"id"` | `by_buffer_pos`: `["buffer_id", "position", "id"]` | `SnapshotBlockV1` 形状：字段 LWW 结果 + 全部叶子。**叶子正文一律保持 `MNB1` 密文**（Tier 1 也不例外），只在渲染 / 复制时于内存中解密 |
| `block_keys` | `"key_id"` | 无 | 同步下来的可用密钥记录（`MNR1`）；收到碎纸执行即 `store.delete(key_id)`，并删除该块的缓存 |
| `vault_header` | `"id"` | 无 | `VaultHeaderV1`（KDF 参数、盐、`wrapped_vkek`），供手机解锁 Vault |

- **VKEK 永不落盘**：口令 → Argon2id（WASM）→ PassKey → 解开 `wrapped_vkek` 得到的 VKEK 只存在于内存，**永不写入 IndexedDB 或 Cache Storage**；`visibilitychange` 或闲置 N 分钟后清零上锁。
- 恢复密钥环（`RecoveryKeyringV1`）、Root Seed 与 `recovery_sk` 不进入手机。
- 由于缓存中的正文都是 `MNB1` 密文，碎纸后即使缓存删除延迟，残留内容也无法解密；但已丢失且一直离线的手机上的缓存属于代码管不到的副本（见 [`threat-model.md`](./threat-model.md)）。门禁要求手机 IndexedDB / Cache Storage 中无明文与 VKEK（SEC 取证，见 [`eval-framework.md`](./eval-framework.md)）。

---

## 7. 已移除 / 推迟的机制（2026-11-24）

依据 [第一性原理审查](../review/2026-11-24-first-principles-review.md)：

- `vault_keys` / `vault_key_records` / `MNK1` 信封 / `key_seq` 水位：由独立密钥表 `block_keys` + `shred_marks`（2P-Set，全量比对）取代（§9.3、F-06）。
- `vault_key_slots`（LUKS 式多槽位、WebAuthn PRF 槽位、独立 Vault 恢复码槽位）：由单套参数的 Vault 头部 + 统一恢复包取代；WebAuthn PRF 推迟（§9.10、F-05）。
- `MNV1`（仅 Tier 2 的正文密文）：并入两层通用的 `MNB1`，Tier 只决定 BDEK 由谁包裹（§9.3）。
- 各文档中重复的 AAD 定义（`"mynote-sync-v1"` 等变体）：统一为 §3.3 的唯一定义（F-01、F-17）。
- `SPAN_PATCH` / `BlockSpanPatch` / `SpanPatchV1` / 每 20 步全量检查点：op 只用全量载荷；单条 op p95 > 64 KB 时再议（§9.4、§9.11、F-02）。
- `block_conflicts` 及其允许明文分支的 Lock-Wins 约束：由 `block_leaves`（多叶子并列、任一叶子加锁则整块按加锁渲染）取代（§9.4、F-06）。
- `purge_op_ids` / `sync_ops.is_purged` / 可置空的 `ops.envelope` / `ScrubBlockPlaintextHistory`：op 密文永不删除，删除只作用于密钥（§9.3、F-04）。
- `ephemeral_clips` 瞬态加密剪贴板：手机复制按钮取代（§9.2、F-06）。
- R2 K=5 多世代快照 + CAS（`snapshot_meta`、`prev_snapshot_id`、`rolling_op_hash`、`state_blake3`、`covers_key_seq`）：改为只给手机用的当前状态快照（§9.2、F-02）。
- DO 滑动窗口 GC 与 `min_retained_seq`：Paid 套餐 10 GB 下不需要（§9.5）。
- HLC 漂移钳制 `MAX_FORWARD_DRIFT_MS` / `ClockDriftExceeded`：HLC 只决定展示顺序，只做本地偏差提示（§9.4、F-03）。
- 分数索引局部重平衡 `MAX_POSITION_BYTES`：并发重平衡会交错打乱顺序，个人规模也触发不到（§9.4、F-18）。
- `WsFastPathOp`（WebSocket 携带 op）：WebSocket 只做唤醒；跨端粘贴 p95 > 1 s 时再议（§9.11、F-12）。
- `mynote update` 回滚槽位（`bin/mynote.prev`）：自升级子系统删除，分发交给包管理器（F-14）。
- 手机端 `sync_ops` / outbox / `block_conflicts` / `vault_store`、`last_key_seq`：手机只读（§9.2）。
- INV-SYNC-6「每 op 严格 2 行写入」：放宽为「按需加索引」（§9.5）。
