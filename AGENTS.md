# AGENTS.md — `my-note` 工程与 AI Agent 协作规范

本文档为在本仓库内工作的人类开发者与 AI 编码 Agent（Claude Code / Codex / Antigravity / OpenCode 等）提供唯一操作手册。在编写代码、运行测试、修改设计文档或提交 PR 之前，必须先遵守本文件约定。

---

## 1. 项目定位与目标优先级

`my-note` 是一款面向单人开发者（及 M6 起 5–50 名受邀亲友各自物理隔离的独立加密空间，D11；覆盖 **macOS + Omarchy Arch/Hyprland + Windows [M5, D9] 三桌面 + 移动端 PWA / iOS Shortcuts**）的轻量、简洁、多端可靠同步、支持块级加密、独立图文剪贴板同步（M4，D8 / D8′：云端 1,000 条/30 天/5 GiB 中继 + 桌面无限归档）、`wasmi` 优先跨平台双宿主插件体系（M5, D10）、受控无账号多租户与桌面设备生命周期管理（M6, D11）与 CLI + Skill（Agent 友好）的 Scratchpad 软件，旨在从架构根源替代 Heynote + iCloud。

所有设计与实现取舍按**不可逆程度**排序：

1. **G1 永不静默丢数**：覆盖同步 bug、**丢钥匙**、误操作、平台存储驱逐与逻辑 bug 扩散。
2. **G2 随手即记、随叫随到**：CLI 本地读写 `< 15 ms` [目标]；三桌面统一纯 CLI + Daemon + 内嵌 HTML 底座（`http://localhost:<port>`），Omarchy 由 Hyprland 键绑定唤出 Chromium webapp，macOS 可通过可选的零依赖纯 Swift `WKWebView` 薄壳 `apps/macos/MyNote.app`（菜单栏 + Carbon 全局热键 `⌃⌥Space`，隐显 `5–8 ms` `[已测]`）或浏览器 / Web App / `mynote open` 直达（D5′ / D5″），Windows（M5, D9）通过跨平台 `LocalIpc` Named Pipe、Credential Manager / DPAPI 与 `mynote open`（`ShellExecuteW`）提供一等桌面支持。
3. **G3 多端可得**：三桌面实时 E2EE 同步；手机对笔记保持只读 + 一键复制 + 可解锁 Vault（D1′、D7），并通过物理隔离的剪贴板通道与桌面双向同步图文剪贴板（D8 / D8′，M4：云端 1,000 条/30 天/5 GiB 滚动中继，桌面无限本地归档、手动清理）。
4. **G4 秘密不落明文、不以明文进云端**：Tier 1 云端盲存储零知识 + Tier 2 客户端内存级 Vault（诚实边界见 `docs/threat-model.md`）。
5. **G5 Agent 可读写**：纯本地 CLI（`--json`、稳定退出码、乐观锁）+ 极轻 `skill/SKILL.md`（`< 250 tokens`），不做 MCP。
6. **G6 Heynote 式分块、格式化、Markdown / Pele 渲染与零云端侵入双宿主插件扩展（M5, D10）**。

**复杂度与成本预算**：
- **C1**：一人可长期维护。M1 结束时 `cloud-cf/src/` 业务代码 `< 500 行` [目标]（M2 实测 `690 行` `[已测]` <= `700 行`；M4 初版实测 `929 行` `[已测]`；D8′ 增补 5 GiB 硬配额与 `/v1/clip/prune` 后实测 `1,025 行` `[已测]` <= `1,050 行`；**M5 硬约束 `cloud-cf/src/` `0 LOC` 改动 `[保证]`、手机 PWA WASM `0 B` 增量 `[保证]`**；**M6 受控无账号多租户与设备管理阶段批准 `cloud-cf/src/` 上限调至 `<= 1,250 行` `[目标]`，手机 PWA WASM 仍保持 `0 B` 增量 `[保证]`**），`mynote-core` 同步核心 `< 3,000 行` [目标]（剪贴板与插件领域契约分别置于独立 `clip` / `plugin` 模块）。任何新增机制必须附上实测触发数据（F-08）。
- **C2**：Cloudflare Workers Paid 约 `\$5/月` [估算]，配置 Spend Management 支出告警（D4）。

---

## 2. 文档分类纪律、单一事实来源（SSOT）地图与裁决顺序

遵循 **单一事实来源原则（F-17）** 与 **调研 / 审查 / 正式方案物理分离纪律**：
- 仓库内严格区分四类文档：**`docs/`（正式方案与 SSOT 规范，唯一允许直接指导开发实施）**、**`docs/spikes/`（限时技术验证实测证据报告，用于升级 ADR 状态）**、**`research/`（独立调研报告，物理分 `pending/` 与 `converted/`）**、**`review/`（独立审查与拍板决策追溯记录）**。
- **调研报告严禁直接实施**：`research/` 下的任何调研报告仅作背景分析、行业对比与决策参考，**不得直接作为编码、原型或联调实施依据**；必须先经明确拍板并将结论完整转化为 `docs/` 正式方案文档正文后方可实施，全部转化后方可从 `research/pending/` 移入 `research/converted/`。
- 每个正式概念只在归属 SSOT 文档中定义一次，其他文档与代码注释只做链接，不复制容易漂移的细节。

| 关注域 | 唯一权威文档 | 关键内容 |
| --- | --- | --- |
| **正式规范目录总览** | [`docs/README.md`](docs/README.md) | 四类文档边界、全部 SSOT 规范与 `docs/spikes/` 实测报告索引 |
| **已拍板决策追溯** | [`review/2026-11-24-first-principles-review.md`](review/2026-11-24-first-principles-review.md) §9 & [`review/2026-11-28-controlled-multi-tenant-and-device-review.md`](review/2026-11-28-controlled-multi-tenant-and-device-review.md) | 决策 D1–D11（含 D1′、D2′、D5′/D5″、D8/D8′、D9、D10、D11）及历次补充拍板；已转化至 `docs/`，冲突时以 §9 与专项审查拍板口径核校 |
| **总览、ADR 与路线图** | [`docs/architecture-proposal.md`](docs/architecture-proposal.md) | 目标、非目标、Monorepo 布局、S0 → M6 路线图、ADR-01～ADR-14 状态 |
| **数据结构与线格式** | [`docs/data-structures.md`](docs/data-structures.md) | ULID、定长 HLC、FractionalIndex、M6 自路由标识与离线邀请码、`InnerOpV1`、M5 插件领域契约与 Core WASM 3-Export ABI、信封布局、**全项目唯一 AAD 定义（§3.3）**、全端 DDL |
| **同步协议与物化语义** | [`docs/sync-protocol.md`](docs/sync-protocol.md) | 路径 γ 多叶子并列、完整因果图 `G(b)`、密钥表 2P-Set、删除/碎纸协议、跨 `epoch` 并集对账、手机状态快照、独立剪贴板通道、M6 首次引导与被移除端停机 |
| **跨边界接口与 CLI 契约** | [`docs/interface-contracts.md`](docs/interface-contracts.md) | 全局 `ErrorCode` 与退出码表、CLI `--json` 信封与子命令、本地 Daemon REST / WS / 跨平台 `LocalIpc`、云端 Sync / Space / Device API、WASM / Tier 2 插件 Worker 边界 |
| **安全承诺与威胁模型** | [`docs/threat-model.md`](docs/threat-model.md) | 敌手矩阵 T1–T10、约 37 天删除上界、代码管不到的副本、本地鉴权、同 UID 诚实边界、手机 PWA、剪贴板、Windows / 双宿主插件与受控多租户安全边界 |
| **云端实现规范** | [`docs/cloudflare-cloud-architecture.md`](docs/cloudflare-cloud-architecture.md) | 极薄盲中继职责、单空间单 DO 惰性初始化/Alarm/WS Hibernation、R2 类别前置布局与生命周期、Spend Management、10 条防坑红线 |
| **质量门禁与执行纪律** | [`docs/eval-framework.md`](docs/eval-framework.md) | Plane A 确定性门禁（proptest / DST / Worker 契约 / INV-RECOVERY / SEC-01..10 / SEC-WIN-* / SEC-MT-* / CLI 黄金测试）、里程碑门禁矩阵（S0 → M6） |
| **限时技术 Spike 实测报告** | `docs/spikes/s0-*.md`、`docs/spikes/s-clip-*.md`（及 M5 `s-plugin-1` / `s-win-1`、M6 `s-mt-1`） | 各 Spike 一页实测结论，支撑 ADR 由 `Proposed` 转为 `Accepted` |
| **独立调研归档（非实施依据）** | [`research/README.md`](research/README.md) | 调研台账：`research/pending/`（未转化禁止实施）与 `research/converted/`（含 D8 剪贴板、D9/D10 插件架构与 D11 受控多租户调研留档） |

> **编码前必核的已知跨文档/Issue 措辞差异**：
> 1. **AAD 字节串**：严格以 `docs/data-structures.md` §3.3 为唯一权威（例如 `MNB1` 为 `"MNB1" || ver || entity_id || op_id || key_id`，`MNS1` 为 `"MNS1" || ver || smk_kid || op_id || device_id.as_bytes() || key_id`），不得采用 Issue 文本或旧草稿中的 `"mynote:mnb1:v1"` / `"mynote-sync-v1"`。
> 2. **快照 / 配对魔数**：`docs/data-structures.md` §3.2 / §3.6 定义手机状态快照魔数为 `MNP1`（`interface-contracts.md` §4.2 曾简写为 `MNSS`，Issue #10 曾把配对票据密文称作 `MNP1`）；实现配对密文与手机快照前须先核对 `data-structures.md` 并保持唯一命名。

---

## 3. 不可违背的工程红线（Hard Invariants）

### 3.1 反丢数红线（Anti-Wipe by Construction）
- **禁止网盘同步活跃库**：绝不把活跃 SQLite 或笔记目录放入 iCloud Drive / Dropbox / OneDrive。
- **OpLog 密文永久只追加**：DO、R2 op 归档与桌面 `sync_ops` 中的 op 密文永不删除、永不置空；唯一让数据不可读的路径是 M2 起带服务端强制宽限期的加密碎纸（作用于密钥表而非 op）。
- **编译期非明文写阻断**：`Unhydrated` / `KeyUnavailable` / `DecryptFailed` / `Sealed` 状态在 Rust 类型签名层面严禁构造明文 `UPDATE`。
- **Bootstrap Gate**：桌面 `bootstrap_completed == false` 时，严禁对远端已有实体发出 `UPDATE / SET_META / LOCK / UNLOCK / DELETE / RESOLVE`。
- **完整因果图求叶子**：必须在完整已解密 `MNS1` 因果图 `G(b)` 上计算极大元叶子集 `L(b)`，再检查各叶子 BDEK 状态——绝不能先过滤不可读节点再算叶子（否则中间版本碎纸会导致旧祖先复活）。
- **跨 `epoch` 集合并集对账**：检测到 `epoch` 变更或 `head_seq < local_seq` 时按 `op_id` 求集合并集，**严禁先 `DELETE FROM blocks` / `DELETE FROM sync_ops` 清表**；拉取水位 `last_seq` **只允许由连续的 `PullResponse` 推进**，绝不能被 `PushAcked` 跳进（否则会永久跳过并发远端 op）。
- **HLC 不拒收**：绝不因时钟偏差拒收或钳制远端 op；偏差超过 5 分钟仅本地发 `CLOCK_SKEW` 告警。
- **零字节熔断**：非交互空 `stdin` 更新非空块默认返回 `EMPTY_STDIN_REFUSED`（退出码 `2`）；外部格式化器 0 字节 / 非零退出 / 超时返回 `FORMAT_SYNTAX_ERROR`（退出码 `7`）且零写库。

### 3.2 M1 不可逆线格式红线（D2′，Day-1 定型）
- **每实体独立 BDEK**：自 M1 第一天起，每个 Block 与每个 Buffer 各自生成随机 32B `BDEK` 与 `key_id`，正文与 Buffer 名称加密为 `MNB1`；op 信封只带 `key_id`，**不带密钥或 `wrapped_dek`**；密钥记录以 `MNR1` 存于独立密钥表 `block_keys`。
- **`op_id` 生成归属（修正 F-01）**：`op_id` 必须由**执行正文加密的 `mynote-core` 实例**在加密前生成并绑定进 `MNB1` / `MNS1` AAD。Tier 2 写入由 `WasmVaultSession` 生成 `(op_id, key_id)` 随请求提交，Daemon 必须原样复用，绝不重新生成。
- **跨设备 PITR 救援保留作者 `device_id`**：`MNS1` AAD 绑定了原始 `device_id`，因此 `POST /v1/sync/push` 必须保留每条 op 的原始作者 `op.device_id`（而非无条件覆盖为本次推送者的认证 `device_id`），否则 B 设备在 DO PITR 后代为补推 A 设备的 op 会令第三台设备及离线归档恢复 AEAD 解密失败。
- **无 BDEK 的 op**：`SET_META` 与 `DELETE` 在外层 JSON / SQL `key_id` 列统一为 `null`，仅在拼装 `MNS1` AAD 时填 16B 全零。
- **统一 24 词恢复包**：唯一一份 24 词 → Root Seed → X25519 恢复密钥对；日常设备只存**恢复公钥**，可无感封装追加新 `SMK` 代际；**旧 `SMK` 代际永久保留**，确保永久 op 归档始终可解。

### 3.3 安全与平台红线
- **常驻 Daemon 零 Tier 2 明文**：Daemon 永不持有 `VKEK` 或加密块明文；解锁态加密块严禁外发给 Layer 2 外部 CLI 格式化器（只能走内置 WASM Layer 1 纯内存格式化）；所有密钥使用 `zeroize::Zeroizing`。
- **本地 Daemon 唯一入口**：绑定 `127.0.0.1` 与 `::1`，但 `Host` 白名单唯一项为 `localhost:<port>`（拒绝 `127.0.0.1:<port>`、`[::1]:<port>` 与其他 Host）；校验 `Origin` 白名单 + 一次性票据换取 `HttpOnly; SameSite=Strict` Cookie。
- **防 `302` 代理静默丢数**：所有同步 HTTP 请求必须设置 `redirect: "manual"`，校验 `HTTP 200` + `Content-Type: application/json` + `body.ok === true` 后才按 `acked` 更新本地状态。
- **Cloudflare DO 平台硬约束**：
  - 单条 SQL 最多 **100 个绑定参数**——批量写入必须在 `ctx.storage.transactionSync` 内单行循环执行；
  - WebSocket 必须使用 `ctx.acceptWebSocket` + `ctx.setWebSocketAutoResponse` + `ws.serializeAttachment`（避免破坏 Hibernation）；
  - 单一 DO Alarm 复用，每次执行后重算下一次触发时刻，DO 启动时同样重算。
- **删除边界**：CLI 只能把块删进回收站；`mynote trash empty / expedite / confirm` **无论是否 TTY** 一律返回 `UI_CONFIRMATION_REQUIRED`（退出码 `2`）。
- **SQLite 单写入方**：本地连接必须执行 `WAL / synchronous=NORMAL / busy_timeout=5000 / foreign_keys=ON / secure_delete=ON`；Daemon 运行时 CLI 写命令经 `0600 daemon.sock` 的 `apply` 帧串行执行，Daemon 未运行时由 CLI 短事务直写 WAL；Schema 迁移前必须 `VACUUM INTO` 自动备份。
- **独立图文剪贴板红线（D8 / D8′，M4）**：
  - **严格物理隔离**：剪贴板条目严禁写入笔记 `ops` / `block_keys` / `shred_marks` / 手机 `MNP1` 快照 / R2 永久 op 归档 / 本地 FTS5 与 Markdown 镜像（`INV-CLIP-ISOLATION`）；原图大对象与本地 `clip_cache/`（桌面无限本地归档，仅手动 `prune`/`clear` 清理）严禁塞进本地或云端 SQLite 主表；
  - **四态令牌最小权限**：绝不因支持手机发剪贴板而赋予手机 `read-write`；`read+clip` 对全部笔记写、密钥与碎纸路由仍返回 `403`，`clip-write` 对全部 `GET`（含 `GET /v1/clip*`）与笔记路由返回 `403` 且配对票据不含 `SMK`；
  - **流式 R2、5 GiB 硬护栏与零 PITR 诚实边界**：图片与 `> 64 KiB` 长文本（单条上限 `10 MiB`）必须通过 `PUT /v1/clip/blob` 流式直写 R2 `clip/blobs/`（防触发 Worker 128 MB 内存上限，物理 0 进入 DO 30 天 PITR；挂 `5 GiB` 硬配额护栏，触顶返 `507 CLIP_QUOTA_EXCEEDED` 且不阻塞内联小文本与 `--ephemeral`）；小文本与轻索引存 DO `clip_items`（云端滚动窗口 `1,000 条 / 30 天 TTL`，R2 孤儿清理 `31 天` 生命周期；桌面后台 Eager Prefetch 落盘并本地无限留存，仅手动清理）并使用与 `SMK`/`VKEK` 隔离、轮换不留旧钥的独立 `ClipKey`（`MNC1`）；云端批量清理（`DELETE /v1/clip` 默认 `scope = "cloud"`、`POST /v1/clip/prune`）与 `mynote clip rotate-key` 默认保留桌面本地归档（除非显式 `--wipe-local`）；`--ephemeral`（`≤ 256 KiB`）严禁写 SQLite 或 R2，无在线桌面直接返回 `409 NO_ONLINE_DESKTOP`；
  - **防 XSS 与桌面隐私过滤**：图片通道严格白名单 `image/png`、`image/jpeg`、`image/webp`、`image/gif`，**严禁 `image/svg+xml` 按图片解析或渲染**；macOS 改用原生 `NSPasteboard`（优先读 `public.png` 避开超大 `public.tiff`），Windows（M5）优先读 `"PNG"` 回退 `CF_DIBV5` 转 PNG，macOS / Wayland / Windows 硬过滤 `ConcealedType` / `TransientType` / `AutoGeneratedType` / `com.apple.is-remote-clipboard` / `x-kde-passwordManagerHint` / `ExcludeClipboardContentFromMonitorProcessing` / `CanIncludeInClipboardHistory == 0` / `CanUploadClipboardDataToCloud == 0`，M4b 后台自动监听（默认关闭 opt-in）须接入 `detect_secret_pattern` 拦截与含转码后 PNG 字节哈希的双重防回环。
- **Windows 一等桌面与 `wasmi` 优先双宿主插件红线（D9 / D10，M5）**：
  - **云端与 PWA 零侵入**：M5 全程强制 `cloud-cf/src/` **`0 LOC` 改动 `[保证]`**、手机 `web/src/wasm/pkg-pwa/` **`0 B` 增量 `[保证]`**；
  - **Windows 本地隔离**：`LocalIpc` Named Pipe 强制 `first_pipe_instance(true)`、显式 SDDL `D:P(A;;GA;;;OW)`（仅当前用户 SID，禁 `Everyone`）与 `reject_remote_clients(true)`；凭据走 Credential Manager / DPAPI、文件施当前用户专属 NTFS DACL；外部子进程保留 Windows 最小系统环境白名单（含 `SYSTEMROOT`）、注入 `PYTHONUTF8=1`、绑定 `CREATE_NO_WINDOW | CREATE_SUSPENDED` + Job Object，**严禁经 `cmd.exe` 启动 `.bat`/`.cmd`**；
  - **零导入 WASM 双宿主与零主 DOM 注入**：Core WASM 3-Export ABI 模块在 Rust `wasmi` 与桌面 `'self'` Web Worker 加载期均强制断言 `module.imports().is_empty()`；解锁态 Tier 2 仅在前端独立 Worker 接收单块明文（绝不传 `VKEK`、常驻 Daemon 永不接触 Tier 2 明文）；`PluginRuntime::Exec` 在类型层禁止 `tier2_capable = true` 且运行时对加锁块返 `423`；前端严禁 Obsidian 式主 DOM / JS 注入，只开放 6 种声明式 `PluginResult` 原语；
  - **严禁云同步自动分发插件 & 禁止插件直写 SQLite**：插件不得通过 `my-note` 同步流下发执行（防 T2 / T8 升级全桌面 RCE），所有插件写操作经 `LocalIpc` 单写入方提交并强制写入 `actor = "plugin:<id>"`（`reactor` 默认忽略自身事件防回环并限流）。
- **受控无账号多租户与设备生命周期管理红线（D11，M6，排在 M5 之后）**：
  - **边缘零唤醒拦截与惰性 DO 初始化**：单一 `SPACE_MASTER_SECRET` 经 HKDF 域分离派生 `K_route` 与 `K_invite`；自路由 `device_token`（`mnt_<space_id>_<64hex>`）与 `pair_id`（`pr_<space_id>_<32hex>`）必须用精确正则解析（严禁对含 `sp_` 的字符串裸 `split("_")`），MAC 失败在 Worker 边缘直接返回 `401`（**0 次 DO 唤醒**）；`SyncJournalDO` 构造函数在 `space_initialized != '1'` 时**零建表、零写行、零设 Alarm**；非 `primary` DO 在 `POST /v1/devices` 与 `/refresh` 强制校验 `pair_id` 以 `pr_${this.spaceId}_` 开头；
  - **R2 类别前置隔离与空闲 Alarm 不变量**：多租户 R2 键必须坚持「类别前缀在前、`<space_id>` 在后」并由服务端强拼接 `this.spaceId`，共享桶 `clip/blobs/` 孤儿清理前缀生命周期**维持 31 天不变**（受邀空间默认 `clip=512 MiB / 500 条 / 14 天` 到期由 DO Alarm 主动 `R2.delete(keys[])` 回收）；空闲空间仅在满足 `INV-MT-IDLE-ALARM`（`head_seq == last_archive_seq` 且碎纸后 `keys_digest == last_archived_keys_digest` 且无待到期票据/碎纸/剪贴板）时方可免设下一次 Alarm；
  - **防自锁、首次引导保底与被移除端差异化收敛**：`DELETE /v1/devices/:id` 硬拒删除最后一台活跃 `read-write` 桌面（`409 LAST_ADMIN_DEVICE_REFUSED`）；桌面建库即派生持久化非机密 `space_owner_pk`（`owner_sk` 永不落盘），恢复挑战存于 **DO 纯内存有界 Map**（0 SQLite 写）；桌面 UI 首次 `claim`/`recover` 强制校验 `UnclaimedFresh` 并先 `VACUUM INTO backups/pre-join-<ts>.db` 保底；桌面收到 `DEVICE_REVOKED` **严禁删本地 SQLite/镜像**，仅擦除 `device_token` 转入 `"device_revoked"` 态并立即熔断后台 WS / 60s 轮询，而手机只读 PWA 在线收到明确 `DEVICE_REVOKED` 自动清空 IndexedDB 7 张表。

---

## 4. 已移除 / 推迟的机制（禁止擅自重新引入）

以下机制已在 2026-11-24 审查中明确裁剪或推迟（2026-11-27 随 D8 局部修订），编码时**不要顺手补回**：
- **D1′**：手机编辑/追加笔记块、笔记 outbox、移动端 CM6 / Layer 3 格式化；旧版写入 DO SQLite 且声称零 PITR 的 `ephemeral_clips` 表（F-06，已永久废弃；M4 剪贴板走 D8 独立通道）。
- **D2′ / F-04 / F-05**：`purge_op_ids`、可变 `vault_keys` / `MNK1` / `key_seq` / `INV-SYNC-4`、`vault_key_slots` 多槽位、Vault 第二套恢复码、云端 `/v1/archive/*` 路由。
- **D3 / F-02 / F-03 / F-18**：`SPAN_PATCH` / delta 链、Loro/Yjs CRDT、HLC 漂移拒收、Lock-Wins 特例、分数索引重平衡。
- **D4**：DO 滑动窗口 GC、R2 K=5 多代快照 + CAS、「\$0/月免费额度」约束。
- **D5′ / D5″（2026-11-25 移除 Tauri，2026-11-28 补充可选纯 Swift 壳）**：macOS Tauri 薄壳（`shell-macos/`）、Tauri 自定义协议 `tauri://localhost` / Bearer 鉴权分支与单端 GPUI 重写均永久不引入；双桌面底座保持纯 `mynote` 单二进制（CLI + Daemon + 内嵌 HTML），macOS 另提供零第三方依赖纯 Swift `WKWebView` 可选薄壳 `apps/macos/`（仅连 `daemon.sock`，不碰 Keychain、不改 `SEC-05`）。
- **D6 / F-13 / F-14 / ADR-08**：本地与云端 MCP、`mynote update` 自升级、WebAuthn PRF、`--help-json`、加密图片附件 `blobs/`、WebSocket 携带 op 顺风车、Plane B 统计评测、自动爬山与 LLM 评委（`evals/archive/` 仅供存档参考）。
- **D10（2026-11-28 插件边界）**：Obsidian 式主 DOM / 任意 JS 注入插件、WASI Preview 2 / WIT 破坏浏览器原生零依赖直跑、捆绑 Node.js / Python 运行时、经 `my-note` 云同步自动分发可执行插件代码、`exec` 子进程接触 Tier 2 明文、以及向外部进程暴露高频按键 `onKeystroke`。
- **D11（2026-11-28 受控无账号多租户边界）**：公网开放匿名注册、账号密码 / 邮箱找回 / OAuth / 中心路由目录（KV / D1）、跨空间笔记共享与多人协作、手机 PWA 端设备增删管理、以及在普通用户 `mynote` 二进制内暴露 `admin` 子命令（离线邀请码仅由运维脚本 `cloud-cf/scripts/issue-invite.ts` 签发；云端 `/v1/archive/*` 仍保持不引入）。

---

## 5. 仓库目录规划与 Spike 隔离策略

```text
my-note/
├── AGENTS.md                  # 本文件（AI Agent 与开发者协作规范）
├── Cargo.toml                 # Rust Workspace 根（M1-1 创建，排除 spikes/）
├── crates/
│   ├── mynote-core/           # Sans-I/O 纯领域核（零 tokio/rusqlite/web-sys，必须编过 wasm32）
│   ├── mynote-wasm/           # wasm-bindgen 封装（桌面 Tier 2 + 手机只读 PWA）
│   ├── mynote-store/          # 桌面 SQLite STRICT/WAL/FTS5/镜像/VACUUM INTO 备份
│   └── mynote-cli/            # 单体二进制入口（CLI + Heynote 导入 + Daemon + 内嵌前端）
├── apps/
│   └── macos/                 # 可选零依赖纯 Swift WKWebView macOS 薄壳（MyNote.app，仅连 daemon.sock、不碰 Keychain）
├── deploy/                    # 各平台后台托管与快捷入口模板（launchd / systemd / hyprland / ios-shortcuts / M5 windows）
├── web/                       # TypeScript 前端（桌面 CM6 + M5 Tier 2 插件 Worker + 手机只读 PWA）
├── cloud-cf/                  # Cloudflare Worker 极薄盲同步中继（M5 硬约束 0 LOC 改动）
├── skill/SKILL.md             # Agent Skill（严格 < 250 tokens）
├── tests/
│   ├── scenarios/             # Rust DST 与真实 Worker 契约测试共用场景
│   └── fixtures/              # Heynote 脏语料、XSS 向量
├── evals/                     # 不可变验证器资产（详见 §7 铁律！）
├── spikes/                    # 限时技术验证原型（隔离目录，严禁被正式 crate/应用依赖）
├── docs/                      # 正式方案与工程规范 SSOT（唯一允许直接指导开发实施，含 docs/README.md 与 docs/spikes/ 实测报告）
├── research/                  # 独立调研报告目录（严禁直接实施；物理分 pending/ 未转化 与 converted/ 已转化留档）
└── review/                    # 方案审查与决策追溯记录（§9 D1–D10 决策台账，已转化为 docs/）
```

- **Spike 隔离规则**：S0 阶段的原型与压测脚本放入 `spikes/`，**不得混入** `crates/`、`web/`、`cloud-cf/` 等正式业务目录；待 S0 全部闭环后可按需清理或归档 `spikes/`。
- **数字诚实标签（F-16）**：在文档、报告与 PR 说明中，所有性能、体积、延迟、成本与行数数字必须标注 `[保证]` / `[目标]` / `[估算]` / `[已测]`。
- **ADR 状态升级规则**：只有拿到对应目标环境的真实测量证据后，才可将 `docs/architecture-proposal.md` §8 中的 ADR 由 `Proposed` 改为 `Accepted`；Linux / `workerd` 模拟数据必须如实标注环境，不得冒充 macOS / iPhone 真机或真实 Cloudflare 账号实测。

---

## 6. 开发顺序与标准验证命令

### 里程碑推进顺序
1. **S0（技术 Spike，可与 M1 纯领域核并行）**：`#32` CM6 形态（已闭环）→ `#33` macOS 形态评估（D5′ 拍板移除 Tauri 壳，已闭环）→ `#34` WASM 体积与 iPhone Argon2id（实测拍板 `(32768, 2, 1)`，已闭环）→ `#35` CF Paid 最小中继 / DO Alarm / R2 生命周期。
2. **M1（替换 Heynote + iCloud）**：`#3` Workspace + `mynote-core` → `#4` Layer 1 格式化 & `#10` M1 线格式/恢复环 → `#5` `mynote-store` & `#11` Sans-I/O 同步状态机 → `#6` Heynote 导入 → `#7` CLI + `SKILL.md` + 黄金测试 → `#8` Daemon & `#13` `cloud-cf` → `#9` 桌面 Web UI → `#14` 端到端闭环 → `#12` DST + `INV-RECOVERY` + 共用场景。
3. **M2**：手机只读 PWA + Tier 2 Vault + 受控加密碎纸（`INV-SHRED-BOUND`、`INV-GRACE`、`SEC-01/03/08`）。
4. **M3**：Markdown 双模 + Pele 纯 SVG + Layer 2 外部格式化 + 时间旅行（`SEC-06`）。
5. **S-Clip & M4（D8 / D8′，2026-11-27 / 2026-11-28 拍板）**：先完成限时 `S-Clip-1`–`S-Clip-5` 真机 Spike（验证后 `ADR-11` 升为 `Accepted`）→ **M4a**（图文显式跨端剪贴板 + 移动端 → 桌面双向通道，`INV-CLIP-ISOLATION` / `SEC-09`；D8′ 升级为云端 `1,000 条 / 30 天 / 5 GiB` 硬护栏 + 桌面无限归档与 Eager Prefetch）→ **M4b**（桌面 ↔ 桌面图文后台自动镜像，默认关闭 opt-in）。
6. **M5（D9 / D10，2026-11-28 拍板）**：Phase 0 限时 Spike（`S-Plugin-1` + `S-Win-1`，隔离于 `spikes/`）→ **Phase 1 Windows 一等桌面基座**（`M5-W1` 跨平台 `LocalIpc` + 子进程/凭据/ACL/`windows-latest` CI → `M5-W2` Win32 剪贴板监听与 `SEC-WIN-CLIP` → `M5-W3` Release ZIP 与 `deploy/windows/`，`ADR-12`）→ **Phase 2 `wasmi` 优先双宿主插件体系**（`M5-P1` `plugin.rs` + `mynote watch` → `M5-P2` `wasmi` 零导入宿主 + `mynote ext` → `M5-P3` 桌面声明式渲染 + Tier 2 `'self'` Web Worker + `SEC-10` → `M5-P4` Level 1 `exec` `oneshot`/`worker` + `reactor` 防回环，`ADR-13`）。全程 `cloud-cf/src/` `0 LOC` 改动、手机 `pkg-pwa` `0 B` 增量。
7. **M6（D11，2026-11-28 拍板，排在 M5 之后）**：**Slice 1**（桌面 UI 设备管理面板 + 本地 SVG 二维码 + `confirm_nonce` + `INV-MT-NO-SELF-LOCKOUT` + 被移除端差异化收敛）→ **`S-MT-1`**（`workerd` 原生 `Ed25519` ↔ Rust 互通与惰性 DO 实测）→ **Slice 3**（单一 `SPACE_MASTER_SECRET` 边缘自路由 + 惰性 DO + R2 类别前置隔离 + 单空间默认硬配额 `12 设备 / 256 MiB ops / 512 MiB·500条·14天 clip` + `INV-MT-IDLE-ALARM` + `cloud-cf/scripts/issue-invite.ts` + `SEC-MT-01..03`，`cloud-cf/src/ <= 1,250` 行）→ **Slice 4**（建库持久化 `space_owner_pk` + `mynote space` CLI + 首次启动 `UnclaimedFresh` `VACUUM INTO` 热切换引导 + `SEC-MT-04`，手机 `pkg-pwa` `0 B` 增量，`ADR-14`）。

### 标准验证命令（随各模块落地执行）
- **Rust 静态检查与测试**（一旦 `Cargo.toml` 就位）：
  ```bash
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  cargo check -p mynote-core --target wasm32-unknown-unknown
  ```
- **前端与云端 Worker**：使用 `pnpm` 执行对应子目录下的类型检查、单测与 `@cloudflare/vitest-pool-workers` 真实 `workerd` 契约测试。
- **禁止云端手工部署**：Worker 与 PWA 静态资源仅允许通过 CI 使用最小权限 Scoped Token 发布，禁止本地 `wrangler deploy` 到生产环境（S0 独立测试账号的临时 echo Spike 除外）。

---

## 7. 验证纪律与 Git / GitHub 协作铁律

1. **不可变验证器规则（IMMUTABLE VERIFIER RULE — 强制）**：
   - 常规功能、重构与 Bug 修复 PR **严禁修改 `evals/` 下的任何文件**（`evals/README.md` 规定非 `[eval-only]` PR 在 CI 中会强制 `git checkout origin/main -- evals/`）。
   - 新增或修改黄金测试、回归种子、测试断言或放宽阈值，必须走单独的 **`[eval-only]`** PR（仅触碰 `evals/` 与 `docs/eval-framework.md`），并在提交说明中写明理由。
2. **严禁凑绿**：
   - 禁止用重试、`sleep`、放宽断言或扩大超时掩盖失败；任何门禁失败必须给出最小复现命令或 `SimSeed(u64)`。
3. **三次失败升级（3-Failure Escalation）**：
   - 在同一验证门禁上连续 3 次修改仍未通过时，**立即停止第 4 次盲试**，向人类输出：① 最小复现；② 3 次尝试各自的根因假设与反证；③ 判断属于「实现缺陷」「契约冲突」还是「测试本身有误」。
4. **Git & GitHub 协作**：
   - **禁止直接推送 `main`**，所有变更走特性分支与 Pull Request；
   - Commit message 使用 Conventional Commits（如 `docs(agents): ...`、`spike(s0-1): ...`、`feat(core): ...`、`test(sync): ...`）；
   - 未经用户明确指令，不得随意关闭 Issue、合并 PR、删除分支或对外发布 Release。
