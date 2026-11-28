# 受控无账号多租户（路线 B）与设备生命周期管理方案审查及拍板记录（D11）

- **审查日期**：2026-11-28
- **审查对象**：[`research/converted/2026-11-28-controlled-multi-tenant-and-device-management.md`](../research/converted/2026-11-28-controlled-multi-tenant-and-device-management.md)（审查时位于 `research/pending/`）与仓库 `v0.3.2` + D8′ / D9 / D10 实时代码基线
- **处理状态**：`已转化至 docs/`（对应拍板决策 **D11** 与 [`docs/architecture-proposal.md`](../docs/architecture-proposal.md) `ADR-14`；编码实施唯一依据为 [`docs/`](../docs/README.md) 各正式规范正文）

---

## 1. 总体审查结论

原调研报告提出的「无中央目录 / 零 KV-D1、单空间单 `SyncJournalDO` 物理隔离、自路由 `device_token` / `pair_id` + Worker 边缘 HMAC 预校验、R2 类别前缀在前路径隔离、24 词独立 HKDF 派生 Ed25519 空间自救、以及本地 Daemon `confirm_nonce` 守护桌面设备管理 UI」核心骨架在第一性原理上成立，可在保持 **手机 PWA WASM `0 B` 增量 `[保证]`** 与 **iOS 快捷指令 `0` 协议改动 `[保证]`** 的前提下支持 5–50 名受邀亲友共用同一 Cloudflare Workers Paid 部署。

但对照 `v0.3.2` + D8′ 真实源码逐行核查后，原报告存在 **4 项 P0 级实现死锁/协议漏洞** 与 **3 项 P1 级基线数据失真/状态机缺口**。若不修正而直接搬入 `docs/`，会导致桌面首次启动 UI 引导 100% 报错卡死、离线先用后建空间无法派生 `owner_pk`、跨空间配对码错路由、被移除桌面后台 60s 无限轮询空耗 DO 请求、`ARCH-04` 代码行数门禁爆表，以及共享 R2 桶 8 天规则误删 `primary` 空间 30 天有效期内的剪贴板原图。

---

## 2. 源码级审查发现与根因修正台账（`F-MT-01` – `F-MT-07`）

| 编号 | 级别 | 原报告盲区或失真点（源码核实证据） | 正式规范采纳的根因修正 |
| --- | :---: | --- | --- |
| **`F-MT-01`** | **P0** | **桌面首次启动 UI 引导死锁**：`mynote daemon` 启动时无条件调用 `LocalStore::open`（`crates/mynote-cli/src/daemon.rs:799`、`crates/mynote-store/src/store.rs:455-530`），立即生成 `mynote.db`、`smk_keyring.local.json`、`gen = 1` `RecoveryKeyringV1` 与初始空 `"scratch"` buffer。随后 `LocalStore::open_for_claim`（`store.rs:3956`）与 `open_for_recovery_bootstrap`（`store.rs:4046`）检测到数据库文件已存在即直接报错拒绝覆盖，导致 Slice 4「桌面 UI 首次启动贴配对码加入 / 24 词恢复」在真实运行路径下 100% 死锁 | 定义显式本地空白未绑定谓词 `UnclaimedFresh`（`sync_url IS NULL`、`device_revoked_at_ms IS NULL`、0 个用户块、0 条回收站记录、0 条本地剪贴板记录，至多含初始空 `"scratch"` buffer）。当用户在桌面 UI 经 `confirm_nonce` 确认执行 `claim` 或 `recover` 且满足 `UnclaimedFresh` 时，Daemon 先执行 `VACUUM INTO backups/pre-join-<ts>.db` 留存兜底快照（严守 **G1**），再在进程内原子重建 `LocalStore` 并经 `creds_tx` watch 通道热切换后台同步与 WS 任务（无需重启 Daemon）；若本地已有任何用户块或剪贴板记录，硬拒绝覆盖，仅允许凭邀请码将当前库绑定为新云空间或提示用户先导出/更换数据目录 |
| **`F-MT-02`** | **P0** | **先离线使用后建空间无法派生 `owner_pk`**：`LocalStore::open` 首次建库时生成 24 词并落盘 X25519 `recovery_pk` 后，立即 `zeroize` 销毁 `entropy` 与 `root_seed`（`store.rs:461-503`）。若用户先离线使用数日再输入邀请码创建云空间，客户端已无 `root_seed`，无法计算 Ed25519 `owner_pk` | 在 `RecoveryKeypair` 首次建库派生（`crates/mynote-core/src/crypto.rs:478-501`）时同步执行 `HKDF-Expand(root_seed, "ed25519-space-owner-v1")` 计算非机密公钥 `owner_pk`（32 B），持久化于本地 `local_meta('space_owner_pk')`（及 `RecoveryKeyringV1` 可选兼容字段），私钥种子 `owner_sk` 仍即刻 `zeroize` 永不落盘；存量单租户库在下次执行 `mynote keyring unlock` 或 `mynote recovery drill` 输入 24 词时自动无感回填 |
| **`F-MT-03`** | **P0** | **客户端自选 `pair_id` 跨空间错路由、下划线分词歧义与 `refresh` 漏传 `ClipKey`**：因 `pair_id` 须预先绑定进 `MNPR` AAD，由客户端生成后提交 `POST /v1/devices`（`sync_client.rs:466-485`、`cloud-cf/src/index.ts:814`）。若目标 DO 不强校验 `pair_id` 前缀，客户端可写入其他 `space_id` 或无前缀 `pair_id`，使认领请求路由至错误 DO；且 `sp_` 自带 `_`，按 `_` 简单切分会拆坏令牌；另 `create_refresh_ticket`（`sync_client.rs:518-525`）未携带 `ClipKey`，导致 `clip-write` 设备在轮换后无法用刷新码更新剪贴板密钥 | 1. 规定唯一解析正则：`device_token` 为 `^mnt_(sp_[0-9a-hjkmnp-tv-z]{16}-[0-9a-f]{16})_([0-9a-f]{64})$`，`pair_id` 为 `^pr_(sp_[0-9a-hjkmnp-tv-z]{16}-[0-9a-f]{16})_([0-9a-f]{32})$`（严禁裸 `split("_")`）；<br>2. 非 `primary` DO 在 `POST /v1/devices` 与 `POST /v1/devices/:id/refresh` 内强校验 `pair_id` 必须以 `pr_${this.spaceId}_` 开头，`primary` 空间拒绝 `pr_sp_` 前缀；<br>3. `refresh` 票据按目标设备 `scope` 封装密钥：`clip-write` 仅含最新 `(clip_kid, clip_key)`（仍不含 `SMK`），`read+clip` 同时含最新 `SMK` 代际与 `(clip_kid, clip_key)` |
| **`F-MT-04`** | **P0** | **被移除桌面后台 60s 轮询死循环与状态丢失**：现有 `daemon_clip.rs:247-253` 收到 WS `4401` 仅发送一次瞬态前端告警，未停止 `daemon.rs:952-969` 的 60s HTTP `run_cloud_sync_now` / `pull_cloud_clips` / `spawn_clip_blob_prefetch` 定时循环（持续空耗 DO 请求）；且若按报告直接清空全部凭据，`sync_state_label()`（`store.rs:753-771`）会退化为 `"unconfigured"`，用户后续打开 UI 看不出设备曾被远程移除 | 桌面端收到 HTTP `401 DEVICE_REVOKED` 或 WS Close `4401` 时：擦除本地机密 `device_token`，保留 `sync_url` 与 `space_id`，写入 `local_meta('device_revoked_at_ms')`，使 `sync_state` 持久返回 `"device_revoked"`，并立即停止云端 WS 重连与 60s HTTP 笔记/剪贴板/预取循环；本地 SQLite 与只读镜像 **100% 完整保留** |
| **`F-MT-05`** | **P1** | **三处代码/规范基线失真**：<br>1. 报告仅计入 `cloud-cf/src/index.ts`（`931` 行），漏算 `cloud-cf/src/wire.ts`（`94` 行），实际基线已达 **`1,025` 行 `[已测]`**（`scripts/check-architecture.py` `ARCH-04` 当前上限为 `1,050` 行），新增 `160–220` 行后达 `1,185–1,245` 行，原定 `<= 1,200` 行必然触发门禁失败；<br>2. 报告 §2.4 仍写「`clip/blobs/` 8 天自动清理」，与已拍板的 **D8′**（`primary` 空间 30 天 TTL + 共享桶 `expire-clip-blobs-31d`）冲突，改回 8 天会静默删毁 `primary` 空间仍在有效期内的剪贴板大对象；<br>3. `store.rs:3712` 的 `restore --from-archive` 硬编码查找 `keys/latest.mnks`，无法直接读取多租户导出的 `keys/latest/<space_id>.mnks` | 1. M5 期间 `cloud-cf/src/` 维持 `1,050` 行上限与 **`0 LOC` 改动 `[保证]`**；M6 落地路线 B 时将 `ARCH-04` 上限诚实调至 **`<= 1,250` 行 `[目标]`**（拆分为 `index.ts` / `space.ts` / `wire.ts`）；<br>2. 共享 R2 桶 `clip/blobs/` 前缀生命周期维持 **31 天**（仅作崩溃孤儿兜底），受邀空间 14 天剪贴板到期由各自 DO Alarm 主动分批 `R2.delete(keys[])` 清理；<br>3. `mynote restore --from-archive` 新增可选 `--space-id <id>` 并在 `keys/latest.mnks` 不存在时自动识别目录下唯一的 `keys/latest/<space_id>.mnks` 与 `ops/<space_id>/` |
| **`F-MT-06`** | **P1** | **空闲 Alarm 跳过在「仅执行碎纸」分支下破坏约 37 天删除上界**：当前 `cloud-cf/src/index.ts:883` 在 `executedShreds > 0 && now < nextArchiveAt` 时跳过当次快照写入，依赖下一轮日常 Alarm 覆写 `latest.mnks`；若省去后续日常 Alarm，已置空密钥不会从 R2 `latest/<space_id>.mnks` 移除 | 制定严格不变量 **`INV-MT-IDLE-ALARM`**：仅当 ① `head_seq == last_archive_seq`、② `current_keys_digest == last_archived_keys_digest`（碎纸执行置空后 `keys_digest` 必变，须先覆写 `latest/<space_id>.mnks` 并更新记录值）、③ `pairing_tickets` 为空、④ 无 `state = 'scheduled'` 的 `shred_marks` 且 `clip_items` 为空时，才免设下一次 Alarm；任一写入端点落库时重新调用 `rescheduleAlarm` 唤醒 |
| **`F-MT-07`** | **P1** | **未认证恢复挑战落表易被刷写 + 双运维 Secret 冗余 + 未认领设备配额漏计**：`space_id` 为公开定位串，若 `recover/challenge` 写 SQLite 并设 Alarm，外部可借其刷 DO 行写计费；同时维护 `SPACE_ROUTING_KEY` 与 `INVITE_SIGNING_KEY` 易发生运维脚本与 Worker 错配；`max_devices` 若不计 `pending_claim` 会被重复刷满预注册表 | 1. 恢复挑战改存 `SyncJournalDO` **纯内存有界 Map**（单空间最多并存 3 条、TTL 5 分钟、单次验签前即原子移除，**0 SQLite 写、0 新表、0 Alarm**；极端休眠回收时客户端重试一次即可）；<br>2. 收敛为单一部署级 Secret **`SPACE_MASTER_SECRET`**，经 HKDF-SHA256 域分离派生路由 MAC 子钥（`info = "mynote-space-route-v1"`）与邀请码签发子钥（`info = "mynote-space-invite-v1"`）；<br>3. `max_devices` 统计口径固定为 `WHERE revoked_at_ms IS NULL`（含 `active` 与 `pending_claim`），取消或超时清理未认领票据后立即释放名额 |

---

## 3. 拍板决策记录（**D11**，2026-11-28 确认）

项目负责人已于 2026-11-28 对原调研 §7 全部待决项（Q1–Q6）及上述审查修正做出最终拍板，编号为 **D11**（同步记入 [`2026-11-24-first-principles-review.md` §9.12](./2026-11-24-first-principles-review.md)）：

1. **Q1（里程碑排期）**：定位为独立里程碑 **`M6`（受控无账号多租户与设备生命周期管理）**，排在 **M5（Windows 一等桌面 + `wasmi` 双宿主插件）之后**推进。M5 全程严格维持 `cloud-cf/src/` **`0 LOC` 改动 `[保证]`**；M6 内部按 `Slice 1（桌面设备管理 UI + 防自锁）→ S-MT-1（限时技术 Spike）→ Slice 3（云端受控多租户核心）→ Slice 4（桌面空间引导与 24 词自救）` 顺序交付。
2. **Q2（C1 云端代码量预算）**：M5 期间 `scripts/check-architecture.py` 保持 `CLOUD_CF_MAX_LOC = 1050` 不变；进入 **M6** 后批准将 `cloud-cf/src/` 预算上调至 **`<= 1,250` 行 TS `[目标]`**，并按职责拆分为 `index.ts`、`space.ts`、`wire.ts` 保持单文件可读。
3. **Q3（无账号全设备丢失 24 词自救）**：**纳入**。采用 24 词 `root_seed` 独立 HKDF 分支 `ed25519-space-owner-v1`（按 `F-MT-02` 在建库时持久化非机密公钥 `owner_pk`，私钥种子永不落盘；按 `F-MT-07` 使用 DO 纯内存有界挑战 Map + Workers 原生 WebCrypto `Ed25519` 验签，0 新增 JS 依赖，手机 PWA WASM `0 B` 增量 `[保证]`）。
4. **Q4（受邀新空间默认硬配额档位）**：受邀新空间默认配额拍板为：
   - `max_devices = 12`（统计未吊销设备，含 `pending_claim`）；
   - `ops_quota_bytes = 256 MiB`（`268,435,456 B`，超限 `POST /v1/sync/push` 返回 `507 SPACE_QUOTA_EXCEEDED`）；
   - `clip_quota_bytes = 512 MiB`（`536,870,912 B`）、`clip_max_items = 500`、`clip_ttl_ms = 14 天`（`1,209,600,000 ms`）；
   - 签发邀请码时可按人单独覆写上述配额；运营者自用的 `primary` 空间保持既有 D8′ 配额（`clip = 5 GiB / 1,000 条 / 30 天`、无 `ops_quota_bytes` 上限）不变；共享 R2 桶 `clip/blobs/` 孤儿清理前缀生命周期保持 **31 天**不变。
5. **Q5（被远程移除设备的本地缓存行为）**：
   - **手机只读 PWA**：收到服务端明确 `401 DEVICE_REVOKED` 或 WS Close `4401` 时，除立即清零内存 `VKEK` / `ClipCodec` 外，**自动清空 IndexedDB 中缓存的包裹密钥（`SMK` / `ClipKey`）与离线只读笔记/剪贴板缓存**，回到未配对引导页并展示「本设备已被桌面端移除」（文档明确声明此举属正常淘汰旧机的礼貌清理，不作为防御离线物理取证的安全承诺）；
   - **三端桌面（macOS / Omarchy / Windows）**：**严禁自动删除本地 SQLite 与只读镜像**，按 `F-MT-04` 仅擦除失效 `device_token`、写入持久 `"device_revoked"` 状态并停止后台同步轮询，常驻告警条引导重新配对或导出备份。
6. **Q6（离线邀请码签发工具形态）**：采用独立运维脚本 **`cloud-cf/scripts/issue-invite.ts`**（读取运营者本地保密的单一 `SPACE_MASTER_SECRET` 离线生成 `mynote-invite:v1:...`），不在面向普通受邀用户的桌面 `mynote` 二进制中暴露 `admin` 子命令。

---

## 4. 正式方案（`docs/`）转化落位表

| 规范文档 | 转化写入章节 |
| --- | --- |
| [`docs/architecture-proposal.md`](../docs/architecture-proposal.md) | §0.1/0.2 目标、预算与非目标、§5.8 受控多租户与设备生命周期管理子系统、§7 `M6` 路线图、§8 `ADR-14`、§9 移除项边界澄清 |
| [`docs/data-structures.md`](../docs/data-structures.md) | §1.1/1.4 自路由 `SpaceId` / `device_token` / `pair_id` / 空间定位串 / 离线邀请码线格式与正则、§3.5 `ed25519-space-owner-v1` 派生与签名消息、§4 `local_meta` 与 `UnclaimedFresh` 谓词、§5 DO `journal_meta` 空间键 |
| [`docs/interface-contracts.md`](../docs/interface-contracts.md) | §1 新增错误码（`SPACE_ALREADY_INITIALIZED` / `SPACE_QUOTA_EXCEEDED` / `LAST_ADMIN_DEVICE_REFUSED`）、§2.1/2.3 `mynote space` 子命令与 `restore --space-id` 及 `"device_revoked"` 状态、§3.2/3.3 `/v1/local/devices*` 与 `/v1/local/space/*` 契约、§4.1/4.2 Worker 自路由与 `/v1/spaces/*` 及增强版 `/v1/devices*` |
| [`docs/sync-protocol.md`](../docs/sync-protocol.md) | §10.4 区分 `primary` 与受邀空间的两级灾难恢复路径、§10.5 首次启动 `UnclaimedFresh` 引导与被移除设备差异化停机协议 |
| [`docs/cloudflare-cloud-architecture.md`](../docs/cloudflare-cloud-architecture.md) | §3.1/3.3/3.5 单空间单 DO 惰性初始化、R2 类别前置多租户键布局（保住 30 天密钥历史与 31 天剪贴板孤儿规则）、`INV-MT-IDLE-ALARM`、§5.3 多租户成本与配额精算、§6 红线 #10、§8/§10 `M6` 云端切片 |
| [`docs/threat-model.md`](../docs/threat-model.md) | §1/§2.3/§7.3 更新 `owner_pk` 与远程移除诚实边界、新增 §11 受控无账号多租户与设备管理安全边界（`T10a`–`T10e`） |
| [`docs/eval-framework.md`](../docs/eval-framework.md) | §3/§5/§9/§10 新增 `INV-MT-ISOLATION`、`INV-MT-NO-SELF-LOCKOUT`、`INV-MT-IDLE-ALARM` 与 `SEC-MT-01`..`SEC-MT-04` 及 `M6` 里程碑门禁矩阵 |
