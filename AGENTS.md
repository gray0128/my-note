# AGENTS.md — `my-note` 工程与 AI Agent 协作规范

本文档为在本仓库内工作的人类开发者与 AI 编码 Agent（Claude Code / Codex / Antigravity / OpenCode 等）提供唯一操作手册。在编写代码、运行测试、修改设计文档或提交 PR 之前，必须先遵守本文件约定。

---

## 1. 项目定位与目标优先级

`my-note` 是一款面向单人开发者（**macOS + Omarchy Arch/Hyprland 双桌面 + 移动端 PWA / iOS Shortcuts**）的轻量、简洁、多端可靠同步、支持块级加密、独立 100 条图文剪贴板同步（M4）与 CLI + Skill（Agent 友好）的 Scratchpad 软件，旨在从架构根源替代 Heynote + iCloud。

所有设计与实现取舍按**不可逆程度**排序：

1. **G1 永不静默丢数**：覆盖同步 bug、**丢钥匙**、误操作、平台存储驱逐与逻辑 bug 扩散。
2. **G2 随手即记、随叫随到**：CLI 本地读写 `< 15 ms` [目标]；双桌面统一纯 CLI + Daemon + 内嵌 HTML（`http://localhost:<port>`），Omarchy 由 Hyprland 键绑定唤出 Chromium webapp，macOS 由浏览器 / Web App（配合系统切窗工具）或 `mynote open` 直达（D5′）。
3. **G3 多端可得**：双桌面实时 E2EE 同步；手机对笔记保持只读 + 一键复制 + 可解锁 Vault（D1′、D7），并通过物理隔离的剪贴板通道与桌面双向同步 100 条文本与位图图片剪贴板（D8，M4）。
4. **G4 秘密不落明文、不以明文进云端**：Tier 1 云端盲存储零知识 + Tier 2 客户端内存级 Vault（诚实边界见 `docs/threat-model.md`）。
5. **G5 Agent 可读写**：纯本地 CLI（`--json`、稳定退出码、乐观锁）+ 极轻 `skill/SKILL.md`（`< 250 tokens`），不做 MCP。
6. **G6 Heynote 式分块、格式化与 Markdown / Pele 渲染**。

**复杂度与成本预算**：
- **C1**：一人可长期维护。M1 结束时 `cloud-cf/src/` 业务代码 `< 500 行` [目标]（M2 实测 `690 行` `[已测]` <= `700 行`；M4 含 100 条图文剪贴板与流式 R2 后约 `870–930 行` `[估算]`），`mynote-core` 同步核心 `< 3,000 行` [目标]（剪贴板逻辑置于独立 `clip` 模块）。任何新增机制必须附上实测触发数据（F-08）。
- **C2**：Cloudflare Workers Paid 约 `\$5/月` [估算]，配置 Spend Management 支出告警（D4）。

---

## 2. 单一事实来源（SSOT）地图与裁决顺序

遵循 **单一事实来源原则（F-17）**：每个概念只在归属文档中定义一次，其他文档与代码注释只做链接，不复制容易漂移的细节。

| 关注域 | 唯一权威文档 | 关键内容 |
| --- | --- | --- |
| **已拍板决策（最高优先级）** | [`review/2026-11-24-first-principles-review.md`](review/2026-11-24-first-principles-review.md) §9 | 决策 D1–D8（含 D1′、D2′、D5′）及 PR #31 / 2026-11-25 / 2026-11-27 补充拍板；**与旧文档冲突时一律以 §9 为准** |
| **总览、ADR 与路线图** | [`docs/architecture-proposal.md`](docs/architecture-proposal.md) | 目标、非目标、Monorepo 布局、S0 → M4 路线图、ADR-01～ADR-11 状态 |
| **剪贴板调研与决策归档** | [`docs/clipboard-sync-proposal.md`](docs/clipboard-sync-proposal.md) | 2026-11-27 D8（Q1–Q6）可行性调研、竞品对比与移动端三梯队交互设计；底层契约以各专题 SSOT 规范为准 |
| **数据结构与线格式** | [`docs/data-structures.md`](docs/data-structures.md) | ULID、定长 HLC、FractionalIndex、`InnerOpV1`、信封布局、**全项目唯一 AAD 定义（§3.3）**、全端 DDL |
| **同步协议与物化语义** | [`docs/sync-protocol.md`](docs/sync-protocol.md) | 路径 γ 多叶子并列、完整因果图 `G(b)`、密钥表 2P-Set、删除/碎纸协议、跨 `epoch` 并集对账、手机状态快照 |
| **跨边界接口与 CLI 契约** | [`docs/interface-contracts.md`](docs/interface-contracts.md) | 全局 `ErrorCode` 与退出码表、CLI `--json` 信封与子命令、本地 Daemon REST/WS/UDS、云端 Sync API、WASM FFI |
| **安全承诺与威胁模型** | [`docs/threat-model.md`](docs/threat-model.md) | 敌手矩阵 T1–T9、约 37 天删除上界、代码管不到的副本、本地鉴权、同 UID 诚实边界、手机 PWA 信任边界 |
| **云端实现规范** | [`docs/cloudflare-cloud-architecture.md`](docs/cloudflare-cloud-architecture.md) | 极薄盲中继职责、DO SQLite/Alarm/WS Hibernation、R2 布局与生命周期、Spend Management、8 条防坑红线 |
| **质量门禁与执行纪律** | [`docs/eval-framework.md`](docs/eval-framework.md) | Plane A 确定性门禁（proptest / DST / Worker 契约 / INV-RECOVERY / SEC / CLI 黄金测试）、里程碑门禁矩阵 |
| **S0 技术 Spike 实测报告** | `docs/spikes/s0-*.md` | 各 Spike 一页实测结论，支撑 ADR 由 `Proposed` 转为 `Accepted` |

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
- **独立 100 条图文剪贴板红线（D8，M4）**：
  - **严格物理隔离**：剪贴板条目严禁写入笔记 `ops` / `block_keys` / `shred_marks` / 手机 `MNP1` 快照 / R2 永久 op 归档 / 本地 FTS5 与 Markdown 镜像（`INV-CLIP-ISOLATION`）；原图大对象与本地 `clip_cache/`（LRU `256 MiB`）严禁塞进本地或云端 SQLite 主表；
  - **四态令牌最小权限**：绝不因支持手机发剪贴板而赋予手机 `read-write`；`read+clip` 对全部笔记写、密钥与碎纸路由仍返回 `403`，`clip-write` 对全部 `GET`（含 `GET /v1/clip*`）与笔记路由返回 `403` 且配对票据不含 `SMK`；
  - **流式 R2 与零 PITR 诚实边界**：图片与 `> 64 KiB` 长文本（单条上限 `10 MiB`）必须通过 `PUT /v1/clip/blob` 流式直写 R2 `clip/blobs/`（防触发 Worker 128 MB 内存上限，物理 0 进入 DO 30 天 PITR）；小文本与轻索引存 DO `clip_items`（保留最近 100 条 / 7 天 TTL）并使用与 `SMK`/`VKEK` 隔离、轮换不留旧钥的独立 `ClipKey`（`MNC1`）；`--ephemeral`（`≤ 256 KiB`）严禁写 SQLite 或 R2，无在线桌面直接返回 `409 NO_ONLINE_DESKTOP`；
  - **防 XSS 与桌面隐私过滤**：图片通道严格白名单 `image/png`、`image/jpeg`、`image/webp`、`image/gif`，**严禁 `image/svg+xml` 按图片解析或渲染**；macOS 改用原生 `NSPasteboard`（优先读 `public.png` 避开超大 `public.tiff`），macOS / Wayland 硬过滤 `ConcealedType` / `TransientType` / `AutoGeneratedType` / `com.apple.is-remote-clipboard` / `x-kde-passwordManagerHint`，M4b 后台自动监听（默认关闭 opt-in）须接入 `detect_secret_pattern` 拦截与含转码后 PNG 字节哈希的双重防回环。

---

## 4. 已移除 / 推迟的机制（禁止擅自重新引入）

以下机制已在 2026-11-24 审查中明确裁剪或推迟（2026-11-27 随 D8 局部修订），编码时**不要顺手补回**：
- **D1′**：手机编辑/追加笔记块、笔记 outbox、移动端 CM6 / Layer 3 格式化；旧版写入 DO SQLite 且声称零 PITR 的 `ephemeral_clips` 表（F-06，已永久废弃；M4 剪贴板走 D8 独立通道）。
- **D2′ / F-04 / F-05**：`purge_op_ids`、可变 `vault_keys` / `MNK1` / `key_seq` / `INV-SYNC-4`、`vault_key_slots` 多槽位、Vault 第二套恢复码、云端 `/v1/archive/*` 路由。
- **D3 / F-02 / F-03 / F-18**：`SPAN_PATCH` / delta 链、Loro/Yjs CRDT、HLC 漂移拒收、Lock-Wins 特例、分数索引重平衡。
- **D4**：DO 滑动窗口 GC、R2 K=5 多代快照 + CAS、「\$0/月免费额度」约束。
- **D5′（2026-11-25 修订）**：macOS Tauri 薄壳（`shell-macos/`）、Tauri 自定义协议 `tauri://localhost` / Bearer 鉴权分支与独立 `.app` 打包（双桌面统一纯 CLI + Daemon + 内嵌 HTML）。
- **D6 / F-13 / F-14 / ADR-08**：本地与云端 MCP、`mynote update` 自升级、WebAuthn PRF、`--help-json`、加密图片附件 `blobs/`、WebSocket 携带 op 顺风车、Plane B 统计评测、自动爬山与 LLM 评委（`evals/archive/` 仅供存档参考）。

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
├── web/                       # TypeScript 前端（桌面 CM6 + 手机只读 PWA）
├── cloud-cf/                  # Cloudflare Worker 极薄盲同步中继（M1 < 500 行 TS）
├── skill/SKILL.md             # Agent Skill（严格 < 250 tokens）
├── tests/
│   ├── scenarios/             # Rust DST 与真实 Worker 契约测试共用场景
│   └── fixtures/              # Heynote 脏语料、XSS 向量
├── evals/                     # 不可变验证器资产（详见 §7 铁律！）
├── spikes/                    # S0 限时技术验证原型（隔离目录，严禁被正式 crate/应用依赖）
├── docs/                      # 设计规范与 docs/spikes/ 实测报告
└── review/                    # 架构审查与决策记录
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
5. **S-Clip & M4（D8，2026-11-27 拍板）**：先完成限时 `S-Clip-1`–`S-Clip-5` 真机 Spike（验证后 `ADR-11` 升为 `Accepted`）→ **M4a**（100 条图文显式跨端剪贴板 + 移动端 → 桌面双向通道，`INV-CLIP-ISOLATION` / `SEC-09`）→ **M4b**（桌面 ↔ 桌面图文后台自动镜像，默认关闭 opt-in）。

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
