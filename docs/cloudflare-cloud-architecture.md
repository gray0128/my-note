# 基于 Cloudflare 技术栈的自部署云端架构：深度评估与设计方案

> 本文档是 [总架构设计方案 (`architecture-proposal.md`)](./architecture-proposal.md) 的云端专项设计。结合已确定的核心取舍——**云端自部署在 Cloudflare 技术栈，且不考虑云端 MCP 与本地 MCP（Agent 统一走本地 CLI + Skill）**——本方案聚焦于构建一个**100% 零知识端到端加密（E2EE）、零运维、亚秒级推送、个人成本 \$0/月**的极简同步中继与 PWA 托管架构。

---

## 目录

1. [概念辨析与架构红利：为什么「Cloudflare + 全量 E2EE 哑中继」是绝配](#1-概念辨析与架构红利为什么cloudflare--全量-e2ee-哑中继是绝配)
2. [Cloudflare 核心组件选型评估（为什么是 DO SQLite + R2，而不是 D1 / KV）](#2-cloudflare-核心组件选型评估为什么是-do-sqlite--r2而不是-d1--kv)
3. [基于 Cloudflare 的推荐云端架构蓝图](#3-基于-cloudflare-的推荐云端架构蓝图)
4. [全量零知识信任模型：放弃云端 MCP 带来的三大简化](#4-全量零知识信任模型放弃云端-mcp-带来的三大简化)
5. [2026 成本与配额精算（个人单用户场景）](#5-2026-成本与配额精算个人单用户场景)
6. [Cloudflare 专属工程暗坑与防御清单（必看）](#6-cloudflare-专属工程暗坑与防御清单必看)
7. [技术栈与开发语言划分（Worker 用 TS，本地核用 Rust）](#7-技术栈与开发语言划分worker-用-ts本地核用-rust)
8. [逃生舱设计（反厂商锁定）](#8-逃生舱设计反厂商锁定)
9. [分阶段落地路线](#9-分阶段落地路线)

---

## 1. 概念辨析与架构红利：为什么「Cloudflare + 全量 E2EE 哑中继」是绝配

先厘清一个本质问题：**自部署在 Cloudflare（Self-Deployed Single-Tenant PaaS）≠ 自有物理机 VPS**。虽然代码和账号完全属于你个人，但 TLS 终结、V8 运行时、DO SQLite 落盘与 R2 磁盘仍由 Cloudflare 运维托管。

当明确**放弃云端 MCP / 云端明文搜索**之后，这个信任边界瞬间变得无比干净——**云端不再需要解密任何一条笔记**，从而同时吃满 Cloudflare 的全部红利并完全消除云厂商隐私顾虑：

### 1.1 获得的巨大红利
- **零服务器运维**：无需维护 Linux VPS、系统补丁、Nginx/Caddy 证书续期、systemd 重启、硬盘故障或自建数据库备份。一条 `wrangler deploy` 即可把 **PWA 静态站点 + 加密同步 API + WebSocket 亚秒级提醒 + 持久化 SQLite + R2 冷备** 全部上线。
- **接近 \$0 的单用户成本**：SQLite-backed Durable Objects（DO）自 2025 年起已开放至 Workers Free Plan，配合免费无限流量的 Workers Static Assets 与 10GB 免费 R2，个人 3–5 台设备几乎完全落在免费额度内。
- **天然单写者强一致性**：单用户映射单个 Durable Object，天然获得全局单调递增的 `server_seq`，比传统无状态 Serverless + 外置数据库更契合「不可变追加操作日志（Append-Only OpLog）」。
- **内置 30 天时间点恢复（PITR）**：SQLite Durable Object 原生支持 30 天内任意书签时间点回滚，等于云端白送了一层防误删保险。

### 1.2 仍需正视的工程挑战
1. **中国大陆网络可达性**：`*.workers.dev` 在中国大陆默认不可直连或极不稳定，**必须绑定个人自定义域名**；跨境 WebSocket 偶发重置不可避免，因此 **WebSocket 仅作为轻量通知/小包加速通道，可靠交付必须建立在幂等 HTTP `push/pull` 之上**。
2. **计费维度隐蔽性**：Durable Objects 涉及 Requests、Duration（GB-s）、SQLite Rows Read/Write、Storage 多个计费维度（DO SQLite 存储已于 2026 年 1 月正式启用计费），必须防范客户端死循环重试或破坏休眠。
3. **厂商特性绑定**：Durable Objects SQLite 与 Hibernation WebSocket 是 Cloudflare 专属原语，必须在协议层收敛到 5 个极简接口，随时可迁回个人 VPS/NAS。

---

## 2. Cloudflare 核心组件选型评估（为什么是 DO SQLite + R2，而不是 D1 / KV）

| Cloudflare 组件 | 适用角色 | 评估结论 | 核心原因 |
| --- | --- | :---: | --- |
| **SQLite-backed Durable Objects (DO)** | **核心同步引擎（热加密 OpLog + 单调序号 + WS 实时广播）** | **✅ 核心首选** | 1. 单用户一个 DO 实例（`idFromName("primary")`）= 严格单线程串行写入，原子分配 `server_seq`，零分布式锁；<br>2. SQLite 与计算同机共置（零网络跳数），免费版单对象 1GB / 付费版 10GB；<br>3. 支持 **WebSocket Hibernation API**，空闲连接不计 Duration 费用；<br>4. 原生 **30 天 PITR** + **Alarm 定时器**（可自动每日导出加密冷备到 R2）。 |
| **Cloudflare R2** | 加密图片附件 + 每日加密冷备份 / 快照 | **✅ 强烈推荐** | 永久免费 **10 GB 存储 + 0 出口流量费（Zero Egress）**，S3 协议兼容；大体积图片与压缩快照放在 R2 既省 DO SQLite 空间，又方便随时 `rclone` 拖回本地冷备。 |
| **Workers Static Assets** | 托管移动端/桌面端 **PWA 前端静态资源** | **✅ 强烈推荐** | 静态资源请求与存储**永久免费且不限流量**；替代独立的 Pages 项目，让 **PWA + Sync API + DO 合并在同一个 Worker 内一键部署**。 |
| **Cloudflare D1** | 托管分布式 SQLite | **❌ 不推荐** | D1 底层本身就是一个 SQLite DO，但经过了额外网络跳数且**不支持 WebSocket 实时广播**；单用户场景下直接用 SQLite DO 更少一层、延迟更低且原生支持跨设备实时推送。 |
| **Cloudflare KV** | 全局最终一致键值存储 | **❌ 不需要** | 最终一致性（高达 60 秒延迟）会破坏同步日志顺序与幂等性；且不做云端 OAuth/MCP 后，连 Session 缓存都无需引入 KV，架构组件再减一。 |

> **关键认知纠正（为什么 Loro 2026 博客放弃了 DO，而我们反而最适合 DO？）**
> Loro 团队在 2026 年的工程复盘中放弃 DO，是因为他们做的是**多租户高频协同 SaaS**，且试图在 DO 内存中加载整棵 CRDT 文档树做版本比对，导致内存与 SQLite 读写费用飙升。
> 而我们的场景是 **个人单用户（3–5 台设备）+ 100% 盲加密追加日志（服务端零业务解析）+ WebSocket Hibernation**：DO 每次被唤醒只执行 1 条 SQL 插入与 1 次轻量 WS 广播（耗时 `< 5ms`），随即重新休眠，**完美踩中 Durable Objects 成本最低、延迟最稳的甜区**！

---

## 3. 基于 Cloudflare 的推荐云端架构蓝图

整个云端只需部署 **1 个极简 Cloudflare Worker（约 250–300 行 TypeScript，单仓库 `wrangler.jsonc` 一键发布）**，承载全部云端职责：

```mermaid
flowchart TD
    subgraph Clients["多端 Local-First 客户端 (持有本地明文与密钥)"]
        Mac["macOS: mynote Rust Daemon + CLI + Skill + Web UI"]
        Linux["Omarchy: mynote Rust Daemon + CLI + Skill + Hyprland WebApp"]
        Phone["iOS / Android: Local-First PWA (IndexedDB + Rust WASM)"]
        Agent["本地 AI Agent (Claude Code / Codex / OpenCode)"]
        Agent -->|"CLI + SKILL.md (渐进披露帮助)"| Mac
        Agent -->|"CLI + SKILL.md (渐进披露帮助)"| Linux
    end

    subgraph CF["Cloudflare 个人单租户云端 (自定义域名: note.yourdomain.com, 全量盲密文)"]
        Edge["Cloudflare Worker 入口 (Token/Device 鉴权 / 限流 / 路由)"]
        Assets["Workers Static Assets (免费托管 PWA 前端静态资源)"]

        subgraph DO_Box["单实例 SQLite Durable Object: SyncJournalDO"]
            WS["WebSocket Hibernation Hub (实时通知 / 小块顺风车)"]
            SQL[("内嵌 SQLite: 盲加密 ops 表 + snapshots 表 + 30天 PITR")]
            Alarm["每日 Alarm 定时任务"]
        end

        R2[("Cloudflare R2 (免费 10GB, 0 出口费): 加密附件 + 每日加密冷备")]

        Edge -->|"/, /assets/*"| Assets
        Edge -->|"/v1/sync/push, /pull, /snapshot, /ws"| DO_Box
        Edge -->|"/v1/blobs/*"| R2
        Alarm -->|"每日导出加密日志"| R2
    end

    Mac <-->|"HTTPS push/pull + WSS (E2EE 密文)"| Edge
    Linux <-->|"HTTPS push/pull + WSS (E2EE 密文)"| Edge
    Phone <-->|"HTTPS push/pull + WSS (E2EE 密文)"| Edge
```

### 同步链路的核心设计哲学：「HTTP 为可靠真相，WebSocket 为零成本唤醒」

参考开源项目 `durable-sync`（2026 年专门针对 Cloudflare DO 打造的离线同步库）的实战教训，并针对**「跨设备复制粘贴（高实时性 + 可靠性优先）」**场景做专项优化，采用 **混合双通道**：

1. **数据主通道（HTTP `POST /v1/sync/push` & `GET /v1/sync/pull?since=seq`）—— 可靠性底线**：
   - 负责所有真实操作日志的可靠传输、批次提交（单次最多 500 ops）、幂等去重（按 `op_id`）与游标追赶。
   - 即使在电梯/地铁/跨境弱网断连后，也能在 App 回到前台（`visibilitychange` / `pageshow` / `focus` / `online`）时 100% 确定性补齐。
2. **实时提醒通道（DO WebSocket Hibernation）—— 亚秒级跨端复制粘贴**：
   - 客户端在线时保持一条极轻的 Hibernatable WebSocket（开启 `ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"))`，心跳在边缘直接回复，**0 唤醒计费**）。
   - **差异化刷盘策略**：普通连续打字防抖 `400–500ms` 合并推送；而检测到 **粘贴事件（`paste`）/ 窗口失焦（`blur`）/ CLI `mynote clip push`** 时走**快车道（`0–100ms` 立即触发 HTTP `push`）**。
   - **小载荷顺风车优化（可靠性严格优先）**：当单条 op 密文 `<= 16 KB`（99% 的跨设备复制粘贴片段都远小于此）时，DO 写入 SQLite 后直接通过 Hibernatable WebSocket 向其他在线设备广播 `{ type: "op", seq, epoch, op }`（半个 RTT 即可落盘，无需再多一轮 `pull`）。**严格一致性兜底**：接收端检查 `seq === local_seq + 1` 才直接应用；一旦发现跳号（`seq > local_seq + 1`）或 `epoch` 不一致，立即丢弃顺风车帧并回退至确定性的 HTTP `GET /v1/sync/pull?since=local_seq`，保证**速度可以降级，序号绝不缺失**。

| 跨设备复制粘贴链路 | 目标 P95 端到端延迟 | 实测体验与保障机制 |
| --- | :---: | --- |
| **Mac ↔ Omarchy（双端 Daemon 常驻）** | **150 – 350 ms** | 粘贴即推，另一端后台 Daemon 毫秒级落入 SQLite；甚至无需切窗口，热键触发 `mynote clip pull` 直入系统剪贴板（`wl-copy` / `pbcopy`） |
| **桌面 → iOS / Android PWA（亮屏唤醒）** | **250 – 500 ms** | iOS 锁屏后后台 WS 会被系统挂起，故 PWA 切回前台瞬间立即并发触发 HTTP `pull` + WS 重连，打开即见最新粘贴块并提供一键复制按钮 |
| **弱网 / 跨境抖动 / 离线恢复** | 断连自动重试 | 顶栏与块头展示诚实状态灯（`✓ 已同步` / `↑ 同步中` / `◌ 离线待同步`），未收到 DO 明确 JSON ack 前永不清本地 Outbox |

---

## 4. 全量零知识信任模型：放弃云端 MCP 带来的三大简化

明确「不做云端 MCP、Agent 全走本地 CLI + Skill」之后，原先纠结的 **E2EE ⚔️ 云端 MCP 悖论**彻底消失，带来三个立竿见影的工程红利：

1. **云端 100% 零知识，无需在「安全」和「便利」间妥协**：
   - DO SQLite 中的每一条 `ops.payload`、R2 中的每一张粘贴图片与每日备份，离开设备前全部经由 `Sync Master Key (SMK)` 执行 `XChaCha20-Poly1305` 加密；加密块再额外套一层 `Vault Key` 加密。
   - 即使 Cloudflare 账号凭证泄露或云端磁盘被导出，攻击者拿到的只有带 AAD 认证的密文噪声。
2. **云端代码量骤减 ~70%**：
   - 无需在 Cloudflare 上维护物化 `blocks` 表、云端 FTS5 索引、OAuth 2.1 授权服（`@cloudflare/workers-oauth-provider`）、KV Token 存储、`createMcpHandler` 或 `cloudflared` 隧道；
   - 整个 `cloud-cf/` 真正做到「写完一次、长期零维护」。
3. **鉴权极简化**：
   - 个人单用户云端无需复杂的多租户 OAuth 流程：只需在 Worker 环境变量（Cloudflare Secrets）配置签发密钥，使用 **设备级 Bearer Token（每台设备独立可吊销）+ HTTPS + 严格请求体大小与频率限制** 即可完成接入鉴权（即使传输层 Token 泄露，也无法解密任何业务数据）。

---

## 5. 2026 成本与配额精算（个人单用户场景）

按 **1 名重度开发者、4 台设备（Mac + Omarchy + 手机 + 备用机）、每天产生 1,000 次编辑/粘贴同步操作、持续使用 3 年** 估算：

| 资源项 | 个人日均/总量估算 | Workers Free 免费额度 | Workers Paid (\$5/月) 额度 | 落点评估 |
| --- | --- | --- | --- | --- |
| **Workers Static Assets (PWA)** | 每日几十次页面加载 | **免费 & 无限请求/存储** | 免费 & 无限 | **\$0** |
| **DO Requests** | ~1,500 次/日（WS 20:1 折算） | **100,000 次/日** | 100 万次/月 | 仅占免费额度 **1.5%** |
| **DO Duration** | 开启 Hibernation，~50 GB-s/日 | **13,000 GB-s/日** | 400,000 GB-s/月 | 仅占免费额度 **0.4%** |
| **DO SQLite 行读写** | 写 ~3,000 行/日，读 ~20,000 行/日 | **写 10 万行/日，读 500 万行/日** | 写 5,000 万行/月，读 250 亿行/月 | 仅占免费额度 **< 3%** |
| **DO SQLite 存储** | 3 年加密 OpLog ≈ 30–100 MB | **1 GB/DO，5 GB 账户总计** | 10 GB/DO，含 5 GB-月 | 仅占免费额度 **< 10%** |
| **R2 存储与流量** | 加密附件 + 每日冷备 ≈ 0.5–2 GB | **10 GB/月 + 0 出口费** | 同左 | **\$0** |

**结论**：
- 正常使用下，**全程 \$0/月**（只需有一个个人自定义域名，约 \$10/年）。
- 仅在你想消除 Free Plan 到达日限额时硬拒绝的风险、或单 DO 需要突破 1GB 时，再升级 **\$5/月 Workers Paid**，并务必开启控制台 **Spending Limit（如 \$10 封顶 + \$5 告警）**。

---

## 6. Cloudflare 专属工程暗坑与防御清单（必看）

以下 6 条均为 Cloudflare Workers + Durable Objects 生产环境中真实发生过的数据丢失或账单爆炸案例，必须在编码规范中强制落地：

1. **【防丢数红线 #1】Cloudflare Access / 代理的 `res.ok === true` 静默丢数据陷阱**：
   - *事故复盘*（源自 `durable-sync` 真实线上丢数事故）：若同步 API 挂在 Cloudflare Access 等登录网关后，Session 过期会返回 `302` 重定向至登录 HTML 页；浏览器 `fetch()` 默认跟随重定向并返回 `HTTP 200 (res.ok === true)`。如果客户端看到 `res.ok` 就清空本地 Outbox，**这批离线笔记会被永久删除且毫无报错**！
   - *强制防御*：
     1. API 使用独立设备 Bearer Token（不走会 302 到 HTML 登录页的 Cookie 代理），并强制 `redirect: "manual"` + 校验 `Content-Type: application/json`；
     2. 只有当响应 JSON 明确包含 `{ ok: true, epoch: "<uuid>", acked: ["op_1", ...] }` 时，才允许按 `acked` 列表逐条移除本地 Outbox！

2. **【防丢数红线 #2】DO 重置 / PITR 回滚后的 `epoch` 游标失配**：
   - *场景*：若未来使用 Cloudflare 30 天 PITR 将 DO 回滚到 2 天前，此时 DO 的 `head_seq` 变为 800，而客户端本地游标仍停在 `last_synced_seq = 950`。若不做校验，客户端后续请求 `pull?since=950` 将永远返回空数组，导致**永久静默失联**！
   - *强制防御*：DO 初始化时生成一个持久化 `journal_epoch`（UUID）。每次 `push/pull` 与 WS 帧必带 `epoch`；一旦客户端发现服务端 `epoch` 变更或 `server_head_seq < local_cursor`，立即触发**安全对账（重放并补推本地存在但服务端缺失的 `op_id`）**，永不丢数据。

3. **【防账单爆炸 #3】严防破坏 WebSocket Hibernation**：
   - 必须使用 `ctx.acceptWebSocket(server)` 而非旧版 `server.accept()`；
   - 必须使用 `ctx.setWebSocketAutoResponse(...)` 处理应用层心跳；
   - 不要在 DO 中保留未 resolve 的悬挂 Promise 或使用会阻断休眠的第三方 APM/Sentry 包装器；
   - DO 被休眠回收后内存变量会清空，连接元信息（如 `device_id`）必须通过 `ws.serializeAttachment(...)` 持久化在 WebSocket 附件中。

4. **【防限额击穿 #4】客户端 Single-Flight + 批量推送 + 指数退避**：
   - 禁止每次敲键盘发一次 DO 请求！本地写入 SQLite 是即时的，同步上行采用 **普通编辑防抖 400–500ms / 粘贴快车道 0–100ms + 批量合并 + 单飞锁（Single-Flight，同一时刻最多一个同步请求在途）+ 失败指数退避（1s → 2s → 4s → 最大 60s）**。

5. **【防单点灾难 #5】DO Alarm 每日加密冷备到 R2**：
   - 尽管 DO 自带 30 天 PITR，仍应利用 DO 的 `ctx.storage.setAlarm()` 每 24 小时执行一次轻量检查：若有新 `server_seq`，将增量/全量密文日志打包写入 R2（`backups/YYYY-MM-DD-seq-N.bin`）。
   - 这样你的笔记同时拥有 **4 重独立物理副本**：macOS 本地 SQLite + Omarchy 本地 SQLite + Cloudflare DO SQLite（含 30 天 PITR）+ Cloudflare R2 冷备归档。

6. **【网络体验 #6】自定义域名 + WebSocket 降级**：
   - 绝不使用 `*.workers.dev` 作为生产同步域名，务必绑定自定义域名并开启合理的 TLS/HTTP3；
   - 桌面与移动端在 WebSocket 断开时自动静默降级为「写后即推 + 切前台即拉 + 60 秒低频轮询」，保证弱网环境下体感完全无感。

---

## 7. 技术栈与开发语言划分（Worker 用 TS，本地核用 Rust）

| 模块 | 推荐技术栈 | 理由 |
| --- | --- | --- |
| **云端 Worker (`cloud-cf/`)** | **TypeScript + Wrangler + SQLite DO + R2** | 1. Cloudflare 的 `ctx.storage.sql` 与 WebSocket Hibernation 是 **TypeScript 一等公民**，`workers-rs` 在新 API 与本地 `miniflare` 调试体验上明显滞后；<br>2. 全量盲密文中继仅约 **250–300 行极简 TS**，无需在云端跑任何密码学或业务逻辑，部署与维护成本趋近于零。 |
| **桌面单体核心 (`core/` + `cli/`)** | **Rust**（单二进制 `<12–15MB`） | 1. 本地 Daemon + 完备 CLI（`clap` 分级渐进披露帮助 + `--json`）+ SQLite WAL/FTS5 + `zeroize` 内存安全擦除；<br>2. 去掉 MCP 依赖后二进制更小、启动更快；<br>3. 同一套加密（`Argon2id` + `XChaCha20-Poly1305`）与 Layer 1 格式化器编译为 **WASM**，直接喂给 Cloudflare 托管的移动端 PWA，消除双端密码学实现差异！ |
| **Web / PWA 前端 (`web/`)** | **TypeScript + CodeMirror 6 + SolidJS/Preact + `core-wasm`** | 编译产物同时服务两处：<br>- 通过 `rust-embed` 嵌进桌面 `mynote` 单二进制（服务 macOS / Omarchy）；<br>- 通过 **Workers Static Assets** 部署到 Cloudflare（服务 iOS / Android PWA）。 |

---

## 8. 逃生舱设计（反厂商锁定）

因为架构是 **Local-First + 全量盲密文 5 接口契约**，未来脱离 Cloudflare 的成本极低：

### 标准化 5 接口同步契约（Cloudflare 与自建 VPS 100% 通用）

| 接口 | 作用 |
| --- | --- |
| `POST /v1/sync/push` | 幂等追加加密 `ops[]`，返回 `{ ok, epoch, acked, head_seq }` |
| `GET /v1/sync/pull?since=<seq>&limit=<n>` | 游标增量拉取密文日志，返回 `{ ok, epoch, ops, head_seq, has_more }` |
| `PUT / GET /v1/sync/snapshot` | 上传/获取客户端生成的最新加密压缩快照（新设备冷启动加速） |
| `GET /v1/sync/ws`（可选） | 实时提醒 / `<=16KB` 加密小包顺风车通道 |
| `PUT / GET /v1/blobs/:sha256` | 内容寻址加密附件存取（CF 走 R2，VPS 走本地目录或 MinIO） |

**随时脱离 Cloudflare 的 3 步逃生路径**：
1. 你的 Mac 和 Omarchy 本机永远存着 **100% 完整的本地 SQLite 数据库与历史操作日志**；
2. 仓库内可保留一个极简的 Rust/Go 独立服务端实现上述 5 个接口（约 250 行代码 + 本地 SQLite）；
3. 未来某天想迁回自建 VPS 或家用 NAS，只需启动该二进制并在各端把配置中的 `sync_url` 改为新地址，首次重连检测到新 `epoch` 后自动完成全量对账上传。

---

## 9. 分阶段落地路线

- **Phase 0（MVP，约 2 周）— 桌面端先替代 Heynote**
  - Rust 单二进制 `mynote`（SQLite WAL + FTS5 + Block 模型 + Layer 1/2 格式化 + **完备 CLI 与分级渐进披露帮助 + `SKILL.md`**）+ 内嵌 CodeMirror 6 Web UI（含 Markdown / Mermaid 离线沙箱渲染）；
  - 跑通 macOS 与 Omarchy（Hyprland Special Workspace）。
- **Phase 1（V1，约 2 周）— Cloudflare 零知识同步 + 跨端剪贴板 + 块级加密 + 移动端 PWA**
  - 新增 `cloud-cf/`（~250 行 TS Worker + `SyncJournalDO` + WebSocket Hibernation + 每日 R2 冷备 Alarm + Workers Static Assets 托管 PWA）；
  - `core-wasm` 编译输出给 PWA，落地 **Tier 1 同步 E2EE + Tier 2 块级 Vault 加密**（支持 WebAuthn PRF 生物识别解锁）；
  - 落地 `mynote clip push/pull` 与跨设备复制粘贴亚秒级快车道。
- **Phase 2（V2，按需扩展）— 极致打磨**
  - R2 加密图片粘贴、macOS 极薄 WKWebView 全局热键壳、非加密块 Loro/Yjs 字符级 CRDT 升级、Math 计算块、只读 Markdown 镜像与终端 TUI 查看器（`ratatui`）。
