# my-note

一款面向开发者的**轻量、简洁、多端可靠同步、支持块级加密、Markdown/Mermaid 渲染与 CLI + Skill（Agent 友好）**的临时笔记 / Scratchpad 软件（设计规划阶段）。

## 背景

源自长期使用 [Heynote](https://heynote.com/) + iCloud 同步过程中多次遭遇「内容被无故清空」的痛点，目标是在保留 Heynote「多语言分块、随手即记、即时格式化」核心体验的基础上，重构底层数据模型、同步协议、安全边界与 Agent 交互能力，完整覆盖 **macOS**、**Omarchy（Arch + Hyprland）** 与 **移动端（iOS / Android）**。

## 已确立的核心架构基线

- **本地核心与 WASM 共享层**：**Rust Sans-I/O** 纯同步核心（`mynote-core`）+ 单体二进制（Daemon + CLI + `rusqlite` WAL/FTS5/`secure_delete` + `clap` + `zeroize`），将协议状态机、加解密与 Layer 1 格式化器编译为 **WASM** 复用到桌面 Web UI 与移动端 PWA（配极简 IndexedDB）。
- **云端自部署栈与信任边界**：基于 **Cloudflare（TypeScript Worker + 5 列盲日志 SQLite Durable Object + WebSocket Hibernation + R2 多世代快照/冷备 + Workers Static Assets）**，对被动存储与备份 100% 零知识 E2EE（桌面端永不加载远端代码，移动端 PWA 代码分发受自有硬件 FIDO2 2FA CF 账号保护），个人单用户稳定运行在 \$0/月免费额度内。
- **Agent 集成范式**：**不做本地或云端 MCP**，纯粹通过 **高完备度 CLI（直写 SQLite WAL + Unix Socket 唤醒，Daemon 未起亦可用）+ 极轻 `SKILL.md` + 四级渐进披露帮助体系（L0–L3）** 实现极低 Token 成本、可管道组合的交互。
- **多端交付形态**：macOS 与 Omarchy（Arch + Hyprland）走本地 Rust Daemon（`Host + Origin + HttpOnly` 鉴权）+ 按块虚拟化 CodeMirror 6 内嵌 Web UI；移动端（iOS / Android）采用 **Local-First PWA**（支持 URL `#fragment` 零泄露扫码配对与平台 Passkey WebAuthn PRF 解锁）。
- **核心能力**：Block-First 数据模型 + 形式化防丢同步协议（`FULL_ZSTD`/`SPAN_PATCH` + `(hlc, op_id)` 纯函数冲突投影 + 确定性模拟测试门禁）+ 三层混合格式化 + 双层加密（Tier 1 同步盲信封 + Tier 2 客户端内存级保险库，常驻 Daemon 零明文）+ Markdown 双模极致复制与 [Obsidian `Pele`](https://github.com/obsidianmd/pele) 零 `<foreignObject>` 纯 SVG 图表渲染。

## 文档索引

- [调研报告与系统架构设计方案 (`docs/architecture-proposal.md`)](./docs/architecture-proposal.md)
  - 根因复盘（Heynote + iCloud 丢数机制）、11 款竞品深度调研与 6 项核心约束剖析
  - 整体架构蓝图、Block-First 数据模型、三层格式化、Markdown/Pele 渲染与 CLI L0–L3 帮助规范
  - Cargo Workspace 目录规划、重切后的 **M0 → M3** 演进路线图与已冻结的架构决策基线（ADR 摘要）
- [核心数据结构、存储 Schema 与二进制线格式规范 (`docs/data-structures.md`)](./docs/data-structures.md)
  - 强类型 ULID、定长可排序 `Hlc` 与 Base62 `FractionalIndex` 编码规范，以及 `mynote-core` Sans-I/O 领域类型定义
  - 256B 双射阶梯填充算法与 `MNS1`（同步盲信封）、`MNV1`（保险库密文）、`MNK1`（密钥同步）、`MNP1`（头体分离快照）精确字节布局
  - 桌面本地 SQLite `STRICT` 完整 DDL（含 `block_conflicts` 物化表与 `CHECK` 硬约束）、Cloudflare DO SQLite 完整 DDL 与移动端 PWA IndexedDB Schema
- [全链路接口与跨边界契约规范 (`docs/interface-contracts.md`)](./docs/interface-contracts.md)
  - 全局错误码注册表（Rust 错误码 ↔ CLI 退出码 `0–8` ↔ HTTP 状态码 ↔ Agent 自愈 `hint`）
  - CLI 全子命令矩阵（含 `mynote update` 离线 `Ed25519` 验签自升级、Homebrew/AUR 包管理器探测护栏与 `--rollback` 秒级回滚）、JSON 信封 DTO、`--help-json` 反射 Schema 与 Layer 2 `formatters.toml` 零字节熔断契约
  - 本地 Daemon REST/WS/Unix Socket NDJSON 协议（含升级热交接排空）、云端 Worker/DO/R2 请求响应 Schema，以及 `mynote-wasm` TypeScript FFI（含 `WasmVaultSession` 不透明句柄）
- [同步协议与确定性物化规范 (`docs/sync-protocol.md`)](./docs/sync-protocol.md)
  - 5 列盲存储线格式、防「空 `UPDATE`」类型门禁、字段级因果拆分、`(hlc, op_id)` 纯函数冲突投影、R2 多代快照与 DO 活跃水位滑动窗口 GC、`epoch` 并集对账状态机及 M1 确定性属性模拟测试门禁
- [安全架构与威胁模型规范 (`docs/threat-model.md`)](./docs/threat-model.md)
  - 7 类敌手诚实信任矩阵（含发布供应链防投毒）、LUKS 式 `vault_key_slots` 多槽位包裹、可变 `vault_keys` 碎纸墓碑同步、「先写后锁」本地 `wal_checkpoint(TRUNCATE)` + 云端 `purge_op_ids` 即时擦除、主备双公钥自升级验签、本地 Daemon 鉴权、严格 CSP 与二维码 `#fragment` 配对/轮换预案
- [Cloudflare 技术栈云端架构专项评估 (`docs/cloudflare-cloud-architecture.md`)](./docs/cloudflare-cloud-architecture.md)
  - Cloudflare 组件选型（SQLite DO + WebSocket Hibernation + R2 + Workers Static Assets）与 2026 配额精算
  - 7 大 Cloudflare 专属工程暗坑（Access `res.ok` 丢数、PITR `epoch` 并集对账、DO SQL 单语句 100 绑定参数与二级索引双倍行写、休眠计费等）与反锁定逃生舱设计
- [全链路评测框架、自动化爬山与执行治理规范 (`docs/eval-framework.md`)](./docs/eval-framework.md)（配 [`evals/`](./evals/) 契约与种子库）
  - 双平面验证架构：Plane A 确定性系统验证（`SimCluster` DST、全盘金丝雀擦除取证、格式化/导入差分属性、FTS5 `Recall@5` 阶段评测）+ Plane B 概率性 Agent + `SKILL.md` + CLI 多轮沙盒评测
  - 受控表面自动化爬山（`climb-spec.toml` 防过拟合三铁律与卡壳零编辑归因复盘）、Cohen's Kappa 评委校准、`pass^3` + 配对 McNemar 统计检验，以及「不可变裁判」四级 CI 执行规范与一页四数发布计分卡
