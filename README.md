# my-note

一款面向开发者的**轻量、简洁、多端可靠同步、支持块级加密、Markdown/Mermaid 渲染与 CLI + Skill（Agent 友好）**的临时笔记 / Scratchpad 软件（设计规划阶段）。

## 背景

源自长期使用 [Heynote](https://heynote.com/) + iCloud 同步过程中多次遭遇「内容被无故清空」的痛点，目标是在保留 Heynote「多语言分块、随手即记、即时格式化」核心体验的基础上，重构底层数据模型、同步协议、安全边界与 Agent 交互能力，完整覆盖 **macOS**、**Omarchy（Arch + Hyprland）** 与 **移动端（iOS / Android）**。

## 已确立的核心架构基线

- **云端自部署栈**：基于 **Cloudflare（Workers + SQLite Durable Object + WebSocket Hibernation + R2 + Workers Static Assets）**，全量零知识端到端加密（E2EE），个人单用户可稳定运行在 \$0/月免费额度内。
- **Agent 集成范式**：**不做本地或云端 MCP**，纯粹通过 **高完备度 CLI + 极轻 `SKILL.md` + 四级渐进披露帮助体系（L0–L3）** 实现极低 Token 成本、可管道组合的 Agent 友好交互。
- **核心能力**：Block-First 数据模型 + 不可变追加日志同步（含跨设备复制粘贴亚秒级快车道）+ 三层混合格式化 + 双层加密（同步 E2EE + 块级 Vault 加密）+ Markdown / Mermaid 离线沙箱渲染。

## 文档索引

- [调研报告与系统架构设计方案 (`docs/architecture-proposal.md`)](./docs/architecture-proposal.md)
  - 根因复盘：为什么 Heynote + iCloud 会反复无故清空内容
  - 成熟开源与商业产品深度调研（11 款代表性项目横评）
  - 对 6 项核心约束的深度剖析、架构级挑战与决策收敛
  - 推荐架构蓝图、数据模型、防丢同步协议、跨设备剪贴板快车道、混合格式化管线、双层加密模型、Markdown/Mermaid 防 XSS 渲染，以及 **CLI + Skill 四级渐进披露帮助体系规范**
  - 分阶段演进路线图与待决策清单
- [Cloudflare 技术栈云端架构专项评估 (`docs/cloudflare-cloud-architecture.md`)](./docs/cloudflare-cloud-architecture.md)
  - 放弃云端 MCP 后的全量零知识 E2EE 架构红利
  - Cloudflare 组件选型（SQLite Durable Object + WebSocket Hibernation + R2 + Workers Static Assets）
  - 2026 年免费/付费额度精算（个人单用户可稳定落在 \$0/月）
  - 6 大 Cloudflare 专属工程暗坑（Access `res.ok` 丢数陷阱、DO PITR `epoch` 游标失配、休眠计费陷阱、大陆网络域名等）与反锁定逃生舱设计
