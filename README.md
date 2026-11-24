# my-note

一款面向开发者的**轻量、简洁、多端可靠同步、支持块级加密与 AI Agent 友好**的临时笔记 / Scratchpad 软件（设计规划阶段）。

## 背景

源自长期使用 [Heynote](https://heynote.com/) + iCloud 同步过程中多次遭遇「内容被无故清空」的痛点，目标是在保留 Heynote「多语言分块、随手即记、即时格式化」核心体验的基础上，重构底层数据模型、同步协议、安全边界与 Agent 交互能力，完整覆盖 **macOS**、**Omarchy（Arch + Hyprland）** 与 **移动端（iOS / Android）**。

## 文档索引

- [调研报告与系统架构设计方案 (`docs/architecture-proposal.md`)](./docs/architecture-proposal.md)
  - 根因复盘：为什么 Heynote + iCloud 会反复无故清空内容
  - 成熟开源与商业产品深度调研（10+ 代表性项目横评）
  - 对 6 项核心约束的深度剖析与架构级挑战（含 E2EE × 云端 MCP 悖论、移动端 PWA 陷阱、Wayland/Omarchy 适配等）
  - 推荐架构蓝图、数据模型、防丢同步协议、混合格式化管线、双层加密模型、Markdown/Mermaid 渲染与 Agent/MCP 接口设计
  - 分阶段演进路线图与待决策清单
- [Cloudflare 技术栈云端架构专项评估 (`docs/cloudflare-cloud-architecture.md`)](./docs/cloudflare-cloud-architecture.md)
  - 信任边界重评：Cloudflare 个人单租户部署 vs. 自有物理机 VPS
  - Cloudflare 组件选型（SQLite Durable Objects + WebSocket Hibernation + R2 + Workers Static Assets + `createMcpHandler` / `cloudflared`）
  - 2026 年免费/付费额度精算（个人单用户可稳定落在 \$0/月）
  - 6 大 Cloudflare 专属工程暗坑（Access `res.ok` 丢数陷阱、DO PITR `epoch` 游标失配、休眠计费陷阱、大陆网络域名等）与反锁定逃生舱设计
