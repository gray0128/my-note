# S0-1 实测报告：CodeMirror 6 编辑器形态对比（Issue #32）

- **结论**：**采纳候选 A（视口虚拟化 + 按源码块独立挂载 `EditorView`）**，将 `docs/architecture-proposal.md` §8 **`ADR-07` 升级为 `Accepted`**，并回填选型结论至 #9（`M1-8`）。
- **实验环境**：Playwright Headless Chromium 159（Linux `x86_64`），CodeMirror 6（`@codemirror/view 6.43.15`、`@codemirror/state 6.7.6`、`@replit/codemirror-vim 6.4.0`），原型位于 [`spikes/s0-1-cm6-editor/`](../../spikes/s0-1-cm6-editor/)，可运行 `python3 run_editor_eval.py` 完整复现。

---

## 1. 实测对比矩阵（全部为 `[已测]` 数据）

| 评估维度 | 候选 A：按块挂载 `EditorView`（+ 视口占位虚拟化） | 候选 B：单 CM6 文档 + 原子块边界装饰 + `transactionFilter` |
| --- | --- | --- |
| 块首 `Backspace` 保护块边界 | ✅ 通过（天然物理隔离） | ✅ 通过（需 `transactionFilter` 拦截边界换行） |
| `Ctrl/Cmd+A` + `Backspace` | ✅ **两段式选中**，默认只清当前块，其余块不受影响 | ⚠️ 块头、预览与锁卡保留，但**清空全部可编辑块正文** |
| **Vim `dd` / `dG` 边界安全** | ✅ **结构性隔离在当前块内**（`dG` 绝不误伤后续块） | ⚠️ 块头存活，但实测 `dG` **同步清空后续全部可编辑块** |
| 跨块 `ArrowUp` / `ArrowDown` 跳转 | ✅ 通过（20 行 keymap 桥接，保持列偏移并自动跳过锁卡/预览） | ✅ 原生支持（跨原子块头需按两次方向键） |
| 跨块查找替换（跳过 Tier 2 锁块） | ✅ 通过（25 行数组遍历 + 批量 dispatch） | ✅ 通过（`SearchCursor` 按块范围过滤） |
| 多语言混合语法高亮（JS + JSON + SQL） | ✅ **18 个高亮 token span**（原生按块挂载语言包） | ✅ **18 个高亮 token span**（需手写 `BlockBoundaryParser` + Lezer `parseMixed`） |
| 块首模拟 CJK IME 输入 | ✅ 通过，无边界破坏 | ✅ 通过，无边界破坏 |
| 原生跨块拖选 / 跨块多光标 | ❌ 不支持（独立 `contenteditable` 根） | ✅ 原生支持 |
| 原生跨块统一 Undo / Redo | ❌ 单块独立历史（可在 M1 视需要加 ~40 行焦点撤销栈） | ✅ 原生统一历史 |
| **200 块首屏挂载耗时** | 未虚拟化 `222.1 ms`；**视口虚拟化（首屏 16 块 + `<pre>` 占位）`31.7 ms`** | **`29.8 ms`**（CM6 内置视口虚拟化） |
| **200 块 DOM 节点数** | 未虚拟化 `2,224`；虚拟化 `892`（16 个挂载编辑器 + 184 个轻量 `<pre>`） | **`96`** |
| **200 块打字延迟（P50 / P95）** | 未虚拟化 `11.2 / 28.94 ms`；**虚拟化 `7.30 / 25.15 ms`** | `17.32 / 32.12 ms`（全量扫描边界 + `parseMixed` 重解析） |
| **Spike 核心实现代码量（LOC）** | **`266 LOC`**（`candidateA.ts`） | **`466 LOC`**（`candidateB.ts`，尚未含多叶子卡片、远端无历史补丁与增量 Lezer 树复用） |

---

## 2. 选型理由与诚实取舍

1. **与 `my-note` 的 Block-First、多叶子冲突与 Tier 2 安全模型 1:1 契合（守护 G1 / G4 / C1）**：
   - 每个源码块对应一个独立 `EditorView`，天然隔离块级 `dirty` 标志、`400–500 ms` 防抖合并、`paste` 快车道、`head_op_ids` 乐观锁；
   - Tier 2 锁卡（绝不向 CM6 注入明文）、Markdown / Pele 预览卡片、路径 γ 多叶子并发版本对比卡片均为普通 DOM 组件，零合成哨兵字符（`\uE000`/`\uE002`）；
   - 远端 WebSocket 推送更新其他块时，不会触碰当前正在编辑块的选区、IME 组合态或 Undo 栈。
2. **消除 Scratchpad 场景最危险的误清空陷阱**：
   - 实测显示，在候选 B 的单文档模型中，Vim `dG` 与 `Ctrl/Cmd+A` + `Backspace` 虽未破坏块分隔符，却会**一次性清空当前 Buffer 内所有未锁定块的正文**；而在候选 A 中，上述操作被结构性地限制在当前聚焦块内。
3. **性能与复杂度预算可控**：
   - 加上轻量视口虚拟化后，候选 A 在 200 块压测下挂载耗时 `31.7 ms` [已测]（与候选 B `29.8 ms` 持平），而按键 P50 延迟 **`7.30 ms`** [已测] 比候选 B 快 2.4 倍；维护代码量约为候选 B 的 57%，符合一人长期维护约束（C1）。
4. **明确接受的权衡**：
   - 放弃原生跨块鼠标拖选与跨块多光标（开发者 Scratchpad 中单块一键 Copy 与两段式 `Cmd/Ctrl+A` 已覆盖高频复制需求）；
   - 撤销默认以块为粒度；M1（#9）实现时须强制包含视口虚拟化（`IntersectionObserver` + 高度保持 `<pre>` 占位，禁止全量同时挂载 200 个 `EditorView`）。
