# S-Win-1 实测报告：Windows Named Pipe SDDL、Job Object 进程树回收与 Win32 原生剪贴板（Issue #77）

- **状态**：通过（GitHub Actions `windows-latest` 真机 8/8 单测与集成测试 + Release 基准全部通过）
- **实测环境**：`Microsoft Windows Server 2025 Datacenter`（`Version 10.0.26100, Build 26100` `[已测]`）/ `x86_64-pc-windows-msvc`（`AMD EPYC 9V74`, `2` 核 `4` 逻辑处理器 `[已测]`）/ `rustc 1.100.1 (20ddd0171 2026-11-25)` / `Python 3.12.10` / 当前会话 `User=runneradmin, IsElevatedAdmin=True` `[已测]`
- **复现路径**：[`spikes/s-win-1-platform/`](../../spikes/s-win-1-platform/) 与 `.github/workflows/spike-win.yml`（Spike 期临时工作流，CI Run `46123187193`；`windows-latest` 常驻门禁合入 `.github/workflows/ci.yml` 后已移除）
  - 静态门禁：`cargo clippy --manifest-path spikes/s-win-1-platform/Cargo.toml --all-targets -- -D warnings`
  - 集成测试：`cargo test --manifest-path spikes/s-win-1-platform/Cargo.toml -- --nocapture`
  - Release 体积与延迟基准：`cargo build --manifest-path spikes/s-win-1-platform/Cargo.toml --release` 与 `s-win-1-platform.exe --bench`
- **预算红线核验**：`crates/`、`cloud-cf/src/`（`0 LOC` `[保证]`）、`web/`（`0 B` `[保证]`）与 `evals/` 均为零改动；`windows-sys 0.61.2` 仅拉入 `windows-link 0.2.1` 共 `2` 个 crate，包含 Tokio 多线程运行时、`serde_json`、`image`（`png`）与三大 Win32 模块的独立 Release 二进制（`lto = "thin", strip = true`）总体积仅 `1,116,672 B`（`1,090.5 KiB` / `1.06 MiB`）`[已测]`，远低于整包 `< 15 MB` `[目标]`。

---

## 1. 核心实测结论（支撑启动 `M5-W1..W3`）

1. **Named Pipe 默认配置确有越权隐患，显式 `D:P(A;;GA;;;OW)` 彻底收敛**：不传 `SECURITY_ATTRIBUTES` 时，`tokio::net::windows::named_pipe::ServerOptions::create` 在 Windows Server 2025 内核生成的默认 SDDL 为 `O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BA)(A;;FR;;;WD)(A;;FR;;;AN)` `[已测]`，即未保护 DACL 同时向 `Everyone`（`WD`）与 `Anonymous Logon`（`AN`）开放了读权限（`FR`）。传入显式 SDDL `D:P(A;;GA;;;OW)` 并开启 `first_pipe_instance(true)` 与 `reject_remote_clients(true)` 后，内核回读 SDDL 收敛为 `O:BAD:P(A;;FA;;;OW)`（DACL 仅 `D:P(A;;FA;;;OW)`，零 `WD` / `AN` / `AU`）`[已测]`，`GetNamedPipeInfo` 实测返回 `pipe_flags = 0x9`（`PIPE_SERVER_END | PIPE_REJECT_REMOTE_CLIENTS`）`[已测]`，同名管道二次 `first_pipe_instance(true)` 抢注确定性失败并返回 `ERROR_ACCESS_DENIED (os error 5)` `[已测]`。
2. **NDJSON 本地 IPC 延迟充裕满足 G2 预算**：在 `D:P(A;;GA;;;OW)` 管道上，Release 模式（5 轮交替采样，每轮 1,000 次长连接帧 + 200 次短连接建连往返，0 错误）实测长连接单帧往返 p50 中位数为 `26.0 µs`（范围 `25.6..33.4 µs`）`[已测]`，模拟 CLI 单次调用「`ClientOptions::open` + NDJSON 读写 + 关闭」全链路 p50 中位数为 `112.6 µs`（范围 `85.9..139.4 µs`）`[已测]`，仅占 G2 `< 15 ms` `[目标]` 预算的 `0.75%`，受限于本地 `npfs.sys` 内核 IOCP 两次线程唤醒。
3. **无黑框挂起建进程 + Job Object 实现毫秒级零孤儿回收**：通过 `CreateProcessW`（`CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT`）在主线程挂起态完成 `AssignProcessToJobObject`（`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`）再调用 `ResumeThread`，消除子进程抢先派生逃逸孙进程的竞态窗口。实测关闭 Job 句柄后，子进程（`python.exe`）与孙进程（`ping.exe`）在 `1.929 ms`（Release）/ `1.883 ms`（Debug）`[已测]` 内全部终止，孤儿残留数为 `0` `[已测]`。最小环境白名单（保留 `SYSTEMROOT`、剥离非白名单 `COMPUTERNAME`）配合注入 `PYTHONUTF8=1` 后，`python.exe` 无需 `-X utf8` 参数即可无损往返中文与 Emoji UTF-8 JSON（5 轮 Release 冷启中位数 `28.53 ms`，范围 `27.93..29.31 ms` `[已测]`）。
4. **Win32 原生剪贴板事件驱动监听、格式优先级与隐私硬过滤全部就绪**：无头 `windows-latest` 会话下，`HWND_MESSAGE` + `AddClipboardFormatListener` 在 `CloseClipboard()` 后 `348.7 µs` `[已测]` 内投递 `WM_CLIPBOARDUPDATE`（零轮询）。同时存在 `"PNG"` 与更大 `CF_DIBV5` 时，先枚举格式可做到仅调用 `1` 次 `GetClipboardData(PNG)`、`0` 次读取 `CF_DIBV5` `[已测]`；缺少 `"PNG"` 时，1080p（`1920×1080`，`8,294,524 B`）`CF_DIBV5` 回退转码为无损 PNG（`52,336 B`）在 Release 下 5 轮中位数仅 `8.41 ms`（范围 `8.34..8.58 ms`）`[已测]`。三项 Windows 隐私格式与 SVG 拦截均按预期阻断且不读取用户正文。

---

## 2. 分项实测数据

### 2.1 Named Pipe 本地隔离与 NDJSON 延迟（`SEC-WIN-PIPE`）

当前进程令牌实测：`TokenUser = S-1-5-21-2315611937-1800655502-2561009274-500`，`TokenOwner = S-1-5-32-544`（UAC 提权管理员组 `BA`）`[已测]`。

| 配置方案 | `GetSecurityInfo` 内核回读完整 SDDL `[已测]` | `PIPE_REJECT_REMOTE_CLIENTS` `[已测]` | 安全判定 |
| --- | --- | :---: | --- |
| Tokio 默认 `ServerOptions::create`（对照基线） | `O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BA)(A;;FR;;;WD)(A;;FR;;;AN)` | 是（默认开启） | 不安全：未设 `P` 保护标志，且允许 `WD`（Everyone）与 `AN`（匿名）读取 |
| 显式 `D:P(A;;GA;;;OW)`（SSOT 契约） | `O:BAD:P(A;;FA;;;OW)`（DACL：`D:P(A;;FA;;;OW)`） | 是（`pipe_flags = 0x9`） | 通过：受保护 DACL，内核将 `GA` 映射为 `FA`，彻底移除 `WD` / `AN` |
| 显式 `D:P(A;;GA;;;<TokenUser SID>)`（对照） | `O:BAD:P(A;;FA;;;LA)`（DACL：`D:P(A;;FA;;;LA)`） | 是（`pipe_flags = 0x9`） | 通过：严格绑定当前用户 SID（RID `-500` 被 SDDL 序列化简写为 `LA`） |

NDJSON 往返延迟（载荷含中文与 Emoji，预热后 5 轮独立测试，`0` 失败响应，限速因素为本地 `npfs.sys` 重叠 I/O 与 Tokio 多线程调度唤醒）：

| 场景 | 构建配置 | 样本量 | p50 中位数 `[已测]` | 5 轮 p50 范围 `[已测]` | 单轮 p95 范围 `[已测]` | 单轮 p99 范围 `[已测]` |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| 已建连长连接单帧往返（对标 `watch` / 复用流） | Release (`lto=thin`) | `5 × 1,000` | `26.0 µs` | `25.6..33.4 µs` | `28.4..38.6 µs` | `36.8..52.8 µs` |
| 短连接 `open` + 往返 + 关闭（对标单次 CLI 写转发） | Release (`lto=thin`) | `5 × 200` | `112.6 µs` | `85.9..139.4 µs` | `105.2..180.1 µs` | `120.4..202.8 µs` |
| 已建连长连接单帧往返 | Debug (`cargo test`) | `5 × 500` | `84.9 µs` | `75.9..85.4 µs` | `106.5..115.2 µs` | `114.6..136.8 µs` |
| 短连接 `open` + 往返 + 关闭 | Debug (`cargo test`) | `5 × 100` | `242.1 µs` | `240.5..242.6 µs` | `265.4..281.8 µs` | `281.2..337.4 µs` |

### 2.2 加固子进程与 Job Object 进程树回收

| 验证项 | 实测观测结果 `[已测]` | 结论 |
| --- | --- | :---: |
| `.bat` / `.cmd` / `cmd.exe` 拦截 | 对 `.bat`、`.CMD`、尾部带点或空格的 `evil.bat. `、`cmd.exe` 以及临时落盘的真实 `.bat` 文件，均在调用 `CreateProcessW` 前返回 `BatchScriptForbidden`（规避 `CVE-2024-24576`） | 通过 |
| 挂起态绑 Job Object 杀孙进程树 | `python.exe` 派生 `ping.exe -n 60 127.0.0.1` 并输出 `GRANDCHILD_PID`；父进程持 `PROCESS_SYNCHRONIZE` 句柄确认父子均处于 `STILL_ACTIVE` 后关闭 Job 句柄，父子进程在 `1.929 ms`（Release）/ `1.883 ms`（Debug）内全部退出，`0` 孤儿残留 | 通过 |
| `oneshot` 超时熔断（PowerShell 派生 `ping.exe`） | 设定 `400 ms` 超时后触发 `drop(job)`，准确返回 `TimedOut { timeout_ms: 400 }` 并清理整棵子进程树 | 通过 |
| 最小环境白名单 + 中文/Emoji UTF-8 往返 | 子进程内 `SYSTEMROOT == true`、`PYTHONUTF8 == "1"`、父进程 `COMPUTERNAME` 实测为 `null`（零泄露）；中文与 Emoji JSON 100% 原样往返，5 轮 Release 耗时中位数 `28.53 ms`（范围 `27.93..29.31 ms`） | 通过 |

### 2.3 Win32 剪贴板读写、格式回退与隐私过滤（`SEC-WIN-CLIP`）

| 验证项 | 剪贴板暴露格式（`EnumClipboardFormats`）`[已测]` | `GetClipboardData` 调用记录 `[已测]` | 实测结果 `[已测]` |
| --- | --- | --- | --- |
| UTF-16 文本 + `WM_CLIPBOARDUPDATE` | `[(13, "CF_UNICODETEXT"), (16, "CF_16"), (1, "CF_1"), (7, "CF_7")]` | `[13]` | `348.7 µs` 收到事件（`seq=5`），多行中文与 Emoji 无损还原 |
| `"PNG"` + 16×16 `CF_DIBV5` 并存 | `[(17, "CF_DIBV5"), (49385, "PNG"), (2, "CF_2"), (8, "CF_8")]` | `[49385]`（`0` 次读 `17`） | 直接返回原始 2×2 PNG 字节，避开 `CF_DIBV5` 解码 |
| 仅 `CF_DIBV5` 回退转 PNG | `[(17, "CF_DIBV5"), (2, "CF_2"), (8, "CF_8")]` | `[17]` | 8×6 RGBA 像素解码比对 100% 一致；1080p（`8.29 MiB`）转 PNG Release 中位数 `8.41 ms`（Debug 为 `433.76 ms`，相差 `51.6×`） |
| SVG XSS 防护（`image/svg+xml` 与伪造 `"PNG"`） | 含 `image/svg+xml` 或 `"PNG"` 槽塞入 `<svg>` 字节 | `[]`（纯 SVG 格式）/ `[49385]`（伪造槽） | 均返回 `RejectedSvg`，拒绝进入位图通道 |
| `ExcludeClipboardContentFromMonitorProcessing` | 含该注册格式 + `CF_UNICODETEXT` | `[]`（`0` 次读数据） | 仅凭格式存在即返回 `SkippedPrivacy`，零正文读取 |
| `CanIncludeInClipboardHistory == 0` / `CanUploadClipboardDataToCloud == 0` | 含对应格式（`DWORD = 0`）+ `CF_UNICODETEXT` | 仅读 4B 标志位，零读 `13` | 均返回 `SkippedPrivacy`；阳性对照 `DWORD = 1` 正常放行读取文本 |
| 本机防回环标记 `dev.mynote.synced-clip` | 含该注册格式 + `CF_UNICODETEXT` | `[]`（`0` 次读数据） | 返回 `SkippedEchoMarker`，与 M4b `BLAKE3` 抑制窗构成双重防回环 |

---

## 3. 指导 `M5-W1..W3` 落地的四项工程发现

1. **UAC 提权会话下的 `TokenOwner` 与 RID `-500` 别名 `LA`（指导 `M5-W1` `local_ipc.rs` 与 `SEC-WIN-PIPE`）**：
   - 在 UAC 提权管理员进程（如 GitHub Actions `runneradmin`）中，`TokenOwner` 为 `S-1-5-32-544`（`BUILTIN\Administrators`，SDDL 简写 `BA`），而 `TokenUser` 为具体用户 SID `S-1-5-21-...-500`；普通非提权桌面用户进程中两者相同。
   - 若生产 `local_ipc.rs` 希望在同一机器存在多个提权管理员账户时仍严格隔离到当前登录用户，可在启动时查询 `TokenUser` 拼装 `D:P(A;;GA;;;<TokenUser SID>)`（或组合 `OW`）；同时 `SEC-WIN-PIPE` 测试用 `ConvertSecurityDescriptorToStringSecurityDescriptorW` 校验内核回读 SDDL 时，必须考虑内置管理员 RID `-500` 会被格式化为两字母别名 `LA`，或直接读取二进制 `ACL` ACE 并调用 `ConvertSidToStringSidW` 比对数值 SID。
2. **Daemon 多客户端 Named Pipe 接受循环模式（指导 `M5-W1` `local_ipc.rs`）**：
   - Windows Named Pipe 每个 `NamedPipeServer` 实例仅服务一条客户端连接。Daemon 首个监听实例必须设置 `first_pipe_instance(true)` 防同名抢注；每次 `server.connect().await` 返回后，在分发当前连接前立即用相同 `SECURITY_ATTRIBUTES`、`reject_remote_clients(true)` 与 `first_pipe_instance(false)` 创建下一个等待实例，可消除高并发 CLI 短连接间的 `ERROR_PIPE_BUSY` 空窗。
3. **Windows CRT 文本模式双重 `\r\r\n` 陷阱（指导 `M5-W1` `formatters.rs` 与 `M5-P4` `exec_host.rs`）**：
   - 实测外部脚本（如 Python）若向默认文本模式的 `sys.stdout` 显式写入 `\r\n`，Windows CRT 会将 `\n` 再次转换为 `\r\n` 从而在管道上产出 `\r\r\n` `[已测]`。单次 `.replace("\r\n", "\n")` 会残留 `\r\n`，生产归一化函数必须循环折叠 `\r+\n -> \n`。
4. **Win32 剪贴板事务原子性与锁争用退避（指导 `M5-W2` `clipboard.rs` / `clip_watch.rs`）**：
   - 写入本机剪贴板时，必须在单次 `OpenClipboard` → `EmptyClipboard` → 先写 `dev.mynote.synced-clip` / 隐私 `DWORD` 标记 → 再写正文/图片 → `CloseClipboard` 事务内完成，确保外部剪贴板管理器在收到 `WM_CLIPBOARDUPDATE` 时不会读到未带标记的中间态。
   - 收到 `WM_CLIPBOARDUPDATE` 后立即调用 `OpenClipboard` 可能与其他剪贴板观察者短暂撞锁（`ERROR_ACCESS_DENIED`），生产实现应保留有限次（如 `10–15` 次 × `5 ms`）退避重试，且 `HWND_MESSAGE` 窗口创建、监听注册与 `GetMessageW` 消息泵必须固定在同一独立 OS 线程上运行。

> **实测诚实边界（F-16）**：本次实测在真实 GitHub Actions `windows-latest`（`Windows Server 2025 Datacenter Build 26100`）内核与 Win32 子系统上完成，完整覆盖 Named Pipe SDDL、Job Object 子进程树回收与 Win32 剪贴板原语；Windows 11 交互式桌面下的 `ShellExecuteW` 默认浏览器拉起、`CONIN$` 终端回显关闭与 Credential Manager / DPAPI 集成将在 `M5-W1..W3` 中验证，待三端 E2EE 闭环后按 `AGENTS.md` §5 规则升级 `ADR-12` 状态。
