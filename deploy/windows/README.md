# Windows 后台守护与桌面接入说明（`deploy/windows/`）

本目录提供 Windows 10 / 11（`x86_64-pc-windows-msvc`）下无黑框驻留 `mynote.exe daemon` 的当前用户后台自启脚本与运维说明，同时支持**标准未提权终端（零 UAC）**与**管理员提权终端**。

## 运行机制与安全边界

- **标准控制台二进制零侵入**：`mynote.exe` 保持标准控制台子系统（CLI 管道、`--json` 与 `CONIN$` 无回显口令输入正常工作）；后台驻留通过 `%LOCALAPPDATA%\mynote-task\MyNoteDaemon.ps1`（受当前用户专属受保护 NTFS DACL 隔离）调用 `CreateProcessW` + `CREATE_NO_WINDOW`（`bInheritHandles = false`）无窗口拉起 `mynote.exe daemon`，不继承调用方标准输出句柄，无控制台闪现。
- **提权与未提权双模式自适应**：
  - **标准未提权终端（零 UAC，自动回退）**：Windows 10 / 11 任务计划程序（`SchRpcRegisterTask`）拒绝未提权会话注册带 `LogonTrigger`（`AtLogOn`）的任务（返回 `0x80070005`）。在普通标准用户或未提权 PowerShell 终端运行 `install-daemon-task.ps1` 时，脚本自动写入当前用户注册表自启项 `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`（键名 `MyNoteDaemon`），全程无需管理员提权；
  - **管理员提权终端（计划任务 + Job Object 托管）**：在已提权 PowerShell 终端运行时，脚本通过 `[Security.Principal.WindowsIdentity]::GetCurrent().Name` 解析带域或机器作用域的当前用户主体，以最小权限（`RunLevel = Limited`、`LogonType = Interactive`、`ExecutionTimeLimit = 0`、异常退出自动重试 3 次）注册计划任务 `MyNoteDaemon`，并将 `mynote.exe` 绑定至 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`（`0x2000`）Win32 Job Object，保证 `Stop-ScheduledTask` 原子回收子进程并释放 `.exe` 与 `daemon.lock` 句柄；同时自动移除同名 `HKCU Run` 项防止重复自启。
- **二进制解析优先级**：未显式传入 `-BinPath` 时，按 `%LOCALAPPDATA%\Programs\mynote\mynote.exe` → `PATH` → `%USERPROFILE%\.cargo\bin\mynote.exe` → 解压包相对路径 `..\..\mynote.exe` 顺序解析，避免在临时解压目录执行脚本时误绑临时目录中的 `mynote.exe`。
- **本地隔离契约（D9）**：
  - 数据目录默认位于 `%LOCALAPPDATA%\mynote\`（受当前用户专属受保护 NTFS DACL 隔离，脚本自动裁剪非盘符根路径末尾斜杠以兼容 Windows PowerShell 5.1 参数转义）；
  - CLI 与 Daemon 经命名管道 `\\.\pipe\mynote-<blake3_16>` 通信（强制 `first_pipe_instance(true)`、当前用户 SID SDDL `D:P(A;;GA;;;OW)` 与 `reject_remote_clients(true)`，长连接单帧往返 `p50 = 26.0 µs` `[已测]`）；
  - 同步密钥存放在 Windows Credential Manager（DPAPI 回退），桌面入口 `mynote open` 通过 `ShellExecuteW` 打开 `http://localhost:19876`（拒绝非 `localhost` Host）。

## 全新设备安装与启用顺序

> [!IMPORTANT]
> 若 `%LOCALAPPDATA%\mynote\mynote.db` 尚不存在，`install-daemon-task.ps1` 只注册开机自启、**不会创建数据目录或提前启动 `daemon`**，防止在新设备上抢先生成孤立本地密钥环而阻断 `mynote device bootstrap`、`mynote device claim` 或 `mynote restore --from-archive`。

1. 解压 `mynote-x86_64-pc-windows-msvc.zip`，将 `mynote.exe` 放入固定目录 `%LOCALAPPDATA%\Programs\mynote\mynote.exe` 并加入当前用户 `PATH`：

```powershell
New-Item -ItemType Directory -Path "$env:LOCALAPPDATA\Programs\mynote" -Force | Out-Null
Copy-Item .\mynote.exe "$env:LOCALAPPDATA\Programs\mynote\mynote.exe" -Force
```

2. 注册当前用户开机后台自启（标准未提权终端与管理员终端均可直接执行）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy\windows\install-daemon-task.ps1
```

若 `mynote.exe` 安装在其他自定义路径，可通过 `-BinPath` 显式指定：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy\windows\install-daemon-task.ps1 -BinPath "D:\Tools\mynote\mynote.exe"
```

3. 按设备角色完成首次初始化（三选一）：
   - **首台桌面接入云端**：执行 `mynote device bootstrap --url <你的-worker-url>`，离线抄录首次输出的 24 词恢复包；
   - **作为新桌面配对接入**：在已配对桌面执行 `mynote device add --name win-pc --scope read-write`，在本机终端执行 `mynote device claim`；
   - **纯离线本地使用**：执行 `mynote buf ls` 初始化本地数据库。
4. 启动后台守护并打开桌面 UI（再次运行幂等安装脚本即可在任意模式下立即拉起守护并校验 `localhost:19876` 就绪）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy\windows\install-daemon-task.ps1
mynote open
```

可在 Edge 或 Chrome 打开的 `http://localhost:19876` 页面中选择「安装应用」，将其固定到任务栏或绑定系统快捷键。

## 升级、状态核验与卸载

### 升级 `mynote.exe`

Windows 下运行中的 `mynote.exe` 会占用可执行文件句柄。替换二进制前先用 `uninstall-daemon-task.ps1 -StopOnly` 停止当前用户守护并等待句柄释放（提权与未提权模式通用），覆盖 `mynote.exe` 后重新执行 `install-daemon-task.ps1` 即可平滑重启：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy\windows\uninstall-daemon-task.ps1 -StopOnly
Copy-Item .\mynote.exe "$env:LOCALAPPDATA\Programs\mynote\mynote.exe" -Force
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy\windows\install-daemon-task.ps1
mynote --version
mynote sync status --json
```

### 查看运行状态

```powershell
Get-ScheduledTask -TaskName MyNoteDaemon -ErrorAction SilentlyContinue | Select-Object TaskName, State
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name MyNoteDaemon -ErrorAction SilentlyContinue
Get-Process -Name mynote -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, Path
mynote sync status --json
```

### 卸载开机自启

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy\windows\uninstall-daemon-task.ps1
```

卸载脚本幂等停止当前用户 `mynote.exe` 守护进程、移除 `HKCU Run` 自启项或注销 `MyNoteDaemon` 计划任务，不会删除 `%LOCALAPPDATA%\mynote\` 下的本地数据库、自动备份、只读镜像与剪贴板归档，也不会清除 Windows Credential Manager 中的同步凭据。
