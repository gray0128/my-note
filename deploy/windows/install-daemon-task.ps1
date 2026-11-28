#Requires -Version 5.1
<#
.SYNOPSIS
  Idempotently register (and conditionally start) current-user Windows autostart for `mynote.exe daemon`.

.DESCRIPTION
  Resolves the current Windows identity principal (`[Security.Principal.WindowsIdentity]::GetCurrent().Name`)
  and supports both elevated and standard unelevated PowerShell sessions:

  - Elevated shell (`Mode = Auto` or `ScheduledTask`):
    Registers Scheduled Task `MyNoteDaemon` under the full domain/machine-scoped current user principal
    with `RunLevel = Limited`, `AtLogOn`, `ExecutionTimeLimit = 0`, and automatic crash restart, while
    binding child `mynote.exe` to a `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (`0x2000`) Win32 Job Object so
    `Stop-ScheduledTask` atomically terminates `mynote.exe` and releases all file/pipe/port handles.
  - Standard unelevated shell (`Mode = Auto` fallback, `Mode = RegistryRun`, or `0x80070005` Access Denied):
    Registers zero-elevation current-user autostart under `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
    (`MyNoteDaemon`) launching `mynote.exe` headless via `CREATE_NO_WINDOW` with zero inherited stdio pipes.

  Anti-wipe onboarding rule:
  If `<DataDir>\mynote.db` (default `%LOCALAPPDATA%\mynote\mynote.db`) does NOT exist yet, this script
  registers autostart WITHOUT creating `<DataDir>` or starting `mynote.exe daemon` immediately so a fresh
  installation never mints an isolated local keyring before `mynote device bootstrap` or `mynote device claim`.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$BinPath = '',

    [Parameter()]
    [string]$DataDir = '',

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$Port = 19876,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TaskName = 'MyNoteDaemon',

    [Parameter()]
    [ValidateSet('Auto', 'ScheduledTask', 'RegistryRun')]
    [string]$Mode = 'Auto',

    [Parameter()]
    [switch]$NoStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($TaskName -notmatch '^[A-Za-z0-9._-]+$') {
    throw "Invalid -TaskName '$TaskName'. Only ASCII letters, digits, '.', '_', and '-' are allowed."
}

function Normalize-WindowsDir {
    param([Parameter(Mandatory = $true)][string]$RawPath)

    $full = [System.IO.Path]::GetFullPath($RawPath)
    $root = [System.IO.Path]::GetPathRoot($full)
    if (-not [string]::IsNullOrEmpty($root) -and $full.Length -gt $root.Length) {
        $full = $full.TrimEnd('\', '/')
    }
    return $full
}

function Resolve-MyNoteBinary {
    param([string]$ExplicitPath)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) {
            throw "mynote binary not found at explicit -BinPath: $ExplicitPath"
        }
        return (Resolve-Path -LiteralPath $ExplicitPath).ProviderPath
    }

    $bundleFallback = $null
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $candFallback = Join-Path $PSScriptRoot '..\..\mynote.exe'
        if (Test-Path -LiteralPath $candFallback -PathType Leaf) {
            $bundleFallback = (Resolve-Path -LiteralPath $candFallback).ProviderPath
        }
    }

    $candidates = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $candidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\mynote\mynote.exe'))
    }

    $cmds = @(Get-Command 'mynote.exe' -CommandType Application -ErrorAction SilentlyContinue)
    foreach ($cmd in $cmds) {
        if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Source)) {
            $srcFull = [System.IO.Path]::GetFullPath($cmd.Source)
            if ($null -eq $bundleFallback -or -not [string]::Equals($srcFull, $bundleFallback, [System.StringComparison]::OrdinalIgnoreCase)) {
                $candidates.Add($srcFull)
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $candidates.Add((Join-Path $env:USERPROFILE '.cargo\bin\mynote.exe'))
    }

    if ($null -ne $bundleFallback) {
        $candidates.Add($bundleFallback)
    }

    foreach ($cand in $candidates) {
        if (Test-Path -LiteralPath $cand -PathType Leaf) {
            $resolved = (Resolve-Path -LiteralPath $cand).ProviderPath
            if ($null -ne $bundleFallback -and [string]::Equals($resolved, $bundleFallback, [System.StringComparison]::OrdinalIgnoreCase)) {
                Write-Warning "Using bundle-relative binary '$resolved'. Copy mynote.exe to '$env:LOCALAPPDATA\Programs\mynote\mynote.exe' before deleting the extracted folder."
            }
            return $resolved
        }
    }

    throw "Could not locate mynote.exe. Copy mynote.exe to %LOCALAPPDATA%\Programs\mynote\mynote.exe, add it to PATH, or pass -BinPath C:\path\to\mynote.exe."
}

function Resolve-MyNoteDataDir {
    param([string]$ExplicitDir)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitDir)) {
        return (Normalize-WindowsDir -RawPath $ExplicitDir)
    }
    if (-not [string]::IsNullOrWhiteSpace($env:MYNOTE_DATA_DIR)) {
        return (Normalize-WindowsDir -RawPath $env:MYNOTE_DATA_DIR)
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        return (Normalize-WindowsDir -RawPath (Join-Path $env:LOCALAPPDATA 'mynote'))
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        return (Normalize-WindowsDir -RawPath (Join-Path $env:USERPROFILE 'AppData\Local\mynote'))
    }
    throw "Could not resolve default data directory (%LOCALAPPDATA% is empty). Pass -DataDir explicitly."
}

function Set-OwnerOnlyAcl {
    param(
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$UserSid,
        [switch]$IsDirectory
    )

    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $adminsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')

    if ($IsDirectory) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $inh = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $prop = [System.Security.AccessControl.PropagationFlags]::None
        foreach ($sid in @($UserSid, $systemSid, $adminsSid)) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inh, $prop, 'Allow')
            $acl.AddAccessRule($rule)
        }
        [System.IO.Directory]::SetAccessControl($TargetPath, $acl)
    } else {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($UserSid, $systemSid, $adminsSid)) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
            $acl.AddAccessRule($rule)
        }
        [System.IO.File]::SetAccessControl($TargetPath, $acl)
    }
}

function Wait-ExclusiveFileReady {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [int]$Attempts = 50
    )

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        return
    }
    for ($i = 0; $i -lt $Attempts; $i++) {
        try {
            $fs = [System.IO.File]::Open(
                $FilePath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None
            )
            $fs.Dispose()
            return
        } catch [System.UnauthorizedAccessException] {
            # Binary may reside in an admin-protected read-only folder (e.g. Program Files) while running unelevated.
            return
        } catch [System.IO.IOException] {
            Start-Sleep -Milliseconds 100
        }
    }
}

function Stop-MyNoteDaemonInstances {
    param(
        [Parameter(Mandatory = $true)][string]$TargetTaskName,
        [Parameter(Mandatory = $true)][string]$CurrentUserSid,
        [Parameter(Mandatory = $true)][string[]]$TargetBins,
        [Parameter(Mandatory = $true)][string[]]$TargetDataDirs,
        [Parameter(Mandatory = $true)][string[]]$TargetRunnerScripts,
        [Parameter(Mandatory = $true)][string]$DefaultDataDir
    )

    $existingTask = Get-ScheduledTask -TaskName $TargetTaskName -ErrorAction SilentlyContinue
    if ($null -ne $existingTask -and $existingTask.State -eq 'Running') {
        try {
            Stop-ScheduledTask -TaskName $TargetTaskName -ErrorAction Stop
        } catch {
            # Unelevated shell may lack Stop rights on an admin-registered task; direct process termination below still succeeds.
        }
        for ($i = 0; $i -lt 30; $i++) {
            $cur = Get-ScheduledTask -TaskName $TargetTaskName -ErrorAction SilentlyContinue
            if ($null -eq $cur -or $cur.State -ne 'Running') {
                break
            }
            Start-Sleep -Milliseconds 100
        }
    }

    $pidsToStop = New-Object System.Collections.Generic.List[int]
    $cimProcs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)
    foreach ($proc in $cimProcs) {
        if ($null -eq $proc -or [int]$proc.ProcessId -eq $PID) {
            continue
        }
        $pName = [string]$proc.Name
        $cmdLine = [string]$proc.CommandLine
        $exePath = [string]$proc.ExecutablePath

        $matched = $false
        if ($pName -ieq 'powershell.exe' -or $pName -ieq 'pwsh.exe') {
            foreach ($rs in $TargetRunnerScripts) {
                if (-not [string]::IsNullOrWhiteSpace($rs) -and $cmdLine.IndexOf($rs, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $matched = $true
                    break
                }
            }
        } elseif ($pName -ieq 'mynote.exe') {
            $isDaemonCmd = ($cmdLine -match '(^|\s|"|'')daemon(\s|$)')
            if ($isDaemonCmd) {
                foreach ($b in $TargetBins) {
                    if (-not [string]::IsNullOrWhiteSpace($b) -and [string]::Equals($exePath, $b, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $matched = $true
                        break
                    }
                }
                if (-not $matched) {
                    foreach ($d in $TargetDataDirs) {
                        if ([string]::IsNullOrWhiteSpace($d)) {
                            continue
                        }
                        if ($cmdLine.IndexOf($d, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $matched = $true
                            break
                        }
                        if ([string]::Equals($d, $DefaultDataDir, [System.StringComparison]::OrdinalIgnoreCase) -and ($cmdLine -notmatch '--data-dir')) {
                            $matched = $true
                            break
                        }
                    }
                }
            }
        }

        if ($matched) {
            $sameOwner = $true
            try {
                $ownerInfo = Invoke-CimMethod -InputObject $proc -MethodName GetOwnerSid -ErrorAction Stop
                if ($null -ne $ownerInfo -and $ownerInfo.ReturnValue -eq 0 -and -not [string]::IsNullOrWhiteSpace($ownerInfo.Sid)) {
                    $sameOwner = [string]::Equals($ownerInfo.Sid, $CurrentUserSid, [System.StringComparison]::OrdinalIgnoreCase)
                }
            } catch {
                $sameOwner = $true
            }
            if ($sameOwner) {
                $pidsToStop.Add([int]$proc.ProcessId)
            }
        }
    }

    foreach ($targetPid in $pidsToStop) {
        try {
            $osProc = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
            if ($null -ne $osProc) {
                Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
                [void]$osProc.WaitForExit(5000)
            }
        } catch {
        }
    }

    foreach ($b in $TargetBins) {
        if (-not [string]::IsNullOrWhiteSpace($b)) {
            Wait-ExclusiveFileReady -FilePath $b
        }
    }
    foreach ($d in $TargetDataDirs) {
        if (-not [string]::IsNullOrWhiteSpace($d)) {
            Wait-ExclusiveFileReady -FilePath (Join-Path $d 'daemon.lock')
        }
    }
}

function Wait-DaemonLoopbackReady {
    param(
        [Parameter(Mandatory = $true)][int]$TargetPort,
        [int]$TimeoutMs = 12000
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $client.BeginConnect([System.Net.IPAddress]::Loopback, $TargetPort, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(150) -and $client.Connected) {
                $client.EndConnect($iar)
                return $true
            }
        } catch {
        } finally {
            $client.Close()
        }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

$resolvedBin = Resolve-MyNoteBinary -ExplicitPath $BinPath
$ext = [System.IO.Path]::GetExtension($resolvedBin)
if ($ext -ine '.exe') {
    throw "Refusing non-.exe daemon target '$resolvedBin' (batch scripts are forbidden per AGENTS.md §3.3)."
}

$resolvedDataDir = Resolve-MyNoteDataDir -ExplicitDir $DataDir
$defaultDataDir = Resolve-MyNoteDataDir -ExplicitDir ''
$dbPath = Join-Path $resolvedDataDir 'mynote.db'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = $identity.Name
$currentUserSidObj = $identity.User
if ([string]::IsNullOrWhiteSpace($currentPrincipal) -or $null -eq $currentUserSidObj) {
    throw "Could not resolve current Windows principal via WindowsIdentity.GetCurrent()."
}
$currentUserSid = $currentUserSidObj.Value
$winPrincipal = New-Object Security.Principal.WindowsPrincipal($identity)
$isElevated = $winPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$runnerBase = if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    Normalize-WindowsDir -RawPath (Join-Path $env:LOCALAPPDATA 'mynote-task')
} elseif (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    Normalize-WindowsDir -RawPath (Join-Path $env:USERPROFILE 'AppData\Local\mynote-task')
} else {
    throw "Could not resolve %LOCALAPPDATA% or %USERPROFILE% for daemon launcher directory."
}

$runnerScriptPath = Join-Path $runnerBase "$TaskName.ps1"
$metaPath = Join-Path $runnerBase "$TaskName.json"

$targetBins = New-Object System.Collections.Generic.List[string]
$targetDataDirs = New-Object System.Collections.Generic.List[string]
$targetRunnerScripts = New-Object System.Collections.Generic.List[string]
$targetBins.Add($resolvedBin)
$targetDataDirs.Add($resolvedDataDir)
$targetRunnerScripts.Add($runnerScriptPath)

if (Test-Path -LiteralPath $metaPath -PathType Leaf) {
    try {
        $prevMeta = Get-Content -LiteralPath $metaPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not [string]::IsNullOrWhiteSpace($prevMeta.bin_path)) { $targetBins.Add([string]$prevMeta.bin_path) }
        if (-not [string]::IsNullOrWhiteSpace($prevMeta.data_dir)) { $targetDataDirs.Add((Normalize-WindowsDir -RawPath ([string]$prevMeta.data_dir))) }
        if (-not [string]::IsNullOrWhiteSpace($prevMeta.runner_script)) { $targetRunnerScripts.Add([string]$prevMeta.runner_script) }
    } catch {
    }
}

Stop-MyNoteDaemonInstances `
    -TargetTaskName $TaskName `
    -CurrentUserSid $currentUserSid `
    -TargetBins $targetBins.ToArray() `
    -TargetDataDirs $targetDataDirs.ToArray() `
    -TargetRunnerScripts $targetRunnerScripts.ToArray() `
    -DefaultDataDir $defaultDataDir

if (-not (Test-Path -LiteralPath $runnerBase -PathType Container)) {
    New-Item -ItemType Directory -Path $runnerBase -Force | Out-Null
}
Set-OwnerOnlyAcl -TargetPath $runnerBase -UserSid $currentUserSidObj -IsDirectory

$escapedBin = $resolvedBin.Replace("'", "''")
$escapedDataDir = $resolvedDataDir.Replace("'", "''")
$escapedDbPath = $dbPath.Replace("'", "''")

$runnerHeader = @"
#Requires -Version 5.1
param(
    [switch]`$Detach
)
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'

`$BinPath = '$escapedBin'
`$DataDir = '$escapedDataDir'
`$DbPath = '$escapedDbPath'
`$Port = $Port
"@

$runnerBody = @'

if (-not (Test-Path -LiteralPath $DbPath -PathType Leaf)) {
    exit 0
}
if ([string]::IsNullOrWhiteSpace($env:RUST_LOG)) {
    $env:RUST_LOG = 'info'
}

if (-not ('MyNoteDaemonNativeHost' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class MyNoteDaemonNativeHost
{
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint HANDLE_FLAG_INHERIT = 0x00000001;
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint INFINITE = 0xFFFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOW
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr hJob,
        int infoType,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInfo,
        int cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(
        string lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFOW lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    public static string QuoteArg(string arg)
    {
        if (!string.IsNullOrEmpty(arg))
        {
            bool needsQuotes = false;
            for (int i = 0; i < arg.Length; i++)
            {
                char c = arg[i];
                if (c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '"')
                {
                    needsQuotes = true;
                    break;
                }
            }
            if (!needsQuotes)
            {
                return arg;
            }
        }
        StringBuilder sb = new StringBuilder(arg.Length + 2);
        sb.Append('"');
        int backslashes = 0;
        for (int i = 0; i < arg.Length; i++)
        {
            char c = arg[i];
            if (c == '\\')
            {
                backslashes++;
            }
            else if (c == '"')
            {
                sb.Append('\\', backslashes * 2 + 1);
                sb.Append('"');
                backslashes = 0;
            }
            else
            {
                if (backslashes > 0)
                {
                    sb.Append('\\', backslashes);
                    backslashes = 0;
                }
                sb.Append(c);
            }
        }
        if (backslashes > 0)
        {
            sb.Append('\\', backslashes * 2);
        }
        sb.Append('"');
        return sb.ToString();
    }

    private static StringBuilder BuildDaemonCommandLine(string binPath, string dataDir, int port)
    {
        string line = QuoteArg(binPath)
            + " --data-dir " + QuoteArg(dataDir)
            + " daemon --port " + port.ToString();
        return new StringBuilder(line);
    }

    public static int StartDetached(string binPath, string dataDir, int port, string workDir)
    {
        STARTUPINFOW si = new STARTUPINFOW();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFOW));
        PROCESS_INFORMATION pi;
        StringBuilder cmdLine = BuildDaemonCommandLine(binPath, dataDir, port);
        bool ok = CreateProcessW(
            binPath,
            cmdLine,
            IntPtr.Zero,
            IntPtr.Zero,
            false,
            CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
            IntPtr.Zero,
            workDir,
            ref si,
            out pi);
        if (!ok)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW(StartDetached) failed");
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return (int)pi.dwProcessId;
    }

    public static int RunJobBound(string binPath, string dataDir, int port, string workDir)
    {
        IntPtr hJob = CreateJobObjectW(IntPtr.Zero, null);
        if (hJob == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObjectW failed");
        }
        try
        {
            SetHandleInformation(hJob, HANDLE_FLAG_INHERIT, 0);
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!SetInformationJobObject(
                hJob,
                JobObjectExtendedLimitInformation,
                ref info,
                Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetInformationJobObject(0x2000) failed");
            }

            STARTUPINFOW si = new STARTUPINFOW();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFOW));
            PROCESS_INFORMATION pi;
            StringBuilder cmdLine = BuildDaemonCommandLine(binPath, dataDir, port);
            bool created = CreateProcessW(
                binPath,
                cmdLine,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATE_NO_WINDOW | CREATE_SUSPENDED,
                IntPtr.Zero,
                workDir,
                ref si,
                out pi);
            if (!created)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW(RunJobBound) failed");
            }

            try
            {
                if (!AssignProcessToJobObject(hJob, pi.hProcess))
                {
                    int assignErr = Marshal.GetLastWin32Error();
                    TerminateProcess(pi.hProcess, 1);
                    throw new Win32Exception(assignErr, "AssignProcessToJobObject failed");
                }
                uint prevCount = ResumeThread(pi.hThread);
                if (prevCount == uint.MaxValue)
                {
                    int resumeErr = Marshal.GetLastWin32Error();
                    TerminateProcess(pi.hProcess, 1);
                    throw new Win32Exception(resumeErr, "ResumeThread failed");
                }
            }
            finally
            {
                CloseHandle(pi.hThread);
            }

            try
            {
                WaitForSingleObject(pi.hProcess, INFINITE);
                uint exitCode = 0;
                if (!GetExitCodeProcess(pi.hProcess, out exitCode))
                {
                    return 1;
                }
                return (int)exitCode;
            }
            finally
            {
                CloseHandle(pi.hProcess);
            }
        }
        finally
        {
            CloseHandle(hJob);
        }
    }
}
"@
}

$workDir = Split-Path -Parent $BinPath
if ($Detach) {
    [void][MyNoteDaemonNativeHost]::StartDetached($BinPath, $DataDir, $Port, $workDir)
    exit 0
}
$rc = [MyNoteDaemonNativeHost]::RunJobBound($BinPath, $DataDir, $Port, $workDir)
exit $rc
'@

[System.IO.File]::WriteAllText($runnerScriptPath, ($runnerHeader + "`r`n" + $runnerBody), [System.Text.Encoding]::UTF8)
Set-OwnerOnlyAcl -TargetPath $runnerScriptPath -UserSid $currentUserSidObj

$systemPwsh = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $systemPwsh -PathType Leaf)) {
    $systemPwsh = 'powershell.exe'
}

$runRegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$workDir = Split-Path -Parent $resolvedBin
$effectiveMode = $null

$tryScheduledTask = ($Mode -eq 'ScheduledTask') -or ($Mode -eq 'Auto' -and $isElevated)
if ($tryScheduledTask) {
    $taskArgs = "-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$runnerScriptPath`""
    $action = New-ScheduledTaskAction -Execute $systemPwsh -Argument $taskArgs -WorkingDirectory $workDir
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentPrincipal
    $principal = New-ScheduledTaskPrincipal -UserId $currentPrincipal -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -Hidden

    try {
        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Description 'my-note local daemon (single-writer SQLite + localhost UI + E2EE cloud sync)' `
            -Force | Out-Null
        $effectiveMode = 'ScheduledTask'
    } catch {
        $errMsg = $_.Exception.ToString()
        $hr = $_.Exception.HResult
        $isAccessDenied = ($hr -eq -2147024891) -or ($errMsg -match '0x80070005|Access is denied|UnauthorizedAccessException')
        if ($Mode -eq 'Auto' -and $isAccessDenied) {
            Write-Host "Task Scheduler registration denied without elevation (0x80070005); falling back to current-user HKCU Run autostart."
        } else {
            throw
        }
    }
}

if ($effectiveMode -eq 'ScheduledTask') {
    if (Test-Path -LiteralPath $runRegKey) {
        Remove-ItemProperty -LiteralPath $runRegKey -Name $TaskName -ErrorAction SilentlyContinue
    }
    Write-Host "Registered Scheduled Task '$TaskName' for '$currentPrincipal' (RunLevel=Limited, AtLogOn, JobObject=0x2000)."
} else {
    $effectiveMode = 'RegistryRun'
    if (-not (Test-Path -LiteralPath $runRegKey)) {
        New-Item -Path $runRegKey -Force | Out-Null
    }
    $runValue = "`"$systemPwsh`" -nop -noni -w Hidden -ep Bypass -File `"$runnerScriptPath`" -Detach"
    Set-ItemProperty -LiteralPath $runRegKey -Name $TaskName -Value $runValue -Type String

    $staleTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $staleTask) {
        try {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
        } catch {
            try { Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
    }
    Write-Host "Registered zero-elevation current-user autostart 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\$TaskName' for '$currentPrincipal'."
}

$metaJson = [ordered]@{
    task_name         = $TaskName
    registration_mode = $effectiveMode
    principal         = $currentPrincipal
    bin_path          = $resolvedBin
    data_dir          = $resolvedDataDir
    port              = $Port
    runner_script     = $runnerScriptPath
} | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText($metaPath, $metaJson, [System.Text.Encoding]::UTF8)
Set-OwnerOnlyAcl -TargetPath $metaPath -UserSid $currentUserSidObj

Write-Host "  Mode:     $effectiveMode"
Write-Host "  Binary:   $resolvedBin"
Write-Host "  DataDir:  $resolvedDataDir"
Write-Host "  UI URL:   http://localhost:$Port"

$scriptDisplayPath = if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) { $PSCommandPath } else { '.\deploy\windows\install-daemon-task.ps1' }

if (-not (Test-Path -LiteralPath $dbPath -PathType Leaf)) {
    Write-Host ""
    Write-Host "Notice: '$dbPath' does not exist yet."
    Write-Host "Skipped starting '$TaskName' so fresh onboarding does not create an isolated local database before pairing or bootstrap."
    Write-Host "Next steps:"
    Write-Host "  1a. First desktop cloud setup:  mynote device bootstrap --url <your-worker-url>"
    Write-Host "  1b. Pair as second desktop:     mynote device claim"
    Write-Host "  1c. Pure offline local setup:   mynote buf ls"
    Write-Host "  2.  Start background daemon:    powershell -NoProfile -ExecutionPolicy Bypass -File `"$scriptDisplayPath`""
    Write-Host "  3.  Open desktop Web UI:        mynote open"
    exit 0
}

if ($NoStart) {
    Write-Host "Database exists at '$dbPath'; skipped immediate start because -NoStart was specified."
    exit 0
}

if ($effectiveMode -eq 'ScheduledTask') {
    Start-ScheduledTask -TaskName $TaskName
} else {
    & $systemPwsh -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File $runnerScriptPath -Detach
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to launch '$TaskName' background daemon (exit code $LASTEXITCODE)."
    }
}

if (-not (Wait-DaemonLoopbackReady -TargetPort $Port -TimeoutMs 12000)) {
    throw "Started '$TaskName' ($effectiveMode), but localhost:$Port did not become ready within 12s."
}

Write-Host "Started '$TaskName' ($effectiveMode) on http://localhost:$Port. Run 'mynote open' to launch the desktop UI."
