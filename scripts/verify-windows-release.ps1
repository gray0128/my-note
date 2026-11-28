#Requires -Version 5.1
<#
.SYNOPSIS
  End-to-end Windows release build, offline CLI JSON smoke, ZIP bundle staging, and daemon deploy verification.

.DESCRIPTION
  Runs on `windows-latest` in CI to verify:
  1. `cargo build --release --locked --bin mynote` builds cleanly and stays strictly `< 15 MiB`;
  2. Offline CLI JSON smoke (`--version`, `add --json`, `ls --json`, `format --json`, `block get --raw`);
  3. Release ZIP staging (`dist/mynote-x86_64-pc-windows-msvc.zip`) + SHA-256 measurement;
  4. End-to-end execution of `deploy/windows/install-daemon-task.ps1` and `uninstall-daemon-task.ps1`
     via real Windows PowerShell 5.1 (`System32\WindowsPowerShell\v1.0\powershell.exe`), covering:
     - Binary resolution precedence (`%LOCALAPPDATA%\Programs\mynote\mynote.exe` wins over extracted `.\mynote.exe`);
     - Spaced + trailing-backslash `-DataDir` handling under Windows PowerShell 5.1;
     - Fresh-install anti-wipe gate (`mynote.db` not prematurely created);
     - Domain/machine-scoped principal (`WindowsIdentity.GetCurrent().Name`);
     - Elevated `ScheduledTask` startup + `Stop-ScheduledTask` killing child `mynote.exe` via `0x2000` Job Object + immediate `Copy-Item -Force` overwrite;
     - Zero-elevation `RegistryRun` mode (`-Mode RegistryRun` + `-StopOnly` upgrade + uninstall);
     - Genuine non-elevated UAC-filtered token (`SaferComputeTokenFromLevel(SAFER_LEVELID_NORMALUSER)` + `CreateProcessWithTokenW`) running default `-Mode Auto` without `0x80070005` failure.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [switch]$SkipBuild,

    [Parameter()]
    [string]$Target = 'x86_64-pc-windows-msvc'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandArgumentPassing = 'Standard'

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
Push-Location -LiteralPath $repoRoot
try {
    if (-not $SkipBuild) {
        Write-Host "[win-verify] 1. Building stripped release binary (cargo build --release --locked --bin mynote)..."
        cargo build --release --locked --bin mynote
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build --release --locked --bin mynote failed ($LASTEXITCODE)"
        }
    }

    $exeItem = Get-Item -LiteralPath 'target/release/mynote.exe'
    $maxBytes = 15 * 1024 * 1024
    $exeMiB = [Math]::Round($exeItem.Length / 1MB, 2)
    Write-Host ("[MEASURED] {0} mynote.exe = {1} bytes ({2:N2} MiB)" -f $Target, $exeItem.Length, $exeMiB)
    if ($exeItem.Length -le 0 -or $exeItem.Length -ge $maxBytes) {
        throw "mynote.exe size $($exeItem.Length) bytes violated < 15 MiB ($maxBytes bytes) budget"
    }

    Write-Host "[win-verify] 2. Running offline CLI JSON smoke check against release binary..."
    $releaseBin = $exeItem.FullName
    $verOut = & $releaseBin --version
    if ($LASTEXITCODE -ne 0) { throw "mynote.exe --version failed ($LASTEXITCODE)" }
    Write-Host "  Version: $verOut"

    $smokeDir = Join-Path ([System.IO.Path]::GetTempPath()) ("mynote-ci-smoke-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $smokeDir -Force | Out-Null
    $prevDataDir = $env:MYNOTE_DATA_DIR
    try {
        $env:MYNOTE_DATA_DIR = $smokeDir
        $addRaw = & $releaseBin add '{"b":1,"a":2}' --buf scratch --lang json --json
        if ($LASTEXITCODE -ne 0) { throw "mynote.exe add failed ($LASTEXITCODE)" }
        $addObj = $addRaw | ConvertFrom-Json
        if (-not $addObj.ok -or $addObj.meta.sync_state -ne 'pending_offline') {
            throw "Unexpected add JSON envelope: $addRaw"
        }
        $blockId = [string]$addObj.data.block_id
        $opId = [string]$addObj.data.op_id

        $lsRaw = & $releaseBin ls --json
        if ($LASTEXITCODE -ne 0) { throw "mynote.exe ls --json failed ($LASTEXITCODE)" }
        $lsObj = $lsRaw | ConvertFrom-Json
        if (-not $lsObj.ok -or @($lsObj.data).Count -ne 1) {
            throw "Unexpected ls JSON envelope: $lsRaw"
        }

        $fmtRaw = & $releaseBin format $blockId --expected-head $opId --json
        if ($LASTEXITCODE -ne 0) { throw "mynote.exe format failed ($LASTEXITCODE)" }
        $fmtObj = $fmtRaw | ConvertFrom-Json
        if (-not $fmtObj.ok) {
            throw "Unexpected format JSON envelope: $fmtRaw"
        }

        $rawText = (& $releaseBin block get $blockId --raw) -join "`n"
        if ($LASTEXITCODE -ne 0) { throw "mynote.exe block get --raw failed ($LASTEXITCODE)" }
        if ($rawText -notmatch '"b":\s*1' -or $rawText -notmatch '"a":\s*2') {
            throw "Unexpected formatted block raw content: $rawText"
        }
    } finally {
        $env:MYNOTE_DATA_DIR = $prevDataDir
        Remove-Item -LiteralPath $smokeDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "[win-verify] 3. Staging release ZIP bundle..."
    $stageDir = "dist/mynote-$Target"
    if (Test-Path -LiteralPath 'dist') {
        Remove-Item -LiteralPath 'dist' -Recurse -Force
    }
    New-Item -ItemType Directory -Path "$stageDir/skill", "$stageDir/deploy/windows", "$stageDir/deploy/ios-shortcuts" -Force | Out-Null
    Copy-Item -LiteralPath 'target/release/mynote.exe' -Destination "$stageDir/mynote.exe" -Force
    Copy-Item -LiteralPath 'skill/SKILL.md' -Destination "$stageDir/skill/SKILL.md" -Force
    Copy-Item -Path 'deploy/windows/*' -Destination "$stageDir/deploy/windows/" -Recurse -Force
    Copy-Item -Path 'deploy/ios-shortcuts/*' -Destination "$stageDir/deploy/ios-shortcuts/" -Recurse -Force
    Copy-Item -LiteralPath 'README.md' -Destination "$stageDir/README.md" -Force
    $zipPath = "dist/mynote-$Target.zip"
    Compress-Archive -Path $stageDir -DestinationPath $zipPath -Force
    $zipItem = Get-Item -LiteralPath $zipPath
    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $zipMiB = [Math]::Round($zipItem.Length / 1MB, 2)
    Write-Host ("[MEASURED] {0} = {1} bytes ({2:N2} MiB) sha256={3}" -f $zipItem.Name, $zipItem.Length, $zipMiB, $zipHash)

    Write-Host "[win-verify] 4. Running end-to-end deploy/windows PowerShell 5.1 lifecycle checks..."
    $winPs51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $winPs51 -PathType Leaf)) {
        throw "Windows PowerShell 5.1 not found at $winPs51"
    }

    function Get-FreeLoopbackPort {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        try {
            return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        } finally {
            $listener.Stop()
        }
    }

    function Quote-WinArg {
        param([string]$Arg)
        if (-not [string]::IsNullOrEmpty($Arg) -and $Arg -notmatch '[\s"]') {
            return $Arg
        }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('"')
        $bs = 0
        foreach ($ch in $Arg.ToCharArray()) {
            if ($ch -eq '\') {
                $bs++
            } elseif ($ch -eq '"') {
                [void]$sb.Append('\', $bs * 2 + 1)
                [void]$sb.Append('"')
                $bs = 0
            } else {
                if ($bs -gt 0) {
                    [void]$sb.Append('\', $bs)
                    $bs = 0
                }
                [void]$sb.Append($ch)
            }
        }
        if ($bs -gt 0) {
            [void]$sb.Append('\', $bs * 2)
        }
        [void]$sb.Append('"')
        return $sb.ToString()
    }

    function Invoke-WinPs51Bounded {
        param(
            [Parameter(Mandatory = $true)][string]$WorkDir,
            [Parameter(Mandatory = $true)][string[]]$ArgsList,
            [Parameter(Mandatory = $true)][string]$SandboxLocalAppData,
            [int]$TimeoutMs = 30000
        )

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $winPs51
        $psi.Arguments = (($ArgsList | ForEach-Object { Quote-WinArg $_ }) -join ' ')
        $psi.WorkingDirectory = $WorkDir
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.EnvironmentVariables['LOCALAPPDATA'] = $SandboxLocalAppData
        $psi.EnvironmentVariables.Remove('MYNOTE_DATA_DIR')

        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutMs)) {
            try { $proc.Kill() } catch {}
            throw "powershell.exe timed out after ${TimeoutMs}ms (possible leaked stdout/stderr pipe)! Args: $($psi.Arguments)"
        }
        if (-not [System.Threading.Tasks.Task]::WaitAll(@($stdoutTask, $stderrTask), 5000)) {
            throw "stdout/stderr pipe stayed open after powershell.exe exited (child process leaked stdio handles)! Args: $($psi.Arguments)"
        }
        return [PSCustomObject]@{
            ExitCode = $proc.ExitCode
            Stdout   = $stdoutTask.Result
            Stderr   = $stderrTask.Result
        }
    }

    function Assert-DaemonHttp401 {
        param([int]$Port)
        for ($i = 0; $i -lt 150; $i++) {
            try {
                $req = [System.Net.HttpWebRequest]::Create("http://localhost:$Port/v1/local/bootstrap")
                $req.Timeout = 1000
                $resp = $req.GetResponse()
                $resp.Close()
                throw "Expected 401 on unauthenticated /v1/local/bootstrap, got 200"
            } catch [System.Net.WebException] {
                $httpResp = $_.Exception.Response -as [System.Net.HttpWebResponse]
                if ($null -ne $httpResp -and [int]$httpResp.StatusCode -eq 401) {
                    $httpResp.Close()
                    return
                }
            }
            Start-Sleep -Milliseconds 100
        }
        throw "Daemon did not respond with HTTP 401 on http://localhost:$Port/v1/local/bootstrap within 15s"
    }

    $e2eRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("mynote-win-e2e-" + [guid]::NewGuid().ToString('N'))
    $extractOuter = Join-Path $e2eRoot 'Temp Extract Dir'
    $sandboxLocal = Join-Path $e2eRoot 'SandboxAppData\Local'
    $suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $task1 = "MyNoteCiTask_$suffix"
    $task2 = "MyNoteCiRun_$suffix"
    $task3 = "MyNoteCiLua_$suffix"

    New-Item -ItemType Directory -Path $extractOuter, $sandboxLocal -Force | Out-Null
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractOuter -Force
    $extractedBundle = Join-Path $extractOuter "mynote-$Target"
    $installScript = Join-Path $extractedBundle 'deploy\windows\install-daemon-task.ps1'
    $uninstallScript = Join-Path $extractedBundle 'deploy\windows\uninstall-daemon-task.ps1'

    $installedDir = Join-Path $sandboxLocal 'Programs\mynote'
    New-Item -ItemType Directory -Path $installedDir -Force | Out-Null
    $installedExe = Join-Path $installedDir 'mynote.exe'
    Copy-Item -LiteralPath $releaseBin -Destination $installedExe -Force

    try {
        # --- 4A: ScheduledTask mode + binary precedence + trailing-backslash spaced DataDir + JobObject stop + overwrite ---
        $port1 = Get-FreeLoopbackPort
        $dataDir1Raw = (Join-Path $e2eRoot 'Jane Doe\mynote data') + '\'
        $dataDir1Clean = $dataDir1Raw.TrimEnd('\')

        $r1 = Invoke-WinPs51Bounded -WorkDir $extractedBundle -SandboxLocalAppData $sandboxLocal -ArgsList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $installScript,
            '-DataDir', $dataDir1Raw, '-Port', "$port1", '-TaskName', $task1
        )
        if ($r1.ExitCode -ne 0) {
            throw "4A fresh install failed ($($r1.ExitCode)): $($r1.Stdout)`n$($r1.Stderr)"
        }

        $meta1 = Get-Content -LiteralPath (Join-Path $sandboxLocal "mynote-task\$task1.json") -Raw | ConvertFrom-Json
        if (-not [string]::Equals([string]$meta1.bin_path, $installedExe, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Binary precedence failed! Expected '$installedExe', got '$($meta1.bin_path)'"
        }
        if ([string]$meta1.data_dir -ne $dataDir1Clean) {
            throw "Trailing-backslash normalization failed! Expected '$dataDir1Clean', got '$($meta1.data_dir)'"
        }

        # Delete temp bundle binary to prove Scheduled Task does not reference the extraction directory
        Remove-Item -LiteralPath (Join-Path $extractedBundle 'mynote.exe') -Force

        $expectedPrincipal = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $expectedSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if ([string]$meta1.principal -ne $expectedPrincipal) {
            throw "Metadata principal mismatch: expected '$expectedPrincipal', got '$($meta1.principal)'"
        }
        $schedTask1 = Get-ScheduledTask -TaskName $task1 -ErrorAction Stop
        $taskUserSid = (New-Object Security.Principal.NTAccount([string]$schedTask1.Principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value
        if ($taskUserSid -ne $expectedSid) {
            throw "ScheduledTask Principal SID mismatch: expected '$expectedSid' ($expectedPrincipal), got '$taskUserSid' ($($schedTask1.Principal.UserId))"
        }
        if ([string]$schedTask1.Principal.RunLevel -ne 'Limited') {
            throw "Expected RunLevel=Limited, got '$($schedTask1.Principal.RunLevel)'"
        }
        if (Test-Path -LiteralPath (Join-Path $dataDir1Clean 'mynote.db')) {
            throw "Fresh-install anti-wipe gate violated: mynote.db was created prematurely!"
        }

        # Initialize DB, start Scheduled Task, verify live HTTP listener and child PID
        & $installedExe --data-dir $dataDir1Clean buf ls --json | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "buf ls init failed ($LASTEXITCODE)" }

        Start-ScheduledTask -TaskName $task1
        Assert-DaemonHttp401 -Port $port1

        $daemonCim1 = @(Get-CimInstance Win32_Process -Filter "Name = 'mynote.exe'" | Where-Object {
            $_.CommandLine -and $_.CommandLine.IndexOf($dataDir1Clean, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
        })
        if ($daemonCim1.Count -ne 1) {
            throw "Expected exactly 1 running mynote.exe daemon for 4A, found $($daemonCim1.Count)"
        }
        $daemonPid1 = [int]$daemonCim1[0].ProcessId

        # Bare Stop-ScheduledTask MUST kill child mynote.exe via 0x2000 Job Object and release .exe lock!
        Stop-ScheduledTask -TaskName $task1
        $dead = $false
        for ($i = 0; $i -lt 50; $i++) {
            if ($null -eq (Get-Process -Id $daemonPid1 -ErrorAction SilentlyContinue)) {
                $dead = $true
                break
            }
            Start-Sleep -Milliseconds 100
        }
        if (-not $dead) {
            throw "ORPHAN LEAK: mynote.exe (PID $daemonPid1) survived Stop-ScheduledTask!"
        }

        # Immediately overwrite $installedExe (proves zero ERROR_SHARING_VIOLATION)
        Copy-Item -LiteralPath $releaseBin -Destination $installedExe -Force

        # Re-run install-daemon-task.ps1 (upgrade restart path) and then full uninstall
        $r1Re = Invoke-WinPs51Bounded -WorkDir $extractedBundle -SandboxLocalAppData $sandboxLocal -ArgsList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $installScript,
            '-DataDir', $dataDir1Raw, '-Port', "$port1", '-TaskName', $task1
        )
        if ($r1Re.ExitCode -ne 0) {
            throw "4A re-install failed ($($r1Re.ExitCode)): $($r1Re.Stdout)`n$($r1Re.Stderr)"
        }
        Assert-DaemonHttp401 -Port $port1

        $r1Un = Invoke-WinPs51Bounded -WorkDir $extractedBundle -SandboxLocalAppData $sandboxLocal -ArgsList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $uninstallScript,
            '-TaskName', $task1
        )
        if ($r1Un.ExitCode -ne 0) {
            throw "4A uninstall failed ($($r1Un.ExitCode)): $($r1Un.Stdout)`n$($r1Un.Stderr)"
        }
        if ($null -ne (Get-ScheduledTask -TaskName $task1 -ErrorAction SilentlyContinue)) {
            throw "4A ScheduledTask '$task1' still exists after uninstall!"
        }
        if (-not (Test-Path -LiteralPath (Join-Path $dataDir1Clean 'mynote.db') -PathType Leaf)) {
            throw "4A uninstall deleted user database mynote.db!"
        }
        Write-Host "  4A PASS: ScheduledTask + JobObject(0x2000) + precedence + trailing-backslash + overwrite"

        # --- 4B: RegistryRun mode + -StopOnly upgrade overwrite + uninstall ---
        $port2 = Get-FreeLoopbackPort
        $dataDir2Raw = (Join-Path $e2eRoot 'Standard User\mynote') + '\'
        $dataDir2Clean = $dataDir2Raw.TrimEnd('\')

        $r2Fresh = Invoke-WinPs51Bounded -WorkDir $extractedBundle -SandboxLocalAppData $sandboxLocal -ArgsList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $installScript,
            '-Mode', 'RegistryRun', '-DataDir', $dataDir2Raw, '-Port', "$port2", '-TaskName', $task2
        )
        if ($r2Fresh.ExitCode -ne 0) {
            throw "4B RegistryRun fresh install failed ($($r2Fresh.ExitCode)): $($r2Fresh.Stdout)`n$($r2Fresh.Stderr)"
        }
        $regVal2 = (Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $task2 -ErrorAction Stop).$task2
        if ([string]::IsNullOrWhiteSpace($regVal2) -or $regVal2.Length -ge 260) {
            throw "4B HKCU Run command invalid or >= 260 chars ($($regVal2.Length)): $regVal2"
        }
        if (Test-Path -LiteralPath (Join-Path $dataDir2Clean 'mynote.db')) {
            throw "4B fresh install prematurely created mynote.db!"
        }

        & $installedExe --data-dir $dataDir2Clean buf ls --json | Out-Null
        $r2Start = Invoke-WinPs51Bounded -WorkDir $extractedBundle -SandboxLocalAppData $sandboxLocal -ArgsList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $installScript,
            '-Mode', 'RegistryRun', '-DataDir', $dataDir2Raw, '-Port', "$port2", '-TaskName', $task2
        )
        if ($r2Start.ExitCode -ne 0) {
            throw "4B RegistryRun start failed ($($r2Start.ExitCode)): $($r2Start.Stdout)`n$($r2Start.Stderr)"
        }
        Assert-DaemonHttp401 -Port $port2

        $r2Stop = Invoke-WinPs51Bounded -WorkDir $extractedBundle -SandboxLocalAppData $sandboxLocal -ArgsList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $uninstallScript,
            '-TaskName', $task2, '-StopOnly'
        )
        if ($r2Stop.ExitCode -ne 0) {
            throw "4B -StopOnly failed ($($r2Stop.ExitCode)): $($r2Stop.Stdout)`n$($r2Stop.Stderr)"
        }
        Copy-Item -LiteralPath $releaseBin -Destination $installedExe -Force
        if ($null -eq (Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $task2 -ErrorAction SilentlyContinue)) {
            throw "4B -StopOnly unexpectedly deleted HKCU Run entry!"
        }

        $r2Un = Invoke-WinPs51Bounded -WorkDir $extractedBundle -SandboxLocalAppData $sandboxLocal -ArgsList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $uninstallScript,
            '-TaskName', $task2
        )
        if ($r2Un.ExitCode -ne 0) {
            throw "4B uninstall failed ($($r2Un.ExitCode)): $($r2Un.Stdout)`n$($r2Un.Stderr)"
        }
        if ($null -ne (Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $task2 -ErrorAction SilentlyContinue)) {
            throw "4B HKCU Run entry still present after uninstall!"
        }
        Write-Host "  4B PASS: RegistryRun + zero pipe hang + -StopOnly binary overwrite + uninstall"

        # --- 4C: Genuine UAC-filtered non-elevated LUA token (`SaferComputeTokenFromLevel` + `ImpersonateLoggedOnUser`) ---
        $port3 = Get-FreeLoopbackPort
        $dataDir3 = Join-Path $e2eRoot 'UnelevatedToken\mynote'
        & $installedExe --data-dir $dataDir3 buf ls --json | Out-Null

        $luaProbeFile = Join-Path $e2eRoot 'lua-probe.ps1'
        $escInstall = $installScript.Replace("'", "''")
        $escUninstall = $uninstallScript.Replace("'", "''")
        $escInstalledExe = $installedExe.Replace("'", "''")
        $escDataDir3 = $dataDir3.Replace("'", "''")

        $luaScriptHeader = @"
param([string]`$Action)
`$ErrorActionPreference = 'Stop'
`$InstallScript = '$escInstall'
`$UninstallScript = '$escUninstall'
`$InstalledExe = '$escInstalledExe'
`$DataDir3 = '$escDataDir3'
`$Port3 = $port3
`$Task3 = '$task3'
"@
        $luaScriptBody = @'
Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class LuaThreadImpersonator
{
    private const uint SAFER_SCOPEID_USER = 2;
    private const uint SAFER_LEVELID_NORMALUSER = 0x20000;
    private const uint SAFER_LEVEL_OPEN = 1;
    private const uint TOKEN_ALL_ACCESS = 0xF01FF;
    private const int SecurityImpersonation = 2;
    private const int TokenImpersonation = 2;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SaferCreateLevel(uint dwScopeId, uint dwLevelId, uint OpenFlags, out IntPtr pLevelHandle, IntPtr lpReserved);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SaferComputeTokenFromLevel(IntPtr LevelHandle, IntPtr InAccessToken, out IntPtr OutAccessToken, uint dwFlags, IntPtr lpReserved);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SaferCloseLevel(IntPtr hLevelHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    public static void EnterNormalUserToken()
    {
        IntPtr hLevel;
        if (!SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN, out hLevel, IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "SaferCreateLevel failed");
        }
        try
        {
            IntPtr hLua;
            if (!SaferComputeTokenFromLevel(hLevel, IntPtr.Zero, out hLua, 0, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SaferComputeTokenFromLevel failed");
            }
            try
            {
                IntPtr hImp;
                if (!DuplicateTokenEx(hLua, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation, TokenImpersonation, out hImp))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx failed");
                }
                try
                {
                    if (!ImpersonateLoggedOnUser(hImp))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "ImpersonateLoggedOnUser failed");
                    }
                }
                finally
                {
                    CloseHandle(hImp);
                }
            }
            finally
            {
                CloseHandle(hLua);
            }
        }
        finally
        {
            SaferCloseLevel(hLevel);
        }
    }
}
"@

[LuaThreadImpersonator]::EnterNormalUserToken()
try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if ($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Expected non-elevated LUA token, but IsInRole(Administrator) was True"
    }
    if ($Action -eq 'install') {
        & $InstallScript -BinPath $InstalledExe -DataDir $DataDir3 -Port $Port3 -TaskName $Task3
    } else {
        & $UninstallScript -TaskName $Task3
    }
} finally {
    [void][LuaThreadImpersonator]::RevertToSelf()
}
'@
        [System.IO.File]::WriteAllText($luaProbeFile, ($luaScriptHeader + "`r`n" + $luaScriptBody), [System.Text.Encoding]::UTF8)

        $r3In = Invoke-WinPs51Bounded -WorkDir $extractedBundle -SandboxLocalAppData $sandboxLocal -ArgsList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $luaProbeFile, 'install'
        )
        if ($r3In.ExitCode -ne 0) {
            throw "4C unelevated LUA token Auto install failed ($($r3In.ExitCode)): $($r3In.Stdout)`n$($r3In.Stderr)"
        }

        $meta3 = Get-Content -LiteralPath (Join-Path $sandboxLocal "mynote-task\$task3.json") -Raw | ConvertFrom-Json
        if ([string]$meta3.registration_mode -ne 'RegistryRun') {
            throw "4C expected unelevated Auto mode to select 'RegistryRun', got '$($meta3.registration_mode)'"
        }
        Assert-DaemonHttp401 -Port $port3

        $r3Un = Invoke-WinPs51Bounded -WorkDir $extractedBundle -SandboxLocalAppData $sandboxLocal -ArgsList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $luaProbeFile, 'uninstall'
        )
        if ($r3Un.ExitCode -ne 0) {
            throw "4C unelevated LUA token uninstall failed ($($r3Un.ExitCode)): $($r3Un.Stdout)`n$($r3Un.Stderr)"
        }
        Write-Host "  4C PASS: Genuine UAC-filtered non-elevated token (-Mode Auto -> RegistryRun) install + start + uninstall"
    } finally {
        foreach ($tn in @($task1, $task2, $task3)) {
            try {
                [void](Invoke-WinPs51Bounded -WorkDir $extractedBundle -SandboxLocalAppData $sandboxLocal -ArgsList @(
                    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $uninstallScript, '-TaskName', $tn
                ))
            } catch {}
            Remove-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $tn -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath 'dist') {
            Remove-Item -LiteralPath 'dist' -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $e2eRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "[win-verify] ALL Windows release & daemon deploy checks PASSED."
} finally {
    Pop-Location
}
