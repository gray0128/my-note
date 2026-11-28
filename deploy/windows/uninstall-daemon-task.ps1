#Requires -Version 5.1
<#
.SYNOPSIS
  Idempotently stop (and optionally unregister) current-user `MyNoteDaemon` Windows autostart.

.DESCRIPTION
  Works in both elevated (Scheduled Task) and standard unelevated (`HKCU\...\Run`) PowerShell shells:
  - Stops Scheduled Task `MyNoteDaemon` if running;
  - Terminates any running current-user `mynote.exe` daemon instance and launcher script matching the
    registered task, `-BinPath`, or `-DataDir`, and waits until file locks (`mynote.exe` and `daemon.lock`)
    are released so binary upgrades (`Copy-Item -Force`) succeed without `ERROR_SHARING_VIOLATION`;
  - Unless `-StopOnly` is specified, removes the `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
    value, unregisters the Scheduled Task, and deletes `%LOCALAPPDATA%\mynote-task\<TaskName>.*`.

  Preserves `%LOCALAPPDATA%\mynote\` (`mynote.db`, `backups\`, `mirror\`, `clip_cache\`) and Windows
  Credential Manager entries untouched.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TaskName = 'MyNoteDaemon',

    [Parameter()]
    [string]$BinPath = '',

    [Parameter()]
    [string]$DataDir = '',

    [Parameter()]
    [switch]$StopOnly
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
            return
        } catch [System.IO.IOException] {
            Start-Sleep -Milliseconds 100
        }
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity.User) {
    throw "Could not resolve current Windows user SID."
}
$currentUserSid = $identity.User.Value

$defaultDataDir = if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    Normalize-WindowsDir -RawPath (Join-Path $env:LOCALAPPDATA 'mynote')
} elseif (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    Normalize-WindowsDir -RawPath (Join-Path $env:USERPROFILE 'AppData\Local\mynote')
} else {
    ''
}

$runnerBase = if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    Normalize-WindowsDir -RawPath (Join-Path $env:LOCALAPPDATA 'mynote-task')
} elseif (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    Normalize-WindowsDir -RawPath (Join-Path $env:USERPROFILE 'AppData\Local\mynote-task')
} else {
    ''
}

$runnerScriptPath = if (-not [string]::IsNullOrWhiteSpace($runnerBase)) { Join-Path $runnerBase "$TaskName.ps1" } else { '' }
$metaPath = if (-not [string]::IsNullOrWhiteSpace($runnerBase)) { Join-Path $runnerBase "$TaskName.json" } else { '' }

$targetBins = New-Object System.Collections.Generic.List[string]
$targetDataDirs = New-Object System.Collections.Generic.List[string]
$targetRunnerScripts = New-Object System.Collections.Generic.List[string]

if (-not [string]::IsNullOrWhiteSpace($runnerScriptPath)) {
    $targetRunnerScripts.Add($runnerScriptPath)
}
if (-not [string]::IsNullOrWhiteSpace($BinPath)) {
    $targetBins.Add([System.IO.Path]::GetFullPath($BinPath))
}
if (-not [string]::IsNullOrWhiteSpace($DataDir)) {
    $targetDataDirs.Add((Normalize-WindowsDir -RawPath $DataDir))
}

if (-not [string]::IsNullOrWhiteSpace($metaPath) -and (Test-Path -LiteralPath $metaPath -PathType Leaf)) {
    try {
        $meta = Get-Content -LiteralPath $metaPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not [string]::IsNullOrWhiteSpace($meta.bin_path)) { $targetBins.Add([string]$meta.bin_path) }
        if (-not [string]::IsNullOrWhiteSpace($meta.data_dir)) { $targetDataDirs.Add((Normalize-WindowsDir -RawPath ([string]$meta.data_dir))) }
        if (-not [string]::IsNullOrWhiteSpace($meta.runner_script)) { $targetRunnerScripts.Add([string]$meta.runner_script) }
    } catch {
    }
}

if ($TaskName -ieq 'MyNoteDaemon' -and $targetBins.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    $targetBins.Add((Join-Path $env:LOCALAPPDATA 'Programs\mynote\mynote.exe'))
}
if ($TaskName -ieq 'MyNoteDaemon' -and $targetDataDirs.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($defaultDataDir)) {
    $targetDataDirs.Add($defaultDataDir)
}

$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $existingTask -and $existingTask.State -eq 'Running') {
    Write-Host "Stopping running Scheduled Task '$TaskName'..."
    try {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    } catch {
    }
    for ($i = 0; $i -lt 30; $i++) {
        $cur = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
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
        foreach ($rs in $targetRunnerScripts) {
            if (-not [string]::IsNullOrWhiteSpace($rs) -and $cmdLine.IndexOf($rs, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $matched = $true
                break
            }
        }
    } elseif ($pName -ieq 'mynote.exe') {
        $isDaemonCmd = ($cmdLine -match '(^|\s|"|'')daemon(\s|$)')
        if ($isDaemonCmd) {
            foreach ($b in $targetBins) {
                if (-not [string]::IsNullOrWhiteSpace($b) -and [string]::Equals($exePath, $b, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $matched = $true
                    break
                }
            }
            if (-not $matched) {
                foreach ($d in $targetDataDirs) {
                    if ([string]::IsNullOrWhiteSpace($d)) {
                        continue
                    }
                    if ($cmdLine.IndexOf($d, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        $matched = $true
                        break
                    }
                    if (-not [string]::IsNullOrWhiteSpace($defaultDataDir) -and [string]::Equals($d, $defaultDataDir, [System.StringComparison]::OrdinalIgnoreCase) -and ($cmdLine -notmatch '--data-dir')) {
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
                $sameOwner = [string]::Equals($ownerInfo.Sid, $currentUserSid, [System.StringComparison]::OrdinalIgnoreCase)
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

foreach ($b in $targetBins) {
    if (-not [string]::IsNullOrWhiteSpace($b)) {
        Wait-ExclusiveFileReady -FilePath $b
    }
}
foreach ($d in $targetDataDirs) {
    if (-not [string]::IsNullOrWhiteSpace($d)) {
        Wait-ExclusiveFileReady -FilePath (Join-Path $d 'daemon.lock')
    }
}

if ($StopOnly) {
    Write-Host "Stopped '$TaskName' daemon instances and verified handle release (autostart registration and local data preserved)."
    exit 0
}

$removedAny = $false
$runRegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (Test-Path -LiteralPath $runRegKey) {
    $existingRunProp = Get-ItemProperty -LiteralPath $runRegKey -Name $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $existingRunProp) {
        Remove-ItemProperty -LiteralPath $runRegKey -Name $TaskName -ErrorAction Stop
        Write-Host "Removed HKCU Run autostart entry '$TaskName'."
        $removedAny = $true
    }
}

foreach ($f in @($runnerScriptPath, $metaPath)) {
    if (-not [string]::IsNullOrWhiteSpace($f) -and (Test-Path -LiteralPath $f -PathType Leaf)) {
        Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
        $removedAny = $true
    }
}
if (-not [string]::IsNullOrWhiteSpace($runnerBase) -and (Test-Path -LiteralPath $runnerBase -PathType Container)) {
    $remaining = @(Get-ChildItem -LiteralPath $runnerBase -Force -ErrorAction SilentlyContinue)
    if ($remaining.Count -eq 0) {
        Remove-Item -LiteralPath $runnerBase -Force -ErrorAction SilentlyContinue
    }
}

$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $existingTask) {
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
        Write-Host "Unregistered Scheduled Task '$TaskName'."
        $removedAny = $true
    } catch {
        try { Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null } catch {}
        throw "Stopped running '$TaskName' daemon and removed runner files, but unregistering Scheduled Task '$TaskName' requires an elevated PowerShell session: $($_.Exception.Message)"
    }
}

if (-not $removedAny) {
    Write-Host "Autostart '$TaskName' is not registered (nothing to remove)."
    exit 0
}

Write-Host "Local data (%LOCALAPPDATA%\mynote) and Windows Credential Manager entries were preserved untouched."
