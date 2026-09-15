<#
.SYNOPSIS
    Reclaims disk space on a Windows workstation by clearing caches, temp files,
    logs, and other safely removable data.

.DESCRIPTION
    Scans a set of well-known disposable locations, reports how much space each
    holds, and removes them. Runs in report-only mode by default so you can see
    the potential savings before committing to anything.

    Only targets data Windows and common applications regenerate automatically.
    User documents, profiles, and application settings are never touched.

.PARAMETER Execute
    Actually delete files. Without this switch the script only reports what it
    would remove.

.PARAMETER Targets
    Which cleanup targets to process. Defaults to all of them.
    Valid values: WindowsTemp, UserTemp, RecycleBin, BrowserCache, WindowsUpdate,
    Thumbnails, Prefetch, CrashDumps, DeliveryOptimization, IisLogs, OldProfiles

.PARAMETER MinimumAgeDays
    Only remove files older than this many days. Default 7. Prevents deleting
    temp files an application is actively using.

.PARAMETER ProfileAgeDays
    For the OldProfiles target, remove profiles not used in this many days.
    Default 90.

.PARAMETER LogPath
    Directory for the run log. Defaults to the user's Desktop.

.EXAMPLE
    .\Workstation-Cleanup.ps1
    Report-only. Shows how much space each target would free.

.EXAMPLE
    .\Workstation-Cleanup.ps1 -Execute
    Perform the cleanup for all default targets.

.EXAMPLE
    .\Workstation-Cleanup.ps1 -Execute -Targets WindowsTemp,BrowserCache,RecycleBin
    Clean only the selected targets.

.EXAMPLE
    .\Workstation-Cleanup.ps1 -Execute -Targets OldProfiles -ProfileAgeDays 180 -Confirm
    Remove stale user profiles, confirming each one.

.NOTES
    Run as Administrator for system-wide targets. Close browsers before running
    the BrowserCache target or locked files will be skipped.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [switch]$Execute,

    [ValidateSet('WindowsTemp', 'UserTemp', 'RecycleBin', 'BrowserCache', 'WindowsUpdate',
                 'Thumbnails', 'Prefetch', 'CrashDumps', 'DeliveryOptimization',
                 'IisLogs', 'OldProfiles')]
    [string[]]$Targets = @('WindowsTemp', 'UserTemp', 'RecycleBin', 'BrowserCache',
                           'WindowsUpdate', 'Thumbnails', 'CrashDumps',
                           'DeliveryOptimization'),

    [ValidateRange(0, 3650)][int]$MinimumAgeDays = 7,
    [ValidateRange(30, 3650)][int]$ProfileAgeDays = 90,
    [string]$LogPath = [Environment]::GetFolderPath('Desktop')
)

$script:Report = New-Object System.Collections.Generic.List[object]

#region Helpers ---------------------------------------------------------------

function Test-IsAdministrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Format-Size {
    param([double]$Bytes)
    switch ($Bytes) {
        { $_ -ge 1GB } { return '{0:N2} GB' -f ($Bytes / 1GB) }
        { $_ -ge 1MB } { return '{0:N1} MB' -f ($Bytes / 1MB) }
        { $_ -ge 1KB } { return '{0:N0} KB' -f ($Bytes / 1KB) }
        default        { return "$([int]$Bytes) B" }
    }
}

function Get-FreeSpace {
    <# Free bytes on the system drive. #>
    $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
    return [double]$drive.FreeSpace
}

function Test-PathSafe {
    <#
        Test-Path throws UnauthorizedAccessException on protected system paths
        when running unelevated. Treat "cannot see it" as "not present" so the
        target is skipped quietly instead of spraying red text at the operator.
    #>
    param([Parameter(Mandatory)][string]$Path)
    try { return Test-Path -LiteralPath $Path -ErrorAction Stop }
    catch { return $false }
}

function Add-Report {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][double]$Bytes,
        [Parameter(Mandatory)][int]$FileCount,
        [string]$Note = ''
    )
    $script:Report.Add([pscustomobject]@{
        Target    = $Target
        Bytes     = $Bytes
        Size      = Format-Size $Bytes
        FileCount = $FileCount
        Note      = $Note
    })
}

function Clear-PathContent {
    <#
        Deletes files under one or more paths that are older than the age
        threshold. Returns a hashtable with the byte count and file count that
        were (or would be) removed. Locked files are skipped, not fatal.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Path,
        [int]$OlderThanDays = 0,
        [string[]]$ExcludeName = @()
    )

    $cutoff    = (Get-Date).AddDays(-$OlderThanDays)
    $totalSize = 0.0
    $count     = 0
    $skipped   = 0

    foreach ($p in $Path) {
        if (-not (Test-PathSafe $p)) { continue }

        $items = Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue |
                 Where-Object {
                     $_.LastWriteTime -lt $cutoff -and
                     ($ExcludeName.Count -eq 0 -or $_.Name -notin $ExcludeName)
                 }

        foreach ($item in $items) {
            $size = $item.Length
            if ($Execute) {
                try {
                    Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
                    $totalSize += $size
                    $count++
                } catch {
                    # In-use file. Expected and harmless.
                    $skipped++
                }
            } else {
                $totalSize += $size
                $count++
            }
        }

        # Remove directories left empty after the file sweep.
        if ($Execute) {
            Get-ChildItem -LiteralPath $p -Recurse -Force -Directory -ErrorAction SilentlyContinue |
                Sort-Object { $_.FullName.Length } -Descending |
                ForEach-Object {
                    if (-not (Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue)) {
                        Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
        }
    }

    return @{ Bytes = $totalSize; Count = $count; Skipped = $skipped }
}

function Invoke-Target {
    <# Runs a cleanup target under ShouldProcess and records the result. #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    Write-Host "  Scanning $Name..." -ForegroundColor Cyan -NoNewline

    if ($Execute -and -not $PSCmdlet.ShouldProcess($Name, 'Delete cached and temporary files')) {
        Write-Host ' skipped' -ForegroundColor DarkGray
        Add-Report $Name 0 0 'Skipped by user'
        return
    }

    try {
        $result = & $Action
        $note = if ($result.Skipped -gt 0) { "$($result.Skipped) locked file(s) skipped" } else { '' }
        Add-Report $Name $result.Bytes $result.Count $note
        Write-Host (" {0} across {1} file(s)" -f (Format-Size $result.Bytes), $result.Count) -ForegroundColor Green
    } catch {
        Add-Report $Name 0 0 "Error: $($_.Exception.Message)"
        Write-Host ' failed' -ForegroundColor Red
        Write-Warning $_.Exception.Message
    }
}

#endregion

#region Cleanup targets -------------------------------------------------------

function Clear-WindowsTemp {
    Clear-PathContent -Path "$env:SystemRoot\Temp" -OlderThanDays $MinimumAgeDays
}

function Clear-UserTemp {
    # Every loaded profile's temp folder, not just the current user.
    $paths = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
             ForEach-Object { Join-Path $_.FullName 'AppData\Local\Temp' } |
             Where-Object { Test-PathSafe $_ }
    if (-not $paths) { return @{ Bytes = 0; Count = 0; Skipped = 0 } }
    Clear-PathContent -Path $paths -OlderThanDays $MinimumAgeDays
}

function Clear-RecycleBinContent {
    $bytes = 0.0
    $count = 0

    # Measure first so the report is accurate even in execute mode.
    Get-ChildItem "$env:SystemDrive\`$Recycle.Bin" -Recurse -Force -File -ErrorAction SilentlyContinue |
        ForEach-Object { $bytes += $_.Length; $count++ }

    if ($Execute) {
        if (Get-Command Clear-RecycleBin -ErrorAction SilentlyContinue) {
            Clear-RecycleBin -DriveLetter $env:SystemDrive.TrimEnd(':') -Force -ErrorAction SilentlyContinue
        } else {
            Remove-Item "$env:SystemDrive\`$Recycle.Bin\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    return @{ Bytes = $bytes; Count = $count; Skipped = 0 }
}

function Clear-BrowserCache {
    $users = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue
    $paths = foreach ($u in $users) {
        $local = Join-Path $u.FullName 'AppData\Local'

        # Chromium-family browsers share the same cache layout.
        "$local\Google\Chrome\User Data\Default\Cache"
        "$local\Google\Chrome\User Data\Default\Code Cache"
        "$local\Microsoft\Edge\User Data\Default\Cache"
        "$local\Microsoft\Edge\User Data\Default\Code Cache"
        "$local\BraveSoftware\Brave-Browser\User Data\Default\Cache"
        "$local\Microsoft\Windows\INetCache"

        # Firefox: target ONLY the cache2 folder inside each profile. The profile
        # directory itself holds bookmarks, logins, and cookies - never purge it.
        $ffProfiles = Join-Path $local 'Mozilla\Firefox\Profiles'
        if (Test-PathSafe $ffProfiles) {
            Get-ChildItem -LiteralPath $ffProfiles -Directory -ErrorAction SilentlyContinue |
                ForEach-Object { Join-Path $_.FullName 'cache2' }
        }
    }

    $existing = $paths | Where-Object { Test-PathSafe $_ }
    if (-not $existing) { return @{ Bytes = 0; Count = 0; Skipped = 0 } }

    # Age filter of 0 - browser caches regenerate immediately and are safe to purge.
    Clear-PathContent -Path $existing -OlderThanDays 0
}

function Clear-WindowsUpdateCache {
    $path = "$env:SystemRoot\SoftwareDistribution\Download"
    if (-not (Test-PathSafe $path)) { return @{ Bytes = 0; Count = 0; Skipped = 0 } }

    $wasRunning = (Get-Service wuauserv -ErrorAction SilentlyContinue).Status -eq 'Running'
    if ($Execute -and $wasRunning) {
        Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    }

    $result = Clear-PathContent -Path $path -OlderThanDays $MinimumAgeDays

    if ($Execute -and $wasRunning) {
        Start-Service wuauserv -ErrorAction SilentlyContinue
    }
    return $result
}

function Clear-ThumbnailCache {
    $paths = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
             ForEach-Object { Join-Path $_.FullName 'AppData\Local\Microsoft\Windows\Explorer' } |
             Where-Object { Test-PathSafe $_ }
    if (-not $paths) { return @{ Bytes = 0; Count = 0; Skipped = 0 } }

    $bytes = 0.0; $count = 0; $skipped = 0
    foreach ($p in $paths) {
        Get-ChildItem -LiteralPath $p -Filter 'thumbcache_*.db' -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                if ($Execute) {
                    try { $s = $_.Length; Remove-Item $_.FullName -Force -ErrorAction Stop; $bytes += $s; $count++ }
                    catch { $skipped++ }
                } else { $bytes += $_.Length; $count++ }
            }
    }
    return @{ Bytes = $bytes; Count = $count; Skipped = $skipped }
}

function Clear-PrefetchData {
    # Note: clearing prefetch briefly slows app launch until it rebuilds.
    Clear-PathContent -Path "$env:SystemRoot\Prefetch" -OlderThanDays $MinimumAgeDays
}

function Clear-CrashDumps {
    $paths = @("$env:SystemRoot\Minidump", "$env:SystemRoot\LiveKernelReports")
    $paths += Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
              ForEach-Object { Join-Path $_.FullName 'AppData\Local\CrashDumps' }

    $existing = $paths | Where-Object { Test-PathSafe $_ }
    if (-not $existing) { return @{ Bytes = 0; Count = 0; Skipped = 0 } }
    Clear-PathContent -Path $existing -OlderThanDays $MinimumAgeDays
}

function Clear-DeliveryOptimizationCache {
    $path = "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
    if (-not (Test-PathSafe $path)) { return @{ Bytes = 0; Count = 0; Skipped = 0 } }
    Clear-PathContent -Path $path -OlderThanDays 0
}

function Clear-IisLogs {
    $path = "$env:SystemDrive\inetpub\logs\LogFiles"
    if (-not (Test-PathSafe $path)) { return @{ Bytes = 0; Count = 0; Skipped = 0 } }
    # IIS logs are often needed for auditing - use a longer retention window.
    Clear-PathContent -Path $path -OlderThanDays ([Math]::Max($MinimumAgeDays, 30))
}

function Remove-StaleProfiles {
    <#
        Removes local profiles unused for $ProfileAgeDays. Uses the CIM profile
        provider so registry entries are cleaned up too - never delete the
        folder directly.
    #>
    $cutoff = (Get-Date).AddDays(-$ProfileAgeDays)
    $bytes = 0.0; $count = 0; $skipped = 0

    $profiles = Get-CimInstance Win32_UserProfile |
        Where-Object {
            -not $_.Special -and
            -not $_.Loaded -and
            $_.LocalPath -notmatch '\\(Administrator|Public|Default)$' -and
            $_.LastUseTime -and $_.LastUseTime -lt $cutoff
        }

    foreach ($p in $profiles) {
        $size = 0.0
        Get-ChildItem -LiteralPath $p.LocalPath -Recurse -Force -File -ErrorAction SilentlyContinue |
            ForEach-Object { $size += $_.Length }

        if ($Execute) {
            try {
                Remove-CimInstance -InputObject $p -ErrorAction Stop
                $bytes += $size; $count++
            } catch { $skipped++ }
        } else {
            $bytes += $size; $count++
        }
    }
    return @{ Bytes = $bytes; Count = $count; Skipped = $skipped }
}

#endregion

#region Main ------------------------------------------------------------------

Write-Host ''
Write-Host '=== Workstation Cleanup ===' -ForegroundColor Green
Write-Host ''

if (-not (Test-IsAdministrator)) {
    Write-Warning 'Not running as Administrator - system targets will be partially skipped.'
}

if (-not $Execute) {
    Write-Host 'REPORT-ONLY MODE - nothing will be deleted. Add -Execute to apply.' -ForegroundColor Yellow
    Write-Host ''
}

if (-not (Test-Path -LiteralPath $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$freeBefore = Get-FreeSpace
Write-Host ("Free space on {0} before: {1}" -f $env:SystemDrive, (Format-Size $freeBefore))
Write-Host ''

$targetMap = [ordered]@{
    WindowsTemp          = { Clear-WindowsTemp }
    UserTemp             = { Clear-UserTemp }
    RecycleBin           = { Clear-RecycleBinContent }
    BrowserCache         = { Clear-BrowserCache }
    WindowsUpdate        = { Clear-WindowsUpdateCache }
    Thumbnails           = { Clear-ThumbnailCache }
    Prefetch             = { Clear-PrefetchData }
    CrashDumps           = { Clear-CrashDumps }
    DeliveryOptimization = { Clear-DeliveryOptimizationCache }
    IisLogs              = { Clear-IisLogs }
    OldProfiles          = { Remove-StaleProfiles }
}

foreach ($name in $targetMap.Keys) {
    if ($name -notin $Targets) { continue }
    Invoke-Target -Name $name -Action $targetMap[$name]
}

$freeAfter = Get-FreeSpace
$reclaimed = ($script:Report | Measure-Object -Property Bytes -Sum).Sum

Write-Host ''
Write-Host '--- Summary -----------------------------------------------' -ForegroundColor White
$script:Report |
    Sort-Object Bytes -Descending |
    Format-Table -AutoSize @{ L = 'Target'; E = { $_.Target } },
                           @{ L = 'Size';   E = { $_.Size } },
                           @{ L = 'Files';  E = { $_.FileCount } },
                           @{ L = 'Note';   E = { $_.Note } }

Write-Host ''
if ($Execute) {
    Write-Host ("Reclaimed: {0}" -f (Format-Size $reclaimed)) -ForegroundColor Green
    Write-Host ("Free space on {0} after: {1} (delta {2})" -f `
        $env:SystemDrive, (Format-Size $freeAfter), (Format-Size ($freeAfter - $freeBefore)))
} else {
    Write-Host ("Recoverable: {0}" -f (Format-Size $reclaimed)) -ForegroundColor Yellow
    Write-Host 'Re-run with -Execute to reclaim this space.' -ForegroundColor Cyan
}

$logFile = Join-Path $LogPath ("Cleanup_{0}_{1}.csv" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))
$script:Report | Export-Csv -Path $logFile -NoTypeInformation -Encoding UTF8
Write-Host ''
Write-Host "Log saved to: $logFile" -ForegroundColor Green
Write-Host ''

#endregion
