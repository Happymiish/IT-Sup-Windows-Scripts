<#
.SYNOPSIS
    Performs a comprehensive Windows system health check and generates an HTML report.

.DESCRIPTION
    Collects CPU, memory, disk, network, service, event log, and update information,
    evaluates each area against configurable thresholds, and writes a colour-coded
    HTML report suitable for attaching to a support ticket.

.PARAMETER OutputPath
    Directory where the HTML report is written. Defaults to the user's Desktop.

.PARAMETER DiskWarningPercent
    Disk used-percentage that triggers a Warning. Default 80.

.PARAMETER DiskCriticalPercent
    Disk used-percentage that triggers a Critical finding. Default 90.

.PARAMETER MemoryWarningPercent
    Memory used-percentage that triggers a Warning. Default 80.

.PARAMETER EventLogHours
    How many hours of event log history to scan. Default 24.

.PARAMETER SkipNetworkTests
    Skip outbound connectivity and DNS tests (useful on isolated networks).

.EXAMPLE
    .\System-Health-Check.ps1

.EXAMPLE
    .\System-Health-Check.ps1 -OutputPath "C:\Reports" -DiskCriticalPercent 95

.NOTES
    Requires PowerShell 3.0+. Run as Administrator for full results.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = [Environment]::GetFolderPath('Desktop'),
    [ValidateRange(1, 99)][int]$DiskWarningPercent = 80,
    [ValidateRange(1, 99)][int]$DiskCriticalPercent = 90,
    [ValidateRange(1, 99)][int]$MemoryWarningPercent = 80,
    [ValidateRange(1, 720)][int]$EventLogHours = 24,
    [switch]$SkipNetworkTests
)

$ErrorActionPreference = 'Stop'
$script:Findings = New-Object System.Collections.Generic.List[object]

#region Helpers ---------------------------------------------------------------

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Item,
        [Parameter(Mandatory)][ValidateSet('OK', 'Warning', 'Critical', 'Info')][string]$Status,
        [string]$Detail = ''
    )
    $script:Findings.Add([pscustomobject]@{
        Category = $Category
        Item     = $Item
        Status   = $Status
        Detail   = $Detail
    })
}

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Test-IsAdministrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CimOrWmi {
    param([Parameter(Mandatory)][string]$ClassName)
    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        Get-CimInstance -ClassName $ClassName
    } else {
        Get-WmiObject -Class $ClassName
    }
}

#endregion

#region Collection ------------------------------------------------------------

function Get-SystemSummary {
    Write-Step 'Collecting system information'
    $os  = Get-CimOrWmi Win32_OperatingSystem
    $cs  = Get-CimOrWmi Win32_ComputerSystem
    $bios = Get-CimOrWmi Win32_BIOS

    $lastBoot = if ($os.LastBootUpTime -is [datetime]) {
        $os.LastBootUpTime
    } else {
        [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
    }
    $uptime = (Get-Date) - $lastBoot

    Add-Finding 'System' 'Computer name'    'Info' $env:COMPUTERNAME
    Add-Finding 'System' 'Operating system' 'Info' "$($os.Caption) ($($os.Version))"
    Add-Finding 'System' 'Manufacturer'     'Info' "$($cs.Manufacturer) $($cs.Model)"
    Add-Finding 'System' 'Serial number'    'Info' $bios.SerialNumber
    Add-Finding 'System' 'Logged-on user'   'Info' $cs.UserName

    $uptimeText = '{0}d {1}h {2}m' -f $uptime.Days, $uptime.Hours, $uptime.Minutes
    if ($uptime.TotalDays -gt 30) {
        Add-Finding 'System' 'Uptime' 'Warning' "$uptimeText - a reboot is overdue"
    } else {
        Add-Finding 'System' 'Uptime' 'OK' $uptimeText
    }
}

function Get-CpuHealth {
    Write-Step 'Sampling CPU load'
    $cpu = Get-CimOrWmi Win32_Processor | Select-Object -First 1
    Add-Finding 'CPU' 'Processor' 'Info' "$($cpu.Name.Trim()) ($($cpu.NumberOfCores) cores / $($cpu.NumberOfLogicalProcessors) threads)"

    # Average three one-second samples for a more stable reading.
    $samples = 1..3 | ForEach-Object {
        (Get-CimOrWmi Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        Start-Sleep -Seconds 1
    }
    $load = [math]::Round(($samples | Measure-Object -Average).Average, 1)

    $status = if ($load -ge 90) { 'Critical' } elseif ($load -ge 75) { 'Warning' } else { 'OK' }
    Add-Finding 'CPU' 'Average load' $status "$load% across 3 samples"
}

function Get-MemoryHealth {
    Write-Step 'Checking memory usage'
    $os = Get-CimOrWmi Win32_OperatingSystem
    $totalGb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeGb  = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    $usedPct = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 1)

    $status = if ($usedPct -ge 90) { 'Critical' } elseif ($usedPct -ge $MemoryWarningPercent) { 'Warning' } else { 'OK' }
    Add-Finding 'Memory' 'Physical memory' $status "$usedPct% used - $freeGb GB free of $totalGb GB"
}

function Get-DiskHealth {
    Write-Step 'Inspecting disk volumes'
    Get-CimOrWmi Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 -and $_.Size -gt 0 } | ForEach-Object {
        $totalGb = [math]::Round($_.Size / 1GB, 2)
        $freeGb  = [math]::Round($_.FreeSpace / 1GB, 2)
        $usedPct = [math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 1)

        $status = if ($usedPct -ge $DiskCriticalPercent) { 'Critical' }
                  elseif ($usedPct -ge $DiskWarningPercent) { 'Warning' }
                  else { 'OK' }
        Add-Finding 'Disk' "Volume $($_.DeviceID)" $status "$usedPct% used - $freeGb GB free of $totalGb GB"
    }

    # SMART predictive failure, when the provider is available.
    try {
        Get-CimOrWmi Win32_DiskDrive | ForEach-Object {
            $status = if ($_.Status -eq 'OK') { 'OK' } else { 'Critical' }
            Add-Finding 'Disk' "Drive $($_.Model)" $status "SMART status: $($_.Status)"
        }
    } catch {
        Add-Finding 'Disk' 'SMART status' 'Info' 'Not available on this system'
    }
}

function Get-NetworkHealth {
    if ($SkipNetworkTests) {
        Add-Finding 'Network' 'Connectivity tests' 'Info' 'Skipped by -SkipNetworkTests'
        return
    }

    Write-Step 'Running network diagnostics'
    Get-CimOrWmi Win32_NetworkAdapterConfiguration |
        Where-Object { $_.IPEnabled } |
        ForEach-Object {
            $ip = ($_.IPAddress | Where-Object { $_ -notmatch ':' }) -join ', '
            Add-Finding 'Network' $_.Description 'Info' "IP: $ip | Gateway: $($_.DefaultIPGateway -join ', ')"
        }

    foreach ($target in '8.8.8.8', '1.1.1.1') {
        try {
            $ok = Test-Connection -ComputerName $target -Count 2 -Quiet -ErrorAction Stop
            if ($ok) {
                Add-Finding 'Network' "Ping $target" 'OK' 'Reachable'
            } else {
                Add-Finding 'Network' "Ping $target" 'Warning' 'No reply'
            }
        } catch {
            Add-Finding 'Network' "Ping $target" 'Warning' $_.Exception.Message
        }
    }

    try {
        $null = [Net.Dns]::GetHostEntry('www.microsoft.com')
        Add-Finding 'Network' 'DNS resolution' 'OK' 'www.microsoft.com resolved'
    } catch {
        Add-Finding 'Network' 'DNS resolution' 'Critical' 'Unable to resolve www.microsoft.com'
    }
}

function Get-ServiceHealth {
    Write-Step 'Verifying critical services'
    $critical = @{
        'wuauserv' = 'Windows Update'
        'WinDefend' = 'Microsoft Defender Antivirus'
        'MpsSvc'   = 'Windows Firewall'
        'BITS'     = 'Background Intelligent Transfer'
        'Dnscache' = 'DNS Client'
        'LanmanWorkstation' = 'Workstation'
        'EventLog' = 'Windows Event Log'
    }

    foreach ($name in $critical.Keys) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) {
            Add-Finding 'Services' $critical[$name] 'Info' 'Not installed on this system'
            continue
        }
        if ($svc.Status -eq 'Running') {
            Add-Finding 'Services' $critical[$name] 'OK' 'Running'
        } else {
            Add-Finding 'Services' $critical[$name] 'Warning' "Status: $($svc.Status)"
        }
    }

    $autoStopped = Get-CimOrWmi Win32_Service |
        Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' }
    if ($autoStopped) {
        $names = ($autoStopped | Select-Object -First 10 -ExpandProperty DisplayName) -join '; '
        Add-Finding 'Services' 'Automatic services not running' 'Warning' "$($autoStopped.Count) found: $names"
    } else {
        Add-Finding 'Services' 'Automatic services not running' 'OK' 'All automatic services are running'
    }
}

function Get-EventLogHealth {
    Write-Step "Scanning event logs (last $EventLogHours hours)"
    $since = (Get-Date).AddHours(-$EventLogHours)

    foreach ($log in 'System', 'Application') {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $log
                Level     = 1, 2   # Critical, Error
                StartTime = $since
            } -ErrorAction Stop
        } catch {
            Add-Finding 'Event Log' "$log log" 'OK' "No errors in the last $EventLogHours hours"
            continue
        }

        $status = if ($events.Count -gt 50) { 'Critical' } elseif ($events.Count -gt 10) { 'Warning' } else { 'OK' }
        $top = $events | Group-Object ProviderName |
            Sort-Object Count -Descending | Select-Object -First 3 |
            ForEach-Object { "$($_.Name) ($($_.Count))" }
        Add-Finding 'Event Log' "$log errors" $status "$($events.Count) entries. Top sources: $($top -join '; ')"
    }
}

function Get-UpdateHealth {
    Write-Step 'Reviewing installed updates'
    try {
        $hotfixes = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending
        $latest = $hotfixes | Select-Object -First 1
        if ($latest -and $latest.InstalledOn) {
            $age = (Get-Date) - $latest.InstalledOn
            $status = if ($age.TotalDays -gt 60) { 'Warning' } else { 'OK' }
            Add-Finding 'Updates' 'Most recent hotfix' $status "$($latest.HotFixID) installed $([math]::Round($age.TotalDays)) days ago"
        }
        Add-Finding 'Updates' 'Total hotfixes installed' 'Info' "$($hotfixes.Count)"
    } catch {
        Add-Finding 'Updates' 'Hotfix history' 'Warning' 'Unable to query update history'
    }
}

function Get-TopProcesses {
    Write-Step 'Identifying resource-heavy processes'
    $byCpu = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
    foreach ($p in $byCpu) {
        if ($null -eq $p.CPU) { continue }
        Add-Finding 'Processes' "$($p.ProcessName) (PID $($p.Id))" 'Info' `
            ("CPU time {0:N1}s | Working set {1:N0} MB" -f $p.CPU, ($p.WorkingSet64 / 1MB))
    }
}

#endregion

#region Reporting -------------------------------------------------------------

function ConvertTo-HtmlReport {
    param([Parameter(Mandatory)][System.Collections.Generic.List[object]]$Findings)

    $counts = @{
        Critical = ($Findings | Where-Object Status -eq 'Critical').Count
        Warning  = ($Findings | Where-Object Status -eq 'Warning').Count
        OK       = ($Findings | Where-Object Status -eq 'OK').Count
    }

    $overall = if ($counts.Critical -gt 0) { 'Critical issues found' }
               elseif ($counts.Warning -gt 0) { 'Warnings found' }
               else { 'System healthy' }

    $rows = foreach ($f in $Findings) {
        $class = $f.Status.ToLower()
        $detail = [System.Web.HttpUtility]::HtmlEncode($f.Detail)
        if (-not $detail) { $detail = '' }
        @"
      <tr class="$class">
        <td>$([System.Web.HttpUtility]::HtmlEncode($f.Category))</td>
        <td>$([System.Web.HttpUtility]::HtmlEncode($f.Item))</td>
        <td><span class="badge $class">$($f.Status)</span></td>
        <td>$detail</td>
      </tr>
"@
    }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>System Health Report - $env:COMPUTERNAME</title>
<style>
  body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 2rem; background: #f5f6f8; color: #1b1f23; }
  h1 { margin-bottom: 0.25rem; }
  .meta { color: #586069; margin-bottom: 1.5rem; }
  .summary { display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
  .card { background: #fff; border-radius: 8px; padding: 1rem 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); min-width: 120px; }
  .card .n { font-size: 2rem; font-weight: 600; display: block; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
  th, td { text-align: left; padding: .6rem .9rem; border-bottom: 1px solid #e1e4e8; font-size: .92rem; vertical-align: top; }
  th { background: #24292e; color: #fff; font-weight: 600; }
  tr:last-child td { border-bottom: none; }
  tr.critical { background: #ffeef0; }
  tr.warning  { background: #fff8c5; }
  .badge { display: inline-block; padding: .15rem .55rem; border-radius: 999px; font-size: .78rem; font-weight: 600; color: #fff; }
  .badge.ok { background: #2da44e; }
  .badge.warning { background: #bf8700; }
  .badge.critical { background: #cf222e; }
  .badge.info { background: #57606a; }
</style>
</head>
<body>
  <h1>System Health Report</h1>
  <div class="meta">
    <strong>$env:COMPUTERNAME</strong> &middot; generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &middot; overall: <strong>$overall</strong>
  </div>
  <div class="summary">
    <div class="card"><span class="n" style="color:#cf222e">$($counts.Critical)</span>Critical</div>
    <div class="card"><span class="n" style="color:#bf8700">$($counts.Warning)</span>Warnings</div>
    <div class="card"><span class="n" style="color:#2da44e">$($counts.OK)</span>Healthy</div>
  </div>
  <table>
    <thead><tr><th>Category</th><th>Item</th><th>Status</th><th>Detail</th></tr></thead>
    <tbody>
$($rows -join "`n")
    </tbody>
  </table>
</body>
</html>
"@
}

#endregion

#region Main ------------------------------------------------------------------

Add-Type -AssemblyName System.Web

Write-Host ''
Write-Host '=== Windows System Health Check ===' -ForegroundColor Green
Write-Host ''

if (-not (Test-IsAdministrator)) {
    Write-Warning 'Not running as Administrator - some checks (event logs, services) may be incomplete.'
}

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$checks = @(
    { Get-SystemSummary },
    { Get-CpuHealth },
    { Get-MemoryHealth },
    { Get-DiskHealth },
    { Get-NetworkHealth },
    { Get-ServiceHealth },
    { Get-EventLogHealth },
    { Get-UpdateHealth },
    { Get-TopProcesses }
)

foreach ($check in $checks) {
    try {
        & $check
    } catch {
        Write-Warning "Check failed: $($_.Exception.Message)"
        Add-Finding 'Errors' 'Check failure' 'Warning' $_.Exception.Message
    }
}

$reportFile = Join-Path $OutputPath ("HealthReport_{0}_{1}.html" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))
ConvertTo-HtmlReport -Findings $script:Findings | Out-File -FilePath $reportFile -Encoding UTF8

$critical = ($script:Findings | Where-Object Status -eq 'Critical').Count
$warning  = ($script:Findings | Where-Object Status -eq 'Warning').Count

Write-Host ''
Write-Host "Critical: $critical   Warnings: $warning" -ForegroundColor $(if ($critical) { 'Red' } elseif ($warning) { 'Yellow' } else { 'Green' })
Write-Host "Report saved to: $reportFile" -ForegroundColor Green
Write-Host ''

# Surface findings on the pipeline so the script can be composed with others.
$script:Findings

#endregion
