<#
.SYNOPSIS
    Audits outbound network activity over time, profiling which processes talk to
    which destinations and highlighting regular, automated connection patterns.

.DESCRIPTION
    Samples TCP connection state repeatedly over a chosen window and aggregates
    the results per process and destination. Unlike a single snapshot, sampling
    reveals short-lived connections and shows whether a destination is contacted
    on a regular cadence.

    Also inspects the DNS client cache for recently resolved names and classifies
    every remote address as private, public, or loopback.

    Entirely read-only. No connections are blocked or terminated.

.PARAMETER DurationMinutes
    How long to sample. Default 5. Use 0 for a single immediate snapshot.

.PARAMETER IntervalSeconds
    Seconds between samples. Default 15. Shorter intervals catch more short-lived
    connections at the cost of more overhead.

.PARAMETER ResolveNames
    Perform reverse DNS on public remote addresses. Adds useful context but emits
    DNS queries, which is sometimes undesirable during an investigation.

.PARAMETER IncludeDnsCache
    Include the local DNS client cache in the report.

.PARAMETER MinimumSamplesForCadence
    How many observations of the same destination are needed before cadence
    analysis runs. Default 4. Below this, timing is not meaningful.

.PARAMETER OutputPath
    Directory for the report. Defaults to the user's Desktop.

.PARAMETER ExportCsv
    Also write the aggregated results as CSV.

.EXAMPLE
    .\Network-Connection-Auditor.ps1
    Sample for five minutes and report.

.EXAMPLE
    .\Network-Connection-Auditor.ps1 -DurationMinutes 0
    Single snapshot, no sampling.

.EXAMPLE
    .\Network-Connection-Auditor.ps1 -DurationMinutes 30 -IntervalSeconds 10 -ResolveNames -ExportCsv

.NOTES
    Run as Administrator to attribute sockets owned by other users' processes.

    On cadence detection: sampling infers regularity from observation times, not
    from packet captures. Legitimate software polls on a schedule constantly, so
    a regular cadence is a starting point for investigation, never a conclusion.
#>

[CmdletBinding()]
param(
    [ValidateRange(0, 1440)][int]$DurationMinutes = 5,
    [ValidateRange(2, 300)][int]$IntervalSeconds = 15,
    [switch]$ResolveNames,
    [switch]$IncludeDnsCache,
    [ValidateRange(3, 100)][int]$MinimumSamplesForCadence = 4,
    [string]$OutputPath = [Environment]::GetFolderPath('Desktop'),
    [switch]$ExportCsv
)

# Key: "process|pid|remoteIP|remotePort" -> observation record
$script:Observations = @{}
$script:SampleCount  = 0
$script:DnsCache     = @()
$script:StartTime    = Get-Date

#region Reference data --------------------------------------------------------

# Ports commonly associated with remote access, tunnelling, or C2 frameworks.
# Being on this list is a prompt to look, not a verdict.
$script:NotableRemotePorts = @{
    21   = 'FTP - cleartext credentials'
    22   = 'SSH - confirm this is an approved destination'
    23   = 'Telnet - cleartext, should not be in use'
    1080 = 'SOCKS proxy - can indicate tunnelling'
    1194 = 'OpenVPN'
    3389 = 'Outbound RDP'
    4444 = 'Common Metasploit handler port'
    5900 = 'VNC'
    6667 = 'IRC - legacy C2 channel'
    8080 = 'HTTP proxy / alternate web'
    8443 = 'Alternate HTTPS'
    9001 = 'Tor relay'
    9050 = 'Tor SOCKS'
}

# Scripting hosts and LOLBins that rarely have a legitimate reason to make
# sustained outbound connections on a normal workstation.
$script:UnexpectedNetworkProcesses = @(
    'cmd', 'powershell', 'pwsh', 'wscript', 'cscript', 'mshta',
    'regsvr32', 'rundll32', 'certutil', 'bitsadmin', 'installutil',
    'msbuild', 'wmic'
)

#endregion

#region Helpers ---------------------------------------------------------------

function Write-Step { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }

function Test-IsAdministrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-AddressScope {
    <# Classifies an IP as Loopback, Private, LinkLocal, Multicast, or Public. #>
    param([string]$Address)

    if (-not $Address) { return 'Unknown' }
    if ($Address -in '127.0.0.1', '::1') { return 'Loopback' }
    if ($Address -eq '0.0.0.0' -or $Address -eq '::') { return 'Unspecified' }

    # IPv6
    if ($Address -match ':') {
        if ($Address -match '^fe80:') { return 'LinkLocal' }
        if ($Address -match '^(fc|fd)')  { return 'Private' }
        if ($Address -match '^ff')       { return 'Multicast' }
        return 'Public'
    }

    $octets = $Address -split '\.'
    if ($octets.Count -ne 4) { return 'Unknown' }
    $a = [int]$octets[0]; $b = [int]$octets[1]

    if ($a -eq 10)                                  { return 'Private' }
    if ($a -eq 172 -and $b -ge 16 -and $b -le 31)   { return 'Private' }
    if ($a -eq 192 -and $b -eq 168)                 { return 'Private' }
    if ($a -eq 169 -and $b -eq 254)                 { return 'LinkLocal' }
    if ($a -eq 100 -and $b -ge 64 -and $b -le 127)  { return 'CGNAT' }
    if ($a -ge 224 -and $a -le 239)                 { return 'Multicast' }
    return 'Public'
}

function Resolve-AddressName {
    param([string]$Address)
    try {
        return [Net.Dns]::GetHostEntry($Address).HostName
    } catch {
        return ''
    }
}

function Measure-Cadence {
    <#
        Classifies a destination's contact pattern from its observation times.

        The critical distinction: a connection that stays open is seen in every
        single sample, so its gaps all equal the sampling interval and would look
        perfectly "regular" under a naive variance test. That is a persistent
        session, NOT periodic contact, and flagging it would bury the report in
        false positives (every browser tab, VPN, and mail client qualifies).

        So we only consider "return gaps" - intervals where the destination
        disappeared for at least one sample and then came back. Regularity across
        those return gaps is what actually indicates scheduled contact.

        Returns Pattern = Persistent | Periodic | Sporadic.
    #>
    param(
        [Parameter(Mandatory)][datetime[]]$Times,
        [Parameter(Mandatory)][int]$SampleIntervalSeconds
    )

    $none = [pscustomobject]@{ Pattern = 'Sporadic'; MeanSeconds = 0; Variation = 0; Returns = 0 }

    $sorted = @($Times | Sort-Object)
    if ($sorted.Count -lt 3) { return $none }

    $gaps = for ($i = 1; $i -lt $sorted.Count; $i++) {
        ($sorted[$i] - $sorted[$i - 1]).TotalSeconds
    }

    # A gap at or near the sampling interval means the connection was still
    # present in the next sample - continuous, not a fresh contact.
    $returnThreshold = $SampleIntervalSeconds * 1.5
    $returnGaps = @($gaps | Where-Object { $_ -gt $returnThreshold })

    if ($returnGaps.Count -eq 0) {
        return [pscustomobject]@{
            Pattern     = 'Persistent'
            MeanSeconds = 0
            Variation   = 0
            Returns     = 0
        }
    }

    # Need several returns before regularity means anything.
    if ($returnGaps.Count -lt 3) { return $none }

    $stats = $returnGaps | Measure-Object -Average -StandardDeviation
    $mean  = $stats.Average
    if ($mean -le 0) { return $none }

    $cv = $stats.StandardDeviation / $mean

    return [pscustomobject]@{
        Pattern     = if ($cv -lt 0.25) { 'Periodic' } else { 'Sporadic' }
        MeanSeconds = [math]::Round($mean, 1)
        Variation   = [math]::Round($cv, 3)
        Returns     = $returnGaps.Count
    }
}

#endregion

#region Collection ------------------------------------------------------------

function Invoke-Sample {
    <# Takes one snapshot of established TCP connections and folds it into the map. #>

    $now = Get-Date
    $script:SampleCount++

    $procNames = @{}
    $procPaths = @{}
    foreach ($p in Get-CimInstance Win32_Process) {
        $procNames[[int]$p.ProcessId] = ($p.Name -replace '\.exe$', '')
        $procPaths[[int]$p.ProcessId] = $p.ExecutablePath
    }

    $connections = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)

    foreach ($c in $connections) {
        $scope = Get-AddressScope $c.RemoteAddress
        if ($scope -in 'Loopback', 'Unspecified') { continue }

        $ownerPid = [int]$c.OwningProcess
        $pname = if ($procNames.ContainsKey($ownerPid)) { $procNames[$ownerPid] } else { '(unknown)' }
        $key = "$pname|$ownerPid|$($c.RemoteAddress)|$($c.RemotePort)"

        if (-not $script:Observations.ContainsKey($key)) {
            $script:Observations[$key] = [pscustomobject]@{
                Process     = $pname
                ProcessId   = $ownerPid
                ProcessPath = $procPaths[$ownerPid]
                RemoteIP    = $c.RemoteAddress
                RemotePort  = [int]$c.RemotePort
                Scope       = $scope
                Hostname    = ''
                Pattern     = 'Unknown'
                Times       = New-Object System.Collections.Generic.List[datetime]
                Flags       = New-Object System.Collections.Generic.List[string]
                IsFlagged   = $false
            }
        }
        $script:Observations[$key].Times.Add($now)
    }

    return $connections.Count
}

function Get-DnsCacheEntries {
    Write-Step 'Reading DNS client cache'

    if (-not (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue)) {
        Write-Warning 'Get-DnsClientCache is unavailable on this system - skipping DNS cache section.'
        return
    }

    $script:DnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue |
        Where-Object { $_.Type -in 1, 5 -and $_.Entry } |
        Select-Object @{ N = 'Name';  E = { $_.Entry } },
                      @{ N = 'Data';  E = { $_.Data } },
                      @{ N = 'TTL';   E = { $_.TimeToLive } } |
        Sort-Object Name -Unique

    Write-Host ("    {0} cached DNS entries" -f $script:DnsCache.Count)
}

function Set-Analysis {
    Write-Step 'Analysing collected observations'

    foreach ($o in $script:Observations.Values) {
        $flags = $o.Flags

        if ($script:NotableRemotePorts.ContainsKey($o.RemotePort)) {
            $flags.Add("Port $($o.RemotePort): $($script:NotableRemotePorts[$o.RemotePort])")
        }

        if ($o.Process.ToLower() -in $script:UnexpectedNetworkProcesses) {
            $flags.Add('Scripting host or LOLBin with an outbound connection')
        }

        if ($o.ProcessPath -match '(?i)\\(AppData\\Local\\Temp|Windows\\Temp|Users\\Public|Downloads)\\') {
            $flags.Add('Process runs from a user-writable directory')
        }

        # Cadence analysis only makes sense with enough observations, and only
        # when we actually sampled over time.
        if ($DurationMinutes -gt 0 -and $o.Times.Count -ge $MinimumSamplesForCadence) {
            $cadence = Measure-Cadence -Times $o.Times -SampleIntervalSeconds $IntervalSeconds
            $o.Pattern = $cadence.Pattern
            if ($cadence.Pattern -eq 'Periodic') {
                $flags.Add("Periodic contact: reconnected $($cadence.Returns) times, roughly every $($cadence.MeanSeconds)s (variation $($cadence.Variation))")
            }
        }

        $o.IsFlagged = $flags.Count -gt 0
    }

    if ($ResolveNames) {
        Write-Step 'Performing reverse DNS on public addresses'
        $cache = @{}
        foreach ($o in $script:Observations.Values) {
            if ($o.Scope -ne 'Public') { continue }
            if (-not $cache.ContainsKey($o.RemoteIP)) {
                $cache[$o.RemoteIP] = Resolve-AddressName $o.RemoteIP
            }
            $o.Hostname = $cache[$o.RemoteIP]
        }
    }
}

#endregion

#region Reporting -------------------------------------------------------------

function Get-Summary {
    $all = @($script:Observations.Values)
    [pscustomobject]@{
        Destinations = $all.Count
        Processes    = @($all | Select-Object -ExpandProperty Process -Unique).Count
        Public       = @($all | Where-Object Scope -eq 'Public').Count
        Private      = @($all | Where-Object Scope -eq 'Private').Count
        Flagged      = @($all | Where-Object IsFlagged).Count
    }
}

function New-HtmlReport {
    $summary = Get-Summary

    # Flagged first, then most-observed. Per-key Descending keeps the two
    # orderings independent - a single trailing -Descending would invert both.
    $rows = $script:Observations.Values |
        Sort-Object @{ Expression = { $_.IsFlagged }; Descending = $true },
                    @{ Expression = { $_.Times.Count }; Descending = $true }

    $body = foreach ($o in $rows) {
        $first = ($o.Times | Measure-Object -Minimum).Minimum
        $last  = ($o.Times | Measure-Object -Maximum).Maximum
        $dest  = if ($o.Hostname) { "$($o.RemoteIP)<br><span class='host'>$([System.Web.HttpUtility]::HtmlEncode($o.Hostname))</span>" } else { $o.RemoteIP }
        $notes = if ($o.Flags.Count -gt 0) {
            ($o.Flags | ForEach-Object { "<span class='flag'>$([System.Web.HttpUtility]::HtmlEncode($_))</span>" }) -join ' '
        } else { '' }

        @"
      <tr class="$(if ($o.IsFlagged) { 'flagged' })">
        <td>$([System.Web.HttpUtility]::HtmlEncode($o.Process))<br><span class="pid">PID $($o.ProcessId)</span></td>
        <td>$dest</td>
        <td>$($o.RemotePort)</td>
        <td><span class="scope $($o.Scope.ToLower())">$($o.Scope)</span></td>
        <td>$($o.Times.Count)</td>
        <td>$($o.Pattern)</td>
        <td class="when">$($first.ToString('HH:mm:ss')) - $($last.ToString('HH:mm:ss'))</td>
        <td>$notes</td>
      </tr>
"@
    }

    $dnsSection = ''
    if ($IncludeDnsCache -and $script:DnsCache.Count -gt 0) {
        $dnsRows = foreach ($d in $script:DnsCache) {
            "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($d.Name))</td><td>$([System.Web.HttpUtility]::HtmlEncode([string]$d.Data))</td><td>$($d.TTL)</td></tr>"
        }
        $dnsSection = @"
<h2>DNS client cache <span class="count">$($script:DnsCache.Count)</span></h2>
<p class="note">Names resolved recently by this machine. The cache is volatile and reflects
only what is still within its TTL, so absence here does not prove a name was never resolved.</p>
<table>
  <thead><tr><th>Name</th><th>Resolved to</th><th>TTL</th></tr></thead>
  <tbody>
$($dnsRows -join "`n")
  </tbody>
</table>
"@
    }

    $windowText = if ($DurationMinutes -eq 0) {
        'single snapshot'
    } else {
        "$DurationMinutes minute(s), $script:SampleCount samples every ${IntervalSeconds}s"
    }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Network Connection Audit - $env:COMPUTERNAME</title>
<style>
  body { font-family:'Segoe UI',Tahoma,sans-serif; margin:2rem; background:#f5f6f8; color:#1b1f23; }
  h1 { margin-bottom:.25rem; }
  h2 { margin-top:2rem; font-size:1.15rem; border-bottom:2px solid #d0d7de; padding-bottom:.35rem; }
  .meta { color:#586069; margin-bottom:1.5rem; }
  .count { background:#d0d7de; border-radius:999px; padding:.1rem .55rem; font-size:.8rem; margin-left:.4rem; }
  .summary { display:flex; gap:1rem; margin-bottom:1.5rem; flex-wrap:wrap; }
  .card { background:#fff; border-radius:8px; padding:1rem 1.5rem; box-shadow:0 1px 3px rgba(0,0,0,.1); min-width:110px; }
  .card .n { font-size:2rem; font-weight:600; display:block; }
  .disclaimer { background:#fff; border-left:4px solid #0969da; padding:.8rem 1.1rem; border-radius:6px;
                margin-bottom:1.5rem; font-size:.9rem; }
  .note { color:#586069; font-size:.85rem; }
  table { width:100%; border-collapse:collapse; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.1); }
  th,td { text-align:left; padding:.5rem .75rem; border-bottom:1px solid #e1e4e8; font-size:.85rem; vertical-align:top; }
  th { background:#24292e; color:#fff; }
  tr:last-child td { border-bottom:none; }
  tr.flagged { background:#fff8c5; }
  .pid,.host { color:#586069; font-size:.75rem; }
  .when { white-space:nowrap; color:#586069; font-size:.8rem; }
  .scope { display:inline-block; padding:.1rem .45rem; border-radius:4px; font-size:.75rem; color:#fff; }
  .scope.public { background:#0969da; }
  .scope.private { background:#2da44e; }
  .scope.cgnat,.scope.linklocal,.scope.multicast { background:#57606a; }
  .flag { display:inline-block; background:#bf8700; color:#fff; border-radius:4px; padding:.1rem .45rem;
          font-size:.75rem; margin:.1rem .15rem .1rem 0; }
</style>
</head>
<body>
  <h1>Network Connection Audit</h1>
  <div class="meta">
    <strong>$env:COMPUTERNAME</strong> &middot; window: $windowText &middot;
    started $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
  </div>
  <div class="summary">
    <div class="card"><span class="n">$($summary.Destinations)</span>Destinations</div>
    <div class="card"><span class="n">$($summary.Processes)</span>Processes</div>
    <div class="card"><span class="n" style="color:#0969da">$($summary.Public)</span>Public</div>
    <div class="card"><span class="n" style="color:#2da44e">$($summary.Private)</span>Private</div>
    <div class="card"><span class="n" style="color:#bf8700">$($summary.Flagged)</span>Flagged</div>
  </div>
  <div class="disclaimer">
    <strong>Reading the Pattern column.</strong>
    <em>Persistent</em> means the connection stayed open for the whole time it was observed -
    normal for browsers, VPNs, and mail clients.
    <em>Periodic</em> means the destination was contacted, dropped, and re-contacted on a
    consistent schedule. Update checkers, telemetry, and monitoring agents do this constantly,
    so it is a reason to identify the process - not evidence of compromise.
    <em>Sporadic</em> means irregular contact.
    Timing is inferred from sampling, not packet capture: anything faster than the sample
    interval is invisible, so a quiet result does not prove absence of activity.
  </div>
  <h2>Destinations <span class="count">$($summary.Destinations)</span></h2>
  <table>
    <thead><tr><th>Process</th><th>Remote address</th><th>Port</th><th>Scope</th><th>Seen</th><th>Pattern</th><th>Window</th><th>Notes</th></tr></thead>
    <tbody>
$($body -join "`n")
    </tbody>
  </table>
$dnsSection
</body>
</html>
"@
}

#endregion

#region Main ------------------------------------------------------------------

Add-Type -AssemblyName System.Web

Write-Host ''
Write-Host '=== Network Connection Auditor ===' -ForegroundColor Green
Write-Host ''

if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
    throw 'Get-NetTCPConnection is not available on this system. Windows 8 / Server 2012 or later is required.'
}

if (-not (Test-IsAdministrator)) {
    Write-Warning 'Not running as Administrator - sockets owned by other users may not be attributed to a process.'
}

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

if ($DurationMinutes -eq 0) {
    Write-Step 'Taking a single snapshot'
    $count = Invoke-Sample
    Write-Host "    $count established connection(s)"
} else {
    $endTime = (Get-Date).AddMinutes($DurationMinutes)
    $total   = [math]::Max(1, [math]::Floor(($DurationMinutes * 60) / $IntervalSeconds))
    Write-Step "Sampling for $DurationMinutes minute(s) every ${IntervalSeconds}s (about $total samples)"
    Write-Host '    Press Ctrl+C to stop early - the report will not be written if you do.' -ForegroundColor DarkGray

    while ((Get-Date) -lt $endTime) {
        $count = Invoke-Sample
        $pct = [math]::Min(100, [math]::Round((($script:SampleCount) / $total) * 100))
        Write-Progress -Activity 'Sampling network connections' `
                       -Status "Sample $script:SampleCount of ~$total - $count active, $($script:Observations.Count) unique destinations" `
                       -PercentComplete $pct

        $remaining = ($endTime - (Get-Date)).TotalSeconds
        if ($remaining -le 0) { break }
        Start-Sleep -Seconds ([math]::Min($IntervalSeconds, [math]::Ceiling($remaining)))
    }
    Write-Progress -Activity 'Sampling network connections' -Completed
    Write-Host ("    {0} samples taken, {1} unique destinations" -f $script:SampleCount, $script:Observations.Count)
}

if ($IncludeDnsCache) { Get-DnsCacheEntries }

Set-Analysis

$summary = Get-Summary
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportFile = Join-Path $OutputPath "NetworkAudit_$($env:COMPUTERNAME)_$stamp.html"
New-HtmlReport | Out-File -FilePath $reportFile -Encoding UTF8

if ($ExportCsv) {
    $csvFile = Join-Path $OutputPath "NetworkAudit_$($env:COMPUTERNAME)_$stamp.csv"
    $script:Observations.Values |
        Select-Object Process, ProcessId, ProcessPath, RemoteIP, RemotePort, Scope, Hostname,
                      @{ N = 'TimesSeen'; E = { $_.Times.Count } },
                      @{ N = 'FirstSeen'; E = { ($_.Times | Measure-Object -Minimum).Minimum } },
                      @{ N = 'LastSeen';  E = { ($_.Times | Measure-Object -Maximum).Maximum } },
                      @{ N = 'Notes';     E = { $_.Flags -join '; ' } } |
        Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "CSV exported to: $csvFile" -ForegroundColor Green
}

Write-Host ''
Write-Host ("Destinations: {0}   Public: {1}   Flagged: {2}" -f
    $summary.Destinations, $summary.Public, $summary.Flagged) -ForegroundColor $(if ($summary.Flagged) { 'Yellow' } else { 'Green' })

foreach ($o in ($script:Observations.Values | Where-Object IsFlagged)) {
    $target = if ($o.Hostname) { "$($o.RemoteIP) ($($o.Hostname))" } else { $o.RemoteIP }
    Write-Host ("  [!] {0} -> {1}:{2}" -f $o.Process, $target, $o.RemotePort) -ForegroundColor Yellow
    foreach ($f in $o.Flags) { Write-Host "        $f" -ForegroundColor DarkGray }
}

Write-Host ''
Write-Host "Report saved to: $reportFile" -ForegroundColor Green
Write-Host ''

$script:Observations.Values

#endregion
