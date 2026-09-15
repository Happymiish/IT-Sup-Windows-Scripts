<#
.SYNOPSIS
    Analyses Windows event logs for security-relevant activity: failed logons,
    account lockouts, privilege escalation, service installs, log clearing, and
    unexpected reboots.

.DESCRIPTION
    Queries the Security, System, and Application logs over a chosen window and
    correlates the events that matter during an investigation, rather than dumping
    raw log entries.

    Produces an HTML report plus optional CSV export for SIEM ingestion, and
    returns structured objects for further filtering.

    Entirely read-only. No logs are cleared or modified.

.PARAMETER Hours
    How far back to analyse. Default 24. Use 168 for a week.

.PARAMETER OutputPath
    Directory for the report. Defaults to the user's Desktop.

.PARAMETER ComputerName
    Remote computer(s) to analyse. Defaults to the local machine.

.PARAMETER FailedLogonThreshold
    Failed logons from a single account before it is flagged. Default 5.

.PARAMETER ExportCsv
    Also write a flat CSV of all collected events for SIEM or spreadsheet use.

.PARAMETER IncludeCategories
    Which analyses to run. Defaults to all.
    Logons, Lockouts, PrivilegeUse, AccountChanges, Services, LogClearing,
    SystemStability, Applications

.EXAMPLE
    .\Event-Log-Analyzer.ps1

.EXAMPLE
    .\Event-Log-Analyzer.ps1 -Hours 168 -ExportCsv

.EXAMPLE
    .\Event-Log-Analyzer.ps1 -ComputerName DC01,FS02 -IncludeCategories Logons,Lockouts

.NOTES
    Requires Administrator to read the Security log. Most detections depend on
    audit policy being enabled - see the README for the required settings.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 8760)][int]$Hours = 24,
    [string]$OutputPath = [Environment]::GetFolderPath('Desktop'),
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [ValidateRange(1, 1000)][int]$FailedLogonThreshold = 5,
    [switch]$ExportCsv,

    [ValidateSet('Logons', 'Lockouts', 'PrivilegeUse', 'AccountChanges',
                 'Services', 'LogClearing', 'SystemStability', 'Applications')]
    [string[]]$IncludeCategories = @('Logons', 'Lockouts', 'PrivilegeUse', 'AccountChanges',
                                     'Services', 'LogClearing', 'SystemStability', 'Applications')
)

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Since = (Get-Date).AddHours(-$Hours)

# Cache of per-computer Security log readability, populated on first use.
$script:SecurityReadable = @{}

#region Reference data --------------------------------------------------------

# Logon types worth distinguishing. Type 3 (network) and 10 (RDP) matter most
# for lateral movement; type 2 (interactive) for physical access.
$script:LogonTypes = @{
    2  = 'Interactive (console)'
    3  = 'Network (share/RPC)'
    4  = 'Batch (scheduled task)'
    5  = 'Service'
    7  = 'Unlock'
    8  = 'NetworkCleartext'
    9  = 'NewCredentials (runas /netonly)'
    10 = 'RemoteInteractive (RDP)'
    11 = 'CachedInteractive'
}

# Common failure reasons. Distinguishing "bad password" from "account disabled"
# changes the investigation completely.
$script:FailureReasons = @{
    '0xC0000064' = 'Account does not exist'
    '0xC000006A' = 'Incorrect password'
    '0xC000006D' = 'Bad username or authentication info'
    '0xC000006E' = 'Account restriction (hours, workstation, expiry)'
    '0xC000006F' = 'Logon outside permitted hours'
    '0xC0000070' = 'Logon from unauthorised workstation'
    '0xC0000071' = 'Password expired'
    '0xC0000072' = 'Account disabled'
    '0xC0000133' = 'Clock skew between client and DC'
    '0xC0000193' = 'Account expired'
    '0xC0000224' = 'Password change required'
    '0xC0000234' = 'Account locked out'
}

#endregion

#region Helpers ---------------------------------------------------------------

function Write-Step { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }

function Test-IsAdministrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Critical', 'Warning', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Summary,
        [string]$Detail = '',
        [datetime]$FirstSeen = [datetime]::MinValue,
        [datetime]$LastSeen = [datetime]::MinValue,
        [int]$Count = 1
    )
    $script:Findings.Add([pscustomobject]@{
        Computer  = $Computer
        Category  = $Category
        Severity  = $Severity
        Summary   = $Summary
        Detail    = $Detail
        FirstSeen = $FirstSeen
        LastSeen  = $LastSeen
        Count     = $Count
    })
}

function Get-EventsSafe {
    <#
        Get-WinEvent throws a terminating-style error when no events match the
        filter, which is a normal outcome. Translate that into an empty result
        and surface genuine failures (access denied, log missing) as warnings.
    #>
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][hashtable]$FilterHashtable,
        [int]$MaxEvents = 0
    )

    $params = @{
        FilterHashtable = $FilterHashtable
        ErrorAction     = 'Stop'
    }
    if ($Computer -ne $env:COMPUTERNAME) { $params.ComputerName = $Computer }
    if ($MaxEvents -gt 0) { $params.MaxEvents = $MaxEvents }

    try {
        return @(Get-WinEvent @params)
    } catch [Exception] {
        if ($_.Exception.Message -match 'No events were found') { return @() }
        Write-Warning "$Computer / $($FilterHashtable.LogName): $($_.Exception.Message)"
        return @()
    }
}

function Test-SecurityLogAccess {
    <#
        Probes whether the Security log is readable on a target. Without this,
        an access-denied result is indistinguishable from "nothing happened",
        which would let the report claim a clean bill of health it cannot back up.
    #>
    param([Parameter(Mandatory)][string]$Computer)

    $params = @{
        LogName     = 'Security'
        MaxEvents   = 1
        ErrorAction = 'Stop'
    }
    if ($Computer -ne $env:COMPUTERNAME) { $params.ComputerName = $Computer }

    try {
        $null = Get-WinEvent @params
        return $true
    } catch {
        # An empty-but-readable log is still readable.
        if ($_.Exception.Message -match 'No events were found') { return $true }
        return $false
    }
}

function Get-EventProperty {
    <#
        Reads a named field from an event's XML. Property indexes shift between
        Windows versions, so resolving by name is far more reliable.
    #>
    param(
        [Parameter(Mandatory)]$Event,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        $xml = [xml]$Event.ToXml()
        $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name }
        if ($node) { return [string]$node.'#text' }
    } catch { }
    return ''
}

#endregion

#region Analyses --------------------------------------------------------------

function Assert-SecurityLogReadable {
    <#
        Returns $true when Security-log analysis can proceed. When it cannot,
        records an explicit Warning so the gap is visible in the report rather
        than being silently reported as "nothing found".
    #>
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][string]$Category
    )

    if (-not $script:SecurityReadable.ContainsKey($Computer)) {
        $script:SecurityReadable[$Computer] = Test-SecurityLogAccess -Computer $Computer
    }
    if ($script:SecurityReadable[$Computer]) { return $true }

    Add-Finding -Computer $Computer -Category $Category -Severity 'Warning' `
        -Summary 'Security log not readable - this check could not run' `
        -Detail 'Reading the Security log requires Administrator (or membership of Event Log Readers). Absence of findings here does NOT mean absence of activity.' `
        -Count 0
    return $false
}

function Measure-LogonActivity {
    param([string]$Computer)
    Write-Step "$Computer - analysing logon activity"

    if (-not (Assert-SecurityLogReadable -Computer $Computer -Category 'Logons')) { return }

    # 4625 = failed logon, 4624 = successful logon.
    $failed = Get-EventsSafe -Computer $Computer -FilterHashtable @{
        LogName = 'Security'; Id = 4625; StartTime = $script:Since
    }

    if ($failed.Count -gt 0) {
        $byAccount = $failed | ForEach-Object {
            [pscustomobject]@{
                Time    = $_.TimeCreated
                Account = Get-EventProperty $_ 'TargetUserName'
                Source  = Get-EventProperty $_ 'IpAddress'
                Type    = Get-EventProperty $_ 'LogonType'
                Status  = Get-EventProperty $_ 'SubStatus'
            }
        } | Group-Object Account

        foreach ($group in $byAccount) {
            $reasonCode = ($group.Group | Select-Object -First 1).Status
            $reason = if ($script:FailureReasons.ContainsKey($reasonCode)) {
                $script:FailureReasons[$reasonCode]
            } else { "Status $reasonCode" }

            $sources = ($group.Group | Where-Object { $_.Source -and $_.Source -notin '-', '::1', '127.0.0.1' } |
                        Select-Object -ExpandProperty Source -Unique) -join ', '

            $severity = if ($group.Count -ge ($FailedLogonThreshold * 4)) { 'Critical' }
                        elseif ($group.Count -ge $FailedLogonThreshold) { 'Warning' }
                        else { 'Info' }

            $detail = "Reason: $reason."
            if ($sources) { $detail += " Source IPs: $sources." }

            Add-Finding -Computer $Computer -Category 'Logons' -Severity $severity `
                -Summary "$($group.Count) failed logon(s) for '$($group.Name)'" `
                -Detail $detail `
                -FirstSeen ($group.Group.Time | Measure-Object -Minimum).Minimum `
                -LastSeen ($group.Group.Time | Measure-Object -Maximum).Maximum `
                -Count $group.Count
        }
    } else {
        Add-Finding -Computer $Computer -Category 'Logons' -Severity 'Info' `
            -Summary 'No failed logons in the window' -Count 0
    }

    # Successful RDP and network logons - the paths used for lateral movement.
    $success = Get-EventsSafe -Computer $Computer -FilterHashtable @{
        LogName = 'Security'; Id = 4624; StartTime = $script:Since
    }

    if ($success.Count -gt 0) {
        $interesting = $success | ForEach-Object {
            [pscustomobject]@{
                Time    = $_.TimeCreated
                Account = Get-EventProperty $_ 'TargetUserName'
                Type    = [int](Get-EventProperty $_ 'LogonType')
                Source  = Get-EventProperty $_ 'IpAddress'
            }
        } | Where-Object {
            # Exclude machine accounts and service noise.
            $_.Account -and $_.Account -notmatch '\$$' -and
            $_.Account -notin 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'DWM-1', 'UMFD-0', 'UMFD-1' -and
            $_.Type -in 3, 10
        }

        foreach ($group in ($interesting | Group-Object Account, Type)) {
            $first = $group.Group | Select-Object -First 1
            $typeName = if ($script:LogonTypes.ContainsKey($first.Type)) {
                $script:LogonTypes[$first.Type]
            } else { "Type $($first.Type)" }

            $sources = ($group.Group | Where-Object { $_.Source -and $_.Source -notin '-', '::1', '127.0.0.1' } |
                        Select-Object -ExpandProperty Source -Unique) -join ', '

            # RDP is worth surfacing at Warning on a workstation.
            $severity = if ($first.Type -eq 10) { 'Warning' } else { 'Info' }

            Add-Finding -Computer $Computer -Category 'Logons' -Severity $severity `
                -Summary "$($group.Count) x $typeName logon by '$($first.Account)'" `
                -Detail $(if ($sources) { "Source IPs: $sources" } else { 'No source IP recorded' }) `
                -FirstSeen ($group.Group.Time | Measure-Object -Minimum).Minimum `
                -LastSeen ($group.Group.Time | Measure-Object -Maximum).Maximum `
                -Count $group.Count
        }
    }
}

function Measure-Lockouts {
    param([string]$Computer)
    Write-Step "$Computer - checking account lockouts"

    if (-not (Assert-SecurityLogReadable -Computer $Computer -Category 'Lockouts')) { return }

    # 4740 = account locked out.
    $events = Get-EventsSafe -Computer $Computer -FilterHashtable @{
        LogName = 'Security'; Id = 4740; StartTime = $script:Since
    }

    if ($events.Count -eq 0) {
        Add-Finding -Computer $Computer -Category 'Lockouts' -Severity 'Info' `
            -Summary 'No account lockouts in the window' -Count 0
        return
    }

    $byAccount = $events | ForEach-Object {
        [pscustomobject]@{
            Time    = $_.TimeCreated
            Account = Get-EventProperty $_ 'TargetUserName'
            Caller  = Get-EventProperty $_ 'TargetDomainName'
        }
    } | Group-Object Account

    foreach ($group in $byAccount) {
        $callers = ($group.Group | Select-Object -ExpandProperty Caller -Unique) -join ', '
        $severity = if ($group.Count -ge 3) { 'Critical' } else { 'Warning' }

        Add-Finding -Computer $Computer -Category 'Lockouts' -Severity $severity `
            -Summary "Account '$($group.Name)' locked out $($group.Count) time(s)" `
            -Detail "Originating workstation(s): $callers. Repeated lockouts usually mean a stale cached credential, a mapped drive, or a scheduled task using an old password." `
            -FirstSeen ($group.Group.Time | Measure-Object -Minimum).Minimum `
            -LastSeen ($group.Group.Time | Measure-Object -Maximum).Maximum `
            -Count $group.Count
    }
}

function Measure-PrivilegeUse {
    param([string]$Computer)
    Write-Step "$Computer - reviewing privilege escalation"

    if (-not (Assert-SecurityLogReadable -Computer $Computer -Category 'PrivilegeUse')) { return }

    # 4672 = special privileges assigned (admin-equivalent logon).
    $events = Get-EventsSafe -Computer $Computer -FilterHashtable @{
        LogName = 'Security'; Id = 4672; StartTime = $script:Since
    }

    if ($events.Count -eq 0) { return }

    $byAccount = $events | ForEach-Object {
        [pscustomobject]@{
            Time    = $_.TimeCreated
            Account = Get-EventProperty $_ 'SubjectUserName'
        }
    } | Where-Object {
        $_.Account -and $_.Account -notmatch '\$$' -and
        $_.Account -notin 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'
    } | Group-Object Account

    foreach ($group in $byAccount) {
        Add-Finding -Computer $Computer -Category 'PrivilegeUse' -Severity 'Info' `
            -Summary "'$($group.Name)' was granted administrative privileges $($group.Count) time(s)" `
            -Detail 'Event 4672. Expected for admin accounts; unexpected for standard users.' `
            -FirstSeen ($group.Group.Time | Measure-Object -Minimum).Minimum `
            -LastSeen ($group.Group.Time | Measure-Object -Maximum).Maximum `
            -Count $group.Count
    }
}

function Measure-AccountChanges {
    param([string]$Computer)
    Write-Step "$Computer - checking account and group changes"

    if (-not (Assert-SecurityLogReadable -Computer $Computer -Category 'AccountChanges')) { return }

    $watch = @{
        4720 = @{ Text = 'User account created';              Severity = 'Warning' }
        4726 = @{ Text = 'User account deleted';              Severity = 'Warning' }
        4722 = @{ Text = 'User account enabled';              Severity = 'Warning' }
        4725 = @{ Text = 'User account disabled';             Severity = 'Info'    }
        4724 = @{ Text = 'Password reset by administrator';   Severity = 'Warning' }
        4738 = @{ Text = 'User account changed';              Severity = 'Info'    }
        4732 = @{ Text = 'Member added to a security group';  Severity = 'Critical'}
        4733 = @{ Text = 'Member removed from a security group'; Severity = 'Info' }
        4756 = @{ Text = 'Member added to a universal group'; Severity = 'Critical'}
    }

    foreach ($id in $watch.Keys) {
        $events = Get-EventsSafe -Computer $Computer -FilterHashtable @{
            LogName = 'Security'; Id = $id; StartTime = $script:Since
        }
        if ($events.Count -eq 0) { continue }

        $targets = $events | ForEach-Object {
            $t = Get-EventProperty $_ 'TargetUserName'
            $g = Get-EventProperty $_ 'TargetSid'
            if ($t) { $t } else { $g }
        } | Where-Object { $_ } | Select-Object -Unique

        Add-Finding -Computer $Computer -Category 'AccountChanges' -Severity $watch[$id].Severity `
            -Summary "$($events.Count) x $($watch[$id].Text)" `
            -Detail "Event $id. Target(s): $($targets -join ', ')" `
            -FirstSeen ($events.TimeCreated | Measure-Object -Minimum).Minimum `
            -LastSeen ($events.TimeCreated | Measure-Object -Maximum).Maximum `
            -Count $events.Count
    }
}

function Measure-ServiceActivity {
    param([string]$Computer)
    Write-Step "$Computer - checking service installs and failures"

    # 7045 (System) = a new service was installed. Classic persistence mechanism.
    $installs = Get-EventsSafe -Computer $Computer -FilterHashtable @{
        LogName = 'System'; Id = 7045; StartTime = $script:Since
    }

    foreach ($e in $installs) {
        $name = Get-EventProperty $e 'ServiceName'
        $path = Get-EventProperty $e 'ImagePath'
        $start = Get-EventProperty $e 'StartType'

        # Services installed from temp directories are a strong signal.
        $severity = if ($path -match '(?i)\\(Temp|Users\\Public|Downloads)\\') { 'Critical' } else { 'Warning' }

        Add-Finding -Computer $Computer -Category 'Services' -Severity $severity `
            -Summary "New service installed: '$name'" `
            -Detail "Image: $path (start type: $start). Event 7045 is a common persistence mechanism - verify this install was expected." `
            -FirstSeen $e.TimeCreated -LastSeen $e.TimeCreated
    }

    # 7034/7031 = service crashed / terminated unexpectedly.
    $crashes = Get-EventsSafe -Computer $Computer -FilterHashtable @{
        LogName = 'System'; Id = 7031, 7034; StartTime = $script:Since
    }

    if ($crashes.Count -gt 0) {
        foreach ($group in ($crashes | Group-Object { $_.Properties[0].Value })) {
            Add-Finding -Computer $Computer -Category 'Services' -Severity 'Warning' `
                -Summary "Service '$($group.Name)' terminated unexpectedly $($group.Count) time(s)" `
                -Detail 'Repeated crashes usually indicate a failing dependency, corruption, or a resource limit.' `
                -FirstSeen ($group.Group.TimeCreated | Measure-Object -Minimum).Minimum `
                -LastSeen ($group.Group.TimeCreated | Measure-Object -Maximum).Maximum `
                -Count $group.Count
        }
    }
}

function Measure-LogClearing {
    param([string]$Computer)
    Write-Step "$Computer - checking for log tampering"

    # 1102 (Security) = audit log cleared. 104 (System) = a log was cleared.
    # The System half still works unelevated, so only the Security half is gated.
    $cleared = @()
    if (Assert-SecurityLogReadable -Computer $Computer -Category 'LogClearing') {
        $cleared += Get-EventsSafe -Computer $Computer -FilterHashtable @{
            LogName = 'Security'; Id = 1102; StartTime = $script:Since
        }
    }
    $cleared += Get-EventsSafe -Computer $Computer -FilterHashtable @{
        LogName = 'System'; Id = 104; StartTime = $script:Since
    }

    foreach ($e in $cleared) {
        $who = Get-EventProperty $e 'SubjectUserName'
        if (-not $who) { $who = Get-EventProperty $e 'userName' }

        Add-Finding -Computer $Computer -Category 'LogClearing' -Severity 'Critical' `
            -Summary "Event log cleared ($($e.LogName))" `
            -Detail "Cleared by: $(if ($who) { $who } else { 'unknown' }). Legitimate reasons exist, but log clearing is a standard anti-forensic step - corroborate with change records." `
            -FirstSeen $e.TimeCreated -LastSeen $e.TimeCreated
    }

    if ($cleared.Count -eq 0) {
        # Name the scope explicitly - claiming a blanket all-clear would be wrong
        # when the Security half of the check was skipped.
        $scope = if ($script:SecurityReadable[$Computer]) { 'Security and System logs' } else { 'System log only' }
        Add-Finding -Computer $Computer -Category 'LogClearing' -Severity 'Info' `
            -Summary "No log clearing detected ($scope)" -Count 0
    }
}

function Measure-SystemStability {
    param([string]$Computer)
    Write-Step "$Computer - reviewing system stability"

    # 6008 = unexpected shutdown, 41 = kernel power loss, 1001 = BugCheck.
    $unexpected = Get-EventsSafe -Computer $Computer -FilterHashtable @{
        LogName = 'System'; Id = 6008, 41; StartTime = $script:Since
    }

    if ($unexpected.Count -gt 0) {
        Add-Finding -Computer $Computer -Category 'SystemStability' -Severity 'Warning' `
            -Summary "$($unexpected.Count) unexpected shutdown(s) or power loss event(s)" `
            -Detail 'Events 6008/41. Check for power issues, thermal shutdown, or a failing PSU before suspecting software.' `
            -FirstSeen ($unexpected.TimeCreated | Measure-Object -Minimum).Minimum `
            -LastSeen ($unexpected.TimeCreated | Measure-Object -Maximum).Maximum `
            -Count $unexpected.Count
    }

    $bugchecks = Get-EventsSafe -Computer $Computer -FilterHashtable @{
        LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; StartTime = $script:Since
    }

    if ($bugchecks.Count -gt 0) {
        Add-Finding -Computer $Computer -Category 'SystemStability' -Severity 'Critical' `
            -Summary "$($bugchecks.Count) bugcheck(s) / blue screen(s)" `
            -Detail 'Analyse the minidump in C:\Windows\Minidump to identify the faulting driver.' `
            -FirstSeen ($bugchecks.TimeCreated | Measure-Object -Minimum).Minimum `
            -LastSeen ($bugchecks.TimeCreated | Measure-Object -Maximum).Maximum `
            -Count $bugchecks.Count
    }

    # Disk errors are an early warning of imminent drive failure.
    $diskErrors = Get-EventsSafe -Computer $Computer -FilterHashtable @{
        LogName = 'System'; ProviderName = 'disk', 'Disk', 'Ntfs'; Level = 1, 2; StartTime = $script:Since
    }

    if ($diskErrors.Count -gt 0) {
        Add-Finding -Computer $Computer -Category 'SystemStability' -Severity 'Critical' `
            -Summary "$($diskErrors.Count) disk or filesystem error(s)" `
            -Detail 'Back up immediately and run chkdsk. Disk errors frequently precede drive failure.' `
            -FirstSeen ($diskErrors.TimeCreated | Measure-Object -Minimum).Minimum `
            -LastSeen ($diskErrors.TimeCreated | Measure-Object -Maximum).Maximum `
            -Count $diskErrors.Count
    }
}

function Measure-ApplicationErrors {
    param([string]$Computer)
    Write-Step "$Computer - summarising application errors"

    $events = Get-EventsSafe -Computer $Computer -FilterHashtable @{
        LogName = 'Application'; Level = 1, 2; StartTime = $script:Since
    }

    if ($events.Count -eq 0) {
        Add-Finding -Computer $Computer -Category 'Applications' -Severity 'Info' `
            -Summary 'No application errors in the window' -Count 0
        return
    }

    foreach ($group in ($events | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 10)) {
        $severity = if ($group.Count -gt 50) { 'Warning' } else { 'Info' }
        Add-Finding -Computer $Computer -Category 'Applications' -Severity $severity `
            -Summary "$($group.Count) error(s) from '$($group.Name)'" `
            -Detail (($group.Group | Select-Object -First 1).Message -split "`n" | Select-Object -First 1) `
            -FirstSeen ($group.Group.TimeCreated | Measure-Object -Minimum).Minimum `
            -LastSeen ($group.Group.TimeCreated | Measure-Object -Maximum).Maximum `
            -Count $group.Count
    }
}

#endregion

#region Reporting -------------------------------------------------------------

function New-HtmlReport {
    $counts = @{
        Critical = @($script:Findings | Where-Object Severity -eq 'Critical').Count
        Warning  = @($script:Findings | Where-Object Severity -eq 'Warning').Count
        Info     = @($script:Findings | Where-Object Severity -eq 'Info').Count
    }

    $sections = foreach ($cat in ($script:Findings | Select-Object -ExpandProperty Category -Unique | Sort-Object)) {
        $rows = $script:Findings |
            Where-Object Category -eq $cat |
            Sort-Object @{ E = { switch ($_.Severity) { 'Critical' { 0 } 'Warning' { 1 } default { 2 } } } }, LastSeen -Descending

        $body = foreach ($f in $rows) {
            $when = if ($f.Count -le 1 -and $f.LastSeen -ne [datetime]::MinValue) {
                $f.LastSeen.ToString('yyyy-MM-dd HH:mm')
            } elseif ($f.LastSeen -ne [datetime]::MinValue) {
                "{0} - {1}" -f $f.FirstSeen.ToString('MM-dd HH:mm'), $f.LastSeen.ToString('MM-dd HH:mm')
            } else { '-' }

            @"
      <tr class="$($f.Severity.ToLower())">
        <td><span class="badge $($f.Severity.ToLower())">$($f.Severity)</span></td>
        <td>$([System.Web.HttpUtility]::HtmlEncode($f.Computer))</td>
        <td>$([System.Web.HttpUtility]::HtmlEncode($f.Summary))</td>
        <td class="when">$when</td>
        <td>$([System.Web.HttpUtility]::HtmlEncode($f.Detail))</td>
      </tr>
"@
        }

        @"
<h2>$cat <span class="count">$($rows.Count)</span></h2>
<table>
  <thead><tr><th>Severity</th><th>Computer</th><th>Finding</th><th>When</th><th>Detail</th></tr></thead>
  <tbody>
$($body -join "`n")
  </tbody>
</table>
"@
    }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Event Log Analysis - $($ComputerName -join ', ')</title>
<style>
  body { font-family:'Segoe UI',Tahoma,sans-serif; margin:2rem; background:#f5f6f8; color:#1b1f23; }
  h1 { margin-bottom:.25rem; }
  h2 { margin-top:2rem; font-size:1.15rem; border-bottom:2px solid #d0d7de; padding-bottom:.35rem; }
  .meta { color:#586069; margin-bottom:1.5rem; }
  .count { background:#d0d7de; border-radius:999px; padding:.1rem .55rem; font-size:.8rem; margin-left:.4rem; }
  .summary { display:flex; gap:1rem; margin-bottom:1.5rem; flex-wrap:wrap; }
  .card { background:#fff; border-radius:8px; padding:1rem 1.5rem; box-shadow:0 1px 3px rgba(0,0,0,.1); min-width:120px; }
  .card .n { font-size:2rem; font-weight:600; display:block; }
  table { width:100%; border-collapse:collapse; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.1); }
  th,td { text-align:left; padding:.5rem .75rem; border-bottom:1px solid #e1e4e8; font-size:.86rem; vertical-align:top; }
  th { background:#24292e; color:#fff; }
  tr:last-child td { border-bottom:none; }
  tr.critical { background:#ffeef0; }
  tr.warning { background:#fff8c5; }
  .when { white-space:nowrap; color:#586069; font-size:.8rem; }
  .badge { display:inline-block; padding:.12rem .5rem; border-radius:999px; font-size:.75rem; font-weight:600; color:#fff; }
  .badge.critical { background:#cf222e; }
  .badge.warning { background:#bf8700; }
  .badge.info { background:#57606a; }
</style>
</head>
<body>
  <h1>Event Log Analysis</h1>
  <div class="meta">
    <strong>$($ComputerName -join ', ')</strong> &middot;
    window: last $Hours hour(s) (since $($script:Since.ToString('yyyy-MM-dd HH:mm'))) &middot;
    generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  </div>
  <div class="summary">
    <div class="card"><span class="n" style="color:#cf222e">$($counts.Critical)</span>Critical</div>
    <div class="card"><span class="n" style="color:#bf8700">$($counts.Warning)</span>Warning</div>
    <div class="card"><span class="n" style="color:#57606a">$($counts.Info)</span>Info</div>
  </div>
$($sections -join "`n")
</body>
</html>
"@
}

#endregion

#region Main ------------------------------------------------------------------

Add-Type -AssemblyName System.Web

Write-Host ''
Write-Host '=== Event Log Analyzer ===' -ForegroundColor Green
Write-Host ("Window: last {0} hour(s), since {1}" -f $Hours, $script:Since.ToString('yyyy-MM-dd HH:mm'))
Write-Host ''

if (-not (Test-IsAdministrator)) {
    Write-Warning 'Not running as Administrator - the Security log is unreadable, so logon, lockout, and account-change analysis will be empty.'
}

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$analyses = [ordered]@{
    Logons          = ${function:Measure-LogonActivity}
    Lockouts        = ${function:Measure-Lockouts}
    PrivilegeUse    = ${function:Measure-PrivilegeUse}
    AccountChanges  = ${function:Measure-AccountChanges}
    Services        = ${function:Measure-ServiceActivity}
    LogClearing     = ${function:Measure-LogClearing}
    SystemStability = ${function:Measure-SystemStability}
    Applications    = ${function:Measure-ApplicationErrors}
}

foreach ($computer in $ComputerName) {
    foreach ($name in $analyses.Keys) {
        if ($name -notin $IncludeCategories) { continue }
        try {
            & $analyses[$name] -Computer $computer
        } catch {
            Write-Warning "$computer / $name failed: $($_.Exception.Message)"
            Add-Finding -Computer $computer -Category $name -Severity 'Warning' `
                -Summary 'Analysis failed' -Detail $_.Exception.Message
        }
    }
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportFile = Join-Path $OutputPath "EventAnalysis_$($env:COMPUTERNAME)_$stamp.html"
New-HtmlReport | Out-File -FilePath $reportFile -Encoding UTF8

if ($ExportCsv) {
    $csvFile = Join-Path $OutputPath "EventAnalysis_$($env:COMPUTERNAME)_$stamp.csv"
    $script:Findings | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "CSV exported to: $csvFile" -ForegroundColor Green
}

$critical = @($script:Findings | Where-Object Severity -eq 'Critical').Count
$warning  = @($script:Findings | Where-Object Severity -eq 'Warning').Count

Write-Host ''
Write-Host "Critical: $critical   Warning: $warning" -ForegroundColor $(if ($critical) { 'Red' } elseif ($warning) { 'Yellow' } else { 'Green' })

foreach ($f in ($script:Findings | Where-Object Severity -eq 'Critical')) {
    Write-Host ("  [!] {0}: {1}" -f $f.Category, $f.Summary) -ForegroundColor Red
}

Write-Host "Report saved to: $reportFile" -ForegroundColor Green
Write-Host ''

$script:Findings

#endregion
