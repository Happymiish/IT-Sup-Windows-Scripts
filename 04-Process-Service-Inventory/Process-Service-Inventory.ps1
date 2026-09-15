<#
.SYNOPSIS
    Inventories running processes, services, listening ports, and active network
    connections, flagging patterns that warrant a closer look.

.DESCRIPTION
    Builds a single HTML report answering "what is running on this machine?" -
    including the command line of each process, which process owns each listening
    port, and which automatic services failed to start.

    Heuristics flag known dual-use tooling, processes running from user-writable
    directories, and unusual parent/child relationships. Flags are LEADS, not
    verdicts: legitimate software trips several of them. Always corroborate.

    Entirely read-only. Nothing is stopped, killed, or modified.

.PARAMETER OutputPath
    Directory for the HTML report. Defaults to the user's Desktop.

.PARAMETER Sections
    Which sections to collect: Processes, Services, Listeners, Connections.
    Defaults to all four.

.PARAMETER IncludeCommandLine
    Include full command lines in the process table. Verbose but invaluable for
    incident response. Command lines can contain credentials - handle the report
    accordingly.

.PARAMETER SuspiciousOnly
    Report only flagged processes and problem services. Useful for fast triage.

.PARAMETER TopProcessCount
    How many processes to list, ordered by memory use. Default 20. Flagged
    processes are always included regardless of this limit.

.EXAMPLE
    .\Process-Service-Inventory.ps1

.EXAMPLE
    .\Process-Service-Inventory.ps1 -IncludeCommandLine -OutputPath \\fileserver\ir

.EXAMPLE
    .\Process-Service-Inventory.ps1 -SuspiciousOnly -Sections Processes,Listeners

.NOTES
    Run as Administrator. Without elevation, command lines and owning PIDs for
    other users' processes are unavailable.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = [Environment]::GetFolderPath('Desktop'),

    [ValidateSet('Processes', 'Services', 'Listeners', 'Connections')]
    [string[]]$Sections = @('Processes', 'Services', 'Listeners', 'Connections'),

    [switch]$IncludeCommandLine,
    [switch]$SuspiciousOnly,
    [ValidateRange(5, 500)][int]$TopProcessCount = 20
)

$ErrorActionPreference = 'Stop'

$script:Processes   = @()
$script:Services    = @()
$script:Listeners   = @()
$script:Connections = @()

#region Reference data --------------------------------------------------------

# Dual-use tooling. Legitimate for admins, also standard attacker tradecraft.
# Presence alone is not malicious - unexpected presence is what matters.
$script:DualUseTools = @(
    'mimikatz', 'procdump', 'psexec', 'psexesvc', 'paexec', 'wce',
    'lazagne', 'rubeus', 'seatbelt', 'sharphound', 'bloodhound',
    'nc', 'ncat', 'netcat', 'socat', 'plink', 'ngrok', 'chisel',
    'anydesk', 'teamviewer', 'ultravnc', 'tightvnc', 'vncserver',
    'rclone', 'megacmd', 'winscp'
)

# Parent -> child pairs that are unusual on a normal workstation.
$script:OddParentChild = @(
    @{ Parent = 'winword';    Child = @('cmd', 'powershell', 'wscript', 'cscript', 'mshta') },
    @{ Parent = 'excel';      Child = @('cmd', 'powershell', 'wscript', 'cscript', 'mshta') },
    @{ Parent = 'powerpnt';   Child = @('cmd', 'powershell', 'wscript', 'cscript', 'mshta') },
    @{ Parent = 'outlook';    Child = @('cmd', 'powershell', 'wscript', 'cscript', 'mshta') },
    @{ Parent = 'acrord32';   Child = @('cmd', 'powershell', 'wscript', 'cscript') },
    @{ Parent = 'w3wp';       Child = @('cmd', 'powershell') },
    @{ Parent = 'sqlservr';   Child = @('cmd', 'powershell') },
    @{ Parent = 'wmiprvse';   Child = @('cmd', 'powershell') }
)

# Directories any user can write to. Code executing from here deserves scrutiny.
# Plain literal fragments - Test-UserWritablePath regex-escapes them before use.
# ProgramData is deliberately omitted: too many legitimate agents install there
# for it to be a useful signal on its own.
$script:UserWritablePatterns = @(
    '\AppData\Local\Temp\',
    '\Windows\Temp\',
    '\Downloads\',
    '\Users\Public\',
    '\AppData\Roaming\Microsoft\Windows\Start Menu\'
)

# Ports that should not normally be listening on a workstation.
$script:NotableListenPorts = @{
    23    = 'Telnet - cleartext, should not be running'
    3389  = 'RDP - confirm this is intentional and firewalled'
    4444  = 'Common Metasploit default handler port'
    5555  = 'Commonly used by ADB and various RATs'
    5900  = 'VNC - confirm this is an approved remote tool'
    8080  = 'Alternate HTTP - often a dev server left running'
    1080  = 'SOCKS proxy - can indicate tunnelling'
    9001  = 'Tor / common backdoor port'
}

#endregion

#region Helpers ---------------------------------------------------------------

function Write-Step { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }

function Test-IsAdministrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-BaseName {
    param([string]$Path)
    if (-not $Path) { return '' }
    try { return [IO.Path]::GetFileNameWithoutExtension($Path).ToLower() }
    catch { return '' }
}

function Test-UserWritablePath {
    param([string]$Path)
    if (-not $Path) { return $false }
    foreach ($pattern in $script:UserWritablePatterns) {
        if ($Path -match [regex]::Escape($pattern)) { return $true }
    }
    return $false
}

#endregion

#region Collection ------------------------------------------------------------

function Get-ProcessInventory {
    Write-Step 'Enumerating processes'

    # Win32_Process gives command line and parent PID, which Get-Process does not.
    $raw = Get-CimInstance Win32_Process
    $byPid = @{}
    foreach ($p in $raw) { $byPid[[int]$p.ProcessId] = $p }

    # Owner lookup is a separate, relatively slow call - cache per process.
    $results = foreach ($p in $raw) {
        $name       = $p.Name -replace '\.exe$', ''
        $nameLower  = $name.ToLower()
        $parent     = $byPid[[int]$p.ParentProcessId]
        $parentName = if ($parent) { ($parent.Name -replace '\.exe$', '').ToLower() } else { '(exited)' }

        $flags = New-Object System.Collections.Generic.List[string]

        if ($nameLower -in $script:DualUseTools) {
            $flags.Add('Dual-use tool - confirm it is expected here')
        }

        if (Test-UserWritablePath $p.ExecutablePath) {
            $flags.Add('Running from a user-writable directory')
        }

        foreach ($rule in $script:OddParentChild) {
            if ($parentName -eq $rule.Parent -and $nameLower -in $rule.Child) {
                $flags.Add("Spawned by $($rule.Parent) - unusual parent for this process")
            }
        }

        # Encoded PowerShell is a classic obfuscation technique. Note that some
        # legitimate management tooling also uses it.
        if ($nameLower -in 'powershell', 'pwsh' -and $p.CommandLine -match '\s-[eE][ncodeman]*\s+[A-Za-z0-9+/=]{40,}') {
            $flags.Add('Base64-encoded PowerShell command line')
        }

        if ($nameLower -in 'powershell', 'pwsh' -and $p.CommandLine -match '(?i)(downloadstring|downloadfile|invoke-webrequest|iwr|frombase64string|-w\s+hidden|-windowstyle\s+hidden)') {
            $flags.Add('PowerShell download or hidden-window switches')
        }

        $owner = ''
        try {
            $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
            if ($o.User) { $owner = "$($o.Domain)\$($o.User)" }
        } catch { $owner = '(unavailable)' }

        [pscustomobject]@{
            Name        = $name
            ProcessId   = [int]$p.ProcessId
            ParentName  = $parentName
            ParentPid   = [int]$p.ParentProcessId
            Owner       = $owner
            MemoryMB    = [math]::Round($p.WorkingSetSize / 1MB, 1)
            Path        = $p.ExecutablePath
            CommandLine = $p.CommandLine
            Flags       = $flags
            IsFlagged   = $flags.Count -gt 0
        }
    }

    $script:Processes = $results | Sort-Object MemoryMB -Descending
    Write-Host ("    {0} processes, {1} flagged" -f $script:Processes.Count,
        ($script:Processes | Where-Object IsFlagged).Count)
}

function Get-ServiceInventory {
    Write-Step 'Enumerating services'

    $results = foreach ($s in Get-CimInstance Win32_Service) {
        $flags = New-Object System.Collections.Generic.List[string]

        if ($s.StartMode -eq 'Auto' -and $s.State -ne 'Running') {
            $flags.Add('Set to automatic but not running')
        }

        # An unquoted path containing spaces allows privilege escalation by
        # planting an executable earlier in the path. Real, commonly missed.
        if ($s.PathName -and $s.PathName -notmatch '^\s*"' -and $s.PathName -match '^[^"]*\s[^"]*\\') {
            $binary = ($s.PathName -split '\s+\-|\s+/')[0].Trim()
            if ($binary -match '\s') {
                $flags.Add('Unquoted service path containing spaces - privilege escalation risk')
            }
        }

        if (Test-UserWritablePath $s.PathName) {
            $flags.Add('Binary located in a user-writable directory')
        }

        if ($s.StartName -and $s.StartName -notmatch '(?i)^(LocalSystem|NT AUTHORITY\\|NT Service\\)') {
            $flags.Add("Runs as a named account: $($s.StartName)")
        }

        [pscustomobject]@{
            Name        = $s.Name
            DisplayName = $s.DisplayName
            State       = $s.State
            StartMode   = $s.StartMode
            Account     = $s.StartName
            Path        = $s.PathName
            Flags       = $flags
            IsFlagged   = $flags.Count -gt 0
        }
    }

    $script:Services = $results | Sort-Object DisplayName
    Write-Host ("    {0} services, {1} flagged" -f $script:Services.Count,
        ($script:Services | Where-Object IsFlagged).Count)
}

function Get-NetworkInventory {
    Write-Step 'Mapping network sockets to processes'

    $procNames = @{}
    $procPaths = @{}
    foreach ($p in Get-CimInstance Win32_Process) {
        $procNames[[int]$p.ProcessId] = ($p.Name -replace '\.exe$', '')
        $procPaths[[int]$p.ProcessId] = $p.ExecutablePath
    }

    $listeners   = New-Object System.Collections.Generic.List[object]
    $connections = New-Object System.Collections.Generic.List[object]

    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        foreach ($c in Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            $pname = if ($c.OwningProcess -and $procNames.ContainsKey([int]$c.OwningProcess)) {
                $procNames[[int]$c.OwningProcess]
            } else { '(unknown)' }

            if ($c.State -eq 'Listen') {
                $flags = New-Object System.Collections.Generic.List[string]

                # Deliberately NOT flagging "listening on 0.0.0.0 on a high port".
                # Windows RPC assigns ephemeral listeners to lsass, wininit,
                # spoolsv and svchost on every boot, so that test is pure noise.
                if ($script:NotableListenPorts.ContainsKey([int]$c.LocalPort)) {
                    $flags.Add($script:NotableListenPorts[[int]$c.LocalPort])
                }
                if ($pname.ToLower() -in 'powershell', 'pwsh', 'cmd', 'wscript', 'cscript', 'rundll32') {
                    $flags.Add('Scripting host or shell is listening - highly unusual')
                }
                if (Test-UserWritablePath $procPaths[[int]$c.OwningProcess]) {
                    $flags.Add('Listening process runs from a user-writable directory')
                }

                $listeners.Add([pscustomobject]@{
                    Protocol  = 'TCP'
                    Address   = $c.LocalAddress
                    Port      = [int]$c.LocalPort
                    Process   = $pname
                    ProcessId = [int]$c.OwningProcess
                    Flags     = $flags
                    IsFlagged = $flags.Count -gt 0
                })
            }
            elseif ($c.State -eq 'Established' -and $c.RemoteAddress -notin '127.0.0.1', '::1') {
                $flags = New-Object System.Collections.Generic.List[string]

                if ($pname.ToLower() -in 'powershell', 'pwsh', 'cmd', 'wscript', 'cscript', 'rundll32', 'regsvr32', 'mshta') {
                    $flags.Add('Scripting host has an outbound connection')
                }
                if ([int]$c.RemotePort -in 4444, 1080, 9001, 6667) {
                    $flags.Add("Connection to notable port $($c.RemotePort)")
                }
                if (Test-UserWritablePath $procPaths[[int]$c.OwningProcess]) {
                    $flags.Add('Connecting process runs from a user-writable directory')
                }

                $connections.Add([pscustomobject]@{
                    Protocol   = 'TCP'
                    Local      = "$($c.LocalAddress):$($c.LocalPort)"
                    Remote     = "$($c.RemoteAddress):$($c.RemotePort)"
                    State      = $c.State
                    Process    = $pname
                    ProcessId  = [int]$c.OwningProcess
                    Flags      = $flags
                    IsFlagged  = $flags.Count -gt 0
                })
            }
        }

        foreach ($u in Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
            $pname = if ($u.OwningProcess -and $procNames.ContainsKey([int]$u.OwningProcess)) {
                $procNames[[int]$u.OwningProcess]
            } else { '(unknown)' }

            $listeners.Add([pscustomobject]@{
                Protocol  = 'UDP'
                Address   = $u.LocalAddress
                Port      = [int]$u.LocalPort
                Process   = $pname
                ProcessId = [int]$u.OwningProcess
                Flags     = New-Object System.Collections.Generic.List[string]
                IsFlagged = $false
            })
        }
    } else {
        # Fallback for older systems without the NetTCPIP module.
        Write-Warning 'Get-NetTCPConnection unavailable - falling back to netstat parsing.'
        $netstat = netstat -ano | Select-String -Pattern '^\s+(TCP|UDP)'
        foreach ($line in $netstat) {
            $parts = ($line -replace '^\s+', '') -split '\s+'
            if ($parts.Count -lt 4) { continue }

            $proto = $parts[0]
            $local = $parts[1]
            $state = if ($proto -eq 'TCP') { $parts[3] } else { 'LISTENING' }
            $ownPid = [int]$parts[-1]
            $pname = if ($procNames.ContainsKey($ownPid)) { $procNames[$ownPid] } else { '(unknown)' }
            $port  = [int]($local -split ':')[-1]

            if ($state -eq 'LISTENING') {
                $listeners.Add([pscustomobject]@{
                    Protocol  = $proto
                    Address   = ($local -replace ':\d+$', '')
                    Port      = $port
                    Process   = $pname
                    ProcessId = $ownPid
                    Flags     = New-Object System.Collections.Generic.List[string]
                    IsFlagged = $false
                })
            }
        }
    }

    # Dual-stack sockets appear twice (0.0.0.0 and ::). Collapse them.
    $script:Listeners = $listeners |
        Sort-Object Protocol, Port, Process |
        Group-Object { "$($_.Protocol)|$($_.Port)|$($_.ProcessId)" } |
        ForEach-Object { $_.Group[0] }

    $script:Connections = $connections | Sort-Object Process, Remote

    Write-Host ("    {0} listeners, {1} established connections" -f $script:Listeners.Count, $script:Connections.Count)
}

#endregion

#region Reporting -------------------------------------------------------------

function ConvertTo-HtmlTable {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string[]]$Columns,
        [string]$EmptyMessage = 'Nothing to report.'
    )

    if (-not $Rows -or $Rows.Count -eq 0) {
        return "<h2>$Title</h2><p class='empty'>$EmptyMessage</p>"
    }

    $head = ($Columns | ForEach-Object { "<th>$_</th>" }) -join ''
    $head += '<th>Notes</th>'

    $body = foreach ($r in $Rows) {
        $cls = if ($r.IsFlagged) { ' class="flagged"' } else { '' }
        $cells = foreach ($c in $Columns) {
            $v = $r.$c
            if ($null -eq $v) { $v = '' }
            "<td>$([System.Web.HttpUtility]::HtmlEncode([string]$v))</td>"
        }
        $notes = if ($r.Flags -and $r.Flags.Count -gt 0) {
            ($r.Flags | ForEach-Object { "<span class='flag'>$([System.Web.HttpUtility]::HtmlEncode($_))</span>" }) -join ' '
        } else { '' }
        "<tr$cls>$($cells -join '')<td>$notes</td></tr>"
    }

    return @"
<h2>$Title <span class="count">$($Rows.Count)</span></h2>
<table>
  <thead><tr>$head</tr></thead>
  <tbody>
$($body -join "`n")
  </tbody>
</table>
"@
}

function New-HtmlReport {
    $flaggedProcs = @($script:Processes | Where-Object IsFlagged)
    $flaggedSvcs  = @($script:Services  | Where-Object IsFlagged)
    $flaggedPorts = @($script:Listeners | Where-Object IsFlagged)
    $flaggedConns = @($script:Connections | Where-Object IsFlagged)
    $totalFlags   = $flaggedProcs.Count + $flaggedSvcs.Count + $flaggedPorts.Count + $flaggedConns.Count

    $procColumns = if ($IncludeCommandLine) {
        @('Name', 'ProcessId', 'ParentName', 'Owner', 'MemoryMB', 'CommandLine')
    } else {
        @('Name', 'ProcessId', 'ParentName', 'Owner', 'MemoryMB', 'Path')
    }

    $sections = New-Object System.Collections.Generic.List[string]

    if ('Processes' -in $Sections) {
        $rows = if ($SuspiciousOnly) {
            $flaggedProcs
        } else {
            # Always include flagged processes even if they fall outside the top N.
            @($script:Processes | Select-Object -First $TopProcessCount) +
            @($flaggedProcs | Where-Object { $_ -notin ($script:Processes | Select-Object -First $TopProcessCount) })
        }
        $sections.Add((ConvertTo-HtmlTable -Title 'Processes' -Rows $rows -Columns $procColumns))
    }

    if ('Services' -in $Sections) {
        $rows = if ($SuspiciousOnly) { $flaggedSvcs } else { $script:Services }
        $sections.Add((ConvertTo-HtmlTable -Title 'Services' -Rows $rows `
            -Columns @('DisplayName', 'Name', 'State', 'StartMode', 'Account')))
    }

    if ('Listeners' -in $Sections) {
        $rows = if ($SuspiciousOnly) { $flaggedPorts } else { $script:Listeners }
        $sections.Add((ConvertTo-HtmlTable -Title 'Listening ports' -Rows $rows `
            -Columns @('Protocol', 'Address', 'Port', 'Process', 'ProcessId')))
    }

    if ('Connections' -in $Sections) {
        $rows = if ($SuspiciousOnly) { $flaggedConns } else { $script:Connections }
        $sections.Add((ConvertTo-HtmlTable -Title 'Established connections' -Rows $rows `
            -Columns @('Local', 'Remote', 'Process', 'ProcessId') `
            -EmptyMessage 'No external established TCP connections at the time of capture.'))
    }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Process &amp; Service Inventory - $env:COMPUTERNAME</title>
<style>
  body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 2rem; background: #f5f6f8; color: #1b1f23; }
  h1 { margin-bottom: .25rem; }
  h2 { margin-top: 2rem; font-size: 1.15rem; border-bottom: 2px solid #d0d7de; padding-bottom: .35rem; }
  .meta { color: #586069; margin-bottom: 1.5rem; }
  .count { background: #d0d7de; border-radius: 999px; padding: .1rem .55rem; font-size: .8rem; margin-left: .4rem; }
  .banner { padding: .9rem 1.2rem; border-radius: 8px; margin-bottom: 1.5rem; font-weight: 600; }
  .banner.clean { background: #dafbe1; color: #116329; }
  .banner.alert { background: #fff8c5; color: #7d4e00; }
  .disclaimer { background:#fff; border-left:4px solid #0969da; padding:.8rem 1.1rem; border-radius:6px;
                margin-bottom:1.5rem; font-size:.9rem; color:#24292f; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px;
          overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
  th, td { text-align: left; padding: .5rem .75rem; border-bottom: 1px solid #e1e4e8;
           font-size: .85rem; vertical-align: top; word-break: break-word; }
  th { background: #24292e; color: #fff; }
  tr:last-child td { border-bottom: none; }
  tr.flagged { background: #fff8c5; }
  .flag { display:inline-block; background:#bf8700; color:#fff; border-radius:4px;
          padding:.1rem .45rem; font-size:.75rem; margin:.1rem .15rem .1rem 0; }
  .empty { color:#586069; font-style: italic; }
</style>
</head>
<body>
  <h1>Process &amp; Service Inventory</h1>
  <div class="meta"><strong>$env:COMPUTERNAME</strong> &middot; captured $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
  <div class="banner $(if ($totalFlags -gt 0) { 'alert' } else { 'clean' })">
    $(if ($totalFlags -gt 0) { "$totalFlags item(s) flagged for review" } else { 'No items flagged' })
  </div>
  <div class="disclaimer">
    <strong>Flags are leads, not verdicts.</strong> Legitimate administrative tooling, remote support
    software, and management agents routinely trip these heuristics. Corroborate against a known-good
    baseline for this machine before treating anything as an incident.
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
Write-Host '=== Process & Service Inventory ===' -ForegroundColor Green
Write-Host ''

if (-not (Test-IsAdministrator)) {
    Write-Warning 'Not running as Administrator - command lines and socket ownership for other users will be incomplete.'
}

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

if ('Processes' -in $Sections) { Get-ProcessInventory }
if ('Services'  -in $Sections) { Get-ServiceInventory }
if (('Listeners' -in $Sections) -or ('Connections' -in $Sections)) { Get-NetworkInventory }

$reportFile = Join-Path $OutputPath ("ProcessInventory_{0}_{1}.html" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-HtmlReport | Out-File -FilePath $reportFile -Encoding UTF8

$flagged = @($script:Processes | Where-Object IsFlagged).Count +
           @($script:Services  | Where-Object IsFlagged).Count +
           @($script:Listeners | Where-Object IsFlagged).Count +
           @($script:Connections | Where-Object IsFlagged).Count

Write-Host ''
Write-Host "Flagged for review: $flagged" -ForegroundColor $(if ($flagged) { 'Yellow' } else { 'Green' })
Write-Host "Report saved to: $reportFile" -ForegroundColor Green
Write-Host ''

if ($flagged -gt 0) {
    Write-Host 'Flagged items (review these first):' -ForegroundColor Yellow
    foreach ($p in ($script:Processes | Where-Object IsFlagged)) {
        Write-Host ("  [proc] {0} (PID {1}) - {2}" -f $p.Name, $p.ProcessId, ($p.Flags -join '; '))
    }
    foreach ($l in ($script:Listeners | Where-Object IsFlagged)) {
        Write-Host ("  [port] {0}/{1} {2} - {3}" -f $l.Protocol, $l.Port, $l.Process, ($l.Flags -join '; '))
    }
    foreach ($c in ($script:Connections | Where-Object IsFlagged)) {
        Write-Host ("  [conn] {0} -> {1} - {2}" -f $c.Process, $c.Remote, ($c.Flags -join '; '))
    }
    $svcFlagged = @($script:Services | Where-Object IsFlagged)
    if ($svcFlagged.Count -gt 0) {
        Write-Host ("  [svc]  {0} service(s) flagged - see the report" -f $svcFlagged.Count)
    }
    Write-Host ''
}

# Emit objects so the results can be filtered or piped downstream.
[pscustomobject]@{
    Processes   = $script:Processes
    Services    = $script:Services
    Listeners   = $script:Listeners
    Connections = $script:Connections
    ReportPath  = $reportFile
}

#endregion
