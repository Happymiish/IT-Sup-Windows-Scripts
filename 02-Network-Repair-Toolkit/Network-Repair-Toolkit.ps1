<#
.SYNOPSIS
    Diagnoses and repairs common Windows network connectivity problems.

.DESCRIPTION
    Runs a layered diagnostic sweep (adapter -> IP -> gateway -> DNS -> internet ->
    HTTPS) to pinpoint where connectivity breaks down, then optionally applies the
    standard remediation stack: DNS flush, IP release/renew, Winsock reset, TCP/IP
    stack reset, and adapter restart.

    Diagnostics run read-only by default. Repairs only run when -Repair is supplied,
    and every repair honours -WhatIf / -Confirm.

.PARAMETER Repair
    Apply repair actions after diagnostics. Without this switch the script only reports.

.PARAMETER RepairLevel
    Which remediation tier to apply when -Repair is used.
      Safe        - DNS flush, ARP/NetBIOS cache clear, IP renew. No reboot needed.
      Standard    - Safe actions plus adapter restart and proxy reset. Brief outage.
      Aggressive  - Standard actions plus Winsock and TCP/IP stack reset. Requires reboot.
    Default is Safe.

.PARAMETER TestTargets
    Hostnames or IPs used for the internet reachability test.

.PARAMETER LogPath
    Directory for the transcript log. Defaults to the user's Desktop.

.EXAMPLE
    .\Network-Repair-Toolkit.ps1
    Diagnose only; print a summary of where the connection breaks.

.EXAMPLE
    .\Network-Repair-Toolkit.ps1 -Repair
    Diagnose, then apply the Safe repair tier.

.EXAMPLE
    .\Network-Repair-Toolkit.ps1 -Repair -RepairLevel Aggressive -WhatIf
    Preview exactly which aggressive repair commands would run.

.NOTES
    Run as Administrator. Aggressive repairs require a reboot to take full effect.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [switch]$Repair,
    [ValidateSet('Safe', 'Standard', 'Aggressive')][string]$RepairLevel = 'Safe',
    [string[]]$TestTargets = @('8.8.8.8', '1.1.1.1'),
    [string]$LogPath = [Environment]::GetFolderPath('Desktop')
)

$script:Results = New-Object System.Collections.Generic.List[object]
$script:ActionsTaken = New-Object System.Collections.Generic.List[string]

#region Helpers ---------------------------------------------------------------

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Layer,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Fail', 'Warn', 'Info')][string]$Result,
        [string]$Detail = ''
    )
    $script:Results.Add([pscustomobject]@{
        Layer  = $Layer
        Result = $Result
        Detail = $Detail
    })

    $colour = switch ($Result) {
        'Pass' { 'Green' }
        'Fail' { 'Red' }
        'Warn' { 'Yellow' }
        default { 'Gray' }
    }
    $symbol = switch ($Result) {
        'Pass' { '[+]' }
        'Fail' { '[X]' }
        'Warn' { '[!]' }
        default { '[i]' }
    }
    Write-Host ("{0} {1,-22} {2}" -f $symbol, $Layer, $Detail) -ForegroundColor $colour
}

function Test-IsAdministrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-RepairAction {
    <#
        Wraps a native command in ShouldProcess so -WhatIf and -Confirm behave
        correctly, and records what was actually executed.
    #>
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, $Description)) {
        return
    }

    Write-Host "  -> $Description" -ForegroundColor Cyan
    try {
        $output = & $Action 2>&1
        $script:ActionsTaken.Add("$Description - completed")
        if ($output) {
            $output | Where-Object { $_ -match '\S' } |
                Select-Object -First 3 |
                ForEach-Object { Write-Host "     $_" -ForegroundColor DarkGray }
        }
    } catch {
        $script:ActionsTaken.Add("$Description - FAILED: $($_.Exception.Message)")
        Write-Warning "     $($_.Exception.Message)"
    }
}

#endregion

#region Diagnostics -----------------------------------------------------------

function Test-AdapterLayer {
    $adapters = Get-CimInstance Win32_NetworkAdapter |
        Where-Object { $_.PhysicalAdapter -and $_.NetEnabled -ne $null }

    $up = $adapters | Where-Object NetEnabled -eq $true
    if (-not $up) {
        Add-Result 'Adapter' 'Fail' 'No enabled physical network adapter found'
        return $false
    }

    foreach ($a in $up) {
        Add-Result 'Adapter' 'Pass' "$($a.Name) is enabled"
    }

    $disabled = $adapters | Where-Object NetEnabled -eq $false
    foreach ($a in $disabled) {
        Add-Result 'Adapter' 'Warn' "$($a.Name) is disabled"
    }
    return $true
}

function Test-IpLayer {
    $configs = Get-CimInstance Win32_NetworkAdapterConfiguration |
        Where-Object { $_.IPEnabled }

    if (-not $configs) {
        Add-Result 'IP address' 'Fail' 'No adapter has an IP configuration'
        return $false
    }

    $healthy = $false
    foreach ($c in $configs) {
        $v4 = $c.IPAddress | Where-Object { $_ -notmatch ':' }
        foreach ($ip in $v4) {
            if ($ip -like '169.254.*') {
                Add-Result 'IP address' 'Fail' "$($c.Description): APIPA address $ip (DHCP failed)"
            } else {
                Add-Result 'IP address' 'Pass' "$($c.Description): $ip"
                $healthy = $true
            }
        }
        if ($c.DHCPEnabled) {
            Add-Result 'DHCP' 'Info' "$($c.Description): DHCP server $($c.DHCPServer)"
        }
    }
    return $healthy
}

function Test-GatewayLayer {
    $gateways = Get-CimInstance Win32_NetworkAdapterConfiguration |
        Where-Object { $_.IPEnabled -and $_.DefaultIPGateway } |
        ForEach-Object { $_.DefaultIPGateway } |
        Where-Object { $_ -notmatch ':' } |
        Select-Object -Unique

    if (-not $gateways) {
        Add-Result 'Gateway' 'Fail' 'No default gateway configured'
        return $false
    }

    $reachable = $false
    foreach ($gw in $gateways) {
        if (Test-Connection -ComputerName $gw -Count 2 -Quiet -ErrorAction SilentlyContinue) {
            Add-Result 'Gateway' 'Pass' "$gw responds to ping"
            $reachable = $true
        } else {
            Add-Result 'Gateway' 'Fail' "$gw is not responding (LAN or router issue)"
        }
    }
    return $reachable
}

function Test-InternetLayer {
    $reachable = $false
    foreach ($target in $TestTargets) {
        if (Test-Connection -ComputerName $target -Count 2 -Quiet -ErrorAction SilentlyContinue) {
            Add-Result 'Internet (ICMP)' 'Pass' "$target reachable"
            $reachable = $true
        } else {
            Add-Result 'Internet (ICMP)' 'Warn' "$target unreachable (may be blocked by firewall)"
        }
    }
    return $reachable
}

function Test-DnsLayer {
    $servers = Get-CimInstance Win32_NetworkAdapterConfiguration |
        Where-Object { $_.IPEnabled -and $_.DNSServerSearchOrder } |
        ForEach-Object { $_.DNSServerSearchOrder } |
        Select-Object -Unique

    if ($servers) {
        Add-Result 'DNS servers' 'Info' ($servers -join ', ')
    } else {
        Add-Result 'DNS servers' 'Warn' 'No DNS servers configured'
    }

    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $null = [Net.Dns]::GetHostEntry('www.microsoft.com')
        $sw.Stop()
        $ms = $sw.ElapsedMilliseconds
        if ($ms -gt 2000) {
            Add-Result 'DNS resolution' 'Warn' "Resolved www.microsoft.com but took ${ms}ms"
        } else {
            Add-Result 'DNS resolution' 'Pass' "Resolved www.microsoft.com in ${ms}ms"
        }
        return $true
    } catch {
        Add-Result 'DNS resolution' 'Fail' 'Cannot resolve www.microsoft.com'
        return $false
    }
}

function Test-HttpsLayer {
    # TLS 1.2 explicitly - older defaults fail against modern endpoints.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $url = 'https://www.msftconnecttest.com/connecttest.txt'

    try {
        $request = [Net.WebRequest]::Create($url)
        $request.Timeout   = 10000
        $request.Method    = 'GET'
        $request.UserAgent = 'NetworkRepairToolkit'
        $response = $request.GetResponse()
        Add-Result 'HTTPS' 'Pass' "$url returned $([int]$response.StatusCode)"
        $response.Close()
        return $true
    } catch [Net.WebException] {
        # An HTTP status response - even 403 or 404 - proves the TCP and TLS
        # handshake succeeded, so connectivity is fine. Only transport-level
        # failures (DNS, timeout, refused) count as a real fault.
        if ($_.Exception.Response) {
            $code = [int]$_.Exception.Response.StatusCode
            Add-Result 'HTTPS' 'Pass' "$url returned HTTP $code - transport is healthy"
            $_.Exception.Response.Close()
            return $true
        }

        # TrustFailure means the TCP connection succeeded but the presented
        # certificate was not trusted - the signature of a TLS-inspecting
        # proxy whose root CA is missing from this machine's trust store.
        # Routing is fine, so this is not a connectivity fault.
        if ($_.Exception.Status -eq [Net.WebExceptionStatus]::TrustFailure) {
            Add-Result 'HTTPS' 'Warn' 'Certificate not trusted - TLS inspection proxy without its root CA installed'
            return $true
        }

        Add-Result 'HTTPS' 'Fail' "$($_.Exception.Status): $($_.Exception.Message)"
        return $false
    } catch {
        Add-Result 'HTTPS' 'Fail' "HTTPS request failed: $($_.Exception.Message)"
        return $false
    }
}

function Test-ProxyLayer {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    try {
        $settings = Get-ItemProperty -Path $key -ErrorAction Stop
        if ($settings.ProxyEnable -eq 1) {
            Add-Result 'Proxy' 'Warn' "Proxy enabled: $($settings.ProxyServer)"
        } else {
            Add-Result 'Proxy' 'Pass' 'No proxy configured'
        }
    } catch {
        Add-Result 'Proxy' 'Info' 'Proxy settings unavailable'
    }
}

#endregion

#region Repairs ---------------------------------------------------------------

function Invoke-SafeRepairs {
    Write-Host ''
    Write-Host 'Applying Safe repairs...' -ForegroundColor Yellow

    Invoke-RepairAction 'Flush DNS resolver cache' { ipconfig /flushdns }
    Invoke-RepairAction 'Re-register DNS records'  { ipconfig /registerdns }
    Invoke-RepairAction 'Clear ARP cache'          { netsh interface ip delete arpcache }
    Invoke-RepairAction 'Release DHCP lease'       { ipconfig /release }
    Invoke-RepairAction 'Renew DHCP lease'         { ipconfig /renew }
}

function Invoke-StandardRepairs {
    Write-Host ''
    Write-Host 'Applying Standard repairs...' -ForegroundColor Yellow

    Invoke-RepairAction 'Reset WinHTTP proxy' { netsh winhttp reset proxy }

    $adapters = Get-CimInstance Win32_NetworkAdapter |
        Where-Object { $_.PhysicalAdapter -and $_.NetEnabled -eq $true }

    foreach ($a in $adapters) {
        Invoke-RepairAction "Restart adapter '$($a.Name)'" {
            if (Get-Command Restart-NetAdapter -ErrorAction SilentlyContinue) {
                Restart-NetAdapter -Name $a.NetConnectionID -Confirm:$false
            } else {
                netsh interface set interface name="$($a.NetConnectionID)" admin=disabled
                Start-Sleep -Seconds 3
                netsh interface set interface name="$($a.NetConnectionID)" admin=enabled
            }
        }.GetNewClosure()
    }
}

function Invoke-AggressiveRepairs {
    Write-Host ''
    Write-Host 'Applying Aggressive repairs (reboot required)...' -ForegroundColor Yellow

    # Deliberately excluded: 'netsh advfirewall reset'. It wipes every custom and
    # group-policy-delivered firewall rule and is almost never the cause of a
    # connectivity fault. Run it manually if you genuinely need it.
    Invoke-RepairAction 'Reset Winsock catalog' { netsh winsock reset }
    Invoke-RepairAction 'Reset TCP/IP stack'    { netsh int ip reset }
    Invoke-RepairAction 'Reset IPv6 stack'      { netsh int ipv6 reset }
}

#endregion

#region Main ------------------------------------------------------------------

Write-Host ''
Write-Host '=== Network Repair Toolkit ===' -ForegroundColor Green
Write-Host ''

$isAdmin = Test-IsAdministrator
if ($Repair -and -not $isAdmin) {
    throw 'Repair actions require Administrator privileges. Re-run PowerShell as Administrator.'
}
if (-not $isAdmin) {
    Write-Warning 'Running without Administrator rights - diagnostics only.'
}

if (-not (Test-Path -LiteralPath $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}
$logFile = Join-Path $LogPath ("NetworkRepair_{0}_{1}.log" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))

# -WhatIf:$false - logging the run is not a change to the system, and letting
# -WhatIf suppress the transcript leaves Stop-Transcript with nothing to close.
$transcribing = $false
try {
    Start-Transcript -Path $logFile -Force -WhatIf:$false | Out-Null
    $transcribing = $true
} catch {
    Write-Warning "Could not start transcript: $($_.Exception.Message)"
}

try {
    Write-Host '--- Diagnostics -------------------------------------------' -ForegroundColor White
    $adapterOk  = Test-AdapterLayer
    $ipOk       = if ($adapterOk) { Test-IpLayer } else { $false }
    $gatewayOk  = if ($ipOk) { Test-GatewayLayer } else { $false }
    $internetOk = if ($gatewayOk) { Test-InternetLayer } else { $false }
    $dnsOk      = Test-DnsLayer
    $httpsOk    = Test-HttpsLayer
    Test-ProxyLayer

    # A TLS-inspection warning means traffic flows but certificates are untrusted -
    # worth reporting even though it is not a routing fault.
    $tlsInspected = [bool]($script:Results | Where-Object { $_.Layer -eq 'HTTPS' -and $_.Result -eq 'Warn' })

    # Identify the first failing layer so the tech knows where to focus.
    $diagnosis = if (-not $adapterOk) { 'No enabled network adapter - check hardware, drivers, or Wi-Fi switch.' }
                 elseif (-not $ipOk)   { 'No valid IP address - DHCP is failing. Check the DHCP server or set a static IP.' }
                 elseif (-not $gatewayOk) { 'Gateway unreachable - problem is on the local network (cable, switch, or router).' }
                 elseif (-not $dnsOk)  { 'DNS resolution failing - check DNS servers; try 1.1.1.1 or 8.8.8.8.' }
                 elseif (-not $httpsOk) { 'HTTPS blocked while lower layers work - suspect proxy, firewall, or TLS inspection.' }
                 elseif ($tlsInspected) { 'Connectivity is fine, but HTTPS certificates are not trusted. A TLS-inspecting proxy is in use and its root CA is missing from this machine. Install the corporate root certificate.' }
                 elseif (-not $internetOk) { 'ICMP blocked but HTTPS works - likely normal for a filtered network.' }
                 else { 'All layers healthy - no network fault detected.' }

    Write-Host ''
    Write-Host '--- Diagnosis ---------------------------------------------' -ForegroundColor White
    Write-Host $diagnosis -ForegroundColor $(if ($httpsOk) { 'Green' } else { 'Yellow' })

    if ($Repair) {
        Write-Host ''
        Write-Host '--- Repairs -----------------------------------------------' -ForegroundColor White

        Invoke-SafeRepairs
        if ($RepairLevel -in 'Standard', 'Aggressive') { Invoke-StandardRepairs }
        if ($RepairLevel -eq 'Aggressive')             { Invoke-AggressiveRepairs }

        Write-Host ''
        Write-Host '--- Re-test -----------------------------------------------' -ForegroundColor White
        Start-Sleep -Seconds 5
        $script:Results.Clear()
        $null = Test-IpLayer
        $null = Test-DnsLayer
        $postHttps = Test-HttpsLayer

        Write-Host ''
        if ($postHttps) {
            Write-Host 'Connectivity restored.' -ForegroundColor Green
        } elseif ($RepairLevel -eq 'Aggressive') {
            Write-Host 'Still failing. A reboot is required for Winsock/TCP-IP resets to take effect.' -ForegroundColor Yellow
        } else {
            Write-Host "Still failing. Try -RepairLevel Standard or Aggressive." -ForegroundColor Yellow
        }
    } else {
        Write-Host ''
        Write-Host 'Diagnostics only. Re-run with -Repair to apply fixes.' -ForegroundColor Cyan
    }

    if ($script:ActionsTaken.Count -gt 0) {
        Write-Host ''
        Write-Host '--- Actions taken -----------------------------------------' -ForegroundColor White
        $script:ActionsTaken | ForEach-Object { Write-Host "  $_" }
    }
} finally {
    if ($transcribing) {
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
        Write-Host ''
        Write-Host "Log saved to: $logFile" -ForegroundColor Green
        Write-Host ''
    }
}

#endregion
