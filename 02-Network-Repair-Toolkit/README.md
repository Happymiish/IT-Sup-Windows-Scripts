# Network Repair Toolkit

Layered network diagnostics and tiered remediation for Windows. Tells you *where* connectivity breaks before it changes anything, then applies only the level of repair you ask for.

## Why this exists

The usual "have you tried `ipconfig /flushdns`?" approach fires a shotgun at the problem. This script tests each layer in order and reports the first one that fails, so you know whether you are dealing with a dead adapter, a DHCP failure, a router problem, a DNS issue, or a proxy intercepting HTTPS.

## Diagnostic layers

Tests run bottom-up and short-circuit sensibly:

1. **Adapter** — is a physical NIC present and enabled?
2. **IP address** — valid lease, or an APIPA `169.254.x.x` address indicating DHCP failure?
3. **Gateway** — does the default gateway respond?
4. **Internet (ICMP)** — are external hosts pingable?
5. **DNS** — are servers configured, and does resolution work (with timing)?
6. **HTTPS** — does a real TLS 1.2 request succeed?
7. **Proxy** — is a proxy configured that could explain HTTPS-only failures?

The script then prints a plain-English diagnosis naming the first failing layer and the likely cause.

## Repair tiers

Repairs run **only** with `-Repair`. Choose the tier with `-RepairLevel`:

| Tier | Actions | Impact |
|---|---|---|
| `Safe` (default) | Flush DNS cache, re-register DNS, clear ARP cache, release/renew DHCP | No outage, no reboot |
| `Standard` | Safe tier + reset WinHTTP proxy + restart each active adapter | Few seconds of downtime |
| `Aggressive` | Standard tier + Winsock reset, TCP/IP reset, IPv6 reset | **Requires a reboot** |

After repairs, the script re-tests IP, DNS, and HTTPS and reports whether connectivity was restored.

### What it deliberately does *not* do

`netsh advfirewall reset` is intentionally excluded. It destroys every custom and group-policy firewall rule and is rarely the cause of a connectivity fault. Run it by hand if you truly need it.

## Requirements

- Windows 8.1 / Server 2012 R2 or later (older versions work with reduced adapter-restart support)
- PowerShell 3.0+
- **Administrator privileges** for any `-Repair` run; diagnostics work unelevated

## Usage

Diagnose only — safe to run on any machine, changes nothing:
```powershell
.\Network-Repair-Toolkit.ps1
```

Diagnose, then apply safe fixes:
```powershell
.\Network-Repair-Toolkit.ps1 -Repair
```

Preview exactly what an aggressive repair would do, without doing it:
```powershell
.\Network-Repair-Toolkit.ps1 -Repair -RepairLevel Aggressive -WhatIf
```

Confirm each action individually:
```powershell
.\Network-Repair-Toolkit.ps1 -Repair -RepairLevel Standard -Confirm
```

Test against your own endpoints (useful on isolated or filtered networks):
```powershell
.\Network-Repair-Toolkit.ps1 -TestTargets '10.0.0.1','intranet.corp.local'
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Repair` | switch | off | Apply repairs after diagnostics |
| `-RepairLevel` | `Safe`/`Standard`/`Aggressive` | `Safe` | Remediation tier |
| `-TestTargets` | string[] | `8.8.8.8`, `1.1.1.1` | Hosts used for the reachability test |
| `-LogPath` | string | Desktop | Where the transcript log is written |
| `-WhatIf` | switch | — | Preview repairs without executing |
| `-Confirm` | switch | — | Prompt before each repair |

## Output

Console output is colour-coded per layer (`[+]` pass, `[!]` warning, `[X]` fail, `[i]` info). A full transcript is saved to:

```
<LogPath>\NetworkRepair_<COMPUTERNAME>_<yyyyMMdd_HHmmss>.log
```

Attach this log to the ticket — it records every test result and every command executed.

## Interpreting common results

| Symptom | Likely cause | Next step |
|---|---|---|
| APIPA address `169.254.x.x` | DHCP server unreachable | Check switch port, VLAN, DHCP scope exhaustion |
| Gateway unreachable | Local network fault | Check cable, switch port, Wi-Fi association |
| ICMP fails but HTTPS passes | Firewall blocks ping | Normal on many corporate networks — not a fault |
| DNS slow (>2000 ms) | Overloaded or distant DNS server | Point to a closer resolver |
| HTTPS fails, everything else passes | Proxy or TLS inspection | Check proxy settings and certificate trust |

## Deployment tips

- Drop it on a USB stick or network share for walk-up support
- Run diagnostics remotely via `Invoke-Command` before dispatching a tech
- Pair with a ticketing workflow: the transcript is already formatted for attachment
- Use `-WhatIf` when training junior staff so they can see what each tier does

## Troubleshooting the script itself

**"Execution of scripts is disabled on this system"**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

**Repairs throw a privileges error** — relaunch PowerShell with *Run as Administrator*.

## License

MIT
