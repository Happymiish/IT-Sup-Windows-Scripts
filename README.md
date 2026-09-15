# System Health Check

A read-only Windows diagnostic sweep that produces a colour-coded HTML report you can attach straight to a ticket.

## Why this exists

When a user says "my computer is slow," you need a fast, consistent baseline rather than a dozen ad-hoc commands. This script collects the same set of facts every time, grades each one against a threshold, and hands you a shareable report.

**It changes nothing.** Every check is read-only, so it is safe to run on a production machine during business hours.

## What it checks

| Area | Details collected | Graded on |
|---|---|---|
| System | Hostname, OS version, make/model, serial, logged-on user, uptime | Uptime > 30 days → Warning |
| CPU | Model, core/thread count, load averaged over 3 samples | ≥75% Warning, ≥90% Critical |
| Memory | Total, free, and percentage used | ≥80% Warning, ≥90% Critical |
| Disk | Per-volume used/free space, plus SMART status per drive | ≥80% Warning, ≥90% Critical |
| Network | Adapter IPs and gateways, ping tests, DNS resolution | Failed DNS → Critical |
| Services | Windows Update, Defender, Firewall, BITS, DNS Client, Workstation, Event Log; plus any automatic service that is not running | Stopped → Warning |
| Event log | System and Application errors/criticals in a configurable window | >10 Warning, >50 Critical |
| Updates | Most recent hotfix and its age, total hotfix count | Last patch > 60 days → Warning |
| Processes | Top 5 processes by CPU time with working-set size | Informational |

Thresholds for disk, memory, and the event log window are all parameterised.

## Requirements

- Windows 7 / Server 2008 R2 or later
- PowerShell 3.0+ (falls back to WMI where CIM cmdlets are unavailable)
- Administrator privileges recommended — event log and service checks are incomplete without them

## Usage

```powershell
.\System-Health-Check.ps1
```

Write the report somewhere specific:
```powershell
.\System-Health-Check.ps1 -OutputPath "C:\Reports"
```

Tighten thresholds and widen the event log window:
```powershell
.\System-Health-Check.ps1 -DiskWarningPercent 70 -DiskCriticalPercent 85 -EventLogHours 72
```

Skip outbound tests on an isolated network:
```powershell
.\System-Health-Check.ps1 -SkipNetworkTests
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-OutputPath` | string | Desktop | Directory for the HTML report |
| `-DiskWarningPercent` | int | 80 | Disk used % that triggers a Warning |
| `-DiskCriticalPercent` | int | 90 | Disk used % that triggers a Critical |
| `-MemoryWarningPercent` | int | 80 | Memory used % that triggers a Warning |
| `-EventLogHours` | int | 24 | Hours of event log history to scan |
| `-SkipNetworkTests` | switch | off | Skip ping and DNS tests |

## Output

An HTML report at:
```
<OutputPath>\HealthReport_<COMPUTERNAME>_<yyyyMMdd_HHmmss>.html
```

It opens in any browser and contains summary counters (Critical / Warning / Healthy) plus a per-finding table with status badges. Rows are tinted red for Critical and amber for Warning so problems are visible at a glance.

The script also emits the findings as objects on the pipeline, so you can filter or aggregate them:

```powershell
.\System-Health-Check.ps1 | Where-Object Status -eq 'Critical'
```

## Fleet usage

Collect reports from many machines at once:
```powershell
Invoke-Command -ComputerName (Get-Content .\machines.txt) `
               -FilePath .\System-Health-Check.ps1
```

Schedule a weekly baseline:
```powershell
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\System-Health-Check.ps1" -OutputPath "\\fileserver\healthreports"'
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 7am
Register-ScheduledTask -TaskName 'Weekly Health Check' `
    -Action $action -Trigger $trigger -RunLevel Highest -User 'SYSTEM'
```

## Notes on interpretation

- **High uptime is not automatically a problem** — it only means pending patches may not have been applied.
- **A stopped automatic service is often benign.** Many vendor services are set to automatic but exit after their work is done. Check the names listed before escalating.
- **SMART status of `OK` is weak evidence.** It reports predicted failure only; a drive can be failing while still reporting OK.

## Troubleshooting

**"Execution of scripts is disabled on this system"**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

**Event log section is empty** — run elevated; the Security and some System channels require Administrator.

## License

MIT
