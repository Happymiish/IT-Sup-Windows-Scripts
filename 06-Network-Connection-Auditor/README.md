# Network Connection Auditor

Samples outbound TCP activity over time and profiles which processes talk to which destinations. Because it samples rather than snapshots, it catches short-lived connections and distinguishes persistent sessions from scheduled, repeating contact.

## Why this exists

A single `netstat` gives you one instant. Malware beacons, update checkers, and telemetry agents connect briefly and disappear between snapshots. Sampling over minutes builds a profile: who connects where, how often, and on what rhythm.

**It changes nothing.** No connections are blocked or terminated.

## How it differs from script 04

Script 04 (Process & Service Inventory) takes a single snapshot across processes, services, and sockets. This script does one thing over time: outbound connection behaviour. Use 04 for "what is on this machine right now"; use this for "what is this machine talking to, and how often".

## The Pattern column

This is the core output, and the distinction matters:

| Pattern | Meaning | Typical cause |
|---|---|---|
| **Persistent** | Connection stayed open across every sample it appeared in | Browser tabs, VPN tunnels, mail clients, chat apps — normal |
| **Periodic** | Destination was contacted, dropped, and re-contacted on a consistent schedule | Update checkers, telemetry, monitoring agents — usually normal, occasionally a beacon |
| **Sporadic** | Irregular contact | Ordinary user-driven browsing |

### Why this distinction is the whole point

A naive implementation computes variance across observation times and calls low variance a "beacon". That is wrong: a connection that stays open appears in *every* sample, so its gaps all equal the sampling interval and its variance is near zero. Under that logic every open browser tab is a beacon.

This script only measures **return gaps** — intervals where a destination vanished for at least one sample and then came back. Regularity across those gaps is what actually indicates scheduled contact. At least three returns are required before any cadence claim is made.

**Periodic is still not a verdict.** Scheduled polling is how most modern software behaves. The flag tells you to identify the process, nothing more.

## What else it flags

- **Notable remote ports** — FTP, Telnet, SSH, RDP, VNC, SOCKS, Tor, IRC, and common handler ports
- **Scripting hosts and LOLBins with outbound connections** — `powershell`, `cmd`, `mshta`, `regsvr32`, `rundll32`, `certutil`, `bitsadmin`, `wmic`, and similar. These rarely have a legitimate reason to sustain network connections on a workstation.
- **Processes running from user-writable directories** — Temp, Downloads, Public

Every remote address is classified as Public, Private, CGNAT, LinkLocal, or Multicast, so internal chatter is easy to separate from internet traffic.

## Requirements

- Windows 8 / Server 2012 or later (requires `Get-NetTCPConnection`)
- PowerShell 3.0+
- Administrator recommended — without it, sockets owned by other users may not be attributed to a process

## Usage

Default five-minute sample:
```powershell
.\Network-Connection-Auditor.ps1
```

Single snapshot, no waiting:
```powershell
.\Network-Connection-Auditor.ps1 -DurationMinutes 0
```

Long investigation run with name resolution and CSV output:
```powershell
.\Network-Connection-Auditor.ps1 -DurationMinutes 30 -IntervalSeconds 10 -ResolveNames -ExportCsv
```

Include the DNS client cache:
```powershell
.\Network-Connection-Auditor.ps1 -IncludeDnsCache
```

Filter the returned objects:
```powershell
.\Network-Connection-Auditor.ps1 | Where-Object { $_.Scope -eq 'Public' -and $_.IsFlagged }
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-DurationMinutes` | int | 5 | Sampling window. 0 = single snapshot |
| `-IntervalSeconds` | int | 15 | Seconds between samples (2–300) |
| `-ResolveNames` | switch | off | Reverse DNS on public addresses |
| `-IncludeDnsCache` | switch | off | Include the local DNS client cache |
| `-MinimumSamplesForCadence` | int | 4 | Observations required before pattern analysis |
| `-OutputPath` | string | Desktop | Directory for the report |
| `-ExportCsv` | switch | off | Also write aggregated results as CSV |

### Choosing an interval

Shorter intervals catch more short-lived connections but add overhead. A connection that opens and closes entirely between two samples is invisible regardless. For suspected beaconing, use `-IntervalSeconds 5` over a longer `-DurationMinutes`.

## Output

```
<OutputPath>\NetworkAudit_<COMPUTERNAME>_<yyyyMMdd_HHmmss>.html
<OutputPath>\NetworkAudit_<COMPUTERNAME>_<yyyyMMdd_HHmmss>.csv   (with -ExportCsv)
```

The HTML report leads with flagged rows, then orders by observation count. Each row shows the process and PID, destination, scope, times seen, pattern, and the time window over which it was observed.

## Operational notes

- **`-ResolveNames` emits DNS queries.** During an active investigation this can tip off an operator monitoring the network, and it writes to your own DNS cache. Leave it off if that matters.
- **The DNS cache is volatile.** It only shows entries still within their TTL. Absence proves nothing.
- **Ctrl+C during sampling abandons the run** — no report is written. Use a shorter duration rather than interrupting.
- Run it on a known-good machine first to learn what normal looks like for your estate. Comparison against a baseline is worth far more than any single report.

## Limitations

- TCP only. UDP-based exfiltration and DNS tunnelling will not appear here.
- Sampling cannot see connections shorter than the interval.
- No traffic volume data — `Get-NetTCPConnection` does not expose byte counts, so this cannot detect large transfers.
- No threat intelligence lookups. Destination reputation must be checked separately.
- Process attribution fails if the owning process exits before the sample is taken.

For packet-level certainty, use a capture tool. This script is for triage and profiling.

## License

MIT
