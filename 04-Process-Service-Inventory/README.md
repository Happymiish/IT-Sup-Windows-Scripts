# Process & Service Inventory

Comprehensive inventory of running processes, services, and network listeners. Detects suspicious execution patterns, auto-start services that fail, and reveals which process owns each listening port.

## Why this exists

Help desk needs to answer "what is running on this machine?" for incident response, licensing audits, and performance troubleshooting. This script provides a cleaner, more actionable view than Task Manager or Services.msc — with command-line arguments exposed (where malware hides), failing auto-start services flagged, and every listening port mapped to its owning process.

## What it collects

| Category | Details | Graded on |
|---|---|---|
| Processes | Name, PID, CPU time, memory, command-line args, executable path | Suspicious names (mimikatz, psexec, etc.), unusual parent process relationships |
| Services | Name, display name, state, startup type, executable path | Auto-start services that are stopped; services in error state |
| Listeners | Protocol, local address, local port, owning PID/process name | Well-known ports used by unexpected processes |
| Network connections | Protocol, local/remote address, connection state, owning process | Established connections to suspicious ports or countries |

## Requirements

- Windows 7 / Server 2008 R2 or later
- PowerShell 3.0+
- Administrator privileges for full network/listener enumeration

## Usage

Full inventory with all sections:
```powershell
.\Process-Service-Inventory.ps1
```

Save to a specific location:
```powershell
.\Process-Service-Inventory.ps1 -OutputPath "C:\Reports"
```

Focus on specific areas:
```powershell
.\Process-Service-Inventory.ps1 -Sections Processes,Listeners
```

Include command-line arguments (verbose, good for incident response):
```powershell
.\Process-Service-Inventory.ps1 -IncludeCommandLine
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-OutputPath` | string | Desktop | Directory for the HTML report |
| `-Sections` | string[] | All | Which sections to include: Processes, Services, Listeners, Connections |
| `-IncludeCommandLine` | switch | off | Include full command-line args for each process (can be verbose) |
| `-SuspiciousOnly` | switch | off | Show only processes/services flagged as suspicious |
| `-TopProcessCount` | int | 20 | How many top CPU/memory processes to include |

## Output

An HTML report at:
```
<OutputPath>\ProcessInventory_<COMPUTERNAME>_<yyyyMMdd_HHmmss>.html
```

Contains:
- **Process summary** — all running processes with CPU, memory, and parent process
- **Suspicious processes** — flagged by name pattern or anomalous parent
- **Service status** — auto-start services that are stopped or in error state
- **Listening ports** — every TCP/UDP listener mapped to its process
- **Active connections** — established TCP connections (useful for detecting beaconing)

Rows flagged red or yellow for quick anomaly spotting.

## Suspicious patterns detected

### Process names
- Mimikatz, Procdump, Psexec, Plink, Putty, VNC, TeamViewer (unapproved remote tools)
- Powershell/cmd spawned from unexpected parents
- Processes with names that don't match their path

### Parent process relationships
- Cmd.exe or PowerShell spawned from user temp folders
- Services.exe parent other than csrss.exe
- Explorer.exe spawning cmd or PowerShell
- Winlogon spawning unexpected processes

### Port misuse
- PowerShell listening on network ports
- Cmd.exe with active listeners
- Services on high-numbered ports (unprivileged processes shouldn't be there)

## Common findings

| Finding | Benign explanation | Malware indicator |
|---|---|---|
| Multiple PowerShell processes | Legitimate scripts running | Reverse shell listening or beacon activity |
| Svchost.exe children | Windows services | Malware injected into svchost |
| Explorer.exe spawning cmd | Batch files in shell association | Ransomware pre-execution |
| Established connection to port 443 | HTTPS traffic (legitimate) | If destination is suspicious IP or known C2 server |

## Tips for incident response

- Run immediately after noticing slow performance or network activity
- Export the report to a network share for remote review before touching the machine
- Focus on the "Suspicious Processes" and "Listening Ports" sections first
- Cross-reference listener ports with firewall logs
- Use `-SuspiciousOnly` for a quick triage report
- Command-line args often reveal the attacker's intent (encrypted payloads, callback domains, etc.)

## Limitations

- Network connection data is point-in-time; long-lived connections may not show in the report
- Parent process info is lost if the parent has already exited
- Some kernel-mode drivers listening on ports won't be attributed to a user-mode process
- Requires elevation for complete network socket enumeration

## License

MIT
