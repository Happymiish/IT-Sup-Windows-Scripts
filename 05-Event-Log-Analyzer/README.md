# Event Log Analyzer

Correlates Windows event logs into an investigation-ready report: failed logons grouped by account and reason, account lockouts with their source, privilege escalation, service installs, log clearing, and stability faults.

## Why this exists

Event Viewer is a log reader, not an analysis tool. Answering "who has been trying to log into this account?" means manually filtering thousands of entries and decoding numeric status codes. This script does the grouping, decoding, and correlation, then ranks the results by severity.

**It changes nothing.** No logs are cleared, no settings altered.

## What it analyses

| Category | Event IDs | What you learn |
|---|---|---|
| `Logons` | 4625, 4624 | Failed logons grouped by account with decoded failure reason and source IP; successful network (type 3) and RDP (type 10) logons |
| `Lockouts` | 4740 | Which accounts locked, how often, and from which workstation |
| `PrivilegeUse` | 4672 | Accounts granted administrative privilege |
| `AccountChanges` | 4720–4756 | Accounts created/deleted/enabled, admin password resets, security group membership changes |
| `Services` | 7045, 7031, 7034 | Newly installed services (a common persistence mechanism) and services crashing repeatedly |
| `LogClearing` | 1102, 104 | Audit or system log cleared, and by whom |
| `SystemStability` | 6008, 41, disk/Ntfs errors, bugchecks | Unexpected shutdowns, blue screens, impending disk failure |
| `Applications` | Level 1–2 | Top ten error sources in the Application log |

### Failure codes are decoded

A 4625 event carries a numeric substatus. The script translates it, because the distinction drives the whole investigation:

- `0xC000006A` — incorrect password (possible brute force)
- `0xC0000064` — account does not exist (username enumeration)
- `0xC0000072` — account disabled
- `0xC0000234` — account already locked out
- `0xC0000133` — clock skew, not an attack at all

## Requirements

- Windows 7 / Server 2008 R2 or later
- PowerShell 3.0+
- **Administrator**, or membership of the *Event Log Readers* group, to read the Security log

### Audit policy dependency

Most Security-log detections only work if auditing is enabled. Without it, the log is genuinely empty and the script will correctly report finding nothing.

Check current settings:
```powershell
auditpol /get /category:*
```

Enable the essentials (run elevated; prefer Group Policy in a domain):
```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
```

### Honest reporting of gaps

If the Security log cannot be read, the script emits an explicit **Warning** for every affected category rather than reporting "no findings". An empty result from an unreadable log is not evidence of a clean machine, and the report says so.

## Usage

Last 24 hours on the local machine:
```powershell
.\Event-Log-Analyzer.ps1
```

A full week, with CSV export for a SIEM or spreadsheet:
```powershell
.\Event-Log-Analyzer.ps1 -Hours 168 -ExportCsv
```

Focus on authentication only, across several servers:
```powershell
.\Event-Log-Analyzer.ps1 -ComputerName DC01,DC02,FS01 -IncludeCategories Logons,Lockouts
```

Tighten the brute-force threshold:
```powershell
.\Event-Log-Analyzer.ps1 -FailedLogonThreshold 3
```

Filter the returned objects directly:
```powershell
.\Event-Log-Analyzer.ps1 | Where-Object Severity -eq 'Critical'
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Hours` | int | 24 | How far back to analyse (1–8760) |
| `-OutputPath` | string | Desktop | Directory for the report |
| `-ComputerName` | string[] | local | Target computer(s) |
| `-FailedLogonThreshold` | int | 5 | Failed logons per account before flagging. 4× this count escalates to Critical |
| `-ExportCsv` | switch | off | Also write a CSV alongside the HTML |
| `-IncludeCategories` | string[] | all | Which analyses to run |

## Output

```
<OutputPath>\EventAnalysis_<COMPUTERNAME>_<yyyyMMdd_HHmmss>.html
<OutputPath>\EventAnalysis_<COMPUTERNAME>_<yyyyMMdd_HHmmss>.csv   (with -ExportCsv)
```

Findings are grouped by category, sorted severity-first, and each row shows the time range over which the activity occurred. Critical findings are also echoed to the console.

## Interpreting results

| Finding | Usually means | Investigate when |
|---|---|---|
| Many 4625 for one account, one source | Stale cached credential or mapped drive | The source IP is unfamiliar |
| Many 4625 across many accounts | Password spraying | Almost always — this is rarely benign |
| `0xC0000064` in bulk | Username enumeration | Almost always |
| Repeated lockouts, same workstation | Old password in a task or service | Rarely malicious, but fix the root cause |
| Service installed from `\Temp\` | Persistence mechanism | Immediately |
| Log cleared | Anti-forensics, or routine maintenance | Correlate with your change record |
| Type 10 (RDP) logon | Remote support session | The account or source is unexpected |

## Remote usage

```powershell
.\Event-Log-Analyzer.ps1 -ComputerName (Get-Content .\servers.txt) -Hours 168 -ExportCsv
```

Requires the Remote Event Log Management firewall rule and appropriate rights on each target. For large fleets, forward to a central collector instead of polling each host.

## Limitations

- Only reports what the audit policy recorded. Silent gaps are a configuration problem, not a script problem.
- Logs roll over. A busy Security log may not retain 168 hours.
- Event 4672 fires for every administrative logon, including routine ones, so it is Info by default.
- Group membership changes report the SID when the group name is not in the event payload.

## License

MIT
