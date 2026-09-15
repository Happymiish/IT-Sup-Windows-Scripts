# Windows IT Support Scripts

Three production-ready PowerShell tools for Windows help desk and desktop support work. Each is self-contained, documented, and safe to run against a user's machine.

## The scripts

### [01 — System Health Check](./01-System-Health-Check)
Read-only diagnostic sweep covering CPU, memory, disk, network, services, event logs, updates, and top processes. Produces a colour-coded HTML report for the ticket.

```powershell
.\System-Health-Check.ps1
```

### [02 — Network Repair Toolkit](./02-Network-Repair-Toolkit)
Layered connectivity diagnostics (adapter → IP → gateway → DNS → HTTPS) that names the failing layer, plus three tiers of remediation from a simple DNS flush to a full Winsock reset.

```powershell
.\Network-Repair-Toolkit.ps1              # diagnose only
.\Network-Repair-Toolkit.ps1 -Repair      # diagnose and fix
```

### [03 — Workstation Cleanup](./03-Workstation-Cleanup)
Reclaims disk space from temp folders, browser caches, Windows Update downloads, crash dumps, and stale user profiles. Report-only until you pass `-Execute`.

```powershell
.\Workstation-Cleanup.ps1                 # report only
.\Workstation-Cleanup.ps1 -Execute        # clean
```

## Design principles

These follow a few rules that make them safe to hand to junior staff:

- **Read-only by default.** Scripts that change the system require an explicit switch (`-Repair`, `-Execute`). Running one by accident cannot break anything.
- **`-WhatIf` and `-Confirm` everywhere.** Every destructive action goes through `ShouldProcess`.
- **Logged.** Each run writes a timestamped log or report suitable for attaching to a ticket.
- **Tiered impact.** Where remediation carries risk, it is separated into levels so you apply the smallest fix that works.
- **No cargo cult.** Actions with no measurable benefit (registry "cleaning") or disproportionate blast radius (firewall reset) are deliberately excluded, and the reasoning is documented.

## Getting started

Clone and unblock the files (Windows marks downloaded scripts as untrusted):

```powershell
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
Get-ChildItem -Recurse -Filter *.ps1 | Unblock-File
```

If script execution is restricted, allow it for the current session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then run any script from its own folder. Start with the report-only modes.

## Requirements

| | Minimum |
|---|---|
| OS | Windows 8.1 / Server 2012 R2 (most features work back to Windows 7) |
| PowerShell | 3.0 |
| Privileges | Administrator for repairs and system-wide cleanup; diagnostics run unelevated |

All three work in both Windows PowerShell 5.1 and PowerShell 7.

## Running against remote machines

Every script is safe to invoke remotely:

```powershell
$computers = Get-Content .\machines.txt
Invoke-Command -ComputerName $computers -FilePath .\01-System-Health-Check\System-Health-Check.ps1
```

Point `-OutputPath` / `-LogPath` at a UNC share to centralise the results.

## Repository layout

```
.
├── 01-System-Health-Check/
│   ├── System-Health-Check.ps1
│   └── README.md
├── 02-Network-Repair-Toolkit/
│   ├── Network-Repair-Toolkit.ps1
│   └── README.md
├── 03-Workstation-Cleanup/
│   ├── Workstation-Cleanup.ps1
│   └── README.md
├── .gitignore
├── LICENSE
└── README.md
```

## Contributing

Issues and pull requests are welcome. If you add a script, please keep the conventions: comment-based help, `ShouldProcess` on anything destructive, a report-only default, and a README of its own.

## License

MIT — see [LICENSE](./LICENSE).
