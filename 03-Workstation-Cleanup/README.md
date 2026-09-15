# Workstation Cleanup

Reclaims disk space on Windows machines by clearing caches, temp files, and other regenerable data. **Report-only by default** — it shows you the savings before it touches anything.

## Why this exists

"Disk is full" is one of the most common help desk tickets, and the built-in Disk Cleanup tool is slow, GUI-only, and misses most per-user caches. This script sweeps every profile on the machine, quantifies what each target holds, and lets you clean selectively.

## Cleanup targets

| Target | What it removes | In default set |
|---|---|---|
| `WindowsTemp` | `C:\Windows\Temp` | Yes |
| `UserTemp` | `AppData\Local\Temp` for **every** profile | Yes |
| `RecycleBin` | Recycle Bin on the system drive | Yes |
| `BrowserCache` | Chrome, Edge, Brave, Firefox, and IE/INetCache caches | Yes |
| `WindowsUpdate` | `SoftwareDistribution\Download` (stops/restarts wuauserv) | Yes |
| `Thumbnails` | `thumbcache_*.db` files | Yes |
| `CrashDumps` | Minidumps, LiveKernelReports, per-user CrashDumps | Yes |
| `DeliveryOptimization` | Windows Update peer-caching store | Yes |
| `Prefetch` | `C:\Windows\Prefetch` | No — opt in |
| `IisLogs` | `inetpub\logs\LogFiles` (30-day minimum retention) | No — opt in |
| `OldProfiles` | Local profiles unused for N days | No — opt in |

### Safety design

- **Nothing is deleted without `-Execute`.** The default run is a pure measurement pass.
- **Age threshold** (`-MinimumAgeDays`, default 7) prevents deleting temp files an app is currently using.
- **Firefox is handled carefully** — only the `cache2` folder inside each profile is cleared. The profile directory holding bookmarks, logins, and cookies is never touched.
- **Locked files are skipped**, not fatal. They are counted and reported.
- **`OldProfiles` uses the CIM profile provider** (`Remove-CimInstance`) so registry entries are cleaned up properly. Deleting `C:\Users\<name>` by hand leaves orphaned registry state and breaks future logons.
- Special, loaded, and built-in profiles (Administrator, Public, Default) are always excluded.
- Honours `-WhatIf` and `-Confirm`.

### What it deliberately does *not* do

- No `cleanmgr /sageset` automation — unpredictable across Windows builds
- No component store cleanup (`DISM /StartComponentCleanup`) — long-running and should be a scheduled maintenance task, not an interactive fix
- No registry "cleaning" — no measurable benefit, real risk

## Requirements

- Windows 8.1 / Server 2012 R2 or later
- PowerShell 3.0+
- Administrator privileges for system-wide targets (`WindowsTemp`, `WindowsUpdate`, `OldProfiles`, other users' profiles)

## Usage

See what can be reclaimed — completely safe, changes nothing:
```powershell
.\Workstation-Cleanup.ps1
```

Clean the default target set:
```powershell
.\Workstation-Cleanup.ps1 -Execute
```

Clean specific targets only:
```powershell
.\Workstation-Cleanup.ps1 -Execute -Targets WindowsTemp,UserTemp,BrowserCache
```

Be more aggressive about file age:
```powershell
.\Workstation-Cleanup.ps1 -Execute -MinimumAgeDays 1
```

Remove profiles unused for six months, confirming each:
```powershell
.\Workstation-Cleanup.ps1 -Execute -Targets OldProfiles -ProfileAgeDays 180 -Confirm
```

Preview what an execute run would do:
```powershell
.\Workstation-Cleanup.ps1 -Execute -WhatIf
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Execute` | switch | off | Actually delete. Omit for report-only |
| `-Targets` | string[] | 8 default targets | Which targets to process |
| `-MinimumAgeDays` | int | 7 | Only remove files older than this |
| `-ProfileAgeDays` | int | 90 | Profile inactivity threshold for `OldProfiles` |
| `-LogPath` | string | Desktop | Where the CSV log is written |
| `-WhatIf` / `-Confirm` | switch | — | Standard PowerShell safety switches |

## Output

Per-target console summary plus free-space before/after, and a CSV log at:

```
<LogPath>\Cleanup_<COMPUTERNAME>_<yyyyMMdd_HHmmss>.csv
```

The CSV contains `Target`, `Bytes`, `Size`, `FileCount`, and `Note` columns — easy to aggregate across a fleet.

## Before you run it

- **Close browsers** before the `BrowserCache` target, or most cache files will be locked and skipped
- `WindowsUpdate` briefly stops the Windows Update service; avoid running it mid-update
- `Prefetch` causes a small, temporary app launch slowdown while the cache rebuilds
- `OldProfiles` is irreversible — always dry-run it first and confirm the list with the machine owner

## Fleet deployment

Run report-only across a fleet and collect the numbers before deciding where to act:

```powershell
$computers = Get-Content .\machines.txt
Invoke-Command -ComputerName $computers -FilePath .\Workstation-Cleanup.ps1
```

As a monthly scheduled task:
```powershell
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Workstation-Cleanup.ps1" -Execute'
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am
Register-ScheduledTask -TaskName 'Monthly Workstation Cleanup' `
    -Action $action -Trigger $trigger -RunLevel Highest -User 'SYSTEM'
```

## Troubleshooting

**"Execution of scripts is disabled on this system"**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

**Reported size is larger than the actual free-space gain** — expected. Some files are locked, and the Recycle Bin measurement is taken before deletion. Compare the `Note` column for skipped counts.

## License

MIT
