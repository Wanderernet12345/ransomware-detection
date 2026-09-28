# RDRS -- Ransomware Detection & Response Service

> A multi-layer, real-time ransomware detection and automatic containment system for Windows,
> built as a **Project-Based Learning (PBL)** exercise in applied cybersecurity.

---

## Table of Contents

1. [Overview](#overview)
2. [How It Works -- The Big Picture](#how-it-works----the-big-picture)
3. [Architecture](#architecture)
4. [Detection Layers](#detection-layers)
   - [Layer 1 -- Honeytoken Deception](#layer-1----honeytoken-deception)
   - [Layer 2 -- ETW Kernel File Monitor](#layer-2----etw-kernel-file-monitor)
   - [Layer 3 -- Crypto API Monitor](#layer-3----crypto-api-monitor)
   - [Layer 4 -- Process Behaviour Scorer](#layer-4----process-behaviour-scorer)
   - [Layer 5 -- Network Monitor](#layer-5----network-monitor)
   - [Layer 6 -- VSS / Shadow Copy Watcher](#layer-6----vss--shadow-copy-watcher)
   - [Layer 7 -- Burst Detector](#layer-7----burst-detector)
5. [Signal Fusion Engine](#signal-fusion-engine)
6. [Automatic Containment](#automatic-containment)
7. [Windows Tray Application](#windows-tray-application)
8. [Live Dashboard](#live-dashboard)
9. [Configuration](#configuration)
10. [Alert Format](#alert-format)
11. [Project Structure](#project-structure)
12. [Requirements](#requirements)
13. [Installation & Build](#installation--build)
14. [Running the Tool](#running-the-tool)
15. [Testing Detection](#testing-detection)
16. [Output Files](#output-files)
17. [Design Decisions & Limitations](#design-decisions--limitations)

---

## Overview

RDRS is a Windows endpoint security tool that detects ransomware **before** it finishes encrypting
your files and **automatically kills the attacking process**.

It combines seven independent detection techniques -- deception files, kernel event tracing,
crypto-API monitoring, process behaviour analysis, network monitoring, shadow-copy watch, and
burst detection -- into a single weighted **Signal Fusion Engine** that produces a composite
threat score per process in real time.

When the fused score of any process reaches **>= 70 / 100** the containment engine:

1. **Suspends** all threads instantly (`NtSuspendProcess`)
2. **Kills** the process and its entire child tree (`Process.Kill(entireProcessTree: true)`)
3. **Blocks** re-execution if the binary lives in `Temp` / `AppData` (`icacls /deny Everyone:(X)`)
4. **Queues** a Windows Defender on-demand scan of the binary path

All events are logged to `rdrs_alerts.json` and `rdrs_containment.json`.

---

## How It Works -- The Big Picture

```
Ransomware starts  ->  touches honeytoken files    ->  FileSystemWatcher fires
                   ->  loads bcrypt.dll repeatedly  ->  ETW ImageLoad fires
                   ->  encrypts 50+ files / 5 sec   ->  ETW FileIO rate fires
                   ->  renames *.docx -> *.locked   ->  extension rename fires
                   ->  deletes shadow copies        ->  WMI VssWatcher fires
                   ->  WMI I/O write rate spikes    ->  ProcessBehaviorScorer fires
                   ->  makes outbound connection    ->  NetworkMonitor fires
                                   |
                                   v
                         SignalFusion accumulates
                         weighted scores per PID
                                   |
                                   v
                      Fused score >= 70  ->  CONTAINMENT
                      Suspend -> Kill -> Block -> Defender
```

The key insight is **no single signal is reliable alone** -- a user can open a DOCX, bcrypt.dll
loads all the time, and file writes are normal. Only the *combination* of signals from the same
process within a short time window reaches a conclusive score.

---

## Architecture

```
+---------------------------------------------------------------------------+
|                          DeceptionEngine.Run()                            |
|                                                                           |
|  +------------------+   +-----------------+   +----------------------+   |
|  | HoneytokenPlanter|   |  WatcherManager  |   |     AlertManager     |   |
|  | Plants 8 decoy   |-->|  FileSystemWatch |-->|  JSON log + OnAlert  |   |
|  | files on Desktop,|   |  per directory   |   |  event               |   |
|  | Documents, etc.  |   +-----------------+   +----------------------+   |
|  +------------------+                                    |               |
|                                                           v               |
|  +------------------------------------------------------------------------+
|  |                       SignalFusion Engine                              |
|  |                                                                        |
|  |  Source         Weight   Feeds from                                   |
|  |  -------------  ------   ------------------------------------         |
|  |  Honeytoken     0.35  <- AlertBuilder (FSW rename/write/delete)       |
|  |  CryptoApi      0.25  <- CryptoApiMonitor (DLL load correlation)      |
|  |  EtwFileRate    0.20  <- EtwMonitor (kernel FileIO + extension rename) |
|  |  Network        0.12  <- NetworkMonitor (TCP + Tor + exfil)           |
|  |  Signature      0.08  <- ProcessBehaviorScorer (I/O + parent-child)   |
|  |                                                                        |
|  |  Per-process rolling score -> fires OnFusedThreat when >= 70/100      |
|  +------------------------------------------------------------------------+
|                                    |                                      |
|                                    v                                      |
|                    +-------------------------------+                      |
|                    |      ContainmentEngine        |                      |
|                    | Suspend -> Kill -> Block path |                      |
|                    | + Defender scan               |                      |
|                    +-------------------------------+                      |
+---------------------------------------------------------------------------+

  Side monitors (independent background threads):
  +--------------+  +------------------+  +--------------+
  |  VssWatcher  |  |  BurstDetector   |  |  EtwMonitor  |
  |  WMI process |  |  >10 FSW events  |  |  NT Kernel   |
  |  creation    |  |  in 3 seconds    |  |  Logger      |
  |  vssadmin /  |  |  + entropy check |  |  (admin req) |
  |  wbadmin etc |  +------------------+  +--------------+
  +--------------+
```

---

## Detection Layers

### Layer 1 -- Honeytoken Deception

**Files:** `HoneytokenPlanter.cs`, `WatcherManager.cs`, `AlertBuilder.cs`

Honeytoken files are **fake high-value documents** planted in directories ransomware always
targets first:

| Directory | File 1 | File 2 |
|-----------|--------|--------|
| Desktop | `_AAAA_resume_final.docx` | `_AAAA_tax_return_2024.pdf` |
| Documents | `_AAAA_family_vacation.jpg` | `_AAAA_bank_statement.xlsx` |
| Downloads | `_AAAA_passwords_backup.txt` | `_AAAA_project_contracts.docx` |
| Pictures | `_AAAA_crypto_wallet.txt` | `_AAAA_medical_records.pdf` |

**Why `_AAAA_` prefix?**
Files sort alphabetically. Ransomware encrypts in directory order, so it hits our decoys
*first* -- triggering detection before any real file is touched.

**File realism:**
Each honeytoken is structurally valid -- DOCX/XLSX are real ZIP+XML Office packages, PDFs
have a working xref table, JPEGs have a correct JFIF/APP0 header. Ransomware that
inspects magic bytes or file structure still treats them as genuine encryption targets.

**ACL setup:**
Files are set `Hidden + System` (invisible in Explorer) with `BUILTIN\Users:Modify` DACL
and `icacls /setintegritylevel Medium` so non-elevated ransomware running in user context
can write to them -- making them maximally attractive as encryption targets.

**When triggered:**
Any `Changed`, `Renamed`, `Deleted`, or `Created` event on a honeytoken fires
`AlertBuilder.Build()` which performs:
- 3-stage process attribution (Restart Manager -> FSW-time shell hint -> handle-count scan)
- Shannon entropy measurement on the written bytes (>7.2 bits/byte = encrypted content)
- Risk scoring (55 base + event-type bonus + entropy bonus + process modifiers)
- A `ThreatSignal(Honeytoken, rawScore)` submitted to SignalFusion

---

### Layer 2 -- ETW Kernel File Monitor

**File:** `Monitoring/EtwMonitor.cs`
**Requires:** Administrator

Opens a private ETW session (`RDRS-FileMonitor`) using `Microsoft.Diagnostics.Tracing.TraceEvent`
and subscribes to:

```
KernelTraceEventParser.Keywords.FileIOInit | FileIO | ImageLoad
```

**Detection rules:**

| Rule | Threshold | Raw Score | Indicator |
|------|-----------|-----------|-----------|
| File I/O rate | >50 files/5 s from one process | 0.50 - 1.0 | `FILE_RATE_HIGH` |
| Ransom extension | New file with `.locked` / `.enc` / `.wncry` / 30+ others | 0.90 | `RANSOM_EXT_RENAME` |
| Crypto DLL load | `bcrypt.dll` / `rsaenh.dll` / `ncrypt.dll` loaded >= 2x in 10 s | 0.60 | `CRYPTO_DLL_LOAD` |

Falls back silently if not running as admin.

---

### Layer 3 -- Crypto API Monitor

**File:** `Monitoring/CryptoApiMonitor.cs`

**Layer A -- Signal correlation (always active):**
Subscribes to `EtwMonitor.OnSignal`. Maintains a 30-second per-process sliding window.
Fires a higher-confidence signal when correlated patterns appear from the *same PID*:

| Pattern | Raw Score | Indicator |
|---------|-----------|-----------|
| `RANSOM_EXT_RENAME` seen | 0.92 | `RANSOM_EXT_CORRELATED` |
| `CRYPTO_DLL_LOAD` x2 + `FILE_RATE_HIGH` | 0.82 | `CRYPTO_LOAD_AND_FILE_BURST` |
| `CRYPTO_DLL_LOAD` x4 in 30 s alone | 0.65 | `HIGH_FREQ_CRYPTO_DLL` |

**Layer B -- BCrypt ETW provider (admin, best-effort):**
Subscribes to the `Microsoft-Windows-Crypto-BCrypt` provider. If BCrypt events arrive
from a non-system process at >20 events / 5 seconds, a `BCRYPT_API_BURST` signal (0.75) fires.
Falls back silently if unavailable.

---

### Layer 4 -- Process Behaviour Scorer

**File:** `Monitoring/ProcessBehaviorScorer.cs`

Polls `Win32_Process` via WMI every **2 seconds**. Tracks three signals:

**I/O write rate** (`WriteTransferCount` delta since last poll):

| Rate | Raw Score |
|------|-----------|
| > 5 MB/s | 0.60 |
| > 20 MB/s | 0.85 |

**Handle storm** (handles acquired per poll interval):

| Delta | Raw Score |
|-------|-----------|
| +500 handles/2 s | 0.65 |

**Parent-child anomaly** (Living-off-the-Land pivot detection):

| Parent | Suspicious children | Raw Score |
|--------|--------------------|----|
| `winword`, `excel`, `outlook`, `powerpnt` | `cmd`, `powershell`, `wscript`, `certutil` | 0.70 |
| `explorer` | `certutil`, `regsvr32`, `mshta`, `wscript` | 0.70 |
| `svchost` | `powershell`, `cmd`, `wscript`, `certutil` | 0.70 |

**Suspicious launch location:**

| Condition | Raw Score | Indicator |
|-----------|-----------|-----------|
| Executable in `%TEMP%`, `%AppData%`, or `%LocalAppData%` | 0.65 | `PROC_SUSPICIOUS_LOCATION` |

---

### Layer 5 -- Network Monitor

**File:** `Monitoring/NetworkMonitor.cs`

Polls TCP connections every **2 seconds** via `IPGlobalProperties.GetActiveTcpConnections()`.

**Detection rules:**

| Rule | Raw Score | Detail |
|------|-----------|--------|
| `TOR_EXIT_NODE` | 0.90 | Connection to one of 20 hardcoded high-bandwidth Tor exit IPs |
| `SUSPICIOUS_PORT` | 0.55 | Outbound to 4444, 1337, 31337, 6667, 9001, 8888, 8443 |
| `HIGH_CONN_RATE` | 0.65 | >30 new distinct remote IPs within 10 seconds |
| `EXFIL_DURING_FILE_ACTIVITY` | 0.70 | New external connection within 30 s of a honeytoken/burst event |

---

### Layer 6 -- VSS / Shadow Copy Watcher

**File:** `Analysis/VssWatcher.cs`
**Requires:** Administrator

WMI `__InstanceCreationEvent` subscription intercepts every new process creation and checks
the command line against 7 patterns:

| Pattern matched | Indicator | Risk Score |
|----------------|-----------|-----------|
| `vssadmin` / `delete shadows` | `SHADOW_COPY_DELETION_ATTEMPT` | 100 / CRITICAL |
| `wbadmin` / `delete catalog` | `BACKUP_CATALOG_DELETED` | 100 / CRITICAL |
| `bcdedit` / `recoveryenabled no` | `BOOT_RECOVERY_DISABLED` | 100 / CRITICAL |

---

### Layer 7 -- Burst Detector

**File:** `Analysis/BurstDetector.cs`

Sliding **3-second window** of all FileSystemWatcher events. Fires when:

```
event_count_in_window > 10
  AND
( average_entropy_of_recent_writes > 7.0  OR  no entropy data yet )
```

A **15-second cooldown** prevents alert storms.

---

## Signal Fusion Engine

**Files:** `Alerting/SignalFusion.cs`, `Alerting/ThreatSignal.cs`

SignalFusion keeps a **per-process** list of signals with a **2-minute decay window**.

```
FusedScore = round( SUM( weight[source] * max(RawScore[source]) ) * 100 )
```

| Source | Weight | Rationale |
|--------|--------|-----------|
| Honeytoken | **0.35** | Strongest signal -- no legitimate process ever touches decoy files |
| CryptoApi | **0.25** | Bulk crypto operations are rare outside ransomware |
| EtwFileRate | **0.20** | Mass file I/O is the physical signature of bulk encryption |
| Network | **0.12** | C2 / exfiltration is indicative but less specific |
| Signature | **0.08** | Process anomalies are supporting evidence |

When `FusedScore >= 70`, a `FusedThreat` is emitted with a **30-second per-process cooldown**.

---

## Automatic Containment

**File:** `Containment/ContainmentEngine.cs`

Triggered by either:
- `HoneytokenAlert.RiskScore >= 70` (direct FSW path, fast)
- `FusedThreat.FusedScore >= 70` (multi-signal fusion path)

**Step 1 -- Suspend** (`NtSuspendProcess` P/Invoke into `ntdll.dll`):
Freezes all threads of the target process in ~1 ms.

**Step 2 -- Kill** (`Process.Kill(entireProcessTree: true)`):
Terminates the process and all its children.

**Step 3 -- Block execution path** (only for `Temp`/`AppData` binaries):
```
icacls.exe "<path>" /deny "Everyone:(X)"
MpCmdRun.exe -Scan -ScanType 3 -File "<path>"
```

**Containment modes** (configurable in `rdrs_config.json`):

| Mode | Behaviour |
|------|-----------|
| `KillAndSuspend` | Full response: suspend, kill, block, scan (default) |
| `SuspendOnly` | Freeze process but do not kill |
| `AlertOnly` | Log the alert only, take no process action |

---

## Windows Tray Application

RDRS runs as a **Windows system tray application** -- no console window by default.

**Tray icon:** Shows the RDRS logo in the system tray (bottom-right of taskbar).

**Right-click context menu:**

| Menu item | Action |
|-----------|--------|
| RDRS Active -- N honeytokens watching | Status display (non-clickable) |
| Open Dashboard | Opens the live WinForms dashboard |
| View Last Alert | Shows last alert in a message box |
| Open Alert Log | Opens `rdrs_alerts.json` in Notepad |
| Pause Protection (30s) | Temporarily disables FSW alerting |
| Exit | Cleans up honeytokens and exits |

**Double-clicking** the tray icon opens the Dashboard.

**Balloon notifications:** A balloon tip appears for every CRITICAL or HIGH alert
(configurable via `NotificationLevel` in the config).

**Auto-start:** RDRS registers itself in
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` on first launch so it starts
automatically on Windows login.

**Desktop shortcut:** `RDRS.lnk` is created on the Desktop on first launch.

---

## Live Dashboard

**File:** `UI/DashboardForm.cs`

A WinForms dark-themed dashboard (1120 x 700) showing real-time detection state.

**Status bar (top):**
- Green `PROTECTED` when watchers are active
- Yellow `PAUSED` when protection is paused

**Left panel -- Alert feed:**
- DataGridView showing the last 50 honeytoken alerts
- Rows colour-coded: red = CRITICAL, orange = HIGH, yellow = MEDIUM, gray = LOW

**Right panel -- Charts and stats:**
- GDI+ bar chart: alert counts by event type (Changed / Renamed / Deleted / Created)
- Stats panel: total alerts, uptime, last alert time, tokens watching

**Toolbar buttons:**

| Button | Action |
|--------|--------|
| Pause / Resume | Toggle FSW protection |
| Clear Alerts | Clear the on-screen grid |
| View Log | Open rdrs_alerts.json in Notepad |
| Close | Hide the dashboard (RDRS keeps running) |

The dashboard refreshes every **2 seconds**. Closing it hides it (X button); RDRS
continues running in the tray. Reopen via right-click menu or double-click tray icon.

---

## Configuration

**File:** `Config/RdrsConfig.cs`, `Config/ConfigManager.cs`

Config is stored at `%APPDATA%\RDRS\rdrs_config.json`. Created automatically on first run.

```json
{
  "ContainmentMode": "KillAndSuspend",
  "NotificationLevel": "All",
  "EnableHoneytokens": true,
  "EnableEtwMonitor": true,
  "EnableNetworkMonitor": true
}
```

**ContainmentMode options:** `KillAndSuspend` | `SuspendOnly` | `AlertOnly`

**NotificationLevel options:** `All` | `High` | `Critical`
(controls which tray balloon notifications appear)

---

## Alert Format

**Honeytoken alert (console):**

```
  +==================================================================+
  |  HONEYTOKEN ALERT [B4B6598D]  --  CRITICAL (Score: 100/100)     |
  +==================================================================+
  Time      : 2026-03-17 02:41:53
  Event     : Renamed
  Token     : _AAAA_resume_final.docx
  Directory : C:\Users\User\Desktop
  Renamed-> : C:\Users\User\Desktop\_AAAA_resume_final.docx.locked
  Process   : cmd (PID: 41920) [UNSIGNED]
  Parent    : explorer (PID: 12044)
  Proc path : C:\WINDOWS\system32\cmd.exe
  Entropy   : 7.9821 bits/byte  [HIGH_ENTROPY_WRITE]
  Indicators: HIGH_ENTROPY_WRITE, RENAMED_UNKNOWN_EXT
  -----------------------------------------------------------------
```

---

## Project Structure

```
RDRS/
|
+-- Program.cs                     Entry point -- tray mode or --console mode
+-- DeceptionEngine.cs             Orchestrator -- starts all monitors, wires callbacks
+-- HoneytokenFile.cs              Data model for a single planted decoy file
+-- HoneytokenPlanter.cs           Creates valid decoy files + configures ACLs/MIL
+-- WatcherManager.cs              FileSystemWatcher per directory + shell-process hint
+-- AlertBuilder.cs                Builds HoneytokenAlert (process attr + entropy + risk)
+-- AlertManager.cs                Thread-safe alert dispatcher + JSON append-logger
+-- ConsoleUI.cs                   Live status board + coloured alert rendering
+-- app.manifest                   UAC requireAdministrator + Windows 10/11 compat
+-- HoneytokenWatcher.csproj       .NET 8 WinExe x64 + embedded logo resource
|
+-- Alerting/
|   +-- ThreatSignal.cs            ThreatSignal / FusedThreat models + SignalSource enum
|   +-- SignalFusion.cs            Weighted per-process fusion engine (2-min decay window)
|
+-- Analysis/
|   +-- EntropyAnalyzer.cs         Shannon entropy (0-8 bits/byte, FileShare.ReadWrite)
|   +-- BurstDetector.cs           Sliding-window file-event rate + entropy threshold
|   +-- VssWatcher.cs              WMI shadow-copy / backup-deletion process watcher
|
+-- Containment/
|   +-- ContainmentEngine.cs       Suspend -> Kill -> icacls block -> Defender scan
|
+-- Config/
|   +-- RdrsConfig.cs              Config model (ContainmentMode, NotificationLevel, flags)
|   +-- ConfigManager.cs           Load/save %APPDATA%\RDRS\rdrs_config.json
|
+-- Monitoring/
|   +-- EtwMonitor.cs              NT Kernel Logger -- FileIO + ImageLoad ETW events
|   +-- CryptoApiMonitor.cs        BCrypt DLL-load frequency + cross-signal correlation
|   +-- ProcessBehaviorScorer.cs   WMI I/O rate + parent-child anomaly + launch path
|   +-- NetworkMonitor.cs          IPGlobalProperties + Tor exit IPs + exfil correlation
|
+-- UI/
|   +-- TrayApplication.cs         NotifyIcon tray agent + context menu + balloon tips
|   +-- DashboardForm.cs           WinForms live dashboard (alert grid + bar chart)
|   +-- ShieldIcon.cs              Loads embedded logo; falls back to GDI+ shield
|   +-- ransa logo.jpg             Embedded RDRS logo (EmbeddedResource)
|
+-- Tests/
    +-- test_1_write_normal.ps1    Write plain text -> CRITICAL ~80
    +-- test_2_rename_extension.ps1 Rename to .locked -> CRITICAL ~100
    +-- test_3_high_entropy_write.ps1 Write random bytes -> CRITICAL 100 + HIGH_ENTROPY_WRITE
    +-- test_4_delete_token.ps1    Delete token -> CRITICAL ~85
    +-- test_5_burst_attack.ps1    Touch all 8 tokens -> 8x CRITICAL + BURST ALERT
    +-- test_6_full_ransomware_sim.ps1 Full chain: read+encrypt+rename -> max score
```

---

## Requirements

| Requirement | Detail |
|-------------|--------|
| **OS** | Windows 10 / 11 (x64) |
| **.NET SDK** | .NET 8.0 or later |
| **Privileges** | Auto-elevates to Admin via UAC prompt on launch |
| **NuGet packages** | `System.Management 7.0.0`, `Microsoft.Diagnostics.Tracing.TraceEvent 3.1.14` |

Features available **without** admin:

- Honeytoken planting and FileSystemWatcher monitoring
- Shannon entropy analysis on writes
- File burst detection
- CryptoApiMonitor correlation layer
- ProcessBehaviorScorer (WMI works for same-user processes)
- NetworkMonitor (TCP connection polling)
- Containment of same-user processes

Features requiring **Administrator**:

- ETW kernel session (FileIOInit / FileIO / ImageLoad)
- VSS/shadow-copy watcher
- BCrypt ETW provider
- Killing elevated/system processes
- `icacls` execution-path block

---

## Installation & Build

```bash
# 1. Clone the repository
git clone https://github.com/Naks-bro/pbl-rans.git
cd pbl-rans

# 2. Restore NuGet packages
dotnet restore

# 3. Build Release (x64)
dotnet build -c Release

# Binary: bin\Release\net8.0-windows\HoneytokenWatcher.exe
```

---

## Running the Tool

Simply double-click **`HoneytokenWatcher.exe`** (or run it from a terminal).

RDRS will:
1. Show a UAC prompt to elevate to Administrator
2. Start silently in the system tray (look for the RDRS logo near the clock)
3. Plant 8 honeytokens across Desktop, Documents, Downloads, and Pictures
4. Start all detection layers in the background

**Tray icon controls:**
- **Double-click** the tray icon to open the live Dashboard
- **Right-click** for the context menu (pause, alerts, log, exit)

**Console mode** (for debugging / development):

```powershell
# Run as Administrator -- shows live status board in terminal
.\bin\Release\net8.0-windows\HoneytokenWatcher.exe --console
```

**Startup sequence (console mode):**

```
  [*] Alert log -> D:\...\rdrs_alerts.json
  [*] Planting honeytokens...
  [*] Planted 8 honeytokens across monitored directories.
  [*] Starting FileSystemWatchers...
  [*] All watchers active. Deception layer is live.
  [*] VSS/Shadow-copy watcher active.
  [*] ETW kernel file-monitor active.
  [*] Crypto-API monitor active (ETW correlation + BCrypt provider).
  [*] Process behaviour scorer active (I/O rate + parent-child anomaly).
  [*] Network monitor active (TCP connections + hardcoded Tor exits).
```

Press **`Ctrl+C`** (console mode) or **Exit** (tray menu) to stop.
All honeytoken files are deleted automatically on shutdown.

---

## Testing Detection

Six ready-to-run PowerShell test scripts are in the `Tests/` folder.

**How to run:**

```powershell
# Open PowerShell AS ADMINISTRATOR, then:
powershell -ExecutionPolicy Bypass -File "D:\PBL RANS\Tests\test_3_high_entropy_write.ps1"
```

Or right-click the `.ps1` file -> **Run with PowerShell** (as admin).

---

### Test 1 -- Write Normal Data (Score: ~80, CRITICAL)

```powershell
powershell -ExecutionPolicy Bypass -File ".\Tests\test_1_write_normal.ps1"
```

Writes plain text to `_AAAA_resume_final.docx` on the Desktop.
Triggers a `Changed` event. Expected: CRITICAL alert.

---

### Test 2 -- Rename with Extension Change (Score: ~100, CRITICAL)

```powershell
powershell -ExecutionPolicy Bypass -File ".\Tests\test_2_rename_extension.ps1"
```

Renames `_AAAA_tax_return_2024.pdf` to `.pdf.locked` then restores it.
Triggers `Renamed` + extension-change bonus. Expected: CRITICAL alert (100/100).

---

### Test 3 -- High Entropy Write (Score: 100, CRITICAL + HIGH_ENTROPY_WRITE)

```powershell
powershell -ExecutionPolicy Bypass -File ".\Tests\test_3_high_entropy_write.ps1"
```

Overwrites `_AAAA_family_vacation.jpg` with 4096 random bytes (Shannon entropy ~8.0 bits/byte,
threshold is 7.2). Triggers `HIGH_ENTROPY_WRITE` indicator (+25 pts).
Expected: CRITICAL + tray balloon notification.

---

### Test 4 -- Delete Token (Score: ~85, CRITICAL)

```powershell
powershell -ExecutionPolicy Bypass -File ".\Tests\test_4_delete_token.ps1"
```

Deletes `_AAAA_passwords_backup.txt` from Downloads.
Expected: CRITICAL alert. Restart RDRS to replant.

---

### Test 5 -- Burst Attack (Score: 80+ x8 + BURST ALERT)

```powershell
powershell -ExecutionPolicy Bypass -File ".\Tests\test_5_burst_attack.ps1"
```

Touches all 8 honeytokens within ~200 ms. Triggers BurstDetector (>= 3 events in <= 2s).
Expected: 8 CRITICAL individual alerts + 1 BURST alert in the dashboard.

---

### Test 6 -- Full Ransomware Simulation (Score: 100 x6+, containment fires)

```powershell
powershell -ExecutionPolicy Bypass -File ".\Tests\test_6_full_ransomware_sim.ps1"
```

Full attack chain: recon reads -> high-entropy overwrites -> rename with `.rdrs_enc` -> restore.
**WARNING:** This triggers full containment. Your PowerShell window may be killed if
`ContainmentMode = KillAndSuspend`. Run from a second window.

---

### Manual tests (inline)

**Shadow copy deletion** (admin required -- RDRS detects the command, does not run it):

```powershell
vssadmin delete shadows /all /quiet
```

Expected: CRITICAL alert (100/100), `SHADOW_COPY_DELETION_ATTEMPT` indicator.

---

## Output Files

| File | Contents |
|------|----------|
| `rdrs_alerts.json` | JSON array of `HoneytokenAlert` objects |
| `rdrs_containment.json` | JSON array of `ContainmentRecord` objects |
| `%APPDATA%\RDRS\rdrs_config.json` | User configuration |
| `%APPDATA%\RDRS\rdrs.ico` | RDRS icon (used by desktop shortcut) |

Example alert entry:

```json
{
  "AlertId": "B4B6598D",
  "Timestamp": "2026-03-17T02:41:53.155",
  "TokenPath": "C:\\Users\\User\\Desktop\\_AAAA_resume_final.docx",
  "TokenFileName": "_AAAA_resume_final.docx",
  "TokenDirectory": "C:\\Users\\User\\Desktop",
  "EventType": "Renamed",
  "NewPath": "C:\\Users\\User\\Desktop\\_AAAA_resume_final.docx.locked",
  "ProcessName": "powershell",
  "ProcessId": 9812,
  "ProcessPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "ParentProcessName": "explorer",
  "ParentProcessId": 12044,
  "IsSigned": true,
  "EntropyScore": -1.0,
  "RiskScore": 100,
  "RiskLabel": "CRITICAL",
  "Indicators": ["RENAMED_UNKNOWN_EXT"]
}
```

---

## Design Decisions & Limitations

**Why honeytokens as the primary signal (weight 0.35)?**
Ransomware *must* touch files. A perfectly hidden decoy that no legitimate software ever opens
provides a near-zero-false-positive signal. Any access = malicious intent.

**Why Shannon entropy?**
AES-256 and ChaCha20 ciphertext is statistically indistinguishable from random noise --
entropy ~7.95-8.0 bits/byte. Plain text sits at 4.5-5.5 bits/byte. The 7.2 threshold
catches ransomware output while tolerating normal ZIP/JPEG content (~7.0-7.5 bits/byte).

**Why `NtSuspendProcess` before `Kill`?**
`Kill()` is not instantaneous -- the OS schedules termination over several ticks.
During those milliseconds the ransomware continues encrypting files. `NtSuspendProcess`
freezes all threads in ~1 ms, stopping I/O cold, then `Kill` terminates cleanly.

**Why a weighted fusion score instead of any-signal-fires?**
Individual signals have high false-positive rates. Bcrypt.dll is loaded by browsers and
system services. File bursts happen during antivirus scans. Only the *combination* from the
same PID in a short window is conclusive.

**Known limitations:**

- ETW and VSS watcher require **admin privileges**. Without them the honeytoken FSW layer
  still works and catches most real-world ransomware.
- The Tor exit-node list is **hardcoded** and will become stale. In production, refresh it
  periodically from the Tor Project's exit-list endpoint.
- Process attribution via Restart Manager only works when the attacker holds a file handle
  open. The FSW-time shell-process hint catches one-shot commands (e.g. `Set-Content`).
- The tool does **not** prevent ransomware from encrypting files it opens *before* any
  honeytoken is touched. Planting tokens in directories with the most sensitive files
  minimises this detection window.
- WMI polling adds ~50-200 ms latency to I/O-rate signals. The FSW path has <5 ms
  end-to-end latency from file event to alert.

---

## Team & Contributions

### My Contributions

I contributed to the first three detection layers of RDRS:

- **Layer 1 — Honeytoken Deception**
  - Hidden decoy-file detection
  - Process attribution
  - Entropy analysis
  - Risk scoring

- **Layer 2 — ETW File Monitoring**
  - ETW-based monitoring of file-system activity
  - Detection of suspicious file-operation patterns

- **Layer 3 — Cryptographic API Monitoring**
  - Cryptographic API monitoring
  - Detection of suspicious encryption-related activity
  - Signal generation for downstream correlation

RDRS was developed collaboratively as a Project-Based Learning (PBL)
project.

---

## Academic Context

This project was built as part of a **Problem-Based Learning (PBL)** assignment in applied
cybersecurity. The goal was to go beyond theory and implement a working detection-and-response
tool from scratch, integrating:

- **Windows internals** -- ETW, WMI, P/Invoke (ntdll, rstrtmgr, iphlpapi), Mandatory
  Integrity Control, FileSystemWatcher, Restart Manager
- **Deception-based security** -- honeypots / honeytokens as zero-false-positive tripwires
- **Signal correlation and weighted scoring** -- multi-sensor fusion for low false-positive rate
- **Automatic incident response** -- process suspension, kill, execution path blocking
- **Windows application** -- system tray agent, WinForms dashboard, UAC elevation, autostart
- **Forensic logging** -- structured JSON audit trails for post-incident analysis

---

*Use tray icon -> Exit (or Ctrl+C in console mode) to stop. Honeytokens are always cleaned up on exit.*
