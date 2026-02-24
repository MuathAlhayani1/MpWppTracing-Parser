# MpWppTracing Forensic Parser

A PowerShell Script for extracting and classifying artifacts from Windows Defender's binary WPP trace files (`MpWppTracing-*.bin`).


## Background

Windows Defender writes diagnostic WPP (Windows Software Trace Preprocessor) trace logs to:

```
C:\ProgramData\Microsoft\Windows Defender\Support\
MpWppTracing-YYYYMMDD-HHMMSS-00000003-fffffffeffffffff.bin
```

These binary files are circular ETW (Event Tracing for Windows) buffers written by Defender's internal components at the instrumentation level — before any filtering or verdict logic is applied. This means they capture:

- Files scanned but **not** flagged (below detection threshold, deleted before signatures updated, or scanned by a LOLBAS)
- Full command-line arguments passed to processes Defender examined
- Internal component activity (MpEngine, MpRtp, MpFilter, NisSrv) with PID, TID, and sub-millisecond UTC timestamps
- Data that persists even when `MPLog` and `MPDetection` have been cleared or rotated

### Comparison with Standard Defender Logs

| Artifact | Detections only | Clean file scans | Command lines | PID/TID | UTC sub-ms timestamps | Component detail |
|---|---|---|---|---|---|---|
| `MPDetection` | Yes | No | Partial | No | No | No |
| `MPLog` | No | Partial | Partial | No | No (local time) | No |
| **MpWppTracing** | No | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** |

---

## How It Works

The parser operates in two independent stages:

### Stage 1 — String Extraction

Performs two passes over the raw byte array:

- **ASCII pass** — extracts contiguous printable ASCII runs (0x20–0x7E)
- **UTF-16LE pass** — walks byte pairs to reconstruct Windows-native wide strings, which is the encoding WPP uses internally for file paths and command lines

Results are deduplicated via a `HashSet` before classification.

### Stage 2 — WPP/ETW Binary Structure Parsing

Walks the ETW circular buffer format, scanning for WPP record markers:
- `0xFF` — user-mode records (MpEngine, MpRtp, MpClient)
- `0xC0` — kernel-mode records (MpFilter driver)

Each record yields: **UTC timestamp** (FILETIME, 100ns resolution), **PID**, **TID**, **Message GUID**, **flags**, and raw **payload bytes** — data invisible to string extraction alone.

---

## Detected Artifact Categories

### PowerShell

| Pattern | Description | Severity |
|---|---|---|
| `PS_ENCODED_CMD` | `-EncodedCommand` / `-enc` with base64 payload (auto-decoded) | CRITICAL |
| `PS_DOWNLOAD_CRADLE` | `IEX`, `WebClient`, `DownloadString`, `BitsTransfer` | CRITICAL |
| `PS_AMSI_BYPASS` | `amsiInitFailed`, `AmsiScanBuffer`, `amsi.dll` references | CRITICAL |
| `PS_EXEC_BYPASS` | `-ExecutionPolicy Bypass` | HIGH |
| `PS_REFLECTION` | `Assembly.Load`, `[Reflection.Assembly]` | HIGH |
| `PS_INVOCATION` | `powershell.exe` with arguments | MEDIUM |

### Executable / DLL Paths

| Pattern | Description | Severity |
|---|---|---|
| `PATH_LOLBAS` | 20+ LOLBAS binaries (certutil, mshta, rundll32, msbuild, etc.) | HIGH |
| `PATH_SUSPICIOUS_LOC` | Executables in Temp, Downloads, Desktop, Public, ProgramData | HIGH |
| `PATH_UNC` | UNC paths — lateral movement / remote execution indicators | HIGH |
| `PATH_EXE_DLL` | Any `.exe`, `.dll`, `.sys`, `.drv` path | INFO |

### Network Indicators

| Pattern | Description | Severity |
|---|---|---|
| `NET_DIRECT_IP_URL` | HTTP/HTTPS URL with raw IP address — C2 indicator | CRITICAL |
| `NET_SUSPICIOUS_TLD` | Domains with abused TLDs (`.top`, `.xyz`, `.tk`, `.onion`, `.ru`, etc.) | HIGH |
| `NET_URL` | HTTP/HTTPS URLs | MEDIUM |
| `NET_IP_ADDRESS` | IPv4 addresses with optional port | MEDIUM |

### Registry Keys

| Pattern | Description | Severity |
|---|---|---|
| `REG_RUN_KEY` | `Run`, `RunOnce`, `RunServices` — persistence | HIGH |
| `REG_PERSISTENCE` | `Winlogon`, `AppInit_DLLs`, `Image File Execution Options`, `ServiceDll` | HIGH |
| `REG_DEFENDER_TAMPER` | Defender Exclusions / Real-Time Protection keys — tamper indicator | HIGH |
| `REG_GENERAL` | Any registry hive path | INFO |

---

## Requirements

- PowerShell 5.1 or later
- **Administrator privileges** to access live Defender support logs
- No external dependencies — pure PowerShell

---

## Usage

### Basic — scan all MpWppTracing files on the local system

```powershell
# Run as Administrator
.\Parse-MpWppTracingBin.ps1
```

### Parse a specific collected file

```powershell
.\Parse-MpWppTracingBin.ps1 -Path "C:\Cases\Case042\MpWppTracing-20260219-022713-00000003-fffffffeffffffff.bin"
```

### Suspicious findings only

```powershell
.\Parse-MpWppTracingBin.ps1 -Path .\*.bin -SuspiciousOnly
```

### Custom CSV export path

```powershell
.\Parse-MpWppTracingBin.ps1 -Path .\*.bin -ExportCsv C:\Cases\findings.csv
```

### String extraction only (skip binary structure parsing)

```powershell
.\Parse-MpWppTracingBin.ps1 -Path .\trace.bin -SkipBinaryParsing
```

### Include all extracted strings for manual review

```powershell
.\Parse-MpWppTracingBin.ps1 -Path .\trace.bin -IncludeRaw
```

### Pipe results for custom triage

```powershell
$iocs = .\Parse-MpWppTracingBin.ps1 -Path .\*.bin
$iocs | Where-Object { $_.Severity -eq 'CRITICAL' } | Select-Object MatchedValue, DecodedB64
$iocs | Where-Object { $_.Category -eq 'WppRecord' } | Format-Table Timestamp, PID, TID, MatchedValue
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Path` | `string[]` | Defender Support dir | Path(s) to `.bin` files. Accepts wildcards. |
| `-MinStringLength` | `int` | `8` | Minimum string length to extract. Raise to reduce noise. |
| `-SuspiciousOnly` | `switch` | off | Show only CRITICAL and HIGH severity findings. |
| `-IncludeRaw` | `switch` | off | Include all extracted strings as additional rows. |
| `-SkipBinaryParsing` | `switch` | off | Skip ETW structure parsing, string extraction only. |
| `-ExportCsv` | `string` | auto-named | Custom CSV output path. |
| `-NoExport` | `switch` | off | Console output only, no CSV written. |

---

## Output

### Console

Color-coded report grouped by category, sorted CRITICAL → HIGH → MEDIUM → INFO. Base64-encoded PowerShell payloads are decoded and printed inline.

### CSV Columns

| Column | Description |
|---|---|
| `SourceFile` | Source `.bin` filename |
| `Severity` | CRITICAL / HIGH / MEDIUM / INFO |
| `Category` | PowerShell / ExecutablePath / NetworkIndicator / RegistryKey / WppRecord |
| `PatternName` | Specific rule that matched |
| `Description` | Human-readable description of the finding |
| `Timestamp` | UTC timestamp from WPP record (binary records only) |
| `PID` | Process ID from WPP record header |
| `TID` | Thread ID from WPP record header |
| `MessageGUID` | WPP message GUID |
| `Flags` | Record flags (hex) |
| `PayloadSize` | Raw payload byte count |
| `MatchedValue` | The string or payload that matched |
| `DecodedB64` | Decoded base64 payload (PowerShell encoded commands) |
| `PayloadHex` | First 128 bytes of payload as hex (binary records) |
| `RecordOffset` | Byte offset of record in source file |

---

## Notes

- The script opens `.bin` files with `FileShare.ReadWrite` so it can read files currently locked by the Defender service — no need to stop Defender or copy files first.
- `MPLog` and `MPDetection` record events at the operational layer (after verdict). `MpWppTracing` records at the instrumentation layer (before verdict), making it useful for recovering artifacts from files that were scanned but not flagged.
- Timestamps in binary WPP records are UTC FILETIME values (100-nanosecond resolution) — suitable for precise timeline correlation with NTFS `$MFT`, Windows Event Logs, and Sysmon.

---

## Author

Muath Alhayani
