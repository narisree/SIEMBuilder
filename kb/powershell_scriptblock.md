# PowerShell Script Block Logging Integration Guide

## Overview

This document provides guidance for integrating PowerShell Script Block Logging (Event ID 4104) and related PowerShell audit logs into Splunk. PowerShell logging provides deep visibility into script execution, command invocation, and module loading — critical for detecting fileless malware, living-off-the-land attacks, and post-exploitation activity.

**Important:** PowerShell Script Block Logging is **not enabled by default** on Windows. It must be explicitly activated via Group Policy, registry, or script before any events are generated. This guide covers both the Windows-side enablement and the Splunk-side collection.

**Log Source Type:** Agent-based (Splunk UF reads PowerShell Windows Event Log channel)  
**Vendor:** Microsoft  
**Category:** Endpoint Telemetry / Script Execution Monitoring  
**Primary Index:** `win_powershell` (or `win_os` if co-located with Windows Events)  
**Sourcetype:** `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`  
**Source:** `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`

## Pre-requisites

Before beginning the integration, ensure the following requirements are met:

1. **Windows Endpoints** — Windows 8.1/Server 2012 R2 or later (Windows 10/Server 2016+ recommended for full logging support)
2. **PowerShell Version** — PowerShell 5.0+ (Windows 10/Server 2016 includes this natively; older OS requires WMF 5.1 update)
3. **Group Policy Access** — Domain admin or local admin access to enable logging via GPO or registry
4. **Splunk Universal Forwarder** — Deployed on target endpoints
5. **Splunk Add-on for Windows** — `Splunk_TA_windows` (version 9.1.2+) from Splunkbase
6. **Administrative Access** — GPO management access for enterprise deployment

### PowerShell Logging Types

| Logging Type | Event ID | Description | Recommended |
|-------------|----------|-------------|-------------|
| **Script Block Logging** | 4104 | Full deobfuscated script content as executed | **Yes — Primary** |
| **Module Logging** | 4103 | Pipeline execution details for loaded modules | Yes — Secondary |
| **Transcription Logging** | N/A (file-based) | Full session transcript written to disk | Optional |
| **Script Block Invocation Logging** | 4104 (verbose) | Logs start/stop of every script block | No — Very noisy |

**Primary focus of this guide:** Event ID 4104 (Script Block Logging), which captures the full, deobfuscated text of PowerShell scripts as they execute. This is the most valuable event for security detection because PowerShell automatically deobfuscates encoded commands before logging them.

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Windows Endpoint (UF) | Splunk HF/Indexer | TCP 9997 | TCP | Log forwarding |
| Windows Endpoint (UF) | Deployment Server | TCP 8089 | TCP | Configuration management |

**Note:** PowerShell logging writes to a local Windows Event Log channel. No additional network connectivity is required beyond the standard Splunk UF forwarding ports.

## Logging Standard

### Key Event IDs

| Event ID | Channel | Description | Priority |
|----------|---------|-------------|----------|
| **4104** | Microsoft-Windows-PowerShell/Operational | Script block text (full deobfuscated script content) | **Critical** |
| **4103** | Microsoft-Windows-PowerShell/Operational | Module/pipeline execution details | High |
| **800** | Windows PowerShell | Pipeline execution (legacy PowerShell 2.0) | Medium |
| **400/403** | Windows PowerShell | Engine start/stop | Low |
| **53504** | PowerShellCore/Operational | PowerShell 7.x+ script block logging | High (if PS7 deployed) |

### Key Fields in Event ID 4104

- `ScriptBlockText` — The full deobfuscated PowerShell script content (the primary detection field)
- `ScriptBlockId` — GUID linking multi-part script blocks together
- `MessageNumber` / `MessageTotal` — Part X of Y for large scripts split across multiple events
- `Path` — Script file path (empty for interactive commands)
- `ProcessID` — PID of the PowerShell process
- `UserID` — SID of the user executing the script

### Volume Considerations

Script Block Logging can generate significant volume, especially on:
- Servers running PowerShell-based automation (DSC, SCCM, Azure Arc)
- Systems with scheduled PowerShell scripts
- Endpoints with PowerShell-based management tools

**Estimated EPS per endpoint:** 5-50 EPS for standard workstations; 50-500+ EPS for automation-heavy servers.

### Time Synchronization

- Events use the Windows system clock (local time in classic format, UTC in XML format)
- Ensure NTP is configured on all endpoints
- Use `renderXml = true` in Splunk inputs for consistent UTC timestamps

## Log Collection Standard

### Source-Side Steps (Windows — Enable PowerShell Logging)

#### Step 1: Enable Script Block Logging via Group Policy

**Path:** `Computer Configuration > Policies > Administrative Templates > Windows Components > Windows PowerShell`

1. Open **Group Policy Management Console** (GPMC)
2. Create or edit a GPO linked to target OUs
3. Navigate to the path above
4. Configure these settings:

| Policy Setting | Value | Purpose |
|---------------|-------|---------|
| **Turn on PowerShell Script Block Logging** | Enabled | Captures Event ID 4104 |
| **Turn on Module Logging** | Enabled (Module Names: `*`) | Captures Event ID 4103 |
| **Turn on PowerShell Transcription** | Optional | File-based session transcripts |

**For Script Block Logging:**
- Set to **Enabled**
- Optionally check "Log script block invocation start / stop events" — **Warning:** This is extremely verbose and not recommended for production unless specifically needed

**For Module Logging:**
- Set to **Enabled**
- Click **Show** next to Module Names
- Enter `*` to log all modules

5. Click **OK** and close the policy editor
6. Force policy update: `gpupdate /force` on target endpoints (or wait for standard refresh)

#### Step 2: Enable via Registry (Alternative for Non-Domain Systems)

For standalone systems or script-based deployment:

```powershell
# Enable Script Block Logging
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# Enable Module Logging
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Type DWord

# Set Module Names to * (log all modules)
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*" -Type String
```

#### Step 3: Verify Logging is Active

```powershell
# Run a test command
Write-Host "PowerShell logging test"

# Check for Event ID 4104 in Event Viewer
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" -MaxEvents 5 | Format-List TimeCreated, Message
```

#### Step 4: Increase Event Log Size (Recommended)

The default PowerShell Operational log size is 15 MB, which may be insufficient for active environments:

```powershell
# Increase to 256 MB
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456
```

Or via GPO: `Computer Configuration > Policies > Administrative Templates > Windows Components > Event Log Service > PowerShell Operational > Maximum Log Size`

### SIEM-Side Steps (Splunk)

#### Step 1: Install Splunk Add-on for Windows

The `Splunk_TA_windows` handles PowerShell event parsing and CIM mapping. Install on:
- **Universal Forwarders** — For input definitions
- **Search Heads** — For field extractions
- **Indexers** — For index-time parsing

#### Step 2: Create PowerShell Index (Optional — Dedicated)

If you want to separate PowerShell logs from general Windows events:

```ini
# indexes.conf
[win_powershell]
homePath = $SPLUNK_DB/win_powershell/db
coldPath = $SPLUNK_DB/win_powershell/colddb
thawedPath = $SPLUNK_DB/win_powershell/thaweddb
maxTotalDataSizeMB = 256000
frozenTimePeriodInSecs = 7776000
```

#### Step 3: Configure Inputs on Universal Forwarders

```ini
# inputs.conf — deploy via Deployment Server
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
renderXml = true
index = win_powershell
sourcetype = XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
current_only = 0
start_from = oldest

# Optional: Legacy PowerShell channel (PowerShell 2.0 events)
[WinEventLog://Windows PowerShell]
disabled = 0
renderXml = true
index = win_powershell
sourcetype = XmlWinEventLog:Windows PowerShell
```

**Critical:** `renderXml = true` is required for proper field extraction of `ScriptBlockText` and other XML-structured fields.

#### Step 4: Configure Splunk Macros (for ESCU Content)

Many Splunk Enterprise Security Content Update (ESCU) detections use a `powershell` macro. Verify or create:

```ini
# macros.conf
[powershell]
definition = index=win_powershell sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
```

#### Step 5: Deploy via Deployment Server

Create an inputs app:

```bash
mkdir -p /opt/splunk/etc/deployment-apps/uf_powershell_inputs/local/
```

Add the `inputs.conf` from Step 3, then create a server class targeting Windows endpoints.

## Required Add-on / Parser

| Component | Name | Purpose |
|-----------|------|---------|
| Add-on | Splunk_TA_windows (v9.1.2+) | Input definitions, field extraction, CIM mapping |
| Index | win_powershell (or win_os) | Storage for PowerShell events |
| Macro | `powershell` | Referenced by ESCU detection content |

### CIM Data Model Mapping

PowerShell Script Block Logging events are not natively mapped to a standard CIM data model. Instead, most Splunk security detections query the raw events using:

```spl
`powershell` EventCode=4104 ScriptBlockText="*<keyword>*"
```

The `Splunk_TA_windows` extracts the key XML fields (`ScriptBlockText`, `ScriptBlockId`, `Path`, `ProcessID`, `UserID`) which detections rely on.

## Sample Configuration Snippets

### inputs.conf (Universal Forwarder)

```ini
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
renderXml = true
index = win_powershell
sourcetype = XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
current_only = 0
start_from = oldest
evt_resolve_ad_obj = 0

[WinEventLog://Windows PowerShell]
disabled = 0
renderXml = true
index = win_powershell
sourcetype = XmlWinEventLog:Windows PowerShell
current_only = 0
start_from = oldest
```

### macros.conf

```ini
[powershell]
definition = index=win_powershell sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
iseval = 0
```

### indexes.conf

```ini
[win_powershell]
homePath = $SPLUNK_DB/win_powershell/db
coldPath = $SPLUNK_DB/win_powershell/colddb
thawedPath = $SPLUNK_DB/win_powershell/thaweddb
maxTotalDataSizeMB = 256000
frozenTimePeriodInSecs = 7776000
```

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=win_powershell EventCode=4104 earliest=-15m
| stats count by host
| sort -count
```

### Check Script Block Content

```spl
index=win_powershell EventCode=4104 earliest=-1h
| stats count by ScriptBlockText
| sort -count
| head 20
```

### Detect Encoded Commands

```spl
index=win_powershell EventCode=4104 ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*EncodedCommand*"
| stats count by host, UserID, ScriptBlockText
```

### Verify Multi-Part Script Blocks

Large scripts are split across multiple Event ID 4104 entries. Verify reassembly:

```spl
index=win_powershell EventCode=4104 MessageTotal>1
| stats count by ScriptBlockId, MessageTotal
| where count < MessageTotal
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No Event ID 4104 events | Script Block Logging not enabled | Enable via GPO or registry (see Source-Side Steps) |
| Events present in Event Viewer but not in Splunk | Input not configured or wrong channel name | Verify `inputs.conf` has the exact channel name |
| `ScriptBlockText` field empty | `renderXml = false` | Set `renderXml = true` in inputs.conf and restart UF |
| Extremely high volume | Automation scripts generating constant 4104 events | Tune with `blacklist` in inputs.conf or filter at search time |
| Old PowerShell events (Event ID 800) only | PowerShell 2.0 on legacy systems | Upgrade to PowerShell 5.1+ (install WMF 5.1) |
| Multi-part scripts not correlating | Missing `ScriptBlockId` extraction | Ensure `Splunk_TA_windows` v9.1.2+ is installed on Search Heads |
| GPO not applying | OU targeting incorrect or GPO link disabled | Run `gpresult /h report.html` to verify policy application |

### Diagnostic Commands

**On Windows Endpoint:**

```powershell
# Verify GPO is applied
gpresult /scope computer /v | Select-String -Pattern "PowerShell"

# Check registry values
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue

# Check event log size
wevtutil gl "Microsoft-Windows-PowerShell/Operational"

# Count recent 4104 events
(Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" -MaxEvents 1000 -ErrorAction SilentlyContinue).Count
```

**On Splunk:**

```spl
# Check indexing throughput
index=_internal source=*metrics.log group=per_sourcetype_thruput series="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
| timechart avg(kb) as avg_kb_sec

# Verify hosts reporting
index=win_powershell EventCode=4104 earliest=-24h
| stats latest(_time) as last_seen count by host
| eval hours_ago = round((now() - last_seen) / 3600, 1)
| sort -hours_ago
```

## Security Notes

1. **Sensitive Content in Script Blocks**: Event ID 4104 captures the **full text** of scripts as they execute. This may include:
   - Passwords and credentials passed as parameters
   - API keys and tokens
   - Connection strings with embedded credentials
   - Personal data processed by scripts
   
   Implement role-based access control on the PowerShell index in Splunk. Consider search-time masking for known credential patterns.

2. **Deobfuscation**: PowerShell automatically deobfuscates encoded commands before logging to Event ID 4104. This means even `powershell -EncodedCommand <base64>` results in the decoded script text being logged — this is a major security advantage.

3. **PowerShell 2.0 Downgrade Attacks**: Attackers may invoke PowerShell 2.0 (which does not support Script Block Logging) to evade detection. Mitigate by:
   - Removing PowerShell 2.0 from systems: `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`
   - Monitoring for PowerShell 2.0 engine start events (Event ID 400 with `EngineVersion=2.0`)

4. **Protected Event Logging**: Windows supports encrypting sensitive script block content using CMS encryption. Splunk cannot process encrypted events — if Protected Event Logging is enabled, decrypt before ingestion or disable it for SIEM visibility.

5. **Volume Management**: On automation-heavy servers, consider:
   - Using `blacklist` in `inputs.conf` to filter known safe script patterns at collection time
   - Filtering at search time rather than collection time to preserve forensic value
   - Separate index with shorter retention for high-volume endpoints

6. **Audit Trail**: Monitor for attempts to disable PowerShell logging:
   - GPO changes to PowerShell policies
   - Registry modifications to `ScriptBlockLogging` keys
   - PowerShell 2.0 engine invocations

---

*Last Updated: March 2026*  
*Version: 1.0*
