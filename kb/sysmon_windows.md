# Sysmon (Windows) Integration Guide

## Overview

This document provides guidance for integrating Microsoft Sysmon (System Monitor) logs into Splunk. Sysmon is a Windows system service and device driver from the Sysinternals suite that monitors and logs detailed system activity — including process creation, network connections, file creation time changes, driver/image loads, and more — to the Windows Event Log. It is one of the highest-value telemetry sources for endpoint detection, threat hunting, and incident response.

**Important:** Sysmon is a **separate deployment** from standard Windows Event Logs. It requires its own installation, XML configuration, and dedicated Splunk input. Do not confuse Sysmon with the native `WinEventLog:Security` or `WinEventLog:System` channels.

**Log Source Type:** Agent-based (Splunk UF reads Sysmon Windows Event Log channel)  
**Vendor:** Microsoft (Sysinternals)  
**Category:** Endpoint Telemetry / EDR  
**Primary Index:** `sysmon`  
**Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`  
**Source:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

## Pre-requisites

Before beginning the integration, ensure the following requirements are met:

1. **Windows Endpoints** — Windows 7/Server 2008 R2 or later (Windows 10/Server 2016+ recommended)
2. **Sysmon Binary** — Download from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) (version 15.x+ recommended)
3. **Sysmon XML Configuration** — A tuned configuration file (SwiftOnSecurity or Olaf Hartong Modular recommended)
4. **Splunk Universal Forwarder** — Version 6.2.0+ (required for `renderXml` support) deployed on target endpoints
5. **Splunk Add-on for Sysmon** — `Splunk_TA_sysmon` downloaded from Splunkbase (App ID 5709)
6. **Administrative Access** — Local administrator privileges on target endpoints for Sysmon installation
7. **Deployment Method** — GPO, SCCM, Intune, or Splunk Deployment Server for enterprise rollout

### Sysmon vs. Native Windows Event Logs

| Aspect | Native Windows Security Log | Sysmon |
|--------|---------------------------|--------|
| Process Creation | Event ID 4688 (basic) | Event ID 1 (detailed — includes hashes, parent process, command line) |
| Network Connections | Not available natively | Event ID 3 (source/dest IP, port, process) |
| File Creation | Not available natively | Event ID 11 (target filename, process, creation time) |
| Registry Changes | Event ID 4657 (limited) | Event IDs 12/13/14 (create, set value, rename) |
| DNS Queries | Not available natively | Event ID 22 (queried domain, process, result) |
| Driver/Image Load | Limited | Event IDs 6/7 (signed/unsigned, hash) |
| Requires Configuration | Audit Policy (GPO) | XML configuration file |

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Windows Endpoint (UF) | Splunk HF/Indexer | TCP 9997 | TCP | Log forwarding |
| Windows Endpoint (UF) | Deployment Server | TCP 8089 | TCP | Configuration management |

**Note:** Sysmon itself does not generate any network traffic. It writes to a local Windows Event Log channel. The Splunk Universal Forwarder reads this channel and forwards the events.

## Logging Standard

### Sysmon Event ID Reference

| Event ID | Name | Description | Priority |
|----------|------|-------------|----------|
| **1** | ProcessCreate | Process creation with full command line, hashes, parent process | **Critical** |
| **2** | FileCreateTime | File creation time changed (timestomping detection) | Medium |
| **3** | NetworkConnect | TCP/UDP network connections with process context | **High** |
| **5** | ProcessTerminate | Process terminated | Low |
| **6** | DriverLoad | Driver loaded (signed/unsigned) | High |
| **7** | ImageLoad | DLL/image loaded into process | High |
| **8** | CreateRemoteThread | Remote thread creation (injection detection) | **High** |
| **9** | RawAccessRead | Raw disk access (MBR/VBR reads) | Medium |
| **10** | ProcessAccess | Process access events (LSASS access detection) | **Critical** |
| **11** | FileCreate | File created or overwritten | **High** |
| **12** | RegistryEvent (Create/Delete) | Registry key/value created or deleted | High |
| **13** | RegistryEvent (ValueSet) | Registry value set | **High** |
| **14** | RegistryEvent (Rename) | Registry key/value renamed | Medium |
| **15** | FileCreateStreamHash | Alternate data stream created | Medium |
| **17** | PipeEvent (Created) | Named pipe created | High |
| **18** | PipeEvent (Connected) | Named pipe connected | High |
| **20** | WmiEvent (Consumer) | WMI consumer registered | High |
| **21** | WmiEvent (ConsumerBind) | WMI consumer bound to filter | High |
| **22** | DNSEvent | DNS query performed with process context | **High** |
| **23** | FileDelete (Archived) | File deleted (archived copy kept) | Medium |
| **25** | ProcessTampering | Process image changed (process hollowing) | **Critical** |
| **26** | FileDeleteDetected | File deleted (logged, not archived) | Medium |
| **29** | FileExecutableDetected | Executable file written to disk | High |

### Time Synchronization

- Sysmon timestamps are generated by the Windows kernel — they use the system clock
- Ensure NTP is configured on all Windows endpoints (`w32tm /query /status`)
- Sysmon logs timestamps in UTC format within the XML event structure
- Use consistent timezone settings across the fleet for correlation

### Recommended Configuration

We recommend using one of these community-maintained Sysmon configurations as a starting point:

1. **SwiftOnSecurity sysmon-config** — Single-file, well-documented, good for getting started
   - Repository: `https://github.com/SwiftOnSecurity/sysmon-config`
   
2. **Olaf Hartong Modular Sysmon** — Modular structure, better for enterprise tuning
   - Repository: `https://github.com/olafhartong/sysmon-modular`

**Important:** Both configurations require tuning for your environment. Out-of-the-box deployment will generate significant noise from legitimate system processes. Plan for a tuning phase after initial deployment.

## Log Collection Standard

### Source-Side Steps (Windows Endpoint)

#### Step 1: Download Sysmon

Download the latest Sysmon from Microsoft Sysinternals:

```
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
```

Extract `Sysmon64.exe` (for 64-bit systems) to a deployment directory, e.g., `C:\Tools\Sysmon\`.

#### Step 2: Obtain and Customize Configuration

Download a base configuration:

```powershell
# SwiftOnSecurity
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"
```

**Recommended exclusions for Splunk environments** — Add these to the `<ProcessCreate onmatch="exclude">` section to prevent Splunk forwarder noise:

```xml
<Image condition="is">C:\Program Files\SplunkUniversalForwarder\bin\splunkd.exe</Image>
<Image condition="is">C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe</Image>
<Image condition="is">C:\Program Files\SplunkUniversalForwarder\bin\splunk-MonitorNoHandle.exe</Image>
```

#### Step 3: Install Sysmon

**Single machine (manual):**

```cmd
# Run as Administrator
Sysmon64.exe -accepteula -i sysmonconfig.xml
```

**Enterprise deployment via GPO Startup Script:**

```cmd
@echo off
REM Check if Sysmon is already installed
sc query Sysmon64 >nul 2>&1
if %errorlevel% NEQ 0 (
    "\\<FILESERVER>\sysmon$\Sysmon64.exe" -accepteula -i "\\<FILESERVER>\sysmon$\sysmonconfig.xml"
)
```

**Update existing configuration:**

```cmd
Sysmon64.exe -c sysmonconfig.xml
```

#### Step 4: Verify Sysmon Installation

```powershell
# Check service status
Get-Service Sysmon64

# Check installed version and config hash
Sysmon64.exe -c

# Verify events in Event Viewer
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

### SIEM-Side Steps (Splunk)

#### Step 1: Install Splunk Add-on for Sysmon

Install `Splunk_TA_sysmon` (Splunkbase App ID 5709) on:
- **Universal Forwarders** — For input collection
- **Heavy Forwarders** — For parsing (if UFs forward through HFs)
- **Search Heads** — For field extractions and CIM mapping
- **Indexers** — For index-time parsing

**Note:** The Splunk Add-on for Sysmon (`Splunk_TA_sysmon`, App 5709) is the **Splunk-supported** version. The older community add-on (`Splunk Add-on for Microsoft Sysmon`, App 1914) is archived. Migrate to the supported version.

#### Step 2: Create Sysmon Index

```ini
# indexes.conf
[sysmon]
homePath = $SPLUNK_DB/sysmon/db
coldPath = $SPLUNK_DB/sysmon/colddb
thawedPath = $SPLUNK_DB/sysmon/thaweddb
maxTotalDataSizeMB = 512000
frozenTimePeriodInSecs = 7776000
```

#### Step 3: Configure Input on Universal Forwarders

Create or edit `inputs.conf` on each Universal Forwarder (or deploy via Deployment Server):

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
index = sysmon
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

**Critical:** `renderXml = true` is required. Without it, events are collected in classic format and the TA's field extractions will not work correctly.

#### Step 4: Deploy via Deployment Server

```bash
# Copy TA to deployment-apps
cp -r Splunk_TA_sysmon /opt/splunk/etc/deployment-apps/

# Create inputs app for forwarders
mkdir -p /opt/splunk/etc/deployment-apps/uf_sysmon_inputs/local/
```

Create `/opt/splunk/etc/deployment-apps/uf_sysmon_inputs/local/inputs.conf`:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
index = sysmon
```

#### Step 5: Create Server Class

1. Navigate to **Settings > Forwarder Management**
2. Create server class: `Sysmon_Windows_Endpoints`
3. Add apps: `Splunk_TA_sysmon` and `uf_sysmon_inputs`
4. Add clients: Windows endpoint forwarders

## Required Add-on / Parser

| Component | Name | App ID | Purpose |
|-----------|------|--------|---------|
| Add-on | Splunk Add-on for Sysmon | 5709 | Input collection, CIM mapping, field extraction |
| Index | sysmon | — | Storage for Sysmon events |

### CIM Data Model Mappings

The Splunk TA for Sysmon maps events to the following CIM data models:

| Sysmon Event ID | CIM Data Model |
|-----------------|----------------|
| 1 (ProcessCreate) | Endpoint.Processes |
| 3 (NetworkConnect) | Network_Traffic |
| 7 (ImageLoad) | Endpoint.Processes |
| 10 (ProcessAccess) | Endpoint.Processes |
| 11 (FileCreate) | Endpoint.Filesystem |
| 12/13/14 (Registry) | Endpoint.Registry |
| 22 (DNSEvent) | Network_Resolution |

## Sample Configuration Snippets

### inputs.conf (Universal Forwarder)

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
index = sysmon
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
current_only = 0
start_from = oldest
```

### props.conf (Reference — included in TA)

```ini
[XmlWinEventLog:Microsoft-Windows-Sysmon/Operational]
SHOULD_LINEMERGE = false
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%Z
TZ = UTC
KV_MODE = xml
```

### indexes.conf

```ini
[sysmon]
homePath = $SPLUNK_DB/sysmon/db
coldPath = $SPLUNK_DB/sysmon/colddb
thawedPath = $SPLUNK_DB/sysmon/thaweddb
maxTotalDataSizeMB = 512000
frozenTimePeriodInSecs = 7776000
```

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=sysmon earliest=-15m
| stats count by EventCode
| sort EventCode
```

### Check Process Creation Events

```spl
index=sysmon EventCode=1 earliest=-1h
| stats count by Image, User
| sort -count
```

### Monitor DNS Queries

```spl
index=sysmon EventCode=22 earliest=-1h
| stats count by QueryName, Image
| sort -count
```

### Verify CIM Mapping

```spl
| tstats count from datamodel=Endpoint.Processes where index=sysmon by Processes.process_name
| sort -count
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No events in Sysmon index | Sysmon not installed on endpoint | Run `Sysmon64.exe -c` to verify installation |
| Events not parsing correctly | `renderXml = false` or missing | Set `renderXml = true` in inputs.conf |
| Missing EventCode types | Configuration filtering them out | Review Sysmon XML config for exclusions |
| Extremely high event volume | Untuned configuration | Add exclusions for noisy legitimate processes |
| Field extractions missing | TA not installed on Search Heads | Install `Splunk_TA_sysmon` on Search Heads |
| CIM data model empty | TA not installed or accelerations not built | Verify TA installation, rebuild data model accelerations |
| Old sourcetype `sysmon` instead of XML | Using legacy community TA | Migrate to `Splunk_TA_sysmon` (App 5709) |

### Diagnostic Commands

**On Windows Endpoint:**

```powershell
# Check Sysmon service
Get-Service Sysmon64

# View Sysmon config and schema version
Sysmon64.exe -c

# Check event count in last hour
(Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1000 | 
    Where-Object {$_.TimeCreated -gt (Get-Date).AddHours(-1)}).Count

# Verify Sysmon driver loaded
fltmc.exe | findstr SysmonDrv
```

**On Splunk:**

```spl
# Check indexing throughput
index=_internal source=*metrics.log group=per_sourcetype_thruput series="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| timechart avg(kb) as avg_kb_sec

# Check for forwarder errors
index=_internal sourcetype=splunkd component=WinEventLog "Sysmon"
| stats count by log_level, message
```

## Security Notes

1. **Sysmon Configuration Security**: The Sysmon configuration file reveals your detection strategy. Store it on restricted file shares and deploy via secure channels (GPO, SCCM). Attackers who obtain your config can craft evasions for your exclusions.

2. **Sysmon Tamper Resistance**: Sysmon installs as a protected Windows service and kernel driver. However, a local administrator can uninstall or reconfigure it. Monitor for Sysmon Event ID 255 (Sysmon errors) and alert on Sysmon service stops.

3. **Hash Algorithms**: Configure Sysmon to log SHA256 hashes (or SHA256 + MD5 + IMPHASH) for threat intelligence correlation:
   ```xml
   <HashAlgorithms>SHA256,MD5,IMPHASH</HashAlgorithms>
   ```

4. **Sensitive Data**: Sysmon Event ID 1 captures full command lines, which may contain passwords, tokens, or connection strings passed as arguments. Consider:
   - Search-time data masking in Splunk for sensitive fields
   - Sysmon configuration exclusions for known credential-bearing processes
   - Role-based access control on the `sysmon` index

5. **Resource Impact**: Sysmon is lightweight but does consume CPU and disk I/O, especially on high-activity servers. Monitor for:
   - Event log queue buildup
   - CPU impact of Sysmon driver
   - Splunk UF queue sizes for the Sysmon input

6. **Update Strategy**: Sysmon updates require a re-install with `-u` (uninstall) followed by fresh install, or in-place upgrade with the installer. Plan maintenance windows for Sysmon binary updates. Configuration updates can be applied live with `Sysmon64.exe -c newconfig.xml`.

---

*Last Updated: March 2026*  
*Version: 1.0*
