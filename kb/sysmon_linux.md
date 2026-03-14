# Sysmon for Linux Integration Guide

## Overview

This document provides guidance for integrating Sysmon for Linux logs into Splunk. Sysmon for Linux is a port of the Windows Sysmon tool to Linux, providing detailed process creation, network connection, and file operation telemetry. It is a critical visibility enhancement for Linux endpoints and servers, filling gaps that standard auditd logging does not cover — particularly process command-line arguments with parent-child relationships, DNS queries, and file creation events.

**Important:** Sysmon for Linux is a **separate tool** from Linux auditd. It requires its own installation, XML configuration file, and dedicated Splunk add-on. It writes events to syslog/journald rather than the audit subsystem.

**Log Source Type:** Agent-based (Splunk UF reads from syslog/journald)  
**Vendor:** Microsoft (Sysinternals)  
**Category:** Endpoint Telemetry  
**Primary Index:** `sysmon_linux`  
**Sourcetype:** `sysmon:linux`  
**Source:** `journald://sysmon`

## Pre-requisites

Before beginning the integration, ensure the following requirements are met:

1. **Linux Distribution** — Ubuntu 18.04+, Debian 10+, RHEL 8+, CentOS 8+, Fedora 33+, or other systemd-based distributions
2. **Kernel Requirements** — Kernel 5.3+ recommended (for eBPF support); Sysmon for Linux uses eBPF tracepoints
3. **Sysmon for Linux Package** — Install from Microsoft's Linux package repository
4. **XML Configuration File** — Tuned configuration (Splunk Attack Range config recommended as starting point)
5. **Splunk Universal Forwarder for Linux** — Deployed on target endpoints
6. **Splunk Add-on for Sysmon for Linux** — `Splunk_TA_sysmon-for-linux` from Splunkbase (App ID 6652)
7. **Root/Sudo Access** — Required for Sysmon installation and service management

### Sysmon for Linux vs. Linux Auditd

| Aspect | Linux Auditd | Sysmon for Linux |
|--------|-------------|------------------|
| Process Creation | SYSCALL records (raw, no parent-child linkage) | Event ID 1 (full command line, parent process, user, hash) |
| Network Connections | Not natively tracked | Event ID 3 (source/dest IP, port, process) |
| File Creation | PATH records (limited context) | Event ID 11 (target filename, creating process) |
| DNS Queries | Not available | Event ID 22 (queried domain, process) |
| Deployment | Built into most distros | Separate install from Microsoft repo |
| Configuration | auditctl rules / audit.rules | XML configuration file |
| Output | /var/log/audit/audit.log | syslog/journald |
| CIM Mapping | Splunk_TA_nix | Splunk_TA_sysmon-for-linux |

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Linux Endpoint (UF) | Splunk HF/Indexer | TCP 9997 | TCP | Log forwarding |
| Linux Endpoint (UF) | Deployment Server | TCP 8089 | TCP | Configuration management |
| Linux Endpoint | packages.microsoft.com | TCP 443 | HTTPS | Sysmon package installation |

## Logging Standard

### Sysmon for Linux Event ID Reference

| Event ID | Name | Description | Priority |
|----------|------|-------------|----------|
| **1** | ProcessCreate | Process creation with command line, parent process, hashes | **Critical** |
| **3** | NetworkConnect | TCP/UDP network connections with process context | **High** |
| **5** | ProcessTerminate | Process terminated | Low |
| **9** | RawAccessRead | Raw device read (disk access) | Medium |
| **11** | FileCreate | File created or overwritten | **High** |
| **16** | ConfigChange | Sysmon configuration changed | Medium |
| **23** | FileDelete | File deleted (archived) | Medium |

**Note:** Sysmon for Linux supports a subset of the Windows Sysmon Event IDs. Registry events (12/13/14), image load (7), and named pipes (17/18) are not applicable on Linux. Event ID 22 (DNS) support varies by version.

### Recommended Configuration

Use the Splunk Attack Range Sysmon for Linux configuration as a starting point:

```
https://github.com/splunk/attack_range/tree/develop/config
```

This configuration is designed for security detection and is pre-tuned to capture the most detection-relevant events while filtering common noise.

### Time Synchronization

- Sysmon for Linux uses the system clock for timestamps
- Ensure NTP is configured: `timedatectl status`
- Events are logged via syslog/journald with system-local timestamps
- Configure UTC timezone on servers for consistency: `timedatectl set-timezone UTC`

## Log Collection Standard

### Source-Side Steps (Linux Endpoint)

#### Step 1: Add Microsoft Package Repository

**For Ubuntu/Debian:**

```bash
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | sudo gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg
sudo sh -c 'echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/$(lsb_release -rs)/prod $(lsb_release -cs) main" > /etc/apt/sources.list.d/microsoft-prod.list'
sudo apt update
```

**For RHEL/CentOS:**

```bash
sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
sudo dnf install -y https://packages.microsoft.com/config/rhel/$(rpm -E %rhel)/packages-microsoft-prod.rpm
```

#### Step 2: Install Sysmon for Linux

```bash
# Ubuntu/Debian
sudo apt install -y sysmonforlinux

# RHEL/CentOS
sudo dnf install -y sysmonforlinux
```

#### Step 3: Download and Apply Configuration

```bash
# Download Splunk Attack Range config (recommended starting point)
sudo wget -O /opt/sysmon/config.xml \
  "https://raw.githubusercontent.com/splunk/attack_range/develop/config/sysmonforlinux.xml"

# Install Sysmon with configuration
sudo sysmon -accepteula -i /opt/sysmon/config.xml
```

#### Step 4: Verify Sysmon Service

```bash
# Check service status
sudo systemctl status sysmon

# Verify events are being generated
sudo journalctl -u sysmon --no-pager -n 10

# Check Sysmon version and config
sudo sysmon -c
```

#### Step 5: Update Configuration (without reinstall)

```bash
sudo sysmon -c /opt/sysmon/config.xml
```

### SIEM-Side Steps (Splunk)

#### Step 1: Install Splunk Add-on for Sysmon for Linux

Install `Splunk_TA_sysmon-for-linux` (Splunkbase App ID 6652) on:
- **Universal Forwarders** — For input collection (journald input)
- **Heavy Forwarders** — For parsing
- **Search Heads** — For field extractions and CIM mapping
- **Indexers** — For index-time parsing

#### Step 2: Create Sysmon Linux Index

```ini
# indexes.conf
[sysmon_linux]
homePath = $SPLUNK_DB/sysmon_linux/db
coldPath = $SPLUNK_DB/sysmon_linux/colddb
thawedPath = $SPLUNK_DB/sysmon_linux/thaweddb
maxTotalDataSizeMB = 256000
frozenTimePeriodInSecs = 7776000
```

#### Step 3: Configure Input on Universal Forwarders

The Splunk Add-on for Sysmon for Linux includes a default `journald://sysmon` input that is enabled by default. Verify or customize:

```ini
# inputs.conf
[journald://sysmon]
disabled = 0
index = sysmon_linux
sourcetype = sysmon:linux
```

**Alternative — File monitor input** (if sysmon writes to a log file instead of journald):

```ini
# inputs.conf
[monitor:///var/log/sysmon/sysmon.log]
disabled = 0
index = sysmon_linux
sourcetype = sysmon:linux
```

#### Step 4: Deploy via Deployment Server

```bash
# Copy TA to deployment-apps
cp -r Splunk_TA_sysmon-for-linux /opt/splunk/etc/deployment-apps/

# Create inputs override if needed
mkdir -p /opt/splunk/etc/deployment-apps/Splunk_TA_sysmon-for-linux/local/
```

Create `local/inputs.conf` if you need to override the default index:

```ini
[journald://sysmon]
disabled = 0
index = sysmon_linux
```

#### Step 5: Create Server Class

1. Navigate to **Settings > Forwarder Management**
2. Create server class: `Sysmon_Linux_Endpoints`
3. Add apps: `Splunk_TA_sysmon-for-linux`
4. Add clients: Linux endpoint forwarders

## Required Add-on / Parser

| Component | Name | App ID | Purpose |
|-----------|------|--------|---------|
| Add-on | Splunk Add-on for Sysmon for Linux | 6652 | Input collection, CIM mapping, field extraction |
| Index | sysmon_linux | — | Storage for Sysmon Linux events |

### CIM Data Model Mappings

| Sysmon Event ID | CIM Data Model |
|-----------------|----------------|
| 1 (ProcessCreate) | Endpoint.Processes |
| 3 (NetworkConnect) | Network_Traffic |
| 5 (ProcessTerminate) | Endpoint.Processes |
| 11 (FileCreate) | Endpoint.Filesystem |

## Sample Configuration Snippets

### inputs.conf (Universal Forwarder)

```ini
[journald://sysmon]
disabled = 0
index = sysmon_linux
sourcetype = sysmon:linux
```

### indexes.conf

```ini
[sysmon_linux]
homePath = $SPLUNK_DB/sysmon_linux/db
coldPath = $SPLUNK_DB/sysmon_linux/colddb
thawedPath = $SPLUNK_DB/sysmon_linux/thaweddb
maxTotalDataSizeMB = 256000
frozenTimePeriodInSecs = 7776000
```

### Sysmon for Linux Configuration (Minimal Security-Focused)

```xml
<Sysmon schemaversion="4.70">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <!-- Process Creation - Log all except known noisy processes -->
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">/opt/splunkforwarder/bin/splunkd</Image>
        <Image condition="is">/usr/lib/systemd/systemd</Image>
      </ProcessCreate>
    </RuleGroup>
    
    <!-- Network Connections - Log outbound connections -->
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <DestinationIp condition="is">127.0.0.1</DestinationIp>
        <Image condition="is">/opt/splunkforwarder/bin/splunkd</Image>
      </NetworkConnect>
    </RuleGroup>
    
    <!-- File Creation - Log all -->
    <RuleGroup name="FileCreate" groupRelation="or">
      <FileCreate onmatch="exclude">
        <Image condition="is">/opt/splunkforwarder/bin/splunkd</Image>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=sysmon_linux earliest=-15m
| stats count by EventID
| sort EventID
```

### Check Process Creation Events

```spl
index=sysmon_linux EventID=1 earliest=-1h
| stats count by Image, User
| sort -count
```

### Monitor Network Connections

```spl
index=sysmon_linux EventID=3 earliest=-1h
| stats count by Image, DestinationIp, DestinationPort
| sort -count
```

### Verify CIM Mapping

```spl
| tstats count from datamodel=Endpoint.Processes where index=sysmon_linux by Processes.process_name
| sort -count
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Sysmon service not starting | Kernel too old (needs 5.3+) | Upgrade kernel or check `dmesg` for eBPF errors |
| No events in journald | Sysmon not installed or config error | Run `sudo sysmon -c` to verify; check `systemctl status sysmon` |
| Events in journald but not in Splunk | Input not configured | Verify `journald://sysmon` input is enabled in inputs.conf |
| Wrong sourcetype | Using generic `syslog` sourcetype | Ensure `sourcetype = sysmon:linux` in inputs.conf |
| Field extractions missing | TA not installed on Search Heads | Install `Splunk_TA_sysmon-for-linux` on Search Heads |
| High CPU from Sysmon | Untuned configuration | Add exclusions for noisy processes (Splunk UF, cron, systemd) |
| Missing Event ID types | Configuration filtering them out | Review XML config `onmatch` rules |

### Diagnostic Commands

**On Linux Endpoint:**

```bash
# Check Sysmon service
sudo systemctl status sysmon

# View Sysmon config and version
sudo sysmon -c

# Check recent events in journald
sudo journalctl -u sysmon --since "10 minutes ago" --no-pager | head -30

# Check kernel compatibility
uname -r
# Should be 5.3+ for full eBPF support

# Verify eBPF programs loaded
sudo bpftool prog list | grep -i sysmon
```

**On Splunk:**

```spl
# Check indexing throughput
index=_internal source=*metrics.log group=per_sourcetype_thruput series="sysmon:linux"
| timechart avg(kb) as avg_kb_sec

# Check for forwarder errors related to journald
index=_internal sourcetype=splunkd "journald" OR "sysmon"
| stats count by log_level, message
```

## Security Notes

1. **Sysmon Configuration Security**: Like Windows Sysmon, the Linux configuration file reveals your detection strategy. Protect it with appropriate file permissions (`chmod 600`). Store it centrally and deploy via configuration management (Ansible, Puppet, Salt).

2. **Root Requirement**: Sysmon for Linux runs as root and installs eBPF programs in the kernel. This is required for the kernel-level visibility it provides. Monitor for unauthorized Sysmon configuration changes (Event ID 16).

3. **Resource Impact**: Sysmon for Linux uses eBPF tracepoints which are lightweight, but on high-activity servers (build servers, database servers), untuned configurations can impact performance. Monitor CPU impact with `top` or `htop` and tune exclusions accordingly.

4. **Hash Algorithms**: Configure SHA256 for hash generation to enable threat intelligence correlation:
   ```xml
   <HashAlgorithms>SHA256</HashAlgorithms>
   ```

5. **Sensitive Data**: Process creation events (Event ID 1) capture full command lines, which may contain credentials, tokens, or connection strings. Implement search-time data masking in Splunk for sensitive patterns.

6. **Complementary to Auditd**: Sysmon for Linux and auditd are **complementary**, not competing. Auditd provides syscall-level auditing, file access monitoring, and compliance-specific logging (SELinux, user/group changes). Sysmon provides process-centric telemetry with parent-child relationships. Deploy both for comprehensive Linux visibility.

7. **Update Strategy**: Sysmon for Linux updates come through the Microsoft package repository. Use your standard package management process (`apt upgrade sysmonforlinux` or `dnf update sysmonforlinux`). Configuration updates can be applied live with `sysmon -c newconfig.xml`.

---

*Last Updated: March 2026*  
*Version: 1.0*
