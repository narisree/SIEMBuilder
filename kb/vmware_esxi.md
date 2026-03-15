# VMware ESXi Integration Guide

## Overview

This document provides guidance for integrating VMware ESXi hypervisor logs into Splunk. ESXi generates syslog data covering authentication events, virtual machine operations, storage events, network configuration changes, and system health — providing critical visibility into the hypervisor layer that sits beneath your virtual infrastructure.

**Log Source Type:** Syslog  
**Vendor:** VMware (Broadcom)  
**Category:** Hypervisor / Virtualization Infrastructure  
**Primary Index:** `vmware_esxi`  
**Sourcetype:** `vmware:esxi:syslog`

## Pre-requisites

1. **VMware ESXi** — Version 7.0+ (8.0 recommended)
2. **vCenter Server** — For centralized management (optional but recommended)
3. **Splunk Infrastructure** — Active Splunk deployment with Heavy Forwarder or syslog relay
4. **Splunk Add-on for VMware ESXi** — From Splunkbase
5. **Network Connectivity** — Syslog from ESXi hosts to Splunk HF on UDP/TCP 514
6. **Administrative Access** — ESXi root or vCenter admin for syslog configuration

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| ESXi Host | Splunk HF / Syslog Server | UDP 514 | UDP | Syslog forwarding |
| ESXi Host | Splunk HF / Syslog Server | TCP 514 | TCP | Reliable syslog (recommended) |
| ESXi Host | Splunk HF / Syslog Server | TCP 1514 | TCP | Alternate syslog port |
| Splunk HF | Splunk Indexer | TCP 9997 | TCP | Log forwarding |

## Logging Standard

### ESXi Log Types

| Log | File Path | Description | Priority |
|-----|-----------|-------------|----------|
| **hostd** | /var/log/hostd.log | Host management daemon (VM operations, auth) | **Critical** |
| **vpxa** | /var/log/vpxa.log | vCenter agent on ESXi | High |
| **vmkernel** | /var/log/vmkernel.log | Kernel messages (storage, network, drivers) | **High** |
| **auth** | /var/log/auth.log | Authentication events (SSH, Direct Console) | **Critical** |
| **shell** | /var/log/shell.log | ESXi Shell/SSH command history | **Critical** |
| **vobd** | /var/log/vobd.log | VMware Observability daemon events | Medium |
| **fdm** | /var/log/fdm.log | vSphere HA fault domain manager | Medium |
| **vmkwarning** | /var/log/vmkwarning.log | Kernel warnings | Medium |

### Key Security Events

| Event | Source Log | Detection Value |
|-------|-----------|-----------------|
| SSH login success/failure | auth.log | Unauthorized access attempts |
| ESXi Shell enabled | hostd.log | Shell should be disabled in production |
| VM power on/off/delete | hostd.log | Unauthorized VM operations |
| Snapshot create/delete | hostd.log | Ransomware targeting snapshots |
| Datastore access | vmkernel.log | Unauthorized storage access |
| Configuration change | hostd.log | Drift detection, unauthorized changes |
| Account lockout | auth.log | Brute force detection |
| vMotion events | vpxa.log | Unexpected VM migrations |

### Time Synchronization

- ESXi uses NTP for time sync — verify with `esxcli system ntp get`
- Syslog timestamps use the ESXi host clock
- Configure UTC timezone for consistency: `esxcli system time set --timezone=UTC`

## Log Collection Standard

### Source-Side Steps (ESXi Host)

#### Step 1: Configure Syslog via ESXi CLI

```bash
# SSH to ESXi host (or use DCUI)

# Set syslog target
esxcli system syslog config set --loghost=tcp://<SPLUNK_HF_IP>:514

# Verify configuration
esxcli system syslog config get

# Reload syslog
esxcli system syslog reload
```

#### Step 2: Configure via vCenter (Multiple Hosts)

1. Navigate to **vCenter > Host > Configure > System > Advanced System Settings**
2. Search for `Syslog.global.logHost`
3. Set value: `tcp://<SPLUNK_HF_IP>:514`
4. For multiple destinations: `tcp://<PRIMARY_IP>:514,tcp://<BACKUP_IP>:514`

#### Step 3: Open ESXi Firewall for Syslog

```bash
# Enable syslog firewall rule
esxcli network firewall ruleset set --ruleset-id=syslog --enabled=true

# Verify
esxcli network firewall ruleset list | grep syslog
```

#### Step 4: Verify Syslog is Sending

```bash
# Generate a test event
logger -t test "Syslog test from ESXi"

# Check syslog status
esxcli system syslog config get
```

### SIEM-Side Steps (Splunk)

#### Step 1: Install VMware TA

Install the Splunk Add-on for VMware ESXi on Heavy Forwarders and Search Heads.

#### Step 2: Create ESXi Index

```ini
[vmware_esxi]
homePath = $SPLUNK_DB/vmware_esxi/db
coldPath = $SPLUNK_DB/vmware_esxi/colddb
thawedPath = $SPLUNK_DB/vmware_esxi/thaweddb
maxTotalDataSizeMB = 128000
frozenTimePeriodInSecs = 7776000
```

#### Step 3: Configure Syslog Input

```ini
# inputs.conf
[tcp://514]
index = vmware_esxi
sourcetype = vmware:esxi:syslog
connection_host = ip
no_appending_timestamp = true
```

## Required Add-on / Parser

| Component | Name | Purpose |
|-----------|------|---------|
| Add-on | Splunk Add-on for VMware ESXi | Field extraction, CIM mapping |
| Index | vmware_esxi | Storage for ESXi logs |

### CIM Data Model Mappings

| ESXi Event Type | CIM Data Model |
|----------------|----------------|
| Authentication events | Authentication |
| VM operations | Change |
| Configuration changes | Change |

## Sample Configuration Snippets

### inputs.conf

```ini
[tcp://514]
index = vmware_esxi
sourcetype = vmware:esxi:syslog
connection_host = ip
```

### ESXi Syslog Configuration

```bash
# Single syslog target
esxcli system syslog config set --loghost=tcp://<SPLUNK_HF_IP>:514

# Multiple targets (primary + backup)
esxcli system syslog config set --loghost=tcp://<PRIMARY>:514,tcp://<BACKUP>:514

# Reload after changes
esxcli system syslog reload
```

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=vmware_esxi earliest=-15m
| stats count by host, sourcetype
```

### Check Authentication Events

```spl
index=vmware_esxi "authentication" OR "login" OR "session" earliest=-24h
| stats count by host, _raw
| sort -count
```

### Monitor VM Operations

```spl
index=vmware_esxi ("VmPoweredOn" OR "VmPoweredOff" OR "VmReconfigured" OR "VmCreated" OR "VmRemoved") earliest=-24h
| table _time, host, _raw
```

### Detect SSH Access

```spl
index=vmware_esxi sourcetype="vmware:esxi:syslog" "SSH" OR "shell"
| stats count by host, _raw
| sort -count
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No syslog received | Firewall rule not enabled | Run `esxcli network firewall ruleset set --ruleset-id=syslog --enabled=true` |
| Logs from only some hosts | Syslog not configured on all hosts | Use vCenter to set syslog globally via Host Profile |
| Timestamp parsing issues | ESXi timezone mismatch | Set UTC timezone on ESXi hosts |
| Missing VM operation events | hostd events not forwarded | Verify syslog config includes all facility levels |
| Duplicate events | Multiple syslog targets sending to same Splunk | Check loghost configuration for duplicates |

## Security Notes

1. **SSH Access**: ESXi Shell and SSH should be disabled in production. Alert on SSH being enabled (`vim-cmd hostsvc/enable_ssh`).
2. **Root Access**: All ESXi management access uses the root account by default. Monitor for root login from unexpected sources.
3. **Lockdown Mode**: Enable Lockdown Mode to restrict direct host access, requiring all management through vCenter.
4. **Syslog Transport**: Use TCP syslog (not UDP) for reliable delivery. Consider TLS-encrypted syslog for compliance environments.
5. **Snapshot Monitoring**: Ransomware targeting VMware environments often deletes snapshots before encrypting VMs. Alert on snapshot deletion events.
6. **Host Profiles**: Use vCenter Host Profiles to enforce consistent syslog configuration across all ESXi hosts.

---

*Last Updated: March 2026*  
*Version: 1.0*
