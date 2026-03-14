# Cisco Secure Firewall (FTD) Integration Guide

## Overview

This document provides guidance for integrating Cisco Secure Firewall Threat Defense (FTD) logs into Splunk. FTD (formerly Firepower Threat Defense) is Cisco's next-generation firewall platform that combines traditional firewall capabilities with intrusion prevention (IPS), advanced malware protection (AMP), URL filtering, and application visibility. FTD generates rich telemetry including connection events, intrusion events, file/malware events, and security intelligence data.

**Important:** Cisco FTD is a **different product** from Cisco ASA. While FTD syslog messages share a similar format to ASA (using `%FTD-` prefix instead of `%ASA-`), FTD also generates additional event types (intrusion, file, malware) via the eStreamer protocol or the Cisco Security Cloud app that ASA does not produce. FTD requires its own integration approach.

**Log Source Type:** Syslog or eStreamer / Cisco Security Cloud App  
**Vendor:** Cisco  
**Category:** Next-Generation Firewall / IPS  
**Primary Index:** `cisco_ftd`  
**Sourcetypes:** `cisco:ftd`, `cisco:firepower:estreamer`

## Pre-requisites

Before beginning the integration, ensure the following requirements are met:

1. **Cisco FTD Appliance** — Running FTD version 6.0+ (7.x recommended)
2. **Firewall Management Center (FMC)** — On-premises FMC or Cloud-delivered FMC (cdFMC) for centralized management
3. **Splunk Infrastructure** — Active Splunk deployment with Heavy Forwarder
4. **Cisco Security Cloud App for Splunk** — `Cisco_Security_Cloud` (App ID 7404) from Splunkbase (recommended for eStreamer)
5. **Network Connectivity** — Syslog or eStreamer connectivity from FTD/FMC to Splunk
6. **Administrative Access** — Admin access to FMC for syslog/eStreamer configuration

### Integration Method Options

| Method | Event Types | Latency | Complexity | Recommended |
|--------|------------|---------|------------|-------------|
| **Syslog** | Connection events, system logs, firewall events | Near real-time | Low | Yes — for basic |
| **eStreamer via Cisco Security Cloud App** | Connection + Intrusion + File + Malware events | Near real-time | Medium | **Yes — for full visibility** |
| **FTD Syslog + Splunk_TA_cisco-asa** | Connection events (parsed as ASA format) | Near real-time | Low | Alternative |

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Cisco FTD | Splunk HF | UDP 514 / TCP 514 | Syslog | Syslog forwarding |
| Cisco FMC | Splunk HF | TCP 8302 | eStreamer | eStreamer event streaming |
| Splunk HF | Splunk Indexer | TCP 9997 | TCP | Log forwarding |

## Logging Standard

### FTD Event Types

| Event Type | Source | Description | Priority |
|-----------|--------|-------------|----------|
| **Connection Events** | FTD Syslog / eStreamer | TCP/UDP session start/end, allow/block decisions | **Critical** |
| **Intrusion Events** | eStreamer only | IPS alerts with signature, impact, classification | **Critical** |
| **File Events** | eStreamer only | File detected, file blocked, file type identification | **High** |
| **Malware Events** | eStreamer only | AMP detections, retrospective malware verdicts | **Critical** |
| **Security Intelligence** | eStreamer only | IP/URL/DNS blocked by security intelligence feeds | High |
| **System Events** | Syslog | FTD platform events, failover, resource utilization | Medium |

### Key Syslog Message IDs (FTD)

FTD syslog messages use the same format as ASA but with `%FTD-` prefix:

| Message ID | Description | Priority |
|-----------|-------------|----------|
| %FTD-6-302013/302014 | TCP connection built/teardown | High |
| %FTD-6-302015/302016 | UDP connection built/teardown | High |
| %FTD-4-106023 | Denied packet | High |
| %FTD-4-419002 | Duplicate TCP SYN | Medium |
| %FTD-5-111008/111010 | Configuration changes | High |
| %FTD-2-106001 | Inbound TCP connection denied | High |
| %FTD-3-710003 | TCP access denied by ACL | High |

### Time Synchronization

- FTD timestamps follow the configured timezone on the device (UTC recommended)
- Ensure NTP is configured on FTD: `show ntp` in FTD CLI
- eStreamer events include epoch timestamps

## Log Collection Standard

### Method 1: Syslog (Basic — Connection Events)

#### Source-Side Steps (FMC)

##### Step 1: Configure Syslog Server in FMC

1. Navigate to **Devices > Platform Settings**
2. Select or create a platform settings policy
3. Go to **Syslog > Syslog Servers**
4. Click **Add** and configure:
   - **IP Address**: `<SPLUNK_HF_IP>`
   - **Protocol**: UDP (or TCP for reliability)
   - **Port**: 514 (or custom high port)
   - **Interface**: Select the management/data interface with connectivity to Splunk

##### Step 2: Configure Logging Settings

1. In the same Platform Settings policy, go to **Syslog > Logging Setup**
2. Enable **Send syslogs**
3. Set **Logging Level**: Informational (level 6)
4. Enable **Include Device ID in Syslog**: Hostname

##### Step 3: Enable Logging on Access Control Rules

1. Navigate to **Policies > Access Control**
2. Edit each rule that should generate logs
3. In the **Logging** tab:
   - Enable **Log at Beginning of Connection** and/or **Log at End of Connection**
   - Select **Syslog** as the logging destination
4. Deploy changes to the FTD

#### SIEM-Side Steps (Splunk — Syslog Method)

##### Configure Syslog Input

```ini
# inputs.conf
[udp://514]
index = cisco_ftd
sourcetype = cisco:ftd
connection_host = ip
no_appending_timestamp = true
```

**Note:** If using the `Splunk_TA_cisco-asa` for parsing (since FTD syslog format is nearly identical to ASA), you may need to create a custom sourcetype alias or use `cisco:asa` as the sourcetype and tag FTD devices separately. See the Troubleshooting section for details.

### Method 2: Cisco Security Cloud App (Full — eStreamer)

#### Source-Side Steps (FMC)

##### Step 1: Create eStreamer Certificate

1. Navigate to **System > Integration > eStreamer**
2. Click **Create Client**
3. Enter the Splunk HF hostname/IP
4. Download the PKCS12 certificate file
5. Note the password provided

##### Step 2: Enable Event Types

In the eStreamer configuration, enable:
- Connection Events
- Intrusion Events
- File Events
- Malware Events
- Security Intelligence Events

#### SIEM-Side Steps (Splunk — eStreamer Method)

##### Step 1: Install Cisco Security Cloud App

Install `Cisco_Security_Cloud` (Splunkbase App ID 7404) on the Heavy Forwarder. This is the successor to the legacy eStreamer add-on and supports FTD, ASA, Duo, and other Cisco products.

##### Step 2: Configure eStreamer Connection

1. Navigate to **Cisco Security Cloud > Configuration**
2. Add FMC connection:
   - **FMC Host**: `<FMC_IP_OR_HOSTNAME>`
   - **eStreamer Port**: 8302
   - **Certificate**: Upload the PKCS12 file from FMC
   - **Certificate Password**: Enter the password

##### Step 3: Create Inputs

Configure data inputs for each event type:
- Connection Events → `index = cisco_ftd`
- Intrusion Events → `index = cisco_ftd`
- File Events → `index = cisco_ftd`
- Malware Events → `index = cisco_ftd`

## Required Add-on / Parser

| Component | Name | App ID | Purpose |
|-----------|------|--------|---------|
| App (Recommended) | Cisco Security Cloud | 7404 | eStreamer collection, dashboards, health monitoring |
| Add-on (Alternative) | Splunk Add-on for Cisco ASA | 1620 | Syslog parsing (FTD syslog format compatible) |
| Index | cisco_ftd | — | Storage for FTD events |

### CIM Data Model Mappings

| FTD Event Type | CIM Data Model |
|---------------|----------------|
| Connection Events | Network_Traffic |
| Intrusion Events | Intrusion_Detection |
| File Events | Endpoint.Filesystem |
| Malware Events | Malware |

## Sample Configuration Snippets

### inputs.conf (Syslog Method)

```ini
[udp://514]
index = cisco_ftd
sourcetype = cisco:ftd
connection_host = ip
no_appending_timestamp = true

# Alternative: Use TCP for reliable delivery
[tcp://514]
index = cisco_ftd
sourcetype = cisco:ftd
connection_host = ip
```

### indexes.conf

```ini
[cisco_ftd]
homePath = $SPLUNK_DB/cisco_ftd/db
coldPath = $SPLUNK_DB/cisco_ftd/colddb
thawedPath = $SPLUNK_DB/cisco_ftd/thaweddb
maxTotalDataSizeMB = 512000
frozenTimePeriodInSecs = 7776000
```

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=cisco_ftd earliest=-15m
| stats count by sourcetype, action
```

### Check Connection Events

```spl
index=cisco_ftd sourcetype="cisco:ftd" earliest=-1h
| stats count by action, src_ip, dest_ip
| sort -count
```

### Monitor Intrusion Events (eStreamer)

```spl
index=cisco_ftd sourcetype="cisco:firepower:estreamer" event_type=intrusion
| stats count by signature, priority, src_ip, dest_ip
| sort -count
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No syslog data | Syslog not enabled on FMC | Configure Platform Settings > Syslog in FMC |
| FTD logs not parsing like ASA | `%FTD-` prefix vs `%ASA-` | Use `cisco:ftd` sourcetype or create props.conf alias |
| eStreamer connection failed | Certificate mismatch or port blocked | Verify PKCS12 cert and TCP 8302 connectivity |
| Missing intrusion events | Syslog method doesn't include IPS events | Switch to eStreamer / Cisco Security Cloud app |
| Duplicate events | Both syslog and eStreamer collecting same events | Disable syslog for connection events if using eStreamer |
| Field extractions missing | TA not installed on Search Heads | Install Cisco Security Cloud or Cisco ASA TA on Search Heads |

### Diagnostic Commands

**On FTD CLI:**

```
# Check syslog configuration
show running-config logging

# Test syslog connectivity
ping <SPLUNK_HF_IP>

# Show logging statistics
show logging
```

**On Splunk:**

```spl
# Check indexing throughput
index=_internal source=*metrics.log group=per_sourcetype_thruput series="cisco:ftd"
| timechart avg(kb) as avg_kb_sec

# Check eStreamer health
index=_internal sourcetype=splunkd "estreamer" OR "cisco_security_cloud"
| stats count by log_level, message
```

## Security Notes

1. **Syslog Security**: FTD syslog over UDP is unencrypted and unreliable. For production environments, consider TCP syslog or eStreamer (which uses TLS-encrypted communication).

2. **eStreamer Certificates**: The PKCS12 certificate used for eStreamer is tied to the specific FMC-Splunk connection. Regenerate if the Splunk HF IP changes. Monitor certificate expiration.

3. **Data Sensitivity**: FTD logs contain source/destination IPs, URLs (if URL filtering is enabled), file names, and potentially malware indicators. Implement role-based access in Splunk.

4. **High Availability**: For FTD HA pairs, configure syslog from both units. For eStreamer, connect to the active FMC in an HA pair.

5. **Volume Considerations**: Connection events at "Log at Beginning and End of Connection" on all rules can generate very high volume. Consider enabling "End of Connection" only for most rules, and "Beginning" only for critical deny rules.

6. **Cisco + Splunk "Better Together"**: Eligible Cisco FTD customers may qualify for additional Splunk ingestion capacity at no extra cost. Check with your Cisco/Splunk representative.

---

*Last Updated: March 2026*  
*Version: 1.0*
