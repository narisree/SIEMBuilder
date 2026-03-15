# Suricata IDS Integration Guide

## Overview

This document provides guidance for integrating Suricata IDS/IPS logs into Splunk. Suricata is an open-source, high-performance network threat detection engine capable of real-time intrusion detection (IDS), inline intrusion prevention (IPS), network security monitoring (NSM), and offline packet capture (PCAP) processing. It outputs structured JSON logs (EVE format) covering alerts, flow metadata, DNS, HTTP, TLS, and file transactions.

**Log Source Type:** File monitor (EVE JSON) or Syslog  
**Vendor:** Open Information Security Foundation (OISF)  
**Category:** Network IDS/IPS  
**Primary Index:** `suricata`  
**Sourcetype:** `suricata` or `suricata:eve`

## Pre-requisites

1. **Suricata** — Version 6.0+ installed and running (7.x recommended)
2. **EVE JSON Logging** — Enabled in `suricata.yaml` (default in modern versions)
3. **Splunk Universal Forwarder** — Deployed on the Suricata sensor (or syslog relay)
4. **Suricata TA for Splunk** — CCX Add-on for Suricata (App ID 6994) or TA-suricata (community)
5. **Network Connectivity** — UF to Splunk HF/Indexer on TCP 9997

### Collection Method Options

| Method | Best For | Description |
|--------|---------|-------------|
| **File Monitor (UF)** | Co-located UF | UF monitors `/var/log/suricata/eve.json` directly |
| **SC4S (Syslog)** | Centralized collection | Suricata sends EVE JSON via syslog to SC4S container |
| **HEC** | Cloud / containerized | Forward EVE JSON to Splunk HTTP Event Collector |

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Suricata Sensor (UF) | Splunk HF/Indexer | TCP 9997 | TCP | Log forwarding |
| Suricata Sensor (syslog) | SC4S / Syslog Server | UDP/TCP 514 | Syslog | EVE JSON via syslog |

## Logging Standard

### Suricata EVE Log Event Types

| Event Type | Description | Priority |
|-----------|-------------|----------|
| **alert** | IDS/IPS rule matches (signatures) | **Critical** |
| **flow** | Network session metadata (duration, bytes, packets) | **High** |
| **dns** | DNS queries and responses | **High** |
| **http** | HTTP request/response metadata | High |
| **tls** | TLS handshake details (SNI, JA3/JA4, certificate info) | High |
| **fileinfo** | Extracted file metadata (name, size, hash) | High |
| **smtp** | Email protocol metadata | Medium |
| **ssh** | SSH protocol metadata | Medium |
| **stats** | Suricata engine performance statistics | Low |

### Key Fields

| Field | Description |
|-------|-------------|
| `event_type` | Log category (alert, flow, dns, http, tls, fileinfo) |
| `src_ip` / `dest_ip` | Source and destination IP addresses |
| `src_port` / `dest_port` | Source and destination ports |
| `proto` | Protocol (TCP, UDP, ICMP) |
| `alert.signature` | IDS rule name that triggered |
| `alert.signature_id` (sid) | Signature ID |
| `alert.severity` | Alert severity (1=high, 2=medium, 3=low) |
| `alert.category` | Alert classification category |
| `flow_id` | Unique flow identifier (correlates events within a session) |
| `app_proto` | Application-layer protocol detected |

### Suricata Rule Sources

| Rule Source | Description | Update Frequency |
|------------|-------------|------------------|
| ET Open (Emerging Threats) | Free community rules | Daily |
| ET Pro | Commercial Emerging Threats rules | Daily |
| Snort Community | Free Snort-compatible rules | Periodic |
| Custom Rules | Organization-specific detections | As needed |

## Log Collection Standard

### Source-Side Steps (Suricata Sensor)

#### Step 1: Enable EVE JSON Logging

Edit `/etc/suricata/suricata.yaml`:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-printable: yes
            packet: no
            metadata: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: yes
            force-hash: [md5, sha256]
        - flow
        - ssh
        - smtp
```

#### Step 2: Configure Rule Updates

```bash
# Install suricata-update
sudo suricata-update

# Enable ET Open rules
sudo suricata-update enable-source et/open

# Update rules
sudo suricata-update
sudo systemctl reload suricata
```

#### Step 3: Verify Suricata is Running

```bash
sudo systemctl status suricata
sudo suricatasc -c "dump-counters" | python3 -m json.tool
tail -5 /var/log/suricata/eve.json | python3 -m json.tool
```

### SIEM-Side Steps (Splunk)

#### Step 1: Install Suricata TA

Install the CCX Add-on for Suricata (App ID 6994) on Search Heads and Forwarders. Alternative: community TA-suricata from GitHub.

#### Step 2: Create Suricata Index

```ini
[suricata]
homePath = $SPLUNK_DB/suricata/db
coldPath = $SPLUNK_DB/suricata/colddb
thawedPath = $SPLUNK_DB/suricata/thaweddb
maxTotalDataSizeMB = 512000
frozenTimePeriodInSecs = 7776000
```

#### Step 3: Configure File Monitor Input

```ini
# inputs.conf on UF co-located with Suricata
[monitor:///var/log/suricata/eve.json]
disabled = 0
sourcetype = suricata
index = suricata
```

## Required Add-on / Parser

| Component | Name | App ID | Purpose |
|-----------|------|--------|---------|
| Add-on | CCX Add-on for Suricata | 6994 | CIM-compliant field extraction for EVE JSON |
| App (optional) | Stamus Networks App for Splunk | 5262 | Pre-built dashboards for Suricata |
| Index | suricata | — | Storage for Suricata events |

### CIM Data Model Mappings

| Suricata Event Type | CIM Data Model |
|--------------------|----------------|
| alert | Intrusion_Detection |
| flow | Network_Traffic |
| dns | Network_Resolution |
| http | Web |
| tls | Certificates |

## Sample Configuration Snippets

### inputs.conf

```ini
[monitor:///var/log/suricata/eve.json]
disabled = 0
sourcetype = suricata
index = suricata
```

### props.conf (if not using TA)

```ini
[suricata]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%z
TIME_PREFIX = "timestamp"\s*:\s*"
MAX_TIMESTAMP_LOOKAHEAD = 33
TZ = UTC
```

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=suricata earliest=-15m
| stats count by event_type
| sort -count
```

### Check IDS Alerts

```spl
index=suricata event_type=alert earliest=-24h
| stats count by alert.signature, alert.severity, src_ip, dest_ip
| sort -count
```

### Monitor DNS Activity

```spl
index=suricata event_type=dns earliest=-1h
| stats count by dns.rrname, dns.rrtype
| sort -count
| head 20
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No events | EVE JSON logging disabled | Enable in suricata.yaml |
| Events not parsing | Wrong sourcetype | Set sourcetype to `suricata` in inputs.conf |
| Missing alert events | No rules loaded or rules outdated | Run `suricata-update` and reload |
| High volume from flow events | All flows logged | Filter to alert + dns + http + tls in inputs or at search time |

## Security Notes

1. **Sensor Placement**: Deploy Suricata on network TAPs or SPAN ports for passive monitoring. For IPS mode, deploy inline.
2. **Rule Tuning**: Suppress or threshold noisy signatures to reduce false positives. Use `threshold.config` or `suppress` directives.
3. **Performance**: Suricata supports multi-threading. Allocate CPU cores based on monitored bandwidth. Monitor `stats` events for dropped packets.
4. **Data Sensitivity**: Flow and HTTP logs contain source/destination IPs, URLs, and hostnames. Implement access controls in Splunk.
5. **Flow ID Correlation**: Use the `flow_id` field to correlate alerts with their associated flow, DNS, HTTP, and TLS metadata for complete session context.

---

*Last Updated: March 2026*  
*Version: 1.0*
