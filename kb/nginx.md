# Nginx Integration Guide

## Overview

This document provides guidance for integrating Nginx web server access and error logs into Splunk. Nginx is one of the most widely deployed web servers and reverse proxies, and its logs provide visibility into HTTP request patterns, client behavior, application errors, upstream failures, and potential web-based attacks (SQL injection, XSS, path traversal, brute force).

**Log Source Type:** File monitor (UF) or Syslog  
**Vendor:** Nginx Inc. (F5)  
**Category:** Web Server / Reverse Proxy  
**Primary Index:** `nginx`  
**Sourcetypes:** `nginx:plus:access`, `nginx:plus:error`, `access_combined`

## Pre-requisites

1. **Nginx** — Open Source or Nginx Plus, any supported version
2. **Access to Nginx Configuration** — Modify `nginx.conf` for log format customization
3. **Splunk Universal Forwarder** — Deployed on the Nginx server (or syslog relay)
4. **Splunk Add-on for Nginx** — From Splunkbase
5. **Network Connectivity** — UF to Splunk HF/Indexer on TCP 9997

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Nginx Server (UF) | Splunk HF/Indexer | TCP 9997 | TCP | Log forwarding |
| Nginx Server (syslog) | Syslog Relay / SC4S | UDP/TCP 514 | Syslog | Syslog forwarding (alternative) |

## Logging Standard

### Nginx Log Types

| Log | Default Path | Description | Priority |
|-----|-------------|-------------|----------|
| **Access Log** | /var/log/nginx/access.log | HTTP request logs (client, URL, status, bytes) | **Critical** |
| **Error Log** | /var/log/nginx/error.log | Server errors, upstream failures, config issues | **High** |

### Recommended Access Log Format

The default `combined` format is functional but lacks fields valuable for security detection. We recommend a custom JSON format for structured parsing:

```nginx
# nginx.conf — Custom JSON log format for security monitoring
log_format security_json escape=json
    '{'
        '"time_local":"$time_local",'
        '"remote_addr":"$remote_addr",'
        '"remote_user":"$remote_user",'
        '"request":"$request",'
        '"request_method":"$request_method",'
        '"request_uri":"$request_uri",'
        '"status":$status,'
        '"body_bytes_sent":$body_bytes_sent,'
        '"request_time":$request_time,'
        '"http_referer":"$http_referer",'
        '"http_user_agent":"$http_user_agent",'
        '"http_x_forwarded_for":"$http_x_forwarded_for",'
        '"upstream_addr":"$upstream_addr",'
        '"upstream_status":"$upstream_status",'
        '"upstream_response_time":"$upstream_response_time",'
        '"ssl_protocol":"$ssl_protocol",'
        '"ssl_cipher":"$ssl_cipher",'
        '"server_name":"$server_name"'
    '}';

access_log /var/log/nginx/access.log security_json;
```

### Key Fields for Security Detection

| Field | Detection Value |
|-------|-----------------|
| `remote_addr` | Source IP — brute force, scanning, geo-anomaly |
| `request_uri` | Attack payloads (SQLi, XSS, path traversal) |
| `status` | 4xx/5xx patterns — scanning, exploitation |
| `request_method` | Unusual methods (PUT, DELETE, CONNECT) |
| `http_user_agent` | Automated tools (sqlmap, nikto, dirbuster) |
| `request_time` | Slow requests — possible DoS or exploitation |
| `upstream_status` | Backend failures — application compromise |

### Error Log Levels

| Level | Description | Priority |
|-------|-------------|----------|
| emerg | System is unusable | Critical |
| alert | Action must be taken immediately | Critical |
| crit | Critical conditions | High |
| error | Error conditions | High |
| warn | Warning conditions | Medium |
| notice | Normal but significant | Low |
| info | Informational | Low |

Configure error log level in `nginx.conf`:

```nginx
error_log /var/log/nginx/error.log warn;
```

## Log Collection Standard

### Source-Side Steps (Nginx Server)

#### Step 1: Verify Log Paths and Format

```bash
# Check current log configuration
nginx -T 2>/dev/null | grep -E "access_log|error_log|log_format"

# Verify log files exist and are being written
ls -la /var/log/nginx/
tail -5 /var/log/nginx/access.log
```

#### Step 2: Apply Custom Log Format (Optional but Recommended)

Edit `/etc/nginx/nginx.conf` and add the `security_json` log format shown above in the `http {}` block. Then update each `server {}` block:

```nginx
server {
    ...
    access_log /var/log/nginx/access.log security_json;
    error_log /var/log/nginx/error.log warn;
}
```

Reload Nginx:

```bash
nginx -t && sudo systemctl reload nginx
```

#### Step 3: Configure Log Rotation

Ensure logrotate is configured to avoid filling disk. Default `/etc/logrotate.d/nginx` is usually sufficient, but verify:

```
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 `cat /var/run/nginx.pid`
    endscript
}
```

### SIEM-Side Steps (Splunk)

#### Step 1: Install Nginx TA

Install the Splunk Add-on for Nginx on Search Heads and Forwarders.

#### Step 2: Create Nginx Index

```ini
# indexes.conf
[nginx]
homePath = $SPLUNK_DB/nginx/db
coldPath = $SPLUNK_DB/nginx/colddb
thawedPath = $SPLUNK_DB/nginx/thaweddb
maxTotalDataSizeMB = 256000
frozenTimePeriodInSecs = 7776000
```

#### Step 3: Configure File Monitor Input

```ini
# inputs.conf on UF co-located with Nginx
[monitor:///var/log/nginx/access.log]
disabled = 0
sourcetype = nginx:plus:access
index = nginx

[monitor:///var/log/nginx/error.log]
disabled = 0
sourcetype = nginx:plus:error
index = nginx
```

If using the custom JSON format, use a JSON-aware sourcetype:

```ini
[monitor:///var/log/nginx/access.log]
disabled = 0
sourcetype = nginx:plus:access
index = nginx
# JSON format is auto-detected if KV_MODE=json in props.conf
```

## Required Add-on / Parser

| Component | Name | Purpose |
|-----------|------|---------|
| Add-on | Splunk Add-on for Nginx | Field extraction, CIM mapping |
| Index | nginx | Storage for Nginx logs |

### CIM Data Model Mappings

| Nginx Log Type | CIM Data Model |
|---------------|----------------|
| Access Log | Web |
| Error Log | Application_State (partial) |

## Sample Configuration Snippets

### inputs.conf

```ini
[monitor:///var/log/nginx/access.log]
disabled = 0
sourcetype = nginx:plus:access
index = nginx

[monitor:///var/log/nginx/error.log]
disabled = 0
sourcetype = nginx:plus:error
index = nginx
```

### props.conf (for custom JSON format)

```ini
[nginx:plus:access]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_FORMAT = %d/%b/%Y:%H:%M:%S %z
TIME_PREFIX = "time_local"\s*:\s*"
MAX_TIMESTAMP_LOOKAHEAD = 30
TZ = UTC
```

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=nginx earliest=-15m
| stats count by sourcetype, status
```

### Check HTTP Status Distribution

```spl
index=nginx sourcetype="nginx:plus:access" earliest=-24h
| stats count by status
| sort -count
```

### Detect Web Scanning

```spl
index=nginx sourcetype="nginx:plus:access" status IN (404, 403, 400) earliest=-1h
| stats count by remote_addr, request_uri
| where count > 20
| sort -count
```

### Detect SQL Injection Attempts

```spl
index=nginx sourcetype="nginx:plus:access" 
| where match(request_uri, "(?i)(union\s+select|'--|\bor\b\s+1=1|drop\s+table)")
| table _time, remote_addr, request_uri, status, http_user_agent
```

### Monitor Error Rates

```spl
index=nginx sourcetype="nginx:plus:error" earliest=-1h
| timechart count by log_level
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No data in index | Wrong log file path | Verify path with `nginx -T | grep access_log` |
| Parsing errors | Log format mismatch with TA | Align sourcetype with actual log format (combined vs JSON) |
| Missing fields | Using default `combined` format | Switch to custom JSON format for richer field extraction |
| Log file not growing | Nginx not reloaded after config change | Run `nginx -t && systemctl reload nginx` |
| Timestamp parsing issues | Timezone mismatch | Set `TZ` in props.conf or configure UTC in Nginx |
| Permission denied | UF user can't read log files | Add splunk user to `adm` or `www-data` group |

## Security Notes

1. **Log Format**: The custom JSON format provides significantly better security detection than the default `combined` format. It includes `request_time`, `upstream_status`, `ssl_protocol`, and `http_x_forwarded_for` which are essential for attack detection and forensic investigation.
2. **Sensitive Data**: Access logs may contain query parameters with session tokens, API keys, or PII. Consider configuring Nginx to strip sensitive query parameters from logs or apply search-time masking in Splunk.
3. **Rate Limiting**: Use Nginx rate limiting (`limit_req_zone`) as a complementary control alongside SIEM detection. Log rate-limited requests by configuring a separate `access_log` for the `limit_req` status.
4. **WAF Integration**: If using Nginx with ModSecurity or Nginx App Protect, configure those log streams separately with dedicated sourcetypes for correlation with access logs.
5. **Log Integrity**: Consider forwarding logs in real-time via syslog rather than relying solely on file monitor to reduce the window for log tampering on a compromised web server.
6. **TLS Visibility**: The `ssl_protocol` and `ssl_cipher` fields enable monitoring for weak TLS configurations and downgrade attacks.

---

*Last Updated: March 2026*  
*Version: 1.0*
