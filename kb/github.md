# GitHub Enterprise Audit Logs Integration Guide

## Overview

This document provides guidance for integrating GitHub Enterprise audit logs into Splunk. GitHub audit logs record administrative and security-relevant activities across your GitHub organization or enterprise — including repository access, user management, OAuth app authorizations, secret scanning alerts, and code security events. This telemetry is critical for supply chain security, insider threat detection, and compliance monitoring in software development environments.

**Log Source Type:** API-based (Audit Log REST API) or Audit Log Streaming (HEC)  
**Vendor:** GitHub (Microsoft)  
**Category:** DevOps / Source Code Management  
**Primary Index:** `github`  
**Sourcetypes:** `github:cloud:audit`, `github:enterprise:audit`, `httpevent` (for streaming)

## Pre-requisites

1. **GitHub Enterprise** — GitHub Enterprise Cloud or GitHub Enterprise Server (GHES 3.2+)
2. **Personal Access Token (PAT)** — With `admin:enterprise` or `admin:org` scope
3. **Splunk Infrastructure** — Active Splunk deployment with Heavy Forwarder (for API polling) or HEC endpoint (for streaming)
4. **Splunk Add-on for GitHub** — `Splunk_TA_github` (App ID 6254) from Splunkbase
5. **Network Connectivity** — Outbound HTTPS from Splunk HF to `api.github.com`

### Collection Method Options

| Method | Best For | Latency | GitHub Tier |
|--------|---------|---------|-------------|
| **Audit Log Streaming to Splunk HEC** | Enterprise Cloud, near-real-time | Seconds | Enterprise Cloud only |
| **API Polling (Splunk Add-on)** | Cloud or Server, scheduled | Minutes | Cloud or Server |
| **GHES Log Forwarding (Syslog)** | Enterprise Server on-prem | Near real-time | Enterprise Server only |

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Splunk HF | api.github.com | 443 | HTTPS | Audit Log API polling |
| Splunk HF | `<GHES_HOSTNAME>` | 443 | HTTPS | GHES API (if applicable) |
| GitHub Cloud | Splunk HEC Endpoint | 8088 | HTTPS | Audit Log Streaming (push) |

## Logging Standard

### GitHub Audit Log Event Categories

| Category | Example Actions | Priority |
|---------|----------------|----------|
| **Repository** | repo.create, repo.destroy, repo.access, repo.rename | **High** |
| **Organization** | org.add_member, org.remove_member, org.update_member | High |
| **Authentication** | oauth_access.create, personal_access_token.create | **Critical** |
| **Team** | team.create, team.add_member, team.add_repository | Medium |
| **Secret Scanning** | secret_scanning_alert.create, secret_scanning_alert.resolve | **Critical** |
| **Code Security** | repository_vulnerability_alert.create, dependabot_alerts.enable | **High** |
| **Branch Protection** | protected_branch.create, protected_branch.destroy | **High** |
| **Webhooks** | hook.create, hook.destroy, hook.config_changed | Medium |
| **Enterprise** | business.set_actions_retention_limit, business.update_member_repository_creation_permission | High |

### Key Fields

| Field | Description |
|-------|-------------|
| `action` | The audit event action (e.g., `repo.create`, `org.add_member`) |
| `actor` | Username who performed the action |
| `actor_id` | Numeric ID of the actor |
| `org` | Organization name |
| `repo` | Repository name (format: `org/repo`) |
| `created_at` / `@timestamp` | Event timestamp (epoch milliseconds) |
| `actor_is_bot` | Whether the actor is a bot account |
| `user` | Target user (for membership events) |
| `user_agent` | Client application/browser |
| `operation_type` | Operation type (create, modify, remove, access) |

## Log Collection Standard

### Method 1: Audit Log Streaming (Enterprise Cloud — Recommended)

#### Step 1: Configure Streaming in GitHub

1. Navigate to **GitHub Enterprise > Settings > Audit log > Log streaming**
2. Click **Configure stream > Splunk**
3. Configure:
   - **Domain**: Your Splunk HEC endpoint (e.g., `https://splunk-hec.company.com`)
   - **Port**: `8088`
   - **HEC Token**: Paste your Splunk HEC token
   - **SSL Verification**: Enable
4. Click **Check endpoint** to verify connectivity
5. Click **Save**

#### Step 2: Configure Splunk HEC

Create an HEC token in Splunk for GitHub:

```ini
# inputs.conf (on HEC-enabled instance)
[http://github_audit_stream]
disabled = 0
index = github
sourcetype = httpevent
token = <GENERATED_HEC_TOKEN>
```

### Method 2: API Polling (Splunk Add-on)

#### Step 1: Generate Personal Access Token

1. Go to **GitHub > Settings > Developer settings > Personal access tokens > Tokens (classic)**
2. Click **Generate new token (classic)**
3. Grant scopes:
   - `admin:enterprise` (for enterprise audit log)
   - `admin:org` (for organization audit log)
   - `read:audit_log` (if available)
4. **Copy the token immediately** — shown only once

#### Step 2: Install Splunk Add-on for GitHub

Install `Splunk_TA_github` (App ID 6254) on:
- **Heavy Forwarder** — For data collection
- **Search Heads** — For field extractions

#### Step 3: Configure Account and Input

1. Navigate to **Splunk Add-on for GitHub > Configuration > Account**
2. Add account with GitHub domain and PAT
3. Create input:
   - **Account Type**: Enterprise or Organization
   - **Enterprise/Org Name**: Your enterprise or org name
   - **Interval**: `*/30 * * * *` (every 30 minutes)
   - **Index**: `github`

### Create GitHub Index

```ini
# indexes.conf
[github]
homePath = $SPLUNK_DB/github/db
coldPath = $SPLUNK_DB/github/colddb
thawedPath = $SPLUNK_DB/github/thaweddb
maxTotalDataSizeMB = 64000
frozenTimePeriodInSecs = 7776000
```

## Required Add-on / Parser

| Component | Name | App ID | Purpose |
|-----------|------|--------|---------|
| Add-on | Splunk Add-on for GitHub | 6254 | API collection, field extraction |
| App (optional) | GitHub App for Splunk | 5596 | Pre-built dashboards |
| Index | github | — | Storage for audit events |

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=github earliest=-1h
| stats count by action
| sort -count
```

### Check Repository Events

```spl
index=github action="repo.*" earliest=-24h
| stats count by action, actor, repo
| sort -count
```

### Monitor Secret Scanning

```spl
index=github action="secret_scanning_alert.*"
| table _time, action, actor, repo, org
```

### Detect PAT Creation

```spl
index=github action="personal_access_token.create" OR action="oauth_access.create"
| table _time, actor, action, org
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No data via streaming | HEC endpoint unreachable from GitHub | Verify firewall allows GitHub IPs to reach HEC on 8088 |
| API polling returns 401 | PAT expired or insufficient scope | Regenerate PAT with required scopes |
| Missing enterprise events | PAT lacks `admin:enterprise` scope | Regenerate with enterprise admin scope |
| Duplicate events | Both streaming and API polling active | Use one collection method per event type |
| Rate limiting | API polling too frequent | Increase polling interval; API allows 1750 calls/hour |

## Security Notes

1. **PAT Security**: Personal access tokens with `admin:enterprise` scope grant broad access. Create a dedicated service account with minimum required permissions. Rotate tokens regularly.
2. **Audit Log Streaming**: Preferred for Enterprise Cloud — push-based, near-real-time, and does not require a PAT stored in Splunk.
3. **Secret Scanning**: Monitor `secret_scanning_alert` events closely — these indicate credentials committed to repositories. Correlate with the Secrets index for remediation tracking.
4. **Supply Chain Security**: Monitor for branch protection rule changes, new webhooks, and repository visibility changes (private to public). These are common attack vectors in supply chain compromises.
5. **Bot Activity**: Use the `actor_is_bot` field to separate automated CI/CD activity from human actions in detection rules.
6. **Data Sensitivity**: Audit logs contain repository names, user actions, and organization structure. Restrict Splunk index access to security and platform teams.

---

*Last Updated: March 2026*  
*Version: 1.0*
