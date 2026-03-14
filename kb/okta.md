# Okta Integration Guide

## Overview

This document provides guidance for integrating Okta Identity Cloud logs into Splunk. Okta is a cloud-based identity and access management (IAM) platform that provides single sign-on (SSO), multi-factor authentication (MFA), user lifecycle management, and API access governance. Okta's System Log provides critical visibility into authentication events, MFA challenges, user provisioning, application access, and administrative changes across the identity layer.

**Log Source Type:** API-based (Okta System Log REST API)  
**Vendor:** Okta  
**Category:** Identity & Access Management  
**Primary Index:** `okta`  
**Sourcetype:** `OktaIM2:log`

## Pre-requisites

Before beginning the integration, ensure the following requirements are met:

1. **Okta Tenant** — Active Okta organization (production or preview)
2. **Okta API Token** — Generated from the Okta Admin Console with appropriate permissions
3. **Administrative Access** — Super Admin or Org Admin role in Okta to create API tokens
4. **Splunk Infrastructure** — Active Splunk deployment with Heavy Forwarder
5. **Splunk Add-on for Okta Identity Cloud** — `Splunk_TA_okta_identity_cloud` (App ID 6553) from Splunkbase
6. **Network Connectivity** — Outbound HTTPS from Splunk HF to `<yourdomain>.okta.com`

### Okta Add-on Options

| Add-on | App ID | Maintained By | Status |
|--------|--------|---------------|--------|
| **Splunk Add-on for Okta Identity Cloud** | 6553 | Splunk (official) | **Recommended — Active** |
| Okta Identity Cloud Add-on for Splunk | 3682 | Okta (community) | Legacy — still functional |

**Recommendation:** Use the Splunk-supported add-on (App ID 6553) for production deployments. It provides comprehensive CIM coverage, higher reliability, and ongoing maintenance from Splunk.

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Splunk HF | `<yourdomain>`.okta.com | 443 | HTTPS | Okta System Log API polling |
| Splunk HF | `<yourdomain>`.oktapreview.com | 443 | HTTPS | Preview tenant (if used) |

## Logging Standard

### Okta System Log Event Categories

| Event Category | Example Events | Priority |
|---------------|----------------|----------|
| **Authentication** | user.session.start, user.authentication.sso, user.session.end | **Critical** |
| **MFA** | user.mfa.factor.activate, user.mfa.factor.deactivate, user.authentication.auth_via_mfa | **Critical** |
| **User Lifecycle** | user.lifecycle.create, user.lifecycle.activate, user.lifecycle.deactivate, user.lifecycle.suspend | **High** |
| **Group Management** | group.user_membership.add, group.user_membership.remove | High |
| **Application Access** | app.user_membership.add, app.user_membership.remove, application.lifecycle.create | High |
| **Admin Actions** | user.account.privilege.grant, policy.lifecycle.update, system.api_token.create | **Critical** |
| **Security Events** | security.threat.detected, user.account.lock, user.session.clear | **Critical** |
| **Policy Changes** | policy.lifecycle.create, policy.lifecycle.update, policy.rule.update | High |

### Key Fields

| Field | Description | Detection Value |
|-------|-------------|-----------------|
| `actor.displayName` | User or system that performed the action | Attribution |
| `actor.alternateId` | Email/username of the actor | User identification |
| `client.ipAddress` | Source IP of the request | Geo-anomaly, impossible travel |
| `client.geographicalContext` | City, state, country of the source | Location-based detection |
| `client.userAgent` | Browser/application making the request | Anomaly detection |
| `outcome.result` | SUCCESS, FAILURE, SKIPPED, UNKNOWN | Outcome-based detection |
| `outcome.reason` | Reason for failure (e.g., INVALID_CREDENTIALS) | Root cause |
| `eventType` | Okta event type string | Primary classification |
| `target` | Resource(s) acted upon | Impact assessment |
| `authenticationContext.authenticationProvider` | IdP used (FACTOR_PROVIDER, OKTA, ACTIVE_DIRECTORY) | Federation analysis |

### Time Synchronization

- Okta timestamps are in UTC (ISO 8601 format)
- Events are available via API within seconds of occurrence
- Polling interval determines collection latency (recommended: 60-120 seconds)

## Log Collection Standard

### Source-Side Steps (Okta Admin Console)

#### Step 1: Create a Service Account (Recommended)

1. Navigate to **Okta Admin Console > Directory > People**
2. Create a dedicated service account: `splunk-integration@yourdomain.com`
3. Assign the **Read Only Admin** role (minimum for System Log access)
4. Enable the account and complete MFA setup

#### Step 2: Generate API Token

1. Log in to Okta Admin Console as the service account (or Super Admin)
2. Navigate to **Security > API > Tokens**
3. Click **Create Token**
4. Name: `Splunk-SIEM-Integration`
5. **Copy the token value immediately** — it is shown only once
6. Store securely (Splunk will encrypt it in credential storage)

**Token Permissions Note:** The API token inherits the permissions of the user who created it. Using a Read Only Admin ensures least-privilege access.

#### Step 3: Verify API Access

```bash
curl -s -H "Authorization: SSWS <API_TOKEN>" \
  "https://<yourdomain>.okta.com/api/v1/logs?limit=1" | python -m json.tool
```

### SIEM-Side Steps (Splunk)

#### Step 1: Install Splunk Add-on for Okta Identity Cloud

Install `Splunk_TA_okta_identity_cloud` (App ID 6553) on:
- **Heavy Forwarder** — For data collection (modular inputs)
- **Search Heads** — For field extractions and CIM mapping
- **Indexers** — For index-time parsing

#### Step 2: Create Okta Index

```ini
# indexes.conf
[okta]
homePath = $SPLUNK_DB/okta/db
coldPath = $SPLUNK_DB/okta/colddb
thawedPath = $SPLUNK_DB/okta/thaweddb
maxTotalDataSizeMB = 128000
frozenTimePeriodInSecs = 7776000
```

#### Step 3: Configure Okta Account

1. Navigate to **Splunk Add-on for Okta Identity Cloud > Configuration > Account**
2. Click **Add**
3. Configure:
   - **Account Name**: `okta-prod`
   - **Okta Domain**: `yourdomain.okta.com` (domain only, not full URL)
   - **API Token**: Paste the token from Step 2

#### Step 4: Create Data Inputs

1. Navigate to **Inputs > Create New Input**
2. Create input for **Logs** (System Log):
   - **Name**: `okta_system_log`
   - **Account**: Select `okta-prod`
   - **Interval**: 120 (seconds)
   - **Index**: `okta`
3. Optionally create inputs for **Users**, **Groups**, **Apps** (for directory enrichment)

## Required Add-on / Parser

| Component | Name | App ID | Purpose |
|-----------|------|--------|---------|
| Add-on | Splunk Add-on for Okta Identity Cloud | 6553 | API collection, CIM mapping, field extraction |
| Index | okta | — | Storage for Okta events |

### Supported Sourcetypes

| Sourcetype | Description |
|-----------|-------------|
| `OktaIM2:log` | System Log events (primary — authentication, admin, security) |
| `OktaIM2:user` | User directory snapshot |
| `OktaIM2:group` | Group directory snapshot |
| `OktaIM2:app` | Application directory snapshot |
| `OktaIM2:groupUser` | Group membership data |
| `OktaIM2:appUser` | Application assignment data |

### CIM Data Model Mappings

| Okta Event Category | CIM Data Model |
|--------------------|----------------|
| Authentication events | Authentication |
| User lifecycle events | Change |
| Group/app membership changes | Change |

## Sample Configuration Snippets

### inputs.conf

```ini
[okta_identity_cloud://okta_system_log]
account = okta-prod
interval = 120
index = okta
sourcetype = OktaIM2:log
metric = Log

# Optional: User directory (for enrichment)
[okta_identity_cloud://okta_users]
account = okta-prod
interval = 86400
index = okta
sourcetype = OktaIM2:user
metric = User
```

### indexes.conf

```ini
[okta]
homePath = $SPLUNK_DB/okta/db
coldPath = $SPLUNK_DB/okta/colddb
thawedPath = $SPLUNK_DB/okta/thaweddb
maxTotalDataSizeMB = 128000
frozenTimePeriodInSecs = 7776000
```

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=okta sourcetype=OktaIM2:log earliest=-1h
| stats count by eventType
| sort -count
```

### Check Authentication Events

```spl
index=okta eventType="user.session.start" earliest=-24h
| stats count by actor.alternateId, client.ipAddress, outcome.result
| sort -count
```

### Monitor MFA Events

```spl
index=okta eventType="user.authentication.auth_via_mfa" OR eventType="user.mfa.factor.deactivate"
| stats count by actor.alternateId, eventType, outcome.result
```

### Detect Suspicious Activity

```spl
index=okta outcome.result=FAILURE earliest=-1h
| stats count by actor.alternateId, client.ipAddress, eventType, outcome.reason
| where count > 5
| sort -count
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No data collected | Invalid API token | Regenerate token and update in Splunk |
| 401 Unauthorized | Token expired or revoked | Create new token; tokens don't expire but can be revoked |
| Rate limiting (429) | Too many API calls | Increase polling interval to 120+ seconds |
| Partial data | Token created by non-admin user | Ensure token owner has Read Only Admin role minimum |
| Missing event types | API scope limitations | Verify admin role assigned to token creator |
| Duplicate events | Multiple inputs polling same tenant | Check for overlapping input configurations |

### Diagnostic Commands

**On Splunk:**

```spl
# Check modular input health
index=_internal sourcetype=splunkd component=ModularInputs okta
| stats count by log_level, message

# Monitor API throughput
index=_internal source=*metrics.log group=per_sourcetype_thruput series="OktaIM2:log"
| timechart avg(kb) as avg_kb_sec
```

## Security Notes

1. **API Token Security**: Okta API tokens do not expire automatically but can be revoked. Rotate tokens on a regular schedule (90 days recommended). Never share tokens across environments.

2. **Least Privilege**: Create a dedicated service account with Read Only Admin role for the Splunk integration. Avoid using Super Admin tokens for data collection.

3. **Data Sensitivity**: Okta System Logs contain usernames, IP addresses, geographic locations, device information, and authentication details. Implement role-based access control in Splunk.

4. **Rate Limits**: Okta enforces API rate limits per organization. The System Log API allows approximately 120 requests per minute. Configure polling intervals appropriately (120 seconds recommended for production).

5. **Multi-Tenant**: If you have multiple Okta tenants (production + preview), create separate accounts and inputs for each. Use distinct index or source labels for differentiation.

6. **Audit the Integration**: Okta logs the API token's own API calls. Monitor for unusual patterns in the integration account's activity.

---

*Last Updated: March 2026*  
*Version: 1.0*
