# AWS CloudTrail Integration Guide

## Overview

This document provides guidance for integrating AWS CloudTrail logs into Splunk. CloudTrail records API calls and account activity across your AWS infrastructure, providing critical visibility into identity actions, resource changes, security events, and compliance-relevant operations across all AWS services.

**Log Source Type:** API-based (SQS-Based S3 polling or Direct CloudTrail input)  
**Vendor:** Amazon Web Services  
**Category:** Cloud Infrastructure / Audit Logging  
**Primary Index:** `aws_cloudtrail`  
**Sourcetype:** `aws:cloudtrail`

## Pre-requisites

Before beginning the integration, ensure the following requirements are met:

1. **AWS Account** — Active AWS account with CloudTrail enabled
2. **CloudTrail Trail** — A trail configured to log management events (and optionally data events) to an S3 bucket
3. **S3 Bucket** — Bucket storing CloudTrail log files with appropriate bucket policies
4. **SQS Queue** — Queue subscribed to SNS notifications from CloudTrail (recommended for SQS-Based S3 method)
5. **IAM User/Role** — Dedicated IAM credentials for Splunk with least-privilege permissions
6. **Splunk Infrastructure** — Active Splunk deployment with Heavy Forwarder (on-prem) or IDM (Splunk Cloud)
7. **Splunk Add-on for AWS** — `Splunk_TA_aws` (version 7.0.0+) from Splunkbase (App ID 1876)
8. **Network Connectivity** — Outbound HTTPS to AWS API endpoints

### CloudTrail Trail Types

| Trail Type | Description | Recommended |
|-----------|-------------|-------------|
| **Management Events** | API calls that manage AWS resources (CreateInstance, DeleteBucket, etc.) | **Yes — Primary** |
| **Data Events** | Object-level operations (S3 GetObject, Lambda Invoke) | Optional — high volume |
| **Insights Events** | Anomalous API call rates | Optional |
| **Organization Trail** | Multi-account trail across AWS Organization | Yes — for multi-account |

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Splunk HF | sts.amazonaws.com | 443 | HTTPS | STS authentication (AssumeRole) |
| Splunk HF | sqs.`<region>`.amazonaws.com | 443 | HTTPS | SQS polling for notifications |
| Splunk HF | s3.`<region>`.amazonaws.com | 443 | HTTPS | S3 log file retrieval |
| Splunk HF | cloudtrail.`<region>`.amazonaws.com | 443 | HTTPS | Direct CloudTrail API (if used) |

**Note:** If using VPC endpoints, configure interface endpoints for SQS, S3, and STS services to keep traffic within the AWS network.

## Logging Standard

### Key CloudTrail Event Fields

| Field | Description | Detection Value |
|-------|-------------|-----------------|
| `eventName` | The AWS API action performed (e.g., `ConsoleLogin`, `CreateUser`) | Primary detection field |
| `eventSource` | The AWS service that processed the request (e.g., `iam.amazonaws.com`) | Service-level filtering |
| `userIdentity.type` | Type of identity (Root, IAMUser, AssumedRole, FederatedUser) | Privilege identification |
| `userIdentity.arn` | ARN of the calling identity | Attribution |
| `sourceIPAddress` | IP address of the API caller | Geo-anomaly, impossible travel |
| `awsRegion` | AWS region where the call was made | Region anomaly detection |
| `errorCode` | Error code if the call failed (e.g., `AccessDenied`, `UnauthorizedAccess`) | Failed access detection |
| `errorMessage` | Detailed error message | Root cause analysis |
| `requestParameters` | Parameters passed to the API call | Deep investigation |
| `responseElements` | Response data from the API call | Impact assessment |
| `userAgent` | Client application that made the call | Tool identification |
| `eventType` | Event category (AwsApiCall, AwsConsoleSignIn, AwsServiceEvent) | Event classification |

### Recommended Event Categories

| Category | Example eventNames | Priority |
|----------|-------------------|----------|
| **Authentication** | ConsoleLogin, GetSessionToken, AssumeRole | **Critical** |
| **IAM Changes** | CreateUser, AttachUserPolicy, CreateAccessKey, DeleteMFADevice | **Critical** |
| **Network Changes** | AuthorizeSecurityGroupIngress, CreateNetworkAcl, ModifyVpcEndpoint | **High** |
| **Data Access** | GetObject, PutObject (S3 data events) | High (if enabled) |
| **Logging/Monitoring** | StopLogging, DeleteTrail, DeleteLogGroup | **Critical** |
| **Resource Creation** | RunInstances, CreateBucket, CreateDBInstance | High |
| **Encryption** | DisableKey, ScheduleKeyDeletion, PutKeyPolicy | **Critical** |

### Time Synchronization

- CloudTrail timestamps are in UTC (ISO 8601 format: `2025-01-15T10:30:00Z`)
- Event delivery delay: typically 5-15 minutes after the API call
- S3 log file delivery: within 15 minutes of the API call

## Log Collection Standard

### Collection Method Options

| Method | Best For | Latency | Reliability |
|--------|---------|---------|-------------|
| **SQS-Based S3** (Recommended) | Production, high volume | 5-15 min | High (SQS guarantees) |
| **Direct CloudTrail Input** | Simple setups, low volume | 5-15 min | Medium |
| **Kinesis Firehose to HEC** | Near-real-time, Splunk Cloud | 1-5 min | High |

### Source-Side Steps (AWS Console)

#### Step 1: Create CloudTrail Trail

1. Navigate to **AWS Console > CloudTrail > Trails**
2. Click **Create trail**
3. Configure:
   - **Trail name**: `splunk-cloudtrail`
   - **Apply to all regions**: Yes (recommended)
   - **Management events**: Read and Write
   - **Data events**: Optional (S3, Lambda — high volume warning)
4. **Storage location**:
   - Create or select an S3 bucket: `cloudtrail-<ACCOUNT_ID>-splunk`
   - Enable **SSE-KMS encryption** (recommended)
5. **SNS notification**: Enable — create topic `cloudtrail-notifications`
6. Click **Create trail**

#### Step 2: Create SQS Queue

1. Navigate to **AWS Console > SQS > Create queue**
2. Configure:
   - **Name**: `splunk-cloudtrail-sqs`
   - **Type**: Standard (not FIFO)
   - **Visibility timeout**: 300 seconds (5 minutes)
   - **Message retention**: 4 days
3. **Create a Dead Letter Queue (DLQ)**:
   - Name: `splunk-cloudtrail-sqs-dlq`
   - Attach to the main queue with maxReceiveCount = 3
4. **Subscribe SQS to the SNS topic**:
   - Go to SNS > Topics > `cloudtrail-notifications`
   - Create subscription: Protocol = SQS, Endpoint = SQS queue ARN

#### Step 3: Create IAM Policy for Splunk

Create a custom IAM policy `SplunkCloudTrailAccess`:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sqs:GetQueueAttributes",
                "sqs:ListQueues",
                "sqs:ReceiveMessage",
                "sqs:GetQueueUrl",
                "sqs:DeleteMessage"
            ],
            "Resource": "arn:aws:sqs:*:<ACCOUNT_ID>:splunk-cloudtrail-sqs"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": [
                "arn:aws:s3:::cloudtrail-<ACCOUNT_ID>-splunk",
                "arn:aws:s3:::cloudtrail-<ACCOUNT_ID>-splunk/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt"
            ],
            "Resource": "arn:aws:kms:*:<ACCOUNT_ID>:key/<KMS_KEY_ID>",
            "Condition": {
                "StringLike": {
                    "kms:ViaService": "s3.*.amazonaws.com"
                }
            }
        }
    ]
}
```

#### Step 4: Create IAM User for Splunk

1. Navigate to **IAM > Users > Create user**
2. Name: `splunk-cloudtrail-reader`
3. Select **Programmatic access only**
4. Attach policy: `SplunkCloudTrailAccess`
5. **Save Access Key ID and Secret Access Key securely**

### SIEM-Side Steps (Splunk)

#### Step 1: Install Splunk Add-on for AWS

Install `Splunk_TA_aws` (Splunkbase App ID 1876) on:
- **Heavy Forwarder** — For data collection (modular inputs run here)
- **Search Heads** — For field extractions and CIM mapping
- **Indexers** — For index-time parsing

#### Step 2: Configure AWS Account in Splunk

1. Navigate to **Splunk Add-on for AWS > Configuration > Account**
2. Click **Add**
3. Configure:
   - **Account Name**: `aws-cloudtrail-prod`
   - **Key ID**: `<ACCESS_KEY_ID>`
   - **Secret Key**: `<SECRET_ACCESS_KEY>`
   - **Region**: Select your primary region

#### Step 3: Create CloudTrail Index

```ini
# indexes.conf
[aws_cloudtrail]
homePath = $SPLUNK_DB/aws_cloudtrail/db
coldPath = $SPLUNK_DB/aws_cloudtrail/colddb
thawedPath = $SPLUNK_DB/aws_cloudtrail/thaweddb
maxTotalDataSizeMB = 512000
frozenTimePeriodInSecs = 7776000
```

#### Step 4: Configure SQS-Based S3 Input (Recommended)

1. Navigate to **Splunk Add-on for AWS > Inputs > Create New Input > SQS-Based S3**
2. Configure:
   - **Name**: `cloudtrail_sqs_s3`
   - **AWS Account**: Select configured account
   - **SQS Queue Name**: `splunk-cloudtrail-sqs`
   - **SQS Queue Region**: Your region
   - **Index**: `aws_cloudtrail`
   - **Sourcetype**: `aws:cloudtrail`
   - **Interval**: 30 seconds

#### Step 5 (Alternative): Configure Direct CloudTrail Input

```ini
# inputs.conf
[aws_cloudtrail://cloudtrail_data]
aws_account = aws-cloudtrail-prod
aws_region = us-east-1
sqs_queue = splunk-cloudtrail-sqs
exclude_describe_events = 1
interval = 30
sourcetype = aws:cloudtrail
index = aws_cloudtrail
```

## Required Add-on / Parser

| Component | Name | App ID | Purpose |
|-----------|------|--------|---------|
| Add-on | Splunk Add-on for AWS | 1876 | Data collection, CIM mapping, field extraction |
| App (optional) | Splunk App for AWS | 5381 | Pre-built dashboards and visualizations |
| Index | aws_cloudtrail | — | Storage for CloudTrail events |

### CIM Data Model Mappings

| CloudTrail Event Type | CIM Data Model |
|----------------------|----------------|
| ConsoleLogin, AssumeRole | Authentication |
| CreateUser, AttachPolicy, CreateAccessKey | Change |
| AuthorizeSecurityGroupIngress | Network_Traffic (Change) |
| All API calls | Web (partial) |

## Sample Configuration Snippets

### inputs.conf (SQS-Based S3)

```ini
[aws_sqs_based_s3://cloudtrail_sqs_s3]
aws_account = aws-cloudtrail-prod
sqs_queue_name = splunk-cloudtrail-sqs
sqs_queue_region = us-east-1
sourcetype = aws:cloudtrail
index = aws_cloudtrail
interval = 30
```

### inputs.conf (Direct CloudTrail)

```ini
[aws_cloudtrail://cloudtrail_direct]
aws_account = aws-cloudtrail-prod
aws_region = us-east-1
sqs_queue = splunk-cloudtrail-sqs
exclude_describe_events = 1
remove_files_when_done = 0
sourcetype = aws:cloudtrail
index = aws_cloudtrail
interval = 30
```

### indexes.conf

```ini
[aws_cloudtrail]
homePath = $SPLUNK_DB/aws_cloudtrail/db
coldPath = $SPLUNK_DB/aws_cloudtrail/colddb
thawedPath = $SPLUNK_DB/aws_cloudtrail/thaweddb
maxTotalDataSizeMB = 512000
frozenTimePeriodInSecs = 7776000
```

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=aws_cloudtrail earliest=-1h
| stats count by eventSource, eventName
| sort -count
```

### Check Authentication Events

```spl
index=aws_cloudtrail eventName=ConsoleLogin
| stats count by userIdentity.arn, sourceIPAddress, errorCode
| sort -count
```

### Monitor Failed API Calls

```spl
index=aws_cloudtrail errorCode=AccessDenied OR errorCode=UnauthorizedAccess
| stats count by eventName, userIdentity.arn, sourceIPAddress
| sort -count
```

### Check for Trail Tampering

```spl
index=aws_cloudtrail eventName IN ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors")
| table _time, eventName, userIdentity.arn, sourceIPAddress, awsRegion
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No data in index | SQS queue not receiving notifications | Verify SNS subscription to SQS is active |
| Access Denied errors in Splunk | IAM policy missing permissions | Add required S3/SQS/KMS permissions |
| Duplicate events | Multiple inputs for same queue | Check for overlapping input configurations |
| Delayed data (>30 min) | CloudTrail delivery delay or SQS backlog | Check SQS queue depth; increase polling interval |
| Events not parsing | Wrong sourcetype | Ensure sourcetype is `aws:cloudtrail` |
| KMS decryption failures | Missing KMS Decrypt permission | Add kms:Decrypt to IAM policy for the trail's KMS key |
| Missing regions | Trail not multi-region | Enable multi-region trail or add per-region trails |
| SQS messages not deleted | IAM missing DeleteMessage | Add sqs:DeleteMessage to IAM policy |

### Diagnostic Commands

**On AWS Console:**
- CloudTrail > Event history — verify events are being logged
- SQS > Queue metrics — check ApproximateNumberOfMessagesVisible
- S3 > Bucket > Objects — verify log files are being delivered

**On Splunk:**

```spl
# Check modular input health
index=_internal sourcetype=splunkd component=ModularInputs aws
| stats count by log_level, message

# Monitor input throughput
index=_internal source=*metrics.log group=per_sourcetype_thruput series=aws:cloudtrail
| timechart avg(kb) as avg_kb_sec
```

## Security Notes

1. **IAM Least Privilege**: Grant only the minimum permissions required (read-only S3, SQS receive/delete). Never use root credentials or broad `*` resource permissions for the Splunk integration.

2. **Credential Rotation**: Rotate the IAM access keys used by Splunk on a regular schedule (90 days recommended). Use IAM roles with AssumeRole for cross-account collection when possible.

3. **Trail Protection**: Enable CloudTrail log file validation to detect tampering. Alert on `StopLogging`, `DeleteTrail`, and `UpdateTrail` events — these are high-confidence indicators of attacker activity.

4. **Multi-Account Strategy**: For AWS Organizations, use an organization trail writing to a centralized S3 bucket in a dedicated security account. Splunk reads from this single bucket.

5. **Data Sensitivity**: CloudTrail logs contain IAM ARNs, IP addresses, request parameters (which may include resource names, tags, and configuration details). Implement role-based access in Splunk.

6. **Cost Management**: S3 data events (GetObject, PutObject) can generate extremely high volume. Enable selectively and monitor S3 storage costs. Management events are generally low volume and always recommended.

7. **Encryption**: Use SSE-KMS encryption on the CloudTrail S3 bucket. Ensure the Splunk IAM role has kms:Decrypt permission for the encryption key.

---

*Last Updated: March 2026*  
*Version: 1.0*
