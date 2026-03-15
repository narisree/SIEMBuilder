# Kubernetes Integration Guide

## Overview

This document provides guidance for integrating Kubernetes audit logs and container runtime logs into Splunk. Kubernetes audit logs record all API server requests, providing visibility into who did what, when, and on which resources across your cluster. Combined with container logs, this telemetry is essential for detecting privilege escalation, unauthorized deployments, secrets access, lateral movement between pods, and compliance violations in cloud-native environments.

**Log Source Type:** API-based (OpenTelemetry Collector / Splunk Connect for Kubernetes) or File Monitor  
**Vendor:** Cloud Native Computing Foundation (CNCF)  
**Category:** Container Orchestration / Cloud Infrastructure  
**Primary Index:** `kubernetes`  
**Sourcetypes:** `kube:apiserver-audit`, `kube:container:*`, `kube:events`

## Pre-requisites

1. **Kubernetes Cluster** — Version 1.19+ (EKS, AKS, GKE, or self-managed)
2. **Kubernetes Audit Logging** — Enabled on the API server with an audit policy
3. **Splunk Infrastructure** — Active Splunk deployment with HEC enabled
4. **Splunk OpenTelemetry Collector for Kubernetes** — Deployed via Helm chart (recommended)
5. **Splunk Connect for Kubernetes** — Alternative: Helm chart for log/metrics/objects forwarding
6. **Cluster Admin Access** — Required for deploying DaemonSets and configuring audit policy

### Collection Method Options

| Method | Best For | Description |
|--------|---------|-------------|
| **Splunk OTel Collector (Helm)** | Production, modern | OpenTelemetry-native, DaemonSet-based, logs + metrics + traces |
| **Splunk Connect for Kubernetes** | Legacy / simple | Fluentd-based, logs + metrics + objects |
| **File Monitor + UF** | Self-managed clusters | UF on control plane nodes monitors audit log files |
| **HEC Direct** | Custom pipelines | Applications send directly to Splunk HEC |

## Network Connectivity Requirements

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| K8s Nodes (Collector) | Splunk HEC | TCP 8088 | HTTPS | Log/event forwarding via HEC |
| K8s Nodes (UF) | Splunk Indexer | TCP 9997 | TCP | Log forwarding (UF method) |

## Logging Standard

### Kubernetes Audit Event Types

| Audit Level | Description | Priority |
|------------|-------------|----------|
| **RequestResponse** | Full request and response bodies logged | High (for sensitive resources) |
| **Request** | Request body logged, response omitted | Medium |
| **Metadata** | Request metadata only (user, resource, verb) | Standard |
| **None** | Event not logged | N/A |

### Key Security-Relevant API Operations

| Resource | Operations to Monitor | Detection Value |
|---------|----------------------|-----------------|
| **Secrets** | get, list, create, patch, delete | Credential access, exfiltration |
| **Pods** | create, exec, attach, port-forward | Container escape, lateral movement |
| **ClusterRoleBindings** | create, patch | Privilege escalation |
| **ServiceAccounts** | create, token request | Identity abuse |
| **Namespaces** | create, delete | Scope manipulation |
| **ConfigMaps** | get, list (if contain sensitive data) | Configuration exposure |
| **DaemonSets/Deployments** | create, patch | Malicious workload deployment |

### Key Fields

| Field | Description |
|-------|-------------|
| `verb` | API operation (get, list, create, update, patch, delete, watch) |
| `user.username` | Authenticated identity making the request |
| `user.groups` | Groups of the authenticated identity |
| `objectRef.resource` | Kubernetes resource type (pods, secrets, configmaps) |
| `objectRef.namespace` | Namespace of the target resource |
| `objectRef.name` | Name of the specific resource |
| `sourceIPs` | IP addresses of the API caller |
| `responseStatus.code` | HTTP response status code |
| `annotations.authorization.k8s.io/decision` | Authorization decision (allow/forbid) |

## Log Collection Standard

### Source-Side Steps (Kubernetes Cluster)

#### Step 1: Configure Kubernetes Audit Policy

Create an audit policy file on the API server node(s):

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Don't log read-only requests to certain resources
  - level: None
    resources:
      - group: ""
        resources: ["events"]
  
  # Log secrets access at RequestResponse level
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]
  
  # Log pod exec/attach at RequestResponse level
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]
  
  # Log RBAC changes at RequestResponse level
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
  
  # Log all other write operations at Request level
  - level: Request
    verbs: ["create", "update", "patch", "delete"]
  
  # Log everything else at Metadata level
  - level: Metadata
```

#### Step 2: Enable Audit Logging on API Server

For self-managed clusters, add flags to the kube-apiserver:

```
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--audit-log-path=/var/log/kubernetes/apiserver/audit.log
--audit-log-maxage=30
--audit-log-maxbackup=10
--audit-log-maxsize=100
```

For managed clusters (EKS, AKS, GKE), enable audit logging through the cloud provider's console — each provider has a different mechanism.

### SIEM-Side Steps (Splunk)

#### Method 1: Splunk OpenTelemetry Collector (Recommended)

```bash
# Add Splunk Helm repo
helm repo add splunk-otel-collector-chart https://signalfx.github.io/splunk-otel-collector-chart
helm repo update

# Install with audit log collection
helm install splunk-otel-collector splunk-otel-collector-chart/splunk-otel-collector \
  --set="splunkObservability.realm=<REALM>" \
  --set="splunkObservability.accessToken=<OTEL_TOKEN>" \
  --set="splunkPlatform.endpoint=https://<SPLUNK_HEC_HOST>:8088/services/collector" \
  --set="splunkPlatform.token=<HEC_TOKEN>" \
  --set="splunkPlatform.index=kubernetes" \
  --set="logsEngine=otel" \
  --set="clusterName=<CLUSTER_NAME>"
```

For audit log file collection, add to `values.yaml`:

```yaml
logsCollection:
  extraFileLogs:
    filelog/audit-log:
      include: [/var/log/kubernetes/apiserver/audit.log]
      start_at: beginning
      include_file_path: true
      resource:
        com.splunk.source: /var/log/kubernetes/apiserver/audit.log
        com.splunk.sourcetype: kube:apiserver-audit
```

#### Method 2: File Monitor (Self-Managed Clusters)

Deploy Splunk UF on control plane nodes:

```ini
# inputs.conf
[monitor:///var/log/kubernetes/apiserver/audit.log]
disabled = 0
sourcetype = kube:apiserver-audit
index = kubernetes
```

#### Create Kubernetes Index

```ini
[kubernetes]
homePath = $SPLUNK_DB/kubernetes/db
coldPath = $SPLUNK_DB/kubernetes/colddb
thawedPath = $SPLUNK_DB/kubernetes/thaweddb
maxTotalDataSizeMB = 256000
frozenTimePeriodInSecs = 7776000
```

## Required Add-on / Parser

| Component | Name | Purpose |
|-----------|------|---------|
| Collector | Splunk OTel Collector for K8s | Log/metrics/traces collection via Helm |
| Alternative | Splunk Connect for Kubernetes | Fluentd-based log forwarding |
| Index | kubernetes | Storage for K8s events |

### CIM Data Model Mappings

| Kubernetes Event Type | CIM Data Model |
|----------------------|----------------|
| API audit events | Change |
| Authentication events | Authentication |
| Network policies | Network_Traffic (partial) |

## Validation & Troubleshooting

### Verify Log Collection

```spl
index=kubernetes earliest=-15m
| stats count by sourcetype
```

### Check Audit Events

```spl
index=kubernetes sourcetype="kube:apiserver-audit" earliest=-1h
| stats count by verb, "objectRef.resource", "user.username"
| sort -count
```

### Detect Secrets Access

```spl
index=kubernetes sourcetype="kube:apiserver-audit" "objectRef.resource"=secrets verb IN ("get", "list")
| stats count by "user.username", "objectRef.namespace", "objectRef.name"
| sort -count
```

### Detect Privileged Pod Creation

```spl
index=kubernetes sourcetype="kube:apiserver-audit" "objectRef.resource"=pods verb=create
| spath "requestObject.spec.containers{}.securityContext.privileged"
| search privileged=true
| table _time, "user.username", "objectRef.namespace", "objectRef.name"
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No audit events | Audit logging not enabled on API server | Configure audit-policy-file and audit-log-path flags |
| OTel Collector pods crashing | Insufficient resources or wrong token | Check pod logs with `kubectl logs`; verify HEC token |
| Missing events from managed clusters | Cloud provider audit pipeline not configured | Enable audit logging via EKS/AKS/GKE console |
| Extremely high volume | Audit policy too verbose | Set `level: None` for high-volume read-only operations |
| Events not parsing | Wrong sourcetype | Ensure sourcetype is `kube:apiserver-audit` |

## Security Notes

1. **Audit Policy Tuning**: Start with Metadata level for most resources, escalate to Request or RequestResponse only for sensitive resources (secrets, RBAC). Logging RequestResponse for all resources generates extreme volume.
2. **Service Account Monitoring**: Most Kubernetes attacks involve compromised service account tokens. Monitor for unusual service account API usage patterns.
3. **RBAC Vigilance**: Alert on ClusterRoleBinding and RoleBinding creation/modification — these are the primary path to privilege escalation.
4. **Namespace Isolation**: Monitor cross-namespace API calls, especially from service accounts that should be namespace-scoped.
5. **Managed Cluster Specifics**: EKS uses CloudWatch for audit logs (requires separate ingestion). AKS uses Azure Monitor diagnostic settings. GKE uses Cloud Logging. Each requires a different Splunk integration path.
6. **Data Sensitivity**: Audit logs at RequestResponse level for secrets will contain the actual secret values in the response body. Use Metadata or Request level for secrets to avoid logging sensitive content.

---

*Last Updated: March 2026*  
*Version: 1.0*
