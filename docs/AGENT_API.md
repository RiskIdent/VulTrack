# VulTrack Agent API Specification

This document describes the API that VulTrack agents must implement to register with the server and report system/package information.

## Base URL

```
https://<vultrack-server>/api/v1/agent
```

---

## 1. Agent Enrollment (Registration)

Agents must register once before they can submit reports.

**Endpoint:** `POST /api/v1/agent/enroll`

### Headers

| Header | Type | Required | Description |
|--------|------|----------|-------------|
| `X-Enrollment-Key` | string | Yes | Enrollment key created in Admin UI |
| `Content-Type` | string | Yes | `application/json` |

### Request Body

```json
{
  "hostname": "server01.example.com"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | string | Yes | Fully qualified hostname of the server |

### Response (201 Created)

```json
{
  "agentToken": "vt_abc123...",
  "status": "active"
}
```

| Field | Description |
|-------|-------------|
| `agentToken` | Unique token for this agent. **Store securely - only returned once!** |
| `status` | `"active"` (auto-approved) or `"pending"` (requires manual approval) |

### Error Responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Missing hostname or invalid JSON |
| `401 Unauthorized` | Missing or invalid enrollment key |
| `409 Conflict` | Agent already registered for this hostname |

---

## 2. Agent Report (Data Submission)

Agents should submit reports periodically (e.g., every hour via cron).

**Endpoint:** `POST /api/v1/agent/report`

### Headers

| Header | Type | Required | Description |
|--------|------|----------|-------------|
| `X-Agent-Token` | string | Yes | Token received from enrollment |
| `Content-Type` | string | Yes | `application/json` |

### Request Body

```json
{
  "hostname": "server01.example.com",
  "agentVersion": "1.0.0",
  "osFamily": "ubuntu",
  "osRelease": "24.04",
  "osCodename": "noble",
  "kernel": "6.8.0-45-generic",
  "arch": "amd64",
  "packageManager": "dpkg",
  "ipv4Addrs": ["192.168.1.10", "10.0.0.5"],
  "reportedAt": "2026-01-25T14:30:00Z",
  "packages": [
    {
      "name": "openssl",
      "version": "3.0.13-0ubuntu3.4",
      "arch": "amd64",
      "source": "openssl"
    },
    {
      "name": "curl",
      "version": "8.5.0-2ubuntu10.6",
      "arch": "amd64",
      "source": "curl"
    }
  ]
}
```

### Required Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `hostname` | string | Server hostname | `"server01.example.com"` |
| `osFamily` | string | OS family (lowercase) | `"ubuntu"`, `"debian"`, `"rhel"`, `"centos"`, `"rocky"`, `"alma"` |
| `osRelease` | string | OS version | `"24.04"`, `"12"`, `"9.4"` |
| `kernel` | string | Kernel version | `"6.8.0-45-generic"` |
| `arch` | string | System architecture | `"amd64"`, `"arm64"`, `"i386"`, `"x86_64"` |
| `ipv4Addrs` | string[] | At least one IPv4 address | `["192.168.1.10"]` |
| `packages` | array | List of installed packages | See package object below |

### Optional Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `agentVersion` | string | Version of the agent software | `"1.0.0"` |
| `osCodename` | string | Distribution codename | `"noble"`, `"bookworm"`, `"jammy"` |
| `packageManager` | string | Package manager type | `"dpkg"`, `"rpm"` |
| `reportedAt` | string | ISO8601 timestamp | `"2026-01-25T14:30:00Z"` |

### Package Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Package name |
| `version` | string | Yes | Installed version (full EVR format) |
| `arch` | string | No | Package architecture |
| `source` | string | No | Source package name |

### Response (200 OK)

```json
{
  "message": "Report processed successfully",
  "serverId": 42,
  "packageCount": 1523
}
```

### Error Responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Missing required field or invalid JSON |
| `401 Unauthorized` | Missing or invalid agent token |
| `403 Forbidden` | Agent status is `pending` or `revoked` |

---

## Data Collection Guide

### System Information

The agent must collect the following system information:

| Information | Linux Command | Example Output |
|-------------|---------------|----------------|
| Hostname | `hostname -f` | `server01.example.com` |
| OS Family | Parse `/etc/os-release` → `ID` | `ubuntu` |
| OS Release | Parse `/etc/os-release` → `VERSION_ID` | `24.04` |
| OS Codename | Parse `/etc/os-release` → `VERSION_CODENAME` | `noble` |
| Kernel | `uname -r` | `6.8.0-45-generic` |
| Architecture | `uname -m` (normalize to amd64/arm64) | `x86_64` → `amd64` |
| IPv4 Addresses | `hostname -I` or parse `ip -4 addr` | `192.168.1.10 10.0.0.5` |

### Package List

#### Debian/Ubuntu (dpkg)

```bash
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\n'
```

Output format (tab-separated):
```
openssl    3.0.13-0ubuntu3.4    amd64    openssl
curl       8.5.0-2ubuntu10.6    amd64    curl
```

#### RHEL/CentOS/Rocky/Alma (rpm)

```bash
rpm -qa --queryformat '%{NAME}\t%{EVR}\t%{ARCH}\t%{SOURCERPM}\n'
```

Output format (tab-separated):
```
openssl    1:3.0.7-27.el9    x86_64    openssl-3.0.7-27.el9.src.rpm
curl       7.76.1-29.el9     x86_64    curl-7.76.1-29.el9.src.rpm
```

---

## Architecture Normalization

The `arch` field should be normalized to standard values:

| Raw Value | Normalized Value |
|-----------|------------------|
| `x86_64` | `amd64` |
| `aarch64` | `arm64` |
| `i686`, `i386` | `i386` |
| `armv7l` | `armhf` |

---

## Complete Agent Workflow Example

### Step 1: Enrollment (one-time)

```bash
#!/bin/bash
VULTRACK_URL="https://vultrack.example.com"
ENROLLMENT_KEY="vt_enroll_abc123..."

# Enroll the agent
RESPONSE=$(curl -s -X POST "${VULTRACK_URL}/api/v1/agent/enroll" \
  -H "X-Enrollment-Key: ${ENROLLMENT_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"hostname\": \"$(hostname -f)\"}")

# Extract and save the agent token
AGENT_TOKEN=$(echo "$RESPONSE" | jq -r '.agentToken')
echo "$AGENT_TOKEN" > /etc/vultrack/agent-token

# Check status
STATUS=$(echo "$RESPONSE" | jq -r '.status')
echo "Agent enrolled with status: $STATUS"
```

### Step 2: Report Submission (scheduled via cron)

```bash
#!/bin/bash
VULTRACK_URL="https://vultrack.example.com"
AGENT_TOKEN=$(cat /etc/vultrack/agent-token)

# Collect system information
HOSTNAME=$(hostname -f)
OS_FAMILY=$(grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"')
OS_RELEASE=$(grep ^VERSION_ID= /etc/os-release | cut -d= -f2 | tr -d '"')
OS_CODENAME=$(grep ^VERSION_CODENAME= /etc/os-release | cut -d= -f2 | tr -d '"')
KERNEL=$(uname -r)
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
IPV4_ADDRS=$(hostname -I | tr ' ' '\n' | grep -E '^[0-9]+\.' | jq -R . | jq -s .)

# Collect package list (Debian/Ubuntu)
PACKAGES=$(dpkg-query -W -f='{"name":"${Package}","version":"${Version}","arch":"${Architecture}","source":"${source:Package}"}\n' | jq -s .)

# Build and send report
curl -s -X POST "${VULTRACK_URL}/api/v1/agent/report" \
  -H "X-Agent-Token: ${AGENT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "hostname": "${HOSTNAME}",
  "osFamily": "${OS_FAMILY}",
  "osRelease": "${OS_RELEASE}",
  "osCodename": "${OS_CODENAME}",
  "kernel": "${KERNEL}",
  "arch": "${ARCH}",
  "packageManager": "dpkg",
  "ipv4Addrs": ${IPV4_ADDRS},
  "packages": ${PACKAGES}
}
EOF
```

### Cron Entry

```cron
# Report to VulTrack every hour
0 * * * * /usr/local/bin/vultrack-report.sh >> /var/log/vultrack-agent.log 2>&1
```

---

## Security Considerations

1. **Store tokens securely**: The agent token should be stored with restricted permissions (e.g., `chmod 600`)
2. **Use HTTPS**: Always use TLS for communication with the VulTrack server
3. **Rotate tokens**: If a token is compromised, revoke the agent in the Admin UI and re-enroll
4. **Firewall**: Ensure the agent can reach the VulTrack API endpoint

---

## Supported Distributions

VulTrack currently supports vulnerability scanning for:

| Distribution | OS Family Value | Package Manager |
|--------------|-----------------|-----------------|
| Ubuntu | `ubuntu` | `dpkg` |
| Debian | `debian` | `dpkg` |
| RHEL | `rhel` | `rpm` |
| CentOS | `centos` | `rpm` |
| Rocky Linux | `rocky` | `rpm` |
| AlmaLinux | `alma` | `rpm` |

> **Note:** OVAL sources must be enabled in the Admin UI for the corresponding distribution and version before vulnerability scanning will work.
