# VulTrack Agent API Specification

This document describes the API that VulTrack agents use to enroll with the server and submit system/package reports.

Two API versions are available in parallel. New agent implementations should use **v2**. Existing v1 agents continue to work without modification.

---

## API Versions

| Version | Base URL | Auth mechanism | Token lifetime |
|---------|----------|----------------|----------------|
| v1 (legacy) | `/api/v1/agent` | Custom headers (`X-Enrollment-Key`, `X-Agent-Token`) | Indefinite (until manually revoked) |
| **v2 (current)** | `/api/v2/agent` | `Authorization: Bearer` (RFC 6750) | Access token: 24 h · Refresh token: 90 days (configurable) |

---

## API v2 (Current)

### Authentication overview

v2 uses a two-token model:

- **Access token** — short-lived signed JWT (HS256). Passed as `Authorization: Bearer <jwt>` on every report request. No database lookup is required on the server to validate it.
- **Refresh token** — long-lived opaque token (`rt_…`). Used exclusively to obtain a new access token. Each use **rotates** the refresh token (old token is revoked, new one is issued atomically).

### v2.1 Enrollment

Agents must enroll once before they can submit reports.

**`POST /api/v2/agent/enroll`**

#### Headers

| Header | Required | Value |
|--------|----------|-------|
| `Authorization` | Yes | `Bearer enroll_<enrollment-key>` |
| `Content-Type` | Yes | `application/json` |

#### Request body

```json
{
  "hostname": "server01.example.com",
  "force": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | string | Yes | Fully qualified hostname of the server |
| `osFamily` | string | No | OS family, e.g. `"ubuntu"` |
| `osRelease` | string | No | OS version, e.g. `"24.04"` |
| `osCodename` | string | No | Distribution codename, e.g. `"noble"` |
| `kernel` | string | No | Kernel version from `uname -r` |
| `arch` | string | No | System architecture, e.g. `"amd64"` |
| `packageManager` | string | No | `"dpkg"` or `"rpm"` |
| `ipv4Addrs` | string[] | No | IPv4 addresses of the system |
| `force` | bool | No | Re-enroll even if this hostname is already registered. The old agent and all its refresh tokens are revoked. Default: `false` |

#### Response (201 Created)

```json
{
  "tokenType": "Bearer",
  "accessToken": "<signed JWT>",
  "refreshToken": "rt_abc123...",
  "expiresIn": 86400,
  "status": "active"
}
```

| Field | Description |
|-------|-------------|
| `tokenType` | Always `"Bearer"` |
| `accessToken` | Short-lived JWT. Use as `Authorization: Bearer <accessToken>` on report requests. |
| `refreshToken` | Long-lived opaque token. **Store securely — only returned once per enrollment.** Use to obtain new access tokens via `/api/v2/agent/token`. |
| `expiresIn` | Access token validity in seconds (default: 86400 = 24 h) |
| `status` | `"active"` or `"pending"` (pending requires manual admin approval before reports are accepted) |

#### Error responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Missing `hostname` or invalid JSON |
| `401 Unauthorized` | Missing, invalid, expired, or inactive enrollment key |
| `409 Conflict` | Hostname already registered. Set `force: true` to re-enroll. |

---

### v2.2 Token refresh

Obtain a new access token (JWT) using the current refresh token. The supplied refresh token is **revoked** and a fresh one is returned (rotation).

**`POST /api/v2/agent/token`**

#### Headers

| Header | Required | Value |
|--------|----------|-------|
| `Authorization` | Yes | `Bearer rt_<refresh-token>` |

#### Response (200 OK)

```json
{
  "tokenType": "Bearer",
  "accessToken": "<new signed JWT>",
  "refreshToken": "rt_xyz789...",
  "expiresIn": 86400
}
```

The agent **must replace both stored tokens** after a successful refresh.

#### Error responses

| Status | Description |
|--------|-------------|
| `401 Unauthorized` | Refresh token not found, already revoked, or expired |

---

### v2.3 Submit report

Submit a system and package report. The server upserts the server record, syncs the package list, and enqueues a vulnerability scan.

**`POST /api/v2/agent/report`**

#### Headers

| Header | Required | Value |
|--------|----------|-------|
| `Authorization` | Yes | `Bearer <access-token (JWT)>` |
| `Content-Type` | Yes | `application/json` |

The JWT is validated by verifying its HMAC-SHA256 signature and expiry time only — no database lookup is performed. If the JWT has expired the agent should obtain a new one via `/api/v2/agent/token` and retry.

#### Request body

Identical to v1 — see [Request Body](#report-request-body) below.

#### Response (200 OK)

```json
{
  "message": "Report processed successfully",
  "serverId": 42,
  "packageCount": 1523,
  "scanJobId": "a1b2c3d4-..."
}
```

#### Error responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Missing required field or invalid JSON |
| `401 Unauthorized` | Missing, invalid, or expired access token; or agent has been revoked |

---

### v2 Complete workflow

```
┌─────────────────────────────────────────────────────────┐
│ FIRST RUN                                               │
│                                                         │
│  POST /api/v2/agent/enroll                              │
│  Authorization: Bearer enroll_<key>                     │
│  → { accessToken, refreshToken, expiresIn, status }     │
│                                                         │
│  Store refreshToken → /etc/vultrack-agent/refresh.token │
│  Keep accessToken in memory (or re-fetch on startup)    │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│ PERIODIC REPORT (e.g. every hour)                       │
│                                                         │
│  POST /api/v2/agent/report                              │
│  Authorization: Bearer <accessToken>                    │
│  → 200 OK                                               │
│                                                         │
│  If 401: access token expired →                         │
│    POST /api/v2/agent/token                             │
│    Authorization: Bearer <refreshToken>                 │
│    → { accessToken, refreshToken }  (rotation!)         │
│    Update stored refreshToken, retry report             │
│                                                         │
│  If 401 on token refresh: refresh token expired →       │
│    Re-enroll using enrollment key from config           │
└─────────────────────────────────────────────────────────┘
```

---

## API v1 (Legacy)

> **Deprecated.** v1 remains fully functional for backward compatibility. New agent implementations should use v2.

### v1.1 Enrollment

**`POST /api/v1/agent/enroll`**

#### Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-Enrollment-Key` | Yes | Enrollment key created in the Admin UI |
| `Content-Type` | Yes | `application/json` |

#### Request body

```json
{
  "hostname": "server01.example.com"
}
```

#### Response (201 Created)

```json
{
  "agentToken": "at_abc123...",
  "status": "active"
}
```

Store `agentToken` securely. It is returned only once and does not expire automatically.

---

### v1.2 Submit report

**`POST /api/v1/agent/report`**

#### Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-Agent-Token` | Yes | Token received from enrollment |
| `Content-Type` | Yes | `application/json` |

---

## Report Request Body

The report body is identical across v1 and v2.

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

### Required fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `hostname` | string | Fully qualified hostname | `"server01.example.com"` |
| `osFamily` | string | OS family (lowercase) | `"ubuntu"`, `"debian"`, `"rhel"`, `"centos"`, `"rocky"`, `"alma"` |
| `osRelease` | string | OS version | `"24.04"`, `"12"`, `"9.4"` |
| `kernel` | string | Kernel version | `"6.8.0-45-generic"` |
| `arch` | string | System architecture | `"amd64"`, `"arm64"`, `"i386"` |
| `ipv4Addrs` | string[] | At least one IPv4 address | `["192.168.1.10"]` |
| `packages` | array | Installed packages (may be empty) | See package object below |

### Optional fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `agentVersion` | string | Version of the agent software | `"1.0.0"` |
| `osCodename` | string | Distribution codename | `"noble"`, `"bookworm"`, `"jammy"` |
| `packageManager` | string | Package manager type | `"dpkg"`, `"rpm"` |
| `reportedAt` | string | ISO 8601 timestamp; server uses `NOW()` if omitted | `"2026-01-25T14:30:00Z"` |

### Package object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Package name |
| `version` | string | Yes | Installed version (full EVR format) |
| `arch` | string | No | Package architecture |
| `source` | string | No | Source package name |

---

## Data Collection Guide

### System information

| Information | Source | Example |
|-------------|--------|---------|
| Hostname | `hostname -f` | `server01.example.com` |
| OS Family | `/etc/os-release` → `ID` | `ubuntu` |
| OS Release | `/etc/os-release` → `VERSION_ID` | `24.04` |
| OS Codename | `/etc/os-release` → `VERSION_CODENAME` | `noble` |
| Kernel | `uname -r` | `6.8.0-45-generic` |
| Architecture | `uname -m` (normalize; see below) | `x86_64` → `amd64` |
| IPv4 Addresses | `hostname -I` or `ip -4 addr` | `192.168.1.10 10.0.0.5` |

### Architecture normalization

| Raw value | Normalized value |
|-----------|-----------------|
| `x86_64` | `amd64` |
| `aarch64` | `arm64` |
| `i686`, `i386` | `i386` |
| `armv7l` | `armhf` |

### Package list collection

**Debian/Ubuntu (dpkg)**

```bash
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\n'
```

**RHEL / CentOS / Rocky / Alma (rpm)**

```bash
rpm -qa --queryformat '%{NAME}\t%{EVR}\t%{ARCH}\t%{SOURCERPM}\n'
```

---

## Complete v2 Agent Example (bash)

### Step 1: Enrollment (first run only)

```bash
#!/bin/bash
set -euo pipefail

VULTRACK_URL="https://vultrack.example.com"
ENROLLMENT_KEY="enroll_abc123..."   # from Admin UI
REFRESH_TOKEN_FILE="/etc/vultrack-agent/refresh.token"
ACCESS_TOKEN_FILE="/run/vultrack-agent/access.token"  # tmpfs / memory

mkdir -p "$(dirname "$REFRESH_TOKEN_FILE")" "$(dirname "$ACCESS_TOKEN_FILE")"

RESPONSE=$(curl -sf -X POST "${VULTRACK_URL}/api/v2/agent/enroll" \
  -H "Authorization: Bearer ${ENROLLMENT_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"hostname\": \"$(hostname -f)\", \"force\": false}")

echo "$RESPONSE" | jq -r '.refreshToken' > "$REFRESH_TOKEN_FILE"
chmod 600 "$REFRESH_TOKEN_FILE"

echo "$RESPONSE" | jq -r '.accessToken' > "$ACCESS_TOKEN_FILE"
chmod 600 "$ACCESS_TOKEN_FILE"

STATUS=$(echo "$RESPONSE" | jq -r '.status')
echo "Agent enrolled with status: $STATUS"
```

### Step 2: Token refresh helper

```bash
#!/bin/bash
# refresh-token.sh — obtain a new access token; update both stored tokens

VULTRACK_URL="https://vultrack.example.com"
REFRESH_TOKEN_FILE="/etc/vultrack-agent/refresh.token"
ACCESS_TOKEN_FILE="/run/vultrack-agent/access.token"

REFRESH_TOKEN=$(cat "$REFRESH_TOKEN_FILE")

RESPONSE=$(curl -sf -X POST "${VULTRACK_URL}/api/v2/agent/token" \
  -H "Authorization: Bearer ${REFRESH_TOKEN}")

# Rotation: both tokens change on every refresh
echo "$RESPONSE" | jq -r '.refreshToken' > "$REFRESH_TOKEN_FILE"
echo "$RESPONSE" | jq -r '.accessToken'  > "$ACCESS_TOKEN_FILE"
chmod 600 "$REFRESH_TOKEN_FILE" "$ACCESS_TOKEN_FILE"
```

### Step 3: Report submission (scheduled via cron)

```bash
#!/bin/bash
set -euo pipefail

VULTRACK_URL="https://vultrack.example.com"
ACCESS_TOKEN_FILE="/run/vultrack-agent/access.token"
ENROLLMENT_KEY="enroll_abc123..."   # kept in config for re-enrollment

# Refresh access token before every report to ensure it is valid
bash /usr/local/lib/vultrack-agent/refresh-token.sh \
  || bash /usr/local/lib/vultrack-agent/enroll.sh    # re-enroll if refresh fails

ACCESS_TOKEN=$(cat "$ACCESS_TOKEN_FILE")

# Collect system information
HOSTNAME=$(hostname -f)
OS_FAMILY=$(grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"')
OS_RELEASE=$(grep ^VERSION_ID= /etc/os-release | cut -d= -f2 | tr -d '"')
OS_CODENAME=$(grep ^VERSION_CODENAME= /etc/os-release | cut -d= -f2 | tr -d '"')
KERNEL=$(uname -r)
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
IPV4_ADDRS=$(hostname -I | tr ' ' '\n' | grep -E '^[0-9]+\.' | jq -R . | jq -s .)

# Collect packages (Debian/Ubuntu)
PACKAGES=$(dpkg-query -W -f='{"name":"${Package}","version":"${Version}","arch":"${Architecture}","source":"${source:Package}"}\n' \
  | jq -s .)

curl -sf -X POST "${VULTRACK_URL}/api/v2/agent/report" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "hostname":       "${HOSTNAME}",
  "osFamily":       "${OS_FAMILY}",
  "osRelease":      "${OS_RELEASE}",
  "osCodename":     "${OS_CODENAME}",
  "kernel":         "${KERNEL}",
  "arch":           "${ARCH}",
  "packageManager": "dpkg",
  "ipv4Addrs":      ${IPV4_ADDRS},
  "packages":       ${PACKAGES}
}
EOF
```

### Cron entry

```cron
# Report to VulTrack every hour
0 * * * * root /usr/local/bin/vultrack-report.sh >> /var/log/vultrack-agent.log 2>&1
```

---

## Server configuration

### Environment variable

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | *(random, not persisted)* | HMAC-SHA256 signing secret for JWT access tokens. **Must be set in production** — otherwise all access tokens are invalidated on server restart. Minimum 32 bytes. |

### Configurable settings (Admin UI → Settings)

| Key | Default | Description |
|-----|---------|-------------|
| `agent_access_token_ttl_hours` | `24` | Access token (JWT) validity in hours |
| `agent_refresh_token_ttl_days` | `90` | Refresh token validity in days |

---

## Security considerations

1. **Use HTTPS.** All communication must be over TLS. Never send tokens over plain HTTP.
2. **Protect stored tokens.** Both the refresh token file and (if persisted) the access token file must have mode `0600` and be owned by the agent's service user.
3. **Keep the enrollment key in the config.** The enrollment key must remain available so the agent can re-enroll automatically if the refresh token expires.
4. **Token rotation.** Every call to `/api/v2/agent/token` issues a new refresh token and revokes the old one. Always persist the new refresh token before discarding the old one.
5. **Revocation.** An admin can revoke an agent in the Admin UI. The next access token validation will return `401` (the revocation check happens on the lightweight DB read in `/api/v2/agent/report`). The agent will then attempt a token refresh, which will also fail, and finally re-enroll.
6. **v1 tokens do not expire.** If you are migrating from v1, revoke old agent records in the Admin UI after switching to v2.

---

## Supported distributions

VulTrack currently supports vulnerability scanning for:

| Distribution | `osFamily` value | Package manager |
|--------------|-----------------|-----------------|
| Ubuntu | `ubuntu` | `dpkg` |
| Debian | `debian` | `dpkg` |
| RHEL | `rhel` | `rpm` |
| CentOS | `centos` | `rpm` |
| Rocky Linux | `rocky` | `rpm` |
| AlmaLinux | `alma` | `rpm` |

> **Note:** OVAL sources must be enabled in the Admin UI for the relevant distribution and version before vulnerability scanning produces results.
