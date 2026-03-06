# VulTrack Agent — v1 → v2 Migration Prompt

Use this prompt with a coding agent to migrate an existing VulTrack agent from the v1 to the v2 API.

---

## Prompt

```
You are migrating an existing VulTrack agent from API v1 to API v2.

Read the existing codebase first so you understand its structure before making any changes.

---

## What is changing

### v1 (current — to be replaced)

| Concern | v1 implementation |
|---------|------------------|
| Enrollment auth | Custom header `X-Enrollment-Key: enroll_<key>` |
| Report auth | Custom header `X-Agent-Token: at_<token>` |
| Base URL | `/api/v1/agent` |
| Token storage | Single long-lived opaque token stored on disk |
| Token expiry | Never — only revoked manually by an admin |
| Re-enrollment | Not supported (409 Conflict) |

### v2 (target — implement this)

| Concern | v2 implementation |
|---------|------------------|
| Enrollment auth | Standard `Authorization: Bearer enroll_<key>` header (RFC 6750) |
| Report auth | Standard `Authorization: Bearer <JWT>` header |
| Token refresh auth | Standard `Authorization: Bearer rt_<refresh-token>` header |
| Base URL | `/api/v2/agent` |
| Access token | Short-lived signed JWT; held in memory only, never written to disk |
| Refresh token | Long-lived opaque token (`rt_…`); persisted to disk; rotated on every use |
| Token expiry | Access token: configurable, default 24 h · Refresh token: configurable, default 90 days |
| Re-enrollment | Supported via `force: true` in the enroll request body |

---

## Step 1 — Configuration changes

Update the agent configuration to add and rename the following fields:

### Remove
- `token_file` (or equivalent field that stored the v1 agent token path)

### Add
- `enrollment_key` — string, required for enrollment and automatic re-enrollment.
  **This value must be kept permanently in the config**, not discarded after first enrollment.
  It is needed to re-enroll when the refresh token expires or is revoked.
- `refresh_token_file` — string, path to persist the refresh token on disk.
  Default: `/etc/vultrack-agent/refresh.token`

The access token is NEVER written to disk. It is held in memory for the lifetime of the
process (or until it expires and is refreshed).

---

## Step 2 — API client changes

Replace all existing API call implementations with the following exact specifications.

### 2a. Enrollment — POST /api/v2/agent/enroll

Request:
```http
POST /api/v2/agent/enroll
Authorization: Bearer enroll_<enrollment_key>
Content-Type: application/json

{
  "hostname": "<fqdn>",
  "force": <bool>
}
```

The `force` field controls re-enrollment behaviour:
- `false` (default): server returns `409 Conflict` if the hostname is already registered.
- `true`: server revokes the existing agent entry and issues fresh tokens.

Only send `force: true` when re-enrollment is the explicit intent (e.g., the refresh token
was rejected and the agent is falling back to the enrollment key).

Success response (HTTP 201):
```json
{
  "tokenType":    "Bearer",
  "accessToken":  "<signed JWT — hold in memory>",
  "refreshToken": "rt_<64 hex chars — persist to disk>",
  "expiresIn":    <seconds, e.g. 86400>,
  "status":       "active" | "pending"
}
```

After a successful enrollment:
1. Write `refreshToken` to `refresh_token_file` using a write-then-rename pattern (see Step 4).
2. Hold `accessToken` in memory only.
3. If `status` is `"pending"`, the agent cannot submit reports until an admin approves it.
   Log a clear message and retry after a suitable delay.

Error handling:
- `401 Unauthorized` → enrollment key is invalid, expired, or inactive. Log clearly and exit.
- `409 Conflict` → hostname already registered and `force` was `false`. Retry with `force: true`.

---

### 2b. Token refresh — POST /api/v2/agent/token

This endpoint replaces both the access token and the refresh token atomically.
The submitted refresh token is REVOKED on use — it cannot be used again.

Request:
```http
POST /api/v2/agent/token
Authorization: Bearer rt_<current_refresh_token>
```

Success response (HTTP 200):
```json
{
  "tokenType":    "Bearer",
  "accessToken":  "<new signed JWT — hold in memory>",
  "refreshToken": "rt_<new token — persist to disk>",
  "expiresIn":    <seconds>
}
```

After a successful refresh:
1. Write the new `refreshToken` to disk using write-then-rename BEFORE discarding the old value.
2. Replace the in-memory access token with the new value.

Error handling:
- `401 Unauthorized` → refresh token is expired, revoked, or invalid.
  Fall through to re-enrollment (Step 3, case C).

---

### 2c. Submit report — POST /api/v2/agent/report

Request:
```http
POST /api/v2/agent/report
Authorization: Bearer <access_token (JWT)>
Content-Type: application/json

{
  "hostname":       "<fqdn>",
  "agentVersion":   "<version string>",
  "osFamily":       "<ubuntu|debian|rhel|centos|rocky|alma>",
  "osRelease":      "<version, e.g. 24.04>",
  "osCodename":     "<codename, e.g. noble>",
  "kernel":         "<uname -r output>",
  "arch":           "<amd64|arm64|i386>",
  "packageManager": "<dpkg|rpm>",
  "ipv4Addrs":      ["<ip1>", "<ip2>"],
  "reportedAt":     "<ISO 8601 timestamp>",
  "packages": [
    {
      "name":    "<package name>",
      "version": "<full version string>",
      "arch":    "<arch>",
      "source":  "<source package name>"
    }
  ]
}
```

Required fields: `hostname`, `osFamily`, `osRelease`, `kernel`, `arch`, `ipv4Addrs`, `packages`.
Optional: `agentVersion`, `osCodename`, `packageManager`, `reportedAt`.

Success response (HTTP 200):
```json
{
  "message":      "Report processed successfully",
  "serverId":     <int>,
  "packageCount": <int>,
  "scanJobId":    "<uuid>"
}
```

Error handling:
- `401 Unauthorized` → access token expired. Refresh it (Step 2b) and retry the report once.
  Do not retry more than once without a fresh token.

---

## Step 3 — Token lifecycle state machine

Replace the existing token loading / validation logic with this state machine.
Implement it as a function called at the start of every `report` and `daemon` cycle.

```
START
  │
  ├─ refresh_token_file does NOT exist or is empty
  │   └─ [A] Enroll → save refresh_token, hold access_token → DONE
  │
  └─ refresh_token_file exists
      │
      ├─ access_token is in memory and not expired
      │   └─ [B] Use existing access_token for report → DONE
      │
      └─ access_token is absent or expired
          │
          ├─ POST /api/v2/agent/token (refresh)
          │   ├─ 200 OK  → [C] save new refresh_token, hold new access_token → DONE
          │   └─ 401     → [D] Re-enroll with force=true → save refresh_token, hold access_token → DONE
          │
          └─ network error → [E] Retry with exponential backoff (max 3 attempts, base 5 s)
                              └─ still failing → log error, skip this cycle
```

**Important for case [D]:** The agent re-enrolls automatically using the `enrollment_key`
from the configuration. It must NOT require manual intervention. This is the primary reason
why the enrollment key must remain permanently available in the config.

---

## Step 4 — Safe token file write (write-then-rename)

All writes to `refresh_token_file` MUST use an atomic write-then-rename pattern to avoid
corrupt state if the process is killed mid-write.

Pseudocode:
```
tmp = refresh_token_file + ".tmp"
write token to tmp
chmod(tmp, 0600)
rename(tmp, refresh_token_file)   // atomic on POSIX systems
```

The file and its directory must be owned by the agent's service user. Permissions:
- Directory: `0700`
- File: `0600`

---

## Step 5 — Remove v1 code

After implementing v2, remove all v1-specific code:

- All usages of `X-Enrollment-Key` header
- All usages of `X-Agent-Token` header
- All references to `/api/v1/agent` URLs
- The old token storage struct / file (if separate from the new refresh token file)
- Any config field that stored the old single agent token

Do NOT leave v1 code as a fallback. The migration is a full replacement, not an addition.

---

## Step 6 — Update the HTTP client

Ensure the HTTP client:

1. Sets `Authorization: Bearer <token>` on every request — never the old custom headers.
2. Reads the access token from memory (not from disk).
3. Does NOT log the full enrollment key, access token, or refresh token.
   Log only the first 8 characters (the token prefix) for identification.
4. Validates TLS certificates by default. An existing `--insecure` flag may remain.

---

## Step 7 — Update tests

Update all existing tests that reference the v1 API:

- Mock server responses at the new v2 endpoints (`/api/v2/agent/…`).
- Replace `X-Enrollment-Key` / `X-Agent-Token` assertions with `Authorization: Bearer` assertions.
- Add tests for the token refresh path:
  - Happy path: refresh succeeds, new tokens are stored and used.
  - Failure path: refresh returns 401, agent falls back to re-enrollment.
- Add a test for the write-then-rename atomic token update.

---

## Step 8 — Update documentation

Update `README.md` and any inline comments / examples:

- Replace all references to `X-Enrollment-Key` and `X-Agent-Token` with the correct v2 headers.
- Update configuration documentation to reflect the renamed fields.
- Add a note explaining that `enrollment_key` must remain in the config permanently.
- Update example `config.yaml` and any shell script examples.

---

## Acceptance criteria

The migration is complete when:

- [ ] All API calls use `/api/v2/agent/` URLs with `Authorization: Bearer` headers.
- [ ] The refresh token is persisted to disk using write-then-rename with mode 0600.
- [ ] The access token is held in memory only and never written to disk.
- [ ] The agent re-enrolls automatically (with `force: true`) when the refresh token is rejected.
- [ ] No v1 headers (`X-Enrollment-Key`, `X-Agent-Token`) remain anywhere in the codebase.
- [ ] All tests pass with the new v2 mock endpoints.
- [ ] The `enrollment_key` config field is clearly documented as permanent.
```

---

## Usage

Copy the prompt above (everything between the triple backticks) and paste it into a coding
agent session (e.g. Claude Code, Cursor) pointed at the existing agent repository.

The agent should read the existing codebase first, then apply the changes described above.
If the codebase deviates significantly from what the prompt assumes, instruct the agent to
adapt the steps to fit the actual structure while preserving all v2 requirements.

## Reference

Full API specification: [AGENT_API.md](AGENT_API.md)
