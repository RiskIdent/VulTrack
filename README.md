# VulTrack

A vulnerability management system for tracking and triaging security vulnerabilities across your Ubuntu Linux infrastructure using agent-based scanning and OVAL definitions.

VulTrack was **developed entirely with AI**. There might be dragons. 🐉

## Features

- **Dashboard**: Overview of your vulnerability landscape with key metrics and charts
- **Server Management**: View all monitored servers and their vulnerability status
- **Findings Browser**: Search and filter vulnerability findings across all servers
- **Triage Queue**: Efficiently assess and categorize high-severity vulnerabilities
- **Statistics**: Trend analysis and detailed reports
- **Agent Management**: Manage agents and enrollment keys
- **OVAL Integration**: Automatic vulnerability detection using OVAL definitions (Ubuntu and others)
- **NVD Enrichment**: CVE details enriched with CVSS scores, CWE IDs, and descriptions
- **ExploitDB Integration**: Identify vulnerabilities with known exploits
- **Scheduled Reports**: Automated PDF reports delivered by email (weekly / monthly)
- **Server Groups**: Organize servers into groups for targeted reporting and filtering
- **Jira Integration**: Automatically create Jira tickets for relevant findings
- **OIDC Authentication**: Optional single sign-on via any OpenID Connect identity provider

## Architecture

```
                                                         ┌────────────────┐
                                                         │  PostgreSQL    │
                                                         │  Port: 5432    │
                                                         └───────▲────────┘
                                                                 │
                                        ┌─────────────────┐      │
                              ┌───────▶│    Frontend     │      │
                              │         │    (React)      │      │
                              │         │    Port: 8080   │      │
┌───────────┐       ┌─────────┴─────┐   └─────────────────┘      │
│           │       │               │                            │
│  Browser  │─────▶│    Reverse    │   ┌─────────────────┐      │
│           │       │    Proxy      │─▶│    Backend      │──────┘
│           │       │               │   │    (Go/Fiber)   │
└───────────┘       │  Port: 443    │   │    Port: 8080   │
                    │               │   └─────────────────┘
┌───────────┐       │   /*  → FE    │           ▲
│           │       │  /api/* → BE  │           │
│  Agents   │─────▶│               │───────────┘
│           │       │               │
└───────────┘       └───────────────┘
```

**Components:**
- **Frontend**: React SPA served by Nginx (static files only)
- **Backend**: Go/Fiber REST API
- **PostgreSQL**: Database for all application data
- **Reverse Proxy**: Routes requests to Frontend or Backend (not included, bring your own)
- **Agents**: Lightweight agents on monitored servers that report package information

## Quick Start

### Important

If you don't enable OIDC (see below) VulTrack can be used without any authentication.

### Prerequisites

- Docker and Docker Compose
- A reverse proxy (e.g., Caddy, Traefik, Nginx)
- PostgreSQL database

### Building the Images

```bash
# Build backend image
docker build -t vultrack-backend ./backend

# Build frontend image
docker build -t vultrack-frontend ./frontend
```

### Example Docker Compose Setup

Below is an example using Caddy as a reverse proxy. Adjust according to your infrastructure.

**docker-compose.yml:**
```yaml
services:
  caddy:
    image: caddy:2-alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
    depends_on:
      - frontend
      - backend
    restart: unless-stopped

  frontend:
    image: vultrack-frontend:latest
    restart: unless-stopped

  backend:
    image: vultrack-backend:latest
    environment:
      - POSTGRES_HOST=postgres
      - POSTGRES_PORT=5432
      - POSTGRES_USER=vultrack
      - POSTGRES_PASSWORD=changeme
      - POSTGRES_DB=vultrack
      - LOG_LEVEL=info
    depends_on:
      - postgres
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=vultrack
      - POSTGRES_PASSWORD=changeme
      - POSTGRES_DB=vultrack
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  caddy_data:
  postgres_data:
```

**Caddyfile:**
```
vultrack.example.com {
    # Frontend (static files)
    handle {
        reverse_proxy frontend:8080
    }

    # Backend API
    handle /api/* {
        reverse_proxy backend:8080
    }
}
```

### Access the Application

1. Start the services: `docker compose up -d`
2. Access the web interface at `https://vultrack.example.com`
3. Create an enrollment key in Admin → Enrollment Keys
4. Deploy agents on your servers using the enrollment key

## Configuration

All configuration is done via environment variables.

### Backend Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_HOST` | PostgreSQL hostname | `localhost` |
| `POSTGRES_PORT` | PostgreSQL port | `5432` |
| `POSTGRES_USER` | PostgreSQL username | `vultrack` |
| `POSTGRES_PASSWORD` | PostgreSQL password | `vultrack` |
| `POSTGRES_DB` | PostgreSQL database name | `vultrack` |
| `BACKEND_PORT` | Port the backend listens on | `8080` |
| `LOG_LEVEL` | Log level (debug, info, warn, error) | `info` |
| `TRIAGE_CVSS_THRESHOLD` | Minimum CVSS score for triage queue | `7.0` |
| `CORS_ORIGINS` | Comma-separated origins for CORS (required when using OIDC) | *(empty)* |

### Scan Queue

| Variable | Description | Default |
|----------|-------------|---------|
| `SCAN_WORKERS` | Number of concurrent scan workers | `5` |
| `SCAN_TIMEOUT` | Timeout per scan in seconds | `600` |
| `SCAN_MAX_RETRIES` | Maximum retry attempts for failed scans | `3` |
| `SCAN_QUEUE_SIZE` | Maximum scan queue depth | `500` |

### Email Notifications (optional)

When `SMTP_ENABLED=true`, VulTrack sends email reports via SMTP.

| Variable | Description | Default |
|----------|-------------|---------|
| `SMTP_ENABLED` | Enable email sending | `false` |
| `SMTP_HOST` | SMTP server hostname | *(empty)* |
| `SMTP_PORT` | SMTP server port | `587` |
| `SMTP_USER` | SMTP username (leave empty for unauthenticated relay) | *(empty)* |
| `SMTP_PASSWORD` | SMTP password | *(empty)* |
| `SMTP_FROM` | Sender address (e.g. `VulTrack <vultrack@example.com>`) | *(empty)* |
| `SMTP_TLS` | TLS mode: `starttls` (port 587), `tls` (port 465), `none` (port 25) | `starttls` |
| `SMTP_HELO_HOST` | EHLO hostname sent to the relay. Many relays reject `localhost`; set to your server's FQDN if needed | *(OS hostname)* |

### Jira Integration (optional)

When `JIRA_ENABLED=true`, a Jira ticket is automatically created whenever a finding is assessed as *Relevant*.

| Variable | Description | Default |
|----------|-------------|---------|
| `JIRA_ENABLED` | Enable Jira integration | `false` |
| `JIRA_BASE_URL` | Jira instance URL (e.g. `https://your-org.atlassian.net`) | *(empty)* |
| `JIRA_USER_EMAIL` | Jira user email for API authentication | *(empty)* |
| `JIRA_API_TOKEN` | Jira API token | *(empty)* |
| `JIRA_PROJECT_KEY` | Jira project key (e.g. `SEC`) | *(empty)* |
| `JIRA_ISSUE_TYPE` | Issue type for created tickets | `Task` |

### Frontend Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_API_URL` | Backend API base URL used during the frontend build | `http://localhost:8080/api/v1` |

### OIDC Authentication (optional)

When `OIDC_ENABLED=true`, the web UI requires users to sign in via an OpenID Connect identity provider (e.g. Keycloak, Auth0, Okta). When disabled, no login is required.

| Variable | Description | Default |
|----------|-------------|---------|
| `OIDC_ENABLED` | Enable OIDC login for the web UI | `false` |
| `OIDC_ISSUER` | IdP issuer URL (e.g. `https://idp.example.com/realms/vultrack`) | *(empty)* |
| `OIDC_CLIENT_ID` | OAuth2 client ID | *(empty)* |
| `OIDC_CLIENT_SECRET` | OAuth2 client secret | *(empty)* |
| `OIDC_REDIRECT_URL` | Backend callback URL (e.g. `https://vultrack.example.com/api/v1/auth/callback`) | *(empty)* |
| `OIDC_FRONTEND_URL` | Frontend URL for redirect after login (e.g. `https://vultrack.example.com`) | `/` |
| `OIDC_SCOPES` | OAuth2 scopes (space or comma separated) | `openid profile email` |

**Setup:**

1. Create an OAuth2/OIDC client in your IdP with redirect URI = `OIDC_REDIRECT_URL`.
2. Set `CORS_ORIGINS` to your frontend origin(s) so session cookies work (e.g. `http://localhost:3000` or `https://vultrack.example.com`).
3. The first user to sign in when no admin exists becomes an admin. Further admins can be assigned in **Admin → Users**.

The agent API (`/api/v1/agent/*`) is unchanged and uses enrollment keys and agent tokens, not OIDC.

## Development

### Backend (Go)

```bash
cd backend
go mod download
go run ./cmd/vultrack
```

### Frontend (React)

```bash
cd frontend
npm install
npm run dev
```

### Database

For development, you can start just the database:

```bash
docker compose up -d postgres
```

## API Endpoints

### Authentication
- `GET /api/v1/auth/login` - Redirect to OIDC identity provider
- `GET /api/v1/auth/callback` - OIDC callback (handles token exchange and session creation)
- `POST /api/v1/auth/logout` - Invalidate current session
- `GET /api/v1/auth/me` - Current user info (returns `authEnabled: false` when OIDC is disabled)

### Dashboard
- `GET /api/v1/dashboard` - Dashboard statistics

### Servers
- `GET /api/v1/servers` - List all servers
- `GET /api/v1/servers/:id` - Get server details
- `GET /api/v1/servers/:id/findings` - Get server findings
- `GET /api/v1/servers/:id/packages` - Get server packages
- `GET /api/v1/servers/:id/groups` - Get groups for a server
- `PUT /api/v1/servers/:id/groups` - Set groups for a server
- `POST /api/v1/servers/:id/scan` - Trigger a vulnerability scan
- `DELETE /api/v1/admin/servers/:id` - Delete server

### Findings
- `GET /api/v1/findings` - List findings with filters
- `GET /api/v1/findings/triage` - Get triage queue
- `GET /api/v1/findings/:id` - Get finding details

### CVEs
- `GET /api/v1/cves/:id` - Get CVE details
- `GET /api/v1/cves/:id/servers` - Get servers affected by CVE

### Assessments
- `GET /api/v1/assessments` - List all assessments
- `POST /api/v1/assessments` - Create assessment
- `PUT /api/v1/assessments/:cveId` - Update assessment
- `DELETE /api/v1/assessments/:cveId` - Delete assessment

### Reason Templates
- `GET /api/v1/reason-templates` - List reason templates
- `POST /api/v1/reason-templates` - Create reason template
- `PUT /api/v1/reason-templates/:id` - Update reason template
- `DELETE /api/v1/reason-templates/:id` - Delete reason template

### Statistics
- `GET /api/v1/stats/severity` - Severity breakdown
- `GET /api/v1/stats/trend` - Finding trends over time
- `GET /api/v1/stats/top-servers` - Most affected servers
- `GET /api/v1/stats/top-cves` - Most widespread CVEs
- `GET /api/v1/stats/assessments-by-severity` - Assessments grouped by severity

### Reports
- `POST /api/v1/reports/generate` - Generate a PDF report on demand
- `GET /api/v1/report-schedules` - List report schedules
- `POST /api/v1/report-schedules` - Create report schedule
- `GET /api/v1/report-schedules/:id` - Get report schedule
- `PUT /api/v1/report-schedules/:id` - Update report schedule
- `DELETE /api/v1/report-schedules/:id` - Delete report schedule
- `POST /api/v1/report-schedules/:id/toggle` - Enable or disable a schedule
- `POST /api/v1/report-schedules/:id/run-now` - Run a schedule immediately

### Scan Queue
- `GET /api/v1/scans` - List scan jobs
- `GET /api/v1/scans/stats` - Scan queue statistics
- `POST /api/v1/scans/:id/cancel` - Cancel a queued scan
- `POST /api/v1/scans/:id/retry` - Retry a failed scan

### Agent API
- `POST /api/v1/agent/enroll` - Register a new agent (requires `X-Enrollment-Key` header)
- `POST /api/v1/agent/report` - Submit agent report (requires `X-Agent-Token` header)

### Admin: Settings
- `GET /api/v1/admin/settings` - Get application settings
- `PUT /api/v1/admin/settings` - Update application settings

### Admin: Users
- `GET /api/v1/admin/users` - List users (requires OIDC)

### Admin: Server Groups
- `GET /api/v1/admin/server-groups` - List server groups
- `POST /api/v1/admin/server-groups` - Create server group
- `GET /api/v1/admin/server-groups/:id` - Get server group
- `PUT /api/v1/admin/server-groups/:id` - Update server group
- `DELETE /api/v1/admin/server-groups/:id` - Delete server group
- `GET /api/v1/admin/server-groups/:id/members` - List group members
- `POST /api/v1/admin/server-groups/:id/members` - Add member to group
- `DELETE /api/v1/admin/server-groups/:id/members/:serverId` - Remove member from group

### Admin: Enrollment Keys
- `GET /api/v1/admin/enrollment-keys` - List enrollment keys
- `POST /api/v1/admin/enrollment-keys` - Create enrollment key
- `PUT /api/v1/admin/enrollment-keys/:id` - Update enrollment key
- `DELETE /api/v1/admin/enrollment-keys/:id` - Delete enrollment key

### Admin: Agents
- `GET /api/v1/admin/agents` - List registered agents
- `PUT /api/v1/admin/agents/:id/approve` - Approve pending agent
- `PUT /api/v1/admin/agents/:id/revoke` - Revoke agent access
- `DELETE /api/v1/admin/agents/:id` - Delete agent

### Admin: OVAL Sources
- `GET /api/v1/admin/oval/distributions` - List available distributions
- `GET /api/v1/admin/oval/sources` - List enabled OVAL sources
- `POST /api/v1/admin/oval/sources` - Enable OVAL source
- `PUT /api/v1/admin/oval/sources/:id/disable` - Disable an OVAL source
- `DELETE /api/v1/admin/oval/sources/:id` - Remove an OVAL source
- `POST /api/v1/admin/oval/sources/:id/sync` - Trigger sync for a specific source
- `POST /api/v1/admin/oval/sync-all` - Trigger sync for all enabled sources

### Admin: NVD & ExploitDB
- `POST /api/v1/admin/nvd/sync` - Trigger NVD CVE sync
- `GET /api/v1/admin/nvd/status` - NVD sync status
- `POST /api/v1/admin/exploitdb/sync` - Trigger ExploitDB sync
- `GET /api/v1/admin/exploitdb/status` - ExploitDB sync status
- `GET /api/v1/admin/sync/status` - Combined sync status

### Admin: System
- `POST /api/v1/admin/system/reset` - Reset all application data

## Agent Deployment

Agents are lightweight scripts or binaries that run on monitored servers. They:

1. Enroll with VulTrack using an enrollment key
2. Periodically report system information and installed packages
3. VulTrack matches packages against OVAL definitions to detect vulnerabilities

See [docs/AGENT_API.md](docs/AGENT_API.md) for the complete agent API specification.

For a deeper OIDC setup guide including IdP-specific instructions, see [docs/OIDC_SETUP.md](docs/OIDC_SETUP.md).

## Roadmap

- [ ] Support for more Linux ditributions (Debian, RHEL...)
- [ ] REST API for report export (CSV)
- [ ] Multi-tenancy / team workspaces

## License

MIT License
