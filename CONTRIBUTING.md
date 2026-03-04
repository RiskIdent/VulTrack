# Contributing to VulTrack

Thank you for your interest in contributing! This document describes how to get started.

## Development Setup

### Prerequisites

- Go 1.24+
- Node.js 22+
- Docker and Docker Compose
- PostgreSQL 16 (or use the provided Docker Compose setup)

### Running Locally

**Start the database:**

```bash
docker compose up -d postgres
```

**Backend:**

```bash
cd backend
cp ../.env.example ../.env   # adjust values as needed
go mod download
go run ./cmd/vultrack
```

**Frontend:**

```bash
cd frontend
npm install
npm run dev
```

The frontend dev server proxies API calls to `http://localhost:8080` by default (see `vite.config.ts`).

## Project Structure

```
vultrack/
├── backend/
│   ├── cmd/vultrack/       # Entry point
│   └── internal/
│       ├── config/         # Environment variable loading
│       ├── database/       # Schema and DB helpers
│       ├── handlers/       # HTTP handlers (Fiber)
│       ├── models/         # Shared data models
│       ├── scanner/        # OVAL-based vulnerability scanner
│       ├── services/       # Business logic layer
│       └── ...             # exploitdb, jira, nvd, oval, oidc, ...
├── frontend/
│   └── src/
│       ├── api/            # API client functions
│       ├── components/     # Reusable UI components
│       ├── pages/          # Page-level components
│       └── types/          # TypeScript types
└── docs/                   # Additional documentation
```

## Code Style

**Go:** Follow standard Go conventions. Run `go vet ./...` before submitting.

**TypeScript/React:** The project uses ESLint. Run `npm run lint` before submitting.

## Submitting Changes

1. Fork the repository and create a feature branch from `main`.
2. Make your changes, keeping commits focused and atomic.
3. Ensure the backend compiles (`go build ./...`) and the frontend lints (`npm run lint`).
4. Open a pull request with a clear description of what changes you made and why.

## Reporting Bugs

Please open a GitHub issue and include:
- A clear description of the problem
- Steps to reproduce
- Expected vs. actual behavior
- VulTrack version or commit hash

For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead.
