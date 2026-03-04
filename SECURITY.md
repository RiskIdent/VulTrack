# Security Policy

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Instead, open a [GitHub Security Advisory](https://github.com/vultrack/vultrack/security/advisories/new) (private disclosure) Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Any suggested remediation (optional)

You will receive an acknowledgment within 5 business days. We aim to release a fix within 30 days for confirmed issues and will credit reporters in the release notes unless they prefer to remain anonymous.

## Security Design Notes

- **No credentials in code.** All secrets (DB password, OIDC client secret, SMTP password, API tokens) are loaded exclusively from environment variables.
- **Agent tokens are SHA-256 hashed** before storage. The plain-text token is only returned once at enrollment time.
- **Enrollment keys are SHA-256 hashed** before storage.
- **Sessions are stored server-side** in PostgreSQL; only a random session ID is kept in the cookie.
- **Containers run as non-root** using distroless (backend) and `nginx-unprivileged` (frontend) base images.
- **OIDC is optional.** When disabled, the API is unauthenticated — deploy behind a network boundary or reverse proxy with access control.
