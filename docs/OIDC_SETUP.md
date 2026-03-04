# OIDC Authentication Setup

VulTrack supports optional single sign-on via any OpenID Connect (OIDC) identity provider (IdP). When disabled (`OIDC_ENABLED=false`), the application runs without any login requirement.

## How It Works

- The backend acts as an OIDC relying party (client).
- On first login, a user account is created automatically from the IdP claims.
- If no admin user exists yet, the first user to log in becomes admin. Further admins can be assigned in **Admin → Users**.
- Sessions are stored server-side in PostgreSQL; only a random session ID is kept in the browser cookie.
- The agent API (`/api/v1/agent/*`) always uses enrollment key / agent token auth and is unaffected by OIDC settings.

## Configuration

Set these environment variables on the backend:

| Variable | Description | Example |
|----------|-------------|---------|
| `OIDC_ENABLED` | Enable OIDC login | `true` |
| `OIDC_ISSUER` | Issuer URL (used for OIDC discovery) | `https://idp.example.com/realms/vultrack` |
| `OIDC_CLIENT_ID` | OAuth2 client ID | `vultrack` |
| `OIDC_CLIENT_SECRET` | OAuth2 client secret | `your-secret` |
| `OIDC_REDIRECT_URL` | Backend callback URL | `https://vultrack.example.com/api/v1/auth/callback` |
| `OIDC_FRONTEND_URL` | Frontend redirect after login | `https://vultrack.example.com` |
| `OIDC_SCOPES` | Requested scopes | `openid profile email` |
| `CORS_ORIGINS` | Frontend origin(s), required for cookie auth | `https://vultrack.example.com` |

> `CORS_ORIGINS` must be set to your frontend URL when OIDC is enabled. Without it, the session cookie cannot be sent cross-origin.

## IdP Setup

### Keycloak

1. Create a new realm (e.g. `vultrack`) or use an existing one.
2. Create a new client:
   - **Client ID:** `vultrack`
   - **Client authentication:** On (confidential)
   - **Valid redirect URIs:** `https://vultrack.example.com/api/v1/auth/callback`
3. Copy the client secret from the **Credentials** tab.
4. Set `OIDC_ISSUER` to `https://<keycloak-host>/realms/<realm-name>`.

### Authentik

1. Create a new OAuth2/OIDC provider:
   - **Client ID:** `vultrack`
   - **Redirect URIs:** `https://vultrack.example.com/api/v1/auth/callback`
   - **Scopes:** `openid`, `profile`, `email`
2. Create an application pointing to this provider.
3. Set `OIDC_ISSUER` to `https://<authentik-host>/application/o/<app-slug>/`.

### Auth0

1. Create a new **Regular Web Application**.
2. Add `https://vultrack.example.com/api/v1/auth/callback` to **Allowed Callback URLs**.
3. Set `OIDC_ISSUER` to `https://<your-tenant>.auth0.com/`.

### Generic

Any IdP that supports OIDC discovery (i.e. exposes `<issuer>/.well-known/openid-configuration`) will work. Set `OIDC_ISSUER` to the issuer URL and ensure the redirect URI is registered.

## Login Flow

```
Browser → GET /api/v1/auth/login
       ← 302 Redirect to IdP

Browser → POST <idp>/token (code exchange, handled by backend)
       ← 302 Redirect to OIDC_FRONTEND_URL

Browser → GET /api/v1/auth/me (with session cookie)
       ← 200 { id, email, name, isAdmin }
```

## Logout

Call `POST /api/v1/auth/logout`. The server deletes the session from the database and clears the cookie. The browser is **not** redirected to the IdP's logout endpoint — the IdP session remains active. If your users need full IdP logout, implement that separately on the frontend.

## Troubleshooting

**"OIDC disabled" error on `/auth/login`**
→ `OIDC_ENABLED` is not set to `true`.

**Session cookie not sent / 401 after login**
→ `CORS_ORIGINS` is not set or does not match the frontend URL exactly (including protocol and port).

**`invalid_client` or `unauthorized_client` from the IdP**
→ Check `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`.

**Redirect URI mismatch**
→ `OIDC_REDIRECT_URL` must exactly match the redirect URI registered in your IdP (including trailing slash, if any).

**User gets created but is not admin**
→ A user with `is_admin = true` already exists. Grant admin in **Admin → Users**.
