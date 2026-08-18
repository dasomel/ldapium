# openldap-suite / ui

A self-contained LDAP management web app: a Go + Echo backend that speaks
LDAP directly and also serves the built React SPA, shipped as a single
container image.

## Authentication modes

There is no local user database. The UI has two mutually exclusive modes:

### LDAP login (default)

When SSO is disabled, logging in performs an actual LDAP bind with the
credentials you type. If the bind succeeds, that exact bound connection is
kept server-side for the rest of your session, and **every subsequent LDAP
operation you make runs over that same connection** — so the directory's own
ACLs decide what you're allowed to do, not this app.

The identifier field on the login form accepts either:

- a full DN (`uid=jdoe,ou=people,dc=example,dc=com`), used to bind directly, or
- a bare uid, resolved to a DN via an **anonymous** LDAP search using
  `LDAP_USER_SEARCH_FILTER` under `LDAP_USER_SEARCH_BASE`. This requires the
  directory to permit anonymous read of that filter's attribute (typically
  `uid`) under the search base — there is no other credential available to
  perform the lookup with, by design. If you'd rather not allow anonymous
  search, only enable full-DN login by leaving `LDAP_USER_SEARCH_FILTER`
  unset.

Sessions are server-side: the browser only ever holds a signed, opaque
session ID in an `HttpOnly` cookie (`ldapui_session`). The bound LDAP
connection and the DN it authenticated as live in an in-memory server-side
table, never in the cookie, never in localStorage. Idle sessions expire
after `SESSION_TTL` (sliding — any request extends it) and a background
janitor closes their LDAP connections; logout closes it immediately.

### Keycloak SSO

Set `SSO_ENABLED=true` only after all SSO variables below are configured.
This makes the UI **SSO-only**: the password form and `POST /api/login` are
disabled. The browser uses OIDC authorization code flow with PKCE (S256),
server-side short-lived single-use state, and an ID-token nonce. The backend
verifies the ID token's signature, issuer, audience, and expiry using
Keycloak's published keys.

Each login is also bound to the browser that started it: `/api/sso/start`
sets a single-use `HttpOnly`, `SameSite=Lax` cookie (`ldapui_sso_login`,
scoped to `/api/sso`) and the callback refuses a state that arrives without
the matching value. Without that, anyone holding a valid state and code —
obtainable by running the flow against their own account — could lure a
victim to the callback URL and have the server hand the victim's browser a
session for the attacker's account.

The Keycloak subject must have `SSO_ADMIN_ROLE` (default `ldap-admin`) in
either the custom array-valued `roles` claim or Keycloak's standard
`realm_access.roles`. Its `preferred_username` is resolved to exactly one
LDAP `uid` under `LDAP_USER_SEARCH_BASE` with the configured, RFC 4515
escaped `LDAP_USER_SEARCH_FILTER`; no matching LDAP entry is rejected.

SSO mode binds LDAP as `LDAP_SERVICE_ACCOUNT_DN`, not as the Keycloak user.
The service account is therefore responsible for the **full existing UI
scope**: DIT read/write, user and group CRUD, password reset, account
unlock, and all related searches. Grant only this UI-specific account the
required LDAP ACLs; it is never provisioned automatically by this project.
The user's display DN remains in the application session and `/api/me`.
The self-password page becomes a service-account reset in SSO mode, so a
Keycloak user is never asked for an LDAP password.

`POST /api/logout` always ends the local UI session and clears its cookie.
When Keycloak advertises an `end_session_endpoint`, the UI sends the
server-side ID-token hint there for RP-initiated logout, then returns to its
login page without auto-starting a new session. Register
`<origin>/login` as a valid post-logout redirect URI in Keycloak. If the
provider does not advertise that endpoint, logout is local-only; use
Keycloak's own session controls when provider-session logout is required.

## Configuration (environment variables)

No security-relevant setting has a hardcoded default — you must set the
LDAP connection details and a session secret explicitly.

| Variable | Required | Default | Description |
|---|---|---|---|
| `LDAP_URL` | yes | — | `ldap://host:389` or `ldaps://host:636` |
| `LDAP_BASE_DN` | yes | — | Search base for the tree browser and user/group listings |
| `SESSION_SECRET` | yes | — | HMAC key for signing session cookies; **32+ bytes** |
| `LISTEN_ADDR` | no | `:8080` | HTTP listen address |
| `LDAP_USER_SEARCH_BASE` | no | `LDAP_BASE_DN` | Subtree searched to resolve uid → DN at login |
| `LDAP_USER_SEARCH_FILTER` | no | *(unset)* | Filter template with one `%s`, e.g. `(uid=%s)`. Unset = full-DN login only |
| `LDAP_USER_CREATE_BASE` | no | `LDAP_BASE_DN` | Where new users are created, e.g. `ou=people,dc=example,dc=com` |
| `LDAP_GROUP_CREATE_BASE` | no | `LDAP_BASE_DN` | Where new groups are created, e.g. `ou=groups,dc=example,dc=com` |
| `LDAP_START_TLS` | no | `false` | Negotiate StartTLS on a plain `ldap://` connection |
| `LDAP_TLS_CA_CERT` | no | *(system trust store)* | Path to a PEM CA bundle for `ldaps://`/StartTLS |
| `LDAP_TLS_INSECURE_SKIP_VERIFY` | no | `false` | Skip TLS certificate verification — local dev only |
| `SESSION_TTL` | no | `30m` | Idle session lifetime (Go duration syntax, e.g. `1h`) |
| `COOKIE_SECURE` | no | `true` | Mark the session cookie `Secure`; disable only for plain-HTTP local dev |
| `SSO_ENABLED` | no | `false` | Enable Keycloak SSO; disables LDAP password login |
| `SSO_ISSUER_URL` | SSO | — | Keycloak realm issuer, e.g. `https://sso.example.com/realms/example` |
| `SSO_CLIENT_ID` | SSO | — | Confidential Keycloak OIDC client ID |
| `SSO_CLIENT_SECRET` | SSO | — | Confidential OIDC client secret; inject from a Secret, never a manifest literal |
| `SSO_ADMIN_ROLE` | no | `ldap-admin` | Required Keycloak realm role |
| `SSO_CALLBACK_ORIGINS` | SSO | — | Comma-separated exact browser origins allowed to form the callback URI; no paths |
| `LDAP_SERVICE_ACCOUNT_DN` | SSO | — | Dedicated LDAP UI service-account DN |
| `LDAP_SERVICE_ACCOUNT_PASSWORD` | SSO | — | Dedicated LDAP UI service-account password |

### Keycloak client setup

Create a **confidential** client in the Beluga realm
(`https://sso.example.com/realms/example`) with Standard Flow
(authorization code) enabled and PKCE method **S256**. Store its client
secret in Kubernetes rather than application configuration. Request/allow
the `openid` and `profile` scopes so the ID token has `preferred_username`.

Register every browser-facing callback URI exactly. For local backend and
Vite development, register both:

```text
http://127.0.0.1:5173/api/sso/callback
http://127.0.0.1:8080/api/sso/callback
```

Also register `<production-origin>/api/sso/callback` for every production
origin placed in `SSO_CALLBACK_ORIGINS`. The backend derives the callback
from the request host/scheme (including forwarded host/proto) only after an
exact allowlist check, so do not use wildcards.

For RP-initiated logout, also register `<origin>/login` as a valid
post-logout redirect URI for each allowed browser origin.

Create the realm role `ldap-admin` (or override `SSO_ADMIN_ROLE`) and map
realm roles into the ID token. The UI accepts either an array custom claim
named `roles` or Keycloak's `realm_access.roles`; ensure one is present in
the **ID token**, not only an access token. Do not map a display name in
place of `preferred_username`: it is used as the LDAP `uid` lookup key.

## Running

```sh
docker build -t openldap-suite-ui .
docker run -p 8080:8080 \
  -e LDAP_URL="ldaps://ldap.example.com:636" \
  -e LDAP_BASE_DN="dc=example,dc=com" \
  -e LDAP_USER_SEARCH_FILTER="(uid=%s)" \
  -e SESSION_SECRET="$(openssl rand -base64 32)" \
  openldap-suite-ui
```

## v1 scope

Login/logout, a lazy-loading DIT tree browser with an attribute inspector,
user CRUD with password changes via the RFC 3062 Password Modify extended
operation (never a raw `userPassword` write), and group CRUD with member
management on `groupOfNames`/`member`. Explicitly out of scope: schema
editor, ACL editor, replication management, self-service password portal.

Note: `groupOfNames` requires at least one `member` value by schema, so a
newly created group is seeded with the creating user as its first member —
there's no service account to use as a placeholder instead. Add the real
member(s) and remove yourself from the group afterwards if you don't want
to remain on it.

## Development

```sh
# backend
cd backend && go run ./cmd/server

# frontend (proxies /api to :8080, see vite.config.ts)
cd frontend && npm install && npm run dev
```

`frontend`'s production build (`npm run build`) writes straight into
`backend/web/dist`, which the Go binary embeds via `go:embed` (see
`backend/web/embed.go`) — there is no separate frontend artifact to deploy.

## Architecture

- `backend/internal/domain` — framework-free data types (`User`, `Group`,
  `Entry`, sentinel errors). No LDAP or HTTP imports allowed.
- `backend/internal/ldapclient` — the only package that imports
  `go-ldap/ldap/v3`. Exposes a `Client` interface (one bound connection,
  one directory user) and a `Dialer` (`Bind` → `Client`), so the HTTP layer
  and tests never depend on a concrete LDAP library type.
- `backend/internal/session` — server-side session table keyed by a
  cryptographically random ID, referenced by an HMAC-signed cookie.
- `backend/internal/httpapi` — thin Echo handlers: bind input, call the
  session's `Client`, map domain errors to HTTP status codes.
- `backend/internal/validate` — pure input validation shared by handlers.
- `backend/web` — `go:embed` of the built SPA.

## Testing note

The LDAP layer (`internal/ldapclient`) is structured behind the `Client`
interface specifically so it can be exercised with a fake in unit tests
(see `internal/session/store_test.go` for one such fake). **Live
integration against a real LDAP server has not been verified** — the
server image this app talks to is being built in a separate, parallel
workstream and wasn't available while this UI was developed. Everything
below `go build ./...`, `go vet ./...`, and `go test ./...` passing is
verified; end-to-end behavior against an actual OpenLDAP instance is not.
