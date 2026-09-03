# ldapium / ui

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
session ID in an `HttpOnly` cookie (`ldapium_session`). The bound LDAP
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
sets a single-use `HttpOnly`, `SameSite=Lax` cookie (`ldapium_sso_login`,
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

### No automatic fallback between modes

LDAP login and SSO are configured, not negotiated — whichever one
`SSO_ENABLED` selects at startup is the only one available until the
process is reconfigured and restarted. If that provider becomes
unreachable there is no automatic switch to the other: an SSO deployment
with an unreachable Keycloak does not fall back to asking for an LDAP
password, and there is no CAS/SAML adapter here to fall back to either —
both are out of scope for this project today.

`GET /api/health/ldap` exists for exactly this gap: an unauthenticated,
LDAP-only reachability check (`{"reachable": true|false}`, HTTP 200/503)
for whatever is watching provider health, separate from the pod's own
`readinessProbe` (`/api/auth/config`, which never touches LDAP — see
`charts/ldapium/templates/ui-deployment.yaml` — so the UI process itself
still comes up and reports its configured mode even when the directory
is down). It reveals nothing about *why* a failed check failed — no error text, just
the boolean and the status code — the same redaction `respondErr`
(`internal/httpapi/errors.go`) applies to every other unmapped internal
error, applied here too since this endpoint has no session to gate it.

See [`docs/auth-provider-policy.md`](../docs/auth-provider-policy.md) for
the full provider priority, failure, audit, and CAS/SAML boundary policy,
including the structured `auth` event line emitted on every login outcome.

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
| `UI_LOGIN_FAILURE_LIMIT` | no | `10` | Failed `POST /api/login` attempts allowed per client IP (see `UI_TRUSTED_PROXIES` below for how that IP is resolved) within the window before a `429` is returned; `0` disables the limiter. In-memory and per-pod — with multiple UI replicas the OpenLDAP ppolicy lockout is the backstop that holds cluster-wide |
| `UI_LOGIN_FAILURE_WINDOW` | no | `1m` | Sliding window `UI_LOGIN_FAILURE_LIMIT` applies over (Go duration syntax) |
| `UI_TRUSTED_PROXIES` | no | `private` | How the login limiter resolves a request's client IP: `private`, a comma-separated CIDR list, or `none` — see "Login throttling and trusted proxies" below |
| `SSO_ENABLED` | no | `false` | Enable Keycloak SSO; disables LDAP password login |
| `SSO_ISSUER_URL` | SSO | — | Keycloak realm issuer, e.g. `https://sso.example.com/realms/example` |
| `SSO_CLIENT_ID` | SSO | — | Confidential Keycloak OIDC client ID |
| `SSO_CLIENT_SECRET` | SSO | — | Confidential OIDC client secret; inject from a Secret, never a manifest literal |
| `SSO_ADMIN_ROLE` | no | `ldap-admin` | Required Keycloak realm role |
| `SSO_CALLBACK_ORIGINS` | SSO | — | Comma-separated exact browser origins allowed to form the callback URI; no paths |
| `LDAP_SERVICE_ACCOUNT_DN` | SSO | — | Dedicated LDAP UI service-account DN |
| `LDAP_SERVICE_ACCOUNT_PASSWORD` | SSO | — | Dedicated LDAP UI service-account password |

### Login throttling and trusted proxies

`UI_TRUSTED_PROXIES` controls how the per-IP `POST /api/login` failure
limiter (above) resolves a request's client IP — get this wrong and the
limiter is either bypassable or shared by everyone:

- `private` (default): trust loopback/link-local/private-network hops
  ahead of the client, matching an in-cluster ingress (this chart's
  default deployment). `X-Forwarded-For` is walked from the right,
  skipping trusted hops, so a public client cannot forge a fresh budget by
  setting its own `X-Forwarded-For` header — the ingress-appended, real
  address is reached first.
- a comma-separated CIDR list: trust ONLY those listed hops — deliberately
  not a superset of `private`, since adding it on top would leave this
  mode no stricter than `private` — for a proxy whose own address isn't
  itself on a private range and needs stricter trust than `private`
  grants. Via Helm, a multi-CIDR list must go in a `-f values.yaml` file
  rather than `--set`, which splits on bare commas (see the chart README's
  "Three helm footguns"); escape with `\,` if `--set` is unavoidable.
- `none`: ignore `X-Forwarded-For` entirely and key on the raw TCP peer.
  Only correct with no proxy in front of this service; behind one, every
  client arrives from the proxy's own address and shares a single budget.

Even configured correctly, blocking is per source IP, not per account:
everyone behind one NAT gateway or corporate egress IP shares a budget, so
one user mistyping a password repeatedly can get a different, correct user
on the same IP a `429` on their next attempt. The default 10 failures per
1-minute window keeps that window brief; `UI_LOGIN_FAILURE_LIMIT=0` turns
the limiter off entirely if this trade-off doesn't fit a deployment.

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
docker build -t ldapium-ui .
docker run -p 8080:8080 \
  -e LDAP_URL="ldaps://ldap.example.com:636" \
  -e LDAP_BASE_DN="dc=example,dc=com" \
  -e LDAP_USER_SEARCH_FILTER="(uid=%s)" \
  -e SESSION_SECRET="$(openssl rand -base64 32)" \
  ldapium-ui
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

## HTTP API

All endpoints under `/api` except `/api/auth/config`, `/api/health/ldap`, `/api/login`,
and `/api/sso/*` require an active session cookie (`ldapium_session`). Every authenticated
operation runs as the bound directory user under OpenLDAP's own ACLs.

| Method | Endpoint | Description | Status Codes |
|---|---|---|---|
| `GET` | `/api/auth/config` | Configured authentication mode (`ldap` or `sso`) | `200` |
| `GET` | `/api/health/ldap` | Unauthenticated LDAP ping reachability check | `200`, `503` |
| `POST` | `/api/login` | Bind as directory user and start session | `200`, `400`, `401`, `429` |
| `POST` | `/api/logout` | End session and close bound LDAP connection | `200` |
| `GET` | `/api/sso/start` | Initiate OIDC authorization code flow | `302`, `400` |
| `GET` | `/api/sso/callback` | Handle OIDC callback and create session | `302`, `400` |
| `GET` | `/api/me` | Current session's authenticated DN | `200`, `401` |
| `GET` | `/api/server-settings` | Directory configuration and deployment metadata | `200`, `401` |
| `GET` | `/api/monitor` | Read `cn=Monitor` statistics | `200`, `401`, `403` |
| `GET` | `/api/tree` | List child nodes of `?dn=` (or base DN if omitted) | `200`, `400`, `401` |
| `GET` | `/api/entry` | Get full attribute set of `?dn=` (redacts `userPassword`) | `200`, `400`, `401`, `404` |
| `POST` | `/api/entry/move` | Move entry to new parent DN (`{dn, newParentDn}`). *Exposed API-only for now.* | `204`, `400`, `401`, `404`, `409` |
| `GET` | `/api/password-policies` | List password policy entries under base | `200`, `401` |
| `GET` | `/api/users` | List user entries under search base | `200`, `401` |
| `POST` | `/api/users` | Create user under `LDAP_USER_CREATE_BASE` | `201`, `400`, `401`, `409` (conflict if uid exists) |
| `PUT` | `/api/users` | Update attributes on user | `204`, `400`, `401`, `404` |
| `DELETE` | `/api/users` | Delete user at `?dn=` | `204`, `400`, `401`, `404` (not found if already deleted) |
| `POST` | `/api/users/password` | Change password via RFC 3062 Password Modify | `200`, `400`, `401`, `403` |
| `POST` | `/api/users/unlock` | Clear ppolicy lockout (`pwdAccountLockedTime`) | `204`, `400`, `401`, `404` |
| `POST` | `/api/users/lock` | Administratively disable user account | `204`, `400`, `401`, `404` |
| `GET` | `/api/groups` | List groups under search base | `200`, `401` |
| `POST` | `/api/groups` | Create group under `LDAP_GROUP_CREATE_BASE` | `201`, `400`, `401`, `409` (conflict if group exists) |
| `PUT` | `/api/groups` | Update group attributes | `204`, `400`, `401`, `404` |
| `DELETE` | `/api/groups` | Delete group at `?dn=` | `204`, `400`, `401`, `404` (not found if already deleted) |
| `POST` | `/api/groups/members` | Add member to group (`{groupDn, memberDn}`) | `204`, `400`, `401`, `404`, `409` |
| `DELETE` | `/api/groups/members` | Remove member from group (`{groupDn, memberDn}`) | `204`, `400`, `401`, `404` |

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
(see `internal/session/store_test.go` for one such fake). Beyond that,
this codebase does not mock the LDAP wire protocol: anything that
actually dials a server (`Bind`, `Ping`, search/dial paths) has no unit
test and isn't meant to — there's no injectable interface for the
underlying `*ldap.Conn`. Instead it's verified live against a running
`ldapium:e2e` container, both continuously (`.github/workflows/*.yml`
— `e2e.yml`, `security-e2e.yml`, `replication-chaos-e2e.yml`, etc. all
stand up real containers/clusters) and as standard practice when
changing this code: rebuild the image, run it, exercise the actual API
over HTTP, tear down. PR descriptions in this repo's history show this
pattern — a "Test plan" section with live verification steps, not just
`go test` output. See the repo root `CLAUDE.md` for specific gotchas
(container UID/bind-mount issues on macOS/Colima, `docker exec -i`).
