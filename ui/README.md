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
| `UI_LOGIN_LIMITER_MAX_ENTRIES` | no | `10000` | Hard cap on client sources the login limiter tracks (IPv6 counts per /64; must be >= 1). When full, expired sources go first, then the non-blocked source with the fewest stored failures (as of its last update; oldest on ties); a blocked source is never evicted, and only if all slots are blocked does a new source get the same `429` a blocked one does |
| `MACHINE_AUTH_ENABLED` | no | `false` | Machine bearer authentication for Keycloak service clients (#214, change package `machine-principal-auth`). **Unit 1 only: with it on, an authorized request still ends in a fixed `503` because the least-privilege LDAP bind identity is not implemented yet.** Unset, no `MACHINE_*` variable is read and nothing changes. When on, startup requires `MACHINE_OIDC_ISSUER_URL` (https; inherits `SSO_ISSUER_URL`; `MACHINE_OIDC_INSECURE_HTTP=true` is a local-test exception that logs a WARN), `MACHINE_OIDC_AUDIENCE`, `MACHINE_ALLOWED_CLIENTS` (`clientId=scope,scope;clientId2=scope`), `MACHINE_LDAP_BIND_DN`, `MACHINE_LDAP_BIND_PASSWORD`, `MACHINE_LDAP_ROOT_DNS` (`;`-separated, escape a literal `;` as `\3B`), and `UI_TRUSTED_PROXIES` set to CIDRs or `none` (not `private`). Optional tuning (`MACHINE_OIDC_ALGS`, `MACHINE_TOKEN_MAX_TTL`, `MACHINE_CLOCK_SKEW` 0-60s, `MACHINE_JWKS_CACHE_TTL`/`_MAX_STALE`/`_MIN_REFRESH`, `MACHINE_SA_USERNAME_PREFIX`, limiter and concurrency values) and the full contract are in `docs/changes/machine-principal-auth/CHANGE.md` and `docs/api.md`. The machine LDAP account and its read-only ACL are created by the operator: see [`docs/machine-ldap-account.md`](../docs/machine-ldap-account.md) (apply it on every LDAP node before turning this on) |
| `UI_IDEMPOTENCY_ENABLED` | no | `false` | Honour `Idempotency-Key` on the core user/group writes (#216). Records are in process memory (24h) and a restart forgets them, so enable it only for a single UI process (the chart does: one replica, `Recreate`). Off, a keyed write is refused with `422 idempotency_unsupported` |
| `UI_IDEMPOTENCY_TTL` | no | `24h` | How long a completed record replays (1m-7d) |
| `UI_IDEMPOTENCY_KEY_FILE` | no | _(unset)_ | Absolute path of the persisted fingerprint key: created once with mode 0600 in a 0700 directory owned by the UI user, never regenerated; startup is refused if it is unsafe. Two lines (`current`, `previous`) rotate it. Required for `Idempotency-Key` on backup start (the key lives in the durable job record); without it that key is refused. Never logged |
| `UI_TRUSTED_PROXIES` | no | `private` | How the login limiter resolves a request's client IP: `private`, a comma-separated CIDR list, or `none` — see "Login throttling and trusted proxies" below |
| `METRICS_ADDR` | no | _(empty)_ | `host:port` of an optional second listener that serves only `GET /metrics` (Prometheus text, `ldapium_ui_*` process metrics). Empty = no listener and nothing collected. Must differ from `LISTEN_ADDR`; unauthenticated, so bind it to loopback or protect it with a NetworkPolicy. The public port answers `/metrics` with a 404 JSON error body. See `docs/api.md` |
| `CORS_ALLOWED_ORIGINS` | no | _(empty)_ | Comma-separated exact `scheme://host[:port]` origins that may read `/api` GET/HEAD responses cross-origin with credentials. Read-only: the write Origin gate ignores this list, so a listed origin cannot write either. Empty = no CORS headers at all. `*`, `null`, paths, userinfo and empty or out-of-range ports are refused at startup; the default ports `:80`/`:443` are dropped (browsers omit them). Same-site use only: the session cookie stays `SameSite=Lax`. See `docs/api.md` |
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
  grants. A peer outside the list (including a loopback, link-local or
  private-network peer) is never trusted: its `X-Forwarded-For` is ignored
  and it keys on its own address. **Compatibility note:** before this fix
  the implicit private-network trust stayed on next to an explicit list, so
  an unlisted private peer could forge `X-Forwarded-For`; if you set a CIDR
  list and relied on that implicit trust, list every proxy CIDR explicitly
  (for example the ingress controller's pod CIDR). Via Helm, a multi-CIDR list must go in a `-f values.yaml` file
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

The limiter's memory is bounded (`UI_LOGIN_LIMITER_MAX_ENTRIES`) and IPv6
clients are grouped per /64. When the table is full a new source evicts, in
order, an expired source, then the non-blocked source with the fewest failures
(oldest on ties); a blocked source is never evicted, so no flood resets it.
"Fewest failures" compares the counts stored as of each source's last update
(its own request or the once-per-window sweep), not a time-decayed count, so a
source with partially expired failures can be kept over one whose real count is
higher. A source with f stored failures is evicted only when the other slots
hold sources that are blocked or have at least f stored failures; if the table holds only
equal-count sources the oldest goes (at f=1 that is cheap, and costs the victim
one failure of budget). The price is fail-closed behaviour: a new source is
refused with the blocked-source `429` only when **all** slots are blocked,
which costs an attacker `UI_LOGIN_LIMITER_MAX_ENTRIES` x
`UI_LOGIN_FAILURE_LIMIT` failed binds inside one window (100000 at the
defaults); already tracked sources are unaffected.

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

This table covers the console's core endpoints. The complete, machine-readable contract (including `/api/v1/*`) is served at `/api/v1/openapi.json`; see [`docs/api.md`](../docs/api.md) and `/llms.txt`.

All endpoints under `/api` except `/api/auth/config`, `/api/health/ldap`, `/api/login`,
and `/api/sso/*` require an active session cookie (`ldapium_session`). Which identity an
operation runs as depends on the authentication mode (see
[Authentication modes](#authentication-modes) above): in LDAP login mode it runs as the
bound directory user, under that user's own OpenLDAP ACLs; in Keycloak SSO mode — including
`POST /api/entry/move` — it runs as `LDAP_SERVICE_ACCOUNT_DN`, scoped by that service
account's own ACLs and gated by the `SSO_ADMIN_ROLE` check on login, never as the
individual Keycloak user. See
[`docs/auth-provider-policy.md`](../docs/auth-provider-policy.md) for the full policy.

| Method | Endpoint | Description | Status Codes |
|---|---|---|---|
| `GET` | `/api/auth/config` | Configured authentication mode (`ldap` or `sso`) | `200` |
| `GET` | `/api/health/ldap` | Unauthenticated LDAP ping reachability check | `200`, `503` |
| `POST` | `/api/login` | Bind as directory user and start session | `200`, `400`, `401`, `429` |
| `POST` | `/api/logout` | End session and close bound LDAP connection (`200` with `{redirectURL}` in SSO mode) | `204`, `200` |
| `GET` | `/api/sso/start` | Initiate OIDC authorization code flow | `302`, `400` |
| `GET` | `/api/sso/callback` | Handle OIDC callback and create session | `303`, `400` |
| `GET` | `/api/me` | Current session's authenticated DN | `200`, `401` |
| `GET` | `/api/server-settings` | Directory configuration and deployment metadata | `200`, `401` |
| `GET` | `/api/monitor` | Read `cn=Monitor` statistics | `200`, `401`, `403` |
| `GET` | `/api/audit/actions` | List operator action history (`?limit=&before=`) from `cn=accesslog` (admin only) | `200`, `401`, `403` |
| `GET` | `/api/tree` | List child nodes of `?dn=` (or base DN if omitted) | `200`, `400`, `401`, `403`, `404` |
| `GET` | `/api/entry` | Get full attribute set of `?dn=` (redacts `userPassword`) | `200`, `400`, `401`, `403`, `404` |
| `POST` | `/api/entry/move` | Move entry to new parent DN (`{dn, newParentDn}`). *Exposed API-only for now.* | `204`, `400`, `401`, `403`, `404`, `409` (`400` if `newParentDn` would move the entry across naming contexts/backends; `409` if an entry with the same RDN already exists under `newParentDn` — OpenLDAP mdb moves a non-leaf entry together with its subtree, so children alone do not cause a `409`) |
| `GET` | `/api/password-policies` | List password policy entries under base | `200`, `401`, `403` |
| `GET` | `/api/users` | List user entries under search base | `200`, `401`, `403` |
| `POST` | `/api/users` | Create user under `LDAP_USER_CREATE_BASE` | `201`, `400`, `401`, `403`, `409` (conflict if uid exists) |
| `PUT` | `/api/users` | Update attributes on user | `204`, `400`, `401`, `403`, `404` |
| `DELETE` | `/api/users` | Delete user at `?dn=` | `204`, `400`, `401`, `403`, `404` (not found if already deleted) |
| `POST` | `/api/users/password` | Change password via RFC 3062 Password Modify | `200`, `400`, `401`, `403`, `404` |
| `POST` | `/api/users/unlock` | Clear ppolicy lockout (`pwdAccountLockedTime`); idempotent, `204` even if not locked | `204`, `400`, `401`, `403`, `404` |
| `POST` | `/api/users/lock` | Administratively disable user account | `204`, `400`, `401`, `403`, `404` |
| `GET` | `/api/groups` | List groups under search base | `200`, `401`, `403` |
| `POST` | `/api/groups` | Create group under `LDAP_GROUP_CREATE_BASE` | `201`, `400`, `401`, `403`, `409` (conflict if group exists) |
| `PUT` | `/api/groups` | Update group attributes | `204`, `400`, `401`, `403`, `404` |
| `DELETE` | `/api/groups` | Delete group at `?dn=` | `204`, `400`, `401`, `403`, `404` (not found if already deleted) |
| `POST` | `/api/groups/members` | Add member to group (`{groupDn, memberDn}`) | `204`, `400`, `401`, `403`, `404`, `409` |
| `DELETE` | `/api/groups/members` | Remove member from group (`?groupDn=&memberDn=` query parameters, no body) | `204`, `400`, `401`, `403`, `404` |

### `cn=accesslog` read access for the History page

`GET /api/audit/actions` (the History page) and the recent-log portion of
`GET /api/monitor` both read `cn=accesslog`. Its default ACL
(`image/ldifs/01-cn-config.ldif`) is `to * by dn.exact="cn=admin,cn=accesslog"
read by * none` — the same "own dedicated bind identity, everyone else
denied" shape `cn=Monitor` uses (see the chart README's "Web console health
view"). **Without an explicit grant, both endpoints return `403` for every
identity, including the directory admin** — not an empty history, a hard
permission error.

To grant read access to your admin DN (LDAP login mode) or the SSO service
account (`ui.ldapServiceAccount` / `LDAP_SERVICE_ACCOUNT_DN`), add a
`by dn.exact=...read` clause the same way `.github/workflows/ui-e2e.yml` does
in CI — look up the accesslog database's numeric index first, since it
shifts depending on which other databases/overlays are enabled, rather than
assuming a fixed value:

```bash
ACCESSLOG_DN=$(ldapsearch -x -LLL -D "cn=admin,cn=config" -w "$LDAP_ADMIN_PASSWORD" \
  -b cn=config "(olcSuffix=cn=accesslog)" dn | sed -n 's/^dn: //p')
cat <<EOF | ldapmodify -x -D "cn=admin,cn=config" -w "$LDAP_ADMIN_PASSWORD"
dn: $ACCESSLOG_DN
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.exact="cn=admin,cn=accesslog" read by dn.exact="<your DN>" read by * none
EOF
```

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
`go test` output. See the repo root `AGENTS.md` ("Local Docker/LDAP verification") for specific gotchas
(container UID/bind-mount issues on macOS/Colima, `docker exec -i`).


## Application SSO integration profiles (first implementation slice)

The **App SSO permissions** page registers arbitrary applications and their OIDC
claim-to-native-role mappings. Keycloak remains the role authority. A saved
profile is `configured`, not applied or verified: this slice makes no Keycloak,
OSS ACL, or LDAP membership changes. Organization-scoped mappings and native
roles behind gateway-only authentication are rejected.

Enable persistence with both environment variables:

- `APP_PROFILES_PATH`: writable JSON file on persistent storage.
- `APP_PROFILES_ADMIN_DNS`: semicolon-separated exact session DNs permitted to
  read and edit profiles. No administrator is granted by default; this gate is
  independent of directory ACLs and the existing SSO login role.

Storage is single-process/single-replica, at most 1,000 profiles and 4 MiB.
Use one UI instance and back up the file. Multiple processes sharing a file are
unsupported; PostgreSQL and HA support remain planned. Startup rejects corrupt
files. Writes use a private temporary file and atomic rename; filesystem/power-loss
recovery still requires a backup. Profile metadata contains no credentials.

Authenticated, allowlisted session API:

| Method | Path | Behavior |
|---|---|---|
| GET | `/api/v1/applications` | List saved profiles |
| GET | `/api/v1/applications/{id}/integration-profile` | Read profile and ETag |
| PUT | `/api/v1/applications/{id}/integration-profile` | Create or replace metadata |

PUT requires same-origin `Origin`, `application/json`, and `If-Match: "0"` for
creation or the current ETag for editing; stale writes return 412. Clients omit
server-owned `revision` and `status`. Unknown fields, including secrets, are
rejected. Profiles use HTTPS issuers, token source `id_token`/`access_token`/`userinfo`,
`native_app` or `gateway_admission` enforcement, and only `app` scope. Issuer URLs
are metadata and are not fetched. Role mappings describe intended configuration,
not observed effective permissions. There is no external bearer API in this slice.

Verification: build the frontend, then run
`python3 scripts/test/test-app-profiles-local.py` from the repository root with
Docker, `ldapium:e2e`, Go, Node and Playwright Chromium available. The test uses
random disposable credentials and a dedicated LDAP container; it exercises real
login, browser saving/reloading, mapping denial and backend restart persistence.
It does not verify OIDC federation or Keycloak role application.
Set `LDAPIUM_IMAGE` to use another server image tag. The same run also executes the
`@fixture` test in `e2e/ui-review.spec.ts`; CI runs it in `.github/workflows/ui-fixture-e2e.yml`.

### Keycloak delegation and application configuration exports

Keycloak remains the authoritative role store. Enable optional read-through with
`KEYCLOAK_ADMIN_URL` (HTTPS), `KEYCLOAK_ADMIN_REALM`, `KEYCLOAK_ADMIN_CLIENT_ID`,
`KEYCLOAK_ADMIN_CLIENT_SECRET`, and semicolon-separated `KEYCLOAK_OBSERVE_CLIENTS`.
The configured issuer must exactly match the profile issuer. Use a dedicated service
account; never use the master realm or an administrator's password.

Writes additionally require `KEYCLOAK_ISOLATED_REALM=true`, explicit
`KEYCLOAK_DELEGATE_CLIENTS` (a subset of observed clients), and explicit
`KEYCLOAK_MANAGED_GROUP_IDS` for group mappings. The isolated-realm flag is an
operator assertion: coarse Keycloak service-account privileges must be confined to
that dedicated realm. Shared-realm writes are unsupported until fine-grained admin
permissions have been proven. Read-only access still requires suitable upstream
Keycloak view/query permissions. Service credentials never reach browser responses.

In Application SSO permissions, load the current Keycloak catalog before changing
roles, composites or group mappings. Composite direction is explicit: a parent
role includes a child role and therefore grants its permissions. Organization
ancestry alone does not grant app permissions. Cross-client/realm composites and
cycles are rejected. Existing assigned roles cannot be deleted. Changes compare
an observed fingerprint, serialize within one process, and reread upstream state;
Keycloak does not offer an atomic compare-and-swap transaction. After an ambiguous
failure reload state before retrying. Existing tokens retain their old claims until
renewal; application sessions require their own revocation policy.

All endpoints require the existing login session and profile-admin DN allowlist.
Mutation requests require same-origin `Origin` and JSON. Under `/api/v1/applications/:id`:

| Endpoint | Behavior |
| --- | --- |
| GET `keycloak-roles` or `roles` | Current role/composite/group catalog; quoted fingerprint ETag |
| POST `keycloak-role-operations` | `action`, `role`, optional `description`, `include`, `group_id`; `If-Match` from catalog |
| DELETE `integration-profile` | Deletes metadata only; profile revision ETag required |
| GET `configuration-export?adapter=generic` | Generic OIDC integration contract; no credentials |
| GET `configuration-export?adapter=grafana\|argocd` | Supported native configuration artifact and warnings |
| POST `mapping-preview` | `{"claim_values":["Developers"]}`; intended mapping preview, not access authorization |
| GET `integration-status` | Configuration and delegation capability; no fabricated application verification |
| POST `integration-verify` | Observes Keycloak catalog; does not prove claim delivery or app enforcement |

Actions: `create`, `delete`, `include_add`, `include_remove`, `group_add`,
`group_remove`. GET `/api/v1/application-profile-types` exposes the versioned
capability/export contract. The legacy mapping field `keycloak_role` represents
an exact source claim value (role or group). Grafana/ArgoCD exports require
`claim_path=groups`, `token_source=id_token`, and `enforcement=native_app`.
Grafana permits Admin/Editor/Viewer; unmatched identities are denied. ArgoCD
permits admin/readonly and leaves the default role without grants. Review and
merge native configuration through each app's normal deployment process.
Generic contracts support arbitrary applications without a fixed OSS catalog;
new native exporters implement `Profile.Export` with capability checks, escaped
values, explicit defaults, and application-level positive/negative tests.
Bearer automation, arbitrary remote adapter execution, organizational scoped
permissions and native ACL provisioning are outside this implementation.

Local end-to-end evidence: `python3 scripts/test/test-app-keycloak-local.py`
uses disposable LDAP, Keycloak 26.7.4 and Grafana containers. It verifies UI changes,
composite token claims, fresh-token revocation, conflict/privilege boundaries, and
Grafana Editor access plus unmapped-user rejection. The Grafana image is local
`grafana/grafana:latest`; the script reports its actual version rather than treating
that tag as pinned. Production configuration must pin your supported image version.
CI sets `GRAFANA_IMAGE=grafana/grafana:13.2.3` and `LDAPIUM_KC_BIND=0.0.0.0` (on Linux, Grafana
reaches Keycloak through the docker bridge, so a loopback-only publish is unreachable);
`LDAPIUM_IMAGE` selects the server image. Defaults are unchanged for local runs.

The application UI includes research-backed setup guides for Grafana, Argo CD,
Harbor, Gitea, Kubernetes, OpenBao and OAuth2 Proxy plus Custom OIDC app. Guides
are optional examples, not a closed supported-app catalog. The optional
`integration_type` profile field selects a guide; older profiles default to
`generic`. `GET /api/v1/application-profile-types` includes these guide IDs,
separately from available `export_adapters`. Only Grafana and Argo CD generate
native configuration; other guides provide a generic contract and official
instructions. The UI separates app/claim setup, live Keycloak operations and
export/verification. Exact group paths are preserved, and mapping rows are ordered
(Grafana uses first matching row). Selecting a guide changes claim/token defaults;
review retained mappings before saving. Selecting gateway clears native mappings.

Before rolling back to a build that predates `integration_type`, restore a
compatible metadata backup or remove this optional field from profiles offline;
strict older decoders reject unknown fields. Do not discard newer profile changes.
Research, acceptance and verification: [OSS UI change](../docs/changes/oidc-organization-authorization/OSS-UI.md).


Administrators can add/edit reusable integration methods in the app setup UI.
Custom `custom-*` methods define claim path, token source, enforcement, app role
choices, HTTPS documentation and ordered instructions; they generate only the
generic contract. They do not execute remote APIs or introduce native exporters.
GET `/api/v1/applications/integration-methods` lists the catalog; PUT the same
path plus `/:method` creates/updates a method with `If-Match: "0"` for creation
or its quoted revision for updates. Profile-admin session, same-origin Origin and
JSON are required. Methods are not deleted while profiles may reference them.
Back up both `APP_PROFILES_PATH` and `APP_PROFILES_PATH + ".templates.json"`;
restore them together. Private file storage supports one backend process only.

The reviewed console uses responsive navigation, named filters, keyboard tabs,
scrollable dialogs with focus return, and light/dark contrast improvements.
See [UI review evidence](../docs/changes/ui-review/CHANGE.md).

Offline native configuration preparation:

```sh
python3 scripts/integration/merge-app-oidc.py \
  --artifact exported-artifact.json --existing grafana.ini
python3 scripts/integration/merge-app-oidc.py \
  --artifact exported-artifact.json --existing grafana.ini --output grafana-merged.ini
```

`--artifact` is the complete configuration-export API response, including content,
adapter and status. For Argo CD supply existing argocd-rbac-cm ConfigMap JSON.
Validation mode reports managed keys without printing secrets. Output must be new
and differs from the source; permissions are 0600. Grafana INI comments/format are
normalized, other settings and secrets retained. Argo CD retains existing policies
and writes only policy.ldapium.<profile-id>.csv with compatible default/scopes. Each profile has a distinct composed key. Review the private result and use your
app's deployment path; no runtime changes occur automatically.

Profile deletion now retains a private revision tombstone. Recreated IDs cannot
accept old tabs' ETags even after restart. Deleted IDs count toward catalog limits;
retain tombstones in backups. Older strict readers require a pre-change compatible
backup on rollback. UI/API listing hides deleted entries.

The Groups view now paginates the fetched list with 10/20/50/100 rows, numbered
pages and first/previous/next/last controls. Search operates on the fetched list
before paging and resets to page 1. Page size changes reset likewise; a smaller
reloaded list clamps the current page. Existing LDAP response limits/truncation
remain visible: UI paging does not fetch beyond that server-side result limit.
Keyboard row editing resolves the visible group, and Enter opening a dialog does
not submit it. Regression: `e2e/groups-pagination.spec.ts` uses synthetic read-only
responses with real session login; it does not modify directory entries.

### Scheduled local / S3 / FTP / SSH backups

The **Backups** page supports manual execution and separate data/log policies:
enabled schedule, interval in minutes, keep-days, keep-count and destinations.
Changing one policy's retention does not reset the other's schedule. Scheduling
is relative to completion, survives backend restart and catches overdue work once;
there is one active job, without a missed-job backlog. This is interval scheduling,
not wall-clock cron. Existing Helm backup CronJob remains available independently;
select one owner to avoid duplicate schedules.

Opt in with absolute operator-owned paths and an explicit administrator DN list:

```sh
BACKUP_OPERATOR_CONFIG=/etc/ldapium-backup/operator.json
BACKUP_POLICY_PATH=/var/lib/ldapium-backups/policies.json
BACKUP_WORKER_PATH=/opt/ldapium/backup-tools/backup_worker.py
BACKUP_PYTHON=/usr/bin/python3
BACKUP_ADMIN_DNS=cn=admin,dc=example,dc=org
BACKUP_JOB_TIMEOUT_DATA=2h   # optional, 1m-24h; same for BACKUP_JOB_TIMEOUT_LOGS
```

Operator example: [operator.example.json](backend/backup-tools/operator.example.json).
Register destinations with rclone (`s3`, `ftp`/FTPS, `sftp`), then reference remote
names and a dedicated prefix in that file. Operator-mounted destinations remain read-only. UI-managed connections accept
write-only credentials from backup administrators; no commands or source paths
are accepted. Use `known_hosts_file` for SFTP; FTPS requires TLS;
plaintext FTP requires explicit `allow_plaintext: true`. Protect operator/rclone
config and password files and mount them read-only. S3 credentials should be scoped
to the bucket/prefix, including list/read/write/delete for verified retention.
Encryption at rest is the storage/PVC owner's responsibility; rclone obscuring
passwords is not encryption. A stable unique `instance_id` separates writers.

The original distroless image stays the default. For managed backup execution:

```sh
docker build --target backup-runtime -t ldapium-ui:backup -f ui/Dockerfile ui
```

This optional runtime includes Python, LDAP clients and rclone. Deploy one replica
with Recreate strategy, a writable private backup volume, operator/rclone Secret
mounts and read-only log file mounts. Enable Helm `ui.backups.enabled`, set `runtimeConfirmed: true` for your built image,
`existingClaim`, `existingSecret` and `adminDNs`. The Secret provides operator.json,
password/rclone config/SSH key files under /etc/ldapium-backup; the PVC is mounted at
/var/lib/ldapium-backups. Optional `logExistingClaim` mounts read-only log files at
/var/log/ldapium-backup. The chart enforces one replica/Recreate. Never mount the
live MDB into UI.
Data uses network logical LDAP export including operational UUID/CSN attributes;
config is optional but required for standalone restore. Data/config queries are
separate and are not a transactional point-in-time snapshot. The same password
file currently serves both data/config binds; provision an appropriate read-only
backup identity rather than assuming normal users can dump the whole directory.

Data and logs are compressed into separate `<root>/<kind>/<run>` directories.
Only allowlisted regular log files are archived. Policy affects backup copies,
never live log rotation. Each archive has SHA256 metadata; data also preserves
legacy manifest-*.sha256 for the existing offline restore script. Minimum one
newest verified copy is retained. Local pruning follows local verification even
if a remote transfer fails; each remote prunes only after its own verified upload.
This prevents failed remotes from growing the local archive without bound.
Remote candidate checksums are verified before they count toward retained copies;
corrupt/unowned records are excluded. Corrupt complete records require operator
cleanup. Only owned incomplete uploads/staging folders are automatically cleaned.

Remote namespace: `<prefix>/<instance_id>/<data|logs>/<run>`; pending upload marker
first, data copied and downloaded for comparison, completion marker last and
reread. Verify/prune can consume significant read bandwidth. Use an additional
storage quota/lifecycle backstop for outages/corrupt objects and transient staging.
Cancellation (and the per-kind job timeout, `BACKUP_JOB_TIMEOUT_DATA` / `BACKUP_JOB_TIMEOUT_LOGS`,
default 2h) sends SIGTERM to the whole worker process group and SIGKILL after 10 seconds. A private worker file
lock prevents overlap; HA/multiple independent writers are unsupported.

API (backup-admin session required): GET `/api/v1/backups`, PUT
`/api/v1/backups/policies` with same-origin JSON and quoted revision `If-Match`,
POST `/api/v1/backups/jobs/data|logs` with same-origin JSON content type and empty
body. Accepted execution is 202 with `job_id` and a `Location` header; read the outcome from
GET `/api/v1/backups/jobs/{id}` (list: GET `/api/v1/backups/jobs`) and cancel with POST
`/api/v1/backups/jobs/{id}/cancel`. Only one job runs at a time: a second start is 409
`backup_busy` with `active_job_id` (that names the running job, it does not prove it is
yours). Job records live in `backup-jobs.json` next to the policy file (at most 200 records /
90 days; the latest success per kind is always kept; no secrets, only a requester
fingerprint) and are safe to delete.

Operating notes: `abandoned` means the controller restarted and no worker result could be
established (the worker may still have produced a local copy, listed under `artifact`).
`worker_busy` means another worker held the lock; it is retried after 60 seconds, not after a
whole interval. After a controller restart a worker that is still running keeps its job
`running` with `orphan_suspected`; the controller polls the worker lock (5s growing to 30s)
and settles the job from the worker's result file once the lock is free. Such a job cannot be
cancelled from the API (its pid is not stored), and a stuck worker blocks new backups until
it is stopped by the operator. Accepted execution is 202; subsequent status may fail. No archive download
endpoint: raw backup attributes/password hashes never reach an HTTP response.
Health's LDAP-recorded last-backup field continues to describe legacy CronJob
backups; Backups is authoritative for this controller's job history.

Evidence: [backup change](../docs/changes/backup-policies/CHANGE.md).

Browser fixture: `LDAPIUM_UI_IMAGE=ldapium-ui:backup python3 scripts/test/test-backup-ui-local.py`
(after building the `backup-runtime` image above and the server image; `LDAPIUM_IMAGE` selects it)
starts disposable LDAP and backup-runtime UI containers with a local destination and runs
`e2e/backups.spec.ts`; CI runs it in `.github/workflows/ui-fixture-e2e.yml`.

Optional `metadata_files` include operator-allowlisted regular files (for example
application mappings and backup policies) in `metadata.tar.gz`. Register only
existing files; missing or symlink sources fail the job. Restore these separately
under operator control; the LDAP offline restore script does not apply UI metadata.
If remote delivery or retention fails after local verification, the job reports
failure and separately exposes `local_verified`, `last_local_success` and the
local run ID. Full `last_success` advances only after all requested work succeeds.
Offline restore preserves Base64-encoded non-ASCII DNs. Its config contract requires
one `dc=` data suffix and plain canonical ASCII MDB paths beneath target-data;
unsupported encoded/folded paths are rejected before clearing targets.

### Backup capacity and UI-managed connections

Backups shows the newest retained local copy size, total local retained bytes and
completed-copy count separately for data/logs. Sizes include compressed archives
and manifests, exclude staging/symlinks/other instance copies, and are actual local
file sizes; they do not estimate remote usage or free filesystem space.

Use **Remote destination settings → Add destination** for S3, FTP, FTPS or SSH/SFTP.
S3 accepts bucket, prefix, optional HTTPS S3-compatible endpoint (blank for AWS),
region, access key and secret key. FTP/FTPS/SFTP accept host, port, username and
password; FTPS uses explicit TLS with certificate verification. SFTP requires
operator-verified known_hosts public keys and rejects mismatches. Plain FTP
requires explicit acknowledgement. Private-key SSH authentication remains available
through operator-mounted rclone connections; UI-managed SSH currently uses passwords.

The administrator can edit connection settings, retain credentials by leaving their
fields blank, then select the new destination in independent data/log policies.
Save does not prove connectivity: the backup job verifies archive delivery.
Unselect and save policies before deleting a connection. Operator destinations
cannot be modified/deleted by these APIs. IDs and transport are fixed in the UI
when editing; create another entry to change transport.

PUT `/api/v1/backups/connections` and DELETE
`/api/v1/backups/connections/:id` require backup-admin session, same-origin JSON and
quoted backup revision `If-Match`. Revision/busy protections are shared with policies.
GET projects only public fields and a credential-presence flag. Credential inputs
never appear in responses/audit logs; worker receives them over stdin, builds a
private transient rclone config and removes it after execution. The private 0600
policy persistence file includes managed secrets. It is not encrypted by the app:
protect/encrypt the volume, use HTTPS for browser access and restrict administrator
accounts/network egress. Policy metadata backups therefore also contain protected
connection settings. A forcibly killed worker may leave a private transient folder;
operator cleanup can remove `.connections-*` only when no worker is running.
