# Authentication provider and fallback policy

ldapium's management UI supports two ways to authenticate: a direct LDAP
bind, or OpenID Connect (OIDC) single sign-on through Keycloak. This
document defines how a provider is selected, what happens when it fails,
what gets audited, and where the protocol boundary sits — backed by what
the code actually does, not by aspirational behavior.

## 1. Provider priority and activation

There is no runtime provider negotiation and no priority order between
LDAP and SSO. Exactly one is active for the lifetime of a running process,
selected once at startup by `SSO_ENABLED` (`ui/backend/internal/config/config.go`):

- **LDAP mode (default)**: active when `SSO_ENABLED` is `false` or unset.
  `POST /api/login` binds directly to the directory with the submitted
  credentials (`ui/backend/internal/httpapi/auth_handlers.go`, `handleLogin`).
  A successful bind's connection is kept server-side for the rest of the
  session, so every later directory operation runs under that user's own
  LDAP ACLs.
- **SSO mode**: active when `SSO_ENABLED` is `true`. `handleLogin` rejects
  every request with `404 Not Found` before it can reach the directory
  (`auth_handlers.go:20-25`) — the password form is not merely hidden in
  the UI, the endpoint itself refuses the request. Directory operations run
  instead under a dedicated `LDAP_SERVICE_ACCOUNT_DN` bound after the OIDC
  callback succeeds (`ui/backend/internal/httpapi/sso.go`).
- **`GET /api/auth/config`** reports which mode is active (`{"mode":"ldap"}`
  or `{"mode":"sso"}`, `auth_handlers.go`, `handleAuthConfig`) so the UI
  renders the right login form; it never touches LDAP itself, which is why
  it — not `/api/health/ldap` — is what the pod's `readinessProbe` targets.

Because only one authenticator is ever constructed (`httpapi.New` only
calls `newOIDCAuthenticator` when `cfg.SSO.Enabled`, `server.go:44-52`),
running both providers side by side is not a supported configuration to
begin with — there is nothing to fall back *to* at runtime even if the
policy below allowed it.

## 2. Failure behavior: no automatic fallback

**Whichever provider `SSO_ENABLED` selects at startup is the only one
available until the process is reconfigured and restarted.** A failure in
that provider does not fail over to the other one, at startup or at
runtime:

- **SSO startup failure**: `httpapi.New` discovers the OIDC issuer with a
  10-second timeout (`server.go:44-52`); a bad or unreachable
  `SSO_ISSUER_URL` returns an error that `main.go` treats as fatal
  (`log.Fatalf("initialize HTTP server: %v", err)`, `cmd/server/main.go:57-59`).
  The process exits and the pod enters `CrashLoopBackOff` — it does not
  start up in LDAP mode instead.
- **SSO runtime failure**: a failed token exchange, an unverifiable ID
  token, an unreachable JWKS endpoint, or a missing `SSO_ADMIN_ROLE`
  redirects the browser to `/login?sso_error=<reason>` via
  `redirectSSOFailure` (`sso.go:107-181`; reason values are enumerated in
  §3 below). There is no code path from `handleSSOCallback` back to a
  password form.
- **LDAP outage in LDAP mode**: `POST /api/login` returns `500` through the
  same redaction `respondErr` applies to every unmapped internal error
  (`ui/backend/internal/httpapi/errors.go`) — no host, port, or connection
  detail leaks to the client. `GET /api/health/ldap` exists precisely for
  this case: an unauthenticated, LDAP-only reachability probe
  (`{"reachable": true|false}`, `handleLDAPHealth`) for whatever external
  system is watching provider health, deliberately separate from the pod's
  own `readinessProbe`.

**Why no fallback**: silently dropping from SSO to an LDAP password prompt
after an SSO failure would be an authentication-strength regression, not a
resilience feature. It would let an attacker — or simply a misconfigured
identity provider — bypass every control the SSO path exists to enforce:
Keycloak's MFA, conditional access policies, and the mandatory
`SSO_ADMIN_ROLE` check (`sso.go`, `hasRequiredRole`). A directory operator
who deploys SSO specifically to require those controls should get a loud
failure (`CrashLoopBackOff`, an error redirect), not a quiet downgrade to
weaker authentication.

## 3. Audit trail and provider identification

Two independent audit layers already existed before this document, and a
third — an explicit per-attempt log line — closes the gap between them:

1. **Directory bind audit (`cn=accesslog`)**: when OpenLDAP access logging
   is enabled, every bind is recorded by actor DN. In LDAP mode the actor is
   the authenticating user; in SSO mode it is always
   `LDAP_SERVICE_ACCOUNT_DN` — the directory's own log cannot distinguish
   *which* Keycloak user was behind a given SSO session, only that the
   service account acted.
2. **HTTP access log**: Echo's request logger (`server.go:69-71`) records
   method, path, status, and request ID for every request, including
   `POST /api/login` and `GET /api/sso/callback` — but carries no explicit
   provider field, and by design excludes the query string (`${path}`, not
   `${uri}`) so an OIDC authorization code or `state` value never lands in
   a log line.
3. **Structured `auth` event line** (added for this issue): every return
   path out of `handleLogin` and `handleSSOCallback` — success, a rejected
   bind, a rate-limited request, a malformed request body, missing
   credentials, and every SSO failure reason — calls `logAuthEvent`
   (`ui/backend/internal/httpapi/audit_log.go`), emitting one JSON line via
   the same `log` sink `errors.go` already uses:

   ```json
   {"event":"auth","provider":"ldap","result":"failure","request_id":"...","subject":"jdoe","reason":"invalid_credentials"}
   ```

   Fields: `event` is always `"auth"`; `provider` is `"ldap"` or `"oidc"`;
   `result` is `"success"`, `"failure"`, or `"rate_limited"`; `request_id`
   matches the access-log line for the same request
   (`echo.HeaderXRequestID`), so the two can be correlated; `subject` is a
   uid or DN and `reason` a short failure code, both omitted entirely
   (never emitted as `""`) when not yet known — for example a
   `rate_limited` outcome is logged before the request body is even
   parsed. `subject_redacted` is `true` only when an identity *was*
   submitted but withheld from the line (see below); it is otherwise
   omitted, so a reader can tell "nothing was submitted" apart from
   "something was submitted and hidden".

   **`subject` and `reason` never carry a password, bearer token, or OIDC
   authorization code.** `POST /api/login`'s `identity` field is free-form
   client input — `dial.go`'s `Bind` tries anything that doesn't parse as a
   DN as a bare uid, with no charset check of its own — so a user who
   pastes a password or token into that field must not have it echoed back
   into the log on the resulting failed bind. `sanitizeLoginSubject`
   (`audit_log.go`) gates this: the submitted identity is only logged
   as-is when it is syntactically a uid (the same charset
   `internal/validate.UID` enforces for the create-user form) or a real DN
   (parses with go-ldap's `ParseDN`, via `ldapclient.LooksLikeDN` — the
   same classifier `dial.go` itself uses to decide whether to bind the
   identity directly or resolve it as a uid first); anything else is
   logged as `subject=""`, `subject_redacted=true`. This is a heuristic,
   not a guarantee — a short secret made only of letters, digits, and
   hyphens is syntactically indistinguishable from a real uid and is still
   logged — but a value using characters outside that charset (spaces,
   `@`, `!`, and most password/token alphabets) never is. An LDAP session's
   `subject` is always the DN the directory itself authenticated
   (`bound.WhoAmI()` / `sess.DN`), never the raw submitted identity, so
   success and post-bind failures need no such gate; an SSO `subject` is
   always a claim from an already-signature-verified ID token or a
   directory-resolved DN, not free-form form input.

   `reason` is always one of a fixed set of constants:
   `malformed_request`, `missing_credentials`, `invalid_credentials`,
   `bind_error`, `session_create_error` (LDAP); `access_denied`,
   `not_authorized`, `authentication_failed`,
   `directory_account_not_found`, `invalid_state`, `invalid_origin` (SSO).
   The field-building and redaction logic lives in the pure
   `buildAuthEvent` and `sanitizeLoginSubject` helpers, unit tested
   independently of any logger or LDAP connection (`audit_log_test.go`),
   plus a handler-level test that captures actual log output and asserts a
   bogus identity never appears in it (`auth_audit_handlers_test.go`).

## 4. Fallback loop and retry-storm prevention

Because cross-provider fallback is prohibited outright (§2), an SSO→LDAP→SSO
oscillation loop is architecturally impossible — there is only ever one
provider registered per process, and nothing in either code path attempts
to reach the other.

What remains is protecting each provider against a client hammering it:

- **LDAP**: `POST /api/login` is throttled by an in-memory sliding-window
  limiter keyed on the caller's IP (`ui/backend/internal/httpapi/login_limiter.go`;
  `UI_LOGIN_FAILURE_LIMIT`, default 10, per `UI_LOGIN_FAILURE_WINDOW`,
  default 1 minute). Exceeding it returns `429` with `Retry-After`. Only a
  rejected bind (`domain.ErrInvalidCredentials`) counts against the budget
  — a `5xx` from an unreachable directory does not, or an outage would lock
  every client out for a full window after the directory recovered
  (`auth_handlers.go:48-57`, decision `D1`).
- **OIDC**: pending logins live in a capped, TTL'd in-memory table
  (`oidcStateStore`, `sso.go:25-28,332-402`; `maxOIDCStates = 10_000`,
  `oidcStateTTL = 10 * time.Minute`). State, PKCE verifier, nonce, and the
  browser-binding cookie are all single-use — `Consume` deletes the entry
  on first use (`sso.go:429-447`) — so a replayed or retried callback fails
  closed rather than looping. Reaching the table's cap fails new logins
  with `500` instead of growing unbounded.
- Every failure — LDAP or OIDC — resolves to one terminal response
  (`401`/`429`/`500` for LDAP, a `/login?sso_error=...` redirect for SSO).
  Nothing in either path automatically retries or redirects a client back
  into the same flow.

## 5. Protocol boundary: CAS and SAML are not native

ldapium implements OIDC authorization code flow with PKCE and nothing else.
There is no CAS ticket-validation route and no SAML metadata endpoint or
assertion consumer anywhere in `ui/backend`. Enterprise CAS or SAML
identity providers are supported **only** as an external adapter boundary:
configure them as identity brokers inside Keycloak. Keycloak performs the
CAS/SAML federation, maps the broker's attributes into
`SSO_ADMIN_ROLE`-bearing token claims, and issues ldapium a standard OIDC
ID token — the same token `sso.go` already verifies signature, issuer,
audience, and expiry on. Adding native CAS/SAML support to this codebase is
out of scope; the Keycloak boundary is the intended integration point.

## See also

- `ui/README.md` — operator-facing configuration for both modes
  (`SSO_ENABLED` and related environment variables).
- `ui/backend/internal/httpapi/errors.go` — the redaction `respondErr`
  applies to every unmapped internal error, referenced in §2 and §3.
