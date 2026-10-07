# Changelog

Notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) — while the project is on 0.x, minor
releases may break compatibility, and the release notes will say so when they do.

A single git tag `vX.Y.Z` publishes the chart and both images under the same
version. `appVersion` is separate: it is the OpenLDAP release being compiled.

## [Unreleased]

### Web UI

- Users and Groups lists page through the cursor API (`limit`/`cursor`/`q`, #253).
  Search is now server-side and matches only `uid`/`cn`/`mail`/`displayName` (users)
  and `cn`/`description` (groups); the old client-side search over `department`,
  `organization` and `organizationalUnit` is gone (accepted in `D215-7`). The list no
  longer shows a total count.

### API

- **Compatibility change (`UI_TRUSTED_PROXIES`):** with an explicit CIDR list, only
  the listed ranges are now trusted for `X-Forwarded-For`. Echo's implicit trust of
  loopback, link-local and private networks used to stay on next to the list, so a
  private peer outside the list could forge `X-Forwarded-For` and take a fresh
  login-limiter/machine-limiter budget per request. The extractor is used by the login
  limiter and the machine limiter only (the machine audit line carries no IP). If you set a CIDR list and relied on the implicit
  private-network trust, list every proxy CIDR explicitly (`private` and `none`
  are unchanged). Related to #214.
- Machine bearer limits: the per-IP reservation now outlives the longest possible
  request (authentication deadline 10 s + `MACHINE_REQUEST_TIMEOUT` + 1 s) and the
  authentication phase has an explicit 10 s deadline that fails closed with `503`
  (change package decision D31).
- The login limiter's per-source state is now bounded (#270): hard cap
  `UI_LOGIN_LIMITER_MAX_ENTRIES` (default 10000), IPv6 clients grouped per /64, an
  amortized expiry sweep, and graded eviction (expired
  first, then the non-blocked source with the fewest stored failures — counts as of
  each source's last update, not time-decayed — oldest on ties; a blocked source is
  never evicted; new sources get the blocked-source `429` only
  when all slots are blocked, which costs cap x limit failed binds). Thresholds,
  window, `Retry-After` and response bodies are unchanged for normal traffic.
- Machine bearer authentication, unit 1 of the staged rollout (#214, change package
  `machine-principal-auth`, **default off**): config parsing and startup validation of
  the `MACHINE_*` environment, a Keycloak service-account token verifier, the JWKS key
  source (refresh budget, single flight, bounded stale use, discovery retry), the pure
  `selectAuth` precedence rules, and the static operation-to-scope allowlist with a
  deny-by-default guard. Additive only: with `MACHINE_AUTH_ENABLED` unset no request,
  response or route changes. OpenAPI gains `securitySchemes.machineBearer` plus
  `security`/`x-machine-scope` on exactly the eight allowed GET operations, and three
  new stable error codes `token_invalid`, `token_expired`, `scope_denied`.
  **Enabling it did not expose any data in unit 1:** an authorized machine request
  ended in a fixed `503` until unit 2 below.
- Machine bearer authentication, unit 2 (#214, **default off**): the machine
  execution identity and its boundaries. An authorized machine request now runs as
  the one dedicated LDAP account `MACHINE_LDAP_BIND_DN`, bound per request and closed
  when the request ends (also on panic, client abort and timeout); the global LDAP
  slot (`MACHINE_MAX_CONCURRENCY`) is taken, non-blocking, before the bind, one
  `MACHINE_REQUEST_TIMEOUT` deadline bounds dial, bind and every search, and a bind
  failure is a `503` with no fallback to another identity. Machine-only boundaries:
  `getEntry`/`listTree` refuse any DN outside `LDAP_BASE_DN` (so cn=accesslog,
  cn=config and cn=Monitor) with `403 scope_denied` before any LDAP connection is
  opened, `listTree` refuses a listing of more than 1000 children with `422
  size_limit_exceeded`, and `getMonitor` reads the accesslog only with the `audit.read`
  scope. List cursors of a machine principal are bound to issuer plus client id (a
  refreshed token keeps paging; cross-client and human/machine replay is `400
  cursor_invalid`). Every request that carries an `Authorization` header while the
  feature is on is exactly one `event=machine_access` log line (see
  `docs/audit-event-schema.md`). The Go interface `Client.MonitorStats` gained an
  `includeAccessLog` parameter (human sessions pass `true`; unchanged behaviour).
  With `MACHINE_AUTH_ENABLED` unset nothing changes. Still later units: the
  operator ACL guide, the rate/concurrency limiters, Helm values and the Keycloak e2e.
- Machine bearer authentication, unit 3 (#214, documentation and proof only, **default
  off**): the operator guide `docs/machine-ldap-account.md` for the dedicated read-only
  LDAP account (strong password, the final `olcAccess` LDIF with the machine rules at
  `{0}`-`{2}` ahead of every existing allow, apply/verify/rotate/rollback commands, the
  derived secret-attribute list, per-node and replication caveats), and the live proof
  `scripts/test/test-machine-acl-readonly-live.py` run in `api-credentials-e2e`: three
  freshly initialised slapd containers (anonymous read base unset, set, operator leading
  allow), `olcAccess` read back in order, the account reads inside its subtree only, never
  sees secrets, cannot write or change its own password, other identities are unchanged,
  and the documented rollback restores the original `olcAccess` byte for byte; three
  deliberately broken variants (including each secret attribute dropped from the deny on its
  own, every one of them seeded with a recognizable value) must fail their expected checks. The committed LDIF's rule `{0}` now also covers
  `pwdHistory`, `pKCS8PrivateKey`, `userPKCS12`, `oathSecret`, `oathEncKey` and
  `oathTokenPIN`. No image, chart or backend change. Known and documented: ACLs are per
  node, the default policy locks the account after 5 bad binds, and the machine rules
  combine with `LDAP_REPLICATION_IDENTITY=prepare` only in the defined order (identity
  rule `{0}`, machine rules `{1}`-`{3}`; D30 / T-034, #277).
- Machine bearer authentication, unit 4 (#214, **default off**): the limits and the
  Helm values. Order per request: `Authorization` grammar, then a per-source **IP
  failure throttle before any signature or JWKS work** (10 failures per sliding 60 s,
  inclusive boundary; in-flight requests hold reservations that are released exactly
  once on every exit path and expire after `MACHINE_REQUEST_TIMEOUT`; `429
  machine_rate_limited` with an exact `Retry-After`), a global authentication
  concurrency cap (`503` + `Retry-After: 1`), verification, then a token bucket and
  concurrency cap per **verified** client (unverified claims never create or drain
  state), then the global LDAP slot. State is bounded: the IP table reuses the bounded
  login-limiter table (`MACHINE_IP_LIMITER_MAX`), per-client state is capped by the
  allowlist. New stable error code `machine_rate_limited` (429, retryable); the audit
  line uses `reason=rate`. Helm gains `ui.machineAuth.*` (off by default; the
  rendered chart is byte-identical when disabled). Limits are per replica.
- Machine bearer authentication, unit 5b (#214, documentation only, **default off**;
  release notes for the feature as a whole). **What it is:** an opt-in way for a
  Keycloak service client (`client_credentials` access token) to call eight read-only
  `GET` operations (`listUsers`, `listGroups`, `listTree`, `getEntry`,
  `listPasswordPolicies`, `getMonitor`, and the opt-in `listAuditActions`,
  `getServerSettings`) as one dedicated read-only LDAP account. Writes, passwords,
  backups, application profiles, `entry/move` and `getMe` are never available to a
  machine. **Compatibility:** with `MACHINE_AUTH_ENABLED` unset (the default, Helm
  `ui.machineAuth.enabled=false`) nothing changes: no `MACHINE_*` variable is read, the
  chart renders byte-identical manifests, and `Authorization` is ignored. Existing
  paths, cookies, sessions and the existing OpenAPI operations are unchanged; the
  OpenAPI additions (`securitySchemes.machineBearer`, `x-machine-scope`) and the four
  new stable error codes (`token_invalid`, `token_expired`, `scope_denied`,
  `machine_rate_limited`) are additive. **Turning it on needs:** the Keycloak client
  settings in `docs/machine-keycloak-client.md` (audience mapper, lightweight access
  token off), the LDAP account and ACL on every LDAP node
  (`docs/machine-ldap-account.md`), and `UI_TRUSTED_PROXIES` set to CIDRs or `none`.
  **Rollback:** `MACHINE_AUTH_ENABLED=false` (or `ui.machineAuth.enabled=false`) and
  replace every replica; there is no persisted state. **Emergency revocation:** remove
  the client from `MACHINE_ALLOWED_CLIENTS` or disable the feature, replace **all**
  replicas and confirm no old pod remains, then disable the Keycloak client.
  Disabling the Keycloak client alone does **not** revoke tokens already issued; they
  stay valid until they expire (at most `MACHINE_TOKEN_MAX_TTL` plus the clock skew).
  Procedure: `docs/machine-auth-operations.md`. **Known limits:** requests the Go HTTP
  server rejects before any handler (431, malformed request line, header timeout,
  TLS/HTTP/2 pre-handler errors) are not audited and leave no log without an ingress
  access log (D25); limits are per replica; the machine ACL combines with
  `LDAP_REPLICATION_IDENTITY=prepare` in the defined order (D30, T-034, #277). **Verification:** the live end-to-end runs against a real Keycloak (both UI modes), the Keycloak client settings checks, the JWKS rotation and flood checks and the emergency revocation drill run in `machine-keycloak-e2e.yml` and gate releases (see the unit 5a note below). **Not verified:** installing the chart with machine auth on a cluster, a real ingress in front of `X-Forwarded-For`, and the ACL on more than one LDAP node (#284).
- Self-service change password with a current password the directory does not
  accept is now `400` with the new stable code `current_password_rejected` and a
  fixed text (#264, `D264-1`..`D264-3`); it used to be `500 internal`. The cause
  is ambiguous by design (slapd answers LDAP result 53 both when the current
  password does not verify and when current-password verification is not
  enabled), so the text does not say the password is wrong. It is 400 like the other
  input and policy rejections, not 401/403. Only the slapd diagnostic
  `unwilling to verify old password` on a request that carries `oldPassword` maps
  to it; result 53 for any other reason (for example `operation restricted` on a
  read-only database), result 53 without `oldPassword` and every other
  unclassified error stay a redacted `500 internal`. If a future slapd rewords
  that diagnostic, this case degrades to 500, never to a wrong 400. The web UI
  shows its translated "ambiguous current password" message for this code.
  Rollback: revert the commit; clients that only read `error` keep working
  either way and older clients just see the text.
- Optional `Idempotency-Key` on the core user/group writes, entry move and backup
  start (change package `api-conditional-writes`, part B, #216). A retry of the
  same request replays the first result (`Idempotent-Replayed: true`) and writes
  nothing again; a different request under the same key is 422
  `idempotency_key_reused`, one in flight is 409 `idempotency_key_conflict`, an
  unknown result is 409 `idempotency_outcome_unknown`. New codes
  `idempotency_key_conflict`, `idempotency_key_reused`,
  `idempotency_outcome_unknown`, `idempotency_capacity` and
  `idempotency_unsupported`. Off by default (`UI_IDEMPOTENCY_ENABLED`, chart
  `ui.idempotency.enabled`); records are in memory and lost on restart, so the
  chart enables it for a single replica only. Backup start keys are stored in the
  durable job record (fingerprint and `key_id` only) and survive restarts; they
  need `UI_IDEMPOTENCY_KEY_FILE`, which the chart sets when backups are enabled.
  `GET /api/server-settings` gains `idempotencyEnabled`.
- Every `/api` error is now one JSON envelope
  `{"error", "message", "code", "requestId", "retryable"}` (change package
  `docs/changes/api-error-envelope`, #218). `error` keeps its text and
  `message` is an identical, deprecated alias, so existing clients keep
  working; new keys are `code` (a closed, append-only set — see
  `docs/api.md`), `requestId` (= `X-Request-Id`) and `retryable`. Bodies that
  used to be `{"message"}` only (sessions, validation, profiles, backups,
  Keycloak, login 429) and router 404/405 now carry all five keys; 5xx
  responses carry a fixed per-code text instead of a handler-chosen one (for
  example `could not save application profile` is now `internal error`; the
  cause is in the server log under the same `requestId`). 429 and retryable
  503 responses carry `Retry-After`. OpenAPI now has one `Error` schema and
  shared error responses.
- 4xx messages no longer carry text derived from LDAP diagnostics, which can
  include DNs. They are replaced by the code's fixed text (for example
  `invalid input`) and the original is logged. Known password-policy texts
  from `ppolicy`/`ppm` still reach the change-password screen; ppm's
  `Password for dn="…"` prefix is dropped, so that screen now reads
  `Password does not pass required number of strength checks (1 of 3)`.
- Rollback: additive for clients that read `error` or `message`; revert the
  commits to restore the old bodies. No configuration, chart or image change.

- User and group writes can now be conditional (opt-in, issue #216 part A).
  List items carry `etag` and `GET /api/entry` an `ETag` header (the entry's
  `entryCSN`); `If-Match` on `PUT`/`PATCH`/`DELETE`, lock/unlock, group member
  add/remove and entry move is enforced by slapd inside the write (RFC 4528
  assertion control), a stale tag is 412 `revision_conflict` with nothing
  written. Requests without the header behave as before. New
  `PATCH /api/users` and `PATCH /api/groups` (JSON Merge Patch) keep fields
  they do not mention; `PUT` is unchanged and still erases omitted optional
  fields. A user creation whose password step fails now removes the entry
  again when it provably is the request's own (the error says the user was
  not created) and otherwise answers 500 `partial_failure` (the one envelope
  that also carries `state` and `dn`) with the entry to check. The
  `ETag` also changes on directory bookkeeping writes (password-policy
  failure records), which can cause a harmless 412 and a re-read, and the
  condition is node-local on multi-provider replication. The ETag only
  reflects attributes written directly to the entry: `memberOf` and refint's
  removal of a deleted member from a group do not change it. Before setting
  the password the new entry is verified as created by this request and
  untouched; otherwise the password is not set and nothing is deleted
  (`state: identity_changed`), and a compensating delete whose outcome is
  not observed is `state: unknown`. Idempotency keys
  are not part of this change (see the Idempotency-Key entry above).

- **Breaking for some non-browser clients:** every state-changing `/api`
  request (`POST`/`PUT`/`PATCH`/`DELETE`, including login and logout) that
  carries an `Origin` header is now refused with 403 `origin_mismatch` before
  any handler runs unless that `Origin` is the server's own origin (change
  package `api-error-envelope`, D218-16, #218). An empty, `null` or repeated
  `Origin` is refused too. Requests without an `Origin` header (curl, scripts,
  services) are unaffected, as are `GET`/`HEAD`/`OPTIONS`. Clients whose HTTP
  library adds an `Origin` header on its own must stop sending it. Behind a
  reverse proxy the server compares against its own scheme (from
  `X-Forwarded-Proto` and friends) and the request `Host`; a proxy that
  rewrites `Host` makes ordinary browser writes 403, one that keeps `Host` and
  forwards the scheme is fine. There is no switch to turn the gate off;
  rollback is reverting the change.
- Opt-in `/metrics` listener (#218): set `METRICS_ADDR` (`host:port`, chart
  `ui.metrics.enabled`) to serve the `ldapium_ui_*` process metrics (request
  rate and latency, API errors per `code`, login failures, directory calls,
  active sessions) on a second port. Unset by default: no listener and no
  collection. The port must differ from the public one, has no authentication
  and answers only `GET /metrics`. On the public port `GET /metrics` is now a
  404 error envelope; the single-page-app fallback used to answer it with
  `index.html`. Adds the Go dependency `github.com/prometheus/client_golang`.
  Remove `METRICS_ADDR` to turn it off again.
- Opt-in CORS for reads (#218): `CORS_ALLOWED_ORIGINS` (comma-separated exact
  `scheme://host[:port]`, chart `ui.cors.allowedOrigins`) lets the listed
  origins read `GET`/`HEAD` responses with credentials and answers their
  preflight for `GET, HEAD, OPTIONS` only. Off by default, in which case no
  `Access-Control-*` header is sent; when on, `Vary: Origin` is on every
  response. It never opens a write path: the Origin gate above ignores the
  list, and the session cookie stays `SameSite=Lax`. The OpenAPI description
  and `llms.txt` no longer claim unconditionally that there are no CORS
  headers.
- Compatibility of the error envelope's `message`: it stays a copy of `error`
  for the whole of `/api/v1`. Removing it needs a separate change package and
  at least one release after the UI stopped reading it (D218-4); new clients
  should read `error`.
- Cursor pagination for `GET /api/users` and `GET /api/groups` (change package
  `api-cursor-pagination`, #215). Sending any of `limit` (1-200, default 50),
  `cursor`, `q` or `sort` selects cursor mode, which walks a directory past the
  5000-entry cap in a fixed order; the response gains `hasMore` and
  `nextCursor` (continue while `hasMore` is true, a page can be short or empty
  while it is). Without those parameters the response is byte-for-byte what it
  was. Cursors are opaque, bound to the login session, the resource and `q`,
  and a re-login invalidates them. New codes: 400 `cursor_invalid`, 422
  `size_limit_exceeded` and `scan_limit_exceeded`, 503 `scan_timeout`
  (retryable, with `Retry-After`). Each page costs a scan of the candidates
  (100000 per request, 30 s deadline); a non-root identity needs read access
  to `entryUUID` on every listed entry. Items carry the same `etag` as in the
  legacy list. See `docs/api.md`. Rollback: additive, revert the commits; no
  stored state. The web UI keeps its client-side paging.
- Backup jobs (change package `backup-job-ids`, #217). `POST
  /api/v1/backups/jobs/{kind}` now answers 202 with `job_id` and a `Location`
  header (the body still has `kind` and `status`). New endpoints:
  `GET /api/v1/backups/jobs`, `GET /api/v1/backups/jobs/{id}` and
  `POST /api/v1/backups/jobs/{id}/cancel`. Compatibility changes:
  `states[kind].status` can now be `cancelled`, so clients that treat it as a
  closed set need updating (job records add `abandoned`, for a run whose
  result could not be established after a restart); the 409 `backup_busy`
  body gains `active_job_id` and `active_kind`; a failure to record a start or
  cancel request is now 503 `persistence_unavailable` (nothing started, no
  signal sent) where it used to be a 422 that also covered other failures,
  which stay 422 `validation_failed`; the `backup_started` log line carries
  `actor_fp` (a one-way fingerprint) instead of `actor` (the DN). New
  `BACKUP_JOB_TIMEOUT_DATA`/`BACKUP_JOB_TIMEOUT_LOGS` (1m-24h, default 2h, chart
  `ui.backups.jobTimeout`) bound a run; cancel and deadline send SIGTERM to the
  worker's process group and SIGKILL after 10 s. Job records are kept in
  `backup-jobs.json` next to the policy file (200 records or 90 days) and the
  worker leaves `<root>/.results/<job_id>.json` (0600) per run. The worker
  ships in the UI image, so the image must be rebuilt and deployed for these to
  work. Rollback: an older version never reads `backup-jobs.json` or
  `.results/`, so both can stay or be deleted; the older version simply shows
  no job history.

### Images

- `LDAP_REPLICATION_IDENTITY` (`admin` default / `prepare` / `dedicated`), unit 1
  of the staged replication-identity change (#229, `docs/changes/replication-identity`,
  T-010). Only `admin` is effective and it changes nothing (`cn=config` and
  `olcSyncrepl` byte-identical). Any other value is validated and then (until
  unit 2 below made `prepare` effective) the
  container refuses to start ("not implemented in this image yet"): an invalid
  value, a non-admin mode without `LDAP_REPLICATION_ENABLED`, `LDAP_ADMIN_DN`
  equal to `cn=replicator,<root>`, `prepare` with an explicit replication
  password, and `dedicated` with a missing or weak replication password (non-printable-ASCII
  or non-ASCII characters, length below 32, fewer than 10 distinct characters, or equal to the admin password;
  a hygiene check, not proof of randomness) are refused with fixed messages.
  Do not set it to anything but `admin` until later units ship.
- `LDAP_REPLICATION_IDENTITY=prepare`, unit 2 of the same change (#229, T-011):
  installs the replication identity's read-only ACL as the FIRST `olcAccess` rule
  (`{0}to * by dn.exact="cn=replicator,<root>" ssf=128 read by dn.exact=... none
  by * break`; slapd renumbers the other rules, so everyone else's rights are
  unchanged) and an `olcLimits` rule (`size=unlimited time=unlimited`) with one
  offline `slapmodify -n 0`, verified by reading `cn=config` back; a second start
  is a no-op. It never creates the identity entry and replication still binds as
  the admin DN. It starts only when the node holds no entry at the reserved DN or
  the rule is already stored, and it refuses (fixed messages, volume untouched):
  an existing entry without the rule, stored `olcAuthzRegexp`/`olcAuthIDRewrite`,
  `olcAuthzPolicy` other than `none`, `olcTLSVerifyClient` other than `never`
  (so `prepare` and `LDAP_TLS_MUTUAL_AUTH` do not combine), any entry with
  `authzTo`/`authzFrom`, a stored `olcRootDN` (any database) or replication bind
  DN equal to the reserved DN, a root DN with quotes/backslashes/non-ASCII, and a
  serverID-1 start on a fresh volume. DNs are compared as slapd normalizes them
  (`slapdn -N`: case, spaces, hex escapes, quoting, multivalued RDN order), and a
  DN that cannot be parsed is refused. The identity's `olcLimits` rule is always
  placed FIRST (limits are first-match) and any other stored rule for the identity
  is replaced, so an earlier `size=1` rule cannot cap it.
  `admin` stays byte-identical; `dedicated` was still refused at this unit
  (unit 3 below). Rollback: an older image or `admin` leaves the rule in place,
  which is harmless while no entry exists at the reserved DN.
- `LDAP_REPLICATION_IDENTITY=dedicated`, unit 3 of the same change (#229, T-012):
  syncrepl binds as `cn=replicator,<root>` (password from
  `LDAP_REPLICATION_PASSWORD(_FILE)`) with `tls_reqcert=demand` and
  `tls_cacert=$LDAP_TLS_CA_FILE`, and EVERY node is consumer-only, serverID 1
  included: no base DIT is created, no peer is probed or waited for, so a wiped
  node, a wrong password or a missing peer leaves the node empty (consumer
  `rc 49` / retry) instead of minting a second tree. It installs the unit-2 ACL
  and shares its refusals. New fixed-message refusals before anything is written:
  `LDAP_TLS_ENABLED` off, no readable `LDAP_TLS_CA_FILE`, a peer list that is not exactly
  `ldaps://<host>[:<port>]` entries (strict grammar: no whitespace, userinfo, path or
  option text, so a smuggled `provider=ldap://...` cannot send the identity's bind in
  clear text; re-checked before `olcSyncrepl` is rendered and read back after), a
  password with a quote or backslash, a retry list or interval outside a strict
  grammar slapd can always load (`retry=+` used to store a config that no offline
  tool could read; a `dedicated` start now removes such an unreadable stored
  `olcSyncrepl` and re-renders it from the corrected environment, only after every
  stored-config refusal has passed (checks run on a throwaway copy) and with a
  crash-safe atomic replace of an already verified file (no clear-text rollback copy is
  ever made); the kept backup is structure only (values withheld, also base64 and
  folded ones; leftovers of a crash are deleted by the next start). Rewriting the config
  cannot erase the old file's disk blocks: rotate the admin password after the switch if
  the old olcSyncrepl held it and the volume may be copied, and encrypt it at rest; the read-back
  check is quote-aware, so a password containing `provider=` starts normally), a `_FILE` secret that is
  read once (never twice, never substituted by the admin password),
  `LDAP_TLS_MUTUAL_AUTH`, a custom `LDAP_REPLICATION_BIND_DN`; stored-config
  refusals (`olcAuthzRegexp`, `olcAuthIDRewrite`, `olcAuthzPolicy`,
  `olcTLSVerifyClient`, `authzTo`/`authzFrom`, rootDN = reserved DN, existing
  entry without the ACL) leave the volume untouched. `admin` and `prepare` stay
  byte-identical. Not yet a supported mode: the identity entry is created by an
  administrator by hand (the `ensure`/`rotate`/`retire` commands, restore.sh
  total-loss, Kubernetes recovery, credential rotation, the checks and the chart
  are later units). A new cluster cannot start in `dedicated`; migrate
  `admin` -> `prepare` -> entry -> `dedicated`. Rollback: restart the node in
  `admin` (re-renders `olcSyncrepl` with the admin DN); `prepare` refuses to start
  on a volume that still stores the identity as its syncrepl bind DN.
- `LDAP_PAGED_TOTAL_LIMIT` (#215), opt-in: lifts the total of a paged search
  for authenticated non-root identities, which `LDAP_SIZE_LIMIT` otherwise caps
  at 10000 however small the pages are (the admin DN is already exempt). Unset
  leaves `cn=config` alone; a number up to 2147483647 or `unlimited` converges
  to one `olcLimits: users size.prtotal=<value>` rule; `off` removes it. It
  weakens `LDAP_SIZE_LIMIT` as a bulk-dump backstop, so leave it unset unless an
  API client must enumerate more than 10000 entries without the admin DN.
  Rollback: set `off` and restart once before moving to an image that predates
  the setting; the rule lives in `cn=config` and an older image would not
  remove it.

### Helm chart

- New values, all off or empty by default: `ui.metrics.enabled` with
  `ui.metrics.port` (9331), `ui.metrics.networkPolicy.from` (required once
  metrics are on; an empty list fails the render) and
  `ui.metrics.serviceMonitor.enabled`/`ui.metrics.podMonitor.enabled` (#218);
  `ui.networkPolicy.httpFrom`; `ui.cors.allowedOrigins` (#218);
  `ldap.limits.pagedTotal` (#215); `ui.backups.jobTimeout.data`/`.logs` (#217).
  Enabling `ui.metrics.enabled` adds a NetworkPolicy that selects the UI pods,
  which makes them default-deny for ingress: the HTTP port stays open to every
  source unless `ui.networkPolicy.httpFrom` narrows it. The metrics port is
  exposed only by a separate `<release>-ldapium-ui-metrics` Service, never by
  the public UI Service.

### CI

- Heavy E2E jobs (anything that builds the OpenLDAP server image and/or
  creates a kind cluster) now share one of three job-level concurrency
  lanes (`heavy-e2e-lane-a`/`b`/`c`, keyed per PR/commit) across
  `e2e.yml`, `backup-restore.yml`, `keycloak-federation-e2e.yml`,
  `metrics-e2e.yml`'s `metrics` job, `replication-chaos-e2e.yml`,
  `security-e2e.yml`, `sssd-e2e.yml`, `ui-e2e.yml`, `upgrade-e2e.yml`, and
  `offline-bundle.yml`'s `offline-e2e` job. A single push previously
  started up to ~16 of these image-build/cluster-create jobs at once; each
  lane now caps that at three concurrent heavy jobs, queued (not
  cancelled) via `queue: max`. Required status check names are unchanged.
- Machine bearer authentication, unit 5a (#214; tests, CI and drills only, no product
  change): the new `machine-keycloak-e2e.yml` workflow (no paths filter; Keycloak
  `quay.io/keycloak/keycloak:26.7.4`) runs four live scripts against a real Keycloak, a real
  slapd and the real UI backend: both UI auth modes with the valid, invalid-token and
  never-allowed-operation matrices (slapd bind counts, JWKS outage, rate limits, secret
  scan of every container log), the Keycloak client settings an operator must apply
  (lightweight tokens, scopes, token exchange incl. the legacy feature, human tokens),
  JWKS key rotation / floods / hostile issuer responses / discovery recovery behind a
  counting proxy, and the emergency revocation and rollback drill across replicas.
  `release.yml` now also requires the job `machine bearer auth (real Keycloak)` to have
  succeeded on the tagged commit. From now on tagging a main commit that predates this
  workflow (no run of that job on the SHA) fails the release gate: re-run the workflow on
  that SHA via `workflow_dispatch` or tag a newer commit; skipped, cancelled or other-SHA
  runs never satisfy it (see `RELEASING.md`).

## [0.1.1] — 2026-09-24

Maintenance release: dependency and base-image refreshes, plus the release
pipeline fix that let 0.1.0's supply-chain evidence run. No behaviour or configuration
changes; upgrading from 0.1.0 is an image/chart version bump.

### Images

- Base images re-pinned to new digests: `debian:trixie-slim` (`a99cfc5`, builder
  and runtime) and `golang:1.27.1-bookworm` (`69a7b97`, exporter builder). Both
  still cover `linux/amd64` and `linux/arm64`.
- UI frontend dependencies: `lucide-react` 1.47.0, `react-router` /
  `react-router-dom` 7.18.4, `@types/node` 26.6.2, `oxlint` 1.83.0.

### Release pipeline and CI

- The supply-chain licence gate installs Go/Node dependencies before running,
  so it no longer regenerates an empty inventory and fails (#191).
- GitHub Actions bumped: `docker/setup-buildx-action` 4.4.1,
  `docker/build-push-action` 7.4.0 (includes an upstream fix for workflow
  command injection through metadata logs), `github/codeql-action` 4.38.1.
- Workflow concurrency groups no longer cancel or get displaced on `main`
  push: a late-starting run for an older commit had cancelled HEAD's
  in-progress E2E after four PRs merged back-to-back (2026-09-24), leaving
  HEAD with no completed E2E. `main`/schedule/dispatch runs are now grouped
  per commit SHA instead of per ref, so they never share a concurrency group
  with another commit's run; `cancel-in-progress` stays scoped to
  `pull_request` only. Docs-only changes (`**.md`, `docs/**`, `research/**`)
  also no longer trigger the non-required E2E suites on push to `main`
  (metrics, replication chaos, security, SSSD, UI); `ci.yml`, `e2e.yml`,
  `backup-restore.yml`, and `upgrade-e2e.yml` still run on every push to
  `main`, since branch protection or `release.yml`'s release-critical checks
  require their results on every commit that could be tagged.

### Note on the dependency policy

These updates were merged before the seven-day cooling window in
`docs/dependency-policy.md` had elapsed, at the maintainer's request, after a
review of each upstream release (see #192–#195).

## [0.1.0] — 2026-08-18

First release, and a prototype: everything below was verified against
something running, but nothing has been run outside its author's environment.
`helm test <release>` is shipped with the chart so an install can be checked
rather than assumed.

### Server image (`ghcr.io/dasomel/ldapium`)

- OpenLDAP **2.6.14** compiled from the upstream tarball, pinned by version and
  sha256, on `debian:trixie-slim`. `linux/amd64` and `linux/arm64`, each built
  on a native runner — OpenLDAP's `configure` uses runtime probes that are not
  reliable under emulation.
- `slapd` runs as PID 1 as uid 999, configured entirely through `cn=config`.
- No sample data and no default admin password. The container refuses to start
  without one; seeding is opt-in through a mounted LDIF directory.
- Overlays enabled by default: `memberof`, `refint`, `ppolicy`, `unique`, and
  `syncprov` when replication is on. Also built and loadable: `accesslog`,
  `auditlog`, `constraint`, `deref`, `dynlist`, `sssvlv`, `otp`.
- `{ARGON2}` password hashing, loaded as a module.
- N-way multi-provider replication, including a cold-start election so several
  nodes booting at once cannot each create their own copy of the base DIT.
- Tuned for large directories: paged results, configurable size/time limits,
  and an explicit file-descriptor limit (slapd reserves memory per descriptor,
  so an inherited 1M-descriptor limit alone cost ~650MB of RSS).

### Management UI (`ghcr.io/dasomel/ldapium-ui`)

- Go backend, React frontend, shipped as one distroless static image running as
  uid 65532.
- DIT browser, user and group CRUD, group membership by search-and-select,
  password set and self-service change, account unlock, `memberOf` display,
  paged listings, and a password-policy view.
- Every request binds as the logged-in user, so the directory's own ACLs decide
  what a session can do. The UI holds no service account.
- Optional Keycloak SSO (OIDC with PKCE), gated on a realm role. The login
  state is bound to the browser that began it, so a state and code obtained
  elsewhere cannot be used to log somebody else's browser into the attacker's
  account. This is the one path that uses a dedicated LDAP service account,
  because a token carries no password to bind with.
- Korean and English throughout, and inline explanations of LDAP terminology
  for people who do not work with directories daily.
- Backup status is read from the directory itself, so the UI needs no
  Kubernetes access to show it.

### Helm chart (`oci://ghcr.io/dasomel/charts/ldapium`)

- StatefulSet with per-replica PVCs, headless Service, PDB, and topology
  spread. `replicaCount: 1` runs standalone; above that, replication turns on
  and the peer list is wired automatically.
- Refuses to render without an admin password.
- Optional UI Deployment, and a backup CronJob that dumps the data tree and
  `cn=config`, prunes by retention, and records each run into `ou=operations`.

### Also in this repo

- `docker-compose.yml` for a non-Kubernetes deployment, and `scripts/backup.sh`
  covering the same ground as the CronJob outside Kubernetes.
- `scripts/get-credentials.sh` for retrieving admin credentials from either a
  Compose or a Kubernetes deployment.

### Known limitations

- **TLS is unverified end to end.** The templates render and the entrypoint
  handles certificates and TLS-protected replication, but no one has watched it
  work against a live cluster. It is off by default. Reports welcome.
- **The settings page lists modules and overlays from configuration, not from
  the server.** Those values live in `cn=config`, which has its own admin
  identity that no UI session can hold, so the list is kept in step with
  `image/Dockerfile` by hand.
- **No upgrade path is promised yet.** 0.1.0 is the first release; there is
  nothing to upgrade from.
- **The e2e workflow has never run.** It installs the chart into a kind
  cluster and runs `helm test`; the test script itself was developed against a
  live directory and its failure modes verified, but the CI wiring around it
  is new.

[0.1.1]: https://github.com/dasomel/ldapium/releases/tag/v0.1.1
[0.1.0]: https://github.com/dasomel/ldapium/releases/tag/v0.1.0
