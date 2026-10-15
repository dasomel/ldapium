# Changelog

Notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) — while the project is on 0.x, minor
releases may break compatibility, and the release notes will say so when they do.

A single git tag `vX.Y.Z` publishes the chart and both images under the same
version. `appVersion` is separate: it is the OpenLDAP release being compiled.

## [Unreleased]

### Documentation

- **Machine `setPassword` second-set response corrected (#417).** The 0.2.0 notes and
  `docs/api.md` said an account whose password was already set answers 409. A completed
  set clears the pending marker, so a second request is refused 403 by the marker check;
  409 `conflict` only appears for a stuck entry (password present, marker left by a
  failed cleanup). The behaviour is unchanged and was measured through a real Keycloak
  token and the UI image.

## [0.2.0] — 2026-10-14

### Breaking / behaviour changes

- **Machine `deleteUser` / modrdn narrowed (Q16).** With the v2c LDAP rules installed,
  machine `deleteUser` and modrdn only reach entries created through `W_data`; other
  entries are refused.
- **ppolicy state attributes are read-only for self (#400).** `pwdReset`,
  `pwdStartTime`, `pwdEndTime` and `pwdAccountLockedTime` can no longer be written by
  the user on its own entry. The ACL is bootstrap-only: existing volumes keep their
  stored `olcAccess` until upgraded in place (see `image/README.md`, in-place upgrade).
- **The image refuses to start with `extended` or `all` in `LDAP_ACCESSLOG_OPS` (#398).**
  Use `writes reads bind`.

### Web UI

- Users and Groups lists page through the cursor API (`limit`/`cursor`/`q`, #253).
  Search is now server-side and matches only `uid`/`cn`/`mail`/`displayName` (users)
  and `cn`/`description` (groups); the old client-side search over `department`,
  `organization` and `organizationalUnit` is gone (accepted in `D215-7`). The list no
  longer shows a total count.

### Image

- The entrypoint now refuses to start when the accesslog overlay is enabled and
  `LDAP_ACCESSLOG_OPS` contains `extended` or `all` (#398, F-7, `D398-1`). OpenLDAP
  2.6.15's accesslog overlay aborts slapd (`accesslog.c:1623`, exit 133) on the first
  Password Modify, including the human `setPassword` path. Use `writes reads bind`;
  there is no override until upstream fixes it.

### API

- **Machine write v2c opened (#379, T-026): machine `setPassword`.** With
  `MACHINE_WRITE_ENABLED` and `MACHINE_WRITE_CRED_ENABLED` on and
  `directory.users.password.write` in a client's ceiling, a machine client sets the
  **initial** password of an account it created itself with `createUser`
  `credentialPending: true` (body exactly `{dn, password}`, `Idempotency-Key`
  required, no `If-Match`, response `{}`; any other target 403, an account whose
  password was already set 409). It runs as the separate `W_cred` identity behind
  the T-028 premise checks. OpenAPI marks it `machineBearer` /
  `x-machine-scope: directory.users.password.write`. A ceiling may now name the
  password scope; with `MACHINE_WRITE_CRED_ENABLED=false` it still starts and the
  request is 403 `scope_denied` without any `W_cred` bind (the emergency block;
  AC-011 (a) is revised to 403, Q19).
  Unlock stays human-only and is the only write scope still refused in a ceiling.
- **Contract narrowing with v2c on (Q16, accepted 2026-10-14):** a deployment that
  installs the v2c LDAP rules narrows machine `deleteUser` (and `W_data`'s direct
  LDAP modrdn; the machine API has no rename operation) to entries `W_data` created; deleting an administrator-made user (any class) or a
  container is refused by the directory (LDAP 50) and answered 403 `forbidden`.
  Groups (v2b `deleteGroup`) and deployments without v2c are unchanged.
- `W_cred` gets a no-lockout password policy (CHANGE.md Q17, decided 2026-10-14):
  guide `docs/machine-write-account.md` 8.1 attaches `wcred-policy.ldif`
  (`pwdLockout FALSE`, no `pwdMaxFailure`), so wrong binds can no longer lock
  `W_cred` and stop `setPassword`; the operator owns brute-force mitigation (long
  random password, network restriction, failed-bind alert). The premise checks
  enforce it (Q18 (b)): at start-up and every 60 s `W_cred`'s policy must exist,
  differ from the default and pending policies and state `pwdLockout: FALSE` with
  no `pwdMaxFailure`/`pwdMaxAge`/`pwdMustChange TRUE`, else start-up is refused /
  `setPassword` answers 503.
- Accepted risk (2026-10-14): with v2c on, a leaked write credential can rename an
  administrator-made user's `mail`/`uid` and give the old value to a new pending
  account; applications that resolve the login name from `mail`/`uid` are at risk
  (bind by `entryUUID` or alert on changes, or keep v2c off).
- Chart: `ui.machineAuth.write.cred.*` renders the `W_cred` identity, the
  configuration reader and the canaries (`MACHINE_WRITE_CRED_*`; passwords are
  Secret references only, every identity and Secret key distinct). It still
  refuses next to `audit.enabled=true` or an accesslog ops list holding
  `extended`/`all`. The chart still grants no write scope in `allowedClients`.
- Machine write v2c (#379, T-020) configuration and start-up validation only; **no
  operation is opened** (`directory.users.password.write` is still refused in a
  ceiling and the password routes stay 403 `scope_denied` with no bind). New
  `MACHINE_WRITE_CRED_ENABLED` (default `false`; when off no other
  `MACHINE_WRITE_CRED_*` is read). When on, start-up requires
  `MACHINE_WRITE_CRED_BIND_DN`/`_PASSWORD` (distinct from every other identity, in
  the protected set), a non-empty `MACHINE_WRITE_PRIVILEGED_GROUPS`,
  `MACHINE_WRITE_CRED_SUBTREES` inside the same client's `MACHINE_WRITE_SUBTREES`,
  and `MACHINE_WRITE_CRED_PENDING_POLICY_DN` (not the default policy); optional
  `MACHINE_WRITE_CRED_MIN_LENGTH` (12–1024, default 12) and
  `MACHINE_WRITE_CRED_POLICY_DNS`. The policy entries join the protected set, so a
  write ceiling holding one fails start-up. The chart is unchanged. See
  [machine-write-account.md](docs/machine-write-account.md) section 8.
- Machine write v2c (#379, T-021) LDAP fragments, opt-in and not yet used by the app: `W_cred`
  (`write-cred.ldif`, initial password on pending `W_data`-made accounts only, cleanup of the marker
  and pending policy values) and the `W_data` v2c rules (`write-data-cred.ldif`). Installing them
  requires `olcAddContentAcl TRUE` on the main database and narrows machine `deleteUser`/modrdn to
  entries `W_data` created, groups excepted (Q16). Guide `docs/machine-write-account.md` section 8; the read-only
  checker gains `--cred-dn`/`--pending-policy-dn`/`--privileged-group`/`--wcred-unpinned`; non-pinned
  providers get `write-cred-deny.ldif`. Image defaults unchanged.
- Machine write v2c (#379, T-023) password limits and audit, still **not opened**:
  new `MACHINE_WRITE_CRED_RATE_LIMIT_RPS` (global password budget, 1–10, default 1,
  read only with `MACHINE_WRITE_CRED_ENABLED=true`) and a per-target serialization
  (`entryUUID`, shared across clients); either refusal is `429 machine_rate_limited`
  with `Retry-After`. Audit lines gain `compartment=cred` (no password field).
- Machine write v2c (#379, T-025) per-compartment emergency-block drill for the password
  compartment, tests and docs only, `setPassword` still closed (T-026 opens it). New
  `scripts/test/test-machine-write-cred-drill.py` and a `live`-tagged Go test measure the
  `MACHINE_WRITE_CRED_ENABLED=false` redeploy, the `W_cred` rotation (old credential refused,
  `W_data`/`W_lock`/read unaffected on running replicas, restarts fail until the new Secret is
  rolled out), the `MACHINE_REQUEST_TIMEOUT` bound of an in-flight request (8.0 s at 10 s, 2.0 s
  at 4 s), the `W_cred` lockout at `pwdMaxFailure` and the Revision 8 manual cleanup of a stuck
  entry, run live. `docs/machine-auth-operations.md` gains "Password compartment emergency
  block". A flag-only redeploy answers 503, not the 403 of AC-011 (a); AC-011 is corrected. The
  `W_cred` lockout policy is an open maintainer decision (CHANGE.md Q17).
- Machine write v2c (#379, T-028) run-time premise checks and sweeps, still **not
  opened** (`setPassword` stays unreachable until T-026). With
  `MACHINE_WRITE_CRED_ENABLED=true` start-up now also requires
  `MACHINE_WRITE_CRED_ACL_READER_DN`/`_PASSWORD` (a `cn=config` reader, distinct from
  every other identity, in the protected set) and `MACHINE_WRITE_CRED_CANARIES` (one
  set of three locked canary entries inside every `MACHINE_WRITE_CRED_SUBTREES` DN), and
  reads `MACHINE_WRITE_CRED_PENDING_TTL` (default `24h`, 1h–720h). The UI then checks,
  at start-up (failure: non-zero exit), before every password write (failure: that
  request 503, no write) and every 60 s (failure: password operations 503 until a
  passing cycle): the main database `olcAccess` against the guide's layout as text,
  `olcAddContentAcl TRUE`, the default and pending policy values against the floor
  (the image's default `pwdMinLength` 8 is below the floor 12: **v2c deployments need
  `LDAP_PASSWORD_MIN_LENGTH>=12`**, an intended operating cost), no `cn=accesslog` child
  readable by `M`, and the canary probes. The 60 s cycle also runs the stuck / TTL /
  orphan / foreign sweeps of the pending policy (W_cred cleans the first three, with a
  re-read retry; a cleanup that still fails closes the password operations and alerts;
  after a failed check the sweep only counts). Start-up sweeps read-only and refuses to
  start on a stuck entry; a cycle older than two periods closes the password operations.
  `MACHINE_WRITE_CRED_POLICY_DNS` has no effect yet (the pre-read admits only the pending
  policy). Only result codes and counts are logged. New
  fixtures `config-reader.ldif`, `config-reader-main.ldif` and guide sections 8.8–8.9
  ([docs/machine-write-account.md](docs/machine-write-account.md)). Chart:
  `ui.machineAuth.write.cred.enabled` (default `false`) exists only to refuse: next to
  `audit.enabled=true` (D379-14), next to an `audit.accessLog.ops` holding `extended`
  or `all` (F-7), and on its own until T-026.
- Machine write v2c (#379, T-024) live proof of the password step, tests only, still
  **not opened**: `scripts/test/test-machine-write-cred-secret-live.py` runs the real
  pipeline (a `live`-tagged test server that adds `setPassword` to its own table) against
  slapd and scans responses, headers, the UI log and audit, the slapd log and
  `cn=accesslog` (rootdn and `M`) for the one-time sentinels and for hash patterns: 0
  in the configuration the chart and T-028 accept; with `audit.enabled` the auditlog
  carries hashes, which the chart refuses. The T-028 check-5 pre-hashed probe is now
  one fixed public constant (`{SSHA}` of `zz`, salt `ldapium!`; it was a random throwaway
  value): its refused Modify still leaves that value in `cn=accesslog` at start-up and
  every 60 s when `writes` is logged, and the scan allowlists exactly it (EVIDENCE.md
  §2k, T024-F1).
- Machine write scope (#285) maintainer decisions, 2026-10-13, docs and one regression
  test only: the closed request-body guard is the sole defence against an objectClass
  value ADD on Modify (#386, option A; the `val.regex` allowlist B is not adopted) and
  against `userPassword` on a `W_data` Add (#390, option (a): slapd checks only
  entry/children on Add). Nested privileged members being lockable, the chart staying
  read-only for write scopes, and over-refusal of non-ASCII `memberOf` are recorded as
  accepted/by-design (#394 items 2, 5, 6). `TestMachineWriteClosedFieldSet` now covers
  `userPassword` spelling variants on every machine write operation. See
  [CHANGE.md](docs/changes/machine-write-scope/CHANGE.md) D17a/D17b/D18.

- Machine write v2b hardening (#394, items 1, 3, 4). **ACL (operators, re-apply on
  every node; roll back the old fragments first, guide section 7):** `write-lock.ldif`
  grants `W_lock` only `add` on `pwdAccountLockedTime`, so a `W_lock` credential can
  set a lock but never delete or replace it (unlock stays human-only at the ACL
  level too); `write-data.ldif` moves `description` into its own rule with
  `filter=(objectClass=groupOfNames)`, so `W_data` cannot write a user's description
  (the fragment now has 9 rules). Machine `lockUser` adds the marker instead of
  replacing it: re-locking is idempotent (204), an account the password policy
  locked with a timestamp answers 409 and keeps that lock. `MACHINE_WRITE_GROUP_SEED_DN`
  must be a direct child of the container that holds `MACHINE_WRITE_DATA_BIND_DN`,
  or start-up fails. `scripts/check-machine-write-acl.sh` reports the old fragments
  as a mismatch.
- Optional LDAP machine-token revocation (#286), **default off**: validated tokens
  are checked against a background snapshot before request budgets or directory
  access. A revoked JTI or client cutoff returns `401 token_invalid`; missing,
  invalid or expired snapshots return `503 unavailable` with `Retry-After` only
  after token verification. The revocation subtree is protected from HTTP reads
  and administrator writes. Initialize the sentinel and schedule the operator
  heartbeat before enabling `MACHINE_REVOCATION_ENABLED` or the chart's
  `ui.machineAuth.revocation.enabled`; keep each replica on a stable LDAP node.
  The healthy propagation bound is `REFRESH + 2×5 s + replication delay`, subject
  to the clock and replication assumptions. A partition eventually refuses
  requests after sentinel freshness and snapshot grace expire. Disabling the
  feature removes these revocations; use the allowlist rollout backstop when
  rolling back. See [operations](docs/machine-auth-operations.md) and the
  [change package](docs/changes/machine-token-revocation/CHANGE.md) for limits,
  migration, evidence and known follow-ups. Live drills (cutoff boundary,
  heartbeat stop, heartbeat-only aging) run in `machine-keycloak-e2e.yml`.
- Optional machine-principal writes (#285, #372, #378), **default off**
  (`MACHINE_WRITE_ENABLED`, a switch separate from `MACHINE_AUTH_ENABLED`). Five
  single-entry operations open to a verified Keycloak client: `createUser`
  (without a password), `patchUser`, `deleteUser` (leaf users only),
  `addGroupMember`, `removeGroupMember`. Each client has a write-subtree ceiling
  (strict descendants only), a group allow-list and a separate write budget;
  `Idempotency-Key` is required (428 `idempotency_key_required`) and all but
  `createUser` need exactly one strong `entryCSN` `If-Match` (428
  `if_match_required`). Writes bind per request as a dedicated LDAP identity
  (`MACHINE_WRITE_DATA_BIND_DN`) behind the ACL in
  [machine-write-account.md](docs/machine-write-account.md); the switch refuses to
  start without idempotency, a single replica and the write identity.
  Emergency block and measured limits: [operations](docs/machine-auth-operations.md).
  Design and evidence: [change package](docs/changes/machine-write-scope/CHANGE.md).
  The idempotency store is in memory, so a restart turns a replay into a
  re-execution (`If-Match` and entry uniqueness remain the second line).
- A machine write whose target no longer exists now returns the cookie path's `404
  not_found` instead of a retryable `503 unavailable` (#385). Only a genuine LDAP
  noSuchObject for the target maps to 404; directory failures stay 503 and a missing
  target outside the client's subtree is still the guard's 403. The audit line carries
  the new `outcome=target_not_found` (`reason=request_rejected`) rather than
  `reason=upstream_error`.
- Chart: new optional `ui.machineAuth.write.groupSeedDN` renders `MACHINE_WRITE_GROUP_SEED_DN`
  (empty by default; the default render is byte-identical). The chart's `allowedClients`
  schema still lists only the read scopes, so write scopes cannot be granted through the chart yet.
- Machine group and lock writes (#379, v2b, accepted 2026-10-12), **default off**:
  with `MACHINE_WRITE_ENABLED=true` (separate switch, default off; off, all of them
  stay 403 `scope_denied` with no bind, byte-identical to before) four more
  operations open, each needing its scope in the client ceiling: `createGroup`
  (`directory.groups.create`; the new group's only initial `member` is the fixed
  placeholder `MACHINE_WRITE_GROUP_SEED_DN`, never the write identity, and it is not
  writable by any machine client until the operator lists its DN in
  `MACHINE_WRITE_GROUPS`), `patchGroup` (`directory.groups.update`, `description`
  only; `cn` is 400), `deleteGroup` (`directory.groups.delete`, allow-listed groups
  only, never a privileged group) and `lockUser` (`directory.users.lock`, separate
  `W_lock` identity, refuses members of `MACHINE_WRITE_PRIVILEGED_GROUPS`; nested
  group membership is an accepted residual risk, see the change package). **Unlock
  stays human-only**: `unlockUser`/`directory.users.unlock` are not opened and a
  machine `POST /api/users/unlock` is 403 with no bind (D379-7). `updateUser`,
  `updateGroup` (PUT) and every password operation stay closed. OpenAPI gains the
  additive `machineBearer`/`x-machine-scope` on the four operations. The T-015 live
  drill (`scripts/test/test-machine-write-v2b-live.py`, real Keycloak and slapd) runs
  in the machine-write E2E workflow. The groundwork notes below describe the
  steps that led here. New optional `MACHINE_WRITE_GROUP_SEED_DN` (read only
  with `MACHINE_WRITE_ENABLED`; canonical DN inside the base, distinct from every
  protected identity, added to the protected set) is the placeholder first member a
  machine-created group will get instead of the `W_data` DN. The group pipeline rows
  (`createGroup`, `patchGroup` description only, `deleteGroup`) exist as catalog data
  and are exercised in tests only. **ACL (operators):** the `W_data` fragment
  (`scripts/test/fixtures/machine-acl/write-data.ldif`, rule `{5}`) now lists
  `description`; re-apply it where `W_data` is installed. Because the ACL cannot tell
  groups from users, `W_data` can then write `description` on user entries too (the
  machine `patchUser` body still excludes it). See
  [change package](docs/changes/machine-write-scope-v2/CHANGE.md).
- Groundwork for machine user locking (#379, v2b), opened by the entry above: the
  `lockUser` pipeline row (`W_lock`, closed body `{dn}`, strong `If-Match`,
  `inetOrgPerson`) was catalog data first. A lock
  refuses a target that is a direct member of a `MACHINE_WRITE_PRIVILEGED_GROUPS`
  group (an `M` read of `memberOf`, before the `W_lock` bind), and a lock ceiling
  with `MACHINE_WRITE_LOCK_ENABLED` off fails startup. Unlocking stays human-only:
  `unlockUser` and `directory.users.unlock` remain unopened (D379-7), so a machine
  token still gets 403 `scope_denied` with no bind on `POST /api/users/unlock`. The
  cookie lock/unlock path is unchanged.
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

- **Security:** a user can no longer choose its own password policy (#399, F-9). The
  catch-all `to * by self write` covered `pwdPolicySubentry`, so any bound user could
  point its own entry at any `pwdPolicy` subentry (e.g. one without lockout, quality
  check or history). A new rule before the catch-all gives the entry itself only
  `read` on `pwdPolicySubentry` and passes every other identity through unchanged
  (`by * break`); the admin still assigns policies. The catch-all moves from `{2}` to
  `{3}` (`{4}` to `{5}` with `LDAP_ANONYMOUS_READ_BASE`). **Upgrade:** the ACL is
  written at bootstrap only, so existing volumes keep the old behaviour until the rule
  is added by hand (one `ldapmodify`, see image/README.md "Access control"). Other
  ppolicy attributes a user can still write on itself, measured and left as they are:
  `pwdReset`, `pwdStartTime`, `pwdEndTime` (replace and delete) and
  `pwdAccountLockedTime` (add, i.e. locking itself out).
- **Security / behaviour change:** a user can no longer write its own ppolicy state
  (#400, D400-1). The #399 rule's `attrs=` list now also covers `pwdReset`,
  `pwdStartTime`, `pwdEndTime` and `pwdAccountLockedTime`, so the entry itself gets
  `read` only: it can no longer clear its own forced reset, extend its own validity
  window or lock itself. No new rule, so the rule count and every `{n}` position stay
  as they were. The ppolicy overlay's own lock/unlock/reset writes and the admin are
  unaffected (live-verified, including lock/unlock replicating to a second node).
  **Users who relied on self-writing these attributes now get Insufficient access
  (50); there is no escape hatch, an operator who wants self-managed validity windows
  must use an admin identity.** `pwdChangedTime`, `pwdFailureTime`, `pwdGraceUseTime`,
  `pwdLastSuccess` and `pwdHistory` were already refused by the schema
  (NO-USER-MODIFICATION, 19). **Upgrade:** bootstrap only, as for #399; existing
  volumes keep the old behaviour until the rule is replaced by hand (image/README.md
  "Access control").
- A kept config volume with a lost data volume now refuses to start in every mode
  with a message naming the missing database directory and the recovery (delete BOTH
  the data and the config claims; the node refills from its peers). `dedicated` no
  longer reports it as an unreadable stored `olcSyncrepl` (#387). Behaviour is
  otherwise unchanged: exit non-zero, nothing created.
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
- Admin-mode startup now logs a WARNING when `LDAP_REPLICATION_PASSWORD(_FILE)`
  differs from the admin password while replication binds as the admin DN: peers
  reject that bind (rc 49) and replication stalls silently (#355, proposed in
  `docs/changes/replication-identity/CHANGE.md`). A log line only; the start is
  never refused, and `cn=config`/`olcSyncrepl` stay byte-identical (a custom
  `LDAP_REPLICATION_BIND_DN` with a password does not warn).
- Documentation (#354): the replication identity transition (prepare, check,
  ensure, check, dedicated, rollback, total-loss recovery) is in
  `docs/migration.md`; the limits of the contextCSN alerts and the data check are
  in `docs/ha-profile.md`. `rotate`, `rollback-admin` and the periodic check
  remain unimplemented.

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

[0.2.0]: https://github.com/dasomel/ldapium/releases/tag/v0.2.0
[0.1.1]: https://github.com/dasomel/ldapium/releases/tag/v0.1.1
[0.1.0]: https://github.com/dasomel/ldapium/releases/tag/v0.1.0
