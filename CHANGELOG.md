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
