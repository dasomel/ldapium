# Changelog

Notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) — while the project is on 0.x, minor
releases may break compatibility, and the release notes will say so when they do.

A single git tag `vX.Y.Z` publishes the chart and both images under the same
version. `appVersion` is separate: it is the OpenLDAP release being compiled.

## [Unreleased]

### API

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
  condition is node-local on multi-provider replication. Idempotency keys
  are not part of this change.

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
