# Current Implementation Status

Last verified: 2026-09-14 against `main`, except the "External HTTP API" section, which was added 2026-10-06 against `main` at `6c118ac` from the audit in `docs/changes/CLOSE-OUT-2026-10.md` and the code, tests and PR history it cites (the live Docker scripts were not re-run for it).

The dedicated replication detail below was added 2026-10-09 against main `3e1f342`; it is an exception to the original snapshot date above.

Refreshed 2026-10-16 against `main` at `7342f96` (v0.2.1) from the code, workflows and CHANGELOG: OpenLDAP version, dedicated replication identity, machine bearer authentication (including revocation and write scopes), generated credentials and the web UI notes. Sections not named here keep their earlier date; the live scripts were not re-run.

This snapshot records features already merged to `main`. Open pull requests and issue-only roadmap items are intentionally excluded.

## Product boundary

ldapium packages upstream OpenLDAP 2.6.15 for modern Kubernetes/container operation. It combines a source-built server image, optional management UI, Helm chart, Docker Compose path, backup/restore, air-gap tooling and release/supply-chain evidence.

## Directory / replication

- OpenLDAP 2.6.15 built from upstream source
- MDB backend
- memberOf / refint / ppolicy / unique / syncprov overlays
- standalone and multi-provider replication paths
- replication chaos testing, including real network partition and same-entry conflict behavior
- raw replication CSN discard evidence in the audit export with entryUUID objectId correlation
- HA topology governance (D11-D13): Active-Active N-Way multi-provider, reference RPO/RTO SLAs, cross-site DR via backup shipping
- Prometheus alert rules for replication lag, ContextCSN divergence, and exporter health

### Dedicated replication identity status (2026-10-16)

Verified against main `7342f96` (v0.2.1): the image supports opt-in `prepare` and
`dedicated` modes, reserved read-only identity ACL/limits, verified LDAPS,
consumer-only startup and fail-closed unsafe configuration checks. The operator
command `scripts/replication-identity.sh` provides `ensure`, `retire`, `reconcile`,
`rotate` (rolling credential rotation) and `rollback-admin` (the gate before returning
to administrator replication). The chart has explicit identity/Secret configuration and
an opt-in periodic check CronJob (`replication.check.*`, default off) with the
`LDAPiumReplicationCheckFailed` alert. The default remains admin. CI runs the env,
prepare, dedicated, ensure, check, reconcile, rotate, rollback-admin and restore scripts
in `e2e.yml` and the Kubernetes recovery script in `replication-chaos-e2e.yml`.
See the [ADR](changes/replication-identity/ADR.md),
[acceptance conditions](changes/replication-identity/CHANGE.md) and
[remaining tasks](changes/replication-identity/TASKS.md); the package's Status line
there still says acceptance is the maintainer's.

The operator procedure (prepare, check, ensure, check, dedicated, rollback,
total-loss recovery) is in [migration.md](migration.md) and the check/alert limits in
[ha-profile.md](ha-profile.md). Admin mode warns, without refusing, when a distinct
`LDAP_REPLICATION_PASSWORD` would stall replication (#355, closed). Shared administrator
credential restriction D43 is retained.

## TLS and authentication hardening

- LDAPS support with strict certificate verification
- TLS 1.2 protocol floor via `olcTLSProtocolMin`
- explicit TLS 1.2 cipher-suite baseline
- certificate expiry and rotation E2E
- two-step CA rotation verification
- StartTLS on port 389 verified in CI
- optional mTLS / SASL EXTERNAL mapping with documented CA-boundary caveat
- failed-login rate limiting in the management UI
- provider fallback policy and structured authentication audit logging

## Authorization / audit

- deny-by-default LDAP ACL boundaries with live negative tests
- optional subtree scoping for anonymous UID/objectClass discovery
- auditlog write attribution
- accesslog for reads and binds, including failed binds
- unified NDJSON export across audit/access/replication-conflict sources
- normalized identity audit event envelope (schemaVersion/seq/correlationId/privileged/objectId) over that same export, with deterministic replay coverage
- tamper-evident cryptographic hash chain verification over normalized audit exports
- audit shipper with bounded exponential backoff retries, dead-letter queue, and idempotent cursor
- rootdn vs ordinary-user actor distinction verified
- HTTP 500 error redaction with request correlation
- `userPassword` redaction from generic DIT browser responses

## UI / client integration

- DIT browser
- user/group create, edit and delete
- entry move via LDAP ModifyDN (`/api/entry/move`) with idempotency error mapping
- password change / reset
- account lock/unlock
- organizational metadata fields
- cn=Monitor health view with uptime, thread/connection waiters, replication CSNs, and access log stream
- operator action history view (`/history`, `GET /api/audit/actions`) with actor/op filtering, cursor pagination, and attribute value redaction
- unauthenticated LDAP reachability health endpoint
- browser-driven Playwright E2E against a real directory
- Keycloak/OIDC integration path with end-to-end user federation testing

## External HTTP API (`/api`, UI backend)

Contract: `docs/api.md`. Operator procedures: `docs/ui-operations.md`. Decisions: `docs/changes/api-error-envelope/ADR.md`, `docs/changes/api-conditional-writes/ADR.md`.

- one JSON error envelope (`error`, `message`, `code`, `requestId`, `retryable`) on every `/api` error, a closed append-only `code` table pinned by a golden-list test, fixed text for 5xx, no DN or LDAP diagnostic text in 4xx (#218; PRs #234, #240, #242, #246)
- `message` is a deprecated copy of `error`, kept for the whole of `/api/v1`
- same-origin gate on state-changing requests that carry an `Origin` header (403 `origin_mismatch`); requests without `Origin` are unaffected and there is no switch to turn it off
- opt-in `/metrics` on a separate listener (`METRICS_ADDR`, chart `ui.metrics.*` with a required scrape-peer list); `GET /metrics` on the public port is a 404 envelope
- opt-in read-only CORS (`CORS_ALLOWED_ORIGINS`, chart `ui.cors.*`); writes are never CORS-enabled
- cursor pagination for `GET /api/users` and `/api/groups` (`limit`, `cursor`, `q`, `sort`; legacy response byte-for-byte unchanged), with the opt-in image setting `LDAP_PAGED_TOTAL_LIMIT` (chart `ldap.limits.pagedTotal`) for non-root enumeration past `LDAP_SIZE_LIMIT` (#215; PRs #237, #243, #244, #256)
- conditional writes: `etag`/`ETag` from `entryCSN`, `If-Match` enforced by slapd through the RFC 4528 assertion control, `PATCH` for users and groups, identity-bound compensation for a user create whose password step fails (#216 part A, PR #235)
- opt-in `Idempotency-Key` for core writes and backup start (#216 part B, PR #241)
- backup job IDs, `GET`/`cancel` job endpoints, durable job records, orphan-aware restart recovery, per-kind deadline (#217, PR #236; live runs for remotes/SIGKILL/deadline: #255)

Boundaries:

- `If-Match` is evaluated on the receiving node only; against multi-provider replication it is optimistic protection, not consensus.
- Core-write idempotency records live in process memory and are lost on restart, so the chart enables them for a single UI replica only. Backup-start keys are the exception: they are stored in the durable job record.
- The web UI's Users and Groups lists page through the cursor API (0.2.0, #253) and its write actions can send `If-Match` and `Idempotency-Key` (`ui/frontend/src/lib/api.ts`, `useWriteAttempt.ts`); this was not re-verified against the #216 REQ-013 and #215 AC-010 wording.
- Live against disposable containers (#255; `scripts/test/test-backup-jobs-remotes-live.py`): the success path to S3/FTP/SFTP, SIGKILL after the grace period, and the deadline path (stand-in worker). Remote failure injection and the real worker's deadline cleanup are unit-test only.
- Live evidence for these features is in the packages' `EVIDENCE*.md` files (local Docker runs); the CI workflows named there were not re-run for this section.

## Machine bearer authentication (#214, default off)

Change package: `docs/changes/machine-principal-auth/` (CHANGE, TASKS, EVIDENCE, [ADR](changes/machine-principal-auth/ADR.md)), accepted 2026-10-07 (Revision 5), merged in staged units (#272, #274, #276, #278, #279, #281, fixes #273, #282) with the feature **off by default**. Contract and operator guides: `docs/api.md`, `docs/machine-keycloak-client.md`, `docs/machine-ldap-account.md`, `docs/machine-auth-operations.md`. Close-out audit (2026-10-07, main `5c74f73`): all REQ-001 to REQ-018 and AC-001 to AC-019 are MET with the limits listed below; the audit's verdict is that the acceptance criteria of #214 are met and the issue can be closed (the maintainer decides, after the audit PR merges). See "Close-out audit" in `docs/changes/machine-principal-auth/CHANGE.md`.

Implemented and merged:

- Keycloak service-account access token as a bearer credential on exactly eight read-only `GET` operations; 37 protected operations always `403 scope_denied`; runtime deny-by-default guard; OpenAPI `machineBearer` additive
- token verification (alg allowlist, `typ`, `iss`, exact `aud` membership, `azp`==`client_id`, service-account rule, scope, `iat`/`exp`/`nbf`/lifetime cap), JWKS key source with fail-closed 503, per-IP failure throttle before signature work, per-client budgets, bounded state
- dedicated read-only LDAP execution identity bound per request with a request deadline, base boundary (`LDAP_BASE_DN`, no accesslog/config/Monitor), cursor binding, one `event=machine_access` audit line per request that reaches a handler
- operator ACL guide with the final `olcAccess` LDIF, Helm `ui.machineAuth.*`, Keycloak client and operations guides, ADR and release notes
- the CI workflow `machine-keycloak-e2e.yml` (job `machine bearer auth (real Keycloak)`) and its entry in the `release.yml` `release_critical` list

Live-verified (local Docker, real slapd and UI backend; recorded in `EVIDENCE.md` sections 4 and 5; run again by CI, run 37557393281 on the merge commit and 37555431534 on the last PR head, both success):

- real Keycloak 26.7.4 in both UI modes (LDAP mode and SSO mode): the eight allowed operations (71 checks), 40 negative tokens and the 37 denied operations with zero machine-DN binds, cookie plus bearer mixes, Origin, JWKS outage, rate limits, over-privileged bind with no secret value in any response, cursor isolation, secret scan of every container log
- Keycloak client settings an operator must apply, positive and negative (33 checks, including the legacy token-exchange feature)
- JWKS key rotation, request floods behind a counting proxy, hostile issuer responses and discovery recovery without restart (34 checks)
- emergency revocation and rollback drill across two UI replicas (18 checks)
- read-only proof of the machine LDAP account in three configurations (349 checks, 11 mutation runs that must each be detected) and the execution boundaries (slow/dead LDAP, aborted requests, slot return, limiter 429, audit reasons)

Unit-tested only (no live run):

- the default-value JWKS stale/expired rows and the exact fetch counts of scenarios a to h (fake clock; live uses shortened TTLs), the full `selectAuth` matrix cell by cell, limiter boundary tables, config validation variants, Helm rendering and kubeconform (`scripts/test/test-chart-machine-auth.sh`; no cluster install), audit lines for early returns other than allowed, verification failure and scope denial

Cluster proof (#284, closed): `chart-machine-auth-kind.yml` runs `scripts/test/test-chart-machine-auth-kind.sh`, which installs the chart with machine auth on a kind cluster behind ingress-nginx and checks the per-node LDAP ACL, a bearer call through the ingress, forged `X-Forwarded-For` against `ui.trustedProxies`, and Helm replica replacement. The machine rules combine with `LDAP_REPLICATION_IDENTITY=prepare` only in the defined `olcAccess` order (#277, closed; CHANGELOG 0.2.0).

Optional LDAP machine-token revocation (#286) shipped in 0.2.0, **default off** (`MACHINE_REVOCATION_ENABLED`, chart `ui.machineAuth.revocation.enabled`):
operator sentinel/heartbeat tooling (#323), background LDAP snapshots (#325),
HTTP enforcement and protected subtree (#336), and chart configuration (#335)
are merged, with live cutoff-boundary, heartbeat-stop and heartbeat-only aging
drills and wiring regression tests (#356, #357, #359). The independent security
review found no blocker; the Codex critic round was not run. Alternative
credentials (#360), shared limiters (#361) and an introspection backstop (#362)
were separate issues and are closed; non-blocking items are listed under "Known
follow-ups" in the package's CHANGE.md. See
[revocation tasks](changes/machine-token-revocation/TASKS.md),
[ADR](changes/machine-token-revocation/ADR.md), and
[operations](machine-auth-operations.md) for evidence and rollback consequences.

### Machine write scope (#285, #379, 0.2.0, default off)

Opt-in writes for a verified Keycloak client behind `MACHINE_WRITE_ENABLED` (separate from `MACHINE_AUTH_ENABLED`; the chart grants no write scope in `allowedClients`). Change packages: `docs/changes/machine-write-scope/`, `docs/changes/machine-write-scope-v2/`. Operator guide: [machine-write-account.md](machine-write-account.md).

- v1 (#285): `createUser` (no password), `patchUser`, `deleteUser` (leaf users), `addGroupMember`, `removeGroupMember`; per-client write-subtree ceiling, group allow-list and write budget; `Idempotency-Key` required, `If-Match` required on all but `createUser`
- v2b (#379): `createGroup`, `patchGroup` (description), `deleteGroup` (allow-listed groups), `lockUser` (separate `W_lock` identity); unlock stays human-only
- v2c (#379): `setPassword` for the initial password of an account the client created with `credentialPending: true`, as the separate `W_cred` identity behind run-time premise checks (needs `MACHINE_WRITE_CRED_ENABLED`, `LDAP_PASSWORD_MIN_LENGTH>=12`; refused next to `audit.enabled=true`)
- live proof runs in `machine-write-e2e.yml` and `machine-keycloak-e2e.yml` (real Keycloak and slapd, including `setPassword` and plaintext/hash secret scans, #427); #285, #379 and #417 are closed
- the idempotency store is in memory, so a restart turns a replay into a re-execution; single replica only

### Generated startup credentials

Without an explicit value, the entrypoint generates `LDAP_ADMIN_PASSWORD` (fresh directory only; a bootstrapped directory without its original password fails closed) and the UI `SESSION_SECRET` once from the OS CSPRNG into private files on durable volumes; Helm shares them through Secrets and refuses to generate in an offline render. Explicit files/environment values take precedence; raw values are only readable through the operator CLI or the Kubernetes Secret (`scripts/get-credentials.sh`). Package: `docs/changes/generated-credentials/CHANGE.md` (D40-D42). Not re-verified live for this refresh.

Known limitations and follow-ups: see "Known limitations and follow-ups" in `docs/changes/machine-principal-auth/TASKS.md`. The issues it lists (#266, #277, #280, #284, #285, #286, #287, #360-#362) are closed as of 2026-10-16; D25 unaudited server-level rejections, per-replica limits and opt-in scopes off by default still apply. Requests the Go HTTP server rejects before any handler are in no log unless the ingress keeps an access log. Publishing the OpenForge status (T-033) is an external maintainer step after the audit PR merges.

## Operations / resilience

- scheduled backup with integrity manifest
- restore tooling and 3-node DR exercise
- real-version rolling upgrade coverage (previous OpenLDAP -> current)
- write-availability sampling during upgrade
- offline bundle verification with `imagePullPolicy=Never`
- cn=config and entry data drift detection against canonicalized baselines
- external LDIF migration dry-run validation and reconciliation report
- deterministic, redacted, versioned incident-evidence export for offline/local-LLM RCA (no ChatOps bot, AI service, or remediation executor shipped)
- local scale benchmark tooling with 1M/10M measured profiles, honest apparent vs allocated disk reporting, 30M+ projections, and identity-lifecycle (joiner/mover/leaver) load profiles
- rendered chart schema validation with kubeconform

## Supply chain

- base images and tooling pinned rather than floating on `latest`
- Go module integrity verification
- build/test egress controls
- offline Go module bundle path
- SBOM / provenance / GitHub artifact attestations
- release preflight gates and digest recording
- OpenLDAP version/source/license metadata embedded in the image

## Important current boundaries

- Encryption at rest is delegated to the storage layer; OpenLDAP MDB itself does not provide transparent database encryption.
- The published image is not claimed to be FIPS validated.
- mTLS client-certificate trust requires careful CA scoping because an unmapped but CA-trusted certificate can still authenticate as a raw certificate subject.
- Multi-provider conflict resolution is observable but still follows OpenLDAP's last-write/CSN behavior; ldapium does not invent a distributed consensus layer on top of it.
- SIEM export tooling is batch-oriented: `scripts/ship-audit-log.sh` ships NDJSON batches with retry/dead-letter and cursor persistence to HTTP sinks; real-time background push daemonization is delegated to platform log forwarders.
- Audit retention is bifurcated: `cn=accesslog` purge age is configurable via `LDAP_ACCESSLOG_PURGE_DAYS` (default 30 days) in `image/entrypoint.sh` (with a fixed 1-hour purge cycle in `olcAccessLogPurge`), whereas `auditlog` writes to `LDAP_AUDIT_FILE` (default `/dev/stdout`) with no OpenLDAP-native retention or log rotation mechanism, leaving file management to container/host log shippers.
- The management REST API (`ui/backend`) has no internal role-based access engine: requests are gated by session cookie validation (`requireSession` in `ui/backend/internal/httpapi/middleware.go` and `server.go`), plus, only when `MACHINE_AUTH_ENABLED=true`, a bearer path with its own static scope allowlist: eight read-only GET operations, and with `MACHINE_WRITE_ENABLED` the opt-in write operations (see the machine sections above). In default LDAP login mode, operations execute over the user's bound LDAP connection and are authorized by OpenLDAP's own ACLs; in SSO mode, the backend binds using `LDAP_SERVICE_ACCOUNT_DN`, meaning all authenticated Keycloak users with `SSO_ADMIN_ROLE` share the service account's directory permissions (see `ui/README.md`).
- The Helm chart is completely cloud-provider agnostic: defaults in `charts/ldapium/values.yaml` specify `service.type: ClusterIP` and default `storageClassName: ""` with no cloud-specific annotations, validated by continuous Kind-based CI (`.github/workflows/e2e.yml`) and air-gapped bundle installations using `imagePullPolicy=Never` (`scripts/offline-install.sh`).

## Related evidence

- `README.md`
- `charts/ldapium/README.md`
- `docs/ha-profile.md`
- `docs/migration.md`
- `docs/product-boundary.md`
- `docs/pam-boundary.md`
- `docs/client-compatibility.md`
- `docs/air-gap.md`
- `docs/encryption-at-rest.md`
- `docs/scale-benchmarks.md`
- `docs/audit-event-schema.md`
- `docs/api.md`
- `docs/ui-operations.md`
- `docs/machine-keycloak-client.md`
- `docs/machine-auth-operations.md`
- `docs/machine-write-account.md`
- `docs/changes/machine-principal-auth/ADR.md`
- `docs/changes/CLOSE-OUT-2026-10.md`
- `docs/incident-evidence.md`
- `.github/workflows/e2e.yml`
- `.github/workflows/security-e2e.yml`
- `.github/workflows/machine-write-e2e.yml`
- `.github/workflows/replication-chaos-e2e.yml`
- `.github/workflows/bench-profile.yml`
- `.github/workflows/bench-lifecycle.yml`

Refresh this document only from merged implementation and reproducible evidence.
