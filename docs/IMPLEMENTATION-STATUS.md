# Current Implementation Status

Last verified: 2026-09-14 against `main`, except the "External HTTP API" section, which was added 2026-10-06 against `main` at `6c118ac` from the audit in `docs/changes/CLOSE-OUT-2026-10.md` and the code, tests and PR history it cites (the live Docker scripts were not re-run for it).

This snapshot records features already merged to `main`. Open pull requests and issue-only roadmap items are intentionally excluded.

## Product boundary

ldapium packages upstream OpenLDAP 2.6.14 for modern Kubernetes/container operation. It combines a source-built server image, optional management UI, Helm chart, Docker Compose path, backup/restore, air-gap tooling and release/supply-chain evidence.

## Directory / replication

- OpenLDAP 2.6.14 built from upstream source
- MDB backend
- memberOf / refint / ppolicy / unique / syncprov overlays
- standalone and multi-provider replication paths
- replication chaos testing, including real network partition and same-entry conflict behavior
- raw replication CSN discard evidence in the audit export with entryUUID objectId correlation
- HA topology governance (D11-D13): Active-Active N-Way multi-provider, reference RPO/RTO SLAs, cross-site DR via backup shipping
- Prometheus alert rules for replication lag, ContextCSN divergence, and exporter health

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
- backup job IDs, `GET`/`cancel` job endpoints, durable job records, orphan-aware restart recovery, per-kind deadline (#217, PR #236)

Boundaries:

- `If-Match` is evaluated on the receiving node only; against multi-provider replication it is optimistic protection, not consensus.
- Core-write idempotency records live in process memory and are lost on restart, so the chart enables them for a single UI replica only. Backup-start keys are the exception: they are stored in the durable job record.
- The web UI does not send `If-Match` or `Idempotency-Key` and still pages Users and Groups on the client (#216 REQ-013 and #215 AC-010 are open).
- Remote backup destinations (S3/FTP/SFTP), the SIGKILL-after-grace path and the job deadline path are covered by unit tests only; they have not been run live (#255 stays open for that).
- Live evidence for these features is in the packages' `EVIDENCE*.md` files (local Docker runs); the CI workflows named there were not re-run for this section.

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
- The management REST API (`ui/backend`) has no internal role-based access engine: requests are gated by session cookie validation (`requireSession` in `ui/backend/internal/httpapi/middleware.go` and `server.go`). In default LDAP login mode, operations execute over the user's bound LDAP connection and are authorized by OpenLDAP's own ACLs; in SSO mode, the backend binds using `LDAP_SERVICE_ACCOUNT_DN`, meaning all authenticated Keycloak users with `SSO_ADMIN_ROLE` share the service account's directory permissions (see `ui/README.md`).
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
- `docs/changes/CLOSE-OUT-2026-10.md`
- `docs/incident-evidence.md`
- `.github/workflows/e2e.yml`
- `.github/workflows/security-e2e.yml`
- `.github/workflows/replication-chaos-e2e.yml`
- `.github/workflows/bench-profile.yml`
- `.github/workflows/bench-lifecycle.yml`

Refresh this document only from merged implementation and reproducible evidence.
