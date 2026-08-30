# Current Implementation Status

Last verified: 2026-08-28 against `main`.

This snapshot records features already merged to `main`. Open pull requests and issue-only roadmap items are intentionally excluded.

## Product boundary

ldapium packages upstream OpenLDAP 2.6.14 for modern Kubernetes/container operation. It combines a source-built server image, optional management UI, Helm chart, Docker Compose path, backup/restore, air-gap tooling and release/supply-chain evidence.

## Directory / replication

- OpenLDAP 2.6.14 built from upstream source
- MDB backend
- memberOf / refint / ppolicy / unique / syncprov overlays
- standalone and multi-provider replication paths
- replication chaos testing, including real network partition and same-entry conflict behavior
- raw replication CSN discard evidence in the audit export

## TLS and authentication hardening

- LDAPS support with strict certificate verification
- TLS 1.2 protocol floor via `olcTLSProtocolMin`
- explicit TLS 1.2 cipher-suite baseline
- certificate expiry and rotation E2E
- two-step CA rotation verification
- StartTLS on port 389 verified in CI
- optional mTLS / SASL EXTERNAL mapping with documented CA-boundary caveat
- failed-login rate limiting in the management UI

## Authorization / audit

- deny-by-default LDAP ACL boundaries with live negative tests
- optional subtree scoping for anonymous UID/objectClass discovery
- auditlog write attribution
- accesslog for reads and binds, including failed binds
- unified NDJSON export across audit/access/replication-conflict sources
- rootdn vs ordinary-user actor distinction verified
- HTTP 500 error redaction with request correlation
- `userPassword` redaction from generic DIT browser responses

## UI / client integration

- DIT browser
- user/group create, edit and delete
- password change / reset
- account lock/unlock
- organizational metadata fields
- cn=Monitor health view
- unauthenticated LDAP reachability health endpoint
- browser-driven Playwright E2E against a real directory
- Keycloak/OIDC integration path

## Operations / resilience

- scheduled backup with integrity manifest
- restore tooling and 3-node DR exercise
- real-version rolling upgrade coverage (previous OpenLDAP -> current)
- write-availability sampling during upgrade
- offline bundle verification with `imagePullPolicy=Never`
- cn=config drift detection
- local scale benchmark tooling and documented 20K / 1M reference measurements
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

## Related evidence

- `README.md`
- `charts/ldapium/README.md`
- `docs/client-compatibility.md`
- `docs/air-gap.md`
- `docs/encryption-at-rest.md`
- `docs/scale-benchmarks.md`
- `.github/workflows/e2e.yml`
- `.github/workflows/security-e2e.yml`
- `.github/workflows/replication-chaos-e2e.yml`

Refresh this document only from merged implementation and reproducible evidence.