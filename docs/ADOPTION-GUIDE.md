# ldapium Adoption Guide

> First success means a client can perform the intended LDAP operation with the expected TLS/authentication/ACL behavior. Pod readiness alone is not enough.

## 1. Choose an entry path

Use Docker Compose for the smallest local evaluation and Helm for Kubernetes adoption. Keep standalone and multi-provider replication evaluations separate.

## 2. First verified success

1. Start ldapium using the documented local or Helm path.
2. Verify LDAP/LDAPS reachability using the intended client trust configuration.
3. Perform a real bind with a non-root test identity.
4. Create/read/update a bounded test entry according to the configured ACL.
5. Verify an operation that should be denied is actually denied.
6. For Helm, run the chart's behavior-oriented test path rather than stopping at pod readiness.
7. Inspect audit/access evidence for the operation.

## 3. Expand only after the baseline

After standalone behavior is verified, evaluate replication, backup/restore, Keycloak/OIDC integration, air-gap operation, rolling upgrades, or mTLS/SASL EXTERNAL independently. Each has a different trust and evidence boundary.

## 4. Read next

- `docs/IMPLEMENTATION-STATUS.md` — merged/verified capability snapshot
- `charts/ldapium/README.md` — Helm adoption
- `docs/client-compatibility.md` — client behavior
- `docs/air-gap.md` — offline operation
- `docs/encryption-at-rest.md` — storage-layer boundary
- `docs/scale-benchmarks.md` — reference measurements
- `docs/incident-evidence.md` — incident-evidence export, redaction guarantee, read-only RCA contract

## 5. Claims to keep precise

ldapium does not claim OpenLDAP MDB transparent encryption at rest, FIPS validation, or a consensus layer beyond OpenLDAP replication semantics. Published-artifact instructions should be treated as verified only when the referenced release/image actually exists.