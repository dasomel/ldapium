# Product boundary

ldapium is a single LDAPv3 directory: upstream OpenLDAP packaged for Kubernetes
plus a thin management UI. It deliberately does not ship, and will not grow:
a multi-directory federation or sync engine, a Source-of-Authority/matching/merge
engine, a SCIM server or client, an IGA connector framework (SPI, retry/dead-letter,
reconciliation engine), a PAM/JIT/JEA request workflow or credential vault, a
SPIFFE/SPIRE integration, or a ChatOps/AI remediation executor.

This document establishes maintainer decision D1 as the binding product boundary.
Where integration requirements touch these capabilities, the boundary itself is
the deliverable: external products own their respective lifecycles and interact
with ldapium exclusively over LDAPv3 (`ldap://`, `ldaps://`, `ldapi://`) and
pull-based audit exports.

## What ldapium is

ldapium packages upstream OpenLDAP 2.6.14 compiled directly from source
(`image/Dockerfile`) for Kubernetes and container environments. It provides:

- A directory server running OpenLDAP's `back-mdb` storage engine with compiled
  standard overlays: `memberof`, `refint`, `ppolicy`, `unique`, `syncprov`,
  `accesslog`, and `auditlog` (`image/ldifs/01-cn-config.ldif`).
- Packaging for Kubernetes via a Helm chart (`charts/ldapium`) supporting single-node
  operation and N-way multi-provider replication (`image/entrypoint.sh`).
- A lightweight management web application (`ui/backend`) providing a DIT browser,
  user/group management, and password controls. The UI operates with no local database:
  it proxies actions over direct LDAP binds or gates access via Keycloak OIDC SSO.
- Operational tooling for deterministic offline backup (`scripts/backup.sh`),
  disaster recovery restore (`scripts/restore.sh`), and unified audit trail export
  (`scripts/export-audit-log.sh`).

## Deliberate non-goals (what ldapium does not ship)

Every capability listed below is intentionally excluded from ldapium's core. Each
belongs in a dedicated external product class that integrates over standard
directory interfaces:

- **Multi-directory federation and sync engine**: Multi-forest, multi-vendor, or
  cloud-to-on-premise directory synchronization belongs in an external Identity
  Provider (IdP) such as Keycloak, Ping, or an enterprise directory synchronization
  broker. That external system federates identities by issuing standard LDAPv3
  `bind`, `search`, `modify`, and `modrdn` requests against ldapium.
- **Source-of-Authority (SoA), matching, and merge engine**: Resolving identity
  conflicts, matching person records across HR systems, and calculating authoritative
  attributes belongs in an external HRIS pipeline or Identity Governance and
  Administration (IGA) platform. The authoritative system pushes reconciled attribute
  updates to ldapium over standard LDAPv3 write operations.
- **SCIM server or client**: Translating between RESTful SCIM 2.0 schemas and LDAP
  attributes belongs in an external SCIM bridge, modern IdP, or cloud directory
  gateway. That gateway translates inbound/outbound SCIM requests into standard
  LDAPv3 operations against ldapium.
- **IGA connector framework**: Plugin Service Provider Interfaces (SPIs), retry
  loops, reconciliation schedules, and dead-letter queues belong in an enterprise
  IGA suite (e.g., MidPoint, SailPoint). The IGA suite reconciles against ldapium
  using standard LDAPv3 search/modify operations and consumes change events from
  ldapium's audit NDJSON export.
- **PAM, JIT/JEA workflows, and credential vaults**: Just-in-time privilege elevation,
  just-enough-administration request approvals, and password rotation vaults belong
  in a dedicated Privileged Access Management (PAM) system (e.g., HashiCorp Vault,
  CyberArk). The external vault rotates passwords by issuing standard LDAP `modify`
  requests on `userPassword` (see [docs/pam-boundary.md](pam-boundary.md)).
- **SPIFFE/SPIRE integration**: Workload identity issuance and short-lived X.509
  SVID lifecycle management belong in an external SPIFFE/SPIRE control plane. ldapium
  authenticates workload certificates at the TLS transport boundary via SASL
  `EXTERNAL` using `olcAuthzRegexp` identity mapping (`image/entrypoint.sh`).
- **ChatOps and AI remediation executors**: Conversational operations bots and
  autonomous remediation agents belong in external SecOps, ITSM, or monitoring
  platforms. These tools pull ldapium's NDJSON audit export (`scripts/export-audit-log.sh`)
  or monitor metrics (`/metrics`) and invoke operational actions via standard Kubernetes
  or LDAP APIs.

## Obligations at the integration boundary

To allow external systems to integrate cleanly, ldapium guarantees specific behaviors
at its boundary:

1. **Stable, documented schema**:
   The directory bootstraps standard schemas: `core`, `cosine`, `inetorgperson`, and
   `nis` (`image/ldifs/01-cn-config.ldif:51-58`), providing standard structural
   classes (`inetOrgPerson`, `organizationalRole`, `dcObject`, `organization`) and
   POSIX/group schemas (`posixAccount`, `posixGroup`, `groupOfNames`). Overlays define
   standard attributes: `memberOf` via `memberof.la`, `pwdAccountLockedTime` via
   `ppolicy.la`, and attribute uniqueness via `unique.la`.
2. **Deny-by-default ACLs**:
   OpenLDAP access controls (`image/ldifs/01-cn-config.ldif:86-102` and
   `image/entrypoint.sh:563-588`) deny anonymous read to user data by default,
   allowing only naming discovery (`entry`, `uid`, `objectClass`). Attribute-level
   rules protect `userPassword` against unauthenticated reads and cross-user snooping.
   Subtree scoping (`LDAP_ANONYMOUS_READ_BASE`) is verified by negative tests in
   `.github/workflows/security-e2e.yml`.
3. **Actor-attributed audit and access export**:
   Write operations are captured via `slapo-auditlog` (`LDAP_AUDIT_ENABLED=true`),
   recording actor DN, timestamp, target entry, and changes. Read and bind operations
   are captured via `slapo-accesslog` (`LDAP_ACCESSLOG_ENABLED=true`). Both streams
   are extractable into unified NDJSON via `scripts/export-audit-log.sh`.
4. **Deterministic offline seed and restore**:
   First-launch initialization deterministically loads LDIF files from `LDAP_SEED_DIR`
   (`/opt/ldifs`, configured in `image/entrypoint.sh:88` and `charts/ldapium` `seed.ldifs`).
   Disaster recovery restores full directory and configuration state from offline backup
   archives using `scripts/restore.sh`, verified in `.github/workflows/backup-restore.yml`.
5. **Explicit documentation of unsupported combinations**:
   Unsupported client mechanisms and protocols are explicitly declared rather than
   left ambiguous. This includes unconfigured SASL mechanisms, lack of Active
   Directory Kerberos/GPO protocol emulation (`docs/client-compatibility.md`), lack of
   push-based SIEM streaming, and strict CA requirements under mutual TLS.

## Capability touchpoint matrix

| External capability | External product class | ldapium touchpoint | Evidence / Reference |
|---|---|---|---|
| Multi-directory sync & federation | IdP (Keycloak, Ping, Okta) | LDAPv3 bind, search, modify | `ui/README.md`, `charts/ldapium/README.md` |
| Source of Authority & merge | HRIS / IGA engine | LDAPv3 add, modify, delete | `image/entrypoint.sh`, `image/ldifs/01-cn-config.ldif` |
| SCIM protocol gateway | SCIM server / bridge | Standard LDAPv3 CRUD | `image/ldifs/01-cn-config.ldif` |
| IGA connector & reconciliation | IGA suite (MidPoint, SailPoint) | LDAPv3 + NDJSON audit export | `scripts/export-audit-log.sh` |
| PAM & credential vault | Secrets vault (Vault, CyberArk) | LDAPv3 modify (`userPassword`) | `docs/pam-boundary.md` |
| Workload identity (SPIFFE/SPIRE) | SPIRE agent / control plane | mTLS / SASL `EXTERNAL` | `image/entrypoint.sh`, `docs/client-compatibility.md` |
| ChatOps & remediation | ITSM / SIEM / AIOps platform | Pull NDJSON audit export | `scripts/export-audit-log.sh` |

## Migration and cutover stance

ldapium is a single directory with no internal Source of Authority (SoA) engine.
It does not merge records across upstream directories or resolve multi-master identity
discrepancies.

Migration into ldapium is supported strictly through standard LDIF export/import and
offline backup/restore tooling:

- **Initial migration**: Operators export source directory entries to standard LDIF,
  reconcile any schema differences against ldapium's loaded schemas, and mount the
  resulting files into `LDAP_SEED_DIR` (`/opt/ldifs`) before first launch.
- **Bulk data loading and disaster recovery**: Existing directory archives are restored
  using `scripts/restore.sh`, which loads database and configuration LDIF dumps
  offline via `slapadd`. This path is tested in `.github/workflows/backup-restore.yml`.

ldapium provides no dual-write engine, no live synchronization proxy, and no staged
canary cutover engine. Transitioning from an existing directory requires an external
cutover procedure (e.g., quiesce writes on legacy directory, export final LDIF, import
into ldapium, switch DNS or service endpoints).
