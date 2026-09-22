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
with ldapium over LDAPv3 (`ldap://`, `ldaps://`, `ldapi://`), its pull-based
audit export, or the operator-invoked batch HTTPS audit shipper.

## What ldapium is

ldapium packages upstream OpenLDAP 2.6.15 compiled directly from source
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
  SVID lifecycle management belong in an external SPIFFE/SPIRE control plane.
  ldapium's generic TLS client-certificate authentication can map a certificate
  subject DN through SASL `EXTERNAL` and `olcAuthzRegexp` (`image/entrypoint.sh`),
  but it does not validate SPIFFE IDs or issue SVIDs.
- **ChatOps and AI remediation executors**: Conversational operations bots and
  autonomous remediation agents belong in external SecOps, ITSM, or monitoring
  platforms. These tools pull ldapium's NDJSON audit export or operators deliver it in
  batches with `scripts/ship-audit-log.sh`; they monitor metrics (`/metrics`) and invoke
  operational actions via standard Kubernetes or LDAP APIs.

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
   a resident real-time SIEM push daemon (the batch shipper is operator-invoked), and
   strict CA requirements under mutual TLS.
6. **Change-origin metadata for federation and sync loop prevention**:
   When external federation, synchronization, or IGA engines consume changes from
   ldapium — whether via LDAPv3 protocol (direct LDAP replication or connector polling)
   or audit export (NDJSON) — they integrate against ldapium's published change-origin
   contract. This contract specifies the metadata available to external systems for
   detecting and preventing replay loops, deduplicating redundant syncs, and implementing
   idempotent reconciliation.
   
   ldapium **does not ship a loop-prevention or conflict-resolution engine**; those
   responsibilities belong to the external federation product. However, ldapium
   guarantees specific metadata in every change event to enable this integration:

   - **`source`**: One of `auditlog` (writes captured by OpenLDAP), `accesslog` (reads/binds),
     or `replication-conflict-raw` (CSN discard diagnostics) in audit export mode. In direct
     LDAP protocol mode, an external engine tracks changes using OpenLDAP's native operational
     attributes (`modifiersName`, `modifyTimestamp`, `creatorsName`, `createTimestamp`)
     instead.
   - **`entryUUID`** (direct LDAP protocol mode): Globally unique, immutable per-entry
     identifier generated and maintained by OpenLDAP (`entryUUID` attribute). This is the
     authoritative identity key for deduplication across syncs and is returned in all LDAP
     search responses unless the caller lacks read permission on the attribute. The audit
     NDJSON export also carries an `entryUUID`/`objectId` field on `auditlog`-sourced
     (write) events, but `accesslog`-sourced (read/bind) events carry no `entryUUID`-equivalent
     (`docs/audit-event-schema.md`).
   - **`entryCSN`** and **`contextCSN`** (direct LDAP protocol mode only — **not** present
     in the audit NDJSON export envelope; see `docs/audit-event-schema.md` for the export's
     actual field set). `entryCSN` (Change Sequence Number) is OpenLDAP-assigned, a
     server-unique timestamp and sequence counter attached to every entry upon creation and
     updated on every modification. Format: `20260904080000.000000Z#000000#000#000000`
     (GeneralizedTime YYYYMMDDHHMMSS.ffffffZ with microseconds, server-id fragment,
     change-id sequence) — the per-entry causality token for ordering and deduplication,
     indexed for efficient polling. `contextCSN` is the maximum `entryCSN` achieved by the
     directory at a point in time, maintained on the root DN entry. An engine consuming
     ldapium over LDAP protocol (not audit export) uses these for watermark-based change
     polling: query the root DN, read `contextCSN`, and in the next sync run, retrieve only
     entries with `entryCSN` greater than the previously stored watermark. This enables
     partial, resumed, and idempotent sync recovery after connector restart. An engine
     consuming only the audit export must instead correlate on `entryUUID`/target DN and
     event timestamp, per the "Limits and non-guarantees" below.
   - **Audit `source` field** (NDJSON export only): When consuming audit export via
     `scripts/export-audit-log.sh`, each event carries a `source` field identifying
     whether the change originated in `auditlog` (a write operation initiated by an
     external client), `accesslog` (a read/search), or `replication-conflict-raw`
     (an internal replication conflict/discard). This distinguishes client-initiated
     changes from replication artifacts.

   **Implementing loop detection**: An external federation engine consuming changes from
   ldapium must track the *source* of each change to avoid re-applying its own outbound
   writes back to ldapium (a loop). The recommended pattern:
   1. Assign a stable identity to the connector (e.g., bind DN, service account name).
   2. When ldapium emits a change via LDAP or audit export, check the audit actor
      (`actor` field) or LDAP `modifiersName`/`creatorsName` attributes.
   3. If the actor matches the connector's own bind identity, skip re-propagation of that
      change to other directories (it is an echo from a prior outbound write).
   4. For changes from other actors (human administrators, other connectors, upstream
      IdPs), apply transformation rules and propagate to peer directories.

   **Implementing idempotent replay**: Undelivered changes (lost network connection,
   connector crash) are recovered by re-running the sync from the last known
   `contextCSN` watermark:
   1. Before each sync run, query the root DN: `ldapsearch -b <rootDN> -s base contextCSN`.
   2. Store the returned `contextCSN` value after successful sync completion.
   3. On restart, query entries with `(entryCSN>=<stored-contextCSN>)` to re-fetch
      potentially missed changes.
   4. Use `entryUUID` and the entry's current state to deduplicate and idempotently
      apply any duplicate deliveries.

   **Limits and non-guarantees**:
   - ldapium does *not* assign change events a client-supplied request id or correlation
     id across LDAP protocol and audit export; the external system must correlate via
     entry identity (`entryUUID`, target DN) and timestamp.
   - `entryCSN` is server-assigned and reflects OpenLDAP's local causality, not
     cross-cluster wall-clock time. Two concurrent writes on different providers in an
     N-way replicated cluster may have entryCSN timestamps in any order; the consumer
     must not assume timestamp order implies logical causality.
   - OpenLDAP's multi-provider replication uses `entryCSN` for conflict resolution
     (last-write-wins by timestamp), not application-level conflict detection. Genuine
     same-entry conflicts on different providers are resolved silently by the larger
     `entryCSN` value, with no explicit conflict log entry to the external consumer.
     The `replication-conflict-raw` audit source reports *discarded* CSNs (losing writes)
     but mixes genuine conflicts with harmless relay duplicates; external systems must
     correlate with directory state rather than treating every discard as confirmed
     data loss.
   - Audit export mode (NDJSON) provides pull-based snapshots; there is no persistent
     server-side cursor or subscription. Consumers implement their own watermarking
     and retry logic (see `scripts/ship-audit-log.sh` for a reference implementation).

   **Quarantine of ambiguous/conflicting objects**: ldapium **does not ship a
   quarantine mechanism** (a holding state that withholds an ambiguous or
   conflicting object from normal read/sync paths pending manual or policy-driven
   resolution) — that responsibility belongs to the external federation/IGA engine,
   consistent with "ldapium does not ship a loop-prevention or conflict-resolution
   engine" above. ldapium's role is limited to supplying the raw signal a quarantine
   decision is built on, and to never silently hiding a quarantined object from an
   authorized reader:

   - **Signal available**: the `replication-conflict-raw` audit source
     (`docs/audit-event-schema.md`) reports discarded CSNs from OpenLDAP's
     multi-provider `entryCSN`-based conflict resolution, resolved to an `objectId`
     (`entryUUID`) at export time. As documented above, this is a *discard*
     diagnostic, not a confirmed-conflict detector — it mixes genuine same-entry
     conflicts with harmless syncrepl relay duplicates. An external engine treats
     each `replication-conflict-raw` event as a candidate for quarantine
     triage, not a verdict.
   - **No suppression of quarantined entries**: ldapium has no concept of a
     "quarantined" object state. An object an external engine has flagged
     ambiguous or conflicting remains fully readable/writable in ldapium under
     normal ACLs — LDAP protocol reads are not filtered based on any
     external-engine quarantine decision. The external engine owns holding that
     object out of *its own* propagation/sync pipeline; it must not expect
     ldapium to enforce that hold.
   - **Marking pattern**: ldapium provides no dedicated attribute for
     recording quarantine state. An external engine that needs to persist a
     quarantine marker on the ldapium side does so the same way any other
     externally-owned attribute is written — as an ordinary `modify` under the
     per-attribute single-writer convention ("Multi-directory topology and
     source-of-authority contract", `docs/client-compatibility.md`), using an attribute the
     engine itself owns (e.g. a custom auxiliary class/attribute registered by
     the operator), never a resident ldapium schema attribute.
   - **Recommended pattern**: on receiving a `replication-conflict-raw` event
     (or observing divergent `entryCSN`/attribute state for the same
     `entryUUID` across providers), the external engine (1) holds that object
     out of outbound propagation, (2) resolves the conflict per its own
     precedence/merge policy, (3) applies the resolved state via a normal
     LDAP `modify`, and (4) releases the hold. ldapium supplies the discard
     signal and the post-resolution write path; it performs none of steps 1–4
     itself.

   **Duplicate/collision preflight gate**: ldapium **does not ship a
   cross-directory duplicate/collision detector** — deciding whether an
   incoming federated identity collides with one already sourced from a
   different upstream is a source-of-authority/merge-policy decision that
   belongs to the external federation engine, consistent with "ldapium does
   not ship a loop-prevention or conflict-resolution engine" above. What
   ldapium provides is a same-node, write-time uniqueness check the external
   engine can use as one input to its own preflight gate, plus the honest
   limits of that check:

   - **Signal available**: the `unique` overlay (`LDAP_UNIQUE_ATTRIBUTES`,
     default `uid,mail`; `image/entrypoint.sh:599-630`,
     `image/ldifs/01-cn-config.ldif:30`) rejects an `Add`/`Modify` on a
     single node that would create a second `(objectClass=inetOrgPerson)`
     entry sharing a value with an existing entry, on any attribute listed
     (`image/README.md`, "Uniqueness enforcement"). Each listed attribute is
     its own independent uniqueness domain — one `olcUniqueURI` per
     attribute, not a combined-key check.
   - **Not a cross-directory gate**: the overlay only ever sees entries
     written to the local ldapium node; it has no knowledge of identities
     held by peer directories, upstream IdPs, or other federation
     endpoints. An external engine cannot rely on it to catch a collision
     between an incoming synced identity and a record that originates
     entirely outside ldapium — that comparison has to happen in the
     engine's own identity store before it ever issues the write.
   - **Not a cluster-wide gate under multi-provider replication**: per
     `image/README.md`, "Uniqueness enforcement", two nodes accepting writes
     for the same value at the same time each pass their own local check
     before either write has replicated, so both can succeed and the
     duplicate surfaces only after sync — visible afterward as a
     `replication-conflict-raw` discard (see "Quarantine of
     ambiguous/conflicting objects" above), not prevented up front.
   - **Bypassed by offline paths**: `slapadd`-based bootstrap and restore
     (`scripts/restore.sh`) write straight to the database file with no
     overlay in the path, so bulk/offline loads carry no duplicate
     protection at all — the external engine's own preflight check is the
     only gate for those paths.
   - **Recommended pattern**: an external federation engine performs its own
     duplicate/collision check against its cross-directory identity store
     *before* issuing a write to ldapium (using `entryUUID`/target DN
     correlation per the change-origin contract above), and treats
     ldapium's `unique` overlay purely as a same-node backstop — a rejected
     write is evidence a check was missed, not the primary detection
     mechanism, and per-attribute `LDAP_UNIQUE_ATTRIBUTES` scope
     (`uid,mail` by default) must match the attributes the engine's own
     collision policy actually cares about or the backstop silently doesn't
     cover them.

   **Audit evidence for authority/conflict decisions**: every metadata
   element an external engine needs to justify *why* it made a given
   authority or conflict decision is already covered above and in
   `docs/audit-event-schema.md`; this subsection collects the pointers so
   the evidence trail doesn't have to be reconstructed from scratch:

   - **Which change fired the decision**: the audit envelope's `source`,
     `actor`, `target`, `op`, and `correlationId` fields
     (`docs/audit-event-schema.md`, "The envelope") identify the write
     (`auditlog`), read/bind (`accesslog`), or discard
     (`replication-conflict-raw`) that a downstream decision was based on.
     `correlationId` is deterministic and reproducible across re-export
     (`docs/audit-event-schema.md`, "correlationId"), so a logged decision
     can be traced back to the exact record that triggered it even after a
     re-run.
   - **Which entry was affected**: `objectId` (resolved `entryUUID`) is
     populated for `auditlog` writes when the LDIF body carries it, and for
     `replication-conflict-raw` discards via
     `scripts/lib/resolve-conflict-objectid.py`'s DN-to-`entryUUID`
     resolution at export time (`docs/audit-event-schema.md`, "objectId").
     `accesslog` reads carry no `entryUUID`-equivalent — a decision based
     solely on a read/search record cannot cite a resolved object identity
     and must fall back to `target` (the requested DN).
   - **Why a write was accepted or rejected as a duplicate**: an `Add`
     rejected by the `unique` overlay (see "Duplicate/collision preflight
     gate" above) is itself a failed write; ldapium's audit surfaces show
     the attempt via the normal `auditlog`/`accesslog` path exactly as any
     other operation, with no separate "rejection reason" field — the
     external engine records *why* it attempted or blocked a write in its
     own decision log, using ldapium's `correlationId`/`objectId` only to
     cite *which* ldapium-side event the decision corresponds to.
   - **What ldapium does not provide as evidence**: no built-in
     signature/attestation over audit records, no server-side decision or
     approval log, and no request-scoped correlation id shared across LDAP
     protocol and audit export (see "Limits and non-guarantees" above) — an
     external engine's audit trail for its own authority/conflict decisions
     must be assembled and retained on its own side, with ldapium's export
     as one cited input, not the system of record for the decision itself.

## Capability touchpoint matrix

| External capability | External product class | ldapium touchpoint | Evidence / Reference |
|---|---|---|---|
| Multi-directory sync & federation | IdP (Keycloak, Ping, Okta) | LDAPv3 bind, search, modify | `ui/README.md`, `charts/ldapium/README.md` |
| Source of Authority & merge | HRIS / IGA engine | LDAPv3 add, modify, delete | `image/entrypoint.sh`, `image/ldifs/01-cn-config.ldif` |
| SCIM protocol gateway | SCIM server / bridge | Standard LDAPv3 CRUD | `image/ldifs/01-cn-config.ldif` |
| IGA connector & reconciliation | IGA suite (MidPoint, SailPoint) | LDAPv3 + NDJSON audit export | `scripts/export-audit-log.sh` |
| PAM & credential vault | Secrets vault (Vault, CyberArk) | LDAPv3 modify (`userPassword`) | `docs/pam-boundary.md` |
| Workload identity (SPIFFE/SPIRE) | SPIRE agent / control plane | Generic mTLS subject-DN → SASL `EXTERNAL` mapping; no SPIFFE support | `image/entrypoint.sh`, `docs/client-compatibility.md` |
| ChatOps & remediation | ITSM / SIEM / AIOps platform | Pull NDJSON export or operator-invoked batch HTTPS shipper | `scripts/export-audit-log.sh`, `scripts/ship-audit-log.sh` |

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
