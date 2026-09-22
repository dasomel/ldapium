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

   **Live-verified: ldapium's own replication layer under conflict and restart**: The
   two subsections above are guidance for an *external* federation engine building its
   own loop detection and idempotent replay against ldapium's LDAP/audit surface — no
   such engine ships with ldapium (see "Deliberate non-goals" above), so that guidance
   itself is untested by definition. What ldapium **does** ship, and does test in CI, is
   its own N-way multi-provider replication (`syncrepl` between ldapium peers), which is
   the closest thing to a "connector" ldapium has any control over. Two scenarios in
   `.github/workflows/replication-chaos-e2e.yml` exercise exactly the properties an
   external engine would otherwise have to take on faith:
   - **Bidirectional same-entry conflict**: "Partition one provider and modify the SAME
     entry on both sides" (`replication-chaos-e2e.yml:437-473`) partitions one of three
     providers with `iptables`, writes a different `description` value to the *same*
     entry on the majority and minority sides while genuinely partitioned (verified by
     reading both sides back and asserting they disagree, not just trusting the
     partition held), then "Heal the partition and confirm the conflict resolved
     silently" (`replication-chaos-e2e.yml:482-521`) heals it and polls all three
     providers until they agree. The outcome — confirmed live, not assumed — is
     `entryCSN` last-write-wins: exactly one of the two writes survives on every
     provider, never a merge or corruption, and this happens with **no error and no
     conflict record** (`replication-chaos-e2e.yml:520`, tracked as a detectability gap
     in #22, not a correctness bug).
   - **Replay/idempotency after a provider restart**: "Delete one provider"
     (`replication-chaos-e2e.yml:213-221`) kills one of three providers, "Continue writes
     while one provider is down" (`replication-chaos-e2e.yml:224-238`) issues five new
     entries against the *surviving* providers during the outage, "Wait for failed
     provider to rejoin" (`replication-chaos-e2e.yml:240-262`) waits for the killed pod
     to become Ready again (its `syncrepl` consumer reconnects and replays from its
     last `contextCSN` watermark on its own — nothing in the test drives that replay
     manually), and "Verify convergence on all three providers"
     (`replication-chaos-e2e.yml:319-328`) then asserts all three providers report
     **exactly 5** matching entries — not fewer (proving the replay wasn't lost) and not
     more (proving the rejoin didn't duplicate anything already applied before the
     restart). This is real restart-and-replay idempotency, live-verified, not a design
     claim.
   - **Scope**: both scenarios prove ldapium's own peer-to-peer replication is robust to
     partition and restart. They do **not** prove anything about a third-party federation
     connector's replay logic against ldapium's LDAP/audit surface — that remains the
     external engine's own responsibility per the guidance above, and per "Deliberate
     non-goals", ldapium ships no such connector to test in the first place.

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

   **Deterministic matching and merge/split policy**: ldapium **does not
   ship an identity matching, merge, or split engine** — deciding whether
   records across disjoint systems represent the same physical person
   (matching), synthesizing composite profiles across multiple data
   sources (merging), or disentangling previously coalesced records upon
   discovering an identity collision or divergence (splitting) are
   Source-of-Authority (SoA) and Identity Governance (IGA) responsibilities
   that belong to an external IdP, IGA platform, or synchronization broker,
   consistent with "ldapium does not ship a loop-prevention or
   conflict-resolution engine" above. What ldapium guarantees is the set
   of stable correlation keys and write-time constraints on its LDAPv3
   surface that an external engine can deterministically evaluate against,
   alongside the explicit non-goals of the directory:

   - **Correlation keys exposed by ldapium**:
     - **Immutable hard-match key (`entryUUID`)**: RFC 4530 operational
       attribute (`1.3.6.1.1.16.1.4`), server-generated upon entry creation
       and indexed for equality searches (`image/ldifs/01-cn-config.ldif:77`).
       Immutable across entry modifications, attribute updates, and tree
       moves (`modrdn`). Returned in LDAP search responses when requested
       explicitly or via `+` operational attribute requests (subject to
       standard ACLs; `image/ldifs/01-cn-config.ldif:86-102` and
       `image/entrypoint.sh:563-588`). An external sync engine uses
       `entryUUID` as the authoritative anchor for 1:1 hard matching.
     - **Mutable uniqueness-enforced soft-match keys (`uid`, `mail`)**:
       Enforced at write time on a single node via OpenLDAP's `unique`
       overlay (`image/entrypoint.sh:166,599-630`,
       `image/ldifs/01-cn-config.ldif:30`), indexed via `olcDbIndex: uid eq`
       and `olcDbIndex: mail eq` (`image/ldifs/01-cn-config.ldif:79,81`).
       Guarantees that a write-time soft match on `(uid=<val>)` or
       `(mail=<val>)` resolves to at most one `(objectClass=inetOrgPerson)`
       entry on that node. The cluster-wide and offline limits documented
       under "Duplicate/collision preflight gate" above apply equally here.
     - **External immutable correlation attributes (e.g. `employeeNumber`)**:
       Included in ldapium's standard schema set via `cosine.ldif` and
       `inetorgperson.ldif` (`image/ldifs/01-cn-config.ldif:53,55`). An
       external IGA system can populate corporate employee identifiers into
       `employeeNumber` under the per-attribute single-writer convention
       ("Multi-directory topology and source-of-authority contract",
       `docs/client-compatibility.md`), using it as a secondary immutable
       correlation key without requiring schema changes.

   - **What ldapium explicitly does NOT decide (non-goals and engine limits)**:
     - **No fuzzy or heuristic matching**: ldapium provides no phonetic
       matching (Soundex, Metaphone), Levenshtein string distance, or
       probabilistic identity scoring algorithms. LDAP filter evaluation
       strictly adheres to RFC 4517 matching rules (exact equality or
       standard substring matching).
     - **No automated merge execution or attribute blending**: ldapium does
       not synthesize a composite entry from conflicting upstream records.
       When an external engine determines that two records match, that
       engine calculates the merged attribute values and writes them to
       ldapium via standard LDAP `modify` or `add` operations under the
       declared single-writer authority model (`docs/client-compatibility.md`).
     - **No automated record splitting**: If an external engine discovers
       that two distinct identities were erroneously merged into the same
       `entryUUID` (an identity conflation), ldapium provides no in-place
       splitting or un-merge primitive. The external engine must resolve the
       split by explicitly provisioning a new entry (which receives a new
       server-generated `entryUUID`) and pruning/updating attributes on the
       original entry via standard LDAPv3 operations.
     - **No cross-directory join queries**: ldapium never initiates queries
       to external directories (Active Directory, Entra ID, HR databases)
       to correlate records. All identity correlation is orchestrated by the
       external consumer before issuing writes to ldapium.

   - **Recommended pattern**: An external sync/federation engine implements
     a two-phase deterministic matching pipeline:
     1. *Phase 1 (Hard match)*: Query ldapium with `(entryUUID=<stored_uuid>)`.
        If found, link the identity directly without altering naming
        attributes.
     2. *Phase 2 (Soft match fallback)*: If no `entryUUID` matches, query
        uniqueness-enforced attributes `(uid=<username>)` or `(mail=<email>)`.
        If exactly one entry matches and satisfies the external engine's
        admission criteria, record its `entryUUID` as the persistent link.
     3. *Conflict routing*: If multiple entries match (e.g. if entries
        predate overlay activation or uniqueness scope was customized), or if
        correlated attributes disagree with upstream authority, route the
        candidate to external quarantine (see "Quarantine of
        ambiguous/conflicting objects" above); never attempt automated
        heuristic merging in ldapium.

   **Offline reproducible federation and convergence verification**: ldapium
   **does not ship an internal multi-directory federation engine or
   bidirectional synchronization daemon** (per "Deliberate non-goals" above
   and "Multi-directory topology and source-of-authority contract",
   `docs/client-compatibility.md`). Therefore, federation convergence cannot
   be verified as an internal OpenLDAP daemon loop. Instead, federation
   convergence is verified at the integration boundary against an external
   Identity Provider (Keycloak) via an offline, fully reproducible
   two-container end-to-end test suite
   (`.github/workflows/keycloak-federation-e2e.yml`):

   - **Offline reproducibility without external dependencies**: The test
     suite runs entirely on an isolated Docker bridge network (`kcfed`,
     `.github/workflows/keycloak-federation-e2e.yml:141-160`) combining
     `ldapium:e2e` with pinned Keycloak (`quay.io/keycloak/keycloak:26.0.7`,
     `.github/workflows/keycloak-federation-e2e.yml:41`), requiring no
     external internet connectivity, cloud infrastructure, or Kubernetes
     cluster.
   - **Initial federation and attribute/group convergence**: Keycloak
     configures an LDAP user storage provider (`uuidLDAPAttribute=["entryUUID"]`,
     `usernameLDAPAttribute=["uid"]`,
     `.github/workflows/keycloak-federation-e2e.yml:228-249`) with group and
     attribute mappers (`.github/workflows/keycloak-federation-e2e.yml:281-328`).
     Triggering initial sync (`triggerFullSync`,
     `.github/workflows/keycloak-federation-e2e.yml:355-360`) proves that
     federated user attributes (`alice`, `bob`,
     `.github/workflows/keycloak-federation-e2e.yml:364-376`) and group
     memberships (`developers`, `marketing`,
     `.github/workflows/keycloak-federation-e2e.yml:378-397`) converge
     deterministically with LDAP directory state, resulting in verified OIDC
     tokens and `groups` claims (`.github/workflows/keycloak-federation-e2e.yml:405-430`).
   - **Update convergence across sync**: Modifying group membership in
     ldapium (removing `bob` from `cn=developers` via `ldapmodify`,
     `.github/workflows/keycloak-federation-e2e.yml:514-520`) followed by
     re-sync (`triggerFullSync`,
     `.github/workflows/keycloak-federation-e2e.yml:525-528`) proves that
     Keycloak's federated group membership converges to `alice` only
     (`.github/workflows/keycloak-federation-e2e.yml:531-539`), demonstrating
     deterministic convergence of live directory updates upon re-sync.
   - **Deprovisioning and revocation convergence**: Locking an account in
     ldapium using the `pwdAccountLockedTime` sentinel (`000001010000Z`,
     `.github/workflows/keycloak-federation-e2e.yml:447-452`) deterministically
     propagates to authentication rejection (HTTP 401) on Keycloak's token
     endpoint within measured latency
     (`.github/workflows/keycloak-federation-e2e.yml:455-470`).
   - **Honest limits of convergence verification**: This workflow proves
     external IdP user storage federation and convergence; it deliberately
     does *not* test multi-master bidirectional synchronization against
     third-party directory servers (such as Active Directory or Entra ID),
     which is unsupported and excluded by Decision D1 ("Multi-directory
     topology and source-of-authority contract",
     `docs/client-compatibility.md:676-681`). Genuine cross-directory
     multi-master synchronization requires external IGA/broker tooling, as
     OpenLDAP replication (`olcMultiProvider`) operates strictly between
     ldapium peer nodes.

## Capability touchpoint matrix

| External capability | External product class | ldapium touchpoint | Evidence / Reference |
|---|---|---|---|
| Multi-directory sync & federation | IdP (Keycloak, Ping, Okta) | LDAPv3 bind, search, modify | `ui/README.md`, `charts/ldapium/README.md`, `.github/workflows/keycloak-federation-e2e.yml` |
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
