# Privileged Access Management (PAM) boundary

This document defines the boundary between ldapium and external Privileged Access
Management (PAM) suites, credential vaults, and just-in-time access systems (addressing
issue #26).

ldapium does not implement a PAM request workflow, credential vault, temporary privilege
escalation broker, or privileged session recorder. It functions purely as an LDAPv3
directory server that external PAM tools manage over standard LDAP operations.

## Privileged vs standard identity

ldapium distinguishes privileged from standard identities at the OpenLDAP protocol and
database layer, not through application-level role tables:

### Directory Root DN (`olcRootDN`)
- **Configuration**: Defined via `olcRootDN: __LDAP_ADMIN_DN__` in
  `image/ldifs/01-cn-config.ldif:71` (defaulting to `cn=admin,<rootDN>`), with its
  password hash minted at first bootstrap (`image/entrypoint.sh:469-478`).
- **Privilege scope**: Under OpenLDAP semantics, the `olcRootDN` on the primary database
  (`{1}mdb`) **bypasses all ACL checks (`olcAccess`) completely**. It has unrestricted
  read and write access across all entries under the suffix, can overwrite protected
  attributes (including `userPassword`), and is not subject to password policy lockout
  or history rules enforced by `slapo-ppolicy`.
- **Database isolation**: `olcRootDN` on `{1}mdb` cannot modify the configuration
  database (`cn=config`).

### Configuration Root DN (`cn=admin,cn=config`)
- **Configuration**: Dedicated administrative identity configured at bootstrap via
  `image/ldifs/02-cn-config-admin.ldif:24` and `image/entrypoint.sh:846`.
- **Privilege scope**: Restricted solely to modifying `cn=config` (schema, overlays,
  ACLs, database definitions) via the local Unix domain socket (`ldapi://`). It has
  no access to user entries in the primary data tree.

### Standard identities
- **Configuration**: Created as `inetOrgPerson` entries (e.g., under `ou=people,<rootDN>`)
  via the UI (`ui/backend/internal/ldapclient/users.go`) or seed LDIFs.
- **Privilege scope**: Strictly constrained by `olcAccess` rules (`image/ldifs/01-cn-config.ldif:86-102`
  and `image/entrypoint.sh:563-588`). Ordinary authenticated users (`by users read`) can
  traverse allowed attributes, self-service change their own password (`by self write`),
  and are subject to password complexity and lockout constraints (`slapo-ppolicy`).
  They cannot read other users' password hashes or access `cn=accesslog` or `cn=Monitor`.

### Administrative groups
- **Actual repository state**: The bootstrap templates and `image/entrypoint.sh` **do not
  configure or seed any administrative group** (such as a default `Directory Admins`
  or `cn=admins,ou=groups`).
- Any group-based delegation of privileged access must be explicitly created by the
  operator via `LDAP_SEED_DIR` and granted specific permissions by adding custom
  `olcAccess` directives (e.g., `by group.exact="cn=admins,ou=groups,..." write`) to
  `cn=config`.

## Credential material and external vault integration

A search across this codebase confirms that **no vault SDK, KMS client, or secret-store
integration exists** in `ui/backend` or the container image:

- `ui/backend/go.mod` includes only `go-ldap`, `go-oidc`, `echo`, and `oauth2`.
- The container image (`image/Dockerfile`) compiles OpenLDAP with standard OpenSSL and
  Cyrus SASL; no secret retrieval hooks are included.

When an external PAM vault (e.g., HashiCorp Vault, CyberArk) manages directory accounts:

1. **Passive storage**: ldapium stores only the password hash in the `userPassword`
   attribute (default `{ARGON2}`, or `{SSHA}`). It never holds cleartext vault secrets
   or API tokens.
2. **Rotation mechanism**: The external vault initiates rotations by connecting over
   LDAPv3 (SIMPLE bind using a privileged identity or the account's existing credentials)
   and issuing a standard LDAP `modify` replacing `userPassword`. ldapium executes the
   password update and updates the password policy history if `slapo-ppolicy` is active.
3. **No outbound communication**: ldapium never contacts the vault, refreshes leases,
   or emits webhooks upon credential expiration.

## Rotation and revocation correlation

Credential rotations and account revocations performed by external PAM systems arrive as
standard LDAP operations:

- **Password rotation**: Arrives as an LDAP `modify` replacing `userPassword`.
- **Account suspension / revocation**: Arrives as an LDAP `modify` setting
  `pwdAccountLockedTime: 000001010000Z` (permanent lockout under `slapo-ppolicy`),
  replacing `userPassword` with a randomized value, or issuing an LDAP `delete`.

### Audit records and correlation limits
When audit logging is enabled:
- `slapo-auditlog` (`LDAP_AUDIT_ENABLED=true`, `image/entrypoint.sh:642-656`) records the
  write operation to container stdout (`LDAP_AUDIT_FILE`), capturing timestamp, target
  entry DN, operation type, modified attributes, and actor DN (`reqDN`).
- `slapo-accesslog` (`LDAP_ACCESSLOG_ENABLED=true`, `image/entrypoint.sh:673-738`) records
  binds and searches to `cn=accesslog`.
- `scripts/export-audit-log.sh` pulls these into a unified NDJSON stream.

**Correlation limitation**: OpenLDAP does not model external transaction IDs, ticket
numbers, or correlation IDs in standard LDAP write operations. An audit record indicates
*which* bind DN performed the operation and *when*, but cannot link that operation to an
external PAM checkout ticket or change request ID. Downstream SIEM or audit pipelines
must correlate events using the timestamp window and the actor DN used by the PAM system.

### Actor-to-identity correlation, live-verified

`.github/workflows/keycloak-federation-e2e.yml:472-503` ("Assert human-actor correlation
between the disable and the auth failure") demonstrates the actor-DN correlation described
above end-to-end rather than only asserting it in the abstract: it locks `uid=alice`'s
account with an `ldapmodify` bind as `cn=admin,<rootDN>` (`:447-452`), reads that write back
out of the `auditlog` overlay's own stdout record (`docker logs ldap`, `:483-488`), and
asserts both fields the record carries — `actor` (the auditlog header's bind-DN field,
`:492`, equals `cn=admin,<rootDN>`) and `target` (the record's `dn:` line, `:493`, equals
`uid=alice,ou=people,<rootDN>`) — matching what changed and who changed it (`:496-499`).
That target DN's RDN (`uid=alice`) is the same identity Keycloak's LDAP federation
authenticates against, so the auditlog record ties the revoking actor to the same identity
whose downstream (federated) access then fails — see "Revocation propagation latency,
measured" below for that failure. This is `slapo-auditlog`'s existing per-write
`actor`/`target` fields (already documented above and in `docs/audit-event-schema.md`)
consumed as-is; no new correlation ID field or library was added to produce this evidence.

## Revocation propagation latency, measured

ldapium itself has no downstream-revocation SLA to declare — it applies a `modify` to
`pwdAccountLockedTime` synchronously and has no queue, cache, or async fan-out of its own.
The SLA that matters operationally is end-to-end: how long a *downstream* identity
consumer (an IdP doing LDAP federation, in this case) keeps honoring the now-revoked
identity. `.github/workflows/keycloak-federation-e2e.yml:432-470` ("Disable alice and
measure Keycloak auth-failure propagation latency") measures exactly this, live against a
running ldapium + Keycloak pair rather than asserting it as a claim:

- It locks `uid=alice`'s account the same way the UI does (`ui/backend/internal/ldapclient/users.go`'s
  `Lock()` — replacing `pwdAccountLockedTime` with the ppolicy "locked indefinitely"
  sentinel `000001010000Z`) via `ldapmodify` (`:447-452`) and records `t0` immediately
  before that write (`:446`).
- It then polls Keycloak's OIDC password-grant token endpoint with alice's real password,
  once per second for up to 30 attempts, until the response is `401` (`:455-464`), and
  records `t1` at that point (`:465`).
- `latency=$((t1 - t0))` (`:466`) is printed to the job log every run
  (`echo "disable->auth-failure propagation latency: ${latency}s"`, `:467`); the job fails
  if 30 polls (30s) elapse without a `401` (`:468-469`).
- Because this Keycloak federation is configured without credential caching, Keycloak
  re-binds to ldapium on every password grant, so the measured latency reflects Keycloak's
  own login-path wall-clock time to observe the lock, not a synthetic delay injected by the
  test (`:439-443` comment).

This gives ldapium's revocation SLA claim a concrete, CI-reproduced upper bound (currently
asserted as ≤30s, with the actual per-run value logged rather than hard-coded) for the one
downstream consumer this repository's test suite integrates with. It does not generalize to
every possible PAM/IdP combination's own caching or polling behavior — an IdP or PAM system
with its own credential cache or longer poll interval will have a longer effective
revocation latency than what this workflow measures, and that gap is the operator's to
close (e.g. by disabling federation-side credential caching, as this workflow's Keycloak
realm already does).

## Break-glass procedures and evidence integrity

Break-glass access (e.g., using `olcRootDN` when SSO or central authentication is offline)
is an external operational workflow. ldapium provides evidentiary tracking rather than
workflow enforcement:

- Any use of the directory admin identity appears in `cn=accesslog` as a bind operation
  with `reqDN: <adminDN>` and in `auditlog` for any resulting modifications.
- **Evidence integrity limits**: The audit export generated by `scripts/export-audit-log.sh`
  draws from container stdout/files and an OpenLDAP MDB database (`cn=accesslog`).
  When run with the `--chain` option (`scripts/export-audit-log.sh --chain` / `audit-normalize.py --chain`),
  records are cryptographically hashed using SHA-256 (`prevHash` and `hash`) in canonical JSON order,
  genesis-anchored to the export manifest line. Interior record modification, reordering, or deletion is
  detected by `scripts/verify-audit-chain.py`. **Tail truncation (deleting the most recent records from the end)**
  is undetectable from the log file alone; it is detected only when the chain head hash is stored out-of-band
  (e.g., recorded in the backup manifest or streamed to an external SIEM) and asserted with `--expected-head`.
- **Still not immutable storage**: Cryptographic hash chaining provides tamper evidence, but is
  **NOT immutable storage on its own**. If an attacker gains root access to the container or direct write
  access to the underlying persistent volume, raw audit log files can still be wiped, truncated, or replaced,
  and local database rows in `cn=accesslog` can be modified before export.
- **Operator requirement**: For regulatory compliance and non-repudiation, operators must
  either run `scripts/ship-audit-log.sh` or stream container stdout immediately to an external,
  write-once/immutable (WORM) SIEM or log aggregator, and store the chain head hash out-of-band.

### Break-glass policy contract

ldapium does not enforce a break-glass workflow, but the following contract defines what
an operator's external policy and the directory's evidence trail must jointly satisfy for
a break-glass use of `olcRootDN` (or the `cn=admin,cn=config` identity) to be considered
policy-compliant rather than an undetected admin bind:

- **Explicit trigger condition**: The operator's break-glass policy (external to ldapium,
  e.g. an incident runbook or PAM vault checkout policy) MUST define the conditions under
  which the admin credential may be checked out — typically "central authentication (SSO/
  Keycloak) or the standard privileged-access path is unavailable." ldapium has no way to
  verify this condition was true; it can only show *that* the admin identity bound, not
  *why*.
- **Dual-control custody**: Because ldapium has no MFA or approval-workflow hooks (see
  "Unsupported PAM and IdP combinations" below), dual control must be enforced upstream —
  e.g. a vault that requires two operators to release the `olcRootDN` password, or a
  sealed/split credential procedure. Storing the credential in an external vault per
  "Credential material and external vault integration" above is a precondition for this,
  not an alternative to it.
- **Immutable evidence production**: Every break-glass use produces, at minimum:
  1. A bind record in `cn=accesslog` (`reqDN: <adminDN>`) for the `olcRootDN` or
     `cn=admin,cn=config` bind itself, and any resulting write to the directory's own
     entries (not `cn=config`) captured in `auditlog`. `slapo-auditlog` is configured
     only on `olcDatabase={1}mdb` (`image/entrypoint.sh:646`), so modifications made
     directly against `cn=config` (the `{0}config` backend) are **not** captured in
     `auditlog`, and administrative operations performed over the local domain socket
     (`ldapi://`) bypass `accesslog` entirely (`docs/audit-event-schema.md:464`). A
     break-glass session that only rotates `olcRootDN` or otherwise limits itself to
     `cn=config` changes over `ldapi://` therefore produces **no accesslog or auditlog
     evidence** — operators relying on this contract for such sessions must add an
     external control (e.g. session recording on the admin bastion, or shell audit on
     the container) rather than assume the directory's own logs will show it.
  2. A `--chain` export (`scripts/export-audit-log.sh --chain`) run before and after the
     break-glass window, with the resulting chain head hash recorded out-of-band (backup
     manifest or external SIEM); `scripts/verify-audit-chain.py --expected-head` is then
     used afterward to assert against that recorded hash, so tail truncation of the
     break-glass records is detectable.
  3. Cross-reference of the operator-side checkout ticket/incident ID against the bind
     timestamp window and actor DN, since ldapium cannot embed a correlation ID in the LDAP
     operation itself (see "Rotation and revocation correlation" above).
- **Post-event reconciliation**: The policy MUST require, after the break-glass window
  closes: (a) rotating the `olcRootDN` password (an LDAP `modify` on `cn=config`, subject to
  the `cn=config` audit limitation documented above), (b) reviewing the accesslog/auditlog window for
  unexpected operations, and (c) re-verifying the audit chain (`scripts/verify-audit-chain.py
  --expected-head`) to confirm no tampering occurred during the elevated-access window.
  ldapium does not automatically revoke or rotate anything on its own; this step is entirely
  an external operational obligation.

## JIT and JEA request and elevation boundary

Just-in-Time (JIT) privilege elevation and Just-Enough-Administration (JEA) temporary access
involve two distinct operational phases: the request/approval workflow and the time-bounded
access lifecycle. In accordance with product boundary D1 (`docs/product-boundary.md:58-62`),
ldapium provides directory-level enforcement primitives but ships no workflow engine or
request broker.

### Request metadata and approval boundary

OpenLDAP operates strictly as an LDAPv3 directory server: standard protocol operations (`bind`,
`add`, `modify`, `delete`) carry target DNs and attribute modifications, but have no protocol
fields or schema attributes to record operational request metadata.

Therefore, an external PAM, IGA, or ITSM system (e.g. CyberArk, HashiCorp Vault, Keycloak
Privileged Access, or ServiceNow) MUST own and enforce the entire request boundary:

1. **Reason / Justification**: Capturing and validating the business reason, incident ticket,
   or change management ID. ldapium's directory cannot inspect or enforce the presence of a
   justification.
2. **Approver / Multi-Party Approval**: Requiring dual-control or designated approver sign-off
   before any directory write is dispatched. In ldapium, any client binding with a DN permitted
   by `olcAccess` directives (`image/ldifs/01-cn-config.ldif:86-102`) can execute modifications;
   slapd has no mechanism to require upstream human or multi-agent approval.
3. **Start and End Time**: Managing the elevation schedule and expiration timers. The PAM
   orchestrator issues the LDAP operations to activate access at `startTime` and deactivate
   it at `endTime`.
4. **Target Scope**: Restricting elevation to designated organizationalUnits, specific user
   entries, or administrative groups. ldapium enforces standard ACLs (`olcAccess`) against the
   binding actor DN, but does not calculate dynamic JEA role scopes on-the-fly.

**Audit correlation**: While OpenLDAP cannot inject ticket numbers or correlation IDs into
standard LDAP writes (`docs/pam-boundary.md:93-98`), write operations on `{1}mdb` are captured
by `slapo-auditlog` (`image/entrypoint.sh:646`, destination `LDAP_AUDIT_FILE`) recording actor
DN (`reqDN`), target DN, and attribute modifications, while binds are recorded in `cn=accesslog`
(`image/entrypoint.sh:673-738`). Downstream SIEM and audit pipelines correlate external PAM
request metadata (reason, approver, ticket ID, approved time window) with directory operations
using the actor DN, target DN, and timestamp window.

### Automatic expiration and renewal lifecycle

Privileged access elevation must not persist indefinitely. The boundary between what ldapium's
OpenLDAP overlays enforce automatically and what the external PAM system must orchestrate is
governed by the identity mechanism used:

1. **Credential expiry via `slapo-ppolicy` (`pwdMaxAge`)**:
   - `slapo-ppolicy` is compiled and enabled on `{1}mdb` (`image/Dockerfile:65`,
     `image/ldifs/01-cn-config.ldif:119-124`, `image/entrypoint.sh:757-837`).
   - The default policy (`cn=default,ou=policies,<rootDN>`) sets `pwdMaxAge: 0`
     (`image/entrypoint.sh:826`, `image/README.md:423`) to avoid forced periodic rotation for
     standard users per NIST 800-63B.
   - For temporary or JIT-elevated credentials, an operator or PAM platform can define a dedicated
     policy under `ou=policies,<rootDN>` with a non-zero `pwdMaxAge` (e.g., `pwdMaxAge: 3600` for
     a 1-hour window) and assign it to an identity via the `pwdPolicySubentry` operational
     attribute (`ui/frontend/src/pages/ChangePasswordPage.tsx:16-17`).
   - Under this policy, `slapo-ppolicy` evaluates `pwdChangedTime` on each bind. When
     `currentTime > pwdChangedTime + pwdMaxAge`, subsequent binds are automatically rejected
     at the LDAP protocol layer with `LDAP_INVALID_CREDENTIALS` (ppolicy passwordExpired).
   - **Renewal mechanism**: To extend access before expiration, the external PAM system must
     issue an LDAP `modify` replacing `userPassword`. This resets `pwdChangedTime` to the current
     timestamp, renewing access for another `pwdMaxAge` interval. If not explicitly renewed,
     access expires automatically without requiring an asynchronous directory reaper at the
     exact expiration second.
2. **Administrative lockout via `pwdAccountLockedTime`**:
   - When an approved elevation window ends, or upon immediate revocation, the PAM orchestrator
     can administratively disable the account by replacing `pwdAccountLockedTime` with the
     ppolicy indefinite-lockout sentinel `000001010000Z` (`ui/backend/internal/ldapclient/users.go:272`,
     `docs/pam-boundary.md:81`, `.github/workflows/keycloak-federation-e2e.yml:450-451`).
   - Any subsequent bind fails immediately until an administrator or PAM service explicitly
     deletes `pwdAccountLockedTime` (`image/README.md:457-464`, `ui/backend/internal/ldapclient/users.go:226-240`).
   - In federated deployments, downstream IdPs (e.g. Keycloak) observe this revocation within
     ≤30s (`keycloak-federation-e2e.yml:432-470`, `docs/pam-boundary.md:116-149`).
3. **Group membership elevation (JEA) limitation**:
   - When elevation is granted by adding an identity as a `member` of an administrative or
     operational group, OpenLDAP's `memberof` overlay (`image/ldifs/01-cn-config.ldif:104-108`)
     maintains static bi-directional group relationships.
   - OpenLDAP has **no native attribute-level TTL or dynamic membership expiration** (no RFC 2589
     dynamic directory or `entryTtl` overlay).
   - Consequently, automatic expiration of group memberships CANNOT occur within the directory
     engine itself. The external PAM/JEA orchestrator MUST manage the lease timer and issue an
     LDAP `modify` deleting the `member` attribute when the approved elevation window closes,
     unless an explicit renewal was granted.
4. **Directory Root DN (`olcRootDN`) bypass**:
   - As documented in `docs/pam-boundary.md:20-24`, `olcRootDN` on `{1}mdb` and `cn=admin,cn=config`
     bypass `slapo-ppolicy` entirely.
   - `pwdMaxAge` and `pwdAccountLockedTime` have no effect on `olcRootDN`. Temporary rootDN
     elevation cannot auto-expire via directory password policies; it relies strictly on external
     vault lease management and mandatory post-event credential rotation per the break-glass policy
     contract (`docs/pam-boundary.md:214-220`).

### Offline policy import and deterministic validation

ldapium does not ship a PAM policy engine or an approval workflow (see "JIT and JEA request and
elevation boundary" above), so it has no bespoke "PAM policy bundle" format to import. What it
does provide is a way to provision and validate the LDAP-side artifacts a PAM policy is actually
built from — `ou=policies` ppolicy entries (e.g. a short-`pwdMaxAge` policy for JIT elevation,
per "Automatic expiration and renewal lifecycle" above) and privileged group/ACL definitions —
entirely offline, with deterministic pre-import validation:

- **Offline import**: `LDAP_SEED_DIR` LDIF files (default `/opt/ldifs`,
  `image/entrypoint.sh:103`) are applied via `ldapadd` against a **temporary local `slapd`
  instance** started for bootstrap only (`image/entrypoint.sh:916-925`) — no network dependency
  or external LDAP server is contacted. This is the same mechanism used to seed any other entry,
  including a custom `ou=policies` ppolicy definition for privileged/JIT identities. Seed
  application is gated by `NEEDS_BOOTSTRAP` (`image/entrypoint.sh:916`), so it runs at most once
  per fresh data volume — re-running the container against an already-provisioned volume does not
  re-import the policy bundle, consistent with the idempotent-provisioning behavior documented in
  `docs/client-compatibility.md`'s "Idempotent provisioning" subsection.
- **Deterministic pre-import validation**: `scripts/migration-dryrun.sh` /
  `scripts/lib/migration-report.py` parses an LDIF file offline against ldapium's known schema
  (`KNOWN_OBJECT_CLASSES`) and produces a structured JSON reconciliation report without writing
  anything to a live directory. `scripts/test/test-migration-dryrun.sh:123-128` proves this is
  deterministic: two dry-run executions against the identical LDIF input produce byte-identical
  reports (`diff -u` on the two JSON outputs). An operator can validate a policy/ACL LDIF bundle
  this way before ever applying it via `LDAP_SEED_DIR` or a manual `ldapadd`.
- **What this does not cover**: schema-level validation only — it cannot verify that a policy's
  *semantics* (e.g. an intended JIT expiry window, an approver list encoded in an external
  system) match operator intent. That review remains the external PAM/IGA system's
  responsibility, consistent with the request-metadata boundary above.

## Privileged session metadata

ldapium does not model privileged session metadata:

- No tracking of session duration, idle timeouts (beyond TCP connection drops), client
  terminal/tty information, MFA authentication factors, or reason codes.
- To OpenLDAP, an administrative connection is identical to any other LDAP connection:
  a TCP socket over which an authenticated bind occurred.

## Unsupported PAM and IdP combinations

The following PAM and IdP interaction models are unverified and out of scope:

- **Just-In-Time (JIT) account provisioning**: ldapium has no dynamic account creation trigger;
  entries must exist in the DIT before binding (see "JIT and JEA request and elevation boundary" above).
- **Just-Enough-Administration (JEA) dynamic escalation**: No mechanism exists inside the directory
  to grant time-bounded group memberships or dynamically adjust `olcAccess` directives; group
  de-escalation must be driven externally by the PAM orchestrator.
- **Ephemeral credential injection**: OpenLDAP expects persistent hashes in `userPassword`;
  there is no pluggable authentication module to query an external vault during bind.
- **Push-based event hooks**: ldapium does not push webhook notifications to PAM platforms
  upon account lockout or password failure.
