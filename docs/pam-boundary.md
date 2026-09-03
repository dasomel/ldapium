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
  genesis-anchored to the export manifest line. When the chain head hash is stored out-of-band
  (e.g., recorded in the backup manifest or streamed to an external SIEM), the exported evidence is
  **tamper-evident**: any record modification, reordering, or deletion is detected by
  `scripts/verify-audit-chain.py`.
- **Still not immutable storage**: Cryptographic hash chaining provides tamper evidence, but is
  **NOT immutable storage on its own**. If an attacker gains root access to the container or direct write
  access to the underlying persistent volume, raw audit log files can still be wiped, truncated, or replaced,
  and local database rows in `cn=accesslog` can be modified before export.
- **Operator requirement**: For regulatory compliance and non-repudiation, operators must
  either run `scripts/ship-audit-log.sh` or stream container stdout immediately to an external,
  write-once/immutable (WORM) SIEM or log aggregator, and store the chain head hash out-of-band.

## Privileged session metadata

ldapium does not model privileged session metadata:

- No tracking of session duration, idle timeouts (beyond TCP connection drops), client
  terminal/tty information, MFA authentication factors, or reason codes.
- To OpenLDAP, an administrative connection is identical to any other LDAP connection:
  a TCP socket over which an authenticated bind occurred.

## Unsupported PAM and IdP combinations

The following PAM and IdP interaction models are unverified and out of scope:

- **Just-In-Time (JIT) provisioning**: ldapium has no dynamic account creation trigger;
  entries must exist in the DIT before binding.
- **Just-Enough-Administration (JEA) temporary escalation**: No mechanism exists to grant
  time-bounded group memberships or dynamically adjust `olcAccess` directives.
- **Ephemeral credential injection**: OpenLDAP expects persistent hashes in `userPassword`;
  there is no pluggable authentication module to query an external vault during bind.
- **Push-based event hooks**: ldapium does not push webhook notifications to PAM platforms
  upon account lockout or password failure.
