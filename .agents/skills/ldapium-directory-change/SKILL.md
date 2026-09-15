---
name: ldapium-directory-change
description: Implement or verify LDAPium directory/API/auth/replication changes using the repository's live LDAP evidence rules, credential/attribute boundaries, Docker/Colima gotchas, and E2E image conventions. Use for OpenLDAP entrypoint, ACL/accesslog, replication, LDAP-wire, auth, backup/restore, upgrade, or LDAP-backed UI/API changes.
license: Apache-2.0
compatibility: Requires the LDAPium checkout and project Docker/Go/Helm/UI toolchain; LDAP-wire verification requires a running LDAP container or equivalent real server.
metadata:
  openforge-scope: project
  openforge-owner: dasomel/ldapium
  openforge-maturity: verified
  openforge-version: "1"
---

# LDAPium Directory Change

## Use When

- Changing OpenLDAP configuration/entrypoint behavior, ACL/accesslog, replication, directory operations, LDAP auth, backup/restore, upgrade, or LDAP-backed API/UI behavior.
- Fixing a defect that depends on real LDAP protocol behavior rather than pure helpers.

## Do Not Use When

- Pure UI styling with no LDAP/auth/data contract impact.
- Generic Go/React changes that do not depend on LDAPium-specific directory semantics.

## Inputs

- Relevant issue/spec and affected subsystem.
- Current E2E workflow/image tag for that subsystem.
- Whether a real LDAP container/server is available.

## Workflow

1. Read `AGENTS.md` and the relevant README/release documentation before editing.
2. Preserve directory-service, API, auth/authz, audit, and credential boundaries. Treat schema/operation semantics, destructive/bulk directory actions, and privilege handling as design changes.
3. For `image/entrypoint.sh` changes, rebuild the E2E image used by the matching workflow; most use `ldapium:e2e`, with specialized chaos/security tags where documented.
4. On macOS/Colima, do not assume a host file bind-mounted into a non-root LDAP container will be readable. When UID mapping blocks it, use a throwaway derived image with explicit ownership rather than weakening permissions blindly.
5. When piping LDIF to a container command, use `docker exec -i`; without stdin attachment the operation can exit successfully while applying nothing.
6. Preserve OpenLDAP-specific semantics documented in `AGENTS.md`: accesslog success/failure behavior, bind operation groups, multi-provider conflict behavior, and ACL `search` vs `read` distinctions.
7. Never expose `userPassword` in HTTP responses, even hashed; enforce the application-side denylist independently of LDAP ACLs/admin binds.
8. Unit-test pure helpers with LDAP entry fixtures. For Bind/Ping/search/dial and other LDAP-wire behavior, verify against a running LDAP server rather than introducing mocks that cannot prove protocol behavior.
9. Run the repository's relevant check/CI/E2E path and state which real directory behavior was exercised.

## Verification

Separate pure-helper/unit evidence from live LDAP, container, browser, backup/restore, replication, or upgrade evidence. A successful container command without checking resulting directory state is not enough.

## Stop / Escalate When

- The change widens LDAP/admin privilege, credential exposure, destructive directory scope, or replication semantics without an approved design.
- Real LDAP behavior is central to the claim but no live server/container evidence is possible.
- A workaround would weaken filesystem/container permissions or bypass application-side attribute redaction.

## References

- `AGENTS.md`
- `image/README.md`
- `ui/README.md`
- `charts/ldapium/README.md`
- repository E2E workflows
