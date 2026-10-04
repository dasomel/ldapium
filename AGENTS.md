# ldapium

Canonical agent contract. Read `README.md`, `ui/README.md`, `image/README.md`, `charts/ldapium/README.md`, `CONTRIBUTING.md`, `RELEASING.md` and the relevant issue only when they apply; this file carries only what those do not make safe to derive.

Change workflow, risk classes and evidence follow the OpenForge docs: https://github.com/dasomel/openforge/blob/main/docs/change-management.md and https://github.com/dasomel/openforge/blob/main/docs/agent-engineering.md. For research-evidence capture see `research/README.md` (opportunistic, never a blocking gate).

For OpenLDAP configuration, directory operations, replication, LDAP auth, backup/restore, upgrade, or LDAP-backed API/UI behavior, load `.agents/skills/ldapium-directory-change/SKILL.md`.

## Rules

- Exported API changes, LDAP schema/operation semantics, privilege/credential handling, destructive directory actions and bulk operations are design changes, not routine edits.
- Keep DNs and low-level LDAP details behind the domain/service abstraction.
- Use integration/E2E evidence for LDAP, auth, backup/restore, upgrade and browser behavior when unit tests cannot prove the real path; unrelated trivial changes don't need it.
- `make check` runs what CI runs, in CI order.
- Shared/production/destructive/release/credential/external mutations need explicit authorization.

## Local Docker/LDAP verification

- macOS/Colima: bind-mounting a file so a non-root container user (e.g. `ldap`, uid 999) can read it silently fails with "not readable" even at `644` — UID mapping across the VM boundary differs from native Linux. Build a throwaway derived image instead (`FROM ldapium:e2e`, `COPY`, `chown ldap:ldap`, `USER ldap`).
- `docker exec <container> <cmd> <<'EOF' ... EOF` does nothing — exit 0, no output, no error — without `docker exec -i`; the heredoc never reaches stdin. Always pass `-i` when piping LDIF into `ldapadd`/`ldapmodify`.
- `ldapium:e2e` is the image tag most workflows build against (`e2e`, `metrics-e2e`, `backup-restore`, `ui-e2e`, `upgrade-e2e`, `keycloak-federation-e2e`); `replication-chaos-e2e` and `security-e2e` use `ldapium:chaos` / `ldapium:security`. Rebuild after any `image/entrypoint.sh` change: `docker build -t ldapium:e2e -f image/Dockerfile ./image`.

## Non-obvious OpenLDAP / entrypoint.sh behavior

- `olcAccessLogSuccess: TRUE` means "log only successful requests": failed binds and denied searches vanish from `cn=accesslog`. `FALSE` logs failures too (what the entrypoint sets).
- `olcAccessLogOps: reads` is `compare, search` only; `bind` is in the separate `session` group. List `bind` explicitly to audit authentication attempts.
- Multi-provider replication (`olcMultiProvider: TRUE`, the chosen topology) resolves same-entry conflicts by `entryCSN` timestamp, last-write-wins, not by node count. An isolated node's later-timestamped write can silently beat a two-node majority's, and nothing logs the conflict.
- ACL `search` vs `read` on the `entry` pseudo-attribute differ: `search` lets slapd use an entry as a search base or traverse it without ever returning it; `read` makes it returnable. `LDAP_ANONYMOUS_READ_BASE` scopes anonymous `read` to a subtree and leaves `by anonymous search` on `entry` elsewhere, so root-base `(uid=x)` lookups work while everything outside the base stays hidden. A filter on an attribute the identity has no `search` access to evaluates undefined (even `(objectClass=*)`), so those entries never match. Live-verified; see the `#__ANON_READ_ACCESS__` comment in `image/entrypoint.sh`.

## Attribute exposure

`userPassword` must never reach an HTTP response, even hashed. It is a hard denylist (`entryRedactedAttrs` in `ui/backend/internal/ldapclient/tree.go`), not something directory ACLs are trusted to gate: a root/admin bind bypasses ACLs, so any handler requesting `"*"` and returning attributes verbatim needs its own check.

## Testing philosophy

LDAP-wire code (`Bind`, `Ping`, search/dial paths) has no unit tests and isn't meant to: there is no injectable interface for `*ldap.Conn`. Unit-test pure helpers (escaping, DTO mapping, filter building) with `ldap.NewEntry(...)` fixtures, and verify anything that talks to a server live against a running container (see "Local Docker/LDAP verification"). Don't introduce a mocking framework.

## Issue tracker convention

Large RFP-derived umbrella issues are deliberately scoped down across multiple PRs. PR bodies say "Related to #N (not closing yet)" until a PR covers everything the issue asks for; never close one on a partial PR. When remaining scope needs reorganizing, split it into focused successor issues.
