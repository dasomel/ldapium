# ldapium

Repo-wide gotchas that aren't derivable from `ls`/README/CI config and that are easy to get
wrong by default. Not a general intro — see `README.md`, `ui/README.md`, `image/README.md`,
`charts/ldapium/README.md` for how things work.

## Local Docker/LDAP verification

- macOS/Colima: bind-mounting a file into a container so a non-root container user (e.g. `ldap`,
  uid 999) can read it silently fails with "not readable" even when the host file is `644` —
  UID mapping across the VM boundary doesn't behave like native Linux. Don't fight the bind
  mount: build a throwaway derived image instead (`FROM ldapium:e2e`, `COPY` the file in,
  `chown ldap:ldap`, `USER ldap`).
- `docker exec <container> <cmd> <<'EOF' ... EOF` silently does nothing — exit 0, no output, no
  error — unless `docker exec -i` is passed. The heredoc never reaches the container's stdin
  without `-i`. Always pass it when piping LDIF into `ldapadd`/`ldapmodify` this way.
- `ldapium:e2e` is the image tag most workflows build against (`e2e.yml`, `metrics-e2e.yml`,
  `backup-restore.yml`, `ui-e2e.yml`, `upgrade-e2e.yml`); `replication-chaos-e2e.yml` and
  `security-e2e.yml` use `ldapium:chaos` / `ldapium:security` instead. Rebuild after any
  `image/entrypoint.sh` change: `docker build -t ldapium:e2e -f image/Dockerfile ./image`.

## Non-obvious OpenLDAP / entrypoint.sh behavior

- `olcAccessLogSuccess: TRUE` means the opposite of what it sounds like: "log only successful
  requests" — every failed operation (rejected bind, denied search) is silently dropped from
  `cn=accesslog`. `FALSE` is what logs failures too.
- `olcAccessLogOps: reads` does not include `bind` — slapo-accesslog's `reads` alias is
  `compare, search` only; `bind` lives in the separate `session` group. List `bind` explicitly
  to audit authentication attempts.
- Multi-provider replication (`olcMultiProvider: TRUE` — already the chosen topology, not an
  open question) resolves a same-entry conflict by `entryCSN` timestamp, last-write-wins — not
  by which side has more nodes. An isolated single node's write can silently beat a two-node
  majority's write if its clock timestamp is later, and nothing logs that a conflict happened.
- ACL `search` vs `read` on the `entry` pseudo-attribute are different grants: `search` lets
  slapd use an entry as a search base / traverse it as a candidate without ever returning it;
  `read` is what makes it returnable. Scoping anonymous `read` to a subtree while leaving
  `by anonymous search` on `entry` elsewhere is how `LDAP_ANONYMOUS_READ_BASE` keeps root-base
  `(uid=x)` lookups working yet hides everything outside the base — and a filter on an
  attribute the identity has no `search` access to evaluates undefined (even `(objectClass=*)`),
  so those entries are never matched. Live-verified; see the `#__ANON_READ_ACCESS__` comment
  in `image/entrypoint.sh`.

## Attribute exposure

`userPassword` must never reach an HTTP response, even hashed. Treat it as a hard denylist
(see `entryRedactedAttrs` in `ui/backend/internal/ldapclient/tree.go`), not something the
directory's ACLs are trusted to gate — a root/admin bind bypasses ACLs entirely, so any handler
requesting `"*"` and returning attributes verbatim needs its own check.

## Testing philosophy

LDAP-wire-touching code (`Bind`, `Ping`, search/dial paths) has no unit tests and isn't meant
to — there's no injectable interface for the underlying `*ldap.Conn`. The established pattern:
unit-test pure helper functions (escaping, DTO mapping, filter building) with
`ldap.NewEntry(...)` fixtures, and verify anything that actually talks to a server live against
a running container (see "Local Docker/LDAP verification" above). Don't introduce a mocking
framework for this.

## Issue tracker convention

Open issues in the low-teens-to-20s range are large RFP-derived umbrella issues, each
intentionally scoped down across multiple PRs rather than done in one shot. PR bodies say
"Related to #N (not closing yet)" until a PR covers everything an issue asks for. Don't close
one of these on a partial PR; when an issue's remaining scope needs reorganizing, split it into
focused successor issues instead.
