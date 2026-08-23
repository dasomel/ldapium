# ldapium image

A from-source OpenLDAP **2.6.14** container image that this project owns outright —
no dependency on [osixia/docker-openldap](https://github.com/osixia/docker-openldap)
(abandoned, last stable release 2021) or
[vegardit/docker-openldap](https://github.com/vegardit/docker-openldap) (built from
Debian packages, and seeds demo accounts on first launch).

**This image never seeds sample data.** On first launch it creates the root
suffix and the admin entry, plus — by default — a password policy container
(`ou=policies` and `cn=default,ou=policies,...`; see
[Password policy](#password-policy)) and nothing else. The policy entries are
operational scaffolding the `ppolicy` overlay needs to function, not sample
content, so "no sample data" still holds; set `LDAP_PASSWORD_POLICY_ENABLED=false`
if you don't want them either. If you want actual demo data, put your own
LDIFs in `LDAP_SEED_DIR`.

## Build

```bash
docker build --platform linux/arm64 -t ldapium:dev image/
```

Multi-stage build: a `debian:trixie-slim` builder stage compiles OpenLDAP 2.6.14
from the official source tarball (checksum-pinned), then only the built
binaries/libraries/modules and schema files are copied into a clean
`debian:trixie-slim` runtime stage. No compiler toolchain ships in the final image.

### Verified installed paths (from a real `make install`, not assumed)

With `--prefix=/usr --sysconfdir=/etc --localstatedir=/var --libexecdir=/usr/lib`:

| Component | Path |
|---|---|
| `slapd` binary | **`/usr/lib/slapd`** — *not* `/usr/sbin/slapd`. OpenLDAP's build installs `slapd` under `libexecdir`, not `sbindir`. |
| Admin/maintenance tools (`slapadd`, `slapcat`, `slapindex`, `slaptest`, `slappasswd`, ...) | `/usr/sbin/` |
| Client tools (`ldapsearch`, `ldapadd`, `ldapwhoami`, ...) | `/usr/bin/` |
| Config directory root | `/etc/openldap` |
| Schema LDIFs | `/etc/openldap/schema/*.ldif` |
| Stock `cn=config` template (superseded by ours) | `/etc/openldap/slapd.ldif.default` |
| Loadable modules (`olcModulepath`) | `/usr/lib/openldap/*.la` + `*.so*` |
| Core libraries | `/usr/lib/libldap.so*`, `/usr/lib/liblber.so*` |

Runtime packages installed on top of `debian:trixie-slim`: `libssl3t64` (not
`libssl3` — that package does not exist on trixie, time_t64 transition),
`libsasl2-2`, `libltdl7`, `ca-certificates`.

## Run

```bash
docker run -d --name ldap \
  -e LDAP_ROOT_DN=dc=example,dc=org \
  -e LDAP_ADMIN_PASSWORD=change-me \
  -p 389:389 -p 636:636 \
  -v ldap-data:/var/lib/openldap/data \
  -v ldap-config:/etc/openldap/slapd.d \
  ldapium:dev
```

Passing a command after the image name runs that command instead of booting the
directory — the entrypoint hands off with `exec "$@"` before it validates the
environment contract or touches a volume. That is how the maintenance scripts
are meant to be run against an image that already has the OpenLDAP tools:

```bash
docker run --rm -v "$PWD/scripts:/scripts:ro" -v /tmp/ldap-backup:/backup \
  ldapium:dev /bin/bash /scripts/verify-backup.sh /backup/manifest-....sha256
```

## Environment variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `LDAP_ROOT_DN` | **yes** | — | e.g. `dc=example,dc=org`. Must start with `dc=`. Container refuses to start if unset. |
| `LDAP_ORG_NAME` | no | first `dc=` component of `LDAP_ROOT_DN` | Used as the `o:` attribute on the root entry. |
| `LDAP_ADMIN_DN` | no | `cn=admin,${LDAP_ROOT_DN}` | Must use `cn=` as its RDN attribute. |
| `LDAP_ADMIN_PASSWORD` | **yes**\* | — | No default, ever. Container refuses to start if unset. Hashed with `slappasswd -h "$LDAP_PASSWORD_HASH"` before it touches disk — never stored in plaintext. |
| `LDAP_ADMIN_PASSWORD_FILE` | no\* | — | Path to a file containing the admin password (for secret mounts). Takes precedence if both are set and readable. |
| `LDAP_LOG_LEVEL` | no | `stats` | Passed to `slapd -d`. Any value (including a quiet one) keeps slapd in the foreground, which is required for it to run as PID 1. |
| `LDAP_TLS_ENABLED` | no | `false` | `true`/`1` to enable `ldaps:///`. |
| `LDAP_TLS_CERT_FILE` | if TLS enabled | — | `olcTLSCertificateFile`. |
| `LDAP_TLS_KEY_FILE` | if TLS enabled | — | `olcTLSCertificateKeyFile`. |
| `LDAP_TLS_CA_FILE` | no | — | `olcTLSCACertificateFile`, optional even with TLS enabled. |
| `LDAP_SEED_DIR` | no | `/opt/ldifs` | Every `*.ldif` in this directory is applied, in sorted order, via `ldapadd` — **once, on first launch only**. Your extension point for OUs, groups, real users, ACLs, etc. |
| `LDAP_SIZE_LIMIT` | no | `10000` | `olcSizeLimit` on the `mdb` database. Digits, or `unlimited`. Applied at bootstrap only (see below). |
| `LDAP_TIME_LIMIT` | no | `3600` | `olcTimeLimit` on the `mdb` database, in seconds. Digits, or `unlimited`. Applied at bootstrap only (see below). |
| `LDAP_PASSWORD_HASH` | no | `{ARGON2}` | `olcPasswordHash` on the frontend database, and the scheme used to mint the bootstrap admin hash. Any `{SCHEME}`-shaped value slapd supports (e.g. `{SSHA}`). Applied at bootstrap only (see below). |
| `LDAP_UNIQUE_ATTRIBUTES` | no | `uid,mail` | Comma-separated attributes the `unique` overlay enforces uniqueness on. **Empty string disables the overlay entirely** — it is not created at all, rather than created with nothing to check. See [Uniqueness enforcement](#uniqueness-enforcement). Applied at bootstrap only (see below). |
| `LDAP_PASSWORD_POLICY_ENABLED` | no | `true` | `false`/`0` disables the whole password policy: no `ou=policies`/`cn=default` entries, no `olcPPolicyDefault` on the `ppolicy` overlay. See [Password policy](#password-policy). Applied at bootstrap only (see below). |
| `LDAP_PASSWORD_MIN_LENGTH` | no | `8` | `pwdMinLength` on the default policy. Digits only. |
| `LDAP_PASSWORD_MAX_FAILURE` | no | `5` | `pwdMaxFailure` — failed binds before lockout. Digits only. |
| `LDAP_PASSWORD_LOCKOUT_DURATION` | no | `900` | `pwdLockoutDuration` in seconds. Digits only. |
| `LDAP_REPLICATION_ENABLED` | no | `false` | `true`/`1` enables N-way multi-provider replication. See [Replication](#replication) below. |
| `LDAP_REPLICATION_PEERS` | if replication enabled | — | Comma-separated LDAP URLs of **every** node, including this one, e.g. `ldap://ols-0.ols-hl.ns.svc.cluster.local:389,ldap://ols-1.ols-hl.ns.svc.cluster.local:389`. |
| `LDAP_SERVER_ID` | no | hostname's numeric ordinal suffix + 1 | `1`..`4095`. Auto-derivation expects a hostname ending in `-<N>` (e.g. `ols-0`); if it doesn't, the container refuses to start rather than risk two nodes silently sharing an ID. |
| `LDAP_REPLICATION_BIND_DN` | no | `$LDAP_ADMIN_DN` | Identity peers use to bind for replication. |
| `LDAP_REPLICATION_PASSWORD` | no | `$LDAP_ADMIN_PASSWORD` | |
| `LDAP_REPLICATION_PASSWORD_FILE` | no | — | Path to a file containing the replication password; takes precedence if set and readable. |
| `LDAP_REPLICATION_RETRY` | no | `5 10 30 +` | `olcSyncrepl` `retry=` value. |
| `LDAP_REPLICATION_INTERVAL` | no | `00:00:00:10` | `olcSyncrepl` `interval=` value. |

\* Exactly one of `LDAP_ADMIN_PASSWORD` / `LDAP_ADMIN_PASSWORD_FILE` must resolve to a non-empty value.

### TLS caveat

TLS settings are only written into `cn=config` at bootstrap time. Enabling
`LDAP_TLS_ENABLED` against an already-bootstrapped data/config volume has no
effect — either seed a fresh volume with TLS enabled from the start, or edit
`cn=config` by hand (`olcTLSCertificateFile` etc. under `cn=config`).

### Other bootstrap-only settings

`LDAP_SIZE_LIMIT`, `LDAP_TIME_LIMIT`, `LDAP_PASSWORD_HASH`,
`LDAP_UNIQUE_ATTRIBUTES`, `LDAP_PASSWORD_POLICY_ENABLED` and its three
`LDAP_PASSWORD_*` knobs, and `LDAP_DB_MAX_SIZE` are all baked into
`cn=config` (or, for the policy entries, directly into the `mdb` database)
the same way TLS is — read once, at first launch, from
`image/ldifs/01-cn-config.ldif` / `image/ldifs/03-base-structure.ldif`.
Changing any of them against an already-bootstrapped volume has no effect
until you edit `cn=config` / `cn=default,ou=policies,...` directly
(`ldapmodify` as `cn=admin,cn=config` or `LDAP_ADMIN_DN` respectively, see
[Managing `cn=config`](#managing-cnconfig-advanced) below).

Switching `LDAP_PASSWORD_HASH` on an existing volume is safe in the sense
that it never breaks logins: OpenLDAP verifies each stored `userPassword`
against its own `{SCHEME}` prefix, not against whatever `olcPasswordHash`
currently says, so passwords hashed under the old scheme keep working and
only get rehashed to the new scheme on their next change.

## First-launch semantics

Bootstrap is gated on a marker file, `/etc/openldap/slapd.d/.bootstrapped`, so
it lives inside the `slapd.d` volume:

1. **Config dir empty, no marker** → full bootstrap: `slapadd -n 0` loads
   `cn=config` (schema, modules, the `mdb` database, `memberof`/`refint`
   overlays), `slapmodify -n 0` grants the `cn=admin,cn=config` identity
   (see below), `slapadd -n 1` loads the root suffix + admin entry directly
   into the database, then (if `LDAP_SEED_DIR` has `*.ldif` files) a temporary
   `slapd` is started long enough to `ldapadd` them, then stopped.
2. **Marker present** → bootstrap and seeding are both skipped entirely; the
   container just execs `slapd` against the existing config/data.

`slapd` always ends up as PID 1 via `exec` — including on first launch, where
a short-lived background `slapd` is used only internally to apply seed files
before the real, PID-1 `slapd` takes over.

## Replication

Set `LDAP_REPLICATION_ENABLED=true` to turn a set of these containers into an
N-way **multi-provider** cluster (every node accepts writes; conflicts
resolve by CSN last-write-wins). This image doesn't know about Kubernetes —
it's given the full peer list via `LDAP_REPLICATION_PEERS` and reconciles
`cn=config` to match it on **every** startup, not just first boot, so
growing a StatefulSet's replica count converges on the next restart of each
pod without a manual `cn=config` edit.

What reconciliation does, each time the container starts (while replication
is enabled):

1. Sets `olcServerID` from `LDAP_SERVER_ID` (or the auto-derived value).
2. Adds the `syncprov` overlay on the `mdb` database if not already present.
3. Replaces `olcMultiProvider` and the entire `olcSyncrepl` value set to
   match the current peer list — a full replace, not an incremental diff, so
   the config also converges when the peer list shrinks. Each entry's `rid`
   is tied to that peer's 1-based position in `LDAP_REPLICATION_PEERS`
   (stable across every node's config). A node's own entry is left out of
   its own `olcSyncrepl` set — its position in the peer list is assumed to
   equal `LDAP_SERVER_ID` — rather than kept and relied on `slapd` to
   recognize and ignore a self-referencing provider.

This uses a short-lived background `slapd` on the local `ldapi://` socket,
the same mechanism used for first-launch seeding — it's stopped again before
the real, PID-1 `slapd` starts.

Replication binds as `LDAP_REPLICATION_BIND_DN` (default: `$LDAP_ADMIN_DN`,
i.e. the database rootDN), not a dedicated account — the baseline ACL denies
`userPassword` to anyone but the entry's own owner, so a non-root bind DN
would silently stop receiving password replication. If you need a dedicated
replication identity, you'll also need to adjust the ACL.

Exactly one node may create the base DIT (`<LDAP_ROOT_DN>` + admin entry).
If more than one does, each mints its own `entryUUID` for the same DN and
the cluster never converges. Two rules enforce that:

- **Only `LDAP_SERVER_ID` 1 ever creates it.** Every other node starts with
  an empty database and lets `syncrepl`'s initial refresh populate the tree
  — the normal consumer path. Probing peers instead is *not* enough: when a
  cluster is created from scratch, every node probes while every other node
  is still bootstrapping, every probe comes back empty, and every node
  creates its own base entry. This was observed on a 3-node cold start, and
  ordinal-based election avoids it because it requires no communication.
- **Even node 1 defers if a peer already holds the suffix**, probed with a
  short-timeout `ldapsearch`. That covers losing node 1's volume while the
  other nodes still have data: re-minting the base entry there would collide
  with the surviving copy, so it pulls instead.

A consequence worth knowing: bringing up a cluster whose node 1 never starts
leaves the other nodes with an empty directory. They are healthy and will
converge the moment node 1 appears, but they have nothing to serve until
then.

Not supported / out of scope:

- **TLS for replication traffic.** Peer URLs are plain `ldap://`, on the
  assumption that inter-node traffic stays inside a trusted cluster network.
  This is unverified and unsupported beyond that assumption.
- Per-peer credentials — every peer is bound to with the same
  `LDAP_REPLICATION_BIND_DN` / password.

## What gets created (and what does not)

On first launch:

- `<LDAP_ROOT_DN>` — `dcObject` + `organization`
- `<LDAP_ADMIN_DN>` — `organizationalRole` + `simpleSecurityObject`, password hash only
- `ou=policies,<LDAP_ROOT_DN>` and `cn=default,ou=policies,<LDAP_ROOT_DN>` —
  only if `LDAP_PASSWORD_POLICY_ENABLED` is true (the default); see
  [Password policy](#password-policy)

Nothing else. No `employee1`, no `guest1`, no `machine1`, no sample
`groupOfUniqueNames` — that vegardit-style seeding is exactly what this image
was built to avoid. The policy entries above are operational configuration
for the `ppolicy` overlay, not sample content, which is why they don't
violate that principle the way seeded demo users would. Anything beyond
what's listed here is your call via `LDAP_SEED_DIR`.

## Access control (ACL)

The `mdb` database ships with a default-deny-to-anonymous ACL (`olcAccess` on
`olcDatabase={1}mdb,cn=config`), applied in order:

1. `userPassword`, `shadowLastChange`: the entry itself may write; anonymous
   may **bind** against it (`by anonymous auth`) but never **read** it;
   everyone else gets nothing.
2. `entry`, `uid`, `objectClass` only: readable by anonymous *and*
   authenticated users. This is deliberately narrow — it's exactly what a
   search-then-bind login flow needs to resolve a bare `uid` to a DN, and
   nothing more (no `cn`, `mail`, `mobile`, etc. leaks to anonymous).
   The `entry` pseudo-attribute is not optional here: rule 3's
   `by anonymous none` covers `entry` too, so without it an anonymous
   `(uid=...)` search fails with `No such object (32)` — the attribute is
   readable but the entry's existence is never disclosed — and uid login
   breaks entirely. Verified the hard way.
3. Everything else: the entry itself may write, any authenticated user may
   read, anonymous gets nothing.

Without this, slapd's built-in default (`to * by * read`) lets anyone who can
reach port 389 dump the whole tree, `userPassword` included.

As a matrix — rows are what is being reached for, columns are who is reaching:

| Target | anonymous | authenticated user | the entry itself | `cn=admin,<rootDN>` |
|---|---|---|---|---|
| `userPassword`, `shadowLastChange` | bind only, never read | none | write | write |
| `entry`, `uid`, `objectClass` | read | read | read (see below) | write |
| every other attribute | none | read | write | write |
| another user's entry (write or delete) | none | **none** | n/a | write |
| `cn=config` | none | none | n/a | no — it is a separate database with its own admin identity, `cn=admin,cn=config` |
| `cn=Monitor` | none | none | n/a | `cn=monitoring,cn=Monitor` reads; everyone else nothing |

The admin column is the rootdn, which bypasses ACLs by definition — the useful
statement is not that it can do everything but that **nothing else in the first
three columns can write anything outside its own entry**.

Rule 2 has no `by self write`, and the omission is deliberate rather than an
oversight. It would be dead anyway — `by` clauses match in order and `self` is
also a `user`, so an entry reaching for its own `uid` matches `by users read`
first and stops. More to the point it would be wrong if it did apply: rewriting
your own `uid` breaks the relationship between the DN and its naming attribute,
and rewriting your own `objectClass` is how a user grants themselves attributes
the schema would otherwise deny. Self-service writes belong to rule 3 (`to *`),
where `by self write` comes first and does apply — which is why a user can
change their own `sn` and not their own `uid`.

Two things the table is easy to misread. `cn=admin,dc=...` cannot administer
`cn=config`: that database answers to `cn=admin,cn=config`, a different
identity. But the two are given the **same password** (`LDAP_ADMIN_PASSWORD`),
so the separation is one of identity and ACL, not of secret — whoever holds the
directory admin password can also bind to `cn=config` on any listener slapd is
serving. Treat that password as configuration-level access, not directory-level
access, and put the LDAP service behind something that does not expose it to
untrusted networks.

`.github/workflows/security-e2e.yml` enforces the interesting cells rather than
leaving them as intent: an anonymous read of `userPassword`, an authenticated
user modifying, deleting and reading the password of *another* user, and
`cn=config` over the LDAP service all have to be refused — and, because a
deny-everything ACL would satisfy all of that, a user writing their own entry
has to still succeed.

This is one ordered multi-valued attribute, not hardcoded logic — replace it
wholesale for a different policy via `ldapmodify` as `cn=admin,cn=config`
(see below), same as any other `cn=config` change.

Which non-LDAP-CLI clients can actually use this — SSSD/PAM, SASL mechanisms,
Windows, Kubernetes RBAC via OIDC groups — is a separate question from what the
ACL permits; see [docs/client-compatibility.md](../docs/client-compatibility.md).

## Password hashing

The `ppolicy` overlay is enabled on the `mdb` database with
`olcPPolicyHashCleartext: TRUE`, so any client that writes a plaintext
`userPassword` gets it hashed at rest instead of stored verbatim — this
applies unconditionally, without needing a `pwdPolicy` subentry assigned to
every user. The hash scheme is set via `olcPasswordHash` on the frontend
database (`olcDatabase=frontend,cn=config` — setting it on the global
`cn=config` entry is deprecated as of 2.6 and slapd warns/may refuse to
start), driven by `LDAP_PASSWORD_HASH` (default `{ARGON2}`). slapd is built
with `--enable-argon2 --with-argon2=libargon2`, but under `--enable-modules`
that still produces a **loadable module** (`argon2.la`/`.so`), not code
linked into slapd — confirmed with `ldd /usr/lib/slapd` (no argon2
reference). It's loaded via `olcModuleload: argon2.la` in
`image/ldifs/01-cn-config.ldif`, and the bootstrap `slappasswd` call in
`image/entrypoint.sh` loads it explicitly too (`-o module-path=... -o
module-load=argon2`), since `slappasswd` is a standalone binary that never
reads `cn=config`. Argon2 — the current OWASP-recommended password hash —
is available out of the box; its default cost parameters on this build are
`m=7168,t=5,p=1` (7 MiB memory, 5 iterations, 1 thread per hash — worth
knowing for CPU/memory sizing under login load). Set
`LDAP_PASSWORD_HASH={SSHA}` to fall back to salted SHA-1 instead. Switching
this on an already-bootstrapped volume is safe for existing passwords — see
[Other bootstrap-only settings](#other-bootstrap-only-settings).

## Password policy

The `ppolicy` overlay, on its own, only does the hashing described above —
it enforces nothing (no lockout, no expiry, no reuse prevention, no
complexity) unless it has a `pwdPolicy` entry to apply. By default this
image creates one, `cn=default,ou=policies,<LDAP_ROOT_DN>`, and points the
overlay at it via `olcPPolicyDefault`. Both halves — the entry and the
`olcPPolicyDefault` pointer — are gated by the same
`LDAP_PASSWORD_POLICY_ENABLED` and always created or omitted together: a
pointer with no entry behind it is a dangling reference, not a graceful
no-op.

**Why this exists:** without it, self-service password change is silently
broken. `pwdSafeModify` — which makes a Modify of `userPassword` require the
*current* password as proof of identity — only exists as an attribute on a
`pwdPolicy` entry; there's no way to turn it on without one. The observed
failure mode before this policy existed:

```
# old password supplied
LDAP Result Code 53 "Unwilling To Perform": unwilling to verify old password
# old password omitted
# ...succeeds anyway, HTTP 200 — no verification happened at all
```

i.e. the check was unconditionally rejected either way, not merely absent.
`pwdSafeModify: TRUE` on the default policy fixes both: supplying the
correct current password now succeeds, and any self-service change flow
that doesn't ask for it will start failing loudly (53) instead of silently
skipping verification — which is the point.

The default policy, and the rationale for values not exposed as env vars:

| Attribute | Value | Why |
|---|---|---|
| `pwdAttribute` | `userPassword` | The only password attribute this schema uses. |
| `pwdCheckQuality` | `1` | Must be `>=1` for `pwdMinLength` to be enforced at all. `1` (not `2`) so writes still succeed if a quality-check module is ever unavailable — length is checked either way. |
| `pwdMinLength` | `LDAP_PASSWORD_MIN_LENGTH` (default `8`) | Configurable — see env table. |
| `pwdInHistory` | `5` | Reuse prevention; fixed, change via `ldapmodify` if needed. |
| `pwdLockout` | `TRUE` | Turns failed-bind counting into actual lockout, paired with the two settings below. |
| `pwdMaxFailure` | `LDAP_PASSWORD_MAX_FAILURE` (default `5`) | Configurable — see env table. |
| `pwdLockoutDuration` | `LDAP_PASSWORD_LOCKOUT_DURATION` (default `900`) | Configurable — see env table. |
| `pwdMaxAge` | `0` (no forced expiry) | Deliberate: NIST 800-63B recommends against mandatory periodic rotation — it measurably pushes users toward weaker, more predictable passwords instead of stronger ones. `pwdMaxFailure`/lockout is the real defense against credential guessing; a rotation timer isn't. |
| `pwdSafeModify` | `TRUE` | See above — this is the one that fixes self-service password change. |

`olcPPolicyUseLockout` on the overlay itself is deliberately left **unset**
(`FALSE`, the default): turning it on makes a locked-out bind return a
distinct "account locked" error instead of the generic invalid-credentials
one, which leaks account existence to anyone probing logins. The generic
error is the safer default for anything reachable outside a fully trusted
network.

To change anything not exposed as an env var, edit the policy entry
directly once the volume is bootstrapped:

```bash
docker exec ldap ldapmodify -x -H "ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi" \
  -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" <<'EOF'
dn: cn=default,ou=policies,dc=example,dc=org
changetype: modify
replace: pwdInHistory
pwdInHistory: 10
EOF
```

(This binds as `LDAP_ADMIN_DN`, not `cn=admin,cn=config` — the policy entry
lives under `LDAP_ROOT_DN` in the `mdb` database, not in `cn=config`.)

### Unlocking a locked account

With `pwdLockout` on, `pwdMaxFailure` consecutive bad binds set
`pwdAccountLockedTime` on the entry and every subsequent bind fails with
`Invalid credentials (49)` — including binds with the *correct* password.
The lock clears itself after `pwdLockoutDuration` seconds (default 900), but
an administrator usually wants it gone now.

Delete **only** `pwdAccountLockedTime`:

```bash
docker exec -i ldap ldapmodify -x -H "ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi" \
  -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" <<'EOF'
dn: uid=alice,ou=people,dc=example,dc=org
changetype: modify
delete: pwdAccountLockedTime
EOF
```

Do not try to clear `pwdFailureTime` in the same operation, or at all — it is
NO-USER-MODIFICATION and the server rejects the whole modify:

```
ldap_modify: Constraint violation (19)
	additional info: pwdFailureTime: no user modification allowed
```

Because LDAP modifies are atomic, bundling the two means the unlock silently
does nothing. Delete `pwdAccountLockedTime` by itself; the stale
`pwdFailureTime` values are harmless and age out on their own.

On a replicated deployment the lock replicates, so an account locked on one
node is locked on all of them — and one unlock likewise propagates. (Verified
on a 3-node cluster: the lock set by failed binds against node 0 also
rejected the correct password on node 2.)

## Modules and overlays

`memberof`, `refint`, `ppolicy`, and `unique` are loaded **and enabled** on
the `mdb` database by default (`unique`'s attribute set is configurable —
see [Uniqueness enforcement](#uniqueness-enforcement)). `syncprov` is
loaded as a module but left uninstantiated — it needs a replication
topology no image can guess; it's either enabled by hand against
`cn=config` (see below) or automatically by setting
`LDAP_REPLICATION_ENABLED` (see [Replication](#replication)).
`LDAP_SEED_DIR` itself only ever binds as `LDAP_ADMIN_DN`, so it can't reach
`cn=config` to enable anything there (see why below).

The following are loaded as modules (`olcModuleload`) but deliberately
**not** instantiated as overlays — each needs a deployment-specific
decision the image can't make for you, and turning one on is the same
`ldapmodify` against `cn=admin,cn=config` as any other. `accesslog` and
`auditlog` are also loaded but are *not* in this table: both graduated to
chart values (`audit.enabled`, `audit.accessLog.enabled`) — see
`charts/ldapium/README.md`, "Audit" — precisely because retention and a
storage decision were the blockers here, and the chart now makes both for
you rather than leaving them for a manual `ldapmodify`.

| Module | What it's for | Why it isn't on by default |
|---|---|---|
| `constraint` | Per-attribute value constraints (regex, size, count, ...). | The constraints themselves are entirely deployment-specific. |
| `deref` | Resolves a grouping attribute (e.g. `member`) in the same round-trip as the search that returns it, instead of one lookup per member. | Only worth enabling once member-list sizes make N+1 lookups actually hurt — no downside to leaving it off otherwise. |
| `dynlist` | Dynamic groups (`memberURL`-based). | Needs a group schema decision (which objectClass carries `memberURL`). |
| `sssvlv` | Server-side sort + virtual list view — paging through large result sets without pulling all of them. | No config needed beyond enabling it; left off by default only because it's paired with the other scale-prep modules here, not because it's risky. |
| `otp` | TOTP 2FA (RFC 6238). | Needs per-user enrollment before it can gate anything — enabling the module alone changes no behavior. |

The `mdb` database also gains four new indexes over the two-attribute set
used to ship (`objectClass`, `entryUUID`, `entryCSN`, `uid`, `cn`, `mail`):
`memberOf eq`, `member eq`, `sn pres,eq,sub`, `givenName eq` — ahead of the
UI actually needing `memberOf`-filtered searches, since building an index
after the fact on a live database needs an offline `slapindex` pass.

## Uniqueness enforcement

The `unique` overlay rejects an Add/Modify that would create a second entry
sharing a value with an existing one, on any attribute listed in
`LDAP_UNIQUE_ATTRIBUTES` (default `uid,mail`). This matters because LDAP
itself doesn't stop `uid=alice,ou=a` and `uid=alice,ou=b` from coexisting —
they're different DNs — and in a deployment federating through Keycloak
with `usernameLDAPAttribute: uid`, a duplicate `uid` is an account
collision. One `olcUniqueURI` value is generated per attribute (each is its
own independent uniqueness domain — combining attributes into a single URI
would mean "the combination is unique" instead of "each one is unique"),
scoped to `(objectClass=inetOrgPerson)` so the `organizationalRole` admin
entry (which has no `uid`) isn't pulled into the check.

Set `LDAP_UNIQUE_ATTRIBUTES=` (empty) to disable the overlay outright — it
is then never created, not created with nothing to enforce.

**Limitations, worth knowing before relying on this:**

- **Not a guarantee under multi-provider replication.** Two nodes accepting
  writes for the same `uid` at the same time each pass their own local
  check before either write has replicated — both succeed, and the
  duplicate surfaces only after sync. `unique` only ever protects a single
  node's write path, not the cluster as a whole. See
  [Replication](#replication).
- **Existing data is never checked.** The overlay only inspects entries as
  they're written from the moment it's active; it does nothing to a
  directory that already has duplicate values before `unique` was enabled.
- **`slapadd` bypasses it entirely.** Bootstrap and any offline restore via
  `slapadd` write straight to the database file, with no overlay in the
  path — uniqueness is only enforced for online writes through `slapd`
  (`ldapadd`/`ldapmodify`).

## Managing `cn=config` (advanced)

The config backend (`cn=config`) is intentionally locked down: it is not
reachable by `LDAP_ADMIN_DN` (that identity only has rights on the `mdb`
database), and since `slapd` runs as a non-root user it gets no implicit
access via SASL EXTERNAL either. A second identity scoped only to the config
backend is created at bootstrap instead — **`cn=admin,cn=config`**, using the
same `LDAP_ADMIN_PASSWORD`:

```bash
docker exec ldap ldapmodify -x -H "ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi" \
  -D "cn=admin,cn=config" -w "$LDAP_ADMIN_PASSWORD" -f my-overlay.ldif
```

This is a separate, manual step — `LDAP_SEED_DIR` LDIFs are always applied as
`LDAP_ADMIN_DN` and are meant for content under `LDAP_ROOT_DN` (OUs, groups,
users, ACLs on the `mdb` database), not for `cn=config` itself.

(`cn=admin,cn=config` can't simply be added as another `olcRootDN` value on
the `mdb` database entry: the config backend's own
`olcDatabase={0}config,cn=config` entry is created implicitly by `slapd`
itself, so it can only be customized with an offline `slapmodify`, not
`slapadd` — see `image/ldifs/02-cn-config-admin.ldif`.)

## Runtime hygiene

- Runs as a non-root `ldap` user for the entire container lifetime (no `USER root` step, no privilege drop needed).
- Data directory (`/var/lib/openldap/data`) is mode `700`.
- `VOLUME`s: `/etc/openldap/slapd.d` (config) and `/var/lib/openldap/data` (data).
- `EXPOSE 389 636`.
- `HEALTHCHECK` runs `ldapwhoami` over the local `ldapi://` Unix socket.

## Operational tools available in the image

`slapcat`, `slapindex`, `slaptest`, `slapadd`, `slappasswd`, and the full
`ldap*` client suite (`ldapsearch`, `ldapadd`, `ldapmodify`, `ldapwhoami`, ...)
are all present under `/usr/sbin` and `/usr/bin` respectively for operational
use (`docker exec`), e.g.:

```bash
docker exec ldap slapcat -F /etc/openldap/slapd.d -n 1
```
