# ldapium image

A from-source OpenLDAP **2.6.15** container image that this project owns outright —
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

Multi-stage build: a `debian:trixie-slim` builder stage compiles OpenLDAP 2.6.15
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
| `LDAP_ANONYMOUS_READ_BASE` | no | `""` (whole DIT) | Must sit under `LDAP_ROOT_DN` if set. Narrows anonymous read of `entry`/`uid`/`objectClass` (see [Access control (ACL)](#access-control-acl)) to this subtree instead of the whole directory; a bind-then-search client (SSSD, this project's UI) can still resolve a `uid` from a root-base search, but anonymous can no longer enumerate entries outside this base. Applied at bootstrap only (see below). |
| `LDAP_ADMIN_PASSWORD` | **yes**\* | — | No default, ever. Container refuses to start if unset. Hashed with `slappasswd -h "$LDAP_PASSWORD_HASH"` before it touches disk — never stored in plaintext. |
| `LDAP_ADMIN_PASSWORD_FILE` | no\* | — | Path to a file containing the admin password (for secret mounts). Takes precedence if both are set and readable. |
| `LDAP_LOG_LEVEL` | no | `stats` | Passed to `slapd -d`. Any value (including a quiet one) keeps slapd in the foreground, which is required for it to run as PID 1. |
| `LDAP_TLS_ENABLED` | no | `false` | `true`/`1` to enable `ldaps:///`. |
| `LDAP_TLS_CERT_FILE` | if TLS enabled | — | `olcTLSCertificateFile`. |
| `LDAP_TLS_KEY_FILE` | if TLS enabled | — | `olcTLSCertificateKeyFile`. |
| `LDAP_TLS_CA_FILE` | no | — | `olcTLSCACertificateFile`, optional even with TLS enabled. |
| `LDAP_TLS_MUTUAL_AUTH` | no | `false` | `true`/`1` enables client-certificate verification and SASL `EXTERNAL`; requires `LDAP_TLS_ENABLED=true` and `LDAP_TLS_CA_FILE`. Uses `olcTLSVerifyClient: try`, so a client certificate is requested but not required and existing password binds remain available. |
| `LDAP_TLS_AUTHZ_REGEXP` | if mutual auth enabled | `^cn=([^,]+)$` | `olcAuthzRegexp` match expression for OpenLDAP's normalized SASL EXTERNAL certificate-subject DN. Override for the subject DN shape issued by your CA; an explicitly empty value is rejected. |
| `LDAP_TLS_AUTHZ_DN` | if mutual auth enabled | `uid=$1,${LDAP_ROOT_DN}` | `olcAuthzRegexp` replacement DN. The default maps the matching certificate CN to a `uid` below the base DN; override it for your DIT. An explicitly empty value is rejected. |
| `LDAP_SEED_DIR` | no | `/opt/ldifs` | Every `*.ldif` in this directory is applied, in sorted order, via `ldapadd` — **once, on the first bootstrap of the node that creates the base DIT**. A failed seed rolls back the whole bootstrap and is retried on the next start; replicas skip seeding and receive the data by replication. Your extension point for OUs, groups, real users, ACLs, etc. |
| `LDAP_SIZE_LIMIT` | no | `10000` | `olcSizeLimit` on the `mdb` database. Digits, or `unlimited`. Applied at bootstrap only (see below). |
| `LDAP_PAGED_TOTAL_LIMIT` | no | unset | Opt-in, **stateless**: unset = hands off (no `olcLimits` rule is read, changed or removed); a positive integer up to `2147483647` or `unlimited` = converge to exactly one rule `users size.prtotal=<value>` appended after the operator's rules, so an authenticated non-root identity can page past `LDAP_SIZE_LIMIT`; `off` = remove exactly `users size.prtotal=<value>`. The selector `users` is reserved while the setting is on. Any failure to apply, verify or restore aborts startup. See [Paged-search total](#paged-search-total-ldap_paged_total_limit). `0`, leading zeros, other non-digits and anything above 2147483647 are refused. |
| `LDAP_TIME_LIMIT` | no | `3600` | `olcTimeLimit` on the `mdb` database, in seconds. Digits, or `unlimited`. Applied at bootstrap only (see below). |
| `LDAP_PASSWORD_HASH` | no | `{ARGON2}` | `olcPasswordHash` on the frontend database, and the scheme used to mint the bootstrap admin hash. Any `{SCHEME}`-shaped value slapd supports (e.g. `{SSHA}`). Applied at bootstrap only (see below). |
| `LDAP_UNIQUE_ATTRIBUTES` | no | `uid,mail` | Comma-separated attributes the `unique` overlay enforces uniqueness on. **Empty string disables the overlay entirely** — it is not created at all, rather than created with nothing to check. See [Uniqueness enforcement](#uniqueness-enforcement). Applied at bootstrap only (see below). |
| `LDAP_PASSWORD_POLICY_ENABLED` | no | `true` | `false`/`0` disables the whole password policy: no `ou=policies`/`cn=default` entries, no `olcPPolicyDefault` on the `ppolicy` overlay. See [Password policy](#password-policy). Applied at bootstrap only (see below). |
| `LDAP_PASSWORD_MIN_LENGTH` | no | `8` | `pwdMinLength` on the default policy. Digits only. |
| `LDAP_PASSWORD_MAX_FAILURE` | no | `5` | `pwdMaxFailure` — failed binds before lockout. Digits only. |
| `LDAP_PASSWORD_LOCKOUT_DURATION` | no | `900` | `pwdLockoutDuration` in seconds. Digits only. |
| `LDAP_PASSWORD_FAILURE_INTERVAL` | no | `900` | `pwdFailureCountInterval` in seconds: how long a failed bind counts toward `LDAP_PASSWORD_MAX_FAILURE`. Digits only. Bootstrap only. |
| `LDAP_IDLE_TIMEOUT` | no | `600` | `olcIdleTimeout` (seconds; `0` disables). Reconciled on every start. Digits only. |
| `LDAP_WRITE_TIMEOUT` | no | `30` | `olcWriteTimeout` (seconds; `0` disables). Reconciled on every start. |
| `LDAP_CONN_MAX_PENDING` | no | `100` | (`olcConnMaxPending*` and `olcSockbufMaxIncoming*` pin slapd's compiled defaults explicitly; they do not newly cap.) `olcConnMaxPending`: queued requests per anonymous connection. |
| `LDAP_CONN_MAX_PENDING_AUTH` | no | `1000` | `olcConnMaxPendingAuth`: queued requests per authenticated connection. |
| `LDAP_SOCKBUF_MAX_INCOMING` | no | `262143` | `olcSockbufMaxIncoming`: max incoming PDU size, anonymous. |
| `LDAP_SOCKBUF_MAX_INCOMING_AUTH` | no | `4194303` | `olcSockbufMaxIncomingAuth`: max incoming PDU size, authenticated (bulk `ldapmodify`/large member lists need this headroom). |
| `LDAP_MAX_FILTER_DEPTH` | no | `20` | `olcMaxFilterDepth`: rejects deeply nested search filters. |
| `LDAP_TLS_EC_NAME` | no | `""` (unset) | `olcTLSECName` (ECDHE curve), written only when `LDAP_TLS_ENABLED` and non-empty; empty removes it (OpenSSL negotiates). Validated at startup against `[A-Za-z0-9_-]+` and `openssl ecparam -list_curves`, since a bad name would stop slapd on the next boot. No DH parameter file. Reconciled on every start. |
| `LDAP_LASTBIND_ENABLED` | no | `false` | `true`/`1` sets `olcLastBind: TRUE` on the main `mdb` database, so a successful bind records `pwdLastSuccess`. Opt-in. **WARNING: keep it off with multi-provider replication** (see below): in one observed run it silently reverted a password change made on another node during a partition. |
| `LDAP_LASTBIND_PRECISION` | no | `3600` | `olcLastBindPrecision` (seconds): `pwdLastSuccess` is rewritten at most once per user per interval. Only applied when `LDAP_LASTBIND_ENABLED`. Digits only. |
| `LDAP_REQUIRE_TLS` | no | `false` | `true`/`1` sets `olcSecurity: ssf=128` (plaintext TCP binds/operations are refused) and `olcLocalSSF: 128` so `ldapi://` keeps working. Only `ssf=` is used, not `tls=`: `tls=` refuses `ldapi://` outright. Requires clients on `ldaps://`/StartTLS, so pair with `LDAP_TLS_ENABLED=true`. Refused at startup if any `LDAP_REPLICATION_PEERS` entry is not `ldaps://` (peers would refuse plaintext syncrepl). Opt-in. |
| `LDAP_DISALLOW_ANON_BIND` | no | `false` | `true`/`1` sets `olcDisallows: bind_anon`. Refused at startup together with `LDAP_ANONYMOUS_READ_BASE`. Opt-in. |
| `LDAP_REQUIRE_AUTHC` | no | `false` | `true`/`1` sets `olcRequires: authc` (no operation before an authenticated bind). Refused at startup together with `LDAP_ANONYMOUS_READ_BASE`. Opt-in. |
| `LDAP_PPM_ENABLED` | no | `true` | Rollback: set `false` and restart once before downgrading to an older image (see [Rollback](#rollback-and-downgrade)). Sets `olcPPolicyCheckModule: /usr/lib/openldap/ppm.so` on `ppolicy` and, when `LDAP_PASSWORD_POLICY_ENABLED`, `pwdUseCheckModule`/`pwdCheckModuleArg` on `cn=default,ou=policies`. ppm is built without cracklib (no dictionary check). Reconciled on every start. |
| `LDAP_PPM_MIN_CLASSES` | no | `1` | `0`-`4`: character classes (upper, lower, digit, special) a password must touch (`minQuality`). `1` is nearly permissive (only a password with no ASCII letter, digit or punctuation is refused). ppm counts ASCII character classes only, so a Hangul-only passphrase is rejected when this is above 1. Written to the policy at bootstrap; re-applied on later starts only when this variable is explicitly set (unset leaves the operator's `ldapmodify` value alone). |
| `LDAP_DEREF_ENABLED` | no | `true` | `true`/`1`/`false`/`0`: `deref` overlay (member dereference in the search round-trip). |
| `LDAP_CONSTRAINT_ENABLED` | no | `true` | `constraint` overlay enforcing `LDAP_CONSTRAINT_MAIL_REGEX` on `mail`. Client writes only; replication updates bypass it. |
| `LDAP_CONSTRAINT_MAIL_REGEX` | no | `^[^@[:space:]]+@[^@[:space:]]+$` | Regex for `mail`. Single line. |
| `LDAP_NESTGROUP_ENABLED` | no | `false` | `nestgroup` overlay (nested groups). Opt-in. |
| `LDAP_NESTGROUP_BASE` | no | `$LDAP_ROOT_DN` | `olcNestGroupBase`. Single line. |
| `LDAP_NESTGROUP_FLAGS` | no | `member-filter memberof-filter` | Space-separated `olcNestGroupFlags`: `member-filter`, `memberof-filter`, `member-values`, `memberof-values`. The `*-values` flags are refused with `LDAP_REPLICATION_ENABLED` (expanded values would enter the syncrepl stream; reasoned, not verified). |
| `LDAP_DYNLIST_ENABLED` | no | `false` | `dynlist` overlay; also loads `dyngroup.schema` (`groupOfURLs`, `memberURL`). Refused with `LDAP_REPLICATION_ENABLED` (same syncrepl reasoning). Opt-in. |
| `LDAP_DYNLIST_ATTRSET` | no | `groupOfURLs memberURL member` | `olcDynListAttrSet`. Single line. |
| `LDAP_SSSVLV_MAIN_ENABLED` | no | `false` | `sssvlv` overlay on the main database (server-side sort / VLV). Opt-in. |
| `LDAP_SSSVLV_MAX` / `_MAX_KEYS` / `_MAX_PER_CONN` | no | `10` / `5` / `5` | `olcSssVlvMax`, `olcSssVlvMaxKeys`, `olcSssVlvMaxPerConn`. Digits only. |
| `LDAP_OTP_ENABLED` | no | `false` | `otp` overlay (TOTP; needs per-user enrollment). Opt-in. |
| `LDAP_REPLICATION_ENABLED` | no | `false` | `true`/`1` enables N-way multi-provider replication. See [Replication](#replication) below. |
| `LDAP_REPLICATION_PEERS` | if replication enabled | — | Comma-separated LDAP URLs of **every** node, including this one, e.g. `ldap://ols-0.ols-hl.ns.svc.cluster.local:389,ldap://ols-1.ols-hl.ns.svc.cluster.local:389`. |
| `LDAP_SERVER_ID` | no | hostname's numeric ordinal suffix + 1 | `1`..`4095`. Auto-derivation expects a hostname ending in `-<N>` (e.g. `ols-0`); if it doesn't, the container refuses to start rather than risk two nodes silently sharing an ID. |
| `LDAP_REPLICATION_BIND_DN` | no | `$LDAP_ADMIN_DN` | Identity peers use to bind for replication. |
| `LDAP_REPLICATION_PASSWORD` | no | `$LDAP_ADMIN_PASSWORD` | |
| `LDAP_REPLICATION_PASSWORD_FILE` | no | — | Path to a file containing the replication password; takes precedence if set and readable. |
| `LDAP_REPLICATION_IDENTITY` | no | `admin` | Staged (change package `docs/changes/replication-identity`, #229). `admin` is today's behavior and changes nothing. `prepare` (T-011) installs the identity's read-only ACL as the first `olcAccess` rule plus its `olcLimits` for `cn=replicator,<LDAP_ROOT_DN>` at start (offline, verified, a no-op on the next start) and **still replicates as the admin identity**; it does not create the identity entry and refuses to start when the node already has an entry at that DN without the rule, when `cn=config` stores `olcAuthzRegexp`, `olcAuthIDRewrite`, an `olcAuthzPolicy` other than `none`, an `olcTLSVerifyClient` other than `never` (so not with `LDAP_TLS_MUTUAL_AUTH`) or an `olcRootDN` / replication bind DN equal to that DN (compared as slapd normalizes DNs, so case, spacing, hex escapes and quoting do not hide an alias; an unparseable DN is refused), when any entry carries `authzTo`/`authzFrom`, and for a serverID-1 start on a fresh volume (start new clusters in `admin`). `dedicated` (T-012) makes syncrepl bind as that identity instead of the admin DN, over verified TLS, and runs **every node as a consumer, serverID 1 included**: no base DIT is created, no peer is probed or waited for, and a node that is wiped, has wrong credentials or has no peer up simply stays empty and retries instead of creating a second directory tree. It installs the same ACL/`olcLimits` as `prepare` (same refusals; its own stored syncrepl bind DN is the identity by design and is not a conflict) and renders `bindmethod=simple binddn="cn=replicator,<LDAP_ROOT_DN>" credentials=<LDAP_REPLICATION_PASSWORD> tls_reqcert=demand tls_cacert=<LDAP_TLS_CA_FILE>`. It never creates the identity entry (the operator creates it on the live cluster; the `ensure` command is a later unit) and an absent or wrong entry or password shows up as consumer `rc 49`, not at start. A `dedicated` start is **refused with a fixed message, never falling back to the admin identity, and before anything is written** (stored-config refusals before the single cn=config write) when: `LDAP_REPLICATION_PASSWORD(_FILE)` is missing or fails the hygiene check (printable ASCII 0x21-0x7E only, no spaces; ≥ 32 characters, ≥ 10 distinct; different from the admin password; a hygiene check, not proof of randomness); `LDAP_TLS_ENABLED` is not true, `LDAP_TLS_CA_FILE` is missing/unreadable (or has whitespace, quotes or a backslash in its path), or any `LDAP_REPLICATION_PEERS` entry is not `ldaps://` (`starttls` is not offered); `LDAP_TLS_MUTUAL_AUTH` is on or `cn=config` stores `olcTLSVerifyClient` ≠ `never` or `olcAuthzRegexp`; `olcAuthIDRewrite` is stored, `olcAuthzPolicy` is not `none`, or an entry carries `authzTo`/`authzFrom`; the reserved DN equals `LDAP_ADMIN_DN` or any stored `olcRootDN` (compared as slapd-normalized DNs); a custom `LDAP_REPLICATION_BIND_DN` is set; or an entry already exists at the reserved DN without the ACL. Invalid values, a non-admin mode without `LDAP_REPLICATION_ENABLED`, and `LDAP_ADMIN_DN` equal to the reserved DN are refused in every non-admin mode, and `prepare` refuses an explicit replication password. **Status: effective but not yet a supported production mode.** The package's acceptance conditions are open (Kubernetes OrderedReady/StatefulSet recovery, restore.sh total-loss path D63, rolling credential rotation, the `ensure`/`rotate`/`retire`/`reconcile` commands, the cross-node checks, the chart), so use it only on a test cluster. The only validated order is `admin` → `prepare` on every node → the identity entry created by an administrator → `dedicated` node by node; a new cluster cannot start in `dedicated` (nothing creates the base DIT), and `prepare` refuses to start on a volume whose stored syncrepl already binds as the identity, so roll back by starting the node in `admin`, which re-renders `olcSyncrepl` with the admin DN (the ACL stays, harmlessly). Refusals from the environment checks happen before anything is written to the volumes; the `cn=config` based `prepare` refusals leave `cn=config` unchanged. |
| `LDAP_REPLICATION_RETRY` | no | `5 10 30 +` | `olcSyncrepl` `retry=` value. |
| `LDAP_REPLICATION_INTERVAL` | no | `00:00:00:10` | `olcSyncrepl` `interval=` value. |

\* Exactly one of `LDAP_ADMIN_PASSWORD` / `LDAP_ADMIN_PASSWORD_FILE` must resolve to a non-empty value.

### TLS caveat

TLS settings are only written into `cn=config` at bootstrap time. Enabling
`LDAP_TLS_ENABLED` against an already-bootstrapped data/config volume has no
effect — either seed a fresh volume with TLS enabled from the start, or edit
`cn=config` by hand (`olcTLSCertificateFile` etc. under `cn=config`).

When `LDAP_TLS_MUTUAL_AUTH=true`, the image writes `olcTLSVerifyClient: try`
and one `olcAuthzRegexp` from `LDAP_TLS_AUTHZ_REGEXP` and
`LDAP_TLS_AUTHZ_DN`. `try` verifies any client certificate presented by a
client trusted by `LDAP_TLS_CA_FILE`, but does not require one; TLS clients
without a certificate continue to use a normal password/SIMPLE bind. The
default regexp/replacement is an example for `CN=<uid>` certificates and a
flat `uid=<uid>,${LDAP_ROOT_DN}` user layout, not a universal CA convention;
set both variables for the certificate subject and DIT you operate.

**`LDAP_TLS_CA_FILE` must be a CA dedicated to this directory's client
certificates when mutual auth is on — never a shared/general-purpose CA.**
Verified live: a certificate signed by that CA whose subject does not match
`LDAP_TLS_AUTHZ_REGEXP` still binds successfully (OpenLDAP falls back to the
raw certificate-subject identity — this holds for both the static-DN and the
`ldap:///…??sub?(…)` search-URI forms of `olcAuthzRegexp`; neither rejects an
unresolved identity). That bind still satisfies `by users` in this image's
default ACLs, which grant any authenticated identity broad read access
across the DIT (see `docs/client-compatibility.md`'s SASL section for the
full verification and #76 for the ACL this depends on) — so **any**
certificate from that CA gets this directory's baseline read access, whether
or not `LDAP_TLS_AUTHZ_REGEXP` was ever meant to cover its subject. There is
no way to scope this down with `LDAP_TLS_AUTHZ_REGEXP` alone.

### Hardening settings are reconciled on every start

Unlike the bootstrap-only settings below, the OpenLDAP 2.6 hardening and
optional-module variables (`LDAP_IDLE_TIMEOUT` through `LDAP_OTP_ENABLED`,
plus `LDAP_TLS_EC_NAME` when TLS is on) are re-applied to `cn=config` on every
start by offline `slapmodify` (entrypoint sections 3b/3c, no temporary slapd),
so changing one, or upgrading the image over an existing volume, takes effect
on the next restart. Turning an opt-in back off removes the attribute, and
for overlays (`deref`, `constraint`, `nestgroup`, `dynlist`, `sssvlv`, `otp`)
removes the overlay entry. Two things are deliberately left behind: the
`olcModuleLoad` line and, for `dynlist`, the `dyngroup` schema stay in
`cn=config` (removing a schema from under entries that may use it is not a
reconcile's call). The ppm arguments on `cn=default,ou=policies` are only
written when the ppm wiring is missing (fresh bootstrap, or a volume from an
older image) and afterwards left to the operator's `ldapmodify` tuning; they are
re-applied only when `LDAP_PPM_MIN_CLASSES` is explicitly set in the
environment. These are offline writes (no `-S`/`-w`): stamped with server ID
000, no `contextCSN` update, so they are **not replicated** and each node
applies its own.

**Ownership rule.** Group A limits and any opt-in switched ON are env-owned and
overwritten each start. An opt-in switched OFF removes its attribute
(`olcSecurity: ssf=128`, `olcLocalSSF: 128`, `olcDisallows: bind_anon`,
`olcRequires: authc`, `olcLastBind: TRUE` + precision, the ppm module path,
`pwdUseCheckModule: TRUE`) only when the current value is exactly what the
entrypoint writes; any other value was set by an operator and is left in place
with a `leaving operator-set ...` log line. `olcTLSECName` is env-driven: it is
removed when `LDAP_TLS_EC_NAME` is empty or TLS is off.

### Paged-search total (`LDAP_PAGED_TOTAL_LIMIT`)

`LDAP_SIZE_LIMIT` (default `10000`) is also a ceiling on the **total** of an
RFC 2696 paged search: a non-root identity cannot page past it however small
the pages are. Measured on this image against a 12001-entry subtree
(`ldapsearch -E pr=500/noprompt`): a normal user receives exactly 10000
entries and then `Size limit exceeded (4)`, while `LDAP_ADMIN_DN` (rootDN,
exempt from limits) receives all 12001. Clients that must enumerate more than
`LDAP_SIZE_LIMIT` entries as a non-root identity (for example the `limit`/
`cursor` mode of `GET /api/users` when the UI is bound as a normal user or an
SSO service account) need the paged total lifted:

```bash
docker run -e LDAP_PAGED_TOTAL_LIMIT=unlimited ... ldapium   # or e.g. 50000
```

**The contract is stateless and explicit.** The setting is a command, not a
file of remembered state; every start converges to what the variable says
(verified live, `scripts/test/test-paged-total-limit.sh`):

| `LDAP_PAGED_TOTAL_LIMIT` | what the entrypoint does |
|---|---|
| unset / empty | **Hands off.** No `olcLimits` rule is read, changed or removed, and nothing is recorded. An operator's own `users size.prtotal=500` stays as it is. |
| `<1..2147483647>` or `unlimited` | Converge to exactly one rule `users size.prtotal=<value>`, **appended** after the existing rules. Already there: no write. A `users size.prtotal=<other value>` rule is the setting's own shape and is changed to the value. A `users` rule of any other shape (e.g. `users size.soft=50 ...`) is a conflict: startup **aborts** and the operator decides. |
| `off` | Remove exactly `users size.prtotal=<any value>`. A differently shaped `users` rule aborts startup (default-deny). Nothing to remove: no-op. |

Because the selector `users` is reserved while the setting is on, the rule
this setting manages is recognised by its shape, not by a remembered marker. The
classification is **default-deny** and done by one awk program (linear time: an
8 KiB or 64 KiB `dn.regex` rule costs milliseconds), one outcome per stored rule:

- **not ours:** the first token, after quote removal and case folding, is not
  `users`: left alone;
- **managed:** selector `users` with only a `size.prtotal` limit whose value is
  parsed with certainty: converged, replaced or removed;
- **abort:** anything else whose first token is `users` (another limit alongside,
  any other argument) or that the parser is not certain about: startup aborts in
  set/off mode before any change. There is no "other shape, ignore" fall-through
  (so `off` does not silently skip a rule it cannot place).

Exactly what is parsed (probed on the image's slapd 2.6.15): tokens split on any
`isspace()` character (space, tab, VT, FF, CR, NL); a double quote toggles a quoted
segment anywhere in a token (`"users"`, `size.prtotal="unlimited"`, `us"ers"`),
quotes are removed and white space inside them belongs to the token, so a quoted
DN stays one token; an empty argument (`""`) after the selector is ignored; selector,
keys and keywords are case-insensitive; the value is trimmed and read as
`unlimited`/`none`/`-1` (any zero padding), `disabled`, `hard`, or a decimal integer
(optional sign, zero padding, `-0` is 0, below -1 aborts, more than 10 digits
aborts). Also aborting: an unterminated quote, a backslash before a double quote, a
backslash in a `users` rule or in a first token that becomes `users` without it, a
rule without tokens, a value that cannot be base64 decoded, a value without a
`{N}` index, an unreadable or empty config dump. Desired and stored values are
compared by parsed value, so `USERS<TAB>SIZE.PRTOTAL=" 0900"` equals `900` and is
not rewritten. Unset never reads the config, so none of this can stop an unset start.

slapd applies only the *first* matching `olcLimits` rule and allows one rule per
selector: the rule is appended, so a rule you wrote for a DN or a group keeps its
effect for the identities it matches (verified: an operator
`dn.exact="..." size.soft=100 size.hard=100 size.prtotal=100` stays in force for
that DN), and the total is lifted for the remaining authenticated identities.

**Fail closed, both directions.** The change is applied after a verified backup
of the database's config file (non-empty and identical), and what is stored
afterwards is read back and compared. If anything fails (backup, modify,
verification), the file is restored through a copy in the same directory and an
atomic rename, and startup **aborts** with `paged-total reconcile failed;
refusing to start`; a restore that cannot be completed aborts with its own
message rather than run slapd on a half-written config. Nothing is served on a
policy that was not proven, whether the request raised or lowered the limit.
A crash between the change and the end of the start leaves a valid config, and
the next start converges (no marker can disagree with it).

What it does and does not change:

- `users` matches every **authenticated** DN; anonymous binds keep the old cap.
- An **unpaged** search by the same identity is still capped by
  `LDAP_SIZE_LIMIT`; only paged searches are affected. The per-page size is not
  capped: `size.pr` is never set because a client asking for a larger page than
  `size.pr` fails with `Administrative limit exceeded (11)`.
- A number caps the paged total at that number (also with `sizeLimitExceeded`
  at the cap); `unlimited` removes the cap.

**Security cost.** Any authenticated user can then page through everything
their ACLs let them read, which weakens `LDAP_SIZE_LIMIT`'s role as a last
backstop against a bulk dump. ACLs still apply. Leave it unset unless an API or
sync client needs a full non-root enumeration, and use `off` (not just unsetting
the variable) to take the rule away again.

To change the rule without a restart, as `cn=admin,cn=config`, use
`ldapmodify` on `olcDatabase={1}mdb,cn=config` (`add: olcLimits` /
`olcLimits: users size.prtotal=unlimited`, or `delete: olcLimits` with the
stored value including its `{N}`); the next start with the variable set
converges back to it.

### Rollback and downgrade

An older image does **not** ignore what a newer one wrote. With
`LDAP_PPM_ENABLED=true` (default) the upgraded volume holds
`olcPPolicyCheckModule: /usr/lib/openldap/ppm.so` (plus `nestgroup.la` when
enabled); an image without `ppm.so` fails at config load
(`lt_dlopen(/usr/lib/openldap/ppm.so) failed: file not found`) and slapd
crash-loops. Before rolling back to an image that predates these modules,
restart once on the NEW image with `LDAP_PPM_ENABLED=false` (and every opt-in
module, e.g. `LDAP_NESTGROUP_ENABLED`, `false`) so the reconcile removes the
wiring, then roll back. Verified live: this removes `olcPPolicyCheckModule` from
the ppolicy overlay and `pwdUseCheckModule`/`pwdCheckModuleArg` from
`cn=default,ou=policies`, and the older image then started healthy on the same
volume. Restoring from backup also works.

- The container `HEALTHCHECK` now uses `ldapwhoami -Y EXTERNAL` over `ldapi://`
  instead of an anonymous simple bind, which `LDAP_DISALLOW_ANON_BIND` /
  `LDAP_REQUIRE_AUTHC` would otherwise make fail. Custom probes against the
  socket must do the same (or bind as an admin) when either is enabled.
  The entrypoint's own temporary-slapd readiness probe does the same.
- `LDAP_REQUIRE_TLS`, `LDAP_DISALLOW_ANON_BIND` and `LDAP_REQUIRE_AUTHC` fail
  fast at startup against `LDAP_ANONYMOUS_READ_BASE` (the latter two) and
  against plain `ldap://` replication peers (the first). The first-boot
  peer check for an existing base DIT binds as `LDAP_REPLICATION_BIND_DN`, not
  anonymously.
- `LDAP_LASTBIND_ENABLED` records the `pwdLastSuccess` attribute. With
  `LDAP_REPLICATION_ENABLED` it is an ordinary write that replicates and
  refreshes the user entry's `entryCSN`, so a concurrent edit of that entry on
  another node can lose last-write-wins to a bind. **WARNING:** in one observed
  2-node run (single run, not repeated), a partitioned node A accepted a bind
  with the OLD password after node B had an admin change it to NEW; A's
  `pwdLastSuccess` write carried the newer `entryCSN`, so after reconnect NEW
  failed (err=49) and OLD succeeded on both nodes. Keep lastbind off on
  multi-provider deployments (single node or single writer only). Not
  verified against the replication-chaos E2E; it defaults to off for this reason.

The new indexes (`uidNumber`, `gidNumber`, `memberUid`, `uniqueMember`) and
`pwdFailureCountInterval` are bootstrap-only like the other indexes/policy
entries; on an existing volume add them with `ldapmodify` and run `slapindex`.

### Other bootstrap-only settings

`LDAP_SIZE_LIMIT`, `LDAP_TIME_LIMIT`, `LDAP_PASSWORD_HASH`,
`LDAP_UNIQUE_ATTRIBUTES`, `LDAP_PASSWORD_POLICY_ENABLED` and its three
`LDAP_PASSWORD_*` knobs, `LDAP_DB_MAX_SIZE`, and `LDAP_ANONYMOUS_READ_BASE`
are all baked into
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
   into the database, then (if `LDAP_SEED_DIR` has `*.ldif` files and this
   node created the base DIT) a temporary `slapd` is started long enough to
   `ldapadd` them, then stopped. The marker is written only after all of this
   succeeds: a failure at any step, seeding included, discards the partial
   state so the next start retries the whole bootstrap and reports the error
   again.
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

This uses a short-lived background `slapd` on a separate setup-only `ldapi://`
socket, the same mechanism used for first-launch seeding — it's stopped again
before the real, PID-1 `slapd` starts. The health-check socket appears only once
the final `slapd` is up and serving all listeners.

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
| `entry`, `uid`, `objectClass` | read — DIT-wide by default, only under `LDAP_ANONYMOUS_READ_BASE` when that is set (see below) | read | read (see below) | write |
| every other attribute | none | read | write | write |
| another user's entry (write or delete) | none | **none** | n/a | write |
| `cn=config` | none | none | n/a | no — it is a separate database with its own admin identity, `cn=admin,cn=config` |
| `cn=Monitor` | none | none | n/a | `cn=monitoring,cn=Monitor` reads; everyone else nothing |

The admin column is the rootdn, which bypasses ACLs by definition — the useful
statement is not that it can do everything but that **nothing else in the first
three columns can write anything outside its own entry**.

### Narrowing anonymous read: `LDAP_ANONYMOUS_READ_BASE`

Rule 2 as shipped has no `dn.subtree` scope, so anonymous can enumerate the
existence, `uid` and `objectClass` of *every* entry — `ou=groups`,
`ou=policies` included — even though the only thing that read exists for is
resolving a `uid` under wherever the user entries live. Setting
`LDAP_ANONYMOUS_READ_BASE` to that subtree (it must sit under `LDAP_ROOT_DN`)
replaces rules 2–3 with four:

1. `dn.subtree="<base>"`, `entry`/`uid`/`objectClass`: anonymous read, users read
2. `entry`, everywhere: anonymous **search**, users read
3. `uid`/`objectClass`, everywhere else: users read (anonymous nothing)
4. everything else: exactly the old rule 3

The load-bearing one is 2. `search` and `read` on the `entry` pseudo-attribute
are different grants: `search` lets slapd use an entry as a search base and
walk through it as a candidate without ever disclosing or returning it, `read`
is what makes it returnable. Keeping `search` DIT-wide is what lets a
root-base anonymous `(uid=x)` search — the SSSD / management-UI login flow —
keep working unchanged; keeping `read` only under the base is what stops
enumeration outside it. And because anonymous has no `search` on `uid` or
`objectClass` outside the base, any filter against those entries — even
`(objectClass=*)` — evaluates undefined and never matches, so a base-scope
search on a known DN there returns nothing rather than confirming it exists.
Authenticated users keep exactly the access described above. Unset (the
default), the ACL is byte-for-byte what it has always been; this is verified
live in `.github/workflows/security-e2e.yml`.

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

`memberof`, `refint`, `ppolicy`, `unique`, `deref` and `constraint` are loaded **and enabled** on
the `mdb` database by default (`deref`/`constraint` via `LDAP_DEREF_ENABLED`/`LDAP_CONSTRAINT_ENABLED`, reconciled every start) (`unique`'s attribute set is configurable —
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
| `dynlist` | Dynamic groups (`memberURL`-based). | Opt-in via `LDAP_DYNLIST_ENABLED`; not allowed with replication. |
| `sssvlv` | Server-side sort + virtual list view. | Opt-in via `LDAP_SSSVLV_MAIN_ENABLED`. |
| `nestgroup` | Nested group membership. | Opt-in via `LDAP_NESTGROUP_ENABLED`; `*-values` flags not allowed with replication. |
| `otp` | TOTP 2FA (RFC 6238). | Opt-in via `LDAP_OTP_ENABLED`; needs per-user enrollment before it can gate anything. |

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
- `HEALTHCHECK` runs `ldapwhoami -Y EXTERNAL` over the local `ldapi://` Unix socket.

## Operational tools available in the image

`slapcat`, `slapindex`, `slaptest`, `slapadd`, `slappasswd`, and the full
`ldap*` client suite (`ldapsearch`, `ldapadd`, `ldapmodify`, `ldapwhoami`, ...)
are all present under `/usr/sbin` and `/usr/bin` respectively for operational
use (`docker exec`), e.g.:

```bash
docker exec ldap slapcat -F /etc/openldap/slapd.d -n 1
```
