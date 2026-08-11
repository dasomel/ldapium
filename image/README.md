# openldap-suite image

A from-source OpenLDAP **2.6.14** container image that this project owns outright —
no dependency on [osixia/docker-openldap](https://github.com/osixia/docker-openldap)
(abandoned, last stable release 2021) or
[vegardit/docker-openldap](https://github.com/vegardit/docker-openldap) (built from
Debian packages, and seeds demo accounts on first launch).

**This image never seeds sample data.** On first launch it creates exactly two
entries — the root suffix and the admin entry — and nothing else. If you want
demo data, put your own LDIFs in `LDAP_SEED_DIR`.

## Build

```bash
docker build --platform linux/arm64 -t openldap-suite:dev image/
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
  openldap-suite:dev
```

## Environment variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `LDAP_ROOT_DN` | **yes** | — | e.g. `dc=example,dc=org`. Must start with `dc=`. Container refuses to start if unset. |
| `LDAP_ORG_NAME` | no | first `dc=` component of `LDAP_ROOT_DN` | Used as the `o:` attribute on the root entry. |
| `LDAP_ADMIN_DN` | no | `cn=admin,${LDAP_ROOT_DN}` | Must use `cn=` as its RDN attribute. |
| `LDAP_ADMIN_PASSWORD` | **yes**\* | — | No default, ever. Container refuses to start if unset. Hashed with `slappasswd -h {SSHA}` before it touches disk — never stored in plaintext. |
| `LDAP_ADMIN_PASSWORD_FILE` | no\* | — | Path to a file containing the admin password (for secret mounts). Takes precedence if both are set and readable. |
| `LDAP_LOG_LEVEL` | no | `stats` | Passed to `slapd -d`. Any value (including a quiet one) keeps slapd in the foreground, which is required for it to run as PID 1. |
| `LDAP_TLS_ENABLED` | no | `false` | `true`/`1` to enable `ldaps:///`. |
| `LDAP_TLS_CERT_FILE` | if TLS enabled | — | `olcTLSCertificateFile`. |
| `LDAP_TLS_KEY_FILE` | if TLS enabled | — | `olcTLSCertificateKeyFile`. |
| `LDAP_TLS_CA_FILE` | no | — | `olcTLSCACertificateFile`, optional even with TLS enabled. |
| `LDAP_SEED_DIR` | no | `/opt/ldifs` | Every `*.ldif` in this directory is applied, in sorted order, via `ldapadd` — **once, on first launch only**. Your extension point for OUs, groups, real users, ACLs, etc. |

\* Exactly one of `LDAP_ADMIN_PASSWORD` / `LDAP_ADMIN_PASSWORD_FILE` must resolve to a non-empty value.

### TLS caveat

TLS settings are only written into `cn=config` at bootstrap time. Enabling
`LDAP_TLS_ENABLED` against an already-bootstrapped data/config volume has no
effect — either seed a fresh volume with TLS enabled from the start, or edit
`cn=config` by hand (`olcTLSCertificateFile` etc. under `cn=config`).

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

## What gets created (and what does not)

On first launch, exactly:

- `<LDAP_ROOT_DN>` — `dcObject` + `organization`
- `<LDAP_ADMIN_DN>` — `organizationalRole` + `simpleSecurityObject`, password hash only

Nothing else. No `employee1`, no `guest1`, no `machine1`, no sample
`groupOfUniqueNames` — that vegardit-style seeding is exactly what this image
was built to avoid. Anything beyond the two entries above is your call via
`LDAP_SEED_DIR`.

## Overlays

`memberof` and `refint` are loaded **and enabled** on the `mdb` database by
default (they have sane parameter-free defaults). `ppolicy`, `unique`, and
`syncprov` are loaded as modules but left uninstantiated — they need
deployment-specific configuration (a policy object, uniqueness scope,
replication topology) that shouldn't be guessed at by the image. Enable them
yourself against `cn=config` (see below) — `LDAP_SEED_DIR` itself only ever
binds as `LDAP_ADMIN_DN`, so it can't reach `cn=config` (see why below).

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
