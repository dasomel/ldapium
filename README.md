# openldap-suite

A maintained OpenLDAP stack for Kubernetes: a server image **compiled from upstream
source**, a management UI, and a Helm chart — built because the existing options stopped
being viable.

> Status: early development. Nothing here is released yet.

## Why this exists

Every common way to run OpenLDAP in Kubernetes broke at roughly the same time:

| Option | State (verified 2026-08-11) |
|---|---|
| `osixia/openldap` | `stable`/`latest`/`1.5.0` all date to **2021-02-19** (OpenLDAP 2.4.57). The only modern tag, `2.6.10-alpha`, has sat unpromoted since 2026-04-27 and changed its env contract incompatibly. |
| `bitnami/openldap` | Free access ended with Broadcom's 2025 catalog change; current images are a paid tier and old tags were frozen into `bitnamilegacy`. |
| `jp-gouin/helm-openldap` | The de-facto standard chart was **archived 2026-01-31**. |
| `symascorp/symas-openldap` | amd64 only — no arm64 manifest. |
| LLDAP · GLAuth · Kanidm | Read-only over the LDAP wire protocol; cannot back a writable directory. |

Upstream OpenLDAP itself is healthy — 2.6 is the LTS stream and 2.6.14 shipped
2026-08-06. The gap is packaging, not the software. So this project packages it.

## What is different here

**Compiled from the upstream tarball**, not from a distribution package, so the version
is ours to pin — currently 2.6.14, the current LTS — rather than whatever a base image's
package archive happens to carry.

**No sample data, ever.** Some images seed demo accounts and groups on first launch. In a
directory that a real identity provider federates, those become real users. This image
creates the base DN, the admin entry, and nothing else; seeding is an explicit opt-in via
a mounted LDIF directory.

**No default admin password.** The container refuses to start unless one is supplied.

**Multi-architecture** — `linux/amd64` and `linux/arm64`, built on native runners rather
than emulation, and rebuilt on a schedule so security fixes in the base layers land
without waiting for a release.

## Components

| Path | What |
|---|---|
| `image/` | OpenLDAP 2.6.14 server, built from source. Overlays: `memberof`, `refint`, `ppolicy`, `unique`, `syncprov`. Backend `back-mdb`, TLS via OpenSSL, Cyrus SASL. |
| `ui/` | Management UI — DIT browser, user and group CRUD, password set. Defaults to LDAP-bind login; optional Keycloak SSO uses a role-gated dedicated LDAP service account. |
| `charts/openldap/` | Helm chart deploying the server, with the UI as an optional component. |

## Standalone (docker compose)

Kubernetes is not required. `replicaCount: 1` in the chart already runs the
server standalone (replication auto-disables), and the server/UI images
don't know Kubernetes exists — they run identically under plain `docker
run`. `docker-compose.yml` at the repo root wires server + UI together in
one step, instead of two `docker run`s and a hand-built Docker network:

```bash
make local-up
make local-credentials
```

Then open `http://localhost:8080` (or `${UI_PORT}`) for the UI, and
`ldap://localhost:389` (or `${LDAP_PORT}`) for direct LDAP access. Data
persists in the named `ldap-config`/`ldap-data` volumes — deliberately named
ones, not anonymous, so they survive `docker compose down` (without `-v`)
and recreates.

To retrieve the local admin bind DN and password from the running Compose
container, run:

```bash
./scripts/get-credentials.sh --local
```

The command prints the password to the terminal; use
`--password-only` only when piping it into another local command.

For UI changes, keep the Compose services running and start Vite separately:

```bash
make frontend-dev
```

It serves `http://127.0.0.1:5173` and proxies API requests to the local UI
backend on port 8080.

### Developing against a Kubernetes deployment

For an existing Helm deployment, use the current `kubectl` context. The credential command reads the deployed StatefulSet and
its referenced Secret; it does not require a local Compose deployment:

```bash
make k8s-credentials
make k8s-ui-forward
```

In another terminal, run `make frontend-dev` and open
`http://127.0.0.1:5173`. To select a non-current namespace or disambiguate
multiple deployments, pass `KUBE_NAMESPACE` and `KUBE_RELEASE`:

```bash
make k8s-credentials KUBE_NAMESPACE=directory KUBE_RELEASE=openldap
make k8s-ui-forward KUBE_NAMESPACE=directory
```

No default admin password or session secret is baked in anywhere — same
principle as the image and the Helm chart (see "No default admin password"
above): compose refuses to start without them, loudly, rather than run with
a guessable credential.

### Backups without Kubernetes

`charts/openldap`'s backup CronJob has no standalone equivalent by
definition — there's no CronJob outside Kubernetes — so `scripts/backup.sh`
covers the same ground for a `docker run`/`docker compose` deployment: it
dumps the directory (data tree + `cn=config`) over `ldapsearch`, gzips it,
prunes by retention, and records the backup's status into the directory
itself (`ou=operations`) the same way the CronJob does — see
`charts/openldap/README.md`'s "Status recorded in the directory" and
"Restoring" sections, which apply unchanged to backups made by this script.

```bash
export LDAP_ADMIN_PASSWORD=...   # or --password-file
./scripts/backup.sh -b dc=example,dc=org -o ./backups
```

Run it from cron or a systemd timer on the host; `./scripts/backup.sh --help`
covers every option (custom LDAP URL/port, retention, skipping the
`cn=config` dump or the directory record).

## License

Original work in this repository is Apache-2.0 (`LICENSE`). Published images bundle
OpenLDAP Software under the OpenLDAP Public License 2.8 — see `NOTICE` and
`docs/OPENLDAP-PUBLIC-LICENSE-2.8.txt`. This project is not affiliated with the OpenLDAP
Foundation.
