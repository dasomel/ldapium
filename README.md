# openldap-suite

A maintained OpenLDAP stack for Kubernetes: a server image **compiled from upstream
source**, a management UI, and a Helm chart — built because the existing options stopped
being viable.

[![CI](https://github.com/dasomel/openldap-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/dasomel/openldap-suite/actions/workflows/ci.yml)
[![CodeQL](https://github.com/dasomel/openldap-suite/actions/workflows/codeql.yml/badge.svg)](https://github.com/dasomel/openldap-suite/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/dasomel/openldap-suite/badge)](https://scorecard.dev/viewer/?uri=github.com/dasomel/openldap-suite)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenLDAP](https://img.shields.io/badge/OpenLDAP-2.6.14-informational)](https://www.openldap.org/)

> **Status: 0.1.0, the first release.** It runs, and every claim in this README
> was checked against something running — but this is a young project with one
> maintainer. The TLS path is the one part still marked unverified; see
> [CHANGELOG.md](CHANGELOG.md) for what that means in practice.

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

## Install

Both images and the chart are published to GHCR and cut from the same git tag,
so `0.1.0` means the same thing everywhere.

### Kubernetes (Helm)

```bash
helm install directory oci://ghcr.io/dasomel/charts/openldap \
  --version 0.1.0 \
  --namespace directory --create-namespace \
  --set auth.adminPassword="$(openssl rand -base64 24)" \
  --set ldap.rootDN=dc=example,dc=org
```

There is no default admin password — the chart refuses to render without one,
because the image refuses to start without one. To keep the password out of
your shell history and out of `helm get values`, create the Secret yourself
and point `auth.existingSecret` at it instead.

Useful from there:

```bash
--set replicaCount=3      # N-way multi-provider replication, peers wired automatically
--set ui.enabled=true     # the management UI
--set backup.enabled=true # scheduled dumps of the data tree and cn=config
```

`charts/openldap/README.md` documents every value, the replication design, the
backup/restore procedure, and the optional Keycloak SSO setup.

### Images

| Image | Contents |
|---|---|
| `ghcr.io/dasomel/openldap-suite:0.1.0` | OpenLDAP 2.6.14 server |
| `ghcr.io/dasomel/openldap-suite-ui:0.1.0` | Management UI |

Both are `linux/amd64` + `linux/arm64` and carry build provenance attestations.
A `:main` tag is rebuilt weekly from the same source so base-image security
updates are available without waiting for a release; released tags are
immutable.

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

## Supply chain

Every released image carries, in the registry alongside it, a **build
provenance attestation** and an **SBOM attestation**, both signed by GitHub's
OIDC identity for this repository:

```bash
gh attestation verify oci://ghcr.io/dasomel/openldap-suite:0.1.0 \
  --repo dasomel/openldap-suite
```

SPDX and CycloneDX SBOMs for both images are also attached to each GitHub
Release, so you can read one without a registry client. `syft` against the
published tag should agree with them — that is the point of publishing them.

Dependency licences are permissive-only and enforced, not merely observed:
`./scripts/licenses.sh --check` runs in CI and fails on a licence outside the
allow-list or a stale [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).
Trivy scans dependencies and manifests on every change and the published
images weekly; CodeQL analyses the Go and TypeScript sources.
[docs/legal.md](docs/legal.md) covers the licensing position in full,
including why the Debian base's GPL packages do not reach this project's code.

## Contributing, security, releases

- [CONTRIBUTING.md](CONTRIBUTING.md) — local setup, what the project is
  opinionated about, and the checks CI runs
- [SECURITY.md](SECURITY.md) — how to report a vulnerability privately, and
  what is in scope (bugs in OpenLDAP itself belong upstream)
- [CHANGELOG.md](CHANGELOG.md) — what changed, and what is still unverified
- [RELEASING.md](RELEASING.md) — how a release is cut

## License

Original work in this repository is Apache-2.0 ([LICENSE](LICENSE)). Published images
bundle OpenLDAP Software under the OpenLDAP Public License 2.8 — see [NOTICE](NOTICE)
and [docs/OPENLDAP-PUBLIC-LICENSE-2.8.txt](docs/OPENLDAP-PUBLIC-LICENSE-2.8.txt).
Third-party dependency licences are inventoried in
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).

OpenLDAP is a registered trademark of the OpenLDAP Foundation. This project is not
affiliated with, endorsed by, or supported by the OpenLDAP Foundation, and builds of it
are not official OpenLDAP releases.
