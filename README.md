# ldapium

A maintained OpenLDAP stack for Kubernetes: a server image **compiled from upstream
source**, a management UI, and a Helm chart — built because the existing options stopped
being viable.

**English | [한국어](README_ko.md)**

[![CI](https://github.com/dasomel/ldapium/actions/workflows/ci.yml/badge.svg)](https://github.com/dasomel/ldapium/actions/workflows/ci.yml)
[![CodeQL](https://github.com/dasomel/ldapium/actions/workflows/codeql.yml/badge.svg)](https://github.com/dasomel/ldapium/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/dasomel/ldapium/badge)](https://scorecard.dev/viewer/?uri=github.com/dasomel/ldapium)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenLDAP](https://img.shields.io/badge/OpenLDAP-2.6.14-informational)](https://www.openldap.org/)

> **Status: prototype.** Published early on purpose — the packaging is the
> point of the project and it is easier to judge in the open. Every claim in
> this README was checked against something actually running, but nothing here
> has been run by anyone other than its author. `helm test` (below) is there so
> you can check an install rather than take this paragraph's word for it. See
> [CHANGELOG.md](CHANGELOG.md) for the known gaps.

> **Registry note:** the repository contains the GHCR release workflow, but
> registry publication must be verified from the actual GitHub Release/Actions
> run before treating `0.1.0` images and the OCI chart as published artifacts.

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
| `charts/ldapium/` | Helm chart deploying the server, with the UI as an optional component. |

## Install

Both images and the chart are **intended** to be published to GHCR and cut from the same git tag,
so `0.1.0` means the same thing everywhere. Confirm the corresponding GitHub Release and GHCR
packages exist before using the commands below as published-artifact instructions.

### Kubernetes (Helm)

```bash
helm install directory oci://ghcr.io/dasomel/charts/ldapium \
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

Then check the install rather than assuming it:

```bash
helm test directory --namespace directory --logs
```

That binds as the admin, creates and deletes a scratch entry, and asserts the
`memberof` overlay actually populated `memberOf` — on a replicated install it
also waits for the entry to reach every pod. A directory server starts happily
with an overlay missing, so this is the only check that notices.

`charts/ldapium/README.md` documents every value, the replication design, the
backup/restore procedure, and the optional Keycloak SSO setup.

### TLS

`--set tls.enabled=true` with a Secret holding `tls.crt`, `tls.key` and
`ca.crt` adds an LDAPS listener on 636 and moves replication onto `ldaps://`.
Certificates are verified strictly, so an unknown CA or a name the certificate
does not cover fails the connection instead of downgrading it.

`slapd` reads its key material at startup only: renewing a certificate means
updating the Secret and then restarting the pods, which is a rolling,
no-downtime operation once `replicaCount > 1`. `charts/ldapium/README.md#tls`
has the runbook, including the two-step procedure for changing the CA itself.

### Images

| Image | Contents |
|---|---|
| `ghcr.io/dasomel/ldapium:0.1.0` | OpenLDAP 2.6.14 server |
| `ghcr.io/dasomel/ldapium-ui:0.1.0` | Management UI |

Both are designed for `linux/amd64` + `linux/arm64` and carry build provenance attestations
when the release workflow completes successfully.

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
make k8s-credentials KUBE_NAMESPACE=directory KUBE_RELEASE=ldapium
make k8s-ui-forward KUBE_NAMESPACE=directory
```

No default admin password or session secret is baked in anywhere — same
principle as the image and the Helm chart (see "No default admin password"
above): compose refuses to start without them, loudly, rather than run with
a guessable credential.

### Backups without Kubernetes

`charts/ldapium`'s backup CronJob has no standalone equivalent by
definition — there's no CronJob outside Kubernetes — so `scripts/backup.sh`
covers the same ground for a `docker run`/`docker compose` deployment: it
dumps the directory (data tree + `cn=config`) over `ldapsearch`, gzips it,
prunes by retention, and records the backup's status into the directory
itself (`ou=operations`) the same way the CronJob does — see
`charts/ldapium/README.md`'s "Status recorded in the directory" and
"Restoring" sections, which apply unchanged to backups made by this script.

```bash
export LDAP_ADMIN_PASSWORD=...   # or --password-file
./scripts/backup.sh -b dc=example,dc=org -o ./backups
```

Run it from cron or a systemd timer on the host; `./scripts/backup.sh --help`
covers every option (custom LDAP URL/port, retention, skipping the
`cn=config` dump or the directory record).

## Supply chain

Every released image is designed to carry, in the registry alongside it, a **build
provenance attestation** and an **SBOM attestation**, signed by GitHub's OIDC identity
when the release workflow completes successfully.

```bash
gh attestation verify oci://ghcr.io/dasomel/ldapium:0.1.0 \
  --repo dasomel/ldapium
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

- [CONTRIBUTING.md](CONTRIBUTING.md) / [한국어](CONTRIBUTING_ko.md) — local setup, project rules, and CI checks
- [SECURITY.md](SECURITY.md) / [한국어](SECURITY_ko.md) — vulnerability reporting and security scope
- [CHANGELOG.md](CHANGELOG.md) / [한국어](CHANGELOG_ko.md) — changes and known gaps
- [RELEASING.md](RELEASING.md) / [한국어](RELEASING_ko.md) — release procedure

## License

Original work in this repository is Apache-2.0 ([LICENSE](LICENSE)). Published images
bundle OpenLDAP Software under the OpenLDAP Public License 2.8 — see [NOTICE](NOTICE)
and [docs/OPENLDAP-PUBLIC-LICENSE-2.8.txt](docs/OPENLDAP-PUBLIC-LICENSE-2.8.txt).
Third-party dependency licences are inventoried in
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).

OpenLDAP is a registered trademark of the OpenLDAP Foundation. This project is not
affiliated with, endorsed by, or supported by the OpenLDAP Foundation, and builds of it
are not official OpenLDAP releases.
