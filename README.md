# ldapium

A maintained OpenLDAP stack for Kubernetes: a server image **compiled from upstream
source** (plus one carried syncrepl fix, [image/patches/](image/patches/)), a management UI, and a Helm chart — built because the existing options stopped
being viable.

**English | [한국어](README-ko.md)**

[![CI](https://github.com/dasomel/ldapium/actions/workflows/ci.yml/badge.svg)](https://github.com/dasomel/ldapium/actions/workflows/ci.yml)
[![CodeQL](https://github.com/dasomel/ldapium/actions/workflows/codeql.yml/badge.svg)](https://github.com/dasomel/ldapium/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/dasomel/ldapium/badge)](https://scorecard.dev/viewer/?uri=github.com/dasomel/ldapium)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenLDAP](https://img.shields.io/badge/OpenLDAP-2.6.15-informational)](https://www.openldap.org/)

> **Status: prototype.** Published early on purpose — the packaging is the
> point of the project and it is easier to judge in the open. Every claim in
> this README was checked against something actually running, but nothing here
> has been run by anyone other than its author. `helm test` (below) is there so
> you can check an install rather than take this paragraph's word for it. See
> [CHANGELOG.md](CHANGELOG.md) for the known gaps.

> **Registry note:** GitHub Releases and GHCR packages (both images and the OCI
> chart) exist for `0.1.0`, `0.1.1`, `0.2.0`, `0.2.1` and `0.3.0`. Verify the one you
> install, for example with the attestation command under "Supply chain".

## Why this exists

Every common way to run OpenLDAP in Kubernetes broke at roughly the same time:

| Option | State (verified 2026-08-11) |
|---|---|
| `osixia/openldap` | `stable`/`latest`/`1.5.0` all date to **2021-02-19** (OpenLDAP 2.4.57). The only modern tag, `2.6.10-alpha`, has sat unpromoted since 2026-04-27 and changed its env contract incompatibly. |
| `bitnami/openldap` | Free access ended with Broadcom's 2025 catalog change; current images are a paid tier and old tags were frozen into `bitnamilegacy`. |
| `jp-gouin/helm-openldap` | The de-facto standard chart was **archived 2026-01-31**. |
| `symascorp/symas-openldap` | amd64 only — no arm64 manifest. |
| LLDAP · GLAuth · Kanidm | Read-only over the LDAP wire protocol; cannot back a writable directory. |

Upstream OpenLDAP itself is healthy — 2.6 is the LTS stream and 2.6.15 shipped
2026-09-08. The gap is packaging, not the software. So this project packages it.

## What is different here

**Compiled from the upstream tarball**, not from a distribution package, so the version
is ours to pin — currently 2.6.15, the current LTS — rather than whatever a base image's
package archive happens to carry.

**No sample data, ever.** Some images seed demo accounts and groups on first launch. In a
directory that a real identity provider federates, those become real users. This image
creates the base DN, the admin entry, and nothing else; seeding is an explicit opt-in via
a mounted LDIF directory.

**No default admin password.** None is baked into the image or the chart. Supply one, or let a
fresh standalone container generate a random one on first start (written to
`<data volume>/.credentials/ldap-admin-password`, mode 600, read back with
`scripts/get-credentials.sh`). Generation is refused when replication is enabled (every node
must share one operator-supplied password) and when existing configuration needs its
original password.

**Multi-architecture** — `linux/amd64` and `linux/arm64`, built on native runners rather
than emulation, and rebuilt on a schedule so security fixes in the base layers land
without waiting for a release.

## Features

Everything below is merged to `main`; opt-in features are marked. The linked document is
the authoritative description, and [docs/IMPLEMENTATION-STATUS.md](docs/IMPLEMENTATION-STATUS.md)
records what was verified and how.

**Replication and HA**

- N-way multi-provider replication, reconciled on every start: [image/README.md](image/README.md#replication)
- Opt-in dedicated read-only replication identity; `scripts/replication-identity.sh` has `ensure`, `retire`, `reconcile`, `rotate` and `rollback-admin`: [docs/migration.md](docs/migration.md)
- Opt-in replication check CronJob (`replication.check.*`) and the `LDAPiumReplicationCheckFailed` alert: [docs/ha-profile.md](docs/ha-profile.md)
- HA topology profile with a failure-modes matrix and RPO/RTO targets: [docs/ha-profile.md](docs/ha-profile.md)

**Security hardening**

- No default admin password: a fresh standalone server generates a random one on first start, the UI generates and persists its own session secret, and the chart generates both Secrets on a live `helm install`; `scripts/get-credentials.sh` reads them back: [image/README.md](image/README.md)
- `ppolicy`, deny-by-default ACLs and opt-in anonymous-read scoping (`LDAP_ANONYMOUS_READ_BASE`): [image/README.md](image/README.md#access-control-acl)
- LDAPS and StartTLS with a TLS 1.2 floor; opt-in `requireTls`, `disallowAnonBind` and `requireAuthc`: [charts/ldapium/README.md](charts/ldapium/README.md#hardening)
- `auditlog` and `accesslog` (reads and binds) with an NDJSON export: [docs/audit-event-schema.md](docs/audit-event-schema.md)
- `userPassword` is never returned by the HTTP API, even hashed: [AGENTS.md](AGENTS.md)

**Backup and restore**

- Scheduled backup CronJob with an integrity manifest (`backup.enabled`): [charts/ldapium/README.md](charts/ldapium/README.md)
- `scripts/verify-backup.sh` and an offline `scripts/restore.sh` into an empty target: [docs/migration.md](docs/migration.md)
- `scripts/backup.sh` for deployments without Kubernetes: [Backups without Kubernetes](#backups-without-kubernetes)
- Opt-in UI Backups page with schedules and local, S3, FTP and SSH destinations: [ui/README.md](ui/README.md#scheduled-local--s3--ftp--ssh-backups)

**Observability**

- Prometheus exporter sidecar, ServiceMonitor, alert rules and a Grafana dashboard (`metrics.*`): [charts/ldapium/README.md](charts/ldapium/README.md)
- Opt-in UI backend `/metrics` on a separate listener: [docs/ui-operations.md](docs/ui-operations.md)
- `scripts/export-incident-evidence.sh`, a redacted snapshot of health, replication and backup state: [docs/incident-evidence.md](docs/incident-evidence.md)

**Management UI**

- DIT browser; users and groups with cursor paging, create, edit, delete, lock/unlock; password change: [ui/README.md](ui/README.md)
- Operator action history, server health, server settings and an API docs page: [ui/README.md](ui/README.md)
- Application SSO profiles and Keycloak SSO login (opt-in): [docs/auth-provider-policy.md](docs/auth-provider-policy.md)

**HTTP API**

- `/api/v1`, an OpenAPI 3.1 spec served by the running build, one error envelope: [docs/api.md](docs/api.md)
- Conditional writes (`ETag` / `If-Match`) and opt-in `Idempotency-Key`: [docs/api.md](docs/api.md)
- Opt-in Keycloak machine bearer access: eight read-only operations, optional token revocation, and a separate switch for scoped writes including `setPassword`: [docs/machine-auth-operations.md](docs/machine-auth-operations.md)

**Clients, migration, delivery**

- Checked client boundaries for SSSD/PAM/nsswitch, Windows/AD and Kubernetes RBAC via Keycloak: [docs/client-compatibility.md](docs/client-compatibility.md)
- PAM and credential-vault boundary: [docs/pam-boundary.md](docs/pam-boundary.md)
- Staged migration from an external LDAP/AD with a dry-run reconciliation report: [docs/migration.md](docs/migration.md)
- Air-gapped bundle and install: [docs/air-gap.md](docs/air-gap.md)
- Reproducible scale benchmarks, 1M profile in CI-sized runs and 10M and larger locally: [docs/scale-benchmarks.md](docs/scale-benchmarks.md)

## Components

| Path | What |
|---|---|
| `image/` | OpenLDAP 2.6.15 server, built from source with one carried syncrepl patch (#432). Overlays: `memberof`, `refint`, `ppolicy`, `unique`, `syncprov`. Backend `back-mdb`, TLS via OpenSSL, Cyrus SASL. |
| `ui/` | Management UI — DIT browser, user and group CRUD, password set. Defaults to LDAP-bind login; optional Keycloak SSO uses a role-gated dedicated LDAP service account. Opt-in bearer-token access for Keycloak service clients (read-only by default; writes behind a separate switch), see `docs/api.md`. |
| `charts/ldapium/` | Helm chart deploying the server, with the UI as an optional component. |

See the [architecture guide](docs/architecture.md) for the runtime boundaries, HA topology,
and differences between Helm and Compose deployments.

## Install

Both images and the chart are published to GHCR and cut from the same git tag,
so `0.3.0` means the same thing everywhere. Confirm the corresponding GitHub Release and GHCR
packages exist for the version you pick.

### Kubernetes (Helm)

```bash
helm install directory oci://ghcr.io/dasomel/charts/ldapium \
  --version 0.3.0 \
  --namespace directory --create-namespace \
  --set auth.adminPassword="$(openssl rand -base64 24)" \
  --set ldap.rootDN=dc=example,dc=org
```

There is no default admin password. If you leave `auth.adminPassword` empty, a
live `helm install` generates a random one into the release's admin Secret and
reuses it on upgrade (via `lookup`); offline renders (`helm template`,
`--dry-run=client`, GitOps controllers that render without cluster access)
cannot see the Secret and fail instead. To keep the password out of your shell
history and out of `helm get values`, create the Secret yourself and point
`auth.existingSecret` at it.

Useful from there:

```bash
--set replicaCount=3      # N-way multi-provider replication, peers wired automatically
--set ui.enabled=true     # the management UI; first install also needs --set ui.session.secret="$(openssl rand -base64 48)"
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
backup/restore procedure and its RPO/RTO, what is known to upgrade in place and
the preflight that goes with it, and the optional Keycloak SSO setup.

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
| `ghcr.io/dasomel/ldapium:0.3.0` | OpenLDAP 2.6.15 server |
| `ghcr.io/dasomel/ldapium-ui:0.3.0` | Management UI |

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

For local Keycloak LDAP federation, run `make keycloak-up` and open
`http://127.0.0.1:8180/admin/`. See [local Keycloak testing](docs/testing/keycloak-local.md)
for login details, user/group synchronization, test commands, and shutdown.

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

No default admin password or session secret is baked in anywhere. If
`LDAP_ADMIN_PASSWORD` / `SESSION_SECRET` are left empty, the server generates
a random admin password into the `ldap-data` volume and the UI generates and
persists its session secret, so nothing guessable is ever used;
`./scripts/get-credentials.sh --local` shows the generated password.

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

## Air-gapped install

Images, chart, SBOMs and checksums travel as one directory built by
`scripts/offline-bundle.sh`, verified and installed by
`scripts/offline-install.sh` with `imagePullPolicy=Never` so a missing archive
fails the install instead of quietly pulling. `docs/air-gap.md` has the
procedure, what the verification refuses and why, and how to keep vulnerability
data current on a disconnected machine.

## Supply chain

Every released image is designed to carry, in the registry alongside it, a **build
provenance attestation** and an **SBOM attestation**, signed by GitHub's OIDC identity
when the release workflow completes successfully.

```bash
gh attestation verify oci://ghcr.io/dasomel/ldapium:0.3.0 \
  --repo dasomel/ldapium
```

SPDX and CycloneDX SBOMs for both images are also attached to each GitHub
Release, so you can read one without a registry client. `syft` against the
published tag should agree with them — that is the point of publishing them.

Dependencies and build tooling are pinned, and the pins are enforced: Go
modules verify against `go.sum` under `-mod=readonly` with a substitution test
that proves the check rejects a tampered hash, actions are pinned by commit SHA,
and the two tools that were floating on `latest` — `syft` in the air-gap
bundler, `govulncheck` in the scanner — are pinned by digest and version.
[docs/dependency-policy.md](docs/dependency-policy.md) covers what is pinned by
what, the review and cooling window for new releases, the rollback procedure for
a dependency that turns out to be compromised, and what is still not covered.

Dependency licences are permissive-only and enforced, not merely observed:
`./scripts/licenses.sh --check` runs in CI and fails on a licence outside the
allow-list or a stale [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).
Trivy scans dependencies and manifests on every change and the published
images weekly; CodeQL analyses the Go and TypeScript sources.
[docs/legal.md](docs/legal.md) covers the licensing position in full,
including why the Debian base's GPL packages do not reach this project's code.

## What CI verifies

These run on pull requests and pushes to `main` (several are path-filtered), against real
containers or a kind cluster rather than mocks.

| Workflow | Proves |
|---|---|
| `e2e.yml` | chart install and `helm test` (standalone and 3-node), TLS and certificate rotation, migration dry-run |
| `upgrade-e2e.yml` | rolling upgrade and rollback, standalone and replicated |
| `backup-restore.yml` | backup, verify, corrupt-check, restore; 3-node bad delete, restore, resync |
| `replication-chaos-e2e.yml` | network partition, same-entry conflict, dedicated replication identity |
| `security-e2e.yml` | ACL negative tests (anonymous, other users, password policy, `cn=config`), LDAP injection, audit and accesslog records, chart security context |
| `sssd-e2e.yml` | SSSD `getent`/`id` identity resolution |
| `keycloak-federation-e2e.yml` | Keycloak LDAP user federation |
| `metrics-e2e.yml` | exporter metrics and alert rules firing on injected faults |
| `ui-e2e.yml` | UI browser regression against a real directory |
| `machine-keycloak-e2e.yml`, `machine-write-e2e.yml` | machine bearer read and write with real Keycloak and slapd |
| `api-credentials-e2e.yml` | generated credentials and API edge codes |
| `offline-bundle.yml` | bundle build and install with no registry |

`release.yml` refuses a tag unless these succeeded on its commit: the reachable-vulnerability
scan, rolling upgrade + rollback (standalone and replicated), backup restore and the 3-node
restore, machine bearer auth, machine write, and generated credentials + API edge codes.

## Documentation

| Document | Purpose |
|---|---|
| [docs/ADOPTION-GUIDE.md](docs/ADOPTION-GUIDE.md) | Choosing an entry path and what counts as a first success |
| [docs/IMPLEMENTATION-STATUS.md](docs/IMPLEMENTATION-STATUS.md) | What is merged and how each part was verified |
| [docs/architecture.md](docs/architecture.md) | Runtime boundaries, HA topology, Helm versus Compose |
| [docs/api.md](docs/api.md) | HTTP API contract, machine bearer authentication (Korean) |
| [docs/ui-operations.md](docs/ui-operations.md) | Operating the UI backend: metrics, Origin gate, conditional writes, idempotency keys (Korean) |
| [docs/auth-provider-policy.md](docs/auth-provider-policy.md) | LDAP bind versus Keycloak SSO and failure behaviour |
| [docs/machine-keycloak-client.md](docs/machine-keycloak-client.md) | Keycloak client setup for machine calls (Korean) |
| [docs/machine-ldap-account.md](docs/machine-ldap-account.md) | Machine read account and read-only ACL (Korean) |
| [docs/machine-write-account.md](docs/machine-write-account.md) | Machine write account and write ACL (Korean) |
| [docs/machine-auth-operations.md](docs/machine-auth-operations.md) | Machine auth rollback, emergency revocation, compatibility (Korean) |
| [docs/ha-profile.md](docs/ha-profile.md) | HA topology, failure modes, RPO/RTO |
| [docs/migration.md](docs/migration.md) | Staged cutover, dry-run reconciliation, rollback, replication identity procedure |
| [docs/air-gap.md](docs/air-gap.md) | Air-gapped bundle, verification and install |
| [docs/client-compatibility.md](docs/client-compatibility.md) | What works for SSSD, Windows/AD, Keycloak and other clients |
| [docs/audit-event-schema.md](docs/audit-event-schema.md) | Identity audit event schema and export |
| [docs/incident-evidence.md](docs/incident-evidence.md) | Redacted incident evidence export |
| [docs/scale-benchmarks.md](docs/scale-benchmarks.md) | Reproducible load and scale measurements |
| [docs/encryption-at-rest.md](docs/encryption-at-rest.md) | Who is responsible for encryption at rest |
| [docs/dependency-policy.md](docs/dependency-policy.md) | Pinning, cooling window and dependency rollback |
| [docs/legal.md](docs/legal.md) | Licensing, attribution and compliance (Korean: legal-ko.md) |
| [docs/product-boundary.md](docs/product-boundary.md) | Scope and non-goals |
| [docs/pam-boundary.md](docs/pam-boundary.md) | PAM and credential-vault boundary |
| [docs/agent-execution-security.md](docs/agent-execution-security.md) | Directory-control profile for agent-driven operations |

Component references: [image/README.md](image/README.md), [ui/README.md](ui/README.md), [charts/ldapium/README.md](charts/ldapium/README.md).

## Contributing, security, releases

- [CONTRIBUTING.md](CONTRIBUTING.md) / [한국어](CONTRIBUTING-ko.md) — local setup, project rules, and CI checks
- [SECURITY.md](SECURITY.md) / [한국어](SECURITY-ko.md) — vulnerability reporting and security scope
- [CHANGELOG.md](CHANGELOG.md) / [한국어](CHANGELOG-ko.md) — changes and known gaps
- [RELEASING.md](RELEASING.md) / [한국어](RELEASING-ko.md) — release procedure
- [docs/ha-profile.md](docs/ha-profile.md) — High Availability topology profile (D11–D13), failure modes matrix, and RPO/RTO SLA
- [docs/migration.md](docs/migration.md) — staged cutover, dry-run reconciliation, and rollback runbook
- [docs/product-boundary.md](docs/product-boundary.md) — product scope, non-goals, and boundary obligations
- [docs/pam-boundary.md](docs/pam-boundary.md) — privileged access management and credential vault boundary

## License

Original work in this repository is Apache-2.0 ([LICENSE](LICENSE)). Published images
bundle OpenLDAP Software under the OpenLDAP Public License 2.8 — see [NOTICE](NOTICE)
and [docs/OPENLDAP-PUBLIC-LICENSE-2.8.txt](docs/OPENLDAP-PUBLIC-LICENSE-2.8.txt).
Third-party dependency licences are inventoried in
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).

OpenLDAP is a registered trademark of the OpenLDAP Foundation. This project is not
affiliated with, endorsed by, or supported by the OpenLDAP Foundation, and builds of it
are not official OpenLDAP releases.
