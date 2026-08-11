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
| `ui/` | Management UI — DIT browser, user and group CRUD, password set. Authenticates by LDAP bind and acts as the logged-in user, so the directory's own ACLs authorize every action. |
| `charts/openldap/` | Helm chart deploying the server, with the UI as an optional component. |

## License

Original work in this repository is Apache-2.0 (`LICENSE`). Published images bundle
OpenLDAP Software under the OpenLDAP Public License 2.8 — see `NOTICE` and
`docs/OPENLDAP-PUBLIC-LICENSE-2.8.txt`. This project is not affiliated with the OpenLDAP
Foundation.
