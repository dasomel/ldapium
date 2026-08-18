# Licensing, attribution, and compliance

What this project distributes, under which licences, and what a downstream
user takes on by deploying it. Written to be checkable rather than reassuring:
every claim points at a file or a command.

> This is a description of how the project is put together, not legal advice.
> If your organisation has a compliance process, feed it the SBOM and this
> document; do not treat either as a substitute for it.

## 1. What this project's own code is

Apache-2.0 ([LICENSE](../LICENSE)). That covers everything written here: the
UI (Go and TypeScript), the Helm chart, the entrypoint and scripts, the
Dockerfiles, and the docs.

Apache-2.0 was chosen over MIT for the explicit patent grant (§3) and the
attribution mechanism ([NOTICE](../NOTICE)) — this project ships a
cryptography-adjacent server component, and an express patent grant is worth
more here than the brevity of MIT.

## 2. What the published images bundle

| Layer | What | Licence | Modified? |
|---|---|---|---|
| OpenLDAP | Compiled from the upstream source release, pinned by version and sha256 in `image/Dockerfile` | [OpenLDAP Public License 2.8](OPENLDAP-PUBLIC-LICENSE-2.8.txt) | **No.** No patches are carried. |
| Base OS | `debian:trixie-slim` and the packages the build installs (OpenSSL, Cyrus SASL, libargon2, runtime libs) | Various — mostly GPL/LGPL, some BSD/Apache/CC0 | No. Redistributed as packaged. |
| UI | This project's Go binary and built frontend assets | Apache-2.0 | n/a |

### Does the GPL in the base image reach this project's code?

No, and the reason is structural rather than a judgement call:

- The Debian packages are **separate programs** in the image, invoked or
  linked by OpenLDAP, not by this project's code. This is the ordinary
  container-base arrangement the GPL calls mere aggregation.
- This project's own binaries link nothing under GPL or LGPL. The Go
  dependency tree is MIT/Apache-2.0/BSD only, the npm production tree is
  MIT/Apache-2.0/ISC/0BSD only, and CI fails if that stops being true — see
  [THIRD-PARTY-LICENSES.md](../THIRD-PARTY-LICENSES.md) and
  `scripts/licenses.sh`.
- The one LGPL component in the picture is `libltdl`, which upstream
  OpenLDAP links **dynamically** for module loading. That is the arrangement
  LGPL-2.1 §6 permits, the library is unmodified, and `NOTICE` records it.
  The experimental `back-sql` backend, which would pull in unixODBC, is
  deliberately not built.
- Debian's own copyright files stay in place inside the image at
  `/usr/share/doc/`, so the source-availability and notice obligations that
  travel with those packages travel with the image.

If you rebuild the image with additional packages, that analysis is yours to
redo — `make sbom` gives you the input.

### OpenLDAP Public License 2.8

A three-clause BSD-style permissive licence. Its conditions are redistribution
of the copyright notice, the conditions, and the disclaimer — all satisfied by
`NOTICE`, by [OPENLDAP-PUBLIC-LICENSE-2.8.txt](OPENLDAP-PUBLIC-LICENSE-2.8.txt)
in this repo, and by the licence text inside every image at
`/usr/share/doc/openldap/`.

## 3. SBOM

Every released image carries an SBOM in two ways:

- **Attached to the image in the registry** as a signed attestation, so it
  travels with the artifact:

      gh attestation verify oci://ghcr.io/dasomel/openldap-suite:0.1.0 \
        --repo dasomel/openldap-suite

- **Attached to the GitHub Release** as `openldap-suite.spdx.json`,
  `openldap-suite.cdx.json` and the same pair for the UI image — SPDX 2.3 and
  CycloneDX, for whichever your tooling reads.

Regenerate one yourself and compare; that is the point of publishing it:

    syft ghcr.io/dasomel/openldap-suite:0.1.0 -o spdx-json

Build provenance is attested the same way, so an image can be traced to the
workflow run and commit that produced it.

## 4. Trademarks

OpenLDAP is a registered trademark of the OpenLDAP Foundation. **This project
is not affiliated with, endorsed by, or supported by the OpenLDAP Foundation
or Symas.** The name `openldap-suite` describes what the software packages;
it does not claim to be an official distribution, and the README says so
explicitly. Do not present builds of this project as official OpenLDAP
releases.

## 5. Cryptography and export

The images contain cryptographic software: OpenSSL and Cyrus SASL from Debian,
TLS and SASL support compiled into OpenLDAP, and Argon2 password hashing. The
source is publicly available and unmodified, which is the situation the US
EAR's TSU exemption (§740.13(e)) exists for, and the same footing every
mainstream Linux container image stands on.

Nothing here is a legal opinion, and import restrictions on cryptography in
your jurisdiction are yours to check.

## 6. What was checked before publication

Run before the repository was made public, and worth repeating before any
release:

| Check | How |
|---|---|
| No credentials or keys in tracked files | `git ls-files -z \| xargs -0 grep -nIE 'BEGIN .*PRIVATE KEY\|AKIA\|ghp_'` — and GitHub secret scanning with push protection enabled on the repository |
| No default passwords shipped | The image, chart and compose file each refuse to start without one; CI asserts the chart's guard still fails (`Reject rendering with no admin password`) |
| No sample or personal data | The image creates the base DN and admin entry only; seeding is opt-in |
| No internal hostnames or private infrastructure in docs | Examples use `example.com` / `dc=example,dc=org` |
| Dependency licences are permissive | `./scripts/licenses.sh --check`, enforced in CI |
| Dependencies and manifests scanned | Trivy, in `.github/workflows/security-scan.yml`, results in the Security tab |

## 7. Questions

Licensing or attribution concerns: open an issue. Security vulnerabilities:
[SECURITY.md](../SECURITY.md), privately.
