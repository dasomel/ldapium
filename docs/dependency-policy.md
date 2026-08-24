# Dependency and build-toolchain policy

The threat this exists for is not a dependency that turns out to be buggy. It is
a dependency — or a build tool, or a container the build hands a socket to —
that runs code during `go test`, `docker build`, or a release job. That code
runs with whatever the build has: credentials, the module cache, the daemon
socket, the registry token. A package can look entirely legitimate while its
build-time tooling is the execution path.

## What is pinned, and how

| Thing | Pinned by | Bumped by |
|---|---|---|
| Go modules | `go.mod` + `go.sum` | Dependabot, weekly, grouped |
| npm packages | `package-lock.json` | Dependabot, weekly, grouped |
| GitHub Actions | commit SHA, with the version in a trailing comment | Dependabot, weekly |
| Base images | tag **and digest** in each Dockerfile | Dependabot, weekly |
| OpenLDAP source | version **and** sha256 in `image/Dockerfile` | by hand — Dependabot cannot see a tarball URL |
| `syft`, used to build air-gap SBOMs | **image digest** in `scripts/offline-bundle.sh` | by hand |
| `govulncheck` | version in `.github/workflows/security-scan.yml` | by hand |

The last two were `:latest` and `@latest`. Both are build-time execution paths —
the syft container is handed the docker socket while a release is being
assembled, and `go run tool@latest` fetches and executes whatever was published
most recently at the moment the scan runs. Neither is allowed to float.

## What CI enforces

- `go mod verify` re-hashes every module in the cache against `go.sum`.
- Every Go command runs under `GOFLAGS=-mod=readonly`, so a build cannot quietly
  rewrite `go.mod`/`go.sum` to make itself work; `git diff --exit-code` on both
  files then fails if anything did.
- A **substitution test** tampers with one recorded hash in a copy of `go.sum`
  and requires the download to fail with a checksum mismatch. A gate nobody has
  watched reject something is a guess.
- `scripts/licenses.sh --check` fails on a licence outside the allow-list or a
  stale `THIRD-PARTY-LICENSES.md`, which also catches a dependency that changed
  identity underneath its version.
- `scripts/check-base-images.sh` requires every `FROM` to carry a digest, and
  every digest to resolve to a manifest list covering the architectures the
  release publishes. See below for why the second half is not redundant.
- `step-security/harden-runner` blocks build/test jobs (`backend`, `frontend`,
  `licenses` in `ci.yml`) to an explicit endpoint allow-list, closing off the
  arbitrary outbound access a compromised build-time dependency would need to
  exfiltrate anything. A separate `egress-negative-test` job proves the block
  is real rather than trusted on faith: it deliberately connects to a host
  outside its own allow-list and fails if that connection succeeds.

## Reviewing a dependency change

Dependabot groups routine updates so a normal week is a few reviewable PRs
rather than a dozen one-line ones. What the review is looking for is not the
version number:

- **Does the diff touch `go.sum` for modules the PR does not claim to update?**
  An unexplained transitive change is the thing to stop on.
- **Is this a first release from a new maintainer, or a first release after a
  long gap?** Both are what a compromised account looks like from the outside.
- **Does the package add build-time execution** — a `//go:generate`, a new
  `tools.go` entry, an npm `postinstall`, a new container in a workflow? That is
  the payload path; a dependency that only adds library code cannot use it.

### Cooling window

Do not adopt a module or tool release on the day it is published. Wait **seven
days** for anything reaching build or test, and let the version soak in a PR
rather than merging on the day it opens. Most compromised releases are found and
yanked inside a week; the cost of waiting is a week of not having a patch that
is almost never urgent. The exception is a fix for a vulnerability that this
project is actually reachable from — `govulncheck` reports reachability, so that
is a decision with evidence behind it rather than a CVE score.

## Base images, and what pinning them by digest changed

Base images are pinned as `name:tag@sha256:...`. The tag stays for readability;
the digest is what actually resolves, so the same commit builds the same bytes.

This is a deliberate trade, and the cost is real: `weekly-rebuild.yml` used to
absorb base-image security updates silently, because `debian:trixie-slim` moved
underneath it. It no longer does — a base update now arrives as a Dependabot PR
that bumps the digest, which is the point. Patches become visible and
attributable instead of automatic and invisible.

One thing a floating tag gave us for free and a digest does not: a tag always
resolves to a manifest list, but a digest can just as easily name a single
architecture inside that list. Pin the inner one and the amd64 build keeps
working while arm64 stops — and it stops in `build-multiarch.yml`, which runs on
push and release rather than on pull requests, so the PR that introduced it goes
green and the breakage surfaces after merge. `scripts/check-base-images.sh` asks
the registry that question at PR time instead, which is also the check a
Dependabot digest bump has to pass.

Two consequences worth knowing:

- **Base patch latency is now Dependabot's cadence**, up to a week for routine
  updates. Dependabot opens security updates separately and immediately, and
  those are the ones worth merging on sight.
- **The weekly rebuild still earns its place**, for a narrower reason than
  before. Pinning froze the base *layer*, not what is installed on top of it:
  `apt-get install` resolves against Debian's current archive on every build, so
  a rebuild is still how a libssl or libsasl patch reaches `:main`. Scanning the
  result is a separate schedule — `security-scan.yml`'s `images` job — and now
  that the inputs are fixed, a new finding against an unchanged digest means the
  vulnerability data moved rather than the image.

## When a dependency turns out to be compromised

The state to get back to is a known-good `go.sum`, not a known-good version
number: the point of the attack is that the version number stayed the same.
`scripts/rollback-dependency.sh` runs the procedure below as one command
instead of hand-typed steps under pressure — the moment a typo is most
likely:

```bash
# Find the last commit whose dependency state you trust, then:
./scripts/rollback-dependency.sh --to <good-commit>
```

That restores `go.mod`/`go.sum` from `<good-commit>`, purges the local module
cache (or the compromised bits stay on the machine and keep verifying
against themselves), and re-downloads + re-verifies from scratch. It leaves
the restored files as an uncommitted change — reviewing and committing them
is a decision the script deliberately leaves to you.

For a container-shaped dependency — a base image, or syft — the equivalent is
reverting the digest or tag in the file that pins it and rebuilding; there is no
cache to purge beyond the local daemon's.

Then rebuild and republish the images. A compromised build-time dependency means
the artifacts built with it are suspect even if the source never changed, which
is the reason images carry provenance attestations: they are what lets you tell
which artifacts were built by which workflow run, from which commit, with which
dependency state.

## Offline module cache

A disconnected build needs the module cache itself, not just the pinned
runtime image `scripts/offline-bundle.sh` already ships for an air-gapped
*install* — that script covers the built product, not the toolchain that
built it. `scripts/bundle-go-modules.sh` downloads exactly what
`ui/backend/go.sum` records into a scratch cache, verifies it, and tars it:

```bash
./scripts/bundle-go-modules.sh -o go-modules.tar.gz
```

On the disconnected machine, extract it and point the toolchain at it with
`GOPROXY=off` — verified end to end (extract, `go mod verify`, `go build
./...`, zero network) before this was written down:

```bash
tar xzf go-modules.tar.gz -C /some/cache/dir
cd ui/backend
GOPROXY=off GOFLAGS=-mod=readonly GOMODCACHE=/some/cache/dir go mod verify
GOPROXY=off GOFLAGS=-mod=readonly GOMODCACHE=/some/cache/dir go build ./...
```

## Known gaps

- **The cooling window is process, not tooling.** Nothing checks that a PR
  actually waited the seven days "Reviewing a dependency change" above
  describes before merging a new module/tool release — it depends on the
  reviewer following the doc.
- **SBOM/provenance covers the shipped artifact's dependency tree, not a
  separate build-toolchain inventory.** `go version`, `govulncheck`'s pinned
  version, and the other build-time tool pins are recorded in the workflow
  files themselves (see "What is pinned, and how" above) but are not
  consolidated into the SBOM/provenance output alongside the image's own
  dependency tree.
