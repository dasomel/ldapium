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
| Base images | tag in each Dockerfile | Dependabot, weekly |
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

## When a dependency turns out to be compromised

The state to get back to is a known-good `go.sum`, not a known-good version
number: the point of the attack is that the version number stayed the same.

```bash
# 1. Find the last commit whose dependency state you trust.
git log --oneline -- ui/backend/go.mod ui/backend/go.sum

# 2. Restore both files together. Restoring only go.mod re-resolves and can
#    pull the same thing back in.
git checkout <good-commit> -- ui/backend/go.mod ui/backend/go.sum

# 3. Purge the module cache, or the compromised bits stay on the machine and
#    keep verifying against themselves.
go clean -modcache

# 4. Re-verify from scratch, then rebuild.
cd ui/backend && go mod download && go mod verify
```

For a container-shaped dependency — a base image, or syft — the equivalent is
reverting the digest or tag in the file that pins it and rebuilding; there is no
cache to purge beyond the local daemon's.

Then rebuild and republish the images. A compromised build-time dependency means
the artifacts built with it are suspect even if the source never changed, which
is the reason images carry provenance attestations: they are what lets you tell
which artifacts were built by which workflow run, from which commit, with which
dependency state.

## Known gaps

- **Build-time network egress is not restricted.** Nothing today stops a
  compromised build step from reaching an arbitrary host, and nothing alerts on
  it. Restricting it means an egress-filtering action or a self-hosted runner,
  which is a decision about CI architecture rather than a change to this
  repository.
- **Base images are pinned by tag, not digest.** Digest pinning would make
  builds reproducible, but the weekly rebuild exists precisely to absorb base
  image security updates without a PR; pinning by digest moves that to
  Dependabot's cadence. That trade-off has not been decided.
- **No offline module proxy.** Reproducing a build without network access needs
  a seeded module cache or a vendored tree; neither is set up.
