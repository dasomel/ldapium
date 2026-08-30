# Contributing

Thanks for looking. This project packages OpenLDAP; it does not fork or patch
it. Changes to LDAP behaviour itself belong upstream at
[openldap.org](https://www.openldap.org/), and this repo tracks upstream
releases rather than carrying local patches.

## What the project is opinionated about

These are not style preferences — a change that breaks one of them will be
asked to change, so it is cheaper to know up front:

- **No default credentials, anywhere.** The image, the chart and the compose
  file each refuse to start without an admin password rather than falling back
  to a guessable one. New configuration follows the same rule.
- **No sample data.** A fresh directory contains the base DN and the admin
  entry, nothing else.
- **The UI binds as the logged-in user.** It has no service account of its own
  (SSO is the single exception, and only because a token carries no password to
  bind with). If a feature needs `cn=config` access, it does not fit — that is
  a different privilege level than any UI session can hold.
- **Verified, not assumed.** Comments in this repo state what was actually
  observed, including when the obvious approach turned out not to work. Please
  keep that up: a comment saying *why* something is not done the obvious way is
  worth more than one restating what the code does.

## Getting a local environment

Everything runs from the repo root.

```sh
make help             # every target, with a one-line description each
make local-init       # write .env with freshly generated dev credentials
make local-up         # server on :389, UI on :8080
make local-credentials
```

`local-init` generates the admin password and session secret rather than
shipping one, so there is no default credential even in development. If you
prefer to write `.env` yourself, `.env.example` lists what is required.

For frontend work, `make frontend-dev` starts Vite on :5173 with `/api`
proxied to the backend on :8080, so the UI hot-reloads against a real
directory.

## Before opening a pull request

`make check` runs what CI runs, in the same order, which is faster than a round
trip. `scripts/check-make-parity.sh` runs in both places — inside `make check`
and as a step in CI — and fails when the two drift apart, so the sentence above
stays true rather than staying written. The one deliberate exception is
`scripts/check-base-images.sh`, which queries a registry for each pinned base
image digest and so needs network that an air-gapped checkout will not have; it
is listed as such in the parity script. Individually:

```sh
# Frontend first — ui/backend/web embeds the built SPA, so the Go module does
# not compile until this has been run at least once.
cd ui/frontend && npm ci && npm run lint && npm run build
cd ui/backend  && gofmt -l . && go vet ./... && go test ./...
helm lint charts/ldapium
shellcheck -s sh image/entrypoint.sh && shellcheck scripts/*.sh
./scripts/check-versions.sh
./scripts/check-modules.sh
./scripts/licenses.sh --check
./scripts/check-make-parity.sh
```

Changes to `image/` need an actual container build and boot, not just a
successful `docker build` — the entrypoint does most of the work, and it only
runs at startup. Say in the PR what you observed.

For anything touching the chart or the image, the fastest real check is the
one CI runs (`.github/workflows/e2e.yml`), locally:

```sh
kind create cluster --name dev
docker build -t ldapium:dev image
kind load docker-image ldapium:dev --name dev
helm install directory charts/ldapium --namespace directory --create-namespace \
  --set image.repository=ldapium --set image.tag=dev --set image.pullPolicy=Never \
  --set auth.adminPassword="$(head -c 24 /dev/urandom | base64)" --wait
helm test directory --namespace directory --logs
```

`charts/ldapium/files/tests/directory-test.sh` is a plain script, so it can
also be pointed at any LDAP server directly — which is how it was developed:

```sh
printf 'secret' > /tmp/pw && chmod 400 /tmp/pw
LDAP_URL=ldap://127.0.0.1:389 LDAP_ROOT_DN=dc=example,dc=org \
LDAP_ADMIN_DN=cn=admin,dc=example,dc=org PASSWORD_FILE=/tmp/pw \
  sh charts/ldapium/files/tests/directory-test.sh
```

## What runs where

`make check` and CI overlap by design (`scripts/check-make-parity.sh` keeps them
honest about it), but most of `make`'s targets have no CI equivalent and most
of CI has no local equivalent — this is that map, so you don't have to
reconstruct it from two sets of files.

| Local | Purpose | CI equivalent |
|---|---|---|
| `make check` | lint, unit tests, build, `check-versions.sh`, `check-modules.sh`, `licenses.sh --check` | `ci.yml`: `backend`, `frontend`, `helm`, `licenses`, `shellcheck` — same commands, same order |
| `make licenses` | regenerate `THIRD-PARTY-LICENSES.md` | `ci.yml`'s `licenses` job runs the check form (`--check`), not the regenerating one — CI verifies the file, it never writes it |
| `make sbom` | SBOM for the images this build produced, written to `./sbom` | `build-multiarch.yml`'s SBOM step — same tool (syft), against the image the workflow just built rather than one you built locally |
| `make local-init` / `local-up` / `local-down` / `local-logs` / `local-credentials` / `frontend-dev` / `k8s-credentials` / `k8s-ui-forward` | local dev loop | none — these exist because CI cannot give you a directory to click through |

The other direction — CI stages nothing in `make` reaches:

| CI stage | Workflow(s) | Why there is no local target |
|---|---|---|
| e2e (install, TLS, upgrade, backup/restore, replication chaos, metrics, security, UI browser) | `e2e.yml`, `upgrade-e2e.yml`, `backup-restore.yml`, `replication-chaos-e2e.yml`, `metrics-e2e.yml`, `security-e2e.yml`, `ui-e2e.yml` | each needs a kind cluster and takes minutes, not seconds — see the kind snippet above for running one by hand instead of packaging it as a target that would just wrap the same three commands. `ui-e2e.yml` additionally needs Playwright's browser binaries (`npx playwright install --with-deps chromium` in `ui/frontend`) and something to point `E2E_BASE_URL`/`E2E_ADMIN_DN`/`E2E_ADMIN_PASSWORD` at — `npx playwright test` in `ui/frontend` once you have those. |
| `base-images` (`scripts/check-base-images.sh`) | `ci.yml` | queries a container registry for each pinned digest; needs network `make check` deliberately does not require |
| `Chart manifests pass kubeconform` (`scripts/verify-chart-schema.sh`) | `ci.yml` | needs the kubeconform binary; CI downloads it as its own step, `make check` deliberately does not require installing it locally |
| `hadolint`, CodeQL, Scorecard, Trivy (`images` job) | `ci.yml`, `codeql.yml`, `scorecard.yml`, `security-scan.yml` | hosted analysis tools without a meaningful local equivalent |
| `Published images` / `Build offline bundle` | `security-scan.yml`, `offline-bundle.yml` | operate on already-published GHCR images, which a local checkout does not have |
| release, build-multiarch, supply-chain evidence | `release.yml`, `build-multiarch.yml`, `supply-chain.yml` | push to GHCR and create a GitHub release; not something to reproduce by hand |

## Commits

[Conventional Commits](https://www.conventionalcommits.org/), e.g.
`fix(ui): treat sizeLimitExceeded as "has children"`. Scopes in use: `image`,
`ui`, `chart`, `scripts`, `ci`, `docs`.

## Reporting security issues

Please do not open a public issue — see [SECURITY.md](SECURITY.md).
