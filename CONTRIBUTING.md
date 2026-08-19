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

`make check` runs everything CI runs, in the same order, which is faster than
a round trip. Individually:

```sh
# Frontend first — ui/backend/web embeds the built SPA, so the Go module does
# not compile until this has been run at least once.
cd ui/frontend && npm ci && npm run lint && npm run build
cd ui/backend  && gofmt -l . && go vet ./... && go test ./...
helm lint charts/openldap
shellcheck -s sh image/entrypoint.sh && shellcheck scripts/*.sh
./scripts/check-versions.sh
./scripts/licenses.sh --check
```

Changes to `image/` need an actual container build and boot, not just a
successful `docker build` — the entrypoint does most of the work, and it only
runs at startup. Say in the PR what you observed.

For anything touching the chart or the image, the fastest real check is the
one CI runs (`.github/workflows/e2e.yml`), locally:

```sh
kind create cluster --name dev
docker build -t openldap-suite:dev image
kind load docker-image openldap-suite:dev --name dev
helm install directory charts/openldap --namespace directory --create-namespace \
  --set image.repository=openldap-suite --set image.tag=dev --set image.pullPolicy=Never \
  --set auth.adminPassword="$(head -c 24 /dev/urandom | base64)" --wait
helm test directory --namespace directory --logs
```

`charts/openldap/files/tests/directory-test.sh` is a plain script, so it can
also be pointed at any LDAP server directly — which is how it was developed:

```sh
printf 'secret' > /tmp/pw && chmod 400 /tmp/pw
LDAP_URL=ldap://127.0.0.1:389 LDAP_ROOT_DN=dc=example,dc=org \
LDAP_ADMIN_DN=cn=admin,dc=example,dc=org PASSWORD_FILE=/tmp/pw \
  sh charts/openldap/files/tests/directory-test.sh
```

## Commits

[Conventional Commits](https://www.conventionalcommits.org/), e.g.
`fix(ui): treat sizeLimitExceeded as "has children"`. Scopes in use: `image`,
`ui`, `chart`, `scripts`, `ci`, `docs`.

## Reporting security issues

Please do not open a public issue — see [SECURITY.md](SECURITY.md).
