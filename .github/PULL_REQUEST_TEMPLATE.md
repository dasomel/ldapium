## What this changes

<!-- And why. If it fixes an issue, "Fixes #123". -->

## How it was verified

<!--
Please say what you actually ran and what it printed, not what should happen.
Changes under image/ need a container that was built and booted — the
entrypoint does most of the work and only runs at startup.
-->

## Checklist

- [ ] `gofmt -l .`, `go vet ./...`, `go test ./...` in `ui/backend`
- [ ] `npm run lint && npm run build` in `ui/frontend`
- [ ] `helm lint charts/ldapium` and `./scripts/check-versions.sh`
- [ ] `shellcheck -s sh image/entrypoint.sh` / `shellcheck scripts/*.sh` if shell changed
- [ ] Docs updated (`README.md`, `charts/ldapium/README.md`, `ui/README.md`) if behaviour or values changed
