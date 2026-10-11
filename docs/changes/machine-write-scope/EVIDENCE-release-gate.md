# EVIDENCE: T-025 CI release gate (#378)

Recorded 2026-10-11 on branch `ci/378-machine-write-release-gate` (base 049fcc3). Not yet verified on a tag SHA: the gate is
verified when `release.yml` runs on a tag whose SHA has a successful `machine write (real Keycloak)` run.

## What was added

- `scripts/test/test-machine-write-keycloak-live.py`: real Keycloak 26.7.4 + real slapd (W_data/W_lock ACL fragments applied
  after the M rules, as the operator guide says) + the **normal** UI image with `MACHINE_WRITE_ENABLED=true`. 84 checks:
  - A: all five operations with positive tokens, W_data is the binding identity, no password on create, D8e refusals.
  - B: 30 negative requests, none binds W_data or changes the directory (reader-only ceiling, token without the scope,
    client ceiling without the scope, no write subtree, tampered/no token, PUT / group create / lock not opened, target outside
    the ceiling, ceiling root, protected DNs, OID-typed DN, group allow-list, privileged group, closed attribute set including
    `userPassword`, `objectClass`, `memberOf`, `pwd*`, `generatedPassword`, RDN); switch off -> 403; a ceiling over `ou=system` and a privileged group on a client allow-list are start-up errors; a privileged group inside the ceiling is refused with outcome `denied_protected`.
  - C: W_data cannot write `userPassword` / `pwd*` / `ou=system` directly (ACL backstop); M writes nothing.
  - D: 428 (no Idempotency-Key, no/empty If-Match), malformed If-Match refused, 412 `revision_conflict` on a stale tag, replay
    (executed once, `Idempotent-Replayed: true`, no W bind), different body 422, other client independent, replay on the SAME replica
    after Keycloak withdraws the client's write scope is 403 (re-authorized first, never the stored 201), the old token still
    replays it.
  - E: one `machine_access` line per request with `write_scope`, `compartment`, `target_kind`, `outcome`, fingerprints,
    `bind_dn`, no plaintext DN; outcomes applied / replayed / precondition_failed, scope and protected-DN denials, 428, LDAP refusal (createUser of an existing uid: W_data binds, slapd refuses, 409 `already_exists`, outcome `ldap_refused`; the line carries no `ldap_result` value there).
  - F: write budget (rps 1, burst 2) -> 429 `machine_rate_limited` + `Retry-After` while reads stay 200; second concurrent write
    of one client refused at once; the held write completes; slot and connections return to the baseline.
  - G: sentinel scan of all container logs (tokens and JWT segments, client secrets, bind/admin/userPassword values, request
    body sentinels, every Idempotency-Key): 0 hits.
- `.github/workflows/machine-write-e2e.yml`: job `machine write (real Keycloak)`, no path filter, heavy-E2E lane b, runs the new
  script and `test-machine-write-drill.py` on the production image, leftover-object check for `ldapium-mwk-`/`ldapium-mwd-`.
- `release.yml`: `"machine write (real Keycloak)"` added to `release_critical`; `RELEASING.md` names it.

## Local run (Colima/macOS, images built from this branch)

```text
$ docker build -t ldapium:mwk -f image/Dockerfile ./image && docker build -t ldapium-ui:mwk ui
$ LDAPIUM_IMAGE=ldapium:mwk LDAPIUM_UI_IMAGE=ldapium-ui:mwk python3 scripts/test/test-machine-write-keycloak-live.py
All machine write Keycloak live checks passed: 84 checks in 32s.   (wall 33 s, no containers left)
$ ... python3 scripts/test/test-machine-write-drill.py
All machine write drill checks passed: 61 checks in 60s.
```

## Not verified

- Protected DNs that are service accounts (W_data, W_lock, M, administrator) cannot be placed inside a ceiling at all (start-up error), so the live proof of the protected set uses a privileged group; the DN-variant matrix (case, escape, OID types) is covered by the Go tests of `machine_write_guard`.

- The workflow itself on GitHub runners and the release gate on a tag SHA (`actionlint` only; `queue: max` is flagged by the local
  actionlint exactly as in `machine-keycloak-e2e.yml`).
- Unauthorized-client isolation across replicas and the idempotency store after a restart (T-004, separate item of #378).
