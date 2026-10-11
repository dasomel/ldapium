# EVIDENCE: T-022 emergency-block drill (#285)

Recorded 2026-10-11 from `scripts/test/test-machine-write-drill.py` on images built from this branch (main at adcb7e2):
server `docker build -t ldapium:l285d -f image/Dockerfile ./image`, UI drill image
`docker build --build-arg GO_TAGS=machinewritedrill -t ldapium-ui:l285d-drill ui`, UI default image `docker build -t ldapium-ui:l285d-default ui`.
Real Keycloak 26.7.4 (start-dev), real slapd, two UI replicas, docker (not Kubernetes). **No production or release build opens a write, enforced by the CI guard and the artifact check** (`scripts/test/test-machine-write-drill-artifact.sh` inspects the built binaries: `go version -m` build settings and the `DRILL BUILD` marker string; the tagged binary is its mirror):
the only thing that registers the five first-ship operations is the drill-only build tag `machinewritedrill` (not published; kept out of release builds by the CI guard and the artifact check).
T-013 is NOT ticked and no operation is registered outside the tag.

## What was built

- `ui/backend/internal/httpapi/machine_write_drill.go` (`//go:build machinewritedrill`): fills `machineWriteOps` from `machineWriteCatalog`
  (createUser without password, patchUser, deleteUser, addGroupMember, removeGroupMember). `ui/backend/internal/config/machine_write_drill.go`
  (same tag) lets a client ceiling name the write scopes (the default build still refuses them at start-up, `machineWriteScopesOpen` in `config/machine.go`).
- `ui/Dockerfile`: `ARG GO_TAGS=""` (empty default) passed to `go build -tags`. `ui/README.md` documents that such images are for drills only.
- `ui/backend/internal/httpapi/machine_write_closed_test.go` (`!machinewritedrill`): the default build has an empty `machineWriteOps`.
- `scripts/test/test-machine-write-drill-guard.py` (+ `--self-test`), wired into `ci.yml` (chart job, two steps).
- `.github/workflows/machine-keycloak-e2e.yml`: builds the drill image with the tag in that job only (`docker build --build-arg GO_TAGS=machinewritedrill -t "$LDAPIUM_UI_DRILL_IMAGE" ui`, not pushed; the guard forbids push/save/upload there) and runs the drill; the leftover-object check also covers `ldapium-mwd-`.

## Result (real output)

```text
$ LDAPIUM_IMAGE=ldapium:l285d LDAPIUM_UI_IMAGE=ldapium-ui:l285d-drill LDAPIUM_UI_DEFAULT_IMAGE=ldapium-ui:l285d-default python3 scripts/test/test-machine-write-drill.py
...
PASS: [F] while locked: writes 503/503 even with the CORRECT password, reads 200, M still binds
PASS: [F] refused writes (correct-password binds while locked) do not extend or re-arm the lock
PASS: [F] alert query 1: (pwdAccountLockedTime=*) under ou=system lists the locked W account
PASS: [F] alert query 2: accesslog (reqType=bind)(reqDN=W)(reqResult=49) counts 13 failed binds
PASS: [F] admin unlock (delete pwdAccountLockedTime): the next write succeeds
PASS: [F] default policy: 5 refused UI writes (one failed bind each) after a rotation lock W_data
PASS: [F] pwdLockout FALSE: writes keep working after 25 wrong-password binds (201)
PASS: [F] mitigation (dedicated policy: pwdLockout FALSE, no pwdMaxFailure): 25 wrong-password binds neither lock nor mark W_data, writes keep working (([], 201))
PASS: [F] with that policy the rotation block still works (8 refused writes, {503}) and 8 failed UI binds do not lock the account
PASS: [F] restoring the password recovers the very next write (no lock to clear)
PASS: [F] removing the manual lock recovers the next write
PASS: [F] mitigation (pwdLockoutDuration 8 s): writes recover by themselves 7.7 s after the lock, no operator action
PASS: [F] W_data back on the default policy and writing
PASS: no token or secret value appears in any container log
All machine write drill checks passed: 53 checks in 54s.
```

Observations quoted by `docs/machine-auth-operations.md` (the `OBS` lines of the same run):

```text
OBS C1 next write after W_data password rotation: 503 on both replicas, +17/31 ms after the modify returned (no polling, the very first request)
OBS C2 restore: both replicas write again on the first request (+30 ms); issued token never revoked (exp 300s lifetime, still valid)
OBS D1 write-only redeploy of two replicas (remove + start + ready, sequential): 0.8 s; the first request on each new replica was already 403
OBS E1 write HELD on its already-bound W_data connection while the password was rotated: response 201, entry applied=True, completed 0.05 s after the rotation (held 1.3 s before it)
OBS E2 while W_data is rotated: replay of the completed key -> 201 (Idempotent-Replayed=true, no LDAP write), a NEW key -> 503
OBS E3 write stalled at the LDAP connection: 409 after 10.0 s in total (MACHINE_REQUEST_TIMEOUT=10s), the UI closed the W connection 10.0 s after the op was held; rotation was 2.3 s into the request, so the request ended 7.7 s after the rotation
OBS E4 retry of the key whose write timed out in flight (outcome unknown): 409 '{"error":"the result of this request could not be determined; read the resource to check its state before retrying","message":"the result of this request could '
OBS E5 same stall with MACHINE_REQUEST_TIMEOUT=4s: 409 after 4.0 s
OBS F0 default policy cn=default,ou=policies,dc=example,dc=org: {'pwdLockout': 'TRUE', 'pwdMaxFailure': '5', 'pwdLockoutDuration': '900', 'pwdFailureCountInterval': '900'}
OBS F1 default policy: lock after 5 wrong binds; writes 503 for pwdLockoutDuration=900 s unless unlocked; reads/M unaffected
OBS F1b default policy: rotation + refused UI writes lock the account at write #5; after the admin restored the password the next write is 201 (lock attribute still present: False)
OBS F2 policy with only pwdLockout FALSE (pwdMaxFailure 5 kept): after 25 wrong binds pwdAccountLockedTime=SET 20261011070022Z, the next write is 201
OBS F2b under the no-lockout policy an operator-set pwdAccountLockedTime=000001010000Z (permanent lock) makes the next write 201: the attribute is NOT honoured when pwdLockout is FALSE (use the password rotation as the block there)
OBS F3 short-duration policy (3 failures, 8 s): self-recovered 7.7 s after the lock; the unrelated reads were 200 throughout
```

Every PASS line of that run (53):

```text
PASS: W_data/W_lock accounts created and the write ACL fragments applied after the M rules
PASS: [A] createUser (no password) -> 201 and the entry exists (got 201 {"dn":"uid=d01,ou=people,dc=example,dc=org"}
PASS: [A] the write bound as W_data (slapd accesslog)
PASS: [A] patchUser with a strong If-Match on the OTHER replica -> 2xx (got 204 )
PASS: [A] addGroupMember -> 204
PASS: [A] removeGroupMember -> 204
PASS: [A] deleteUser (leaf) -> 204 and the entry is gone
PASS: [A] the write audit line is emitted: {"event": "machine_access", "provider": "oidc", "actor": "svc-writer", "request_id": "wGQLwbYXZWcNPacGNElwnJKYBRLmWmRR", "operation": "createUser", "method": "POST", "
PASS: [A] negative "reader token (no write scope)" -> 403 (got 403 {"error":"insufficient scope","message":"insufficient scope","code":"scope_denied","requestId":"HwJoAyHvQqyANfUlGJpQhLWP)
PASS: [A] negative "client without a write subtree" -> 403 (got 403 {"error":"insufficient scope","message":"insufficient scope","code":"scope_denied","requestId":"HusvuOObYYqvSnBNwFSGQMuS)
PASS: [A] negative "tampered token" -> 401 (got 401 {"error":"invalid bearer token","message":"invalid bearer token","code":"token_invalid","requestId":"yQYpApOilAgwxgzQzBI)
PASS: [A] negative "no Idempotency-Key" -> 428 (got 428 {"error":"Idempotency-Key is required for machine writes","message":"Idempotency-Key is required for machine writes","co)
PASS: [A] negative "patch without If-Match" -> 428 (got 428 {"error":"If-Match is required for machine writes","message":"If-Match is required for machine writes","code":"if_match_)
PASS: [A] negative "target outside the ceiling" -> 403 (got 403 {"error":"dn is not permitted for this machine client","message":"dn is not permitted for this machine client","code":"s)
PASS: [A] negative "group not on the allow-list" -> 403 (got 403 {"error":"group is not writable for this machine client","message":"group is not writable for this machine client","code)
PASS: [A] negative "PUT is not opened" -> 403 (got 403 {"error":"operation not permitted for machine clients","message":"operation not permitted for machine clients","code":"s)
PASS: [A] negative "createUser with a password field" -> 400 (got 400 {"error":"request body is not a permitted machine write body","message":"request body is not a permitted machine write b)
PASS: [A] none of the negative requests bound as W_data
PASS: [A] rotating W_LOCK does not affect the five operations (createUser 201)
PASS: [B] default (tag-free) image: a client ceiling naming a write scope is a START-UP ERROR (it exits, no listener)
PASS: [B] default image with MACHINE_WRITE_ENABLED=true and read-only ceilings: write is 403, no entry, no W bind
PASS: [B] default image: reads are 200
PASS: [C] the first write after the rotation is 503 on every replica (503/503); first-503 at +17 ms (replica a), +31 ms (replica b) after the rotation returned
PASS: [C] reads stay 200 on both replicas with the same token (M is untouched)
PASS: [C] slapd saw exactly 4 failed W_data binds for 4 refused writes (one bind per request, no retry)
PASS: [C] the refusals are audited with reason bind_failed (4 lines): failed","subject_fingerprint":"92155ecf7faf","write_scope":"directory.users.create","compartment":"data","target_kind":"user","target_dn_fin
PASS: [C] after restoring the password the same token and the same Idempotency-Keys write again on both replicas (201/201)
PASS: [D] replica a redeployed with MACHINE_WRITE_ENABLED=false: write 403 (scope_denied), read 200, SAME pre-event token ({"error":"operation not permitted for machine clients","message":"operation not permitt
PASS: [D] replica b redeployed with MACHINE_WRITE_ENABLED=false: write 403 (scope_denied), read 200, SAME pre-event token ({"error":"operation not permitted for machine clients","message":"operation not permitt
PASS: [D] no entry was created by the refused writes
PASS: [D] redeploy with MACHINE_WRITE_ENABLED=true: the same token writes again on both replicas
PASS: [E] via the proxy a write works and leaves no open LDAP connection (open=0): no connection reuse across requests
PASS: [E] an in-flight write on an already bound connection COMPLETES after the rotation (measured: 201, applied=True)
PASS: [E] a new write after the rotation is 503 (503)
PASS: [E] a write stalled at the LDAP connection ends at the request deadline with 409 '{"error":"the result of this request could not be determined; read the resource to check its state before retrying","messa
PASS: [E] the UI closed the stalled LDAP connection itself
PASS: [E] with MACHINE_REQUEST_TIMEOUT=4s the stalled write ends after 4.0 s (409): the in-flight bound follows the setting
PASS: [E] password restored: writes work again on the proxied replica
PASS: [F] default policy: W_data is locked after 5 wrong-password binds (pwdMaxFailure=5)
PASS: [F] while locked: writes 503/503 even with the CORRECT password, reads 200, M still binds
PASS: [F] refused writes (correct-password binds while locked) do not extend or re-arm the lock
PASS: [F] alert query 1: (pwdAccountLockedTime=*) under ou=system lists the locked W account
PASS: [F] alert query 2: accesslog (reqType=bind)(reqDN=W)(reqResult=49) counts 13 failed binds
PASS: [F] admin unlock (delete pwdAccountLockedTime): the next write succeeds
PASS: [F] default policy: 5 refused UI writes (one failed bind each) after a rotation lock W_data
PASS: [F] pwdLockout FALSE: writes keep working after 25 wrong-password binds (201)
PASS: [F] mitigation (dedicated policy: pwdLockout FALSE, no pwdMaxFailure): 25 wrong-password binds neither lock nor mark W_data, writes keep working (([], 201))
PASS: [F] with that policy the rotation block still works (8 refused writes, {503}) and 8 failed UI binds do not lock the account
PASS: [F] restoring the password recovers the very next write (no lock to clear)
PASS: [F] removing the manual lock recovers the next write
PASS: [F] mitigation (pwdLockoutDuration 8 s): writes recover by themselves 7.7 s after the lock, no operator action
PASS: [F] W_data back on the default policy and writing
PASS: no token or secret value appears in any container log
```

## What the drill shows (AC-011, AC-017(c), D12, D24)

- **(b) rotation**: the first write after the `W_data` password rotation is 503 on both replicas (+17 ms and +31 ms after the modify returned), reads stay 200, slapd saw
  exactly four failed `W_data` binds for four refused writes; the same pre-event token and the same `Idempotency-Key`s write again after the restore (+30 ms).
- **(a) write-only redeploy** (`MACHINE_WRITE_ENABLED=false`): first request on each new replica is 403, reads 200, same token; redeploy with `true` writes again.
- **(c) issued token**: never revoked by either lever (same token verified before, during and after).
- **in-flight**: a write held on its already-bound `W_data` connection while the password was rotated COMPLETED (201, entry applied). A write stalled at the LDAP connection ends at
  `MACHINE_REQUEST_TIMEOUT` (10.0 s at 10 s, 4.0 s at 4 s) with 409 outcome-unknown; with a rotation 2.3 s in it ended 7.7 s after the rotation. A completed key replays its stored 201 while `W_data` is rotated; a new key is 503.
- **D24 lockout**: default policy locks `W_data` after 5 wrong binds (the 5th refused UI write after a rotation also locks it), writes 503 even with the correct password, reads and `M` unaffected,
  an admin password reset or `delete: pwdAccountLockedTime` recovers. Mitigations measured: `pwdLockout FALSE` without `pwdMaxFailure` (25 wrong binds: no lock, rotation block still works, but an operator-set lock is ignored);
  flag-only (`pwdMaxFailure 5` kept) still stamps `pwdAccountLockedTime` while writes keep working; short duration (8 s) self-recovers 7.7 s after the lock. Alert queries verified.
- The default (tag-free) image: a ceiling naming a write scope is a start-up error (container exits), and with read-only ceilings and `MACHINE_WRITE_ENABLED=true` a write is 403 with no W bind.

## Guard test and its mutation test

```text
$ python3 scripts/test/test-machine-write-drill-guard.py
drill guard: OK (the drill tag is confined to the drill files)
$ python3 scripts/test/test-machine-write-drill-guard.py --self-test
PASS: clean tree: 0 problems
PASS: mutation "Dockerfile default ARG GO_TAGS=tag" is detected ...
... (19 mutations: Dockerfile ARG/ENV/hard-coded -tags/empty ARG removed, release.yml build and push, build-multiarch.yml, Makefile target and build-arg,
     Helm chart value, docker-compose override, a script, the drill workflow pushing / using the tag outside its sanctioned line / losing it,
     the three build constraints removed, a Go file elsewhere)
self-test: 19/19 mutations detected
```

Go: `TestDefaultBuildHasNoMachineWriteOperations` passes in the default build. Mutation (scratch copy, not committed): `var machineWriteOps = []machineOp{{ID: "createUser", ...}}` fails it:
`machine_write_closed_test.go:13: default build registers 1 machine write operations, want 0`.
`go vet ./... && go vet -tags live ./... && go vet -tags machinewritedrill ./... && go test ./...` all pass in `ui/backend` (default build); with `-tags machinewritedrill` the default-build refusal test in `config` fails by design
(one failing test), which is why the drill tag is kept out of the test and release builds (enforced by the CI guard and the artifact check).

## Mutation: the drill FAILS if the rotation does not block

Scratch change (copy of `ui/backend` in the session scratchpad, NOT in the repository): `ldapclient.dialer.Bind` caches the authenticated `W_data` connection for the process lifetime
(never closed, not tied to the request context) and hands it out again, so a rotation in the directory cannot block the next write. Built with the tag, layered on the drill image, run unchanged:

```text
PASS: [B] default image: reads are 200
AssertionError: [C] the first write after the rotation is 503 on every replica (201/201); first-503 at +4 ms (replica a), +7 ms (replica b) after the rotation returned
rc=1
```

## Not run / limits

- CI: the new `ci.yml` steps and the `machine-keycloak-e2e.yml` drill step have not run in GitHub Actions (only locally); `actionlint` reports only the pre-existing `queue:` key of that workflow.
- The mutation drill is not wired into CI (it needs a second UI image build); it was run locally once.
- Not measured: Kubernetes rolling update, multi-node LDAP, a request stalled in the `M` pre-read, the natural expiry of the 900 s default lock, `W_lock` operations (none opened in the first ship).
- The drill image is the only place the operations exist; T-013 remains open and must replace the two drill files with the real registration.
