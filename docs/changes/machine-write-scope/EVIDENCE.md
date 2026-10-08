# Machine write scope evidence

## 2026-10-08: T-001, T-003 and T-010 baseline

Reviewed main `f03a36d` (PR #318 is merged). This records source observations and
executed checks separately; it does not claim that any machine write is enabled.

### T-001: runtime and contract source of truth

- `httpapi/machine_scopes.go`: `machineOps` has eight GET operations;
  `machineOpFor` rejects every other method before lookup. The runtime depends
  on the allowlist, not a test denylist.
- `httpapi/machine_write_scopes.go`: `machineWriteOps` is empty and is not
  consulted by the runtime. T-013 is the only planned opening unit.
- `config/machine.go`: `MachineScopes` is read + 11 write vocabulary entries;
  the client ceiling parser still refuses every write scope.
- `httpapi/machine_contract_test.go`: 24 D2 permanent denials plus 13 unopened
  writes = 37. The golden list detects removal; an opening must cite a D-id in
  `machineWriteOpenedBy`. This matches D13's planned shrink gate.
- OpenAPI contract tests require the published `machineBearer` set to equal the
  runtime allowlist and prohibit non-GET machineBearer operations today.

### T-003: downstream observation

- `ui/frontend/src/lib/api-docs.ts`: an explicit empty `security` array marks an
  operation public. Adding machineBearer to an existing protected operation does
  not make it public; scope display uses the scheme and `x-machine-scope`.
- `ui/frontend/src/lib/api.ts`: the frontend now supports optional `If-Match`
  and `Idempotency-Key`. Older design descriptions saying it never sends them
  predate #258/#308. Machine requirements must be limited to the machine path;
  they must preserve the optional human path.
- `docs/api.md`, `llms.txt`, the OpenAPI schema and the closed audit reason set
  need synchronized updates when operations open; no opening has happened here.
- `charts/ldapium/README.md`: write values are still pending T-024. No Helm value
  or operation was added by this evidence update.

### Executed verification

```sh
LDAPIUM_IMAGE=ldapium:revocation-review LDAPIUM_ACL_CONFIGS=a,b,c,d \
  python3 scripts/test/test-machine-acl-readonly-live.py
```

Observed: `RESULT: 461 checks passed, 0 failed, mutation=none, 32s`.
Four fresh isolated real LDAP containers, including the leading replication
identity rule, exercised read boundaries, secret suppression, direct write
refusal, unchanged admin/anonymous/human results and exact ACL rollback.
The image was built from `985d4b0` before #317's exporter-only change; LDAP
entrypoint/ACL content is the same at `f03a36d`.

The three-package race check and full `make check` also passed in the T-013
revocation writer worktree (same baseline plus operator tool/Go evidence test).
These checks validate compatibility, not machine-write execution.

Not verified: T-002's complete attribute inventory/overlay behavior; T-004's
write identity runtime matrix; T-011 onward implementation and opening gates.

## T-002 attribute inventory baseline (2026-10-08)

Current request builders (`ldapclient/users.go`, `groups.go`, `domain/patch.go`, `httpapi/patch_handlers.go`):

| Operation | Attributes actually written | Notes |
|---|---|---|
| createUser | objectClass={top,person,organizationalPerson,inetOrgPerson}; uid,cn,sn; optional givenName,mail,departmentNumber,o,ou | password triggers separate RFC3062 operation and compensation; future data-only machine create must reject password |
| patchUser | cn,sn,givenName,mail,departmentNumber,o,ou (Replace only) | uid absent from DTO; target DN unchanged; no ModifyDN |
| patchGroup | cn,description | membership separate; first machine release keeps group writes closed |
| add/removeGroupMember | member (Add/Delete) | server overlays may update memberOf/refint effects |
| lock/unlockUser | pwdAccountLockedTime | separate lock identity stage |
| setPassword | RFC3062 extended operation | separately approved credential stage; no data identity access |

PATCH rejects unknown/LDAP-only attributes before directory calls, including uid,
password/userPassword, objectClass, memberOf, pwd*, operational timestamps/CSN and
displayName (readable but not a patchable DTO field). The baseline test verifies
rejection alongside otherwise valid cn/sn fields and no echo of rejected values.
The pure request-builder test now checks exactly seven changes and the original
DN, so an added attribute or changed target fails.

The POST baseline test observes current human create behavior: unknown LDAP-only
fields are accepted but ignored by the supported DTO; a 201 reaches CreateUser
with the expected uid/cn/sn and no password. Thus PATCH strictness must not be
assumed for machine POST; its future guard must independently reject unknown keys.

T-002 source/DTO observations and separate live overlay evidence are complete below. These fixtures do not establish the future production write ACL or open any write route.

Final `go test -race -count=1 ./internal/httpapi ./internal/ldapclient` passed after the POST baseline test was added. Logs: `/tmp/ldapium-write-inventory-tests.log`.


T-002 live memberOf evidence: `LDAPIUM_IMAGE=ldapium:revocation-review python3 scripts/test/test-machine-write-overlay-live.py` exited 0. A fresh uniquely owned LDAP container gives its writer only group-member write plus general read. User cn Modify is denied rc50. Direct memberOf Modify is refused rc19 (`no user modification allowed`), a schema restriction rather than an ACL result. The same writer's group member Add sets user memberOf and member Delete clears it despite no user-attribute write permission. Credential log scan passes. CI runs this test in API+credentials E2E. Initial rc50 expectation for memberOf was corrected to the observed schema result; no ACL was weakened. Logs: `/tmp/ldapium-write-overlay-live.log`.

Separate live refint evidence: the fixture then grants the writer deletion of the one baseline user (entry + parent children), while all other user attributes stay read-only. Direct removal of a second user’s manager reference returns rc50. Deleting the referenced baseline user succeeds, and an administrator read confirms refint removed manager from the second user. Final full script exits 0 with credential-log scan clean. This observes configured refint behavior and does not claim the future machine write ACL is validated.


## T-018 read-identity / server identity proof (partial)

`WriteIdentityReader` uses M to base-read requested targets and each configured protected identity on one fresh connection/node. It requires server `entryDN`, validated `entryUUID`, and the required inetOrgPerson/groupOfNames class; compares UUIDs with protected identities; re-resolves protected entries for each check rather than trusting a stale cache. The constructor derives M/root/backup/profile/service protection and accepts all enabled writer identities from the trusted caller. Missing protected identities fail closed. Canonical naming types/ASCII/unambiguous values are checked before LDAP. Root DNs outside BaseDN cannot be reached by a strict target and are not queried. The image's optional fixed admin/replicator DNs are lexically denied even when no such entry exists.

Actual M is a separately created read-only bind identity in the disposable fixture. Direct user cn Modify by M returns LDAP50. The Go reader then accepts real user/group identities (including ASCII case variants), rejects wrong types, M/W/admin/replicator targets, aliases/OIDs/BER notation, invalid M bind and unresolved protection. Credentials are absent from logs.

`LDAPIUM_IMAGE=ldapium:revocation-review python3 scripts/test/test-machine-write-identity-live.py`: PASS, actual Go live test0.08s. HTTP/executor/member wiring is not present; no writes are opened and T-018 remains incomplete. Read-before-write TOCTOU remains and must be paired with atomic target revision/type constraints and least-privilege ACLs. The pre-decode LDAP allocation limit is unchanged; retained selected identity attributes are bounded (DN4096, class128×512).

Final identity-reader live proof additionally installs two separate real ACL denials: entryUUID hidden from M and all target read access hidden from M. Both Go checks fail closed (live0.01s each). `go test -race ./internal/ldapclient ./internal/httpapi -count=1` passes after final tests. `make check` exits0 after pinned frontend npm ci (0 reachable vulnerabilities). No HTTP write route is enabled.
