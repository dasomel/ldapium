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

## T-011 configuration draft (2026-10-08)

Adds separate data and optional lock identities, validates idempotency/auth prerequisites and DN separation, and ignores subordinate variables behind disabled switches. Uses v1's administrator/root/service-identity checks, adding the read and fixed replication identities. Numeric attribute type and ambiguous whitespace spellings on either side of the DN comparison fail closed. Credential identities are deliberately excluded under Resolved Q1's separate-approval rule; this is recorded as a T-011 partial scope rather than implementing the parenthetical W_cred early.

The HTTP regression presents a valid token containing all scope vocabulary with both identities configured: every non-GET protected route remains 403 scope_denied, no executor or directory bind is reached. No operation registration, client write ceiling, request execution, ACL, image or Helm change.

Remaining: independent security review, documentation/Helm integration at later stages, live bind/ACL proof when the identities acquire consumers, and the separately approved credential stage. T-011 remains unchecked pending review and the clarified scope.

Observed `go test -race -count=1 ./internal/config ./internal/httpapi ./internal/machineauth`: all three packages passed. Removing the protected-identity comparison made `TestMachineWriteIdentitiesRejectProtectedDNVariants` fail with real assertions; source restored and `go test ./internal/config -run ^TestMachineWrite -count=1` passed. Logs: `/tmp/ldapium-write-identities-{tests,mutation,restored}.log`.

Final `make check` exited 0 after the identity ambiguity guard was added (frontend lint/build; backend formatting/vet/live-tag vet/tests/build; shell, manifest, chart, license and reachable vulnerability checks). The 3-package race run also passed after the final code change. This is configuration/HTTP guard evidence; no claim of live write-identity bind or ACL verification is made because there is no consumer or opened operation in this unit.


### T-011 independent review correction: schema aliases

Independent review reproduced `commonName=admin` and `domainComponent` base aliases binding as rootdn while the old Go distinctness check accepted them (`/tmp/ldapium-security-alias-live.log`). Canonical `uid/cn/ou/dc` naming types are now required on writer and protected identities; unknown names, OIDs, ambiguous whitespace and non-ASCII values fail closed. The cost is refusal of unusual but legitimate naming types; operators must use canonical spelling, with no privileged fallback.

`go test -race ./internal/config -count=1` passed after adding the review reproducer plus writer/read/root/backup/profile/service/lock alias cases. Independent reviewer recheck remains required; no machine write route is opened.

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
