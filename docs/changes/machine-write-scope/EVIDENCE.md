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

Remaining T-002 evidence: live memberOf/refint behavior outside the writing
identity's ACL, and POST unknown-field binding baseline. This inspection does
not establish LDAP permissions, open any write route or complete T-002.
