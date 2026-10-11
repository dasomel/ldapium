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


## T-014 subject/header prerequisite (partial stage)

Core route middleware now refuses a verified machine principal without Idempotency-Key (428 `idempotency_key_required`), while human header-less requests retain their existing path. Machine record ownership uses `machine:` + issuer byte length + `:` + issuer + client ID, never the shared bind DN or token subject hash. Missing issuer/client fails closed. Tests exercise tuple collision, token renewal, client/client and human/machine store separation, and a client filling its quota without exhausting another client's quota. Existing human middleware tests remain unchanged. Error table/golden/OpenAPI enum and API/LLM documentation are synchronized.

`go test -race ./internal/httpapi -count=1` passed. The machine write-operation table stays empty. Startup client quota capacity validation and authorization-before-replay integration remain T-014 opening gates; this stage does not mark T-014 complete. No LDAP-wire behavior is claimed by in-memory subject/store tests.

## T-018 atomic target-type constraint (partial)

`WithMachineWriteConstraints` marks the future machine execution context. User Modify/Delete controls add `objectClass=inetOrgPerson`, group Modify/Delete controls add `objectClass=groupOfNames`, ANDed with the mandatory entryCSN. Human contexts preserve the old revision/unconditional controls. The marker is not connected to HTTP until T-013. This is not full T-018: protected-entry UUID comparison and read-identity member checks remain required.

Actual Go LDAP-wire test runs inside a fresh `ldapium:revocation-review` container, bound as `cn=writer` (not root). Wrong-type group→DeleteUser and user→DeleteGroup both return ErrRevisionConflict (LDAP122); correct PatchUser and AddMember succeed; missing machine revision is refused. Administrator readback confirms both wrong-type targets survive, correct mail/member values exist, forbidden mail absent. Credential scan passes. The fixture grants the writer broad non-secret writes deliberately to isolate the type control; it does not validate final least-privilege ACLs.

- `LDAPIUM_IMAGE=ldapium:revocation-review python3 scripts/test/test-machine-write-type-live.py`: PASS, actual Go live test 0.02s plus post-write readback.
- Mutation removing the class conjunct: live test fails `group through user deletion: <nil>` (the wrongly typed entry was deleted). Restored binary/source and final live rerun PASS.
- `go test -race ./internal/ldapclient ./internal/httpapi -count=1`: PASS (4.987s / 12.687s).
- `make check`: exit0, formatting/vet/build/test/chart/license/vulnerability checks passed (0 reachable vulnerabilities). Initial failure was missing frontend oxlint; `npm ci` installed pinned dependencies and the complete rerun passed.
- Initial test binary had Darwin format; rebuilding with GOOS=linux corrected the container exec format failure. CI explicitly cross-builds Linux and runs the live path; no path filter added.

## T-018 read-identity / server identity proof (partial)

`WriteIdentityReader` uses M to base-read requested targets and each configured protected identity on one fresh connection/node. It requires server `entryDN`, validated `entryUUID`, and the required inetOrgPerson/groupOfNames class; compares UUIDs with protected identities; re-resolves protected entries for each check rather than trusting a stale cache. The constructor derives M/root/backup/profile/service protection and accepts all enabled writer identities from the trusted caller. Missing protected identities fail closed. Canonical naming types/ASCII/unambiguous values are checked before LDAP. Root DNs outside BaseDN cannot be reached by a strict target and are not queried. The image's optional fixed admin/replicator DNs are lexically denied even when no such entry exists.

Actual M is a separately created read-only bind identity in the disposable fixture. Direct user cn Modify by M returns LDAP50. The Go reader then accepts real user/group identities (including ASCII case variants), rejects wrong types, M/W/admin/replicator targets, aliases/OIDs/BER notation, invalid M bind and unresolved protection. Credentials are absent from logs.

`LDAPIUM_IMAGE=ldapium:revocation-review python3 scripts/test/test-machine-write-identity-live.py`: PASS, actual Go live test0.08s. HTTP/executor/member wiring is not present; no writes are opened and T-018 remains incomplete. Read-before-write TOCTOU remains and must be paired with atomic target revision/type constraints and least-privilege ACLs. The pre-decode LDAP allocation limit is unchanged; retained selected identity attributes are bounded (DN4096, class128×512).

Final identity-reader live proof additionally installs two separate real ACL denials: entryUUID hidden from M and all target read access hidden from M. Both Go checks fail closed (live0.01s each). `go test -race ./internal/ldapclient ./internal/httpapi -count=1` passes after final tests. `make check` exits0 after pinned frontend npm ci (0 reachable vulnerabilities). No HTTP write route is enabled.


Independent review raised virtual-root availability: actual startup RootDNs include cn=admin,BaseDN. The live test now includes this root DN. The existing helper still passes: this image creates an actual admin DIT entry (`image/ldifs/03-base-structure.ldif`), confirmed by successful M UUID resolution. The attempted red reproduction did not fail (`/tmp/ldapium-write-identity-root-red.log` contains PASS); no unobserved failure is claimed. External LDAP deployments whose configured in-base root DN has no readable DIT entry are intentionally refused by the unresolved-protection rule and require an explicit reviewed virtual-root design before opening writes.

## T-012/T-018/T-019 pre-connect DN policy scaffold

This unit has no request-path connection and does not complete the LDAP identity/type acceptance gates. `dnStrictlyWithinBase` refuses the boundary itself. `machineWritePolicy` separates creation-parent inclusion from target/member strict descendants, refuses protected identities and descendants, and requires exact group allowlist membership even inside allowed subtrees. The existing inclusive read guard is unchanged.

D26 canonical `uid/cn/ou/dc` naming types and reproducible ASCII values deliberately reject LDAP schema aliases/OIDs, BER hex values, repeated/edge whitespace and unsupported naming types. Positive tests retain case-insensitive spelling, escaped ASCII and multivalued RDN support. Invalid protected policy fails closed.

`go test -race ./internal/httpapi -count=1`: PASS (13.187s). Initial BER test failed because go-ldap decodes the hex value into a normal string; rejecting BER notation before parsing made it pass. Live server identity/entryUUID comparison, closed attribute whitelist, bind selection and configuration wiring remain pending. No T-012/T-018/T-019 completion boxes are checked by this scaffold.


T-012 closed-body field guard added to this scaffold: data-only create accepts only uid/cn/sn/givenName/mail/department/organization/organizationalUnit, patch adds dn and excludes uid/password, membership accepts only groupDn/memberDn, user delete accepts no body. Unknown operations deny. Duplicate/case-colliding keys, operational LDAP attributes, objectClass, password (even empty), userPassword, memberOf and privilege fields are refused; human handlers remain unchanged. DTO value validation still belongs to the existing handlers. This helper remains unwired until T-013.

Full httpapi race passed (12.734s; final restored rerun also passed). Two mutations were detected: replacing strict descendant with inclusive ancestry admits the boundary (two failed assertions), and adding password to create's allowlist admits the empty secret field and sentinel password (two failed assertions). Both restored. Logs `/tmp/ldapium-write-boundary-mutation.log`, `/tmp/ldapium-write-password-mutation.log`.

## T-017 machine If-Match prerequisite

`machineIfMatch` is intentionally not wired until T-013. The write-operation table stays empty.
Unit table covers absent/empty (428), wildcard/weak/list/repeated/malformed/unquoted/whitespace (400), and a valid strong entryCSN tag. Existing human conditional-write tests remain unchanged. Existing OpenAPI error enum already contains `if_match_required` and `invalid_request`; operation security stays unchanged while writes are closed.

- `go test ./internal/httpapi -run 'TestMachineIfMatch|Conditional' -count=1`: PASS.
- `go test -race ./internal/httpapi -count=1`: PASS (12.801s).
- Mutation allowing `*`: `TestMachineIfMatch/wildcard` fails with `missing rejection`; mutation restored.
- Live LDAP is not claimed by this header parser unit; LDAP assertion evidence belongs to T-018/T-021.
- Independent security review and final request-path integration remain pending.


## T-016 separate write limiter core (unwired)

A dedicated bounded clientBudget instance enforces integer RPS/burst, one active writer per allowlisted client and a bounded nonblocking global channel. The read budget is separate. Unknown clients create no state; expired/canceled contexts allocate no reservation. Global capacity refusal releases client concurrency (the attempted request consumes its rate token, matching the existing request-budget convention). Reservations release exactly once; cancellation does not release an active writer until its handler exits.

`go test -race ./internal/httpapi -count=1`: PASS (12.291s). Pure state tests cover per-client/global capacity, burst/refill, read/write independence, unknown-client state bounds, repeated release, panic/cancel/error exits and an expired deadline. Removing run's defer release produces three real failed assertions (panic/cancel/error leaked client slot), source restored and targeted suite PASS0.372s. No LDAP claims are made by this limiter unit. Configuration/HTTP/executor integration remains pending, so T-016 stays unchecked.

## T-013 operation opening (2026-10-11)

What changed: `machineWriteOps` (`httpapi/machine_write_scopes.go`) registers exactly `createUser` (no password, D15), `patchUser`, `deleteUser`, `addGroupMember`, `removeGroupMember`; the drill-only mechanism is deleted (`machine_write_drill.go` in `httpapi` and `config`, `machineWriteScopesOpen`, `appVersionSuffix`, `GO_TAGS`, `test-machine-write-drill-guard.py`, `test-machine-write-drill-artifact.sh`, their `ci.yml` steps, `TestDefaultBuildHasNoMachineWriteOperations`/`TestDefaultBuildHasNoDrillMarker`). Writes stay off by default (`MACHINE_WRITE_ENABLED=false`).

- Self-refusal: `config/machine_write*.go` (idempotency, W_data identity, at least one `MACHINE_WRITE_SUBTREES` client with an opened write scope in its ceiling; `TestMachineWriteSwitchRefusesItself`) and `checkMachineWritePrerequisites` in `httpapi/machine_write_runtime.go` (idempotency store, audit middleware, write limits, W_data identity, subtrees; `TestMachineWriteSwitchRefusesStartupWithoutAPrerequisite`, one prerequisite removed per row). Flag off: `TestMachineWriteScopeOffReadsNothing`, `TestMachineWriteOffValidatesNothing`.
- Ceilings: only the five opened write scopes parse in `MACHINE_ALLOWED_CLIENTS` (`config.MachineWriteOpenScopes`, kept equal to the table by `TestMachineWriteOpenScopesEqualTheTable`); they parse with the switch off too and grant nothing there, so the emergency "write-only redeploy" (flip only `MACHINE_WRITE_ENABLED=false`) can start. Lock, group create/update/delete and password scopes are refused at start-up.
- Contract: deny list 37 -> 32 (`deniedGolden`), `machineWriteOpenedBy` cites D15, D7, D8, D14, D14. Exhaustive test: writes off -> 8 reads reach exec, 37 rejected; writes on -> 8 reads + 5 writes allowed past the scope gate, 32 rejected. OpenAPI: `security` + `x-machine-scope` added to the five (additive), `docs/api.md`, `llms.txt`, `ui/README.md`, `machine-auth-operations.md` synchronised; the frontend badge test no longer pins 8.
- Drill on the normal image: `LDAPIUM_IMAGE=ldapium:l285t LDAPIUM_UI_IMAGE=ldapium-ui:l285t python3 scripts/test/test-machine-write-drill.py` -> `All machine write drill checks passed: 53 checks in 56s.` Step B now proves the start-up refusal and that the switch off writes nothing.
- Mutations (scratch copy, named tests fail): unregister `addGroupMember` -> `TestMachineDenyListShrinkNeedsDID`, `TestOpenAPIMachineBearerEqualsCodeAllowlist`, `TestWritePipeline_ProductionTableHasExactlyTheFiveOperations`, `TestMachineWriteOpenScopesEqualTheTable`, exhaustive tests; register `PUT updateUser` -> `TestMachineWriteOpenScopesEqualTheTable`, `TestOpenAPINoNonGetCarriesMachineBearer`, `TestMachineWriteSwitchRefusesStartupWithoutAPrerequisite` (catalog mismatch), exhaustive tests; drop the idempotency / limits prerequisite -> `TestMachineWriteSwitchRefusesStartupWithoutAPrerequisite`; drop the subtree prerequisite in config -> `TestMachineWriteSwitchRefusesItself`.
- Not verified here: a Kubernetes rollout, the CI result of `machine-keycloak-e2e.yml` on the normal image; T-025 (the release-critical write e2e workflow) is still open.
- D8e leaf-only delete, live (drill step A, 61 checks after this addition, `All machine write drill checks passed: 61 checks in 57s.`): `deleteUser` on a user that has a child entry -> **409 `conflict`** (slapd refuses the non-leaf delete; generic conflict body, audit `outcome":"ldap_refused"`), entry and child intact; on a group DN and on a container DN under the ceiling -> **403 `scope_denied` "target is not permitted for machine writes"** (audit `outcome":"denied_protected"`, refused before any bind, so these two are stopped by the pre-connect target policy, not by the class assertion; the assertion stays the second line and is covered at `ldapclient` level by T-018); a plain leaf user -> 204 and gone.
- Runtime prerequisite check also requires a client with both a write subtree and an opened write scope (`hasWriter`, rows "no client holds an opened write scope" / "write scope only on a client without a subtree"). The audit flag is set by `machineAuditMiddleware` itself when it is built.


## T-004 live measurements (2026-10-11, #378)

Script: `scripts/test/test-machine-write-t004-live.py` (reproducible; real slapd with the accesslog overlay, the package's `write-data.ldif` W_data fragment applied after the three M rules, the normal UI image and Keycloak for the replay step).
Images built from this branch: `docker build -t ldapium:t004 -f image/Dockerfile ./image`, `docker build -t ldapium-ui:t004 -f ui/Dockerfile ./ui`.

```text
$ LDAPIUM_IMAGE=ldapium:t004 LDAPIUM_UI_IMAGE=ldapium-ui:t004 python3 scripts/test/test-machine-write-t004-live.py
...
All T-004 measurement checks passed: 31 checks in 24s.
```

Failures during development, kept: run 1 used a `uid=` RDN for a `groupOfNames` Add (rc 65, naming violation: my test bug, fixed to `cn=`); `ldappasswd` returns rc 1 (not 50) with `Result: Insufficient access (50)` in its text, so the check reads the text.

| Item | Measured (real output) | Decision it bears on |
|---|---|---|
| 1 accesslog, direct | Add/Modify/Delete by W_data each leave `reqType`, `reqDN=<target>`, `reqAuthzID: uid=machine-write-data,ou=system,...` (plain DN, no `dn:` prefix), `reqResult: 0`; the refused Modify (objectClass replace) is logged too with `reqResult: 50`; `reqMod` carries the attribute values written (so a password written through the app would be in `reqMod`; none is, D15) | D4 confirmed: slapd attributes by compartment (W_data) only |
| 1 accesslog, via the UI | createUser/patchUser/deleteUser and addGroupMember/removeGroupMember (204/204, two new group modify records) through the UI: the only `reqAuthzID` value is W_data; the client id is not in slapd, only in the app audit line | D4/D6 confirmed |
| 2 non-leaf / container | `ldapdelete` of a user with a child: `rc 66 Operation not allowed on non-leaf (66) ... subordinate objects must be deleted first`; same for the non-empty container `ou=people`; an EMPTY container inside the write subtree is deletable by W_data (rc 0); W_data can also Add an `organizationalUnit` under a user | REQ-010 confirmed; D8e (app class assertion for containers) is required, the ACL cannot tell a container from a user |
| 3 memberOf / refint | W_data cannot write `memberOf` (`rc 19 memberOf: no user modification allowed`, schema, and ACL `none`), cannot read it, yet a permitted group `member` Add updates `memberOf` on the user and deleting a member user removes it from the group `member` (refint) | T-002 overlay facts confirmed under the real W_data fragment |
| 4 entryCSN assertion | `!assert=(&(entryCSN=<current>)(objectClass=inetOrgPerson))` as W_data: current -> rc 0; stale entryCSN -> `122 Assertion Failed`, no change; wrong objectClass half -> 122; `(userPassword=*)` as an assertion on a target that really has a `userPassword` -> 122; as a search filter on that target the admin finds the entry and W_data finds nothing (presence probe). A value-prefix probe was not informative: the admin's own prefix filter did not match either (no substring rule on `userPassword`), so a prefix oracle is NOT shown absent; stale assertion on Delete -> 122, entry stays | D19/D21 confirmed: the AND filter is evaluated for W_data, ACL `read` on the rest is enough for the operational `entryCSN` |
| 5 objectClass (D18) | Add with `objectClass: inetOrgPerson` rc 0 under the `add` level; Modify REPLACE and DELETE-value of objectClass rc 50; **Modify ADD of an objectClass value (`extensibleObject`) rc 0**; Add of a `groupOfNames` with `member=cn=admin,...` under the user subtree rc 0 | D18(a) confirmed (the `add` level exists and works). **Contradicts the D18 sentence that objectClass cannot be written by Modify**: value-add passes the ACL, so the closed-attribute app guard is the only barrier (D18(b) fallback already names this); same limit as EVIDENCE-acl.md |
| 5 Password Modify | `ldappasswd` as W_data on a user that has a password: `Insufficient access (50)`; afterwards the user still binds with the OLD password (rc 0) and not with the new one (rc 49). Caveat: the message is `Must supply old password ...`, so a ppolicy rule may be what answers; EVIDENCE-acl.md is the ACL proof that `userPassword` writes are refused with 50 | T-004 item 5 (v2c): not a password-stage proof |
| 6 replay after restart | same process: replay 201 `Idempotent-Replayed=true`. After `docker restart` of the UI: the same createUser key (entry deleted meanwhile) -> **201 re-executed**, no `Idempotent-Replayed`, entry exists again; create with a fresh key while it exists -> 409 `already_exists`; patch key replayed with the pre-restart `If-Match` -> 412, mail unchanged; delete key replayed with the pre-restart tag against the re-created entry -> 412, entry stays | D9 confirmed exactly: restart turns replay into re-execution; `If-Match` (412) and DN uniqueness (409) are the second line |
| 6 (new finding) | deleteUser when the target no longer exists (same key or a new key, any tag) -> **503 `unavailable`**, audit `reason=upstream_error`, not 404: `WriteIdentityReader.Check` cannot resolve the missing target and reports a directory error (`machine_write_identity.go:161-166`) | not a decision change; a retrying client sees a retryable 503 for a permanent condition after a restart replay. Follow-up candidate, not changed here |

Rotation/lockout on in-flight and next requests (item 2 of T-004) is not repeated: `EVIDENCE-drill.md` measured it (next write 503 on every replica, in-flight write completes, `MACHINE_REQUEST_TIMEOUT` bound, D24 lockout and the no-lockout policy).

Not verified here: a userPassword value-prefix oracle (no substring rule to probe); multi-node replication behaviour of W writes (accesslog per node); the Password Modify refusal as an ACL-only proof; a Kubernetes restart (a pod restart is the same empty memory store, but not run).
