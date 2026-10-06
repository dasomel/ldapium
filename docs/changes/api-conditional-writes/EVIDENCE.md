# Evidence: api-conditional-writes (issue #216)

Spike for T-002 / "검증하지 못한 사실" 1-5, 8 (partial). Run 2026-10-06 against a real slapd built from
this tree: `docker build -t l2-ldap:1 -f image/Dockerfile ./image` (OpenLDAP 2.6.15), container
`l2-s1` with `LDAP_ROOT_DN=dc=example,dc=org`, an explicit `LDAP_ADMIN_PASSWORD` and named volumes
(`l2-cfg`, `l2-data`). Fixtures: `ou=people`, `ou=groups`, non-admin users `uid=alice`/`uid=bob` (plain
`inetOrgPerson`, password set with `ldappasswd`). Output below is trimmed to the relevant lines.
"admin" = the rootDN `cn=admin,dc=example,dc=org`; "alice" = a non-root bind under the image's default
ACL (`to * by self write by users read by anonymous none`, `image/entrypoint.sh:810-816`).

## Verdict

The package's mechanism works as designed: slapd supports the RFC 4528 assertion control for Modify,
Delete and ModifyDN; `entryCSN`/`entryUUID`/`creatorsName` are readable by any authenticated non-root
bind; stale assertions return LDAP result 122 with no write. No design change is needed. Findings that
refine the package are listed under "Differences / caveats" at the end.

## (a) Assertion control (OID 1.3.6.1.1.12): match succeeds, mismatch is 122

```
$ ldapsearch -x -LLL -H ldap://localhost -b "" -s base supportedControl   (excerpt)
supportedControl: 1.3.6.1.1.13.2        # post-read
supportedControl: 1.3.6.1.1.13.1        # pre-read
supportedControl: 1.3.6.1.1.12          # assertion

bob csn=20261006012753.858701Z#000000#000#000000
--- modify, matching CSN (admin), critical:  ldapmodify -e '!assert=(entryCSN=<csn>)'
modifying entry "uid=bob,ou=people,dc=example,dc=org"
rc=0
bob csn now=20261006012810.732606Z#000000#000#000000 (changed? yes)
--- modify, STALE CSN
ldap_modify: Assertion Failed (122)
rc=122
csn after failed=20261006012810.732606Z#000000#000#000000 (unchanged? yes)
--- delete stale CSN:  ldapdelete -e '!assert=(entryCSN=<stale>)'
ldap_delete: Assertion Failed (122)         rc=122    (entry still present)
--- delete matching CSN
rc=0                                         (entry gone: "No such object (32)")
--- ModifyDN (ldapmodrdn) stale / matching
Rename Result: Assertion Failed (122)       rc=122
matching modrdn rc=0
```

Assertion on a missing entry yields `No such object (32)`, not 122 (so 404 mapping stays as today).
Non-root, no write access: matching assertion -> `Insufficient access (50)`; stale -> `Assertion
Failed (122)`. Authorization is therefore evaluated after the assertion on a stale tag: a caller without
write access learns only "stale" vs "denied" for an entry it can already read; no DN is in either message.

## (b) Non-root bind reads `entryCSN`, `entryUUID`, `creatorsName`

```
--- alice (non-root) reads bob, names given explicitly
dn: uid=bob,ou=people,dc=example,dc=org
entryUUID: e5a37acc-5570-1041-9458-c76ad85cdc75
creatorsName: cn=admin,dc=example,dc=org
entryCSN: 20261006012753.858701Z#000000#000#000000
--- alice reads bob with '*' only: no operational attributes (must be requested by name or '+')
--- alice, filter (&(uid=bob)(entryCSN>=2020...)) -> matches (entry returned)
--- anonymous, explicit names: entry returned but with NO entryCSN/entryUUID/creatorsName  (by anonymous none)
```

No ETag fallback is needed for authenticated binds. Anonymous cannot read them (the UI never binds
anonymously for these routes). Self-modify with a matching assertion by alice itself returned rc=0.

## (c) Which operations bump `entryCSN`

Measured on alice's (or the named entry's) `entryCSN` before/after:

| operation | `entryCSN` |
|---|---|
| plain read (admin `* +`, alice) | unchanged |
| attribute modify | CHANGED |
| password change via RFC 3062 (`ldappasswd`) | CHANGED (also sets `pwdChangedTime`) |
| FAILED bind (ppolicy writes `pwdFailureTime`) | CHANGED (each failure) |
| next SUCCESSFUL bind after failures (ppolicy clears `pwdFailureTime`) | CHANGED |
| successful bind with no pending failures, lastbind off (default) | unchanged |
| successful bind with `LDAP_LASTBIND_ENABLED=true` (`pwdLastSuccess` written) | CHANGED (separate container `l2-s2`) |
| user added to a group (memberOf overlay writes `memberOf` on the user) | unchanged (user); the group CHANGED |
| user removed from a group | user unchanged; group CHANGED |
| member entry deleted (refint removes it from the group's `member`) | group UNCHANGED, user unchanged (the `member` value is removed without a new CSN) |
| group description modify | member users unchanged |

A stale `If-Match` after a failed bind was observed directly: alice read `c`, a later
successful bind (clearing three `pwdFailureTime` values) bumped the CSN, and a self-modify asserting `c`
returned 122 even though no admin edit happened (false conflict, as D216-1 predicted; the reload
gives a fresh tag). Group membership edits never produce false conflicts on the *user* entry.

## (c2) AC-022 primitive: delete + recreate same DN, old identity assertion fails

```
orig uuid=0f9edc0e-5571-1041-945b-c76ad85cdc75 csn=20261006012904.292729Z#000000#000#000000
recreated uuid=0fbddea6-5571-1041-945c-c76ad85cdc75 csn=20261006012904.495958Z#000000#000#000000
ldapdelete -e '!assert=(&(entryUUID=<orig>)(entryCSN=<orig csn>))'  -> Assertion Failed (122)   (entry survives)
ldapdelete -e '!assert=(&(entryUUID=<new>)(entryCSN=<orig csn>))'   -> Assertion Failed (122)
ldapdelete -e '!assert=(&(entryUUID=<new>)(entryCSN=<new csn>))'    -> rc=0
```

Non-root compensation: a user with only `by self write` cannot delete its own entry
(`Insufficient access (50) additional info: no write access to parent`), so a compensating Delete needs
the same delete right the Add needed (the UI's admin bind); where that is missing the package's
`partial_failure` path applies.

## (d) go-ldap v3.4.14 (`go env GOMODCACHE`/github.com/go-ldap/ldap/v3@v3.4.14)

- `ModifyRequest.Controls` (`modify.go:58,96`, `NewModifyRequest(dn, controls)`), `DelRequest.Controls`
  (`del.go:14-34`, `NewDelRequest(dn, controls)`), `ModifyDNRequest.Controls`
  (`NewModifyDNWithControlsRequest`, `moddn.go:41-53`) are encoded by `encodeControls`.
- No assertion control type exists in the library (`grep 1.3.6.1.1.12 *.go` finds nothing). A local type
  implementing `ldap.Control` (`GetControlType`/`Encode`/`String`) works: `ControlString.Encode`
  (`control.go:228-239`) sends the value as a string, so the BER bytes of `ldap.CompileFilter`
  (`filter.go:77`) must be put into the OCTET STRING by a local `Encode`.
- `Conn.Add` (`add.go:70-100`) returns only `GetLDAPError(packet)` and drops response controls;
  `doRequest`/`readPacket` are unexported. Post-Read (RFC 4527) cannot be used, so the package's
  search-by-DN + `creatorsName` identity read after Add is the right design. (slapd itself advertises
  post-read, `1.3.6.1.1.13.2`.)
- `LDAPResultAssertionFailed = 122` (`error.go:82`).

Not run in this spike: single Add carrying `userPassword` (T-002 item 4, deferred by Q2), multi-provider
two-node behaviour (see the final live section).

## Part A implementation: live run through the real stack

Images built from this tree: `l2-ldap:1` (`docker build -t l2-ldap:1 -f image/Dockerfile ./image`) and
`l2-ui:1` (`docker build -t l2-ui:1 -f ui/Dockerfile ui`).

```
LDAPIUM_IMAGE=l2-ldap:1 LDAPIUM_UI_IMAGE=l2-ui:1 LDAPIUM_EDGE_PREFIX=l2-edge- \
  python3 scripts/test/test-api-edge-codes-local.py
ok: admin password absent from every /proc/*/environ and /proc/*/cmdline (names=0 hits=0 seen=2)
ok: conditional writes (ETag/If-Match on every protected route, stale 412 with no write,
    concurrent writers 1x204+1x412 x15, PATCH merge, create rollback, identity-bound delete 122)
PASS: unlock idempotent (204/404), ... conditional writes (If-Match/ETag/PATCH/create rollback)
```

The conditional section runs as a NON-root operator (`uid=ops,ou=admins`, `olcAccess {0}` write on the
tree with `by * break`), so the assertion is evaluated under ordinary ACLs, not the rootDN bypass.
It checks, through the UI backend: `etag` on list items and the `ETag` header of `GET /api/entry`
(no `entryCSN` or `etag` in the entry body); stale `If-Match` is 412 `revision_conflict` with no DN,
filter or `assert` text and the entry's ETag unchanged, for user PUT/PATCH/DELETE/lock/unlock, group
PUT/PATCH/DELETE, member add/remove and entry move (each also checked to have written nothing);
matching `If-Match` applies and moves the ETag on the same routes; malformed tags are 400 and `*` is
unconditional; two sessions racing the same ETag give exactly one 204 and one 412 in each of 15
rounds, and the stored value is the 204 winner's; PATCH keeps unmentioned fields while PUT still erases
them; a user create whose password step fails (see below) returns an envelope saying the user was not created, leaves no
entry (`GET /api/entry` 404) and the same uid can then be created; 10 rounds of delete + re-create of
the same DN each defeat the old `(&(entryUUID=..)(entryCSN=..))` assertion delete with LDAP 122 and the
re-created entry survives; an unknown critical control (`ldapmodify -e '!1.2.3.4.5.6.7.8'`) is refused
with 12 and writes nothing.

How the password step is forced to fail: the rootDN bypasses ppolicy and ppm, so a weak password for a
root-bound create is simply accepted (`ldappasswd -s Ab1` as `cn=admin` succeeded). For a non-root bind
this image's default policy (`pwdSafeModify: TRUE`) refuses to set an initial password at all:
`Insufficient access (50) Additional info: Must supply old password to be changed as well as new one`
(any password, including a strong one). That is the forced failure: Add succeeds, the Password Modify
fails (403), the identity-bound delete removes the entry, 403 `forbidden` envelope "user not created: ...".
Consequence worth knowing: with this default policy only a root-bound administrator can create users
with an initial password.

Non-vacuity (implementation deliberately broken, live and unit tests then fail; code restored after):

- `revisionControls` returning no controls (If-Match silently ignored), image `l2-ui:broken1`:
  `FAIL: AssertionError: user PUT with a stale If-Match: PUT /api/users expected 412, got 204`.
  Unit tests with the same break: `TestRevisionControlsEncoding`, `TestControlsRefuseMalformedValues`,
  `TestPatchModifyCarriesControls`, `FuzzRevisionControls` fail.
- compensation never deleting, image `l2-ui:broken2`: the forced-failure create returned a real
  `500 {"code":"partial_failure","state":"partial","dn":"uid=cw-new,...","retryable":false,...}` and the
  run failed at `forced password failure`, i.e. the orphan assertion is not vacuous.
- compensating delete without the assertion control (unit): `TestCreateOutcome/*` ("compensating delete
  must carry exactly the assertion control") and `TestCompensationAssertionBindsUUIDAndCSN` fail.

## Multi-provider (2 nodes, real run)

Two replicated nodes (`l2-r1`, `l2-r2`, `LDAP_REPLICATION_ENABLED=true`, same image), entry `uid=zoe`:

```
n1 tag after create: 20261006015308.274046Z#000000#001#000000
n2 holds the SAME entryCSN after replication: 20261006015308.274046Z#000000#001#000000
(1) tag read on n1, conditional write sent to n2: rc=0   -> new tag ...508088Z#000000#002#000000
    immediately write n1 with the OLD tag: rc=0           (replication lag: a stale tag passed)
(2) partition (docker network disconnect), both nodes hold Tx, conditional write on BOTH with Tx:
    n1 write rc=0, n2 write rc=0
    diverged: n1 desc='written-on-n1' csn=...150015Z#000000#001#000000
              n2 desc='written-on-n2' csn=...213167Z#000000#002#000000
    after heal (network reconnect): both nodes: desc='written-on-n2' csn=...213167Z#000000#002#000000
```

So the caveat of D216-1a is real: `entryCSN` replicates verbatim (a tag is valid on any node once
replicated), but the condition is node-local: inside the replication lag, or under a partition, two
writers holding the same tag both pass, and the earlier-timestamped write (`written-on-n1`) is silently
dropped by last-write-wins after the heal. Route writes to a single node to keep the guarantee.

## Not verified

- Wire-level proof that a stale IDENTITY assertion through go-ldap (the compensation's
  `(&(entryUUID=..)(entryCSN=..))` delete) answers 122: the `ldapdelete` primitive (above and live script)
  proves slapd's side, and the match path through go-ldap is proven live by the `rolled_back` runs; the
  mismatch path through go-ldap is covered by the decision-function unit tests, not by a real go-ldap
  Delete against a mismatching entry.
- `partial_failure` produced by the product code path with a genuinely refused or stale compensation
  (only the deliberately broken `broken2` image reached it live); the ACL cannot distinguish add from
  delete rights (both need write on the parent's children), so a refused delete cannot be staged here.
- Browser UI (no frontend change in Part A), ppolicy `lastbind` + If-Match end to end, SSO mode.

## Review follow-up (identity guard)

- Verified in the module source: `ldap.PasswordModifyRequest` has only `UserIdentity`, `OldPassword`,
  `NewPassword`; `appendTo` writes no controls (`passwdmodify.go:13-55`), so the password step cannot be made
  conditional. The window between the identity check and the Password Modify is residual.
- Decision-function tests cover each mismatch: other modifier, same-second modify by another administrator,
  later-second modify, unreadable modifier/timestamps, other creator, replaced entry, read failure; plus
  lost delete response (`unknown`) versus a server refusal (`partial`). A real second-administrator edit
  between Add and the read was NOT staged live (no seam in the production path; no new hook was added for
  it). The positive path is live: the unchanged entry's attributes satisfy the check on real slapd
  (the forced-failure create still rolls back after this change).
- The refint limitation is pinned by the live script (section 6b): the group's ETag does not move when refint
  removes a deleted member.

## Where Part A differs from the package text

- Scope: only the conditional-write half (revision/ETag, If-Match, PATCH, create compensation, docs, tests).
  Idempotency keys, their switch, the persisted fingerprint key, `idempotency_*` codes, the chart changes
  and the frontend (T-014, T-016, T-018, T-019, T-024) are Part B / follow-ups.
- The revision condition travels as a trailing `ifMatch string` argument (bare CSN, "" = unconditional) on
  the `ldapclient.Client` write methods; `PatchUser`/`PatchGroup` are new methods.
- Errors use the #218 envelope (rebased onto #234): a stale tag is `domain.ErrRevisionConflict`, mapped by
  `domainStatus` to 412 `revision_conflict`; `partial_failure` (500) is a new registry code and the one
  envelope with the extra `state` and `dn` keys (states `partial`, `unknown`, `identity_changed`), with the
  registry's static 5xx text. A rolled-back create is NOT a separate `state`: it is a plain envelope
  (400/403/500 by cause, text starting "user not created", diagnostics through the D218-15 allowlist), so the
  package's `state: rolled_back` key does not exist. Logs use `logQuote`/`logDetail`.
- Spike corrections to D216-1: a successful bind that clears earlier `pwdFailureTime` values also bumps
  `entryCSN` (not only the failed bind), and `LDAP_LASTBIND_ENABLED=true` bumps it on every successful
  bind; memberOf maintenance and refint's removal of a deleted member do NOT bump the affected entries'
  `entryCSN`.
- AC-007 cannot use a ppm-rejected password: the rootDN bypasses ppolicy/ppm. The failure is forced with a
  non-root bind (`pwdSafeModify` refuses an initial password), see above.
- go-ldap encodes criticality TRUE as `0x01` (BER allows any non-zero); slapd honours it (unknown critical
  control gives 12).

## Part B: Idempotency-Key, live run through the real stack

Images built from this tree: `l7-ldap:1` (`docker build -t l7-ldap:1 -f image/Dockerfile ./image`) and `l7-ui:1`
(`docker build -t l7-ui:1 --target backup-runtime -f ui/Dockerfile ui`); docker context `colima`, named volumes,
objects prefixed `l7-` and removed afterwards.

```
python3 scripts/test/test-api-idempotency-local.py
PASS: server-settings reports idempotencyEnabled=true
PASS: create replay: same 201 body, Idempotent-Replayed only on the replay
PASS: create replay wrote nothing a second time (1 entry, entryCSN unchanged)
PASS: without a key the same create is today's 409 already_exists
PASS: same key, different body: 422 idempotency_key_reused
PASS: the rejected reuse wrote nothing
PASS: lock applied / another administrator unlocked
PASS: retrying the lock with the same key is replayed and does NOT re-lock
PASS: delete replay: 204 replayed, entry gone
PASS: without a key the delete retry is today's 404
PASS: concurrent same-key creates: one execution (1 original, 9 conflict/replay), 1 entry
PASS: password with a key: replay body is {} (no secret)
PASS: generated password + key is refused (422 validation_failed)
PASS: backup start with a key: 202
PASS: backup start replay while the job exists: same job id and Location
PASS: same backup key for another kind: 422 idempotency_key_reused
PASS: one backup job record for three start requests
PASS: key file is 0600 in a 0700 directory (700 ldapium / 600 ldapium)
PASS: job file holds key hash/fingerprint/key_id only (no key, no DN)
PASS: UI log does not contain a key/password (8 checks)
PASS: after a restart the in-memory core record is gone ... 409 already_exists (documented limit)
PASS: after a restart the same backup key returns the same job id (status succeeded)
PASS: still exactly one job record after the restart
PASS: switch off: keyed write is 422 idempotency_unsupported and writes nothing
PASS: switch off: server-settings reports false / the same write without a key is unchanged (201)
PASS: idempotency live run
```

Non-vacuity (code deliberately broken, tests fail, code restored): the store ignoring existing records
(`Begin` never finds a record) fails 8 `internal/idempotency` tests and `TestIdempotency_ReplayDoesNotWriteTwice`
(`replay: 204 replayed=""`); the fingerprint comparison forced to "same" fails `TestSameKeyDifferentRequestIsReused`,
`TestKeyringRotationVerifiesPreviousKeyID`, `TestIdempotency_DifferentRequestSameKeyIs422AndDoesNotWrite`
(`status 204`) and `TestBackupStartKeyScopeAndConflicts` (`other kind: 202`).

Not verified: browser UI (no frontend change); a real LDAP connection drop in the middle of a write
(`outcome_unknown` is proven with an injected go-ldap `ErrorNetwork` and a panic, not on a live socket);
a multi-replica deployment; helm install against a cluster (only `helm template` and `--dry-run=client`).

Review follow-up (Codex high): the lost-response classifier, strict keyed bodies and the oversized
`partial_failure` record are covered by `idempotency_review_test.go` with the real go-ldap error shape (a `net.Pipe`
peer that reads the request and closes). Key persistence, stated exactly: only backup-start keys live in the durable job
record and survive a backend restart; the keys of every other route are process memory and are forgotten on restart
(the live script checks both: the core retry after a restart meets 409 already_exists, the backup retry returns the same job).
