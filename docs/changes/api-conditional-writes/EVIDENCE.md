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
