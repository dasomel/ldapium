# EVIDENCE: T-021 live write-ACL proof (#285)

Recorded 2026-10-11 from `scripts/test/test-machine-write-acl-live.py` on an image built from this branch
(`docker build -t ldapium:l285v -f image/Dockerfile ./image`, main at 3489d49). No operation is opened, no Go or chart change.
Every write in the proof is a direct `ldapmodify`/`ldapadd`/`ldapdelete`/`ldapmodrdn` as the LDAP identity (the app guard is bypassed).

## Result (real output tail)

```text
$ LDAPIUM_IMAGE=ldapium:l285v python3 scripts/test/test-machine-write-acl-live.py
...
PASS: [p1] root-wide ... but never its userPassword (50)
PASS: [p1] rolled back again: byte for byte the state before the write fragments
RESULT: 1456 checks passed, 0 failed, mutation=none, 110s
```

Checks per configuration: n0 348, n1 348, p0 357, p1 357 (n = no replication identity, p = `LDAP_REPLICATION_IDENTITY=prepare`;
0 = `LDAP_ANONYMOUS_READ_BASE` unset, 1 = set to the managed subtree), plus 5 guide/fixture checks. 40 of the checks are tagged `KNOWN-LIMIT`.
`dedicated` was NOT run (needs mutual TLS CA material and peers; `prepare` produces the same `{0}` rule, which is what the layout depends on).
The v1 proof, run unchanged on the same image: `RESULT: 461 checks passed, 0 failed` (`test-machine-acl-readonly-live.py`).

## What is proven (per configuration)

- Layout, exact text and index, read back from `cn=config` after each step: `[replication {0}] M x3, W_data x8, W_lock x6, image rules unchanged and in order`.
  n: M `{0}-{2}`, W_data `{3}-{10}`, W_lock `{11}-{16}`; p: M `{1}-{3}`, W_data `{4}-{11}`, W_lock `{12}-{17}` (guide 4.2 printed `BASE=3/11` resp. `BASE=4/12`).
  Second W_data apply refused by the guide itself; every rule naming a W DN names only it and ends in `by * break`; `prepare` keeps `{0}` over a restart.
- Existing identities, same result before and after the write fragments: admin (read, userPassword read, write), anonymous (4 probes), the human
  user (reads, writes other/self/own mail, own password change), M (reads, outside, writes), and in `p` the replication identity (hash read over TLS,
  cleartext refused 32, write 50).
- W_data allowed: add a user with the closed attributes, replace cn/sn/givenName/mail/departmentNumber/o/ou each, add/remove a `uid` value, delete/re-add `mail`,
  group `member` add/remove, delete a leaf. Each result re-read as the admin.
- W_data refused (50): 25 attributes outside the list (plus group description/owner), objectClass replace and value delete, `userPassword` (delete-old+add-new, and add), DELETE of the 8 secret attributes and
  pwdAccountLockedTime/pwdReset/pwdPolicySubentry/pwdStartTime/pwdEndTime, REPLACE/ADD of shadowLastChange, oath*, pwd*; reads of every secret, `pwd*`, `memberOf`
  return nothing (explicit, `*`+`+`, filter `(attr=*)`), nothing readable outside the subtree.
  Refused by the SCHEMA (19), ACL not reached (not an ACL proof): `memberOf`, `pwdHistory`, `pwdChangedTime`, `pwdFailureTime`, `pwdGraceUseTime`, `pwdLastSuccess` (NO-USER-MODIFICATION).
- W_lock: set/clear `pwdAccountLockedTime` only; 50 for every data attribute, objectClass (also value add), entry add/delete/rename/move, member add, secrets, other `pwd*`;
  reads the lock attribute (finds the locked user by filter) but no secret; cannot lock anything outside the subtree, M, W_data, itself, admin, root; no cn=config.
- Outside the ceiling (direct, W_data and W_lock): entries/adds/deletes/modrdn in ou=other, ou=system (M, W_*), root, admin, cn=config, moving an entry out of the subtree: all 50.
- M: all 25 direct write shapes (add/modify/delete/modrdn/move/objectClass/lock attribute/group member/own password and entry/cn=config) 50 on the combined layout;
  the v1 read facts re-asserted (reads exactly B; 8 secrets x explicit/`*`/`+`/filter never returned; nothing outside B or in cn=config).
- Rollback: refuses a not-installed fragment, byte-for-byte restore (`n`: W_lock then W_data, `p`: W_data then W_lock; intermediate layouts asserted), W_data then an ordinary user, M still read-only.
- Write subtree widened to the root: the `SYSTEM_DN` deny keeps M/W_data/W_lock entries and `ou=system` at 50, the `REPL_DN` deny keeps the replication identity entry
  unmodifiable/undeletable (`p`) and the reserved `cn=replicator` entry uncreatable (`n`); rolled back byte for byte again.

## What ONLY the app guard protects (asserted as limits, so a silent ACL change is noticed)

ModifyDN rename and cross-container move; objectClass VALUE add (extensibleObject; its removal is refused, the admin must undo it); entry creation with any objectClass
(a `groupOfNames` with `member=<admin DN>`); creating a container directly under the subtree base; modifying the subtree base entry itself; modifying any user of the union
subtree (protected DNs, humans); cross-client isolation (people and groups both writable by the one W_data DN); W_lock locking any user; with a root-wide `WRITE_DN`,
the `cn=admin` entry directly under the root takes the closed attributes (never `userPassword`): protected identities belong under `SYSTEM_DN`.

## Mutation results (`LDAPIUM_WACL_MUTATE`, configurations n0 and p0)

| Mutation | Result | Behavioral failures (beyond layout/index checks) |
|---|---|---|
| `loosen-secrets` ({2} `none`->`write`) | rc 1, 112 failed | 104; e.g. `userPassword delete-old + add-new refused (50)`, every secret/pwd* DELETE (rc 0) |
| `loosen-objectclass` ({4} `add`->`write`) | rc 1, 14 failed | 6; `objectClass REPLACE refused (50)`, `objectClass value DELETE refused (50)` |
| `reorder` (W fragments after the image rules) | rc 1, 233 failed | 218; W_data cannot even add or replace (image `by users read` wins) |
| `drop-replicator-deny` ({1} removed) | rc 1, 18 failed | 5; `backstop REPL_DN: cannot CREATE cn=replicator (n)`, `modify/delete/lock the replication identity (p)` |

CI wiring runs each mutation on n0 and requires rc 1, no `ERROR`, and a `RESULT` with at least one failure (verified locally by extracting that step from the workflow):
`RESULT: 312 checks passed, 56 failed, mutation=loosen-secrets` / `357 passed, 7 failed, mutation=loosen-objectclass` / `248 passed, 116 failed, mutation=reorder` / `357 passed, 7 failed, mutation=drop-replicator-deny`.

## Not verified

`dedicated` replication identity; a multi-node cluster (olcAccess is per node by design); ACL behaviour of operations the app does not yet expose; the app guard itself (T-012/T-018/T-019 own that).
