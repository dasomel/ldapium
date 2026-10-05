# Change: wiped multi-provider node must not make peers delete entries

- Change class: `D` (replication / data safety)
- Related issue: #206
- Status: `Done` — implemented in #226 (164fad4) and verified in CI (`e2e.yml`, job "migration dry-run (live image validation)": `test-wiped-node-resync.sh` and `test-bootstrap-seed.sh`, green on #228). Acceptance was recorded after the merge: the maintainer instructed on 2026-10-06 to process and close #206.

## Problem

Wiping the volumes of a multi-provider node and restarting it could delete
entries on BOTH nodes (observed: every entry whose entryCSN carries the wiped
node's own serverID; entries of other sids survived). Racy: ~2 of 3 runs.

## Root cause (controlled experiment, not the suspected cause)

The suspected cause in #206 (local `cn=default,ou=policies` write) is refuted:
with a peer holding the base DIT, `slapadd -n 1` (which contains the policy
entry) is skipped, so nothing is written locally. The real cause:

1. Section 4 of `entrypoint.sh` applied `olcSyncrepl` through a *temporary
   slapd*, whose consumer immediately started pulling, then SIGTERMed it.
   In the failing runs the refresh was cut after `dc=...` and `cn=admin`
   arrived but before any contextCSN was stored.
2. The real slapd then opened a non-empty DB with no contextCSN;
   `syncprov_db_open` (syncprov.c ~4133) logged
   `generated a new ctxcsn=<now>#001` for its own sid, newer than the peer's
   sid-1 entries.
3. Consumer side: peer entries with sid=1 are "not new enough, ignored";
   provider side: the peer's consumer receives a present list lacking them
   and deletes them.

## Fix

Edit cn=config offline (`slapmodify`/`slapadd`/`slapcat -n 0`) in section 4;
no temporary slapd, so a wiped node reaches the real slapd with a completely
empty database. First-ever bootstrap, #203/#204 seed and marker semantics and
the peer-unreachable path are unchanged.

## Verification

- `scripts/test/test-wiped-node-resync.sh` (wired into `e2e.yml`): before fix
  fails (2 of 3 runs), after fix passes (4 of 4).
- `scripts/test/test-bootstrap-seed.sh`: passes.

## Not covered

Wiping a serverID>=2 node uses the same code path but is not tested;
k8s/helm path not run.
