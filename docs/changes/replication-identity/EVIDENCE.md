
## T-013 reconcile credential primitive

Command: `scripts/test/test-replication-identity-reconcile.sh ldapium:revocation-review`.
Result: `ALL PASS: real verified TLS, add, repeat, old credential, bytes, missing entry`.
The current file initially fails an actual identity bind with LDAP 49. Reconcile adds
an SSHA hash using file input, verifies the current TLS bind, preserves the prior
credential, and leaves the hash count unchanged on repeat. The test rejects clear
LDAP, disabled certificate verification, LF/NUL input and a missing identity. A
credential ending with an ASCII space is refused, matching dedicated entrypoint
hygiene (0x21–0x7e).
A temporary CA/server certificate and named volume avoid Colima file UID mapping.

This evidence covers the online credential primitive. Peer isolation and restored
backup orchestration, post-reconcile ACL/content checks, multi-node recovery,
rotation and rollback-admin remain unverified here. It does not complete T-013,
T-021 or package acceptance. Log: `/tmp/ldapium-229-reconcile.log` (local run).

## D63 restore / current credential primitive

Command: `scripts/test/test-replication-identity-restore.sh ldapium:revocation-review`.
Result: `ALL PASS: real backup, total populated-volume loss, restore, 49 control,
reconcile, dedicated peer refill`. A temporary verified-TLS source is bootstrapped
as admin, switched to prepare, then ensure creates the reserved identity. A normal
inetOrgPerson/password fixture is added, real backup.sh exports data/config with
manifest verification, and both populated volumes are deleted with peers absent.
Real offline restore.sh restores those volumes. Dedicated startup with a different
current credential produces LDAP49 (control), then reconcile proves TLS identity
bind success. Two fresh dedicated peers refill from the restored node. All three
preserve the suffix UUID, match a normalized explicit-data/password/entryUUID digest,
and bind with the current TLS identity credential.

This is source-only backup/total populated-volume loss evidence, not a complete
pre-loss three-node scenario, automated peer-isolation procedure, actual rolling
rotate command, or complete G1/G2/canary acceptance. Restore still requires operator
checks before peers start. The temporary fixture starts peers after bind/UUID checks
only to measure refill; it is not the production recovery runbook.

The live path exposed backup.sh returning exit 1 after successful file-password
backup because its EXIT cleanup ended with a false conditional. The conditional is
now an explicit if: same cleanup behavior, successful backup exit 0. The restore
fixture asserts the real command exits successfully. Log:
`/tmp/ldapium-229-restore.log`; disposable fixture credential scan: zero occurrences.

## T-020..T-024 unified verification set (#353)

Environment: macOS/Colima, Docker 29.8.2, image `ldapium:e2e` built from this branch (OpenLDAP 2.6.15), kind v1.37 with
the chart for the Kubernetes script. Every check is live against real slapd and the real entrypoint, operator command
and check script; nothing is mocked. Passwords never reach a log or output (the unified script scans the command output
and the node logs of the final `cluster` scenario for the administrator, wrong and both identity credentials: 0 occurrences).

| Command | Result | Runtime |
|---|---|---|
| `scripts/test/test-replication-identity.sh ldapium:e2e` (all parts) | `ALL PASS`, 94 checks | 3 min 14 s |
| `RIDU_ONLY=chaos scripts/test/test-replication-identity.sh ldapium:e2e` | `ALL PASS` (setup + chaos) | ~1 min |
| `scripts/test/test-replication-identity-k8s.sh ldapium:e2e` (kind) | `ALL PASS`, 15 checks | 2 min 11 s |

CI placement: `e2e.yml` runs parts `cluster`, `pair`, `proxy` (~2.5 min); `replication-chaos-e2e.yml` job
`replication-identity-dedicated` (image `ldapium:chaos`) runs part `chaos` and the Kubernetes script (~4 min).

### E1-E17 assertion table

`test-replication-identity.sh` prints the same table; "unified" = that script, the others are the sibling tests.

| E | Live check | Notes |
|---|---|---|
| E1 | unified `pair`: a dedicated consumer of a provider without the ACL receives the entry but no `userPassword`; contextCSN set and user count are identical; the check fails with "stable entry comparisons differ"; repair = `retire`, `prepare`, `ensure`, wipe the damaged consumer | `prepare` alone does not repair it (documented) |
| E2 | unified `cluster`: real `ensure` entry; `description`, `pwdEndTime`, `pwdAccountLockedTime`, `pwdPolicySubentry`, own password (also with `pwdAllowUserChange TRUE`), delete self, add, other entry: 50; `cn=config` 32; `cn=accesslog` unreadable; plaintext reads nothing; ordinary users unchanged | + `-prepare.sh` Part 3 |
| E3 | unified `cluster`: 12 wrong binds then the right bind, no `pwdAccountLockedTime`: (1) existing volume, (2) `LDAP_PASSWORD_POLICY_ENABLED=false` restart, (3) hardened default policy, (4) first bootstrap with the policy disabled, (5) during rotation; controls: an ordinary user locks under (3), the identity locks with `pwdLockout TRUE` | |
| E4 | `-prepare.sh` (ssf, plaintext), `-dedicated.sh` (rogue CA and host name at runtime) | not repeated |
| E5 | unified `cluster`: `LDAP_SIZE_LIMIT=5`, 14 users: identity reads all, an ordinary user is cut (rc 4), wiped node resyncs 14/14, removing `olcLimits` makes the identity hit the limit | |
| E6, E7 | `-dedicated.sh` (wrong password: err=49, nothing written), `-rotate.sh` (R0-R4, premature removal); unified: R0 gate (3), rolling restart, removal | |
| E8 | unified `pair`: admin mode, sid 1 wiped, wrong `LDAP_REPLICATION_PASSWORD`: the peer's users 3 -> 0 (contrast); dedicated is the fix (`-dedicated.sh` Part 2) | asserts the CURRENT admin-mode behavior; update when admin mode is hardened |
| E9, E12 | `-dedicated.sh` Part 2; unified `chaos`: hard kill, partition with writes on both sides (control: the split is real), strict check after healing, no err=49; Kubernetes K1/K2 | |
| E10 | unified: mixed modes (n2 admin, n1/n3 dedicated), `rollback-admin` gate, all nodes back to `admin`, equal hashes; `-rollback-admin.sh`; `pair` (prepare provider + dedicated consumer) | |
| E11 | unified: five checks under ~3 writes/s on other entries, no false failure; contrast (all-attribute comparison changes on an unchanged entry, enumerated set does not); defects (a) denied hash -> 1, (b) size limit without `olcLimits` -> 2, (c) wrong credential file -> 1, (d) consumers old while the new value is valid -> 1; documented limit: a non-enumerated attribute is not caught (0) | |
| E13 | unified: client certificate with subject `CN=replicator,DC=example,DC=org` signed by the CA, `-Y EXTERNAL` over ldaps: rc 7 (mechanism not supported), no hash; controls: ldapi EXTERNAL works, simple bind of the identity with that certificate works; no client-authenticating `olcTLSVerifyClient`; stored regexp/verify refusals in `-dedicated.sh` Part 3 | |
| E14 | `-prepare.sh` Part 4 | |
| E15 | not applicable: SASL EXTERNAL consumer is a follow-up package (D57) | |
| E16 | `-dedicated.sh` (err=49); unified `chaos` (none while healthy); K2 | |
| E17 | unified `cluster`: proxy authorization refused (123) by default; SASL DIGEST-MD5, CRAM-MD5, PLAIN as `replicator` never yield the identity. unified `proxy`: policy `to` alone refused, policy `to` + `authzTo` lets an ordinary user read a hash as the identity (contrast), the configuration check refuses it, `prepare` and `dedicated` refuse to start, and start again once removed | |

### Kubernetes / StatefulSet (T-024)

`test-replication-identity-k8s.sh`: chart 3 replicas (OrderedReady) with verified TLS, `helm upgrade` admin -> prepare ->
operator `ensure` -> dedicated; K1 deleted pod-0 returns Ready while 1 and 2 serve; K2 all pods deleted at once, pod-0
starts alone and becomes Ready without peers, all pods recover with identical users and hash, no err=49; K3 data claim
of pod-1 lost with its config claim kept: see below.

### Finding: data volume lost, config volume kept (AC-004)

The image refuses the configuration (`olcDbDirectory: invalid path`, `slapcat: bad configuration directory`) and exits 1 in
every mode (checked by hand in `admin` too). Under Kubernetes the pod crash-loops (K3) without creating anything: the
peers are byte-identical afterwards. Recovery is to delete BOTH claims; the node refills from the peers (Docker: unified
`chaos`; Kubernetes: K3). `dedicated` words the refusal as "stored olcSyncrepl makes cn=config unreadable ... refusing to
start", which misleads (the cause is the missing database directory). Not fixed here (scope); suggest a follow-up issue
for the message and an operator note in `docs/migration.md`/the runbook.

### Accepted gaps (each AC has a committed live check or one of these)

| AC | Gap | Concrete reason |
|---|---|---|
| AC-005 case 4 | rollback of a rotation is guidance text only | no rollback command exists (`rotate` prints the steps); `-rotate.sh` asserts the text |
| AC-006 | omitted-attribute defects are not detected | by design (D59); the limit is asserted (unified E11), the documentation part is T-030 |
| AC-010 | a live SASL bind through a configured `olcAuthIDRewrite` | `prepare`/`dedicated` refuse that configuration before slapd starts and the hash-only identity has no cleartext secret for DIGEST-MD5; the refusal is tested (`-dedicated.sh`, `-prepare.sh`), the mechanisms are shown unable to reach the identity |
| AC-011 a | `admin`/`prepare` + `LDAP_REPLICATION_PASSWORD` is not refused | maintainer decision (T-010 deferral): it would break the documented custom `LDAP_REPLICATION_BIND_DN` use; the unified `pair` part shows the resulting data loss (E8) |
| T-023 | refusing a switch toward a provider without the ACL | a consumer cannot see a peer's ACL; the check detects the loss (E1) instead |
| Kubernetes | rotation, `rollback-admin`, backup CronJob and NetworkPolicy under the chart | the Docker tests cover the commands; the chart paths for them were not exercised on kind |
| E15 | SASL EXTERNAL consumer | follow-up package, nothing to test |

T-015 (D43 relaxation) stays gated: not implemented. It may start only once this set is green in CI.
