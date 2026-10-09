
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
