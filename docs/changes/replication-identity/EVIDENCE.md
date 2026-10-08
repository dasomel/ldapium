
## T-013 reconcile credential primitive

Command: `scripts/test/test-replication-identity-reconcile.sh ldapium:revocation-review`.
Result: `ALL PASS: real verified TLS, add, repeat, old credential, bytes, missing entry`.
The current file initially fails an actual identity bind with LDAP 49. Reconcile adds
an SSHA hash using file input, verifies the current TLS bind, preserves the prior
credential, and leaves the hash count unchanged on repeat. The test rejects clear
LDAP, disabled certificate verification, LF/NUL input and a missing identity. A
credential ending with an ASCII space is preserved exactly and binds successfully.
A temporary CA/server certificate and named volume avoid Colima file UID mapping.

This evidence covers the online credential primitive. Peer isolation and restored
backup orchestration, post-reconcile ACL/content checks, multi-node recovery,
rotation and rollback-admin remain unverified here. It does not complete T-013,
T-021 or package acceptance. Log: `/tmp/ldapium-229-reconcile.log` (local run).
