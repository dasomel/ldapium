#!/usr/bin/env bash
# Operator check of the machine WRITE ACL (#285, T-023, REQ-011, D11/D17/D18/D26, Resolved Q6).
# Read only: reads the main database olcAccess and exits non-zero on ANY failure; there is
# no path that prints a pass without having parsed a real, complete rule list.
#
# It verifies the order defined by docs/machine-write-account.md section 2:
#   {0}                 replication identity rule (when present; --replication-identity required
#                       makes it mandatory, as under LDAP_REPLICATION_IDENTITY=prepare/dedicated)
#   next 3              the M read rules
#   next 9 / 6          the W_data / W_lock rules (either order), contiguous, each rule exactly the
#                       fragment's text and ending "by * break", naming only its own identity
#   then                the image's own rules (nothing of W may come after them)
# and: no duplicate fragment (applied twice), no rule for W_cred, the secret/pwd*/memberOf
# attributes are "none" for W (evaluated through the whole list), the cn=replicator deny rule and
# the SYSTEM_DN backstop are in place, and no W identity can reach M, the replication identity,
# the admin entry or each other (static first-match evaluation of the rules).
#
# Usage:
#   scripts/check-machine-write-acl.sh [SOURCE] --root-dn DN --machine-dn DN --system-dn DN \
#     --write-dn DN (--wdata-dn DN | --wlock-dn DN | both) [options]
#   SOURCE (default: local `slapcat -n 0 -F /etc/openldap/slapd.d`; --config-dir DIR changes it)
#     --container NAME       docker exec NAME slapcat -n 0
#     --kube-pod POD [-n NAMESPACE] [--kube-container C]    kubectl exec POD -- slapcat -n 0
#     --input FILE|-         an LDIF dump of the main database entry (offline / fixture)
#   options: --allowed-dn DN (M read base, default --root-dn)   --repl-dn DN (default
#     cn=replicator,<root>)   --admin-dn DN (repeatable; default cn=admin,<root>)
#     --wcred-dn DN (repeatable; no rule may name it)   --protected-dn DN (repeatable)
#     --replication-identity auto|required   --main-db-dn DN (default olcDatabase={1}mdb,cn=config)
#   v2c (guide section 8, #379 T-021): ONE --wcred-dn plus --cred-dn DN --pending-policy-dn DN and
#     --privileged-group DN (repeatable, installed order) expects instead: olcAddContentAcl TRUE, the
#     W_data v2c rules (write-data-cred.ldif) right after W_data's two backstops, and the 7 W_cred
#     rules (write-cred.ldif) as a further contiguous fragment; filter= and val= are compared.
#
# Output: PASS/FAIL lines, then ONE machine-readable summary line
#   RESULT status=pass|fail|error checks=N failed=M rules=R
# Exit: 0 all checks passed, 1 a check failed, 2 usage, 3 the olcAccess could not be read or
# parsed (slapcat failed, empty output, no main database entry): never a pass.
# slapcat output holds no secret used here; only the olcAccess rules are printed, and nothing
# is read from argv besides DNs. Run it on EVERY node: cn=config ACLs are per node.
set -euo pipefail
exec python3 "$(dirname "$0")/lib/machine_write_acl_check.py" "$@"
