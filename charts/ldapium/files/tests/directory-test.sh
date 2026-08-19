#!/bin/sh
# `helm test` for an ldapium release: does the deployed directory
# actually answer, and do the overlays the chart claims to enable actually
# work?
#
# This lives in the chart, not in the image. The server image ships a
# directory server and nothing else — no test fixtures, no test data, no test
# runner — so what gets tested and whether it runs at all is the operator's
# decision at install time, not a property baked into the artifact. The image
# is only reused here as an LDAP *client*, the same way the backup CronJob
# reuses it: ldapsearch and friends are already in it, so a test needs no
# second image and no extra supply chain.
#
# Environment (set by the chart):
#   LDAP_URL, LDAP_ROOT_DN, LDAP_ADMIN_DN   as for the backup CronJob
#   PASSWORD_FILE                            admin password, mounted 0400
#   TEST_WRITE                               1 to exercise the write path
#   REPLICA_URLS                             space-separated per-pod URLs,
#                                            empty when not replicated
#   TIMEOUT_SECONDS                          per-wait budget
#
# The password is read with -y from a file, never -w, so it never appears in
# the process list. Same reasoning as the backup job.
set -eu

: "${LDAP_URL:?}" "${LDAP_ROOT_DN:?}" "${LDAP_ADMIN_DN:?}" "${PASSWORD_FILE:?}"
TEST_WRITE="${TEST_WRITE:-1}"
REPLICA_URLS="${REPLICA_URLS:-}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-60}"

# A fixed DN, not a random one: a pod that is killed mid-run leaves entries
# behind, and a fixed name means the next run cleans them up instead of
# accumulating one orphan subtree per failed test.
TEST_OU="ou=helm-test,${LDAP_ROOT_DN}"
TEST_USER="uid=helm-test-user,${TEST_OU}"
TEST_GROUP="cn=helm-test-group,${TEST_OU}"

failures=0
log() { printf '[test] %s\n' "$*"; }
pass() { printf '[test]   PASS  %s\n' "$*"; }
fail() {
	printf '[test]   FAIL  %s\n' "$*"
	failures=$((failures + 1))
}

search() {
	url="$1"
	shift
	ldapsearch -x -LLL -o nettimeout=10 -H "$url" \
		-D "$LDAP_ADMIN_DN" -y "$PASSWORD_FILE" "$@"
}

# ---------------------------------------------------------------- reachable
log "waiting for $LDAP_URL (up to ${TIMEOUT_SECONDS}s)"
waited=0
until ldapsearch -x -o nettimeout=5 -H "$LDAP_URL" -b "" -s base namingContexts >/dev/null 2>&1; do
	waited=$((waited + 2))
	if [ "$waited" -ge "$TIMEOUT_SECONDS" ]; then
		fail "server did not answer within ${TIMEOUT_SECONDS}s"
		exit 1
	fi
	sleep 2
done
pass "server answers an anonymous root DSE search"

# ------------------------------------------------------------------- bind
whoami=$(ldapwhoami -x -o nettimeout=10 -H "$LDAP_URL" \
	-D "$LDAP_ADMIN_DN" -y "$PASSWORD_FILE" 2>&1) || whoami="(bind failed: $whoami)"
case "$whoami" in
dn:*"$LDAP_ADMIN_DN") pass "admin bind returns $whoami" ;;
*) fail "admin bind: expected dn:$LDAP_ADMIN_DN, got $whoami" ;;
esac

# --------------------------------------------------------------- base DIT
if search "$LDAP_URL" -b "$LDAP_ROOT_DN" -s base dn >/dev/null 2>&1; then
	pass "base DN $LDAP_ROOT_DN exists"
else
	fail "base DN $LDAP_ROOT_DN is missing — bootstrap did not complete"
fi

# ------------------------------------------------------------- write path
if [ "$TEST_WRITE" = "1" ]; then
	cleanup() {
		# Children first: the directory refuses to delete a non-leaf entry.
		for dn in "$TEST_USER" "$TEST_GROUP" "$TEST_OU"; do
			ldapdelete -x -o nettimeout=10 -H "$LDAP_URL" \
				-D "$LDAP_ADMIN_DN" -y "$PASSWORD_FILE" "$dn" >/dev/null 2>&1 || true
		done
	}
	# Also runs up front, in case an earlier run died before its own cleanup.
	cleanup
	trap cleanup EXIT INT TERM

	# No userPassword on the test user on purpose: with ppolicy enabled a
	# password would be subject to quality/history rules, and a policy
	# rejection would look like a write failure when it is the policy doing
	# its job. Group membership is what this checks.
	if ldapadd -x -o nettimeout=10 -H "$LDAP_URL" \
		-D "$LDAP_ADMIN_DN" -y "$PASSWORD_FILE" >/dev/null 2>&1 <<-LDIF
			dn: ${TEST_OU}
			objectClass: organizationalUnit
			ou: helm-test

			dn: ${TEST_USER}
			objectClass: inetOrgPerson
			uid: helm-test-user
			cn: helm test user
			sn: user

			dn: ${TEST_GROUP}
			objectClass: groupOfNames
			cn: helm-test-group
			member: ${TEST_USER}
		LDIF
	then
		pass "created a scratch OU, user and group under $TEST_OU"
	else
		fail "could not write to $TEST_OU — admin bind cannot create entries"
	fi

	# The point of this check: memberOf is maintained by an overlay, so it is
	# populated only if the overlay is really loaded on the running server.
	# The chart advertises memberof; nothing else here would notice if the
	# module failed to load and slapd carried on without it.
	if search "$LDAP_URL" -b "$TEST_USER" -s base memberOf 2>/dev/null |
		grep -qi "^memberOf: ${TEST_GROUP}$"; then
		pass "memberof overlay populated memberOf on the test user"
	else
		fail "memberOf was not populated — the memberof overlay is not active"
	fi

	# ------------------------------------------------------- replication
	for replica in $REPLICA_URLS; do
		[ "$replica" = "$LDAP_URL" ] && continue
		waited=0
		converged=0
		while [ "$waited" -lt "$TIMEOUT_SECONDS" ]; do
			if search "$replica" -b "$TEST_USER" -s base dn >/dev/null 2>&1; then
				converged=1
				break
			fi
			waited=$((waited + 2))
			sleep 2
		done
		if [ "$converged" = "1" ]; then
			pass "entry replicated to $replica in under ${waited}s"
		else
			fail "entry never reached $replica (waited ${TIMEOUT_SECONDS}s)"
		fi
	done
else
	log "write checks disabled (tests.write=false) — read-only run"
fi

log "----------------------------------------"
if [ "$failures" -ne 0 ]; then
	log "$failures check(s) failed"
	exit 1
fi
log "all checks passed"
