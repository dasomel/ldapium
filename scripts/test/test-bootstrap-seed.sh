#!/usr/bin/env bash
# Live regression test for issue #203 (fixed in #204): image/entrypoint.sh
# must apply LDAP_SEED_DIR LDIFs inside the FIRST bootstrap, BEFORE the
# bootstrap marker is written, under the rollback trap, and only on the node
# that created the base DIT (LOAD_BASE_DIT=1). Replicas must skip seeding
# and let syncrepl supply the data instead. This drives the real entrypoint
# against live containers; it is not a fixture-only unit test.
#
# Cases:
#   1. A seed LDIF that violates the schema must fail bootstrap on every
#      (re)start — never silently mark the directory "bootstrapped" with a
#      half-applied seed.
#   2. A valid seed LDIF is applied exactly once and survives a restart.
#   3. A replica (serverID != 1, derived from the "ols-N" hostname ordinal)
#      with seed files present must skip seeding and still come up.
#   4. serverID 1 with no reachable peer still creates the base DIT and
#      applies seeds normally.
#
# Usage: scripts/test/test-bootstrap-seed.sh [image]
#   image defaults to ldapium:e2e. Requires Docker. BOOTSTRAP_SEED_TIMEOUT
#   (seconds, default 180) bounds each wait for a container to come up or exit.
set -euo pipefail
# Never pipe into `grep -q` here: it exits on the first match, the writer
# gets SIGPIPE, and pipefail turns a real match into a failure. Match
# against captured variables with here-strings instead.

here="$(cd "$(dirname "$0")" && pwd)"
fixtures="${here}/fixtures/bootstrap-seed"
base_image="${1:-ldapium:e2e}"
admin_pw="bootstrapSeedTestPw1"
# Generous by default for slow shared runners; override for local runs.
ready_timeout="${BOOTSTRAP_SEED_TIMEOUT:-180}"

work="$(mktemp -d)"
containers=()
images=()

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

dump_tail() {
  echo "---- last 20 log lines: $1 ----" >&2
  docker logs --tail 20 "$1" >&2 2>&1 || true
}

# shellcheck disable=SC2317,SC2329 # invoked via the EXIT trap below (code differs by shellcheck version)
cleanup() {
  local c i
  for c in ${containers[@]+"${containers[@]}"}; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  for i in ${images[@]+"${images[@]}"}; do
    docker rmi -f "$i" >/dev/null 2>&1 || true
  done
  rm -rf "$work"
}
trap cleanup EXIT

# Bake seed LDIFs into a throwaway derived image instead of bind-mounting
# them: on macOS/Colima, UID mapping across the VM boundary leaves a
# bind-mounted file unreadable by the container's non-root ldap (uid 999)
# user even when it's 644 on the host, so this keeps local runs and CI
# identical instead of working around the bind-mount gap.
build_seed_image() {
  local tag="$1" seed_src="$2" ctx
  ctx="${work}/${tag//[:\/]/_}"
  mkdir -p "$ctx"
  cp "${seed_src}"/*.ldif "$ctx"/
  cat > "${ctx}/Dockerfile" <<DOCKERFILE
FROM ${base_image}
USER root
COPY *.ldif /opt/ldifs/
RUN chown -R ldap:ldap /opt/ldifs
USER ldap
DOCKERFILE
  docker build -q -t "$tag" "$ctx" >/dev/null
  images+=("$tag")
}

# Poll (never a bare fixed sleep as the only synchronization) until either
# slapd answers inside the container or the container has exited, whichever
# comes first.
wait_ready_or_exited() {
  local cid="$1" timeout="${2:-$ready_timeout}" waited=0 status
  while [ "$waited" -lt "$timeout" ]; do
    if docker exec "$cid" ldapwhoami -x -H ldap://localhost >/dev/null 2>&1; then
      echo ready
      return 0
    fi
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo missing)"
    if [ "$status" = "exited" ] || [ "$status" = "missing" ]; then
      echo exited
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  echo timeout
}

query_people_and_alice() {
  docker exec "$1" ldapsearch -x -LLL -H ldap://localhost \
    -D "cn=admin,dc=example,dc=org" -w "$admin_pw" \
    -b dc=example,dc=org '(|(ou=people)(uid=alice))' dn 2>&1 || true
}

# shellcheck disable=SC2054 # the commas are inside env values, not separators
common_env=(-e LDAP_ROOT_DN=dc=example,dc=org -e LDAP_ADMIN_PASSWORD="$admin_pw")
# shellcheck disable=SC2054
repl_env=(-e LDAP_REPLICATION_ENABLED=true \
  -e LDAP_REPLICATION_PEERS=ldap://ols-0.invalid:389,ldap://ols-1.invalid:389)

build_seed_image "t203-bad-$$" "${fixtures}/bad"
build_seed_image "t203-good-$$" "${fixtures}/good"

# --- Case 1: bad seed must fail bootstrap on every start, never once. -----
c1="t203-c1-$$"
containers+=("$c1")
docker run -d --name "$c1" "${common_env[@]}" "t203-bad-$$" >/dev/null

status1="$(wait_ready_or_exited "$c1" "$ready_timeout")"
exit1="$(docker inspect -f '{{.State.ExitCode}}' "$c1" 2>/dev/null || echo -1)"
if [ "$status1" = "exited" ] && [ "$exit1" != "0" ]; then
  ok "bad seed: first start exited non-zero (${exit1})"
else
  bad "bad seed: first start reached '${status1}' (exit=${exit1}), expected a non-zero exit"
  dump_tail "$c1"
fi

docker start "$c1" >/dev/null
status1b="$(wait_ready_or_exited "$c1" "$ready_timeout")"
exit1b="$(docker inspect -f '{{.State.ExitCode}}' "$c1" 2>/dev/null || echo -1)"
if [ "$status1b" = "exited" ] && [ "$exit1b" != "0" ]; then
  ok "bad seed: second start (retry) exited non-zero (${exit1b})"
else
  bad "bad seed: second start reached '${status1b}' (exit=${exit1b}), expected a non-zero exit"
  dump_tail "$c1"
fi

c1_logs="$(docker logs "$c1" 2>&1)"
violation_count="$(printf '%s\n' "$c1_logs" | grep -c 'Object class violation' || true)"
if [ "$violation_count" -eq 2 ]; then
  ok "bad seed: 'Object class violation' logged exactly twice (once per start)"
else
  bad "bad seed: 'Object class violation' logged ${violation_count} time(s), expected 2"
  dump_tail "$c1"
fi
if grep -q 'bootstrap marker present' <<<"$c1_logs"; then
  bad "bad seed: bootstrap marker was written despite the failing seed (partial-seed regression)"
  dump_tail "$c1"
else
  ok "bad seed: bootstrap marker never written; the real error keeps being retried"
fi

# --- Case 2: good seed is applied once and survives a restart. ------------
c2="t203-c2-$$"
containers+=("$c2")
docker run -d --name "$c2" "${common_env[@]}" "t203-good-$$" >/dev/null

status2="$(wait_ready_or_exited "$c2" "$ready_timeout")"
if [ "$status2" = "ready" ]; then
  ok "good seed: first start came up"
else
  bad "good seed: first start reached '${status2}' instead of ready"
  dump_tail "$c2"
fi
q2="$(query_people_and_alice "$c2")"
if grep -q '^dn: ou=people,dc=example,dc=org$' <<<"$q2" \
  && grep -q '^dn: uid=alice,ou=people,dc=example,dc=org$' <<<"$q2"; then
  ok "good seed: ou=people and uid=alice present after first start"
else
  bad "good seed: expected entries missing after first start: ${q2}"
fi

docker restart "$c2" >/dev/null
status2b="$(wait_ready_or_exited "$c2" "$ready_timeout")"
if [ "$status2b" = "ready" ]; then
  ok "good seed: still up after restart"
else
  bad "good seed: reached '${status2b}' after restart instead of ready"
  dump_tail "$c2"
fi
q2b="$(query_people_and_alice "$c2")"
if grep -q '^dn: ou=people,dc=example,dc=org$' <<<"$q2b" \
  && grep -q '^dn: uid=alice,ou=people,dc=example,dc=org$' <<<"$q2b"; then
  ok "good seed: both entries still present after restart"
else
  bad "good seed: expected entries missing after restart: ${q2b}"
fi
apply_count="$(docker logs "$c2" 2>&1 | grep -c 'applying seed file' || true)"
if [ "$apply_count" -eq 2 ]; then
  ok "good seed: 'applying seed file' logged exactly twice in total (not re-applied on restart)"
else
  bad "good seed: 'applying seed file' logged ${apply_count} time(s) in total, expected 2"
  dump_tail "$c2"
fi

# --- Case 3: replica (serverID 2) with seeds must skip seeding. -----------
c3="t203-c3-$$"
containers+=("$c3")
docker run -d --name "$c3" --hostname ols-1 "${common_env[@]}" "${repl_env[@]}" "t203-good-$$" >/dev/null

status3="$(wait_ready_or_exited "$c3" "$ready_timeout")"
if [ "$status3" = "ready" ]; then
  ok "replica (serverID 2): came up and ldap:// answers"
else
  bad "replica (serverID 2): reached '${status3}' instead of ready"
  dump_tail "$c3"
fi
c3_logs="$(docker logs "$c3" 2>&1)"
if grep -q 'skipping seeding' <<<"$c3_logs"; then
  ok "replica (serverID 2): logs report skipping seeding"
else
  bad "replica (serverID 2): logs do not mention skipping seeding"
  dump_tail "$c3"
fi

# --- Case 4: serverID 1, no reachable peer, still seeds normally. ---------
c4="t203-c4-$$"
containers+=("$c4")
docker run -d --name "$c4" --hostname ols-0 "${common_env[@]}" "${repl_env[@]}" "t203-good-$$" >/dev/null

status4="$(wait_ready_or_exited "$c4" "$ready_timeout")"
if [ "$status4" = "ready" ]; then
  ok "serverID 1 (no reachable peer): came up"
else
  bad "serverID 1 (no reachable peer): reached '${status4}' instead of ready"
  dump_tail "$c4"
fi
q4="$(query_people_and_alice "$c4")"
if grep -q '^dn: ou=people,dc=example,dc=org$' <<<"$q4" \
  && grep -q '^dn: uid=alice,ou=people,dc=example,dc=org$' <<<"$q4"; then
  ok "serverID 1 (no reachable peer): both entries present"
else
  bad "serverID 1 (no reachable peer): expected entries missing: ${q4}"
  dump_tail "$c4"
fi

if [ "$fail" -eq 0 ]; then
  echo "all bootstrap seed tests passed"
  exit 0
else
  echo "bootstrap seed tests failed" >&2
  exit 1
fi
