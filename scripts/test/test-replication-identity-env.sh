#!/usr/bin/env bash
# Live test for LDAP_REPLICATION_IDENTITY parsing + replication-password hygiene
# (docs/changes/replication-identity, #229, T-010). Drives the real entrypoint.
#
# Part 1 (refusals): invalid value, non-admin modes without replication, the
#   password hygiene check (length / distinct characters / equal to admin
#   password), reserved-DN = admin DN, prepare + explicit password
#   (prepare is T-011, covered by test-replication-identity-prepare.sh; the
#   dedicated start-up refusals and runtime are T-012, covered by
#   test-replication-identity-dedicated.sh). Every refusal must
#   exit non-zero with a fixed message and must not leak password material.
# Part 2 (defaults byte-identical, only when a base image is given): a
#   standalone node and a replicated 2-node pair started in `admin` mode from
#   BASE_IMAGE (unset env) and from IMAGE (LDAP_REPLICATION_IDENTITY=admin);
#   `slapcat -n 0` (volatile attributes and password hashes removed) and the
#   rendered olcSyncrepl lines must be identical.
#
# Usage: scripts/test/test-replication-identity-env.sh [image] [base-image]
#   image defaults to ldapium:e2e; base-image (e.g. built from origin/main)
#   enables Part 2. Requires Docker. RIDENV_TIMEOUT (seconds, default 120)
#   bounds each readiness wait. Resources are named ldapium-ridenv-* and only
#   those are removed on exit.
set -euo pipefail
# Never pipe into `grep -q` (SIGPIPE + pipefail): match captured variables.

image="${1:-ldapium:e2e}"
base_image="${2:-}"
timeout_s="${RIDENV_TIMEOUT:-120}"
suffix="$$"
pw="ridenvAdminPw-Zq7Lm2Xv9Kd4Hs8Wt1Bn6Rc3Yf5Ug0Pe"   # 40 chars, >10 distinct
good="Rp#4kV9wQm2Xz7LhT5bN8cY1dFjG3sAe"                 # 32 chars, >10 distinct
base="dc=example,dc=org"
peers="ldap://ldapium-ridenv-n1-${suffix}:389,ldap://ldapium-ridenv-n2-${suffix}:389"
work="$(mktemp -d)"
net="ldapium-ridenv-net-${suffix}"
n1="ldapium-ridenv-n1-${suffix}"
n2="ldapium-ridenv-n2-${suffix}"
solo="ldapium-ridenv-solo-${suffix}"
vols=("${n1}-cfg" "${n1}-data" "${n2}-cfg" "${n2}-data" "${solo}-cfg" "${solo}-data")

fail=0
ok() { printf 'PASS: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

# Every container and volume is registered here BEFORE it is created, so the
# trap removes it even when the run is interrupted mid-way.
reg_containers=("$n1" "$n2" "$solo")
reg_vols=("${vols[@]}")

# shellcheck disable=SC2317,SC2329 # invoked via the trap below
cleanup() {
  local x
  trap - EXIT
  for x in "${reg_containers[@]}"; do docker rm -fv "$x" >/dev/null 2>&1 || true; done
  for x in "${reg_vols[@]}"; do docker volume rm -f "$x" >/dev/null 2>&1 || true; done
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- Part 1: refusals --------------------------------------------------------
# refuse <label> <expected message fragment> <docker -e args...>
# The container must exit non-zero within REFUSE_DEADLINE seconds, print the
# fragment, never print the admin password or the candidate replication
# password, and leave fresh config/data volumes exactly as they were (a refused
# start must not create .credentials, markers or directories). Set
# admin_args=() beforehand to start without an admin password.
refuse_deadline="${REFUSE_DEADLINE:-60}"
admin_args=(-e LDAP_ADMIN_PASSWORD="$pw")
cn=0

pv="ldapium-ridenv-pristine-${suffix}"
reg_vols+=("${pv}-cfg" "${pv}-data")
docker volume create "${pv}-cfg" >/dev/null
docker volume create "${pv}-data" >/dev/null
# Mounted at the real paths so any image-seeded content is part of the baseline.
pristine_cfg="$(docker run --rm --entrypoint ls -v "${pv}-cfg:/etc/openldap/slapd.d" "$image" -A /etc/openldap/slapd.d 2>&1 | sort | tr '\n' ' ')"
pristine_data="$(docker run --rm --entrypoint ls -v "${pv}-data:/var/lib/openldap/data" "$image" -A /var/lib/openldap/data 2>&1 | sort | tr '\n' ' ')"

refuse() {
  local label="$1" want="$2" out rc=0 name cfgv datav w=0 state
  shift 2
  cn=$((cn + 1))
  name="ldapium-ridenv-refuse-${cn}-${suffix}"
  cfgv="${name}-cfg"
  datav="${name}-data"
  reg_containers+=("$name")
  reg_vols+=("$cfgv" "$datav")
  docker volume create "$cfgv" >/dev/null
  docker volume create "$datav" >/dev/null
  docker run -d --name "$name" \
    -v "${cfgv}:/etc/openldap/slapd.d" -v "${datav}:/var/lib/openldap/data" \
    -e LDAP_ROOT_DN="$base" ${admin_args[@]+"${admin_args[@]}"} \
    -e LDAP_REPLICATION_PEERS="$peers" -e LDAP_SERVER_ID=1 \
    "$@" "$image" >/dev/null
  while [ "$w" -lt "$refuse_deadline" ]; do
    state="$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || echo gone)"
    [ "$state" = "false" ] && break
    sleep 1
    w=$((w + 1))
  done
  if [ "$state" != "false" ]; then
    bad "${label}: container still running after ${refuse_deadline}s, expected refusal"
    docker rm -fv "$name" >/dev/null 2>&1 || true
    return
  fi
  rc="$(docker inspect -f '{{.State.ExitCode}}' "$name")"
  out="$(docker logs "$name" 2>&1)"
  if [ "$rc" -eq 0 ]; then
    bad "${label}: container exited 0, expected refusal"
    return
  fi
  if [[ "$out" != *"$want"* ]]; then
    bad "${label}: message missing '${want}'; got: $(printf '%s' "$out" | tail -n 3)"
    return
  fi
  if [ "$(docker run --rm --entrypoint ls -v "${cfgv}:/etc/openldap/slapd.d" "$image" -A /etc/openldap/slapd.d 2>&1 | sort | tr '\n' ' ')" != "$pristine_cfg" ] ||
    [ "$(docker run --rm --entrypoint ls -v "${datav}:/var/lib/openldap/data" "$image" -A /var/lib/openldap/data 2>&1 | sort | tr '\n' ' ')" != "$pristine_data" ]; then
    bad "${label}: refusal modified the config/data volume"
    return
  fi
  # Candidate replication password is the last -e LDAP_REPLICATION_PASSWORD=<v>.
  local arg v
  for arg in "$@"; do
    case "$arg" in
      LDAP_REPLICATION_PASSWORD=*)
        v="${arg#*=}"
        [ -z "$v" ] || [[ "$out" != *"$v"* ]] || bad "${label}: replication password leaked into output"
        ;;
    esac
  done
  [[ "$out" != *"$pw"* ]] || bad "${label}: admin password leaked into output"
  ok "${label}"
}

rep=(-e LDAP_REPLICATION_ENABLED=true)
hyg="a hygiene check, not proof of randomness"

refuse "invalid value" "LDAP_REPLICATION_IDENTITY must be one of: admin, prepare, dedicated" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=bogus
refuse "invalid value, replication off" "LDAP_REPLICATION_IDENTITY must be one of" \
  -e LDAP_REPLICATION_IDENTITY=Dedicated
refuse "dedicated without replication" "requires LDAP_REPLICATION_ENABLED=true" \
  -e LDAP_REPLICATION_IDENTITY=dedicated
refuse "prepare without replication" "requires LDAP_REPLICATION_ENABLED=true" \
  -e LDAP_REPLICATION_IDENTITY=prepare
refuse "dedicated without password" "requires an explicit LDAP_REPLICATION_PASSWORD" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=dedicated
refuse "dedicated short password (31)" "length must be at least 32" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=${good:0:31}"
refuse "hygiene message names its limit (length)" "$hyg" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=${good:0:31}"
refuse "dedicated low-distinct password" "at least 10 distinct characters" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=abababababababababababababababab"
refuse "hygiene message names its limit (distinct)" "$hyg" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=abababababababababababababababab"
refuse "dedicated multibyte password (9 distinct chars, 10 bytes)" "only printable ASCII characters" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=éñöøçßåäüéñöøçßåäüéñöøçßåäüéñöøçßåäü"
refuse "dedicated password with a space" "only printable ASCII characters" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=${good:0:16} ${good:16}"
refuse "dedicated ASCII password with 9 distinct chars" "at least 10 distinct characters" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=abcdefghiabcdefghiabcdefghiabcdefghi"
refuse "dedicated ASCII password with 10 distinct chars passes hygiene (next refusal: TLS)" "requires LDAP_TLS_ENABLED=true" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=abcdefghijabcdefghijabcdefghijabcdefghij"
# Fresh volume and no admin password: the refusal must come before admin-password
# generation would create .credentials on the data volume.
admin_args=()
refuse "prepare without replication, no admin password (volume untouched)" "requires LDAP_REPLICATION_ENABLED=true" \
  -e LDAP_REPLICATION_IDENTITY=prepare
refuse "dedicated without replication, no admin password (volume untouched)" "requires LDAP_REPLICATION_ENABLED=true" \
  -e LDAP_REPLICATION_IDENTITY=dedicated
refuse "invalid value, no admin password (volume untouched)" "LDAP_REPLICATION_IDENTITY must be one of" \
  -e LDAP_REPLICATION_IDENTITY=bogus
refuse "dedicated good password without TLS, no admin password (volume untouched)" "requires LDAP_TLS_ENABLED=true" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=${good}"
admin_args=(-e LDAP_ADMIN_PASSWORD="$pw")
refuse "dedicated password equals admin" "must differ from the admin password" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=${pw}"
refuse "dedicated good password without TLS is refused" "requires LDAP_TLS_ENABLED=true" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=${good}"
refuse "prepare with explicit password" "replicates as the admin identity" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=prepare -e "LDAP_REPLICATION_PASSWORD=${good}"
refuse "dedicated admin DN = reserved DN" "must not equal the reserved replication identity DN" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=${good}" \
  -e "LDAP_ADMIN_DN=cn=REPLICATOR,DC=example,DC=org"
refuse "dedicated admin DN = reserved DN (space variant)" "must not equal the reserved replication identity DN" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=dedicated -e "LDAP_REPLICATION_PASSWORD=${good}" \
  -e "LDAP_ADMIN_DN=cn=replicator, dc=example,dc=org"
refuse "prepare admin DN = reserved DN" "must not equal the reserved replication identity DN" \
  "${rep[@]}" -e LDAP_REPLICATION_IDENTITY=prepare -e "LDAP_ADMIN_DN=cn=replicator,${base}"

# --- Part 2: admin mode is byte-identical to the base image -------------------
norm() { grep -v -E '^(entryCSN|entryUUID|modifyTimestamp|createTimestamp|olcRootPW|userPassword)'; }

wait_ready() {
  local w=0
  while [ "$w" -lt "$timeout_s" ]; do
    docker exec "$1" ldapwhoami -x -H ldap://localhost >/dev/null 2>&1 && return 0
    sleep 1
    w=$((w + 1))
  done
  return 1
}

dump() { # container outfile-prefix
  docker exec "$1" slapcat -n 0 -o ldif-wrap=no 2>/dev/null | norm >"$2.cfg"
  grep '^olcSyncrepl' "$2.cfg" >"$2.syncrepl" || true
}

run_variant() { # label image [extra -e args...]
  local label="$1" img="$2" x
  shift 2
  for x in "${vols[@]}"; do docker volume create "$x" >/dev/null; done
  docker run -d --name "$solo" -v "${solo}-cfg:/etc/openldap/slapd.d" -v "${solo}-data:/var/lib/openldap/data" \
    -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" "$@" "$img" >/dev/null
  wait_ready "$solo" || { bad "${label}: standalone never ready"; return 1; }
  dump "$solo" "${work}/${label}.solo"
  docker rm -f "$solo" >/dev/null
  local n
  for n in "$n1" "$n2"; do
    docker run -d --name "$n" --network "$net" --hostname "$n" \
      -v "${n}-cfg:/etc/openldap/slapd.d" -v "${n}-data:/var/lib/openldap/data" \
      -e LDAP_ROOT_DN="$base" -e LDAP_ADMIN_PASSWORD="$pw" \
      -e LDAP_REPLICATION_ENABLED=true -e LDAP_SERVER_ID="$([ "$n" = "$n1" ] && echo 1 || echo 2)" \
      -e LDAP_REPLICATION_PEERS="$peers" "$@" "$img" >/dev/null
    wait_ready "$n" || { bad "${label}: ${n} never ready"; return 1; }
  done
  dump "$n1" "${work}/${label}.n1"
  dump "$n2" "${work}/${label}.n2"
  docker rm -f "$n1" "$n2" >/dev/null
  for x in "${vols[@]}"; do docker volume rm -f "$x" >/dev/null; done
}

if [ -n "$base_image" ]; then
  docker network create "$net" >/dev/null
  run_variant base "$base_image" || exit 1
  run_variant new "$image" -e LDAP_REPLICATION_IDENTITY=admin || exit 1
  for part in solo n1 n2; do
    [ -s "${work}/base.${part}.cfg" ] || bad "${part}: empty base dump"
    if diff -u "${work}/base.${part}.cfg" "${work}/new.${part}.cfg" >"${work}/${part}.diff"; then
      ok "${part}: cn=config identical to base image ($(wc -l <"${work}/base.${part}.cfg" | tr -d ' ') lines)"
    else
      bad "${part}: cn=config differs from base image"
      head -n 40 "${work}/${part}.diff" >&2
    fi
  done
  for part in n1 n2; do
    [ -s "${work}/base.${part}.syncrepl" ] || bad "${part}: no olcSyncrepl line rendered"
    if diff -u "${work}/base.${part}.syncrepl" "${work}/new.${part}.syncrepl" >/dev/null; then
      ok "${part}: olcSyncrepl identical to base image"
    else
      bad "${part}: olcSyncrepl differs from base image"
    fi
  done
else
  echo "SKIP: Part 2 (no base image given)"
fi

if [ "$fail" -eq 0 ]; then
  echo "replication-identity env test passed"
  exit 0
fi
echo "replication-identity env test FAILED" >&2
exit 1
