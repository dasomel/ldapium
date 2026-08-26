#!/usr/bin/env bash
# LDAPS availability probe for the TLS E2E job — CI-only, hardwired to the
# `directory` namespace / `directory-ldapium` release that e2e.yml installs.
# Not an operator tool; it lives in scripts/ so `shellcheck scripts/*.sh`
# covers it like the other CI helpers here (check-*.sh, licenses.sh).
#
#   e2e-ldaps-probe.sh start <probe-pod-name>
#   e2e-ldaps-probe.sh stop  <probe-pod-name> <evidence-prefix> <what-was-rotated>
#
# `start` runs a Pod outside the StatefulSet that binds over LDAPS once a
# second and prints OK/FAIL per attempt, so it survives every directory pod
# being replaced in turn. `stop` ends the sampling, saves the verdict log to
# <evidence-prefix>-availability.txt and the figures to
# <evidence-prefix>-availability-summary.txt, then applies the zero-downtime
# contract the chart README promises for a rolling restart:
#
#   - at least 20 samples, or the rotation finished too fast to have been
#     measured at all
#   - no more than 5 consecutive failures: a rolling restart drains one pod
#     at a time, so a single bind landing on an endpoint already on its way
#     out is expected, but a *run* of failures means no pod was answering
#   - at least 80% of binds succeeded overall
#
# Both rotation steps in e2e.yml (server certificate, and the two-step CA
# swap) share this exact contract; it used to be inlined in each, and the
# two copies had already started to drift.
set -euo pipefail

ns=directory
ldaps_url="ldaps://directory-ldapium.directory.svc.cluster.local:636"

usage() {
  echo "usage: $0 start <probe-pod-name> | stop <probe-pod-name> <evidence-prefix> <what-was-rotated>" >&2
  exit 2
}

start() {
  name="$1"
  kubectl -n "$ns" apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
spec:
  restartPolicy: Never
  containers:
    - name: probe
      image: ldapium:e2e
      imagePullPolicy: Never
      command:
        - sh
        - -c
        - |
          while [ ! -f /tmp/stop ]; do
            if LDAPTLS_REQCERT=demand LDAPTLS_CACERT=/etc/openldap/tls/ca.crt \\
              ldapwhoami -x -o nettimeout=2 \\
              -H "${ldaps_url}" \\
              -D "\$LDAP_ADMIN_DN" -w "\$LDAP_ADMIN_PASSWORD" >/dev/null 2>&1; then
              echo OK
            else
              echo FAIL
            fi
            sleep 1
          done
      env:
        - name: LDAP_ADMIN_DN
          value: cn=admin,dc=example,dc=org
        - name: LDAP_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: directory-ldapium-admin
              key: admin-password
      volumeMounts:
        - name: tls
          mountPath: /etc/openldap/tls
          readOnly: true
  volumes:
    - name: tls
      secret:
        secretName: ldapium-tls
EOF
  kubectl -n "$ns" wait --for=condition=Ready "pod/${name}" --timeout=3m
}

stop() {
  name="$1"
  prefix="$2"
  label="$3"
  log="${prefix}-availability.txt"

  kubectl -n "$ns" exec "$name" -- touch /tmp/stop
  kubectl -n "$ns" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/${name}" --timeout=2m
  kubectl -n "$ns" logs "$name" > "$log"
  kubectl -n "$ns" delete pod "$name" --ignore-not-found

  # Counting every line would fold anything the probe's shell wrote on its
  # way in or out into the availability figure. Only the verdicts count.
  total=$(grep -cE '^(OK|FAIL)$' "$log" || true)
  ok=$(grep -c '^OK$' "$log" || true)
  streak=$(awk '/^FAIL$/ { n++; if (n > m) m = n; next } { n = 0 } END { print m + 0 }' "$log")
  echo "LDAPS binds during ${label}: ${ok}/${total}, longest consecutive failure run: ${streak}"
  printf 'attempts=%s\nsucceeded=%s\nlongest_failure_run=%s\n' "$total" "$ok" "$streak" \
    > "${prefix}-availability-summary.txt"

  if [ "$total" -lt 20 ]; then
    echo "::error::${label} completed too quickly to measure availability (${total} samples)"
    exit 1
  fi
  if [ "$streak" -gt 5 ]; then
    echo "::error::LDAPS was unanswerable for ${streak} consecutive probes during ${label}"
    exit 1
  fi
  if [ $((ok * 100 / total)) -lt 80 ]; then
    echo "::error::LDAPS availability dropped to ${ok}/${total} during ${label}"
    exit 1
  fi
}

case "${1:-}" in
  start) [ $# -eq 2 ] || usage; start "$2" ;;
  stop)  [ $# -eq 4 ] || usage; stop "$2" "$3" "$4" ;;
  *) usage ;;
esac
