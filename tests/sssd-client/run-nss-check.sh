#!/bin/sh
set -eu

echo 'Starting a real SSSD daemon with NSS enabled...'
grep -Eq '^passwd: sss files$' /etc/nsswitch.conf || {
  echo '::error::NSS passwd ordering is not sss files' >&2
  exit 1
}
grep -Eq '^group: sss files$' /etc/nsswitch.conf || {
  echo '::error::NSS group ordering is not sss files' >&2
  exit 1
}
sssd -i --logger=files &
sssd_pid=$!
trap 'kill "$sssd_pid" 2>/dev/null || true; wait "$sssd_pid" 2>/dev/null || true' EXIT

attempt=0
until getent passwd posixuser > /tmp/posixuser.passwd; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo '::error::SSSD did not resolve posixuser through NSS within 120 seconds' >&2
    find /var/log/sssd -maxdepth 1 -type f -print -exec tail -100 {} \; 2>/dev/null || true
    exit 1
  fi
  sleep 2
done

cat /tmp/posixuser.passwd
grep -Eq '^posixuser:[^:]*:10001:10001:POSIX User:/home/posixuser:/bin/sh$' /tmp/posixuser.passwd || {
  echo '::error::getent passwd returned an unexpected POSIX account' >&2
  exit 1
}

id posixuser > /tmp/posixuser.id
cat /tmp/posixuser.id
grep -Fx 'uid=10001(posixuser) gid=10001(posixgroup) groups=10001(posixgroup)' /tmp/posixuser.id || {
  echo '::error::id returned an unexpected POSIX user or group identity' >&2
  exit 1
}

echo 'PASS: SSSD NSS getent passwd and id resolved the seeded POSIX identity'
