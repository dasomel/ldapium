#!/usr/bin/env python3
"""Disposable LDAP/UI containers prove API edge status codes through the real backend (#223).

Covers unlock idempotency, lock/unlock bind behaviour, group member 409/404,
router 404/405 JSON, the /api/v1/meta allowlist and userPassword redaction.
Also pins the error envelope (#218): every checked error carries exactly
{error, message, code, requestId, retryable}, error == message, requestId ==
X-Request-Id, no DN in the body, and a real 5xx (a wrong current password,
LDAP result 53) is redacted with its cause only in the UI log. The password
policy refusals the change-password screen shows are checked end to end,
including that ppm's user DN is stripped. Image tags come from LDAPIUM_IMAGE /
LDAPIUM_UI_IMAGE (default ldapium:e2e, ldapium-ui:e2e); LDAPIUM_EDGE_PREFIX renames the throwaway docker objects.
"""
import http.cookiejar
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ldap_image = os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')
ui_image = os.environ.get('LDAPIUM_UI_IMAGE', 'ldapium-ui:e2e')
root = 'dc=example,dc=org'
admin_dn = 'cn=admin,' + root
name = os.environ.get('LDAPIUM_EDGE_PREFIX', 'ldapium-edge-') + uuid.uuid4().hex[:8]
network = name + '-network'
volumes = [name + '-config', name + '-data']
ldap = name + '-ldap'
ui = name + '-ui'
containers = []
# Throwaway values for a disposable stack; the user password is only used
# against this container.
admin_password = uuid.uuid4().hex + uuid.uuid4().hex
user_password = 'Edge-' + uuid.uuid4().hex[:12] + '!'


def mask(text):
  return str(text).replace(admin_password, '***').replace(user_password, '***')


def command(args, **kw):
  # No secret rides in argv (docker run gets them through the environment), and
  # a failure is re-raised with the masked stderr only: CalledProcessError's
  # str() would embed the whole argv.
  try:
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout.strip()
  except subprocess.CalledProcessError as error:
    raise RuntimeError('%s failed (exit %d): %s' % (' '.join(args[:3]), error.returncode, mask(error.stderr).strip())) from None


def check(condition, message):
  if not condition:
    raise AssertionError(message)


def start_ldap():
  command(['docker', 'run', '-d', '--name', ldap, '--network', network, '--network-alias', 'edge-ldap',
           '-e', 'LDAP_ROOT_DN=' + root, '-e', 'LDAP_ADMIN_PASSWORD', '-e', 'LDAP_PPM_MIN_CLASSES=3',
           '-v', volumes[0] + ':/etc/openldap/slapd.d', '-v', volumes[1] + ':/var/lib/openldap/data', ldap_image],
          env={**os.environ, 'LDAP_ADMIN_PASSWORD': admin_password})
  containers.append(ldap)
  for _ in range(60):
    # $LDAP_ADMIN_PASSWORD is expanded inside the container so the password never
    # appears in this process's argv or output.
    result = subprocess.run(['docker', 'exec', ldap, 'sh', '-c',
                             'ldapwhoami -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD"', admin_dn],
                            capture_output=True, text=True)
    if result.returncode == 0:
      return
    time.sleep(1)
  raise RuntimeError('LDAP server did not accept the admin bind')


# #229 probe, run in the LDAP container with the admin password on stdin. Exit 0
# with "names= hits= seen=" on success; any probe failure aborts with a distinct
# status (3 pid-1 environ unreadable, 4 mktemp/empty pattern/grep error) so a
# broken probe can never read as "no match". Messages never contain the secret.
# Only PID 1 and its descendants are scanned: `docker exec` and HEALTHCHECK
# processes inherit the container-configured env (the password included) and have
# PPID 0 inside the namespace, so they are not entrypoint-started processes.
PROCESS_ENV_PROBE = r'''
umask 077
f=$(mktemp) || { echo "probe-error: mktemp failed"; exit 4; }
trap 'rm -f "$f"' EXIT HUP INT TERM
cat > "$f"
[ -s "$f" ] || { echo "probe-error: empty pattern file"; exit 4; }
chk() { case $1 in 0) return 0 ;; 1) return 1 ;; *) echo "probe-error: grep status $1"; exit 4 ;; esac; }
rd() { { tr "\0" "\n" < "$1"; } 2>/dev/null; }
[ -r /proc/1/environ ] || { echo "probe-error: /proc/1/environ unreadable"; exit 3; }
d=$(rd /proc/1/environ) || { echo "probe-error: cannot read /proc/1/environ"; exit 3; }
names=0
for v in ADMIN REPLICATION; do
  printf '%s\n' "$d" | grep -q "^LDAP_${v}_PASSWORD="; chk $? && names=$((names+1))
done
desc() {
  q=$1; i=0
  while [ "$i" -lt 64 ]; do
    [ "$q" = 1 ] && return 0
    s=$(cat "/proc/$q/stat" 2>/dev/null) || return 1
    q=$(printf '%s\n' "$s" | sed "s/^.*) [A-Za-z] //; s/ .*//")
    case $q in ''|*[!0-9]*|0) return 1 ;; esac
    i=$((i+1))
  done
  return 1
}
hits=0; seen=0
for p in /proc/[0-9]*; do
  desc "${p#/proc/}" || continue
  for n in environ cmdline; do
    d=$(rd "$p/$n") || continue
    seen=$((seen+1))
    printf '%s\n' "$d" | grep -qFf "$f"; chk $? && hits=$((hits+1))
  done
done
echo "names=$names hits=$hits seen=$seen"
'''


def check_secret_not_in_process_env():
  # The probe runs under `env -u` (docker exec inherits the container env, which
  # would otherwise make the probe itself a false hit) and takes the value on
  # stdin, so it is never in any argv. Output is counts only, never the value.
  result = subprocess.run(['docker', 'exec', '-i', ldap, 'env', '-u', 'LDAP_ADMIN_PASSWORD', '-u', 'LDAP_REPLICATION_PASSWORD',
                           'sh', '-c', PROCESS_ENV_PROBE], input=admin_password, capture_output=True, text=True)
  out = mask(result.stdout).strip()
  check(result.returncode == 0, 'process-env probe failed (exit %d): %s %s' % (result.returncode, out, mask(result.stderr).strip()))
  fields = dict(item.split('=') for item in out.split())
  check(int(fields['seen']) >= 2, 'process probe successfully read too few /proc entries: ' + out)
  check(fields['names'] == '0', 'LDAP_*_PASSWORD still present in /proc/1/environ: ' + out)
  check(fields['hits'] == '0', 'admin password value found in a container process environ/cmdline: ' + out)
  print('ok: admin password absent from every /proc/*/environ and /proc/*/cmdline (' + out + ')')


def scaffold():
  ldif = ''.join('dn: ou=%s,%s\nobjectClass: organizationalUnit\nou: %s\n\n' % (ou, root, ou) for ou in ('people', 'groups'))
  command(['docker', 'exec', '-i', ldap, 'sh', '-c',
           'ldapadd -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD"', admin_dn], input=ldif)


def start_ui():
  # --tmpfs + APP_PROFILES_*: the profile routes are what produce 422/412/428/415.
  command(['docker', 'run', '-d', '--name', ui, '--network', network, '-p', '127.0.0.1::8080', '--tmpfs', '/tmp:rw,mode=1777',
           '-e', 'APP_PROFILES_PATH=/tmp/profiles.json', '-e', 'APP_PROFILES_ADMIN_DNS=' + admin_dn,
           '-e', 'LDAP_URL=ldap://edge-ldap:389', '-e', 'LDAP_BASE_DN=' + root,
           '-e', 'LDAP_USER_CREATE_BASE=ou=people,' + root, '-e', 'LDAP_GROUP_CREATE_BASE=ou=groups,' + root,
           '-e', 'COOKIE_SECURE=false', ui_image])
  containers.append(ui)
  port = command(['docker', 'port', ui, '8080/tcp']).rsplit(':', 1)[1]
  url = 'http://127.0.0.1:' + port
  for _ in range(60):
    try:
      urllib.request.urlopen(url + '/api/auth/config', timeout=1).close()
      return url
    except Exception:
      time.sleep(1)
  raise RuntimeError('UI did not start')


def bind_ok(dn):
  # -y /dev/stdin keeps the user password out of argv.
  result = subprocess.run(['docker', 'exec', '-i', ldap, 'ldapwhoami', '-x', '-H', 'ldap://127.0.0.1', '-D', dn, '-y', '/dev/stdin'],
                          input=user_password, capture_output=True, text=True)
  return result.returncode == 0


ENVELOPE_KEYS = {'error', 'message', 'code', 'requestId', 'retryable'}


def envelope(text, headers, code, what, forbidden=()):
  """Assert text is the five-key error envelope with the expected code."""
  body = json.loads(text)
  check(isinstance(body, dict) and set(body) == ENVELOPE_KEYS, '%s: keys %s != %s (%s)' % (what, sorted(body), sorted(ENVELOPE_KEYS), text[:200]))
  check(isinstance(body['error'], str) and body['error'] and body['error'] == body['message'], '%s: error/message differ or empty (%s)' % (what, text[:200]))
  check(body['code'] == code, '%s: code %r, want %r' % (what, body['code'], code))
  check(body['requestId'] and body['requestId'] == headers.get('X-Request-Id'), '%s: requestId %r != X-Request-Id %r' % (what, body['requestId'], headers.get('X-Request-Id')))
  check(isinstance(body['retryable'], bool), '%s: retryable is not a bool' % what)
  for needle in forbidden:
    check(needle not in text, '%s: body contains %r: %s' % (what, needle, text[:300]))
  return body


def run():
  command(['docker', 'network', 'create', network])
  for volume in volumes:
    command(['docker', 'volume', 'create', volume])
  start_ldap()
  check_secret_not_in_process_env()
  scaffold()
  url = start_ui()
  opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

  def call(method, path, body=None, headers=None, who=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url + path, data, {'Content-Type': 'application/json', 'Origin': url, **(headers or {})}, method=method)
    try:
      with (who or opener).open(request) as response:
        return response.status, response.read().decode(), response.headers
    except urllib.error.HTTPError as error:
      return error.code, error.read().decode(), error.headers

  def expect(code, method, path, body=None, what='', headers=None, who=None):
    status, text, headers = call(method, path, body, headers, who)
    check(status == code, '%s: %s %s expected %d, got %d (%s)' % (what, method, path, code, status, text[:200]))
    return text, headers

  expect(200, 'POST', '/api/login', {'identity': admin_dn, 'password': admin_password}, 'admin login')

  text, _ = expect(201, 'POST', '/api/users', {'uid': 'edge-user', 'cn': 'Edge User', 'sn': 'User', 'password': user_password}, 'create user')
  user_dn = json.loads(text)['dn']
  check(user_dn == 'uid=edge-user,ou=people,' + root, 'unexpected user DN ' + user_dn)
  text, _ = expect(201, 'POST', '/api/groups', {'cn': 'edge-group'}, 'create group')
  group_dn = json.loads(text)['dn']
  check(group_dn == 'cn=edge-group,ou=groups,' + root, 'unexpected group DN ' + group_dn)

  member = {'groupDn': group_dn, 'memberDn': user_dn}
  query = '/api/groups/members?' + urllib.parse.urlencode(member)
  expect(204, 'POST', '/api/groups/members', member, 'add member')
  text, headers = expect(409, 'POST', '/api/groups/members', member, 'add duplicate member')
  envelope(text, headers, 'conflict', 'duplicate member 409', forbidden=(user_dn, group_dn, 'member'))
  expect(204, 'DELETE', query, None, 'remove member')
  expect(404, 'DELETE', query, None, 'remove non-member')

  expect(204, 'POST', '/api/users/unlock', {'dn': user_dn}, 'unlock never-locked user')
  check(bind_ok(user_dn), 'user cannot bind before locking')
  expect(204, 'POST', '/api/users/lock', {'dn': user_dn}, 'lock user')
  check(not bind_ok(user_dn), 'locked user could still bind')
  expect(204, 'POST', '/api/users/unlock', {'dn': user_dn}, 'unlock locked user')
  check(bind_ok(user_dn), 'user cannot bind after unlock')
  text, headers = expect(404, 'POST', '/api/users/unlock', {'dn': 'uid=nobody,ou=people,' + root}, 'unlock missing user')
  envelope(text, headers, 'not_found', 'missing user 404', forbidden=('uid=nobody',))

  text, headers = expect(404, 'GET', '/api/no-such-endpoint', None, 'unknown api path')
  envelope(text, headers, 'not_found', 'unknown path 404')
  text, headers = expect(405, 'PATCH', '/api/users', None, 'wrong method')
  check(headers.get('Allow'), 'wrong method response lacks Allow header')
  envelope(text, headers, 'method_not_allowed', 'wrong method 405')

  # #218: the envelope on the other error classes, through the real backend.
  anonymous = urllib.request.build_opener()
  text, headers = expect(401, 'GET', '/api/users', None, 'no session', who=anonymous)
  envelope(text, headers, 'unauthenticated', 'no session 401')
  text, headers = expect(400, 'POST', '/api/users', {'uid': '!bad', 'cn': 'x', 'sn': 'x'}, 'invalid uid')
  body = envelope(text, headers, 'invalid_request', 'validation 400', forbidden=('!bad',))
  check(body['retryable'] is False, 'validation 400 must not be retryable')
  profile = {'id': 'edge-app', 'name': 'Edge', 'client_id': 'edge', 'issuer': 'https://sso.example/realms/company', 'claim_path': 'groups',
             'token_source': 'access_token', 'enforcement': 'native_app', 'scope': 'subtree', 'mappings': [{'keycloak_role': 'admin', 'native_role': 'owner'}]}
  path = '/api/v1/applications/edge-app/integration-profile'
  text, headers = expect(422, 'PUT', path, profile, 'invalid profile scope', headers={'If-Match': '"0"'})
  envelope(text, headers, 'validation_failed', 'validation 422')
  text, headers = expect(428, 'PUT', path, profile, 'missing If-Match')
  envelope(text, headers, 'if_match_required', 'precondition required 428')
  text, headers = expect(403, 'PUT', path, profile, 'foreign origin', headers={'Origin': 'https://evil.example', 'If-Match': '"0"'})
  envelope(text, headers, 'origin_mismatch', 'foreign origin 403')
  profile['scope'] = 'app'
  expect(200, 'PUT', path, profile, 'create profile', headers={'If-Match': '"0"'})
  text, headers = expect(412, 'PUT', path, profile, 'stale revision', headers={'If-Match': '"0"'})
  envelope(text, headers, 'revision_conflict', 'stale revision 412')

  # Password-policy refusals reach the change-password screen as the server
  # sends them: fixed policy text, never the user's DN (ppm puts it in every
  # message). A wrong current password is LDAP 53, which is a redacted 500.
  user_session = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
  expect(200, 'POST', '/api/login', {'identity': user_dn, 'password': user_password}, 'user login', who=user_session)
  change = {'dn': user_dn, 'oldPassword': user_password}
  text, headers = expect(400, 'POST', '/api/users/password', {**change, 'password': 'Ab1!'}, 'too short', who=user_session)
  body = envelope(text, headers, 'invalid_request', 'ppolicy quality 400', forbidden=(user_dn, 'dn='))
  check(body['error'] == 'invalid input: Password fails quality checking policy', 'ppolicy text changed: ' + body['error'])
  text, headers = expect(400, 'POST', '/api/users/password', {**change, 'password': 'aaaaaaaaaaaaaaaa'}, 'ppm strength', who=user_session)
  body = envelope(text, headers, 'invalid_request', 'ppm strength 400', forbidden=(user_dn, 'dn=', 'edge-user'))
  check(body['error'] == 'invalid input: Password does not pass required number of strength checks (1 of 3)', 'ppm text: ' + body['error'])
  text, headers = expect(500, 'POST', '/api/users/password', {**change, 'oldPassword': 'Wrong-' + user_password, 'password': 'New-' + user_password}, 'wrong current password', who=user_session)
  body = envelope(text, headers, 'internal', 'LDAP 53 -> 500', forbidden=('LDAP Result', 'Unwilling', 'verify old password', user_dn))
  check(body['error'] == 'internal error' and body['retryable'] is False, '500 body is not the fixed redacted text: ' + text[:200])
  ui_log = subprocess.run(['docker', 'logs', ui], capture_output=True, text=True)
  ui_log = ui_log.stdout + ui_log.stderr
  check(body['requestId'] in ui_log and 'LDAP Result Code 53' in ui_log, 'UI log lacks the unredacted cause under requestId ' + body['requestId'])

  text, _ = expect(200, 'GET', '/api/v1/meta', None, 'meta')
  keys = set(json.loads(text))
  allowed = {'name', 'apiVersion', 'version', 'authMode', 'openapi'}
  check(keys == allowed, '/api/v1/meta keys %s != allowlist %s' % (sorted(keys), sorted(allowed)))

  text, _ = expect(200, 'GET', '/api/entry?' + urllib.parse.urlencode({'dn': user_dn}), None, 'get entry')
  check('userpassword' not in text.lower(), '/api/entry leaked userPassword')
  check(user_password not in text, '/api/entry leaked the user password')

  print('PASS: unlock idempotent (204/404), lock->bind fails->unlock->bind works, group member 204/409/404, error envelope on 400/401/403/404/405/409/412/422/428/500 (error==message, requestId==X-Request-Id, no DN), password-policy text without DN, meta allowlist, no userPassword in /api/entry')


try:
  run()
except Exception as error:
  print('FAIL: %s: %s' % (type(error).__name__, mask(error)), file=sys.stderr)
  # Containers are removed in finally, so show their logs now, with every
  # secret this script knows scrubbed out.
  for container in containers:
    logs = subprocess.run(['docker', 'logs', '--tail', '60', container], capture_output=True, text=True)
    text = mask(logs.stdout + logs.stderr)
    print('--- logs %s ---\n%s' % (container, text), file=sys.stderr)
  sys.exit(1)
finally:
  for container in set(containers + [ldap, ui]):
    subprocess.run(['docker', 'rm', '-f', container], capture_output=True)
  for volume in volumes:
    subprocess.run(['docker', 'volume', 'rm', volume], capture_output=True)
  subprocess.run(['docker', 'network', 'rm', network], capture_output=True)
