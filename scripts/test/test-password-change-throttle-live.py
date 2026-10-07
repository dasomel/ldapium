#!/usr/bin/env python3
"""Live proof of the POST /api/users/password failure throttle (#266, merged in #300).

Disposable slapd + UI containers on a private network, UI limit 3 failures per 8s window
(UI_PASSWORD_CHANGE_FAILURE_LIMIT / _WINDOW). Proves through the real backend:
  - 3 consecutive wrong current passwords from one session are 400 current_password_rejected,
    the 4th is 429 password_change_rate_limited with an integer Retry-After in 1..window;
  - while blocked even the correct current password is 429 and changes nothing;
  - another session for another DN, and a fresh login of the same DN (new session = new
    budget, maintainer decision D266-2), are unaffected;
  - the throttle never touches ppolicy: pwdAccountLockedTime stays unset and the account
    still binds with its real password (D266-1: ppolicy owns bind lockout);
  - after the window the correct password succeeds, resets the budget, and the new password binds;
  - no response body or header contains a password.
Image tags come from LDAPIUM_IMAGE / LDAPIUM_UI_IMAGE (default ldapium:e2e, ldapium-ui:e2e);
LDAPIUM_THROTTLE_PREFIX renames the throwaway docker objects.
"""
import http.cookiejar
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

ldap_image = os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')
ui_image = os.environ.get('LDAPIUM_UI_IMAGE', 'ldapium-ui:e2e')
root = 'dc=example,dc=org'
admin_dn = 'cn=admin,' + root
name = os.environ.get('LDAPIUM_THROTTLE_PREFIX', 'ldapium-pwt-') + uuid.uuid4().hex[:8]
network = name + '-network'
volumes = [name + '-config', name + '-data']
ldap = name + '-ldap'
ui = name + '-ui'
containers = []
LIMIT = 3
WINDOW = 8
admin_password = uuid.uuid4().hex + uuid.uuid4().hex
user_password = 'Throttle-' + uuid.uuid4().hex[:12] + '!'
new_password = 'Rotated-' + uuid.uuid4().hex[:12] + '!'
wrong_password = 'Wrong-' + uuid.uuid4().hex[:12] + '!'
other_password = 'Other-' + uuid.uuid4().hex[:12] + '!'
secrets = [admin_password, user_password, new_password, wrong_password, other_password]
users = {'alice': 'uid=alice,ou=people,' + root, 'bob': 'uid=bob,ou=people,' + root}


def mask(text):
  text = str(text)
  for secret in secrets:
    text = text.replace(secret, '***')
  return text


def command(args, **kw):
  try:
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout.strip()
  except subprocess.CalledProcessError as error:
    raise RuntimeError('%s failed (exit %d): %s' % (' '.join(args[:3]), error.returncode, mask(error.stderr).strip())) from None


def check(condition, message):
  if not condition:
    raise AssertionError(message)
  print('ok:', message)


def start_ldap():
  command(['docker', 'run', '-d', '--name', ldap, '--network', network, '--network-alias', 'pwt-ldap',
           '-e', 'LDAP_ROOT_DN=' + root, '-e', 'LDAP_ADMIN_PASSWORD', '-e', 'LDAP_PPM_MIN_CLASSES=3',
           '-v', volumes[0] + ':/etc/openldap/slapd.d', '-v', volumes[1] + ':/var/lib/openldap/data', ldap_image],
          env={**os.environ, 'LDAP_ADMIN_PASSWORD': admin_password})
  containers.append(ldap)
  for _ in range(60):
    result = subprocess.run(['docker', 'exec', ldap, 'sh', '-c',
                             'ldapwhoami -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD"', admin_dn],
                            capture_output=True, text=True)
    if result.returncode == 0:
      return
    time.sleep(1)
  raise RuntimeError('LDAP server did not accept the admin bind')


def admin_tool(tool, args, input=None):
  # The admin password is expanded inside the container, never put in argv.
  return subprocess.run(['docker', 'exec', '-i', ldap, 'sh', '-c',
                         'tool=$1; shift; exec "$tool" -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD" "$@"',
                         admin_dn, tool] + args, input=input, capture_output=True, text=True)


def scaffold():
  ldif = 'dn: ou=people,%s\nobjectClass: organizationalUnit\nou: people\n\n' % root
  ldif += 'dn: ou=groups,%s\nobjectClass: organizationalUnit\nou: groups\n\n' % root
  for uid, dn in users.items():
    ldif += 'dn: %s\nobjectClass: inetOrgPerson\nuid: %s\ncn: %s\nsn: %s\n\n' % (dn, uid, uid, uid)
  result = admin_tool('ldapadd', [], ldif)
  check(result.returncode == 0, 'scaffold users: ' + mask(result.stderr))
  for dn, password in ((users['alice'], user_password), (users['bob'], other_password)):
    result = admin_tool('ldappasswd', ['-T', '/dev/stdin', dn], password)
    check(result.returncode == 0, 'set initial password: ' + mask(result.stderr))


def bind_ok(dn, password):
  result = subprocess.run(['docker', 'exec', '-i', ldap, 'ldapwhoami', '-x', '-H', 'ldap://127.0.0.1', '-D', dn, '-y', '/dev/stdin'],
                          input=password, capture_output=True, text=True)
  return result.returncode == 0


def locked_time(dn):
  result = admin_tool('ldapsearch', ['-LLL', '-b', dn, '-s', 'base', '+', 'pwdAccountLockedTime'])
  check(result.returncode == 0, 'ldapsearch operational attrs: ' + mask(result.stderr))
  return [line for line in result.stdout.splitlines() if line.lower().startswith('pwdaccountlockedtime')]


def start_ui():
  command(['docker', 'run', '-d', '--name', ui, '--network', network, '-p', '127.0.0.1::8080', '--tmpfs', '/tmp:rw,mode=1777',
           '-e', 'UI_PASSWORD_CHANGE_FAILURE_LIMIT=%d' % LIMIT, '-e', 'UI_PASSWORD_CHANGE_FAILURE_WINDOW=%ds' % WINDOW,
           '-e', 'LDAP_URL=ldap://pwt-ldap:389', '-e', 'LDAP_BASE_DN=' + root,
           '-e', 'LDAP_USER_CREATE_BASE=ou=people,' + root, '-e', 'LDAP_GROUP_CREATE_BASE=ou=groups,' + root,
           '-e', 'COOKIE_SECURE=false', ui_image])
  containers.append(ui)
  port = command(['docker', 'port', ui, '8080/tcp']).splitlines()[0].rsplit(':', 1)[1]
  url = 'http://127.0.0.1:' + port
  for _ in range(60):
    try:
      urllib.request.urlopen(url + '/api/auth/config', timeout=1).close()
      return url
    except Exception:
      time.sleep(1)
  raise RuntimeError('UI did not start')


def run():
  command(['docker', 'network', 'create', network])
  for volume in volumes:
    command(['docker', 'volume', 'create', volume])
  start_ldap()
  scaffold()
  url = start_ui()

  def login(dn, password):
    # Each login is its own session (own cookie jar).
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(method, path, body):
      request = urllib.request.Request(url + path, json.dumps(body).encode(),
                                       {'Content-Type': 'application/json', 'Origin': url}, method=method)
      try:
        with opener.open(request) as response:
          return response.status, response.read().decode(), response.headers
      except urllib.error.HTTPError as error:
        return error.code, error.read().decode(), error.headers

    status, text, _ = call('POST', '/api/login', {'identity': dn, 'password': password})
    check(status == 200, 'login as %s (got %d %s)' % (dn, status, mask(text)[:200]))
    return call

  def change(call, dn, old, new):
    status, text, headers = call('POST', '/api/users/password', {'dn': dn, 'oldPassword': old, 'password': new})
    blob = text + str(headers)
    for secret in secrets:
      if secret in blob:
        raise AssertionError('response %d leaked a password: %s' % (status, mask(blob)[:200]))
    return status, text, headers

  def code_of(text):
    return json.loads(text).get('code')

  alice, bob_dn = users['alice'], users['bob']
  session_a = login(alice, user_password)
  session_b = login(bob_dn, other_password)

  for i in range(1, LIMIT + 1):
    status, text, _ = change(session_a, alice, wrong_password, new_password)
    check(status == 400 and code_of(text) == 'current_password_rejected', 'wrong current password #%d -> 400 current_password_rejected (got %d %s)' % (i, status, code_of(text)))
  blocked_at = time.monotonic()
  status, text, headers = change(session_a, alice, wrong_password, new_password)
  check(status == 429 and code_of(text) == 'password_change_rate_limited', 'wrong current password #%d -> 429 password_change_rate_limited (got %d)' % (LIMIT + 1, status))
  retry = headers.get('Retry-After', '')
  check(retry.isdigit() and 1 <= int(retry) <= WINDOW, 'Retry-After is an integer in 1..%d (got %r)' % (WINDOW, retry))
  check(json.loads(text).get('retryable') is not None, 'error envelope carries retryable')

  status, text, headers = change(session_a, alice, user_password, new_password)
  check(status == 429 and code_of(text) == 'password_change_rate_limited', 'while blocked the CORRECT current password is 429 too (got %d)' % status)
  check(bind_ok(alice, user_password) and not bind_ok(alice, new_password), 'blocked correct attempt changed nothing: old password still binds')

  # Not in scope of the throttle: another DN, and a new login of the same DN.
  status, text, _ = change(session_b, bob_dn, wrong_password, new_password)
  check(status == 400 and code_of(text) == 'current_password_rejected', 'another session/DN unaffected (400 current_password_rejected, not 429)')
  session_a2 = login(alice, user_password)
  status, text, _ = change(session_a2, alice, wrong_password, new_password)
  check(status == 400 and code_of(text) == 'current_password_rejected', 'a fresh login of the same DN starts a new budget (D266-2)')
  status, text, _ = change(session_a, alice, user_password, new_password)
  check(status == 429, 'the original session stays blocked after the other sessions acted')

  # ppolicy is independent of the throttle.
  check(locked_time(alice) == [], 'pwdAccountLockedTime unset after the throttle fired (D266-1: no account lockout)')
  check(bind_ok(alice, user_password), 'account still binds with its real password while the session is throttled')

  wait = WINDOW - (time.monotonic() - blocked_at) + 1.5
  if wait > 0:
    time.sleep(wait)
  status, text, _ = change(session_a, alice, user_password, new_password)
  check(status == 200, 'after the window the correct password succeeds (got %d %s)' % (status, mask(text)[:120]))
  check(bind_ok(alice, new_password) and not bind_ok(alice, user_password), 'new password binds, old one no longer does')
  check(locked_time(alice) == [], 'pwdAccountLockedTime still unset after the success')

  # Success resets the budget: LIMIT more wrong attempts are 400 again, the next one is 429.
  for i in range(1, LIMIT + 1):
    status, text, _ = change(session_a, alice, wrong_password, user_password)
    check(status == 400 and code_of(text) == 'current_password_rejected', 'budget reset after success: wrong attempt #%d -> 400 (got %d)' % (i, status))
  status, _, _ = change(session_a, alice, wrong_password, user_password)
  check(status == 429, 'budget exhausted again after %d new failures -> 429' % LIMIT)

  logs = subprocess.run(['docker', 'logs', ui], capture_output=True, text=True)
  for secret in secrets:
    if secret in logs.stdout + logs.stderr:
      raise AssertionError('UI log leaked a password')
  print('PASS: password-change throttle live (limit %d / %ds): 400x%d -> 429 + Retry-After, correct password 429 while blocked, other DN and new login unaffected, ppolicy untouched (no pwdAccountLockedTime, binds), success after window resets, no password in responses or UI log' % (LIMIT, WINDOW, LIMIT))


try:
  run()
except Exception as error:
  print('FAIL: %s: %s' % (type(error).__name__, mask(error)), file=sys.stderr)
  for container in containers:
    logs = subprocess.run(['docker', 'logs', '--tail', '60', container], capture_output=True, text=True)
    print('--- logs %s ---\n%s' % (container, mask(logs.stdout + logs.stderr)), file=sys.stderr)
  sys.exit(1)
finally:
  for container in set(containers + [ldap, ui]):
    subprocess.run(['docker', 'rm', '-fv', container], capture_output=True)
  for volume in volumes:
    subprocess.run(['docker', 'volume', 'rm', volume], capture_output=True)
  subprocess.run(['docker', 'network', 'rm', network], capture_output=True)
