#!/usr/bin/env python3
"""Live proof of Idempotency-Key (#216 part B) against disposable containers.

Real slapd + the real backup-runtime UI image (core routes and backup start in
one process); no mocks. It shows, through the HTTP API:
  1. a replay returns the first result and writes nothing a second time (create,
     delete, and "lock, someone unlocks, retry the lock" that must NOT re-lock),
  2. the same key with a different body is 422 idempotency_key_reused,
  3. concurrent requests with one key execute once,
  4. the key store is memory-only: after a restart a core key is forgotten
     (documented limit), while a backup-start key survives and returns the same job,
  5. no key, password or DN-of-requester is in the UI log or the job file, and the
     key file is 0600 in a 0700 directory,
  6. a server with the switch off refuses a keyed write (422 idempotency_unsupported).

Image tags: LDAPIUM_IMAGE / LDAPIUM_UI_IDEMPOTENCY_IMAGE (the UI must be the
backup-runtime target). Docker objects carry LDAPIUM_TEST_PREFIX (default l7-) and
are removed at the end. Named volumes only (Colima bind mounts are unreliable).
"""
import http.cookiejar
import json
import os
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ldap_image = os.environ.get('LDAPIUM_IMAGE', 'l7-ldap:1')
ui_image = os.environ.get('LDAPIUM_UI_IDEMPOTENCY_IMAGE', 'l7-ui:1')
name = os.environ.get('LDAPIUM_TEST_PREFIX', 'l7-') + uuid.uuid4().hex[:6]
network, ldap, ui, ui_off = name + '-net', name + '-ldap', name + '-ui', name + '-uioff'
volumes = {k: name + '-' + k for k in ('config', 'data', 'etc', 'state', 'log')}
base_dn = 'dc=example,dc=org'
admin_dn = 'cn=admin,' + base_dn
password = secrets.token_urlsafe(32)
session_secret = secrets.token_hex(32)
user_password = 'Idem-' + uuid.uuid4().hex[:12] + '!x'
operator = {'instance_id': 'idem-live', 'root': '/var/lib/ldapium-backups',
  'ldap': {'url': 'ldap://idem-ldap:389', 'base_dn': base_dn, 'admin_dn': admin_dn,
           'password_file': '/etc/ldapium-backup/ldap-password', 'include_config': False},
  'log_paths': ['/var/log/ldapium-backup/audit.log'],
  'destinations': [{'id': 'local', 'name': 'Local archive', 'type': 'local'}]}
KEY_FILE = '/var/lib/ldapium-backups/.idempotency/key'
containers = []


def sh(args, **kw):
  return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout.strip()


def prepare(script, stdin=''):
  mounts = ['-v', volumes['etc'] + ':/etc/ldapium-backup', '-v', volumes['state'] + ':/var/lib/ldapium-backups', '-v', volumes['log'] + ':/var/log/ldapium-backup']
  sh(['docker', 'run', '--rm', '-i', '--user', '0', '--entrypoint', 'sh', *mounts, ui_image, '-c', script], input=stdin)


def wait(predicate, what, timeout=120, step=0.5):
  end = time.time() + timeout
  while time.time() < end:
    value = predicate()
    if value:
      return value
    time.sleep(step)
  raise AssertionError('timed out waiting for ' + what)


def check(condition, message):
  assert condition, message
  print('PASS: ' + message)


class Api:
  def __init__(self, base):
    self.base = base
    self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

  def call(self, method, path, body=None, headers=None):
    hdr = {'Origin': self.base, 'Content-Type': 'application/json', **(headers or {})}
    request = urllib.request.Request(self.base + path, method=method, data=None if body is None else json.dumps(body).encode(), headers=hdr)
    try:
      with self.opener.open(request, timeout=60) as response:
        raw = response.read()
        return response.status, dict(response.headers), json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
      raw = error.read()
      return error.code, dict(error.headers), json.loads(raw) if raw else None

  def login(self):
    status, _, body = self.call('POST', '/api/login', {'identity': admin_dn, 'password': password})
    assert status == 200, (status, body)


def idem(key):
  return {'Idempotency-Key': key}


def replayed(headers):
  return headers.get('Idempotent-Replayed') == 'true'


def ldap_search(filter_, attrs=('dn',)):
  out = subprocess.run(['docker', 'exec', ldap, 'sh', '-c',
                        'ldapsearch -x -LLL -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD" -b "$1" "$2" "$@"',
                        admin_dn, base_dn, filter_, *attrs], capture_output=True, text=True).stdout
  return out


def entry_count(uid):
  return ldap_search('(uid=%s)' % uid).count('dn: ')


def csn_of(dn):
  out = subprocess.run(['docker', 'exec', ldap, 'sh', '-c',
                        'ldapsearch -x -LLL -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD" -b "$1" -s base entryCSN', admin_dn, dn],
                       capture_output=True, text=True).stdout
  return [line for line in out.splitlines() if line.startswith('entryCSN:')]


def locked(dn):
  return 'pwdAccountLockedTime' in subprocess.run(['docker', 'exec', ldap, 'sh', '-c',
    'ldapsearch -x -LLL -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD" -b "$1" -s base "+"', admin_dn, dn], capture_output=True, text=True).stdout


def start_ui(container, enabled, extra_ports=True):
  with tempfile.TemporaryDirectory(prefix='l7-ui-') as tmp:
    envfile = Path(tmp) / 'ui.env'
    lines = ['LDAP_URL=ldap://idem-ldap:389', 'LDAP_BASE_DN=' + base_dn, 'COOKIE_SECURE=false', 'SESSION_SECRET=' + session_secret,
             'LDAP_USER_CREATE_BASE=ou=people,' + base_dn, 'LDAP_GROUP_CREATE_BASE=ou=groups,' + base_dn,
             'BACKUP_OPERATOR_CONFIG=/etc/ldapium-backup/operator.json', 'BACKUP_POLICY_PATH=/var/lib/ldapium-backups/policies.json',
             'BACKUP_ADMIN_DNS=' + admin_dn, 'UI_IDEMPOTENCY_KEY_FILE=' + KEY_FILE]
    if enabled:
      lines.append('UI_IDEMPOTENCY_ENABLED=true')
    envfile.write_text('\n'.join(lines) + '\n')
    envfile.chmod(0o600)
    sh(['docker', 'run', '-d', '--name', container, '--network', network, '-p', '127.0.0.1::8080', '--env-file', str(envfile),
        '-v', volumes['etc'] + ':/etc/ldapium-backup:ro', '-v', volumes['state'] + ':/var/lib/ldapium-backups', '-v', volumes['log'] + ':/var/log/ldapium-backup:ro', ui_image])
  containers.append(container)
  return wait_ui(container)


def wait_ui(container):
  port = sh(['docker', 'port', container, '8080/tcp']).splitlines()[0].rsplit(':', 1)[1]
  base = 'http://127.0.0.1:' + port

  def ready():
    try:
      urllib.request.urlopen(base + '/api/auth/config', timeout=1).close()
      return True
    except Exception:
      return False
  wait(ready, 'UI readiness', 60, 1)
  return base


try:
  sh(['docker', 'network', 'create', network])
  for volume in volumes.values():
    sh(['docker', 'volume', 'create', volume])
  prepare('umask 077; cat > /etc/ldapium-backup/ldap-password', password)
  prepare('umask 077; cat > /etc/ldapium-backup/operator.json', json.dumps(operator))
  prepare('echo "audit line" > /var/log/ldapium-backup/audit.log; chown -R 65532:65532 /etc/ldapium-backup /var/lib/ldapium-backups /var/log/ldapium-backup; chmod 700 /etc/ldapium-backup /var/lib/ldapium-backups')
  with tempfile.TemporaryDirectory(prefix='l7-ldap-') as tmp:
    envfile = Path(tmp) / 'ldap.env'
    envfile.write_text('LDAP_ROOT_DN=' + base_dn + '\nLDAP_ADMIN_PASSWORD=' + password + '\n')
    envfile.chmod(0o600)
    sh(['docker', 'run', '-d', '--name', ldap, '--network', network, '--network-alias', 'idem-ldap', '--env-file', str(envfile),
        '-v', volumes['config'] + ':/etc/openldap/slapd.d', '-v', volumes['data'] + ':/var/lib/openldap/data', ldap_image])
  containers.append(ldap)
  wait(lambda: subprocess.run(['docker', 'exec', ldap, 'ldapsearch', '-x', '-H', 'ldap://127.0.0.1', '-b', '', '-s', 'base', 'namingContexts'], capture_output=True).returncode == 0, 'LDAP readiness', 60)
  ldif = ''.join('dn: ou=%s,%s\nobjectClass: organizationalUnit\nou: %s\n\n' % (ou, base_dn, ou) for ou in ('people', 'groups'))
  subprocess.run(['docker', 'exec', '-i', ldap, 'sh', '-c', 'ldapadd -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD"', admin_dn], input=ldif, text=True, check=True, capture_output=True)

  base = start_ui(ui, True)
  api = Api(base)
  api.login()
  status, _, settings = api.call('GET', '/api/server-settings')
  check(status == 200 and settings.get('idempotencyEnabled') is True, 'server-settings reports idempotencyEnabled=true')

  # 1a. create: replay returns the same result, one entry, entryCSN untouched ---------------------------------
  key = 'live-create-' + uuid.uuid4().hex
  body = {'uid': 'l7-a', 'cn': 'L7 A', 'sn': 'A', 'mail': 'a@example.org'}
  s1, h1, b1 = api.call('POST', '/api/users', body, idem(key))
  dn_a = b1['dn']
  csn = csn_of(dn_a)
  s2, h2, b2 = api.call('POST', '/api/users', body, idem(key))
  check(s1 == 201 and s2 == 201 and b1 == b2 and replayed(h2) and not replayed(h1), 'create replay: same 201 body, Idempotent-Replayed only on the replay')
  check(entry_count('l7-a') == 1 and csn_of(dn_a) == csn, 'create replay wrote nothing a second time (1 entry, entryCSN unchanged)')
  s3, _, b3 = api.call('POST', '/api/users', body)
  check(s3 == 409 and b3['code'] == 'already_exists', 'without a key the same create is today\'s 409 already_exists')

  # 2. reused key ---------------------------------------------------------------------------------------------
  s4, _, b4 = api.call('POST', '/api/users', {**body, 'cn': 'Different'}, idem(key))
  check(s4 == 422 and b4['code'] == 'idempotency_key_reused' and b4['retryable'] is False, 'same key, different body: 422 idempotency_key_reused')
  check(csn_of(dn_a) == csn, 'the rejected reuse wrote nothing')

  # 1b. lock, someone unlocks, retry the lock with the same key: must not re-lock ------------------------------------
  lock_key = 'live-lock-' + uuid.uuid4().hex
  sl, _, _ = api.call('POST', '/api/users/lock', {'dn': dn_a}, idem(lock_key))
  check(sl == 204 and locked(dn_a), 'lock applied')
  su, _, _ = api.call('POST', '/api/users/unlock', {'dn': dn_a})
  check(su == 204 and not locked(dn_a), 'another administrator unlocked')
  sr, hr, _ = api.call('POST', '/api/users/lock', {'dn': dn_a}, idem(lock_key))
  check(sr == 204 and replayed(hr) and not locked(dn_a), 'retrying the lock with the same key is replayed and does NOT re-lock')

  # 1c. delete replay (without the key the retry is a 404) ---------------------------------------------------------------
  del_key = 'live-delete-' + uuid.uuid4().hex
  path = '/api/users?' + urllib.parse.urlencode({'dn': dn_a})
  sd1, _, _ = api.call('DELETE', path, None, idem(del_key))
  sd2, hd2, _ = api.call('DELETE', path, None, idem(del_key))
  sd3, _, bd3 = api.call('DELETE', path)
  check(sd1 == 204 and sd2 == 204 and replayed(hd2) and entry_count('l7-a') == 0, 'delete replay: 204 replayed, entry gone')
  check(sd3 == 404 and bd3['code'] == 'not_found', 'without a key the delete retry is today\'s 404')

  # 3. concurrent same key executes once -------------------------------------------------------------------------------
  ckey = 'live-concurrent-' + uuid.uuid4().hex
  cbody = {'uid': 'l7-c', 'cn': 'L7 C', 'sn': 'C'}
  results = []
  lock = threading.Lock()

  def worker():
    own = Api(base)
    own.login()
    r = own.call('POST', '/api/users', cbody, idem(ckey))
    with lock:
      results.append(r)
  # One session (same subject): a different session of the same DN shares the key scope.
  threads = [threading.Thread(target=worker) for _ in range(10)]
  [t.start() for t in threads]
  [t.join() for t in threads]
  originals = [r for r in results if r[0] == 201 and not replayed(r[1])]
  others = [r for r in results if r[0] == 409 and r[2]['code'] == 'idempotency_key_conflict' or (r[0] == 201 and replayed(r[1]))]
  check(len(originals) == 1 and len(originals) + len(others) == 10 and entry_count('l7-c') == 1,
        'concurrent same-key creates: one execution (%d original, %d conflict/replay), 1 entry' % (len(originals), len(others)))

  # password route: explicit password replays as {}; a generated one cannot carry a key -----------------------------------
  dn_c = originals[0][2]['dn']
  pkey = 'live-password-' + uuid.uuid4().hex
  sp1, _, _ = api.call('POST', '/api/users/password', {'dn': dn_c, 'password': user_password}, idem(pkey))
  sp2, hp2, bp2 = api.call('POST', '/api/users/password', {'dn': dn_c, 'password': user_password}, idem(pkey))
  check(sp1 == 200 and sp2 == 200 and replayed(hp2) and bp2 == {}, 'password with a key: replay body is {} (no secret)')
  sg, _, bg = api.call('POST', '/api/users/password', {'dn': dn_c}, idem('live-gen-' + uuid.uuid4().hex))
  check(sg == 422 and bg['code'] == 'validation_failed', 'generated password + key is refused (422 validation_failed)')

  # backup start: same key -> same job -------------------------------------------------------------------------------------
  bkey = 'live-backup-' + uuid.uuid4().hex
  sb1, hb1, bb1 = api.call('POST', '/api/v1/backups/jobs/data', None, idem(bkey))
  check(sb1 == 202, 'backup start with a key: 202 (%s)' % bb1)
  job_id = bb1['job_id']
  sb2, hb2, bb2 = api.call('POST', '/api/v1/backups/jobs/data', None, idem(bkey))
  check(sb2 == 202 and bb2['job_id'] == job_id and replayed(hb2) and hb2.get('Location') == '/api/v1/backups/jobs/' + job_id,
        'backup start replay while the job exists: same job id and Location')
  wait(lambda: api.call('GET', '/api/v1/backups/jobs/' + job_id)[2]['status'] in ('succeeded', 'failed'), 'backup job to finish', 120)
  sb3, _, bb3 = api.call('POST', '/api/v1/backups/jobs/logs', None, idem(bkey))
  check(sb3 == 422 and bb3['code'] == 'idempotency_key_reused', 'same backup key for another kind: 422 idempotency_key_reused')
  jobs = api.call('GET', '/api/v1/backups/jobs')[2]['jobs']
  check(len(jobs) == 1, 'one backup job record for three start requests')

  # 5. files and logs hold no key/password -----------------------------------------------------------------------------------
  mode = subprocess.run(['docker', 'run', '--rm', '--user', '0', '--entrypoint', 'sh', '-v', volumes['state'] + ':/s', ui_image, '-c',
                         'stat -c "%a %U" /s/.idempotency /s/.idempotency/key; cat /s/backup-jobs.json'], capture_output=True, text=True).stdout
  lines = mode.splitlines()
  check(lines[0].startswith('700 ') and lines[1].startswith('600 '), 'key file is 0600 in a 0700 directory (%s / %s)' % (lines[0], lines[1]))
  jobfile = '\n'.join(lines[2:])
  check(bkey not in jobfile and admin_dn not in jobfile and '"key_id"' in jobfile and '"fingerprint"' in jobfile, 'job file holds key hash/fingerprint/key_id only (no key, no DN)')
  logs = subprocess.run(['docker', 'logs', ui], capture_output=True, text=True)
  text = logs.stdout + logs.stderr
  # Labels only: no part of a key or password is ever printed.
  for label, secret in (('create key', key), ('lock key', lock_key), ('delete key', del_key), ('concurrent key', ckey),
                        ('password-route key', pkey), ('backup key', bkey), ('user password', user_password), ('admin password', password)):
    check(secret not in text, 'UI log does not contain the ' + label)

  # 4. restart: core keys forgotten (documented), backup key survives ---------------------------------------------------------
  sh(['docker', 'restart', ui])
  base = wait_ui(ui)
  api = Api(base)
  api.login()
  sa, ha, ba = api.call('POST', '/api/users', cbody, idem(ckey))
  check(sa == 409 and ba['code'] == 'already_exists' and not replayed(ha),
        'after a restart the in-memory core record is gone: the retry executes and meets today\'s 409 already_exists (documented limit)')
  sk, hk, bk = api.call('POST', '/api/v1/backups/jobs/data', None, idem(bkey))
  check(sk == 202 and bk['job_id'] == job_id and replayed(hk) and bk['status'] in ('succeeded', 'failed'),
        'after a restart the same backup key returns the same job id (%s, status %s)' % (job_id, bk['status']))
  check(len(api.call('GET', '/api/v1/backups/jobs')[2]['jobs']) == 1, 'still exactly one job record after the restart')

  # 6. switch off ----------------------------------------------------------------------------------------------------------------
  off = Api(start_ui(ui_off, False))
  off.login()
  so, _, bo = off.call('POST', '/api/users', {'uid': 'l7-off', 'cn': 'L7 Off', 'sn': 'Off'}, idem('live-off-' + uuid.uuid4().hex))
  check(so == 422 and bo['code'] == 'idempotency_unsupported' and entry_count('l7-off') == 0, 'switch off: keyed write is 422 idempotency_unsupported and writes nothing')
  check(off.call('GET', '/api/server-settings')[2]['idempotencyEnabled'] is False, 'switch off: server-settings reports false')
  sn, _, _ = off.call('POST', '/api/users', {'uid': 'l7-off', 'cn': 'L7 Off', 'sn': 'Off'})
  check(sn == 201, 'switch off: the same write without a key is unchanged (201)')
  print('PASS: idempotency live run')
except BaseException:
  for container in containers:
    out = subprocess.run(['docker', 'logs', '--tail', '40', container], capture_output=True, text=True)
    dump = out.stdout + out.stderr
    for secret in (password, user_password, session_secret):
      dump = dump.replace(secret, '***')
    print('--- logs ' + container + '\n' + dump[-3000:])
  raise
finally:
  for container in reversed(containers):
    subprocess.run(['docker', 'rm', '-f', container], capture_output=True)
  subprocess.run(['docker', 'network', 'rm', network], capture_output=True)
  for volume in volumes.values():
    subprocess.run(['docker', 'volume', 'rm', volume], capture_output=True)
