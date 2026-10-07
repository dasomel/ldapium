#!/usr/bin/env python3
"""Live proof of backup job IDs (docs/changes/backup-job-ids, T-021) against disposable containers.

Real LDAP + real backup-runtime UI image + the real backup_worker.py; no mocks. It shows that
  1. start returns a job id + Location and the job completes (artifact == complete.json on disk),
  2. a second start is 409 backup_busy naming the active job, and cancel kills the worker group,
  3. after the backend process alone is SIGKILLed while its worker keeps running, the job comes
     back `running` + `orphan_suspected`, new starts get 409 with that id, and once the worker
     is done the job is settled from the worker's result file.

The log source is a sparse file so a run can be made long (~tens of seconds) without disk use.
Named volumes only (bind-mounted files readable by uid 65532 are unreliable on Colima). Docker
objects carry LDAPIUM_TEST_PREFIX (default ldapium-backup-jobs-) and are removed at the end.
"""
import http.cookiejar
import json
import os
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ldap_image = os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')
ui_image = os.environ.get('LDAPIUM_UI_IMAGE', 'ldapium-ui:backup')
name = os.environ.get('LDAPIUM_TEST_PREFIX', 'ldapium-backup-jobs-') + uuid.uuid4().hex[:6]
network, ldap, ui = name + '-net', name + '-ldap', name + '-ui'
volumes = {k: name + '-' + k for k in ('config', 'data', 'etc', 'state', 'log')}
base_dn = 'dc=example,dc=org'
admin_dn = 'cn=admin,' + base_dn
password = secrets.token_urlsafe(32)
session_secret = secrets.token_hex(32)
operator = {'instance_id': 'jobs-live', 'root': '/var/lib/ldapium-backups',
  'ldap': {'url': 'ldap://backup-ldap:389', 'base_dn': base_dn, 'admin_dn': admin_dn,
           'password_file': '/etc/ldapium-backup/ldap-password', 'include_config': False},
  'log_paths': ['/var/log/ldapium-backup/audit.log'],
  'destinations': [{'id': 'local', 'name': 'Local archive', 'type': 'local'}]}
SLOW = '10G'   # sparse; gzip of zeros runs at ~0.5 GiB/s


def sh(args, **kw):
  return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout.strip()


def prepare(script, stdin=''):
  mounts = ['-v', volumes['etc'] + ':/etc/ldapium-backup', '-v', volumes['state'] + ':/var/lib/ldapium-backups', '-v', volumes['log'] + ':/var/log/ldapium-backup']
  sh(['docker', 'run', '--rm', '-i', '--user', '0', '--entrypoint', 'sh', *mounts, ui_image, '-c', script], input=stdin)


def in_ui(script):
  return subprocess.run(['docker', 'exec', ui, 'sh', '-c', script], capture_output=True, text=True).stdout.strip()


def set_log_size(size):
  prepare(f'rm -f /var/log/ldapium-backup/audit.log; truncate -s {size} /var/log/ldapium-backup/audit.log; chown 65532:65532 /var/log/ldapium-backup/audit.log')


def pids(match):
  """PIDs inside the UI container whose full command line matches the grep regex."""
  return in_ui("for p in /proc/[0-9]*; do tr '\\0' ' ' < $p/cmdline 2>/dev/null | grep -q '" + match + "' && echo ${p#/proc/}; done").split()


def wait(predicate, what, timeout=180, step=0.5):
  end = time.time() + timeout
  while time.time() < end:
    value = predicate()
    if value:
      return value
    time.sleep(step)
  raise AssertionError('timed out waiting for ' + what)


class Api:
  def __init__(self, base):
    self.base = base
    self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

  def call(self, method, path, body=None):
    request = urllib.request.Request(self.base + path, method=method, data=None if body is None else json.dumps(body).encode(),
      headers={'Origin': self.base, 'Content-Type': 'application/json'})
    try:
      with self.opener.open(request, timeout=30) as response:
        return response.status, dict(response.headers), json.loads(response.read() or b'null')
    except urllib.error.HTTPError as error:
      return error.code, dict(error.headers), json.loads(error.read() or b'null')

  def login(self):
    status, _, body = self.call('POST', '/api/login', {'identity': admin_dn, 'password': password})
    if not (status == 200):
      raise AssertionError((status, body))

  def job(self, job_id):
    status, _, body = self.call('GET', '/api/v1/backups/jobs/' + job_id)
    if not (status == 200):
      raise AssertionError((status, body))
    return body


def check(condition, message):
  if not condition:
    raise AssertionError(message)
  print('PASS: ' + message)


try:
  sh(['docker', 'network', 'create', network])
  for volume in volumes.values():
    sh(['docker', 'volume', 'create', volume])
  prepare('umask 077; cat > /etc/ldapium-backup/ldap-password', password)
  prepare('umask 077; cat > /etc/ldapium-backup/operator.json', json.dumps(operator))
  prepare('echo "audit line" > /var/log/ldapium-backup/audit.log; chown -R 65532:65532 /etc/ldapium-backup /var/lib/ldapium-backups /var/log/ldapium-backup; chmod 700 /etc/ldapium-backup /var/lib/ldapium-backups')
  with tempfile.TemporaryDirectory(prefix='ldapium-jobs-live-') as tmp:
    envfile = Path(tmp) / 'ldap.env'
    envfile.write_text('LDAP_ROOT_DN=' + base_dn + '\nLDAP_ADMIN_PASSWORD=' + password + '\n')
    envfile.chmod(0o600)
    sh(['docker', 'run', '-d', '--name', ldap, '--network', network, '--network-alias', 'backup-ldap', '--env-file', str(envfile),
        '-v', volumes['config'] + ':/etc/openldap/slapd.d', '-v', volumes['data'] + ':/var/lib/openldap/data', ldap_image])
  wait(lambda: subprocess.run(['docker', 'exec', ldap, 'ldapsearch', '-x', '-H', 'ldap://127.0.0.1', '-b', '', '-s', 'base', 'namingContexts'], capture_output=True).returncode == 0, 'LDAP readiness', 60)

  with tempfile.TemporaryDirectory(prefix='ldapium-jobs-live-') as tmp:
    envfile = Path(tmp) / 'ui.env'
    envfile.write_text('\n'.join(['LDAP_URL=ldap://backup-ldap:389', 'LDAP_BASE_DN=' + base_dn, 'COOKIE_SECURE=false', 'SESSION_SECRET=' + session_secret,
      'BACKUP_OPERATOR_CONFIG=/etc/ldapium-backup/operator.json', 'BACKUP_POLICY_PATH=/var/lib/ldapium-backups/policies.json',
      'BACKUP_ADMIN_DNS=' + admin_dn]) + '\n')
    envfile.chmod(0o600)
    # A tiny supervisor as PID 1: killing only the server process (like a crashed backend whose
    # worker survives in its own process group) must not take the whole container down.
    sh(['docker', 'run', '-d', '--name', ui, '--network', network, '-p', '127.0.0.1::8080', '--env-file', str(envfile),
        '-v', volumes['etc'] + ':/etc/ldapium-backup:ro', '-v', volumes['state'] + ':/var/lib/ldapium-backups', '-v', volumes['log'] + ':/var/log/ldapium-backup:ro',
        '--entrypoint', 'sh', ui_image, '-c', 'while :; do /server; sleep 1; done'])
  port = sh(['docker', 'port', ui, '8080/tcp']).splitlines()[0].rsplit(':', 1)[1]
  base = 'http://127.0.0.1:' + port

  def ready():
    try:
      urllib.request.urlopen(base + '/api/auth/config', timeout=1).close()
      return True
    except Exception:
      return False
  wait(ready, 'UI readiness', 60, 1)
  api = Api(base)
  api.login()

  # --- 1. start returns an id; the job completes; the record matches the disk ----------------
  status, headers, body = api.call('POST', '/api/v1/backups/jobs/logs')
  check(status == 202 and body['job_id'].startswith('job-') and headers['Location'] == '/api/v1/backups/jobs/' + body['job_id'],
        'start returned 202 with job_id=%s and Location' % body['job_id'])
  first = body['job_id']
  done = wait(lambda: (lambda j: j if j['status'] != 'running' else None)(api.job(first)), 'first job to finish', 60)
  check(done['status'] == 'succeeded' and done['local']['verified'] and done['destinations'] == [{'id': 'local', 'status': 'succeeded'}], 'job succeeded with a per-destination result')
  run_id = done['artifact']['run_id']
  manifest = json.loads(in_ui('cat /var/lib/ldapium-backups/logs/%s/complete.json' % run_id))
  check({f['name']: f['sha256'] for f in done['artifact']['files']} == manifest['sha256'] and manifest['job_id'] == first,
        'artifact files/sha256 equal the on-disk complete.json (which carries job_id)')
  _, _, view = api.call('GET', '/api/v1/backups')
  check(view['states']['logs']['run_id'] == run_id and view['states']['logs']['status'] == 'succeeded', 'GET /api/v1/backups states.logs agrees (run_id %s)' % run_id)
  result_mode = in_ui('stat -c "%a" /var/lib/ldapium-backups/.results/' + first + '.json')
  check(result_mode == '600', 'worker left .results/<job_id>.json with mode 600')
  _, _, listing = api.call('GET', '/api/v1/backups/jobs?kind=logs&status=succeeded')
  check([j['job_id'] for j in listing['jobs']] == [first], 'job list filters by kind/status')

  # --- 2. busy returns the active id; cancel terminates the worker --------------------------
  set_log_size(SLOW)
  _, _, second = api.call('POST', '/api/v1/backups/jobs/logs')
  second = second['job_id']
  wait(lambda: pids('backup_worke[r].py --config'), 'worker process to start', 30)
  status, _, env = api.call('POST', '/api/v1/backups/jobs/data')
  check(status == 409 and env['code'] == 'backup_busy' and env['active_job_id'] == second and env['active_kind'] == 'logs' and env['retryable'] is True and env['requestId'],
        'second start is 409 backup_busy naming active job %s' % second)
  status, _, cancelled = api.call('POST', '/api/v1/backups/jobs/%s/cancel' % second)
  check(status == 202 and cancelled['cancel_requested_at'], 'cancel accepted (202)')
  final = wait(lambda: (lambda j: j if j['status'] != 'running' else None)(api.job(second)), 'cancelled job to finish', 60)
  check(final['status'] == 'cancelled' and final['staging_cleanup'] == 'done', 'job ended cancelled, staging cleaned by the worker (staging_cleanup=done)')
  check(not pids('backup_worke[r].py --config'), 'no worker process left after cancel')
  check(in_ui('ls -A /var/lib/ldapium-backups/logs | grep -c "^[.]pending-" || true') == '0', 'no .pending-* staging directory remains')
  status, _, again = api.call('POST', '/api/v1/backups/jobs/%s/cancel' % second)
  check(status == 200, 'second cancel is idempotent (200)')
  status, _, env = api.call('POST', '/api/v1/backups/jobs/%s/cancel' % first)
  check(status == 409 and env['code'] == 'job_not_cancellable', 'cancelling a finished job is 409 job_not_cancellable')
  status, _, env = api.call('GET', '/api/v1/backups/jobs/job-20200101T000000Z-000000000000')
  check(status == 404 and env['code'] == 'job_not_found', 'unknown job id is 404 job_not_found')

  # --- 3. orphan: only the backend dies; the worker keeps the lock --------------------------
  _, _, third = api.call('POST', '/api/v1/backups/jobs/logs')
  third = third['job_id']
  worker = wait(lambda: pids('backup_worke[r].py --config'), 'orphan-to-be worker', 30)[0]
  server = [p for p in pids('^/server $')]
  check(len(server) == 1, 'found the server process (pid %s)' % server[0])
  in_ui('kill -9 ' + server[0])
  wait(lambda: pids('^/server $') and pids('^/server $') != server and ready(), 'supervisor to restart the server', 60, 1)
  check(worker in pids('backup_worke[r].py --config'), 'the worker survived the backend SIGKILL (pid %s)' % worker)
  api = Api(base)
  api.login()
  job = api.job(third)
  check(job['status'] == 'running' and job['orphan_suspected'] is True, 'after restart the job is running + orphan_suspected, not abandoned')
  status, _, env = api.call('POST', '/api/v1/backups/jobs/logs')
  check(status == 409 and env['code'] == 'backup_busy' and env['active_job_id'] == third, 'start during the orphan is 409 naming the orphan job %s' % third)
  status, _, env = api.call('POST', '/api/v1/backups/jobs/%s/cancel' % third)
  check(status == 409 and env['code'] == 'job_not_cancellable', 'an orphan cannot be cancelled (its pid is unknown), honestly 409')
  settled = wait(lambda: (lambda j: j if j['status'] != 'running' else None)(api.job(third)), 'orphan to settle after the worker ends', 240, 2)
  check(settled['status'] == 'succeeded' and not settled.get('orphan_suspected') and settled['artifact']['run_id'] and settled['local']['verified'],
        'orphan settled as succeeded from the worker result file (run %s)' % settled['artifact']['run_id'])
  _, _, view = api.call('GET', '/api/v1/backups')
  check(view['running'] is False and view['states']['logs']['status'] == 'succeeded', 'running cleared; new runs are possible again')
  set_log_size('1k')
  status, _, body = api.call('POST', '/api/v1/backups/jobs/logs')
  check(status == 202, 'a new start is accepted after the orphan settled')
  wait(lambda: api.job(body['job_id'])['status'] != 'running', 'follow-up job', 60)
  logs = subprocess.run(['docker', 'logs', ui], capture_output=True, text=True)
  text = logs.stdout + logs.stderr
  backup_lines = '\n'.join(line for line in text.splitlines() if ' backup_' in line)
  check('backup_started job_id=' + third in backup_lines and 'orphan=true result_source=file' in backup_lines and admin_dn not in backup_lines and password not in text,
        'backup log lines carry job ids and the orphan settlement (result_source=file) but no DN; the password appears nowhere')
  print('ALL LIVE CHECKS PASSED')
except Exception:
  logs = subprocess.run(['docker', 'logs', '--tail', '80', ui], capture_output=True, text=True)
  print((logs.stdout + logs.stderr).replace(password, '[redacted]'))
  raise
finally:
  subprocess.run(['docker', 'rm', '-f', ui, ldap], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  for volume in volumes.values():
    subprocess.run(['docker', 'volume', 'rm', volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
