#!/usr/bin/env python3
"""Live proof of remote destinations (S3, FTP, SFTP), SIGKILL-after-grace, and deadline.

Covers Issue #255 / docs/changes/backup-job-ids (T-021 remaining scope):
  1. Remote destinations: S3 (MinIO), FTP (delfer/alpine-ftp-server), and SFTP (atmoz/sftp)
     in throwaway containers. A backup job succeeds to each destination, and the result file
     lands in .results/<job_id>.json (mode 0600) with remote artifacts verified.
  2. SIGKILL-after-grace path: A worker process ignoring SIGTERM is terminated by SIGKILL after
     the 10-second grace period; the job settles as cancelled with staging_cleanup=pending.
  3. Deadline path: A worker exceeding the configured BACKUP_JOB_TIMEOUT_LOGS=1m deadline is
     cancelled by context timeout and recorded as failed with code deadline_exceeded.

All Docker objects use LDAPIUM_TEST_PREFIX (default ldapium-jobs-remotes-255-) and are removed on exit.
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
ui_image = os.environ.get('LDAPIUM_UI_IMAGE', 'ldapium-ui:e2e')
# Remote images are pinned by digest (recorded in docs/changes/backup-job-ids/EVIDENCE.md).
minio_image = os.environ.get('MINIO_IMAGE', 'alpine/minio@sha256:cf23643a6cf9ce159c57643ceb88279e431262282428c9e0bf3a7ef1a97e84b4')
ftp_image = os.environ.get('FTP_IMAGE', 'delfer/alpine-ftp-server@sha256:60bb774d8408d9d4d5c74d05d1c086a34ce192c6c1a142ffac268cac0dbc6fac')
sftp_image = os.environ.get('SFTP_IMAGE', 'atmoz/sftp@sha256:6d41b9200f8115ce925bbd295376cb3c6b72634a267f41946e5aee4efe482186')

prefix = os.environ.get('LDAPIUM_TEST_PREFIX', 'ldapium-jobs-remotes-255-') + uuid.uuid4().hex[:6]
network = prefix + '-net'
ldap = prefix + '-ldap'
ui = prefix + '-ui'
minio = prefix + '-minio'
ftp = prefix + '-ftp'
sftp = prefix + '-sftp'

volumes = {k: prefix + '-' + k for k in ('config', 'data', 'etc', 'state', 'log', 'minio', 'ftp', 'sftp', 'sftpconf')}
base_dn = 'dc=example,dc=org'
admin_dn = 'cn=admin,' + base_dn
ldap_password = secrets.token_urlsafe(32)
remote_password = secrets.token_urlsafe(16)
session_secret = secrets.token_hex(32)
secret_values = [ldap_password, remote_password, session_secret]

operator = {
  'instance_id': 'jobs-live-remotes-255',
  'root': '/var/lib/ldapium-backups',
  'ldap': {
    'url': f'ldap://{ldap}:389',
    'base_dn': base_dn,
    'admin_dn': admin_dn,
    'password_file': '/etc/ldapium-backup/ldap-password',
    'include_config': False,
  },
  'log_paths': ['/var/log/ldapium-backup/audit.log'],
  'rclone_config': '/etc/ldapium-backup/rclone.conf',
  'destinations': [
    {'id': 'local', 'name': 'Local archive', 'type': 'local'},
    {'id': 's3-dest', 'name': 'S3 Remote', 'type': 's3', 'remote': 's3', 'prefix': 'bucket/backups'},
    {'id': 'ftp-dest', 'name': 'FTP Remote', 'type': 'ftp', 'remote': 'ftp', 'prefix': 'backups', 'allow_plaintext': True},
    {'id': 'sftp-dest', 'name': 'SFTP Remote', 'type': 'sftp', 'remote': 'sftp', 'prefix': 'backups'},
  ],
}

WORKER_WRAPPER = """#!/usr/bin/env python3
import os
import shutil
import signal
import sys
import time

FLAG_IGNORE = '/etc/ldapium-backup/ignore-sigterm'
FLAG_DEADLINE = '/etc/ldapium-backup/simulate-deadline'

if os.path.exists(FLAG_IGNORE):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.makedirs('/var/lib/ldapium-backups/logs/.pending-sigkill-test', exist_ok=True)
    with open('/var/lib/ldapium-backups/worker.started', 'w') as f:
        f.write(str(os.getpid()))
    while True:
        time.sleep(1)

if os.path.exists(FLAG_DEADLINE):
    # Stand-in for the real worker's staging dir and SIGTERM cleanup (D217-6).
    staging = '/var/lib/ldapium-backups/logs/.pending-deadline-test'
    os.makedirs(staging, exist_ok=True)

    def on_term(signum, frame):
        shutil.rmtree(staging, ignore_errors=True)
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, on_term)
    with open('/var/lib/ldapium-backups/worker.started', 'w') as f:
        f.write(str(os.getpid()))
    time.sleep(90)
    sys.exit(0)

real_worker = '/opt/ldapium/backup-tools/backup_worker.py'
os.execv('/usr/bin/python3', ['/usr/bin/python3', real_worker] + sys.argv[1:])
"""


def mask(text):
  text = str(text)
  for secret in secret_values:
    text = text.replace(secret, '***')
  return text


def sh(args, **kw):
  # check=True would embed the whole argv in the traceback; re-raise with masked stderr only.
  try:
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout.strip()
  except subprocess.CalledProcessError as error:
    raise RuntimeError('%s failed (exit %d): %s' % (' '.join(args[:3]), error.returncode, mask(error.stderr).strip())) from None


def prepare(script, stdin=''):
  mounts = [
    '-v', volumes['etc'] + ':/etc/ldapium-backup',
    '-v', volumes['state'] + ':/var/lib/ldapium-backups',
    '-v', volumes['log'] + ':/var/log/ldapium-backup',
  ]
  sh(['docker', 'run', '--rm', '-i', '--user', '0', '--entrypoint', 'sh', *mounts, ui_image, '-c', script], input=stdin)


def in_ui(script):
  return subprocess.run(['docker', 'exec', ui, 'sh', '-c', script], capture_output=True, text=True).stdout.strip()


def in_container(cid, script):
  # Fails on a non-zero exit: `test -f` prints nothing either way, so output alone proves nothing.
  result = subprocess.run(['docker', 'exec', cid, 'sh', '-c', script], capture_output=True, text=True)
  if result.returncode != 0:
    raise RuntimeError('in_container(%s) exit %d: %s' % (cid, result.returncode, mask(result.stderr).strip()))
  return result.stdout.strip()


def remote_artifact(cid, path):
  # Returns the artifact's size in bytes; raises if the file is missing or empty.
  return int(in_container(cid, f'test -s {path} && wc -c < {path}'))


def raises(fn):
  try:
    fn()
  except RuntimeError:
    return True
  return False


def write_env(directory, name, lines):
  path = Path(directory) / name
  path.write_text('\n'.join(lines) + '\n')
  path.chmod(0o600)
  return str(path)


def pids(match):
  return in_ui("for p in /proc/[0-9]*; do tr '\\0' ' ' < $p/cmdline 2>/dev/null | grep -q '" + match + "' && echo ${p#/proc/}; done").split()


def wait(predicate, what, timeout=120, step=0.5):
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

  def call(self, method, path, body=None, headers=None):
    hdrs = {'Origin': self.base, 'Content-Type': 'application/json'}
    if headers:
      hdrs.update(headers)
    request = urllib.request.Request(
      self.base + path,
      method=method,
      data=None if body is None else json.dumps(body).encode(),
      headers=hdrs,
    )
    try:
      with self.opener.open(request, timeout=30) as response:
        return response.status, dict(response.headers), json.loads(response.read() or b'null')
    except urllib.error.HTTPError as error:
      return error.code, dict(error.headers), json.loads(error.read() or b'null')

  def login(self):
    status, _, body = self.call('POST', '/api/login', {'identity': admin_dn, 'password': ldap_password})
    if not (status == 200):
      raise AssertionError((status, body))

  def job(self, job_id):
    status, _, body = self.call('GET', '/api/v1/backups/jobs/' + job_id)
    if not (status == 200):
      raise AssertionError((status, body))
    return body

  def set_destinations(self, kind, destinations):
    status, _, view = self.call('GET', '/api/v1/backups')
    if not (status == 200):
      raise AssertionError('status == 200')
    rev = view['policies']['revision']
    policies = view['policies']
    policies[kind]['destinations'] = destinations
    body = {'data': policies['data'], 'logs': policies['logs']}
    status, _, saved = self.call('PUT', '/api/v1/backups/policies', body, headers={'If-Match': f'"{rev}"'})
    if not (status == 200):
      raise AssertionError((status, saved))
    return saved


def check(condition, message):
  if not condition:
    raise AssertionError(message)
  print('PASS: ' + message)


try:
  sh(['docker', 'network', 'create', network])
  for vol in volumes.values():
    sh(['docker', 'volume', 'create', vol])

  # Obscure remote password with rclone from the UI image
  obscured = sh(['docker', 'run', '--rm', '-i', '--entrypoint', 'rclone', ui_image, 'obscure', '-'], input=remote_password)
  secret_values.append(obscured)

  # Prepare configuration files in /etc/ldapium-backup
  prepare('umask 077; cat > /etc/ldapium-backup/ldap-password', ldap_password)
  prepare('umask 077; cat > /etc/ldapium-backup/operator.json', json.dumps(operator))
  prepare('cat > /etc/ldapium-backup/worker-wrapper.py && chmod 755 /etc/ldapium-backup/worker-wrapper.py', WORKER_WRAPPER)

  rclone_conf = f"""[s3]
type = s3
provider = Other
access_key_id = admin
secret_access_key = {remote_password}
endpoint = http://{minio}:9000
force_path_style = true

[ftp]
type = ftp
host = {ftp}
port = 21
user = backup
pass = {obscured}

[sftp]
type = sftp
host = {sftp}
port = 22
user = backup
pass = {obscured}
known_hosts_file = /etc/ldapium-backup/known_hosts
"""
  prepare('umask 077; cat > /etc/ldapium-backup/rclone.conf', rclone_conf)
  prepare('echo "audit log line for backup testing" > /var/log/ldapium-backup/audit.log')
  prepare('chown -R 65532:65532 /etc/ldapium-backup /var/lib/ldapium-backups /var/log/ldapium-backup; chmod 700 /etc/ldapium-backup /var/lib/ldapium-backups')

  # 1. Start LDAP container
  with tempfile.TemporaryDirectory(prefix='ldapium-env-') as tmp:
    envfile = Path(tmp) / 'ldap.env'
    envfile.write_text(f'LDAP_ROOT_DN={base_dn}\nLDAP_ADMIN_PASSWORD={ldap_password}\n')
    envfile.chmod(0o600)
    sh([
      'docker', 'run', '-d', '--name', ldap, '--network', network, '--network-alias', ldap,
      '--env-file', str(envfile),
      '-v', volumes['config'] + ':/etc/openldap/slapd.d',
      '-v', volumes['data'] + ':/var/lib/openldap/data',
      ldap_image,
    ])
  wait(
    lambda: subprocess.run(
      ['docker', 'exec', ldap, 'ldapsearch', '-x', '-H', 'ldap://127.0.0.1', '-b', '', '-s', 'base', 'namingContexts'],
      capture_output=True,
    ).returncode == 0,
    'LDAP readiness',
    60,
  )

  # 2. Start MinIO container
  with tempfile.TemporaryDirectory(prefix='ldapium-minio-env-') as tmp:
    sh([
      'docker', 'run', '-d', '--name', minio, '--network', network, '--network-alias', minio,
      '--user', '0',
      '--env-file', write_env(tmp, 'minio.env', ['MINIO_ROOT_USER=admin', f'MINIO_ROOT_PASSWORD={remote_password}']),
      '-v', volumes['minio'] + ':/data',
      minio_image, 'server', '/data',
    ])
  wait(
    lambda: subprocess.run(['docker', 'exec', minio, 'mkdir', '-p', '/data/bucket'], capture_output=True).returncode == 0,
    'MinIO bucket creation',
    30,
  )

  # 3. Start FTP container
  with tempfile.TemporaryDirectory(prefix='ldapium-ftp-env-') as tmp:
    sh([
      'docker', 'run', '-d', '--name', ftp, '--network', network, '--network-alias', ftp,
      '--env-file', write_env(tmp, 'ftp.env', [f'USERS=backup|{remote_password}']),
      '-v', volumes['ftp'] + ':/ftp',
      ftp_image,
    ])
  wait(lambda: 'running' in sh(['docker', 'inspect', ftp, '--format', '{{.State.Status}}']), 'FTP readiness', 30)

  # 4. Start SFTP container
  # The user definition (with the password) goes through a root-owned volume file, not argv.
  sh(['docker', 'run', '--rm', '-i', '--user', '0', '--entrypoint', 'sh', '-v', volumes['sftpconf'] + ':/c', ui_image, '-c',
      'umask 077; cat > /c/users.conf'], input=f'backup:{remote_password}:::backups\n')
  sh([
    'docker', 'run', '-d', '--name', sftp, '--network', network, '--network-alias', sftp,
    '-v', volumes['sftp'] + ':/home/backup',
    '-v', volumes['sftpconf'] + ':/etc/sftp',
    sftp_image,
  ])
  wait(lambda: subprocess.run(['docker', 'exec', sftp, 'test', '-f', '/etc/ssh/ssh_host_ed25519_key.pub'], capture_output=True).returncode == 0, 'SFTP ed25519 host key generation', 30)
  wait(lambda: subprocess.run(['docker', 'exec', sftp, 'test', '-f', '/etc/ssh/ssh_host_rsa_key.pub'], capture_output=True).returncode == 0, 'SFTP RSA host key generation', 30)
  ed_key = in_container(sftp, 'cat /etc/ssh/ssh_host_ed25519_key.pub').strip()
  rsa_key = in_container(sftp, 'cat /etc/ssh/ssh_host_rsa_key.pub').strip()
  known_hosts = f"{sftp} {ed_key}\n[{sftp}]:22 {ed_key}\n{sftp} {rsa_key}\n[{sftp}]:22 {rsa_key}\n"
  prepare('cat > /etc/ldapium-backup/known_hosts && chmod 600 /etc/ldapium-backup/known_hosts && chown 65532:65532 /etc/ldapium-backup/known_hosts', known_hosts)

  # 5. Start UI container with BACKUP_JOB_TIMEOUT_LOGS=1m
  with tempfile.TemporaryDirectory(prefix='ldapium-ui-env-') as tmp:
    envfile = Path(tmp) / 'ui.env'
    envfile.write_text('\n'.join([
      f'LDAP_URL=ldap://{ldap}:389',
      f'LDAP_BASE_DN={base_dn}',
      'COOKIE_SECURE=false',
      f'SESSION_SECRET={session_secret}',
      'BACKUP_OPERATOR_CONFIG=/etc/ldapium-backup/operator.json',
      'BACKUP_POLICY_PATH=/var/lib/ldapium-backups/policies.json',
      f'BACKUP_ADMIN_DNS={admin_dn}',
      'BACKUP_WORKER_PATH=/etc/ldapium-backup/worker-wrapper.py',
      'BACKUP_JOB_TIMEOUT_LOGS=1m',
      'BACKUP_JOB_TIMEOUT_DATA=2h',
    ]) + '\n')
    envfile.chmod(0o600)
    sh([
      'docker', 'run', '-d', '--name', ui, '--network', network, '-p', '127.0.0.1::8080',
      '--env-file', str(envfile),
      '-v', volumes['etc'] + ':/etc/ldapium-backup',
      '-v', volumes['state'] + ':/var/lib/ldapium-backups',
      '-v', volumes['log'] + ':/var/log/ldapium-backup:ro',
      '--entrypoint', 'sh', ui_image, '-c', 'while :; do /server; sleep 1; done',
    ])

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

  # =========================================================================
  # Phase 1: Remote destinations live (S3 MinIO, FTP, SFTP)
  # =========================================================================
  print('--- Phase 1: Remote destinations (S3, FTP, SFTP) ---')

  # Negative self-test: the artifact check must FAIL for a missing path and a missing container,
  # otherwise the remote checks below would be vacuous.
  missing = f'/nonexistent-{uuid.uuid4().hex}/complete.json'
  for cid in (minio, ftp, sftp):
    check(raises(lambda cid=cid: remote_artifact(cid, missing)), f'negative self-test: artifact check fails for a missing path on {cid}')
  check(raises(lambda: remote_artifact(prefix + '-no-such-container', missing)), 'negative self-test: artifact check fails for a missing container')

  # 1a. S3 destination
  api.set_destinations('logs', ['local', 's3-dest'])
  status, _, body = api.call('POST', '/api/v1/backups/jobs/logs')
  check(status == 202 and body['job_id'].startswith('job-'), 'S3 backup job accepted (202)')
  s3_job_id = body['job_id']
  s3_done = wait(lambda: (lambda j: j if j['status'] != 'running' else None)(api.job(s3_job_id)), 'S3 backup completion', 60)
  check(s3_done['status'] == 'succeeded' and s3_done['local']['verified'], 'S3 backup job completed with status=succeeded')
  check(any(d['id'] == 's3-dest' and d['status'] == 'succeeded' for d in s3_done['destinations']), 'S3 per-destination outcome is succeeded')
  s3_result_mode = in_ui(f'stat -c "%a" /var/lib/ldapium-backups/.results/{s3_job_id}.json')
  check(s3_result_mode == '600', f'S3 job left .results/{s3_job_id}.json with mode 600')
  s3_run_id = s3_done['artifact']['run_id']
  check(
    remote_artifact(minio, f'/data/bucket/backups/jobs-live-remotes-255/logs/{s3_run_id}/complete.json/xl.meta') > 0,
    f'S3 MinIO storage contains non-empty complete.json (xl.meta) (run {s3_run_id})',
  )

  # 1b. FTP destination
  api.set_destinations('logs', ['local', 'ftp-dest'])
  status, _, body = api.call('POST', '/api/v1/backups/jobs/logs')
  check(status == 202 and body['job_id'].startswith('job-'), 'FTP backup job accepted (202)')
  ftp_job_id = body['job_id']
  ftp_done = wait(lambda: (lambda j: j if j['status'] != 'running' else None)(api.job(ftp_job_id)), 'FTP backup completion', 60)
  check(ftp_done['status'] == 'succeeded' and ftp_done['local']['verified'], 'FTP backup job completed with status=succeeded')
  check(any(d['id'] == 'ftp-dest' and d['status'] == 'succeeded' for d in ftp_done['destinations']), 'FTP per-destination outcome is succeeded')
  ftp_result_mode = in_ui(f'stat -c "%a" /var/lib/ldapium-backups/.results/{ftp_job_id}.json')
  check(ftp_result_mode == '600', f'FTP job left .results/{ftp_job_id}.json with mode 600')
  ftp_run_id = ftp_done['artifact']['run_id']
  check(
    remote_artifact(ftp, f'/ftp/backup/backups/jobs-live-remotes-255/logs/{ftp_run_id}/complete.json') > 0,
    f'FTP server storage contains verified complete.json (run {ftp_run_id})',
  )

  # 1c. SFTP destination
  api.set_destinations('logs', ['local', 'sftp-dest'])
  status, _, body = api.call('POST', '/api/v1/backups/jobs/logs')
  check(status == 202 and body['job_id'].startswith('job-'), 'SFTP backup job accepted (202)')
  sftp_job_id = body['job_id']
  sftp_done = wait(lambda: (lambda j: j if j['status'] != 'running' else None)(api.job(sftp_job_id)), 'SFTP backup completion', 60)
  check(sftp_done['status'] == 'succeeded' and sftp_done['local']['verified'], 'SFTP backup job completed with status=succeeded')
  check(any(d['id'] == 'sftp-dest' and d['status'] == 'succeeded' for d in sftp_done['destinations']), 'SFTP per-destination outcome is succeeded')
  sftp_result_mode = in_ui(f'stat -c "%a" /var/lib/ldapium-backups/.results/{sftp_job_id}.json')
  check(sftp_result_mode == '600', f'SFTP job left .results/{sftp_job_id}.json with mode 600')
  sftp_run_id = sftp_done['artifact']['run_id']
  check(
    remote_artifact(sftp, f'/home/backup/backups/jobs-live-remotes-255/logs/{sftp_run_id}/complete.json') > 0,
    f'SFTP server storage contains verified complete.json (run {sftp_run_id})',
  )

  # 1d. Combined: all 3 remote destinations + local
  api.set_destinations('logs', ['local', 's3-dest', 'ftp-dest', 'sftp-dest'])
  status, _, body = api.call('POST', '/api/v1/backups/jobs/logs')
  check(status == 202, 'Combined remote backup job accepted (202)')
  all_job_id = body['job_id']
  all_done = wait(lambda: (lambda j: j if j['status'] != 'running' else None)(api.job(all_job_id)), 'Combined backup completion', 60)
  check(all_done['status'] == 'succeeded' and len(all_done['destinations']) == 4, 'Combined job succeeded across all 4 destinations')
  for dest_name in ('local', 's3-dest', 'ftp-dest', 'sftp-dest'):
    check(any(d['id'] == dest_name and d['status'] == 'succeeded' for d in all_done['destinations']), f'Combined destination {dest_name} is succeeded')

  # =========================================================================
  # Phase 2: SIGKILL-after-grace path live
  # =========================================================================
  print('--- Phase 2: SIGKILL-after-grace path ---')
  api.set_destinations('logs', ['local'])
  in_ui('touch /etc/ldapium-backup/ignore-sigterm; rm -f /var/lib/ldapium-backups/worker.started')

  status, _, body = api.call('POST', '/api/v1/backups/jobs/logs')
  check(status == 202, 'SIGKILL-test job started (202)')
  sigkill_job_id = body['job_id']

  wait(lambda: in_ui('test -f /var/lib/ldapium-backups/worker.started && echo ok') == 'ok', 'worker process to start ignoring SIGTERM', 30)
  worker_pid = in_ui('cat /var/lib/ldapium-backups/worker.started').strip()
  check(in_ui(f'kill -0 {worker_pid} 2>/dev/null && echo alive') == 'alive', f'worker process active with pid {worker_pid}')

  t_cancel = time.time()
  status, _, cancelled_resp = api.call('POST', f'/api/v1/backups/jobs/{sigkill_job_id}/cancel')
  check(status == 202 and cancelled_resp.get('cancel_requested_at'), 'cancel accepted (202) with cancel_requested_at')

  sigkill_done = wait(lambda: (lambda j: j if j['status'] != 'running' else None)(api.job(sigkill_job_id)), 'SIGKILL termination after grace period', 60)
  duration = time.time() - t_cancel
  check(duration >= 9.5, f'escalation to SIGKILL waited out the 10s grace period (elapsed {duration:.1f}s)')
  check(sigkill_done['status'] == 'cancelled', f'job status is cancelled: {sigkill_done["status"]}')
  check(sigkill_done['staging_cleanup'] == 'pending', f'SIGKILLed worker left staging_cleanup=pending: {sigkill_done["staging_cleanup"]}')
  check(in_ui(f'kill -0 {worker_pid} 2>/dev/null || echo dead') == 'dead', f'worker process {worker_pid} was killed by SIGKILL')

  check(in_ui('ls -d /var/lib/ldapium-backups/logs/.pending-* 2>/dev/null | wc -l') == '1', 'SIGKILL leftover staging directory still exists and is reported pending')
  # Removing the leftover staging directory causes subsequent reads to report staging_cleanup=done (computed)
  in_ui('rm -rf /var/lib/ldapium-backups/logs/.pending-sigkill-test /etc/ldapium-backup/ignore-sigterm /var/lib/ldapium-backups/worker.started')
  refreshed = api.job(sigkill_job_id)
  check(refreshed['staging_cleanup'] == 'done', 'staging_cleanup dynamically evaluates to done after pending staging removed')

  # =========================================================================
  # Phase 3: Deadline path live (BACKUP_JOB_TIMEOUT_LOGS=1m)
  # =========================================================================
  print('--- Phase 3: Deadline path (BACKUP_JOB_TIMEOUT_LOGS=1m) ---')
  in_ui('touch /etc/ldapium-backup/simulate-deadline; rm -f /var/lib/ldapium-backups/worker.started')

  t_start = time.time()
  status, _, body = api.call('POST', '/api/v1/backups/jobs/logs')
  check(status == 202, 'Deadline-test job started (202)')
  deadline_job_id = body['job_id']
  job_record = api.job(deadline_job_id)
  check('deadline_at' in job_record and job_record['deadline_at'] is not None, f'job record carries deadline_at: {job_record.get("deadline_at")}')

  wait(lambda: in_ui('test -f /var/lib/ldapium-backups/worker.started && echo ok') == 'ok', 'slow worker to start', 30)
  slow_pid = in_ui('cat /var/lib/ldapium-backups/worker.started').strip()
  check(in_ui(f'kill -0 {slow_pid} 2>/dev/null && echo alive') == 'alive', f'slow worker process active with pid {slow_pid}')
  check(in_ui('test -d /var/lib/ldapium-backups/logs/.pending-deadline-test && echo ok') == 'ok', 'deadline worker created a staging directory while running')

  deadline_done = wait(lambda: (lambda j: j if j['status'] != 'running' else None)(api.job(deadline_job_id)), 'deadline termination (1m timeout)', 90)
  total_time = time.time() - t_start
  check(58.0 <= total_time <= 75.0, f'job was cancelled near the 60s deadline boundary (elapsed {total_time:.1f}s)')
  check(deadline_done['status'] == 'failed', f'job status is failed: {deadline_done["status"]}')
  check(deadline_done.get('error', {}).get('code') == 'deadline_exceeded', f'error.code is deadline_exceeded: {deadline_done.get("error")}')
  check(deadline_done.get('error', {}).get('message') == 'backup job deadline exceeded', f'error.message matches catalog: {deadline_done.get("error")}')
  check(deadline_done['staging_cleanup'] == 'done', 'staging_cleanup is done on deadline SIGTERM exit')
  check(in_ui('ls -A /var/lib/ldapium-backups/logs | grep -c "^[.]pending-" || true') == '0', 'deadline worker staging directory was removed by its SIGTERM handler')
  check(in_ui(f'kill -0 {slow_pid} 2>/dev/null || echo dead') == 'dead', f'slow worker process {slow_pid} terminated upon deadline')

  _, _, view = api.call('GET', '/api/v1/backups')
  check(view['states']['logs']['status'] == 'failed', 'GET /api/v1/backups states.logs.status agrees (failed)')

  in_ui('rm -f /etc/ldapium-backup/simulate-deadline /var/lib/ldapium-backups/worker.started')

  # =========================================================================
  # Follow-up health check: fresh job succeeds
  # =========================================================================
  status, _, follow_up = api.call('POST', '/api/v1/backups/jobs/logs')
  check(status == 202, 'follow-up job started successfully')
  follow_done = wait(lambda: (lambda j: j if j['status'] != 'running' else None)(api.job(follow_up['job_id'])), 'follow-up job completion', 60)
  check(follow_done['status'] == 'succeeded', 'controller remains healthy and follow-up job succeeded')

  print('ALL LIVE CHECKS PASSED (Remote destinations S3/FTP/SFTP, SIGKILL-after-grace, and Deadline paths verified)')

except Exception:
  logs = subprocess.run(['docker', 'logs', '--tail', '80', ui], capture_output=True, text=True)
  print('=== UI LOGS ===\n' + mask(logs.stdout + logs.stderr))
  raise
finally:
  for c in (ui, ldap, minio, ftp, sftp):
    subprocess.run(['docker', 'rm', '-fv', c], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  for vol in volumes.values():
    subprocess.run(['docker', 'volume', 'rm', vol], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
