"""Shared harness for the machine bearer live scripts (#214, staged unit 5a).

Used by scripts/test/test-machine-keycloak-live.py, ...-keycloak-settings-live.py,
...-jwks-live.py and ...-revocation-drill.py. Not a test by itself.

What it provides (everything real, no mocking framework):
  - Live: container/network registry with EXIT/INT/TERM cleanup (every name is
    registered BEFORE the object is created), a global deadline watchdog,
    0700 secret files (secrets never on argv), env-overridable image names.
  - Slapd: a real slapd container (accesslog on), seeded directory, the package's
    ACL LDIF applied from scripts/test/fixtures/machine-acl/, bind counting
    through the slapd accesslog (the directory's own view).
  - Keycloak: the pinned image in start-dev with a FIXED hostname (so `iss` and
    `jwks_uri` are stable whichever address the script uses), admin REST helper.
  - Signer: a private key imported into the realm (Keycloak `rsa` key provider)
    so the script can sign negative tokens that differ from a real token in
    exactly one claim and still verify against the real JWKS.
  - UI containers and a small HTTP client.
"""
import atexit
import base64
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

REPO = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = REPO / 'scripts/test/fixtures/machine-acl'

BASE_DN = 'dc=example,dc=org'
ADMIN_DN = 'cn=admin,' + BASE_DN
MACHINE_DN = 'uid=machine,ou=system,' + BASE_DN
OVER_DN = 'uid=machine-over,ou=system,' + BASE_DN
HUMAN_DN = 'uid=human,ou=people,' + BASE_DN
SEED_USER_DN = 'uid=u01,ou=people,' + BASE_DN

READER = ['directory.users.read', 'directory.groups.read', 'directory.tree.read', 'directory.entry.read',
          'directory.policies.read', 'server.monitor.read']
AUDIT = ['server.monitor.read', 'audit.read', 'directory.entry.read']
ALL_SCOPES = READER + ['audit.read', 'server.settings.read']

AUDIENCE = 'ldapium-api'


def b64u(raw):
  return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def b64u_decode(text):
  return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def jbody(text):
  try:
    return json.loads(text)
  except ValueError:
    return {}


def tamper(token):
  head, body, sig = token.split('.')
  return '.'.join([head, body, sig[:3] + ('B' if sig[3] == 'A' else 'A') + sig[4:]])


def decode_jwt(token):
  head, body, _ = token.split('.')
  return json.loads(b64u_decode(head)), json.loads(b64u_decode(body))


def free_port():
  s = socket.socket()
  s.bind(('127.0.0.1', 0))
  port = s.getsockname()[1]
  s.close()
  return port


class Live:
  def __init__(self, default_prefix, deadline_seconds=1500):
    self.ldap_image = os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')
    self.ui_image = os.environ.get('LDAPIUM_UI_IMAGE', 'ldapium-ui:e2e')
    self.keycloak_image = os.environ.get('KEYCLOAK_IMAGE', 'quay.io/keycloak/keycloak:26.7.4')
    self.run_id = uuid.uuid4().hex[:6]
    self.name_prefix = os.environ.get('LDAPIUM_TEST_PREFIX', default_prefix) + self.run_id
    self.network = self.name_prefix + '-net'
    self.containers = []
    self.networks = []
    self.tmp_dirs = []
    self.closers = []
    self.secret_values = []  # masked in logs and scanned for in container logs
    self.start = time.monotonic()
    self.deadline = float(os.environ.get('LDAPIUM_TEST_DEADLINE', deadline_seconds))
    self.checks = 0
    atexit.register(self.cleanup)
    for sig in (signal.SIGTERM, signal.SIGINT):
      signal.signal(sig, lambda *_: sys.exit(130))
    watchdog = threading.Timer(self.deadline, self._deadline_hit)
    watchdog.daemon = True
    watchdog.start()
    self.secret_dir = tempfile.mkdtemp(prefix='mk-secrets-')
    self.tmp_dirs.append(self.secret_dir)
    os.chmod(self.secret_dir, stat.S_IRWXU)

  def _deadline_hit(self):
    print(f'ERROR: deadline of {self.deadline:.0f}s exceeded, aborting', file=sys.stderr, flush=True)
    os.kill(os.getpid(), signal.SIGTERM)

  # ---- reporting -------------------------------------------------------------

  def check(self, condition, message):
    assert condition, message
    self.checks += 1
    print('PASS: ' + message, flush=True)

  def mask(self, text):
    text = text if isinstance(text, str) else str(text)
    for secret in self.secret_values:
      text = text.replace(secret, '***')
    return text

  def secret(self, value):
    self.secret_values.append(value)
    return value

  def run(self, cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

  def wait_until(self, predicate, what, timeout=30.0, interval=0.2):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
      if predicate():
        return
      time.sleep(interval)
    raise AssertionError(f'timed out after {timeout}s waiting for {what}')

  def elapsed(self):
    return time.monotonic() - self.start

  # ---- cleanup ---------------------------------------------------------------

  def cleanup(self):
    for closer in self.closers:
      try:
        closer()
      except Exception:
        pass
    for c in self.containers:
      self.run(['docker', 'rm', '-fv', c])
    for n in self.networks:
      self.run(['docker', 'network', 'rm', n])
    for d in self.tmp_dirs:
      self.run(['rm', '-rf', d])

  def dump_logs(self, tail=120):
    for c in self.containers:
      res = self.run(['docker', 'logs', '--tail', str(tail), c])
      print(f'--- docker logs {c} (scrubbed, last {tail} lines) ---', file=sys.stderr)
      print(self.mask(res.stdout + res.stderr), file=sys.stderr)

  def all_logs(self):
    out = ''
    for c in self.containers:
      res = self.run(['docker', 'logs', c])
      out += res.stdout + res.stderr
    return out

  # ---- files and networks ----------------------------------------------------

  def write_secret_file(self, name, text):
    path = os.path.join(self.secret_dir, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
      f.write(text)
    return path

  def make_network(self):
    self.networks.append(self.network)
    assert self.run(['docker', 'network', 'create', self.network]).returncode == 0

  def register(self, name):
    self.containers.append(name)
    return name

  def published_port(self, container, port):
    out = self.run(['docker', 'port', container, port]).stdout.splitlines()
    return int(out[0].rsplit(':', 1)[1]) if out else None  # None: the container already exited

  # ---- UI containers ---------------------------------------------------------

  def start_ui(self, name, ldap_url, env, hold_secrets, port=None, extra_docker=(), wait=True, labels=()):
    self.register(name)
    body = ''.join(f'{k}={v}\n' for k, v in env.items()) + ''.join(f'{k}={v}\n' for k, v in hold_secrets.items())
    env_path = self.write_secret_file(name + '.env', body)
    publish = f'127.0.0.1:{port}:8080' if port else '127.0.0.1::8080'
    cmd = ['docker', 'run', '-d', '--name', name, '--network', self.network,
           '--add-host', 'host.docker.internal:host-gateway', '-p', publish, '--env-file', env_path,
           '-e', 'LDAP_URL=' + ldap_url]
    for lab in labels:
      cmd += ['--label', lab]
    cmd += list(extra_docker) + [self.ui_image]
    res = self.run(cmd)
    assert res.returncode == 0, res.stderr
    published = port or self.published_port(name, '8080/tcp')
    assert published or not wait, f'{name} exited during startup'
    api = Api(self, f'http://127.0.0.1:{published}')
    if wait:
      self.wait_ui(api, name)
    return api

  def wait_ui(self, api, name, timeout=60):
    def ready():
      try:
        with urllib.request.urlopen(api.base_url + '/api/auth/config', timeout=1) as r:
          return r.status == 200
      except Exception:
        return False
    self.wait_until(ready, f'{name} readiness', timeout)

  def audit_lines(self, container):
    logs = self.run(['docker', 'logs', container])
    return [ln for ln in (logs.stdout + logs.stderr).splitlines() if '"event":"machine_access"' in ln]


class Api:
  def __init__(self, live, base_url):
    self.live = live
    self.base_url = base_url

  def call(self, method, path, headers=None, body=None, timeout=30):
    req = urllib.request.Request(self.base_url + path, method=method, headers=headers or {},
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
      with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.headers, resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as err:
      return err.code, err.headers, err.read().decode('utf-8', 'replace')

  def machine(self, token, path, method='GET', req_id=None, timeout=30, extra=None):
    h = {'Authorization': 'Bearer ' + token}
    if req_id:
      h['X-Request-Id'] = req_id
    h.update(extra or {})
    return self.call(method, path, h, timeout=timeout)

  def login_human(self, human_password):
    status, hdrs, body = self.call('POST', '/api/login', {'Origin': self.base_url, 'Content-Type': 'application/json'},
                                   {'identity': HUMAN_DN, 'password': human_password})
    assert status == 200, f'human login failed: {status} {self.live.mask(body)}'
    cookie = hdrs.get('Set-Cookie', '').split(';')[0]
    assert cookie.startswith('ldapium_session='), 'no session cookie'
    return {'Cookie': cookie}


# ---- slapd ------------------------------------------------------------------

class Slapd:
  def __init__(self, live, name=None):
    self.live = live
    self.name = name or live.name_prefix + '-ldap'
    self.admin_password = live.secret(secrets.token_urlsafe(24))
    self.machine_password = live.secret('Mach-' + secrets.token_urlsafe(18))
    self.over_password = live.secret('Over-' + secrets.token_urlsafe(18))
    self.human_password = live.secret('Human-' + secrets.token_urlsafe(18))
    self.seed_secret = live.secret('SeedSecret-' + secrets.token_hex(8))
    self.port = free_port()
    self.accesslog_secrets = []

  def start(self):
    live = self.live
    live.register(self.name)
    env = live.write_secret_file('ldap.env', f'LDAP_ADMIN_PASSWORD={self.admin_password}\n')
    # A fixed host port: an ephemeral mapping would change when slapd is stopped and started again.
    res = live.run(['docker', 'run', '-d', '--name', self.name, '--network', live.network,
                    '-p', f'127.0.0.1:{self.port}:389', '--env-file', env, '-e', 'LDAP_ROOT_DN=' + BASE_DN,
                    '-e', 'LDAP_ACCESSLOG_ENABLED=true', '-e', 'LDAP_ACCESSLOG_OPS=writes reads bind', live.ldap_image])
    assert res.returncode == 0, res.stderr

    def ready():
      put = live.run(['docker', 'exec', '-i', self.name, 'sh', '-c', 'umask 077; cat > /tmp/.pw-admin'],
                     input=self.admin_password)
      return put.returncode == 0 and self.admin_tool('ldapsearch', ['-b', BASE_DN, '-s', 'base']).returncode == 0
    live.wait_until(ready, 'slapd readiness', 90)
    for path, pw in (('/tmp/.pw-machine', self.machine_password), ('/tmp/.pw-over', self.over_password)):
      self.put_password(path, pw)

  def put_password(self, path, password):
    res = self.live.run(['docker', 'exec', '-i', self.name, 'sh', '-c', f'umask 077; cat > {path}'], input=password)
    assert res.returncode == 0, res.stderr

  def tool(self, tool, args, bind_dn, pw_path, input_data=None, uri='ldap://127.0.0.1'):
    # docker exec -i: the heredoc/stdin must reach the tool (AGENTS.md).
    return self.live.run(['docker', 'exec', '-i', self.name, tool, '-x', '-H', uri, '-D', bind_dn, '-y', pw_path] + args,
                         input=input_data)

  def admin_tool(self, tool, args, input_data=None):
    return self.tool(tool, args, ADMIN_DN, '/tmp/.pw-admin', input_data)

  def config_tool(self, tool, args, input_data=None):
    return self.tool(tool, args, 'cn=admin,cn=config', '/tmp/.pw-admin', input_data)

  def seed(self, users=6, groups=5):
    ldif = f"""dn: ou=people,{BASE_DN}
objectClass: organizationalUnit
ou: people

dn: ou=groups,{BASE_DN}
objectClass: organizationalUnit
ou: groups

dn: ou=system,{BASE_DN}
objectClass: organizationalUnit
ou: system

dn: {MACHINE_DN}
objectClass: inetOrgPerson
uid: machine
cn: machine
sn: machine
userPassword: {self.machine_password}

dn: {OVER_DN}
objectClass: inetOrgPerson
uid: machine-over
cn: machine-over
sn: machine-over
userPassword: {self.over_password}

dn: {HUMAN_DN}
objectClass: inetOrgPerson
uid: human
cn: human
sn: human
userPassword: {self.human_password}
"""
    for i in range(1, users + 1):
      ldif += f"""
dn: uid=u0{i},ou=people,{BASE_DN}
objectClass: inetOrgPerson
uid: u0{i}
cn: User {i}
sn: User{i}
userPassword: initial-pw-{i}
"""
    for i in range(1, groups + 1):
      ldif += f"""
dn: cn=g0{i},ou=groups,{BASE_DN}
objectClass: groupOfNames
cn: g0{i}
member: {SEED_USER_DN}
"""
    res = self.admin_tool('ldapadd', [], ldif)
    assert res.returncode == 0, 'seed failed: ' + self.live.mask(res.stderr)

  def apply_ldif(self, template, tokens):
    text = (FIXTURES / template).read_text()
    for k, v in tokens.items():
      text = text.replace('@' + k + '@', v)
    res = self.config_tool('ldapmodify', [], text)
    assert res.returncode == 0, f'ldapmodify {template}: {self.live.mask(res.stderr)}'

  def apply_acl(self, over_privileged=False):
    """The package's ACL LDIF for the least-privilege machine DN (and, when asked,
    the deliberately over-privileged identity used by the secret-value probes)."""
    res = self.config_tool('ldapsearch', ['-LLL', '-b', 'cn=config', '(olcDatabase=*)', 'dn', 'olcSuffix'])
    dbs = {}
    for block in res.stdout.split('\n\n'):
      m = re.search(r'^dn: (olcDatabase=\{\d+\}(\w+),cn=config)$', block, re.M)
      if m:
        suffix = re.search(r'^olcSuffix: (.*)$', block, re.M)
        dbs[(m.group(2), suffix.group(1) if suffix else '')] = m.group(1)
    main_db = dbs[('mdb', BASE_DN)]
    accesslog_db = dbs[('mdb', 'cn=accesslog')]
    monitor_db = next(v for (kind, _), v in dbs.items() if kind == 'monitor')
    tokens = {'MACHINE_DN': MACHINE_DN, 'ALLOWED_DN': BASE_DN, 'MAIN_DB_DN': main_db,
              'MONITOR_DB_DN': monitor_db, 'ACCESSLOG_DB_DN': accesslog_db}
    self.apply_ldif('main-database.ldif', tokens)
    self.apply_ldif('monitor-optin.ldif', tokens)
    if over_privileged:
      over = dict(tokens, MACHINE_DN=OVER_DN)
      self.apply_ldif('overprivileged-main.ldif', over)
      self.apply_ldif('monitor-optin.ldif', over)
      self.apply_ldif('accesslog-optin.ldif', over)
    res = self.config_tool('ldapsearch', ['-LLL', '-b', main_db, '-s', 'base', 'olcAccess'])
    return re.findall(r'^olcAccess: (\{\d+\}.*)$', res.stdout.replace('\n ', ''), re.M)

  def seed_password_secret(self):
    """Change a user's password so the accesslog holds a userPassword reqMod VALUE."""
    mod = f"dn: {SEED_USER_DN}\nchangetype: modify\nreplace: userPassword\nuserPassword: {self.seed_secret}\n"
    assert self.admin_tool('ldapmodify', [], mod).returncode == 0
    res = self.tool('ldapsearch', ['-LLL', '-b', 'cn=accesslog', '(reqMod=userPassword:*)', 'reqMod'],
                    'cn=admin,cn=accesslog', '/tmp/.pw-admin')
    found = []
    for line in res.stdout.replace('\n ', '').splitlines():
      text = None
      if line.startswith('reqMod:: '):
        text = base64.b64decode(line[len('reqMod:: '):]).decode('utf-8', 'replace')
      elif line.startswith('reqMod: '):
        text = line[len('reqMod: '):]
      if text and text.startswith('userPassword:') and ' ' in text:
        value = text.split(' ', 1)[1].strip()
        if value:
          found.append(value)
    self.accesslog_secrets = found
    return found

  def binds(self, dn):
    """Number of binds slapd's own accesslog recorded for `dn` (the directory's view)."""
    res = self.tool('ldapsearch', ['-LLL', '-b', 'cn=accesslog', f'(&(reqType=bind)(reqDN={dn}))', 'reqDN'],
                    'cn=admin,cn=accesslog', '/tmp/.pw-admin')
    return res.stdout.count('reqDN:')


class LDAPProxy:
  """TCP proxy in front of slapd. pass: forward. stall: forward the first client
  message (the bind), then hold the rest until release(). Counts accepted and
  currently open connections."""

  def __init__(self, target_host, target_port):
    self.target = (target_host, target_port)
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.sock.bind(('0.0.0.0', 0))
    self.port = self.sock.getsockname()[1]
    self.sock.listen(64)
    self.mode = 'pass'
    self.lock = threading.Lock()
    self.accepted = 0
    self.open = 0
    self.stalled = threading.Event()
    self.released = threading.Event()
    self.running = True
    threading.Thread(target=self._accept, daemon=True).start()

  def set_mode(self, mode):
    self.mode = mode
    self.stalled.clear()
    self.released.clear()

  def release(self):
    self.released.set()

  def _accept(self):
    while self.running:
      try:
        client, _ = self.sock.accept()
      except OSError:
        return
      with self.lock:
        self.accepted += 1
        self.open += 1
      threading.Thread(target=self._serve, args=(client,), daemon=True).start()

  def _serve(self, client):
    server = None
    try:
      server = socket.create_connection(self.target, timeout=10)
      server.settimeout(None)
      client.settimeout(None)
      state = {'up': 0}

      def shut():
        for s in (client, server):
          try:
            s.shutdown(socket.SHUT_RDWR)
          except OSError:
            pass

      def up():
        try:
          while True:
            data = client.recv(65536)
            if not data:
              break
            if self.mode == 'stall' and state['up'] >= 1:
              self.stalled.set()
              self.released.wait(timeout=60)
            state['up'] += 1
            server.sendall(data)
        except OSError:
          pass
        finally:
          shut()

      def down():
        try:
          while True:
            data = server.recv(65536)
            if not data:
              break
            client.sendall(data)
        except OSError:
          pass
        finally:
          shut()

      t1 = threading.Thread(target=up, daemon=True)
      t2 = threading.Thread(target=down, daemon=True)
      t1.start()
      t2.start()
      t1.join()
      t2.join()
    except OSError:
      pass
    finally:
      for s in (client, server):
        if s is not None:
          try:
            s.close()
          except OSError:
            pass
      with self.lock:
        self.open -= 1

  def close(self):
    self.running = False
    try:
      self.sock.close()
    except OSError:
      pass


# ---- Keycloak -----------------------------------------------------------------

class Keycloak:
  """The pinned Keycloak in start-dev. KC_HOSTNAME is fixed, so every token's `iss` and the
  discovery document's `jwks_uri` are `hostname_url` no matter which address a request used
  (EVIDENCE 2.5); the script itself always talks to 127.0.0.1:<port>."""

  def __init__(self, live, name, hostname_url, port=None, features=None):
    self.live = live
    self.name = name
    self.hostname_url = hostname_url.rstrip('/')
    self.port = port or free_port()
    self.features = features
    self.admin_password = live.secret('KcAdmin-' + secrets.token_urlsafe(16))
    self._token = None
    self._token_until = 0.0

  @property
  def base(self):
    return f'http://127.0.0.1:{self.port}'

  def issuer(self, realm):
    return f'{self.hostname_url}/realms/{realm}'

  def start(self):
    live = self.live
    live.register(self.name)
    env = {'KC_BOOTSTRAP_ADMIN_USERNAME': 'admin', 'KC_BOOTSTRAP_ADMIN_PASSWORD': self.admin_password,
           'KC_HOSTNAME': self.hostname_url}
    if self.features:
      env['KC_FEATURES'] = self.features
    env_path = live.write_secret_file(self.name + '.env', ''.join(f'{k}={v}\n' for k, v in env.items()))
    res = live.run(['docker', 'run', '-d', '--name', self.name, '--network', live.network,
                    '-p', f'127.0.0.1:{self.port}:8080', '--env-file', env_path, live.keycloak_image, 'start-dev'])
    assert res.returncode == 0, res.stderr
    self.wait_ready()

  def wait_ready(self, timeout=180):
    def ready():
      try:
        with urllib.request.urlopen(self.base + '/realms/master/.well-known/openid-configuration', timeout=2) as r:
          return r.status == 200
      except Exception:
        return False
    self.live.wait_until(ready, f'{self.name} readiness', timeout, interval=1.0)
    self._token = None

  def stop(self):
    assert self.live.run(['docker', 'stop', '-t', '5', self.name]).returncode == 0

  def restart(self):
    assert self.live.run(['docker', 'start', self.name]).returncode == 0
    self.wait_ready()

  # -- plain HTTP --
  def http(self, method, url, headers=None, data=None, timeout=30):
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
      with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.headers, resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as err:
      return err.code, err.headers, err.read().decode('utf-8', 'replace')

  def admin_login(self):
    form = urllib.parse.urlencode({'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'admin',
                                   'password': self.admin_password}).encode()
    st, _, body = self.http('POST', self.base + '/realms/master/protocol/openid-connect/token',
                            {'Content-Type': 'application/x-www-form-urlencoded'}, form)
    assert st == 200, f'Keycloak admin login failed: {st} {self.live.mask(body)[:200]}'
    self._token = json.loads(body)['access_token']
    self._token_until = time.monotonic() + 40

  def admin(self, method, path, body=None, expect=None):
    if not self._token or time.monotonic() > self._token_until:
      self.admin_login()
    st, hdrs, text = self.http(method, self.base + '/admin/realms' + path,
                               {'Authorization': 'Bearer ' + self._token, 'Content-Type': 'application/json'},
                               json.dumps(body).encode() if body is not None else None)
    if expect is not None:
      assert st in expect, f'Keycloak admin {method} {path}: {st} {self.live.mask(text)[:300]}'
    return st, hdrs, text

  # -- realm / scopes / clients --
  def create_realm(self, realm, lifespan=300):
    self.admin('POST', '', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'accessTokenLifespan': lifespan},
               expect=(201,))

  def create_user(self, realm, username, password):
    self.admin('POST', f'/{realm}/users', {'username': username, 'enabled': True, 'emailVerified': True,
                                           'firstName': username, 'lastName': 'Test',
                                           'email': f'{username}@example.org',
                                           'credentials': [{'type': 'password', 'value': password, 'temporary': False}]},
               expect=(201,))

  def scope_ids(self, realm):
    st, _, text = self.admin('GET', f'/{realm}/client-scopes', expect=(200,))
    return {s['name']: s['id'] for s in json.loads(text)}

  def create_scope(self, realm, name):
    st, hdrs, _ = self.admin('POST', f'/{realm}/client-scopes',
                             {'name': name, 'protocol': 'openid-connect',
                              'attributes': {'include.in.token.scope': 'true', 'display.on.consent.screen': 'false'}},
                             expect=(201,))
    return hdrs['Location'].rsplit('/', 1)[1]

  def create_client(self, realm, client_id, secret, scopes=(), audience=AUDIENCE, direct_grant=False,
                    standard_flow=False, attributes=None, service_account=True):
    body = {'clientId': client_id, 'enabled': True, 'protocol': 'openid-connect', 'publicClient': False,
            'secret': secret, 'serviceAccountsEnabled': service_account, 'standardFlowEnabled': standard_flow,
            'directAccessGrantsEnabled': direct_grant, 'attributes': attributes or {}}
    if standard_flow:
      body['redirectUris'] = ['*']
    st, hdrs, _ = self.admin('POST', f'/{realm}/clients', body, expect=(201,))
    cid = hdrs['Location'].rsplit('/', 1)[1]
    ids = self.scope_ids(realm)
    for scope in scopes:
      self.admin('PUT', f'/{realm}/clients/{cid}/default-client-scopes/{ids[scope]}', expect=(204,))
    if audience:
      self.add_audience_mapper(realm, cid, audience)
    return cid

  def add_audience_mapper(self, realm, cid, audience):
    self.admin('POST', f'/{realm}/clients/{cid}/protocol-mappers/models',
               {'name': 'aud-' + audience, 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper',
                'config': {'included.custom.audience': audience, 'id.token.claim': 'false',
                           'access.token.claim': 'true', 'introspection.token.claim': 'true'}},
               expect=(201,))

  def mappers(self, realm, cid):
    st, _, text = self.admin('GET', f'/{realm}/clients/{cid}/protocol-mappers/models', expect=(200,))
    return json.loads(text)

  def get_client(self, realm, cid):
    st, _, text = self.admin('GET', f'/{realm}/clients/{cid}', expect=(200,))
    return json.loads(text)

  def update_client(self, realm, cid, **changes):
    client = self.get_client(realm, cid)
    attrs = changes.pop('attributes', None)
    client.update(changes)
    if attrs:
      client['attributes'] = dict(client.get('attributes') or {}, **attrs)
    self.admin('PUT', f'/{realm}/clients/{cid}', client, expect=(204,))

  def default_scope_names(self, realm, cid):
    st, _, text = self.admin('GET', f'/{realm}/clients/{cid}/default-client-scopes', expect=(200,))
    return {s['name']: s['id'] for s in json.loads(text)}

  def remove_default_scope(self, realm, cid, name):
    sid = self.default_scope_names(realm, cid)[name]
    self.admin('DELETE', f'/{realm}/clients/{cid}/default-client-scopes/{sid}', expect=(204,))

  def add_default_scope(self, realm, cid, name):
    self.admin('PUT', f'/{realm}/clients/{cid}/default-client-scopes/{self.scope_ids(realm)[name]}', expect=(204,))

  # -- tokens --
  def token(self, realm, client_id, secret, **form):
    data = {'client_id': client_id, 'client_secret': secret}
    data.update(form)
    data.setdefault('grant_type', 'client_credentials')
    st, _, text = self.http('POST', f'{self.base}/realms/{realm}/protocol/openid-connect/token',
                            {'Content-Type': 'application/x-www-form-urlencoded'},
                            urllib.parse.urlencode(data).encode())
    return st, jbody(text)

  def sa_token(self, realm, client_id, secret, **form):
    st, body = self.token(realm, client_id, secret, **form)
    assert st == 200, f'client_credentials for {client_id}: {st} {self.live.mask(str(body))[:200]}'
    return body['access_token']

  def jwks(self, realm):
    st, _, text = self.http('GET', f'{self.base}/realms/{realm}/protocol/openid-connect/certs')
    assert st == 200, text
    return json.loads(text)['keys']


# ---- local signing key imported into a realm ---------------------------------

class Signer:
  """A private key the script owns, imported into a realm as an `rsa` key provider.
  Tokens it signs verify against the REAL JWKS (kid taken from the realm), so a
  negative token can differ from a real one in exactly one claim."""

  def __init__(self, live):
    self.live = live
    self.dir = tempfile.mkdtemp(prefix='mk-key-', dir=live.secret_dir)
    self.key = os.path.join(self.dir, 'key.pem')
    self.cert = os.path.join(self.dir, 'cert.pem')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=machine-live',
                    '-days', '2', '-keyout', self.key, '-out', self.cert], check=True, capture_output=True)
    os.chmod(self.key, 0o600)
    mod = subprocess.run(['openssl', 'rsa', '-in', self.key, '-noout', '-modulus'], capture_output=True, text=True,
                         check=True).stdout.strip().split('=')[1]
    self.n_b64 = b64u(bytes.fromhex(mod))
    self.pub_pem = subprocess.run(['openssl', 'pkey', '-in', self.key, '-pubout'], capture_output=True,
                                  check=True).stdout
    self.kid = None

  def import_into(self, kc, realm, priority=1000):
    def body(path):
      return ''.join(l for l in pathlib.Path(path).read_text().splitlines() if '-----' not in l)
    kc.admin('POST', f'/{realm}/components',
             {'name': 'imported-' + self.live.run_id, 'providerId': 'rsa',
              'providerType': 'org.keycloak.keys.KeyProvider',
              'config': {'priority': [str(priority)], 'enabled': ['true'], 'active': ['true'], 'algorithm': ['RS256'],
                         'privateKey': [body(self.key)], 'certificate': [body(self.cert)]}}, expect=(201,))
    self.kid = next(k['kid'] for k in kc.jwks(realm) if k.get('n') == self.n_b64)
    return self.kid

  def sign(self, data, digest='sha256'):
    return subprocess.run(['openssl', 'dgst', '-' + digest, '-sign', self.key], input=data, capture_output=True,
                          check=True).stdout

  def craft(self, base_claims, header=None, set_claims=None, drop=(), alg='RS256'):
    """Re-sign `base_claims` (taken from a real token) with one deliberate change."""
    claims = dict(base_claims)
    claims.update(set_claims or {})
    for k in drop:
      claims.pop(k, None)
    hdr = {'alg': alg, 'typ': 'JWT', 'kid': self.kid}
    hdr.update(header or {})
    for k in [k for k, v in hdr.items() if v is None]:
      del hdr[k]
    signing_input = f'{b64u(json.dumps(hdr).encode())}.{b64u(json.dumps(claims).encode())}'
    if alg == 'none':
      return signing_input + '.'
    if alg.startswith('HS'):
      digest = {'HS256': 'sha256', 'HS384': 'sha384', 'HS512': 'sha512'}[alg]
      return signing_input + '.' + b64u(hmac.new(self.pub_pem, signing_input.encode(), getattr(hashlib, digest)).digest())
    digest = {'RS256': 'sha256', 'RS384': 'sha384', 'RS512': 'sha512'}[alg]
    return signing_input + '.' + b64u(self.sign(signing_input.encode(), digest))
