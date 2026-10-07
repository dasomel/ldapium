#!/usr/bin/env python3
"""Live verification of the machine execution identity (#214, staged unit 2).

Against a real OpenLDAP slapd and the real UI backend with MACHINE_AUTH_ENABLED
(a local mock OIDC issuer signs the tokens; the real Keycloak e2e is a later
unit), proves what unit tests cannot (docs/changes/machine-principal-auth,
T-013 / T-040 / T-041 / T-017, AC-001/003/005/009/010/015/017):

  - a machine token reads users/groups (cursor paging), entry, tree, monitor
    through ONE least-privilege LDAP account created from the package's ACL
    LDIF (scripts/test/fixtures/machine-acl/), and the slapd accesslog shows
    that account, not an administrator, binding;
  - denied scopes and operations answer 403 with ZERO LDAP connections;
  - getEntry/listTree refuse cn=accesslog, cn=config, cn=Monitor and anything
    outside the base DN with zero LDAP connections;
  - with a deliberately over-privileged bind identity (it can read userPassword
    and cn=accesslog) no seeded secret VALUE appears in any machine-reachable
    response, and getMonitor includes accesslog entries only with audit.read;
  - a wrong machine password is a 503 (never a fallback to another identity); a
    hung directory ends at MACHINE_REQUEST_TIMEOUT with a 503; stopping slapd
    mid-request is a 503; client aborts, timeouts and the outage leave no
    connection behind and the slot is reusable afterwards;
  - the machine DN cannot write (ldapmodify/ldapadd/ldapdelete/modrdn/ldappasswd
    all insufficient access), and no write route is reachable over HTTP;
  - cursors are bound to issuer+client (cross-client and human<->machine replay
    400, a refreshed token pages on);
  - every Authorization-carrying request is exactly one audit line and no
    token, signature or bind password appears in any container log.

Run with (images default to the names the other live API scripts use):
  python3 scripts/test/test-machine-execution-live.py
Override LDAPIUM_IMAGE / LDAPIUM_UI_IMAGE / LDAPIUM_TEST_PREFIX as needed.
"""
import atexit
import base64
import struct
import http.server
import json
import os
import pathlib
import re
import secrets
import signal
import socket
import socketserver
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

try:
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.asymmetric import padding, rsa
  HAVE_CRYPTO = True
except ImportError:
  HAVE_CRYPTO = False

repo_root = pathlib.Path(__file__).resolve().parents[2]
fixtures = repo_root / 'scripts/test/fixtures/machine-acl'
ldap_image = os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')
ui_image = os.environ.get('LDAPIUM_UI_IMAGE', 'ldapium-ui:e2e')
prefix = os.environ.get('LDAPIUM_TEST_PREFIX', 'ldapium-mx-')
run_id = uuid.uuid4().hex[:6]
name_prefix = prefix + run_id

network = name_prefix + '-net'
ldap_container = name_prefix + '-ldap'
ui_main = name_prefix + '-ui'
ui_over = name_prefix + '-uiover'
ui_off = name_prefix + '-uioff'
ui_tls = name_prefix + '-uitls'
ui_lim = name_prefix + '-uilim'
ui_cap = name_prefix + '-uicap'

base_dn = 'dc=example,dc=org'
admin_dn = 'cn=admin,' + base_dn
machine_dn = 'uid=machine,ou=system,' + base_dn
over_dn = 'uid=machine-over,ou=system,' + base_dn
human_dn = 'uid=human,ou=people,' + base_dn
seed_user_dn = 'uid=u01,ou=people,' + base_dn

admin_password = secrets.token_urlsafe(24)
machine_password = 'Mach-' + secrets.token_urlsafe(18)
over_password = 'Over-' + secrets.token_urlsafe(18)
human_password = 'Human-' + secrets.token_urlsafe(18)
# Recognizable secrets that must never leave the process in a response or log.
seed_secret = 'SeedSecret-' + secrets.token_hex(8)
session_secret = secrets.token_hex(32)

# Everything registered here is removed by cleanup(), which runs from atexit and
# from SIGTERM/SIGINT; names are appended BEFORE the object is created.
containers = []
networks = []
tmp_dirs = []
proxies = []
mock_idp = None
start_monotonic = time.monotonic()


def check(condition, message):
  if not condition:
    raise AssertionError(message)
  print('PASS: ' + message, flush=True)


def mask(text):
  text = text if isinstance(text, str) else str(text)
  for secret in (admin_password, machine_password, over_password, human_password, session_secret):
    text = text.replace(secret, '***')
  return text


def run(cmd, **kw):
  return subprocess.run(cmd, capture_output=True, text=True, **kw)


def cleanup():
  for p in proxies:
    p.close()
  if mock_idp:
    mock_idp.close()
  for c in containers:
    run(['docker', 'rm', '-fv', c])
  for n in networks:
    run(['docker', 'network', 'rm', n])
  for d in tmp_dirs:
    run(['rm', '-rf', d])


atexit.register(cleanup)
for _sig in (signal.SIGTERM, signal.SIGINT):
  signal.signal(_sig, lambda *_: sys.exit(130))


def dump_logs():
  for c in containers:
    res = run(['docker', 'logs', '--tail', '120', c])
    print(f'--- docker logs {c} (scrubbed, last 120 lines) ---', file=sys.stderr)
    print(mask(res.stdout + res.stderr), file=sys.stderr)


def wait_until(predicate, what, timeout=30.0):
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if predicate():
      return
    time.sleep(0.1)
  raise AssertionError(f'timed out after {timeout}s waiting for {what}')


# ---- secrets live in 0700 temp files, never on argv --------------------------

secret_dir = tempfile.mkdtemp(prefix='mx-secrets-')
tmp_dirs.append(secret_dir)
os.chmod(secret_dir, stat.S_IRWXU)


def write_secret_file(name, text):
  path = os.path.join(secret_dir, name)
  fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
  with os.fdopen(fd, 'w') as f:
    f.write(text)
  return path


def put_password_in_container(path, password):
  # stdin, not argv: the password never appears in a process listing.
  res = run(['docker', 'exec', '-i', ldap_container, 'sh', '-c', f'umask 077; cat > {path}'], input=password)
  if not (res.returncode == 0):
    raise AssertionError(res.stderr)


def ldap_tool(tool, args, bind_dn, pw_path, input_data=None, uri='ldap://127.0.0.1'):
  # docker exec -i: the heredoc/stdin must reach the tool (AGENTS.md).
  return run(['docker', 'exec', '-i', ldap_container, tool, '-x', '-H', uri, '-D', bind_dn, '-y', pw_path] + args,
             input=input_data)


def admin_tool(tool, args, input_data=None):
  return ldap_tool(tool, args, admin_dn, '/tmp/.pw-admin', input_data)


def config_tool(tool, args, input_data=None):
  return ldap_tool(tool, args, 'cn=admin,cn=config', '/tmp/.pw-admin', input_data)


# ---- mock OIDC issuer ---------------------------------------------------------

def b64u(b):
  return base64.urlsafe_b64encode(b).decode().rstrip('=')


class MockIdP:
  """Serves discovery + JWKS and signs service-account access tokens."""

  def __init__(self):
    self.tmp = tempfile.TemporaryDirectory(prefix='mx-idp-')
    self.key_file = os.path.join(self.tmp.name, 'key.pem')
    if HAVE_CRYPTO:
      self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
      pub = self.key.public_key().public_numbers()
      n, e = pub.n, pub.e
      n_b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
      e_b = e.to_bytes((e.bit_length() + 7) // 8, 'big')
    else:
      subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', self.key_file],
                     check=True, stderr=subprocess.DEVNULL)
      mod = subprocess.run(['openssl', 'rsa', '-in', self.key_file, '-noout', '-modulus'], capture_output=True, text=True, check=True)
      n_b = bytes.fromhex(mod.stdout.strip().split('=')[1])
      e_b = bytes([1, 0, 1])
    self.jwk = {'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': 'mx-1', 'n': b64u(n_b), 'e': b64u(e_b)}
    self.server = None
    self.port = 0
    self.jwks_hits = 0

  @property
  def issuer(self):
    return f'http://host.docker.internal:{self.port}'

  def sign(self, data):
    if HAVE_CRYPTO:
      return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    p = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', self.key_file], input=data, capture_output=True, check=True)
    return p.stdout

  def mint(self, client, scopes, **override):
    now = int(time.time())
    kid = override.pop('kid', 'mx-1')  # a JOSE header value, not a claim
    claims = {
        'iss': self.issuer, 'sub': 'sa-' + client, 'typ': 'Bearer', 'azp': client, 'client_id': client,
        'aud': ['ldapium-api', 'account'], 'iat': now, 'exp': now + 300, 'jti': secrets.token_hex(8),
        'scope': 'profile email ' + ' '.join(scopes), 'preferred_username': 'service-account-' + client,
        'clientHost': '10.0.0.1', 'clientAddress': '10.0.0.1',
    }
    claims.update(override)
    hdr = b64u(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': kid}).encode())
    body = b64u(json.dumps(claims).encode())
    sig = b64u(self.sign(f'{hdr}.{body}'.encode()))
    return f'{hdr}.{body}.{sig}'

  def start(self):
    parent = self

    class Handler(http.server.BaseHTTPRequestHandler):
      def log_message(self, *_):
        pass

      def do_GET(self):
        if self.path == '/.well-known/openid-configuration':
          body = json.dumps({'issuer': parent.issuer, 'jwks_uri': parent.issuer + '/jwks'}).encode()
        elif self.path == '/jwks':
          parent.jwks_hits += 1
          body = json.dumps({'keys': [parent.jwk]}).encode()
        else:
          self.send_response(404)
          self.end_headers()
          return
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(body)

    self.server = socketserver.ThreadingTCPServer(('0.0.0.0', 0), Handler)
    self.server.daemon_threads = True
    self.port = self.server.server_address[1]
    threading.Thread(target=self.server.serve_forever, daemon=True).start()

  def close(self):
    if self.server:
      self.server.shutdown()
      self.server.server_close()
    self.tmp.cleanup()


# ---- a TCP proxy in front of slapd to inject faults and count connections ----

class LDAPProxy:
  """pass: forward. blackhole: accept and say nothing (a hung directory).
  stall: forward the first client message (the bind), then hold the rest until
  release(). Counts accepted and currently open connections."""

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
      if self.mode == 'blackhole':
        client.settimeout(60)
        while client.recv(4096):
          pass
        return
      server = socket.create_connection(self.target, timeout=10)
      server.settimeout(None)
      client.settimeout(None)
      state = {'up': 0}

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
          for s in (client, server):
            try:
              s.shutdown(socket.SHUT_RDWR)
            except OSError:
              pass

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
          for s in (client, server):
            try:
              s.shutdown(socket.SHUT_RDWR)
            except OSError:
              pass

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


# ---- HTTP client --------------------------------------------------------------

class StartTLSStaller:
  """Answers the first LDAP message (the StartTLS extended request) with success
  and then never speaks again, so the client's TLS handshake stalls. Counts
  accepted and currently open connections."""

  def __init__(self):
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.sock.bind(('0.0.0.0', 0))
    self.port = self.sock.getsockname()[1]
    self.sock.listen(8)
    self.lock = threading.Lock()
    self.accepted = 0
    self.open = 0
    threading.Thread(target=self._accept, daemon=True).start()

  def _accept(self):
    while True:
      try:
        c, _ = self.sock.accept()
      except OSError:
        return
      with self.lock:
        self.accepted += 1
        self.open += 1
      threading.Thread(target=self._serve, args=(c,), daemon=True).start()

  def _serve(self, c):
    try:
      data = c.recv(4096)
      if len(data) >= 5:
        # LDAPMessage{id, ExtendedResponse{success}} for the request's message id
        c.sendall(bytes([0x30, 0x0c, 0x02, 0x01, data[4], 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]))
      while c.recv(4096):
        pass
    except OSError:
      pass
    finally:
      c.close()
      with self.lock:
        self.open -= 1

  def close(self):
    self.sock.close()


class Api:
  def __init__(self, base_url):
    self.base_url = base_url

  def call(self, method, path, headers=None, body=None, timeout=30):
    req = urllib.request.Request(self.base_url + path, method=method, headers=headers or {},
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
      with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        return resp.status, resp.headers, raw.decode('utf-8', 'replace')
    except urllib.error.HTTPError as err:
      return err.code, err.headers, err.read().decode('utf-8', 'replace')

  def machine(self, token, path, method='GET', req_id=None, timeout=30):
    h = {'Authorization': 'Bearer ' + token}
    if req_id:
      h['X-Request-Id'] = req_id
    return self.call(method, path, h, timeout=timeout)

  def login_human(self):
    # Same-origin POST like the browser; the cookie jar is a plain header here.
    status, hdrs, body = self.call('POST', '/api/login', {'Origin': self.base_url, 'Content-Type': 'application/json'},
                                   {'identity': human_dn, 'password': human_password})
    if not (status == 200):
      raise AssertionError(f'human login failed: {status} {mask(body)}')
    cookie = hdrs.get('Set-Cookie', '').split(';')[0]
    if not (cookie.startswith('ldapium_session=')):
      raise AssertionError('no session cookie')
    return {'Cookie': cookie}


def jbody(text):
  try:
    return json.loads(text)
  except ValueError:
    return {}


# ---- containers ---------------------------------------------------------------

def free_port():
  s = socket.socket()
  s.bind(('127.0.0.1', 0))
  port = s.getsockname()[1]
  s.close()
  return port


def published_port(container, port):
  out = run(['docker', 'port', container, port]).stdout.splitlines()
  return int(out[0].rsplit(':', 1)[1])


def start_ui(name, ldap_url, env, hold_secrets):
  containers.append(name)
  env_path = write_secret_file(name + '.env', ''.join(f'{k}={v}\n' for k, v in env.items()) + ''.join(
      f'{k}={v}\n' for k, v in hold_secrets.items()))
  cmd = ['docker', 'run', '-d', '--name', name, '--network', network,
         '--add-host', 'host.docker.internal:host-gateway', '-p', '127.0.0.1::8080', '--env-file', env_path,
         '-e', 'LDAP_URL=' + ldap_url, ui_image]
  res = run(cmd)
  if not (res.returncode == 0):
    raise AssertionError(res.stderr)
  base = f'http://127.0.0.1:{published_port(name, "8080/tcp")}'

  def ready():
    try:
      with urllib.request.urlopen(base + '/api/auth/config', timeout=1) as r:
        return r.status == 200
    except Exception:
      return False
  wait_until(ready, f'{name} readiness', 60)
  return Api(base)


def machine_env(bind_dn, clients, limits=None):
  # The limiters (T-018) are on in every machine container. This script sends
  # hundreds of requests from ONE client and ONE source IP, including probes
  # that are denied (403) or invalid (401) on purpose, so the defaults (5 rps,
  # 10 failures per minute) would turn those probes into 429s and test the
  # wrong thing. The generous values keep the probes out of the limiters; the
  # "limiters" phase passes `limits` for its own small-limit container.
  env = {
      'LDAP_BASE_DN': base_dn, 'LDAP_USER_CREATE_BASE': 'ou=people,' + base_dn,
      'LDAP_GROUP_CREATE_BASE': 'ou=groups,' + base_dn, 'COOKIE_SECURE': 'false',
      'UI_TRUSTED_PROXIES': 'none',
      'MACHINE_AUTH_ENABLED': 'true', 'MACHINE_OIDC_ISSUER_URL': mock_idp.issuer, 'MACHINE_OIDC_INSECURE_HTTP': 'true',
      'MACHINE_OIDC_AUDIENCE': 'ldapium-api', 'MACHINE_ALLOWED_CLIENTS': clients,
      'MACHINE_LDAP_BIND_DN': bind_dn, 'MACHINE_LDAP_ROOT_DNS': admin_dn,
      'MACHINE_REQUEST_TIMEOUT': '3s', 'MACHINE_MAX_CONCURRENCY': '2',
  }
  env.update(limits or {
      'MACHINE_AUTH_FAILURE_LIMIT': '1000', 'MACHINE_RATE_LIMIT_RPS': '10000', 'MACHINE_RATE_LIMIT_BURST': '10000',
      'MACHINE_CLIENT_CONCURRENCY': '1000', 'MACHINE_MAX_AUTH_CONCURRENCY': '1000',
  })
  return env


READER = ['directory.users.read', 'directory.groups.read', 'directory.tree.read', 'directory.entry.read',
          'directory.policies.read', 'server.monitor.read']
CLIENTS = (f'svc-reader={",".join(READER)};svc-reader2=directory.users.read,directory.groups.read;'
           'svc-groups=directory.groups.read;'
           'svc-audit=server.monitor.read,audit.read,directory.entry.read')

RUN_ID_RE = re.compile(r'"request_id":"([^"]+)"')


def audit_lines(container):
  logs = run(['docker', 'logs', container])
  text = logs.stdout + logs.stderr
  return [l for l in text.splitlines() if '"event":"machine_access"' in l]


def apply_ldif(template, tokens, tool=config_tool):
  text = (fixtures / template).read_text()
  for k, v in tokens.items():
    text = text.replace('@' + k + '@', v)
  res = tool('ldapmodify', [], text)
  if not (res.returncode == 0):
    raise AssertionError(f'ldapmodify {template}: {mask(res.stderr)}')


def main():
  global mock_idp
  print(f'Run {name_prefix}: server image {ldap_image}, UI image {ui_image}', flush=True)
  mock_idp = MockIdP()
  mock_idp.start()

  networks.append(network)
  if not (run(['docker', 'network', 'create', network]).returncode == 0):
    raise AssertionError("run(['docker', 'network', 'create', network]).returncode == 0")

  # ---- slapd with accesslog recording writes, reads and binds -----------------
  containers.append(ldap_container)
  admin_env = write_secret_file('ldap.env', f'LDAP_ADMIN_PASSWORD={admin_password}\n')
  # A host port chosen now and kept: an ephemeral mapping would change when slapd is
  # stopped and started again, and the fault-injection proxy points at it.
  ldap_port = free_port()
  res = run(['docker', 'run', '-d', '--name', ldap_container, '--network', network, '-p', f'127.0.0.1:{ldap_port}:389',
             '--env-file', admin_env, '-e', 'LDAP_ROOT_DN=' + base_dn, '-e', 'LDAP_ACCESSLOG_ENABLED=true',
             '-e', 'LDAP_ACCESSLOG_OPS=writes reads bind', ldap_image])
  if not (res.returncode == 0):
    raise AssertionError(res.stderr)

  def slapd_ready():
    put = run(['docker', 'exec', '-i', ldap_container, 'sh', '-c', 'umask 077; cat > /tmp/.pw-admin'], input=admin_password)
    if put.returncode != 0:
      return False
    return admin_tool('ldapsearch', ['-b', base_dn, '-s', 'base']).returncode == 0
  wait_until(slapd_ready, 'slapd readiness', 90)
  for path, pw in (('/tmp/.pw-machine', machine_password), ('/tmp/.pw-over', over_password)):
    put_password_in_container(path, pw)

  ldif = f"""dn: ou=people,{base_dn}
objectClass: organizationalUnit
ou: people

dn: ou=groups,{base_dn}
objectClass: organizationalUnit
ou: groups

dn: ou=system,{base_dn}
objectClass: organizationalUnit
ou: system

dn: {machine_dn}
objectClass: inetOrgPerson
uid: machine
cn: machine
sn: machine
userPassword: {machine_password}

dn: {over_dn}
objectClass: inetOrgPerson
uid: machine-over
cn: machine-over
sn: machine-over
userPassword: {over_password}

dn: {human_dn}
objectClass: inetOrgPerson
uid: human
cn: human
sn: human
userPassword: {human_password}
"""
  for i in range(1, 7):
    ldif += f"""
dn: uid=u0{i},ou=people,{base_dn}
objectClass: inetOrgPerson
uid: u0{i}
cn: User {i}
sn: User{i}
userPassword: initial-pw-{i}
"""
  for i in range(1, 6):
    ldif += f"""
dn: cn=g0{i},ou=groups,{base_dn}
objectClass: groupOfNames
cn: g0{i}
member: {seed_user_dn}
"""
  res = admin_tool('ldapadd', [], ldif)
  check(res.returncode == 0, 'seeded people, groups, ou=system, the machine accounts and a human user: ' + mask(res.stderr))

  # ---- discover the config DNs, then apply the package's ACL LDIF --------------
  res = config_tool('ldapsearch', ['-LLL', '-b', 'cn=config', '(olcDatabase=*)', 'dn', 'olcSuffix'])
  dbs = {}
  for block in res.stdout.split('\n\n'):
    m = re.search(r'^dn: (olcDatabase=\{\d+\}(\w+),cn=config)$', block, re.M)
    if m:
      suffix = re.search(r'^olcSuffix: (.*)$', block, re.M)
      dbs[(m.group(2), suffix.group(1) if suffix else '')] = m.group(1)
  main_db = dbs[('mdb', base_dn)]
  accesslog_db = dbs[('mdb', 'cn=accesslog')]
  monitor_db = next(v for (kind, _), v in dbs.items() if kind == 'monitor')
  tokens = {'MACHINE_DN': machine_dn, 'ALLOWED_DN': base_dn, 'MAIN_DB_DN': main_db,
            'MONITOR_DB_DN': monitor_db, 'ACCESSLOG_DB_DN': accesslog_db}
  apply_ldif('main-database.ldif', tokens)
  apply_ldif('monitor-optin.ldif', tokens)
  over_tokens = dict(tokens, MACHINE_DN=over_dn)
  apply_ldif('overprivileged-main.ldif', over_tokens)
  apply_ldif('monitor-optin.ldif', over_tokens)
  apply_ldif('accesslog-optin.ldif', over_tokens)
  res = config_tool('ldapsearch', ['-LLL', '-b', main_db, '-s', 'base', 'olcAccess'])
  rules = re.findall(r'^olcAccess: (\{\d+\}.*)$', res.stdout.replace('\n ', ''), re.M)
  check(len(rules) >= 5 and f'by dn.exact="{over_dn}" read' in rules[0] and
        rules[1].startswith('{1}to attrs=userPassword,shadowLastChange,') and
        rules[1].endswith('by dn.exact="' + machine_dn + '" none by * break') and
        rules[2].startswith('{2}to dn.subtree="' + base_dn + '" by dn.exact="' + machine_dn + '" read') and
        rules[3].startswith('{3}to * by dn.exact="' + machine_dn + '" none'),
        'olcAccess read back: the machine rules sit in front of the existing rules: ' + ' | '.join(r[:60] for r in rules[:4]))

  # ---- the secret goes into the directory AND into the accesslog ---------------
  mod = f"dn: {seed_user_dn}\nchangetype: modify\nreplace: userPassword\nuserPassword: {seed_secret}\n"
  res = admin_tool('ldapmodify', [], mod)
  check(res.returncode == 0, 'set a known password on u01 (its change lands in the accesslog reqMod)')
  res = ldap_tool('ldapsearch', ['-LLL', '-b', 'cn=accesslog', f'(reqMod=userPassword:*)', 'reqMod'],
                  'cn=admin,cn=accesslog', '/tmp/.pw-admin')
  # Whatever form slapd logged (the clear text, or a hash if ppolicy hashed it first)
  # is a secret VALUE the machine path must never return.
  accesslog_secrets = []
  for line in res.stdout.replace('\n ', '').splitlines():
    text = None
    if line.startswith('reqMod:: '):
      text = base64.b64decode(line[len('reqMod:: '):]).decode('utf-8', 'replace')
    elif line.startswith('reqMod: '):
      text = line[len('reqMod: '):]
    if text and text.startswith('userPassword:') and ' ' in text:
      value = text.split(' ', 1)[1].strip()
      if value:
        accesslog_secrets.append(value)
  check(res.returncode == 0 and accesslog_secrets,
        f'the accesslog really holds {len(accesslog_secrets)} userPassword reqMod value(s) (the seed is not vacuous; '
        f'clear text logged: {seed_secret in accesslog_secrets})')
  res = ldap_tool('ldapsearch', ['-LLL', '-b', seed_user_dn, '-s', 'base', 'userPassword'], over_dn, '/tmp/.pw-over')
  check('userPassword' in res.stdout, 'the over-privileged identity can read userPassword (the guard test is not vacuous)')
  res = ldap_tool('ldapsearch', ['-LLL', '-b', seed_user_dn, '-s', 'base', 'userPassword'], machine_dn, '/tmp/.pw-machine')
  check('userPassword' not in res.stdout, 'the least-privilege machine account cannot read userPassword at the directory')

  # ---- UI containers ------------------------------------------------------------
  proxy = LDAPProxy('127.0.0.1', ldap_port)
  proxies.append(proxy)
  main_api = start_ui(ui_main, f'ldap://host.docker.internal:{proxy.port}', machine_env(machine_dn, CLIENTS),
                      {'SESSION_SECRET': session_secret, 'MACHINE_LDAP_BIND_PASSWORD': machine_password})
  over_api = start_ui(ui_over, f'ldap://{ldap_container}:389', machine_env(over_dn, CLIENTS),
                      {'SESSION_SECRET': session_secret, 'MACHINE_LDAP_BIND_PASSWORD': over_password})
  off_api = start_ui(ui_off, f'ldap://{ldap_container}:389',
                     {'LDAP_BASE_DN': base_dn, 'COOKIE_SECURE': 'false'}, {'SESSION_SECRET': session_secret})

  def tok(client, scopes=None, **kw):
    return mock_idp.mint(client, scopes if scopes is not None else {'svc-reader': READER, 'svc-reader2': READER[:2],
                                                                    'svc-groups': ['directory.groups.read'],
                                                                    'svc-audit': ['server.monitor.read', 'audit.read', 'directory.entry.read']}[client], **kw)

  def settled():
    wait_until(lambda: proxy.open == 0, 'proxy connections to drain', 15)

  def no_ldap_connections(desc, fn):
    settled()
    before = proxy.accepted
    out = fn()
    check(proxy.accepted == before, f'{desc}: zero LDAP connections ({proxy.accepted - before} opened)')
    return out

  # ---- AC-014: feature off ------------------------------------------------------
  st, _, body = off_api.machine(tok('svc-reader'), '/api/users')
  check(st == 401 and jbody(body).get('code') == 'unauthenticated', 'feature off: a bearer token is ignored (401 not logged in)')

  def accesslog_binds(dn):
    res = ldap_tool('ldapsearch', ['-LLL', '-b', 'cn=accesslog', f'(&(reqType=bind)(reqDN={dn}))', 'reqDN'],
                    'cn=admin,cn=accesslog', '/tmp/.pw-admin')
    return res.stdout.count('reqDN:')

  admin_binds_before, machine_binds_before = accesslog_binds(admin_dn), accesslog_binds(machine_dn)

  # ---- allowed operations as the machine principal -----------------------------
  rid = 'mx-ok-' + secrets.token_hex(4)
  st, _, body = main_api.machine(tok('svc-reader'), '/api/users?limit=2', req_id=rid)
  page1 = jbody(body)
  check(st == 200 and len(page1.get('users', [])) == 2 and page1.get('nextCursor'), 'machine: GET /api/users?limit=2 -> 200 with a next cursor')
  st, _, body = main_api.machine(tok('svc-reader'), '/api/users?limit=2&cursor=' + urllib.parse.quote(page1['nextCursor']))
  page2 = jbody(body)
  check(st == 200 and page2['users'][0]['uid'] > page1['users'][-1]['uid'] and not {u['uid'] for u in page1['users']} & {u['uid'] for u in page2['users']}, 'machine: cursor page 2 continues after page 1 without overlap')
  st, _, body = main_api.machine(tok('svc-reader'), '/api/groups?limit=2')
  gp1 = jbody(body)
  check(st == 200 and len(gp1['groups']) == 2 and gp1.get('nextCursor'), 'machine: GET /api/groups?limit=2 -> 200 with a next cursor')
  st, _, body = main_api.machine(tok('svc-reader'), '/api/groups?limit=2&cursor=' + urllib.parse.quote(gp1['nextCursor']))
  check(st == 200 and jbody(body)['groups'][0]['cn'] == 'g03', 'machine: groups cursor page 2 continues (g03...)')
  st, _, body = main_api.machine(tok('svc-reader'), '/api/entry?dn=' + urllib.parse.quote(seed_user_dn))
  entry = jbody(body)
  check(st == 200 and entry['dn'] == seed_user_dn and 'userPassword' not in json.dumps(entry), 'machine: getEntry inside BASE_DN -> 200, no userPassword')
  st, _, body = main_api.machine(tok('svc-reader'), '/api/entry?dn=' + urllib.parse.quote(base_dn))
  check(st == 200, 'machine: getEntry of the base DN itself -> 200')
  st, _, body = main_api.machine(tok('svc-reader'), '/api/tree')
  check(st == 200 and any(n['dn'].startswith('ou=people') for n in jbody(body)), 'machine: listTree of the base -> 200')
  st, _, body = main_api.machine(tok('svc-reader'), '/api/password-policies')
  check(st == 200, 'machine: listPasswordPolicies -> 200')
  st, _, body = main_api.machine(tok('svc-reader'), '/api/monitor')
  mon = jbody(body)
  check(st == 200 and mon.get('connectionsCurrent') is not None and not mon.get('recentLogs'),
        'machine: getMonitor -> 200 with statistics and WITHOUT accesslog entries (no audit.read)')

  new_machine = accesslog_binds(machine_dn) - machine_binds_before
  new_admin = accesslog_binds(admin_dn) - admin_binds_before
  check(new_machine == 9, f'the slapd accesslog shows exactly one bind as the machine DN per request ({new_machine} binds for 9 requests)')
  check(new_admin == 0, f'no administrator bind came from the machine path ({new_admin} new binds as {admin_dn})')

  # ---- denied scopes, operations and sensitive DNs: no LDAP connection at all --
  def denied_batch():
    gt = tok('svc-groups')
    st, _, body = main_api.machine(gt, '/api/users')
    check(st == 403 and jbody(body).get('code') == 'scope_denied', 'svc-groups (groups only): GET /api/users -> 403 scope_denied')
    rt = tok('svc-reader')
    for method, path in [('POST', '/api/users'), ('PUT', '/api/users'), ('PATCH', '/api/users'), ('DELETE', '/api/users?dn=x'),
                         ('POST', '/api/users/password'), ('POST', '/api/groups'), ('DELETE', '/api/groups/members'),
                         ('POST', '/api/entry/move'), ('GET', '/api/me'), ('GET', '/api/v1/application-profile-types'),
                         ('GET', '/api/audit/actions'), ('GET', '/api/server-settings'),
                         ('GET', '/api/nope')]:
      st, _, body = main_api.machine(rt, path, method=method)
      expect = 404 if path == '/api/nope' else 403
      if not (st == expect):
        raise AssertionError(f'{method} {path}: status {st} body {mask(body)}')
    print('PASS: reader token: 12 write/admin/not-granted routes -> 403 scope_denied and an unknown route -> 404', flush=True)
    for dn in ['cn=accesslog', 'reqStart=20260101000000.000000Z,cn=accesslog', 'cn=config', 'cn=Monitor', 'cn=Connections,cn=Monitor',
               'dc=org', 'dc=other,dc=org', 'cn=ACCESSLOG', 'cn=\\61ccesslog', 'uid=u01,dc=notexample,dc=org']:
      for route in ('/api/entry', '/api/tree'):
        st, _, body = main_api.machine(rt, route + '?dn=' + urllib.parse.quote(dn))
        if not (st == 403 and jbody(body).get('code') == 'scope_denied'):
          raise AssertionError(f'{route} dn={dn}: status {st} body {mask(body)}')
    print('PASS: getEntry/listTree refuse accesslog/config/Monitor/out-of-base/escaped variants -> 403 scope_denied', flush=True)
    st, _, body = main_api.machine(tamper(rt), '/api/users')
    check(st == 401, 'a token with a tampered signature -> 401')
  no_ldap_connections('denied scopes, write/admin routes, sensitive DNs and a bad token', denied_batch)

  # ---- ACL backstop (AC-015): even without the application guard the account cannot read them
  for base in ('cn=accesslog', 'cn=config'):
    res = ldap_tool('ldapsearch', ['-LLL', '-b', base, '-s', 'base', '(objectClass=*)'], machine_dn, '/tmp/.pw-machine')
    check('dn:' not in res.stdout, f'the machine DN reads nothing from {base} at the directory (ACL backstop, exit {res.returncode})')

  # ---- machine writes are impossible at the directory itself --------------------
  res = ldap_tool('ldapmodify', [], machine_dn, '/tmp/.pw-machine',
                  f'dn: {seed_user_dn}\nchangetype: modify\nreplace: description\ndescription: x\n')
  check('Insufficient access' in res.stderr, 'ldapmodify of another entry as the machine DN -> insufficient access (50)')
  res = ldap_tool('ldapmodify', [], machine_dn, '/tmp/.pw-machine',
                  f'dn: {machine_dn}\nchangetype: modify\nreplace: description\ndescription: x\n')
  check('Insufficient access' in res.stderr, 'ldapmodify of its own entry -> insufficient access (50)')
  res = ldap_tool('ldappasswd', ['-s', 'New-pw-1', machine_dn], machine_dn, '/tmp/.pw-machine')
  check('Insufficient access' in res.stdout + res.stderr and res.returncode != 0, 'ldappasswd of its own password -> insufficient access (50): ' + mask(res.stdout + res.stderr).strip())
  res = ldap_tool('ldapadd', [], machine_dn, '/tmp/.pw-machine',
                  f'dn: uid=evil,ou=people,{base_dn}\nobjectClass: inetOrgPerson\nuid: evil\ncn: e\nsn: e\n')
  check('Insufficient access' in res.stderr, 'ldapadd as the machine DN -> insufficient access (50)')
  res = ldap_tool('ldapdelete', [seed_user_dn], machine_dn, '/tmp/.pw-machine')
  check('Insufficient access' in res.stderr, 'ldapdelete as the machine DN -> insufficient access (50)')
  res = ldap_tool('ldapmodrdn', ['-r', seed_user_dn, 'uid=u01x'], machine_dn, '/tmp/.pw-machine')
  check('Insufficient access' in res.stdout + res.stderr and res.returncode != 0, 'ldapmodrdn as the machine DN -> insufficient access (50): ' + (res.stdout + res.stderr).strip()[:80])
  res = admin_tool('ldapsearch', ['-LLL', '-b', seed_user_dn, '-s', 'base', 'uid'])
  check('uid: u01' in res.stdout, 'the entry the machine tried to change/delete/rename is untouched')

  # ---- AC-005: nothing secret leaves, even with an over-privileged bind --------
  collected = []

  def over_get(client, path):
    st, hdrs, body = over_api.machine(tok(client), path)
    collected.append(body)
    return st, body

  def all_pages(client, resource):
    cursor, pages = '', 0
    while True:
      st, body = over_get(client, f'/api/{resource}?limit=2' + (('&cursor=' + urllib.parse.quote(cursor)) if cursor else ''))
      if not (st == 200):
        raise AssertionError(f'{resource}: {st} {mask(body)}')
      pages += 1
      cursor = jbody(body).get('nextCursor', '')
      if not cursor:
        return pages

  st, body = over_get('svc-reader', '/api/entry?dn=' + urllib.parse.quote(seed_user_dn))
  check(st == 200 and 'userPassword' not in body, 'over-privileged bind: getEntry(user) -> 200 and still no userPassword (the application denylist, not the ACL)')
  for dn in ['cn=accesslog', 'reqStart=20260101000000.000000Z,cn=accesslog', 'cn=config', 'cn=Monitor']:
    st, body = over_get('svc-reader', '/api/entry?dn=' + urllib.parse.quote(dn))
    check(st == 403, f'over-privileged bind: getEntry({dn}) -> 403 even though the ACL would allow it')
  st, body = over_get('svc-reader', '/api/tree?dn=' + urllib.parse.quote('cn=accesslog'))
  check(st == 403, 'over-privileged bind: listTree(cn=accesslog) -> 403')
  check(all_pages('svc-reader', 'users') == 5 and all_pages('svc-reader', 'groups') == 3, 'over-privileged bind: users and groups paged to the end (9 users in 5 pages, 5 groups in 3)')
  over_get('svc-reader', '/api/tree')
  st, body = over_get('svc-reader', '/api/monitor')
  check(st == 200 and not jbody(body).get('recentLogs'), 'over-privileged bind: getMonitor without audit.read -> no recentLogs although the ACL would let it read the accesslog')
  st, body = over_get('svc-audit', '/api/monitor')
  logs_with = jbody(body).get('recentLogs') or []
  check(st == 200 and len(logs_with) > 0, f'over-privileged bind: getMonitor WITH audit.read and server.monitor.read -> {len(logs_with)} recentLogs entries')
  st, body = over_get('svc-audit', '/api/audit/actions')
  check(st == 200, 'over-privileged bind: listAuditActions with audit.read -> 200 (attribute names only)')
  blob = '\n'.join(collected)
  forbidden = ['{SSHA}', '{ARGON2}', 'initial-pw-1', over_password, machine_password]
  for secret_value in accesslog_secrets + [seed_secret]:
    forbidden += [secret_value, base64.b64encode(secret_value.encode()).decode(),
                  base64.urlsafe_b64encode(secret_value.encode()).decode().rstrip('=')]
  hits = [f for f in forbidden if f in blob]
  check(not hits, f'no seeded secret value, hash or password in {len(collected)} machine responses (and reqMod names only: "userPassword" the attribute NAME may appear)')
  check('"changedAttrs"' in blob and 'userPassword' in blob, 'the audit DTO does carry the attribute NAME userPassword (the scan above is not vacuous)')

  # ---- AC-017: cursors are bound to issuer + client ----------------------------
  # On the second instance: a human session keeps its LDAP connection open, which
  # would disturb the connection accounting of the first one's proxy.
  human = over_api.login_human()
  st, _, body = over_api.machine(tok('svc-reader'), '/api/users?limit=2')
  cur_a = jbody(body)['nextCursor']
  st, _, body = over_api.call('GET', '/api/users?limit=2', human)
  check(st == 200 and jbody(body).get('nextCursor'), 'human session: users page 1 with a cursor (unchanged path)')
  human_cursor = jbody(body)['nextCursor']
  st, _, body = over_api.call('GET', '/api/users?limit=2&cursor=' + urllib.parse.quote(human_cursor), human)
  check(st == 200, 'human session: its own cursor continues (200)')
  st, _, body = over_api.machine(tok('svc-reader2'), '/api/users?limit=2&cursor=' + urllib.parse.quote(cur_a))
  check(st == 400 and jbody(body).get('code') == 'cursor_invalid', "client B replaying client A's cursor -> 400 cursor_invalid")
  st, _, body = over_api.call('GET', '/api/users?limit=2&cursor=' + urllib.parse.quote(cur_a), human)
  check(st == 400 and jbody(body).get('code') == 'cursor_invalid', "a human session replaying a machine cursor -> 400 cursor_invalid")
  st, _, body = over_api.machine(tok('svc-reader'), '/api/users?limit=2&cursor=' + urllib.parse.quote(human_cursor))
  check(st == 400 and jbody(body).get('code') == 'cursor_invalid', "the machine path replaying a human cursor -> 400 cursor_invalid")
  st, _, body = over_api.machine(tok('svc-reader'), '/api/users?limit=2&cursor=' + urllib.parse.quote(cur_a))
  check(st == 200, 'a freshly minted token of the same client continues its cursor (200)')

  # ---- AC-009: bind failure, hung directory, outage, aborts --------------------
  settled()
  # (1) wrong machine password -> 503, no fallback to any other identity
  res = admin_tool('ldapmodify', [], f'dn: {machine_dn}\nchangetype: modify\nreplace: userPassword\nuserPassword: Changed-{secrets.token_hex(6)}\n')
  check(res.returncode == 0, 'rotated the machine account password behind the UI (the UI now holds a wrong password)')
  st, _, body = main_api.machine(tok('svc-reader'), '/api/users?limit=2')
  check(st == 503 and jbody(body).get('code') == 'unavailable' and 'userPassword' not in body, 'wrong machine password -> 503 unavailable (no fallback to another identity, no data)')
  put_password_in_container('/tmp/.pw-machine', machine_password)
  res = admin_tool('ldapmodify', [], f'dn: {machine_dn}\nchangetype: modify\nreplace: userPassword\nuserPassword: {machine_password}\n')
  check(res.returncode == 0, 'restored the machine account password')
  st, _, body = main_api.machine(tok('svc-reader'), '/api/users?limit=2')
  check(st == 200, 'with the right password the same request is 200 again')

  # (2) a directory that accepts the connection and never answers
  settled()
  proxy.set_mode('blackhole')
  t0 = time.monotonic()
  st, _, body = main_api.machine(tok('svc-reader'), '/api/users?limit=2', timeout=20)
  elapsed = time.monotonic() - t0
  check(st == 503 and elapsed < 8, f'hung directory (bind never answered): 503 in {elapsed:.1f}s with MACHINE_REQUEST_TIMEOUT=3s')
  wait_until(lambda: proxy.open == 0, 'the UI to close the hung connection', 15)
  print('PASS: the hung connection was closed by the UI (proxy open connections 0)', flush=True)
  # (3) a directory that answers the bind and then hangs on the search
  proxy.set_mode('stall')
  t0 = time.monotonic()
  st, _, body = main_api.machine(tok('svc-reader'), '/api/users?limit=2', timeout=20)
  elapsed = time.monotonic() - t0
  check(st == 503 and elapsed < 8, f'hung directory (search never answered): 503 in {elapsed:.1f}s')
  proxy.release()
  proxy.set_mode('pass')
  wait_until(lambda: proxy.open == 0, 'the UI to close the connection after the deadline', 15)
  for _ in range(4):
    st, _, body = main_api.machine(tok('svc-reader'), '/api/users?limit=2')
    if not (st == 200):
      raise AssertionError(f'after the timeouts: {st} {mask(body)}')
  print('PASS: after the timeouts 4 sequential requests succeed (MACHINE_MAX_CONCURRENCY=2: no slot leaked)', flush=True)

  # (3b) a directory that accepts StartTLS and then stalls the TLS handshake: the
  # request deadline covers the handshake too, the connection is closed, and the
  # (single, MACHINE_MAX_CONCURRENCY=1) slot is free for the next request.
  staller = StartTLSStaller()
  proxies.append(staller)
  tls_env = machine_env(machine_dn, CLIENTS)
  tls_env.update({'LDAP_START_TLS': 'true', 'LDAP_TLS_INSECURE_SKIP_VERIFY': 'true', 'MACHINE_MAX_CONCURRENCY': '1'})
  tls_api = start_ui(ui_tls, f'ldap://host.docker.internal:{staller.port}', tls_env,
                     {'SESSION_SECRET': session_secret, 'MACHINE_LDAP_BIND_PASSWORD': machine_password})
  for attempt in range(2):
    t0 = time.monotonic()
    st, _, body = tls_api.machine(tok('svc-reader'), '/api/users?limit=2', timeout=20)
    elapsed = time.monotonic() - t0
    check(st == 503 and elapsed < 4.5, f'stalled StartTLS handshake (attempt {attempt + 1}): 503 in {elapsed:.1f}s with a 3s deadline (the single slot was free again for attempt 2)')
  wait_until(lambda: staller.open == 0, 'the UI to close the stalled StartTLS connection', 15)
  check(staller.accepted == 2, 'the stalled StartTLS connections were closed by the UI (open 0, 2 accepted)')

  # (4) clients that give up mid-request: connections and slots come back. The
  # directory's own view (cn=Monitor, readable by the image's monitoring identity)
  # must return to its baseline, not only the proxy's.
  def monitor_current_connections():
    res = ldap_tool('ldapsearch', ['-LLL', '-b', 'cn=Current,cn=Connections,cn=Monitor', '-s', 'base', 'monitorCounter'],
                    'cn=monitoring,cn=Monitor', '/tmp/.pw-admin')
    m = re.search(r'^monitorCounter: (\d+)$', res.stdout, re.M)
    if not m:
      raise AssertionError('cn=Monitor unreadable: ' + mask(res.stderr))
    return int(m.group(1))

  settled()
  baseline = monitor_current_connections()
  proxy.set_mode('stall')
  socks = []
  ui_port = int(main_api.base_url.rsplit(':', 1)[1])
  for _ in range(50):
    s = socket.create_connection(('127.0.0.1', ui_port), timeout=5)
    s.sendall((f'GET /api/users?limit=2 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {tok("svc-reader")}\r\n\r\n').encode())
    socks.append(s)
  wait_until(lambda: proxy.stalled.is_set(), 'a request to stall in the directory', 10)
  for s in socks:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))  # RST: the client is gone
    s.close()
  proxy.release()
  proxy.set_mode('pass')
  wait_until(lambda: proxy.open == 0, 'all connections to return to the baseline after 50 client aborts', 20)
  wait_until(lambda: monitor_current_connections() == baseline, 'slapd cn=Monitor connection count to return to its baseline', 20)
  codes = [main_api.machine(tok('svc-reader'), '/api/users?limit=2')[0] for _ in range(4)]
  check(codes == [200] * 4, f'50 aborted requests: proxy open 0, slapd cn=Monitor connections back at the baseline ({baseline}), slots free: next requests {codes}')

  # (5) slapd stopped while a request is in flight
  settled()
  proxy.set_mode('stall')
  result = {}

  def inflight():
    result['r'] = main_api.machine(tok('svc-reader'), '/api/users?limit=2', timeout=30)
  th = threading.Thread(target=inflight)
  th.start()
  wait_until(lambda: proxy.stalled.is_set(), 'the request to be in flight inside the directory', 10)
  if not (run(['docker', 'stop', '-t', '2', ldap_container]).returncode == 0):
    raise AssertionError("run(['docker', 'stop', '-t', '2', ldap_container]).returncode == 0")
  proxy.release()
  th.join(30)
  st = result['r'][0]
  check(st == 503, f'slapd stopped mid-request -> 503 (got {st})')
  proxy.set_mode('pass')
  wait_until(lambda: proxy.open == 0, 'connections to drain after the outage', 15)
  st, _, _ = main_api.machine(tok('svc-reader'), '/api/users?limit=2')
  check(st == 503, 'while slapd is down a new machine request is a 503 as well')
  if not (run(['docker', 'start', ldap_container]).returncode == 0):
    raise AssertionError("run(['docker', 'start', ldap_container]).returncode == 0")
  put = lambda: run(['docker', 'exec', '-i', ldap_container, 'sh', '-c', 'umask 077; cat > /tmp/.pw-admin'], input=admin_password).returncode == 0
  wait_until(lambda: put() and admin_tool('ldapsearch', ['-b', base_dn, '-s', 'base']).returncode == 0, 'slapd to come back', 90)
  wait_until(lambda: main_api.machine(tok('svc-reader'), '/api/users?limit=2')[0] == 200, 'the machine path to recover without a restart', 30)
  codes = [main_api.machine(tok('svc-reader'), '/api/users?limit=2')[0] for _ in range(4)]
  check(codes == [200] * 4 and proxy.open <= 1, 'after slapd came back the machine path recovered without restarting the UI; no leaked slot or connection')
  settled()

  # ---- limiters (T-018, AC-011): a small-limit container against the real stack ----
  # Own container so the small budget cannot disturb the probes above. Source IP
  # is the docker gateway for every request here (UI_TRUSTED_PROXIES=none), and
  # the failure window is the 1s minimum x5 so recovery is observable quickly.
  lim_window = 5
  lim_api = start_ui(ui_lim, f'ldap://{ldap_container}:389',
                     machine_env(machine_dn, CLIENTS, {
                         'MACHINE_AUTH_FAILURE_LIMIT': '3', 'MACHINE_AUTH_FAILURE_WINDOW': f'{lim_window}s',
                         'MACHINE_RATE_LIMIT_RPS': '1', 'MACHINE_RATE_LIMIT_BURST': '2',
                         'MACHINE_CLIENT_CONCURRENCY': '4', 'MACHINE_MAX_AUTH_CONCURRENCY': '16',
                         # 1 s so an unknown kid really triggers a JWKS refresh when it is allowed to
                         'MACHINE_JWKS_MIN_REFRESH': '1s'}),
                     {'SESSION_SECRET': session_secret, 'MACHINE_LDAP_BIND_PASSWORD': machine_password})
  limiter_tokens = []

  def lim_tok(client):
    t = tok(client)
    limiter_tokens.append(t)
    return t

  # client budget: burst 2 at 1 rps; another client keeps working
  codes = [lim_api.machine(lim_tok('svc-reader'), '/api/users?limit=1')[0] for _ in range(2)]
  st, hdrs, body = lim_api.machine(lim_tok('svc-reader'), '/api/users?limit=1')
  check(codes == [200, 200] and st == 429 and jbody(body).get('code') == 'machine_rate_limited' and jbody(body).get('retryable') is True,
        f'client budget: burst of 2 passes, the 3rd is 429 machine_rate_limited (got {codes} then {st})')
  retry = hdrs.get('Retry-After', '')
  check(retry.isdigit() and int(retry) >= 1, f'the budget 429 carries an integer Retry-After ({retry!r})')
  st2, _, _ = lim_api.machine(lim_tok('svc-reader2'), '/api/users?limit=1')
  check(st2 == 200, 'budget isolation: another client is still served while svc-reader is exhausted')
  time.sleep(int(retry) + 0.5)
  check(lim_api.machine(lim_tok('svc-reader'), '/api/users?limit=1')[0] == 200, 'the exhausted client recovers after Retry-After')
  # a refused request is not an authentication failure of the source
  time.sleep(lim_window + 1)  # drain the bucket and any window state

  # IP failure throttle: malformed headers count, the 4th attempt is refused
  def raw_get(headers):
    return lim_api.call('GET', '/api/users?limit=1', headers)

  odd = [raw_get({'Authorization': 'Bearer  two-spaces'})[0] for _ in range(3)]
  st, hdrs, body = raw_get({'Authorization': 'Bearer  two-spaces'})
  check(odd == [401, 401, 401] and st == 429 and jbody(body).get('code') == 'machine_rate_limited',
        f'IP throttle: 3 malformed Authorization headers are 401, the 4th is 429 (got {odd} then {st})')
  ra = hdrs.get('Retry-After', '')
  check(ra.isdigit() and 1 <= int(ra) <= lim_window, f'the IP 429 Retry-After is within the window ({ra!r})')
  # before any signature work: even a perfectly valid token is refused, and the issuer is never asked again
  jwks_before = mock_idp.jwks_hits
  st, _, body = lim_api.machine(lim_tok('svc-reader'), '/api/users?limit=1')
  check(st == 429 and jbody(body).get('code') == 'machine_rate_limited' and mock_idp.jwks_hits == jwks_before,
        'a VALID token from the throttled IP is refused with 429 before verification')
  time.sleep(int(ra) + 1)
  check(lim_api.machine(lim_tok('svc-reader'), '/api/users?limit=1')[0] == 200, 'recovery: the same source is served again after the window')
  # invalid signatures count as well
  bad_sigs = [lim_api.machine(tamper(lim_tok('svc-reader')), '/api/users?limit=1')[0] for _ in range(3)]
  st, _, _ = lim_api.machine(tamper(lim_tok('svc-reader')), '/api/users?limit=1')
  check(bad_sigs == [401, 401, 401] and st == 429, f'IP throttle: 3 bad signatures are 401, the 4th is 429 (got {bad_sigs} then {st})')
  time.sleep(lim_window + 1)
  check(lim_api.machine(lim_tok('svc-reader'), '/api/users?limit=1')[0] == 200, 'recovery after the window again')

  # ---- ordering proof: the IP throttle runs BEFORE any signature or JWKS work ----
  # A token whose kid the key set does not know forces a JWKS refresh whenever the
  # refresh budget allows one (MIN_REFRESH is 1s in this container), and the mock
  # issuer counts the fetches. So the proof is observable: from an unblocked
  # source such a token DOES cause a fetch (control); from the blocked source,
  # with the budget open again, neither it nor a large garbage JWS causes any.
  # (A cached-key verification would not move the counter, which is why a valid
  # token alone proves nothing about ordering.)
  def unknown_kid_token(n):
    t = mock_idp.mint('svc-reader', READER, kid=f'mx-unknown-{n}-{secrets.token_hex(3)}')
    limiter_tokens.append(t)
    return t

  time.sleep(1.5)
  h0 = mock_idp.jwks_hits
  st, _, body = lim_api.machine(unknown_kid_token(0), '/api/users?limit=1')
  check(st == 401 and mock_idp.jwks_hits == h0 + 1,
        f'control: an unknown-kid token from an unblocked source is a 401 AND forces a JWKS refresh ({mock_idp.jwks_hits - h0} fetch)')
  for _ in range(2):  # with the control's 401 that is 3 failures inside the window: blocked
    raw_get({'Authorization': 'Bearer  two-spaces'})
  time.sleep(1.5)  # the refresh budget is open again, so processed tokens WOULD fetch
  h1 = mock_idp.jwks_hits
  junk = '.'.join([b64u(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': 'mx-1'}).encode()), b64u(os.urandom(5000)), b64u(os.urandom(256))])
  statuses = [lim_api.machine(unknown_kid_token(i), '/api/users?limit=1')[0] for i in (1, 2, 3)]
  statuses.append(lim_api.machine(junk, '/api/users?limit=1')[0])
  check(statuses == [429] * 4 and mock_idp.jwks_hits == h1,
        f'blocked source: unknown-kid tokens and a ~7 KiB garbage JWS are 429 with ZERO upstream fetches (statuses {statuses}, fetches {mock_idp.jwks_hits - h1})')
  time.sleep(lim_window + 1)
  check(lim_api.machine(lim_tok('svc-reader'), '/api/users?limit=1')[0] == 200, 'recovery after the ordering proof')

  # ---- holds are released on every exit path (real container, caps of 1) ----------
  # Global authentication cap 1 and client concurrency 1: a slot or reservation that
  # leaked even once would turn every later request into 503/429. Sequential
  # requests of every kind, including client aborts mid-request, run first; then N
  # normal requests must all succeed. Panic-release is NOT covered here (there is
  # no test-only way to make a real handler panic in the shipped build); the unit
  # tests inject panics at every stage.
  cap_api = start_ui(ui_cap, f'ldap://{ldap_container}:389',
                     machine_env(machine_dn, CLIENTS, {
                         # 10 failures: the 8 deliberate 401s stay below it, but leaked IP
                         # reservations (each held up to the 3s request timeout) would not
                         'MACHINE_AUTH_FAILURE_LIMIT': '10', 'MACHINE_RATE_LIMIT_RPS': '10000',
                         'MACHINE_RATE_LIMIT_BURST': '10000', 'MACHINE_CLIENT_CONCURRENCY': '1',
                         'MACHINE_MAX_AUTH_CONCURRENCY': '1'}),
                     {'SESSION_SECRET': session_secret, 'MACHINE_LDAP_BIND_PASSWORD': machine_password})
  cap_host, cap_port = urllib.parse.urlparse(cap_api.base_url).netloc.split(':')

  def abort_midrequest(token):
    s = socket.create_connection((cap_host, int(cap_port)), timeout=5)
    s.sendall(f'GET /api/users?limit=5 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n\r\n'.encode())
    s.close()  # gone before (or while) the server answers
    time.sleep(0.4)  # the aborted request finishes server side; a leak would outlive this

  seq = []
  for _ in range(8):
    seq.append(cap_api.machine(lim_tok('svc-reader'), '/api/users?limit=2')[0])           # 200
    seq.append(cap_api.machine(tamper(lim_tok('svc-reader')), '/api/users?limit=2')[0])   # 401
    seq.append(cap_api.machine(lim_tok('svc-groups'), '/api/users?limit=2')[0])           # 403
    abort_midrequest(lim_tok('svc-reader'))
  check(seq == [200, 401, 403] * 8, f'caps of 1: 8 rounds of 200/401/403 plus a mid-request client abort are served as expected (statuses seen {sorted(set(seq))})')
  after = [cap_api.machine(lim_tok('svc-reader'), '/api/users?limit=2')[0] for _ in range(12)]
  check(after == [200] * 12, f'caps of 1: after all exit paths 12 sequential requests all succeed (a leaked slot or reservation would be 503/429): {after}')
  lim_lines = audit_lines(ui_lim)
  check(any('"reason":"rate"' in l and '"actor":"svc-reader"' in l for l in lim_lines) and
        any('"reason":"rate"' in l and '"actor":"unknown"' in l and '"token_fingerprint"' in l for l in lim_lines),
        'audit: the budget 429 names the client, the IP 429 is actor unknown with a fingerprint, both reason=rate')

  # ---- AC-010: one audit line per request, no token material in any log -------
  rids = []
  tokens_used = list(limiter_tokens)
  for i in range(6):
    t = tok('svc-reader')
    tokens_used.append(t)
    rid = f'mx-audit-{i}-{secrets.token_hex(3)}'
    rids.append(rid)
    main_api.machine(t, '/api/users?limit=2', req_id=rid)
  bad = tamper(tokens_used[0])
  tokens_used.append(bad)
  bad_rid = 'mx-audit-bad-' + secrets.token_hex(3)
  rids.append(bad_rid)
  main_api.machine(bad, '/api/users', req_id=bad_rid)
  rid = 'mx-audit-denied-' + secrets.token_hex(3)
  rids.append(rid)
  main_api.machine(tok('svc-groups'), '/api/users', req_id=rid)
  lines = audit_lines(ui_main)
  for rid in rids:
    n = sum(1 for l in lines if f'"request_id":"{rid}"' in l)
    if not (n == 1):
      raise AssertionError(f'request {rid}: {n} audit lines')
  print(f'PASS: each of {len(rids)} Authorization-carrying requests produced exactly one machine_access line', flush=True)
  bad_line = next(l for l in lines if f'"request_id":"{bad_rid}"' in l)
  check('"actor":"unknown"' in bad_line and '"token_fingerprint"' in bad_line, 'a bad signature is logged with actor unknown plus a token fingerprint')
  check(any('"actor":"svc-groups"' in l and '"reason":"scope"' in l for l in lines), 'a scope denial after verification names the verified client as actor')
  scan = ''
  for c in (ui_main, ui_over, ui_off, ui_tls, ui_lim, ui_cap, ldap_container):
    out = run(['docker', 'logs', c])
    scan += out.stdout + out.stderr
  leaks = []
  for t in tokens_used + [machine_password, over_password, admin_password, session_secret, 'Bearer ey']:
    parts = [t] if t.count('.') != 2 else [t] + t.split('.')
    for p in parts:
      if p in scan:
        leaks.append(p[:12] + '...')
  check(not leaks, 'no token, signature piece, JWT segment, bind password or secret in any container log: ' + str(leaks))

  print('\nAll machine execution identity checks passed in %.0fs.' % (time.monotonic() - start_monotonic), flush=True)


def tamper(token):
  head, body, sig = token.split('.')
  flipped = ('B' if sig[3] == 'A' else 'A')
  return '.'.join([head, body, sig[:3] + flipped + sig[4:]])


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    dump_logs()
    raise
