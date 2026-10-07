#!/usr/bin/env python3
"""Live verification of conditional writes and idempotency (#216, issue #251).

Exercises against a real OpenLDAP slapd and ldapium UI backend:
  (a) Socket kill mid-write and retry with the same Idempotency-Key,
      proving no duplicate or destructive effect.
  (b) Wire-level go-ldap DelRequest with mismatching (entryUUID, entryCSN)
      assertion control answering LDAP result code 122 (assertionFailed)
      and mapping to domain.ErrRevisionConflict (412) / domain.CreatePartial (500).
  (c) Forcing a genuinely refused compensation on user create to observe
      the 500 partial_failure response with state=partial and surviving entry.
  (d) ppolicy lastbind bumping entryCSN and exercising If-Match in SSO mode.
  (e) Concurrent same-tag writes (one 204, rest 412), concurrent same-key requests
      (409 idempotency_key_conflict while in flight), PATCH merge preservation (#268).

Run with:
  python3 scripts/test/test-api-conditional-writes-local.py
"""
import base64
import http.client
import http.cookiejar
import http.server
import json
import os
import pathlib
import secrets
import socket
import socketserver
import struct
import sys
import subprocess
import threading
import tempfile
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
ldap_image = os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')
ui_image = os.environ.get('LDAPIUM_UI_IMAGE', 'ldapium-ui:e2e')
prefix = os.environ.get('LDAPIUM_TEST_PREFIX', 'ldapium-cw-251-')
run_id = uuid.uuid4().hex[:6]
name_prefix = prefix + run_id

network = name_prefix + '-net'
ldap_container = name_prefix + '-ldap'
ui_container = name_prefix + '-ui'
base_dn = 'dc=example,dc=org'
admin_dn = 'cn=admin,' + base_dn
admin_password = secrets.token_urlsafe(24)
ops_dn = 'uid=ops,ou=admins,' + base_dn
ops_password = 'Ops-' + secrets.token_urlsafe(16) + '!x'
session_secret = secrets.token_hex(32)

containers = []
created_network = False


def check(condition, message):
  if not condition:
    raise AssertionError(message)
  print('PASS: ' + message)


def mask(text):
  # Scrub every secret this run generated before anything reaches CI logs.
  text = text if isinstance(text, str) else str(text)
  for secret in (admin_password, ops_password, session_secret, 'sso-secret'):
    text = text.replace(secret, '***')
  return text


def dump_container_logs():
  for c in containers:
    res = subprocess.run(['docker', 'logs', '--tail', '200', c], capture_output=True, text=True)
    print(f'--- docker logs {c} (scrubbed, last 200 lines) ---', file=sys.stderr)
    print(mask(res.stdout + res.stderr), file=sys.stderr)


def describe(status, hdrs, body):
  keep = ('location', 'content-type', 'etag', 'set-cookie', 'www-authenticate')
  shown = {k: mask(v) for k, v in (hdrs.items() if hdrs is not None else []) if k.lower() in keep}
  return f'status={status} headers={shown} body={mask(json.dumps(body) if not isinstance(body, str) else body)[:500]}'


def cleanup():
  for c in containers:
    subprocess.run(['docker', 'rm', '-fv', c], capture_output=True)
  if created_network:
    subprocess.run(['docker', 'network', 'rm', network], capture_output=True)


def wait_until(predicate, what, timeout=30.0):
  # Poll an observable condition with a deadline instead of sleeping a fixed time.
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if predicate():
      return
    time.sleep(0.1)
  raise AssertionError(f'timed out after {timeout}s waiting for {what}')


def entry_snapshot(dn):
  res = ldap_admin_tool('ldapsearch', ['-LLL', '-b', dn, '-s', 'base', '*', '+'])
  if not (res.returncode == 0):
    raise AssertionError(f'ldapsearch {dn} failed: {res.stderr}')
  return res.stdout


def retry_keyed(api, method, path, body, key):
  # While the dropped request is still in flight the key is held: 409 idempotency_key_conflict.
  # Retry on exactly that until the original finishes, then expect the recorded result.
  deadline = time.monotonic() + 30
  while True:
    status, hdrs, resp = api.call(method, path, body, {'Idempotency-Key': key})
    in_flight = status == 409 and isinstance(resp, dict) and resp.get('code') == 'idempotency_key_conflict'
    if not in_flight or time.monotonic() > deadline:
      return status, hdrs, resp
    time.sleep(0.2)


def ldap_admin_tool(tool, args, input_data=None):
  return subprocess.run(
      ['docker', 'exec', '-i', ldap_container, tool, '-x', '-H', 'ldap://127.0.0.1',
       '-D', admin_dn, '-w', admin_password] + args,
      input=input_data, capture_output=True, text=True
  )


def ldap_config_tool(tool, args, input_data=None):
  return subprocess.run(
      ['docker', 'exec', '-i', ldap_container, tool, '-x', '-H', 'ldap://127.0.0.1',
       '-D', 'cn=admin,cn=config', '-w', admin_password] + args,
      input=input_data, capture_output=True, text=True
  )


class ApiClient:
  def __init__(self, base_url):
    self.base_url = base_url
    self.jar = http.cookiejar.CookieJar()
    self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

  def call(self, method, path, body=None, headers=None):
    hdrs = {'Origin': self.base_url, 'Content-Type': 'application/json', **(headers or {})}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(self.base_url + path, method=method, data=data, headers=hdrs)
    try:
      with self.opener.open(req, timeout=30) as resp:
        raw = resp.read()
        return resp.status, resp.headers, json.loads(raw) if raw else None
    except urllib.error.HTTPError as err:
      raw = err.read()
      return err.code, err.headers, json.loads(raw) if raw else None

  def login_ldap(self, identity, password):
    status, _, body = self.call('POST', '/api/login', {'identity': identity, 'password': password})
    check(status == 200, f'LDAP login as {identity} (status={status})')


PWD_MODIFY_OID = b'1.3.6.1.4.1.4203.1.11.1'


class OIDScanner:
  """Detects an OID in a TCP byte stream even when split across recv() chunks.

  Keeps a rolling tail of len(OID)-1 bytes so a match straddling any chunk
  boundary is still found (D1: recv() chunking is not a protocol boundary).
  """
  def __init__(self, oid=PWD_MODIFY_OID):
    self.oid = oid
    self.tail = b''

  def feed(self, data):
    window = self.tail + data
    found = self.oid in window
    self.tail = window[-(len(self.oid) - 1):]
    return found


def selftest_oid_scanner():
  pad = b'\x30\x1d\x02\x01\x02\x77\x18\x80\x17'
  stream = pad + PWD_MODIFY_OID + b'\x81\x00'
  for cut in range(1, len(stream)):
    sc = OIDScanner()
    hit = sc.feed(stream[:cut]) or sc.feed(stream[cut:])
    if not hit:
      raise AssertionError(f'OIDScanner missed OID split at byte {cut}')
  sc = OIDScanner()
  for i in range(len(stream)):
    if sc.feed(stream[i:i + 1]):
      break
  else:
    raise AssertionError('OIDScanner missed OID fed byte-by-byte')
  sc = OIDScanner()
  if sc.feed(pad) or sc.feed(b'\x81\x00'):
    raise AssertionError('OIDScanner false positive')
  print(f'PASS: OIDScanner detects the OID split at all {len(stream) - 1} boundaries and byte-by-byte')


class DropProxy:
  """One-shot HTTP proxy that RSTs the client once the full request is at the backend.

  Forwards exactly one request (headers + Content-Length body) to the backend,
  sets `forwarded`, never relays any response bytes, then resets the client
  socket and closes the backend side. This makes 'closed while in flight'
  deterministic: the request is fully delivered before the drop.
  """
  def __init__(self, target_host, target_port):
    self.target = (target_host, target_port)
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock.bind(('127.0.0.1', 0))
    self.port = self.sock.getsockname()[1]
    self.sock.listen(1)
    self.forwarded = threading.Event()
    self.response_bytes_to_client = 0
    threading.Thread(target=self._run, daemon=True).start()

  def _run(self):
    try:
      client, _ = self.sock.accept()
      backend = socket.create_connection(self.target, timeout=10)
      buf = b''
      while b'\r\n\r\n' not in buf:
        chunk = client.recv(4096)
        if not chunk:
          return
        buf += chunk
      head, _, body = buf.partition(b'\r\n\r\n')
      length = 0
      for line in head.split(b'\r\n')[1:]:
        k, _, v = line.partition(b':')
        if k.strip().lower() == b'content-length':
          length = int(v.strip())
      while len(body) < length:
        chunk = client.recv(4096)
        if not chunk:
          return
        body += chunk
      backend.sendall(head + b'\r\n\r\n' + body)
      self.forwarded.set()
      client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
      client.close()
      backend.close()
    except Exception:
      pass
    finally:
      self.sock.close()


def drop_in_flight(ui_port, raw_req):
  """Send raw_req through a DropProxy; return after the proxy has RST the client."""
  dp = DropProxy('127.0.0.1', ui_port)
  s = socket.create_connection(('127.0.0.1', dp.port), timeout=10)
  s.sendall(raw_req)
  check(dp.forwarded.wait(timeout=10), 'full request reached the backend before the drop')
  s.settimeout(5)
  try:
    got = s.recv(4096)
  except ConnectionResetError:
    got = b''
  check(got == b'', f'client saw no response bytes before/at the drop (got {len(got)} bytes)')
  s.close()


# --- TCP Proxy for intercepting LDAP traffic (used in parts a & c) ---
class LDAPProxy:
  def __init__(self, target_host, target_port):
    self.target_host = target_host
    self.target_port = target_port
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.sock.bind(('0.0.0.0', 0))
    self.port = self.sock.getsockname()[1]
    self.sock.listen(20)
    self.intercept_pwd_modify = False
    self.drop_next_modify = False
    self.pwd_modify_event = threading.Event()
    self.bump_done = threading.Event()
    self.running = True
    threading.Thread(target=self._accept_loop, daemon=True).start()

  def _accept_loop(self):
    while self.running:
      try:
        client, _ = self.sock.accept()
        threading.Thread(target=self._handle_conn, args=(client,), daemon=True).start()
      except Exception:
        break

  def _handle_conn(self, client):
    try:
      server = socket.create_connection((self.target_host, self.target_port), timeout=10)
    except Exception:
      client.close()
      return

    def fwd(src, dst, is_upstream):
      scanner = OIDScanner()
      try:
        while self.running:
          data = src.recv(4096)
          if not data:
            break
          if is_upstream:
            if self.drop_next_modify and (b'\x66' in data or b'replace' in data): # Modify / Del tag
              self.drop_next_modify = False
              dst.sendall(data)
              # Force drop connection immediately before response
              src.close()
              dst.close()
              return
            if scanner.feed(data) and self.intercept_pwd_modify:
              self.pwd_modify_event.set()
              # Hold the request until the external entryCSN bump has landed in slapd
              self.bump_done.wait(timeout=30)
          dst.sendall(data)
      except Exception:
        pass
      finally:
        src.close()
        dst.close()

    threading.Thread(target=fwd, args=(client, server, True), daemon=True).start()
    threading.Thread(target=fwd, args=(server, client, False), daemon=True).start()

  def close(self):
    self.running = False
    self.sock.close()


# --- Mock OIDC Server (used in part d) ---
class MockOIDCServer:
  def __init__(self):
    self.tmp_dir = tempfile.TemporaryDirectory(prefix='oidc-key-')
    self.key_file = os.path.join(self.tmp_dir.name, 'key.pem')
    if HAVE_CRYPTO:
      self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
      pub = self.key.public_key().public_numbers()
      def b64u(n):
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return base64.urlsafe_b64encode(b).decode().rstrip('=')
      self.jwk = {
          'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': 'k1',
          'n': b64u(pub.n), 'e': b64u(pub.e)
      }
    else:
      subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', self.key_file], check=True, stderr=subprocess.DEVNULL)
      p = subprocess.Popen(['openssl', 'rsa', '-in', self.key_file, '-noout', '-modulus'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
      mod_out, _ = p.communicate()
      mod_hex = mod_out.decode().strip().split('=')[1]
      n_b64 = base64.urlsafe_b64encode(bytes.fromhex(mod_hex)).decode().rstrip('=')
      e_b64 = base64.urlsafe_b64encode(bytes([1, 0, 1])).decode().rstrip('=')
      self.jwk = {
          'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': 'k1',
          'n': n_b64, 'e': e_b64
      }
    self.nonces = {}
    self.server = None
    self.port = 0

  def sign(self, data: bytes) -> bytes:
    if HAVE_CRYPTO:
      return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    p = subprocess.Popen(['openssl', 'dgst', '-sha256', '-sign', self.key_file], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    sig, _ = p.communicate(input=data)
    return sig

  def start(self):
    parent = self
    class Handler(http.server.BaseHTTPRequestHandler):
      def log_message(self, format, *args):
        pass

      def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == '/.well-known/openid-configuration':
          body = json.dumps({
              'issuer': f'http://host.docker.internal:{parent.port}',
              'authorization_endpoint': f'http://127.0.0.1:{parent.port}/auth',
              'token_endpoint': f'http://host.docker.internal:{parent.port}/token',
              'jwks_uri': f'http://host.docker.internal:{parent.port}/jwks',
              'response_types_supported': ['code'],
              'subject_types_supported': ['public'],
              'id_token_signing_alg_values_supported': ['RS256'],
              'end_session_endpoint': f'http://127.0.0.1:{parent.port}/logout',
          }).encode()
          self.send_response(200)
          self.send_header('Content-Type', 'application/json')
          self.end_headers()
          self.wfile.write(body)
        elif u.path == '/jwks':
          self.send_response(200)
          self.send_header('Content-Type', 'application/json')
          self.end_headers()
          self.wfile.write(json.dumps({'keys': [parent.jwk]}).encode())
        elif u.path == '/auth':
          q = urllib.parse.parse_qs(u.query)
          state = q['state'][0]
          parent.nonces[state] = q.get('nonce', [''])[0]
          redir = q['redirect_uri'][0] + f'?code=code-{state}&state={state}'
          self.send_response(302)
          self.send_header('Location', redir)
          self.end_headers()
        else:
          self.send_response(404)
          self.end_headers()

      def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == '/token':
          length = int(self.headers.get('Content-Length', 0))
          form = urllib.parse.parse_qs(self.rfile.read(length).decode())
          code = form['code'][0]
          state = code.replace('code-', '')
          nonce = parent.nonces.get(state, '')
          now = int(time.time())
          def b64u_bytes(b):
            return base64.urlsafe_b64encode(b).decode().rstrip('=')
          hdr = b64u_bytes(json.dumps({'alg': 'RS256', 'kid': 'k1'}).encode())
          payload = b64u_bytes(json.dumps({
              'iss': f'http://host.docker.internal:{parent.port}',
              'sub': 'ops',
              'aud': 'ldapium-sso',
              'exp': now + 3600,
              'iat': now,
              'preferred_username': 'ops',
              'nonce': nonce,
              'realm_access': {'roles': ['admin']}
          }).encode())
          sig = b64u_bytes(parent.sign(f'{hdr}.{payload}'.encode()))
          jwt = f'{hdr}.{payload}.{sig}'
          res = json.dumps({'access_token': 'test-acc', 'token_type': 'Bearer', 'expires_in': 3600, 'id_token': jwt}).encode()
          self.send_response(200)
          self.send_header('Content-Type', 'application/json')
          self.end_headers()
          self.wfile.write(res)
        else:
          self.send_response(404)
          self.end_headers()

    self.server = socketserver.TCPServer(('0.0.0.0', 0), Handler)
    self.port = self.server.server_address[1]
    threading.Thread(target=self.server.serve_forever, daemon=True).start()

  def close(self):
    if self.server:
      self.server.shutdown()
    self.tmp_dir.cleanup()


def get_free_port():
  s = socket.socket()
  s.bind(('127.0.0.1', 0))
  port = s.getsockname()[1]
  s.close()
  return port


def start_ui_container(container_name, extra_env=None, fixed_port=None):
  port_line = subprocess.run(['docker', 'port', ldap_container, '389/tcp'], check=True, capture_output=True, text=True).stdout
  ldap_host_port = port_line.splitlines()[0].rsplit(':', 1)[1]
  env = [
      '-e', 'LDAP_BASE_DN=' + base_dn,
      '-e', 'LDAP_USER_CREATE_BASE=ou=people,' + base_dn,
      '-e', 'LDAP_GROUP_CREATE_BASE=ou=groups,' + base_dn,
      '-e', 'SESSION_SECRET=' + session_secret,
      '-e', 'COOKIE_SECURE=false',
      '-e', 'UI_IDEMPOTENCY_ENABLED=true',
  ]
  if extra_env:
    for k, v in extra_env.items():
      env += ['-e', f'{k}={v}']

  subprocess.run(['docker', 'rm', '-fv', container_name], capture_output=True)
  port_arg = ['-p', f'127.0.0.1:{fixed_port}:8080'] if fixed_port else ['-p', '127.0.0.1::8080']
  cmd = [
      'docker', 'run', '-d', '--name', container_name,
      '--network', network,
      '--add-host', 'host.docker.internal:host-gateway',
  ] + port_arg + env + [ui_image]
  subprocess.run(cmd, check=True)
  containers.append(container_name)

  # Wait for UI readiness
  port_str = subprocess.run(['docker', 'port', container_name, '8080/tcp'], check=True, capture_output=True, text=True).stdout.splitlines()[0].rsplit(':', 1)[1]
  base_url = 'http://127.0.0.1:' + port_str
  for _ in range(60):
    try:
      with urllib.request.urlopen(base_url + '/api/auth/config', timeout=1) as resp:
        if resp.status == 200:
          return base_url, int(port_str)
    except Exception:
      time.sleep(0.5)
  raise RuntimeError(f'UI container {container_name} failed to become ready')


def main():
  global created_network
  selftest_oid_scanner()
  try:
    print(f'Starting test run {name_prefix} using LDAP image {ldap_image} and UI image {ui_image}...')
    subprocess.run(['docker', 'network', 'create', network], check=True)
    created_network = True

    # 1. Start OpenLDAP slapd container with LDAP_LASTBIND_ENABLED=true
    print('Starting OpenLDAP slapd container...')
    cmd = [
        'docker', 'run', '-d', '--name', ldap_container,
        '--network', network,
        '-p', '127.0.0.1::389',
        '-e', f'LDAP_ROOT_DN={base_dn}',
        '-e', f'LDAP_ADMIN_PASSWORD={admin_password}',
        '-e', 'LDAP_LASTBIND_ENABLED=true',
        '-e', 'LDAP_LASTBIND_PRECISION=0',
        ldap_image
    ]
    subprocess.run(cmd, check=True)
    containers.append(ldap_container)

    # Wait for slapd
    ldap_port_str = subprocess.run(['docker', 'port', ldap_container, '389/tcp'], check=True, capture_output=True, text=True).stdout.splitlines()[0].rsplit(':', 1)[1]
    ldap_host_port = int(ldap_port_str)
    for _ in range(60):
      res = ldap_admin_tool('ldapsearch', ['-b', base_dn, '-s', 'base'])
      if res.returncode == 0:
        break
      time.sleep(0.5)
    else:
      raise RuntimeError('OpenLDAP slapd failed to become ready')

    # Bootstrap tree
    bootstrap_ldif = f"""dn: ou=people,{base_dn}
objectClass: organizationalUnit
ou: people

dn: ou=admins,{base_dn}
objectClass: organizationalUnit
ou: admins

dn: {ops_dn}
objectClass: inetOrgPerson
uid: ops
cn: Ops
sn: Ops
userPassword: {ops_password}
"""
    res = ldap_admin_tool('ldapadd', [], bootstrap_ldif)
    check(res.returncode == 0, 'bootstrapped ou=people, ou=admins and ops user')

    # Give ops write access on dc=example,dc=org with by * break
    ops_acl = f"""dn: olcDatabase={{1}}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {{0}}to dn.subtree="{base_dn}" by dn.exact="{ops_dn}" write by * break
"""
    res = ldap_config_tool('ldapmodify', [], ops_acl)
    check(res.returncode == 0, 'granted ops operator ACL on the database')

    # -------------------------------------------------------------------------------------------------
    # (b) Wire-level go-ldap Delete with mismatching (entryUUID, entryCSN) assertion control
    # -------------------------------------------------------------------------------------------------
    print('\n--- Executing (b): wire-level go-ldap Delete with mismatching assertion control ---')
    go_test_env = dict(
        os.environ,
        LDAP_LIVE_URL=f'ldap://127.0.0.1:{ldap_host_port}',
        LDAP_LIVE_ROOT=base_dn,
        LDAP_LIVE_ADMIN_PASSWORD=admin_password
    )
    test_res = subprocess.run(
        ['go', 'test', '-tags', 'live', '-v', '-run', 'TestLiveAssertionDelete', './internal/ldapclient/'],
        cwd=repo_root / 'ui/backend', env=go_test_env, capture_output=True, text=True
    )
    check(test_res.returncode == 0, '(b) go-ldap Delete with mismatching assertion control answers LDAP 122 and maps to ErrRevisionConflict/CreatePartial')
    print(test_res.stdout.strip())

    # -------------------------------------------------------------------------------------------------
    # Setup TCP proxy to slapd for (a) and (c)
    # -------------------------------------------------------------------------------------------------
    proxy = LDAPProxy('127.0.0.1', ldap_host_port)
    print(f'LDAP proxy listening on host port {proxy.port}')

    # Start UI container pointing to proxy via host.docker.internal
    ui_url, ui_port = start_ui_container(ui_container, {
        'LDAP_URL': f'ldap://host.docker.internal:{proxy.port}'
    })
    api = ApiClient(ui_url)
    api.login_ldap(ops_dn, ops_password)

    # -------------------------------------------------------------------------------------------------
    # (a) Kill the socket mid-write and retry with the same Idempotency-Key
    # -------------------------------------------------------------------------------------------------
    print('\n--- Executing (a): socket kill mid-write and retry with same Idempotency-Key ---')
    idem_key_create = 'idem-key-' + secrets.token_hex(8)
    user_body = {'uid': 'cw-idem-1', 'cn': 'CW Idem 1', 'sn': 'Idem'}
    user_body_json = json.dumps(user_body)

    raw_req = (
        f'POST /api/users HTTP/1.1\r\n'
        f'Host: 127.0.0.1:{ui_port}\r\n'
        f'Origin: {ui_url}\r\n'
        f'Content-Type: application/json\r\n'
        f'Idempotency-Key: {idem_key_create}\r\n'
        f'Cookie: {"; ".join([c.name + "=" + c.value for c in api.jar])}\r\n'
        f'Content-Length: {len(user_body_json)}\r\n\r\n'
        f'{user_body_json}'
    ).encode()
    # Request is forwarded in full to the backend, then the client is RST (no response relayed)
    drop_in_flight(ui_port, raw_req)

    # Wait until the decoupled write (context.WithoutCancel) is observable in the directory
    idem_dn = f'uid=cw-idem-1,ou=people,{base_dn}'
    wait_until(lambda: 'dn: uid=cw-idem-1' in ldap_admin_tool('ldapsearch', ['-b', base_dn, '(uid=cw-idem-1)', 'dn']).stdout,
               'dropped create to reach the directory')

    # Retry with the EXACT SAME Idempotency-Key
    status, hdrs, body = retry_keyed(api, 'POST', '/api/users', user_body, idem_key_create)
    check(status == 201, f'(a) create retry returned 201 (got {status})')
    check(hdrs.get('Idempotent-Replayed') == 'true', '(a) create retry carries Idempotent-Replayed: true')
    check(body.get('dn') == f'uid=cw-idem-1,ou=people,{base_dn}', '(a) create body has correct DN')

    # Verify LDAP contains exactly 1 entry
    search_res = ldap_admin_tool('ldapsearch', ['-b', base_dn, '(uid=cw-idem-1)', 'dn'])
    count = search_res.stdout.count('dn: uid=cw-idem-1')
    check(count == 1, f'(a) LDAP has exactly 1 entry for cw-idem-1 (count={count})')

    # Test lock retry with socket kill
    idem_key_lock = 'idem-key-' + secrets.token_hex(8)
    lock_body = {'dn': f'uid=cw-idem-1,ou=people,{base_dn}'}
    lock_body_json = json.dumps(lock_body)
    raw_lock_req = (
        f'POST /api/users/lock HTTP/1.1\r\n'
        f'Host: 127.0.0.1:{ui_port}\r\n'
        f'Origin: {ui_url}\r\n'
        f'Content-Type: application/json\r\n'
        f'Idempotency-Key: {idem_key_lock}\r\n'
        f'Cookie: {"; ".join([c.name + "=" + c.value for c in api.jar])}\r\n'
        f'Content-Length: {len(lock_body_json)}\r\n\r\n'
        f'{lock_body_json}'
    ).encode()
    drop_in_flight(ui_port, raw_lock_req)
    wait_until(lambda: 'pwdAccountLockedTime:' in entry_snapshot(idem_dn), 'dropped lock to reach the directory')
    locked_before = entry_snapshot(idem_dn)

    # Retry lock with same key
    status, hdrs, _ = retry_keyed(api, 'POST', '/api/users/lock', lock_body, idem_key_lock)
    check(status == 204, f'(a) lock retry returned 204 (got {status})')
    check(hdrs.get('Idempotent-Replayed') == 'true', '(a) lock retry carries Idempotent-Replayed: true')

    # Verify user is locked and entryCSN is stable
    locked_after = entry_snapshot(idem_dn)
    check('pwdAccountLockedTime:' in locked_after, '(a) entry is locked in directory')
    # Whole-entry equality covers pwdAccountLockedTime, entryCSN and modifyTimestamp
    check(locked_after == locked_before, '(a) replay left the entry byte-identical (lock timestamp and entryCSN unchanged)')

    # -------------------------------------------------------------------------------------------------
    # (e) #268: concurrent same-tag write, concurrent same-key requests, PATCH merge preservation
    # -------------------------------------------------------------------------------------------------
    print('\n--- Executing (e): concurrent same If-Match tag, concurrent same Idempotency-Key, PATCH merge ---')
    entry_path = lambda dn: f'/api/entry?dn={urllib.parse.quote(dn)}'

    # (e1) N concurrent writes carrying the SAME If-Match tag: assertion control is evaluated inside
    # the directory write, so exactly one wins and every other gets 412 revision_conflict.
    conc_dn = f'uid=cw-conc-1,ou=people,{base_dn}'
    status, _, _ = api.call('POST', '/api/users', {'uid': 'cw-conc-1', 'cn': 'CW Conc 1', 'sn': 'Conc', 'mail': 'conc@example.org'})
    check(status == 201, f'(e1) created {conc_dn} (status={status})')
    status, hdrs, _ = api.call('GET', entry_path(conc_dn))
    conc_tag = hdrs.get('ETag')
    check(status == 200 and conc_tag, f'(e1) read ETag {conc_tag}')
    # Proves: against the real directory the assertion decides each write, so concurrent same-tag writers
    # never both succeed. Does not prove atomicity of the server's code path by itself (the barrier only
    # aligns the clients); that is the directory's assertion control, covered by (b).
    n_writers = 6
    barrier = threading.Barrier(n_writers)
    results = [None] * n_writers

    def conc_writer(i):
      try:
        barrier.wait(timeout=10)
        if i % 2 == 0:
          results[i] = api.call('PUT', '/api/users', {'dn': conc_dn, 'cn': f'Conc Writer {i}', 'sn': 'Conc'}, {'If-Match': conc_tag})
        else:
          results[i] = api.call('PATCH', '/api/users', {'dn': conc_dn, 'cn': f'Conc Writer {i}'}, {'If-Match': conc_tag})
      except Exception as exc:
        results[i] = ('error', None, repr(exc))

    writers = [threading.Thread(target=conc_writer, args=(i,)) for i in range(n_writers)]
    for t in writers:
      t.start()
    for t in writers:
      t.join(timeout=60)
    codes = sorted(r[0] if r else 'none' for r in results)
    check(codes == [204] + [412] * (n_writers - 1),
          f'(e1) {n_writers} concurrent PUT/PATCH with the same If-Match: exactly one 204, rest 412 (got {codes})')
    for r in results:
      if r[0] == 412:
        check(r[2].get('code') == 'revision_conflict' and r[2].get('retryable') is False,
              f'(e1) loser body is revision_conflict, retryable false (got {r[2]})')
    winners = [i for i, r in enumerate(results) if r[0] == 204]
    cn_now = ldap_admin_tool('ldapsearch', ['-LLL', '-b', conc_dn, '-s', 'base', 'cn']).stdout
    check(f'cn: Conc Writer {winners[0]}' in cn_now and cn_now.count('cn: ') == 1,
          f'(e1) directory holds only the winner\'s value (writer {winners[0]}): {cn_now.strip()!r}')

    # (e2) Concurrent requests with the SAME Idempotency-Key while the first is in flight. The first
    # request is held at the LDAP proxy (its password step stalls) and released only after every
    # duplicate answered; the documented behaviour is asserted: 409 idempotency_key_conflict, retryable.
    # Why the held create ends in 403 (expected env property, not a product defect): ops has `write`
    # but not `manage` on userPassword, so slapd's ppolicy pwdSafeModify refuses the password set
    # (LDAP 50), the UI maps that to 403 forbidden and compensates by deleting the new entry. (c) relies
    # on the same refusal. The probe below pins that cause instead of assuming it.
    probe = subprocess.run(
        ['docker', 'exec', '-i', ldap_container, 'ldappasswd', '-x', '-H', 'ldap://127.0.0.1',
         '-D', ops_dn, '-w', ops_password, '-s', 'Probe-Pw-Strong-1x!', conc_dn],
        capture_output=True, text=True)
    probe_out = (probe.stdout + probe.stderr).strip()
    check(probe.returncode != 0 and '(50)' in probe_out,
          f'(e2) ops cannot set a password on another entry (LDAP 50 insufficient access, pwdSafeModify): rc={probe.returncode} {probe_out[:160]!r}')
    proxy.intercept_pwd_modify = True
    proxy.pwd_modify_event.clear()
    proxy.bump_done.clear()
    held_uid = 'cw-held-' + secrets.token_hex(4)
    held_dn = f'uid={held_uid},ou=people,{base_dn}'
    held_body = {'uid': held_uid, 'cn': 'CW Held', 'sn': 'Held', 'password': 'Held-Pw-Strong-1x!'}
    held_key = 'idem-key-' + secrets.token_hex(8)
    held_result = []
    first = threading.Thread(
        target=lambda: held_result.append(api.call('POST', '/api/users', held_body, {'Idempotency-Key': held_key})),
        daemon=True)
    first.start()
    n_dups = 5
    dup_results = [None] * n_dups
    try:
      check(proxy.pwd_modify_event.wait(timeout=30), '(e2) first keyed request is held in flight at the LDAP proxy')

      def dup_caller(i):
        try:
          dup_results[i] = api.call('POST', '/api/users', held_body, {'Idempotency-Key': held_key})
        except Exception as exc:
          dup_results[i] = ('error', None, repr(exc))

      dups = [threading.Thread(target=dup_caller, args=(i,)) for i in range(n_dups)]
      for t in dups:
        t.start()
      for t in dups:
        t.join(timeout=20)
      # The proxy hold self-expires after 30s; a slow run that lost the hold must fail loudly here.
      check(first.is_alive() and not held_result and all(r is not None for r in dup_results),
            f'(e2) all duplicates answered while the first request was still held (held_result={held_result}, dups={[r and r[0] for r in dup_results]})')
      dup_codes = [r[0] for r in dup_results]
      check(dup_codes == [409] * n_dups, f'(e2) {n_dups} concurrent same-key requests while in flight all got 409 (got {dup_codes})')
      for r in dup_results:
        check(r[2].get('code') == 'idempotency_key_conflict' and r[2].get('retryable') is True,
              f'(e2) body is idempotency_key_conflict, retryable true (got {r[2]})')
    finally:
      # Release the held request whatever happened above.
      proxy.intercept_pwd_modify = False
      proxy.bump_done.set()
      first.join(timeout=60)
    check(not first.is_alive() and held_result, '(e2) held request finished after release')
    held_status, _, held_body_resp = held_result[0]
    check(held_status == 403 and held_body_resp.get('code') == 'forbidden',
          f'(e2) held create ends in exactly 403 forbidden (password step refused) (got {held_status} {held_body_resp.get("code")})')
    gone = ldap_admin_tool('ldapsearch', ['-LLL', '-b', held_dn, '-s', 'base', 'dn'])
    check(gone.returncode == 32 and held_uid not in gone.stdout,
          f'(e2) compensation removed the entry: base search rc=32 noSuchObject (rc={gone.returncode})')
    allq = ldap_admin_tool('ldapsearch', ['-LLL', '-b', base_dn, f'(uid={held_uid})', 'dn'])
    check(allq.returncode == 0 and held_uid not in allq.stdout, f'(e2) subtree search finds no entry for the key\'s uid (rc={allq.returncode})')
    proxy.pwd_modify_event.clear()
    proxy.bump_done.clear()

    # (e3) PATCH merge preservation: changing one attribute must leave the others (single- and
    # multi-valued, incl. ones the API does not model) untouched in the directory.
    patch_uid = 'cw-patch-1'
    patch_dn = f'uid={patch_uid},ou=people,{base_dn}'
    seed_ldif = f"""dn: {patch_dn}
objectClass: inetOrgPerson
uid: {patch_uid}
cn: CW Patch 1
cn: CW Patch Alias
sn: Patch
givenName: Pat
mail: patch@example.org
telephoneNumber: +82 10 0000 0001
telephoneNumber: +82 10 0000 0002
description: first description
description: second description
"""
    res = ldap_admin_tool('ldapadd', [], seed_ldif)
    check(res.returncode == 0, f'(e3) seeded {patch_dn} with multi-valued attributes')
    status, hdrs, _ = api.call('GET', entry_path(patch_dn))
    patch_tag = hdrs.get('ETag')
    check(status == 200 and patch_tag, f'(e3) read ETag {patch_tag}')

    def attr_values(dn, attr):
      out = ldap_admin_tool('ldapsearch', ['-LLL', '-b', dn, '-s', 'base', attr]).stdout
      return sorted(line.split(': ', 1)[1] for line in out.splitlines() if line.startswith(attr + ': '))

    before = {a: attr_values(patch_dn, a) for a in ('cn', 'sn', 'givenName', 'telephoneNumber', 'description', 'objectClass', 'uid')}
    status, hdrs, body = api.call('PATCH', '/api/users', {'dn': patch_dn, 'mail': 'patched@example.org'}, {'If-Match': patch_tag})
    check(status == 204, f'(e3) PATCH of one attribute with If-Match returned 204 ({describe(status, hdrs, body)})')
    check(attr_values(patch_dn, 'mail') == ['patched@example.org'], '(e3) patched attribute changed in the directory')
    after = {a: attr_values(patch_dn, a) for a in before}
    check(after == before, f'(e3) every other attribute and multi-value preserved (before={before} after={after})')
    check(len(after['telephoneNumber']) == 2 and len(after['description']) == 2 and len(after['cn']) == 2,
          '(e3) multi-valued attributes kept both values')

    # Group PATCH: description change keeps the multi-valued member list.
    group_dn = f'cn=cw-patch-grp,ou=people,{base_dn}'
    group_ldif = f"""dn: {group_dn}
objectClass: groupOfNames
cn: cw-patch-grp
description: old group description
member: {patch_dn}
member: {conc_dn}
member: {ops_dn}
"""
    res = ldap_admin_tool('ldapadd', [], group_ldif)
    check(res.returncode == 0, f'(e3) seeded group {group_dn} with 3 members')
    status, hdrs, _ = api.call('GET', entry_path(group_dn))
    group_tag = hdrs.get('ETag')
    members_before = attr_values(group_dn, 'member')
    status, hdrs, body = api.call('PATCH', '/api/groups', {'dn': group_dn, 'description': 'new group description'}, {'If-Match': group_tag})
    check(status == 204, f'(e3) group PATCH with If-Match returned 204 ({describe(status, hdrs, body)})')
    check(attr_values(group_dn, 'description') == ['new group description'], '(e3) group description changed')
    check(attr_values(group_dn, 'member') == members_before and len(members_before) == 3,
          '(e3) group PATCH preserved all 3 member values')
    # A PATCH with the now-stale tag must still 412 and not touch anything.
    snap = entry_snapshot(patch_dn)
    status, _, body = api.call('PATCH', '/api/users', {'dn': patch_dn, 'mail': 'stale@example.org'}, {'If-Match': patch_tag})
    check(status == 412 and entry_snapshot(patch_dn) == snap, f'(e3) stale-tag PATCH is 412 and leaves the entry byte-identical (status={status})')

    # -------------------------------------------------------------------------------------------------
    # (c) Force a genuinely refused compensation and observe 500 partial_failure response
    # -------------------------------------------------------------------------------------------------
    print('\n--- Executing (c): forcing genuinely refused compensation -> 500 partial_failure ---')
    proxy.intercept_pwd_modify = True
    proxy.pwd_modify_event.clear()
    proxy.bump_done.clear()

    partial_uid = 'cw-part-' + secrets.token_hex(4)
    partial_dn = f'uid={partial_uid},ou=people,{base_dn}'
    partial_body = {
        'uid': partial_uid,
        'cn': 'CW Partial',
        'sn': 'Partial',
        'password': 'Forced-Pw-Refused-1x!'
    }

    def bump_entry():
      try:
        # Wait for proxy to intercept PasswordModifyRequest
        if proxy.pwd_modify_event.wait(timeout=30):
          # Entry exists in slapd! Bump description to change entryCSN from csn0 to csn1
          bump_ldif = f"""dn: {partial_dn}
changetype: modify
replace: description
description: bumped-during-create
"""
          res = ldap_admin_tool('ldapmodify', [], bump_ldif)
          if not (res.returncode == 0):
            raise AssertionError('bumped description successfully')
      finally:
        # Release the proxy only once the bump is committed (or the wait gave up)
        proxy.bump_done.set()

    bumper_thread = threading.Thread(target=bump_entry, daemon=True)
    bumper_thread.start()

    # Call POST /api/users with password:
    # 1. Add succeeds, reads id.CSN = csn0
    # 2. Proxy intercepts PasswordModify and pauses
    # 3. bumper_thread modifies description, bumping entryCSN to csn1 in slapd
    # 4. Proxy forwards PasswordModify, which fails with 50 (pwdSafeModify requires old password)
    # 5. UI calls compensateCreate: DelRequest with assert=(entryCSN=csn0)
    # 6. slapd evaluates assertion against csn1 and returns 122 assertionFailed!
    # 7. UI deleteOutcome maps 122 to domain.CreatePartial
    # 8. UI returns HTTP 500 code=partial_failure state=partial
    status, hdrs, body = api.call('POST', '/api/users', partial_body)
    bumper_thread.join()
    proxy.intercept_pwd_modify = False

    check(status == 500, f'(c) create with refused compensation returned 500 (got {status})')
    check(isinstance(body, dict), '(c) response body is JSON dict')
    check(body.get('code') == 'partial_failure', f'(c) response code is partial_failure (got {body.get("code")})')
    check(body.get('state') == 'partial', f'(c) response state is partial (got {body.get("state")})')
    check(body.get('dn') == partial_dn, f'(c) response dn is {partial_dn}')
    check(body.get('retryable') is False, '(c) partial_failure retryable is False')

    # Verify that the entry SURVIVED in LDAP and has the bumped description
    survive_res = ldap_admin_tool('ldapsearch', ['-b', partial_dn, '-s', 'base', 'description'])
    check('description: bumped-during-create' in survive_res.stdout, '(c) entry survived in LDAP with bumped description')

    # -------------------------------------------------------------------------------------------------
    # (d) Exercises ppolicy lastbind + If-Match in SSO mode
    # -------------------------------------------------------------------------------------------------
    print('\n--- Executing (d): ppolicy lastbind + If-Match in SSO mode ---')
    # Start mock OIDC server
    oidc = MockOIDCServer()
    oidc.start()

    # Stop LDAP-mode UI and start SSO-mode UI
    subprocess.run(['docker', 'rm', '-fv', ui_container], capture_output=True)
    sso_ui_port = get_free_port()
    sso_env = {
        # Same docker network as slapd: ldap_host_port is published on 127.0.0.1 only, which a
        # container reaches via host.docker.internal on Docker Desktop/Colima but NOT on a Linux
        # runner (host-gateway is the bridge IP, where a loopback-bound port is not listening).
        'LDAP_URL': f'ldap://{ldap_container}:389',
        'SSO_ENABLED': 'true',
        'SSO_ISSUER_URL': f'http://host.docker.internal:{oidc.port}',
        'SSO_CLIENT_ID': 'ldapium-sso',
        'SSO_CLIENT_SECRET': 'sso-secret',
        'SSO_ADMIN_ROLE': 'admin',
        'LDAP_SERVICE_ACCOUNT_DN': admin_dn,
        'LDAP_SERVICE_ACCOUNT_PASSWORD': admin_password,
        'LDAP_USER_SEARCH_FILTER': '(uid=%s)',
        'SSO_CALLBACK_ORIGINS': f'http://127.0.0.1:{sso_ui_port}',
    }

    # Start container with fixed port
    sso_ui_url, _ = start_ui_container(ui_container, sso_env, fixed_port=sso_ui_port)
    sso_api = ApiClient(sso_ui_url)

    # Perform SSO flow: GET /api/sso/start -> redirects to /auth -> redirects to /api/sso/callback.
    # urllib follows the 302/303 chain; a failed login ends on /login?sso_error=... with 200,
    # so the final URL and the session itself are asserted, not just the status.
    req = urllib.request.Request(sso_ui_url + '/api/sso/start', headers={'Origin': sso_ui_url})
    with sso_api.opener.open(req, timeout=30) as resp:
      final_url = resp.geturl()
      check(resp.status == 200, f'(d) SSO login flow completed (status={resp.status}, final_url={mask(final_url)})')
    check('sso_error' not in final_url, f'(d) SSO login did not end on an error redirect (final_url={mask(final_url)})')
    check(any(c.name for c in sso_api.jar), f'(d) session cookie stored (cookies={[c.name for c in sso_api.jar]})')
    status, hdrs, body = sso_api.call('GET', '/api/me')
    check(status == 200 and isinstance(body, dict) and body.get('dn'),
          f'(d) /api/me reports an authenticated SSO session ({describe(status, hdrs, body)})')

    # Create test user for lastbind check
    sso_user_uid = 'sso-user-' + secrets.token_hex(4)
    sso_user_dn = f'uid={sso_user_uid},ou=people,{base_dn}'
    sso_user_pw = 'SsoUser-Pw-123!'
    create_ldif = f"""dn: {sso_user_dn}
objectClass: inetOrgPerson
uid: {sso_user_uid}
cn: SSO User
sn: User
userPassword: {sso_user_pw}
"""
    res = ldap_admin_tool('ldapadd', [], create_ldif)
    check(res.returncode == 0, f'(d) created target user {sso_user_dn}')

    # In SSO mode, read the entry to obtain ETag (CSN0)
    status, hdrs, body = sso_api.call('GET', f'/api/entry?dn={urllib.parse.quote(sso_user_dn)}')
    check(status == 200, f'(d) GET /api/entry succeeded in SSO mode ({describe(status, hdrs, body)})')
    tag0 = hdrs.get('ETag')
    check(tag0 and tag0.startswith('"') and tag0.endswith('"'), f'(d) obtained quoted ETag {tag0}')

    # Bind as sso-user directly to slapd to trigger ppolicy lastbind
    whoami = subprocess.run(
        ['docker', 'exec', '-i', ldap_container, 'ldapwhoami', '-x', '-H', 'ldap://127.0.0.1',
         '-D', sso_user_dn, '-w', sso_user_pw],
        capture_output=True, text=True
    )
    check(whoami.returncode == 0, f'(d) bind as {sso_user_dn} succeeded')

    # Verify pwdLastSuccess was written by lastbind
    lastbind_check = ldap_admin_tool('ldapsearch', ['-b', sso_user_dn, '-s', 'base', '+'])
    check('pwdLastSuccess:' in lastbind_check.stdout, '(d) slapd lastbind overlay wrote pwdLastSuccess')

    # Snapshot the whole entry (attributes + entryCSN) so a write-then-412 bug cannot hide
    entry_before_stale = entry_snapshot(sso_user_dn)

    # Attempt conditional write with stale ETag (tag0) in SSO mode
    stale_put_body = {
        'dn': sso_user_dn,
        'cn': 'SSO User Modified',
        'sn': 'User',
        'mail': 'stale@example.org'
    }
    status, hdrs, body = sso_api.call('PUT', '/api/users', stale_put_body, {'If-Match': tag0})
    check(status == 412, f'(d) stale If-Match with bumped lastbind entryCSN returned 412 ({describe(status, hdrs, body)})')
    check(body.get('code') == 'revision_conflict', f'(d) error code is revision_conflict (got {body.get("code")})')
    check(body.get('retryable') is False, '(d) revision_conflict retryable is False')
    check(entry_snapshot(sso_user_dn) == entry_before_stale,
          '(d) stale request left the entry byte-identical (attributes and entryCSN unchanged)')

    # Re-read the entry to get fresh ETag (tag1)
    status, hdrs, body = sso_api.call('GET', f'/api/entry?dn={urllib.parse.quote(sso_user_dn)}')
    tag1 = hdrs.get('ETag')
    check(tag1 != tag0, f'(d) entryCSN moved after lastbind (tag0={tag0}, tag1={tag1})')

    # Conditional write with matching ETag (tag1) in SSO mode
    matching_put_body = {
        'dn': sso_user_dn,
        'cn': 'SSO User Updated',
        'sn': 'User',
        'mail': 'updated@example.org'
    }
    status, hdrs, _ = sso_api.call('PUT', '/api/users', matching_put_body, {'If-Match': tag1})
    check(status == 204, f'(d) matching If-Match conditional write succeeded with 204 ({describe(status, hdrs, _)})')

    # Verify attribute update and new ETag
    status, hdrs, body = sso_api.call('GET', f'/api/entry?dn={urllib.parse.quote(sso_user_dn)}')
    tag2 = hdrs.get('ETag')
    check(tag2 != tag1, '(d) ETag moved after successful conditional write')
    check(body.get('attributes', {}).get('mail') == ['updated@example.org'], '(d) attributes updated in directory')

    print('\nAll checks (a), (b), (c), (d), (e) passed successfully!')
  except BaseException:
    dump_container_logs()
    raise
  finally:
    print('Cleaning up test containers and network...')
    cleanup()


if __name__ == '__main__':
  main()
