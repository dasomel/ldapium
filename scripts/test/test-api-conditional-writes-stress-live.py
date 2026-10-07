#!/usr/bin/env python3
"""Live stress / capability / replication checks for conditional writes (#268, T-021 remainder).

Sibling of test-api-conditional-writes-local.py (single node); this one needs a
2-node multi-provider topology, so it has its own script and the same workflow.

  (f) Delete/recreate concurrent stress on one node: concurrent DELETE (If-Match),
      recreate POST, PUT/PATCH (If-Match) of the same DN. Every response is a
      documented status, a stale tag never touches a recreated entry
      (entryUUID differs), final state is consistent; a replayed keyed DELETE
      does not delete the recreated entry.
  (g) Server WITHOUT assertion-control support: a proxy answers the critical
      assertion control with unavailableCriticalExtension(12) exactly as a
      server lacking RFC 4528 must (RFC 4511 4.1.11). Proves fail-closed: 500
      internal, no write, no unconditional fallback; header-less writes still work.
  (h) 2-node replication (multi-provider, last-write-wins by entryCSN): what an
      If-Match tag taken from node A does against node B before/after sync.

Run with:
  python3 scripts/test/test-api-conditional-writes-stress-live.py
"""
import http.cookiejar
import json
import os
import random
import secrets
import signal
import socket
import subprocess
import sys
import threading
import traceback
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ldap_image = os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')
ui_image = os.environ.get('LDAPIUM_UI_IMAGE', 'ldapium-ui:e2e')
prefix = os.environ.get('LDAPIUM_TEST_PREFIX', 'ldapium-cw-268-')
name_prefix = prefix + uuid.uuid4().hex[:6]

network = name_prefix + '-net'          # replication link between the nodes (the one that gets cut)
node_a = name_prefix + '-a'
node_b = name_prefix + '-b'
access_networks = {node_a: name_prefix + '-acc-a', node_b: name_prefix + '-acc-b'}  # one per node, so they never link the nodes
base_dn = 'dc=example,dc=org'
admin_dn = 'cn=admin,' + base_dn
admin_password = secrets.token_urlsafe(24)
session_secret = secrets.token_hex(32)
people = 'ou=people,' + base_dn

containers = []
volumes = []
created_network = False
created_access = []


def check(condition, message):
  if not condition:
    raise AssertionError(message)
  print('PASS: ' + message)


def mask(text):
  text = text if isinstance(text, str) else str(text)
  for secret in (admin_password, session_secret):
    text = text.replace(secret, '***')
  return text


def dump_container_logs():
  for c in containers:
    res = subprocess.run(['docker', 'logs', '--tail', '40', c], capture_output=True, text=True)
    print(f'--- docker logs {c} (scrubbed, last 40 lines) ---', file=sys.stderr)
    print(mask(res.stdout + res.stderr), file=sys.stderr)


def cleanup():
  for c in containers:
    subprocess.run(['docker', 'rm', '-fv', c], capture_output=True)
  for v in volumes:
    subprocess.run(['docker', 'volume', 'rm', '-f', v], capture_output=True)
  for net in ([network] if created_network else []) + created_access:
    subprocess.run(['docker', 'network', 'rm', net], capture_output=True)


def wait_until(predicate, what, timeout=60.0):
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if predicate():
      return
    time.sleep(0.2)
  raise AssertionError(f'timed out after {timeout}s waiting for {what}')


def ldap_tool(node, tool, args, input_data=None):
  return subprocess.run(
      ['docker', 'exec', '-i', node, tool, '-x', '-H', 'ldap://127.0.0.1',
       '-D', admin_dn, '-w', admin_password] + args,
      input=input_data, capture_output=True, text=True)


def read_attrs(node, dn, attrs):
  """Return {attr: [values]} for dn on node, or None when the entry does not exist."""
  res = ldap_tool(node, 'ldapsearch', ['-LLL', '-b', dn, '-s', 'base'] + attrs)
  if res.returncode == 32:
    return None
  if res.returncode != 0:
    raise AssertionError(f'ldapsearch {dn} on {node} failed rc={res.returncode}: {res.stderr}')
  out = {}
  for line in res.stdout.splitlines():
    if ': ' in line and not line.startswith('dn:'):
      k, v = line.split(': ', 1)
      out.setdefault(k, []).append(v)
  return out


def entry_csn(node, dn):
  attrs = read_attrs(node, dn, ['entryCSN'])
  return attrs['entryCSN'][0] if attrs else None


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

  def login(self):
    status, _, _ = self.call('POST', '/api/login', {'identity': admin_dn, 'password': admin_password})
    check(status == 200, f'{self.base_url} LDAP login as admin (status={status})')

  def etag(self, dn):
    status, hdrs, _ = self.call('GET', '/api/entry?dn=' + urllib.parse.quote(dn))
    return hdrs.get('ETag') if status == 200 else None


def host_port(container, port):
  out = subprocess.run(['docker', 'port', container, port], check=True, capture_output=True, text=True).stdout
  return int(out.splitlines()[0].rsplit(':', 1)[1])


# The admin password and session secret are throwaway, test-only values; like the neighbouring
# test scripts they are passed in docker argv.
def start_node(name, server_id):
  vol_cfg, vol_data = name + '-cfg', name + '-data'
  volumes.extend([vol_cfg, vol_data])
  containers.append(name)  # registered before creation so an interruption cannot leak it
  # Start on the default bridge (publishes the LDAP port to the host, used by the UIs) and attach
  # the replication network afterwards. UIs reach a node over a separate access network: cutting the
  # replication network re-plumbs the published-port path, which hung an established UI->node connection.
  subprocess.run(
      ['docker', 'create', '--name', name, '--hostname', name, '-p', '127.0.0.1::389',
       '-v', f'{vol_cfg}:/etc/openldap/slapd.d', '-v', f'{vol_data}:/var/lib/openldap/data',
       '-e', 'LDAP_ROOT_DN=' + base_dn, '-e', 'LDAP_ADMIN_PASSWORD=' + admin_password,
       '-e', 'LDAP_REPLICATION_ENABLED=true', '-e', f'LDAP_SERVER_ID={server_id}',
       '-e', f'LDAP_REPLICATION_PEERS=ldap://{node_a}:389,ldap://{node_b}:389', ldap_image],
      check=True, capture_output=True)
  subprocess.run(['docker', 'network', 'connect', network, name], check=True)
  subprocess.run(['docker', 'network', 'connect', access_networks[name], name], check=True)
  subprocess.run(['docker', 'start', name], check=True, capture_output=True)


def start_ui(name, ldap_url, net=None):
  subprocess.run(['docker', 'rm', '-fv', name], capture_output=True)
  containers.append(name)  # registered before the run so an interruption cannot leak it
  subprocess.run(
      ['docker', 'run', '-d', '--name', name] + (['--network', net] if net else []) + ['--add-host', 'host.docker.internal:host-gateway',
       '-p', '127.0.0.1::8080',
       '-e', 'LDAP_URL=' + ldap_url, '-e', 'LDAP_BASE_DN=' + base_dn,
       '-e', 'LDAP_USER_CREATE_BASE=' + people, '-e', 'LDAP_GROUP_CREATE_BASE=ou=groups,' + base_dn,
       '-e', 'SESSION_SECRET=' + session_secret, '-e', 'COOKIE_SECURE=false',
       '-e', 'UI_IDEMPOTENCY_ENABLED=true', ui_image],
      check=True, capture_output=True)
  url = f'http://127.0.0.1:{host_port(name, "8080/tcp")}'
  for _ in range(60):
    try:
      with urllib.request.urlopen(url + '/api/auth/config', timeout=1) as resp:
        if resp.status == 200:
          return url
    except Exception:
      time.sleep(0.5)
  raise RuntimeError(f'UI {name} failed to become ready')


# --- (g) BER-aware LDAP proxy emulating a server without assertion-control support ---
ASSERTION_OID = b'1.3.6.1.1.12'
# request tag -> response tag: Modify 0x66->0x67, Delete 0x4a->0x6b, ModifyDN 0x6c->0x6d
RESPONSE_TAG = {0x66: 0x67, 0x4a: 0x6b, 0x6c: 0x6d}


def ber_len(buf, pos):
  first = buf[pos]
  if first < 0x80:
    return first, pos + 1
  n = first & 0x7f
  return int.from_bytes(buf[pos + 1:pos + 1 + n], 'big'), pos + 1 + n


def enc_len(n):
  if n < 0x80:
    return bytes([n])
  raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
  return bytes([0x80 | len(raw)]) + raw


def unsupported_response(msg):
  """Build the LDAPMessage a server answers for an unsupported critical control, or None."""
  _, pos = ber_len(msg, 1)                    # SEQUENCE length
  id_len, pos = ber_len(msg, pos + 1)         # INTEGER messageID
  msg_id = msg[pos:pos + id_len]
  op_tag = msg[pos + id_len]
  if op_tag not in RESPONSE_TAG or ASSERTION_OID not in msg:
    return None
  # LDAPResult: resultCode ENUMERATED 12, matchedDN "", diagnosticMessage "..."
  diag = b'critical extension is unavailable'
  result = b'\x0a\x01\x0c' + b'\x04\x00' + b'\x04' + enc_len(len(diag)) + diag
  op = bytes([RESPONSE_TAG[op_tag]]) + enc_len(len(result)) + result
  inner = b'\x02' + enc_len(len(msg_id)) + msg_id + op
  return b'\x30' + enc_len(len(inner)) + inner


class NoAssertionProxy:
  def __init__(self, target_host, target_port):
    self.target = (target_host, target_port)
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.sock.bind(('0.0.0.0', 0))
    self.port = self.sock.getsockname()[1]
    self.sock.listen(20)
    self.rejected = 0
    self.forwarded_writes = 0
    self.running = True
    threading.Thread(target=self._accept_loop, daemon=True).start()

  def _accept_loop(self):
    while self.running:
      try:
        client, _ = self.sock.accept()
      except OSError:
        break
      threading.Thread(target=self._handle, args=(client,), daemon=True).start()

  def _handle(self, client):
    try:
      server = socket.create_connection(self.target, timeout=10)
    except OSError:
      client.close()
      return

    def downstream():
      try:
        while True:
          data = server.recv(65536)
          if not data:
            break
          client.sendall(data)
      except OSError:
        pass
      finally:
        client.close()
        server.close()

    threading.Thread(target=downstream, daemon=True).start()
    buf = b''
    try:
      while True:
        data = client.recv(65536)
        if not data:
          break
        buf += data
        while len(buf) >= 2:
          body_len, pos = ber_len(buf, 1)
          total = pos + body_len
          if len(buf) < total:
            break
          msg, buf = buf[:total], buf[total:]
          reply = unsupported_response(msg)
          if reply is not None:
            self.rejected += 1
            client.sendall(reply)
          else:
            if msg[pos + 2 + msg[pos + 1]] in RESPONSE_TAG:
              self.forwarded_writes += 1
            server.sendall(msg)
    except OSError:
      pass
    finally:
      client.close()
      server.close()

  def close(self):
    self.running = False
    self.sock.close()


def uuid_of(node, dn):
  attrs = read_attrs(node, dn, ['entryUUID'])
  return attrs['entryUUID'][0] if attrs else None


def stress_part(api, node):
  print('\n--- Executing (f): delete/recreate concurrent stress ---')
  documented = {'DELETE': {204, 404, 412}, 'POST': {201, 409}, 'PUT': {204, 404, 412}, 'PATCH': {204, 404, 412}}
  rounds = 30
  outcome = {'recreated': 0, 'absent': 0, 'original_survived': 0}
  for rnd in range(rounds):
    uid = f'cw-st-{rnd}-' + secrets.token_hex(3)
    dn = f'uid={uid},{people}'
    status, _, _ = api.call('POST', '/api/users', {'uid': uid, 'cn': 'orig', 'sn': 'S'})
    if status != 201:
      raise AssertionError(f'round {rnd}: create failed with {status}')
    tag0 = api.etag(dn)
    u0 = uuid_of(node, dn)
    res = {}
    barrier = threading.Barrier(4)
    d_done = threading.Event()

    def deleter():
      barrier.wait(timeout=10)
      res['DELETE'] = api.call('DELETE', '/api/users?dn=' + urllib.parse.quote(dn), None, {'If-Match': tag0})
      d_done.set()

    def recreator():
      barrier.wait(timeout=10)
      key = 'idem-key-' + secrets.token_hex(8)
      deadline = time.monotonic() + 5
      while True:
        r = api.call('POST', '/api/users', {'uid': uid, 'cn': 'recreated', 'sn': 'S', 'password': 'Recreated-Pw-1x!'}, {'Idempotency-Key': key})
        seen.add(r[0])
        if r[0] == 201 or (d_done.is_set() and r[0] == 409) or time.monotonic() > deadline:
          res['POST'] = r
          return
        time.sleep(0.02 + random.random() * 0.05)  # jittered backoff: do not starve the DELETE with a 409 flood

    def putter():
      barrier.wait(timeout=10)
      res['PUT'] = api.call('PUT', '/api/users', {'dn': dn, 'cn': 'stale-put', 'sn': 'S'}, {'If-Match': tag0})

    def patcher():
      barrier.wait(timeout=10)
      res['PATCH'] = api.call('PATCH', '/api/users', {'dn': dn, 'mail': 'stale-patch@example.org'}, {'If-Match': tag0})

    seen = set()

    def guarded(fn):
      def run():
        try:
          fn()
        except BaseException:
          res['ERROR ' + fn.__name__] = (0, None, traceback.format_exc())
      return run

    threads = [threading.Thread(target=guarded(f)) for f in (deleter, recreator, putter, patcher)]
    for t in threads:
      t.start()
    for t in threads:
      t.join(timeout=60)
    errors = {k: v[2] for k, v in res.items() if k.startswith('ERROR ')}
    if errors or len(res) != 4:
      raise AssertionError(f'round {rnd}: worker failure or missing responses {sorted(res)}: {errors}')
    for m, r in res.items():
      if r[0] not in documented[m]:
        raise AssertionError(f'round {rnd}: {m} answered undocumented status {r[0]}: {r[2]}')
    if not seen <= documented['POST']:
      raise AssertionError(f'round {rnd}: recreate POST saw undocumented statuses {seen}')
    for m in ('DELETE', 'PUT', 'PATCH'):
      if res[m][0] == 412 and res[m][2].get('code') != 'revision_conflict':
        raise AssertionError(f'round {rnd}: {m} 412 is not revision_conflict: {res[m][2]}')

    # final-state invariants
    found = ldap_tool(node, 'ldapsearch', ['-LLL', '-b', people, f'(uid={uid})', 'dn'])
    if found.returncode != 0:
      raise AssertionError(f'round {rnd}: ldapsearch failed rc={found.returncode}: {found.stderr}')
    hits = found.stdout.count('dn: ')
    if hits > 1:
      raise AssertionError(f'round {rnd}: duplicated entries for {uid}: {hits}')
    now = read_attrs(node, dn, ['entryUUID', 'cn', 'mail'])
    d, r, u, p = (res[k][0] for k in ('DELETE', 'POST', 'PUT', 'PATCH'))
    # DELETE, PUT and PATCH all carry tag0: each success moves entryCSN, so at most one may win.
    winners = [m for m, c in (('DELETE', d), ('PUT', u), ('PATCH', p)) if c == 204]
    if len(winners) > 1:
      raise AssertionError(f'round {rnd}: several writers with the same If-Match tag succeeded: {winners}')
    if now is None:
      outcome['absent'] += 1
      if not (d == 204 and r != 201):
        raise AssertionError(f'round {rnd}: entry absent but DELETE={d} POST={r}')
    elif now['entryUUID'][0] != u0:
      outcome['recreated'] += 1
      if not (d == 204 and r == 201):
        raise AssertionError(f'round {rnd}: recreated entry but DELETE={d} POST={r}')
      if now['cn'] != ['recreated'] or 'mail' in now:
        raise AssertionError(f'round {rnd}: stale write resurrected state on the recreated entry: {now}')
    else:
      outcome['original_survived'] += 1
      if d == 204 or r == 201:
        raise AssertionError(f'round {rnd}: original entry survived but DELETE={d} POST={r}')
      if now['cn'] != (['stale-put'] if u == 204 else ['orig']):
        raise AssertionError(f'round {rnd}: PUT={u} but cn={now["cn"]}')
      if now.get('mail') != (['stale-patch@example.org'] if p == 204 else None):
        raise AssertionError(f'round {rnd}: PATCH={p} but mail={now.get("mail")}')
    api.call('DELETE', '/api/users?dn=' + urllib.parse.quote(dn))
  print(f'INFO: (f) {rounds} rounds outcome distribution: {outcome}')
  check(True, f'(f) {rounds} concurrent DELETE/POST/PUT/PATCH rounds: documented statuses only, no duplicate, no resurrected state, final state consistent')
  check(sum(outcome.values()) == rounds, f'(f) every round ended in exactly one consistent outcome class {outcome} (the mix is scheduler-dependent and not asserted; the deterministic recreate case below is)')

  # Deterministic: old tag against a recreated entry, and keyed DELETE replay after recreate.
  uid = 'cw-det-' + secrets.token_hex(3)
  dn = f'uid={uid},{people}'
  check(api.call('POST', '/api/users', {'uid': uid, 'cn': 'v1', 'sn': 'S'})[0] == 201, '(f) deterministic: created v1')
  old_tag, old_uuid = api.etag(dn), uuid_of(node, dn)
  del_key = 'idem-key-' + secrets.token_hex(8)
  status, _, _ = api.call('DELETE', '/api/users?dn=' + urllib.parse.quote(dn), None, {'If-Match': old_tag, 'Idempotency-Key': del_key})
  check(status == 204, f'(f) deterministic: keyed conditional DELETE -> 204 (got {status})')
  check(api.call('POST', '/api/users', {'uid': uid, 'cn': 'v2', 'sn': 'S'})[0] == 201, '(f) deterministic: recreated as v2')
  new_uuid = uuid_of(node, dn)
  check(new_uuid != old_uuid, '(f) deterministic: recreated entry is a new incarnation (entryUUID differs)')
  status, _, body = api.call('PUT', '/api/users', {'dn': dn, 'cn': 'stale', 'sn': 'S'}, {'If-Match': old_tag})
  check(status == 412 and body.get('code') == 'revision_conflict', f'(f) deterministic: old tag on recreated entry -> 412 revision_conflict (got {status})')
  status, _, _ = api.call('DELETE', '/api/users?dn=' + urllib.parse.quote(dn), None, {'If-Match': old_tag})
  check(status == 412, f'(f) deterministic: old-tag DELETE on recreated entry -> 412 (got {status})')
  status, _, _ = api.call('DELETE', '/api/users?dn=' + urllib.parse.quote(dn), None, {'If-Match': old_tag, 'Idempotency-Key': del_key})
  after = read_attrs(node, dn, ['entryUUID', 'cn'])
  check(after is not None and after['entryUUID'][0] == new_uuid and after['cn'] == ['v2'],
        f'(f) deterministic: replayed keyed DELETE (status={status}) left the recreated entry intact')
  status, _, _ = api.call('DELETE', '/api/users?dn=' + urllib.parse.quote(dn))
  check(status == 204, '(f) deterministic: cleanup delete')


def no_assertion_part(node):
  print('\n--- Executing (g): server without assertion-control support (proxy answers critical control with 12) ---')
  rootdse = subprocess.run(
      ['docker', 'exec', '-i', node, 'ldapsearch', '-x', '-H', 'ldap://127.0.0.1', '-b', '', '-s', 'base', 'supportedControl'],
      capture_output=True, text=True).stdout
  check('1.3.6.1.1.12' in rootdse, '(g) control: the real slapd advertises the assertion control (1.3.6.1.1.12) in rootDSE supportedControl')
  proxy = NoAssertionProxy('127.0.0.1', host_port(node, '389/tcp'))
  try:
    url = start_ui(name_prefix + '-ui-noassert', f'ldap://host.docker.internal:{proxy.port}')
    api = ApiClient(url)
    api.login()
    uid = 'cw-na-' + secrets.token_hex(3)
    dn = f'uid={uid},{people}'
    check(api.call('POST', '/api/users', {'uid': uid, 'cn': 'before', 'sn': 'S', 'mail': 'a@example.org'})[0] == 201,
          '(g) header-less create works through the proxy (no control sent)')
    tag = api.etag(dn)
    snap = read_attrs(node, dn, ['*', '+'])
    cases = [
        ('PUT', '/api/users', {'dn': dn, 'cn': 'after', 'sn': 'S'}),
        ('PATCH', '/api/users', {'dn': dn, 'cn': 'after'}),
        ('POST', '/api/users/lock', {'dn': dn}),
        ('DELETE', '/api/users?dn=' + urllib.parse.quote(dn), None),
    ]
    for method, path, body in cases:
      status, _, resp = api.call(method, path, body, {'If-Match': tag})
      check(status == 500 and isinstance(resp, dict) and resp.get('code') == 'internal',
            f'(g) {method} {path.split("?")[0]} with If-Match on a server without support -> 500 internal (got {status} {resp})')
      check(read_attrs(node, dn, ['*', '+']) == snap, f'(g) {method}: no write happened (entry byte-identical, no unconditional fallback)')
    check(proxy.rejected >= len(cases), f'(g) proxy rejected {proxy.rejected} critical-assertion operations with result 12')
    writes_before = proxy.forwarded_writes
    status, _, _ = api.call('PUT', '/api/users', {'dn': dn, 'cn': 'unconditional', 'sn': 'S'})
    check(status == 204 and proxy.forwarded_writes == writes_before + 1,
          f'(g) the same PUT without If-Match still works unconditionally (documented opt-in; status={status})')
    check(api.call('DELETE', '/api/users?dn=' + urllib.parse.quote(dn))[0] == 204, '(g) cleanup delete')
  finally:
    proxy.close()


def replication_part(api_a, api_b):
  print('\n--- Executing (h): 2-node replication semantics of If-Match ---')
  uid = 'cw-rep-' + secrets.token_hex(3)
  dn = f'uid={uid},{people}'
  check(api_a.call('POST', '/api/users', {'uid': uid, 'cn': 'v0', 'sn': 'S'})[0] == 201, '(h) created on node A via UI A')
  wait_until(lambda: read_attrs(node_b, dn, ['cn']) is not None, 'entry replicated to B')
  wait_until(lambda: entry_csn(node_b, dn) == entry_csn(node_a, dn), 'entryCSN equal on A and B')
  tag_a, tag_b = api_a.etag(dn), api_b.etag(dn)
  check(tag_a is not None and tag_a == tag_b, f'(h1) after sync the ETag is identical on both nodes ({tag_a}): entryCSN is replicated verbatim')

  # h1: tag from A used against B after sync -> succeeds, and replicates back.
  status, _, _ = api_b.call('PUT', '/api/users', {'dn': dn, 'cn': 'v1-via-B', 'sn': 'S'}, {'If-Match': tag_a})
  check(status == 204, f'(h1) If-Match tag taken from A, used on B after sync -> 204 (got {status})')
  wait_until(lambda: (read_attrs(node_a, dn, ['cn']) or {}).get('cn') == ['v1-via-B'], 'B write replicated to A')
  wait_until(lambda: entry_csn(node_a, dn) == entry_csn(node_b, dn), 'entryCSN equal again')

  # h2: cut the replication link. A writes (tag moves on A only); B still holds the old tag.
  tag0 = api_a.etag(dn)
  for n in (node_a, node_b):
    subprocess.run(['docker', 'network', 'disconnect', network, n], check=True, capture_output=True)
  try:
    status, _, _ = api_a.call('PUT', '/api/users', {'dn': dn, 'cn': 'v2-on-A', 'sn': 'S'}, {'If-Match': tag0})
    check(status == 204, f'(h2) partitioned: conditional write on A with tag0 -> 204 (got {status})')
    tag1 = api_a.etag(dn)
    check(tag1 != tag0, '(h2) A moved to a new tag')
    check(api_b.etag(dn) == tag0, '(h2) B still serves the old tag (replication cut)')
    status, _, body = api_b.call('PUT', '/api/users', {'dn': dn, 'cn': 'v2-on-B', 'sn': 'S'}, {'If-Match': tag1})
    check(status == 412 and body.get('code') == 'revision_conflict',
          f'(h2) tag1 (new, from A) used on B before sync -> 412 (B has not seen that revision; got {status})')
    time.sleep(1.1)  # entryCSN has one-second timestamp granularity per origin; keep B's write strictly later
    status, _, _ = api_b.call('PUT', '/api/users', {'dn': dn, 'cn': 'v2-on-B', 'sn': 'S'}, {'If-Match': tag0})
    check(status == 204, f'(h2) STALE window: tag0 (already superseded on A) is still accepted on B before sync -> 204 (got {status})')
    csn_a, csn_b = entry_csn(node_a, dn), entry_csn(node_b, dn)
  finally:
    for n in (node_a, node_b):
      subprocess.run(['docker', 'network', 'connect', network, n], check=True, capture_output=True)
  print(f'INFO: (h3) diverged: A cn=v2-on-A csn={csn_a} ; B cn=v2-on-B csn={csn_b}')
  wait_until(lambda: entry_csn(node_a, dn) == entry_csn(node_b, dn), 'nodes converge after the link is restored', timeout=120)
  final_a = read_attrs(node_a, dn, ['cn', 'entryCSN'])
  final_b = read_attrs(node_b, dn, ['cn', 'entryCSN'])
  check(final_a == final_b, f'(h3) nodes converged to one state: {final_a}')
  later = 'v2-on-B' if csn_b > csn_a else 'v2-on-A'
  check(final_a['cn'] == [later], f'(h3) last-write-wins by entryCSN: the later CSN ({later}) won; the other 204 was silently overwritten, no 412 was ever raised')
  # h4: after convergence the tags agree again.
  check(api_a.etag(dn) == api_b.etag(dn), '(h4) after convergence the ETag is identical on both nodes again')
  status, _, _ = api_a.call('DELETE', '/api/users?dn=' + urllib.parse.quote(dn), None, {'If-Match': api_a.etag(dn)})
  check(status == 204, '(h4) cleanup conditional delete on A')
  wait_until(lambda: read_attrs(node_b, dn, ['cn']) is None, 'delete replicated to B')


def main():
  global created_network
  # CI cancellation sends SIGTERM/SIGHUP; turn it into SystemExit so `finally` runs the cleanup.
  for sig in (signal.SIGTERM, signal.SIGHUP):
    signal.signal(sig, lambda signum, frame: sys.exit(128 + signum))
  try:
    print(f'Starting run {name_prefix} with {ldap_image} / {ui_image}')
    subprocess.run(['docker', 'network', 'create', network], check=True, capture_output=True)
    created_network = True
    for net in access_networks.values():
      subprocess.run(['docker', 'network', 'create', net], check=True, capture_output=True)
      created_access.append(net)
    start_node(node_a, 1)
    start_node(node_b, 2)
    for n in (node_a, node_b):
      wait_until(lambda n=n: ldap_tool(n, 'ldapsearch', ['-b', base_dn, '-s', 'base']).returncode == 0, f'{n} ready', 90)
    res = ldap_tool(node_a, 'ldapadd', [], f'dn: {people}\nobjectClass: organizationalUnit\nou: people\n')
    check(res.returncode == 0, 'bootstrapped ou=people on node A')
    wait_until(lambda: read_attrs(node_b, people, ['ou']) is not None, 'ou=people replicated to B')

    url_a = start_ui(name_prefix + '-ui-a', f'ldap://{node_a}:389', access_networks[node_a])
    url_b = start_ui(name_prefix + '-ui-b', f'ldap://{node_b}:389', access_networks[node_b])
    api_a, api_b = ApiClient(url_a), ApiClient(url_b)
    api_a.login()
    api_b.login()

    stress_part(api_a, node_a)
    no_assertion_part(node_a)
    replication_part(api_a, api_b)
    print('\nAll checks (f), (g), (h) passed successfully!')
  except BaseException:
    dump_container_logs()
    raise
  finally:
    print('Cleaning up test containers, volumes and network...')
    cleanup()


if __name__ == '__main__':
  main()
