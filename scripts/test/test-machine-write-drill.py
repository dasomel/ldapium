#!/usr/bin/env python3
"""Machine WRITE emergency-block drill (machine-write-scope T-022, REQ-012, AC-011, AC-017(c), D12, D24).

Real Keycloak + real slapd + the DRILL-ONLY UI image (Go build tag `machinewritedrill`, which registers the five
first-ship operations so the real write pipeline runs end to end; the default and release images stay closed, see
scripts/test/test-machine-write-drill-guard.py). Everything here is measured; the OBS lines are what
docs/machine-auth-operations.md and EVIDENCE-drill.md quote.

  A. write path end to end for the five operations (W_data), positive and negative tokens / requests, bind counts
  B. the default (tag-free) image with the same configuration: every write is 403 (production stays closed)
  C. EMERGENCY BLOCK (b): rotate W_data's LDAP password -> the NEXT write on EVERY replica is 503, reads stay 200,
     an already issued token is unaffected, restore -> writes recover
  D. EMERGENCY BLOCK (a): write-only redeploy (MACHINE_WRITE_ENABLED=false) -> writes 403, reads 200
  E. IN-FLIGHT WINDOW: a write held at the LDAP connection while the password is rotated (stalled LDAP connection
     through a TCP proxy): does it complete, how long can it run, replay of an earlier key
  F. D24 lockout: wrong-password binds lock W_data (default policy) -> writes 503, reads unchanged; the mitigation
     (dedicated W_* ppolicy without lockout / with a short duration) and the alert queries

Run (local):  LDAPIUM_IMAGE=ldapium:x LDAPIUM_UI_IMAGE=<drill image> [LDAPIUM_UI_DEFAULT_IMAGE=<default image>] \
              python3 scripts/test/test-machine-write-drill.py
"""
import base64
import json
import os
import pathlib
import re
import secrets
import select
import socket
import sys
import threading
import time
import uuid
from urllib.parse import quote as urlquote

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'lib'))
from machine_live import (ADMIN_DN, AUDIENCE, BASE_DN, FIXTURES, MACHINE_DN, READER, SEED_USER_DN, Keycloak, Live,  # noqa: E402
                          Slapd, ensure, tamper)

live = Live('ldapium-mwd-', deadline_seconds=1500)
REALM = 'write-drill'
SYSTEM_DN = 'ou=system,' + BASE_DN
WDATA_DN = 'uid=machine-write-data,' + SYSTEM_DN
WLOCK_DN = 'uid=machine-write-lock,' + SYSTEM_DN
PEOPLE = 'ou=people,' + BASE_DN
GROUPS = 'ou=groups,' + BASE_DN
G1 = 'cn=g01,' + GROUPS
G2 = 'cn=g02,' + GROUPS
WRITE_SCOPES = ['directory.users.create', 'directory.users.update', 'directory.users.delete',
                'directory.groups.members.add', 'directory.groups.members.remove']
POLICY_DEFAULT = 'cn=default,ou=policies,' + BASE_DN


def obs(text):
  print('OBS ' + text, flush=True)


class HoldProxy:
  """TCP proxy in front of slapd. In mode `hold`, a connection whose FIRST client message contains `hold_dn` (the
  bind request of the identity under test) is forwarded up to and including that bind; its NEXT client message (the
  write operation) is held until release(). If the client closes while the message is held, the message is dropped
  (a partition: the operation never reached slapd) and the time is recorded."""

  def __init__(self, target_host, target_port):
    self.target = (target_host, target_port)
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.sock.bind(('0.0.0.0', 0))
    self.port = self.sock.getsockname()[1]
    self.sock.listen(64)
    self.mode = 'pass'
    self.hold_dn = b''
    self.lock = threading.Lock()
    self.open = 0
    self.held_at = None
    self.client_closed_at = None
    self.released = threading.Event()
    self.running = True
    threading.Thread(target=self._accept, daemon=True).start()

  def hold(self, dn):
    self.hold_dn = dn.encode()
    self.held_at = self.client_closed_at = None
    self.released.clear()
    self.mode = 'hold'

  def release(self):
    self.mode = 'pass'
    self.released.set()

  def _accept(self):
    while self.running:
      try:
        client, _ = self.sock.accept()
      except OSError:
        return
      with self.lock:
        self.open += 1
      threading.Thread(target=self._serve, args=(client,), daemon=True).start()

  def _serve(self, client):
    server = None
    try:
      server = socket.create_connection(self.target, timeout=10)
      server.settimeout(None)
      state = {'n': 0, 'target': False}

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
            if state['n'] == 0:
              state['target'] = bool(self.hold_dn) and self.hold_dn in data
            elif state['target'] and self.mode == 'hold':
              self.held_at = time.monotonic()
              while not self.released.is_set():
                ready, _, _ = select.select([client], [], [], 0.05)
                if ready and client.recv(1, socket.MSG_PEEK) == b'':
                  self.client_closed_at = time.monotonic()
                  return
            state['n'] += 1
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


def main():
  print(f'Run {live.name_prefix}: server {live.ldap_image}, UI {live.ui_image}, Keycloak {live.keycloak_image}', flush=True)
  default_image = os.environ.get('LDAPIUM_UI_DEFAULT_IMAGE')
  live.make_network()
  ldap = Slapd(live)
  ldap.start()
  ldap.seed(users=4, groups=2)
  ldap.apply_acl()

  # ---- W_data / W_lock accounts and the package's write ACL fragments (docs/machine-write-account.md) ------
  wdata_pw = live.secret('WData-' + secrets.token_urlsafe(18))
  wlock_pw = live.secret('WLock-' + secrets.token_urlsafe(18))
  for dn, uid, pw in ((WDATA_DN, 'machine-write-data', wdata_pw), (WLOCK_DN, 'machine-write-lock', wlock_pw)):
    r = ldap.admin_tool('ldapadd', [], f'dn: {dn}\nobjectClass: inetOrgPerson\nuid: {uid}\ncn: {uid}\nsn: {uid}\nuserPassword: {pw}\n')
    ensure(r.returncode == 0, 'account: ' + live.mask(r.stderr))
  main_db = next(l[4:] for l in ldap.config_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=config',
                                                               '(&(objectClass=olcMdbConfig)(olcSuffix=' + BASE_DN + '))', 'dn']).stdout.splitlines()
                 if l.startswith('dn: '))

  def apply_fragment(name, who_token, who_dn, shift):
    text = (FIXTURES / name).read_text()
    for k, v in {who_token: who_dn, 'WRITE_DN': BASE_DN, 'SYSTEM_DN': SYSTEM_DN, 'REPL_DN': 'cn=replicator,' + BASE_DN,
                 'MAIN_DB_DN': main_db}.items():
      text = text.replace('@' + k + '@', v)
    text = re.sub(r'(?m)^olcAccess: \{(\d+)\}', lambda m: 'olcAccess: {%d}' % (int(m.group(1)) + shift), text)
    r = ldap.config_tool('ldapmodify', [], text)
    ensure(r.returncode == 0, f'{name}: {live.mask(r.stderr)}')

  apply_fragment('write-data.ldif', 'WDATA_DN', WDATA_DN, 3)   # after the three M rules
  apply_fragment('write-lock.ldif', 'WLOCK_DN', WLOCK_DN, 11)  # after the eight W_data rules
  ldap.put_password('/tmp/.pw-wdata', wdata_pw)
  ldap.put_password('/tmp/.pw-wlock', wlock_pw)
  ldap.put_password('/tmp/.pw-wrong', 'definitely-not-the-password')
  live.check(True, 'W_data/W_lock accounts created and the write ACL fragments applied after the M rules')

  def whoami(dn, pw_path):
    return ldap.tool('ldapwhoami', [], dn, pw_path).returncode

  def set_password(dn, pw):
    r = ldap.admin_tool('ldapmodify', [], f'dn: {dn}\nchangetype: modify\nreplace: userPassword\nuserPassword: {pw}\n')
    ensure(r.returncode == 0, 'set password: ' + live.mask(r.stderr))

  def op_attr(dn, attr):
    out = ldap.admin_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', dn, '-s', 'base', attr]).stdout
    return [l.split(': ', 1)[1] for l in out.splitlines() if l.lower().startswith(attr.lower() + ': ')]

  def entry_exists(dn):
    return ldap.admin_tool('ldapsearch', ['-LLL', '-b', dn, '-s', 'base', 'dn']).returncode == 0

  def failed_binds(dn):
    time.sleep(0.4)
    out = ldap.tool('ldapsearch', ['-LLL', '-b', 'cn=accesslog', f'(&(reqType=bind)(reqDN={dn})(reqResult=49))', 'reqDN'],
                    'cn=admin,cn=accesslog', '/tmp/.pw-admin').stdout
    return out.count('reqDN:')

  def w_binds():
    time.sleep(0.4)
    return ldap.binds(WDATA_DN)

  # ---- Keycloak -------------------------------------------------------------------------------------------
  kcname = live.name_prefix + '-kc'
  kc = Keycloak(live, kcname, f'http://{kcname}:8080')
  kc.start()
  kc.create_realm(REALM)
  for scope in READER + WRITE_SCOPES:
    kc.create_scope(REALM, scope)
  client_secret = {}
  for name, scopes in (('svc-writer', READER + WRITE_SCOPES), ('svc-reader', READER), ('svc-nosub', READER + WRITE_SCOPES)):
    client_secret[name] = live.secret(name + '-' + secrets.token_hex(10))
    kc.create_client(REALM, name, client_secret[name], scopes=scopes)
  issued = []

  def token(name='svc-writer'):
    value = kc.sa_token(REALM, name, client_secret[name])
    issued.append(value)
    return value

  session_secret = live.secret(secrets.token_hex(32))
  proxy = HoldProxy('127.0.0.1', ldap.port)
  live.closers.append(proxy.close)

  def env_for(write_enabled=True, write_scopes=True):
    env = {'LDAP_BASE_DN': BASE_DN, 'LDAP_USER_CREATE_BASE': PEOPLE, 'COOKIE_SECURE': 'false', 'UI_TRUSTED_PROXIES': 'none',
           'MACHINE_AUTH_ENABLED': 'true', 'MACHINE_OIDC_INSECURE_HTTP': 'true', 'MACHINE_OIDC_ISSUER_URL': kc.issuer(REALM),
           'MACHINE_OIDC_AUDIENCE': AUDIENCE, 'MACHINE_CLOCK_SKEW': '0s',
           'MACHINE_ALLOWED_CLIENTS': ';'.join(f'{c}={",".join(s)}' for c, s in (
             ('svc-writer', READER + (WRITE_SCOPES if write_scopes else [])), ('svc-reader', READER),
             ('svc-nosub', READER + (WRITE_SCOPES if write_scopes else [])))),
           'MACHINE_LDAP_BIND_DN': MACHINE_DN, 'MACHINE_LDAP_ROOT_DNS': ADMIN_DN,
           'MACHINE_AUTH_FAILURE_LIMIT': '1000', 'MACHINE_RATE_LIMIT_RPS': '10000', 'MACHINE_RATE_LIMIT_BURST': '10000',
           'UI_IDEMPOTENCY_ENABLED': 'true', 'MACHINE_WRITE_ENABLED': 'true' if write_enabled else 'false',
           'MACHINE_WRITE_DATA_BIND_DN': WDATA_DN, 'MACHINE_WRITE_LOCK_ENABLED': 'true', 'MACHINE_WRITE_LOCK_BIND_DN': WLOCK_DN,
           'MACHINE_WRITE_SUBTREES': f'svc-writer={PEOPLE}|{GROUPS}', 'MACHINE_WRITE_GROUPS': f'svc-writer={G1}',
           'MACHINE_WRITE_PRIVILEGED_GROUPS': 'cn=admins,' + GROUPS,
           'MACHINE_WRITE_RATE_LIMIT_RPS': '100', 'MACHINE_WRITE_RATE_LIMIT_BURST': '100'}
    return env

  held = {'SESSION_SECRET': session_secret, 'MACHINE_LDAP_BIND_PASSWORD': ldap.machine_password,
          'MACHINE_WRITE_DATA_BIND_PASSWORD': wdata_pw, 'MACHINE_WRITE_LOCK_BIND_PASSWORD': wlock_pw}
  default_timeout = '10s'

  def replica(name, write_enabled=True, via_proxy=False, image=None, write_scopes=True, wait=True, extra_env=None):
    url = f'ldap://host.docker.internal:{proxy.port}' if via_proxy else f'ldap://{ldap.name}:389'
    previous = live.ui_image
    if image:
      live.ui_image = image
    try:
      return live.start_ui(f'{live.name_prefix}-{name}', url, dict(env_for(write_enabled, write_scopes), **(extra_env or {})), held, wait=wait)
    finally:
      live.ui_image = previous

  def call(api, tok, method, path, body=None, key=None, etag=None, timeout=30):
    headers = {'Authorization': 'Bearer ' + tok}
    if body is not None:
      headers['Content-Type'] = 'application/json'
    if key:
      headers['Idempotency-Key'] = key
    if etag:
      headers['If-Match'] = etag
    began = time.monotonic()
    status, hdrs, text = api.call(method, path, headers, body, timeout=timeout)
    return status, hdrs, text, time.monotonic() - began

  def new_key():
    return 'drill-' + uuid.uuid4().hex

  def create(api, tok, uid, key=None, timeout=30):
    return call(api, tok, 'POST', '/api/users', {'uid': uid, 'cn': uid, 'sn': 'Drill', 'mail': uid + '@example.org'},
                key or new_key(), timeout=timeout)

  def etag_of(api, tok, dn):
    status, hdrs, text, _ = call(api, tok, 'GET', '/api/entry?dn=' + urlquote(dn))
    ensure(status == 200 and hdrs.get('ETag'), f'entry {dn}: {status} {text[:200]}')
    return hdrs['ETag']

  def read_ok(api, tok):
    return call(api, tok, 'GET', '/api/users?limit=1')[0]

  A = replica('a')
  B = replica('b')

  # ======== A. write path end to end ========================================================================
  tok = token()
  before = w_binds()
  st, _, text, _ = create(A, tok, 'd01')
  live.check(st == 201 and entry_exists('uid=d01,' + PEOPLE), f'[A] createUser (no password) -> 201 and the entry exists (got {st} {text[:160]})')
  ensure(not op_attr('uid=d01,' + PEOPLE, 'userPassword'), 'createUser must not set a password')
  live.check(w_binds() > before, '[A] the write bound as W_data (slapd accesslog)')
  d01 = 'uid=d01,' + PEOPLE
  st, _, text, _ = call(B, tok, 'PATCH', '/api/users', {'dn': d01, 'mail': 'changed@example.org'}, new_key(), etag_of(A, tok, d01))
  live.check(st in (200, 204) and op_attr(d01, 'mail') == ['changed@example.org'], f'[A] patchUser with a strong If-Match on the OTHER replica -> 2xx (got {st} {text[:160]})')
  st, _, text, _ = call(A, tok, 'POST', '/api/groups/members', {'groupDn': G1, 'memberDn': d01}, new_key(), etag_of(A, tok, G1))
  live.check(st in (200, 204) and d01 in op_attr(G1, 'member'), f'[A] addGroupMember -> {st}')
  st, _, text, _ = call(A, tok, 'DELETE', f'/api/groups/members?groupDn={urlquote(G1)}&memberDn={urlquote(d01)}', None, new_key(), etag_of(A, tok, G1))
  live.check(st in (200, 204) and d01 not in op_attr(G1, 'member'), f'[A] removeGroupMember -> {st}')
  st, _, text, _ = call(A, tok, 'DELETE', f'/api/users?dn={urlquote(d01)}', None, new_key(), etag_of(A, tok, d01))
  live.check(st in (200, 204) and not entry_exists(d01), f'[A] deleteUser (leaf) -> {st} and the entry is gone')
  # the audit line of a write
  lines = live.audit_lines(live.name_prefix + '-a')
  writes = [json.loads(l[l.index('{'):]) for l in lines if '"write"' in l or 'directory.users.create' in l]
  live.check(bool(writes), '[A] the write audit line is emitted: ' + json.dumps(writes[-1])[:300] if writes else 'no write audit line')

  # negatives: each must be refused WITHOUT binding as W_data
  before = w_binds()
  create(A, tok, 'x01')  # keep one successful create for the count baseline below
  base_binds = w_binds()
  neg = [
    ('reader token (no write scope)', lambda: create(A, token('svc-reader'), 'n01'), 403),
    ('client without a write subtree', lambda: create(A, token('svc-nosub'), 'n02'), 403),
    ('tampered token', lambda: create(A, tamper(tok), 'n03'), 401),
    ('no Idempotency-Key', lambda: call(A, tok, 'POST', '/api/users', {'uid': 'n04', 'cn': 'n04', 'sn': 'n'}), 428),
    ('patch without If-Match', lambda: call(A, tok, 'PATCH', '/api/users', {'dn': 'uid=x01,' + PEOPLE, 'mail': 'a@b.c'}, new_key()), 428),
    ('target outside the ceiling', lambda: call(A, tok, 'DELETE', f'/api/users?dn={urlquote(MACHINE_DN)}', None, new_key(), '"20260101000000.000000Z#000000#000#000000"'), 403),
    ('group not on the allow-list', lambda: call(A, tok, 'POST', '/api/groups/members', {'groupDn': G2, 'memberDn': 'uid=x01,' + PEOPLE}, new_key(), '"20260101000000.000000Z#000000#000#000000"'), 403),
    ('PUT is not opened', lambda: call(A, tok, 'PUT', '/api/users', {'dn': 'uid=x01,' + PEOPLE, 'cn': 'a', 'sn': 'b'}, new_key(), '"20260101000000.000000Z#000000#000#000000"'), 403),
    ('createUser with a password field', lambda: call(A, tok, 'POST', '/api/users', {'uid': 'n05', 'cn': 'n', 'sn': 'n', 'password': 'Sup3rSecret!'}, new_key()), 400),
  ]
  for name, run, want in neg:
    st, _, text, _ = run()
    live.check(st == want, f'[A] negative "{name}" -> {want} (got {st} {text[:120]})')
  live.check(w_binds() == base_binds, '[A] none of the negative requests bound as W_data')
  for u in ('n01', 'n02', 'n03', 'n04', 'n05'):
    ensure(not entry_exists(f'uid={u},{PEOPLE}'), f'{u} must not exist')
  # W_lock is configured but none of the five operations uses it: rotating it changes nothing for data writes
  set_password(WLOCK_DN, 'rotated-lock-' + secrets.token_hex(6))
  st = create(A, tok, 'wl1')[0]
  live.check(st == 201, f'[A] rotating W_LOCK does not affect the five operations (createUser {st})')
  set_password(WLOCK_DN, wlock_pw)

  # ======== B. the default image stays closed ===============================================================
  if default_image:
    replica('default1', image=default_image, wait=False)
    live.wait_until(lambda: live.run(['docker', 'inspect', '-f', '{{.State.Running}}', live.name_prefix + '-default1']).stdout.strip() == 'false',
                    'the default image to refuse the write configuration', 30)
    refusal = live.run(['docker', 'logs', live.name_prefix + '-default1'])
    live.check('no write operation is available yet' in refusal.stdout + refusal.stderr,
               '[B] default (tag-free) image: a client ceiling naming a write scope is a START-UP ERROR (it exits, no listener)')
    D = replica('default2', image=default_image, write_scopes=False)
    before = w_binds()
    st, _, text, _ = create(D, token(), 'closed1')
    live.check(st == 403 and not entry_exists('uid=closed1,' + PEOPLE) and w_binds() == before,
               f'[B] default image with MACHINE_WRITE_ENABLED=true and read-only ceilings: write is {st}, no entry, no W bind')
    live.check(read_ok(D, token()) == 200, '[B] default image: reads are 200')
    ensure(live.run(['docker', 'rm', '-fv', live.name_prefix + '-default2']).returncode == 0)
  else:
    print('SKIP: [B] LDAPIUM_UI_DEFAULT_IMAGE not set', flush=True)

  # ======== C. emergency block (b): rotate W_data's password =================================================
  tok = token()  # the "already issued" token: issued BEFORE the event, used throughout
  claims_exp = json.loads(base64.urlsafe_b64decode(tok.split('.')[1] + '=='))
  ensure(create(A, tok, 'c01')[0] == 201 and create(B, tok, 'c02')[0] == 201, 'baseline writes on both replicas')
  new_pw = live.secret('Rot-' + secrets.token_urlsafe(18))
  failed_before = failed_binds(WDATA_DN)
  set_password(WDATA_DN, new_pw)
  t_rot = time.monotonic()
  first = {}
  keys = {}
  for name, api in (('a', A), ('b', B)):
    keys[name] = new_key()
    st, _, text, secs = create(api, tok, 'blocked-' + name, key=keys[name])
    first[name] = (st, time.monotonic() - t_rot)
  live.check(all(v[0] == 503 for v in first.values()),
             f'[C] the first write after the rotation is 503 on every replica ({first["a"][0]}/{first["b"][0]}); '
             f'first-503 at +{first["a"][1]*1000:.0f} ms (replica a), +{first["b"][1]*1000:.0f} ms (replica b) after the rotation returned')
  obs(f'C1 next write after W_data password rotation: 503 on both replicas, +{first["a"][1]*1000:.0f}/{first["b"][1]*1000:.0f} ms after the modify returned (no polling, the very first request)')
  for api in (A, B):
    st = create(api, tok, 'blocked-more-' + uuid.uuid4().hex[:4])[0]
    ensure(st == 503, f'second write after rotation is {st}')
  live.check(read_ok(A, tok) == 200 and read_ok(B, tok) == 200, '[C] reads stay 200 on both replicas with the same token (M is untouched)')
  live.check(failed_binds(WDATA_DN) - failed_before == 4, '[C] slapd saw exactly 4 failed W_data binds for 4 refused writes (one bind per request, no retry)')
  for u in ('blocked-a', 'blocked-b'):
    ensure(not entry_exists(f'uid={u},{PEOPLE}'), 'refused write must not exist')
  audit = [l for n in ('a', 'b') for l in live.audit_lines(f'{live.name_prefix}-{n}') if 'bind_failed' in l]
  live.check(len(audit) >= 4, f'[C] the refusals are audited with reason bind_failed ({len(audit)} lines): ' + audit[-1][-260:])
  # ppolicy: restoring the password while < pwdMaxFailure failures happened recovers immediately
  set_password(WDATA_DN, wdata_pw)
  t_res = time.monotonic()
  st_a = create(A, tok, 'restored-a', key=keys['a'])[0]   # the SAME key that got the 503: a refusal before the write does not burn it
  st_b = create(B, tok, 'restored-b', key=keys['b'])[0]
  live.check((st_a, st_b) == (201, 201), f'[C] after restoring the password the same token and the same Idempotency-Keys write again on both replicas ({st_a}/{st_b})')
  obs(f'C2 restore: both replicas write again on the first request (+{(time.monotonic()-t_res)*1000:.0f} ms); issued token never revoked (exp {claims_exp["exp"]-claims_exp["iat"]}s lifetime, still valid)')

  # ======== D. emergency block (a): write-only redeploy =====================================================
  tok = token()
  ensure(create(A, tok, 'd-pre')[0] == 201, 'pre-redeploy write')
  new_names = []
  t0 = time.monotonic()
  for name in ('a', 'b'):
    ensure(live.run(['docker', 'rm', '-fv', f'{live.name_prefix}-{name}']).returncode == 0)
    api = replica(name, write_enabled=False)
    new_names.append(api)
    st, _, text, _ = create(api, tok, 'd-after-' + name)
    live.check(st == 403 and read_ok(api, tok) == 200,
               f'[D] replica {name} redeployed with MACHINE_WRITE_ENABLED=false: write {st} (scope_denied), read 200, SAME pre-event token ({text[:100]})')
  A, B = new_names
  obs(f'D1 write-only redeploy of two replicas (remove + start + ready, sequential): {time.monotonic()-t0:.1f} s; the first request on each new replica was already 403')
  live.check(not entry_exists('uid=d-after-a,' + PEOPLE), '[D] no entry was created by the refused writes')
  # roll writes back on
  for name in ('a', 'b'):
    ensure(live.run(['docker', 'rm', '-fv', f'{live.name_prefix}-{name}']).returncode == 0)
  A = replica('a')
  B = replica('b')
  live.check(create(A, tok, 'd-back-a')[0] == 201 and create(B, tok, 'd-back-b')[0] == 201,
             '[D] redeploy with MACHINE_WRITE_ENABLED=true: the same token writes again on both replicas')

  # ======== E. in-flight window =============================================================================
  P_name = 'p'
  P = replica(P_name, via_proxy=True)
  tok = token()
  st = create(P, tok, 'e-warm')[0]
  time.sleep(0.5)
  live.check(st == 201 and proxy.open == 0, f'[E] via the proxy a write works and leaves no open LDAP connection (open={proxy.open}): no connection reuse across requests')
  # E1: the write is held after W bound; rotate; release
  proxy.hold(WDATA_DN)
  result = {}
  key1 = new_key()

  def worker(uid, key, slot, api=None):
    began = time.monotonic()
    try:
      got = create(api or P, tok, uid, key=key, timeout=40)
      result[slot] = (got[0], got[2], time.monotonic() - began)
    except Exception as exc:  # noqa: BLE001
      result[slot] = ('error', str(exc), time.monotonic() - began)

  th = threading.Thread(target=worker, args=('e-inflight', key1, 'e1'))
  th.start()
  live.wait_until(lambda: proxy.held_at is not None, 'the write operation held at the LDAP connection', 15)
  held_for = 1.0
  time.sleep(held_for)
  set_password(WDATA_DN, new_pw)
  rot_at = time.monotonic()
  ensure(whoami(WDATA_DN, '/tmp/.pw-wdata') == 49, 'old W_data password must be rejected for NEW binds after the rotation')
  proxy.release()
  th.join(40)
  done_after = time.monotonic() - rot_at
  status1 = result['e1'][0]
  applied = entry_exists('uid=e-inflight,' + PEOPLE)
  obs(f'E1 write HELD on its already-bound W_data connection while the password was rotated: response {status1}, entry applied={applied}, '
      f'completed {done_after:.2f} s after the rotation (held {held_for + 0.3:.1f} s before it)')
  live.check(status1 in (200, 201, 204) and applied, f'[E] an in-flight write on an already bound connection COMPLETES after the rotation (measured: {status1}, applied={applied})')
  # E4: while rotated: replay of the completed key, and a new key
  rep = create(P, tok, 'e-inflight', key=key1)
  new = create(P, tok, 'e-new-after')
  obs(f'E2 while W_data is rotated: replay of the completed key -> {rep[0]} (Idempotent-Replayed={rep[1].get("Idempotent-Replayed")}, no LDAP write), a NEW key -> {new[0]}')
  live.check(new[0] == 503, f'[E] a new write after the rotation is 503 ({new[0]})')
  set_password(WDATA_DN, wdata_pw)

  # E2/E3: held for good, rotation 2 s in: how long can it run, how does it end, what does the key say afterwards
  proxy.hold(WDATA_DN)
  key2 = new_key()
  th = threading.Thread(target=worker, args=('e-stalled', key2, 'e2'))
  started = time.monotonic()
  th.start()
  live.wait_until(lambda: proxy.held_at is not None, 'the second write held', 15)
  time.sleep(2.0)
  set_password(WDATA_DN, new_pw)
  rot2 = time.monotonic()
  th.join(60)
  proxy.release()
  status2, body2, total2 = result['e2']
  closed_after_hold = (proxy.client_closed_at - proxy.held_at) if proxy.client_closed_at else None
  live.check(status2 in (409, 503) and total2 < 15, f'[E] a write stalled at the LDAP connection ends at the request deadline with {status2} {body2[:150]!r}')
  live.check(closed_after_hold is not None, '[E] the UI closed the stalled LDAP connection itself')
  ensure(not entry_exists('uid=e-stalled,' + PEOPLE), 'the held operation was dropped by the proxy (partition), nothing applied')
  obs(f'E3 write stalled at the LDAP connection: {status2} after {total2:.1f} s in total (MACHINE_REQUEST_TIMEOUT={default_timeout}), '
      f'the UI closed the W connection {closed_after_hold:.1f} s after the op was held; rotation was {rot2-started:.1f} s into the request, '
      f'so the request ended {total2-(rot2-started):.1f} s after the rotation')
  replay = create(P, tok, 'e-stalled', key=key2)
  obs(f'E4 retry of the key whose write timed out in flight (outcome unknown): {replay[0]} {replay[2][:160]!r}')
  set_password(WDATA_DN, wdata_pw)
  # the bound is the configured request timeout, not a constant: same experiment with MACHINE_REQUEST_TIMEOUT=4s
  P2 = replica('p2', via_proxy=True, extra_env={'MACHINE_REQUEST_TIMEOUT': '4s'})
  proxy.hold(WDATA_DN)
  th = threading.Thread(target=worker, args=('e-stalled4', new_key(), 'e5', P2))
  th.start()
  live.wait_until(lambda: proxy.held_at is not None, 'the third write held', 15)
  th.join(30)
  proxy.release()
  status5, _, total5 = result['e5']
  live.check(status5 in (409, 503) and 3.5 <= total5 <= 5.5, f'[E] with MACHINE_REQUEST_TIMEOUT=4s the stalled write ends after {total5:.1f} s ({status5}): the in-flight bound follows the setting')
  obs(f'E5 same stall with MACHINE_REQUEST_TIMEOUT=4s: {status5} after {total5:.1f} s')
  live.check(create(P, tok, 'e-after')[0] == 201, '[E] password restored: writes work again on the proxied replica')

  # ======== F. D24: W_* ppolicy lockout =====================================================================
  pol = {k: (op_attr(POLICY_DEFAULT, k) or [''])[0] for k in ('pwdLockout', 'pwdMaxFailure', 'pwdLockoutDuration', 'pwdFailureCountInterval')}
  obs(f'F0 default policy {POLICY_DEFAULT}: {pol}')
  tok = token()
  ensure(create(A, tok, 'f-pre')[0] == 201, 'pre-lockout write')
  locked_after = None
  for n in range(1, 11):
    ensure(whoami(WDATA_DN, '/tmp/.pw-wrong') == 49, 'wrong password must be rejected')
    if op_attr(WDATA_DN, 'pwdAccountLockedTime'):
      locked_after = n
      break
  live.check(locked_after == int(pol['pwdMaxFailure'] or 5),
             f'[F] default policy: W_data is locked after {locked_after} wrong-password binds (pwdMaxFailure={pol["pwdMaxFailure"]})')
  lock_stamp = op_attr(WDATA_DN, 'pwdAccountLockedTime')
  st = create(A, tok, 'f-locked')[0]
  st2 = create(B, tok, 'f-locked2')[0]
  live.check((st, st2) == (503, 503) and read_ok(A, tok) == 200 and read_ok(B, tok) == 200 and whoami(MACHINE_DN, '/tmp/.pw-machine') == 0,
             f'[F] while locked: writes {st}/{st2} even with the CORRECT password, reads 200, M still binds')
  live.check(op_attr(WDATA_DN, 'pwdAccountLockedTime') == lock_stamp, '[F] refused writes (correct-password binds while locked) do not extend or re-arm the lock')
  obs(f'F1 default policy: lock after {locked_after} wrong binds; writes 503 for pwdLockoutDuration={pol["pwdLockoutDuration"]} s unless unlocked; reads/M unaffected')
  # alert queries
  locked = ldap.admin_tool('ldapsearch', ['-LLL', '-b', SYSTEM_DN, '(&(objectClass=inetOrgPerson)(pwdAccountLockedTime=*))', 'dn']).stdout
  live.check(WDATA_DN in locked, '[F] alert query 1: (pwdAccountLockedTime=*) under ou=system lists the locked W account')
  fb = failed_binds(WDATA_DN)
  live.check(fb >= locked_after, f'[F] alert query 2: accesslog (reqType=bind)(reqDN=W)(reqResult=49) counts {fb} failed binds')
  # unlock
  r = ldap.admin_tool('ldapmodify', [], f'dn: {WDATA_DN}\nchangetype: modify\ndelete: pwdAccountLockedTime\n')
  ensure(r.returncode == 0, 'unlock: ' + live.mask(r.stderr))
  live.check(create(A, tok, 'f-unlocked')[0] == 201, '[F] admin unlock (delete pwdAccountLockedTime): the next write succeeds')

  # mitigation 1: dedicated policy without lockout
  # F1b: the UI's OWN refused writes are failed binds too: a rotation plus a stream of writes locks the account
  set_password(WDATA_DN, new_pw)
  ui_locked_at = None
  for n in range(1, 9):
    ensure(create(A, tok, f'f-uilock-{n}')[0] == 503, 'write must be refused while the password is rotated')
    if op_attr(WDATA_DN, 'pwdAccountLockedTime'):
      ui_locked_at = n
      break
  set_password(WDATA_DN, wdata_pw)
  after_restore = create(A, tok, 'f-uilock-restored')[0]
  live.check(ui_locked_at == int(pol['pwdMaxFailure'] or 5),
             f'[F] default policy: {ui_locked_at} refused UI writes (one failed bind each) after a rotation lock W_data')
  obs(f'F1b default policy: rotation + refused UI writes lock the account at write #{ui_locked_at}; after the admin restored the password the next write is {after_restore} '
      f'(lock attribute still present: {bool(op_attr(WDATA_DN, "pwdAccountLockedTime"))})')
  if op_attr(WDATA_DN, 'pwdAccountLockedTime'):
    ldap.admin_tool('ldapmodify', [], f'dn: {WDATA_DN}\nchangetype: modify\ndelete: pwdAccountLockedTime\n')
  ensure(create(A, tok, 'f-uilock-clear')[0] == 201, 'unlocked: the next write succeeds')

  def add_policy(name, attrs):
    dn = f'cn={name},ou=policies,{BASE_DN}'
    body = f'dn: {dn}\nobjectClass: top\nobjectClass: device\nobjectClass: pwdPolicy\ncn: {name}\npwdAttribute: userPassword\n' + ''.join(f'{k}: {v}\n' for k, v in attrs.items())
    r = ldap.admin_tool('ldapadd', [], body)
    ensure(r.returncode == 0, 'policy: ' + live.mask(r.stderr))
    return dn

  def assign_policy(dn, policy_dn):
    r = ldap.admin_tool('ldapmodify', [], f'dn: {dn}\nchangetype: modify\nreplace: pwdPolicySubentry\npwdPolicySubentry: {policy_dn}\n')
    ensure(r.returncode == 0, 'assign policy: ' + live.mask(r.stderr))

  # variant 1: pwdLockout FALSE but pwdMaxFailure still 5 (what an operator who only flips the flag gets)
  flag_only = add_policy('machine-writers-flag', {'pwdLockout': 'FALSE', 'pwdMaxFailure': '5'})
  assign_policy(WDATA_DN, flag_only)
  for _ in range(25):
    ensure(whoami(WDATA_DN, '/tmp/.pw-wrong') == 49, 'wrong password rejected')
  stamp = op_attr(WDATA_DN, 'pwdAccountLockedTime')
  st_flag = create(A, tok, 'f-flag')[0]
  obs(f'F2 policy with only pwdLockout FALSE (pwdMaxFailure 5 kept): after 25 wrong binds pwdAccountLockedTime={"SET " + stamp[0] if stamp else "absent"}, the next write is {st_flag}')
  live.check(st_flag == 201, f'[F] pwdLockout FALSE: writes keep working after 25 wrong-password binds ({st_flag})')
  if op_attr(WDATA_DN, 'pwdAccountLockedTime'):
    ldap.admin_tool('ldapmodify', [], f'dn: {WDATA_DN}\nchangetype: modify\ndelete: pwdAccountLockedTime\n')
  # variant 2 (the recommended one): no failure counting at all
  nolock = add_policy('machine-writers', {'pwdLockout': 'FALSE'})
  assign_policy(WDATA_DN, nolock)
  for _ in range(25):
    ensure(whoami(WDATA_DN, '/tmp/.pw-wrong') == 49, 'wrong password rejected')
  nolock_state = (op_attr(WDATA_DN, 'pwdAccountLockedTime'), create(A, tok, 'f-nolock')[0])
  live.check(not nolock_state[0] and nolock_state[1] == 201,
             f'[F] mitigation (dedicated policy: pwdLockout FALSE, no pwdMaxFailure): 25 wrong-password binds neither lock nor mark W_data, writes keep working ({nolock_state})')
  set_password(WDATA_DN, new_pw)
  codes = [create(A, tok, f'f-rot-{i}')[0] for i in range(8)]
  live.check(codes == [503] * 8 and not op_attr(WDATA_DN, 'pwdAccountLockedTime'),
             f'[F] with that policy the rotation block still works (8 refused writes, {set(codes)}) and 8 failed UI binds do not lock the account')
  set_password(WDATA_DN, wdata_pw)
  live.check(create(A, tok, 'f-rot-back')[0] == 201, '[F] restoring the password recovers the very next write (no lock to clear)')
  # a manual lock under that policy: does pwdLockout FALSE ignore an operator-set pwdAccountLockedTime?
  r = ldap.admin_tool('ldapmodify', [], f'dn: {WDATA_DN}\nchangetype: modify\nadd: pwdAccountLockedTime\npwdAccountLockedTime: 000001010000Z\n')
  ensure(r.returncode == 0, 'manual lock: ' + live.mask(r.stderr))
  manual = create(A, tok, 'f-manual')[0]
  obs(f'F2b under the no-lockout policy an operator-set pwdAccountLockedTime=000001010000Z (permanent lock) makes the next write {manual}: the attribute is {"honoured" if manual == 503 else "NOT honoured"} when pwdLockout is FALSE (use the password rotation as the block there)')
  ldap.admin_tool('ldapmodify', [], f'dn: {WDATA_DN}\nchangetype: modify\ndelete: pwdAccountLockedTime\n')
  live.check(create(A, tok, 'f-manual-off')[0] == 201, '[F] removing the manual lock recovers the next write')

  # mitigation 2: short lockout duration
  short = add_policy('machine-writers-short', {'pwdLockout': 'TRUE', 'pwdMaxFailure': '3', 'pwdLockoutDuration': '8', 'pwdFailureCountInterval': '60'})
  assign_policy(WDATA_DN, short)
  for _ in range(3):
    whoami(WDATA_DN, '/tmp/.pw-wrong')
  ensure(op_attr(WDATA_DN, 'pwdAccountLockedTime'), 'short policy: not locked after 3 wrong binds')
  t_lock = time.monotonic()
  ensure(create(A, tok, 'f-short-locked')[0] == 503, 'locked under the short policy: write must be 503')
  ensure(read_ok(A, tok) == 200 and read_ok(B, tok) == 200, 'reads must stay 200 while W_data is locked')
  recovered = None
  while time.monotonic() - t_lock < 40:
    time.sleep(0.5)
    if create(A, tok, 'f-short-' + uuid.uuid4().hex[:5])[0] == 201:
      recovered = time.monotonic() - t_lock
      break
  live.check(recovered is not None and 7 <= recovered <= 20,
             f'[F] mitigation (pwdLockoutDuration 8 s): writes recover by themselves {recovered and round(recovered, 1)} s after the lock, no operator action')
  obs(f'F3 short-duration policy (3 failures, 8 s): self-recovered {recovered:.1f} s after the lock; the unrelated reads were 200 throughout')
  # clean up: back to the default policy
  ldap.admin_tool('ldapmodify', [], f'dn: {WDATA_DN}\nchangetype: modify\ndelete: pwdPolicySubentry\n')
  live.check(create(A, tok, 'f-final')[0] == 201, '[F] W_data back on the default policy and writing')

  # ======== end: secrets must not be in any log =============================================================
  logs = live.all_logs()
  leaked = [v for v in issued + live.secret_values if len(v) >= 8 and v in logs]
  live.check(not leaked, 'no token or secret value appears in any container log')
  print(f'All machine write drill checks passed: {live.checks} checks in {live.elapsed():.0f}s.', flush=True)


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    live.dump_logs()
    raise
