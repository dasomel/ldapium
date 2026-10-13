#!/usr/bin/env python3
"""Machine WRITE end to end against a REAL Keycloak + real slapd + the normal UI image
(machine-write-scope T-025, #378; AC-001, AC-003, AC-004, AC-005, AC-006, AC-007, AC-008, AC-009, AC-013-AC-017).

The release gate for the five first-ship write operations (createUser, patchUser, deleteUser, addGroupMember,
removeGroupMember). The UI runs with MACHINE_WRITE_ENABLED=true on the production image (no drill build) against a
directory prepared exactly as the operator guide says (W_data / W_lock accounts, the write ACL fragments after the M
rules). Sibling of test-machine-keycloak-live.py (read side) and test-machine-write-drill.py (emergency block).

  A. positive writes of all five operations with positive tokens; W_data is the binding identity
  B. negative tokens and requests, each refused WITHOUT binding W_data and without any directory change:
     scope (reader-only ceiling, token without the scope, client ceiling without it), no write subtree, tampered token,
     subtree / strict-descendant / protected DN / group allow-list / target-type denials, PUT, closed attribute set
     (userPassword, objectClass, memberOf, pwd*, generatedPassword), the switch off (default)
  C. W_data ACL backstop: the attributes the application never sends are refused by slapd itself
  D. 428 (no Idempotency-Key, no / empty / malformed If-Match), 412 stale If-Match, idempotent replay (once, replayed
     header, different body 422, other client independent, replay after the ceiling is withdrawn is 403)
  E. audit: one machine_access line per request with the documented write fields, outcome per path
  F. limits: write budget 429 + Retry-After with reads unaffected, single write slot per client, recovery to baseline
  G. sentinel scan: no token, client secret, bind password, userPassword, request body value or Idempotency-Key in any log

Run (local):  LDAPIUM_IMAGE=ldapium:x LDAPIUM_UI_IMAGE=ldapium-ui:x python3 scripts/test/test-machine-write-keycloak-live.py
"""
import base64
import json
import pathlib
import re
import secrets
import sys
import threading
import time
import uuid
from urllib.parse import quote as urlquote

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'lib'))
from machine_live import (ADMIN_DN, AUDIENCE, BASE_DN, FIXTURES, MACHINE_DN, READER, Keycloak, LDAPProxy, Live,  # noqa: E402
                          Slapd, ensure, jbody, tamper)

live = Live('ldapium-mwk-', deadline_seconds=1500)
REALM = 'write-live'
SYSTEM_DN = 'ou=system,' + BASE_DN
WDATA_DN = 'uid=machine-write-data,' + SYSTEM_DN
WLOCK_DN = 'uid=machine-write-lock,' + SYSTEM_DN
PEOPLE = 'ou=people,' + BASE_DN
GROUPS = 'ou=groups,' + BASE_DN
G1 = 'cn=g01,' + GROUPS
G2 = 'cn=g02,' + GROUPS
WRITE_SCOPES = ['directory.users.create', 'directory.users.update', 'directory.users.delete',
                'directory.groups.members.add', 'directory.groups.members.remove']
STALE = '"20260101000000.000000Z#000000#000#000000"'
# values that must never reach a log: request body values and Idempotency-Keys are generated per run
SENTINEL_MAIL = 'sentinel-' + secrets.token_hex(6) + '@example.org'
SENTINEL_SN = 'SentinelSn' + secrets.token_hex(5)


def obs(text):
  print('OBS ' + text, flush=True)


def main():
  print(f'Run {live.name_prefix}: server {live.ldap_image}, UI {live.ui_image}, Keycloak {live.keycloak_image}', flush=True)
  live.make_network()
  ldap = Slapd(live)
  ldap.start()
  ldap.seed(users=4, groups=2)
  ldap.apply_acl()

  # ---- W_data / W_lock accounts and the write ACL fragments (docs/machine-write-account.md) ----------------
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
  apply_fragment('write-lock.ldif', 'WLOCK_DN', WLOCK_DN, 12)  # after the nine W_data rules
  ldap.put_password('/tmp/.pw-wdata', wdata_pw)
  live.check(True, 'W_data/W_lock accounts created and the write ACL fragments applied after the M rules')

  def op_attr(dn, attr):
    out = ldap.admin_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', dn, '-s', 'base', attr]).stdout
    return [l.split(': ', 1)[1] for l in out.splitlines() if l.lower().startswith(attr.lower() + ': ')]

  def entry_exists(dn):
    return ldap.admin_tool('ldapsearch', ['-LLL', '-b', dn, '-s', 'base', 'dn']).returncode == 0

  def w_binds():
    time.sleep(0.4)
    return ldap.binds(WDATA_DN)

  # ---- Keycloak: one client per refusal reason --------------------------------------------------------------
  kcname = live.name_prefix + '-kc'
  kc = Keycloak(live, kcname, f'http://{kcname}:8080')
  kc.start()
  kc.create_realm(REALM)
  for scope in READER + WRITE_SCOPES:
    kc.create_scope(REALM, scope)
  # name -> (scopes in the Keycloak token, scopes in the application ceiling)
  clients = {
    'svc-writer': (READER + WRITE_SCOPES, READER + WRITE_SCOPES),    # PEOPLE + GROUPS, group g01
    'svc-people': (READER + WRITE_SCOPES, READER + WRITE_SCOPES),    # PEOPLE only, no group allow-list
    'svc-other': (READER + WRITE_SCOPES, READER + WRITE_SCOPES),     # second client for idempotency isolation
    'svc-reader': (READER, READER),                                  # reader-only
    'svc-tokscope': (READER, READER + WRITE_SCOPES),                 # ceiling has write, the TOKEN does not
    'svc-ceiling': (READER + WRITE_SCOPES, READER),                  # token has write, the client CEILING does not
    'svc-nosub': (READER + WRITE_SCOPES, READER + WRITE_SCOPES),     # write scopes, no write subtree
    'svc-revoke': (READER + WRITE_SCOPES, READER + WRITE_SCOPES),    # its Keycloak write scope is withdrawn mid-run (D)
  }
  client_secret = {}
  client_uuid = {}
  for name, (token_scopes, _) in clients.items():
    client_secret[name] = live.secret(name + '-' + secrets.token_hex(10))
    client_uuid[name] = kc.create_client(REALM, name, client_secret[name], scopes=token_scopes)
  issued = []

  def token(name='svc-writer'):
    value = kc.sa_token(REALM, name, client_secret[name])
    issued.append(value)
    # a failing run dumps container logs: every issued token and each of its segments is masked there
    for part in [value] + value.split('.'):
      live.secret(part)
    return value

  session_secret = live.secret(secrets.token_hex(32))
  proxy = LDAPProxy('127.0.0.1', ldap.port)
  live.closers.append(proxy.close)

  def env_for(write_enabled=True, ceilings=None, subtrees=None, extra=None):
    ceilings = ceilings or {c: s for c, (_, s) in clients.items()}
    subtrees = subtrees or {'svc-writer': f'{PEOPLE}|{GROUPS}', 'svc-people': PEOPLE, 'svc-other': PEOPLE,
                            'svc-tokscope': PEOPLE, 'svc-ceiling': PEOPLE, 'svc-revoke': PEOPLE}
    env = {'LDAP_BASE_DN': BASE_DN, 'LDAP_USER_CREATE_BASE': PEOPLE, 'COOKIE_SECURE': 'false', 'UI_TRUSTED_PROXIES': 'none',
           'MACHINE_AUTH_ENABLED': 'true', 'MACHINE_OIDC_INSECURE_HTTP': 'true', 'MACHINE_OIDC_ISSUER_URL': kc.issuer(REALM),
           'MACHINE_OIDC_AUDIENCE': AUDIENCE, 'MACHINE_CLOCK_SKEW': '0s',
           'MACHINE_ALLOWED_CLIENTS': ';'.join(f'{c}={",".join(s)}' for c, s in ceilings.items()),
           'MACHINE_LDAP_BIND_DN': MACHINE_DN, 'MACHINE_LDAP_ROOT_DNS': ADMIN_DN,
           'MACHINE_AUTH_FAILURE_LIMIT': '1000', 'MACHINE_RATE_LIMIT_RPS': '10000', 'MACHINE_RATE_LIMIT_BURST': '10000',
           'UI_IDEMPOTENCY_ENABLED': 'true', 'MACHINE_WRITE_ENABLED': 'true' if write_enabled else 'false',
           'MACHINE_WRITE_DATA_BIND_DN': WDATA_DN, 'MACHINE_WRITE_LOCK_ENABLED': 'true', 'MACHINE_WRITE_LOCK_BIND_DN': WLOCK_DN,
           'MACHINE_WRITE_SUBTREES': ';'.join(f'{c}={s}' for c, s in subtrees.items()),
           'MACHINE_WRITE_GROUPS': f'svc-writer={G1}',
           'MACHINE_WRITE_PRIVILEGED_GROUPS': 'cn=admins,' + GROUPS,
           'MACHINE_WRITE_RATE_LIMIT_RPS': '100', 'MACHINE_WRITE_RATE_LIMIT_BURST': '100'}
    env.update(extra or {})
    return env

  held = {'SESSION_SECRET': session_secret, 'MACHINE_LDAP_BIND_PASSWORD': ldap.machine_password,
          'MACHINE_WRITE_DATA_BIND_PASSWORD': wdata_pw, 'MACHINE_WRITE_LOCK_BIND_PASSWORD': wlock_pw}

  def replica(name, via_proxy=False, **kw):
    url = f'ldap://host.docker.internal:{proxy.port}' if via_proxy else f'ldap://{ldap.name}:389'
    return live.start_ui(f'{live.name_prefix}-{name}', url, env_for(**kw), held)

  def call(api, tok, method, path, body=None, key=None, etag=None, rid=None, timeout=30, headers=None):
    h = {'Authorization': 'Bearer ' + tok}
    if body is not None:
      h['Content-Type'] = 'application/json'
    if key:
      h['Idempotency-Key'] = key
    if etag:
      h['If-Match'] = etag
    if rid:
      h['X-Request-Id'] = rid
    h.update(headers or {})
    status, hdrs, text = api.call(method, path, h, body, timeout=timeout)
    return status, hdrs, text

  def new_key():
    return 'mwk-' + uuid.uuid4().hex

  def create(api, tok, uid, key=None, rid=None, timeout=30, **fields):
    body = {'uid': uid, 'cn': uid, 'sn': 'Live', 'mail': uid + '@example.org'}
    body.update(fields)
    return call(api, tok, 'POST', '/api/users', body, key or new_key(), rid=rid, timeout=timeout)

  def etag_of(api, tok, dn):
    status, hdrs, text = call(api, tok, 'GET', '/api/entry?dn=' + urlquote(dn))
    ensure(status == 200 and hdrs.get('ETag'), f'entry {dn}: {status} {text[:200]}')
    return hdrs['ETag']

  def patch(api, tok, dn, fields, etag, key=None, rid=None):
    return call(api, tok, 'PATCH', '/api/users', dict(fields, dn=dn), key or new_key(), etag, rid=rid)

  def audit(container, rid):
    out = []
    for line in live.audit_lines(f'{live.name_prefix}-{container}'):
      event = json.loads(line[line.index('{'):])
      if event.get('request_id') == rid:
        out.append(event)
    return out

  def rid_new(tag):
    return f'mwk-{tag}-{secrets.token_hex(3)}'

  A = replica('a')
  tok = token()

  # ======== A. positive writes ===============================================================================
  before = w_binds()
  st, _, text = create(A, tok, 'w01', mail=SENTINEL_MAIL, sn=SENTINEL_SN)
  w01 = 'uid=w01,' + PEOPLE
  live.check(st == 201 and entry_exists(w01), f'[A] createUser -> 201 and the entry exists (got {st} {text[:140]})')
  live.check(not op_attr(w01, 'userPassword'), '[A] createUser sets no password')
  live.check(w_binds() > before, '[A] the write bound as W_data (slapd accesslog)')
  st, _, text = patch(A, tok, w01, {'department': 'ops'}, etag_of(A, tok, w01))
  entry_ldif = ldap.admin_tool('ldapsearch', ['-LLL', '-b', w01, '-s', 'base']).stdout
  live.check(st in (200, 204) and ': ops' in entry_ldif, f'[A] patchUser with a strong If-Match -> {st}, the department value is stored')
  st, _, text = call(A, tok, 'POST', '/api/groups/members', {'groupDn': G1, 'memberDn': w01}, new_key(), etag_of(A, tok, G1))
  live.check(st in (200, 204) and w01 in op_attr(G1, 'member'), f'[A] addGroupMember -> {st}')
  st, _, text = call(A, tok, 'DELETE', f'/api/groups/members?groupDn={urlquote(G1)}&memberDn={urlquote(w01)}', None, new_key(), etag_of(A, tok, G1))
  live.check(st in (200, 204) and w01 not in op_attr(G1, 'member'), f'[A] removeGroupMember -> {st}')
  st, _, text = call(A, tok, 'DELETE', f'/api/users?dn={urlquote(w01)}', None, new_key(), etag_of(A, tok, w01))
  live.check(st in (200, 204) and not entry_exists(w01), f'[A] deleteUser (leaf) -> {st} and the entry is gone')
  # AC-009: a user with a child entry, a group and a container are not deleted
  dp = 'uid=dp1,' + PEOPLE
  ensure(create(A, tok, 'dp1')[0] == 201, 'dp1 created')
  child = 'ou=child,' + dp
  r = ldap.admin_tool('ldapadd', [], f'dn: {child}\nobjectClass: organizationalUnit\nou: child\n')
  ensure(r.returncode == 0, 'child: ' + live.mask(r.stderr))
  for label, dn in (('user with a child entry', dp), ('group', G1), ('container', PEOPLE)):
    st, _, text = call(A, tok, 'DELETE', f'/api/users?dn={urlquote(dn)}', None, new_key(), etag_of(A, tok, dn) if dn != PEOPLE else STALE)
    live.check(st >= 400 and entry_exists(dn), f'[A] AC-009 deleteUser on a {label} is refused ({st}) and the entry stays')
  ldap.admin_tool('ldapdelete', [child])
  ldap.admin_tool('ldapdelete', [dp])

  # ======== B. negatives: no W_data bind, no directory change ===============================================
  victim = 'uid=victim,' + PEOPLE
  ensure(create(A, tok, 'victim')[0] == 201, 'victim created')
  victim_tag = etag_of(A, tok, victim)
  other_user = ldap.admin_tool('ldapsearch', ['-LLL', '-b', PEOPLE, '-s', 'one', '(uid=u01)', 'dn']).stdout.split('dn: ')[1].split('\n')[0]
  base_binds = w_binds()
  members_g2 = op_attr(G2, 'member')
  tokens = {n: token(n) for n in clients}
  neg = [
    ('reader-only client (ceiling and token)', lambda: create(A, tokens['svc-reader'], 'n01'), 403),
    ('token without the write scope (ceiling has it)', lambda: create(A, tokens['svc-tokscope'], 'n02'), 403),
    ('client ceiling without the write scope (token has it)', lambda: create(A, tokens['svc-ceiling'], 'n03'), 403),
    ('write scopes but no write subtree', lambda: create(A, tokens['svc-nosub'], 'n04'), 403),
    ('tampered token', lambda: create(A, tamper(tok), 'n05'), 401),
    ('no token', lambda: A.call('POST', '/api/users', {'Content-Type': 'application/json', 'Idempotency-Key': new_key()},
                                {'uid': 'n06', 'cn': 'n06', 'sn': 'n'}), 401),
    ('PUT is not opened', lambda: call(A, tok, 'PUT', '/api/users', {'dn': victim, 'cn': 'a', 'sn': 'b'}, new_key(), victim_tag), 403),
    ('group create is not opened', lambda: call(A, tok, 'POST', '/api/groups', {'cn': 'grp-n07'}, new_key()), 403),
    ('lock is not opened', lambda: call(A, tok, 'POST', '/api/users/lock', {'dn': victim}, new_key(), victim_tag), 403),
    # subtree ceiling (AC-003b, AC-015, AC-014)
    ('patch a target outside the ceiling (svc-people -> a group)', lambda: patch(A, tokens['svc-people'], G1, {'mail': 'a@b.c'}, STALE), 403),
    ('patch the ceiling root itself (strict descendant)', lambda: patch(A, tok, PEOPLE, {'mail': 'a@b.c'}, STALE), 403),
    ('patch the ceiling root, upper-case and spaced', lambda: patch(A, tok, 'OU=People , ' + BASE_DN.upper(), {'mail': 'a@b.c'}, STALE), 403),
    ('patch a protected DN (W_data)', lambda: patch(A, tok, WDATA_DN, {'mail': 'a@b.c'}, STALE), 403),
    ('patch the machine read account M', lambda: patch(A, tok, MACHINE_DN, {'mail': 'a@b.c'}, STALE), 403),
    ('delete the administrator', lambda: call(A, tok, 'DELETE', f'/api/users?dn={urlquote(ADMIN_DN)}', None, new_key(), STALE), 403),
    ('delete an OID-typed spelling of a user outside the ceiling', lambda: call(A, tok, 'DELETE', f'/api/users?dn={urlquote("0.9.2342.19200300.100.1.1=machine," + SYSTEM_DN)}', None, new_key(), STALE), 403),
    ('member add to a group that is not on the client allow-list', lambda: call(A, tok, 'POST', '/api/groups/members', {'groupDn': G2, 'memberDn': victim}, new_key(), STALE), 403),
    ('member add by a client without any group', lambda: call(A, tokens['svc-people'], 'POST', '/api/groups/members', {'groupDn': G1, 'memberDn': victim}, new_key(), STALE), 403),
    ('member DN outside the ceiling', lambda: call(A, tok, 'POST', '/api/groups/members', {'groupDn': G1, 'memberDn': MACHINE_DN}, new_key(), STALE), 403),
    ('privileged group as member target', lambda: call(A, tok, 'POST', '/api/groups/members', {'groupDn': 'cn=admins,' + GROUPS, 'memberDn': victim}, new_key(), STALE), 403),
    # closed attribute set (AC-003c, AC-008)
    ('createUser with a password field', lambda: create(A, tok, 'n08', password='Sup3rSecret!'), 400),
    ('createUser with userPassword', lambda: create(A, tok, 'n09', userPassword='Sup3rSecret!'), 400),
    ('createUser with generatedPassword', lambda: create(A, tok, 'n10', generatedPassword=True), 400),
    ('createUser with objectClass', lambda: create(A, tok, 'n11', objectClass='organizationalPerson'), 400),
    ('patchUser with userPassword', lambda: patch(A, tok, victim, {'userPassword': 'Sup3rSecret!'}, victim_tag), 400),
    ('patchUser with objectClass', lambda: patch(A, tok, victim, {'objectClass': 'posixAccount'}, victim_tag), 400),
    ('patchUser with memberOf', lambda: patch(A, tok, victim, {'memberOf': G1}, victim_tag), 400),
    ('patchUser with pwdAccountLockedTime', lambda: patch(A, tok, victim, {'pwdAccountLockedTime': '000001010000Z'}, victim_tag), 400),
    ('patchUser with uid (RDN)', lambda: patch(A, tok, victim, {'uid': 'renamed'}, victim_tag), 400),
  ]
  for name, run, want in neg:
    st, _, text = run()
    live.check(st == want, f'[B] negative "{name}" -> {want} (got {st} {text[:100]})')
  live.check(w_binds() == base_binds, '[B] none of the negative requests bound as W_data')
  for u in ('n01', 'n02', 'n03', 'n04', 'n05', 'n06', 'n08', 'n09', 'n10', 'n11', 'renamed'):
    ensure(not entry_exists(f'uid={u},{PEOPLE}'), f'{u} must not exist')
  ensure(op_attr(G2, 'member') == members_g2 and not op_attr(victim, 'userPassword'), 'directory state unchanged by the refusals')
  ensure(entry_exists(PEOPLE) and entry_exists(other_user), 'containers and other users untouched')
  live.check(etag_of(A, tok, victim) == victim_tag, '[B] the victim entry is byte-for-byte unchanged (same ETag) after all refusals')
  # AC-001: the switch off (default) writes nothing even with write scopes in every ceiling
  OFF = replica('off', write_enabled=False)
  before = w_binds()
  st = create(OFF, tok, 'closed1')[0]
  live.check(st == 403 and not entry_exists('uid=closed1,' + PEOPLE) and w_binds() == before and call(OFF, tok, 'GET', '/api/users?limit=1')[0] == 200,
             f'[B] MACHINE_WRITE_ENABLED off: write {st} (no entry, no W bind), reads 200')
  # AC-014: a protected entry INSIDE the allowed subtree. A privileged group is in the protected set; here it lies in
  # ou=groups, which is inside svc-writer's ceiling (subtree and strict-descendant checks pass), and the audit outcome
  # names the guard that refused: denied_protected, not denied_guard.
  privg = 'cn=privg,' + GROUPS
  ensure(ldap.admin_tool('ldapadd', [], f'dn: {privg}\nobjectClass: groupOfNames\ncn: privg\nmember: {victim}\n').returncode == 0, 'privg')
  PROT = replica('prot', extra={'MACHINE_WRITE_PRIVILEGED_GROUPS': privg})
  ptag = etag_of(PROT, tok, privg)
  before = w_binds()
  prid1, prid2 = rid_new('priv1'), rid_new('priv2')
  s1 = call(PROT, tok, 'DELETE', f'/api/users?dn={urlquote(privg)}', None, new_key(), ptag, rid=prid1)
  s2 = patch(PROT, tok, privg, {'mail': 'a@b.c'}, ptag, rid=prid2)
  time.sleep(0.6)
  live.check(s1[0] == 403 and s2[0] == 403 and w_binds() == before and entry_exists(privg) and op_attr(privg, 'mail') == [],
             f'[B] a privileged group inside the ceiling: deleteUser {s1[0]}, patchUser {s2[0]}, no W bind, group intact')
  pa = audit('prot', prid1) + audit('prot', prid2)
  live.check(len(pa) == 2 and all(e['outcome'] == 'denied_protected' for e in pa), '[B] both are audited as denied_protected (the protected-DN guard, not the subtree guard): ' + json.dumps([e.get('outcome') for e in pa]))
  live.start_ui(f'{live.name_prefix}-prot2', f'ldap://{ldap.name}:389', env_for(extra={'MACHINE_WRITE_GROUPS': f'svc-writer={privg}', 'MACHINE_WRITE_PRIVILEGED_GROUPS': privg}), held, wait=False)
  live.wait_until(lambda: live.run(['docker', 'inspect', '-f', '{{.State.Running}}', live.name_prefix + '-prot2']).stdout.strip() == 'false',
                  'the UI to refuse a privileged group on the allow-list', 30)
  refusal = live.run(['docker', 'logs', live.name_prefix + '-prot2'])
  live.check('must not list a privileged group' in refusal.stdout + refusal.stderr, '[B] a privileged group on a client allow-list is a start-up error')
  # AC-014 / AC-002: a ceiling that covers a protected identity is a START-UP error, not a runtime guess
  live.start_ui(f'{live.name_prefix}-wide', f'ldap://{ldap.name}:389',
                env_for(subtrees={'svc-writer': SYSTEM_DN, 'svc-people': PEOPLE, 'svc-other': PEOPLE}), held, wait=False)
  live.wait_until(lambda: live.run(['docker', 'inspect', '-f', '{{.State.Running}}', live.name_prefix + '-wide']).stdout.strip() == 'false',
                  'the UI to refuse a write ceiling over ou=system', 30)
  refusal = live.run(['docker', 'logs', live.name_prefix + '-wide'])
  live.check('must not overlap a protected identity' in refusal.stdout + refusal.stderr,
             '[B] a write ceiling over the service accounts (ou=system) is a start-up error: the protected DNs cannot be put inside a ceiling')

  # ======== C. the W_data ACL backstop (the app never sends these) ==========================================
  def as_wdata(args_ldif, tool='ldapmodify'):
    return ldap.tool(tool, [], WDATA_DN, '/tmp/.pw-wdata', input_data=args_ldif)

  r = as_wdata(f'dn: {victim}\nchangetype: modify\nreplace: userPassword\nuserPassword: Direct-Attempt-1\n')
  live.check(r.returncode != 0 and 'Insufficient access' in r.stderr and not op_attr(victim, 'userPassword'), '[C] W_data cannot write userPassword directly (ACL)')
  r = as_wdata(f'dn: {victim}\nchangetype: modify\nreplace: pwdAccountLockedTime\npwdAccountLockedTime: 000001010000Z\n')
  live.check(r.returncode != 0 and not op_attr(victim, 'pwdAccountLockedTime'), '[C] W_data cannot write pwd* state directly (ACL)')
  r = as_wdata(f'dn: {MACHINE_DN}\nchangetype: modify\nreplace: description\ndescription: x\n')
  live.check(r.returncode != 0 and not op_attr(MACHINE_DN, 'description'), '[C] W_data cannot write under ou=system (M) (ACL)')
  r = ldap.tool('ldapmodify', [], MACHINE_DN, '/tmp/.pw-machine', input_data=f'dn: {victim}\nchangetype: modify\nreplace: mail\nmail: m@x.y\n')
  live.check(r.returncode != 0, '[C] M still writes nothing, ever')

  # ======== D. 428 / 412 / replay ============================================================================
  before = w_binds()
  tag = etag_of(A, tok, victim)
  d_cases = [
    ('create without Idempotency-Key', lambda: call(A, tok, 'POST', '/api/users', {'uid': 'd01', 'cn': 'd', 'sn': 'd'}), 428),
    ('patch without If-Match', lambda: patch(A, tok, victim, {'mail': 'a@b.c'}, None), 428),
    ('patch with an empty If-Match', lambda: call(A, tok, 'PATCH', '/api/users', {'dn': victim, 'mail': 'a@b.c'}, new_key(), '', headers={'If-Match': ''}), 428),
    ('patch without Idempotency-Key', lambda: call(A, tok, 'PATCH', '/api/users', {'dn': victim, 'mail': 'a@b.c'}, None, tag), 428),
    ('delete without If-Match', lambda: call(A, tok, 'DELETE', f'/api/users?dn={urlquote(victim)}', None, new_key()), 428),
    ('member add without If-Match', lambda: call(A, tok, 'POST', '/api/groups/members', {'groupDn': G1, 'memberDn': victim}, new_key()), 428),
  ]
  for name, run, want in d_cases:
    st, _, text = run()
    live.check(st == want, f'[D] "{name}" -> {want} (got {st} {text[:100]})')
  for name, header in (('wildcard', '*'), ('weak', 'W/' + tag), ('two values', tag + ', ' + STALE), ('unquoted', tag.strip('"'))):
    st, _, text = call(A, tok, 'PATCH', '/api/users', {'dn': victim, 'mail': 'bad@b.c'}, new_key(), None, headers={'If-Match': header})
    live.check(st in (400, 412, 428), f'[D] If-Match "{name}" is refused ({st}), nothing written')
  live.check(w_binds() == before and op_attr(victim, 'mail') != ['bad@b.c'] and op_attr(victim, 'mail') != ['a@b.c'], '[D] none of the 428/If-Match refusals bound as W_data or wrote')
  # 412: someone else changes the entry between the read and the write
  stale = etag_of(A, tok, victim)
  ensure(ldap.admin_tool('ldapmodify', [], f'dn: {victim}\nchangetype: modify\nreplace: description\ndescription: concurrent\n').returncode == 0)
  before = w_binds()
  rid412 = rid_new('412')
  st, _, text = patch(A, tok, victim, {'mail': 'stale@b.c'}, stale, rid=rid412)
  live.check(st == 412 and jbody(text).get('code') == 'revision_conflict' and op_attr(victim, 'mail') != ['stale@b.c'],
             f'[D] stale If-Match -> 412 revision_conflict, no write ({st})')
  # idempotent replay
  key = new_key()
  rid_first, rid_replay = rid_new('first'), rid_new('replay')
  st1, h1, t1 = create(A, tok, 'rp1', key=key, rid=rid_first, mail=SENTINEL_MAIL)
  before = w_binds()
  st2, h2, t2 = create(A, tok, 'rp1', key=key, rid=rid_replay, mail=SENTINEL_MAIL)
  live.check((st1, st2) == (201, 201) and h2.get('Idempotent-Replayed') == 'true' and not h1.get('Idempotent-Replayed'),
             f'[D] same key + same request: executed once ({st1}), the retry is the stored 201 with Idempotent-Replayed: true ({st2})')
  live.check(w_binds() == before, '[D] the replay did not bind as W_data (no LDAP work)')
  st3, _, t3 = create(A, tok, 'rp1-other', key=key)
  live.check(st3 == 422 and jbody(t3).get('code') == 'idempotency_key_reused' and not entry_exists('uid=rp1-other,' + PEOPLE),
             f'[D] same key, different request -> 422 idempotency_key_reused ({st3})')
  other = token('svc-other')
  st4, h4, _ = create(A, other, 'rp1x', key=key)
  live.check(st4 == 201 and h4.get('Idempotent-Replayed') != 'true' and entry_exists('uid=rp1x,' + PEOPLE),
             f'[D] AC-005 another client with the same key is independent: executed, not a replay or a conflict ({st4})')
  ldap.admin_tool('ldapdelete', ['uid=rp1,' + PEOPLE, 'uid=rp1x,' + PEOPLE])
  # AC-017(b), SAME process (the idempotency store is process memory, so no restart): svc-revoke records a key, then
  # Keycloak withdraws its create scope; the same key and the same request with the new token must be re-authorized
  # first (403 scope_denied), never answered with the stored 201.
  rtok = token('svc-revoke')
  rk = new_key()
  rrid = rid_new('revoked')
  ensure(create(A, rtok, 'rp2', key=rk)[0] == 201, 'rp2 created')
  kc.remove_default_scope(REALM, client_uuid['svc-revoke'], 'directory.users.create')
  rtok2 = token('svc-revoke')
  live.check('directory.users.create' not in json.loads(base64.urlsafe_b64decode(rtok2.split('.')[1] + '==')).get('scope', '').split(),
             '[D] Keycloak no longer puts directory.users.create in the new svc-revoke token')
  before = w_binds()
  st = create(A, rtok2, 'rp2', key=rk, rid=rrid)
  live.check(st[0] == 403 and st[1].get('Idempotent-Replayed') != 'true' and w_binds() == before,
             f'[D] AC-017b same replica: replaying a stored key after the token lost the write scope is 403 (re-authorized first), not the stored 201 ({st[0]})')
  st = create(A, rtok, 'rp2', key=rk)
  live.check(st[0] == 201 and st[1].get('Idempotent-Replayed') == 'true', f'[D] the stored record is intact: the old, still valid token replays it ({st[0]}, replayed={st[1].get("Idempotent-Replayed")})')

  # ======== E. audit ========================================================================================
  time.sleep(0.6)
  ok = audit('a', rid_first)
  live.check(len(ok) == 1, '[E] the applied create has exactly one machine_access line')
  ev = ok[0]
  live.check(ev['actor'] == 'svc-writer' and ev['status'] == 201 and ev['bind_dn'] == WDATA_DN and ev['write_scope'] == 'directory.users.create'
             and ev['compartment'] == 'data' and ev['target_kind'] == 'user' and ev['outcome'] == 'applied' and ev['target_dn_fingerprint']
             and ev['idempotency_subject_fingerprint'] and 'target_dn' not in ev, '[E] applied line: actor, bind_dn=W_data, write_scope, compartment, target_kind, outcome, fingerprints, no plaintext DN: ' + json.dumps(ev)[:360])
  rp = audit('a', rid_replay)
  live.check(len(rp) == 1 and rp[0]['outcome'] == 'replayed' and rp[0]['status'] == 201, f'[E] the replay has one line, outcome replayed: {json.dumps(rp)[:240]}')
  pf = audit('a', rid412)
  live.check(len(pf) == 1 and pf[0]['status'] == 412 and pf[0]['outcome'] == 'precondition_failed' and pf[0]['if_match'] is True, f'[E] the 412 has one line, outcome precondition_failed: {json.dumps(pf)[:240]}')
  rid_scope, rid_sub, rid_428 = rid_new('scope'), rid_new('sub'), rid_new('428')
  create(A, tokens['svc-reader'], 'n20', rid=rid_scope)
  patch(A, tok, WDATA_DN, {'mail': 'a@b.c'}, STALE, rid=rid_sub)
  call(A, tok, 'POST', '/api/users', {'uid': 'n21', 'cn': 'n', 'sn': 'n'}, rid=rid_428)
  time.sleep(0.6)
  for tag_, rid, status, reason in (('scope denial', rid_scope, 403, 'scope'), ('protected-DN denial', rid_sub, 403, None), ('missing Idempotency-Key', rid_428, 428, None)):
    lines = audit('a', rid)
    live.check(len(lines) == 1 and lines[0]['status'] == status and lines[0]['actor'] and lines[0]['result'] and (reason is None or lines[0]['reason'] == reason),
               f'[E] {tag_}: exactly one line with actor, status {status}, result: {json.dumps(lines)[:240]}')
  # LDAP refusal: the request passes every application guard, binds as W_data and slapd itself answers
  # entryAlreadyExists: 409 already_exists, outcome ldap_refused, bind_dn W_data (one W bind), and the entry is unchanged.
  rid_ldap = rid_new('ldap')
  victim_tag_now = etag_of(A, tok, victim)
  before = w_binds()
  st, _, text = create(A, tok, 'victim', rid=rid_ldap)
  time.sleep(0.6)
  lines = audit('a', rid_ldap)
  live.check(st == 409 and jbody(text).get('code') == 'already_exists' and w_binds() == before + 1 and len(lines) == 1
             and lines[0]['outcome'] == 'ldap_refused' and lines[0]['bind_dn'] == WDATA_DN and lines[0]['status'] == 409
             and lines[0]['write_scope'] == 'directory.users.create' and etag_of(A, tok, victim) == victim_tag_now,
             f'[E] createUser of an existing uid: W_data bound, slapd refused: 409 already_exists + one ldap_refused line ({st}, {json.dumps(lines)[:240]})')

  # ======== F. limits ========================================================================================
  LIM = replica('lim', extra={'MACHINE_WRITE_RATE_LIMIT_RPS': '1', 'MACHINE_WRITE_RATE_LIMIT_BURST': '2'})
  ltok = token()
  results = [create(LIM, ltok, f'lim{i}') for i in range(8)]
  codes = [r[0] for r in results]
  limited = [r for r in results if r[0] == 429]
  live.check(codes[:2] == [201, 201] and limited and all(r[1].get('Retry-After', '').isdigit() and jbody(r[2]).get('code') == 'machine_rate_limited' for r in limited),
             f'[F] write budget (rps 1, burst 2): first two 201, then 429 machine_rate_limited with Retry-After ({codes})')
  live.check(all(call(LIM, ltok, 'GET', '/api/users?limit=1')[0] == 200 for _ in range(5)), '[F] the same client\'s reads are not affected by the exhausted write budget')
  # single write slot per client, and recovery to the baseline
  PX = replica('px', via_proxy=True)
  ptok = token()
  ensure(create(PX, ptok, 'slot-warm')[0] == 201, 'warm-up write via the proxy')
  proxy.set_mode('stall')
  holder = {}

  def slow():
    holder['r'] = create(PX, ptok, 'slot-held', timeout=40)

  th = threading.Thread(target=slow)
  th.start()
  live.wait_until(proxy.stalled.is_set, 'the first write stalled at the LDAP connection', 15)
  began = time.monotonic()
  st, hdrs, text = create(PX, ptok, 'slot-second')
  took = time.monotonic() - began
  live.check(st in (429, 503) and took < 5 and not entry_exists('uid=slot-second,' + PEOPLE),
             f'[F] a second concurrent write of the same client is refused at once ({st} after {took:.2f}s, Retry-After={hdrs.get("Retry-After")})')
  proxy.set_mode('pass')
  proxy.release()
  th.join(45)
  live.check(holder.get('r', (0,))[0] == 201 and entry_exists('uid=slot-held,' + PEOPLE), f'[F] the held write completes after the stall is released ({holder.get("r", (0,))[0]})')
  live.wait_until(lambda: proxy.open == 0, 'LDAP connections to return to the baseline', 15)
  after_ok = create(PX, ptok, 'slot-after')[0] == 201
  # the proxy sees the close a moment after the response, so poll instead of sampling once
  live.wait_until(lambda: proxy.open == 0, 'the connection of the next write to close', 15)
  live.check(after_ok and proxy.open == 0, '[F] the write slot and the connections are back at the baseline: the next write works, no connection left open')

  # ======== G. sentinel scan =================================================================================
  time.sleep(0.5)
  logs = live.all_logs()
  pool = [t for t in issued if t] + [live.secret_values[i] for i in range(len(live.secret_values))] + [SENTINEL_MAIL, SENTINEL_SN,
                                                                                                       'Sup3rSecret!', 'Direct-Attempt-1']
  leaks = []
  for value in pool:
    parts = [value] if value.count('.') != 2 else [value] + value.split('.')
    leaks += [part[:10] + '...' for part in parts if len(part) >= 8 and part in logs]
  keys_in_logs = re.findall(r'mwk-[0-9a-f]{32}', logs)
  live.check(not leaks and not keys_in_logs,
             f'[G] sentinel scan of ALL {len(live.containers)} container logs ({len(logs)} bytes): no token, JWT segment, client secret, bind/admin/userPassword value, request body value or Idempotency-Key: {leaks} {keys_in_logs[:2]}')
  print(f'All machine write Keycloak live checks passed: {live.checks} checks in {live.elapsed():.0f}s.', flush=True)


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    live.dump_logs()
    raise
