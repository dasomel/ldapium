#!/usr/bin/env python3
"""Machine WRITE v2b live drill (machine-write-scope-v2 T-015, #379; AC-002, AC-003, AC-004, AC-005, AC-005b, AC-006).

Real Keycloak tokens + real slapd + the normal UI image, fresh containers, a directory prepared exactly as the
operator guide says (M, W_data, W_lock and the write ACL fragments). Drills the four operations T-014 opens
(createGroup, patchGroup, deleteGroup, lockUser) and the one it must NOT open (unlockUser). It runs only on a tree that
contains BOTH the T-015 drill and the T-014 opening: before the opening these operations are 403 scope_denied. That is
intended; T-014's gate "T-015 green" is satisfied by running this on the final tree.

  A. start-up refusals: group create without the seed, a seed outside the reserved placeholder form (#394), unlock in a
     ceiling, lock without W_lock, lock without privileged groups
  B. createGroup: the created group's `member` is the placeholder seed and nothing else, the W_data entry's memberOf does
     not change, the human (cookie) path still seeds with the bind DN, the seed is untouchable (member add/remove, user
     patch/delete), closed body, cn rejection, scope / ceiling denials, duplicate
  C. group targets: allow-list, a created group is not writable until its DN is listed, ceiling root, case / OID / space
     spellings, privileged group (denied_protected, no bind), patchGroup description only (cn refused), delete + refint
  D. lockUser: marker value, W_lock is the binding identity, replay, group / protected / user-only targets, privileged
     member (direct) refused, the NESTED group case (accepted residual risk, recorded), fail-closed on a hidden
     or missing privileged group, 428 / 412 / 422
  E. AC-006 compartment boundary: W_lock and W_data direct writes; #394: W_lock is add-only (delete / replace of
     pwdAccountLockedTime refused, 50), W_data cannot write a USER description (50)
  F. AC-005b: the five unlock bypass attempts (403, zero binds, state unchanged), again across a real UI + slapd restart
  G. audit lines of the new operations and a sentinel scan of every container log

Run (local):  LDAPIUM_IMAGE=ldapium:x LDAPIUM_UI_IMAGE=ldapium-ui:x python3 scripts/test/test-machine-write-v2b-live.py
"""
import json
import pathlib
import re
import secrets
import subprocess
import sys
import time
import uuid
from urllib.parse import quote as urlquote

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'lib'))
from machine_live import (ADMIN_DN, AUDIENCE, BASE_DN, FIXTURES, MACHINE_DN, READER, Api, Keycloak, Live,  # noqa: E402
                          Slapd, ensure, jbody)

live = Live('ldapium-mwk-', deadline_seconds=1700)
REALM = 'write-v2b'
SYSTEM_DN = 'ou=system,' + BASE_DN
WDATA_DN = 'uid=machine-write-data,' + SYSTEM_DN
WLOCK_DN = 'uid=machine-write-lock,' + SYSTEM_DN
SEED_DN = 'uid=group-seed,' + SYSTEM_DN
PEOPLE = 'ou=people,' + BASE_DN
GROUPS = 'ou=groups,' + BASE_DN
G1 = 'cn=g01,' + GROUPS
G2 = 'cn=g02,' + GROUPS
GDEL = 'cn=gdel,' + GROUPS
ADMINS = 'cn=admins,' + GROUPS          # the privileged group
SUBADMINS = 'cn=subadmins,' + GROUPS    # a member of ADMINS (nested)
ADMINS2 = 'cn=admins2,' + GROUPS        # privileged in the fail-closed replicas
MARKER = '000001010000Z'
STALE = '"20260101000000.000000Z#000000#000#000000"'
OLD_WRITE_SCOPES = ['directory.users.create', 'directory.users.update', 'directory.users.delete',
                    'directory.groups.members.add', 'directory.groups.members.remove']
V2B_SCOPES = ['directory.groups.create', 'directory.groups.update', 'directory.groups.delete', 'directory.users.lock']
SENTINEL_DESC = 'sentinel-desc-' + secrets.token_hex(6)


def user_dn(uid):
  return f'uid={uid},{PEOPLE}'


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
  ldap.put_password('/tmp/.pw-wlock', wlock_pw)
  live.check(True, 'W_data/W_lock accounts created and the write ACL fragments applied after the M rules')

  # ---- directory fixtures ----------------------------------------------------------------------------------
  user_pw = {}
  ldif = f'dn: {SEED_DN}\nobjectClass: inetOrgPerson\nuid: group-seed\ncn: group-seed\nsn: seed\n\n'  # no userPassword: not bindable
  for uid in ('lk1', 'lk2', 'lk3', 'lk4', 'lk5', 'lk6', 'lk7', 'lk8', 'lk9', 'victim'):
    user_pw[uid] = live.secret('Lk-' + secrets.token_urlsafe(12))
    ldif += f'dn: {user_dn(uid)}\nobjectClass: inetOrgPerson\nuid: {uid}\ncn: {uid}\nsn: {uid}\nuserPassword: {user_pw[uid]}\n\n'
  ldif += (f'dn: {SUBADMINS}\nobjectClass: groupOfNames\ncn: subadmins\nmember: {user_dn("lk4")}\n\n'
           f'dn: {ADMINS}\nobjectClass: groupOfNames\ncn: admins\nmember: {user_dn("lk3")}\nmember: {SUBADMINS}\n\n'
           f'dn: {ADMINS2}\nobjectClass: groupOfNames\ncn: admins2\nmember: {user_dn("lk3")}\n\n'
           f'dn: {GDEL}\nobjectClass: groupOfNames\ncn: gdel\nmember: {user_dn("u02")}\n')
  r = ldap.admin_tool('ldapadd', [], ldif)
  ensure(r.returncode == 0, 'fixtures: ' + live.mask(r.stderr))

  def op_attr(dn, attr):
    out = ldap.admin_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', dn, '-s', 'base', attr]).stdout
    return [l.split(': ', 1)[1] for l in out.splitlines() if l.lower().startswith(attr.lower() + ': ')]

  def entry_exists(dn):
    return ldap.admin_tool('ldapsearch', ['-LLL', '-b', dn, '-s', 'base', 'dn']).returncode == 0

  def binds(dn):
    time.sleep(0.4)
    return ldap.binds(dn)

  def all_binds():
    time.sleep(0.4)
    return (ldap.binds(WDATA_DN), ldap.binds(WLOCK_DN), ldap.binds(MACHINE_DN))

  def try_bind(uid, password):
    res = live.run(['docker', 'exec', '-i', ldap.name, 'ldapwhoami', '-x', '-H', 'ldap://127.0.0.1', '-D', user_dn(uid), '-w', password])
    return res.returncode

  def obs(text):
    print('OBS ' + text, flush=True)

  # ---- Keycloak: one client per refusal reason --------------------------------------------------------------
  kcname = live.name_prefix + '-kc'
  kc = Keycloak(live, kcname, f'http://{kcname}:8080')
  kc.start()
  kc.create_realm(REALM)
  for scope in READER + OLD_WRITE_SCOPES + V2B_SCOPES + ['directory.users.unlock']:
    kc.create_scope(REALM, scope)
  full = READER + OLD_WRITE_SCOPES + V2B_SCOPES
  # name -> (scopes in the Keycloak token, scopes in the application ceiling). The unlock scope is in the TOKEN of the
  # writers (never in a ceiling: that is a start-up error), so the bypass attempts carry every scope there is.
  clients = {
    'svc-writer': (full + ['directory.users.unlock'], full),
    'svc-other': (full + ['directory.users.unlock'], full),
    'svc-old': (READER + OLD_WRITE_SCOPES, READER + OLD_WRITE_SCOPES),    # first-ship scopes only
    'svc-tokscope': (READER, full),                                       # ceiling has the v2b scopes, the TOKEN does not
  }
  client_secret = {}
  for name, (token_scopes, _) in clients.items():
    client_secret[name] = live.secret(name + '-' + secrets.token_hex(10))
    kc.create_client(REALM, name, client_secret[name], scopes=token_scopes)
  issued = []

  def token(name='svc-writer'):
    value = kc.sa_token(REALM, name, client_secret[name])
    issued.append(value)
    for part in [value] + value.split('.'):
      live.secret(part)
    return value

  session_secret = live.secret(secrets.token_hex(32))
  held = {'SESSION_SECRET': session_secret, 'MACHINE_LDAP_BIND_PASSWORD': ldap.machine_password,
          'MACHINE_WRITE_DATA_BIND_PASSWORD': wdata_pw, 'MACHINE_WRITE_LOCK_BIND_PASSWORD': wlock_pw}

  def env_for(groups=None, privileged=ADMINS, extra=None, drop=(), ceilings_over=None):
    ceilings = {c: s for c, (_, s) in clients.items()}
    ceilings.update(ceilings_over or {})
    subtrees = {c: f'{PEOPLE}|{GROUPS}' for c in clients}
    env = {'LDAP_BASE_DN': BASE_DN, 'LDAP_USER_CREATE_BASE': PEOPLE, 'LDAP_GROUP_CREATE_BASE': GROUPS, 'COOKIE_SECURE': 'false',
           'UI_TRUSTED_PROXIES': 'none', 'MACHINE_AUTH_ENABLED': 'true', 'MACHINE_OIDC_INSECURE_HTTP': 'true',
           'MACHINE_OIDC_ISSUER_URL': kc.issuer(REALM), 'MACHINE_OIDC_AUDIENCE': AUDIENCE, 'MACHINE_CLOCK_SKEW': '0s',
           'MACHINE_ALLOWED_CLIENTS': ';'.join(f'{c}={",".join(s)}' for c, s in ceilings.items()),
           'MACHINE_LDAP_BIND_DN': MACHINE_DN, 'MACHINE_LDAP_ROOT_DNS': ADMIN_DN,
           'MACHINE_AUTH_FAILURE_LIMIT': '1000', 'MACHINE_RATE_LIMIT_RPS': '10000', 'MACHINE_RATE_LIMIT_BURST': '10000',
           'UI_IDEMPOTENCY_ENABLED': 'true', 'MACHINE_WRITE_ENABLED': 'true',
           'MACHINE_WRITE_DATA_BIND_DN': WDATA_DN, 'MACHINE_WRITE_LOCK_ENABLED': 'true', 'MACHINE_WRITE_LOCK_BIND_DN': WLOCK_DN,
           'MACHINE_WRITE_SUBTREES': ';'.join(f'{c}={s}' for c, s in subtrees.items()),
           'MACHINE_WRITE_GROUPS': 'svc-writer=' + '|'.join(groups or [G1, GDEL]),
           'MACHINE_WRITE_GROUP_SEED_DN': SEED_DN,
           'MACHINE_WRITE_PRIVILEGED_GROUPS': privileged,
           'MACHINE_WRITE_RATE_LIMIT_RPS': '100', 'MACHINE_WRITE_RATE_LIMIT_BURST': '100'}
    env.update(extra or {})
    for k in drop:
      env.pop(k, None)
    return env

  def replica(name, **kw):
    return live.start_ui(f'{live.name_prefix}-{name}', f'ldap://{ldap.name}:389', env_for(**kw), held)

  def refuses_start(name, what, fragment, **kw):
    cname = f'{live.name_prefix}-{name}'
    live.start_ui(cname, f'ldap://{ldap.name}:389', env_for(**kw), held, wait=False)
    live.wait_until(lambda: live.run(['docker', 'inspect', '-f', '{{.State.Running}}', cname]).stdout.strip() == 'false', what, 30)
    out = live.run(['docker', 'logs', cname])
    text = out.stdout + out.stderr
    live.check(fragment in text, f'[A] {what} is a start-up error ("{fragment}")')

  def call(api, tok, method, path, body=None, key=None, etag=None, rid=None, headers=None, timeout=30):
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
    return api.call(method, path, h, body, timeout=timeout)

  def new_key():
    return 'v2b-' + uuid.uuid4().hex

  def rid_new(tag):
    return f'v2b-{tag}-{secrets.token_hex(3)}'

  def etag_of(api, tok, dn):
    status, hdrs, text = call(api, tok, 'GET', '/api/entry?dn=' + urlquote(dn))
    ensure(status == 200 and hdrs.get('ETag'), f'entry {dn}: {status} {text[:200]}')
    return hdrs['ETag']

  def create_group(api, tok, cn, key=None, rid=None, **fields):
    return call(api, tok, 'POST', '/api/groups', dict({'cn': cn}, **fields), key or new_key(), rid=rid)

  def patch_group(api, tok, dn, fields, etag, key=None, rid=None):
    return call(api, tok, 'PATCH', '/api/groups', dict(fields, dn=dn), key or new_key(), etag, rid=rid)

  def delete_group(api, tok, dn, etag, key=None, rid=None):
    return call(api, tok, 'DELETE', '/api/groups?dn=' + urlquote(dn), None, key or new_key(), etag, rid=rid)

  def lock(api, tok, dn, etag, key=None, rid=None):
    return call(api, tok, 'POST', '/api/users/lock', {'dn': dn}, key or new_key(), etag, rid=rid)

  def unlock(api, tok, dn, etag, key=None, rid=None):
    return call(api, tok, 'POST', '/api/users/unlock', {'dn': dn}, key or new_key(), etag, rid=rid)

  def audit(container, rid):
    out = []
    for line in live.audit_lines(f'{live.name_prefix}-{container}'):
      event = json.loads(line[line.index('{'):])
      if event.get('request_id') == rid:
        out.append(event)
    return out

  def scope_denied(res):
    return res[0] == 403 and jbody(res[2]).get('code') == 'scope_denied'

  # ======== A. start-up refusals ============================================================================
  refuses_start('nos', 'a directory.groups.create ceiling without MACHINE_WRITE_GROUP_SEED_DN', 'MACHINE_WRITE_GROUP_SEED_DN is required',
                drop=('MACHINE_WRITE_GROUP_SEED_DN',))
  refuses_start('unl', 'directory.users.unlock in a client ceiling', 'names a write scope that no operation uses yet',
                ceilings_over={'svc-writer': full + ['directory.users.unlock']})
  refuses_start('nolock', 'a lock ceiling without MACHINE_WRITE_LOCK_ENABLED', 'requires MACHINE_WRITE_LOCK_ENABLED=true',
                extra={'MACHINE_WRITE_LOCK_ENABLED': 'false'})
  refuses_start('nopriv', 'a lock ceiling without MACHINE_WRITE_PRIVILEGED_GROUPS', 'MACHINE_WRITE_PRIVILEGED_GROUPS', privileged='-')

  # Start-up validation is the first layer behind the two guards a drill cannot isolate at request time: a ceiling that contains the
  # seed, and a privileged group on the allow-list, never start. (The request-time guards behind them are pinned in unit tests
  # that inject such a config: TestGroupPipeline_SeedIsProtectedWithoutTheCeiling / _TargetRestrictions.)
  # #394 item 4 (D394-4): only a direct child of the W_data container is accepted. A real, bindable user (victim has a
  # userPassword) or any DN inside a write ceiling is refused at start-up, before the ceiling-overlap rule.
  refuses_start('seedin', 'a real bindable user inside a write ceiling as MACHINE_WRITE_GROUP_SEED_DN', 'reserved placeholder form',
                extra={'MACHINE_WRITE_GROUP_SEED_DN': user_dn('victim')})
  refuses_start('seedbase', 'a seed directly under the base (not in the W_data container)', 'reserved placeholder form',
                extra={'MACHINE_WRITE_GROUP_SEED_DN': 'uid=group-seed,' + BASE_DN})
  refuses_start('privlist', 'a privileged group on a client\'s MACHINE_WRITE_GROUPS', 'must not list a privileged group',
                groups=[G1, ADMINS])

  A = replica('a')
  tok = token()

  # ======== B. createGroup ==================================================================================
  m_before = op_attr(WDATA_DN, 'memberOf')
  seed_memberof_before = op_attr(SEED_DN, 'memberOf')
  wd0, wl0, mm0 = all_binds()
  rid = rid_new('cg')
  st, hdrs, text = create_group(A, tok, 'mw-new1', rid=rid, description=SENTINEL_DESC)
  NEW1 = 'cn=mw-new1,' + GROUPS
  live.check(st == 201 and entry_exists(NEW1), f'[B] createGroup -> 201 and the group exists ({st} {text[:140]})')
  live.check([m.lower() for m in op_attr(NEW1, 'member')] == [SEED_DN.lower()],
             f'[B] AC-002 the created group\'s member is exactly the placeholder seed: {op_attr(NEW1, "member")}')
  live.check(WDATA_DN.lower() not in [m.lower() for m in op_attr(NEW1, 'member')] and op_attr(WDATA_DN, 'memberOf') == m_before,
             f'[B] AC-002 W_data is not a member and its memberOf is unchanged ({m_before})')
  obs(f'seed entry memberOf before={seed_memberof_before} after={op_attr(SEED_DN, "memberOf")}')
  live.check(op_attr(NEW1, 'description') == [SENTINEL_DESC] and 'groupOfNames' in op_attr(NEW1, 'objectClass'),
             '[B] the group is a groupOfNames with the requested description')
  wd1, wl1, _ = all_binds()
  live.check(wd1 > wd0 and wl1 == wl0, '[B] createGroup bound as W_data only (slapd accesslog)')
  # human (cookie) path baseline: still seeds with the bind DN (AC-002 last sentence)
  status, h, body = A.call('POST', '/api/login', {'Origin': A.base_url, 'Content-Type': 'application/json'},
                           {'identity': ADMIN_DN, 'password': ldap.admin_password})
  ensure(status == 200, f'admin login: {status}')
  cookie = {'Cookie': h.get('Set-Cookie', '').split(';')[0], 'Origin': A.base_url, 'Content-Type': 'application/json',
            'Idempotency-Key': new_key()}
  status, _, body = A.call('POST', '/api/groups', cookie, {'cn': 'human-grp'})
  HUMAN = 'cn=human-grp,' + GROUPS
  live.check(status == 201 and [m.lower() for m in op_attr(HUMAN, 'member')] == [ADMIN_DN.lower()],
             f'[B] AC-002 the human (cookie) createGroup still seeds with the bind DN, unchanged ({status} {op_attr(HUMAN, "member")})')
  ldap.admin_tool('ldapdelete', [HUMAN])
  # the seed is untouchable by the machine
  wd0, wl0, mm0 = all_binds()
  neg = [
    ('addGroupMember with the seed as member', lambda: call(A, tok, 'POST', '/api/groups/members', {'groupDn': G1, 'memberDn': SEED_DN}, new_key(), STALE)),
    ('removeGroupMember of the seed', lambda: call(A, tok, 'DELETE', f'/api/groups/members?groupDn={urlquote(G1)}&memberDn={urlquote(SEED_DN)}', None, new_key(), STALE)),
    ('patchUser on the seed', lambda: call(A, tok, 'PATCH', '/api/users', {'dn': SEED_DN, 'mail': 'a@b.c'}, new_key(), STALE)),
    ('deleteUser on the seed', lambda: call(A, tok, 'DELETE', f'/api/users?dn={urlquote(SEED_DN)}', None, new_key(), STALE)),
    ('lockUser on the seed', lambda: lock(A, tok, SEED_DN, STALE)),
    ('createGroup with a comma in cn', lambda: create_group(A, tok, 'a,ou=x')),
    ('createGroup with a member field', lambda: create_group(A, tok, 'mw-n2', member=user_dn('lk1'))),
    ('createGroup with an objectClass field', lambda: create_group(A, tok, 'mw-n3', objectClass='posixGroup')),
    ('createGroup with an empty cn', lambda: create_group(A, tok, '')),
    ('createGroup by a client without the v2b scopes', lambda: create_group(A, token('svc-old'), 'mw-n4')),
    ('createGroup with a token that lacks the scope (ceiling has it)', lambda: create_group(A, token('svc-tokscope'), 'mw-n5')),
  ]
  want = {'addGroupMember with the seed as member': 403, 'removeGroupMember of the seed': 403, 'patchUser on the seed': 403,
          'deleteUser on the seed': 403, 'lockUser on the seed': 403, 'createGroup with a comma in cn': 400,
          'createGroup with a member field': 400, 'createGroup with an objectClass field': 400, 'createGroup with an empty cn': 400}
  for name, run in neg:
    res = run()
    exp = want.get(name, 403)
    live.check(res[0] == exp, f'[B] "{name}" -> {exp} (got {res[0]} {res[2][:100]})')
  wd1, wl1, mm1 = all_binds()
  live.check((wd1, wl1) == (wd0, wl0), '[B] none of the refused createGroup / seed requests bound as W_data or W_lock')
  for cn in ('mw-n2', 'mw-n3', 'mw-n4', 'mw-n5', 'a,ou=x'):
    ensure(not entry_exists(f'cn={cn},{GROUPS}'), f'{cn} must not exist')
  st, _, text = create_group(A, tok, 'mw-new1')
  live.check(st == 409 and len(op_attr(NEW1, 'member')) == 1, f'[B] createGroup of an existing cn -> 409, the group is unchanged ({st})')
  # replay: same key, same body -> the stored 201, one group
  key = new_key()
  st1, h1, _ = create_group(A, tok, 'mw-rp1', key=key)
  wd0, wl0, _ = all_binds()
  st2, h2, _ = create_group(A, tok, 'mw-rp1', key=key)
  st3, _, t3 = create_group(A, tok, 'mw-rp2', key=key)
  live.check((st1, st2) == (201, 201) and h2.get('Idempotent-Replayed') == 'true' and st3 == 422 and jbody(t3).get('code') == 'idempotency_key_reused'
             and all_binds()[0] == wd0 and not entry_exists(f'cn=mw-rp2,{GROUPS}'),
             f'[B] createGroup replay: executed once ({st1}), retry is the stored {st2} with Idempotent-Replayed, other body 422 ({st3}), no extra bind')
  st, _, _ = call(A, tok, 'POST', '/api/groups', {'cn': 'mw-nokey'})
  live.check(st == 428 and not entry_exists(f'cn=mw-nokey,{GROUPS}'), f'[B] createGroup without Idempotency-Key -> 428 ({st})')
  ldap.admin_tool('ldapdelete', [f'cn=mw-rp1,{GROUPS}'])

  # ======== C. group targets: allow-list, privileged group, description only ================================
  wd0, wl0, mm0 = all_binds()
  g1_tag = etag_of(A, tok, G1)
  new1_tag = etag_of(A, tok, NEW1)
  untouched = {dn: etag_of(A, tok, dn) for dn in (ADMINS, G2, GROUPS)}
  mm0 = binds(MACHINE_DN)  # the ETag reads above are M binds
  rid_priv1, rid_priv2 = rid_new('priv1'), rid_new('priv2')
  neg = [
    ('AC-003 patchGroup on the just-created group (not on the allow-list)', lambda: patch_group(A, tok, NEW1, {'description': 'x'}, new1_tag), 403),
    ('AC-003 deleteGroup on the just-created group', lambda: delete_group(A, tok, NEW1, new1_tag), 403),
    ('AC-003 addGroupMember on the just-created group', lambda: call(A, tok, 'POST', '/api/groups/members', {'groupDn': NEW1, 'memberDn': user_dn('lk1')}, new_key(), new1_tag), 403),
    ('patchGroup on a group that is not on the list (g02)', lambda: patch_group(A, tok, G2, {'description': 'x'}, STALE), 403),
    ('deleteGroup on a group that is not on the list (g02)', lambda: delete_group(A, tok, G2, STALE), 403),
    ('patchGroup on the ceiling root', lambda: patch_group(A, tok, GROUPS, {'description': 'x'}, STALE), 403),
    ('deleteGroup on the ceiling root, upper-case and spaced', lambda: delete_group(A, tok, 'OU=Groups , ' + BASE_DN.upper(), STALE), 403),
    ('patchGroup on a listed group written with an OID type', lambda: patch_group(A, tok, '2.5.4.3=g01,' + GROUPS, {'description': 'x'}, g1_tag), 403),
    ('patchGroup on a user DN', lambda: patch_group(A, tok, user_dn('victim'), {'description': 'x'}, STALE), 403),
    ('deleteGroup on a protected DN (W_data)', lambda: delete_group(A, tok, WDATA_DN, STALE), 403),
    ('deleteGroup on the placeholder seed', lambda: delete_group(A, tok, SEED_DN, STALE), 403),
    ('patchGroup on the PRIVILEGED group', lambda: patch_group(A, tok, ADMINS, {'description': 'x'}, STALE, rid=rid_priv1), 403),
    ('deleteGroup on the PRIVILEGED group', lambda: delete_group(A, tok, ADMINS, STALE, rid=rid_priv2), 403),
    ('patchGroup with cn (RDN rename, D379-5)', lambda: patch_group(A, tok, G1, {'cn': 'renamed'}, g1_tag), 400),
    ('patchGroup with member', lambda: patch_group(A, tok, G1, {'member': user_dn('lk1')}, g1_tag), 400),
    ('patchGroup with an unknown field', lambda: patch_group(A, tok, G1, {'owner': 'x'}, g1_tag), 400),
    ('patchGroup without any If-Match', lambda: patch_group(A, tok, G1, {'description': 'x'}, None), 428),
    ('deleteGroup without If-Match', lambda: delete_group(A, tok, G1, None), 428),
    ('patchGroup by a client without the v2b scopes', lambda: patch_group(A, token('svc-old'), G1, {'description': 'x'}, g1_tag), 403),
  ]
  for name, run, exp in neg:
    res = run()
    live.check(res[0] == exp, f'[C] "{name}" -> {exp} (got {res[0]} {res[2][:100]})')
  wd1, wl1, mm1 = all_binds()
  live.check((wd1, wl1) == (wd0, wl0), '[C] none of the refused group requests bound as W_data or W_lock')
  live.check(all(etag_of(A, tok, dn) == tag_ for dn, tag_ in untouched.items()) and op_attr(ADMINS, 'description') == []
             and op_attr(G1, 'cn') == ['g01'] and etag_of(A, tok, G1) == g1_tag and etag_of(A, tok, NEW1) == new1_tag,
             '[C] the privileged group, g02, the ceiling root, g01 and the created group are untouched (same ETags before and after)')
  # (c) the target-type guard ALONE: a USER DN on the allow-list (inside the ceiling, not protected) is refused by the M
  # pre-read class assertion only; the message differs from the protected-DN / allow-list refusals ("target is not permitted").
  TY = replica('typ', groups=[G1, GDEL, user_dn('victim')])
  tokty = token()
  wd0, wl0, _ = all_binds()
  for label, run in (('patchGroup', lambda: patch_group(TY, tokty, user_dn('victim'), {'description': 'x'}, etag_of(TY, tokty, user_dn('victim')))),
                     ('deleteGroup', lambda: delete_group(TY, tokty, user_dn('victim'), etag_of(TY, tokty, user_dn('victim'))))):
    res = run()
    live.check(res[0] == 403 and 'target is not permitted for machine writes' in res[2] and entry_exists(user_dn('victim')) and op_attr(user_dn('victim'), 'description') == [],
               f'[C] target-type guard alone: {label} on an allow-listed USER DN -> 403 "target is not permitted", user untouched ({res[0]} {res[2][:80]})')
  live.check(all_binds()[:2] == (wd0, wl0), '[C] the type-mismatch refusals bound neither W_data nor W_lock (the pre-read refuses before any W bind)')
  pa = audit('a', rid_priv1) + audit('a', rid_priv2)
  live.check(len(pa) == 2 and all(e['outcome'] == 'denied_protected' and e['operation'] in ('patchGroup', 'deleteGroup') for e in pa),
             '[C] the privileged-group refusals are audited as denied_protected: ' + json.dumps([(e.get('operation'), e.get('outcome')) for e in pa]))
  # description set / cleared on a listed group (AC-004)
  rid_pg = rid_new('pg')
  st, _, text = patch_group(A, tok, G1, {'description': 'managed by automation'}, g1_tag, rid=rid_pg)
  live.check(st in (200, 204) and op_attr(G1, 'description') == ['managed by automation'] and op_attr(G1, 'cn') == ['g01'],
             f'[C] AC-004 patchGroup sets the description on a listed group ({st}), cn unchanged')
  st, _, text = patch_group(A, tok, G1, {'description': None}, etag_of(A, tok, G1))
  live.check(st in (200, 204) and op_attr(G1, 'description') == [], f'[C] AC-004 description null removes it ({st})')
  # 412: the group changed between read and write
  stale = etag_of(A, tok, G1)
  ensure(ldap.admin_tool('ldapmodify', [], f'dn: {G1}\nchangetype: modify\nreplace: description\ndescription: concurrent\n').returncode == 0)
  st, _, text = patch_group(A, tok, G1, {'description': 'late'}, stale)
  live.check(st == 412 and jbody(text).get('code') == 'revision_conflict' and op_attr(G1, 'description') == ['concurrent'],
             f'[C] stale If-Match on patchGroup -> 412 revision_conflict, nothing written ({st})')
  # deleteGroup of a listed group: refint cleans the member's memberOf (D379-6, intended and irreversible)
  u02_before = op_attr(user_dn('u02'), 'memberOf')
  rid_dg = rid_new('dg')
  st, _, text = delete_group(A, tok, GDEL, etag_of(A, tok, GDEL), rid=rid_dg)
  u02_after = op_attr(user_dn('u02'), 'memberOf')
  live.check(st in (200, 204) and not entry_exists(GDEL) and GDEL.lower() not in [m.lower() for m in u02_after] and GDEL.lower() in [m.lower() for m in u02_before],
             f'[C] AC-003 deleteGroup on a listed group -> {st}, gone, and refint cleaned the member\'s memberOf (D379-6): {u02_before} -> {u02_after}')
  # the operator lists the created group (DN added, redeploy): now patch and delete work (D379-4)
  B = replica('b', groups=[G1, GDEL, NEW1])
  tokb = token()
  st, _, text = patch_group(B, tokb, NEW1, {'description': 'listed now'}, etag_of(B, tokb, NEW1))
  live.check(st in (200, 204) and op_attr(NEW1, 'description') == ['listed now'], f'[C] AC-003 after the operator lists it, patchGroup on the created group works ({st})')
  st, _, text = delete_group(B, tokb, NEW1, etag_of(B, tokb, NEW1))
  live.check(st in (200, 204) and not entry_exists(NEW1), f'[C] and deleteGroup works too ({st}); the seed entry survives: {entry_exists(SEED_DN)}')
  live.check(entry_exists(SEED_DN), '[C] the placeholder seed entry still exists after its groups are deleted')

  # ======== D. lockUser =====================================================================================
  lk1 = user_dn('lk1')
  wd0, wl0, mm0 = all_binds()
  tag = etag_of(A, tok, lk1)
  rid_lock = rid_new('lock')
  wl_before = binds(WLOCK_DN)
  wd_before = binds(WDATA_DN)
  st, _, text = lock(A, tok, lk1, tag, rid=rid_lock)
  live.check(st in (200, 204) and op_attr(lk1, 'pwdAccountLockedTime') == [MARKER], f'[D] AC-005 lockUser -> {st}, pwdAccountLockedTime = {op_attr(lk1, "pwdAccountLockedTime")}')
  live.check(binds(WLOCK_DN) > wl_before and binds(WDATA_DN) == wd_before, '[D] the lock bound as W_lock and not as W_data')
  live.check(try_bind('lk1', user_pw['lk1']) != 0, '[D] the locked account cannot bind with its correct password (ldapwhoami fails)')
  # #394: the machine lock is an LDAP Add; re-locking (new key, so no replay) hits attributeOrValueExists (20) = success.
  wl_before = binds(WLOCK_DN)
  st, h, text = lock(A, tok, lk1, etag_of(A, tok, lk1))
  live.check(st in (200, 204) and h.get('Idempotent-Replayed') != 'true' and binds(WLOCK_DN) > wl_before and op_attr(lk1, 'pwdAccountLockedTime') == [MARKER],
             f'[D] #394 re-locking an already locked account executes as W_lock and succeeds idempotently ({st}, value unchanged)')
  key = new_key()
  rid1, rid2 = rid_new('l1'), rid_new('l2')
  st1, h1, _ = lock(A, tok, user_dn('lk2'), etag_of(A, tok, user_dn('lk2')), key=key, rid=rid1)
  wl_mid = binds(WLOCK_DN)
  st2, h2, _ = lock(A, tok, user_dn('lk2'), etag_of(A, tok, user_dn('lk2')), key=key, rid=rid2)
  live.check(st1 in (200, 204) and st2 == st1 and h2.get('Idempotent-Replayed') == 'true' and binds(WLOCK_DN) == wl_mid,
             f'[D] AC-005 the same key replays the stored lock ({st1}/{st2}) without another W_lock bind')
  other = token('svc-other')
  st, h, _ = lock(A, other, user_dn('lk2'), etag_of(A, other, user_dn('lk2')), key=key)
  live.check(st in (200, 204) and h.get('Idempotent-Replayed') != 'true', f'[D] another client with the same key is independent: executed, not replayed ({st})')
  res = lock(A, tok, G2, etag_of(A, tok, G2))
  live.check(res[0] == 403 and 'target is not permitted for machine writes' in res[2],
             f'[D] lockUser on a group DN is refused by the target-type guard (its own message, not the protected-DN one): {res[2][:90]}')
  # refusals: no bind of any W identity
  wd0, wl0, mm0 = all_binds()
  lk5 = user_dn('lk5')
  lk5_tag = etag_of(A, tok, lk5)
  lk3 = user_dn('lk3')
  lk3_tag = etag_of(A, tok, lk3)
  g02_tag = etag_of(A, tok, G2)
  wd0, wl0, _ = all_binds()
  rid_priv = rid_new('lkpriv')
  neg = [
    ('lockUser on a group DN inside the ceiling (target-type assertion only)', lambda: lock(A, tok, G2, g02_tag), 403),
    ('lockUser on W_data', lambda: lock(A, tok, WDATA_DN, STALE), 403),
    ('lockUser on W_lock', lambda: lock(A, tok, WLOCK_DN, STALE), 403),
    ('lockUser on M', lambda: lock(A, tok, MACHINE_DN, STALE), 403),
    ('lockUser on the administrator', lambda: lock(A, tok, ADMIN_DN, STALE), 403),
    ('lockUser on a DN outside the ceiling (ou=people root)', lambda: lock(A, tok, PEOPLE, STALE), 403),
    ('AC-005 lockUser on a DIRECT member of the privileged group', lambda: lock(A, tok, lk3, lk3_tag, rid=rid_priv), 403),
    ('lockUser without If-Match', lambda: lock(A, tok, lk5, None), 428),
    ('lockUser without Idempotency-Key', lambda: call(A, tok, 'POST', '/api/users/lock', {'dn': lk5}, None, lk5_tag), 428),
    ('lockUser with a weak If-Match', lambda: lock(A, tok, lk5, 'W/' + lk5_tag), 400),
    ('lockUser with an extra body field', lambda: call(A, tok, 'POST', '/api/users/lock', {'dn': lk5, 'reason': 'x'}, new_key(), lk5_tag), 400),
    ('lockUser by a client without the lock scope', lambda: lock(A, token('svc-old'), lk5, lk5_tag), 403),
    ('lockUser with a token that lacks the scope (ceiling has it)', lambda: lock(A, token('svc-tokscope'), lk5, lk5_tag), 403),
  ]
  for name, run, exp in neg:
    res = run()
    live.check(res[0] == exp, f'[D] "{name}" -> {exp} (got {res[0]} {res[2][:100]})')
  live.check(all_binds()[:2] == (wd0, wl0), '[D] none of the refused lock requests bound as W_data or W_lock')
  live.check(op_attr(lk3, 'pwdAccountLockedTime') == [] and op_attr(lk5, 'pwdAccountLockedTime') == [] and try_bind('lk3', user_pw['lk3']) == 0,
             '[D] the privileged member stays unlocked and can still bind')
  pl = audit('a', rid_priv)
  live.check(len(pl) == 1 and pl[0]['outcome'] == 'denied_protected' and pl[0]['status'] == 403, '[D] the privileged-member refusal is audited as denied_protected: ' + json.dumps(pl)[:200])
  # 412 on lockUser
  stale = etag_of(A, tok, lk5)
  ensure(ldap.admin_tool('ldapmodify', [], f'dn: {lk5}\nchangetype: modify\nreplace: description\ndescription: concurrent\n').returncode == 0)
  wd0, wl0, _ = all_binds()
  st, _, text = lock(A, tok, lk5, stale)
  live.check(st == 412 and jbody(text).get('code') == 'revision_conflict' and op_attr(lk5, 'pwdAccountLockedTime') == [],
             f'[D] stale If-Match on lockUser -> 412 revision_conflict, not locked ({st})')
  # NESTED group: lk4 is a member of subadmins, which is a member of the privileged group (REQ-007 accepted residual risk)
  lk4 = user_dn('lk4')
  obs(f'nested: memberOf of lk4 = {op_attr(lk4, "memberOf")}; member of {ADMINS} = {op_attr(ADMINS, "member")}')
  st, _, text = lock(A, tok, lk4, etag_of(A, tok, lk4))
  nested_locked = op_attr(lk4, 'pwdAccountLockedTime') == [MARKER]
  obs(f'nested-group lockUser -> {st}, locked={nested_locked}')
  live.check(st in (200, 204) and nested_locked,
             f'[D] RESIDUAL RISK (REQ-007, accepted 2026-10-12): a user in a group NESTED inside the privileged group is NOT recognised as privileged and IS locked ({st}); only direct members are refused')
  # lockUser over a ppolicy timestamp lock (#394): W_lock may only ADD, the attribute is single-valued, so slapd answers 19
  # and the API 409; the account stays locked with ppolicy's own timestamp (never looser; turning it into the marker is human)
  for i in range(5):
    try_bind('lk8', 'wrong-password-' + str(i))
  ts = op_attr(user_dn('lk8'), 'pwdAccountLockedTime')
  live.check(len(ts) == 1 and ts[0] != MARKER, f'[D] five wrong binds made ppolicy lock lk8 with a timestamp: {ts}')
  st, _, text = lock(A, tok, user_dn('lk8'), etag_of(A, tok, user_dn('lk8')))
  live.check(st == 409 and jbody(text).get('code') == 'conflict' and op_attr(user_dn('lk8'), 'pwdAccountLockedTime') == ts,
             f'[D] #394 lockUser over a ppolicy timestamp lock -> {st} {jbody(text).get("code")}, the timestamp lock is kept: {ts} -> {op_attr(user_dn("lk8"), "pwdAccountLockedTime")}')

  # fail closed on a hidden / missing privileged group (D379-17)
  hide = (f'dn: {main_db}\nchangetype: modify\nadd: olcAccess\n'
          f'olcAccess: {{0}}to dn.exact="{ADMINS2}" attrs=member\n  by dn.exact="{MACHINE_DN}" none\n  by * break\n')
  r = ldap.config_tool('ldapmodify', [], hide)
  ensure(r.returncode == 0, 'hide ACL: ' + live.mask(r.stderr))
  rows = ldap.tool('ldapsearch', ['-LLL', '-b', ADMINS2, '-s', 'base', 'member'], MACHINE_DN, '/tmp/.pw-machine').stdout
  live.check('member:' not in rows, '[D] precondition: M no longer sees the member attribute of the privileged group admins2 (ACL)')
  H = replica('hid', privileged=ADMINS2)
  tokh = token()
  wd0, wl0, _ = all_binds()
  lk9 = user_dn('lk9')
  res = lock(H, tokh, lk9, etag_of(H, tokh, lk9))
  live.check(res[0] == 403 and op_attr(lk9, 'pwdAccountLockedTime') == [] and all_binds()[:2] == (wd0, wl0),
             f'[D] D379-17 FAIL CLOSED: the privileged group\'s member list is hidden from M -> a non-member target is refused, no bind ({res[0]} {res[2][:100]})')
  G = replica('ghost', privileged='cn=ghost-priv,' + GROUPS)
  tokg = token()
  res = lock(G, tokg, lk9, etag_of(G, tokg, lk9))
  live.check(res[0] in (403, 503) and op_attr(lk9, 'pwdAccountLockedTime') == [] and all_binds()[:2] == (wd0, wl0),
             f'[D] D379-17 FAIL CLOSED: a privileged group that does not exist -> refused ({res[0]} {res[2][:100]}), no bind')
  obs(f'missing privileged group -> {res[0]}')
  ldap.config_tool('ldapmodify', [], f'dn: {main_db}\nchangetype: modify\ndelete: olcAccess\nolcAccess: {{0}}\n')

  # ======== E. AC-006 compartment boundary (direct LDAP) ====================================================
  def as_wlock(ldif, tool='ldapmodify'):
    return ldap.tool(tool, [], WLOCK_DN, '/tmp/.pw-wlock', input_data=ldif)

  def as_wdata(ldif, tool='ldapmodify'):
    return ldap.tool(tool, [], WDATA_DN, '/tmp/.pw-wdata', input_data=ldif)

  victim = user_dn('victim')
  for label, ldif, tool in (
      ('mail (any other attribute)', f'dn: {victim}\nchangetype: modify\nreplace: mail\nmail: x@example.org\n', 'ldapmodify'),
      ('userPassword', f'dn: {victim}\nchangetype: modify\nreplace: userPassword\nuserPassword: Direct-Attempt-2\n', 'ldapmodify'),
      ('objectClass', f'dn: {victim}\nchangetype: modify\nadd: objectClass\nobjectClass: posixAccount\n', 'ldapmodify'),
      ('entry Add', f'dn: uid=w-lock-add,{PEOPLE}\nobjectClass: inetOrgPerson\nuid: w-lock-add\ncn: x\nsn: x\n', 'ldapadd'),
      ('group member', f'dn: {G1}\nchangetype: modify\nadd: member\nmember: {victim}\n', 'ldapmodify'),
      ('group description', f'dn: {G1}\nchangetype: modify\nreplace: description\ndescription: x\n', 'ldapmodify')):
    r = as_wlock(ldif, tool)
    live.check(r.returncode != 0 and 'Insufficient access' in r.stderr, f'[E] AC-006 W_lock cannot write {label} directly (insufficientAccessRights)')
  r = ldap.tool('ldapdelete', [victim], WLOCK_DN, '/tmp/.pw-wlock')
  live.check(r.returncode != 0 and entry_exists(victim), '[E] AC-006 W_lock cannot Delete an entry')
  r = as_wlock(f'dn: {victim}\nchangetype: modify\nadd: pwdAccountLockedTime\npwdAccountLockedTime: {MARKER}\n')
  live.check(r.returncode == 0 and op_attr(victim, 'pwdAccountLockedTime') == [MARKER], '[E] W_lock adds pwdAccountLockedTime (its one job)')
  # #394 item 1: add-only. slapd checks delete access for Delete AND Replace, so a leaked W_lock credential cannot unlock.
  for label, ldif in (('Modify-delete of the attribute', f'dn: {victim}\nchangetype: modify\ndelete: pwdAccountLockedTime\n'),
                      ('Modify-delete of the value', f'dn: {victim}\nchangetype: modify\ndelete: pwdAccountLockedTime\npwdAccountLockedTime: {MARKER}\n'),
                      ('Replace with nothing', f'dn: {victim}\nchangetype: modify\nreplace: pwdAccountLockedTime\n'),
                      ('Replace with another value', f'dn: {victim}\nchangetype: modify\nreplace: pwdAccountLockedTime\npwdAccountLockedTime: 20260101000000Z\n')):
    r = as_wlock(ldif)
    live.check(r.returncode == 50 and op_attr(victim, 'pwdAccountLockedTime') == [MARKER],
               f'[E] #394 W_lock {label} of pwdAccountLockedTime is refused (rc {r.returncode}, 50 expected) and the lock stays')
  r = as_wlock(f'dn: {victim}\nchangetype: modify\nadd: pwdAccountLockedTime\npwdAccountLockedTime: {MARKER}\n')
  live.check(r.returncode == 20, f'[E] #394 a second W_lock Add of the marker answers attributeOrValueExists (rc {r.returncode}, 20 expected)')
  ldap.admin_tool('ldapmodify', [], f'dn: {victim}\nchangetype: modify\ndelete: pwdAccountLockedTime\n')
  r = as_wlock(f'dn: {lk3}\nchangetype: modify\nadd: pwdAccountLockedTime\npwdAccountLockedTime: {MARKER}\n')
  live.check(r.returncode == 0 and op_attr(lk3, 'pwdAccountLockedTime') == [MARKER],
             '[E] F-3 / E-07 PINNED: the shipped write-lock.ldif has no privileged-group filter, so W_lock CAN lock a privileged member directly; the application check in lockUser is the only defence (if this ever turns into a refusal, update CHANGE.md Revision 3)')
  ldap.admin_tool('ldapmodify', [], f'dn: {lk3}\nchangetype: modify\ndelete: pwdAccountLockedTime\n')
  r = as_wdata(f'dn: {victim}\nchangetype: modify\nreplace: pwdAccountLockedTime\npwdAccountLockedTime: {MARKER}\n')
  live.check(r.returncode != 0 and op_attr(victim, 'pwdAccountLockedTime') == [], '[E] AC-006 W_data cannot write pwdAccountLockedTime')
  r = as_wdata(f'dn: {G1}\nchangetype: modify\nreplace: description\ndescription: by-wdata\n')
  live.check(r.returncode == 0 and op_attr(G1, 'description') == ['by-wdata'], '[E] W_data writes a group description (T-012)')
  # #394 item 3: the description rule has filter=(objectClass=groupOfNames); a user's description is out of W_data's reach.
  for label, ldif in (('replace', f'dn: {victim}\nchangetype: modify\nreplace: description\ndescription: by-wdata\n'),
                      ('add', f'dn: {victim}\nchangetype: modify\nadd: description\ndescription: by-wdata\n')):
    r = as_wdata(ldif)
    live.check(r.returncode == 50 and op_attr(victim, 'description') == [], f'[E] #394 W_data {label} of a USER description is refused (rc {r.returncode}, 50 expected)')
  r = as_wdata(f'dn: {G1}\nchangetype: modify\nreplace: cn\ncn: g01-renamed\n')
  obs(f'E-05 W_data replace cn (RDN) on a group -> rc={r.returncode} {live.mask(r.stderr).strip()[:90]}; cn now {op_attr(G1, "cn")}')
  live.check(op_attr(G1, 'cn') == ['g01'], '[E] a direct cn replace did not rename the group')
  r = as_wdata(f'dn: {G1}\nchangetype: modify\nreplace: userPassword\nuserPassword: x\n')
  live.check(r.returncode != 0, '[E] W_data cannot write userPassword')

  # ======== F. AC-005b unlock bypass ========================================================================
  # targets: (a) real ppolicy lock (timestamp) by brute force, (b) duration-0 policy lock, (c) lockUser lock, (e) other client
  policy = f'cn=lockforever,ou=policies,{BASE_DN}'
  r = ldap.admin_tool('ldapadd', [], f'dn: {policy}\nobjectClass: top\nobjectClass: device\nobjectClass: pwdPolicy\ncn: lockforever\n'
                                      'pwdAttribute: userPassword\npwdLockout: TRUE\npwdMaxFailure: 3\npwdLockoutDuration: 0\npwdFailureCountInterval: 0\n')
  ensure(r.returncode == 0, 'policy: ' + live.mask(r.stderr))
  r = ldap.admin_tool('ldapmodify', [], f'dn: {user_dn("lk7")}\nchangetype: modify\nadd: pwdPolicySubentry\npwdPolicySubentry: {policy}\n')
  obs(f'pwdPolicySubentry on lk7 -> rc={r.returncode} {live.mask(r.stderr).strip()[:100]}')
  for i in range(3):
    try_bind('lk7', 'wrong-password-' + str(i))
  for i in range(5):
    try_bind('lk6', 'wrong-password-' + str(i))
  pol_attrs = ldap.admin_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', policy, '-s', 'base', 'pwdLockoutDuration', 'pwdMaxFailure']).stdout
  live.check('pwdLockoutDuration: 0' in pol_attrs and 'pwdMaxFailure: 3' in pol_attrs and op_attr(user_dn('lk7'), 'pwdPolicySubentry') == [policy],
             f'[F] the duration-0 policy exists and is assigned to lk7 (pwdPolicySubentry {op_attr(user_dn("lk7"), "pwdPolicySubentry")}); default policy would need 5 failures, this one locks after 3')
  a_val, b_val, c_val = op_attr(user_dn('lk6'), 'pwdAccountLockedTime'), op_attr(user_dn('lk7'), 'pwdAccountLockedTime'), op_attr(lk1, 'pwdAccountLockedTime')
  obs(f'lock values: (a) ppolicy timestamp lock lk6={a_val}; (b) duration-0 policy lock lk7={b_val}; (c) machine lockUser lk1={c_val}')
  live.check(len(a_val) == 1 and a_val[0] != MARKER, f'[F] (a) real ppolicy brute-force lock holds a timestamp: {a_val}')
  # CHANGE.md P22(b) assumed this lock has the SAME value as the machine marker. On the shipped build it does not: ppolicy
  # stores the lock time even with pwdLockoutDuration=0 (the lock simply never expires). Recorded, not assumed (EVIDENCE.md).
  live.check(len(b_val) == 1 and re.fullmatch(r'\d{14}Z', b_val[0]) and try_bind('lk7', user_pw['lk7']) != 0 and op_attr(user_dn('lk7'), 'pwdFailureTime') != [],
             f'[F] (b) a pwdLockoutDuration=0 policy lock is a permanent lock: value {b_val} (marker form: {b_val == [MARKER]}), the correct password cannot bind')
  live.check(c_val == [MARKER], f'[F] (c) the machine lockUser marker is {c_val}')

  def attempt_unlock(label, api, client, dn):
    tk = token(client)
    tag_ = etag_of(api, tk, dn)
    before = (op_attr(dn, 'pwdAccountLockedTime'), all_binds())
    rid_ = rid_new('unlock')
    res = unlock(api, tk, dn, tag_, rid=rid_)
    after = (op_attr(dn, 'pwdAccountLockedTime'), all_binds())
    ok = scope_denied(res) and before[0] == after[0] and before[1] == after[1] and before[0] != []
    live.check(ok, f'[F] AC-005b {label}: POST /api/users/unlock -> {res[0]} {jbody(res[2]).get("code")}, bind counts W_data/W_lock/M {before[1]} -> {after[1]}, pwdAccountLockedTime {before[0]} -> {after[0]}')

  attempt_unlock('(a) ppolicy timestamp lock (lk6), same client', A, 'svc-writer', user_dn('lk6'))
  attempt_unlock('(b) duration-0 policy lock (lk7), same client', A, 'svc-writer', user_dn('lk7'))
  attempt_unlock('(c) right after the same client\'s lockUser (lk1)', A, 'svc-writer', lk1)
  attempt_unlock('(e) a DIFFERENT client on the machine-locked lk1', A, 'svc-other', lk1)
  # the unlock route is refused before the scope gate does anything for lock-only variants too
  res = call(A, tok, 'PUT', '/api/users', {'dn': lk1, 'cn': 'x', 'sn': 'y'}, new_key(), etag_of(A, tok, lk1))
  live.check(scope_denied(res), f'[F] PUT /api/users (the other way to touch a user) is still 403 scope_denied ({res[0]})')

  # (d) the same after a REAL restart of slapd and the UI: the locked state persists in the directory, the unlock stays refused
  ensure(live.run(['docker', 'restart', '-t', '5', ldap.name]).returncode == 0, 'slapd restart')

  def slapd_ready():
    return ldap.admin_tool('ldapsearch', ['-b', BASE_DN, '-s', 'base']).returncode == 0
  live.wait_until(slapd_ready, 'slapd after the restart', 90)
  ensure(live.run(['docker', 'restart', '-t', '5', f'{live.name_prefix}-a']).returncode == 0, 'UI restart')
  port = live.published_port(f'{live.name_prefix}-a', '8080/tcp')
  A2 = Api(live, f'http://127.0.0.1:{port}')
  live.wait_ui(A2, 'UI after the restart')
  live.check(op_attr(lk1, 'pwdAccountLockedTime') == [MARKER] and op_attr(user_dn('lk7'), 'pwdAccountLockedTime') == b_val
             and op_attr(user_dn('lk6'), 'pwdAccountLockedTime') == a_val and try_bind('lk1', user_pw['lk1']) != 0,
             '[F] after a real slapd + UI restart the machine lock, the ppolicy lock and the duration-0 lock hold the same values: the state lives in the directory')
  attempt_unlock('(d) lk1 after the restart (idempotency store and in-memory limits are empty), same client', A2, 'svc-writer', lk1)
  attempt_unlock('(d) lk7 after the restart', A2, 'svc-writer', user_dn('lk7'))
  attempt_unlock('(d+e) lk1 after the restart, a DIFFERENT client', A2, 'svc-other', lk1)
  st, _, _ = lock(A2, token(), user_dn('lk9'), etag_of(A2, token(), user_dn('lk9')))
  live.check(st in (200, 204) and op_attr(user_dn('lk9'), 'pwdAccountLockedTime') == [MARKER],
             f'[F] after the restart lockUser still works end to end ({st}); only unlock stays human-only')
  ul = [e for e in live.audit_lines(f'{live.name_prefix}-a') if '"operation":"unlockUser"' in e]
  obs(f'audit lines naming an unlockUser operation: {len(ul)} (an unregistered route has no operation id)')

  # ======== G. audit lines + sentinel scan ==================================================================
  time.sleep(0.6)
  ev = audit('a', rid_lock)
  live.check(len(ev) == 1 and ev[0]['operation'] == 'lockUser' and ev[0]['outcome'] == 'applied' and ev[0]['compartment'] == 'lock'
             and ev[0]['bind_dn'] == WLOCK_DN and ev[0]['write_scope'] == 'directory.users.lock' and ev[0]['target_kind'] == 'user' and 'target_dn' not in ev[0],
             '[G] lockUser audit line: operation, applied, compartment=lock, bind_dn=W_lock, write_scope, target_kind, no plaintext DN: ' + json.dumps(ev)[:300])
  for rid_, op, kind, scope, outcome in ((rid, 'createGroup', 'group', 'directory.groups.create', 'applied'),
                                         (rid_pg, 'patchGroup', 'group', 'directory.groups.update', 'applied'),
                                         (rid_dg, 'deleteGroup', 'group', 'directory.groups.delete', 'applied')):
    ev = audit('a', rid_)
    live.check(len(ev) == 1 and ev[0]['operation'] == op and ev[0]['outcome'] == outcome and ev[0]['compartment'] == 'data' and ev[0]['bind_dn'] == WDATA_DN
               and ev[0]['write_scope'] == scope and ev[0]['target_kind'] == kind,
               f'[G] {op} audit line: applied, compartment=data, bind_dn=W_data, write_scope, target_kind: ' + json.dumps(ev)[:240])
  logs = live.all_logs()
  pool = [t for t in issued if t] + [live.secret_values[i] for i in range(len(live.secret_values))] + [SENTINEL_DESC, 'Direct-Attempt-2']
  leaks = []
  for value in pool:
    parts = [value] if value.count('.') != 2 else [value] + value.split('.')
    leaks += [part[:10] + '...' for part in parts if len(part) >= 8 and part in logs]
  keys_in_logs = re.findall(r'v2b-[0-9a-f]{32}', logs)
  live.check(not leaks and not keys_in_logs,
             f'[G] sentinel scan of ALL {len(live.containers)} container logs ({len(logs)} bytes): no token, JWT segment, client secret, bind/admin/user password, description value or Idempotency-Key: {leaks} {keys_in_logs[:2]}')
  print(f'All machine write v2b live checks passed: {live.checks} checks in {live.elapsed():.0f}s.', flush=True)


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    live.dump_logs()
    raise
