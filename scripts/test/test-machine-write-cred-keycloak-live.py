#!/usr/bin/env python3
"""Machine setPassword (v2c) end to end: REAL Keycloak + real slapd + the production UI image + config.Load
(#417 (b), machine-write-scope-v2 T-031; AC-008, AC-009, AC-010, AC-011 (a)).

docs/changes/machine-write-scope-v2. The sibling proofs (test-machine-write-cred-secret-live.py, -drill.py) drive
the application through a `live`-tagged Go test with an in-process IdP and a configuration built in code. This one
closes that gap: the tokens are issued by a real Keycloak (client credentials), the application is the image built by
`docker build ui` configured only by environment variables (the real config.Load, the chart's MACHINE_WRITE_CRED_*
contract), and the directory is a fresh slapd prepared with the T-028 proof's setup (operator guide 4.2/4.3, 8.1
no-lockout policy of W_cred, 8.2-8.5, 8.8: reader and canaries in two cred subtrees; accesslog `writes reads bind`).

Paths: createUser with credentialPending, then setPassword -> 200 {} and the new password binds (ldapwhoami); idempotent
replay (Idempotent-Replayed: true); a second set on the same account (403 once cleaned, 409 when it is a stuck entry
again); 403 for a token without directory.users.password.write; 400 for a too-short value (application floor) and for a
value slapd's pending policy refuses; the emergency block (MACHINE_WRITE_CRED_ENABLED=false container: 403
scope_denied, zero W_cred binds in cn=accesslog).

Then the scans (AC-009): the one-time plaintext sentinels, their base64 forms and password-hash patterns must appear 0
times in every HTTP response (status, headers, body), the UI container logs (audit lines included), the slapd container
log, the Keycloak container log, and cn=accesslog reqMod/reqOld read as the accesslog rootdn (check 5's public probe
constant allowlisted exactly as in the secret proof, T024-F1). Controls prove each scanner can see: the seed's plain
userPassword Adds make the accesslog hash scan non-zero. A hit fails the run and names the surface, never the value.

A second set on a completed account is 403 scope_denied (the cleanup cleared the marker); 409 is only for a stuck
entry (password, marker and pending policy together), which the script recreates as the administrator.

Mutation self-test (LDAPIUM_CREDKC_MUTATE writes the value into the slapd container log, a scanned surface):
  leak       a sentinel in plain text                      -> must FAIL (scan)
  leak-b64   the same sentinel base64-encoded               -> must FAIL (scan)
  leak-hash  a {SSHA} hash                                  -> must FAIL (scan)
The injection is verified to have landed; the run exits 1 only when exactly the slapd-log scan check(s) failed
("MUTATION SELF-TEST: caught by the slapd log scan"), and 3 when the failure is anything else or nothing failed.

Run (docker; builds not included):
  docker build -t ldapium:e2e image && docker build -t ldapium-ui:e2e ui
  python3 scripts/test/test-machine-write-cred-keycloak-live.py
Override LDAPIUM_IMAGE / LDAPIUM_UI_IMAGE / KEYCLOAK_IMAGE / LDAPIUM_TEST_PREFIX.
"""
import base64
import importlib.util
import os
import pathlib
import re
import secrets
import sys
import time
import uuid
from urllib.parse import quote as urlquote

repo_root = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(repo_root / 'scripts/lib'))
from machine_live import AUDIENCE, READER, Keycloak, Live  # noqa: E402

mutation = os.environ.get('LDAPIUM_CREDKC_MUTATE', '')
MUTATIONS = ('leak', 'leak-b64', 'leak-hash')
if mutation not in ('',) + MUTATIONS:
  raise SystemExit('LDAPIUM_CREDKC_MUTATE must be one of ' + ', '.join(MUTATIONS))
os.environ.setdefault('LDAPIUM_TEST_PREFIX', 'ldapium-mwk-')
# The secret proof carries the scanners and the 60 one-time sentinels; its main() does not run.
_spec = importlib.util.spec_from_file_location('csec', repo_root / 'scripts/test/test-machine-write-cred-secret-live.py')
sec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sec)
pre, acl = sec.pre, sec.acl
check, require, mask, run = acl.check, acl.require, acl.mask, acl.run

live = Live(os.environ['LDAPIUM_TEST_PREFIX'], deadline_seconds=1800)
REALM = 'cred-live'
CRED_SCOPE = 'directory.users.password.write'
WRITE_SCOPES = ['directory.users.create', CRED_SCOPE]
_run_net = acl.run


def _on_live_network(cmd, *a, **kw):
  """The slapd container of the T-028 setup is started with `--network none`; the UI and Keycloak must reach it."""
  if cmd[:3] == ['docker', 'run', '-d'] and '--network' in cmd and cmd[cmd.index('--network') + 1] == 'none':
    cmd = list(cmd)
    cmd[cmd.index('--network') + 1] = live.network
  return _run_net(cmd, *a, **kw)


acl.run = _on_live_network
sentinels = list(sec.SENTINELS)
for s in sentinels:  # a failure dump masks the whole value, its 11-character prefix (the short request) and base64 forms
  for v in (s, s[:sec.SHORTEST]):
    live.secret(v)
    for f in sec.b64_forms(v):
      live.secret(f)


def next_sentinel():
  require(sentinels, 'out of sentinels')
  return sentinels.pop(0)


def main():
  print(f'Run {live.name_prefix}: server {live.ldap_image}, UI {live.ui_image}, Keycloak {live.keycloak_image}, mutation={mutation or "none"}', flush=True)
  live.make_network()
  node = acl.Node('n0')
  live.register(node.container)  # removed (with the network's last endpoint) by live.cleanup
  canaries = pre.setup(node)
  ldap_url = f'ldap://{node.container}:389'
  wcred_dn, base = acl.wc_dn, acl.base_dn

  def wcred_binds():
    time.sleep(0.5)
    res = run(['docker', 'exec', '-i', node.container, 'ldapsearch', '-x', '-H', acl.ldap_uri, '-D', 'cn=admin,cn=accesslog', '-y', '/tmp/.pw-admin',
               '-LLL', '-b', 'cn=accesslog', f'(&(reqType=bind)(reqDN={wcred_dn}))', 'reqDN'])
    require(res.returncode == 0, 'accesslog bind count: ' + mask(res.stderr))
    return res.stdout.count('reqDN:')

  def admin_ldif(ldif, tool='ldapmodify'):
    res = node.tool('admin', tool, [], ldif)
    require(res.returncode == 0, 'admin ' + tool + ': ' + mask(res.stderr))

  def entry_attrs(dn, *names):
    out = node.search('admin', dn, '(objectClass=*)', names, 'base').stdout
    got = {}
    for line in out.replace('\n ', '').splitlines():
      if ': ' in line:
        k, v = line.split(': ', 1)
        got.setdefault(k.lower(), []).append(v)
    return got

  def binds(dn, password):
    node.put('/tmp/.pw-whoami', password)
    return run(['docker', 'exec', '-i', node.container, 'ldapwhoami', '-x', '-H', acl.ldap_uri, '-D', dn, '-y', '/tmp/.pw-whoami']).returncode == 0

  # ---- Keycloak: one client with the write scopes, one whose TOKEN lacks the password scope --------------------
  kcname = live.name_prefix + '-kc'
  kc = Keycloak(live, kcname, f'http://{kcname}:8080')
  kc.start()
  kc.create_realm(REALM)
  for scope in READER + WRITE_SCOPES:
    kc.create_scope(REALM, scope)
  clients = {'svc-pw': READER + WRITE_SCOPES, 'svc-nopw': READER + ['directory.users.create']}  # name -> scopes in the TOKEN
  ceiling = READER + WRITE_SCOPES                                                              # the application ceiling of both
  csecret = {}
  for name, scopes in clients.items():
    csecret[name] = live.secret(name + '-' + secrets.token_hex(10))
    kc.create_client(REALM, name, csecret[name], scopes=scopes)

  def token(name):
    value = kc.sa_token(REALM, name, csecret[name])
    for part in [value] + value.split('.'):
      live.secret(part)
    return value

  # ---- the production UI image, configured by environment only (config.Load) ---------------------------------
  pw = acl.passwords
  held = {'SESSION_SECRET': live.secret(secrets.token_hex(32)), 'MACHINE_LDAP_BIND_PASSWORD': pw['machine'],
          'MACHINE_WRITE_DATA_BIND_PASSWORD': pw['wdata'], 'MACHINE_WRITE_LOCK_BIND_PASSWORD': pw['wlock'],
          'MACHINE_WRITE_CRED_BIND_PASSWORD': pw['wcred'], 'MACHINE_WRITE_CRED_ACL_READER_PASSWORD': pw['reader']}
  for v in held.values():
    live.secret(v)

  def env_for(cred_enabled=True):
    subtrees = ';'.join(f'{c}={acl.managed}' for c in clients)
    cred = ';'.join(f'{c}={pre.sub_a}|{pre.sub_b}' for c in clients)
    return {'LDAP_BASE_DN': base, 'LDAP_USER_CREATE_BASE': pre.sub_a, 'COOKIE_SECURE': 'false', 'UI_TRUSTED_PROXIES': 'none',
            'MACHINE_AUTH_ENABLED': 'true', 'MACHINE_OIDC_INSECURE_HTTP': 'true', 'MACHINE_OIDC_ISSUER_URL': kc.issuer(REALM),
            'MACHINE_OIDC_AUDIENCE': AUDIENCE, 'MACHINE_CLOCK_SKEW': '0s',
            'MACHINE_ALLOWED_CLIENTS': ';'.join(f'{c}={",".join(ceiling)}' for c in clients),
            'MACHINE_LDAP_BIND_DN': acl.machine_dn, 'MACHINE_LDAP_ROOT_DNS': acl.admin_dn,
            'MACHINE_AUTH_FAILURE_LIMIT': '1000', 'MACHINE_RATE_LIMIT_RPS': '10000', 'MACHINE_RATE_LIMIT_BURST': '10000',
            'UI_IDEMPOTENCY_ENABLED': 'true', 'MACHINE_WRITE_ENABLED': 'true',
            'MACHINE_WRITE_DATA_BIND_DN': acl.wd_dn, 'MACHINE_WRITE_LOCK_ENABLED': 'true', 'MACHINE_WRITE_LOCK_BIND_DN': acl.wl_dn,
            'MACHINE_WRITE_SUBTREES': subtrees, 'MACHINE_WRITE_PRIVILEGED_GROUPS': acl.priv,
            'MACHINE_WRITE_RATE_LIMIT_RPS': '100', 'MACHINE_WRITE_RATE_LIMIT_BURST': '100',
            'MACHINE_WRITE_CRED_ENABLED': 'true' if cred_enabled else 'false', 'MACHINE_WRITE_CRED_BIND_DN': wcred_dn,
            'MACHINE_WRITE_CRED_SUBTREES': cred, 'MACHINE_WRITE_CRED_PENDING_POLICY_DN': acl.pending_pol,
            'MACHINE_WRITE_CRED_MIN_LENGTH': '12', 'MACHINE_WRITE_CRED_RATE_LIMIT_RPS': '10', 'MACHINE_WRITE_CRED_PENDING_TTL': '24h',
            'MACHINE_WRITE_CRED_ACL_READER_DN': pre.reader_dn, 'MACHINE_WRITE_CRED_CANARIES': ';'.join(canaries)}

  capture = []  # every HTTP response: status, headers, body

  def call(api, step, tok, method, path, body=None, key=None, rid=None):
    h = {'Authorization': 'Bearer ' + tok}
    if body is not None:
      h['Content-Type'] = 'application/json'
    if key:
      h['Idempotency-Key'] = key
    if rid:
      h['X-Request-Id'] = rid
    status, hdrs, text = api.call(method, path, h, body)
    capture.append(f'### {step} {method} {path} -> {status}\n{hdrs}\n{text}\n')
    return status, hdrs, text

  def code_of(text):
    m = re.search(r'"code"\s*:\s*"([^"]*)"', text)
    return m.group(1) if m else ''

  def key():
    return 'ckc-' + uuid.uuid4().hex

  def create_pending(api, tok, uid):
    status, _, text = call(api, f'create {uid}', tok, 'POST', '/api/users',
                           {'uid': uid, 'cn': uid, 'sn': 'Live', 'credentialPending': True}, key())
    dn = f'uid={uid},{pre.sub_a}'
    check(status == 201, f'createUser credentialPending {uid} -> 201 (got {status} {mask(text)[:160]})')
    return dn

  def set_password(api, step, tok, dn, password, k, rid=None):
    """The production password budget (1-10 rps, global) may answer 429 to a fast sequence: wait Retry-After and
    send the same request again (same Idempotency-Key). A 429 never stands in for an expected status."""
    for _ in range(6):
      status, hdrs, text = call(api, step, tok, 'POST', '/api/users/password', {'dn': dn, 'password': password}, k, rid)
      if status != 429:
        break
      time.sleep(float(hdrs.get('Retry-After') or 1) + 0.2)
    return status, hdrs, text

  ui_names = []

  def start_ui(tag, cred_enabled=True):
    name = f'{live.name_prefix}-ui-{tag}'
    ui_names.append(name)
    return live.start_ui(name, ldap_url, env_for(cred_enabled), held)

  # ======== the T-024 setup is in place; start the real application =========================================
  t0 = sec.slapd_now(node)
  time.sleep(1.2)  # reqStart has second precision
  t0 = sec.slapd_now(node)
  A = start_ui('a')
  check(A.call('GET', '/api/auth/config')[0] == 200,
        'the production UI image started from environment variables alone (config.Load accepted the v2c contract, premise checks passed) and answers')
  tok = token('svc-pw')

  # --- success -> the new password binds -> replay -> second set -------------------------------------------
  p1 = create_pending(A, tok, 'ckc-p1')
  marker = entry_attrs(p1, 'employeeType').get('employeetype', [''])[0]
  check(marker.startswith('ldapium-credential-pending:') and 'employeetype' in entry_attrs(p1, 'employeeType'),
        'createUser credentialPending wrote the pending marker (the entry is a v2c target)')
  s0, s1, s2 = next_sentinel(), next_sentinel(), next_sentinel()
  k1, rid = key(), 'ckc-' + secrets.token_hex(4)
  before_binds = wcred_binds()
  status, hdrs, text = set_password(A, 'success', tok, p1, s0, k1, rid)
  check(status == 200 and text.strip() == '{}', f'setPassword on the pending account -> 200 {{}} (got {status} {mask(text)[:120]})')
  check(wcred_binds() > before_binds, 'the write bound as W_cred (slapd accesslog)')
  check(binds(p1, s0), 'the new password binds (ldapwhoami)')
  attrs = entry_attrs(p1, 'employeeType', 'pwdPolicySubentry')
  check(not attrs.get('employeetype') and not attrs.get('pwdpolicysubentry'), 'the cleanup removed the pending marker and the pending policy')
  status, hdrs, text = set_password(A, 'replay', tok, p1, s0, k1)
  check(status == 200 and text.strip() == '{}' and hdrs.get('Idempotent-Replayed') == 'true',
        f'same key + same body -> 200 {{}} with Idempotent-Replayed: true (got {status}, replayed={hdrs.get("Idempotent-Replayed")})')
  status, _, text = set_password(A, '422', tok, p1, s1, k1)
  check(status == 422 and code_of(text) == 'idempotency_key_reused', f'same key + another password -> 422 idempotency_key_reused (got {status} {code_of(text)})')
  status, _, text = set_password(A, 'second-cleaned', tok, p1, s2, key())
  check(status == 403 and code_of(text) == 'scope_denied',
        f'a second set with a new key on the cleaned account (no marker) -> 403 scope_denied (got {status} {code_of(text)})')
  admin_ldif(f'dn: {p1}\nchangetype: modify\nadd: employeeType\nemployeeType: {marker}\n-\nadd: pwdPolicySubentry\npwdPolicySubentry: {acl.pending_pol}\n')
  status, _, text = set_password(A, 'second-stuck', tok, p1, s2, key())
  check(status == 409, f'a second set on the same account as a stuck entry (password, marker, pending policy) -> 409 (got {status} {code_of(text)})')
  admin_ldif(f'dn: {p1}\nchangetype: modify\ndelete: employeeType\n-\ndelete: pwdPolicySubentry\n')
  check(binds(p1, s0) and not binds(p1, s1) and not binds(p1, s2), 'only the first value binds after replay / 422 / 403 / 409')

  # --- 403 without the scope in the token; 400 short; 400 refused by slapd's policy --------------------------
  p2 = create_pending(A, tok, 'ckc-p2')
  status, _, text = set_password(A, 'no-scope', token('svc-nopw'), p2, next_sentinel(), key())
  check(status == 403 and code_of(text) == 'scope_denied', f'token without {CRED_SCOPE} -> 403 scope_denied (got {status} {code_of(text)})')
  status, _, text = set_password(A, 'short', tok, p2, next_sentinel()[:11], key())
  check(status == 400 and code_of(text) == 'invalid_request', f'a value shorter than MACHINE_WRITE_CRED_MIN_LENGTH (11 < 12) -> 400 (got {status} {code_of(text)})')
  check(not entry_attrs(p2, 'pwdChangedTime').get('pwdchangedtime') and entry_attrs(p2, 'employeeType').get('employeetype'),
        'the refused requests changed nothing: p2 is still pending and has no password')
  pend = acl.pending_pol
  admin_ldif(f'dn: {pend}\nchangetype: modify\nreplace: pwdMinLength\npwdMinLength: 40\n')
  try:
    sp = next_sentinel()
    status, _, text = set_password(A, 'policy', tok, p2, sp, key())
    check(status == 400 and code_of(text) == 'invalid_request',
          f'a 32-character value under a pending pwdMinLength 40 reaches slapd and is refused -> 400 invalid_request (got {status} {code_of(text)})')
    check(not binds(p2, sp) and entry_attrs(p2, 'employeeType').get('employeetype'), 'slapd stored nothing; the account stays pending')
  finally:
    admin_ldif(f'dn: {pend}\nchangetype: modify\nreplace: pwdMinLength\npwdMinLength: 12\n')

  # --- the emergency block: a container with MACHINE_WRITE_CRED_ENABLED=false ----------------------------------
  p3 = create_pending(A, tok, 'ckc-p3')  # made while the compartment is on: credentialPending is refused once it is off
  require(run(['docker', 'stop', '-t', '5', ui_names[0]]).returncode == 0, 'stop the first UI (its logs stay for the scan)')
  time.sleep(1.0)
  binds_before = wcred_binds()
  B = start_ui('off', cred_enabled=False)
  status, _, text = set_password(B, 'block', token('svc-pw'), p3, next_sentinel(), key())
  check(status == 403 and code_of(text) == 'scope_denied', f'MACHINE_WRITE_CRED_ENABLED=false -> 403 scope_denied (got {status} {code_of(text)})')
  check(wcred_binds() == binds_before, 'the emergency block bound W_cred 0 times (slapd accesslog)')
  check(entry_attrs(p3, 'employeeType').get('employeetype') and not entry_attrs(p3, 'pwdChangedTime').get('pwdchangedtime'),
        'the blocked account is untouched: still pending, no password')

  # ======== AC-009 scans =====================================================================================
  if mutation:  # the scan must bite: put the value on a scanned surface (the slapd container log)
    leak = {'leak': sentinels[0], 'leak-b64': base64.b64encode(sentinels[0].encode()).decode(), 'leak-hash': '{SSHA}' + 'A' * 28}[mutation]
    require(run(['docker', 'exec', '-u', 'ldap', '-e', 'LEAK=' + leak, node.container, 'sh', '-c', 'echo "$LEAK" > /proc/1/fd/1']).returncode == 0, 'mutation inject')
    time.sleep(0.5)
    landed = run(['docker', 'logs', node.container])
    require(leak in landed.stdout + landed.stderr, 'mutation inject did not land in the slapd container log')
  rows = [('HTTP responses (status, headers, body)', '\n'.join(capture))]
  logs = ''
  for name in ui_names:
    res = run(['docker', 'logs', name])
    logs += res.stdout + res.stderr
  check('"event":"machine_access"' in logs and f'"request_id":"{rid}"' in logs, 'control: the UI log holds the audit lines, the success request among them')
  rows.append(('UI container logs (audit lines included)', logs))
  res = run(['docker', 'logs', node.container])
  rows.append(('slapd container log', res.stdout + res.stderr))
  res = run(['docker', 'logs', kcname])
  rows.append(('Keycloak container log', res.stdout + res.stderr))
  since, n_since = sec.accesslog(node, 'alog-admin', t0)
  whole, _ = sec.accesslog(node, 'alog-admin')
  check(n_since > 0, f'control: accesslog recorded the run\'s writes ({n_since} entries)')
  seed_hashes = sec.scan(whole)[2] - sec.scan(since)[2]
  check(seed_hashes > 0, f'control: the hash scan finds the seed\'s plain userPassword Adds in the accesslog before the run ({seed_hashes} hits)')
  since_other, n_probe, stray = sec.allow_probe(since, canaries)
  check(n_probe >= 1 and stray == 0, f'T024-F1: only check 5\'s public probe constant is allowlisted in accesslog ({n_probe} times, {stray} elsewhere)')
  rows.append(('accesslog reqMod/reqOld (accesslog rootdn, written during the run, probe constant allowlisted)', since_other))
  rows.append(('accesslog reqMod/reqOld (accesslog rootdn, whole log: sentinels only)', whole))
  print('--- AC-009 scan (plaintext sentinel / base64 sentinel / hash pattern hits) ---', flush=True)
  for path, text in rows:
    plain, b64, hashes = sec.scan(text)
    sentinels_only = 'sentinels only' in path
    print(f'SCAN {path}: plaintext {plain}, base64 {b64}, hash {"(not counted)" if sentinels_only else hashes}', flush=True)
    check(plain == 0 and b64 == 0, f'{path}: 0 plaintext and base64 sentinels')
    if not sentinels_only:
      check(hashes == 0, f'{path}: 0 hash patterns')


if __name__ == '__main__':
  code = 0
  try:
    main()
  except Exception as e:
    print('ERROR: ' + mask(live.mask(e)), flush=True)
    import traceback
    traceback.print_exc()
    live.dump_logs()
    code = 1
  print(f'RESULT: {acl.passed} checks passed, {len(acl.failed)} failed, mutation={mutation or "none"}, {time.monotonic() - acl.start_time:.0f}s', flush=True)
  for f in acl.failed:
    print('  FAILED: ' + f, flush=True)
  if mutation:
    caught = bool(acl.failed) and not code and all(f.startswith('slapd container log:') for f in acl.failed)
    print('MUTATION SELF-TEST: ' + ('caught by the slapd log scan' if caught else 'NOT attributable to the slapd log scan'), flush=True)
    sys.exit(1 if caught else 3)
  sys.exit(1 if acl.failed or code else 0)
