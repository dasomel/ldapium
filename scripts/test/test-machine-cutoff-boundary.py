#!/usr/bin/env python3
"""Client-cutoff boundary against a real directory clock (machine-token-revocation T-017 (b), AC-002).

Rule (CHANGE.md "폐기 판정 규칙" step 2, D7): with T = the cutoff entry's server-stamped
createTimestamp, a token of that client is revoked iff iat <= T + MACHINE_CLOCK_SKEW.
Tokens are minted by the real Keycloak and re-signed with a key imported into the realm
(machine_live.Signer), so each crafted token differs from a genuine one only in iat/exp/jti.
The verdict is proven by the audit reason (`revoked`), not just by the status, because an
iat in the future would also be a 401.

Run: python3 scripts/test/test-machine-cutoff-boundary.py
"""
import json
import os
import pathlib
import sys
import time
import datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'lib'))
from machine_live import (ADMIN_DN, AUDIENCE, BASE_DN, MACHINE_DN, READER, Keycloak, Live, Signer, Slapd, decode_jwt,  # noqa: E402
                          ensure)

live = Live('ldapium-mcb-', deadline_seconds=600)
BASE = 'ou=revocations,ou=system,' + BASE_DN
TOOL = os.environ.get('LDAPIUM_REVOCATION_TOOL', str(pathlib.Path(__file__).resolve().parents[1] / 'machine-revocation.sh'))
SKEW = 5


def main():
  live.make_network()
  ldap = Slapd(live)
  ldap.start()
  ldap.seed(users=2, groups=1)
  ldap.apply_acl()
  ensure(ldap.admin_tool('ldapadd', [], f'dn: {BASE}\nobjectClass: organizationalUnit\nou: revocations\n').returncode == 0)

  def tool(command, *extra):
    r = live.run([TOOL, command, '--container', ldap.name, '--uri', 'ldap://127.0.0.1',
                  '--base', BASE, '--bind-dn', ADMIN_DN, '--password-file', '/tmp/.pw-admin', *extra])
    ensure(r.returncode == 0, 'operator tool failed: ' + live.mask(r.stderr))

  kcname = live.name_prefix + '-kc'
  kc = Keycloak(live, kcname, f'http://{kcname}:8080')
  kc.start()
  realm = 'cutoff-boundary'
  kc.create_realm(realm)
  for scope in READER:
    kc.create_scope(realm, scope)
  signer = Signer(live)
  signer.import_into(kc, realm)
  secrets = {}
  for name in ('svc-cut', 'svc-peer'):
    secrets[name] = live.secret(name + '-' + os.urandom(12).hex())
    kc.create_client(realm, name, secrets[name], scopes=READER)
  bases = {n: decode_jwt(kc.sa_token(realm, n, secrets[n]))[1] for n in secrets}
  tokens = []

  env = {'LDAP_BASE_DN': BASE_DN, 'COOKIE_SECURE': 'false', 'UI_TRUSTED_PROXIES': 'none',
         'MACHINE_AUTH_ENABLED': 'true', 'MACHINE_OIDC_INSECURE_HTTP': 'true',
         'MACHINE_OIDC_ISSUER_URL': kc.issuer(realm), 'MACHINE_OIDC_AUDIENCE': AUDIENCE,
         'MACHINE_ALLOWED_CLIENTS': ';'.join(f'{c}=' + ','.join(READER) for c in secrets),
         'MACHINE_LDAP_BIND_DN': MACHINE_DN, 'MACHINE_LDAP_ROOT_DNS': ADMIN_DN, 'MACHINE_CLOCK_SKEW': f'{SKEW}s',
         'MACHINE_AUTH_FAILURE_LIMIT': '1000', 'MACHINE_RATE_LIMIT_RPS': '10000', 'MACHINE_RATE_LIMIT_BURST': '10000',
         'MACHINE_REVOCATION_ENABLED': 'true', 'MACHINE_REVOCATION_REFRESH': '1s',
         'MACHINE_REVOCATION_MAX_STALE': '6s', 'MACHINE_REVOCATION_SENTINEL_MAX_AGE': '300s',
         'MACHINE_REVOCATION_BASE_DN': BASE}
  ui = live.name_prefix + '-ui'
  api = live.start_ui(ui, f'ldap://{ldap.name}:389', env,
                      {'SESSION_SECRET': live.secret(os.urandom(32).hex()), 'MACHINE_LDAP_BIND_PASSWORD': ldap.machine_password})
  tool('init')
  fresh = kc.sa_token(realm, 'svc-cut', secrets['svc-cut'])
  tokens.append(fresh)
  live.wait_until(lambda: api.machine(fresh, '/api/users?limit=1')[0] == 200, 'snapshot ready', 15)

  tool('add', '--kind', 'cutoff', '--client', 'svc-cut')
  rows = ldap.admin_tool('ldapsearch', ['-LLL', '-b', BASE, '(cn=cutoff-*)', 'createTimestamp']).stdout
  stamp = next(l.split(': ', 1)[1] for l in rows.splitlines() if l.startswith('createTimestamp: '))
  T = int(datetime.datetime.strptime(stamp, '%Y%m%d%H%M%SZ').replace(tzinfo=datetime.timezone.utc).timestamp())
  # Wait until the container clock (Keycloak's iat) is >= T+2, so the future-iat rule
  # (iat <= now+skew) cannot be what rejects iat = T+skew+1.
  def clock_passed():
    t = kc.sa_token(realm, 'svc-cut', secrets['svc-cut'])
    tokens.append(t)
    return decode_jwt(t)[1]['iat'] >= T + 2
  live.wait_until(clock_passed, 'container clock >= T+2', 20, 1.0)
  print(f'OBS server createTimestamp T={T} skew={SKEW}s', flush=True)

  def probe(client, iat, label, revoked):
    jti = 'boundary-' + os.urandom(8).hex()
    claims = bases[client]
    ttl = claims['exp'] - claims['iat']
    token = signer.craft(claims, set_claims={'iat': iat, 'exp': iat + ttl, 'jti': jti})
    tokens.append(token)
    rid = 'req-' + os.urandom(6).hex()
    status = api.machine(token, '/api/users?limit=1', req_id=rid)[0]
    lines = [json.loads(l[l.index('{'):]) for l in live.audit_lines(ui)]
    mine = [l for l in lines if l.get('request_id') == rid]
    ensure(len(mine) == 1, f'{label}: expected exactly one audit line, got {len(mine)}')
    reason = mine[0].get('reason')
    print(f'OBS {label}: iat=T{iat - T:+d} (T+skew{iat - T - SKEW:+d}) status={status} reason={reason!r}', flush=True)
    if revoked:
      live.check(status == 401 and reason == 'revoked', f'{label}: 401 with audit reason revoked')
    else:
      live.check(status == 200 and reason != 'revoked', f'{label}: 200, not revoked')

  probe('svc-cut', T - 1, 'iat=T-1', True)
  probe('svc-cut', T, 'iat=T', True)
  probe('svc-cut', T + SKEW - 1, 'iat=T+skew-1', True)
  probe('svc-cut', T + SKEW, 'iat=T+skew (boundary, rejected)', True)
  probe('svc-cut', T + SKEW + 1, 'iat=T+skew+1 (boundary, allowed)', False)
  probe('svc-cut', T + SKEW + 2, 'iat=T+skew+2', False)
  probe('svc-peer', T, 'other client iat=T', False)
  probe('svc-peer', T + SKEW, 'other client iat=T+skew', False)
  logs = live.all_logs()
  live.check(not any(v in logs for v in tokens + live.secret_values if len(v) >= 8), 'all container logs contain no tokens or secrets')
  print(f'All cutoff boundary checks passed: {live.checks} checks in {live.elapsed():.0f}s.', flush=True)


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    live.dump_logs()
    raise
