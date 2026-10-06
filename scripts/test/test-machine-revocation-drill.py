#!/usr/bin/env python3
"""Emergency revocation and rollback drill for machine bearer auth (#214, unit 5a, T-027 / AC-019).

A real Keycloak, a real slapd and TWO UI replicas per revision (the compose equivalent of two
pods of one Deployment), rolled revision by revision the way an operator would. Every container
carries the label ldapium.drill.revision=<n> so "no old replica is left" is an observable fact.
docs/changes/machine-principal-auth CHANGE.md D7 / REQ-018 / AC-019:

  (a) Disable the Keycloak client: new tokens cannot be issued, but the token issued BEFORE keeps
      passing on every replica until it expires (documented; this is why (b) exists).
  (b) Remove the client from MACHINE_ALLOWED_CLIENTS and REPLACE ALL replicas: during the rollout an
      old replica still accepts the token; a request that is in flight on an old replica when it is
      stopped is finished (graceful shutdown, exit 0); after the rollout no old container exists and
      the SAME token is 401 on every new replica with zero new binds; a client that stays allowed is
      served throughout.
  (c) Feature off (MACHINE_AUTH_ENABLED=false) and replace all replicas: the bearer is ignored
      (the same 401 `unauthenticated` as a request with no credentials) and the cookie flow
      (login, read, logout) is unchanged.
  (d) Rollback of the rollback: redeploying the original allowlist makes the still-unexpired token
      pass again, which is exactly why the server allowlist, not Keycloak, is the revocation gate.

Run: python3 scripts/test/test-machine-revocation-drill.py
Override LDAPIUM_IMAGE / LDAPIUM_UI_IMAGE / KEYCLOAK_IMAGE / LDAPIUM_TEST_PREFIX /
LDAPIUM_TEST_DEADLINE as needed.
"""
import pathlib
import secrets
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / 'scripts/lib'))
from machine_live import (ADMIN_DN, ALL_SCOPES, AUDIENCE, BASE_DN, MACHINE_DN, READER, Keycloak, LDAPProxy, Live,  # noqa: E402
                          Slapd, jbody)

live = Live('ldapium-md-', deadline_seconds=900)
REALM = 'ldapium'
check = live.check
LABEL = 'ldapium.drill.revision'


def main():
  print(f'Run {live.name_prefix}: server {live.ldap_image}, UI {live.ui_image}, Keycloak {live.keycloak_image}', flush=True)
  live.make_network()
  slapd = Slapd(live)
  slapd.start()
  slapd.seed(users=3, groups=1)
  slapd.apply_acl()
  proxy = LDAPProxy('127.0.0.1', slapd.port)
  live.closers.append(proxy.close)
  kc_name = live.name_prefix + '-kc'
  kc = Keycloak(live, kc_name, f'http://{kc_name}:8080')
  kc.start()
  issuer = kc.issuer(REALM)
  kc.create_realm(REALM)
  for s in ALL_SCOPES:
    kc.create_scope(REALM, s)
  secrets_by = {}
  cids = {}
  for name in ('svc-drill', 'svc-other'):
    secrets_by[name] = live.secret(name + '-' + secrets.token_hex(8))
    cids[name] = kc.create_client(REALM, name, secrets_by[name], scopes=READER)
  session_secret = live.secret(secrets.token_hex(32))
  tokens = []
  old_logs = []

  def token(name):
    t = kc.sa_token(REALM, name, secrets_by[name])
    tokens.append(t)
    return t

  def binds():
    time.sleep(0.4)
    return slapd.binds(MACHINE_DN)

  def replica(revision, tag, allowed, enabled=True, via_proxy=False):
    env = {'LDAP_BASE_DN': BASE_DN, 'LDAP_USER_CREATE_BASE': 'ou=people,' + BASE_DN, 'COOKIE_SECURE': 'false',
           'UI_TRUSTED_PROXIES': 'none'}
    if enabled:
      env.update({'MACHINE_AUTH_ENABLED': 'true', 'MACHINE_OIDC_INSECURE_HTTP': 'true', 'MACHINE_OIDC_ISSUER_URL': issuer,
                  'MACHINE_OIDC_AUDIENCE': AUDIENCE,
                  'MACHINE_ALLOWED_CLIENTS': ';'.join(f'{c}=' + ','.join(READER) for c in allowed),
                  'MACHINE_LDAP_BIND_DN': MACHINE_DN, 'MACHINE_LDAP_ROOT_DNS': ADMIN_DN, 'MACHINE_REQUEST_TIMEOUT': '10s',
                  'MACHINE_AUTH_FAILURE_LIMIT': '1000', 'MACHINE_RATE_LIMIT_RPS': '10000', 'MACHINE_RATE_LIMIT_BURST': '10000'})
    held = {'SESSION_SECRET': session_secret}
    if enabled:
      held['MACHINE_LDAP_BIND_PASSWORD'] = slapd.machine_password
    url = f'ldap://host.docker.internal:{proxy.port}' if via_proxy else f'ldap://{slapd.name}:389'
    return live.start_ui(f'{live.name_prefix}-r{revision}{tag}', url, env, held, labels=[f'{LABEL}={revision}'])

  def containers_of(revision):
    out = live.run(['docker', 'ps', '-a', '--filter', f'label={LABEL}={revision}', '--format', '{{.Names}}']).stdout
    return [n for n in out.split() if n]

  def rollout(old_revision, old_replicas):
    """Stop the old replicas one after the other (SIGTERM, then at most 15s, like
    terminationGracePeriodSeconds) and delete them."""
    codes = {}
    for name in old_replicas:
      assert live.run(['docker', 'stop', '-t', '15', name]).returncode == 0
      logs = live.run(['docker', 'logs', name])
      old_logs.append(logs.stdout + logs.stderr)  # kept for the final secret scan; the container is deleted next
      codes[name] = live.run(['docker', 'inspect', '-f', '{{.State.ExitCode}}', name]).stdout.strip()
      assert live.run(['docker', 'rm', '-fv', name]).returncode == 0
    return codes

  both = ('svc-drill', 'svc-other')
  # ==== revision 1: both clients allowed, two replicas ======================================
  r1 = [(f'{live.name_prefix}-r1a', replica(1, 'a', both, via_proxy=True)), (f'{live.name_prefix}-r1b', replica(1, 'b', both))]
  t_drill = token('svc-drill')
  for name, api in r1:
    st, _, _ = api.machine(t_drill, '/api/users?limit=1')
    assert st == 200, f'{name}: {st}'
  check(True, 'revision 1 (2 replicas, svc-drill allowed): the svc-drill token -> 200 on every replica')

  # ==== (a) disable the Keycloak client ======================================================
  kc.update_client(REALM, cids['svc-drill'], enabled=False)
  st, resp = kc.token(REALM, 'svc-drill', secrets_by['svc-drill'])
  check(st != 200 and resp.get('error') in ('invalid_client', 'unauthorized_client'), f'(a) Keycloak refuses NEW tokens for the disabled client ({st} {resp.get("error")})')
  for name, api in r1:
    st, _, _ = api.machine(t_drill, '/api/users?limit=1')
    assert st == 200, f'{name}: {st}'
  check(True, '(a) the token issued BEFORE the disable STILL passes on every replica until it expires (documented: disabling the client is not revocation)')

  # ==== (b) remove the client from the server allowlist and replace ALL replicas =============
  r2 = [(f'{live.name_prefix}-r2a', replica(2, 'a', ('svc-other',))), (f'{live.name_prefix}-r2b', replica(2, 'b', ('svc-other',)))]
  check(len(containers_of(1)) == 2 and len(containers_of(2)) == 2, 'rollout in progress: two old and two new replicas coexist')
  st, _, _ = r1[1][1].machine(t_drill, '/api/users?limit=1')
  check(st == 200, 'during the rollout an OLD replica still accepts the token (the exposure window, why every replica must be replaced)')
  # a request is in flight on old replica 1a (held inside the directory) when it is stopped
  proxy.set_mode('stall')
  result = {}

  def inflight():
    result['r'] = r1[0][1].machine(t_drill, '/api/users?limit=2', timeout=30)
  th = threading.Thread(target=inflight)
  th.start()
  live.wait_until(lambda: proxy.stalled.is_set(), 'the request to be in flight inside the directory', 10)
  stopper = {}

  def stop_old():
    stopper['codes'] = rollout(1, [r1[0][0]])
  stop_th = threading.Thread(target=stop_old)
  stop_th.start()
  time.sleep(1.5)
  check(stop_th.is_alive() and 'r' not in result, 'old replica 1a received SIGTERM and is draining: the in-flight request has not been cut off')
  proxy.release()
  th.join(30)
  stop_th.join(30)
  st = result['r'][0]
  check(st == 200 and len(jbody(result['r'][2]).get('users', [])) == 2, f'the in-flight request FINISHED with its full 200 response after SIGTERM (got {st})')
  check(stopper['codes'][r1[0][0]] == '0', f'old replica 1a exited cleanly (exit code {stopper["codes"][r1[0][0]]}) within the 15s grace')
  codes = rollout(1, [r1[1][0]])
  check(codes[r1[1][0]] == '0' and containers_of(1) == [], f'old replica 1b stopped (exit {codes[r1[1][0]]}); containers left from revision 1: {containers_of(1)} (none)')
  proxy.set_mode('pass')
  before = binds()
  for name, api in r2:
    st, _, body = api.machine(t_drill, '/api/users?limit=1')
    assert st == 401 and jbody(body).get('code') == 'token_invalid', f'{name}: {st} {body[:100]}'
  check(binds() == before, '(b) after the rollout the SAME token is 401 token_invalid on every new replica, BIND COUNT 0')
  for name, api in r2:
    assert api.machine(token('svc-other'), '/api/users?limit=1')[0] == 200
  check(True, '(b) a client that stays allowed (svc-other) is served by every new replica')
  kc.update_client(REALM, cids['svc-drill'], enabled=True)
  st, _, _ = r2[0][1].machine(token('svc-drill'), '/api/users?limit=1')
  check(st == 401, '(b) even with the Keycloak client re-enabled a fresh svc-drill token is 401: the server allowlist is the gate')

  # ==== (c) feature off, replace all replicas ================================================
  r3 = [(f'{live.name_prefix}-r3a', replica(3, 'a', (), enabled=False)), (f'{live.name_prefix}-r3b', replica(3, 'b', (), enabled=False))]
  codes = rollout(2, [n for n, _ in r2])
  check(all(c == '0' for c in codes.values()) and containers_of(2) == [], f'revision 2 replaced: exit codes {codes}, containers left {containers_of(2)} (none)')
  t_other = token('svc-other')
  before = binds()
  for name, api in r3:
    st, _, body = api.machine(t_other, '/api/users?limit=1')
    st2, _, body2 = api.call('GET', '/api/users?limit=1')
    assert st == 401 and jbody(body).get('code') == 'unauthenticated' and (st2, jbody(body2).get('code')) == (st, 'unauthenticated'), \
        f'{name}: bearer {st} {body[:100]} vs none {st2} {body2[:100]}'
  check(binds() == before, '(c) with MACHINE_AUTH_ENABLED=false the bearer is ignored: the same 401 unauthenticated as a request without credentials, BIND COUNT 0')
  for name, api in r3:
    cookie = api.login_human(slapd.human_password)
    st, _, body = api.call('GET', '/api/users?limit=2', cookie)
    assert st == 200 and len(jbody(body).get('users', [])) == 2, f'{name}: cookie read {st}'
    st, _, _ = api.call('POST', '/api/logout', dict(cookie, Origin=api.base_url))
    assert st in (200, 204), f'{name}: logout {st}'
    assert api.call('GET', '/api/users?limit=1', cookie)[0] == 401
  check(True, '(c) the cookie flow is unchanged on every replica: login, read (200), logout, session gone (401)')

  # ==== (d) rollback: redeploy the original allowlist =============================================
  r4 = [(f'{live.name_prefix}-r4a', replica(4, 'a', both)), (f'{live.name_prefix}-r4b', replica(4, 'b', both))]
  codes = rollout(3, [n for n, _ in r3])
  check(containers_of(3) == [] and all(c == '0' for c in codes.values()), 'revision 3 replaced, none left')
  for name, api in r4:
    st, _, _ = api.machine(t_drill, '/api/users?limit=1')
    assert st == 200, f'{name}: {st}'
  check(True, '(d) rollback: with the original allowlist the still-unexpired svc-drill token passes again on every replica')

  scan = live.all_logs() + ''.join(old_logs)
  leaks = [t[:10] + '...' for t in tokens + [t_drill] if t in scan] + [s[:6] + '...' for s in live.secret_values if len(s) >= 8 and s in scan]
  check(not leaks, f'no token or secret in the {len(live.containers)} container logs: {leaks}')
  print(f'\nAll revocation drill checks passed: {live.checks} checks in {live.elapsed():.0f}s.', flush=True)


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    live.dump_logs()
    raise
