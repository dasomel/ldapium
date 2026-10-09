#!/usr/bin/env python3
"""Actual HTTP revocation enforcement while a real replication peer is isolated."""
import base64
import json
import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'lib'))
from machine_live import ADMIN_DN, AUDIENCE, BASE_DN, MACHINE_DN, READER, Keycloak, Live, Slapd, ensure

live = Live('ldapium-mhp-', deadline_seconds=300)
BASE = 'ou=revocations,ou=system,' + BASE_DN
TOOL = os.environ.get('LDAPIUM_REVOCATION_TOOL', str(pathlib.Path(__file__).resolve().parents[1] / 'machine-revocation.sh'))


def main():
  live.make_network()
  peer_network = live.name_prefix + '-peers'
  ensure(live.run(['docker', 'network', 'create', peer_network]).returncode == 0)
  live.networks.append(peer_network)
  nodes = [Slapd(live, live.name_prefix + '-a'), Slapd(live, live.name_prefix + '-b')]
  for key in ('admin_password', 'machine_password', 'human_password', 'over_password', 'seed_secret'):
    setattr(nodes[1], key, getattr(nodes[0], key))

  def start_node(index):
    original = live.run
    def run(cmd, **kwargs):
      if cmd[:3] == ['docker', 'run', '-d'] and '--name' in cmd and cmd[cmd.index('--name') + 1] == nodes[index].name:
        cmd = list(cmd)
        cmd[1:3] = ['create']
        cmd[-1:-1] = ['-e', 'LDAP_REPLICATION_ENABLED=true', '-e', f'LDAP_SERVER_ID={index + 1}',
                       '-e', 'LDAP_REPLICATION_PEERS=ldap://peer-a:389,ldap://peer-b:389',
                       '-e', 'LDAP_REPLICATION_INTERVAL=00:00:00:01']
        result = original(cmd, **kwargs)
        ensure(result.returncode == 0)
        ensure(original(['docker', 'network', 'connect', '--alias', 'peer-' + ('a' if index == 0 else 'b'), peer_network, nodes[index].name]).returncode == 0)
        ensure(original(['docker', 'start', nodes[index].name]).returncode == 0)
        return result
      return original(cmd, **kwargs)
    live.run = run
    try:
      nodes[index].start()
    finally:
      live.run = original

  start_node(0)
  nodes[0].seed(users=2, groups=1)
  start_node(1)
  live.wait_until(lambda: nodes[1].admin_tool('ldapsearch', ['-LLL', '-b', MACHINE_DN, '-s', 'base']).returncode == 0,
                  'actual initial peer replication', 60)
  for node in nodes:
    node.apply_acl()
  ensure(nodes[0].admin_tool('ldapadd', [], f'dn: {BASE}\nobjectClass: organizationalUnit\nou: revocations\n').returncode == 0)
  def tool(command, *extra):
    result = live.run([TOOL, command, '--container', nodes[0].name, '--uri', 'ldap://localhost', '--base', BASE,
                       '--bind-dn', ADMIN_DN, '--password-file', '/tmp/.pw-admin', *extra])
    ensure(result.returncode == 0, live.mask(result.stderr))
  tool('init')
  live.wait_until(lambda: 'cn: sentinel' in nodes[1].admin_tool('ldapsearch', ['-LLL', '-b', BASE, '(cn=sentinel)', 'cn']).stdout,
                  'sentinel replicated', 60)
  kcname = live.name_prefix + '-kc'
  kc = Keycloak(live, kcname, f'http://{kcname}:8080')
  kc.start()
  realm, client = 'partition', 'svc-partition'
  kc.create_realm(realm)
  for scope in READER:
    kc.create_scope(realm, scope)
  secret = live.secret(os.urandom(24).hex())
  kc.create_client(realm, client, secret, scopes=READER)
  token = live.secret(kc.sa_token(realm, client, secret))
  tool('heartbeat')
  env = {'LDAP_BASE_DN': BASE_DN, 'COOKIE_SECURE': 'false', 'UI_TRUSTED_PROXIES': 'none',
         'MACHINE_AUTH_ENABLED': 'true', 'MACHINE_OIDC_INSECURE_HTTP': 'true',
         'MACHINE_OIDC_ISSUER_URL': kc.issuer(realm), 'MACHINE_OIDC_AUDIENCE': AUDIENCE,
         'MACHINE_AUTH_FAILURE_LIMIT': '1000', 'MACHINE_RATE_LIMIT_RPS': '10000', 'MACHINE_RATE_LIMIT_BURST': '10000',
         'MACHINE_ALLOWED_CLIENTS': client + '=' + ','.join(READER), 'MACHINE_LDAP_BIND_DN': MACHINE_DN,
         'MACHINE_LDAP_ROOT_DNS': ADMIN_DN, 'MACHINE_REVOCATION_ENABLED': 'true',
         'MACHINE_REVOCATION_REFRESH': '1s', 'MACHINE_REVOCATION_MAX_STALE': '6s',
         'MACHINE_REVOCATION_SENTINEL_MAX_AGE': '30s', 'MACHINE_REVOCATION_BASE_DN': BASE}
  names = [live.name_prefix + '-ui-a', live.name_prefix + '-ui-b']
  apis = [live.start_ui(name, f'ldap://{node.name}:389', env,
                      {'SESSION_SECRET': live.secret(os.urandom(32).hex()), 'MACHINE_LDAP_BIND_PASSWORD': node.machine_password})
          for name, node in zip(names, nodes)]
  def status(index):
    return apis[index].machine(token, '/api/users?limit=1')[0]
  live.wait_until(lambda: all(status(i) == 200 for i in range(2)), 'both HTTP snapshots initially ready', 12)
  ids = [live.run(['docker', 'inspect', '-f', '{{.Id}}', n]).stdout.strip() for n in names]
  ensure(live.run(['docker', 'network', 'disconnect', peer_network, nodes[1].name]).returncode == 0)
  # D-HTTP-partition: peer aliases exist only on the replication bridge. UI/data
  # connections keep the separate client bridge; no LDAP replies are fabricated.
  tool('heartbeat')
  identifier = json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '=='))['jti']
  file = live.write_secret_file('jti', identifier)
  tool('add', '--kind', 'jti', '--client', client, '--id-file', file)
  began = time.monotonic()
  live.wait_until(lambda: status(0) == 401, 'healthy peer HTTP revokes real JTI', 12)
  ensure(status(1) == 200, 'isolated peer did not serve its previously valid snapshot')
  live.check(True, 'actual peer partition: healthy HTTP 401, isolated peer temporarily 200 within stale-sentinel bound')
  live.wait_until(lambda: status(1) == 503, 'isolated peer HTTP sentinel-age plus stale failure', 42)
  elapsed = time.monotonic() - began
  print(f'OBS isolated HTTP 503 after {elapsed:.2f}s; t={live.elapsed():.2f}s', flush=True)
  live.check(elapsed <= 42, 'isolated live LDAP peer eventually HTTP 503 on real wall clock')
  ensure(nodes[1].admin_tool('ldapsearch', ['-b', BASE_DN, '-s', 'base']).returncode == 0,
         'isolated LDAP peer itself became unavailable')
  ensure(live.run(['docker', 'network', 'connect', '--alias', 'peer-b', peer_network, nodes[1].name]).returncode == 0)
  tool('heartbeat')
  next_heartbeat = [time.monotonic() + 5]
  def recovered():
    if time.monotonic() >= next_heartbeat[0]:
      tool('heartbeat')
      next_heartbeat[0] = time.monotonic() + 5
    return all(status(i) == 401 for i in range(2))
  live.wait_until(recovered, 'reconnected peer catches up and HTTP denies JTI', 60)
  live.check(ids == [live.run(['docker', 'inspect', '-f', '{{.Id}}', n]).stdout.strip() for n in names],
             'replication catch-up restores revocation on both unchanged UI containers')
  live.check(not any(value in live.all_logs() for value in live.secret_values if len(value) >= 8), 'raw container logs contain no credentials or tokens')
  print(f'All actual HTTP partition checks passed: {live.checks} checks in {live.elapsed():.0f}s.', flush=True)


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    live.dump_logs()
    raise
