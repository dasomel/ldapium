#!/usr/bin/env python3
"""Live snapshot enforcement on two unchanged UI replicas (machine-token-revocation T-017).

This complements the rolling allowlist drill; it never replaces production data.
Uses real Keycloak tokens, the operator tool, LDAP ACLs and the production UI image.
"""
import base64
import datetime
import json
import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'lib'))
from machine_live import ADMIN_DN, AUDIENCE, BASE_DN, MACHINE_DN, READER, Keycloak, Live, Slapd, ensure

live = Live('ldapium-mlr-', deadline_seconds=900)
BASE = 'ou=revocations,ou=system,' + BASE_DN
TOOL = os.environ.get('LDAPIUM_REVOCATION_TOOL', str(pathlib.Path(__file__).resolve().parents[1] / 'machine-revocation.sh'))


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
    return r.stdout

  kcname = live.name_prefix + '-kc'
  kc = Keycloak(live, kcname, f'http://{kcname}:8080')
  kc.start()
  realm, client = 'live-revocation', 'svc-live-revocation'
  kc.create_realm(realm)
  for scope in READER:
    kc.create_scope(realm, scope)
  password = live.secret('client-' + os.urandom(18).hex())
  kc.create_client(realm, client, password, scopes=READER)
  tokens = []

  def token():
    value = kc.sa_token(realm, client, password)
    tokens.append(value)
    return value

  env = {'LDAP_BASE_DN': BASE_DN, 'COOKIE_SECURE': 'false', 'UI_TRUSTED_PROXIES': 'none',
         'MACHINE_AUTH_ENABLED': 'true', 'MACHINE_OIDC_INSECURE_HTTP': 'true',
         'MACHINE_OIDC_ISSUER_URL': kc.issuer(realm), 'MACHINE_OIDC_AUDIENCE': AUDIENCE,
         'MACHINE_ALLOWED_CLIENTS': client + '=' + ','.join(READER), 'MACHINE_LDAP_BIND_DN': MACHINE_DN,
         'MACHINE_LDAP_ROOT_DNS': ADMIN_DN, 'MACHINE_CLOCK_SKEW': '0s',
         'MACHINE_AUTH_FAILURE_LIMIT': '1000', 'MACHINE_RATE_LIMIT_RPS': '10000', 'MACHINE_RATE_LIMIT_BURST': '10000',
         'MACHINE_REVOCATION_ENABLED': 'true', 'MACHINE_REVOCATION_REFRESH': '1s',
         'MACHINE_REVOCATION_MAX_STALE': '6s', 'MACHINE_REVOCATION_SENTINEL_MAX_AGE': '30s',
         'MACHINE_REVOCATION_BASE_DN': BASE, 'MACHINE_REVOCATION_MAX_ENTRIES': '10'}
  names = [live.name_prefix + '-ui-a', live.name_prefix + '-ui-b']
  apis = [live.start_ui(name, f'ldap://{ldap.name}:389', env,
                      {'SESSION_SECRET': live.secret(os.urandom(32).hex()), 'MACHINE_LDAP_BIND_PASSWORD': ldap.machine_password})
          for name in names]
  ids = [live.run(['docker', 'inspect', '-f', '{{.Id}}', n]).stdout.strip() for n in names]
  original = token()

  def status(value, wanted, timeout=12):
    began = time.monotonic()
    def matched():
      return all(api.machine(value, '/api/users?limit=1')[0] == wanted for api in apis)
    live.wait_until(matched, f'both replicas status {wanted}', timeout)
    print(f'OBS t={live.elapsed():.2f}s status={wanted} both replicas after={time.monotonic()-began:.2f}s', flush=True)

  status(original, 503)
  live.check(all(api.machine('invalid', '/api/users')[0] == 401 for api in apis), 'invalid JWT cannot probe missing snapshot')
  tool('init')
  status(original, 200)
  live.check(True, 'initial sentinel makes both replicas ready without replacement')
  for api in apis:
    cookie = api.login_human(ldap.human_password)
    ensure(api.call('GET', '/api/users?limit=1', cookie)[0] == 200)
    ensure(api.call('POST', '/api/logout', cookie)[0] == 204)
  live.check(True, 'enabled empty snapshot preserves human login/read/logout')
  payload = json.loads(base64.urlsafe_b64decode(original.split('.')[1] + '=='))
  identifier = payload['jti']
  identifier_file = live.write_secret_file('jti', identifier)
  before = time.monotonic()
  tool('add', '--kind', 'jti', '--client', client, '--id-file', identifier_file)
  status(original, 401)
  elapsed = time.monotonic() - before
  live.check(elapsed <= 12, f'JTI revocation reaches both replicas within bound ({elapsed:.2f}s)')
  live.check(ids == [live.run(['docker', 'inspect', '-f', '{{.Id}}', n]).stdout.strip() for n in names],
             'both UI container IDs unchanged by revocation')
  tool('remove', '--cn', 'jti-' + identifier)
  status(original, 200)
  live.check(True, 'removing JTI restores both replicas')

  tool('add', '--kind', 'cutoff', '--client', client)
  status(original, 401)
  time.sleep(1.2)
  newer = token()
  status(newer, 200)
  stamped_row = ldap.admin_tool('ldapsearch', ['-LLL', '-b', BASE, '(cn=cutoff-*)', 'createTimestamp']).stdout
  server_stamp = next(line.split(': ', 1)[1] for line in stamped_row.splitlines() if line.startswith('createTimestamp: '))
  cutoff_epoch = int(datetime.datetime.strptime(server_stamp, '%Y%m%d%H%M%SZ').replace(tzinfo=datetime.timezone.utc).timestamp())
  new_claims = json.loads(base64.urlsafe_b64decode(newer.split('.')[1] + '=='))
  ensure(payload['iat'] <= cutoff_epoch < new_claims['iat'], 'cutoff does not match actual server timestamp')
  live.check(True, 'cutoff revokes old token while later-issued token passes (zero skew)')

  malformed = 'cn=bad,' + BASE
  ensure(ldap.admin_tool('ldapadd', [], f'dn: {malformed}\nobjectClass: device\ncn: bad\nou: {client}\n').returncode == 0)
  status(newer, 503)
  ensure(ldap.admin_tool('ldapdelete', [malformed]).returncode == 0)
  tool('heartbeat')
  status(newer, 200)
  live.check(True, 'malformed live entry fails closed after old snapshot expires, then recovers')

  # Hide all revocation rows with a real slapd ACL while searches still return rc 0.
  db = ldap.config_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=config',
                                    '(olcSuffix=' + BASE_DN + ')', 'dn']).stdout
  dbdn = next(line[4:] for line in db.splitlines() if line.startswith('dn: '))
  old = ldap.config_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', dbdn, '-s', 'base', 'olcAccess']).stdout
  acl = [line[len('olcAccess: '):] for line in old.splitlines() if line.startswith('olcAccess: ')]
  rule = f'{{0}}to dn.subtree="{BASE}" by dn.exact="{MACHINE_DN}" none by * break'
  ensure(ldap.config_tool('ldapmodify', [], f'dn: {dbdn}\nchangetype: modify\nadd: olcAccess\nolcAccess: {rule}\n').returncode == 0)
  status(newer, 503)
  restore = f'dn: {dbdn}\nchangetype: modify\nreplace: olcAccess\n' + ''.join('olcAccess: ' + a + '\n' for a in acl)
  ensure(ldap.config_tool('ldapmodify', [], restore).returncode == 0)
  tool('heartbeat')
  status(newer, 200)
  live.check(True, 'ACL-hidden revocation snapshot refuses authenticated callers and recovers')

  # A lower generation never replaces an already accepted snapshot.
  sentinel = 'cn=sentinel,' + BASE
  current = ldap.admin_tool('ldapsearch', ['-LLL', '-b', sentinel, '-s', 'base', 'serialNumber']).stdout
  generation = int(next(line.split(': ', 1)[1] for line in current.splitlines() if line.startswith('serialNumber: ')))
  ensure(ldap.admin_tool('ldapmodify', [], f'dn: {sentinel}\nchangetype: modify\nreplace: serialNumber\nserialNumber: 1\n').returncode == 0)
  status(newer, 503)
  ensure(ldap.admin_tool('ldapmodify', [], f'dn: {sentinel}\nchangetype: modify\nreplace: serialNumber\nserialNumber: {generation}\n').returncode == 0)
  tool('heartbeat')
  status(newer, 200)
  live.check(True, 'generation regression is refused; monotonic heartbeat recovers')

  ensure(live.run(['docker', 'stop', ldap.name]).returncode == 0)
  status(newer, 503, 15)
  ensure(live.run(['docker', 'start', ldap.name]).returncode == 0)
  live.wait_until(lambda: ldap.admin_tool('ldapsearch', ['-b', BASE_DN, '-s', 'base']).returncode == 0, 'LDAP restart', 30)
  tool('heartbeat')
  status(newer, 200)
  live.check(True, 'LDAP outage expires both snapshots; restored directory recovers')

  # Offline age fixtures are confined to this disposable LDAP volume. They
  # verify source/tool boundary behavior, not natural 4440-second wall-clock aging.
  cutoff_rows = ldap.admin_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', BASE,
                                             '(cn=cutoff-*)', 'cn']).stdout
  for line in cutoff_rows.splitlines():
    if line.startswith('cn: '):
      tool('remove', '--cn', line[4:])
  status(original, 200)
  tool('add', '--kind', 'jti', '--client', client, '--id-file', identifier_file)
  marker = 'aged-marker'
  marker_file = live.write_secret_file('aged-jti', marker)
  tool('add', '--kind', 'jti', '--client', client, '--id-file', marker_file)
  status(original, 401)
  stamped = int(time.time())
  modifications = ''
  for cn, age in [('jti-' + identifier, 590), ('jti-' + marker, 4470)]:
    value = datetime.datetime.fromtimestamp(stamped - age, datetime.timezone.utc).strftime('%Y%m%d%H%M%SZ')
    modifications += f'dn: cn={cn},{BASE}\nchangetype: modify\nreplace: createTimestamp\ncreateTimestamp: {value}\n\n'
  ensure(live.run(['docker', 'stop', '-t', '1', ldap.name]).returncode == 0)
  changed = live.run(['docker', 'run', '--rm', '-i', '--volumes-from', ldap.name,
                      '--entrypoint', 'slapmodify', live.ldap_image, '-F', '/etc/openldap/slapd.d', '-n', '1'],
                     input=modifications)
  ensure(changed.returncode == 0, 'offline age fixture failed')
  ensure(live.run(['docker', 'start', ldap.name]).returncode == 0)
  live.wait_until(lambda: ldap.admin_tool('ldapsearch', ['-b', BASE_DN, '-s', 'base']).returncode == 0, 'aged LDAP restart', 30)
  for cn, age in [('jti-' + identifier, 590), ('jti-' + marker, 4470)]:
    row = ldap.admin_tool('ldapsearch', ['-LLL', '-b', 'cn=' + cn + ',' + BASE, '-s', 'base', 'createTimestamp']).stdout
    expected = datetime.datetime.fromtimestamp(stamped - age, datetime.timezone.utc).strftime('%Y%m%d%H%M%SZ')
    ensure('createTimestamp: ' + expected in row, 'offline timestamp fixture not observed')
  tool('heartbeat')
  status(original, 401)
  status(newer, 200)
  physical = ldap.admin_tool('ldapsearch', ['-LLL', '-b', 'cn=jti-' + marker + ',' + BASE, '-s', 'base', 'createTimestamp'])
  ensure(physical.returncode == 32, 'heartbeat did not prune past-ret JTI')
  tool('prune')
  status(original, 401)
  status(newer, 200)
  live.check(True, 'offline age: heartbeat prunes past-ret JTI without downtime; near-TTL JTI remains revoked after prune')

  # Actual active-entry cap failure, independent of the operator's preventive cap.
  overflow = []
  for n in range(11):
    dn = f'cn=jti-overflow-{n},{BASE}'
    overflow.append(dn)
    ensure(ldap.admin_tool('ldapadd', [], f'dn: {dn}\nobjectClass: device\ncn: jti-overflow-{n}\nou: {client}\n').returncode == 0)
  status(newer, 503)
  for dn in overflow:
    ensure(ldap.admin_tool('ldapdelete', [dn]).returncode == 0)
  tool('heartbeat')
  status(newer, 200)
  live.check(True, 'active entry overflow fails closed on both replicas and recovers')

  # No heartbeat: even successful reads cannot indefinitely refresh an old sentinel.
  status(newer, 503, 42)
  tool('heartbeat')
  status(newer, 200)
  live.check(True, 'stopped heartbeat reaches sentinel-age plus stale failure and recovers')
  other = 'svc-not-allowed'
  other_secret = live.secret('client-' + os.urandom(18).hex())
  kc.create_client(realm, other, other_secret, scopes=READER)
  denied = kc.sa_token(realm, other, other_secret)
  tokens.append(denied)
  status(denied, 401)
  status(original, 401)
  status(newer, 200)
  live.check(True, 'allowlist denial and individual revocation combine while allowed fresh token passes')
  logs = live.all_logs()
  live.check(not any(value in logs for value in tokens + live.secret_values if len(value) >= 8), 'all container logs contain no tokens or secrets')
  print(f'All live revocation checks passed: {live.checks} checks in {live.elapsed():.0f}s.', flush=True)


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    live.dump_logs()
    raise
