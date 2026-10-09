#!/usr/bin/env python3
"""Run existing machine contracts with an initialized, empty revocation snapshot.

Only fixture startup and bind accounting change. HTTP assertions stay in the
original scripts. Accesslog sessions that read the revocation base are background
source connections, and are excluded from the request-bind counter.
"""
import pathlib
import re
import runpy
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/lib'))
from machine_live import ADMIN_DN, BASE_DN, Live, Slapd, ensure  # noqa: E402

BASE = 'ou=revocations,ou=system,' + BASE_DN
original_acl = Slapd.apply_acl
original_start = Live.start_ui


def acl(self, *args, **kwargs):
  result = original_acl(self, *args, **kwargs)
  # D1: create once, keep no active entries. Cost: separate fixture state;
  # escape hatch: run the original script directly for feature-off evidence.
  exists = self.admin_tool('ldapsearch', ['-LLL', '-b', BASE, '-s', 'base', 'dn'])
  if exists.returncode != 0:
    ensure(self.admin_tool('ldapadd', [], f'dn: {BASE}\nobjectClass: organizationalUnit\nou: revocations\n').returncode == 0)
    command = [str(ROOT / 'scripts/machine-revocation.sh'), 'init', '--container', self.name,
               '--uri', 'ldap://127.0.0.1', '--base', BASE, '--bind-dn', ADMIN_DN,
               '--password-file', '/tmp/.pw-admin']
    result_init = self.live.run(command)
    ensure(result_init.returncode == 0, self.live.mask(result_init.stderr))
  return result


def start(self, name, ldap_url, env, hold_secrets, *args, **kwargs):
  configured = dict(env)
  if configured.get('MACHINE_AUTH_ENABLED') == 'true':
    configured.update({'MACHINE_REVOCATION_ENABLED': 'true', 'MACHINE_REVOCATION_REFRESH': '60s',
                       'MACHINE_REVOCATION_MAX_STALE': '180s', 'MACHINE_REVOCATION_SENTINEL_MAX_AGE': '1h',
                       'MACHINE_REVOCATION_BASE_DN': BASE, 'METRICS_ADDR': '0.0.0.0:9090'})
    kwargs['extra_docker'] = tuple(kwargs.get('extra_docker', ())) + ('-p', '127.0.0.1::9090')
  api = original_start(self, name, ldap_url, configured, hold_secrets, *args, **kwargs)
  if configured.get('MACHINE_AUTH_ENABLED') == 'true' and kwargs.get('wait', True):
    # D3: observe completion instead of assuming one second is enough. Cost:
    # a loopback-only fixture metrics port; escape hatch: direct feature-off runs.
    # The wrong-password contract intentionally completes with refresh failure.
    port = self.published_port(name, '9090/tcp')
    ensure(port, 'fixture metrics port unavailable')
    def refreshed():
      try:
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/metrics', timeout=1) as response:
          metrics = response.read().decode()
        return any(float(value) > 0 for value in re.findall(
          r'^ldapium_ui_machine_revocation_refresh_total\{result="(?:success|failure)"\} (\S+)$', metrics, re.M))
      except (OSError, ValueError):
        return False
    self.wait_until(refreshed, 'first actual revocation refresh completion', 15)
  return api


def binds(self, dn):
  result = self.tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=accesslog',
                                  '(|(reqType=bind)(reqType=search))', 'reqType', 'reqDN', 'reqSession'],
                     'cn=admin,cn=accesslog', '/tmp/.pw-admin')
  ensure(result.returncode == 0, 'accesslog query failed')
  rows = []
  for block in result.stdout.split('\n\n'):
    row = dict(re.findall(r'^(reqType|reqDN|reqSession): (.*)$', block, re.M))
    if row:
      rows.append(row)
  source = {r.get('reqSession') for r in rows if r.get('reqType') == 'search' and r.get('reqDN') == BASE}
  # D2: exclude only positively identified source sessions. Cost: live accesslog
  # must expose reqSession; escape hatch: fail rather than silently count zero.
  targeted = [r for r in rows if r.get('reqType') == 'bind' and r.get('reqDN') == dn]
  ensure(all(r.get('reqSession') for r in targeted), 'bind missing accesslog session')
  return sum(r['reqSession'] not in source for r in targeted)


def main():
  allowed = {'test-machine-keycloak-live.py', 'test-machine-keycloak-settings-live.py',
             'test-machine-jwks-live.py', 'test-machine-revocation-drill.py'}
  ensure(len(sys.argv) == 2 and sys.argv[1] in allowed, 'select an existing machine contract script')
  Slapd.apply_acl = acl
  Slapd.binds = binds
  Live.start_ui = start
  script = ROOT / 'scripts/test' / sys.argv[1]
  sys.argv = [str(script)]
  runpy.run_path(str(script), run_name='__main__')


if __name__ == '__main__':
  main()
