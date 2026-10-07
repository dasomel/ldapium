#!/usr/bin/env python3
"""Real slapd writer/CAS proof; owns only its uniquely named container."""
import argparse
import concurrent.futures
import importlib.util
import json
import os
import pathlib
import secrets
import subprocess
import tempfile
import threading
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('revocation_tool', ROOT / 'scripts/lib/machine_revocation.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
name = 'ldapium-revtool-' + uuid.uuid4().hex[:8]
base = 'dc=example,dc=org'
revbase = 'ou=revocations,ou=system,' + base
password = secrets.token_urlsafe(32)


def run(cmd, data=None, accepted=(0,)):
  p = subprocess.run(cmd, input=data, text=True, capture_output=True, timeout=90)
  if p.returncode not in accepted:
    raise AssertionError('command failed rc=%d: %s' % (p.returncode, p.stderr.replace(password, '<redacted>')))
  return p


def ldap(tool, extra=(), data=None, accepted=(0,)):
  return run(['docker', 'exec', '-i', name, tool, '-x', '-H', 'ldap://127.0.0.1',
    '-D', 'cn=admin,' + base, '-y', '/tmp/.revtool-password', *extra], data, accepted)


def tool(command, extra=(), accepted=(0,)):
  return run(['bash', str(ROOT / 'scripts/machine-revocation.sh'), command,
    '--container', name, '--uri', 'ldap://127.0.0.1', '--base', revbase,
    '--bind-dn', 'cn=admin,' + base, '--password-file', '/tmp/.revtool-password', *extra], accepted=accepted)


with tempfile.TemporaryDirectory(prefix='ldapium-revtool-') as tmp:
  tmp = pathlib.Path(tmp)
  env = tmp / 'env'
  env.write_text('LDAP_ADMIN_PASSWORD=' + password + '\nLDAP_ROOT_DN=' + base + '\n')
  env.chmod(0o600)
  try:
    run(['docker', 'run', '-d', '--name', name, '--network', 'none', '--env-file', str(env),
         os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')])
    for _ in range(90):
      run(['docker', 'exec', '-i', name, 'sh', '-c', 'umask 077; cat > /tmp/.revtool-password'], password)
      if ldap('ldapsearch', ['-LLL', '-b', base, '-s', 'base', 'dn'], accepted=(0, 255)).returncode == 0:
        break
      time.sleep(1)
    else:
      raise AssertionError('LDAP startup timeout')
    for dn, ou in [('ou=system,' + base, 'system'), (revbase, 'revocations')]:
      ldap('ldapadd', data=module.ldif([('dn', dn), ('objectClass', 'organizationalUnit'), ('ou', ou)]) + '\n', accepted=(0, 68))
    assert tool('heartbeat', accepted=(1,)).returncode == 1
    tool('init')
    assert tool('init', accepted=(1,)).returncode == 1
    identifier = tmp / 'jti'
    identifier.write_text('live-jti')
    tool('add', ['--kind', 'jti', '--client', 'tool-client', '--id-file', str(identifier)])
    tool('add', ['--kind', 'jti', '--client', 'tool-client', '--id-file', str(identifier)])
    assert tool('add', ['--kind', 'jti', '--client', 'other-client', '--id-file', str(identifier)], accepted=(1,)).returncode == 1
    identifier.write_text('LIVE-JTI')
    assert tool('add', ['--kind', 'jti', '--client', 'tool-client', '--id-file', str(identifier)], accepted=(1,)).returncode == 1
    for invalid in ['bad\njti', 'bad\x00jti', 'header.payload.signature']:
      identifier.write_text(invalid)
      assert tool('add', ['--kind', 'jti', '--client', 'tool-client', '--id-file', str(identifier)], accepted=(1,)).returncode == 1
    identifier.write_text('live-jti')
    print('PASS identifier files reject newline, NUL, and bearer JWT')
    print('PASS repeat JTI is idempotent; case-fold/client collisions are refused')
    tool('add', ['--kind', 'cutoff', '--client', 'tool-client'])
    time.sleep(1)
    tool('add', ['--kind', 'cutoff', '--client', 'tool-client'])
    args = argparse.Namespace(container=name, uri='ldap://127.0.0.1', base=revbase,
      bind_dn='cn=admin,' + base, password_file='/tmp/.revtool-password', retention=4440, max_entries=2000)
    sent, entries = module.Directory(args).search()
    assert len([e for e in entries if e['cn'][0].startswith('cutoff-')]) == 1
    print('PASS init, duplicate init refusal, jti, cutoff replacement')

    # Force the two first modifications to carry the same old values, then let
    # actual ldapmodify/slapd decide the race; no LDAP replies are synthesized.
    barrier = threading.Barrier(2)
    results = []
    lock = threading.Lock()
    def publish():
      d = module.Directory(argparse.Namespace(**vars(args)))
      original = d.run
      first = True
      def gated(tool_name, extra=(), data=None, allowed=(0,)):
        nonlocal first
        if tool_name == 'ldapmodify' and first:
          first = False
          barrier.wait(timeout=20)
        result = original(tool_name, extra, data, allowed)
        if tool_name == 'ldapmodify':
          with lock:
            results.append(result.returncode)
        return result
      d.run = gated
      d.publish()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
      list(pool.map(lambda _: publish(), range(2)))
    assert sorted(results) == [0, 0, 16], results
    print('PASS real concurrent CAS: one rc 16, reread/retry succeeds')
    rows = tmp / 'rows.json'
    sent, entries = module.Directory(args).search()
    rows.write_text(json.dumps([sent, *entries]))
    goenv = dict(os.environ, LDAPIUM_REVOCATION_ROWS=str(rows))
    p = subprocess.run(['go', 'test', './internal/machineauth', '-run', 'TestRevocationTool', '-count=1', '-v'],
      cwd=ROOT / 'ui/backend', env=goenv, text=True, capture_output=True, timeout=90)
    assert p.returncode == 0, p.stdout + p.stderr
    print(p.stdout.strip())
    print('PASS live tool digest/count/sentinel validated by Go; JTI revokes')
    tool('prune')
    _, entries = module.Directory(args).search()
    assert any(e['cn'] == ['jti-live-jti'] for e in entries)
    print('PASS prune retains fresh JTI')
    straydn = 'cn=stray,' + revbase
    ldap('ldapadd', data=module.ldif([('dn', straydn), ('objectClass', 'organizationalRole'), ('cn', 'stray')]) + '\n')
    for command in ['add', 'heartbeat', 'remove', 'prune']:
      assert tool(command, accepted=(1,)).returncode == 1
    ldap('ldapdelete', [straydn])
    print('PASS non-device stray blocks every mutation')
    # Multi-valued cn and newline are real LDAP attributes, not parser fixtures.
    for value in ['extra-cn', 'bad\ncn']:
      dn = 'cn=jti-live-jti,' + revbase
      ldap('ldapmodify', data=module.ldif([('dn', dn)]) + 'changetype: modify\nadd: cn\n' + module.ldif([('cn', value)]) + '\n')
      assert tool('heartbeat', accepted=(1,)).returncode == 1
      ldap('ldapmodify', data=module.ldif([('dn', dn)]) + 'changetype: modify\ndelete: cn\n' + module.ldif([('cn', value)]) + '\n')
    print('PASS multi-valued/newline cn blocks publication')
    tool('remove', ['--cn', 'jti-live-jti'])
    assert tool('remove', ['--cn', 'sentinel'], accepted=(1,)).returncode == 1
    tool('heartbeat')
    print('PASS explicit remove, sentinel deletion refusal, heartbeat')
    logs = run(['docker', 'logs', name])
    assert password not in logs.stdout + logs.stderr
    print('PASS container logs contain no credential')
    print('NOT VERIFIED: aged createTimestamp prune boundary (server-owned, 4440s minimum)')
  finally:
    logs = subprocess.run(['docker', 'logs', name], text=True, capture_output=True)
    (pathlib.Path('/tmp') / (name + '.log')).write_text((logs.stdout + logs.stderr).replace(password, '<redacted>'))
    subprocess.run(['docker', 'rm', '-f', '-v', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
