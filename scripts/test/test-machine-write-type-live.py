#!/usr/bin/env python3
"""T-018: actual Go writer path enforces atomic target-type assertions."""
import os
import pathlib
import secrets
import subprocess
import tempfile
import time
import uuid

name = 'ldapium-write-type-' + uuid.uuid4().hex[:8]
base = 'dc=example,dc=org'
writer = 'cn=writer,' + base
user = 'uid=baseline,' + base
group = 'cn=baseline-group,' + base
other = 'uid=refint-consumer,' + base
password = secrets.token_hex(24)


def run(args, data=None, allowed=(0,)):
  result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=45)
  if result.returncode not in allowed:
    raise AssertionError('command failed rc=%d: %s' % (result.returncode,
      (result.stdout + result.stderr).replace(password, '<redacted>')))
  return result


def ldap(command, extra=(), data=None, dn=None, uri='ldap://127.0.0.1', allowed=(0,)):
  return run(['docker', 'exec', '-i', name, command, '-x', '-H', uri,
    '-D', dn or 'cn=admin,' + base, '-y', '/tmp/.write-type-password', *extra], data, allowed)


with tempfile.TemporaryDirectory(prefix='ldapium-write-type-') as temp:
  env = pathlib.Path(temp) / 'env'
  env.write_text('LDAP_ROOT_DN=' + base + '\nLDAP_ADMIN_PASSWORD=' + password + '\n')
  env.chmod(0o600)
  try:
    run(['docker', 'run', '-d', '--name', name, '--network', 'none', '--env-file', str(env),
      os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')])
    run(['docker', 'exec', '-i', name, 'sh', '-c', 'umask 077; cat > /tmp/.write-type-password'], password)
    for _ in range(60):
      if ldap('ldapsearch', ['-LLL', '-b', base, '-s', 'base', 'dn'], allowed=(0, 255)).returncode == 0:
        break
      time.sleep(1)
    else:
      raise AssertionError('LDAP startup timeout')
    ldap('ldapadd', data=f'''dn: {writer}
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: writer
userPassword: {password}

dn: {user}
objectClass: inetOrgPerson
uid: baseline
cn: Baseline
sn: Name

dn: {group}
objectClass: groupOfNames
cn: baseline-group
member: {writer}
''')
    ldap('ldapmodify', dn='cn=admin,cn=config',
      uri='ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi', data=f'''dn: olcDatabase={{1}}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {{0}}to attrs=userPassword by anonymous auth by * none
olcAccess: {{1}}to * by dn.exact="{writer}" write by * read
''')
    binary = os.environ.get('LDAPIUM_WRITE_TYPE_TEST_BINARY', '/tmp/ldapium-write-type-test')
    run(['docker', 'cp', binary, name + ':/tmp/.write-type-test'])
    result = run(['docker', 'exec', '-e', 'LDAPIUM_WRITE_TYPE_LIVE=1', name,
      '/tmp/.write-type-test', '-test.run', '^TestMachineWriteTypeAssertionLive$', '-test.v'])
    print(result.stdout)
    for dn in (user, group):
      ldap('ldapsearch', ['-LLL', '-b', dn, '-s', 'base', 'dn'])
    result = ldap('ldapsearch', ['-LLL', '-b', user, '-s', 'base', 'mail'])
    assert 'mail: baseline@example.org' in result.stdout
    assert 'forbidden@example.org' not in result.stdout
    result = ldap('ldapsearch', ['-LLL', '-b', group, '-s', 'base', 'member'])
    assert 'member: ' + user in result.stdout
    logs = run(['docker', 'logs', name])
    assert password not in logs.stdout + logs.stderr
    print('PASS both wrong-type targets survive, correct attributes change and credential logs are clean')
  finally:
    subprocess.run(['docker', 'rm', '-f', '-v', name], capture_output=True)
