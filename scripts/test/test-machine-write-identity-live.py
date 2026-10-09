#!/usr/bin/env python3
"""T-018: read identity verifies server entryDN/UUID and protected targets."""
import os
import pathlib
import secrets
import subprocess
import tempfile
import time
import uuid

name = 'ldapium-write-identity-' + uuid.uuid4().hex[:8]
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
    '-D', dn or 'cn=admin,' + base, '-y', '/tmp/.write-identity-password', *extra], data, allowed)


with tempfile.TemporaryDirectory(prefix='ldapium-write-identity-') as temp:
  env = pathlib.Path(temp) / 'env'
  env.write_text('LDAP_ROOT_DN=' + base + '\nLDAP_ADMIN_PASSWORD=' + password + '\n')
  env.chmod(0o600)
  try:
    run(['docker', 'run', '-d', '--name', name, '--network', 'none', '--env-file', str(env),
      os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')])
    run(['docker', 'exec', '-i', name, 'sh', '-c', 'umask 077; cat > /tmp/.write-identity-password'], password)
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
    reader = 'cn=reader,' + base
    ldap('ldapadd', data=f'dn: {reader}\nobjectClass: organizationalRole\nobjectClass: simpleSecurityObject\ncn: reader\nuserPassword: {password}\n')
    assert ldap('ldapmodify', dn=reader, data=f'dn: {user}\nchangetype: modify\nreplace: cn\ncn: Forbidden\n', allowed=(50,)).returncode == 50
    binary = os.environ.get('LDAPIUM_WRITE_IDENTITY_TEST_BINARY', '/tmp/ldapium-write-identity-test')
    run(['docker', 'cp', binary, name + ':/tmp/.write-identity-test'])
    result = run(['docker', 'exec', '-e', 'LDAPIUM_WRITE_IDENTITY_LIVE=1', name,
      '/tmp/.write-identity-test', '-test.run', '^TestMachineWriteIdentityLive$', '-test.v'])
    print(result.stdout)
    for deny in ('uuid', 'all'):
      rule = f'to attrs=entryUUID by dn.exact="{reader}" none by * break' if deny == 'uuid' else f'to * by dn.exact="{reader}" none by * break'
      ldap('ldapmodify', dn='cn=admin,cn=config',
        uri='ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi', data=f"""dn: olcDatabase={{1}}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {{0}}to attrs=userPassword by anonymous auth by * none
olcAccess: {{1}}{rule}
olcAccess: {{2}}to * by dn.exact="{writer}" write by * read
""")
      result = run(['docker', 'exec', '-e', 'LDAPIUM_WRITE_IDENTITY_LIVE=1',
        '-e', 'LDAPIUM_WRITE_IDENTITY_DENIED_READ=1', name, '/tmp/.write-identity-test',
        '-test.run', '^TestMachineWriteIdentityLive$', '-test.v'])
      print(deny + ' ACL: ' + result.stdout)
    logs = run(['docker', 'logs', name])
    assert password not in logs.stdout + logs.stderr
    print('PASS actual M read proof, no directory writes performed by reader and credentials absent from logs')
  finally:
    subprocess.run(['docker', 'rm', '-f', '-v', name], capture_output=True)
