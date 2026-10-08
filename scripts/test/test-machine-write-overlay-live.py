#!/usr/bin/env python3
"""T-002: real memberOf writes are independent of the writer's user ACL."""
import os
import pathlib
import secrets
import subprocess
import tempfile
import time
import uuid

name = 'ldapium-write-overlay-' + uuid.uuid4().hex[:8]
base = 'dc=example,dc=org'
writer = 'cn=writer,' + base
user = 'uid=baseline,' + base
group = 'cn=baseline-group,' + base
password = secrets.token_hex(24)


def run(args, data=None, allowed=(0,)):
  result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=45)
  if result.returncode not in allowed:
    raise AssertionError('command failed rc=%d: %s' % (result.returncode,
      result.stderr.replace(password, '<redacted>')))
  return result


def ldap(command, extra=(), data=None, dn=None, uri='ldap://127.0.0.1', allowed=(0,)):
  return run(['docker', 'exec', '-i', name, command, '-x', '-H', uri,
    '-D', dn or 'cn=admin,' + base, '-y', '/tmp/.overlay-password', *extra], data, allowed)


with tempfile.TemporaryDirectory(prefix='ldapium-write-overlay-') as temp:
  env = pathlib.Path(temp) / 'env'
  env.write_text('LDAP_ROOT_DN=' + base + '\nLDAP_ADMIN_PASSWORD=' + password + '\n')
  env.chmod(0o600)
  try:
    run(['docker', 'run', '-d', '--name', name, '--network', 'none', '--env-file', str(env),
      os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')])
    run(['docker', 'exec', '-i', name, 'sh', '-c', 'umask 077; cat > /tmp/.overlay-password'], password)
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
olcAccess: {{1}}to dn.exact="{group}" attrs=member by dn.exact="{writer}" write by * break
olcAccess: {{2}}to * by dn.exact="{writer}" read by * read
''')
    # Same identity cannot directly write memberOf, even before/after overlay updates.
    assert ldap('ldapmodify', dn=writer, data=f'dn: {user}\nchangetype: modify\nreplace: cn\ncn: Forbidden\n', allowed=(50,)).returncode == 50
    forbidden = f'dn: {user}\nchangetype: modify\nreplace: memberOf\nmemberOf: {group}\n'
    assert ldap('ldapmodify', dn=writer, data=forbidden, allowed=(19,)).returncode == 19
    ldap('ldapmodify', dn=writer, data=f'dn: {group}\nchangetype: modify\nadd: member\nmember: {user}\n')
    result = ldap('ldapsearch', ['-LLL', '-b', user, '-s', 'base', 'memberOf'])
    assert 'memberOf: ' + group in result.stdout
    assert ldap('ldapmodify', dn=writer, data=forbidden, allowed=(19,)).returncode == 19
    print('PASS writer cannot Modify user cn (rc50) or memberOf (rc19 schema restriction), but permitted member Add updates it')
    ldap('ldapmodify', dn=writer, data=f'dn: {group}\nchangetype: modify\ndelete: member\nmember: {user}\n')
    result = ldap('ldapsearch', ['-LLL', '-b', user, '-s', 'base', 'memberOf'])
    assert 'memberOf:' not in result.stdout
    print('PASS permitted member Delete clears overlay memberOf despite user write denial')
    logs = run(['docker', 'logs', name])
    assert password not in logs.stdout + logs.stderr
    print('PASS container logs contain no credential')
  finally:
    subprocess.run(['docker', 'rm', '-f', '-v', name], capture_output=True)
