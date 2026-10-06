#!/usr/bin/env python3
"""Live read-only proof of the machine LDAP account's ACL (#214, staged unit 3).

docs/changes/machine-principal-auth, T-015 / T-026 / AC-018, against real slapd.
Applies the documented procedure (docs/machine-ldap-account.md) to THREE freshly
initialised containers and proves, as the machine DN M with allowed subtree B:

  (a) LDAP_ANONYMOUS_READ_BASE unset
  (b) LDAP_ANONYMOUS_READ_BASE set (to B)
  (c) an operator added a leading allow rule (`{0}to attrs=description by users
      write`) before the machine rules were applied

In each configuration:
  - the olcAccess read back after applying is exactly the three machine rules at
    {0}-{2} (text compared with the committed LDIF) followed by EVERY pre-existing
    rule in its original order (the operator's extra rule included);
  - M binds, reads entries and attributes inside B, never sees userPassword,
    shadowLastChange, pwdHistory (or any attribute of the secret list) even with
    explicit requests, `*`, `+` or a filter on them, and sees nothing outside B
    (no entry, no uid/objectClass/entry hint); the outside-B answers are identical
    in all three configurations;
  - M cannot write anywhere: add, modify, delete, modrdn, its own password
    (ldappasswd, ldapmodify of userPassword/shadowLastChange) or its own entry,
    all insufficient access (50); a control proves M COULD write before the rules;
  - M reads nothing from cn=config, cn=Monitor or cn=accesslog (controls prove
    those databases hold entries);
  - admin, anonymous and an ordinary user get byte-identical results for a fixed
    probe set before and after the rules, an ordinary user still changes their own
    password, and the accesslog/monitor databases' own rules are untouched;
  - the documented rollback restores the original olcAccess byte for byte and
    M is back to its pre-rules reach; the rollback refuses to run twice.
  - the LDIF blocks in the operator guide are the committed fixtures.

Mutation self-test (the proof must FAIL when the rules are broken). The same script
applies a broken variant of the documented LDIF when LDAPIUM_ACL_MUTATE is set:
  LDAPIUM_ACL_MUTATE=reorder    machine rules after the image's `by self write` rule
  LDAPIUM_ACL_MUTATE=widen      the allowed subtree widened to the whole base
  LDAPIUM_ACL_MUTATE=nosecret   the secret-attribute deny rule dropped
Each makes this script exit non-zero (scripts print every failed check).

Run (the image defaults to the name the other live scripts use):
  python3 scripts/test/test-machine-acl-readonly-live.py
Override LDAPIUM_IMAGE / LDAPIUM_TEST_PREFIX as needed. Needs docker only; the
containers run with --network none, and every secret goes through 0600 files.
"""
import atexit
import base64
import os
import pathlib
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import uuid

repo_root = pathlib.Path(__file__).resolve().parents[2]
fixtures = repo_root / 'scripts/test/fixtures/machine-acl'
guide_path = repo_root / 'docs/machine-ldap-account.md'
ldap_image = os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')
prefix = os.environ.get('LDAPIUM_TEST_PREFIX', 'ldapium-macl-')
mutation = os.environ.get('LDAPIUM_ACL_MUTATE', '')
assert mutation in ('', 'reorder', 'widen', 'nosecret'), 'LDAPIUM_ACL_MUTATE must be reorder, widen or nosecret'
run_id = uuid.uuid4().hex[:6]
name_prefix = prefix + run_id

base_dn = 'dc=example,dc=org'
allowed_dn = 'ou=people,' + base_dn          # B
machine_dn = 'uid=machine,ou=system,' + base_dn  # M, outside B
admin_dn = 'cn=admin,' + base_dn
cfg_dn = 'cn=admin,cn=config'
ldapi_uri = 'ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi'
ldap_uri = 'ldap://127.0.0.1'

admin_password = secrets.token_urlsafe(24)
machine_password = secrets.token_urlsafe(32)
human_password = 'Human-' + secrets.token_urlsafe(18)

containers = []
tmp_dirs = []
passed = 0
failed = []
start = time.monotonic()
GLOBAL_DEADLINE_S = 1500


def check(condition, message):
  global passed
  if condition:
    passed += 1
    print('PASS: ' + message, flush=True)
  else:
    failed.append(message)
    print('FAIL: ' + message, flush=True)


def require(condition, message):
  assert condition, message


def mask(text):
  text = text if isinstance(text, str) else str(text)
  for secret in (admin_password, machine_password, human_password):
    text = text.replace(secret, '***')
  return text


def run(cmd, input_data=None, timeout=120):
  return subprocess.run(cmd, capture_output=True, text=True, input=input_data, timeout=timeout)


def cleanup():
  # Registered names are removed even if creation never happened; -v takes the
  # anonymous data volumes with them. Only this run's own objects.
  for c in containers:
    subprocess.run(['docker', 'rm', '-fv', c], capture_output=True, text=True)
  for d in tmp_dirs:
    subprocess.run(['rm', '-rf', d], capture_output=True, text=True)


atexit.register(cleanup)


def on_signal(*_):
  sys.exit(130)


def on_alarm(*_):
  print(f'FAIL: global deadline of {GLOBAL_DEADLINE_S}s exceeded', flush=True)
  sys.exit(124)


for _sig in (signal.SIGTERM, signal.SIGINT):
  signal.signal(_sig, on_signal)
signal.signal(signal.SIGALRM, on_alarm)
signal.alarm(GLOBAL_DEADLINE_S)


def wait_until(predicate, what, timeout=90.0):
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if predicate():
      return
    time.sleep(0.5)
  raise AssertionError(f'timed out after {timeout}s waiting for {what}')


# ---- container helpers (docker exec -i always: the stdin must reach the tool) ---

class Node:
  def __init__(self, name, anon_base):
    self.name = name
    self.container = f'{name_prefix}-{name}'
    self.anon_base = anon_base
    self.main_db = ''
    self.human_pw = human_password
    self.machine_pw = machine_password
    self.rules_before = []
    self.raw_before = ''

  def sh(self, script, input_data=None, env=None, timeout=120):
    cmd = ['docker', 'exec', '-i']
    for k, v in (env or {}).items():
      cmd += ['-e', f'{k}={v}']
    return run(cmd + [self.container, 'sh', '-c', script], input_data, timeout)

  def put(self, path, text):
    res = self.sh(f'umask 077; cat > {path}', text)
    require(res.returncode == 0, 'put ' + path + ': ' + res.stderr)

  def tool(self, tool, args, dn=None, pw='', uri=ldap_uri, input_data=None):
    cmd = ['docker', 'exec', '-i', self.container, tool, '-x', '-H', uri]
    if dn:
      cmd += ['-D', dn, '-y', pw]
    return run(cmd + args, input_data)

  def admin(self, tool, args, input_data=None):
    return self.tool(tool, args, admin_dn, '/tmp/.pw-admin', input_data=input_data)

  def cfg(self, tool, args, input_data=None):
    return self.tool(tool, args, cfg_dn, '/tmp/.pw-admin', ldapi_uri, input_data)

  def machine(self, tool, args, input_data=None):
    return self.tool(tool, args, machine_dn, '/tmp/.pw-machine', input_data=input_data)

  def human(self, tool, args, input_data=None):
    return self.tool(tool, args, 'uid=human,' + allowed_dn, '/tmp/.pw-human', input_data=input_data)

  def anon(self, tool, args):
    return self.tool(tool, args)

  def start(self):
    containers.append(self.container)  # before creation: cleanup knows it
    envfile = os.path.join(secret_dir, self.name + '.env')
    fd = os.open(envfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
      f.write(f'LDAP_ADMIN_PASSWORD={admin_password}\n')
    cmd = ['docker', 'run', '-d', '--name', self.container, '--network', 'none', '--env-file', envfile,
           '-e', 'LDAP_ROOT_DN=' + base_dn, '-e', 'LDAP_ACCESSLOG_ENABLED=true',
           '-e', 'LDAP_ACCESSLOG_OPS=writes reads bind']
    if self.anon_base:
      cmd += ['-e', 'LDAP_ANONYMOUS_READ_BASE=' + self.anon_base]
    res = run(cmd + [ldap_image])
    require(res.returncode == 0, 'docker run: ' + res.stderr)

    def ready():
      if self.sh('umask 077; cat > /tmp/.pw-admin', admin_password).returncode != 0:
        return False
      return self.admin('ldapsearch', ['-b', base_dn, '-s', 'base', 'dn']).returncode == 0
    wait_until(ready, f'{self.name}: slapd readiness')
    self.put('/tmp/.pw-machine', machine_password)
    self.put('/tmp/.pw-human', human_password)

  def change_own_password(self, dn, who, old, new):
    """The self-service path this image accepts: pwdSafeModify wants the old value
    deleted and the new one added in ONE modify (a replace, or ldappasswd, is refused by
    the policy overlay before any ACL decides, so it cannot prove an ACL)."""
    ldif = (f'dn: {dn}\nchangetype: modify\ndelete: userPassword\nuserPassword: {old}\n-\n'
            f'add: userPassword\nuserPassword: {new}\n')
    return who('ldapmodify', [], ldif)

  def stop(self):
    run(['docker', 'rm', '-fv', self.container])
    containers.remove(self.container)

  # ---- cn=config reads --------------------------------------------------------

  def olc_access(self, db_dn=None):
    res = self.cfg('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', db_dn or self.main_db, '-s', 'base', 'olcAccess'])
    require(res.returncode == 0, 'read olcAccess: ' + mask(res.stderr))
    return res.stdout, re.findall(r'^olcAccess: (.*)$', res.stdout, re.M)


secret_dir = tempfile.mkdtemp(prefix='macl-secrets-')
os.chmod(secret_dir, 0o700)
tmp_dirs.append(secret_dir)


def norm(text):
  return re.sub(r'\s+', ' ', text).strip()


def dn_set(out):
  return sorted(l[4:].strip().lower() for l in out.splitlines() if l.startswith('dn: '))


def has_attr(out, *names):
  wanted = tuple(n.lower() + ':' for n in names)
  return any(l.lower().startswith(wanted) for l in out.splitlines())


def mod_ldif(dn, op, attr, value=None):
  body = f'dn: {dn}\nchangetype: modify\n{op}: {attr}\n'
  if value is not None:
    body += f'{attr}: {value}\n'
  return body


# ---- the committed LDIF, the operator guide and the mutations --------------------

def fixture_text(name):
  return (fixtures / name).read_text()


def ldif_values(text):
  """olcAccess values of an LDIF (comments dropped, folded lines joined)."""
  values = []
  for line in text.splitlines():
    if line.startswith('#'):
      continue
    if line.startswith('olcAccess: '):
      values.append(line[len('olcAccess: '):])
    elif line.startswith(' ') and values:
      values[-1] += line[1:]
  return values


def guide_blocks():
  text = guide_path.read_text()
  return [b.strip() for b in re.findall(r'```ldif\n(.*?)```', text, re.S)]


def significant(text):
  return [l.rstrip() for l in text.splitlines() if l.strip() and not l.startswith('#')]


def mutate(text):
  """Broken variants of the documented LDIF, for the mutation self-test only."""
  if mutation == 'reorder':
    return re.sub(r'olcAccess: \{(\d)\}', lambda m: f'olcAccess: {{{int(m.group(1)) + 1}}}', text)
  if mutation == 'widen':
    return text.replace('to dn.subtree="@ALLOWED_DN@"', f'to dn.subtree="{base_dn}"')
  if mutation == 'nosecret':
    lines = text.splitlines(keepends=True)
    out, skip = [], False
    for line in lines:
      if line.startswith('olcAccess: {0}'):
        skip = True
        continue
      if skip and line.startswith(' '):
        continue
      skip = False
      out.append(line)
    text = ''.join(out)
    text = text.replace('olcAccess: {1}', 'olcAccess: {0}').replace('olcAccess: {2}', 'olcAccess: {1}')
    return text
  return text


# The documented apply command: the committed LDIF goes in on stdin, the three
# values are substituted inside the container, ldapmodify binds as the config
# admin over the local ldapi socket (the image gives ldapi EXTERNAL no cn=config
# access; see the guide).
APPLY = ('sed -e "s|@MACHINE_DN@|$MACHINE_DN|g" -e "s|@ALLOWED_DN@|$ALLOWED_DN|g" '
         '-e "s|@MAIN_DB_DN@|$MAIN_DB_DN|g" | '
         'ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin')

# The documented discovery of the main database's config DN (the guide pipes it
# through `sed -n 's/^dn: //p'`).
DISCOVER = 'ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -b cn=config "(olcSuffix=$ROOT_DN)" dn'

# The documented rollback: refuse unless {0}-{2} are the machine rules, then
# delete exactly those three indexes (highest first).
ROLLBACK = r'''
n=$(ldapsearch -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin -LLL -o ldif-wrap=no \
      -b "$MAIN_DB_DN" -s base olcAccess \
    | grep -c "^olcAccess: {[0-2]}.*dn.exact=\"$MACHINE_DN\"")
if [ "$n" != 3 ]; then echo "refusing: {0}-{2} are not the machine rules" >&2; exit 1; fi
printf "dn: %s\nchangetype: modify\ndelete: olcAccess\nolcAccess: {2}\nolcAccess: {1}\nolcAccess: {0}\n" "$MAIN_DB_DN" \
  | ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin
'''


def proc_env(node):
  return {'MACHINE_DN': machine_dn, 'ALLOWED_DN': allowed_dn, 'MAIN_DB_DN': node.main_db, 'CFG_URI': ldapi_uri}


# ---- seed data ---------------------------------------------------------------------

def seed(node):
  pw_b64 = base64.b64encode(machine_password.encode()).decode()
  ldif = f"""dn: ou=people,{base_dn}
objectClass: organizationalUnit
ou: people

dn: ou=groups,{base_dn}
objectClass: organizationalUnit
ou: groups

dn: ou=other,{base_dn}
objectClass: organizationalUnit
ou: other

dn: ou=system,{base_dn}
objectClass: organizationalUnit
ou: system

dn: {machine_dn}
objectClass: inetOrgPerson
uid: machine
cn: machine
sn: machine
userPassword:: {pw_b64}

dn: uid=outsider,ou=other,{base_dn}
objectClass: inetOrgPerson
uid: outsider
cn: outsider
sn: outsider
userPassword: Outsider-{secrets.token_urlsafe(12)}

dn: uid=human,{allowed_dn}
objectClass: inetOrgPerson
uid: human
cn: human
sn: human
userPassword: {human_password}

dn: cn=g01,ou=groups,{base_dn}
objectClass: groupOfNames
cn: g01
member: uid=u01,{allowed_dn}
"""
  for i in range(1, 4):
    ldif += f"""
dn: uid=u0{i},{allowed_dn}
objectClass: inetOrgPerson
objectClass: shadowAccount
uid: u0{i}
cn: User {i}
sn: User{i}
shadowLastChange: 19000
userPassword: Initial-{secrets.token_urlsafe(12)}
"""
  res = node.admin('ldapadd', [], ldif)
  require(res.returncode == 0, 'seed ldapadd: ' + mask(res.stderr))
  # M gets shadowAccount so a shadowLastChange write is an ACL decision, not a schema error.
  res = node.admin('ldapmodify', [], f'dn: {machine_dn}\nchangetype: modify\nadd: objectClass\nobjectClass: shadowAccount\n-\n'
                   'add: shadowLastChange\nshadowLastChange: 19000\n')
  require(res.returncode == 0, 'seed M shadowAccount: ' + mask(res.stderr))
  # Change the human's password once so a pwdHistory value exists (the default policy keeps 5).
  new_pw = human_password + 'x'
  res = node.change_own_password(f'uid=human,{allowed_dn}', node.human, human_password, new_pw)
  require(res.returncode == 0, 'seed human password change: ' + mask(res.stderr))
  node.put('/tmp/.pw-human', new_pw)
  node.human_pw = new_pw
  res = node.sh(DISCOVER, None, {'ROOT_DN': base_dn, 'CFG_URI': ldapi_uri})
  m = re.search(r'^dn: (olcDatabase=\{\d+\}mdb,cn=config)$', res.stdout, re.M)
  require(m is not None, 'main database DN not found: ' + mask(res.stderr))
  node.main_db = m.group(1)
  check(len(re.findall(r'^dn: ', res.stdout, re.M)) == 1, f'[{node.name}] the documented discovery command finds exactly one main database: {node.main_db}')


B_DNS = sorted(d.lower() for d in [allowed_dn, f'uid=u01,{allowed_dn}', f'uid=u02,{allowed_dn}',
                                   f'uid=u03,{allowed_dn}', f'uid=human,{allowed_dn}'])


# ---- unchanged-for-others probes -------------------------------------------------------

def probes(node):
  out = {}

  def rec(name, res, with_text=True):
    out[name] = (res.returncode, norm('\n'.join(sorted(res.stdout.splitlines()))) if with_text else '')

  base = ['-LLL', '-b', base_dn, '-s', 'sub']
  rec('admin sub', node.admin('ldapsearch', base + ['(objectClass=*)', 'dn', 'uid', 'cn', 'sn', 'description', 'objectClass', 'shadowLastChange']))
  res = node.admin('ldapsearch', ['-LLL', '-b', f'uid=u01,{allowed_dn}', '-s', 'base', 'userPassword'])
  out['admin reads userPassword'] = (res.returncode, has_attr(res.stdout, 'userPassword'))
  rec('admin write', node.admin('ldapmodify', [], mod_ldif(f'uid=u03,{allowed_dn}', 'replace', 'description', 'probe')), False)
  rec('anon all dns', node.anon('ldapsearch', base + ['(objectClass=*)', 'dn']))
  rec('anon uid', node.anon('ldapsearch', base + ['(uid=u01)', 'uid', 'dn']))
  rec('anon userPassword', node.anon('ldapsearch', base + ['(uid=u01)', 'userPassword']))
  rec('anon outside base', node.anon('ldapsearch', ['-LLL', '-b', 'ou=system,' + base_dn, '-s', 'base', 'dn']))
  rec('human sub', node.human('ldapsearch', base + ['(objectClass=*)', 'dn', 'uid', 'cn', 'objectClass', 'description']))
  rec('human userPassword of other', node.human('ldapsearch', base + ['(uid=u01)', 'userPassword']))
  rec('human reads M', node.human('ldapsearch', ['-LLL', '-b', machine_dn, '-s', 'base', 'uid', 'cn']))
  rec('human writes other', node.human('ldapmodify', [], mod_ldif(f'uid=u01,{allowed_dn}', 'replace', 'description', 'x')), False)
  rec('human writes self', node.human('ldapmodify', [], mod_ldif(f'uid=human,{allowed_dn}', 'replace', 'description', 'self')), False)
  new_pw = node.human_pw + 'y'
  res = node.change_own_password(f'uid=human,{allowed_dn}', node.human, node.human_pw, new_pw)
  out['human changes own password'] = (res.returncode, '')
  if res.returncode == 0:
    node.put('/tmp/.pw-human', new_pw)
    node.human_pw = new_pw
  return out
  return out


# ---- the machine DN's reach -----------------------------------------------------------------

SECRET_ATTRS = ('userPassword', 'shadowLastChange', 'pwdHistory', 'pKCS8PrivateKey', 'userPKCS12',
                'oathSecret', 'oathEncKey', 'oathTokenPIN')


def machine_reads(node, cfg):
  res = node.machine('ldapwhoami', [])
  check(res.returncode == 0 and machine_dn.lower() in res.stdout.lower(), f'[{cfg}] M binds ({machine_dn})')

  q = ['-LLL', '-o', 'ldif-wrap=no']
  res = node.machine('ldapsearch', q + ['-b', allowed_dn, '-s', 'sub', '(objectClass=*)', 'dn', 'uid', 'cn', 'sn', 'objectClass'])
  check(res.returncode == 0 and dn_set(res.stdout) == B_DNS and has_attr(res.stdout, 'uid', 'cn', 'objectClass'),
        f'[{cfg}] M reads exactly the entries of B with uid/cn/objectClass ({len(dn_set(res.stdout))} entries, rc {res.returncode})')
  res = node.machine('ldapsearch', q + ['-b', allowed_dn, '-s', 'sub', '(&(objectClass=inetOrgPerson)(uid=human))', 'uid'])
  check(dn_set(res.stdout) == [f'uid=human,{allowed_dn}'.lower()], f'[{cfg}] M searches inside B by filter')

  # Secrets: control first (an admin does see them), then M with every way to ask.
  ctl = node.admin('ldapsearch', q + ['-b', f'uid=u01,{allowed_dn}', '-s', 'base', 'userPassword', 'shadowLastChange'])
  check(has_attr(ctl.stdout, 'userPassword') and has_attr(ctl.stdout, 'shadowLastChange'),
        f'[{cfg}] control: the entries do hold userPassword and shadowLastChange')
  hist = node.admin('ldapsearch', q + ['-b', allowed_dn, '-s', 'sub', '(pwdHistory=*)', 'pwdHistory'])
  hist_exists = has_attr(hist.stdout, 'pwdHistory')
  print(f'INFO: [{cfg}] pwdHistory present in the directory for the admin: {hist_exists}', flush=True)
  for label, attrs in (('explicit secret attributes', list(SECRET_ATTRS)), ('*', ['*']), ('+', ['+']), ('* and +', ['*', '+'])):
    res = node.machine('ldapsearch', q + ['-b', allowed_dn, '-s', 'sub', '(objectClass=*)'] + attrs)
    check(res.returncode == 0 and not has_attr(res.stdout, *SECRET_ATTRS),
          f'[{cfg}] M asks for {label} inside B: no secret attribute returned (rc {res.returncode})')
  for filt in ('(userPassword=*)', '(shadowLastChange=*)', '(pwdHistory=*)'):
    res = node.machine('ldapsearch', q + ['-b', allowed_dn, '-s', 'sub', filt, 'dn'])
    check(not dn_set(res.stdout), f'[{cfg}] M filter {filt} matches nothing (undefined without search access)')
  res = node.machine('ldapsearch', q + ['-b', f'uid=u01,{allowed_dn}', '-s', 'base', 'userPassword'])
  check(not has_attr(res.stdout, 'userPassword'), f'[{cfg}] M base read of one entry with userPassword requested: none returned')

  # Outside B: nothing, not even the entry/uid/objectClass hints `by users read` would give.
  outside = {}
  hints = ['dn', 'uid', 'objectClass', 'entry', 'cn']
  for name, args in (
      ('root base', ['-b', base_dn, '-s', 'base', '(objectClass=*)']),
      ('system ou', ['-b', 'ou=system,' + base_dn, '-s', 'base', '(objectClass=*)']),
      ('own entry', ['-b', machine_dn, '-s', 'base', '(objectClass=*)']),
      ('other ou', ['-b', 'ou=other,' + base_dn, '-s', 'base', '(objectClass=*)']),
      ('outsider', ['-b', f'uid=outsider,ou=other,{base_dn}', '-s', 'base', '(objectClass=*)']),
      ('groups ou one', ['-b', 'ou=groups,' + base_dn, '-s', 'one', '(objectClass=*)']),
      ('uid filter', ['-b', base_dn, '-s', 'sub', '(uid=machine)']),
      ('outsider filter', ['-b', base_dn, '-s', 'sub', '(uid=outsider)']),
      ('group filter', ['-b', base_dn, '-s', 'sub', '(cn=g01)']),
      ('ou filter', ['-b', base_dn, '-s', 'sub', '(objectClass=organizationalUnit)'])):
    res = node.machine('ldapsearch', q + args + hints)
    dns = dn_set(res.stdout)
    ok = dns == []
    check(ok and res.returncode in (0, 32), f'[{cfg}] M outside B / {name}: no entry beyond B (rc {res.returncode}, entries {len(dns)})')
    outside[name] = (res.returncode, dns, norm(res.stdout))
  # M has no access to the base entry itself, so a search must START inside B: from the
  # root it is noSuchObject even for the entries of B (documented in the guide).
  res = node.machine('ldapsearch', q + ['-b', base_dn, '-s', 'sub', '(objectClass=*)', 'dn'])
  check(dn_set(res.stdout) == [] and res.returncode in (0, 32),
        f'[{cfg}] M subtree search from the root finds nothing, searches must start inside B (rc {res.returncode})')

  # Other databases: controls prove they are not empty.
  acc = node.tool('ldapsearch', q + ['-b', 'cn=accesslog', '-s', 'sub', 'dn'], 'cn=admin,cn=accesslog', '/tmp/.pw-admin')
  check(len(dn_set(acc.stdout)) > 1, f'[{cfg}] control: cn=accesslog holds entries ({len(dn_set(acc.stdout))})')
  mon = node.tool('ldapsearch', q + ['-b', 'cn=Monitor', '-s', 'sub', 'dn'], 'cn=monitoring,cn=Monitor', '/tmp/.pw-admin')
  check(len(dn_set(mon.stdout)) > 1, f'[{cfg}] control: cn=Monitor holds entries ({len(dn_set(mon.stdout))})')
  cfgc = node.cfg('ldapsearch', q + ['-b', 'cn=config', '-s', 'one', 'dn'])
  check(len(dn_set(cfgc.stdout)) > 1, f'[{cfg}] control: cn=config holds entries ({len(dn_set(cfgc.stdout))})')
  for base in ('cn=accesslog', 'cn=Monitor', 'cn=config'):
    res = node.machine('ldapsearch', q + ['-b', base, '-s', 'sub', '(objectClass=*)', '*', '+'])
    check(not dn_set(res.stdout), f'[{cfg}] M reads nothing under {base} (rc {res.returncode})')
  return outside


def machine_writes(node, cfg):
  secret_before = node.admin('ldapsearch', ['-LLL', '-b', machine_dn, '-s', 'base', 'userPassword']).stdout
  node.put('/tmp/.pw-new', 'New-' + secrets.token_urlsafe(12))
  attempts = []

  def attempt(name, tool, args, ldif=None):
    res = node.machine(tool, args, ldif)
    attempts.append(name)
    if tool == 'ldappasswd':
      # ldappasswd exits 1 and prints "Result: Insufficient access (50)" on stdout. The
      # policy overlay may refuse first (it wants the old password), so this is a
      # secondary check; the delete-old/add-new modify below is the ACL proof.
      ok = res.returncode != 0 and 'Insufficient access (50)' in res.stdout + res.stderr
    else:
      ok = res.returncode == 50
    check(ok, f'[{cfg}] M {name}: insufficient access (rc {res.returncode})')

  def person(dn, uid):
    return f'dn: {dn}\nobjectClass: inetOrgPerson\nuid: {uid}\ncn: {uid}\nsn: {uid}\n'

  attempt('ldapadd inside B', 'ldapadd', [], person(f'uid=new1,{allowed_dn}', 'new1'))
  attempt('ldapadd in ou=other', 'ldapadd', [], person(f'uid=new2,ou=other,{base_dn}', 'new2'))
  attempt('ldapadd in ou=system', 'ldapadd', [], person(f'uid=new3,ou=system,{base_dn}', 'new3'))
  attempt('ldapadd below the root', 'ldapadd', [], f'dn: ou=evil,{base_dn}\nobjectClass: organizationalUnit\nou: evil\n')
  attempt('ldapmodify of an entry inside B', 'ldapmodify', [], mod_ldif(f'uid=u01,{allowed_dn}', 'replace', 'description', 'm'))
  attempt('ldapmodify of an entry outside B', 'ldapmodify', [], mod_ldif(f'uid=outsider,ou=other,{base_dn}', 'replace', 'description', 'm'))
  attempt('ldapmodify of its own description', 'ldapmodify', [], mod_ldif(machine_dn, 'replace', 'description', 'm'))
  attempt('ldapmodify adding to its own entry', 'ldapmodify', [], mod_ldif(machine_dn, 'add', 'description', 'm'))
  # The one self-service form the policy lets through (old deleted, new added in one
  # modify): only the ACL can refuse it.
  attempt('self password change (delete old, add new)', 'ldapmodify', [],
          f'dn: {machine_dn}\nchangetype: modify\ndelete: userPassword\nuserPassword: {node.machine_pw}\n-\n'
          'add: userPassword\nuserPassword: Hijack-1aA-bB-cC\n')
  attempt('ldapmodify replacing its own userPassword', 'ldapmodify', [], mod_ldif(machine_dn, 'replace', 'userPassword', 'Hijack-1aA-bB-cC'))
  attempt('ldapmodify of its own shadowLastChange', 'ldapmodify', [], mod_ldif(machine_dn, 'replace', 'shadowLastChange', '19001'))
  attempt('ldappasswd of itself', 'ldappasswd', ['-T', '/tmp/.pw-new', machine_dn])
  attempt('ldappasswd of an entry inside B', 'ldappasswd', ['-T', '/tmp/.pw-new', f'uid=u02,{allowed_dn}'])
  attempt('ldapdelete inside B', 'ldapdelete', [f'uid=u02,{allowed_dn}'])
  attempt('ldapdelete of its own entry', 'ldapdelete', [machine_dn])
  attempt('ldapmodrdn inside B', 'ldapmodrdn', [f'uid=u03,{allowed_dn}', 'uid=u03x'])
  attempt('ldapmodrdn outside B', 'ldapmodrdn', [f'uid=outsider,ou=other,{base_dn}', 'uid=outsiderx'])

  # The directory is as it was, and M still binds with its password.
  left = node.admin('ldapsearch', ['-LLL', '-b', base_dn, '-s', 'sub', '(|(uid=new1)(uid=new2)(uid=new3)(ou=evil)(uid=u03x)(uid=outsiderx))', 'dn'])
  check(not dn_set(left.stdout), f'[{cfg}] after {len(attempts)} write attempts nothing was created or renamed')
  still = node.admin('ldapsearch', ['-LLL', '-b', base_dn, '-s', 'sub', '(|(uid=u02)(uid=u03)(uid=machine)(uid=outsider))', 'dn'])
  check(len(dn_set(still.stdout)) == 4, f'[{cfg}] after the write attempts nothing was deleted')
  secret_after = node.admin('ldapsearch', ['-LLL', '-b', machine_dn, '-s', 'base', 'userPassword']).stdout
  desc = node.admin('ldapsearch', ['-LLL', '-b', f'uid=u01,{allowed_dn}', '-s', 'base', 'description']).stdout
  check(secret_after == secret_before and node.machine('ldapwhoami', []).returncode == 0 and 'description: m' not in desc,
        f'[{cfg}] M password unchanged, M still binds, no attribute was written')


# ---- one configuration ------------------------------------------------------------------------

def other_dbs_rules(node):
  res = node.cfg('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=config', '(&(objectClass=olcDatabaseConfig)(!(olcSuffix=%s)))' % base_dn, 'olcAccess'])
  return res.stdout


def run_config(node, cfg, operator_rule):
  print(f'=== configuration {cfg}: LDAP_ANONYMOUS_READ_BASE={node.anon_base or "(unset)"}, operator rule={operator_rule} ===', flush=True)
  node.start()
  seed(node)
  if operator_rule:
    res = node.cfg('ldapmodify', [], f'dn: {node.main_db}\nchangetype: modify\nadd: olcAccess\nolcAccess: {{0}}to attrs=description by users write\n')
    require(res.returncode == 0, 'operator rule: ' + mask(res.stderr))

  node.raw_before, rules = node.olc_access()
  node.rules_before = [re.sub(r'^\{\d+\}', '', r) for r in rules]
  print(f'INFO: [{cfg}] {len(rules)} pre-existing rules', flush=True)
  require(len(rules) >= 3, 'expected at least the image rules')

  # Controls: before the rules M is an ordinary user; this is what the rules must take away.
  res = node.machine('ldapsearch', ['-LLL', '-b', 'ou=other,' + base_dn, '-s', 'sub', 'dn'])
  check(len(dn_set(res.stdout)) == 2, f'[{cfg}] control: before the rules M reads outside B (by users read)')
  res = node.machine('ldapmodify', [], mod_ldif(machine_dn, 'replace', 'description', 'before-rules'))
  check(res.returncode == 0, f'[{cfg}] control: before the rules M writes its own entry (by self write)')
  new_machine_pw = 'M2-' + secrets.token_urlsafe(20)
  res = node.change_own_password(machine_dn, node.machine, node.machine_pw, new_machine_pw)
  check(res.returncode == 0, f'[{cfg}] control: before the rules M changes its own password (by self write on userPassword)')
  if res.returncode == 0:
    node.put('/tmp/.pw-machine', new_machine_pw)
    node.machine_pw = new_machine_pw
  res = node.machine('ldapmodify', [], mod_ldif(f'uid=u02,{allowed_dn}', 'replace', 'description', 'before-rules'))
  expected = 0 if operator_rule else 50
  check(res.returncode == expected,
        f'[{cfg}] control: before the rules M writing another entry gives rc {res.returncode} (expected {expected}'
        + (', the operator\'s leading allow is what opens it)' if operator_rule else ')'))

  probes(node)  # warm-up: the probes' own writes (descriptions, password) settle first
  before = probes(node)
  other_before = other_dbs_rules(node)

  template = mutate(fixture_text('main-database.ldif')) if mutation else fixture_text('main-database.ldif')
  res = node.sh(APPLY, template, proc_env(node))
  require(res.returncode == 0, 'apply (documented procedure): ' + mask(res.stderr))

  # Read back: the machine rules are {0}-{2}, then every old rule in its old order.
  _, after_rules = node.olc_access()
  machine_values = [norm(re.sub('@MACHINE_DN@', machine_dn, re.sub('@ALLOWED_DN@', allowed_dn, v)))
                    for v in ldif_values(fixture_text('main-database.ldif'))]
  expected_rules = [f'{{{i}}}{norm(v)}' for i, v in enumerate([re.sub(r'^\{\d+\}', '', mv) for mv in machine_values]
                                                                 + [norm(r) for r in node.rules_before])]
  check([norm(r) for r in after_rules] == expected_rules,
        f'[{cfg}] olcAccess read back: machine rules are exactly {{0}}-{{2}}, then the {len(node.rules_before)} previous rules in order')
  if [norm(r) for r in after_rules] != expected_rules:
    for r in after_rules:
      print('  read back: ' + r[:150], flush=True)
  check(len(after_rules) >= 3 and all(f'dn.exact="{machine_dn}"' in r for r in after_rules[:3])
        and not any(f'dn.exact="{machine_dn}"' in r for r in after_rules[3:]),
        f'[{cfg}] the three rules naming M occupy positions 0-2 and no other position')
  check(other_dbs_rules(node) == other_before, f'[{cfg}] the monitor and accesslog databases\' own olcAccess are untouched')

  outside = machine_reads(node, cfg)
  machine_writes(node, cfg)

  after = probes(node)
  for name in before:
    check(before[name] == after[name], f'[{cfg}] unchanged for others: {name} (rc {before[name][0]})')

  # Rollback: exact text, M back to its old reach, and a second run refuses.
  res = node.sh(ROLLBACK, None, proc_env(node))
  check(res.returncode == 0, f'[{cfg}] documented rollback command succeeded {mask(res.stderr).strip()[:80]}')
  raw_after, _ = node.olc_access()
  check(raw_after == node.raw_before, f'[{cfg}] olcAccess after the rollback equals the original byte for byte')
  res = node.machine('ldapsearch', ['-LLL', '-b', 'ou=other,' + base_dn, '-s', 'sub', 'dn'])
  check(len(dn_set(res.stdout)) == 2, f'[{cfg}] after the rollback M is an ordinary user again (reads outside B)')
  res = node.sh(ROLLBACK, None, proc_env(node))
  raw_again, _ = node.olc_access()
  check(res.returncode != 0 and raw_again == node.raw_before, f'[{cfg}] a second rollback refuses and changes nothing')
  node.stop()
  return outside


def main():
  print(f'Run {name_prefix}: image {ldap_image}, mutation={mutation or "none"}', flush=True)
  require(run(['docker', 'version', '--format', 'ok']).returncode == 0, 'docker is not available')

  # The guide's LDIF is the committed fixture, not a copy that can drift.
  blocks = guide_blocks()
  for name in ('main-database.ldif', 'monitor-optin.ldif', 'accesslog-optin.ldif'):
    want = significant(fixture_text(name))
    check(any(significant(b) == want for b in blocks), f'operator guide contains the committed {name} verbatim')

  guide = norm(guide_path.read_text())
  for label, script in (('apply', APPLY), ('discovery', DISCOVER), ('rollback', ROLLBACK)):
    check(norm(script) in guide, f'operator guide contains the {label} command exactly as this script runs it')

  outcomes = {}
  for node, cfg, operator_rule in ((Node('a', ''), 'a', False), (Node('b', allowed_dn), 'b', False), (Node('c', ''), 'c', True)):
    outcomes[cfg] = run_config(node, cfg, operator_rule)
  for name in outcomes['a']:
    same = outcomes['a'][name] == outcomes['b'][name] == outcomes['c'][name]
    check(same, f'outside-B answer identical in (a), (b) and (c): {name}')


if __name__ == '__main__':
  code = 0
  try:
    main()
  except AssertionError as e:
    print('ERROR: ' + mask(e), flush=True)
    for c in containers:
      res = run(['docker', 'logs', '--tail', '40', c])
      print(f'--- docker logs {c} (scrubbed, last 40 lines) ---', file=sys.stderr)
      print(mask(res.stdout + res.stderr), file=sys.stderr)
    code = 1
  print(f'RESULT: {passed} checks passed, {len(failed)} failed, mutation={mutation or "none"}, {time.monotonic() - start:.0f}s', flush=True)
  for f in failed:
    print('  FAILED: ' + f, flush=True)
  sys.exit(1 if failed or code else 0)
