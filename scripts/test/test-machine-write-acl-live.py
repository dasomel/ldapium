#!/usr/bin/env python3
"""Live proof of the machine WRITE ACL fragments (#285, T-021; AC-002, AC-003d, AC-008, AC-010).

docs/changes/machine-write-scope, against real slapd. The exhaustive version of the
short smoke scripts/test/test-machine-write-acl-smoke.sh; the pattern is the v1 read-only
proof scripts/test/test-machine-acl-readonly-live.py. No operation is opened and no
application code runs: every write here is a direct ldapmodify/ldapadd/ldapdelete/ldapmodrdn
as the LDAP identity, which is exactly what an attacker who bypasses the app guard has.

Four freshly initialised containers, the matrix
  replication identity: none | prepare (LDAP_REPLICATION_IDENTITY=prepare, rule at {0})
  x LDAP_ANONYMOUS_READ_BASE: unset | set (to the managed subtree)
and in each of them the DOCUMENTED procedure (the guide's install and rollback shell
blocks are cut out of docs/machine-write-account.md and run as written):

  * the exact olcAccess layout: [replication rule] M x3, W_data x8, W_lock x6, then every
    image rule unchanged and in order; the write fragments name only their own DN;
  * the access results of the existing identities (admin, replication identity,
    anonymous, an ordinary user's self service, M) are identical before and after the
    write fragments are installed;
  * W_data: per attribute and per subtree what it MAY do, and that everything else is
    refused (50 where the ACL expresses it); W_lock may touch pwdAccountLockedTime only;
  * the documented limits that ONLY the application guard protects are asserted as
    limits (ModifyDN rename/move, objectClass value add, entry creation with any
    objectClass, the union of all clients' subtrees, locking any user) so a future
    ACL change that silently closes or opens one is noticed;
  * direct writes outside the ceiling (write subtree) are refused;
  * M writes nothing, ever; the v1 read-only facts are re-asserted on the COMBINED layout;
  * the offset-aware rollback restores the olcAccess byte for byte (two orders, a refusal
    for a not-installed fragment), and the write subtree widened to the root keeps the
    SYSTEM_DN / REPL_DN deny backstops.

Mutation self-test: LDAPIUM_WACL_MUTATE installs a broken variant of the W fragments and
the proof must FAIL with named checks:
  loosen-secrets          the W_data secrets/pwd* rule {2} grants write instead of none
  loosen-objectclass      the W_data objectClass rule {4} grants write instead of add
  reorder                 the W fragments are placed after the image's allow rules
  drop-replicator-deny    the REPL_DN deny rule {1} dropped from both fragments
LDAPIUM_WACL_CONFIGS limits the run to some of the configurations n0 n1 p0 p1
(<identity: n = none, p = prepare><anonymous read base: 0 = unset, 1 = set>).

Run (needs docker only; all secrets are throwaway test values passed through 0600 files):
  python3 scripts/test/test-machine-write-acl-live.py
Override LDAPIUM_IMAGE / LDAPIUM_TEST_PREFIX as needed.
"""
import atexit
import base64
import os
import pathlib
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

repo_root = pathlib.Path(__file__).resolve().parents[2]
fixtures = repo_root / 'scripts/test/fixtures/machine-acl'
write_guide = repo_root / 'docs/machine-write-account.md'
read_guide = repo_root / 'docs/machine-ldap-account.md'
ldap_image = os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')
prefix = os.environ.get('LDAPIUM_TEST_PREFIX', 'ldapium-wacl-')
mutation = os.environ.get('LDAPIUM_WACL_MUTATE', '')
only_configs = os.environ.get('LDAPIUM_WACL_CONFIGS', 'n0,n1,p0,p1').split(',')
if not (only_configs and set(only_configs) <= {'n0', 'n1', 'p0', 'p1'}):
  raise SystemExit('LDAPIUM_WACL_CONFIGS is a comma list of n0, n1, p0, p1')
if mutation not in ('', 'loosen-secrets', 'loosen-objectclass', 'reorder', 'drop-replicator-deny'):
  raise SystemExit('LDAPIUM_WACL_MUTATE must be loosen-secrets, loosen-objectclass, reorder or drop-replicator-deny')
run_id = uuid.uuid4().hex[:6]
name_prefix = prefix + run_id

base_dn = 'dc=example,dc=org'
admin_dn = 'cn=admin,' + base_dn
repl_dn = 'cn=replicator,' + base_dn          # the reserved DN of image/entrypoint.sh
system_dn = 'ou=system,' + base_dn
machine_dn = 'uid=machine,' + system_dn       # M
wd_dn = 'uid=machine-write-data,' + system_dn
wl_dn = 'uid=machine-write-lock,' + system_dn
managed = 'ou=managed,' + base_dn             # WRITE_DN, also M's allowed subtree B
people = 'ou=people,' + managed
groups = 'ou=groups,' + managed
other = 'ou=other,' + base_dn
alice = 'uid=alice,' + people                 # an ordinary user (self service)
secrets_dn = 'uid=secrets,' + people
dave = 'uid=dave,' + people                   # locked by the admin
g1 = 'cn=g1,' + groups
outsider = 'uid=outsider,' + other
cfg_dn = 'cn=admin,cn=config'
ldapi_uri = 'ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi'
ldap_uri = 'ldap://127.0.0.1'

passwords = {k: k[:3] + '-' + secrets.token_urlsafe(24) for k in ('admin', 'machine', 'wdata', 'wlock', 'human', 'id')}
human_new = 'HumanNew-' + secrets.token_urlsafe(12)

SECRET_ATTRS = ('userPassword', 'shadowLastChange', 'pwdHistory', 'pKCS8PrivateKey', 'userPKCS12',
                'oathSecret', 'oathEncKey', 'oathTokenPIN')
PWD_STATE = ('pwdAccountLockedTime', 'pwdChangedTime', 'pwdFailureTime', 'pwdGraceUseTime', 'pwdReset',
             'pwdPolicySubentry', 'pwdStartTime', 'pwdEndTime', 'pwdLastSuccess')
# Attributes of the closed W_data list (write-data.ldif rule {5}) and what a modify of each looks like.
DATA_ATTRS = ('uid', 'cn', 'sn', 'givenName', 'mail', 'departmentNumber', 'o', 'ou', 'member')

containers, volumes, networks, tmp_dirs = [], [], [], []
passed = 0
failed = []
start_time = time.monotonic()
GLOBAL_DEADLINE_S = 2400


def check(condition, message):
  global passed
  if condition:
    passed += 1
    print('PASS: ' + message, flush=True)
  else:
    failed.append(message)
    print('FAIL: ' + message, flush=True)


def limit(condition, message):
  """A documented limit: the ACL does NOT stop this, only the application guard does."""
  check(condition, 'KNOWN-LIMIT (app guard only): ' + message)


def require(condition, message):
  if not condition:
    raise AssertionError(message)


def mask(text):
  text = text if isinstance(text, str) else str(text)
  for secret in list(passwords.values()) + [human_new]:
    text = text.replace(secret, '***')
  return text


def run(cmd, input_data=None, timeout=180, env=None, cwd=None):
  return subprocess.run(cmd, capture_output=True, text=True, input=input_data, timeout=timeout, env=env, cwd=cwd)


def cleanup():
  for c in containers:
    subprocess.run(['docker', 'rm', '-fv', c], capture_output=True, text=True)
  for v in volumes:
    subprocess.run(['docker', 'volume', 'rm', '-f', v], capture_output=True, text=True)
  for n in networks:
    subprocess.run(['docker', 'network', 'rm', n], capture_output=True, text=True)
  for d in tmp_dirs:
    shutil.rmtree(d, ignore_errors=True)


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


def wait_until(predicate, what, timeout=120.0):
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if predicate():
      return
    time.sleep(0.5)
  raise AssertionError(f'timed out after {timeout}s waiting for {what}')


def norm(text):
  return re.sub(r'\s+', ' ', text).strip()


def dn_set(out):
  return sorted(l[4:].strip().lower() for l in out.splitlines() if l.startswith('dn: '))


def has_attr(out, *names):
  pat = re.compile(r'^(' + '|'.join(re.escape(n) for n in names) + r')(;[^:]*)?::?( |$)', re.I)
  return any(pat.match(l) for l in out.splitlines())


def attr_values(out, name):
  pat = re.compile(r'^' + re.escape(name) + r'(;[^:]*)?::? ?(.*)$', re.I)
  return [m.group(2) for m in (pat.match(l) for l in out.splitlines()) if m]


def mod(dn, *ops):
  """A modify LDIF; each op is (operation, attribute, [values])."""
  body = f'dn: {dn}\nchangetype: modify\n'
  parts = []
  for op, attr, values in ops:
    part = f'{op}: {attr}\n'
    for v in values:
      part += f'{attr}: {v}\n'
    parts.append(part)
  return body + '-\n'.join(parts)


def person(dn, uid, extra=''):
  return (f'dn: {dn}\nchangetype: add\nobjectClass: top\nobjectClass: person\nobjectClass: organizationalPerson\n'
          f'objectClass: inetOrgPerson\nuid: {uid}\ncn: {uid}\nsn: {uid}\n{extra}')


# ---- the fixtures, the guides and the mutations -----------------------------------------------

def fixture_text(name):
  return (fixtures / name).read_text()


def ldif_values(text):
  """olcAccess values of an LDIF (comments dropped, folded lines joined), index stripped."""
  values = []
  for line in text.splitlines():
    if line.startswith('#'):
      continue
    if line.startswith('olcAccess: '):
      values.append(re.sub(r'^\{\d+\}', '', line[len('olcAccess: '):]))
    elif line.startswith(' ') and values:
      values[-1] += line[1:]
  return values


def guide_ldif_blocks(path):
  return [b.strip() for b in re.findall(r'```ldif\n(.*?)```', path.read_text(), re.S)]


def significant(text):
  return [l.rstrip() for l in text.splitlines() if l.strip() and not l.startswith('#')]


def guide_sh(marker):
  """The write guide's ```sh block that contains marker, as written."""
  for m in re.finditer(r'```sh\n(.*?)```', write_guide.read_text(), re.S):
    if marker in m.group(1):
      return m.group(1)
  raise AssertionError(f'no sh block with {marker} in {write_guide}')


def mutate(name, text, shift):
  """Broken variants of a W fragment, for the mutation self-test only. `shift` is the number
  of leading rules the reorder mutation must jump over (the image rules)."""
  if not mutation:
    return text
  if mutation == 'loosen-secrets' and name == 'write-data.ldif':
    out, n = re.subn(r'(olcAccess: \{2\}to attrs=[^\n]*\n  by dn\.exact="@WDATA_DN@") none', r'\1 write', text)
    require(n == 1, 'loosen-secrets did not apply')
    return out
  if mutation == 'loosen-objectclass' and name == 'write-data.ldif':
    out, n = re.subn(r'(attrs=objectClass\n  by dn\.exact="@WDATA_DN@") add', r'\1 write', text)
    require(n == 1, 'loosen-objectclass did not apply')
    return out
  if mutation == 'reorder':
    return re.sub(r'^olcAccess: \{(\d+)\}', lambda m: f'olcAccess: {{{int(m.group(1)) + shift}}}', text, flags=re.M)
  if mutation == 'drop-replicator-deny':
    out, n = re.subn(r'olcAccess: \{1\}to dn\.exact="@REPL_DN@"\n  by dn\.exact="@\w+@" none\n  by \* break\n', '', text)
    require(n == 1, 'drop-replicator-deny did not apply')
    for i in range(2, 8):
      out = out.replace(f'olcAccess: {{{i}}}', f'olcAccess: {{{i - 1}}}')
    return out
  return text


# ---- container helpers (docker exec -i always: the stdin must reach the tool) --------------------

secret_dir = tempfile.mkdtemp(prefix='wacl-secrets-')
os.chmod(secret_dir, 0o700)
tmp_dirs.append(secret_dir)

WHO = {  # identity -> (bind DN, password file in the container)
    'admin': (admin_dn, '/tmp/.pw-admin'), 'machine': (machine_dn, '/tmp/.pw-machine'),
    'wdata': (wd_dn, '/tmp/.pw-wdata'), 'wlock': (wl_dn, '/tmp/.pw-wlock'),
    'human': (alice, '/tmp/.pw-human'), 'id': (repl_dn, '/tmp/.pw-id'),
}


class Node:
  def __init__(self, key):
    self.key = key
    self.prepare = key[0] == 'p'
    self.anon_base = managed if key[1] == '1' else ''
    self.cfg = key
    self.container = f'{name_prefix}-{key}'
    self.net = f'{name_prefix}-{key}-net'
    self.certs = f'{name_prefix}-{key}-certs'
    self.vols = (f'{name_prefix}-{key}-cfg', f'{name_prefix}-{key}-data')
    self.main_db = 'olcDatabase={1}mdb,cn=config'
    self.human_pw = passwords['human']
    self.guide_env = {}

  # -- running tools
  def sh(self, script, input_data=None, env=None):
    cmd = ['docker', 'exec', '-i']
    for k, v in (env or {}).items():
      cmd += ['-e', f'{k}={v}']
    return run(cmd + [self.container, 'sh', '-c', script], input_data)

  def put(self, path, text):
    res = self.sh(f'umask 077; cat > {path}', text)
    require(res.returncode == 0, 'put ' + path + ': ' + res.stderr)

  def tool(self, who, tool, args, input_data=None, uri=ldap_uri, bind=True, env=None):
    cmd = ['docker', 'exec', '-i']
    for k, v in (env or {}).items():
      cmd += ['-e', f'{k}={v}']
    cmd += [self.container, tool, '-x', '-H', uri]
    if who and bind:
      dn, pwf = WHO[who]
      cmd += ['-D', dn, '-y', pwf]
    return run(cmd + args, input_data)

  def search(self, who, base, flt='(objectClass=*)', attrs=(), scope='sub'):
    return self.tool(who, 'ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', base, '-s', scope, flt] + list(attrs))

  def rc(self, who, ldif, tool='ldapmodify'):
    return self.tool(who, tool, [], ldif).returncode

  def cfgtool(self, tool, args, input_data=None):
    return run(['docker', 'exec', '-i', self.container, tool, '-x', '-H', ldapi_uri, '-D', cfg_dn, '-y', '/tmp/.pw-admin'] + args, input_data)

  def olc_access(self):
    res = self.cfgtool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', self.main_db, '-s', 'base', 'olcAccess'])
    require(res.returncode == 0, 'read olcAccess: ' + mask(res.stderr))
    return res.stdout, re.findall(r'^olcAccess: (.*)$', res.stdout, re.M)

  # -- lifecycle
  def _run_container(self, replication_mode):
    envfile = os.path.join(secret_dir, self.key + '.env')
    fd = os.open(envfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
      f.write(f'LDAP_ADMIN_PASSWORD={passwords["admin"]}\n')
    cmd = ['docker', 'run', '-d', '--name', self.container, '--env-file', envfile, '-e', 'LDAP_ROOT_DN=' + base_dn]
    if self.anon_base:
      cmd += ['-e', 'LDAP_ANONYMOUS_READ_BASE=' + self.anon_base]
    if self.prepare:
      cmd += ['--network', self.net, '--hostname', self.container,
              '-v', f'{self.vols[0]}:/etc/openldap/slapd.d', '-v', f'{self.vols[1]}:/var/lib/openldap/data',
              '-v', f'{self.certs}:/certs:ro',
              '-e', 'LDAP_REPLICATION_ENABLED=true', '-e', 'LDAP_SERVER_ID=1',
              '-e', f'LDAP_REPLICATION_PEERS=ldap://{self.container}:389',
              '-e', 'LDAP_TLS_ENABLED=true', '-e', 'LDAP_TLS_CERT_FILE=/certs/c.pem', '-e', 'LDAP_TLS_KEY_FILE=/certs/k.pem',
              '-e', f'LDAP_REPLICATION_IDENTITY={replication_mode}']
    else:
      cmd += ['--network', 'none']
    res = run(cmd + [ldap_image])
    require(res.returncode == 0, 'docker run: ' + res.stderr)

    def ready():
      if self.sh('umask 077; cat > /tmp/.pw-admin', passwords['admin']).returncode != 0:
        return False
      return self.tool('admin', 'ldapsearch', ['-b', base_dn, '-s', 'base', 'dn']).returncode == 0
    wait_until(ready, f'{self.key}: slapd readiness')
    for name in ('machine', 'wdata', 'wlock', 'id'):
      self.put(f'/tmp/.pw-{name}', passwords[name])
    self.put('/tmp/.pw-human', self.human_pw)
    if getattr(self, 'secrets_pw', None):
      self.put('/tmp/.pw-secrets', self.secrets_pw)

  def start(self):
    containers.append(self.container)
    if self.prepare:  # prepare refuses to bootstrap serverID 1: initialise as admin, seed, then switch
      networks.append(self.net)
      volumes.extend([self.certs, *self.vols])
      require(run(['docker', 'network', 'create', self.net]).returncode == 0, 'network create')
      for v in (self.certs, *self.vols):
        require(run(['docker', 'volume', 'create', v]).returncode == 0, 'volume create')
      for step in (['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', '/certs/k.pem', '-out', '/certs/c.pem',
                    '-days', '2', '-subj', '/CN=localhost'], ['chown', '-R', '999:999', '/certs'], ['chmod', '600', '/certs/k.pem']):
        res = run(['docker', 'run', '--rm', '--user', '0', '-v', f'{self.certs}:/certs', '--entrypoint', step[0], ldap_image] + step[1:])
        require(res.returncode == 0, 'cert prep: ' + res.stderr)
    self._run_container('admin')

  def switch_to_prepare(self):
    require(run(['docker', 'rm', '-f', self.container]).returncode == 0, 'rm for the prepare restart')
    self._run_container('prepare')
    res = self.tool('admin', 'ldapadd', [], f'dn: {repl_dn}\nobjectClass: organizationalRole\nobjectClass: simpleSecurityObject\n'
                    f'cn: replicator\nuserPassword: {passwords["id"]}\n')
    require(res.returncode == 0, 'add the replication identity entry: ' + mask(res.stderr))

  def restart(self):
    require(run(['docker', 'restart', self.container]).returncode == 0, 'docker restart')
    wait_until(lambda: self.tool('admin', 'ldapsearch', ['-b', base_dn, '-s', 'base', 'dn']).returncode == 0, 'restart readiness')

  def stop(self):
    run(['docker', 'rm', '-fv', self.container])
    containers.remove(self.container)

  def change_pw(self, dn, who, old, new):
    """Self service as this image accepts it: delete old + add new in ONE modify (a replace or
    ldappasswd is refused by the policy overlay before any ACL decides)."""
    return self.tool(who, 'ldapmodify', [], f'dn: {dn}\nchangetype: modify\ndelete: userPassword\nuserPassword: {old}\n-\n'
                     f'add: userPassword\nuserPassword: {new}\n')


# ---- seed -----------------------------------------------------------------------------------

def seed(node):
  b64 = lambda raw: base64.b64encode(raw).decode()
  marker = secrets.token_hex(6)
  der = bytes.fromhex('302e020100300506032b657004220420') + os.urandom(32)
  secrets_pw = 'Secrets-' + secrets.token_urlsafe(12)
  ldif = f"""dn: {managed}
objectClass: organizationalUnit
ou: managed

dn: {people}
objectClass: organizationalUnit
ou: people

dn: {groups}
objectClass: organizationalUnit
ou: groups

dn: {other}
objectClass: organizationalUnit
ou: other

dn: {system_dn}
objectClass: organizationalUnit
ou: system

dn: {machine_dn}
objectClass: inetOrgPerson
objectClass: shadowAccount
uid: machine
cn: machine
sn: machine
shadowLastChange: 19000
userPassword: {passwords['machine']}

dn: {wd_dn}
objectClass: inetOrgPerson
uid: machine-write-data
cn: machine-write-data
sn: machine-write-data
userPassword: {passwords['wdata']}

dn: {wl_dn}
objectClass: inetOrgPerson
uid: machine-write-lock
cn: machine-write-lock
sn: machine-write-lock
userPassword: {passwords['wlock']}

dn: {outsider}
objectClass: inetOrgPerson
uid: outsider
cn: outsider
sn: outsider
userPassword: Outsider-{secrets.token_urlsafe(12)}

dn: {alice}
objectClass: inetOrgPerson
uid: alice
cn: alice
sn: alice
userPassword: {passwords['human']}

dn: uid=u01,{people}
objectClass: inetOrgPerson
uid: u01
cn: u01
sn: u01
userPassword: U01-{secrets.token_urlsafe(12)}

dn: {g1}
objectClass: groupOfNames
cn: g1
member: {alice}

dn: cn=g1,{other}
objectClass: groupOfNames
cn: g1
member: {alice}

dn: {secrets_dn}
objectClass: inetOrgPerson
objectClass: shadowAccount
objectClass: extensibleObject
uid: secrets
cn: secrets
sn: secrets
shadowLastChange: 19777
userPassword: {secrets_pw}
userPKCS12:: {b64(('SEED-userPKCS12-' + marker).encode())}
pKCS8PrivateKey;binary:: {b64(der)}
oathSecret: SEED-oathSecret-{marker}
oathEncKey: SEED-oathEncKey-{marker}
oathTokenPIN: SEED-oathTokenPIN-{marker}

dn: {dave}
objectClass: inetOrgPerson
uid: dave
cn: dave
sn: dave
userPassword: Dave-{secrets.token_urlsafe(12)}
"""
  res = node.tool('admin', 'ldapadd', [], ldif)
  require(res.returncode == 0, 'seed ldapadd: ' + mask(res.stderr))
  # a REAL locked entry (a never-locked user would make the lock-attribute read checks vacuous)
  res = node.tool('admin', 'ldapmodify', [], mod(dave, ('add', 'pwdAccountLockedTime', ['20260101000000Z'])))
  require(res.returncode == 0, 'lock dave: ' + mask(res.stderr))
  # pwdHistory is operational: produced by password changes of the entry itself (the policy keeps 5)
  node.put('/tmp/.pw-secrets', secrets_pw)
  WHO['secrets'] = (secrets_dn, '/tmp/.pw-secrets')
  pw = secrets_pw
  for i in range(2):
    new_pw = f'{pw}-{i}'
    res = node.change_pw(secrets_dn, 'secrets', pw, new_pw)
    require(res.returncode == 0, 'seed pwdHistory: ' + mask(res.stderr))
    node.put('/tmp/.pw-secrets', new_pw)
    pw = new_pw
  node.secrets_pw = pw
  new_pw = passwords['human'] + 'x'
  res = node.change_pw(alice, 'human', passwords['human'], new_pw)  # so a pwdHistory value exists for alice
  require(res.returncode == 0, 'seed human password change: ' + mask(res.stderr))
  node.put('/tmp/.pw-human', new_pw)
  node.human_pw = new_pw
  res = node.cfgtool('ldapsearch', ['-LLL', '-b', 'cn=config', f'(olcSuffix={base_dn})', 'dn'])
  require(res.stdout.strip() == f'dn: {node.main_db}', 'main database DN: ' + res.stdout)


# ---- installing and rolling back, exactly as the guides say ------------------------------------------

# The documented M apply commands (docs/machine-ldap-account.md 5 and 5.1), as the v1 proof runs them.
M_APPLY = ('sed -e "s|@MACHINE_DN@|$MACHINE_DN|g" -e "s|@ALLOWED_DN@|$ALLOWED_DN|g" '
           '-e "s|@MAIN_DB_DN@|$MAIN_DB_DN|g" | '
           'ldapmodify -x -H "$CFG_URI" -D cn=admin,cn=config -y /tmp/.pw-admin')
M_SHIFT = ('sed -e "s|^olcAccess: {2}|olcAccess: {3}|" -e "s|^olcAccess: {1}|olcAccess: {2}|" '
           '-e "s|^olcAccess: {0}|olcAccess: {1}|" | ')
M_ROLLBACK_NOTE = 'M rules stay installed: the v1 proof owns the M rollback'


def tokens(write_dn):
  return {'@MACHINE_DN@': machine_dn, '@ALLOWED_DN@': managed, '@WDATA_DN@': wd_dn, '@WLOCK_DN@': wl_dn,
          '@WRITE_DN@': write_dn, '@SYSTEM_DN@': system_dn, '@REPL_DN@': repl_dn, '@MAIN_DB_DN@': 'olcDatabase={1}mdb,cn=config'}


def subst(text, write_dn):
  for k, v in tokens(write_dn).items():
    text = text.replace(k, v)
  return text


def fixture_bodies(name, write_dn):
  return [norm(subst(v, write_dn)) for v in ldif_values(fixture_text(name))]


def guide_env(node, write_dn):
  env = os.environ.copy()
  env.update({'EXEC': f'docker exec -i {node.container}', 'MACHINE_DN': machine_dn, 'WDATA_DN': wd_dn, 'WLOCK_DN': wl_dn,
              'SYSTEM_DN': system_dn, 'REPL_DN': repl_dn, 'MAIN_DB_DN': node.main_db, 'CFG_URI': ldapi_uri,
              'ROOT_DN': base_dn, 'WRITE_DN': write_dn})
  return env


def guide_install(node, fragdir, frag, who, write_dn):
  env = guide_env(node, write_dn)
  env.update({'FRAG': frag, 'WHO': who})
  res = run(['bash', '-c', guide_sh('PRESENT='), '-'], env=env, cwd=fragdir)
  return res.stdout + res.stderr


def guide_rollback(node, who, k):
  env = guide_env(node, managed)
  env.update({'WHO': who, 'K': str(k)})
  res = run(['bash', '-c', guide_sh('FIRST='), '-'], env=env, cwd=str(tmp_dirs[0]))
  return res.stdout + res.stderr


def idx_of(node, dn):
  _, rules = node.olc_access()
  return [i for i, r in enumerate(rules) if f'dn.exact="{dn}"' in r]


def acl_bodies(node):
  _, rules = node.olc_access()
  return [norm(re.sub(r'^\{\d+\}', '', r)) for r in rules]


def expected_layout(node, write_dn, wd=True, wl=True, wd_first=True):
  """The defined order: [replication rule] M x3, W_data x8, W_lock x6, then the image rules, unchanged."""
  vals = list(node.repl_rules) + fixture_bodies('main-database.ldif', write_dn)
  if wd:
    vals += fixture_bodies('write-data.ldif', write_dn)
  if wl:
    vals += fixture_bodies('write-lock.ldif', write_dn)
  vals += node.image_rules
  return vals


def install_m(node):
  apply = (M_SHIFT if node.prepare else '') + M_APPLY
  env = {'MACHINE_DN': machine_dn, 'ALLOWED_DN': managed, 'MAIN_DB_DN': node.main_db, 'CFG_URI': ldapi_uri}
  res = node.sh(apply, fixture_text('main-database.ldif'), env)
  require(res.returncode == 0, 'M apply: ' + mask(res.stderr))


def fragdir_for(node, tag):
  """A directory holding the (possibly mutated) fragments; the guide's commands run in it."""
  d = tempfile.mkdtemp(prefix=f'wacl-frag-{tag}-')
  tmp_dirs.append(d)
  n_image = len(node.image_rules)
  shifts = {'write-data.ldif': n_image, 'write-lock.ldif': n_image + 8}
  for name in ('write-data.ldif', 'write-lock.ldif'):
    pathlib.Path(d, name).write_text(mutate(name, fixture_text(name), shifts[name]))
  return d


def k_installed(name):
  """How many rules of the fragment as actually installed (a mutation can change the count)."""
  return len(ldif_values(mutate(name, fixture_text(name), 0)))


# ---- probes: access results of the identities that exist before the write fragments --------------------

def probes(node):
  out = {}

  def rec(name, res, text=True):
    out[name] = (res.returncode, norm('\n'.join(sorted(res.stdout.splitlines()))) if text else '')

  sub = ['-LLL', '-o', 'ldif-wrap=no', '-b', base_dn, '-s', 'sub']
  attrs = ['dn', 'uid', 'cn', 'sn', 'mail', 'description', 'objectClass', 'member', 'shadowLastChange', 'pwdAccountLockedTime']
  rec('admin sub', node.tool('admin', 'ldapsearch', sub + ['(objectClass=*)'] + attrs))
  res = node.tool('admin', 'ldapsearch', ['-LLL', '-b', alice, '-s', 'base', 'userPassword'])
  out['admin reads userPassword'] = (res.returncode, has_attr(res.stdout, 'userPassword'))
  rec('admin writes', node.tool('admin', 'ldapmodify', [], mod(f'uid=u01,{people}', ('replace', 'description', ['probe']))), False)
  rec('anon all dns', node.tool(None, 'ldapsearch', sub + ['(objectClass=*)', 'dn']))
  rec('anon uid', node.tool(None, 'ldapsearch', sub + ['(uid=u01)', 'uid', 'dn']))
  rec('anon userPassword', node.tool(None, 'ldapsearch', sub + ['(uid=u01)', 'userPassword']))
  rec('anon outside', node.tool(None, 'ldapsearch', ['-LLL', '-b', system_dn, '-s', 'base', 'dn']))
  rec('human sub', node.tool('human', 'ldapsearch', sub + ['(objectClass=*)'] + attrs))
  rec('human reads others userPassword', node.tool('human', 'ldapsearch', sub + ['(uid=u01)', 'userPassword']))
  rec('human reads W_data entry', node.tool('human', 'ldapsearch', ['-LLL', '-b', wd_dn, '-s', 'base', 'uid', 'cn']))
  rec('human writes other', node.tool('human', 'ldapmodify', [], mod(f'uid=u01,{people}', ('replace', 'description', ['x']))), False)
  rec('human writes self', node.tool('human', 'ldapmodify', [], mod(alice, ('replace', 'description', ['self']))), False)
  rec('human writes own mail', node.tool('human', 'ldapmodify', [], mod(alice, ('replace', 'mail', ['alice@example.org']))), False)
  new_pw = 'HumanProbe-' + secrets.token_urlsafe(12)  # never a reused value: the policy keeps a history
  res = node.change_pw(alice, 'human', node.human_pw, new_pw)
  out['human changes own password'] = (res.returncode, '')
  if res.returncode == 0:
    node.put('/tmp/.pw-human', new_pw)
    node.human_pw = new_pw
  # M (installed before the write fragments): reads, outside, write refusals
  rec('M reads B', node.tool('machine', 'ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', managed, '-s', 'sub', '(objectClass=*)'] + attrs))
  rec('M outside', node.tool('machine', 'ldapsearch', ['-LLL', '-b', other, '-s', 'sub', 'dn']))
  rec('M root', node.tool('machine', 'ldapsearch', ['-LLL', '-b', base_dn, '-s', 'base', 'dn']))
  rec('M writes', node.tool('machine', 'ldapmodify', [], mod(f'uid=u01,{people}', ('replace', 'description', ['m']))), False)
  rec('M writes self', node.tool('machine', 'ldapmodify', [], mod(machine_dn, ('replace', 'description', ['m']))), False)
  if node.prepare:  # the replication identity reads everything including hashes, over TLS only
    tls = {'LDAPTLS_CACERT': '/certs/c.pem', 'LDAPTLS_REQCERT': 'never'}
    rec('replication identity reads hashes', node.tool('id', 'ldapsearch', ['-LLL', '-b', base_dn, '-s', 'sub', '(uid=u01)', 'userPassword'],
                                                         uri='ldaps://localhost', env=tls))
    rec('replication identity sub', node.tool('id', 'ldapsearch', sub + ['(objectClass=*)', 'dn'], uri='ldaps://localhost', env=tls))
    rec('replication identity cleartext refused', node.tool('id', 'ldapsearch', sub + ['(uid=u01)', 'userPassword']))
    rec('replication identity writes', node.tool('id', 'ldapmodify', [], mod(f'uid=u01,{people}', ('replace', 'description', ['id'])),
                                                  uri='ldaps://localhost', env=tls), False)
  return out


# ---- reads: what an identity must NOT see ----------------------------------------------------------

DENIED_READ = SECRET_ATTRS + PWD_STATE + ('memberOf',)


def reads_deny(node, who, tag, allowed=()):
  """`who` returns none of the secret / pwd* / memberOf attributes of the subtree, however it asks,
  and cannot match on them. The admin control proves which of them the subtree really holds."""
  ctl = node.search('admin', managed, '(objectClass=*)', ['*', '+'])
  present = [a for a in DENIED_READ if has_attr(ctl.stdout, a)]
  check(all(a in present for a in SECRET_ATTRS + ('pwdAccountLockedTime', 'pwdChangedTime', 'pwdHistory', 'memberOf')),
        f'[{node.cfg}] control: the admin reads every secret attribute, pwdAccountLockedTime, pwdChangedTime, pwdHistory and memberOf in the subtree ({len(present)} present)')
  denied = [a for a in present if a not in allowed]
  seeing = node.search(who, managed, '(objectClass=*)', ['uid', 'cn', 'objectClass'])
  check(seeing.returncode == 0 and has_attr(seeing.stdout, 'uid', 'cn', 'objectClass') and len(dn_set(seeing.stdout)) >= 5,
        f'[{node.cfg}] control: {tag} reads the subtree itself ({len(dn_set(seeing.stdout))} entries)')
  # a VALUE is matched only for the seeded secrets (unique markers); DN- and time-valued attributes would collide with other output
  values = {a: [v for v in attr_values(ctl.stdout, a) if len(v) >= 8] if a in SECRET_ATTRS else [] for a in denied}
  asks = {'explicit': node.search(who, managed, '(objectClass=*)', denied),
          '* and +': node.search(who, managed, '(objectClass=*)', ['*', '+'])}
  for label, res in asks.items():
    leaked = [a for a in denied if has_attr(res.stdout, a) or any(v in res.stdout for v in values[a])]
    check(res.returncode == 0 and not leaked, f'[{node.cfg}] {tag} asking {label}: none of {len(denied)} denied attributes returned {leaked} (rc {res.returncode})')
  for a in denied:
    res = node.search(who, managed, f'({a}=*)', ['dn'])
    check(not dn_set(res.stdout), f'[{node.cfg}] {tag}: filter ({a}=*) matches nothing')


# ---- W_data -------------------------------------------------------------------------------------------

OTHER_ATTRS = ('telephoneNumber', 'title', 'l', 'st', 'street', 'postalAddress', 'employeeNumber', 'employeeType',
               'carLicense', 'displayName', 'initials', 'labeledURI', 'manager', 'roomNumber', 'preferredLanguage', 'seeAlso',
               'businessCategory', 'facsimileTelephoneNumber', 'mobile', 'pager', 'homePhone', 'physicalDeliveryOfficeName',
               'registeredAddress', 'secretary')
DN_ATTRS = ('manager', 'seeAlso', 'secretary')
# What the ACL answers to a write of each denied attribute: 50 where the ACL decides, 19 where the
# schema (NO-USER-MODIFICATION) refuses first and the ACL is never reached.
SCHEMA_REFUSED = {a: 19 for a in ('memberOf', 'pwdHistory', 'pwdChangedTime', 'pwdFailureTime', 'pwdGraceUseTime', 'pwdLastSuccess')}


def value_for(attr):
  if attr in DN_ATTRS:
    return f'uid=u01,{people}'
  if attr.endswith(';binary'):
    return None
  if attr in ('registeredAddress', 'postalAddress'):
    return 'x$y'
  return 'v1'


def wdata_proof(node):
  cfg = node.cfg
  wd = lambda ldif: node.rc('wdata', ldif)
  bob = f'uid=bob,{people}'
  c = lambda m: f'[{cfg}] W_data {m}'
  check(node.tool('wdata', 'ldapwhoami', []).returncode == 0, c('binds'))

  print(f'--- {cfg}: W_data allowed ---', flush=True)
  check(wd(person(bob, 'bob', 'mail: bob@example.org\ngivenName: Bob\ndepartmentNumber: 7\no: Org\nou: Unit\n')) == 0,
        c('adds a user with the closed attribute set (uid, cn, sn, mail, givenName, departmentNumber, o, ou) inside the subtree'))
  for attr, value in (('cn', 'bob-cn'), ('sn', 'bob-sn'), ('givenName', 'B'), ('mail', 'bob2@example.org'), ('departmentNumber', '9'),
                      ('o', 'Org2'), ('ou', 'Unit2')):
    check(wd(mod(bob, ('replace', attr, [value]))) == 0, c(f'replaces {attr}'))
    got = node.search('admin', bob, '(objectClass=*)', [attr], 'base').stdout
    check(f'{attr}: {value}' in got, c(f'{attr} really changed (admin reads {value})'))
  check(wd(mod(bob, ('add', 'uid', ['bob-alias']))) == 0 and wd(mod(bob, ('delete', 'uid', ['bob-alias']))) == 0,
        c('adds and removes a second uid value (uid is in the list; the RDN value stays)'))
  check(wd(mod(bob, ('delete', 'mail', []))) == 0 and wd(mod(bob, ('add', 'mail', ['bob3@example.org']))) == 0, c('deletes and re-adds mail'))
  check(wd(mod(g1, ('add', 'member', [bob]))) == 0, c('adds a group member'))
  check(wd(mod(g1, ('delete', 'member', [bob]))) == 0, c('removes a group member'))
  check(wd(mod(g1, ('add', 'member', [bob]))) == 0 and wd(mod(g1, ('delete', 'member', [bob]))) == 0, c('adds and removes a member again'))
  # v2b D379-5 (T-012): description joined the closed list for machine patchGroup. The ACL cannot tell a group from a
  # user entry, so it is writable on both; patchUser's closed body has no description (application guard, not the ACL).
  check(wd(mod(g1, ('replace', 'description', ['machine-set']))) == 0, c('sets a group description'))
  got = node.search('admin', g1, '(objectClass=*)', ['description'], 'base').stdout
  check('description: machine-set' in got, c('the group description really changed (admin reads it)'))
  check(wd(mod(g1, ('delete', 'description', []))) == 0, c('clears a group description'))
  check(wd(mod(bob, ('replace', 'description', ['class-level']))) == 0 and wd(mod(bob, ('delete', 'description', []))) == 0,
        c('description is writable on a user entry too (class-level backstop; the closed patchUser body excludes it)'))

  print(f'--- {cfg}: W_data refused ---', flush=True)
  for attr in OTHER_ATTRS:
    value = value_for(attr)
    if value is None:
      continue
    check(wd(mod(bob, ('replace', attr, [value]))) == 50, c(f'attribute outside the closed list ({attr}) refused (50)'))
  check(wd(mod(g1, ('add', 'owner', [alice]))) == 50, c('group attribute outside the closed list (owner) refused (50)'))
  check(wd(mod(bob, ('replace', 'objectClass', ['top', 'person', 'organizationalPerson', 'inetOrgPerson']))) == 50, c('objectClass REPLACE refused (50)'))
  check(wd(mod(bob, ('delete', 'objectClass', ['organizationalPerson']))) == 50, c('objectClass value DELETE refused (50)'))
  check(wd(f'dn: {alice}\nchangetype: modify\ndelete: userPassword\nuserPassword: {node.human_pw}\n-\nadd: userPassword\nuserPassword: {human_new}-w\n') == 50,
        c('userPassword delete-old + add-new (the form that reaches the ACL) refused (50)'))
  check(wd(mod(bob, ('add', 'userPassword', ['Bob-1aA-bB-cC']))) == 50, c('userPassword ADD on an entry without one refused (50)'))
  check(wd(mod(bob, ('replace', 'memberOf', [g1]))) == SCHEMA_REFUSED['memberOf'], c('memberOf modify refused by the SCHEMA (19), not by the ACL'))
  for attr in SECRET_ATTRS + PWD_STATE:
    rc = wd(mod(secrets_dn, ('delete', attr + (';binary' if attr == 'pKCS8PrivateKey' else ''), [])))
    who_ = 'schema NO-USER-MODIFICATION, ACL not reached' if attr in SCHEMA_REFUSED else 'ACL'
    check(rc == SCHEMA_REFUSED.get(attr, 50), c(f'DELETE of {attr} on the entry that holds it refused by the {who_} (rc {rc})'))
  strict = {'shadowLastChange': ['19999'], 'userPassword': None, 'oathSecret': ['x'], 'oathEncKey': ['x'], 'oathTokenPIN': ['x'],
            'pwdAccountLockedTime': ['20260101000000Z'], 'pwdReset': ['TRUE'], 'pwdStartTime': ['20260101000000Z'],
            'pwdEndTime': ['20300101000000Z'], 'pwdPolicySubentry': [f'cn=default,ou=policies,{base_dn}']}
  for attr, values in strict.items():
    if values is None:
      continue
    check(wd(mod(secrets_dn, ('replace', attr, values))) == 50, c(f'REPLACE of {attr} refused by the ACL (50)'))
    check(wd(mod(bob, ('add', attr, values))) == 50, c(f'ADD of {attr} on a plain user refused by the ACL (50)'))
  print(f'--- {cfg}: W_data reads ---', flush=True)
  reads_deny(node, 'wdata', 'W_data')
  res = node.search('wdata', managed, '(objectClass=*)', ['member', 'mail', 'uid', 'objectClass'])
  check(res.returncode == 0 and has_attr(res.stdout, 'member', 'mail', 'uid'), c('reads the data attributes inside the subtree (assertions, reads)'))
  for dn in (other, system_dn, outsider, base_dn):
    rc = node.search('wdata', dn, '(objectClass=*)', ['dn'], 'base')
    check(not dn_set(rc.stdout), c(f'reads nothing at {dn} (rc {rc.returncode})'))

  print(f'--- {cfg}: W_data outside the ceiling (direct ldapmodify) ---', flush=True)
  outs = {
      'modify mail of an entry outside': mod(outsider, ('replace', 'mail', ['x@example.org'])),
      'modify sn of an entry outside': mod(outsider, ('replace', 'sn', ['x'])),
      'add member outside': mod('cn=g1,' + other, ('add', 'member', [alice])),
      'modify the sibling container ou=other': mod(other, ('add', 'ou', ['x'])),
      'modify M': mod(machine_dn, ('replace', 'sn', ['x'])),
      'modify W_data itself': mod(wd_dn, ('replace', 'sn', ['x'])),
      'modify W_lock': mod(wl_dn, ('replace', 'sn', ['x'])),
      'modify the container ou=system': mod(system_dn, ('add', 'ou', ['x'])),
      'modify the root entry': mod(base_dn, ('add', 'o', ['x'])),
      'modify the admin entry': mod(admin_dn, ('replace', 'description', ['x'])),
      'modify cn=config': mod(node.main_db, ('replace', 'olcSizeLimit', ['5'])),
      'modify cn=config (the global entry)': mod('cn=config', ('replace', 'olcLogLevel', ['none'])),
  }
  for label, ldif in outs.items():
    check(wd(ldif) == 50, c(f'{label}: refused (50)'))
  adds = {
      'add a user outside': person(f'uid=evil,{other}', 'evil'),
      'add under ou=system': person(f'uid=evil,{system_dn}', 'evil'),
      'add a sibling container below the root': f'dn: ou=evil,{base_dn}\nchangetype: add\nobjectClass: organizationalUnit\nou: evil\n',
      'add the reserved replication identity entry': f'dn: {repl_dn}\nchangetype: add\nobjectClass: organizationalRole\nobjectClass: simpleSecurityObject\ncn: replicator\nuserPassword: Evil-1aA-bB\n'
      if not node.prepare else None,
  }
  for label, ldif in adds.items():
    if ldif:
      check(wd(ldif) == 50, c(f'{label}: refused (50)'))
  for dn in (outsider, machine_dn, wd_dn, wl_dn, system_dn, other, admin_dn, repl_dn):
    exists = dn_set(node.search('admin', dn, '(objectClass=*)', ['dn'], 'base').stdout)
    if exists or dn != repl_dn:
      check(wd(f'dn: {dn}\nchangetype: delete\n') == 50, c(f'delete of {dn} refused (50)'))
  check(node.rc('wdata', f'dn: {outsider}\nchangetype: modrdn\nnewrdn: uid=outsider2\ndeleteoldrdn: 1\n', 'ldapmodify') == 50, c('ModifyDN of an entry outside refused (50)'))
  check(node.rc('wdata', f'dn: {bob}\nchangetype: modrdn\nnewrdn: uid=bob\ndeleteoldrdn: 0\nnewsuperior: {other}\n') == 50, c('moving a managed entry OUT of the subtree (to ou=other) refused (50)'))
  check(node.rc('wdata', f'dn: {bob}\nchangetype: modrdn\nnewrdn: uid=bob\ndeleteoldrdn: 0\nnewsuperior: {system_dn}\n') == 50, c('moving a managed entry into ou=system refused (50)'))
  gone = node.search('admin', base_dn, '(|(uid=evil)(ou=evil)(uid=outsider2))', ['dn'])
  check(not dn_set(gone.stdout), c('left nothing behind outside the subtree'))

  print(f'--- {cfg}: W_data documented limits (the ACL does not stop these; the app guard must) ---', flush=True)
  carol = f'uid=carol,{people}'
  check(wd(person(carol, 'carol')) == 0, c('creates carol'))
  limit(wd(f'dn: {carol}\nchangetype: modrdn\nnewrdn: uid=carol2\ndeleteoldrdn: 1\nnewsuperior: {groups}\n') == 0,
        c('ModifyDN renames AND moves an entry across containers inside the subtree (the app must never expose rename/move)'))
  check(wd(f'dn: uid=carol2,{groups}\nchangetype: delete\n') == 0, c('deletes the moved entry'))
  limit(wd(mod(bob, ('add', 'objectClass', ['extensibleObject']))) == 0, c('objectClass VALUE ADD on an existing entry passes (extensibleObject)'))
  limit(wd(mod(bob, ('delete', 'objectClass', ['extensibleObject']))) == 50, c('... but its removal is refused: a value added this way stays (needs the admin)'))
  g2 = f'cn=g2,{groups}'
  limit(wd(f'dn: {g2}\nchangetype: add\nobjectClass: groupOfNames\ncn: g2\nmember: {admin_dn}\n') == 0,
        c('entry creation takes any objectClass: a groupOfNames with member=<admin DN> is created'))
  check(wd(f'dn: {g2}\nchangetype: delete\n') == 0, c('deletes g2'))
  limit(wd(f'dn: ou=sub,{managed}\nchangetype: add\nobjectClass: organizationalUnit\nou: sub\n') == 0,
        c('creates a container directly under the write subtree base (children of the base is write)'))
  check(wd('dn: ou=sub,%s\nchangetype: delete\n' % managed) == 0, c('deletes ou=sub'))
  limit(wd(mod(managed, ('add', 'ou', ['x']))) == 0 and wd(mod(managed, ('delete', 'ou', ['x']))) == 0,
        c('modifies the write subtree base entry itself (ou is in the closed list); dnStrictlyWithinBase must keep it out'))
  limit(wd(mod(alice, ('replace', 'mail', ['alice2@example.org']))) == 0,
        c('modifies ANY user of the union subtree (alice, a human): protected DNs and per-client caps are the app guard'))
  # cross-client isolation: client A may write people only and client B groups only; one DN holds both
  uA, uB = f'uid=clientA,{people}', f'uid=clientB,{groups}'
  limit(wd(person(uA, 'clientA')) == 0 and wd(person(uB, 'clientB')) == 0 and wd(mod(uB, ('replace', 'mail', ['b@example.org']))) == 0,
        c('writes in BOTH containers of the union (cross-client isolation is the app guard\'s per-client subtree cap, not this ACL)'))
  for dn in (uA, uB):
    check(wd(f'dn: {dn}\nchangetype: delete\n') == 0, c(f'deletes {dn}'))
  check(wd(f'dn: {bob}\nchangetype: delete\n') == 0, c('deletes the leaf user'))


# ---- W_lock -------------------------------------------------------------------------------------------

def wlock_proof(node):
  cfg = node.cfg
  wl = lambda ldif: node.rc('wlock', ldif)
  c = lambda m: f'[{cfg}] W_lock {m}'
  lock_target = f'uid=lockme,{people}'
  check(node.rc('admin', person(lock_target, 'lockme', 'mail: l@example.org\n')) == 0, c('control: the admin creates the lock target'))
  check(node.tool('wlock', 'ldapwhoami', []).returncode == 0, c('binds'))
  print(f'--- {cfg}: W_lock allowed ---', flush=True)
  check(wl(mod(lock_target, ('replace', 'pwdAccountLockedTime', ['20260101000000Z']))) == 0, c('sets pwdAccountLockedTime'))
  got = node.search('admin', lock_target, '(objectClass=*)', ['pwdAccountLockedTime'], 'base').stdout
  check('pwdAccountLockedTime: 20260101000000Z' in got, c('the lock is really there (admin reads it)'))
  check(wl(mod(lock_target, ('delete', 'pwdAccountLockedTime', []))) == 0, c('clears pwdAccountLockedTime'))
  limit(wl(mod(alice, ('replace', 'pwdAccountLockedTime', ['20260101000000Z']))) == 0 and wl(mod(alice, ('delete', 'pwdAccountLockedTime', []))) == 0,
        c('locks and unlocks ANY user of the subtree (alice): which target may be locked is the app guard'))
  print(f'--- {cfg}: W_lock refused ---', flush=True)
  for attr, value in (('uid', 'x'), ('cn', 'x'), ('sn', 'x'), ('givenName', 'x'), ('mail', 'x@example.org'), ('departmentNumber', '1'),
                      ('o', 'x'), ('ou', 'x'), ('description', 'x'), ('telephoneNumber', '1'), ('title', 'x')):
    check(wl(mod(lock_target, ('replace' if attr != 'uid' else 'add', attr, [value]))) == 50, c(f'cannot write {attr} (50)'))
  check(wl(mod(g1, ('add', 'member', [lock_target]))) == 50, c('cannot add a group member (50)'))
  check(wl(mod(lock_target, ('replace', 'objectClass', ['top', 'person', 'organizationalPerson', 'inetOrgPerson']))) == 50, c('objectClass replace refused (50)'))
  check(wl(mod(lock_target, ('add', 'objectClass', ['extensibleObject']))) == 50, c('objectClass value add refused (50): unlike W_data'))
  check(wl(person(f'uid=lk2,{people}', 'lk2')) == 50, c('cannot create an entry (50)'))
  check(wl(f'dn: {lock_target}\nchangetype: delete\n') == 50, c('cannot delete an entry (50)'))
  check(wl(f'dn: {lock_target}\nchangetype: modrdn\nnewrdn: uid=lockme2\ndeleteoldrdn: 1\n') == 50, c('cannot rename an entry (50)'))
  check(wl(f'dn: {lock_target}\nchangetype: modrdn\nnewrdn: uid=lockme\ndeleteoldrdn: 0\nnewsuperior: {groups}\n') == 50, c('cannot move an entry (50)'))
  check(wl(f'dn: {alice}\nchangetype: modify\ndelete: userPassword\nuserPassword: {node.human_pw}\n-\nadd: userPassword\nuserPassword: {human_new}-l\n') == 50,
        c('cannot change userPassword (50)'))
  for attr in SECRET_ATTRS + PWD_STATE:
    if attr == 'pwdAccountLockedTime':
      continue
    rc = wl(mod(secrets_dn, ('delete', attr + (';binary' if attr == 'pKCS8PrivateKey' else ''), [])))
    who_ = 'schema NO-USER-MODIFICATION, ACL not reached' if attr in SCHEMA_REFUSED else 'ACL'
    check(rc == SCHEMA_REFUSED.get(attr, 50), c(f'DELETE of {attr} refused by the {who_} (rc {rc})'))
  for attr, values in (('shadowLastChange', ['19999']), ('oathSecret', ['x']), ('pwdReset', ['TRUE']), ('pwdStartTime', ['20260101000000Z'])):
    check(wl(mod(secrets_dn, ('replace', attr, values))) == 50, c(f'REPLACE of {attr} refused (50)'))
  print(f'--- {cfg}: W_lock outside the ceiling (direct ldapmodify) ---', flush=True)
  lock = ('replace', 'pwdAccountLockedTime', ['20260101000000Z'])
  for label, dn in (('an entry outside the subtree', outsider), ('M', machine_dn), ('W_data', wd_dn), ('W_lock itself', wl_dn),
                    ('the admin entry', admin_dn), ('the root entry', base_dn), ('the machine system container', system_dn)):
    check(wl(mod(dn, lock)) == 50, c(f'cannot lock {label} (50)'))
  check(wl(mod(node.main_db, ('replace', 'olcSizeLimit', ['5']))) == 50, c('cannot touch cn=config (50)'))
  check(wl(person(f'uid=evil,{other}', 'evil')) == 50, c('cannot create outside the subtree (50)'))
  print(f'--- {cfg}: W_lock reads ---', flush=True)
  reads_deny(node, 'wlock', 'W_lock', allowed=('pwdAccountLockedTime',))
  res = node.search('wlock', dave, '(objectClass=*)', ['pwdAccountLockedTime'], 'base')
  check(has_attr(res.stdout, 'pwdAccountLockedTime'), c('reads the lock attribute (it owns it) on a locked user'))
  res = node.search('wlock', managed, '(pwdAccountLockedTime=*)', ['dn'])
  check(dn_set(res.stdout) == [dave.lower()], c('finds the locked user by filter (dave only)'))
  rc = node.search('wlock', other, '(objectClass=*)', ['dn'], 'base')
  check(not dn_set(rc.stdout), c(f'reads nothing outside the subtree (rc {rc.returncode})'))
  check(node.rc('admin', f'dn: {lock_target}\nchangetype: delete\n') == 0, c('control: the admin deletes the lock target'))


# ---- M: the v1 read-only facts on the COMBINED layout, and every direct write refused -----------------------

def machine_proof(node):
  cfg = node.cfg
  m = lambda msg: f'[{cfg}] M {msg}'
  check(node.tool('machine', 'ldapwhoami', []).returncode == 0, m('binds'))
  seen = node.search('machine', managed, '(objectClass=*)', ['dn', 'uid', 'cn', 'objectClass'])
  adm = node.search('admin', managed, '(objectClass=*)', ['dn'])
  check(seen.returncode == 0 and dn_set(seen.stdout) == dn_set(adm.stdout) and has_attr(seen.stdout, 'uid', 'cn', 'objectClass'),
        m(f'reads exactly the entries of B ({len(dn_set(seen.stdout))}) with uid/cn/objectClass'))
  # v1 facts: secrets never returned, however asked
  reads_deny_m = node.search('admin', managed, '(objectClass=*)', ['*', '+'])
  values = {a: [v for v in attr_values(reads_deny_m.stdout, a) if len(v) >= 8] for a in SECRET_ATTRS}
  for attr in SECRET_ATTRS:
    check(bool([v for v in attr_values(reads_deny_m.stdout, attr) if v]), m(f'control: the admin reads a seeded {attr}'))
    for label, asks in (('explicit', [attr]), ('*', ['*']), ('+', ['+'])):
      res = node.search('machine', secrets_dn, '(objectClass=*)', asks, 'base')
      leaked = has_attr(res.stdout, attr) or any(v in res.stdout for v in values[attr])
      check(res.returncode == 0 and not leaked, m(f'{attr}: asking {label} returns neither the attribute nor its value'))
    check(not dn_set(node.search('machine', managed, f'({attr}=*)', ['dn']).stdout), m(f'{attr}: filter ({attr}=*) matches nothing'))
  # outside B: nothing, not even hints
  hints = ['dn', 'uid', 'objectClass', 'entry', 'cn']
  for label, args in (('root base', (base_dn, 'base')), ('ou=system', (system_dn, 'one')), ('own entry', (machine_dn, 'base')),
                      ('W_data entry', (wd_dn, 'base')), ('W_lock entry', (wl_dn, 'base')), ('ou=other', (other, 'sub')),
                      ('whole directory from the root', (base_dn, 'sub'))):
    res = node.search('machine', args[0], '(objectClass=*)', hints, args[1])
    check(not dn_set(res.stdout) and res.returncode in (0, 32), m(f'outside B / {label}: no entry (rc {res.returncode})'))
  res = node.tool('machine', 'ldapsearch', ['-LLL', '-b', 'cn=config', '-s', 'sub', '(objectClass=*)', 'dn'])
  check(not dn_set(res.stdout), m('reads nothing under cn=config'))
  # ALL direct writes refused (50), including every shape the W identities may do
  bob = f'uid=mbob,{people}'
  attempts = {
      'ldapadd of a user inside B': person(bob, 'mbob'),
      'ldapadd in ou=other': person(f'uid=mbob,{other}', 'mbob'),
      'ldapadd in ou=system': person(f'uid=mbob,{system_dn}', 'mbob'),
      'ldapadd of a group': f'dn: cn=mg,{groups}\nchangetype: add\nobjectClass: groupOfNames\ncn: mg\nmember: {alice}\n',
      'ldapadd below the root': f'dn: ou=evil,{base_dn}\nchangetype: add\nobjectClass: organizationalUnit\nou: evil\n',
      'modify mail of a user inside B': mod(f'uid=u01,{people}', ('replace', 'mail', ['m@example.org'])),
      'modify description inside B': mod(f'uid=u01,{people}', ('replace', 'description', ['m'])),
      'modify an entry outside B': mod(outsider, ('replace', 'description', ['m'])),
      'add a group member': mod(g1, ('add', 'member', [f'uid=u01,{people}'])),
      'remove a group member': mod(g1, ('delete', 'member', [alice])),
      'objectClass value add': mod(f'uid=u01,{people}', ('add', 'objectClass', ['extensibleObject'])),
      'set pwdAccountLockedTime': mod(f'uid=u01,{people}', ('replace', 'pwdAccountLockedTime', ['20260101000000Z'])),
      'modify its own description': mod(machine_dn, ('replace', 'description', ['m'])),
      'add to its own entry': mod(machine_dn, ('add', 'description', ['m'])),
      'replace its own userPassword': mod(machine_dn, ('replace', 'userPassword', ['Hijack-1aA-bB-cC'])),
      'replace its own shadowLastChange': mod(machine_dn, ('replace', 'shadowLastChange', ['19001'])),
      'delete-old + add-new of its own password': f'dn: {machine_dn}\nchangetype: modify\ndelete: userPassword\nuserPassword: {passwords["machine"]}\n-\nadd: userPassword\nuserPassword: Hijack-1aA-bB-cC\n',
      'modify W_data': mod(wd_dn, ('replace', 'sn', ['m'])),
      'modify W_lock': mod(wl_dn, ('replace', 'sn', ['m'])),
      'delete a user inside B': f'dn: uid=u01,{people}\nchangetype: delete\n',
      'delete its own entry': f'dn: {machine_dn}\nchangetype: delete\n',
      'rename a user inside B': f'dn: uid=u01,{people}\nchangetype: modrdn\nnewrdn: uid=u01x\ndeleteoldrdn: 1\n',
      'move a user inside B': f'dn: uid=u01,{people}\nchangetype: modrdn\nnewrdn: uid=u01\ndeleteoldrdn: 0\nnewsuperior: {groups}\n',
      'rename an entry outside B': f'dn: {outsider}\nchangetype: modrdn\nnewrdn: uid=outsiderx\ndeleteoldrdn: 1\n',
      'modify cn=config': mod(node.main_db, ('replace', 'olcSizeLimit', ['5'])),
  }
  for label, ldif in attempts.items():
    check(node.rc('machine', ldif) == 50, m(f'{label}: insufficient access (50)'))
  pw = node.tool('machine', 'ldappasswd', ['-s', 'Hijack-1aA-bB-cC', machine_dn])
  check(pw.returncode != 0 and 'Insufficient access (50)' in pw.stdout + pw.stderr, m('ldappasswd of itself refused (50)'))
  left = node.search('admin', base_dn, '(|(uid=mbob)(ou=evil)(cn=mg)(uid=u01x)(uid=outsiderx))', ['dn'])
  check(not dn_set(left.stdout), m(f'after {len(attempts) + 1} write attempts nothing was created or renamed'))
  check(node.tool('machine', 'ldapwhoami', []).returncode == 0, m('still binds with its password after the attempts'))


# ---- one configuration ---------------------------------------------------------------------------------

def layout_check(node, label, write_dn, **kw):
  want = expected_layout(node, write_dn, **kw)
  got = acl_bodies(node)
  ok = got == want
  check(ok, f'[{node.cfg}] olcAccess layout {label}: exactly {len(want)} rules in the defined order')
  if not ok:
    for i, (g, w) in enumerate(zip(got + [''] * len(want), want + [''] * len(got))):
      if g != w:
        print(f'  first difference at {{{i}}}:\n    got : {g[:170]}\n    want: {w[:170]}', flush=True)
        break
  return ok


def own_dn_only(node):
  """Every W rule names only its own DN in a `by` clause (and ends in `by * break`)."""
  _, rules = node.olc_access()
  bad = []
  for r in rules:
    names = re.findall(r'by dn\.exact="([^"]*)"', r)
    if (wd_dn in names or wl_dn in names) and (len(set(names)) != 1 or not r.rstrip().endswith('by * break')):
      bad.append(r[:80])
  check(not bad, f'[{node.cfg}] every rule naming W_data / W_lock names only that DN in its by clauses and ends in `by * break` {bad}')


def run_config(node):
  cfg = node.cfg
  print(f'=== configuration {cfg}: replication identity={"prepare" if node.prepare else "none"}, '
        f'LDAP_ANONYMOUS_READ_BASE={node.anon_base or "(unset)"} ===', flush=True)
  node.start()
  seed(node)
  if node.prepare:
    node.switch_to_prepare()
  raw0, rules0 = node.olc_access()
  bodies0 = [norm(re.sub(r'^\{\d+\}', '', r)) for r in rules0]
  node.repl_rules = bodies0[:1] if node.prepare else []
  node.image_rules = bodies0[1:] if node.prepare else bodies0
  if node.prepare:
    check(idx_of(node, repl_dn) == [0], f'[{cfg}] prepare put the replication identity rule at {{0}}')
  else:
    check(idx_of(node, repl_dn) == [], f'[{cfg}] no replication identity rule')
  check((f'dn.subtree="{managed}"' in ' '.join(node.image_rules)) == bool(node.anon_base),
        f'[{cfg}] the image rules {"carry" if node.anon_base else "do not carry"} the anonymous read base rule')
  print(f'INFO: [{cfg}] {len(node.image_rules)} image rules, {len(node.repl_rules)} replication rule', flush=True)

  # Controls: before any rule M and the W identities are ordinary users, which the fragments must take away.
  ctl = node.search('wdata', other, '(objectClass=*)', ['dn'])
  n_other = len(dn_set(node.search('admin', other, '(objectClass=*)', ['dn']).stdout))
  check(n_other >= 3 and len(dn_set(ctl.stdout)) == n_other, f'[{cfg}] control: before the rules W_data reads outside the subtree (by users read, {n_other} entries)')
  check(node.rc('wdata', mod(wd_dn, ('replace', 'description', ['self']))) == 0, f'[{cfg}] control: before the rules W_data writes its own entry (by self write)')
  check(node.rc('wdata', mod(f'uid=u01,{people}', ('replace', 'description', ['w']))) == 50, f'[{cfg}] control: before the rules W_data cannot write another entry')

  install_m(node)
  layout_check(node, 'with M only', managed, wd=False, wl=False)
  check(idx_of(node, machine_dn) == list(range(len(node.repl_rules), len(node.repl_rules) + 3)),
        f'[{cfg}] M rules at {{{len(node.repl_rules)}}}..{{{len(node.repl_rules) + 2}}}')
  raw_m, _ = node.olc_access()

  probes(node)
  before = probes(node)  # the first run settles the probes' own writes
  fragdir = fragdir_for(node, cfg)
  o = len(node.repl_rules)
  out = guide_install(node, fragdir, 'write-data.ldif', wd_dn, managed)
  check(re.search(rf'^BASE={o + 3}$', out, re.M) is not None, f'[{cfg}] guide 4.2 computed BASE={o + 3} for W_data ({"replication + M" if o else "M"} lead): {out.strip()[-60:]}')
  layout_check(node, 'with M and W_data', managed, wl=False)
  check(idx_of(node, wd_dn) == list(range(o + 3, o + 3 + k_installed('write-data.ldif'))),
        f'[{cfg}] W_data rules at {{{o + 3}}}..{{{o + 10}}} ({k_installed("write-data.ldif")} contiguous values naming W_data)')
  acl_w1 = acl_bodies(node)
  out = guide_install(node, fragdir, 'write-data.ldif', wd_dn, managed)
  check('refusing: ' in out and acl_bodies(node) == acl_w1, f'[{cfg}] a second W_data apply is refused by the guide itself and changes nothing')
  out = guide_install(node, fragdir, 'write-lock.ldif', wl_dn, managed)
  check(re.search(rf'^BASE={o + 3 + k_installed("write-data.ldif")}$', out, re.M) is not None or mutation == 'reorder',
        f'[{cfg}] guide 4.2 computed the W_lock BASE counting W_data: {out.strip()[-40:]}')
  layout_check(node, 'with M, W_data and W_lock', managed)
  check(idx_of(node, wl_dn) == list(range(o + 11, o + 11 + k_installed('write-lock.ldif'))), f'[{cfg}] W_lock rules at {{{o + 11}}}..{{{o + 16}}}')
  check(idx_of(node, machine_dn) == list(range(o, o + 3)) and (idx_of(node, repl_dn) == ([0, o + 4, o + 12] if o else [o + 4, o + 12])),
        f'[{cfg}] M still at {{{o}}}..{{{o + 2}}}; the replication identity is named at {{0}} and by the two REPL_DN deny rules only')
  own_dn_only(node)
  if node.prepare:
    node.restart()
    layout_check(node, 'after a restart (prepare keeps its rule first)', managed)
    check(idx_of(node, repl_dn)[0] == 0, f'[{cfg}] the replication rule is still {{0}} after the restart')
    node.put('/tmp/.pw-secrets', node.secrets_pw)
    for name in ('machine', 'wdata', 'wlock', 'id'):
      node.put(f'/tmp/.pw-{name}', passwords[name])
    node.put('/tmp/.pw-human', node.human_pw)
  raw_w, _ = node.olc_access()

  after = probes(node)
  for name in before:
    check(before[name] == after[name], f'[{cfg}] unchanged for existing identities: {name} (rc {before[name][0]})')

  wdata_proof(node)
  wlock_proof(node)
  machine_proof(node)

  # ---- rollback: refusal, offset-aware order, byte for byte
  print(f'--- {cfg}: rollback ---', flush=True)
  out = guide_rollback(node, 'uid=nobody,' + system_dn, 6)
  check('refusing: ' in out and node.olc_access()[0] == raw_w, f'[{cfg}] rollback of a not-installed fragment refuses and changes nothing')
  order = ('wl', 'wd') if not node.prepare else ('wd', 'wl')
  for which in order:
    if which == 'wl':
      guide_rollback(node, wl_dn, k_installed('write-lock.ldif'))
    else:
      guide_rollback(node, wd_dn, k_installed('write-data.ldif'))
    left = [w for w in ('wd', 'wl') if w not in order[:order.index(which) + 1]]
    layout_check(node, f'after rolling back {which}', managed, wd='wd' in left, wl='wl' in left)
  raw_back, _ = node.olc_access()
  check(raw_back == raw_m, f'[{cfg}] olcAccess after the rollback equals the state before the write fragments byte for byte')
  check(node.rc('wdata', mod(alice, ('replace', 'mail', ['after@example.org']))) == 50, f'[{cfg}] W_data no longer writes after the rollback (50)')
  check(len(dn_set(node.search('wdata', other, '(objectClass=*)', ['dn']).stdout)) == n_other, f'[{cfg}] after the rollback W_data is an ordinary user again (reads outside)')
  check(node.rc('machine', mod(f'uid=u01,{people}', ('replace', 'description', ['m']))) == 50, f'[{cfg}] M is still read-only after the rollback (50)')

  # ---- the write subtree widened to the root: the SYSTEM_DN / REPL_DN backstops
  print(f'--- {cfg}: write subtree widened to the root ---', flush=True)
  guide_install(node, fragdir, 'write-data.ldif', wd_dn, base_dn)
  guide_install(node, fragdir, 'write-lock.ldif', wl_dn, base_dn)
  layout_check(node, 'with the root as write subtree', base_dn)
  wd = lambda ldif: node.rc('wdata', ldif)
  wl = lambda ldif: node.rc('wlock', ldif)
  w = lambda m: f'[{cfg}] root-wide {m}'
  check(wd(mod(outsider, ('replace', 'mail', ['wide@example.org']))) == 0, w('W_data now writes where it was refused (ou=other)'))
  check(wl(mod(outsider, ('replace', 'pwdAccountLockedTime', ['20260101000000Z']))) == 0 and wl(mod(outsider, ('delete', 'pwdAccountLockedTime', []))) == 0,
        w('W_lock now locks where it was refused (ou=other)'))
  for label, ldif in (('M entry', mod(machine_dn, ('replace', 'sn', ['x']))), ('W_lock entry', mod(wl_dn, ('replace', 'sn', ['x']))),
                      ('W_data entry (itself)', mod(wd_dn, ('replace', 'sn', ['x']))),
                      ('ou=system container', mod(system_dn, ('add', 'ou', ['x']))),
                      ('an add below ou=system', person(f'uid=evil,{system_dn}', 'evil')),
                      ('delete of M', f'dn: {machine_dn}\nchangetype: delete\n'),
                      ('password change of M', f'dn: {machine_dn}\nchangetype: modify\ndelete: userPassword\nuserPassword: {passwords["machine"]}\n-\nadd: userPassword\nuserPassword: Evil-1aA-bB\n')):
    check(wd(ldif) == 50, w(f'backstop SYSTEM_DN: W_data {label} refused (50)'))
  check(wl(mod(machine_dn, ('replace', 'pwdAccountLockedTime', ['20260101000000Z']))) == 50, w('backstop SYSTEM_DN: W_lock cannot lock M (50)'))
  check(wl(mod(wd_dn, ('replace', 'pwdAccountLockedTime', ['20260101000000Z']))) == 50, w('backstop SYSTEM_DN: W_lock cannot lock W_data (50)'))
  if node.prepare:
    check(wd(mod(repl_dn, ('replace', 'description', ['x']))) == 50 and wd(mod(repl_dn, ('add', 'cn', ['x']))) == 50,
          w('backstop REPL_DN: W_data cannot modify the replication identity entry (50)'))
    check(wd(f'dn: {repl_dn}\nchangetype: delete\n') == 50, w('backstop REPL_DN: W_data cannot delete the replication identity entry (50)'))
    check(wl(mod(repl_dn, ('replace', 'pwdAccountLockedTime', ['20260101000000Z']))) == 50, w('backstop REPL_DN: W_lock cannot lock the replication identity (50)'))
    check(len(dn_set(node.search('admin', repl_dn, '(objectClass=*)', ['dn'], 'base').stdout)) == 1, w('control: the replication identity entry still exists'))
  else:
    check(wd(f'dn: {repl_dn}\nchangetype: add\nobjectClass: organizationalRole\nobjectClass: simpleSecurityObject\ncn: replicator\nuserPassword: Evil-1aA-bB\n') == 50,
          w('backstop REPL_DN: W_data cannot CREATE the reserved cn=replicator entry (it would become the replication identity, 50)'))
  reads = node.search('wdata', system_dn, '(objectClass=*)', ['dn'])
  check(not dn_set(reads.stdout), w('W_data still reads nothing under ou=system'))
  limit(wd(mod(admin_dn, ('add', 'ou', ['x']))) == 0 and wd(mod(admin_dn, ('delete', 'ou', ['x']))) == 0,
        w('the admin entry (directly under the root, not under SYSTEM_DN) IS writable for the closed attributes: move protected identities under SYSTEM_DN or keep WRITE_DN narrow'))
  check(wd(mod(admin_dn, ('replace', 'userPassword', ['Evil-1aA-bB']))) in (50, 19) and wd(mod(admin_dn, ('add', 'userPassword', ['Evil-1aA-bB']))) == 50,
        w('... but never its userPassword (50)'))
  guide_rollback(node, wl_dn, k_installed('write-lock.ldif'))
  guide_rollback(node, wd_dn, k_installed('write-data.ldif'))
  check(node.olc_access()[0] == raw_m, f'[{cfg}] rolled back again: byte for byte the state before the write fragments')
  node.stop()


def main():
  print(f'Run {name_prefix}: image {ldap_image}, mutation={mutation or "none"}', flush=True)
  require(run(['docker', 'version', '--format', 'ok']).returncode == 0, 'docker is not available')
  for name in ('write-data.ldif', 'write-lock.ldif'):
    want = significant(fixture_text(name))
    check(any(significant(b) == want for b in guide_ldif_blocks(write_guide)), f'write guide contains the committed {name} verbatim as one block')
  for name in ('main-database.ldif',):
    want = significant(fixture_text(name))
    check(any(significant(b) == want for b in guide_ldif_blocks(read_guide)), f'read guide contains the committed {name} verbatim')
  guide = norm(read_guide.read_text())
  check(norm(M_APPLY) in guide and norm(M_SHIFT + M_APPLY) in guide, 'read guide contains the M apply commands exactly as this script runs them')
  check(guide_sh('PRESENT=') != guide_sh('FIRST='), 'install (4.2) and rollback (7) commands cut out of the write guide')
  check(len(ldif_values(fixture_text('write-data.ldif'))) == 8 and len(ldif_values(fixture_text('write-lock.ldif'))) == 6,
        'the fixtures hold 8 W_data and 6 W_lock rules')
  for key in ('n0', 'n1', 'p0', 'p1'):
    if key in only_configs:
      run_config(Node(key))


if __name__ == '__main__':
  code = 0
  try:
    main()
  except Exception as e:
    print('ERROR: ' + mask(e), flush=True)
    import traceback
    traceback.print_exc()
    for cn in containers:
      res = run(['docker', 'logs', '--tail', '40', cn])
      print(f'--- docker logs {cn} (scrubbed, last 40 lines) ---', file=sys.stderr)
      print(mask(res.stdout + res.stderr), file=sys.stderr)
    code = 1
  print(f'RESULT: {passed} checks passed, {len(failed)} failed, mutation={mutation or "none"}, {time.monotonic() - start_time:.0f}s', flush=True)
  for f in failed:
    print('  FAILED: ' + f, flush=True)
  sys.exit(1 if failed or code else 0)
