#!/usr/bin/env python3
"""Live measurement of the v2c multi-provider rule R-3 (#417 item (c), AC-010c, E-17; D379-10/13).

docs/machine-write-scope-v2/CHANGE.md R-3: concurrent initial password sets on one pending account give
exactly ONE success. E-17 measured that on a single slapd. For multi-provider replication (entryCSN
last-write-wins, AGENTS.md) the design installs the W_cred bundle (write-cred.ldif) on ONE pinned provider A,
puts write-cred-deny.ldif (`to * by W_cred none`) in the same place on every other provider B, and pins the
application to A. This script measures that on two real providers built from the image
(LDAP_REPLICATION_ENABLED, serverID 1/2, one network), with the ACL set up the way test-machine-write-cred-
experiments.py FINAL does (olcAddContentAcl TRUE, pending policy copy, W_data v2c rules, W_cred no-lockout
policy; the pending account is made by W_data, marker in employeeType, creatorsName = W_data).

  M1  W_cred Password Modify and plain Modify directly on B (deny rule): 50 insufficientAccess
  M2  N=10 parallel W_cred Password Modify on A, different values, ROUNDS rounds: exactly one 0, nine 50;
      after replication converges B holds the same single winning value (the winner binds on both nodes,
      losers fail on both, the stored hashes are equal)
  M3  split race: W_cred on A (5 parallel) AND on B (5 parallel) released together, ROUNDS rounds, and the
      same with B partitioned from the network while A sets: B refuses (50), one value survives
  M4  cn=config replication: the shipped topology puts olcSyncrepl on the main database only; cn=config is
      NOT replicated (olcAccess differs per node, a probe rule written on A never reaches B)
  M5  negative control: the bundle on BOTH providers. A partitioned B accepts a second "first password"
      (two successes), and after healing one value silently wins on both nodes (asserted: the loss is
      shown). The same race without a partition (one set on A, one on B, released together) is asserted to
      converge on every round (#432: the carried retry_diff patch in image/patches/); how often both sets
      succeed is only counted, since that depends on replication latency

Exit 0 only if every assertion holds. The raw numbers are printed as `MEASURE ...` lines. Every password is a
fresh random sentinel; output carries only counts and result codes.

Run (docker): python3 scripts/test/test-machine-write-cred-multiprovider-live.py
Override LDAPIUM_IMAGE (default ldapium:e2e), LDAPIUM_TEST_PREFIX, MP_ROUNDS (default 5), MP_N (default 10).
"""
import hashlib
import os
import pathlib
import re
import secrets
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'lib'))
from machine_live import ADMIN_DN, BASE_DN, FIXTURES, Live, Slapd, ensure  # noqa: E402

live = Live('ldapium-v2cmp-', deadline_seconds=1500)
ROUNDS = int(os.environ.get('MP_ROUNDS', '5'))
N = int(os.environ.get('MP_N', '10'))
SYSTEM_DN = 'ou=system,' + BASE_DN
PEOPLE = 'ou=people,' + BASE_DN
WDATA_DN = 'uid=machine-write-data,' + SYSTEM_DN
WCRED_DN = 'uid=machine-write-cred,' + SYSTEM_DN
REPL_DN = 'cn=replicator,' + BASE_DN
PENDING_POL = 'cn=credential-pending,ou=policies,' + BASE_DN
WCRED_POL = 'cn=machine-writers,ou=policies,' + BASE_DN
PRIV = 'cn=admins,ou=groups,' + BASE_DN
MARKER = 'ldapium-credential-pending:' + secrets.token_hex(8)


class Node(Slapd):
  """One provider of a 2-node multi-provider cluster (serverID = position in the peer list)."""

  def __init__(self, live, name, sid, peers, admin_password):
    super().__init__(live, name)
    self.admin_password = admin_password
    self.sid = sid
    self.peers = peers

  def start(self):
    l = self.live
    l.register(self.name)
    env = l.write_secret_file(self.name + '.env', f'LDAP_ADMIN_PASSWORD={self.admin_password}\n')
    res = l.run(['docker', 'run', '-d', '--name', self.name, '--hostname', self.name, '--network', l.network,
                 '--env-file', env, '-e', 'LDAP_ROOT_DN=' + BASE_DN, '-e', 'LDAP_PASSWORD_POLICY_ENABLED=true',
                 '-e', 'LDAP_REPLICATION_ENABLED=true', '-e', f'LDAP_SERVER_ID={self.sid}',
                 '-e', 'LDAP_REPLICATION_PEERS=' + self.peers, l.ldap_image])
    ensure(res.returncode == 0, res.stderr)

    def ready():
      put = l.run(['docker', 'exec', '-i', self.name, 'sh', '-c', 'umask 077; cat > /tmp/.pw-admin'], input=self.admin_password)
      return put.returncode == 0 and self.admin_tool('ldapsearch', ['-b', BASE_DN, '-s', 'base']).returncode == 0
    l.wait_until(ready, self.name + ' readiness (the base DIT arrives by syncrepl on serverID 2)', 120)


def fixture_rules(name, tokens):
  """olcAccess values of a shipped fixture, tokens substituted, index stripped, LDIF folding undone."""
  text = (FIXTURES / name).read_text()
  for k, v in tokens.items():
    text = text.replace('@' + k + '@', v)
  text = re.sub(r'\n ', '', '\n'.join(l for l in text.splitlines() if not l.startswith('#')))
  return [re.sub(r'^\{\d+\}', '', l[len('olcAccess: '):]) for l in text.splitlines() if l.startswith('olcAccess: ')]


def lcode(r):
  """LDAP result code of a CLI run: 0 ok, else the (NN) in the output."""
  if r.returncode == 0:
    return 0
  m = re.search(r'\((\d+)\)', r.stdout + r.stderr)
  return int(m.group(1)) if m else -r.returncode


def measure(text):
  print('MEASURE ' + live.mask(text), flush=True)


def main():
  # ---- the cluster ---------------------------------------------------------------------------------------------

  live.make_network()
  admin_pw = live.secret(secrets.token_urlsafe(24))
  n1, n2 = live.name_prefix + '-a', live.name_prefix + '-b'
  peers = f'ldap://{n1}:389,ldap://{n2}:389'
  A = Node(live, n1, 1, peers, admin_pw)
  B = Node(live, n2, 2, peers, admin_pw)
  A.start()
  A.seed(users=2, groups=1)
  B.start()
  WD = (WDATA_DN, '/tmp/.pw-wdata')
  WC = (WCRED_DN, '/tmp/.pw-wcred')
  pws = {k: live.secret(k + '-' + secrets.token_urlsafe(18)) for k in ('wdata', 'wcred')}
  for dn, key in ((WDATA_DN, 'wdata'), (WCRED_DN, 'wcred')):
    uid = dn.split(',', 1)[0][4:]
    ensure(A.admin_tool('ldapadd', [], f'dn: {dn}\nobjectClass: inetOrgPerson\nuid: {uid}\ncn: {uid}\nsn: {uid}\nuserPassword: {pws[key]}\n').returncode == 0, key)
  default = [l for l in A.admin_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=default,ou=policies,' + BASE_DN, '-s', 'base']).stdout.splitlines()
             if l and not l.startswith('dn: ') and not l.lower().startswith(('cn:', 'pwdsafemodify:', 'pwdcheckquality:'))]
  ensure(A.admin_tool('ldapadd', [], f'dn: {PENDING_POL}\ncn: credential-pending\n' + '\n'.join(default) + '\npwdSafeModify: FALSE\npwdCheckQuality: 2\n').returncode == 0, 'pending policy')
  wcp = (FIXTURES / 'wcred-policy.ldif').read_text().replace('@WCRED_POLICY_DN@', WCRED_POL).replace('@WCRED_POLICY_CN@', 'machine-writers')
  ensure(A.admin_tool('ldapadd', [], wcp).returncode == 0, 'W_cred no-lockout policy')
  ensure(A.admin_tool('ldapmodify', [], f'dn: {WCRED_DN}\nchangetype: modify\nadd: pwdPolicySubentry\npwdPolicySubentry: {WCRED_POL}\n').returncode == 0, 'W_cred policy attach')


  def exists_on(node, dn):
    return node.admin_tool('ldapsearch', ['-LLL', '-b', dn, '-s', 'base', 'dn']).stdout.startswith('dn: ')


  for dn in (WDATA_DN, WCRED_DN, PENDING_POL, WCRED_POL):
    live.wait_until(lambda dn=dn: exists_on(B, dn), 'replication of ' + dn, 60)
  for node in (A, B):
    node.put_password('/tmp/.pw-wdata', pws['wdata'])
    node.put_password('/tmp/.pw-wcred', pws['wcred'])

  tokens = {'WDATA_DN': WDATA_DN, 'WCRED_DN': WCRED_DN, 'WRITE_DN': BASE_DN, 'CRED_DN': PEOPLE, 'SYSTEM_DN': SYSTEM_DN, 'REPL_DN': REPL_DN,
            'PENDING_POLICY_DN': PENDING_POL, 'PRIV_FILTER': f'(!(memberOf={PRIV}))', 'PRIV_GROUP_DN': PRIV}
  main_db = {}
  for node in (A, B):
    out = node.config_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=config', f'(&(objectClass=olcMdbConfig)(olcSuffix={BASE_DN}))', 'dn']).stdout
    main_db[node.name] = next(l[4:] for l in out.splitlines() if l.startswith('dn: '))
    tokens['MAIN_DB_DN'] = main_db[node.name]
    base, dcred = fixture_rules('write-data.ldif', tokens), fixture_rules('write-data-cred.ldif', tokens)
    rules = base[:2] + dcred + base[2:]
    node.wd_count = len(rules)
    node.rules_at = len(rules)          # W_cred bundle / deny go right behind the W_data rules (guide 8.5)
    body = (f'dn: {main_db[node.name]}\nchangetype: modify\nreplace: olcAddContentAcl\nolcAddContentAcl: TRUE\n-\nadd: olcAccess\n'
            + ''.join(f'olcAccess: {{{i}}}{r}\n' for i, r in enumerate(rules)))
    ensure(node.config_tool('ldapmodify', [], body).returncode == 0, 'W_data rules on ' + node.name)


  def install_wcred(node, *frags):
    """frags: write-cred.ldif (the 7-rule bundle) and/or write-cred-deny.ldif (1 rule), in this order, at the guide's place."""
    rules = [r for frag in frags for r in fixture_rules(frag, dict(tokens, MAIN_DB_DN=main_db[node.name]))]
    frag = '+'.join(frags)
    body = f'dn: {main_db[node.name]}\nchangetype: modify\nadd: olcAccess\n' + ''.join(f'olcAccess: {{{node.rules_at + i}}}{r}\n' for i, r in enumerate(rules))
    r = node.config_tool('ldapmodify', [], body)
    ensure(r.returncode == 0, f'{frag} on {node.name}: ' + live.mask(r.stderr))
    node.wcred_rules = len(rules)


  def remove_wcred(node):
    body = f'dn: {main_db[node.name]}\nchangetype: modify\n' + ''.join(
        f'delete: olcAccess\nolcAccess: {{{node.rules_at}}}\n-\n' for _ in range(node.wcred_rules))
    r = node.config_tool('ldapmodify', [], body)
    ensure(r.returncode == 0, 'remove W_cred rules on ' + node.name + ': ' + live.mask(r.stderr))


  def olc_access(node):
    out = node.config_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', main_db[node.name], '-s', 'base', 'olcAccess']).stdout
    return re.findall(r'^olcAccess: (.*)$', out, re.M)


  install_wcred(A, 'write-cred.ldif')
  install_wcred(B, 'write-cred-deny.ldif')
  measure(f'setup: A olcAccess values {len(olc_access(A))} (W_data {A.wd_count} + W_cred bundle {A.wcred_rules} + image rules), B {len(olc_access(B))} (W_data {B.wd_count} + deny {B.wcred_rules} + image rules)')

  # ---- helpers: accounts, races, convergence -------------------------------------------------------------------

  counter = [0]


  def pending(uid):
    """A pending account made by W_data on A, replicated to B; returns its DN."""
    dn = f'uid={uid},{PEOPLE}'
    r = A.tool('ldapadd', [], WD[0], WD[1], f'dn: {dn}\nobjectClass: inetOrgPerson\nuid: {uid}\ncn: {uid}\nsn: {uid}\n'
               f'employeeType: {MARKER}\npwdPolicySubentry: {PENDING_POL}\n')
    ensure(r.returncode == 0, f'W_data pending Add {uid}: ' + live.mask(r.stderr))
    live.wait_until(lambda: exists_on(B, dn), f'replication of {uid}', 60)
    return dn


  def secret_file(node):
    """A fresh random password on `node`, returns (value, path)."""
    counter[0] += 1
    v = live.secret(f'MP{counter[0]}-' + secrets.token_urlsafe(18))
    path = f'/tmp/.mp-{counter[0]}'
    node.put_password(path, v)
    return v, path


  def attempt_script(dn, files, gate):
    """Shell for one container: len(files) parallel W_cred Password Modify, released when `gate` exists."""
    script = ''
    for i, p in enumerate(files):
      script += (f'( while [ ! -e {gate} ]; do :; done; ldappasswd -x -H ldap://127.0.0.1 -D "{WCRED_DN}" -y /tmp/.pw-wcred -T {p} "{dn}" '
                 f'> /tmp/.out{i} 2>&1; echo $? > /tmp/.rc{i} ) &\n')
    script += 'wait\n' + ''.join(f'echo "@@ $(cat /tmp/.rc{i}) $(tr "\\n" " " < /tmp/.out{i})"\n' for i in range(len(files)))
    return script


  def parse(out):
    rcs = []
    for line in out.splitlines():
      if line.startswith('@@ '):
        rc = int(line.split()[1])
        m = re.search(r'\((\d+)\)', line)
        rcs.append(0 if rc == 0 else (int(m.group(1)) if m else -rc))
    return rcs


  def race(dn, plan):
    """plan: [(node, n)]. n parallel W_cred Password Modify on each node, all released together.
    Returns {node.name: (rcs, [(value, path)])}."""
    gate = f'/tmp/.go-{secrets.token_hex(4)}'
    jobs = []
    for node, n in plan:
      pairs = [secret_file(node) for _ in range(n)]
      p = subprocess.Popen(['docker', 'exec', '-i', node.name, 'sh'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
      jobs.append((node, pairs, p, attempt_script(dn, [x[1] for x in pairs], gate)))
    outs = {}
    threads = []
    for node, pairs, p, script in jobs:
      t = threading.Thread(target=lambda p=p, s=script, name=node.name: outs.__setitem__(name, p.communicate(s)[0]))
      t.start()
      threads.append(t)
    time.sleep(1.5)   # every shell is parked on the gate
    rel = [threading.Thread(target=lambda node=node: live.run(['docker', 'exec', node.name, 'touch', gate])) for node, _, _, _ in jobs]
    for t in rel:
      t.start()
    for t in rel + threads:
      t.join()
    return {node.name: (parse(outs[node.name]), pairs) for node, pairs, _, _ in jobs}


  def stored(node, dn):
    out = node.admin_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', dn, '-s', 'base', 'userPassword']).stdout
    return ''.join(l for l in out.splitlines() if l.lower().startswith('userpassword'))


  def converge(dn, timeout=120):
    live.wait_until(lambda: stored(A, dn) != '' and stored(A, dn) == stored(B, dn), f'{dn} userPassword equal on both providers', timeout)


  def entry_csn(node, dn):
    out = node.admin_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', dn, '-s', 'base', 'entryCSN']).stdout
    return next((l.split(':', 1)[1].strip() for l in out.splitlines() if l.lower().startswith('entrycsn:')), '<missing>')


  def snapshot(dn):
    """Redacted state of `dn` on both providers: sha256 prefixes of the userPassword line, never the value (#432)."""
    fp = lambda node: hashlib.sha256(stored(node, dn).encode()).hexdigest()[:10]
    return f'userPassword sha256[:10] A {fp(A)} B {fp(B)}; entryCSN A {entry_csn(A, dn)} B {entry_csn(B, dn)}'


  def converged(dn, timeout):
    """Non-raising convergence probe: True when userPassword is equal and present on both providers within `timeout`."""
    end = time.time() + timeout
    while time.time() < end:
      if stored(A, dn) != '' and stored(A, dn) == stored(B, dn):
        return True
      time.sleep(1)
    return False


  def binds(node, dn, path):
    return node.tool('ldapwhoami', [], dn, path).returncode == 0


  def stage(node, values):
    """Put each value (string) on `node` as a file; returns the paths."""
    out = []
    for v in values:
      counter[0] += 1
      path = f'/tmp/.st-{counter[0]}'
      node.put_password(path, v)
      out.append(path)
    return out


  def verify_single(dn, successes):
    """successes: [(value, ...)] the values that returned 0. After convergence exactly one binds, on BOTH nodes, and
    every other attempted value fails on both. Returns (winner index or None, #nodes agreeing)."""
    converge(dn)
    values = [v for v, _ in successes]
    pa, pb = stage(A, values), stage(B, values)
    hit_a = [i for i in range(len(values)) if binds(A, dn, pa[i])]
    hit_b = [i for i in range(len(values)) if binds(B, dn, pb[i])]
    return hit_a, hit_b


  def partition(node):
    ensure(live.run(['docker', 'network', 'disconnect', live.network, node.name]).returncode == 0, 'disconnect ' + node.name)


  def heal(node):
    r = live.run(['docker', 'network', 'connect', '--alias', node.name, live.network, node.name])
    ensure(r.returncode == 0, 'connect ' + node.name + ': ' + r.stderr)


  def wcred_exop(node, dn):
    v, path = secret_file(node)
    return lcode(node.tool('ldappasswd', ['-T', path, dn], WC[0], WC[1])), v


  # ---- M1: B refuses ------------------------------------------------------------------------------------------

  def try_b(label, uid):
    """W_cred Password Modify + plain Modify on B for ROUNDS fresh pending accounts; [(rc_exop, rc_mod)]."""
    out = []
    for k in range(ROUNDS):
      dn = pending(f'{uid}-{k}')
      rc_exop, _ = wcred_exop(B, dn)
      v, _ = secret_file(B)
      rc_mod = lcode(B.tool('ldapmodify', [], WC[0], WC[1], f'dn: {dn}\nchangetype: modify\nreplace: userPassword\nuserPassword: {v}\n'))
      out.append((rc_exop, rc_mod))
    measure(f'M1 {label}, {ROUNDS} accounts: Password Modify rc {[x[0] for x in out]}; plain Modify rc {[x[1] for x in out]}')
    return out


  live.check(live.run(['docker', 'exec', B.name, 'ldapwhoami', '-x', '-H', 'ldap://127.0.0.1', '-D', WCRED_DN, '-y', '/tmp/.pw-wcred']).returncode == 0,
             'M1 control: W_cred binds on B (the 50 below is the ACL, not a missing account)')
  m1 = try_b('B shipped non-pinned (deny rule only, no bundle)', 'mp1')
  live.check(all(x == (50, 50) for x in m1), 'M1 B as shipped (deny rule, no bundle): Password Modify and Modify -> 50')
  # M1b: which part decides? The image rules alone already refuse W_cred, so the deny rule matters only where the bundle is present.
  remove_wcred(B)
  m1n = try_b('B with neither deny nor bundle (image rules only)', 'mp1n')
  live.check(all(x == (50, 50) for x in m1n), 'M1b without the bundle B refuses W_cred by the image rules alone: the deny rule is a backstop, not the cause')
  install_wcred(B, 'write-cred-deny.ldif', 'write-cred.ldif')
  m1d = try_b('B with deny placed BEFORE the bundle (both installed)', 'mp1d')
  live.check(all(x == (50, 50) for x in m1d), 'M1b bundle + deny in front of it: the deny decides, W_cred -> 50')
  remove_wcred(B)
  install_wcred(B, 'write-cred.ldif')
  m1b = try_b('B with the bundle and NO deny', 'mp1b')
  live.check(all(x == (0, 50) for x in m1b), 'M1b bundle without deny: W_cred Password Modify lands (0) on B, so the deny rule is what keeps a bundled node closed')
  remove_wcred(B)
  install_wcred(B, 'write-cred-deny.ldif')    # the shipped non-pinned configuration for M2-M4

  # ---- M2: N parallel on A -------------------------------------------------------------------------------------

  m2 = []
  for k in range(ROUNDS):
    dn = pending(f'mp2-{k}')
    t0 = time.monotonic()
    res = race(dn, [(A, N)])
    rcs, pairs = res[A.name]
    wins = [pairs[i] for i, rc in enumerate(rcs) if rc == 0]
    hit_a, hit_b = verify_single(dn, wins) if wins else ([], [])
    # the losers must not bind on either node (probe the first two on each: failures count towards lockout)
    losers = [pairs[i] for i, rc in enumerate(rcs) if rc != 0][:2]
    lo = [binds(n, dn, stage(n, [v for v, _ in losers])[i]) for n in (A, B) for i in range(len(losers))]
    m2.append((sorted(rcs), len(wins), hit_a, hit_b, any(lo), stored(A, dn) == stored(B, dn) != ''))
    measure(f'M2 round {k}: A rc {sorted(rcs)}; successes {len(wins)}; winner binds on A {hit_a} on B {hit_b}; a loser binds {any(lo)}; hash equal {m2[-1][5]}; {time.monotonic() - t0:.1f}s')
  live.check(all(r[1] == 1 and r[0].count(0) == 1 and set(r[0]) <= {0, 50} for r in m2), f'M2 {ROUNDS} rounds x N={N} on the pinned provider A: exactly one success, {N - 1} x 50')
  live.check(all(r[2] == [0] and r[3] == [0] and not r[4] and r[5] for r in m2), 'M2 after convergence B holds the same single winning value (binds on A and B, losers do not, hashes equal)')

  # ---- M3: split race ------------------------------------------------------------------------------------------

  m3 = []
  for k in range(ROUNDS):
    dn = pending(f'mp3-{k}')
    res = race(dn, [(A, 5), (B, 5)])
    (ra, pa), (rb, pb) = res[A.name], res[B.name]
    wins = [pa[i] for i, rc in enumerate(ra) if rc == 0] + [pb[i] for i, rc in enumerate(rb) if rc == 0]
    hit_a, hit_b = verify_single(dn, wins) if wins else ([], [])
    m3.append((sorted(ra), sorted(rb), len(wins), hit_a, hit_b))
    measure(f'M3 round {k} (timed, A x5 + B x5): A rc {sorted(ra)}; B rc {sorted(rb)}; successes {len(wins)}; winner binds on A {hit_a} on B {hit_b}')
  live.check(all(r[2] == 1 and r[0].count(0) == 1 and set(r[0]) <= {0, 50} and set(r[1]) == {50} and r[3] == [0] and r[4] == [0] for r in m3),
             f'M3 {ROUNDS} rounds, A (bundle) x5 and B (deny, no bundle) x5 released together: A losers 50, B refuses all (50), exactly one value exists and it binds on both providers')

  m3p = []
  for k in range(ROUNDS):
    dn = pending(f'mp3p-{k}')
    partition(B)
    try:
      rb, _ = wcred_exop(B, dn)
      res = race(dn, [(A, 3)])
    finally:
      heal(B)
    ra, pa = res[A.name]
    wins = [pa[i] for i, rc in enumerate(ra) if rc == 0]
    hit_a, hit_b = verify_single(dn, wins) if wins else ([], [])
    m3p.append((rb, sorted(ra), len(wins), hit_a, hit_b))
    measure(f'M3 round {k} (B partitioned while A sets): B rc {rb}; A rc {sorted(ra)}; successes {len(wins)}; winner binds on A {hit_a} on B {hit_b}')
  live.check(all(r[0] == 50 and r[2] == 1 and r[3] == [0] and r[4] == [0] for r in m3p),
             f'M3 {ROUNDS} rounds, B partitioned from A: B still refuses (50), A gives one success, after healing it binds on both providers')

  # ---- M4: is cn=config replicated? ----------------------------------------------------------------------------

  sync = {}
  for node in (A, B):
    out = node.config_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=config', '(olcSyncrepl=*)', 'dn', 'olcSyncrepl', 'olcMultiProvider']).stdout
    sync[node.name] = out
    measure(f'M4 {node.name} entries carrying olcSyncrepl: {re.findall(r"^dn: (.*)$", out, re.M)}; olcMultiProvider {re.findall(r"^olcMultiProvider: (.*)$", out, re.M)}')
    for line in out.splitlines():
      if line.startswith('olcSyncrepl'):
        measure('M4 ' + node.name + ' ' + re.sub(r'credentials="[^"]*"', 'credentials="<withheld>"', line))
  live.check(all(re.findall(r'^dn: (.*)$', sync[n.name], re.M) == [main_db[n.name]] for n in (A, B)),
             'M4 olcSyncrepl exists on the main database only; olcDatabase={0}config has none, so cn=config is not a replicated suffix')
  probe = f'to dn.exact="cn=cfgprobe-{secrets.token_hex(3)},{BASE_DN}" by * break'
  before_b = olc_access(B)
  ensure(A.config_tool('ldapmodify', [], f'dn: {main_db[A.name]}\nchangetype: modify\nadd: olcAccess\nolcAccess: {probe}\n').returncode == 0, 'probe rule on A')
  time.sleep(15)   # past LDAP_REPLICATION_INTERVAL (10 s); refreshAndPersist would be immediate
  seen_a = any(probe in x for x in olc_access(A))
  live.check(seen_a, 'M4 the probe olcAccess rule is present on A (read back)')
  seen_b = any(probe in x for x in olc_access(B))
  measure(f'M4 probe olcAccess rule written on A cn=config: present on A {seen_a}; present on B after 15 s {seen_b}; B olcAccess unchanged {olc_access(B) == before_b}')
  ensure(A.config_tool('ldapmodify', [], f'dn: {main_db[A.name]}\nchangetype: modify\ndelete: olcAccess\nolcAccess: {probe}\n').returncode == 0, 'remove probe rule')
  live.check(not seen_b and olc_access(B) == before_b, 'M4 a cn=config olcAccess write on A does not reach B: the pinned bundle / deny split survives replication')
  live.check(len(olc_access(A)) - A.wcred_rules == len(olc_access(B)) - B.wcred_rules and A.wcred_rules != B.wcred_rules,
             f'M4 the per-provider difference is in place and stable (A {A.wcred_rules} W_cred rules, B {B.wcred_rules})')

  # ---- M5: negative control, the bundle on both ----------------------------------------------------------------

  remove_wcred(B)
  install_wcred(B, 'write-cred.ldif')
  measure(f'M5 setup: the 7-rule W_cred bundle now on BOTH providers (A {A.wcred_rules}, B {B.wcred_rules})')
  m5p = []
  for k in range(ROUNDS):
    dn = pending(f'mp5p-{k}')
    partition(B)
    try:
      ra, va = wcred_exop(A, dn)
      time.sleep(1)    # B's set is the later one: entryCSN last-write-wins picks it
      rb, vb = wcred_exop(B, dn)
    finally:
      heal(B)
    hit_a, hit_b = verify_single(dn, [(va, None), (vb, None)])
    m5p.append((ra, rb, hit_a, hit_b))
    measure(f'M5 round {k} (partition): A rc {ra}, B rc {rb} -> two successes; after healing the value that binds on A {hit_a} on B {hit_b} (0 = A\'s, 1 = B\'s)')
  live.check(all(r[0] == 0 and r[1] == 0 for r in m5p), 'M5 with the bundle on both providers a partitioned B accepts a second "first password" (two successes)')
  live.check(all(len(r[2]) == 1 and r[2] == r[3] for r in m5p),
             'M5 last-write-wins: after healing exactly one of the two successful values survives, the same one on both providers; the other success is silently lost')
  # Unpartitioned, released together: every round must converge. Stock OpenLDAP 2.6.15 syncrepl can leave the
  # earlier-CSN node on a wrong state after a same-entry local/peer write race (#432, retry_diff) and it does not
  # heal; the image carries a patch for it (image/patches/), so this fails on an image built without that patch.
  m5t = []
  for k in range(ROUNDS):
    dn = pending(f'mp5t-{k}')
    res = race(dn, [(A, 1), (B, 1)])
    (ra, pa), (rb, pb) = res[A.name], res[B.name]
    wins = [x for rcs, p in ((ra, pa), (rb, pb)) for rc, x in zip(rcs, p) if rc == 0]
    ok = converged(dn, 60) if wins else True   # no success: nothing to converge on
    snap = snapshot(dn)
    hit_a, hit_b = verify_single(dn, wins) if wins and ok else ([], [])
    m5t.append((ra, rb, len(wins), hit_a, hit_b, ok))
    measure(f'M5 round {k} (no partition, released together): A rc {ra}, B rc {rb}; successes {len(wins)}; '
            f'{"converged" if ok else "DIVERGED (#432)"}; surviving values A {hit_a} B {hit_b}')
    if not ok or os.environ.get('MP_DIAG') == '1':
      measure(f'M5 round {k} snapshot: {snap}')
  double = sum(1 for r in m5t if r[2] == 2)
  diverged = sum(1 for r in m5t if not r[5])
  measure(f'M5 unpartitioned race, bundle on both: {double} of {ROUNDS} rounds gave two successes (one silently lost); {ROUNDS - double} gave one (the later set saw the replicated password and got 50)')
  measure(f'M5 unpartitioned race: diverged {diverged} of {ROUNDS} (#432, OpenLDAP syncrepl retry_diff)')
  live.check(diverged == 0, f'M5 unpartitioned race: every round converged (diverged {diverged} of {ROUNDS}; #432 patched retry_diff)')
  live.check(all(len(r[3]) == (1 if r[2] >= 1 else 0) and r[3] == r[4] for r in m5t if r[5]),
             f'M5 unpartitioned rounds that converged ({ROUNDS - diverged} of {ROUNDS}) hold exactly one value, identical on both providers')

  print(f'\nALL {live.checks} CHECKS PASSED in {live.elapsed():.0f}s (image {live.ldap_image})', flush=True)


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    live.dump_logs()
    raise
