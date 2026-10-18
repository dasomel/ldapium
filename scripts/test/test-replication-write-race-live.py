#!/usr/bin/env python3
"""Local opt-in race harness for #432/#434: two providers write the same entries at the same instant.

Not part of CI (it takes minutes). Use it to check an image carries the syncrepl retry_diff fix
(image/patches/openldap-2.6.15-its-retry-diff.patch), or to measure a stock build: after each batch both
providers must hold identical entries (description, entryCSN, modifiersName, modifyTimestamp, userPassword).
Exit 0 only if no entry diverged; the counts are printed as `MEASURE ...` lines. Passwords never reach the
output.

Two modes. `plain`: both providers replace `description` on the same entries as root. `pw`: both set a
password on the same pending accounts through W_cred (Password Modify), with the W_cred bundle on both.

Run (docker): python3 scripts/test/test-replication-write-race-live.py
Env: LDAPIUM_IMAGE (default ldapium:e2e), LDAPIUM_TEST_PREFIX,
  RACE_MODE   plain | pw (default plain)
  RACE_ROUNDS entries raced in total (default 200)
  RACE_BATCH  entries per batch, one racing ldapmodify/ldappasswd loop per provider (default 50)
  RACE_STEP_NS  plain mode: provider B's start is offset by -10..+10 steps of this many ns across batches (default 300000)
  RACE_LOGDUMP  path prefix; when set, each provider's container log is written to <prefix>a.log / <prefix>b.log
"""
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

live = Live('ldapium-race-', deadline_seconds=3600)
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


  install_wcred(A, 'write-cred.ldif')
  install_wcred(B, 'write-cred.ldif')

  # ---- the race: A and B write the same entries at the same instant ---------------------------------------------

  MODE = os.environ.get('RACE_MODE', 'plain')
  BATCH = int(os.environ.get('RACE_BATCH', '50'))
  TOTAL = int(os.environ.get('RACE_ROUNDS', '200'))
  ensure(MODE in ('plain', 'pw'), 'RACE_MODE must be plain or pw')
  prefix = {'plain': 'pl', 'pw': 'pw'}[MODE]

  def dump_all(node, pat):
    attrs = ['description', 'entryCSN', 'modifiersName', 'modifyTimestamp', 'userPassword']
    out = node.admin_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', PEOPLE, f'(uid={pat}*)'] + attrs).stdout
    res, cur = {}, None
    for l in out.splitlines():
      if l.startswith('dn: '):
        cur = l[4:]
        res[cur] = []
      elif cur and l:
        res[cur].append(l)
    return {k: sorted(v) for k, v in res.items()}

  def spin(t):
    return f'while [ "$(date +%s%N)" -lt {t} ]; do :; done\n'

  tot_div = 0
  tot_rounds = 0
  examples = []
  for b in range(TOTAL // BATCH):
    pat = f'{prefix}{b}-'
    uids = [f'{pat}{i}' for i in range(BATCH)]
    if MODE == 'plain':
      ldif = ''.join(f'dn: uid={u},{PEOPLE}\nobjectClass: inetOrgPerson\nuid: {u}\ncn: {u}\nsn: {u}\ndescription: init\n\n' for u in uids)
      ensure(A.admin_tool('ldapadd', [], ldif).returncode == 0, 'bulk add')
    else:
      ldif = ''.join(f'dn: uid={u},{PEOPLE}\nobjectClass: inetOrgPerson\nuid: {u}\ncn: {u}\nsn: {u}\nemployeeType: {MARKER}\npwdPolicySubentry: {PENDING_POL}\n\n' for u in uids)
      r = A.tool('ldapadd', [], WD[0], WD[1], ldif)
      ensure(r.returncode == 0, 'bulk pending add ' + live.mask(r.stderr))
    live.wait_until(lambda: len(dump_all(B, pat)) == BATCH, 'replication of batch', 120)
    time.sleep(2)
    t = time.time_ns() + 2_500_000_000
    procs = []
    for node in (A, B):
      tag = node.name[-1]
      if MODE == 'plain':
        mods = ''.join(f'dn: uid={u},{PEOPLE}\nchangetype: modify\nreplace: description\ndescription: from-{tag}-{b}\n\n' for u in uids)
        node.put_password('/tmp/.pl.ldif', mods)
        off = ((b % 21) - 10) * int(os.environ.get('RACE_STEP_NS', '300000')) if tag == 'b' else 0
        sc = spin(t + off) + f'ldapmodify -x -c -H ldap://127.0.0.1 -D "{ADMIN_DN}" -y /tmp/.pw-admin -f /tmp/.pl.ldif > /tmp/.plo 2>&1; echo "@@ $?"\n'
      else:
        sc = spin(t) + 'for u in ' + ' '.join(uids) + '; do ' + \
          f'ldappasswd -x -H ldap://127.0.0.1 -D "{WCRED_DN}" -y /tmp/.pw-wcred -s "RV{tag}-$u-{secrets.token_hex(6)}" "uid=$u,{PEOPLE}" > /dev/null 2>&1; ' + 'done; echo "@@ done"\n'
      p = subprocess.Popen(['docker', 'exec', '-i', node.name, 'sh'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
      procs.append((node, p, sc))
    outs = {}
    ths = [threading.Thread(target=lambda n=n, p=p, s=s: outs.__setitem__(n.name, p.communicate(s)[0])) for n, p, s in procs]
    for th in ths:
      th.start()
    for th in ths:
      th.join()
    # settle: wait for equality, then require it to stay equal 15 s later
    end = time.time() + 60
    bad = None
    while time.time() < end:
      da, db = dump_all(A, pat), dump_all(B, pat)
      bad = [k for k in da if da.get(k) != db.get(k)]
      if not bad:
        break
      time.sleep(3)
    if bad:
      time.sleep(15)
      da, db = dump_all(A, pat), dump_all(B, pat)
      bad = [k for k in da if da.get(k) != db.get(k)]
    tot_div += len(bad)
    tot_rounds += BATCH
    for k in bad[:2]:
      if len(examples) < 6:
        keys = lambda d: sorted(x.split(':')[0] for x in d.get(k, []))
        examples.append(f'{k.split(",")[0]} A keys {keys(da)} | B keys {keys(db)} | A {[x for x in da[k] if x.startswith(("description", "entryCSN"))]} B {[x for x in db[k] if x.startswith(("description", "entryCSN"))]}')
    measure(f'RACE {MODE} batch {b}: diverged {len(bad)} of {BATCH} (cumulative {tot_div} of {tot_rounds}); writer out A {outs[A.name].strip()[-30:]} B {outs[B.name].strip()[-30:]}')
  for e in examples:
    measure('RACE example ' + e)
  for node in (A, B):
    r = live.run(['docker', 'logs', node.name])
    txt = r.stdout + r.stderr
    if os.environ.get('RACE_LOGDUMP'):
      open(os.environ['RACE_LOGDUMP'] + node.name[-1] + '.log', 'w').write(txt)
    n122 = len(re.findall(r'be_modify .*\(122\)', txt))
    n0 = len(re.findall(r'be_modify .*\(0\)', txt))
    nmr = len(re.findall(r'be_modrdn .*\(122\)', txt))
    nlate = len(re.findall(r'new entry is older than ours', txt))
    measure(f'RACE {MODE} {node.name} log: be_modify(122)={n122} be_modify(0)={n0} be_modrdn(122)={nmr} older-than-ours={nlate}')
  measure(f'RACE RESULT image {live.ldap_image} mode {MODE}: {tot_div} diverged of {tot_rounds} rounds')
  live.check(tot_div == 0, f'{MODE} race: no entry diverged ({tot_div} of {tot_rounds})')
  print(f'\nALL {live.checks} CHECKS PASSED in {live.elapsed():.0f}s (image {live.ldap_image})', flush=True)


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    live.dump_logs()
    raise
