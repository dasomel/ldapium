#!/usr/bin/env python3
"""Machine WRITE v2c (W_cred) ship-gating experiments, LIVE (#379 v2c, machine-write-scope-v2 EVIDENCE.md §2e).

Design gate only: no feature code exists. Real slapd built from this tree (accesslog `writes reads bind`, failures
logged, auditlog overlay ON so its stdout can be inspected), the shipped M / W_data / W_lock fragments, and a SCRATCH
W_cred fragment that is the CHANGE.md "W_cred ACL sketch" with its tokens substituted. Nothing here is a fixture the
product ships; the W_cred rules exist only inside this script.

Every probe is RECORDED (an `OBS` line) and compared with the measured reality the design relies on (an `EXPECT` line).
Known refusals and known defects (the F-4 baseline, the rejected `manage` alternative, F-6 at quality 1, F-7, F-9) are
expectations of what slapd DOES, so a change in that behaviour fails the run. A FAIL does not stop the run: every
experiment still runs, and the script exits 1 at the end listing the failed expectations; exit 0 means every expectation
matched reality.

  E-07  memberOf negation in the W_cred filter (direct / nested member)
  E-08  (!(userPassword=*)) evaluated for an identity that cannot read userPassword
  E-09  minimum `entry` / userPassword access for Password Modify; ppolicy internal mods vs. W_cred `none`
  E-10  ppolicy length / history on an administrator-style set (requester != target); pre-hashed value via Modify
  E-11  sequential second set (same and other value)
  E-12  accesslog reqMod / auditlog stdout hash; value-level deny for reqMod/reqOld
  E-16  creatorsName / marker substring filter, val.regex limiting =z, W_data marker add rule
  E-17  N parallel Password Modify on one pending account (exop only, and exop + Modify mixed)
  E-20  pwdChangedTime written by ppolicy and readable by M
  E-21  cn=config reader ACL exposure, olcAccess byte stability (incl. a slapd restart), comparator mutations
  E-23  accesslog child entries: base search vs subtree, a refused Password Modify, an operator-added reader
  FINAL the design after the reviews (Revision 8) on a fresh slapd: olcAddContentAcl TRUE, Add-only marker/policy,
        narrowed filters, cross matrix, sweeps with exact sets, sweep/runbook cleanup, rollback ordering, E-17 again
  D-0..D-7  the F-4 design the maintainer chose (2026-10-13): a pending policy (pwdSafeModify FALSE, pwdCheckQuality 2)
        attached by W_data only to marker entries, removed by W_cred with the marker; the atomic one-Modify variant

Run (local):  LDAPIUM_IMAGE=ldapium:e2e python3 scripts/test/test-machine-write-cred-experiments.py
Secrets: every password is a fresh random sentinel; output carries only counts, rc values and hash SCHEME names.
"""
import base64
import pathlib
import re
import secrets
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'lib'))
from machine_live import ADMIN_DN, BASE_DN, FIXTURES, HUMAN_DN, MACHINE_DN, Live, Slapd, ensure  # noqa: E402

live = Live('ldapium-v2cx-', deadline_seconds=1500)
SYSTEM_DN = 'ou=system,' + BASE_DN
PEOPLE = 'ou=people,' + BASE_DN
STAFF = 'ou=staff,' + BASE_DN          # inside the W_data cap, OUTSIDE the W_cred cap (Q9)
GROUPS = 'ou=groups,' + BASE_DN
WDATA_DN = 'uid=machine-write-data,' + SYSTEM_DN
WLOCK_DN = 'uid=machine-write-lock,' + SYSTEM_DN
WCRED_DN = 'uid=machine-write-cred,' + SYSTEM_DN
READER_DN = 'uid=machine-acl-reader,' + SYSTEM_DN
AUDITOR_DN = 'uid=auditor,' + SYSTEM_DN
REPL_DN = 'cn=replicator,' + BASE_DN
PRIV = 'cn=admins,' + GROUPS
SUBPRIV = 'cn=subadmins,' + GROUPS
TAG = secrets.token_hex(8)
MARKER = 'ldapium-credential-pending:' + TAG
MARKER_RE = '^ldapium-credential-pending:[0-9a-f]{16}$'
HASH_RE = re.compile(r'\{(SSHA(256|384|512)?|ARGON2|CRYPT|PBKDF2[^}]*|SHA(256|384|512)?|S?MD5)\}', re.I)
B64_PREFIXES = ('e1NTSEF9', 'e0FSR09OMn0', 'e0NSWVBUfQ')

results = []


def obs(text):
  print('OBS ' + text, flush=True)


def expect(eid, cond, text):
  results.append((eid, bool(cond), text))
  print(('EXPECT PASS ' if cond else 'EXPECT FAIL ') + f'[{eid}] {text}', flush=True)
  live.checks += 1


class AuditSlapd(Slapd):
  """Slapd with the auditlog overlay on (stdout), everything else as the shared harness starts it."""

  def __init__(self, live, name=None, ops='writes reads bind'):
    super().__init__(live, name)
    self.ops = ops

  def start(self):
    l = self.live
    l.register(self.name)
    env = l.write_secret_file('ldap.env', f'LDAP_ADMIN_PASSWORD={self.admin_password}\n')
    res = l.run(['docker', 'run', '-d', '--name', self.name, '--network', l.network,
                 '-p', f'127.0.0.1:{self.port}:389', '--env-file', env, '-e', 'LDAP_ROOT_DN=' + BASE_DN,
                 '-e', 'LDAP_ACCESSLOG_ENABLED=true', '-e', 'LDAP_ACCESSLOG_OPS=' + self.ops,
                 '-e', 'LDAP_AUDIT_ENABLED=true', '-e', 'LDAP_PASSWORD_POLICY_ENABLED=true', l.ldap_image])
    ensure(res.returncode == 0, res.stderr)
    self.wait()
    for path, pw in (('/tmp/.pw-machine', self.machine_password), ('/tmp/.pw-over', self.over_password)):
      self.put_password(path, pw)

  def wait(self):
    def ready():
      put = self.live.run(['docker', 'exec', '-i', self.name, 'sh', '-c', 'umask 077; cat > /tmp/.pw-admin'],
                          input=self.admin_password)
      return put.returncode == 0 and self.admin_tool('ldapsearch', ['-b', BASE_DN, '-s', 'base']).returncode == 0
    self.live.wait_until(ready, 'slapd readiness', 90)


def fixture_rules(name, tokens):
  """olcAccess values of a shipped fixture, tokens substituted, index stripped, LDIF folding undone."""
  text = (FIXTURES / name).read_text()
  for k, v in tokens.items():
    text = text.replace('@' + k + '@', v)
  text = re.sub(r'\n ', '', '\n'.join(l for l in text.splitlines() if not l.startswith('#')))
  return [re.sub(r'^\{\d+\}', '', l[len('olcAccess: '):]) for l in text.splitlines() if l.startswith('olcAccess: ')]


def wcred_rules(cred_dn, entry_level='=x', pw_level='=w', creators=True, marker=True, priv=True, policy=None):
  """The CHANGE.md W_cred sketch, substituted. Knobs exist for E-09 and the comparator mutations only."""
  wc = f'dn.exact="{WCRED_DN}"'
  flt = '(objectClass=inetOrgPerson)'
  if creators:
    flt += f'(creatorsName={WDATA_DN})'
  if marker:
    flt += '(employeeType=ldapium-credential-pending:*)'
  flt += '(!(userPassword=*))'
  if priv:
    flt += f'(!(memberOf={PRIV}))'
  if policy:
    flt += f'(pwdPolicySubentry={policy})'
  secrets_list = ('userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN,'
                  'memberOf,pwdAccountLockedTime,pwdChangedTime,pwdFailureTime,pwdGraceUseTime,pwdReset,pwdPolicySubentry,'
                  'pwdStartTime,pwdEndTime,pwdLastSuccess')
  return [
    f'to dn.subtree="{SYSTEM_DN}" by {wc} none by * break',
    f'to dn.exact="{REPL_DN}" by {wc} none by * break',
    f'to dn.subtree="{cred_dn}" attrs=userPassword filter=(&{flt}) by {wc} {pw_level} by * break',
    f'to dn.subtree="{cred_dn}" attrs=employeeType val.regex="{MARKER_RE}" by {wc} =z by * break',
    f'to attrs={secrets_list} by {wc} none by * break',
    f'to dn.subtree="{cred_dn}" attrs=entry by {wc} {entry_level} by * break',
    f'to * by {wc} none by * break',
  ]


def lcode(r):
  """(LDAP result code, kind) of a CLI run: 0 ok, else the (NN) in the output; kind separates ppolicy refusals."""
  if r.returncode == 0:
    return 0, 'ok'
  text = r.stdout + r.stderr
  m = re.search(r'\((\d+)\)', text)
  c = int(m.group(1)) if m else -r.returncode
  return c, 'safeModify' if 'old password' in text else ('policy' if c == 19 else ('acl' if c == 50 else 'other'))


def final_phase():
  """The design as revised after the independent reviews (Revision 8), on a FRESH slapd:
  olcAddContentAcl TRUE (Q15), marker + pending policy settable by W_data at Add ONLY (each rule's filter names the
  attribute it guards, so a Modify on an entry that does not carry it yet cannot pass), attach/set filter
  creatorsName=W_data AND marker AND no password AND non-privileged AND the pending policy, cleanup limited to the
  marker value and the exact policy DN on W_data-made entries."""
  f = AuditSlapd(live, name=live.name_prefix + '-final')
  f.start()
  f.seed(users=3, groups=1)
  f.apply_acl()
  adm = lambda tool, args=(), data=None: f.admin_tool(tool, list(args), data)  # noqa: E731
  cfg = lambda tool, args=(), data=None: f.config_tool(tool, list(args), data)  # noqa: E731
  pws = {}
  for dn, key in ((WDATA_DN, 'wdata'), (WCRED_DN, 'wcred')):
    pws[key] = live.secret(key + '-' + secrets.token_urlsafe(18))
    uid = dn.split(',', 1)[0][4:]
    ensure(adm('ldapadd', [], f'dn: {dn}\nobjectClass: inetOrgPerson\nuid: {uid}\ncn: {uid}\nsn: {uid}\nuserPassword: {pws[key]}\n').returncode == 0, key)
    f.put_password('/tmp/.pw-' + key, pws[key])
  f.put_password('/tmp/.pw-human', f.human_password)
  ensure(adm('ldapadd', [], f'dn: {PRIV}\nobjectClass: groupOfNames\ncn: admins\nmember: uid=u03,{PEOPLE}\n\n'
                            f'dn: {SUBPRIV}\nobjectClass: groupOfNames\ncn: subadmins\nmember: uid=u03,{PEOPLE}\n').returncode == 0, 'groups')
  adm('ldapmodify', [], f'dn: {PRIV}\nchangetype: modify\nadd: member\nmember: {SUBPRIV}\n')
  dflt = [l for l in adm('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=default,ou=policies,' + BASE_DN, '-s', 'base']).stdout.splitlines()
          if l and not l.startswith('dn: ') and not l.lower().startswith(('cn:', 'pwdsafemodify:', 'pwdcheckquality:'))]
  pol = 'cn=credential-pending,ou=policies,' + BASE_DN
  ensure(adm('ldapadd', [], f'dn: {pol}\ncn: credential-pending\n' + '\n'.join(dflt) + '\npwdSafeModify: FALSE\npwdCheckQuality: 2\n').returncode == 0, 'policy')
  main_db = next(l[4:] for l in cfg('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=config', f'(&(objectClass=olcMdbConfig)(olcSuffix={BASE_DN}))', 'dn']).stdout.splitlines() if l.startswith('dn: '))
  wd, wc = f'dn.exact="{WDATA_DN}"', f'dn.exact="{WCRED_DN}"'
  target = (f'(&(objectClass=inetOrgPerson)(creatorsName={WDATA_DN})(employeeType=ldapium-credential-pending:*)(!(userPassword=*))'
            f'(!(memberOf={PRIV}))(pwdPolicySubentry={pol}))')
  wd_rules = fixture_rules('write-data.ldif', {'WDATA_DN': WDATA_DN, 'WRITE_DN': BASE_DN, 'SYSTEM_DN': SYSTEM_DN, 'REPL_DN': REPL_DN, 'MAIN_DB_DN': main_db})
  wd_extra = [f'to dn.subtree="{PEOPLE}" attrs=employeeType val.regex="{MARKER_RE}" filter={target} by {wd} add by * break',
              f'to dn.subtree="{PEOPLE}" attrs=pwdPolicySubentry val="{pol}" filter={target} by {wd} add by * break']
  wd_rules = wd_rules[:2] + wd_extra + wd_rules[2:]      # before W_data's secrets/pwd* `none`
  secrets_list = ('userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN,memberOf,'
                  'pwdAccountLockedTime,pwdChangedTime,pwdFailureTime,pwdGraceUseTime,pwdReset,pwdPolicySubentry,pwdStartTime,pwdEndTime,pwdLastSuccess')
  wc_rules = [f'to dn.subtree="{SYSTEM_DN}" by {wc} none by * break',
              f'to dn.exact="{REPL_DN}" by {wc} none by * break',
              f'to dn.subtree="{PEOPLE}" attrs=userPassword filter={target} by {wc} =w by * break',
              f'to dn.subtree="{PEOPLE}" attrs=employeeType val.regex="{MARKER_RE}" filter=(&(creatorsName={WDATA_DN})(pwdPolicySubentry={pol})) by {wc} =z by * break',
              f'to dn.subtree="{PEOPLE}" attrs=pwdPolicySubentry val="{pol}" filter=(creatorsName={WDATA_DN}) by {wc} =z by * break',
              f'to attrs={secrets_list} by {wc} none by * break',
              f'to * by {wc} none by * break']
  body = (f'dn: {main_db}\nchangetype: modify\nreplace: olcAddContentAcl\nolcAddContentAcl: TRUE\n-\nadd: olcAccess\n'
          + ''.join(f'olcAccess: {{{3 + i}}}{r}\n' for i, r in enumerate(wd_rules + wc_rules)))
  r = cfg('ldapmodify', [], body)
  ensure(r.returncode == 0, 'final ACL: ' + live.mask(r.stderr))
  cs = 3 + len(wd_rules)
  obs(f'FINAL layout: olcAddContentAcl TRUE; M {{0}}-{{2}}; W_data {{3}}-{{{cs - 1}}} (Add-only marker {{5}}, Add-only policy {{6}}); W_cred {{{cs}}}-{{{cs + 6}}}')
  for i, rule in enumerate(wd_extra):
    obs(f'FINAL W_data {{{5 + i}}}: {rule}')
  for i, rule in enumerate(wc_rules[2:5]):
    obs(f'FINAL W_cred {{{cs + 2 + i}}}: {rule}')

  WD, WC, MI, HU = ((WDATA_DN, '/tmp/.pw-wdata'), (WCRED_DN, '/tmp/.pw-wcred'), (MACHINE_DN, '/tmp/.pw-machine'), (HUMAN_DN, '/tmp/.pw-human'))
  n = [0]

  def run(who, tool, args=(), data=None):
    return lcode(f.tool(tool, list(args), who[0], who[1], data))

  def sent(prefix='F'):
    n[0] += 1
    v = live.secret(f'{prefix}{n[0]}-' + secrets.token_urlsafe(18))
    f.put_password(f'/tmp/.fp-{n[0]}', v)
    return v, f'/tmp/.fp-{n[0]}'

  def add(uid, who=WD, mark=True, policy=pol, parent=PEOPLE, extra=''):
    dn = f'uid={uid},{parent}'
    ldif = (f'dn: {dn}\nobjectClass: inetOrgPerson\nuid: {uid}\ncn: {uid}\nsn: {uid}\n' + (f'employeeType: {MARKER}\n' if mark else '')
            + (f'pwdPolicySubentry: {policy}\n' if policy else '') + extra)
    return dn, run(who, 'ldapadd', [], ldif)

  def mod(who, dn, change):
    return run(who, 'ldapmodify', [], f'dn: {dn}\nchangetype: modify\n{change}\n')

  def vals(dn, *names):
    out = adm('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', dn, '-s', 'base', *names]).stdout
    return [l for l in out.splitlines() if l and not l.startswith('dn: ')]

  def setpw(dn, path=None):
    return run(WC, 'ldappasswd', ['-T', path or sent()[1], dn])

  def bind(dn, path):
    return f.tool('ldapwhoami', [], dn, path).returncode == 0

  def sweep(flt):
    out = f.tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', BASE_DN, flt, 'dn'], *MI).stdout
    return sorted(l[4:] for l in out.splitlines() if l.startswith('dn: '))

  # ---- M-3: leaked W_data (+ a password.write client): delete + re-Add as pending, then privilege -----------
  def victim(uid):
    dn = f'uid={uid},{PEOPLE}'
    ensure(adm('ldapadd', [], f'dn: {dn}\nobjectClass: inetOrgPerson\nuid: {uid}\ncn: {uid}\nsn: {uid}\nmail: {uid}@example.org\n').returncode == 0, uid)
    adm('ldapmodify', [], f'dn: {PRIV}\nchangetype: modify\nadd: member\nmember: {dn}\n')
    return dn

  def attack(uid, priv_candidate=None):
    dn = victim(uid)
    out = {'delete admin-made victim': run(WD, 'ldapdelete', [dn])}
    out['victim still in admins'] = any(dn in l for l in vals(PRIV, 'member'))
    out['re-Add as pending'] = add(uid)[1]
    vp = sent('M3')
    out['W_cred set'] = setpw(dn, vp[1])
    out['takeover bind'] = bind(dn, vp[1])
    out['W_data adds it to admins'] = mod(WD, PRIV, f'add: member\nmember: {priv_candidate or dn}')
    return dn, out

  v1dn, before = attack('fvic1')
  obs('M-3 WITHOUT mitigation: ' + '; '.join(f'{k} {v}' for k, v in before.items()))
  expect('M-3', before['delete admin-made victim'] == (0, 'ok') and before['re-Add as pending'] == (0, 'ok') and before['takeover bind']
         and before['W_data adds it to admins'] == (0, 'ok'),
         'M-3 reproduced without mitigation: W_data deletes an admin-made privileged account, re-Adds it as pending, W_cred sets it, W_data re-privileges it')
  m3 = [f'to dn.subtree="{BASE_DN}" attrs=entry filter=(&(objectClass=inetOrgPerson)(!(creatorsName={WDATA_DN}))) by {wd} =rsc by * break',
        f'to dn.exact="{PRIV}" attrs=member by {wd} =rsc by * break']
  ensure(cfg('ldapmodify', [], f'dn: {main_db}\nchangetype: modify\nadd: olcAccess\n' + ''.join(f'olcAccess: {{{5 + i}}}{r}\n' for i, r in enumerate(m3))).returncode == 0, 'm3 rules')
  cs += len(m3)
  for i, rule in enumerate(m3):
    obs(f'M-3 mitigation W_data {{{5 + i}}}: {rule}')
  wmade, _ = add('fwmade', mark=False, policy=None)
  wmade2, _ = add('fwmade2', mark=False, policy=None)
  vdn, after_m = attack('fvic2', priv_candidate=wmade2)
  outside = victim('fvic3')
  side = {'delete a W_data-made user (deleteUser of own creations)': run(WD, 'ldapdelete', [wmade]),
          'patchUser mail on an admin-made user': mod(WD, outside, 'replace: mail\nmail: fvic3b@example.org'),
          'modrdn an admin-made user': run(WD, 'ldapmodrdn', [outside, 'uid=fvic3x']),
          'add a member to subadmins (nested privilege)': mod(WD, SUBPRIV, f'add: member\nmember: uid=u02,{PEOPLE}'),
          'add a member to ordinary g01': mod(WD, f'cn=g01,{GROUPS}', f'add: member\nmember: uid=u02,{PEOPLE}'),
          'pending Add reusing an existing uid under another RDN': run(WD, 'ldapadd', [], f'dn: cn=fvic3alt,{PEOPLE}\nobjectClass: inetOrgPerson\nuid: fvic3\ncn: fvic3alt\nsn: x\nemployeeType: {MARKER}\npwdPolicySubentry: {pol}\n')}
  obs('M-3 WITH mitigation: ' + '; '.join(f'{k} {v}' for k, v in after_m.items()) + ' || side effects: ' + '; '.join(f'{k} {v}' for k, v in side.items()))
  expect('M-3', after_m['delete admin-made victim'][0] == 50 and after_m['victim still in admins'] and after_m['re-Add as pending'][0] != 0
         and after_m['W_cred set'][0] == 50 and not after_m['takeover bind'],
         'mitigation (a): W_data cannot delete a non-W_data user, so the re-Add (68 exists / unique uid) and the set fail')
  expect('M-3', after_m['W_data adds it to admins'][0] == 50, 'mitigation (b): W_data cannot write `member` of the privileged group')
  expect('M-3', side['delete a W_data-made user (deleteUser of own creations)'] == (0, 'ok') and side['patchUser mail on an admin-made user'] == (0, 'ok')
         and side['modrdn an admin-made user'][0] == 50 and side['add a member to ordinary g01'] == (0, 'ok'),
         'side effects pinned: deleteUser of W_data-made users and patchUser still work; modrdn and DELETE of non-W_data users now refused (v2a deleteUser narrowed)')
  expect('M-3', side['add a member to subadmins (nested privilege)'] == (0, 'ok'), 'RESIDUAL (recorded): a nested group of a privileged group is not covered by (b)')
  # boundary of (a): an account W_data ITSELF created earlier (v2a createUser, e.g. an SSO user provisioned by automation)
  v2a_dn, _ = add('fv2a', mark=False, policy=None, extra='mail: fv2a@example.org\n')
  r_del = run(WD, 'ldapdelete', [v2a_dn])
  r_re = add('fv2a')[1]
  rp = sent('V2A')
  r_set = setpw(v2a_dn, rp[1])
  obs(f'M-3 boundary: v2a-made (W_data-created) account: delete {r_del}, re-Add as pending {r_re}, W_cred set {r_set}, binds {bind(v2a_dn, rp[1])}')
  expect('M-3', r_del == (0, 'ok') and r_re == (0, 'ok') and r_set == (0, 'ok'),
         'RESIDUAL (recorded): rule (a) does not cover accounts W_data itself created; a leaked W_data + a password.write client can delete, re-create and set them')
  clean_v2a = mod(WC, v2a_dn, f'delete: employeeType\nemployeeType: {MARKER}\n-\ndelete: pwdPolicySubentry\npwdPolicySubentry: {pol}')
  ensure(clean_v2a == (0, 'ok'), 'clean v2a residual probe')
  expect('M-3', side['pending Add reusing an existing uid under another RDN'][0] == 19,
         'the unique overlay (uid, mail) refuses a pending twin of an existing account under another RDN (19)')

  # ---- Q15: olcAddContentAcl TRUE, what W_data can put in an Add -------------------------------------------
  a, ra = add('fa')
  plain, rp = add('fplain', mark=False, policy=None, extra='mail: fplain@example.org\n')
  _, rpw = add('fpw', mark=False, policy=None, extra=f'userPassword: {sent()[0]}\n')
  _, rnom = add('fnomark', mark=False)
  _, rnop = add('fnopol', policy=None)
  _, roth = add('fother', policy='cn=default,ou=policies,' + BASE_DN)
  _, rmpw = add('fmarkpw', extra=f'userPassword: {sent()[0]}\n')
  _, rstaff = add('fstaff', parent=GROUPS)
  obs(f'Q15 W_data Add: marker+policy {ra}; ordinary createUser (closed list) {rp}; carrying userPassword {rpw}; policy without marker {rnom}; '
      f'marker without policy {rnop}; marker+DEFAULT policy {roth}; marker+policy+userPassword {rmpw}; marker+policy outside the cred subtree {rstaff}')
  expect('Q15', ra == (0, 'ok') and rp == (0, 'ok') and vals(a, 'employeeType', 'pwdPolicySubentry') == [f'employeeType: {MARKER}', f'pwdPolicySubentry: {pol}'],
         'with olcAddContentAcl TRUE: the pending Add (marker + policy) and an ordinary createUser still succeed')
  expect('Q15', all(x[0] == 50 for x in (rpw, rnom, rnop, roth, rmpw, rstaff)),
         'with olcAddContentAcl TRUE the Add is checked per attribute: userPassword, a lone policy, a lone marker, another policy, a marker outside the cred subtree -> 50')

  g_ok = run(WD, 'ldapadd', [], f'dn: cn=fgrp,{GROUPS}\nobjectClass: groupOfNames\ncn: fgrp\ndescription: made by W_data\nmember: uid=u01,{PEOPLE}\n')
  u_desc = add('fudesc', mark=False, policy=None, extra='description: on a user\n')[1]
  obs(f'Q15 createGroup-shaped Add (groupOfNames + description) {g_ok}; user Add carrying description {u_desc}')
  expect('Q15', g_ok == (0, 'ok') and u_desc[0] == 50, 'olcAddContentAcl TRUE: createGroup with description still 0, a user Add carrying description 50 (#386 description limit closed)')

  # ---- M-1: W_data cannot mark or attach by Modify -----------------------------------------------------------
  sso, _ = add('fsso', who=(ADMIN_DN, '/tmp/.pw-admin'), mark=False, policy=None)
  m1 = {'mark v2a-made': mod(WD, plain, f'add: employeeType\nemployeeType: {MARKER}'),
        'mark admin-made SSO': mod(WD, sso, f'add: employeeType\nemployeeType: {MARKER}'),
        'policy on v2a-made': mod(WD, plain, f'add: pwdPolicySubentry\npwdPolicySubentry: {pol}'),
        'marker+policy on v2a-made in one Modify': mod(WD, plain, f'add: employeeType\nemployeeType: {MARKER}\n-\nadd: pwdPolicySubentry\npwdPolicySubentry: {pol}'),
        'delete the marker of a pending entry': mod(WD, a, f'delete: employeeType\nemployeeType: {MARKER}'),
        'delete the policy of a pending entry': mod(WD, a, f'delete: pwdPolicySubentry\npwdPolicySubentry: {pol}')}
    # a second marker value on an already pending entry: the filter is true for it, so the APP must require exactly one
  other_tag = 'ldapium-credential-pending:' + secrets.token_hex(8)
  second = mod(WD, a, f'add: employeeType\nemployeeType: {other_tag}')
  obs('M-1 W_data Modify: ' + '; '.join(f'{k} {v}' for k, v in m1.items()) + f'; add a SECOND marker value to a pending entry {second} -> {vals(a, "employeeType")}')
  expect('M-1', all(v[0] == 50 for v in m1.values()), 'W_data cannot mark, attach or un-mark by Modify (Add-only rules): every probe 50')
  expect('M-1', second == (0, 'ok') and len(vals(a, 'employeeType')) == 2,
         'KNOWN: a second marker value CAN be added to an entry that is already pending -> the app pre-read must require exactly one marker value')
  mod((ADMIN_DN, '/tmp/.pw-admin'), a, f'delete: employeeType\nemployeeType: {other_tag}')

  # ---- cross matrix with the final filters ----------------------------------------------------------------
  t = {'a': a}
  t['b'], _ = add('fb')
  bpw = live.secret('Fb-' + secrets.token_urlsafe(14))
  mod((ADMIN_DN, '/tmp/.pw-admin'), t['b'], f'add: userPassword\nuserPassword: {bpw}')
  t['c'], _ = add('fc', who=(ADMIN_DN, '/tmp/.pw-admin'))                       # rootdn: same attributes, creatorsName = admin
  t['d'] = plain
  t['f'], _ = add('ff')
  adm('ldapmodify', [], f'dn: {PRIV}\nchangetype: modify\nadd: member\nmember: {t["f"]}\n')
  t['g'], _ = add('fg')
  adm('ldapmodify', [], f'dn: {SUBPRIV}\nchangetype: modify\nadd: member\nmember: {t["g"]}\n')
  t['h'] = f'cn=fh,{PEOPLE}'
  adm('ldapadd', [], f'dn: {t["h"]}\nobjectClass: groupOfNames\nobjectClass: extensibleObject\ncn: fh\nemployeeType: {MARKER}\npwdPolicySubentry: {pol}\nmember: {a}\n')
  t['i'], t['j'], t['k'] = WDATA_DN, MACHINE_DN, WCRED_DN
  for key in 'ijk':
    adm('ldapmodify', [], f'dn: {t[key]}\nchangetype: modify\nreplace: pwdPolicySubentry\npwdPolicySubentry: {pol}\n')
  t['m'] = sso
  adm('ldapmodify', [], f'dn: {sso}\nchangetype: modify\nadd: employeeType\nemployeeType: {MARKER}\n-\nadd: pwdPolicySubentry\npwdPolicySubentry: {pol}\n')
  va, pa = sent('Fa')
  res = {k: setpw(t[k], pa if k == 'a' else None) for k in 'abcdfghijkm'}
  obs('FINAL cross matrix (W_cred exop): ' + ', '.join(f'{k} {v}' for k, v in res.items())
      + ' [a pending, b has a password, c admin-made pending, d v2a-made, f direct privileged, g nested privileged, h group, i/j/k identities, m SSO marked by the ADMIN]')
  expect('FINAL', res['a'] == (0, 'ok') and bind(a, pa), 'the pending account is set and the value binds')
  expect('FINAL', all(res[k][0] == 50 for k in 'bcdfhijkm'),
         'every non-target is refused (b, c, d, f, h, i, j, k, m) with the final filters')
  f.put_password('/tmp/.fp-b', bpw)
  expect('FINAL', bind(t['b'], '/tmp/.fp-b'), 'b keeps its original password')
  obs(f'FINAL nested privileged member g: {res["g"]} (REQ-007 accepted risk: direct members only)')

  # ---- policy under the final rules ---------------------------------------------------------------------------
  p2, _ = add('fp2')
  short = live.secret('aB3$' + secrets.token_hex(2)[:3])
  f.put_password('/tmp/.fp-short', short)
  weak = live.secret('y' + secrets.token_hex(1)[:1])
  hashed = live.secret(live.run(['docker', 'exec', '-i', f.name, 'slappasswd', '-h', '{SSHA}', '-T', '/dev/stdin'], input=weak).stdout.strip())
  ps = (setpw(p2, '/tmp/.fp-short'), mod(WC, p2, f'add: userPassword\nuserPassword: {hashed}'), setpw(p2))
  obs(f'FINAL policy on a pending entry: 7-char exop {ps[0]}, pre-hashed plain Modify {ps[1]}, compliant exop {ps[2]}')
  expect('FINAL', ps[0][0] == 19 and ps[1][0] == 19 and ps[2] == (0, 'ok'), 'pending policy: short 19, pre-hashed 19 (quality 2), compliant 0')

  # ---- window, pre-read signal, sweeps ----------------------------------------------------------------------
  oracle = (run(MI, 'ldappasswd', ['-T', pa, a]), run(MI, 'ldappasswd', ['-T', sent()[1], a]))
  pct = f.tool('ldapsearch', ['-LLL', '-b', a, '-s', 'base', 'pwdChangedTime'], *MI).stdout.count('pwdChangedTime:')
  f_self = run(HU, 'ldapmodify', [], f'dn: {HUMAN_DN}\nchangetype: modify\nadd: pwdPolicySubentry\npwdPolicySubentry: {pol}\n')
  stuck = sweep(f'(&(pwdPolicySubentry={pol})(creatorsName={WDATA_DN})(pwdChangedTime=*))')
  foreign = sweep(f'(&(pwdPolicySubentry={pol})(!(creatorsName={WDATA_DN})))')
  orphan = sweep(f'(&(pwdPolicySubentry={pol})(creatorsName={WDATA_DN})(!(employeeType=ldapium-credential-pending:*)))')
  obs(f'FINAL after the sets: M new=current {oracle[0]} vs wrong {oracle[1]}; M sees pwdChangedTime on a: {pct} (pre-read 409 signal); '
      f'F-9 self-attach on this image {f_self}; sweeps: stuck {stuck}; foreign {foreign}; orphan {orphan}')
  rules_now = cfg('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', main_db, '-s', 'base', 'olcAccess']).stdout
  f9_fixed = bool(re.search(r'olcAccess: \{\d+\}to attrs=[^ ]*pwdPolicySubentry[^\n]*by self (none|read|=)', rules_now, re.I))
  if f9_fixed:
    expect('F-9', f_self[0] == 50, 'F-9 fixed in this image (#399): a user cannot self-attach the pending policy (50)')
  else:
    obs(f'F-9 image WITHOUT the #399 fix: self-attach {f_self} (recorded, not asserted; the assertion becomes 50 once the fix is in the image)')
  expect('Q14', oracle == ((19, 'policy'), (50, 'acl')) and pct == 1, 'the accepted window: 19/50 exists before cleanup; M sees pwdChangedTime (the pre-read can answer 409)')
  want_stuck = sorted([a, t['b'], p2, t['g'], v1dn])   # v1dn: the M-3 victim taken over before the mitigation
  want_foreign = sorted([t['c'], t['h'], t['i'], t['j'], t['k'], t['m']] + ([HUMAN_DN] if f_self[0] == 0 else []))
  # TTL condition: the abandoned sweep only acts on entries older than the TTL (createTimestamp ordering, as M)
  now = live.run(['docker', 'exec', f.name, 'date', '-u', '+%Y%m%d%H%M%SZ']).stdout.strip()
  old_cut = live.run(['docker', 'exec', f.name, 'date', '-u', '-d', '@' + str(int(time.time()) - 3600), '+%Y%m%d%H%M%SZ']).stdout.strip()
  aband = f'(&(pwdPolicySubentry={pol})(creatorsName={WDATA_DN})(employeeType=ldapium-credential-pending:*)(!(pwdChangedTime=*))'
  ttl_young = sweep(aband + f'(createTimestamp<={old_cut}))')
  ttl_now = sweep(aband + f'(createTimestamp<={now}))')
  obs(f'TTL sweep: createTimestamp <= now-1h -> {len(ttl_young)}; <= now -> {[d.split(",")[0] for d in ttl_now]}')
  expect('SWEEP', ttl_young == [] and t['f'] in ttl_now, 'the TTL condition works for M: entries younger than the cut-off are not swept, older ones are')
  expect('SWEEP', stuck == want_stuck, f'stuck sweep finds exactly the W_data-made pending entries that have a password ({len(want_stuck)}, incl. the pre-mitigation M-3 victim)')
  expect('SWEEP', foreign == want_foreign, f'foreign sweep (!(creatorsName=W_data)) finds exactly the non-W_data entries carrying the policy ({len(want_foreign)})')
  expect('SWEEP', orphan == [], 'no W_data-made entry carries the policy without the marker (Add-only rules)')

  # ---- cleanup by the sweep (W_cred) and by the runbook (admin) ---------------------------------------------
  clean = lambda dn: mod(WC, dn, f'delete: employeeType\nemployeeType: {MARKER}\n-\ndelete: pwdPolicySubentry\npwdPolicySubentry: {pol}')  # noqa: E731
  neg = {'whole employeeType': mod(WC, p2, 'delete: employeeType'), 'whole policy attr': mod(WC, p2, 'delete: pwdPolicySubentry'),
         'add policy': mod(WC, plain, f'add: pwdPolicySubentry\npwdPolicySubentry: {pol}'), 'foreign c': clean(t['c']), 'foreign m (SSO)': clean(sso)}
  # rollback ordering: with the cleanup grant gone first, W_cred cannot clean a leftover attachment
  delete_body = f'dn: {main_db}\nchangetype: modify\ndelete: olcAccess\nolcAccess: {{{cs + 4}}}\n-\ndelete: olcAccess\nolcAccess: {{{cs + 3}}}\n'
  ensure(cfg('ldapmodify', [], delete_body).returncode == 0, 'drop cleanup grant')
  wrong_order = clean(p2)
  ensure(cfg('ldapmodify', [], f'dn: {main_db}\nchangetype: modify\nadd: olcAccess\nolcAccess: {{{cs + 3}}}{wc_rules[3]}\nolcAccess: {{{cs + 4}}}{wc_rules[4]}\n').returncode == 0, 'restore cleanup grant')
  swept = {dn: clean(dn) for dn in stuck}
  runbook = {dn: lcode(f.admin_tool('ldapmodify', [], f'dn: {dn}\nchangetype: modify\ndelete: pwdPolicySubentry\npwdPolicySubentry: {pol}\n'))
             for dn in foreign if dn not in (t['h'],)}
  # abandoned pending entries never get a password (refused, or the automation gave up): the stuck sweep cannot see
  # them; a TTL sweep (createTimestamp older than N, here: everything left) lets W_cred remove marker + policy
  abandoned = sweep(f'(&(pwdPolicySubentry={pol})(creatorsName={WDATA_DN})(employeeType=ldapium-credential-pending:*)(!(pwdChangedTime=*)))')
  ttl = {dn: clean(dn) for dn in abandoned}
  after = (sweep(f'(pwdPolicySubentry={pol})'), run(MI, 'ldappasswd', ['-T', pa, a]), bind(a, pa))
  obs('FINAL cleanup negatives: ' + '; '.join(f'{k} {v}' for k, v in neg.items()) + f'; cleanup with the grant removed first {wrong_order}')
  obs(f'FINAL sweep cleanup (W_cred): { {k.split(",")[0]: v for k, v in swept.items()} }; runbook admin cleanup: { {k.split(",")[0]: v for k, v in runbook.items()} }; '
      f'abandoned-pending sweep {[d.split(",")[0] for d in abandoned]} cleaned {list(ttl.values())}; '
      f'left with the policy {after[0]}; M new=current on a afterwards {after[1]}; a still binds {after[2]}')
  expect('CLEANUP', all(v[0] == 50 for v in neg.values()), 'W_cred cleanup cannot delete whole attributes, add the policy, or touch non-W_data entries')
  expect('CLEANUP', wrong_order[0] == 50, 'rollback ordering: once the cleanup grant is removed W_cred cannot clean a leftover (remove attachments first)')
  expect('SWEEP', abandoned == [t['f']],
         'the abandoned-pending sweep finds exactly the pending entry that never got a password (the refused privileged member f)')
  expect('CLEANUP', all(v == (0, 'ok') for v in list(swept.values()) + list(ttl.values()) + list(runbook.values())) and after[0] == [t['h']],
         'the stuck and abandoned sweeps (W_cred) and the admin runbook (foreign) leave only the group h (its own check)')
  expect('CLEANUP', after[1] == (50, 'safeModify') and after[2], 'after cleanup the default policy applies (no oracle) and the password is kept')

  # ---- E-17 with the final policy (lockout on: bind the winner first, then three losers) -------------------
  rounds = []
  for k in range(5):
    dn, _ = add(f'frace{k}')
    paths = [sent('FR') for _ in range(10)]
    script = ''
    for i, (_, p) in enumerate(paths):
      if k == 4 and i % 2:
        cmd = (f'printf "dn: {dn}\\nchangetype: modify\\nreplace: userPassword\\nuserPassword: %s\\n" "$(cat {p})" | '
               f'ldapmodify -x -H ldap://127.0.0.1 -D "{WCRED_DN}" -y /tmp/.pw-wcred')
      else:
        cmd = f'ldappasswd -x -H ldap://127.0.0.1 -D "{WCRED_DN}" -y /tmp/.pw-wcred -T {p} "{dn}"'
      script += f'( {cmd} > /tmp/.fo{i} 2>&1; echo $? > /tmp/.fr{i} ) &\n'
    script += 'wait\n' + ''.join(f'echo "@@ $(cat /tmp/.fr{i}) $(tr "\\n" " " < /tmp/.fo{i})"\n' for i in range(10))
    rcs = []
    for line in live.run(['docker', 'exec', '-i', f.name, 'sh'], input=script).stdout.splitlines():
      if line.startswith('@@ '):
        m = re.search(r'\((\d+)\)', line)
        rcs.append(0 if line.split()[1] == '0' else (int(m.group(1)) if m else -1))
    win = [i for i, x in enumerate(rcs) if x == 0]
    ok = len(win) == 1 and bind(dn, paths[win[0]][1]) and not any(bind(dn, paths[i][1]) for i in [j for j in range(10) if j not in win][:3])
    rounds.append((rcs, ok))
    obs(f'FINAL E-17 round {k} ({"mixed" if k == 4 else "exop"}): rc {rcs}; winner binds and 3 losers do not: {ok}')
  expect('E-17', all(ok and sorted(set(r)) == [0, 50] for r, ok in rounds), 'final policy: every round exactly one success (single slapd), losers 50')

  # ---- Codex P1: rollback ordering (attach grant first, drain, verify zero, then the cleanup grant) ---------
  def clean_all():
    for dn in sweep(f'(&(pwdPolicySubentry={pol})(creatorsName={WDATA_DN}))'):
      clean(dn)
    return sweep(f'(&(pwdPolicySubentry={pol})(creatorsName={WDATA_DN}))')
  zero1 = clean_all()
  late_dn, late = add('flate1')                     # attach rules still live: a late Add re-attaches
  wrong = sweep(f'(&(pwdPolicySubentry={pol})(creatorsName={WDATA_DN}))')
  zero2 = clean_all()
  attach_idx = 5 + len(m3)                           # W_data's two Add-only rules (after the M-3 rules)
  ensure(cfg('ldapmodify', [], f'dn: {main_db}\nchangetype: modify\ndelete: olcAccess\nolcAccess: {{{attach_idx + 1}}}\n-\ndelete: olcAccess\nolcAccess: {{{attach_idx}}}\n').returncode == 0, 'drop attach rules')
  cs -= 2
  late2 = add('flate2')[1]
  zero3 = clean_all()
  obs(f'ROLLBACK zero after cleanup {zero1}; late Add with the attach grant still live {late} -> attachments {[d.split(",")[0] for d in wrong]}; '
      f'cleaned again {zero2}; attach grant removed first, late Add {late2}; attachments {zero3}')
  expect('ROLLBACK', zero1 == [] and late == (0, 'ok') and wrong == [late_dn], 'wrong order: with the attach grant live a late Add re-attaches after "zero" was verified')
  expect('ROLLBACK', late2[0] == 50 and zero3 == [], 'right order: attach grant removed (and in-flight drained) first, then zero holds; only then remove the cleanup grant')


def main():
  print(f'Run {live.name_prefix}: server {live.ldap_image}, marker tag {TAG}', flush=True)
  live.make_network()
  ldap = AuditSlapd(live)
  ldap.start()
  ldap.seed(users=3, groups=1)
  ldap.apply_acl()  # M: three rules at {0}-{2}

  def adm(tool, args=(), data=None):
    return ldap.admin_tool(tool, list(args), data)

  def cfg(tool, args=(), data=None):
    return ldap.config_tool(tool, list(args), data)

  def tail(r):
    return (live.mask(r.stdout) + live.mask(r.stderr)).strip().replace('\n', ' | ')[:160]

  def attrs(dn, *names, who=None):
    if who:
      out = ldap.tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', dn, '-s', 'base', *names], who[0], who[1]).stdout
    else:
      out = adm('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', dn, '-s', 'base', *names]).stdout
    return [l for l in out.splitlines() if l and not l.startswith('dn: ')]

  def has(dn, name):
    return any(l.lower().startswith(name.lower() + ':') for l in attrs(dn, name))

  # ---- identities -----------------------------------------------------------------------------------------
  pw = {}
  for dn, key in ((WDATA_DN, 'wdata'), (WLOCK_DN, 'wlock'), (WCRED_DN, 'wcred'), (READER_DN, 'reader'), (AUDITOR_DN, 'auditor')):
    pw[key] = live.secret(key.capitalize() + '-' + secrets.token_urlsafe(18))
    uid = dn.split(',', 1)[0][4:]
    r = adm('ldapadd', [], f'dn: {dn}\nobjectClass: inetOrgPerson\nuid: {uid}\ncn: {uid}\nsn: {uid}\nuserPassword: {pw[key]}\n')
    ensure(r.returncode == 0, f'{key} account: ' + tail(r))
    ldap.put_password('/tmp/.pw-' + key, pw[key])
  r = adm('ldapadd', [], f'dn: {STAFF}\nobjectClass: organizationalUnit\nou: staff\n\n'
                         f'dn: {PRIV}\nobjectClass: groupOfNames\ncn: admins\nmember: uid=u03,{PEOPLE}\n\n'
                         f'dn: {SUBPRIV}\nobjectClass: groupOfNames\ncn: subadmins\nmember: uid=u03,{PEOPLE}\n')
  ensure(r.returncode == 0, 'staff/admins: ' + tail(r))
  adm('ldapmodify', [], f'dn: {PRIV}\nchangetype: modify\nadd: member\nmember: {SUBPRIV}\n')

  dbs = {}
  for block in cfg('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=config', '(olcDatabase=*)', 'dn', 'olcSuffix']).stdout.split('\n\n'):
    m = re.search(r'^dn: (olcDatabase=\{\d+\}(\w+),cn=config)$', block, re.M)
    if m:
      s = re.search(r'^olcSuffix: (.*)$', block, re.M)
      dbs[(m.group(2), s.group(1) if s else '')] = m.group(1)
  main_db, alog_db = dbs[('mdb', BASE_DN)], dbs[('mdb', 'cn=accesslog')]
  ppolicy_dn = next(l[4:] for l in cfg('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', main_db, '(objectClass=olcPPolicyConfig)', 'dn']).stdout.splitlines()
                    if l.startswith('dn: '))

  def install(db, start, rules):
    body = f'dn: {db}\nchangetype: modify\nadd: olcAccess\n' + ''.join(f'olcAccess: {{{start + i}}}{r}\n' for i, r in enumerate(rules))
    r = cfg('ldapmodify', [], body)
    ensure(r.returncode == 0, f'install {len(rules)} rules at {{{start}}} in {db}: ' + tail(r))

  def delete_at(db, idx, count=1):
    body = f'dn: {db}\nchangetype: modify\ndelete: olcAccess\n' + ''.join(f'olcAccess: {{{idx + i}}}\n' for i in reversed(range(count)))
    r = cfg('ldapmodify', [], body)
    ensure(r.returncode == 0, f'delete olcAccess {{{idx}}}x{count}: ' + tail(r))

  wd_rules = fixture_rules('write-data.ldif', {'WDATA_DN': WDATA_DN, 'WRITE_DN': BASE_DN, 'SYSTEM_DN': SYSTEM_DN, 'REPL_DN': REPL_DN, 'MAIN_DB_DN': main_db})
  marker_add = f'to dn.subtree="{BASE_DN}" attrs=employeeType val.regex="{MARKER_RE}" by dn.exact="{WDATA_DN}" add by * break'
  wd_rules = wd_rules[:6] + [marker_add] + wd_rules[6:]   # after {5} description, before the closed list/read
  wl_rules = fixture_rules('write-lock.ldif', {'WLOCK_DN': WLOCK_DN, 'WRITE_DN': BASE_DN, 'SYSTEM_DN': SYSTEM_DN, 'REPL_DN': REPL_DN, 'MAIN_DB_DN': main_db})
  install(main_db, 3, wd_rules)
  install(main_db, 3 + len(wd_rules), wl_rules)
  cred_start = 3 + len(wd_rules) + len(wl_rules)
  wc_rules = wcred_rules(PEOPLE)
  install(main_db, cred_start, wc_rules)
  entry_slot = cred_start + 5
  pw_slot = cred_start + 2
  obs(f'ACL layout on {main_db}: M {{0}}-{{2}}, W_data (+marker add rule) {{3}}-{{{2 + len(wd_rules)}}}, W_lock '
      f'{{{3 + len(wd_rules)}}}-{{{cred_start - 1}}}, W_cred {{{cred_start}}}-{{{cred_start + len(wc_rules) - 1}}}')
  for i, rule in enumerate(wc_rules):
    obs(f'W_cred rule {{{cred_start + i}}}: {rule}')

  def wdata(tool, args=(), data=None):
    return ldap.tool(tool, list(args), WDATA_DN, '/tmp/.pw-wdata', data)

  def wcred(tool, args=(), data=None):
    return ldap.tool(tool, list(args), WCRED_DN, '/tmp/.pw-wcred', data)

  counter = [0]

  def sentinel(prefix='S'):
    counter[0] += 1
    value = live.secret(f'{prefix}{counter[0]}-' + secrets.token_urlsafe(18))
    path = f'/tmp/.np-{counter[0]}'
    ldap.put_password(path, value)
    return value, path

  def setpw(dn, path=None, who=wcred):
    """Password Modify extended operation (what the app would send) with the new value from a file."""
    if path is None:
      _, path = sentinel()
    return who('ldappasswd', ['-T', path, dn])

  def binds(dn, path):
    return ldap.tool('ldapwhoami', [], dn, path).returncode

  def pending(uid, parent=PEOPLE, mark=True, by='wdata', extra=''):
    dn = f'uid={uid},{parent}'
    body = f'dn: {dn}\nobjectClass: inetOrgPerson\nuid: {uid}\ncn: {uid}\nsn: {uid}\n' + (f'employeeType: {MARKER}\n' if mark else '') + extra
    r = (wdata if by == 'wdata' else adm)('ldapadd', [], body)
    ensure(r.returncode == 0, f'create {dn} as {by}: ' + tail(r))
    return dn

  # ======== E-16 (part): who can put the marker, and creatorsName is server-filled ========================
  a = pending('p-a')
  cn_a = attrs(a, 'creatorsName')
  obs(f'E-16a W_data Add carrying the marker: rc 0; creatorsName {cn_a}')
  expect('E-16', cn_a == ['creatorsName: ' + WDATA_DN], 'creatorsName of a W_data Add is the W_data DN (server-filled)')
  spoof = adm('ldapadd', [], f'dn: uid=p-spoof,{PEOPLE}\nobjectClass: inetOrgPerson\nuid: p-spoof\ncn: s\nsn: s\ncreatorsName: {WDATA_DN}\n')
  spoof_relax = adm('ldapadd', ['-e', 'relax'], f'dn: uid=p-spoof2,{PEOPLE}\nobjectClass: inetOrgPerson\nuid: p-spoof2\ncn: s\nsn: s\ncreatorsName: {WDATA_DN}\n')
  spoof_cn2 = attrs(f'uid=p-spoof2,{PEOPLE}', 'creatorsName')
  obs(f'E-16b admin (rootdn) Add with an explicit creatorsName=W_data: rc {spoof.returncode} {tail(spoof)}; with the relax control: rc {spoof_relax.returncode} {tail(spoof_relax)} -> stored {spoof_cn2}')
  expect('E-16', spoof.returncode != 0, 'an explicit creatorsName on Add is refused without the relax control (even for the rootdn)')
  wspoof = wdata('ldapadd', ['-e', 'relax'], f'dn: uid=p-spoof3,{PEOPLE}\nobjectClass: inetOrgPerson\nuid: p-spoof3\ncn: s\nsn: s\ncreatorsName: cn=admin,{BASE_DN}\n')
  obs(f'E-16b2 W_data Add with relax + explicit creatorsName=cn=admin: rc {wspoof.returncode} {tail(wspoof)}')
  expect('E-16', wspoof.returncode != 0, 'W_data cannot forge creatorsName with the relax control')
  for dn in (f'uid=p-spoof,{PEOPLE}', f'uid=p-spoof2,{PEOPLE}', f'uid=p-spoof3,{PEOPLE}'):
    adm('ldapdelete', [dn])
  nomark = pending('p-nomark', mark=False)
  r_madd = wdata('ldapmodify', [], f'dn: {nomark}\nchangetype: modify\nadd: employeeType\nemployeeType: {MARKER}\n')
  r_oadd = wdata('ldapmodify', [], f'dn: {nomark}\nchangetype: modify\nadd: employeeType\nemployeeType: contractor\n')
  r_mdel = wdata('ldapmodify', [], f'dn: {nomark}\nchangetype: modify\ndelete: employeeType\nemployeeType: {MARKER}\n')
  r_xmark = wdata('ldapmodify', [], f'dn: {nomark}\nchangetype: modify\nadd: employeeType\nemployeeType: ldapium-credential-pending:XYZ\n')
  obs(f'E-16c W_data Modify on its own entry: add marker rc {r_madd.returncode}; add other employeeType rc {r_oadd.returncode}; '
      f'delete marker rc {r_mdel.returncode}; add malformed marker rc {r_xmark.returncode}')
  expect('E-16', (r_madd.returncode, r_oadd.returncode, r_mdel.returncode, r_xmark.returncode) == (0, 50, 50, 50),
         'W_data `add` rule: marker value add 0; other value / delete / malformed marker 50')
  adm('ldapmodify', [], f'dn: {nomark}\nchangetype: modify\ndelete: employeeType\n')
  adm_made = pending('p-admmade', mark=False, by='adm')
  r_adm_mark = wdata('ldapmodify', [], f'dn: {adm_made}\nchangetype: modify\nadd: employeeType\nemployeeType: {MARKER}\n')
  obs(f'E-16d W_data adds the marker to an ADMIN-created entry: rc {r_adm_mark.returncode} (the marker rule has no creatorsName filter)')

  # ======== policies: the shipped default has pwdSafeModify TRUE ============================================
  # Measured in run 2 of this script: with the shipped default policy EVERY non-self Password Modify by W_cred is
  # refused before the ACL is consulted ("Must supply old password ...", 50). The ACL filter is therefore measured
  # (mode `pending`) on targets whose pwdPolicySubentry is a copy of the default with pwdSafeModify FALSE, and the
  # alternative (mode `pwadmin`) keeps the default policy and gives W_cred `manage` on the filtered userPassword rule,
  # which makes it a ppolicy "password administrator".
  dflt = [l for l in adm('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=default,ou=policies,' + BASE_DN, '-s', 'base']).stdout.splitlines()
          if l and not l.startswith('dn: ') and not l.lower().startswith(('cn:', 'pwdsafemodify:', 'pwdlockout:'))]

  def policy(cn, safe, lockout):
    body = f'dn: cn={cn},ou=policies,{BASE_DN}\ncn: {cn}\n' + '\n'.join(dflt) + f'\npwdSafeModify: {safe}\npwdLockout: {lockout}\n'
    r = adm('ldapadd', [], body)
    ensure(r.returncode == 0, f'policy {cn}: ' + tail(r))
    return f'cn={cn},ou=policies,{BASE_DN}'

  POL_PENDING = policy('pending', 'FALSE', 'TRUE')
  POL_NOLOCK = policy('nolock', 'FALSE', 'FALSE')
  POL_NOLOCK_SAFE = policy('nolock-safe', 'TRUE', 'FALSE')
  dflt = [l for l in dflt if not l.lower().startswith('pwdcheckquality:')] + ['pwdCheckQuality: 2']
  POL_Q2 = policy('pending-q2', 'FALSE', 'TRUE')
  obs(f'policies: default {sorted(l.split(":")[0] for l in dflt)} + pwdSafeModify TRUE; copies {POL_PENDING} (safeModify FALSE), '
      f'{POL_NOLOCK} (safeModify FALSE, no lockout), {POL_NOLOCK_SAFE} (safeModify TRUE, no lockout)')

  def assign(dn, pol):
    r = adm('ldapmodify', [], f'dn: {dn}\nchangetype: modify\nreplace: pwdPolicySubentry\npwdPolicySubentry: {pol}\n')
    ensure(r.returncode == 0, f'assign {pol} to {dn}: ' + tail(r))

  def code(r):
    if r.returncode == 0:
      return 0, 'ok'
    text = r.stdout + r.stderr
    m = re.search(r'\((\d+)\)', text)
    c = int(m.group(1)) if m else -r.returncode
    kind = 'safeModify' if 'old password' in text else ('policy' if c == 19 else ('acl' if c == 50 else 'other'))
    return c, kind

  # who may carry pwdPolicySubentry on the Add (the pending policy would have to be set at creation)
  r_pps = wdata('ldapadd', [], f'dn: uid=p-pps,{PEOPLE}\nobjectClass: inetOrgPerson\nuid: p-pps\ncn: p\nsn: p\nemployeeType: {MARKER}\npwdPolicySubentry: {POL_PENDING}\n')
  r_pps_mod = wdata('ldapmodify', [], f'dn: {nomark}\nchangetype: modify\nadd: pwdPolicySubentry\npwdPolicySubentry: {POL_PENDING}\n')
  obs(f'policy placement: W_data Add carrying pwdPolicySubentry rc {code(r_pps)} (stored {attrs(f"uid=p-pps,{PEOPLE}", "pwdPolicySubentry")}); '
      f'W_data Modify adding it rc {code(r_pps_mod)}')

  # the shipped default policy, W_cred =w, a correct pending account
  d0 = pending('p-default')
  r_d0 = setpw(d0)
  obs(f'E-09/E-10 DEFAULT policy (pwdSafeModify TRUE), W_cred =w, correct pending account: {code(r_d0)} {tail(r_d0)}')
  expect('E-09', code(r_d0) == (50, 'safeModify'),
         'F-4 baseline (expected refusal): the SHIPPED default policy (pwdSafeModify TRUE) refuses a W_cred initial set before the ACL')

  # ======== E-08 / E-16 / E-07: who the W_cred userPassword rule reaches (per mode) ========================
  def swap(slot, rule):
    delete_at(main_db, slot)
    install(main_db, slot, [rule])

  def matrix(mode):
    pol = POL_PENDING if mode == 'pending' else None
    t = {}
    t['a'] = pending('a-' + mode)
    t['b'] = pending('b-' + mode)
    bpw = live.secret('Bpw-' + secrets.token_urlsafe(14))
    ensure(adm('ldapmodify', [], f'dn: {t["b"]}\nchangetype: modify\nadd: userPassword\nuserPassword: {bpw}\n').returncode == 0, 'b password')
    ldap.put_password('/tmp/.pw-b-' + mode, bpw)
    t['c'] = pending('c-' + mode, by='adm')
    t['d'] = pending('d-' + mode, mark=False)
    t['e'] = pending('e-' + mode, parent=STAFF)
    t['f'] = pending('f-' + mode)
    adm('ldapmodify', [], f'dn: {PRIV}\nchangetype: modify\nadd: member\nmember: {t["f"]}\n')
    t['g'] = pending('g-' + mode)
    adm('ldapmodify', [], f'dn: {SUBPRIV}\nchangetype: modify\nadd: member\nmember: {t["g"]}\n')
    t['h'] = f'cn=h-{mode},{PEOPLE}'
    adm('ldapadd', [], f'dn: {t["h"]}\nobjectClass: groupOfNames\nobjectClass: extensibleObject\ncn: h-{mode}\nemployeeType: {MARKER}\nmember: {t["a"]}\n')
    t['l'] = pending('l-' + mode, mark=False, by='adm')
    ensure(wdata('ldapmodify', [], f'dn: {t["l"]}\nchangetype: modify\nadd: employeeType\nemployeeType: {MARKER}\n').returncode == 0, 'l marker')
    t['i'], t['j'], t['k'] = WDATA_DN, MACHINE_DN, WCRED_DN
    if pol:
      for key in 'abcdefghlijk':
        assign(t[key], pol)
    labels = {'a': 'pending W_data-made, no password', 'b': 'pending W_data-made, HAS password', 'c': 'marker by hand, admin-made',
              'd': 'W_data-made, NO marker', 'e': 'pending outside the W_cred subtree', 'f': 'pending, DIRECT privileged member',
              'g': 'pending, NESTED privileged member', 'h': 'groupOfNames carrying the marker', 'i': 'W_data itself',
              'j': 'M itself', 'k': 'W_cred itself', 'l': 'admin-made, marker added by W_data'}
    va, pa = sentinel()
    res = {}
    for key in 'abcdefghijkl':
      r = setpw(t[key], pa if key == 'a' else None)
      res[key] = code(r)
      obs(f'E-08/16/07 [{mode}] W_cred Password Modify on {key} ({labels[key]}): {res[key]} {tail(r) if r.returncode else ""}')
    res['a_binds'] = binds(t['a'], pa) == 0
    res['b_keeps'] = binds(t['b'], '/tmp/.pw-b-' + mode) == 0
    return t, res, pa

  wcred_read = wcred('ldapsearch', ['-LLL', '-b', d0, '-s', 'base', 'userPassword', 'employeeType', 'creatorsName']).stdout
  obs(f'E-08 W_cred reads (userPassword/employeeType/creatorsName) on a pending entry: '
      f'{"userPassword" in wcred_read}/{"employeeType" in wcred_read}/{"creatorsName" in wcred_read}')
  expect('E-08', 'userPassword' not in wcred_read, 'W_cred cannot read userPassword')

  T, R, pa = matrix('pending')
  a, b, c, t_g = T['a'], T['b'], T['c'], T['g']
  obs(f'E-07 memberOf of f {attrs(T["f"], "memberOf")}; of g (nested via subadmins) {attrs(t_g, "memberOf")}')
  expect('E-08', R['a'] == (0, 'ok') and R['a_binds'], '[pending policy] pending W_data-made account without a password: Password Modify 0 and the value binds')
  expect('E-08', R['b'] == (50, 'acl') and R['b_keeps'], '[pending policy] pending account that already has a password: ACL 50, original password still binds ((!(userPassword=*)) holds for a non-reader)')
  expect('E-16', R['c'] == (50, 'acl'), '[pending policy] marker set by hand on an admin-created account: ACL 50 (creatorsName filter)')
  expect('E-16', R['d'] == (50, 'acl'), '[pending policy] W_data-made account without the marker: ACL 50 (marker substring filter)')
  expect('E-16', R['l'] == (50, 'acl'), '[pending policy] admin-made account whose marker W_data added: ACL 50 (creatorsName filter)')
  expect('E-16', R['e'] == (50, 'acl'), '[pending policy] pending account outside the W_cred subtree: ACL 50')
  expect('E-07', R['f'] == (50, 'acl'), '[pending policy] pending DIRECT member of the privileged group: ACL 50 ((!(memberOf=...)) holds)')
  obs(f'E-07 [pending] nested privileged member (no nestgroup overlay): {R["g"]} (0 = the filter does not see nesting, as REQ-007 accepted)')
  expect('E-16', all(R[k] == (50, 'acl') for k in 'hijk'), '[pending policy] group carrying the marker, W_data, M, W_cred itself: ACL 50')

  swap(pw_slot, wcred_rules(PEOPLE, pw_level='=wm')[2])
  T2, R2, pa2 = matrix('pwadmin')
  obs('E-09 [pwadmin] W_cred userPassword rule `=wm` (password administrator), default policy (safeModify TRUE): '
      + ', '.join(f'{k} {R2[k]}' for k in 'abcdefghijkl'))
  expect('E-09', R2['a'] == (0, 'ok') and R2['a_binds'], '[pwadmin] with `=wm` on the filtered rule W_cred sets the initial password under the shipped default policy')
  expect('E-08', all(R2[k][0] != 0 for k in 'bcdefhijkl') and R2['b_keeps'], '[pwadmin] every non-target is still refused')
  obs(f'E-08 [pwadmin] refusal kinds for non-targets: { {k: R2[k][1] for k in "bcdefhijkl"} } (safeModify = refused by ppolicy because the filtered manage rule did not match)')
  swap(pw_slot, wcred_rules(PEOPLE)[2])

  # ======== E-09: minimum access, ppolicy internal mods (pending policy) =====================================
  sweep = {}
  for lvl in ('none', '=x', '=d', '=c', '=s', '=r'):
    swap(entry_slot, wcred_rules(PEOPLE, entry_level=lvl)[5])
    dn = pending('p-e9e' + re.sub(r'\W', '', lvl))
    assign(dn, POL_PENDING)
    sweep['entry ' + lvl] = code(setpw(dn))
  swap(entry_slot, wcred_rules(PEOPLE)[5])
  for lvl in ('=a', '=z', '=az', '=w', 'write', '=wm'):
    swap(pw_slot, wcred_rules(PEOPLE, pw_level=lvl)[2])
    dn = pending('p-e9p' + re.sub(r'\W', '', lvl))
    assign(dn, POL_PENDING)
    sweep['userPassword ' + lvl] = code(setpw(dn))
  swap(pw_slot, wcred_rules(PEOPLE)[2])
  obs('E-09 [pending] Password Modify by W_cred level (entry sweep with userPassword =w; userPassword sweep with entry =x): '
      + ', '.join(f'{k}: {v}' for k, v in sweep.items()))
  entry_min = next((k for k in ('entry none', 'entry =x', 'entry =d', 'entry =c', 'entry =s', 'entry =r') if sweep[k][0] == 0), None)
  obs(f'E-09 minimum entry level that lets Password Modify through: {entry_min}')
  expect('E-09', sweep['userPassword =w'][0] == 0, 'userPassword =w (with the filter) is sufficient once pwdSafeModify is off')
  pp = attrs(a, 'pwdChangedTime', 'pwdHistory', 'pwdFailureTime')
  obs(f'E-09 ppolicy state on a-pending after the W_cred set (admin view, names only): {[l.split(":", 1)[0] for l in pp]}')
  expect('E-09', any(l.startswith('pwdChangedTime') for l in pp), 'ppolicy wrote pwdChangedTime although W_cred has `none` on it (internal mods bypass the requester ACL)')
  expect('E-09', live.mask('\n'.join(attrs(a, 'employeeType'))).count(MARKER) == 1, 'the marker is still present after the set (cleanup is a separate step)')

  # ======== E-20: pwdChangedTime readable by M =================================================================
  MID = ('uid=machine,' + SYSTEM_DN, '/tmp/.pw-machine')
  m_view = attrs(a, 'pwdChangedTime', 'creatorsName', 'employeeType', 'userPassword', 'pwdPolicySubentry', who=MID)
  m_names = sorted({l.split(':', 1)[0] for l in m_view})
  m_before = attrs(c, 'pwdChangedTime', who=MID)
  obs(f'E-20 M reads on a-pending after the set: {m_names}; pwdChangedTime on the never-set c-pending: {m_before}')
  expect('E-20', 'pwdChangedTime' in m_names and 'creatorsName' in m_names and 'employeeType' in m_names and 'userPassword' not in m_names,
         'M reads pwdChangedTime, creatorsName, employeeType but not userPassword')
  expect('E-20', m_before == [], 'a never-set pending account has no pwdChangedTime')

  # ======== E-11: sequential second set; cleanup; (e) after-cleanup delete ===================================
  r_same, r_other = setpw(a, pa), setpw(a)
  obs(f'E-11 second W_cred set on a-pending: same value {code(r_same)}, other value {code(r_other)}; first value still binds: {binds(a, pa) == 0}')
  expect('E-11', code(r_same)[0] in (19, 50) and code(r_other) == (50, 'acl') and binds(a, pa) == 0,
         'sequential second set is refused (other value: ACL 50; same value: refused, see the oracle below) and the first value stays')
  # 19 vs 50 tells the requester whether its guess equals the current password: ppolicy's "same as current/history"
  # check runs BEFORE the backend ACL. Who else gets that oracle on a safeModify-FALSE account, and does it count failures?
  HUMAN = ('uid=human,' + PEOPLE, '/tmp/.pw-human')
  ldap.put_password('/tmp/.pw-human', ldap.human_password)
  fail_before = attrs(a, 'pwdFailureTime')
  orc = {}
  for who_label, who in (('M', MID), ('human user', HUMAN)):
    hit = code(ldap.tool('ldappasswd', ['-T', pa, a], *who))
    miss = code(ldap.tool('ldappasswd', ['-T', sentinel()[1], a], *who))
    orc[who_label] = (hit, miss)
  fail_after = attrs(a, 'pwdFailureTime')
  obs(f'E-11 oracle on a-pending (pending policy, safeModify FALSE): Password Modify with new = CURRENT value vs a wrong guess: '
      f'W_cred {code(r_same)} / {code(r_other)}; ' + '; '.join(f'{k} {v[0]} / {v[1]}' for k, v in orc.items())
      + f'; pwdFailureTime entries before/after {len(fail_before)}/{len(fail_after)}')
  # the shipped default policy (safeModify TRUE): the same question with an old-password guess, as a non-admin requester
  base_u = 'uid=u01,' + PEOPLE
  ldap.put_password('/tmp/.np-u01old', 'initial-pw-1')
  ldap.put_password('/tmp/.np-u01bad', 'initial-pw-x')
  okold = code(ldap.tool('ldappasswd', ['-t', '/tmp/.np-u01old', '-T', sentinel()[1], base_u], *MID))
  badold = code(ldap.tool('ldappasswd', ['-t', '/tmp/.np-u01bad', '-T', sentinel()[1], base_u], *MID))
  obs(f'E-11 baseline, shipped default policy: M Password Modify on u01 with the CORRECT old password {okold}, with a WRONG one {badold}; '
      f'u01 pwdFailureTime entries {len(attrs(base_u, "pwdFailureTime"))}')
  r_cl_absent = wcred('ldapmodify', [], f'dn: {a}\nchangetype: modify\ndelete: employeeType\nemployeeType: contractor\n')
  adm('ldapmodify', [], f'dn: {a}\nchangetype: modify\nadd: employeeType\nemployeeType: contractor\n')
  r_cl_other = wcred('ldapmodify', [], f'dn: {a}\nchangetype: modify\ndelete: employeeType\nemployeeType: contractor\n')
  r_cl_attr = wcred('ldapmodify', [], f'dn: {a}\nchangetype: modify\ndelete: employeeType\n')
  r_cl_add = wcred('ldapmodify', [], f'dn: {a}\nchangetype: modify\nadd: employeeType\nemployeeType: ldapium-credential-pending:{secrets.token_hex(8)}\n')
  r_cl_rep = wcred('ldapmodify', [], f'dn: {a}\nchangetype: modify\nreplace: employeeType\nemployeeType: {MARKER}\n')
  r_cl = wcred('ldapmodify', [], f'dn: {a}\nchangetype: modify\ndelete: employeeType\nemployeeType: {MARKER}\n')
  et = attrs(a, 'employeeType')
  obs(f'E-16 W_cred on employeeType of a-pending: delete other value {code(r_cl_other)} (value absent: {code(r_cl_absent)}); '
      f'delete whole attribute {code(r_cl_attr)}; add a marker {code(r_cl_add)}; replace {code(r_cl_rep)}; '
      f'delete the marker value {code(r_cl)}; left {et}')
  expect('E-16', code(r_cl)[0] == 0 and et == ['employeeType: contractor'], 'val.regex limits W_cred =z to the marker value: marker delete 0, other value kept')
  expect('E-16', (code(r_cl_other)[0], code(r_cl_add)[0], code(r_cl_rep)[0], code(r_cl_attr)[0]) == (50, 50, 50, 50),
         'W_cred cannot delete another employeeType value, the whole attribute, add a marker or replace employeeType')
  adm('ldapmodify', [], f'dn: {a}\nchangetype: modify\ndelete: userPassword\n')
  r_after = setpw(a)
  obs(f'E-11/AC-007b(e) cleanup done, admin then deletes userPassword, W_cred set again: {code(r_after)}')
  expect('E-11', code(r_after) == (50, 'acl'), 'after cleanup an admin-cleared password is NOT re-settable by W_cred (no marker)')

  # ======== E-10: policy on an administrator-style set (both modes) ==========================================
  pol_txt = attrs('cn=default,ou=policies,' + BASE_DN, 'pwdMinLength', 'pwdCheckQuality', 'pwdInHistory', 'pwdSafeModify', 'pwdUseCheckModule', 'pwdCheckModuleArg')
  obs(f'E-10 default policy: {pol_txt}')
  short_v = live.secret('aB3$' + secrets.token_hex(2)[:3])  # 7 characters
  ldap.put_password('/tmp/.np-short', short_v)
  weak = live.secret('x' + secrets.token_hex(1)[:1])         # 2 characters
  ldap.put_password('/tmp/.np-weak', weak)
  hashed = live.secret(live.run(['docker', 'exec', '-i', ldap.name, 'slappasswd', '-h', '{SSHA}', '-T', '/dev/stdin'], input=weak).stdout.strip())

  def e10(mode):
    out = {}
    pol = {'pending': POL_PENDING, 'pending-q2': POL_Q2}.get(mode)
    if mode == 'pwadmin':
      swap(pw_slot, wcred_rules(PEOPLE, pw_level='=wm')[2])
    t10 = pending('t10-' + mode)
    if pol:
      assign(t10, pol)
    out['short'] = code(setpw(t10, '/tmp/.np-short'))
    out['short_stored'] = has(t10, 'userPassword')
    _, h1p = sentinel('H')
    out['first'] = code(setpw(t10, h1p))
    adm('ldapmodify', [], f'dn: {t10}\nchangetype: modify\ndelete: userPassword\n')
    out['hist_entries'] = len(attrs(t10, 'pwdHistory'))
    r = setpw(t10, h1p)
    out['reuse'] = code(r)
    out['reuse_text'] = tail(r)
    tb = pending('t10b-' + mode)
    tc = pending('t10c-' + mode)
    if pol:
      assign(tb, pol)
      assign(tc, pol)
    out['prehashed'] = code(wcred('ldapmodify', [], f'dn: {tb}\nchangetype: modify\nadd: userPassword\nuserPassword: {hashed}\n'))
    out['prehashed_binds'] = binds(tb, '/tmp/.np-weak') == 0
    out['clear2'] = code(wcred('ldapmodify', [], f'dn: {tc}\nchangetype: modify\nadd: userPassword\nuserPassword: {weak}\n'))
    if mode == 'pwadmin':
      swap(pw_slot, wcred_rules(PEOPLE)[2])
    obs(f'E-10 [{mode}] 7-char exop {out["short"]} (stored {out["short_stored"]}); compliant first set {out["first"]}; '
        f'pwdHistory entries after admin cleared userPassword {out["hist_entries"]}; re-set of that previous value {out["reuse"]} {out["reuse_text"] if out["reuse"][0] else ""}; '
        f'plain Modify PRE-HASHED {{SSHA}} of a 2-char value {out["prehashed"]} (binds {out["prehashed_binds"]}); plain Modify 2-char cleartext {out["clear2"]}')
    return out

  P = e10('pending')
  expect('E-10', P['short'][0] == 19 and not P['short_stored'], '[pending policy] ppolicy refuses a too-short value on a W_cred (requester != target) exop: 19, nothing stored')
  expect('E-10', P['first'] == (0, 'ok'), '[pending policy] a policy-compliant initial set succeeds')
  expect('E-10', P['clear2'][0] == 19, '[pending policy] a too-short cleartext value through a plain Modify is refused (19)')
  expect('E-10', P['prehashed'] == (0, 'ok') and P['prehashed_binds'],
         'F-6 (recorded): at pwdCheckQuality 1 a PRE-HASHED 2-char value through a plain Modify is stored and binds -> the pending policy needs quality 2')
  obs(f'E-10 [pending] pwdInHistory enforced on a W_cred re-set of a previous value: {P["reuse"][0] == 19}')
  Q = e10('pending-q2')
  expect('E-10', Q['first'] == (0, 'ok') and Q['short'][0] == 19, '[pending-q2] pwdCheckQuality 2 still accepts a compliant exop and refuses a short one')
  expect('E-10', Q['prehashed'][0] != 0 and not Q['prehashed_binds'], '[pending-q2] pwdCheckQuality 2 refuses a PRE-HASHED value through a plain Modify')
  A = e10('pwadmin')
  expect('E-10', A['short'] == (0, 'ok') and A['short_stored'] and A['clear2'] == (0, 'ok'),
         'rejected alternative (recorded): a ppolicy password administrator (`manage`) bypasses the length rule (7-char exop and 2-char Modify stored)')
  obs(f'E-10 [pwadmin] pwdInHistory enforced on a re-set of a previous value: {A["reuse"][0] == 19}')
  t10 = 'uid=t10-pending,' + PEOPLE

  # ======== E-17: concurrency ===================================================================================
  def race(dn, n, mixed):
    paths = [sentinel('R') for _ in range(n)]
    script = ''
    for i, (_, p) in enumerate(paths):
      if mixed and i % 2:
        cmd = (f'printf "dn: {dn}\\nchangetype: modify\\nreplace: userPassword\\nuserPassword: %s\\n" "$(cat {p})" | '
               f'ldapmodify -x -H ldap://127.0.0.1 -D "{WCRED_DN}" -y /tmp/.pw-wcred')
      else:
        cmd = f'ldappasswd -x -H ldap://127.0.0.1 -D "{WCRED_DN}" -y /tmp/.pw-wcred -T {p} "{dn}"'
      script += f'( {cmd} > /tmp/.out{i} 2>&1; echo $? > /tmp/.rc{i} ) &\n'
    script += 'wait\n' + ''.join(f'echo "@@ $(cat /tmp/.rc{i}) $(tr "\\n" " " < /tmp/.out{i})"\n' for i in range(n))
    r = live.run(['docker', 'exec', '-i', ldap.name, 'sh'], input=script)
    rcs = []
    for line in r.stdout.splitlines():
      if line.startswith('@@ '):
        rc = int(line.split()[1])
        m = re.search(r'\((\d+)\)', line)
        rcs.append(0 if rc == 0 else (int(m.group(1)) if m else -rc))
    bound = [i for i, (_, p) in enumerate(paths) if binds(dn, p) == 0]
    return rcs, bound

  rounds = []
  plan = [('pending', False)] * 6 + [('pending', True)] * 2 + [('pwadmin', False)] * 2 + [('pwadmin', True)]
  for k, (mode, mixed) in enumerate(plan):
    if mode == 'pwadmin' and (k == 0 or plan[k - 1][0] != 'pwadmin'):
      swap(pw_slot, wcred_rules(PEOPLE, pw_level='=wm')[2])
    dn = pending(f'race{k}-{mode}')
    assign(dn, POL_NOLOCK if mode == 'pending' else POL_NOLOCK_SAFE)
    rcs, bound = race(dn, 10, mixed)
    rounds.append((mode, mixed, rcs, bound))
    obs(f'E-17 round {k} [{mode}] ({"exop+Modify mixed" if mixed else "exop only"}, N=10): LDAP rc {rcs}; successes {rcs.count(0)}; values that bind {bound}')
  swap(pw_slot, wcred_rules(PEOPLE)[2])
  single = all(r[2].count(0) == 1 and r[3] == [r[2].index(0)] for r in rounds)
  expect('E-17', single, 'every round: exactly one Password Modify succeeds and only the winning value binds')
  losers = sorted({x for r in rounds for x in r[2] if x})
  obs(f'E-17 loser result codes over all rounds: {losers}')
  expect('E-17', set(losers) <= {50}, 'every loser fails with 50 (ACL or safeModify), not a transient/busy error')

  # ======== E-12 / E-23: accesslog and auditlog ===============================================================
  time.sleep(1)

  def alog(flt, who=('cn=admin,cn=accesslog', '/tmp/.pw-admin'), base='cn=accesslog', scope='sub', want=('reqType', 'reqResult', 'reqMod', 'reqOld')):
    out = ldap.tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', base, '-s', scope, flt, *want], who[0], who[1]).stdout
    vals = []
    for line in out.splitlines():
      if line.startswith(('reqMod:: ', 'reqOld:: ')):
        vals.append((line[:6], base64.b64decode(line.split(':: ', 1)[1]).decode('utf-8', 'replace')))
      elif line.startswith(('reqMod: ', 'reqOld: ', 'reqType: ', 'reqResult: ')):
        k, v = line.split(': ', 1)
        vals.append((k, v))
    return out, vals

  def pw_hashes(vals):
    return [v for k, v in vals if k in ('reqMod', 'reqOld') and v.lower().startswith('userpassword:') and HASH_RE.search(v)]

  def schemes(values):
    return sorted({m.group(0) for v in values for m in [HASH_RE.search(v)] if m})

  def shape(v):
    m = HASH_RE.search(v)
    return v[:m.end()] + '<redacted>' if m else v[:16] + '...'

  _, vals_a = alog(f'(reqDN={a})')
  hp_a = pw_hashes(vals_a)
  obs(f'E-12a accesslog rows for a-pending (accesslog rootdn): reqType {sorted({v for k, v in vals_a if k == "reqType"})}; '
      f'reqResult {sorted({v for k, v in vals_a if k == "reqResult"})}; hashed userPassword values {len(hp_a)} {[shape(v) for v in hp_a]}')
  _, vals_f = alog(f'(&(reqDN={b})(!(reqResult=0)))')
  hp_f = pw_hashes(vals_f)
  obs(f'E-23b ACL-refused (50) Password Modify on b-pending: non-zero rows {sum(1 for k, _ in vals_f if k == "reqType")} '
      f'(reqResult {sorted({v for k, v in vals_f if k == "reqResult"})}); hashed userPassword values {len(hp_f)} {[shape(v) for v in hp_f]}')
  _, vals_19 = alog(f'(&(reqDN={t10})(reqResult=19))')
  hp_19 = pw_hashes(vals_19)
  obs(f'E-23b policy-refused (19) Password Modify on t10-pending: rows {sum(1 for k, _ in vals_19 if k == "reqType")}; hashed userPassword values {len(hp_19)}')
  _, vals_d0 = alog(f'(reqDN={d0})')
  obs(f'E-23b safeModify-refused Password Modify on p-default: reqType {sorted({v for k, v in vals_d0 if k == "reqType"})}; hashed values {len(pw_hashes(vals_d0))}')
  pass_rows = [v for k, v in vals_a if k == 'reqType']
  obs(f'E-12a the successful Password Modify EXOP on a-pending left {len(hp_a)} hashed values; accesslog rows by type {sorted(pass_rows)}')
  hash_dn = 'uid=t10b-pending,' + PEOPLE   # W_cred plain Modify with a pre-hashed value succeeded there (E-10)
  _, vals_pm = alog(f'(reqDN={hash_dn})')
  hp_pm = pw_hashes(vals_pm)
  obs(f'E-12a the successful plain MODIFY of userPassword on t10b-pending: hashed values {len(hp_pm)} {[shape(v) for v in hp_pm]}')
  expect('E-12', len(hp_a) == 0, 'accesslog `writes reads bind`: a Password Modify EXOP leaves NO accesslog record (no hash)')
  expect('E-12', len(hp_pm) > 0, 'accesslog `writes reads bind`: a plain Modify of userPassword leaves the HASH in reqMod (P21 holds for that path)')
  rm = wcred('ldapmodify', [], f'dn: {b}\nchangetype: modify\nreplace: userPassword\nuserPassword: {sentinel()[0]}\n')
  time.sleep(0.6)
  _, vals_rm = alog(f'(&(reqDN={b})(reqResult=50))')
  hp_rm = pw_hashes(vals_rm)
  obs(f'E-23b W_cred plain Modify of b-pending REFUSED by the ACL {code(rm)}: rows {sum(1 for k, _ in vals_rm if k == "reqType")}, hashed values of the ATTEMPTED password {len(hp_rm)} {[shape(v) for v in hp_rm]}')
  expect('E-12', not any(live.mask(v) != v for k, v in vals_a + vals_f + vals_19 + vals_d0), 'no plaintext sentinel in any accesslog reqMod/reqOld')

  # auditlog stdout
  logs = live.run(['docker', 'logs', ldap.name])
  text = logs.stdout + logs.stderr
  unfolded = re.sub(r'\n ', '', text)
  rec_a = [blk for blk in re.split(r'(?m)^# ', unfolded) if f'dn: {a}' in blk]
  au_pw = [l for blk in rec_a for l in blk.splitlines() if l.lower().startswith('userpassword')]
  au_sch = schemes([base64.b64decode(l.split(':: ', 1)[1]).decode('utf-8', 'replace') if '::' in l else l for l in au_pw])
  obs(f'E-12b auditlog (LDAP_AUDIT_ENABLED=true, stdout) records for p-a: {len(rec_a)}; userPassword lines {len(au_pw)} schemes {au_sch}')
  expect('E-12', len(au_pw) > 0, 'auditlog stdout carries the userPassword hash of the W_cred set (P20 confirmed: D379-14 (a) is required)')
  expect('E-13', not any(v in text or v in unfolded for v in live.secret_values if len(v) >= 8), 'no plaintext secret in the slapd container log (auditlog included)')

  # accesslog DB ACL variants for M and an operator reader
  base_alog = [l[len('olcAccess: '):] for l in cfg('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', alog_db, '-s', 'base', 'olcAccess']).stdout.splitlines() if l.startswith('olcAccess: ')]
  obs(f'E-23 accesslog DB olcAccess as shipped: {base_alog}')
  M = ('uid=machine,' + SYSTEM_DN, '/tmp/.pw-machine')
  AUD = (AUDITOR_DN, '/tmp/.pw-auditor')

  def m_reads(who=M):
    _, sub = alog(f'(reqDN={hash_dn})', who=who)
    out_b, _ = alog('(objectClass=*)', who=who, scope='base', want=('reqMod',))
    return pw_hashes(sub), [v for k, v in sub if k == 'reqMod'], 'dn: cn=accesslog' in out_b

  hp, allmod, base_seen = m_reads()
  obs(f'E-23 shipped accesslog ACL: M subtree userPassword values {len(hp)}, any reqMod {len(allmod)}, base entry returned {base_seen}')
  expect('E-23', len(hp) == 0 and len(allmod) == 0, 'shipped accesslog ACL: M reads nothing')
  install(alog_db, 0, [f'to * by dn.exact="{MACHINE_DN}" read by * break'])   # f/accesslog-optin.ldif
  hp, allmod, base_seen = m_reads()
  obs(f'E-12/E-23 opt-in (to * by M read): M subtree userPassword values {len(hp)} schemes {schemes(hp)}; other reqMod values {len(allmod) - len(hp)}; base returned {base_seen}')
  expect('E-12', len(hp) > 0, 'with the shipped M accesslog opt-in M reads the userPassword hash (P21 confirmed: mutual exclusion needed)')
  install(alog_db, 0, ['to attrs=reqMod val.regex="^userPassword:" by * none', 'to attrs=reqOld val.regex="^userPassword:" by * none'])
  hp_v, allmod_v, _ = m_reads()
  _, adm_vals = alog(f'(reqDN={hash_dn})')
  obs(f'E-12c value-level deny + opt-in: M userPassword values {len(hp_v)}, M other reqMod values {len(allmod_v)}; '
      f'accesslog rootdn still sees userPassword values: {len(pw_hashes(adm_vals))}')
  expect('E-12', len(hp_v) == 0 and len(allmod_v) > 0, 'val.regex="^userPassword:" hides exactly the userPassword reqMod/reqOld values from M and keeps the others')
  delete_at(alog_db, 0, 3)
  install(alog_db, 0, [f'to dn.base="cn=accesslog" by dn.exact="{MACHINE_DN}" search by * break',
                       f'to dn.subtree="cn=accesslog" by dn.exact="{MACHINE_DN}" read by * break'])
  hp_c, allmod_c, base_c = m_reads()
  obs(f'E-23a base `search` + children `read`: M base entry returned {base_c}; M subtree userPassword values {len(hp_c)}')
  expect('E-23', not base_c and len(hp_c) > 0, 'base hidden + children readable: a base search shows nothing yet the subtree search returns the hash (check 6 must search children)')
  delete_at(alog_db, 0, 2)
  install(alog_db, 0, [f'to * by dn.exact="{AUDITOR_DN}" read by * break'])
  hp_d, _, _ = m_reads(AUD)
  hp_m, _, _ = m_reads()
  obs(f'E-23c operator-added reader: auditor userPassword values {len(hp_d)}; M (no opt-in) {len(hp_m)}')
  expect('E-23', len(hp_d) > 0 and len(hp_m) == 0, 'an operator-added accesslog reader gets the hash while M sees nothing (R-5: invisible to an M-only check)')
  delete_at(alog_db, 0, 1)

  # ======== E-21: cn=config reader ============================================================================
  cfg_db = 'olcDatabase={0}config,cn=config'
  cfg_rules = [l[len('olcAccess: '):] for l in cfg('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', cfg_db, '-s', 'base', 'olcAccess']).stdout.splitlines() if l.startswith('olcAccess: ')]
  obs(f'E-21 cn=config olcAccess as shipped: {cfg_rules}')
  RD = (READER_DN, '/tmp/.pw-reader')

  # A filter on an attribute the identity cannot search evaluates undefined (AGENTS.md): the reader asks with a
  # filter on the attribute it is granted, so each probe below is (base, filter) and the union of what comes back.
  cfg_bases = ['cn=config', cfg_db, 'olcDatabase={-1}frontend,cn=config', main_db, ppolicy_dn, alog_db]

  def reader_view():
    ents = {}
    for base in cfg_bases:
      for flt in ('(objectClass=*)', '(olcAccess=*)', '(olcPPolicyDefault=*)', '(olcRootPW=*)', '(olcSuffix=*)'):
        out = ldap.tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', base, '-s', 'base', flt, '*', '+'], *RD).stdout
        cur = None
        for line in out.splitlines():
          if line.startswith('dn: '):
            cur = line[4:]
            ents.setdefault(cur, set())
          elif cur and ': ' in line:
            ents[cur].add(line.split(':', 1)[0])
    sub = ldap.tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=config', '-s', 'sub', '(olcAccess=*)', 'dn'], *RD)
    return ents, sub.stdout.count('dn: '), code(sub)

  obs(f'E-21 reader before any cn=config rule: {reader_view()}')
  install(cfg_db, 0, [f'to dn.base="{main_db}" attrs=olcAccess by dn.exact="{READER_DN}" read by * break',
                      f'to dn.base="{ppolicy_dn}" attrs=olcPPolicyDefault by dn.exact="{READER_DN}" read by * break'])
  v1, n1, c1s = reader_view()
  obs(f'E-21 attrs=olcAccess / olcPPolicyDefault only (no entry): {{dn: attrs}} = { {k: sorted(v) for k, v in v1.items()} }; subtree search from cn=config: {n1} entries {c1s}')
  delete_at(cfg_db, 0, 2)
  install(cfg_db, 0, [f'to dn.base="{main_db}" attrs=entry,olcAccess by dn.exact="{READER_DN}" read by * break',
                      f'to dn.base="{ppolicy_dn}" attrs=entry,olcPPolicyDefault by dn.exact="{READER_DN}" read by * break'])
  v2, n2, c2s = reader_view()
  obs(f'E-21 attrs=entry,olcAccess / entry,olcPPolicyDefault: {{dn: attrs}} = { {k: sorted(v) for k, v in v2.items()} }; subtree search from cn=config: {n2} entries {c2s}')
  expect('E-21', set(v2) == {main_db, ppolicy_dn} and v2[main_db] <= {'olcAccess'} and v2[ppolicy_dn] <= {'olcPPolicyDefault'}
         and 'olcAccess' in v2[main_db] and 'olcPPolicyDefault' in v2[ppolicy_dn],
         'the reader sees exactly the two entries and only olcAccess / olcPPolicyDefault')
  rd_main = ldap.tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', PEOPLE, '-s', 'sub', '(objectClass=*)', 'dn'], *RD).stdout.count('dn: ')
  obs(f'E-21 the reader identity in the MAIN database (no rule names it): entries visible under {PEOPLE}: {rd_main}')

  def reader_rules():
    out = ldap.tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', main_db, '-s', 'base', '(olcAccess=*)', 'olcAccess'], *RD).stdout
    return [re.sub(r'^\{\d+\}', '', l[len('olcAccess: '):]) for l in out.splitlines() if l.startswith('olcAccess: ')]

  m_rules = fixture_rules('main-database.ldif', {'MACHINE_DN': MACHINE_DN, 'ALLOWED_DN': BASE_DN, 'MAIN_DB_DN': main_db})
  expected = m_rules + wd_rules + wl_rules + wcred_rules(PEOPLE)

  def compare(rules):
    return rules[:len(expected)] == expected

  got = reader_rules()
  diffs = [(i, e, g) for i, (e, g) in enumerate(zip(expected, got)) if e != g]
  obs(f'E-21 byte comparison of the {len(expected)} leading rules (fixture text, tokens substituted, folding undone, {{n}} stripped) '
      f'with what slapd returns to the reader: {"identical" if not diffs else diffs[:3]}')
  expect('E-21', compare(got), 'slapd returns every machine rule (W_cred filter / val.regex included) byte-identical to the substituted fixture text')
  ldap.live.run(['docker', 'restart', ldap.name])
  ldap.wait()
  got_r = reader_rules()
  expect('E-21', got_r == got, 'the returned rule text is identical after a slapd restart (stable across re-parse)')

  wc = f'dn.exact="{WCRED_DN}"'
  # (1) a looser rule for a SECOND subtree in front of the W_cred bundle
  loose2 = f'to dn.subtree="{STAFF}" attrs=userPassword by {wc} write by * break'
  install(main_db, cred_start, [loose2])
  staff_user = f'uid=st-pw,{STAFF}'
  adm('ldapadd', [], f'dn: {staff_user}\nobjectClass: inetOrgPerson\nuid: st-pw\ncn: s\nsn: s\nuserPassword: {live.secret("St-" + secrets.token_urlsafe(12))}\n')
  assign(staff_user, POL_PENDING)  # without it pwdSafeModify would refuse first and hide the ACL effect
  eff = code(setpw(staff_user))
  c1 = compare(reader_rules())
  obs(f'E-21 mutation 1 (looser rule for {STAFF} in front of the bundle): comparator match {c1}; W_cred now resets an EXISTING staff password: rc {eff}')
  delete_at(main_db, cred_start)
  # (2) the bundle's filter without creatorsName
  delete_at(main_db, pw_slot)
  install(main_db, pw_slot, [wcred_rules(PEOPLE, creators=False)[2]])
  c2 = compare(reader_rules())
  eff2 = code(setpw(c))
  obs(f'E-21 mutation 2 (creatorsName dropped from the filter): comparator match {c2}; W_cred on the hand-marked admin-made p-c: rc {eff2}')
  delete_at(main_db, pw_slot)
  install(main_db, pw_slot, [wcred_rules(PEOPLE)[2]])
  # (3) a rule at {0}, ahead of everything
  install(main_db, 0, [f'to dn.subtree="{PEOPLE}" attrs=userPassword by {wc} write by * break'])
  c3 = compare(reader_rules())
  obs(f'E-21 mutation 3 (rule inserted at {{0}}): comparator match {c3}')
  delete_at(main_db, 0)
  restored = compare(reader_rules())
  expect('E-21', (c1, c2, c3, restored) == (False, False, False, True), 'the comparator rejects each mutation and matches again once restored')

  # ======== F-4 decided design (maintainer 2026-10-13): per-pending-account policy ===========================
  # A dedicated policy (copy of the default, pwdSafeModify FALSE, pwdCheckQuality 2) is attached ONLY to marker
  # accounts, by W_data, and removed by W_cred together with the marker in one cleanup Modify. Scratch ACL:
  #   W_data (before its {2} none): pwdPolicySubentry, exactly that DN, only on a marker entry   -> add
  #   W_cred (before its secrets none): pwdPolicySubentry, exactly that DN                       -> =z
  #   W_cred userPassword filter gains (pwdPolicySubentry=<that DN>)
  POL = policy('credential-pending', 'FALSE', 'TRUE')   # dflt carries pwdCheckQuality 2 at this point
  pol_attrs = attrs(POL, 'pwdSafeModify', 'pwdCheckQuality', 'pwdMinLength', 'pwdLockout', 'pwdAttribute', who=MID)
  obs(f'D-0 the pending policy as M reads it (what a start-up check can compare): {pol_attrs}')
  expect('D-0', {'pwdSafeModify: FALSE', 'pwdCheckQuality: 2', 'pwdMinLength: 8', 'pwdAttribute: userPassword'} <= set(pol_attrs),
         'M reads pwdSafeModify / pwdCheckQuality / pwdMinLength / pwdAttribute of the pending policy entry')
  wd_pol = (f'to dn.subtree="{PEOPLE}" attrs=pwdPolicySubentry val="{POL}" filter=(employeeType=ldapium-credential-pending:*) '
            f'by dn.exact="{WDATA_DN}" add by * break')
  install(main_db, 5, [wd_pol])          # W_data {2} (secrets none) is at {5}
  cs = cred_start + 1
  install(main_db, cs + 4, [f'to dn.subtree="{PEOPLE}" attrs=pwdPolicySubentry val="{POL}" by dn.exact="{WCRED_DN}" =z by * break'])
  swap(cs + 2, wcred_rules(PEOPLE, policy=POL)[2])
  got_rules = [re.sub(r'^\{\d+\}', '', l[len('olcAccess: '):]) for l in cfg('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', main_db, '-s', 'base', 'olcAccess']).stdout.splitlines() if l.startswith('olcAccess: ')]
  obs(f'D-0 rules as slapd stores them: W_data {{5}} {got_rules[5]!r}; W_cred {{{cs + 2}}} {got_rules[cs + 2]!r}; W_cred {{{cs + 4}}} {got_rules[cs + 4]!r}')

  def wadd(uid, mark=True, pol=POL, extra=''):
    dn = f'uid={uid},{PEOPLE}'
    body = (f'dn: {dn}\nobjectClass: inetOrgPerson\nuid: {uid}\ncn: {uid}\nsn: {uid}\n' + (f'employeeType: {MARKER}\n' if mark else '')
            + (f'pwdPolicySubentry: {pol}\n' if pol else '') + extra)
    return dn, code(wdata('ldapadd', [], body))

  def polof(dn):
    return [l.split(': ', 1)[1] for l in attrs(dn, 'pwdPolicySubentry')]

  # --- attach at Add (olcAddContentAcl as shipped = FALSE: an Add is not checked per attribute, #386)
  d1, r1 = wadd('d1')
  d2, r2 = wadd('d2', mark=False)
  d3, r3 = wadd('d3', pol=POL_NOLOCK)
  obs(f'D-1 W_data Add (olcAddContentAcl FALSE): marker+pending policy {r1} {polof(d1)}; NO marker+pending policy {r2} {polof(d2)}; marker+OTHER policy {r3} {polof(d3)}')
  expect('D-1', r1 == (0, 'ok') and polof(d1) == [POL], 'W_data attaches the pending policy in the createUser Add that carries the marker')
  expect('D-1', r2 == (0, 'ok') and r3 == (0, 'ok'),
         'KNOWN LIMIT (#386, olcAddContentAcl FALSE): at Add the ACL does not constrain pwdPolicySubentry (any DN, with or without the marker); only the app closed body does')
  # --- attach by Modify (the ACL rule applies)
  d4, _ = wadd('d4', pol=None)
  d5, _ = wadd('d5', mark=False, pol=None)
  m_ok = code(wdata('ldapmodify', [], f'dn: {d4}\nchangetype: modify\nadd: pwdPolicySubentry\npwdPolicySubentry: {POL}\n'))
  adm('ldapmodify', [], f'dn: {d4}\nchangetype: modify\ndelete: pwdPolicySubentry\n')
  m_other = code(wdata('ldapmodify', [], f'dn: {d4}\nchangetype: modify\nadd: pwdPolicySubentry\npwdPolicySubentry: {POL_NOLOCK}\n'))
  m_nomark = code(wdata('ldapmodify', [], f'dn: {d5}\nchangetype: modify\nadd: pwdPolicySubentry\npwdPolicySubentry: {POL}\n'))
  m_u01 = code(wdata('ldapmodify', [], f'dn: uid=u01,{PEOPLE}\nchangetype: modify\nadd: pwdPolicySubentry\npwdPolicySubentry: {POL}\n'))
  m_repl = code(wdata('ldapmodify', [], f'dn: {d1}\nchangetype: modify\ndelete: pwdPolicySubentry\npwdPolicySubentry: {POL}\n'))
  obs(f'D-2 W_data Modify: add the pending policy to a marker entry {m_ok}; add another policy DN to a marker entry {m_other}; '
      f'add the pending policy to a NON-marker W_data entry {m_nomark} / to ordinary u01 {m_u01}; delete it {m_repl}')
  expect('D-2', m_ok[0] == 0 and (m_other[0], m_nomark[0], m_u01[0], m_repl[0]) == (50, 50, 50, 50),
         'W_data Modify: only the exact pending DN, only on a marker entry, add only')
  h_self = code(ldap.tool('ldapmodify', [], *HUMAN, f'dn: uid=human,{PEOPLE}\nchangetype: modify\nadd: pwdPolicySubentry\npwdPolicySubentry: {POL}\n'))
  h_other = code(ldap.tool('ldapmodify', [], *HUMAN, f'dn: uid=u02,{PEOPLE}\nchangetype: modify\nadd: pwdPolicySubentry\npwdPolicySubentry: {POL}\n'))
  m_m = code(ldap.tool('ldapmodify', [], *MID, f'dn: uid=u02,{PEOPLE}\nchangetype: modify\nadd: pwdPolicySubentry\npwdPolicySubentry: {POL}\n'))
  w_c = code(wcred('ldapmodify', [], f'dn: {d5}\nchangetype: modify\nadd: pwdPolicySubentry\npwdPolicySubentry: {POL}\n'))
  obs(f'D-2 attach by others: ordinary user on itself {h_self}, on u02 {h_other}; M {m_m}; W_cred {w_c}')
  expect('D-2', all(x[0] == 50 for x in (h_other, m_m, w_c)), 'an ordinary user (on another account), M and W_cred cannot attach the pending policy')
  self_set = attrs(f'uid=human,{PEOPLE}', 'pwdPolicySubentry')
  self_w = code(wcred('ldappasswd', ['-T', sentinel()[1], f'uid=human,{PEOPLE}']))
  self_orphan = 'uid=human' in ldap.tool('ldapsearch', ['-LLL', '-b', PEOPLE, f'(&(pwdPolicySubentry={POL})(!(employeeType=ldapium-credential-pending:*)))', 'dn'], *MID).stdout
  obs(f'D-2 F-9: the image rule `to * by self write` lets a user put ANY pwdPolicySubentry on itself: {h_self} -> {self_set}; W_cred on it {self_w}; M orphan sweep sees it {self_orphan}')
  expect('D-2', h_self == (0, 'ok') and self_w[0] == 50 and self_orphan,
         'F-9 known pre-existing (recorded, separate issue): a user can self-attach the pending policy; it is no W_cred target and the orphan sweep finds it')
  # --- the same Adds with olcAddContentAcl TRUE (hardening candidate, a database-wide switch)
  ensure(cfg('ldapmodify', [], f'dn: {main_db}\nchangetype: modify\nreplace: olcAddContentAcl\nolcAddContentAcl: TRUE\n').returncode == 0, 'aca on')
  t1, q1 = wadd('t1')
  t2, q2 = wadd('t2', mark=False)
  t3, q3 = wadd('t3', pol=POL_NOLOCK)
  t4, q4 = wadd('t4', pol=None, mark=False, extra='mail: t4@example.org\n')
  t5, q5 = wadd('t5', pol=None, mark=False, extra=f'userPassword: {sentinel()[0]}\n')
  ensure(cfg('ldapmodify', [], f'dn: {main_db}\nchangetype: modify\ndelete: olcAddContentAcl\n').returncode == 0, 'aca off')
  obs(f'D-3 olcAddContentAcl TRUE: W_data Add marker+pending policy {q1}; NO marker+pending {q2}; marker+OTHER policy {q3}; '
      f'plain user (closed list) {q4}; plain user carrying userPassword {q5}')
  expect('D-3', q1[0] == 0 and q2[0] == 50 and q3[0] == 50 and q4[0] == 0,
         'with olcAddContentAcl TRUE the Add-time attach is ACL-limited to the exact DN on a marker entry, ordinary createUser still works')
  # --- set under the attached policy
  short_r = code(setpw(d1, '/tmp/.np-short'))
  pre_r = code(wcred('ldapmodify', [], f'dn: {d1}\nchangetype: modify\nadd: userPassword\nuserPassword: {hashed}\n'))
  nolock_r = code(setpw(d3))
  before_oracle = code(ldap.tool('ldappasswd', ['-T', sentinel()[1], d1], *MID))
  vd, pd = sentinel('D')
  ok_r = code(setpw(d1, pd))
  obs(f'D-4 W_cred on d1 (pending policy): 7-char exop {short_r}; pre-hashed 2-char Modify {pre_r}; compliant exop {ok_r} (binds {binds(d1, pd) == 0}); '
      f'on d3 (marker + OTHER policy) {nolock_r}; M Password Modify on d1 BEFORE the set {before_oracle}')
  expect('D-4', short_r[0] == 19 and pre_r[0] == 19 and ok_r == (0, 'ok') and binds(d1, pd) == 0,
         'under the attached policy: short exop 19, pre-hashed Modify 19 (quality 2), compliant exop 0 and binds')
  expect('D-4', nolock_r == (50, 'acl'), 'the (pwdPolicySubentry=<pending>) filter clause refuses a marker entry carrying another policy')
  # --- window between set and cleanup: the F-5 oracle, and how M finds a stuck account
  win = (code(ldap.tool('ldappasswd', ['-T', pd, d1], *MID)), code(ldap.tool('ldappasswd', ['-T', sentinel()[1], d1], *MID)))
  stuck = ldap.tool('ldapsearch', ['-LLL', '-b', PEOPLE, f'(&(pwdPolicySubentry={POL})(pwdChangedTime=*))', 'dn'], *MID).stdout.count('dn: ')
  orphan = ldap.tool('ldapsearch', ['-LLL', '-b', PEOPLE, f'(&(pwdPolicySubentry={POL})(!(employeeType=ldapium-credential-pending:*)))', 'dn'], *MID).stdout.count('dn: ')
  obs(f'D-5 after the set, before cleanup: M new=current {win[0]} vs wrong {win[1]} (oracle); M sweep "pending policy AND pwdChangedTime" finds {stuck}; '
      f'"pending policy WITHOUT marker" finds {orphan} (d2, t-entries)')
  expect('D-5', win == ((19, 'policy'), (50, 'acl')) and stuck == 1, 'between set and cleanup the oracle exists, and an M sweep finds the account (stuck-cleanup detector)')
  expect('D-5', orphan >= 1, 'an M sweep finds a pending policy on an entry without the marker (#386 Add-time attach is detectable)')
  # --- cleanup: one Modify removes the marker value and the policy value
  cl_other = code(wcred('ldapmodify', [], f'dn: {d3}\nchangetype: modify\ndelete: pwdPolicySubentry\npwdPolicySubentry: {POL_NOLOCK}\n'))
  cl_attr = code(wcred('ldapmodify', [], f'dn: {d1}\nchangetype: modify\ndelete: pwdPolicySubentry\n'))
  cl = code(wcred('ldapmodify', [], f'dn: {d1}\nchangetype: modify\ndelete: employeeType\nemployeeType: {MARKER}\n-\ndelete: pwdPolicySubentry\npwdPolicySubentry: {POL}\n'))
  after = attrs(d1, 'employeeType', 'pwdPolicySubentry')
  post = (code(ldap.tool('ldappasswd', ['-T', pd, d1], *MID)), code(setpw(d1)), binds(d1, pd) == 0)
  stuck2 = ldap.tool('ldapsearch', ['-LLL', '-b', PEOPLE, f'(&(pwdPolicySubentry={POL})(pwdChangedTime=*))', 'dn'], *MID).stdout.count('dn: ')
  obs(f'D-6 W_cred cleanup: delete ANOTHER policy value {cl_other}; delete the whole attribute {cl_attr}; marker+policy values in one Modify {cl} -> left {after}; '
      f'afterwards M new=current {post[0]}, W_cred exop {post[1]}, password still binds {post[2]}; stuck sweep {stuck2}')
  expect('D-6', cl == (0, 'ok') and after == [] and cl_other[0] == 50 and cl_attr[0] == 50,
         'cleanup removes exactly the marker value and the pending policy value in one Modify; nothing else')
  expect('D-6', post[0] == (50, 'safeModify') and post[1] == (50, 'safeModify') and post[2] and stuck2 == 0,
         'after cleanup the default policy applies again (safeModify, no 19/50 oracle) and the password is kept')
  # --- atomic alternative: one plain Modify sets the password AND cleans up (no window)
  d6, _ = wadd('d6')
  v6, p6 = sentinel('A')
  at_short = code(wcred('ldapmodify', [], f'dn: {d6}\nchangetype: modify\nreplace: userPassword\nuserPassword: {short_v}\n-\ndelete: employeeType\nemployeeType: {MARKER}\n-\ndelete: pwdPolicySubentry\npwdPolicySubentry: {POL}\n'))
  at_short_left = attrs(d6, 'employeeType', 'pwdPolicySubentry')
  at = code(wcred('ldapmodify', [], f'dn: {d6}\nchangetype: modify\nreplace: userPassword\nuserPassword: {v6}\n-\ndelete: employeeType\nemployeeType: {MARKER}\n-\ndelete: pwdPolicySubentry\npwdPolicySubentry: {POL}\n'))
  time.sleep(0.6)
  _, vals6 = alog(f'(reqDN={d6})')
  obs(f'D-7 atomic plain Modify (set + cleanup in one op): 7-char {at_short} (entry unchanged: {len(at_short_left) == 2}); compliant {at}, binds {binds(d6, p6) == 0}, '
      f'left {attrs(d6, "employeeType", "pwdPolicySubentry")}; accesslog hashed values {len(pw_hashes(vals6))} {[shape(v) for v in pw_hashes(vals6)]}')
  expect('D-7', at_short[0] == 19 and len(at_short_left) == 2 and at == (0, 'ok') and binds(d6, p6) == 0 and attrs(d6, 'employeeType', 'pwdPolicySubentry') == [],
         'one plain Modify can set and clean up atomically (policy enforced; nothing left to clean)')

  final_phase()

  # ======== E-12d: accesslog logging `extended` ==================================================================
  for ops in ('writes reads bind extended', 'all'):
    x = AuditSlapd(live, name=live.name_prefix + '-ext' + str(len(ops)), ops=ops)
    x.start()
    ensure(x.admin_tool('ldapadd', [], f'dn: {PEOPLE}\nobjectClass: organizationalUnit\nou: people\n\n'
                                        f'dn: uid=x,{PEOPLE}\nobjectClass: inetOrgPerson\nuid: x\ncn: x\nsn: x\n').returncode == 0, 'ext seed')
    xp = '/tmp/.np-x'
    x.put_password(xp, live.secret('Xx-' + secrets.token_urlsafe(14)))
    rx = x.admin_tool('ldappasswd', ['-T', xp, 'uid=x,' + PEOPLE])
    time.sleep(2)
    state = live.run(['docker', 'inspect', '-f', '{{.State.Status}} {{.State.ExitCode}}', x.name]).stdout.strip()
    xlog = live.run(['docker', 'logs', x.name])
    assertion = [l for l in (xlog.stdout + xlog.stderr).splitlines() if 'Assertion' in l]
    obs(f'E-12d LDAP_ACCESSLOG_OPS="{ops}": admin Password Modify exop rc {rx.returncode}; container {state}; {assertion}')
    expect('E-12', rx.returncode != 0 and state.startswith('exited') and assertion,
           f'F-7 known defect (recorded, separate issue): LDAP_ACCESSLOG_OPS="{ops}" aborts slapd on a Password Modify exop; flips when fixed')

  # ---- summary ------------------------------------------------------------------------------------------
  failed = [r for r in results if not r[1]]
  print('\nSUMMARY', flush=True)
  for eid, ok, text in results:
    print(f'  {"PASS" if ok else "FAIL"} [{eid}] {text}')
  print(f'{len(results) - len(failed)} of {len(results)} expectations held, {len(failed)} failed, {live.elapsed():.0f}s.', flush=True)
  if failed:
    sys.exit(1)


if __name__ == '__main__':
  try:
    main()
  except SystemExit:
    raise
  except BaseException:
    live.dump_logs()
    raise
