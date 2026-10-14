#!/usr/bin/env python3
"""Live proof of the v2c run-time premise checks and sweeps (#379, T-028; AC-010b, REQ-014, D379-15/16).

docs/changes/machine-write-scope-v2, against real slapd. The application side is the
ldapclient.CredPremise checker the UI runs at start-up, before every setPassword and every
60 s; this script runs that exact code (the `live`-tagged Go test binary,
TestCredPremiseLive, inside the container) and asserts its result codes. The gate around
it (start-up refusal, 503, the 60 s cycle) is unit-tested in internal/httpapi; the
opened operation (T-026) runs through it in the T-024/T-025 proofs.

One fresh container (no replication identity, accesslog on with `writes reads bind`),
built with the base proof's helpers (scripts/test/test-machine-write-acl-live.py, imported:
its main() does not run) and the DOCUMENTED procedure: guide 4.2/4.3 W_data and W_lock,
8.1 the no-lockout policy of W_cred (Q17), 8.2-8.5 v2c, then the new 8.8 blocks cut out of docs/machine-write-account.md (the
configuration reader account and ACL, the canaries in TWO cred subtrees). Then:

  * the baseline passes (start-up/periodic check with canaries, and the request check);
  * AC-010b, each a change made after the baseline and undone after: a looser
    userPassword rule for the SECOND cred subtree only, in front of the W_cred bundle
    (its real effect is shown: W_cred resets an existing password there); a rule at {0};
    a W_cred filter term dropped; olcAddContentAcl off; default policy below the floor /
    pwdSafeModify FALSE; pending policy quality 1 / pwdSafeModify TRUE; no
    olcPPolicyDefault; M reading accesslog CHILDREN with the base hidden (E-23a) and the
    full opt-in; the reader's main-DB deny and its cn=config grant removed; a canary
    that accepts a write and one the ACL refuses;
  * the sweeps: stuck / TTL / orphan cleaned by W_cred, foreign only counted, canaries
    left alone, a cleanup that cannot succeed fails the round;
  * the reader account sees nothing else (E-21, D379-16).

Mutation self-test (LDAPIUM_PREMISE_MUTATE builds the checker from a patched copy of the
source; the proof must then FAIL with named checks):
  drop-acl-check          check 1 (the olcAccess comparison) removed
  accesslog-base-search   check 6 searches the cn=accesslog BASE instead of its children
  accesslog-objectclass   check 6 back to the (objectClass=*) filter (MINOR1)
  sweep-nosuchattr-ok     a cleanup failing with noSuchAttribute counts as cleaned (Codex P1)

Run (docker and go): python3 scripts/test/test-machine-write-cred-premise-live.py
Override LDAPIUM_IMAGE / LDAPIUM_TEST_PREFIX; LDAPIUM_PREMISE_TEST_BINARY skips the build.
"""
import importlib.util
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

repo_root = pathlib.Path(__file__).resolve().parents[2]
mutation = os.environ.get('LDAPIUM_PREMISE_MUTATE', '')
MUTATIONS = ('drop-acl-check', 'accesslog-base-search', 'accesslog-objectclass', 'sweep-nosuchattr-ok')
if mutation not in ('',) + MUTATIONS:
  raise SystemExit('LDAPIUM_PREMISE_MUTATE must be one of ' + ', '.join(MUTATIONS))
os.environ.setdefault('LDAPIUM_TEST_PREFIX', 'ldapium-cpre-')
os.environ['LDAPIUM_WACL_MUTATE'] = ''  # the base proof's own fragment mutations stay off
os.environ['LDAPIUM_WACL_CONFIGS'] = 'n0'
_spec = importlib.util.spec_from_file_location('wacl', repo_root / 'scripts/test/test-machine-write-acl-live.py')
acl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(acl)

check, require, mask, run, guide_sh, lcode = acl.check, acl.require, acl.mask, acl.run, acl.guide_sh, acl.lcode
base_dn, managed, people, groups, system_dn = acl.base_dn, acl.managed, acl.people, acl.groups, acl.system_dn
wd_dn, wl_dn, wc_dn, machine_dn, priv, pending_pol, default_pol = (acl.wd_dn, acl.wl_dn, acl.wc_dn, acl.machine_dn, acl.priv,
                                                                   acl.pending_pol, acl.default_pol)
reader_dn = 'uid=machine-cred-acl-reader,' + system_dn
sub_a, sub_b = 'ou=a,' + people, 'ou=b,' + people        # two cred subtrees; their common ancestor is the CRED_DN people
wcred_policy = 'cn=machine-writers,ou=policies,' + base_dn  # guide 8.1 no-lockout policy of W_cred (Q17)
CMARK = 'ldapium-credential-pending:0000000000000000'
MAIN = 'olcDatabase={1}mdb,cn=config'
CFGDB = 'olcDatabase={0}config,cn=config'


# The base proof's containers have no accesslog; this proof needs it (check 6 and E-23a).
_run = acl.run


def _run_with_accesslog(cmd, *a, **kw):
  if cmd[:3] == ['docker', 'run', '-d']:
    cmd = cmd[:3] + ['-e', 'LDAP_ACCESSLOG_ENABLED=true', '-e', 'LDAP_ACCESSLOG_OPS=writes reads bind'] + cmd[3:]
  return _run(cmd, *a, **kw)


acl.run = _run_with_accesslog


def build_binary():
  given = os.environ.get('LDAPIUM_PREMISE_TEST_BINARY')
  if given:
    return given
  arch = run(['docker', 'info', '--format', '{{.Architecture}}']).stdout.strip()
  goarch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(arch, arch)
  src = repo_root / 'ui/backend'
  work = tempfile.mkdtemp(prefix='cpre-src-')
  acl.tmp_dirs.append(work)
  if mutation:
    shutil.copytree(src, work + '/backend', ignore=shutil.ignore_patterns('dist', 'node_modules'))
    src = pathlib.Path(work + '/backend')
    f = src / 'internal/ldapclient/machine_write_premise_ldap.go'
    if mutation == 'accesslog-objectclass':
      f = src / 'internal/ldapclient/machine_write_premise_verdict.go'
    text = f.read_text()
    if mutation == 'drop-acl-check':
      text, n = re.subn(r'if code := compareCredACL\(values, params\); code != "" \{', 'if code := compareCredACL(values, params); false && code != "" {', text)
    elif mutation == 'accesslog-base-search':
      text, n = re.subn(r'credPremiseAccesslogBase, ldap\.ScopeWholeSubtree', 'credPremiseAccesslogBase, ldap.ScopeBaseObject', text)
    elif mutation == 'accesslog-objectclass':
      text, n = re.subn(r'const accesslogProbeFilter = "[^"]*"', 'const accesslogProbeFilter = "(objectClass=*)"', text)
    else:
      text, n = re.subn(r'if cred\.Modify\(sweepCleanupModify\(e\.DN, attrValues\(e, "employeeType"\), policy\)\) == nil \{',
                        'if err := cred.Modify(sweepCleanupModify(e.DN, attrValues(e, "employeeType"), policy)); err == nil || ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute) {', text)
    require(n == 1, f'mutation {mutation} did not apply')
    f.write_text(text)
  out = work + '/premise-test'
  env = dict(os.environ, GOOS='linux', GOARCH=goarch, CGO_ENABLED='0')
  res = run(['go', 'test', '-tags=live', '-c', '-o', out, './internal/ldapclient'], env=env, cwd=str(src), timeout=600)
  require(res.returncode == 0, 'go test -c: ' + res.stderr[-400:])
  return out


class Premise:
  """The checker binary inside the container; one call per scenario."""

  def __init__(self, node, binary, canaries):
    self.node = node
    require(run(['docker', 'cp', binary, node.container + ':/tmp/.premise-test']).returncode == 0, 'docker cp the checker')
    self.env = {'LDAPIUM_CRED_PREMISE_LIVE': '1', 'P_BASE': base_dn, 'P_M_DN': machine_dn, 'P_WDATA_DN': wd_dn, 'P_WLOCK_DN': wl_dn,
                'P_WCRED_DN': wc_dn, 'P_READER_DN': reader_dn, 'P_CEILINGS': managed, 'P_CRED': sub_a + ';' + sub_b,
                'P_PRIV': priv, 'P_PENDING': pending_pol, 'P_ALLOWED': '', 'P_CANARIES': ';'.join(canaries), 'P_TTL': '2s'}

  def _go(self, mode):
    cmd = ['docker', 'exec']
    for k, v in dict(self.env, P_MODE=mode).items():
      cmd += ['-e', f'{k}={v}']
    res = run(cmd + [self.node.container, '/tmp/.premise-test', '-test.run', '^TestCredPremiseLive$', '-test.v'], timeout=120)
    text = res.stdout + res.stderr + f'\n(exit {res.returncode})\n'
    check(mask(text) == text and not any(v in text for v in acl.passwords.values() if len(v) >= 8),
          f'checker output ({mode}) carries no password value')
    return text

  def check(self):
    m = re.search(r'^PREMISE full=(\S+) request=(\S+)$', self._go('check'), re.M)
    require(m is not None, 'no PREMISE line')
    return m.group(1), m.group(2)

  def sweep(self, mode='sweep'):
    text = self._go(mode)
    m = re.search(r'^SWEEP stuck=(\d+) ttl=(\d+) orphan=(\d+) foreign=(\d+) cleaned=(\d+) failed=(\w+) code=(\S+)$', text, re.M)
    require(m is not None, 'no SWEEP line: ' + mask(text)[-400:])
    return dict(stuck=int(m.group(1)), ttl=int(m.group(2)), orphan=int(m.group(3)), foreign=int(m.group(4)),
                cleaned=int(m.group(5)), failed=m.group(6) == 'true', code=m.group(7))


# ---- small cn=config editors (as cn=admin,cn=config, the operator) ---------------------------------

def rules(node, db=MAIN):
  res = node.cfgtool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', db, '-s', 'base', 'olcAccess'])
  require(res.returncode == 0, 'read olcAccess')
  return re.findall(r'^olcAccess: (.*)$', res.stdout, re.M)


def cfg_mod(node, ldif):
  res = node.cfgtool('ldapmodify', [], ldif)
  require(res.returncode == 0, 'cn=config modify: ' + mask(res.stderr))


def insert_rule(node, i, text, db=MAIN):
  cfg_mod(node, f'dn: {db}\nchangetype: modify\nadd: olcAccess\nolcAccess: {{{i}}}{text}\n')


def delete_rule(node, i, db=MAIN):
  cfg_mod(node, f'dn: {db}\nchangetype: modify\ndelete: olcAccess\nolcAccess: {{{i}}}\n')


def body(rule):
  return re.sub(r'^\{\d+\}', '', rule)


def cred_at(node):
  return [i for i, r in enumerate(rules(node)) if f'by dn.exact="{wc_dn}"' in r][0]


def admin(node, ldif, tool='ldapmodify'):
  res = node.tool('admin', tool, [], ldif)
  require(res.returncode == 0, 'admin write: ' + mask(res.stderr))


def attr_set(node, dn, attr, value):
  admin(node, f'dn: {dn}\nchangetype: modify\nreplace: {attr}\n{attr}: {value}\n')


def guide(node, marker, extra=None):
  env = acl.guide_env(node, managed)
  env.update({'READER_DN': reader_dn})
  env.update(extra or {})
  res = run(['bash', '-c', guide_sh(marker), '-'], env=env, cwd=node.fragdir)
  return res.stdout + res.stderr


# ---- setup -----------------------------------------------------------------------------------------

def setup(node):
  node.start()
  acl.seed(node)
  raw0, rules0 = node.olc_access()
  node.repl_rules, node.image_rules = [], [acl.norm(body(r)) for r in rules0]
  # M with the documented default read base, the root (machine-ldap-account.md 3): check 2 reads the
  # policies under ou=policies and the sweeps search the whole base as M (T028-D10)
  res = node.sh(acl.M_APPLY, acl.fixture_text('main-database.ldif'),
                {'MACHINE_DN': machine_dn, 'ALLOWED_DN': base_dn, 'MAIN_DB_DN': node.main_db, 'CFG_URI': acl.ldapi_uri})
  require(res.returncode == 0, 'M apply: ' + mask(res.stderr))
  node.fragdir = acl.fragdir_for(node, 'premise')
  for name in ('config-reader.ldif', 'config-reader-main.ldif', 'wcred-policy.ldif'):
    shutil.copy(acl.fixtures / name, node.fragdir)
  for frag, who in (('write-data.ldif', wd_dn), ('write-lock.ldif', wl_dn)):
    out = acl.guide_install(node, node.fragdir, frag, who, managed)
    require('BASE=' in out and 'refusing' not in out, f'guide 4.2 {frag}: {out[-200:]}')
  # v2c accounts and data (as the base proof's v2c phase)
  admin(node, acl.person(wc_dn, 'machine-write-cred', f'userPassword: {acl.passwords["wcred"]}\n'))
  # 8.1, Q17 (2026-10-14): W_cred carries the no-lockout policy (a second apply only re-checks it)
  for _ in range(2):
    out = acl.guide_v2c(node, 'v2c-wcred-policy', {'WCRED_POLICY_DN': wcred_policy})
    require('refusing' not in out and f'WCRED_POLICY={wcred_policy}' in out, 'guide 8.1 no-lockout policy: ' + mask(out[-300:]))
  res = node.search('admin', wc_dn, '(objectClass=*)', ['pwdPolicySubentry'], 'base')
  check(res.returncode == 0 and re.search(rf'^pwdPolicySubentry: {re.escape(wcred_policy)}$', res.stdout, re.M | re.I) is not None,
        'guide 8.1: W_cred carries the no-lockout policy (Q17)')
  admin(node, f'dn: {priv}\nchangetype: add\nobjectClass: groupOfNames\ncn: admins\nmember: uid=u01,{people}\n')
  for ou in (sub_a, sub_b):
    admin(node, f'dn: {ou}\nchangetype: add\nobjectClass: organizationalUnit\nou: {ou.split(",")[0][3:]}\n')
  # 8.8: the default policy at the v2c floor BEFORE 8.3 copies it (the shipped 8 fails check 2)
  attr_set(node, default_pol, 'pwdMinLength', '12')
  for marker, extra in (('v2c-policy', {}), ('v2c-switch-on', {}), ('V2C_AT=', {'FRAG': 'write-data-cred.ldif'}),
                        ('V2C_AT=', {'FRAG': 'write-cred.ldif'})):
    out = acl.guide_v2c(node, marker, extra)
    require('refusing' not in out, f'guide {marker} {extra}: {out[-200:]}')
  # 8.8 reader
  out = guide(node, 'v2c-reader-account')
  require(node.search('admin', reader_dn, '(objectClass=*)', ['dn'], 'base').returncode == 0, 'reader account: ' + mask(out[-200:]))
  acl.passwords['reader'] = pathlib.Path(node.fragdir, 'reader.pw').read_text()
  node.put('/tmp/.pw-reader', acl.passwords['reader'])
  acl.WHO['reader'] = (reader_dn, '/tmp/.pw-reader')
  at = cred_at(node)
  out = guide(node, 'RD_AT=')
  check(re.search(rf'^RD_AT={at + 7}$', out, re.M) is not None and f'by dn.exact="{reader_dn}"' in rules(node)[at + 7],
        f'guide 8.8 put the reader deny rule directly after the W_cred bundle {{{at + 7}}}')
  check(sum(f'dn.exact="{reader_dn}"' in r for r in rules(node, CFGDB)) == 2, 'guide 8.8 put the two cn=config reader rules')
  before = rules(node), rules(node, CFGDB)
  out = guide(node, 'RD_AT=')
  check('refusing' in out and (rules(node), rules(node, CFGDB)) == before, 'a second 8.8 reader apply is refused and changes nothing')
  # 8.8 canaries, one set per cred subtree
  canaries = []
  for base, uid in ((sub_a, 'canary-a'), (sub_b, 'canary-b')):
    out = guide(node, 'v2c-canaries', {'CANARY_BASE': base, 'CANARY_UID': uid})
    m = re.search(r'^CANARY_SET=(.*)$', out, re.M)
    require(m is not None, 'canaries: ' + mask(out[-300:]))
    canaries.append(m.group(1))
  return canaries


# ---- the proof -------------------------------------------------------------------------------------

def reader_sees_only_its_two_entries(node):
  res = node.tool('reader', 'ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', MAIN, '-s', 'sub', '(|(olcAccess=*)(olcPPolicyDefault=*))', 'olcAccess', 'olcAddContentAcl', 'olcPPolicyDefault', 'olcSuffix'])
  dns = acl.dn_set(res.stdout)
  check(res.returncode == 0 and len(dns) == 2 and dns[0].startswith('olcdatabase={1}mdb') and 'olcppolicyconfig' not in res.stdout.lower()
        and not acl.has_attr(res.stdout, 'olcSuffix'), f'E-21: the reader sees exactly the main DB entry and the ppolicy overlay, only the granted attributes ({dns})')
  res = node.tool('reader', 'ldapsearch', ['-LLL', '-b', 'cn=config', '-s', 'sub', '(objectClass=*)', 'dn'])
  check(not acl.dn_set(res.stdout), 'E-21: the reader finds nothing with (objectClass=*) from cn=config')
  res = node.tool('reader', 'ldapsearch', ['-LLL', '-b', base_dn, '-s', 'sub', '(objectClass=*)', 'dn'])
  check(not acl.dn_set(res.stdout), 'D379-16: the reader reads nothing in the main database (its deny rule)')
  res = node.tool('reader', 'ldapmodify', [], f'dn: {MAIN}\nchangetype: modify\nadd: olcAccess\nolcAccess: {{0}}to * by * write\n')
  check(lcode(res) == 50, 'the reader cannot write olcAccess (50)')


def scenario(p, label, want_full, want_request=None, setup_fn=None, undo=None):
  if setup_fn:
    setup_fn()
  try:
    full, req = p.check()
    want_request = want_full if want_request is None else want_request
    check(full == want_full and req == want_request,
          f'AC-010b {label}: start-up/periodic {full} (want {want_full}), request {req} (want {want_request})')
  finally:
    if undo:
      undo()


def main():
  print(f'Run {acl.name_prefix}: image {acl.ldap_image}, premise mutation={mutation or "none"}', flush=True)
  require(run(['docker', 'version', '--format', 'ok']).returncode == 0, 'docker is not available')
  for name in ('config-reader.ldif', 'config-reader-main.ldif'):
    want = acl.significant(acl.fixture_text(name))
    check(any(acl.significant(b) == want for b in acl.guide_ldif_blocks(acl.write_guide)), f'write guide contains the committed {name} verbatim as one block')
  binary = build_binary()
  node = acl.Node('n0')
  canaries = setup(node)
  p = Premise(node, binary, canaries)
  reader_sees_only_its_two_entries(node)

  print('--- baseline ---', flush=True)
  scenario(p, 'baseline (the guide layout, both cred subtrees with canaries)', 'ok')
  check(len(acl.idx_of(node, wc_dn)) == 7, 'W_cred bundle installed (7 rules)')

  print('--- AC-010b: ACL changes after start-up ---', flush=True)
  victim = f'uid=premise-victim,{sub_b}'
  # an existing account with a password; it carries the pending policy (as a Q14-window account would)
  # so the default policy's pwdSafeModify does not hide what the loose ACL allows
  admin(node, acl.person(victim, 'premise-victim', f'userPassword: Victim-{secrets.token_urlsafe(12)}\npwdPolicySubentry: {pending_pol}\n'))
  loose = f'to dn.subtree="{sub_b}" attrs=userPassword by users write'
  at = cred_at(node)

  def loose_effect():
    insert_rule(node, at, loose)
    path = '/tmp/.cpre-loose'
    node.put(path, 'Loose-' + secrets.token_urlsafe(18))
    check(lcode(node.tool('wcred', 'ldappasswd', ['-T', path, victim])) == 0,
          'real effect: with the looser second-subtree rule W_cred resets an EXISTING password there (0), what check 1 must refuse')
  scenario(p, 'a looser userPassword rule for the SECOND cred subtree in front of the W_cred bundle', 'acl_cred_bundle_mismatch',
           setup_fn=loose_effect, undo=lambda: delete_rule(node, at))
  admin(node, f'dn: {victim}\nchangetype: delete\n')
  scenario(p, 'a rule inserted at {0}', 'acl_prefix_mismatch',
           setup_fn=lambda: insert_rule(node, 0, f'to dn.subtree="{sub_b}" by users read by * break'), undo=lambda: delete_rule(node, 0))
  orig = body(rules(node)[at + 2])
  scenario(p, 'the W_cred userPassword filter loses (!(userPassword=*))', 'acl_cred_bundle_mismatch',
           setup_fn=lambda: (delete_rule(node, at + 2), insert_rule(node, at + 2, orig.replace('(!(userPassword=*))', ''))),
           undo=lambda: (delete_rule(node, at + 2), insert_rule(node, at + 2, orig)))
  scenario(p, 'olcAddContentAcl switched off', 'acl_add_content_acl_off',
           setup_fn=lambda: cfg_mod(node, f'dn: {MAIN}\nchangetype: modify\ndelete: olcAddContentAcl\n'),
           undo=lambda: cfg_mod(node, f'dn: {MAIN}\nchangetype: modify\nreplace: olcAddContentAcl\nolcAddContentAcl: TRUE\n'))
  rd = at + 7
  reader_rule = body(rules(node)[rd])

  def drop_reader_deny():
    delete_rule(node, rd)
    check(len(acl.dn_set(node.tool('reader', 'ldapsearch', ['-LLL', '-b', people, '-s', 'sub', '(objectClass=*)', 'dn']).stdout)) > 0,
          'real effect: without its main-DB deny the reader reads the directory (E-21), what check 1 must refuse')
  scenario(p, "the reader's main-DB deny rule removed", 'acl_reader_rule_missing', setup_fn=drop_reader_deny,
           undo=lambda: insert_rule(node, rd, reader_rule))
  cfg0 = body(rules(node, CFGDB)[0])
  scenario(p, "the reader's cn=config grant removed", 'reader_unreadable',
           setup_fn=lambda: delete_rule(node, 0, CFGDB), undo=lambda: insert_rule(node, 0, cfg0, CFGDB))

  print('--- AC-010b: policies ---', flush=True)
  for label, dn, attr, bad, good, want in (
      ('default policy pwdMinLength 8 (the shipped value, below the floor 12)', default_pol, 'pwdMinLength', '8', '12', 'policy_default_min_length'),
      ('default policy pwdSafeModify FALSE (F-5 on every account)', default_pol, 'pwdSafeModify', 'FALSE', 'TRUE', 'policy_default_safe_modify'),
      ('pending policy pwdCheckQuality 1 (F-6)', pending_pol, 'pwdCheckQuality', '1', '2', 'policy_pending_check_quality'),
      ('pending policy pwdSafeModify TRUE (F-4)', pending_pol, 'pwdSafeModify', 'TRUE', 'FALSE', 'policy_pending_safe_modify'),
      ('pending policy pwdMinLength 8', pending_pol, 'pwdMinLength', '8', '12', 'policy_pending_min_length')):
    scenario(p, label, want, setup_fn=lambda dn=dn, attr=attr, bad=bad: attr_set(node, dn, attr, bad),
             undo=lambda dn=dn, attr=attr, good=good: attr_set(node, dn, attr, good))
  pp = re.search(r'^dn: (.*)$', node.cfgtool('ldapsearch', ['-LLL', '-b', MAIN, '-s', 'one', '(objectClass=olcPPolicyConfig)', 'dn']).stdout, re.M).group(1)
  scenario(p, 'no olcPPolicyDefault (stands in for a policy-less node)', 'policy_default_unknown',
           setup_fn=lambda: cfg_mod(node, f'dn: {pp}\nchangetype: modify\ndelete: olcPPolicyDefault\n'),
           undo=lambda: cfg_mod(node, f'dn: {pp}\nchangetype: modify\nreplace: olcPPolicyDefault\nolcPPolicyDefault: {default_pol}\n'))

  print('--- AC-010b: accesslog children (D379-14, E-23) ---', flush=True)
  alog = re.search(r'^dn: (.*)$', node.cfgtool('ldapsearch', ['-LLL', '-b', 'cn=config', '(olcSuffix=cn=accesslog)', 'dn']).stdout, re.M).group(1)
  m_rules = [f'to dn.base="cn=accesslog" by dn.exact="{machine_dn}" search by * break',
             f'to dn.subtree="cn=accesslog" by dn.exact="{machine_dn}" read by * break']

  def hidden_base():
    for i, r in enumerate(m_rules):
      insert_rule(node, i, r, alog)
    base = node.tool('machine', 'ldapsearch', ['-LLL', '-b', 'cn=accesslog', '-s', 'base', '(objectClass=*)', 'dn'])
    subt = node.tool('machine', 'ldapsearch', ['-LLL', '-b', 'cn=accesslog', '-s', 'sub', '-z', '3', '(objectClass=*)', 'reqMod'])
    check(not acl.dn_set(base.stdout) and len(acl.dn_set(subt.stdout)) > 0,
          'E-23a control: base hidden from M (0 entries) while M reads accesslog children')
  scenario(p, 'M reads accesslog CHILDREN with the base hidden', 'accesslog_children_readable',
           setup_fn=hidden_base, undo=lambda: [delete_rule(node, 0, alog) for _ in m_rules])
  attr_rule = f'to dn.subtree="cn=accesslog" attrs=entry,reqMod,reqOld,reqDN by dn.exact="{machine_dn}" read by * break'

  def attrs_only():
    insert_rule(node, 0, attr_rule, alog)
    oc = node.tool('machine', 'ldapsearch', ['-LLL', '-b', 'cn=accesslog', '-s', 'sub', '-z', '3', '(objectClass=*)', 'dn'])
    dnf = node.tool('machine', 'ldapsearch', ['-LLL', '-b', 'cn=accesslog', '-s', 'sub', '-z', '3', '(reqDN=*)', 'reqMod'])
    check(not acl.dn_set(oc.stdout) and len(acl.dn_set(dnf.stdout)) > 0,
          'MINOR1 control: M reads reqMod/reqDN children while (objectClass=*) matches nothing (no search on objectClass)')
  scenario(p, 'M reads accesslog reqMod/reqOld/reqDN without objectClass (MINOR1)', 'accesslog_children_readable',
           setup_fn=attrs_only, undo=lambda: delete_rule(node, 0, alog))
  scenario(p, 'the M accesslog opt-in (accesslog-optin.ldif)', 'accesslog_children_readable',
           setup_fn=lambda: insert_rule(node, 0, f'to * by dn.exact="{machine_dn}" read by * break', alog), undo=lambda: delete_rule(node, 0, alog))

  print('--- check 5: canaries ---', flush=True)
  c_pw, c_unmarked, c_pending = canaries[1].split('|')
  # Finding (T028-F1): ppolicy judges the value BEFORE the ACL, so a pending canary that the ACL no
  # longer admits still answers 19. The 19 probes prove the pending policy applies to W_cred; that the
  # ACL admits the canary is not observable without a write (check 1 is the ACL proof).
  scenario(p, 'the second subtree\'s pending canary loses its marker: still 19 (the policy decides first, T028-F1)', 'ok', 'ok',
           setup_fn=lambda: admin(node, f'dn: {c_pending}\nchangetype: modify\ndelete: employeeType\n'),
           undo=lambda: admin(node, f'dn: {c_pending}\nchangetype: modify\nadd: employeeType\nemployeeType: {CMARK}\n'))
  scenario(p, 'the second subtree\'s pending canary loses the pending policy (default policy: pwdSafeModify refuses, 50)', 'canary_pending_short_unexpected', 'ok',
           setup_fn=lambda: admin(node, f'dn: {c_pending}\nchangetype: modify\ndelete: pwdPolicySubentry\n'),
           undo=lambda: admin(node, f'dn: {c_pending}\nchangetype: modify\nadd: pwdPolicySubentry\npwdPolicySubentry: {pending_pol}\n'))
  # Review MAJOR (T028-F1): the unmarked canary is W_data-made with the pending policy, so the marker term
  # is the only one that keeps W_cred out; giving it a marker must turn its 50 into an accepted write.
  def unmarked_gets_marker_undo():
    admin(node, f'dn: {c_unmarked}\nchangetype: modify\ndelete: employeeType\n')
    pwv = node.search('admin', c_unmarked, '(objectClass=*)', ['userPassword'], 'base').stdout
    if 'userPassword' in pwv:
      admin(node, f'dn: {c_unmarked}\nchangetype: modify\ndelete: userPassword\n')
  cre = node.search('admin', c_unmarked, '(objectClass=*)', ['creatorsName', 'pwdPolicySubentry', 'employeeType'], 'base').stdout
  check(f'creatorsName: {wd_dn}' in cre and f'pwdPolicySubentry: {pending_pol}' in cre and 'employeeType' not in cre,
        'guide 8.8: the unmarked canary is W_data-made, carries the pending policy and no marker (only the marker term differs)')
  scenario(p, 'the unmarked canary gains a marker (the marker term isolated: W_cred can now set it)', 'canary_unmarked_accepted', 'ok',
           setup_fn=lambda: admin(node, f'dn: {c_unmarked}\nchangetype: modify\nadd: employeeType\nemployeeType: {CMARK}\n'),
           undo=unmarked_gets_marker_undo)
  scenario(p, 'the with-password canary loses its password (W_cred can now set it: accepted, reset needed)', 'canary_with_password_accepted', 'ok',
           setup_fn=lambda: admin(node, f'dn: {c_pw}\nchangetype: modify\ndelete: userPassword\n'),
           undo=lambda: attr_set(node, c_pw, 'userPassword', secrets.token_hex(24)))
  locked = [l for l in node.search('admin', c_pending, '(objectClass=*)', ['pwdAccountLockedTime', 'userPassword', 'pwdChangedTime'], 'base').stdout.splitlines()]
  check(any(l.startswith('pwdAccountLockedTime: 000001010000Z') for l in locked) and not any(l.startswith(('userPassword', 'pwdChangedTime')) for l in locked),
        'after the probes the pending canary is still locked, password-less and never set (the 19s stored nothing)')
  scenario(p, 'everything restored', 'ok')

  print('--- sweeps (Revision 8/9) ---', flush=True)
  s = p.sweep()
  check(s == dict(stuck=0, ttl=0, orphan=0, foreign=0, cleaned=0, failed=False, code='ok'),
        f'sweep with only the canaries carrying the pending policy: nothing found (canaries skipped) {s}')
  mark = 'ldapium-credential-pending:' + secrets.token_hex(8)

  def pending(uid, who='wdata', marker=True):
    dn = f'uid={uid},{sub_a}'
    extra = (f'employeeType: {mark}\n' if marker else '') + f'pwdPolicySubentry: {pending_pol}\n'
    res = node.tool(who, 'ldapadd', [], acl.person(dn, uid, extra).replace('changetype: add\n', ''))
    require(res.returncode == 0, f'add {uid}: ' + mask(res.stderr))
    return dn
  stuck = pending('sw-stuck')
  path = '/tmp/.cpre-stuck'
  node.put(path, 'Stuck-' + secrets.token_urlsafe(18))
  require(lcode(node.tool('wcred', 'ldappasswd', ['-T', path, stuck])) == 0, 'set the stuck entry (no cleanup)')
  ttl = pending('sw-ttl')
  orphan = pending('sw-orphan')
  admin(node, f'dn: {orphan}\nchangetype: modify\ndelete: employeeType\n')
  foreign = pending('sw-foreign', who='admin', marker=False)
  time.sleep(3)  # P_TTL is 2s
  s = p.sweep()
  check(s == dict(stuck=1, ttl=1, orphan=1, foreign=1, cleaned=3, failed=False, code='ok'), f'sweep finds exactly one of each and cleans three {s}')
  left = acl.dn_set(node.search('admin', base_dn, f'(pwdPolicySubentry={pending_pol})', ['dn']).stdout)
  want_left = sorted([foreign.lower()] + [d.lower() for c in canaries for d in c.split('|')])
  check(left == want_left, f'after the sweep only the foreign entry and the canaries carry the pending policy ({len(left)})')
  for dn in (stuck, ttl):
    vals = node.search('admin', dn, '(objectClass=*)', ['employeeType', 'pwdPolicySubentry'], 'base').stdout
    check('employeeType' not in vals and 'pwdPolicySubentry' not in vals, f'{dn.split(",")[0]}: marker and policy removed by W_cred')
  s = p.sweep()
  check(s == dict(stuck=0, ttl=0, orphan=0, foreign=1, cleaned=0, failed=False, code='ok'), f'second sweep: only the foreign entry, alert only {s}')
  at = cred_at(node)
  grant = body(rules(node)[at + 4])
  stuck2 = pending('sw-stuck2')
  node.put(path, 'Stuck2-' + secrets.token_urlsafe(18))
  require(lcode(node.tool('wcred', 'ldappasswd', ['-T', path, stuck2])) == 0, 'set the second stuck entry')
  delete_rule(node, at + 4)
  s = p.sweep()
  check(s['failed'] and s['code'] == 'sweep_stuck_cleanup_failed' and s['stuck'] == 1, f'without the W_cred policy cleanup grant the stuck cleanup fails twice: the round fails {s}')
  insert_rule(node, at + 4, grant)
  s = p.sweep()
  check(not s['failed'] and s['cleaned'] == 1, f'with the grant back the next round cleans it {s}')
  # MINOR2/3: a read-only sweep counts and never writes
  stuck3 = pending('sw-stuck3')
  node.put(path, 'Stuck3-' + secrets.token_urlsafe(18))
  require(lcode(node.tool('wcred', 'ldappasswd', ['-T', path, stuck3])) == 0, 'set the third stuck entry')
  s = p.sweep('sweep-readonly')
  pol3 = node.search('admin', stuck3, '(objectClass=*)', ['pwdPolicySubentry'], 'base').stdout
  check(s['stuck'] == 1 and s['cleaned'] == 0 and not s['failed'] and 'pwdPolicySubentry' in pol3,
        f'read-only sweep: finds the stuck entry, writes nothing (the policy is still on it) {s}')
  # Codex P1: the marker disappears between the search and the cleanup; the cleanup must still remove
  # the policy (re-read, delete what is left), never count a noSuchAttribute as cleaned
  s = p.sweep('sweep-race')
  pol3 = node.search('admin', stuck3, '(objectClass=*)', ['pwdPolicySubentry', 'employeeType'], 'base').stdout
  check(s['stuck'] == 1 and s['orphan'] == 0 and s['cleaned'] == 1 and not s['failed'] and 'pwdPolicySubentry' not in pol3,
        f'race: marker removed after the search, the cleanup re-reads and removes the policy (cleaned only when gone) {s}')
  scenario(p, 'after the sweeps', 'ok')


if __name__ == '__main__':
  code = 0
  try:
    main()
  except Exception as e:
    print('ERROR: ' + mask(e), flush=True)
    import traceback
    traceback.print_exc()
    code = 1
  print(f'RESULT: {acl.passed} checks passed, {len(acl.failed)} failed, mutation={mutation or "none"}, {time.monotonic() - acl.start_time:.0f}s', flush=True)
  for f in acl.failed:
    print('  FAILED: ' + f, flush=True)
  sys.exit(1 if acl.failed or code else 0)
