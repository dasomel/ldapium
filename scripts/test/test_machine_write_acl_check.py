"""Fixture-driven unit test of scripts/check-machine-write-acl.sh (#285, T-023). No Docker.

Dumps: scripts/test/fixtures/machine-acl-check/good-prepare.ldif is the REAL main-database
olcAccess of a slapd with LDAP_REPLICATION_IDENTITY=prepare + the M read rules + both W
fragments applied with the guide's commands (written by test-check-machine-write-acl-live.sh).
The other static dumps are single-fault copies of it; the rest are mutated in memory.
Every failure case must exit non-zero and must NOT print status=pass (never a false pass).
"""
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).parents[2]
FIX = ROOT / 'scripts/test/fixtures/machine-acl'
DUMPS = ROOT / 'scripts/test/fixtures/machine-acl-check'
TOOL = ROOT / 'scripts/check-machine-write-acl.sh'

spec = importlib.util.spec_from_file_location('machine_write_acl_check', ROOT / 'scripts/lib/machine_write_acl_check.py')
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)

BASE = 'dc=example,dc=org'
MDN = 'uid=machine,ou=system,' + BASE
WD = 'uid=machine-write-data,ou=system,' + BASE
WL = 'uid=machine-write-lock,ou=system,' + BASE
SYS = 'ou=system,' + BASE
WRITE = 'ou=managed,' + BASE
REPL = 'cn=replicator,' + BASE
HEAD = 'dn: olcDatabase={1}mdb,cn=config\n'
ARGS = ['--root-dn', BASE, '--machine-dn', MDN, '--system-dn', SYS, '--write-dn', WRITE,
        '--wdata-dn', WD, '--wlock-dn', WL, '--replication-identity', 'required']
IMAGE_RULES = ['to attrs=userPassword,shadowLastChange by self write by anonymous auth by * none',
               'to attrs=entry,uid,objectClass by anonymous read by users read',
               'to * by self write by users read by anonymous none']


def values(dump):
  return [l[len('olcAccess: '):] for l in dump.splitlines() if l.startswith('olcAccess: ')]


def strip_idx(v):
  return re.sub(r'^\{\d+\}', '', v)


def render(rules, head=HEAD):
  return head + ''.join('olcAccess: {%d}%s\n' % (i, strip_idx(r)) for i, r in enumerate(rules))


def synthetic(write=WRITE, repl=True, image=True, wdata=True, wlock=True):
  # The good state built from the tool's embedded templates (cross-checked against the real dump below).
  out = []
  if repl:
    out.append('to * by dn.exact="%s" ssf=128 read by dn.exact="%s" none by * break' % (REPL, REPL))
  out += [r.text for r in lib.expected_rules(lib.M_RULES, {'@MACHINE_DN@': MDN, '@ALLOWED_DN@': BASE})]
  sub = {'@SYSTEM_DN@': SYS, '@REPL_DN@': REPL, '@WRITE_DN@': write}
  if wdata:
    out += [r.text for r in lib.expected_rules(lib.DATA_RULES, dict(sub, **{'@WHO@': WD}))]
  if wlock:
    out += [r.text for r in lib.expected_rules(lib.LOCK_RULES, dict(sub, **{'@WHO@': WL}))]
  return out + (IMAGE_RULES if image else [])


class Run:
  def __init__(self, rc, out, err):
    self.rc, self.out, self.err = rc, out, err

  def passed(self):
    return 'status=pass' in self.out


def tool(extra, env=None, stdin=None):
  e = dict(os.environ)
  e.update(env or {})
  p = subprocess.run([str(TOOL)] + extra, capture_output=True, text=True, env=e, input=stdin)
  return Run(p.returncode, p.stdout, p.stderr)


def check_dump(text, extra=None, args=None):
  with tempfile.TemporaryDirectory() as d:
    f = Path(d) / 'dump.ldif'
    f.write_text(text)
    return tool((args or ARGS) + ['--input', str(f)] + (extra or []))


class CheckTests(unittest.TestCase):
  def assertFails(self, r, rc=1, needle=None):
    self.assertEqual(r.rc, rc, r.out + r.err)
    self.assertFalse(r.passed(), 'FALSE PASS: ' + r.out)
    if needle:
      self.assertIn(needle, r.out + r.err)

  def test_real_dump_passes(self):
    r = check_dump((DUMPS / 'good-prepare.ldif').read_text())
    self.assertEqual(r.rc, 0, r.err)
    self.assertRegex(r.out, r'RESULT status=pass checks=\d+ failed=0 rules=21')

  def test_embedded_templates_equal_the_real_dump(self):
    real = values((DUMPS / 'good-prepare.ldif').read_text())
    self.assertEqual([lib.Rule(i, ' '.join(strip_idx(v).split())).sig() for i, v in enumerate(real)],
                     [lib.Rule(i, r).sig() for i, r in enumerate(synthetic())])

  def test_embedded_templates_equal_the_fixtures(self):
    # The tool carries its own copy of the rules; the fixtures (= guide) must say the same.
    for name, tpl in (('main-database.ldif', lib.M_RULES), ('write-data.ldif', lib.DATA_RULES), ('write-lock.ldif', lib.LOCK_RULES)):
      text = '\n'.join(l for l in (FIX / name).read_text().splitlines() if not l.startswith('#'))
      body = text[text.index('olcAccess: {0}'):]
      norm = lambda s: re.sub(r'@(WDATA|WLOCK)_DN@', '@WHO@', ' '.join(s.split()))
      self.assertEqual(norm(body), norm(tpl), name)

  def test_static_unreadable_dumps_fail(self):
    for name in ('empty.ldif', 'no-main-database.ldif'):
      with self.subTest(name):
        self.assertFails(check_dump((DUMPS / name).read_text()), 3)

  def test_static_fault_dumps_fail(self):
    for name, needle in (('wrong-order-swap.ldif', 'W_data rule'), ('missing-secrets-rule.ldif', 'incomplete'),
                         ('duplicate-fragment.ldif', 'duplicate'), ('w-after-image-rules.ldif', 'W_data')):
      with self.subTest(name):
        self.assertFails(check_dump((DUMPS / name).read_text()), 1, needle)

  def test_no_replication_identity(self):
    dump = render(synthetic(repl=False))
    self.assertEqual(check_dump(dump, args=[a for a in ARGS if a not in ('--replication-identity', 'required')]).rc, 0)
    self.assertFails(check_dump(dump), 1, 'missing')  # required (prepare/dedicated) but absent

  def test_order_violations(self):
    good = synthetic()
    swap = lambda i, j: [good[j] if k == i else good[i] if k == j else r for k, r in enumerate(good)]
    cases = {
      'replication rule not first (swapped with M)': swap(0, 1),
      'replication rule moved behind the M rules': good[1:4] + good[:1] + good[4:],
      'W_data before M': good[:1] + good[4:12] + good[1:4] + good[12:],
      'two rules of W_data swapped': swap(7, 8),
      'secrets rule swapped with the SYSTEM backstop': swap(4, 6),
      'W_lock inside W_data': good[:12] + good[18:19] + good[12:18] + good[19:],
      'W block behind the image rules': good[:4] + good[-3:] + good[4:-3],
      'W_lock behind the image rules': good[:12] + good[-3:] + good[12:-3],
    }
    for label, rules in cases.items():
      with self.subTest(label):
        self.assertFails(check_dump(render(rules)))

  def test_either_fragment_order_is_accepted(self):
    good = synthetic()
    lock_first = good[:4] + good[12:18] + good[4:12] + good[18:]
    self.assertEqual(check_dump(render(lock_first)).rc, 0)  # guide: the order of the two fragments is irrelevant

  def test_missing_or_altered_rules(self):
    good = synthetic()
    cases = {
      'secrets rule removed': good[:6] + good[7:],
      'SYSTEM backstop removed': good[:4] + good[5:],
      'replicator deny backstop removed': good[:5] + good[6:],
      'last "to * none" rule removed': good[:11] + good[12:],
      'W_lock fragment partly missing': good[:15] + good[16:],
      'no M rules': good[:1] + good[4:],
      'no image rules': good[:-3],
      'by * break dropped from a W_data rule': [r.replace(' by * break', '') if i == 7 else r for i, r in enumerate(good)],
      'extra grantee clause in a W_data rule': [r + ' by users read' if i == 9 else r for i, r in enumerate(good)],
      'description dropped from the closed list (the pre-v2b fragment)': [r.replace('description,', '') if i == 9 else r for i, r in enumerate(good)],
      'attribute added to the closed list': [r.replace(',member', ',member,telephoneNumber') if i == 9 else r for i, r in enumerate(good)],
      'W_data may write userPassword': [r.replace('none by * break', 'write by * break') if i == 6 else r for i, r in enumerate(good)],
      'secret attribute dropped from the list': [r.replace('memberOf,', '') if i == 6 else r for i, r in enumerate(good)],
      'M may write': [r.replace('read by', 'write by') if i == 2 else r for i, r in enumerate(good)],
    }
    for label, rules in cases.items():
      with self.subTest(label):
        self.assertFails(check_dump(render(rules)))

  def test_attribute_order_and_case_are_not_a_difference(self):
    good = synthetic()
    good[6] = good[6].replace('attrs=userPassword,shadowLastChange', 'ATTRS=shadowLastChange,USERPASSWORD')
    self.assertEqual(check_dump(render(good)).rc, 0)

  def test_duplicates(self):
    good = synthetic()
    cases = {'W_data twice (as the guide BASE would place it)': good[:12] + good[4:12] + good[12:],
             'W_lock twice': good[:18] + good[12:18] + good[18:],
             'M twice': good[:4] + good[1:4] + good[4:],
             'replication rule twice': good[:1] + good[:1] + good[1:]}
    for label, rules in cases.items():
      with self.subTest(label):
        self.assertFails(check_dump(render(rules)))

  def test_wcred_has_no_rule(self):
    cred = 'uid=machine-write-cred,' + SYS
    good = synthetic()
    self.assertEqual(check_dump(render(good), ['--wcred-dn', cred]).rc, 0)
    bad = good[:4] + ['to attrs=userPassword by dn.exact="%s" write by * break' % cred] + good[4:]
    self.assertFails(check_dump(render(bad), ['--wcred-dn', cred]), 1, 'W_cred')
    # Even when the operator did not name it: an unknown identity under SYSTEM_DN with write access.
    self.assertFails(check_dump(render(bad)), 1, 'unknown identity')

  def test_reach_to_protected_entries(self):
    # WRITE_DN = the root puts the admin entry inside it: nothing before the W rules denies it.
    root_args = [BASE if a == WRITE else a for a in ARGS]
    r = check_dump(render(synthetic(write=BASE)), args=root_args)
    self.assertFails(r, 1, 'admin')
    # ... but the SYSTEM_DN / replicator backstops still hold for M, W_*, and the replication identity.
    self.assertNotIn('can reach M entry', r.err)
    self.assertNotIn('can reach replication identity', r.err)
    # The operator moved the admin account elsewhere and says so: that is the documented fix.
    moved = ['--admin-dn', 'cn=admin,ou=system,' + BASE]
    self.assertEqual(check_dump(render(synthetic(write=BASE)), moved, root_args).rc, 0)
    # Without the backstops the same layout is open to M and the replication entry.
    bad = synthetic(write=BASE)
    bad = [r for i, r in enumerate(bad) if i not in (4, 5)]
    self.assertFails(check_dump(render(bad), moved, root_args))

  def test_opaque_rule_before_w_is_a_failure_not_a_pass(self):
    good = synthetic()
    bad = good[:4] + ['to dn.regex=".*" by * write'] + good[4:]
    self.assertFails(check_dump(render(bad)))

  def test_unreadable_input_is_never_a_pass(self):
    good = render(synthetic())
    cases = {
      'empty input': '',
      'only whitespace': '\n\n',
      'no main database entry': 'dn: olcDatabase={2}monitor,cn=config\nolcAccess: {0}to * by * read\n',
      'main database without olcAccess': HEAD + 'olcSuffix: dc=example,dc=org\n',
      'value without {n}': HEAD + 'olcAccess: to * by * read\n',
      'indices not sequential': HEAD + 'olcAccess: {1}to * by * read\n',
      'truncated dump (first value missing)': HEAD + ''.join(l + '\n' for l in good.splitlines()[2:]),
    }
    for label, text in cases.items():
      with self.subTest(label):
        self.assertFails(check_dump(text), 3)
    with tempfile.TemporaryDirectory() as d:
      self.assertFails(tool(ARGS + ['--input', str(Path(d) / 'missing.ldif')]), 3, 'cannot read')

  def test_unparseable_rule_fails(self):
    good = synthetic()
    bad = good[:6] + ['to * by'] + good[7:]
    self.assertFails(check_dump(render(bad)))

  def test_ldif_wrapping_and_base64(self):
    import base64
    text = render(synthetic())
    wrapped = re.sub(r'(olcAccess: \{\d+\}to attrs=userPassword,shadowLastChange,pwdHistory)(.*)', r'\1\n \2', text)
    self.assertEqual(check_dump(wrapped).rc, 0)
    b64 = HEAD + ''.join('olcAccess:: %s\n' % base64.b64encode(('{%d}%s' % (i, strip_idx(r))).encode()).decode() for i, r in enumerate(synthetic()))
    self.assertEqual(check_dump(b64).rc, 0)

  def test_other_databases_are_ignored(self):
    decoy = 'dn: olcDatabase={2}monitor,cn=config\nolcAccess: {0}to * by * read\n\n'
    self.assertEqual(check_dump(decoy + render(synthetic())).rc, 0)
    self.assertEqual(check_dump(render(synthetic()) + '\n' + decoy).rc, 0)

  def test_usage_errors(self):
    no_w = [a for a in ARGS if a not in ('--wdata-dn', WD, '--wlock-dn', WL)]
    self.assertFails(tool(no_w + ['--input', '/dev/null']), 2)
    same = ARGS + ['--wcred-dn', WD]
    self.assertFails(tool(same + ['--input', '/dev/null']), 2)
    self.assertFails(tool([]), 2)

  def test_stdin(self):
    self.assertEqual(tool(ARGS + ['--input', '-'], stdin=render(synthetic())).rc, 0)
    self.assertFails(tool(ARGS + ['--input', '-'], stdin=''), 3)


class StubSourceTests(unittest.TestCase):
  # --container / --kube-pod / local slapcat are exercised with stub commands first on PATH.
  def stub(self, d, name, body):
    p = Path(d) / name
    p.write_text('#!/bin/sh\n' + body)
    p.chmod(p.stat().st_mode | stat.S_IXUSR)

  def run_with(self, name, body, extra):
    with tempfile.TemporaryDirectory() as d:
      self.stub(d, name, body)
      log = Path(d) / 'args'
      # printf, not echo: a first argument of -n would be eaten as an echo option by a POSIX sh (CI)
      self.stub(d, name, 'printf "%%s " "$@" > %s\n%s' % (log, body))
      r = tool(ARGS + extra, env={'PATH': d + os.pathsep + os.environ['PATH']})
      return r, (log.read_text() if log.exists() else '')

  def test_container_mode_runs_slapcat_in_the_container(self):
    r, args = self.run_with('docker', 'cat "%s"' % (DUMPS / 'good-prepare.ldif'), ['--container', 'c1'])
    self.assertEqual(r.rc, 0, r.err)
    self.assertEqual(args.strip(), 'exec c1 slapcat -n 0 -F /etc/openldap/slapd.d -o ldif-wrap=no')

  def test_kube_mode_arguments(self):
    r, args = self.run_with('kubectl', 'cat "%s"' % (DUMPS / 'good-prepare.ldif'),
                            ['--kube-pod', 'ldapium-0', '-n', 'ldap', '--kube-container', 'openldap'])
    self.assertEqual(r.rc, 0, r.err)
    self.assertEqual(args.strip(), '-n ldap exec ldapium-0 -c openldap -- slapcat -n 0 -F /etc/openldap/slapd.d -o ldif-wrap=no')

  def test_local_slapcat(self):
    r, args = self.run_with('slapcat', 'cat "%s"' % (DUMPS / 'good-prepare.ldif'), ['--config-dir', '/x/slapd.d'])
    self.assertEqual(r.rc, 0, r.err)
    self.assertEqual(args.strip(), '-n 0 -F /x/slapd.d -o ldif-wrap=no')

  def test_failing_or_empty_slapcat_is_never_a_pass(self):
    for label, body in (('rc 1, no output', 'exit 1'), ('rc 0, empty output', 'exit 0'),
                        ('rc 1 but complete output', 'cat "%s"; exit 1' % (DUMPS / 'good-prepare.ldif'))):
      with self.subTest(label):
        r, _ = self.run_with('docker', body, ['--container', 'c1'])
        self.assertEqual(r.rc, 3, r.out + r.err)
        self.assertFalse(r.passed())

  def test_missing_tool_is_never_a_pass(self):
    with tempfile.TemporaryDirectory() as d:
      p = subprocess.run([sys.executable, str(ROOT / 'scripts/lib/machine_write_acl_check.py')] + ARGS + ['--container', 'c1'],
                         capture_output=True, text=True, env={'PATH': d})
      self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
      self.assertNotIn('status=pass', p.stdout)


if __name__ == '__main__':
  unittest.main()
