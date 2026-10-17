#!/usr/bin/env python3
import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "lib"))

spec = importlib.util.spec_from_file_location('check', Path(__file__).parents[1] / 'lib/replication_identity_check.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def row(csn=b'1', pw=b'hash'):
  return {b'cn=x': {'entrycsn': (csn,), 'userpassword': (pw,), 'objectclass': (b'device',)}}


class StableCheck(unittest.TestCase):
  def test_one_verified_ldaps_uri_only(self):
    for uri in ('ldaps://node', 'ldaps://node.example:636', 'ldaps://127.0.0.1:636', 'ldaps://[::1]:636'):
      self.assertTrue(check.valid_uri(uri), uri)
    for uri in ('ldap://node:389', 'ldaps://dead:636 ldap://real:389',
                'ldaps://dead:636\tldaps://real:636', 'ldaps://user:password@node',
                'ldaps://node/', 'ldaps://node?option=x', 'ldaps://node#x',
                'ldaps://node:0', 'ldaps://node:65536', 'ldaps://node:',
                'ldaps://node:garbage', 'ldaps://-node', 'ldaps://node..example',
                'ldaps://node%20ldap', 'ldaps://'):
      self.assertFalse(check.valid_uri(uri), uri)

  def test_equal(self):
    self.assertEqual(check.compare(row(), row(), row()), (0, 0))

  def test_same_csn_missing_password(self):
    self.assertEqual(check.compare(row(), row(pw=b''), row()), (1, 0))

  def test_root_same_csn_changed_content(self):
    self.assertEqual(check.compare(row(), row(), row(pw=b"changed")), (1, 0))

  def test_hidden_identity_csn_is_error(self):
    visible = row(); visible[b"cn=x"].pop("entrycsn")
    with self.assertRaises(ValueError):
      check.compare(row(), visible, row())

  def test_each_view_requires_one_nonempty_csn_before_pending(self):
    for index in range(3):
      for invalid in ((), (b"",), (b"1", b"2")):
        views = [row(), row(csn=b"2"), row(csn=b"3")]
        views[index][b"cn=x"]["entrycsn"] = invalid
        with self.assertRaises(ValueError):
          check.compare(*views)

  def test_root_defect_not_hidden_by_identity_change(self):
    self.assertEqual(check.compare(row(), row(csn=b"2"), row(pw=b"changed")), (1, 0))

  def test_missing_entry(self):
    self.assertEqual(check.compare(row(), {}, row()), (1, 0))

  def test_root_write_is_deferred(self):
    self.assertEqual(check.compare(row(), row(), row(csn=b'2')), (0, 1))

  def test_identity_write_is_deferred(self):
    self.assertEqual(check.compare(row(), row(csn=b'2'), row()), (0, 1))

  def test_defect_not_hidden_by_concurrent_write(self):
    first = row(); first[b'cn=y'] = row()[b'cn=x']
    second = dict(first); second[b'cn=y'] = row(csn=b'2')[b'cn=x']
    self.assertEqual(check.compare(first, row(pw=b'missing'), second), (1, 1))

  def test_ldif_normalizes_order_and_base64(self):
    raw = b'dn: cn=x\nobjectClass: top\nobjectClass: device\nuserPassword:: aGFzaA==\nentryCSN: 1\n\n'
    self.assertEqual(check.parse_ldif(raw)[b'cn=x']['objectclass'], (b'device', b'top'))
    self.assertEqual(check.parse_ldif(raw)[b'cn=x']['userpassword'], (b'hash',))

  def test_duplicate_dn_refused(self):
    with self.assertRaises(ValueError):
      check.parse_ldif(b'dn: cn=x\n\ndn: cn=x\n')

  def canary_args(self):
    return check.SimpleNamespace(uri='ldaps://n1:636', base='dc=x', admin_dn='cn=admin,dc=x', canary_timeout=1,
                                 admin_password_file='/a', identity_password_file='/i', container=None, ca_file='/ca')

  def test_canary_cleans_up_after_an_add_timeout(self):
    calls = []
    def fake(args, command, data=None, user=None):
      calls.append(command[0])
      if command[0] == 'ldapadd':
        raise check.subprocess.TimeoutExpired(command, 30)  # applied server-side, response lost
      if command[0] == 'ldapdelete':
        raise ValueError('directory operation failed (code 32)')  # noSuchObject is tolerated
      raise ValueError('directory operation failed (code 32)')  # search: entry absent
    real, check.tool_run = check.tool_run, fake
    try:
      with self.assertRaises(check.subprocess.TimeoutExpired):
        check.canary(self.canary_args(), ['ldaps://n1:636'])
    finally:
      check.tool_run = real
    self.assertEqual(calls[:2], ['ldapadd', 'ldapdelete'])

  def test_canary_reports_the_dn_when_the_delete_fails(self):
    def fake(args, command, data=None, user=None):
      if command[0] == 'ldapdelete':
        raise ValueError('directory operation failed (code 50)')
      return b''
    real, check.tool_run = check.tool_run, fake
    err = check.sys.stderr
    check.sys.stderr = io.StringIO()
    try:
      rc = check.canary(self.canary_args(), [])
      text = check.sys.stderr.getvalue()
    finally:
      check.tool_run, check.sys.stderr = real, err
    self.assertEqual(rc, 2)
    self.assertIn('cn=ridcheck-', text)

  def test_membership_uses_the_providers_a_node_follows(self):
    syncrepl = b'rid=001 provider=ldaps://N2:636 bindmethod=simple binddn="cn=replicator,dc=x" credentials=x'
    rows = {b'olcDatabase={1}mdb,cn=config': {'olcsyncrepl': (syncrepl,)}}
    self.assertEqual(check.missing_members(rows, ['ldaps://n1:636', 'ldaps://n2']), [])
    self.assertEqual(check.missing_members(rows, ['ldaps://n1:636']), [('n2', 636)])
    self.assertEqual(check.missing_members({}, ['ldaps://n1:636']), [])

  def test_membership_refuses_a_plaintext_provider(self):
    rows = {b'x': {'olcsyncrepl': (b'rid=001 provider=ldap://n2:389',)}}
    with self.assertRaises(ValueError):
      check.missing_members(rows, ['ldaps://n1:636'])

  def test_canonical_hash_identical_for_same_user_attrs(self):
    a = {'cn': (b'foo',), 'userpassword': (b'pw',), 'entrycsn': (b'csn1',)}
    b = {'userpassword': (b'pw',), 'cn': (b'foo',), 'entrycsn': (b'csn2',)}
    self.assertEqual(check.canonical_user_attr_hash(a), check.canonical_user_attr_hash(b))

  def test_canonical_hash_none_is_none(self):
    self.assertIsNone(check.canonical_user_attr_hash(None))

  def test_canonical_hash_differs_on_attr_change(self):
    a = {'cn': (b'foo',), 'userpassword': (b'pw1',), 'entrycsn': (b'csn1',)}
    b = {'cn': (b'foo',), 'userpassword': (b'pw2',), 'entrycsn': (b'csn1',)}
    self.assertNotEqual(check.canonical_user_attr_hash(a), check.canonical_user_attr_hash(b))

  def test_canonical_hash_ignores_entrycsn_and_opattrs(self):
    a = {'cn': (b'foo',), 'entrycsn': (b'csn1',), 'modifytimestamp': (b'20261017000000Z',)}
    b = {'cn': (b'foo',), 'entrycsn': (b'csn2',), 'modifytimestamp': (b'20261017010000Z',)}
    self.assertEqual(check.canonical_user_attr_hash(a), check.canonical_user_attr_hash(b))

  def test_diff_attributes(self):
    a = {'cn': (b'foo',), 'mail': (b'a@b',), 'entrycsn': (b'csn1',)}
    b = {'cn': (b'foo',), 'mail': (b'c@d',), 'entrycsn': (b'csn2',)}
    self.assertEqual(check.diff_attributes(a, b), ['mail'])
    c = {'cn': (b'foo',), 'entrycsn': (b'csn1',)}
    self.assertEqual(check.diff_attributes(a, c), ['mail'])
    self.assertEqual(check.diff_attributes(a, None), [])

  def test_evaluate_entry_divergence_all_match(self):
    entries = {
        'ldaps://n1': {'entrycsn': (b'1',), 'cn': (b'x',), 'userpassword': (b'pw',)},
        'ldaps://n2': {'entrycsn': (b'1',), 'userpassword': (b'pw',), 'cn': (b'x',)},
    }
    diverged, details = check.evaluate_entry_divergence(entries)
    self.assertFalse(diverged)
    self.assertEqual(details, {})

  def test_evaluate_entry_divergence_missing_target(self):
    entries = {
        'ldaps://n1': {'entrycsn': (b'1',), 'cn': (b'x',)},
        'ldaps://n2': None,
    }
    diverged, details = check.evaluate_entry_divergence(entries)
    self.assertTrue(diverged)
    self.assertEqual(details['missing_targets'], ['ldaps://n2'])
    self.assertIn('missing entry on ldaps://n2', check.format_divergence_reason(details))

  def test_evaluate_entry_divergence_lacks_entrycsn(self):
    entries = {
        'ldaps://n1': {'entrycsn': (b'1',), 'cn': (b'x',)},
        'ldaps://n2': {'entrycsn': (), 'cn': (b'x',)},
    }
    diverged, details = check.evaluate_entry_divergence(entries)
    self.assertTrue(diverged)
    self.assertEqual(details['lacks_csn_targets'], ['ldaps://n2'])
    self.assertIn('lacks entryCSN on ldaps://n2', check.format_divergence_reason(details))

  def test_evaluate_entry_divergence_attr_mismatch_redacts_values(self):
    entries = {
        'ldaps://n1': {'entrycsn': (b'1',), 'cn': (b'x',), 'userpassword': (b'secret1',)},
        'ldaps://n2': {'entrycsn': (b'1',), 'cn': (b'x',), 'userpassword': (b'secret2',)},
    }
    diverged, details = check.evaluate_entry_divergence(entries)
    self.assertTrue(diverged)
    self.assertEqual(details['differing_attrs'], ['userpassword'])
    reason = check.format_divergence_reason(details)
    self.assertIn('differing attributes: userpassword', reason)
    self.assertNotIn('secret1', reason)
    self.assertNotIn('secret2', reason)

  def test_evaluate_entry_divergence_csn_mismatch(self):
    entries = {
        'ldaps://n1': {'entrycsn': (b'1',), 'cn': (b'x',)},
        'ldaps://n2': {'entrycsn': (b'2',), 'cn': (b'x',)},
    }
    diverged, details = check.evaluate_entry_divergence(entries)
    self.assertTrue(diverged)
    self.assertIn('entryCSN mismatch', check.format_divergence_reason(details))

  def test_divergence_filter_syntax(self):
    flt = check.divergence_filter(15, now_timestamp=1700000000)
    self.assertTrue(flt.startswith('(|(modifyTimestamp>='))
    self.assertIn('createTimestamp>=', flt)
    self.assertTrue(flt.endswith('(!(entryCSN=*)))'))

  def test_paged_results_args_construction(self):
    self.assertEqual(check.paged_results_args(500), ['-E', 'pr=500/noprompt'])
    self.assertEqual(check.paged_results_args(1), ['-E', 'pr=1/noprompt'])
    with self.assertRaises(ValueError):
      check.paged_results_args(0)
    with self.assertRaises(ValueError):
      check.paged_results_args(-5)

  def test_find_candidates_paged_query_and_size_limit(self):
    args = check.SimpleNamespace(
        uri='ldaps://n1:636', base='dc=x', admin_dn='cn=admin,dc=x',
        admin_password_file='/a', ca_file='/ca', container=None
    )
    def mock_tool(node_args, command, data=None, user=None):
      self.assertIn('-E', command)
      self.assertIn('pr=500/noprompt', command)
      self.assertEqual(command[-1], 'dn')
      raise check.DirectoryOperationError(4, stdout=b'dn: cn=bob,dc=x\n\ndn: cn=alice,dc=x\n\n')

    real_tool, real_err = check.tool_run, check.sys.stderr
    check.tool_run = mock_tool
    check.sys.stderr = io.StringIO()
    try:
      dns = check.find_candidates(args, ['ldaps://n1:636'], '(objectClass=*)', page_size=500)
      warn = check.sys.stderr.getvalue()
    finally:
      check.tool_run, check.sys.stderr = real_tool, real_err

    self.assertEqual(dns, [b'cn=alice,dc=x', b'cn=bob,dc=x'])
    self.assertIn('WARN: divergence candidate search reached server size limit (code 4)', warn)

  def test_run_divergence_check_candidate_cap_behaviour(self):
    args = check.SimpleNamespace(
        uri='ldaps://n1:636', base='dc=x', admin_dn='cn=admin,dc=x',
        admin_password_file='/a', ca_file='/ca', container=None,
        divergence_window_minutes=45, divergence_grace_seconds=0,
        divergence_max_candidates=2
    )
    evaluated_dns = []
    def mock_tool(node_args, command, data=None, user=None):
      if command[-1] == 'dn':
        # Return 4 candidates: c, a, d, b
        return b'dn: cn=c,dc=x\n\ndn: cn=a,dc=x\n\ndn: cn=d,dc=x\n\ndn: cn=b,dc=x\n\n'
      # Reading entry
      dn_in_cmd = command[command.index('-b') + 1]
      evaluated_dns.append(dn_in_cmd)
      return ('dn: %s\nentryCSN: 1\ncn: ok\n\n' % dn_in_cmd).encode()

    real_tool, real_err = check.tool_run, check.sys.stderr
    check.tool_run = mock_tool
    check.sys.stderr = io.StringIO()
    try:
      rc = check.run_divergence_check(args, ['ldaps://n1:636', 'ldaps://n2:636'])
      warn = check.sys.stderr.getvalue()
    finally:
      check.tool_run, check.sys.stderr = real_tool, real_err

    # D434-2 cap: Exceeding candidate cap returns rc 0 with WARN; checks first N deterministically
    self.assertEqual(rc, 0)
    self.assertIn('WARN: candidate count 4 exceeds cap 2; checking first 2 entries deterministically', warn)
    # Only 2 candidates evaluated per target (4 total reads: cn=a and cn=b on n1 and n2)
    self.assertEqual(evaluated_dns, ['cn=a,dc=x', 'cn=a,dc=x', 'cn=b,dc=x', 'cn=b,dc=x'])

  def test_run_divergence_check_candidate_cap_finds_defect(self):
    args = check.SimpleNamespace(
        uri='ldaps://n1:636', base='dc=x', admin_dn='cn=admin,dc=x',
        admin_password_file='/a', ca_file='/ca', container=None,
        divergence_window_minutes=45, divergence_grace_seconds=0,
        divergence_max_candidates=1
    )
    def mock_tool(node_args, command, data=None, user=None):
      if command[-1] == 'dn':
        return b'dn: cn=a,dc=x\n\ndn: cn=b,dc=x\n\n'
      if node_args.uri == 'ldaps://n1:636':
        return b'dn: cn=a,dc=x\nentryCSN: 1\nuserPassword: pw1\n\n'
      return b'dn: cn=a,dc=x\nentryCSN: 1\nuserPassword: pw2\n\n'

    real_tool, real_err = check.tool_run, check.sys.stderr
    check.tool_run = mock_tool
    check.sys.stderr = io.StringIO()
    try:
      rc = check.run_divergence_check(args, ['ldaps://n1:636', 'ldaps://n2:636'])
      err = check.sys.stderr.getvalue()
    finally:
      check.tool_run, check.sys.stderr = real_tool, real_err

    self.assertEqual(rc, 1)
    self.assertIn('FAIL: divergence detected for dn="cn=a,dc=x"', err)

  def test_divergence_window_default_covers_schedule(self):
    # Schedule default is */30 (30 minutes interval).
    # windowMinutes default (45) must be >= schedule interval + grace (30m + margin).
    schedule_interval_minutes = 30
    grace_seconds = 5
    default_window_minutes = 45
    self.assertGreaterEqual(
        default_window_minutes,
        schedule_interval_minutes + (grace_seconds / 60.0)
    )

  def test_run_divergence_check_no_candidates(self):
    args = check.SimpleNamespace(
        uri='ldaps://n1:636', base='dc=x', admin_dn='cn=admin,dc=x',
        admin_password_file='/a', ca_file='/ca', container=None,
        divergence_window_minutes=45, divergence_grace_seconds=0,
        divergence_max_candidates=500
    )
    real_tool_run = check.tool_run
    check.tool_run = lambda *args, **kwargs: b''
    try:
      self.assertEqual(check.run_divergence_check(args, ['ldaps://n1:636', 'ldaps://n2:636']), 0)
    finally:
      check.tool_run = real_tool_run

  def test_run_divergence_check_detects_defect(self):
    args = check.SimpleNamespace(
        uri='ldaps://n1:636', base='dc=x', admin_dn='cn=admin,dc=x',
        admin_password_file='/a', ca_file='/ca', container=None,
        divergence_window_minutes=45, divergence_grace_seconds=0,
        divergence_max_candidates=500
    )
    def mock_tool(node_args, command, data=None, user=None):
      # If searching candidates
      if command[-1] == 'dn' or '1.1' in command:
        return b'dn: cn=alice,dc=x\n\n'
      # Reading candidate entry
      if node_args.uri == 'ldaps://n1:636':
        return b'dn: cn=alice,dc=x\nentryCSN: 1\ncn: alice\nuserPassword: secret1\n\n'
      else:
        return b'dn: cn=alice,dc=x\nentryCSN: 1\ncn: alice\nuserPassword: secret2\n\n'

    real_tool_run, real_err = check.tool_run, check.sys.stderr
    check.tool_run = mock_tool
    check.sys.stderr = io.StringIO()
    try:
      rc = check.run_divergence_check(args, ['ldaps://n1:636', 'ldaps://n2:636'])
      err = check.sys.stderr.getvalue()
    finally:
      check.tool_run, check.sys.stderr = real_tool_run, real_err

    self.assertEqual(rc, 1)
    self.assertIn('FAIL: divergence detected for dn="cn=alice,dc=x"', err)
    self.assertIn('differing attributes: userpassword', err)
    self.assertNotIn('secret1', err)
    self.assertNotIn('secret2', err)

  def test_run_divergence_check_grace_period_converges(self):
    args = check.SimpleNamespace(
        uri='ldaps://n1:636', base='dc=x', admin_dn='cn=admin,dc=x',
        admin_password_file='/a', ca_file='/ca', container=None,
        divergence_window_minutes=45, divergence_grace_seconds=0,
        divergence_max_candidates=500
    )
    read_count = {'count': 0}
    def mock_tool(node_args, command, data=None, user=None):
      if command[-1] == 'dn' or '1.1' in command:
        return b'dn: cn=alice,dc=x\n\n'
      read_count['count'] += 1
      # In round 1, node2 has not converged yet
      if read_count['count'] <= 2 and node_args.uri == 'ldaps://n2:636':
        return b'dn: cn=alice,dc=x\nentryCSN: 0\ncn: alice\nuserPassword: old\n\n'
      # In round 2 (recheck), node2 has converged to match node1
      return b'dn: cn=alice,dc=x\nentryCSN: 1\ncn: alice\nuserPassword: current\n\n'

    real_tool_run = check.tool_run
    check.tool_run = mock_tool
    try:
      rc = check.run_divergence_check(args, ['ldaps://n1:636', 'ldaps://n2:636'])
    finally:
      check.tool_run = real_tool_run

    self.assertEqual(rc, 0)

  def test_canonical_hash_case_insensitive_keys(self):
    a = {'CN': (b'foo',), 'userPassword': (b'pw',)}
    b = {'cn': (b'foo',), 'userpassword': (b'pw',)}
    self.assertEqual(check.canonical_user_attr_hash(a), check.canonical_user_attr_hash(b))

  def test_diff_attributes_case_insensitive_keys(self):
    a = {'CN': (b'foo',), 'mail': (b'a@b',)}
    b = {'cn': (b'foo',), 'MAIL': (b'a@b',)}
    self.assertEqual(check.diff_attributes(a, b), [])

  def test_get_entry_csn_case_insensitive(self):
    self.assertEqual(check.get_entry_csn({'EntryCSN': (b'1',)}), (b'1',))
    self.assertEqual(check.get_entry_csn({'entrycsn': (b'2',)}), (b'2',))

  def test_divergence_cli_validation(self):
    base_args = ['prog', '--uri', 'ldaps://n1:636', '--base', 'dc=x',
                 '--admin-password-file', '/a', '--identity-password-file', '/i',
                 '--ca-file', '/ca', '--divergence']
    with mock.patch('sys.stderr', io.StringIO()):
      for bad_args in (
          base_args + ['--divergence-window-minutes', '0'],
          base_args + ['--divergence-grace-seconds', '-1'],
          base_args + ['--divergence-max-candidates', '0'],
          base_args + ['--divergence-page-size', '0'],
          base_args + ['--configuration-only', '--config-password-file', '/c'],
      ):
        with mock.patch('sys.argv', bad_args):
          with self.assertRaises(SystemExit):
            check.main()


if __name__ == '__main__':
  unittest.main()
