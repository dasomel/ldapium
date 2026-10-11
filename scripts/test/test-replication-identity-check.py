#!/usr/bin/env python3
import importlib.util
import io
from pathlib import Path
import unittest
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


if __name__ == '__main__':
  unittest.main()
