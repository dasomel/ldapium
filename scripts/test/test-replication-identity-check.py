#!/usr/bin/env python3
import importlib.util
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


if __name__ == '__main__':
  unittest.main()
