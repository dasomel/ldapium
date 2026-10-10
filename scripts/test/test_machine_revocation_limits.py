import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
import machine_revocation as mr  # noqa: E402


def run_main(*argv):
  with mock.patch.object(sys, 'argv', ['machine_revocation.py', *argv]):
    mr.main()


class MaxEntriesCap(unittest.TestCase):
  def test_above_replica_maximum_refused(self):
    with self.assertRaisesRegex(mr.Error, 'exceeds the replica maximum 2500'):
      run_main('retention', '--max-entries', '2501')

  def test_replica_maximum_and_default_accepted(self):
    run_main('retention', '--max-entries', '2500')
    run_main('retention')

  def test_zero_refused(self):
    with self.assertRaises(mr.Error):
      run_main('retention', '--max-entries', '0')


class ClientIdSet(unittest.TestCase):
  def test_accepted(self):
    for c in ('machine-a', 'a.b_c:d-1', 'X'):
      self.assertEqual(mr.check_client(c), c)

  def test_refused_with_clear_message(self):
    for c in ('a b', 'a,b', 'a+b', 'a\\b', 'a"b', 'a#b', 'a<b>', 'a=b', 'a;b', "a'b",
              'a\nb', 'a\x00b', 'é', ''):
      with self.assertRaisesRegex(mr.Error, r'client id must match'):
        mr.check_client(c)


if __name__ == '__main__':
  unittest.main()
