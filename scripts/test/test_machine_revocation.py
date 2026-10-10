import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('machine_revocation', Path(__file__).parents[1] / 'lib/machine_revocation.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class WarnThresholdTests(unittest.TestCase):
  def test_default_cap_boundary(self):
    self.assertFalse(tool.above_warn_threshold(1600, 2000))
    self.assertTrue(tool.above_warn_threshold(1601, 2000))

  def test_range_edges(self):
    self.assertFalse(tool.above_warn_threshold(0, 1))
    self.assertTrue(tool.above_warn_threshold(1, 1))
    self.assertFalse(tool.above_warn_threshold(2000, 2500))
    self.assertTrue(tool.above_warn_threshold(2001, 2500))

  def test_small_cap_has_no_rounding_slack(self):
    self.assertFalse(tool.above_warn_threshold(4, 5))
    self.assertTrue(tool.above_warn_threshold(5, 5))


if __name__ == '__main__':
  unittest.main()
