#!/usr/bin/env python3
"""Unit tests for scripts/bench-generate-lifecycle-ops.py.

Pure fixture-based tests, no Docker/network needed — the generator is
explicitly designed to be side-effect-free (see its own module docstring),
so this follows the project's "unit-test pure helper functions" testing
philosophy (AGENTS.md) rather than the live-container pattern used for
LDAP-wire-touching code.

The script's filename has a hyphen, so it can't be imported by name; it is
loaded by file path for direct access to `largest_remainder`, and invoked
as a subprocess (matching how scripts/test/*.sh already exercise the other
scripts/lib/*.py helpers) to cover full-CLI behavior: exit codes, stdout
shape, and stderr messages.

Run: python3 -m unittest discover -s scripts/test -p 'test_*.py'
"""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "bench-generate-lifecycle-ops.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("bench_generate_lifecycle_ops", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULE = _load_module()


def run(args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
    )


def parse_output(stdout):
    lines = stdout.splitlines()
    header = lines[0].split("\t")
    assert header[0] == "#counts"
    joiner_count, mover_count, leaver_count = (int(x) for x in header[1:])
    ops = [tuple(line.split("\t")) for line in lines[1:]]
    return joiner_count, mover_count, leaver_count, ops


class LargestRemainderTests(unittest.TestCase):
    def test_sums_to_total(self):
        for total, weights in [(2000, [50, 30, 20]), (10, [1, 1, 1]), (7, [1, 0, 0]), (0, [1, 1, 1])]:
            with self.subTest(total=total, weights=weights):
                self.assertEqual(sum(MODULE.largest_remainder(total, weights)), total)

    def test_exact_split_needs_no_rounding(self):
        self.assertEqual(MODULE.largest_remainder(2000, [50, 30, 20]), [1000, 600, 400])

    def test_remainder_goes_to_earliest_tied_weight(self):
        # 10 * 1/3 = 3.33.. for each of 3 equal weights -> remainder 1, and
        # equal fractional remainders resolve by original order (stable),
        # per the function's own docstring.
        self.assertEqual(MODULE.largest_remainder(10, [1, 1, 1]), [4, 3, 3])

    def test_zero_weight_sum_raises(self):
        with self.assertRaises(ValueError):
            MODULE.largest_remainder(10, [0, 0, 0])


class DeterminismTests(unittest.TestCase):
    def test_same_inputs_produce_identical_output(self):
        args = ["--identities", "1000", "--ops", "200", "--mix", "50:30:20"]
        first = run(args)
        second = run(args)
        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 0)
        self.assertEqual(first.stdout, second.stdout)


class MixRatioTests(unittest.TestCase):
    def test_counts_sum_to_ops_and_match_largest_remainder(self):
        result = run(["--identities", "500", "--ops", "77", "--mix", "50:30:20"])
        self.assertEqual(result.returncode, 0)
        joiner_count, mover_count, leaver_count, ops = parse_output(result.stdout)
        self.assertEqual(joiner_count + mover_count + leaver_count, 77)
        self.assertEqual(
            [joiner_count, mover_count, leaver_count],
            MODULE.largest_remainder(77, [50, 30, 20]),
        )
        self.assertEqual(len(ops), 77)


class DisjointRangeTests(unittest.TestCase):
    def test_mover_and_leaver_ranges_disjoint_and_within_identities(self):
        identities = 1000
        result = run(["--identities", str(identities), "--ops", "300", "--mix", "50:30:20"])
        self.assertEqual(result.returncode, 0)
        joiner_count, mover_count, leaver_count, ops = parse_output(result.stdout)

        leaver_indices = [int(arg) for kind, arg in ops if kind == "leaver"]
        mover_indices = [int(arg) for kind, arg in ops if kind == "mover"]
        joiner_indices = [int(arg) for kind, arg in ops if kind == "joiner"]

        self.assertEqual(len(leaver_indices), leaver_count)
        self.assertEqual(len(mover_indices), mover_count)
        self.assertEqual(len(joiner_indices), joiner_count)

        self.assertEqual(set(leaver_indices), set(range(0, leaver_count)))
        self.assertEqual(set(mover_indices), set(range(leaver_count, leaver_count + mover_count)))
        self.assertTrue(set(leaver_indices).isdisjoint(mover_indices))
        self.assertLess(max(leaver_indices + mover_indices), identities)


class ValidationTests(unittest.TestCase):
    def test_insufficient_identities_rejected(self):
        result = run(["--identities", "10", "--ops", "100", "--mix", "0:50:50"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("increase --identities", result.stderr)

    def test_malformed_mix_wrong_part_count_rejected(self):
        result = run(["--identities", "100", "--ops", "10", "--mix", "50:50"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("--mix must be J:M:L", result.stderr)

    def test_malformed_mix_non_numeric_rejected(self):
        result = run(["--identities", "100", "--ops", "10", "--mix", "a:b:c"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("--mix must be J:M:L", result.stderr)

    def test_malformed_mix_all_zero_rejected(self):
        result = run(["--identities", "100", "--ops", "10", "--mix", "0:0:0"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("at least one positive part", result.stderr)

    def test_ops_zero_rejected(self):
        result = run(["--identities", "100", "--ops", "0", "--mix", "50:30:20"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("--ops must be at least 1", result.stderr)

    def test_identities_zero_rejected(self):
        result = run(["--identities", "0", "--ops", "10", "--mix", "50:30:20"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("--identities must be at least 1", result.stderr)


if __name__ == "__main__":
    unittest.main()
