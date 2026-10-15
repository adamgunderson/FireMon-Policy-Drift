#!/usr/bin/env python3
"""Run the unit test suite.

    python3 run_tests.py

Use this rather than calling unittest directly: `python3 -m unittest` runs
under whatever `python3` is, and on FMOS that is 3.6 -- too old to import the
package. This wrapper re-executes itself under a suitable interpreter first,
exactly as run_drift.py does.

No network access; the suite runs against synthetic rules built in
tests/support.py.
"""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from firemon_drift._bootstrap import ensure_interpreter  # noqa: E402

ensure_interpreter(__file__)

import unittest  # noqa: E402


def main():
    tests_dir = os.path.join(ROOT, "tests")
    if not os.path.isdir(tests_dir):
        sys.stderr.write("tests directory not found at %s\n" % tests_dir)
        return 1
    sys.path.insert(0, tests_dir)
    suite = unittest.defaultTestLoader.discover(tests_dir, pattern="test_*.py")
    verbosity = 2 if "-v" in sys.argv[1:] else 1
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
