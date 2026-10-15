#!/usr/bin/env python3
"""Entry point for the FireMon policy drift report.

    python3 run_drift.py --config config.ini --dry-run --print

A thin wrapper so the tool runs straight out of its install directory
without being on PYTHONPATH or installed as a package.

On FMOS the default `python3` is 3.6, which predates dataclasses, but newer
interpreters are installed alongside. The bootstrap below re-executes this
script under the newest suitable one, so the command above works whatever
`python3` happens to point at.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Must come before any other package import: everything else needs 3.7+.
from firemon_drift._bootstrap import ensure_interpreter  # noqa: E402

ensure_interpreter(__file__)

from firemon_drift.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
