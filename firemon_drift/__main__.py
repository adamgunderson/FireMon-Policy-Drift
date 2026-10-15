"""Allow `python3 -m firemon_drift --config ...`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
