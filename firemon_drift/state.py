"""What the previous run found, so this run can say what is new.

One small JSON file per configured pair under state_dir, named after the pair. It holds the
fingerprints of every finding the last LIVE run reported -- not the findings
themselves, which are recomputed from the firewalls each time -- plus when
that was. Losing the file costs one report's worth of NEW markers and
nothing else.

Dry runs do not write it: a rehearsal that quietly consumed the "new" flags
would leave the real scheduled run reporting old drift as familiar.
"""

import json
import logging
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

LOG = logging.getLogger(__name__)

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _slug(value: str) -> str:
    return _UNSAFE.sub("_", str(value)).strip("_") or "x"


def state_path(state_dir: str, pair_name: str) -> str:
    return os.path.join(state_dir, "last-%s.json" % _slug(pair_name))


def load_previous(path: str) -> Tuple[Optional[List[str]], Optional[str]]:
    """(fingerprints, run time) of the previous run, or (None, None) when
    there is no usable state -- which is treated as 'first run', never as
    'everything is new'."""
    if not os.path.isfile(path):
        return None, None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        prints = data.get("fingerprints")
        if not isinstance(prints, list):
            raise ValueError("fingerprints missing")
        return [str(p) for p in prints], data.get("run_time")
    except (OSError, ValueError) as exc:
        LOG.warning("ignoring unreadable state file %s: %s", path, exc)
        return None, None


def load_labels(path: str) -> Dict[str, str]:
    """The human label the previous run stored for each fingerprint, so a
    resolved finding can be named even when its key is a vendor rule id.
    Empty for a file written before labels existed."""
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            labels = json.load(handle).get("labels")
        if not isinstance(labels, dict):
            return {}
        return {str(k): str(v) for k, v in labels.items()}
    except (OSError, ValueError, AttributeError):
        return {}


def save(path: str, fingerprints: List[str], run_time: datetime, counts: dict,
         labels: Optional[Dict[str, str]] = None) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump({
            "run_time": run_time.isoformat(),
            "fingerprints": sorted(fingerprints),
            "counts": counts,
            "labels": dict(labels or {}),
        }, handle, indent=1, sort_keys=True)
    os.replace(tmp, path)
