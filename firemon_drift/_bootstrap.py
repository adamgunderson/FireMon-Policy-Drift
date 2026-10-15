"""Interpreter bootstrap. MUST stay importable on old Pythons.

This module is imported before anything else in the package, by an interpreter
that may be too old to run the rest of it. Keep it free of dataclasses,
f-strings and anything else newer than Python 3.4 -- its whole job is to hand
off to a newer interpreter, and it cannot do that if importing it is itself a
syntax or import error.

FMOS 2026.2.x ships 3.6.8 as the default `python3`, with 3.9.25 and 3.12.13
installed alongside. Without this, every documented command would have to name
an explicit interpreter, and would break again whenever an upgrade moved the
versions around.
"""

import os
import sys

MINIMUM = (3, 7)  # dataclasses

# Newest first. Only consulted when the running interpreter is too old.
_CANDIDATES = (
    "python3.13", "python3.12", "python3.11",
    "python3.10", "python3.9", "python3.8", "python3.7",
)

_REEXEC_MARKER = "FMDRIFT_REEXEC"


def find_newer_interpreter():
    """Path to an installed interpreter meeting MINIMUM, or None."""
    search_dirs = [d for d in os.environ.get("PATH", "").split(os.pathsep) if d]
    search_dirs += ["/usr/bin", "/usr/local/bin", "/opt/rh/bin"]

    seen = set()
    for name in _CANDIDATES:
        for directory in search_dirs:
            candidate = os.path.join(directory, name)
            if candidate in seen:
                continue
            seen.add(candidate)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None


def ensure_interpreter(script_path, argv=None):
    """Re-execute `script_path` under a newer interpreter if this one is old.

    Returns normally when the running interpreter is already good enough.
    Never returns when it re-executes. An environment marker prevents an exec
    loop if the interpreter we pick turns out to be unsuitable too.
    """
    if sys.version_info >= MINIMUM:
        return

    running = "%d.%d" % (sys.version_info[0], sys.version_info[1])
    need = "%d.%d" % MINIMUM

    if os.environ.get(_REEXEC_MARKER):
        sys.stderr.write(
            "firemon-drift: re-executed under %s but that is still older than "
            "Python %s.\n" % (sys.executable, need)
        )
        raise SystemExit(1)

    interpreter = find_newer_interpreter()
    if not interpreter:
        sys.stderr.write(
            "firemon-drift requires Python %s or newer, but this is %s and no "
            "newer interpreter was found.\n\n"
            "On FMOS the default python3 is 3.6; look for one of\n"
            "    ls /usr/bin/python3.[0-9]*\n"
            "and run it explicitly:\n"
            "    /usr/bin/python3.12 %s ...\n"
            % (need, running, os.path.abspath(script_path))
        )
        raise SystemExit(1)

    os.environ[_REEXEC_MARKER] = "1"
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        os.execv(interpreter, [interpreter, os.path.abspath(script_path)] + args)
    except OSError as exc:
        sys.stderr.write(
            "firemon-drift: could not start %s (%s)\n" % (interpreter, exc)
        )
        raise SystemExit(1)
