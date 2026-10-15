"""CLI-level behaviour that does not need a network: pair selection with a
config that has zero pairs configured, and its console output.

This is the exact shape of a real bug: the setup wizard runs diagnostics
(--list-devices, then --list-policies with --primary/--secondary) against a
candidate config that has not had any [pair:NAME] section written into it
yet -- pairs are only appended after every pair's prompts finish. Config
loading must not treat "zero pairs, so far" as an error, and pair selection
must not assume cfg.pairs is non-empty.
"""

import contextlib
import io
import os
import shutil
import tempfile
import unittest

import support  # noqa: F401

from firemon_drift import cli, config as config_module

BARE = """
[firemon]
base_url = https://fw.example.com
username = svc
password = secret
verify_tls = false

[email]
subject_prefix = [G]

[smtp]
from_address = noreply@example.com

[paths]
template_dir = %(templates)s
"""


class ZeroPairConfig(unittest.TestCase):
    """A config with no [pair] / [pair:NAME] section at all -- the state the
    setup wizard's candidate file is in while gathering the first pair."""

    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.templates = os.path.join(support.ROOT, "templates")

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def write(self, text=BARE):
        path = os.path.join(self.work, "config.ini")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text % {"templates": self.templates})
        return path

    def parse(self, *extra):
        # --config is required by the parser but unused by _select_pairs.
        return cli.build_parser().parse_args(["--config", "x"] + list(extra))

    def test_loads_with_no_pairs_configured(self):
        cfg = config_module.load(self.write())
        self.assertEqual(cfg.pairs, [])

    def test_list_devices_needs_no_pair(self):
        # The actual bug: --list-devices must not require a pair to exist.
        # (Reaching this far without config_module.load raising is the fix;
        # cli.run() itself needs a live server past this point.)
        cfg = config_module.load(self.write())
        args = self.parse("--list-devices", "FTDV")
        self.assertIsNotNone(args.list_devices)
        self.assertEqual(cfg.pairs, [])

    def test_primary_secondary_override_works_with_zero_configured_pairs(self):
        cfg = config_module.load(self.write())
        args = self.parse("--primary", "USE-FW", "--secondary", "USW-FW")
        pairs = cli._select_pairs(cfg, args)
        self.assertEqual(len(pairs), 1)
        pair = pairs[0]
        self.assertEqual(pair.name, "adhoc")
        self.assertEqual((pair.primary, pair.secondary), ("USE-FW", "USW-FW"))
        # This is the specific regression: subject_prefix used to be pulled
        # from cfg.pairs[0], which raised IndexError when there were none.
        self.assertEqual(pair.subject_prefix, "[G]")

    def test_no_overrides_and_zero_pairs_returns_empty_without_raising(self):
        cfg = config_module.load(self.write())
        args = self.parse()
        self.assertEqual(cli._select_pairs(cfg, args), [])

    def test_named_pair_against_zero_configured_pairs_is_a_clear_error(self):
        cfg = config_module.load(self.write())
        args = self.parse("--pair", "us-dr")
        with self.assertRaises(config_module.ConfigError) as ctx:
            cli._select_pairs(cfg, args)
        self.assertIn("(none configured)", str(ctx.exception))

    def test_print_pairs_empty_is_friendly_not_a_bare_zero_count(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli._print_pairs([])
        text = out.getvalue()
        self.assertIn("No firewall pairs are configured yet", text)
        self.assertNotIn("Configured pairs (0)", text)


if __name__ == "__main__":
    unittest.main()
