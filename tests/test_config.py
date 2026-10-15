"""Config loading and validation, against temporary INI files."""

import os
import shutil
import tempfile
import unittest

import support  # noqa: F401

from firemon_drift import config as config_module
from firemon_drift.model import DEFAULT_FIELDS, FIELD_ORDER

MINIMAL = """
[firemon]
base_url = https://fw.example.com
username = svc
password = secret
verify_tls = false

[pair]
primary = FW-EAST
secondary = FW-WEST

[smtp]
from_address = noreply@example.com

[paths]
template_dir = %(templates)s
"""

# No plain [pair]; everything comes from named sections.
MULTI = """
[firemon]
base_url = https://fw.example.com
username = svc
password = secret

[policies]
Transit East = Transit West

[filter]
categories = AVD

[property_filters]
Business Owner = netops@example.com

[normalise]
site = (?i)\\bEAST\\b => SITE

[email]
recipients = global@example.com
send_when = drift
subject_prefix = [G]

[pair:us]
primary = US-EAST
secondary = US-WEST
recipients = us@example.com, US2@example.com
send_when = changes
categories = ESO*
policies = US Transit = US DR Transit, Prefilter
subject_prefix = [US]
primary_label = US East
object_mode = contents
fields = action, log

[pair:eu]
primary = EU-1
secondary = EU-2
policies = all
categories = none
recipients = none
send_when = never

[pair:apac]
primary = AP-1
secondary = AP-2

[policies:apac]
APAC Transit = APAC DR Transit

[property_filters:apac]
Business Owner = apac@example.com

[normalise:apac]
site = (?i)\\bAP\\b => X

[smtp]
from_address = noreply@example.com

[paths]
template_dir = %(templates)s
"""


class ConfigLoading(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.templates = os.path.join(support.ROOT, "templates")
        self.saved_env = {k: os.environ.pop(k) for k in
                          (config_module.ENV_FM_PASSWORD, config_module.ENV_FM_TOKEN,
                           config_module.ENV_SMTP_PASSWORD) if k in os.environ}

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)
        os.environ.update(self.saved_env)

    def write(self, text, name="config.ini"):
        path = os.path.join(self.work, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text % {"templates": self.templates})
        return path

    def test_minimal_config_and_defaults(self):
        cfg = config_module.load(self.write(MINIMAL))
        self.assertEqual(len(cfg.pairs), 1)
        pair = cfg.pairs[0]
        self.assertEqual(pair.name, "default")
        self.assertEqual((pair.primary, pair.secondary), ("FW-EAST", "FW-WEST"))
        self.assertEqual(pair.policy_pairs, [])
        self.assertEqual(pair.fields, DEFAULT_FIELDS)
        self.assertEqual(pair.object_mode, "name")
        self.assertEqual(pair.send_when, "drift")
        self.assertEqual(pair.recipients, [])
        self.assertEqual(cfg.portal_url, "https://fw.example.com/securitymanager/")
        self.assertEqual(cfg.support_email, "noreply@example.com")
        self.assertEqual(cfg.state_dir, os.path.join(self.work, "state"))

    def test_example_config_loads(self):
        example = os.path.join(support.ROOT, "config.example.ini")
        with open(example, "r", encoding="utf-8") as handle:
            text = handle.read()
        text = text.replace("password    =\n", "password    = x\n", 1)
        text = text.replace("primary   =\n", "primary   = A\n", 1)
        text = text.replace("secondary =\n", "secondary = B\n", 1)
        text = text.replace("template_dir = ./templates", "template_dir = %(templates)s")
        cfg = config_module.load(self.write(text))
        self.assertEqual(cfg.pairs[0].primary, "A")
        self.assertEqual(cfg.category_property, "FMC ACP Category")
        # The category pattern contains ';' and must survive inline-comment parsing.
        self.assertEqual(cfg.category_comment_pattern, r"cat:\s*([^;]*?)\s*;")

    def test_example_without_a_pair_loads_with_zero_pairs(self):
        # A config with no [pair]/[pair:NAME] section at all is not a load
        # error: the setup wizard builds one exactly this way while it is
        # still gathering pairs, and --list-devices needs no pair either.
        # Whether a *run* can proceed with zero pairs is cli.py's call.
        example = os.path.join(support.ROOT, "config.example.ini")
        with open(example, "r", encoding="utf-8") as handle:
            text = handle.read()
        text = text.replace("password    =\n", "password    = x\n", 1)
        text = text.replace("template_dir = ./templates", "template_dir = %(templates)s")
        cfg = config_module.load(self.write(text))
        self.assertEqual(cfg.pairs, [])
        self.assertIsNone(cfg.pair("anything"))

    def test_multi_pair_inheritance_and_overrides(self):
        cfg = config_module.load(self.write(MULTI))
        self.assertEqual([p.name for p in cfg.pairs], ["us", "eu", "apac"])
        us, eu, apac = cfg.pairs

        # us: everything overridden inline.
        self.assertEqual(us.recipients, ["us@example.com", "us2@example.com"])
        self.assertEqual(us.send_when, "changes")
        self.assertEqual(us.categories, ["ESO*"])
        self.assertEqual(us.policy_pairs, [("US Transit", "US DR Transit"), ("Prefilter", "Prefilter")])
        self.assertEqual(us.subject_prefix, "[US]")
        self.assertEqual(us.primary_label, "US East")
        self.assertEqual(us.object_mode, "contents")
        self.assertEqual(us.fields, ("action", "log"))
        # ...but property filters and normalisation still inherit.
        self.assertEqual(us.properties, {"Business Owner": ["netops@example.com"]})
        self.assertEqual(us.normalise_rules, [(r"(?i)\bEAST\b", "SITE")])

        # eu: "all" / "none" switch the global values off.
        self.assertEqual(eu.policy_pairs, [])
        self.assertEqual(eu.categories, [])
        self.assertEqual(eu.recipients, [])
        self.assertEqual(eu.send_when, "never")
        self.assertEqual(eu.subject_prefix, "[G]")

        # apac: nothing inline, so global defaults, except the scoped sections.
        self.assertEqual(apac.recipients, ["global@example.com"])
        self.assertEqual(apac.send_when, "drift")
        self.assertEqual(apac.categories, ["AVD"])
        self.assertEqual(apac.policy_pairs, [("APAC Transit", "APAC DR Transit")])
        self.assertEqual(apac.properties, {"Business Owner": ["apac@example.com"]})
        self.assertEqual(apac.normalise_rules, [(r"(?i)\bAP\b", "X")])
        self.assertEqual(apac.fields, DEFAULT_FIELDS)

        self.assertIs(cfg.pair("APAC"), apac)
        self.assertIsNone(cfg.pair("nope"))

    def test_plain_pair_and_named_pairs_coexist(self):
        cfg = config_module.load(self.write(MINIMAL + "\n[pair:second]\nprimary = A\nsecondary = B\n"))
        self.assertEqual([p.name for p in cfg.pairs], ["default", "second"])

    def test_pair_errors(self):
        base = MINIMAL.replace("primary = FW-EAST\nsecondary = FW-WEST\n", "")
        self.assertEqual(config_module.load(self.write(base)).pairs, [])  # no pair at all: not an error
        with self.assertRaises(config_module.ConfigError):
            config_module.load(self.write(base + "\n[pair:x]\nprimary = A\n"))  # half a pair
        with self.assertRaises(config_module.ConfigError):
            config_module.load(self.write(base + "\n[pair:x]\nprimary = A\nsecondary = a\n"))
        with self.assertRaises(config_module.ConfigError):
            config_module.load(self.write(base + "\n[pair:x]\nprimary = A\nsecondary = B\n"
                                          "[pair:X]\nprimary = C\nsecondary = D\n"))  # duplicate
        with self.assertRaises(config_module.ConfigError):
            config_module.load(self.write(base + "\n[pair:bad/name]\nprimary = A\nsecondary = B\n"))
        with self.assertRaises(config_module.ConfigError) as ctx:
            config_module.load(self.write(MINIMAL + "\n[policies:ghost]\nA = B\n"))
        self.assertIn("not defined", str(ctx.exception))
        with self.assertRaises(config_module.ConfigError):
            config_module.load(self.write(MINIMAL + "\n[pair:x]\nprimary = A\nsecondary = B\nsend_when = maybe\n"))

    def test_policies_keep_case_and_colon(self):
        cfg = config_module.load(self.write(MINIMAL + """
[policies]
Transit East = Transit West
Prefilter =
Site: A = Site: B
"""))
        self.assertEqual(cfg.pairs[0].policy_pairs, [("Transit East", "Transit West"),
                                                     ("Prefilter", "Prefilter"),
                                                     ("Site: A", "Site: B")])

    def test_property_filters_and_normalise(self):
        cfg = config_module.load(self.write(MINIMAL + r"""
[property_filters]
Business Owner = netops@example.com, security@*

[normalise]
east = (?i)\bUSE\b => SITE
west = (?i)\bUSW\b =>
"""))
        self.assertEqual(cfg.filter_properties, {"Business Owner": ["netops@example.com", "security@*"]})
        self.assertEqual(cfg.normalise_rules, [(r"(?i)\bUSE\b", "SITE"), (r"(?i)\bUSW\b", "")])

    def test_normalise_needs_arrow_and_valid_regex(self):
        with self.assertRaises(config_module.ConfigError):
            config_module.load(self.write(MINIMAL + "\n[normalise]\nx = USE\n"))
        with self.assertRaises(config_module.ConfigError):
            config_module.load(self.write(MINIMAL + "\n[normalise]\nx = (unclosed => y\n"))

    def test_fields_parsing(self):
        self.assertEqual(config_module.parse_fields(""), DEFAULT_FIELDS)
        self.assertEqual(config_module.parse_fields("all"), FIELD_ORDER)
        self.assertEqual(config_module.parse_fields("Action, source zones, prop:Business Owner"),
                         ("action", "source_zones", "prop:Business Owner"))
        with self.assertRaises(config_module.ConfigError):
            config_module.parse_fields("action, colour")
        with self.assertRaises(config_module.ConfigError):
            config_module.parse_fields("prop:")

    def test_inline_policy_pairs(self):
        self.assertEqual(config_module.parse_policy_pairs_inline("A = B, C", "x"),
                         [("A", "B"), ("C", "C")])
        with self.assertRaises(config_module.ConfigError):
            config_module.parse_policy_pairs_inline("= B", "x")

    def test_env_password_wins_and_missing_password_fails(self):
        path = self.write(MINIMAL.replace("password = secret\n", ""))
        with self.assertRaises(config_module.ConfigError):
            config_module.load(path)
        os.environ[config_module.ENV_FM_PASSWORD] = "from-env"
        cfg = config_module.load(path)
        self.assertEqual(cfg.password, "from-env")

    def test_bad_enums_rejected(self):
        for section, key, value in (("compare", "object_mode", "fuzzy"),
                                    ("compare", "fetch_ruledoc", "sometimes"),
                                    ("email", "send_when", "whenever")):
            with self.assertRaises(config_module.ConfigError):
                config_module.load(self.write(MINIMAL + "\n[%s]\n%s = %s\n" % (section, key, value)))

    def test_missing_template_dir(self):
        with self.assertRaises(config_module.ConfigError):
            config_module.load(self.write(MINIMAL.replace("%(templates)s", "/nonexistent/dir")))

    def test_needs_ruledoc_for_compare(self):
        cfg = config_module.load(self.write(MINIMAL))
        self.assertFalse(cfg.pairs[0].needs_ruledoc_for_compare)
        cfg = config_module.load(self.write(MINIMAL + "\n[compare]\nfields = action, prop:Owner\n"))
        self.assertTrue(cfg.pairs[0].needs_ruledoc_for_compare)


if __name__ == "__main__":
    unittest.main()
