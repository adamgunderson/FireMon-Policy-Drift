"""Matching by vendor rule id, and the warning when the two configurations
FireMon holds were retrieved far apart.

Both came out of comparing a real Firepower HA pair: matched by name, four
renamed rules read as four missing plus four extra; and the secondary's
configuration in FireMon was six weeks older than the primary's, so every
finding was retrieval lag, not drift. The report has to say so.
"""

import os
import shutil
import tempfile
import unittest

import support  # noqa: F401  (puts the package on sys.path)

from firemon_drift import compare, config as config_module, normalize, state
from firemon_drift.model import (
    CHANGED, ONLY_PRIMARY, ONLY_SECONDARY, DeviceInfo, DriftReport,
    describe_skew, parse_timestamp,
)
from firemon_drift.render import Renderer


def build(raw, device="FW-EAST", device_id=1, **kw):
    return normalize.build_rule(raw, device_id, device, normalize.NameNormaliser(), **kw)


class VendorIdMatching(unittest.TestCase):
    def test_rename_is_a_name_difference_not_missing_plus_extra(self):
        a = build(support.raw_rule("KFONE-PRD-OCP-APP_DB", vendorIdentifier="uuid-1"),
                  match_by="vendor_id")
        b = build(support.raw_rule("KFONE-PRD-HRM_DB", vendorIdentifier="uuid-1"),
                  device="FW-WEST", match_by="vendor_id")
        findings, sa, sb, matched, identical = compare.compare([a], [b], match_by="vendor_id")
        self.assertEqual((sa, sb, matched, identical), (1, 1, 1, 0))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, CHANGED)
        self.assertEqual([d.field for d in findings[0].diffs], ["name"])
        self.assertEqual(findings[0].diffs[0].primary, ["KFONE-PRD-OCP-APP_DB"])
        self.assertEqual(findings[0].diffs[0].secondary, ["KFONE-PRD-HRM_DB"])
        self.assertEqual(findings[0].diffs[0].label, "Rule name")

    def test_same_rename_by_name_is_missing_plus_extra(self):
        a = build(support.raw_rule("KFONE-PRD-OCP-APP_DB", vendorIdentifier="uuid-1"))
        b = build(support.raw_rule("KFONE-PRD-HRM_DB", vendorIdentifier="uuid-1"), device="FW-WEST")
        findings, *_ = compare.compare([a], [b])
        self.assertEqual({f.kind for f in findings}, {ONLY_PRIMARY, ONLY_SECONDARY})

    def test_name_is_not_compared_when_matching_by_name(self):
        # Matched by name the names are equal by construction; the field must
        # not be added, or a [normalise] fold would report every rule.
        a = build(support.raw_rule("r"))
        b = build(support.raw_rule("r"), device="FW-WEST")
        findings, *_ = compare.compare([a], [b])
        self.assertEqual(findings, [])

    def test_rule_without_vendor_id_falls_back_to_its_name(self):
        a = build(support.raw_rule("default-action", vendorIdentifier=None), match_by="vendor_id")
        b = build(support.raw_rule("default-action", vendorIdentifier=""), device="FW-WEST",
                  match_by="vendor_id")
        self.assertEqual(a.key, "default-action")
        self.assertEqual(a.vendor_id, "")
        findings, *_ = compare.compare([a], [b], match_by="vendor_id")
        self.assertEqual(findings, [])

    def test_vendor_id_key_is_policy_scoped_like_a_name_key(self):
        a = build(support.raw_rule("r", vendorIdentifier="uuid-9"), policy_key="Transit",
                  scope_key_by_policy=True, match_by="vendor_id")
        self.assertEqual(a.key, "Transit\x00uuid-9")
        self.assertEqual(a.match_name, "r")

    def test_different_rules_with_the_same_name_are_both_reported(self):
        # The case vendor-id matching exists for: a rule deleted and recreated
        # under the same name has a new id, so the old is gone and the new is
        # extra -- which is exactly what the firewall sees.
        a = build(support.raw_rule("r", vendorIdentifier="uuid-old"), match_by="vendor_id")
        b = build(support.raw_rule("r", vendorIdentifier="uuid-new"), device="FW-WEST",
                  match_by="vendor_id")
        findings, *_ = compare.compare([a], [b], match_by="vendor_id")
        self.assertEqual({f.kind for f in findings}, {ONLY_PRIMARY, ONLY_SECONDARY})

    def test_invalid_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            compare.compare([], [], match_by="uuid")


class FingerprintLabels(unittest.TestCase):
    """With vendor-id keys the fingerprint is opaque; the state file carries a
    label so the resolved section can still name the rule."""

    def test_labels_name_the_rule_and_the_field(self):
        a = build(support.raw_rule("allow-x", vendorIdentifier="uuid-1", log=True),
                  match_by="vendor_id")
        b = build(support.raw_rule("allow-x", vendorIdentifier="uuid-1", log=False),
                  device="FW-WEST", match_by="vendor_id")
        only = build(support.raw_rule("solo", vendorIdentifier="uuid-2"), match_by="vendor_id")
        findings, *_ = compare.compare([a, only], [b], match_by="vendor_id")
        labels = {}
        for finding in findings:
            labels.update(finding.labels())
        self.assertEqual(labels, {
            "changed|uuid-1|log": "allow-x (Transit East) -- differed in logging",
            "only_primary|uuid-2": "solo (Transit East) -- was only on primary",
        })
        self.assertEqual(compare.describe_fingerprint("changed|uuid-1|log", labels),
                         "allow-x (Transit East) -- differed in logging")
        # An older state file without labels still gets the parsed form.
        self.assertEqual(compare.describe_fingerprint("changed|uuid-1|log", {}),
                         "uuid-1 -- differed in logging")

    def test_state_file_round_trips_labels(self):
        work = tempfile.mkdtemp()
        try:
            path = state.state_path(work, "A")
            state.save(path, ["changed|k|action"], support.RUN_TIME, {"changed": 1},
                       labels={"changed|k|action": "r (P) -- differed in action"})
            self.assertEqual(state.load_previous(path)[0], ["changed|k|action"])
            self.assertEqual(state.load_labels(path),
                             {"changed|k|action": "r (P) -- differed in action"})
            self.assertEqual(state.load_labels(os.path.join(work, "missing.json")), {})
        finally:
            shutil.rmtree(work, ignore_errors=True)


def make_report(date_a, date_b, limit=24, findings=()):
    return DriftReport(
        primary=DeviceInfo(id=1, name="FW-EAST", revision_id=10, revision_date=date_a,
                           rule_total=3, in_scope=3),
        secondary=DeviceInfo(id=2, name="FW-WEST", revision_id=11, revision_date=date_b,
                             rule_total=3, in_scope=3),
        generated_at=support.RUN_TIME, findings=list(findings), matched=3, identical=3,
        max_revision_skew_hours=limit,
    )


class RevisionSkew(unittest.TestCase):
    def test_timestamps_and_skew(self):
        self.assertIsNone(parse_timestamp(None))
        self.assertIsNone(parse_timestamp("yesterday"))
        self.assertEqual(parse_timestamp("2026-07-20T21:30:30.993Z").hour, 21)
        report = make_report("2026-07-20T21:30:30.993Z", "2026-06-09T14:12:20.963Z")
        self.assertAlmostEqual(report.revision_skew_hours(), 991.3, places=0)
        self.assertTrue(report.revisions_stale)
        self.assertEqual(report.older_side, "secondary")
        self.assertEqual(describe_skew(report.revision_skew_hours()), "41 days")
        self.assertEqual(describe_skew(1.2), "1 hour")
        self.assertEqual(describe_skew(30), "30 hours")

    def test_fresh_pair_is_not_stale(self):
        report = make_report("2026-07-20T21:30:30.993Z", "2026-07-20T21:31:44.890Z")
        self.assertFalse(report.revisions_stale)
        self.assertEqual(report.older_side, "primary")

    def test_unknown_date_or_disabled_limit_never_warns(self):
        self.assertFalse(make_report(None, "2026-07-20T21:31:44.890Z").revisions_stale)
        self.assertFalse(make_report("2026-07-20T21:30:30.993Z", "2026-06-09T14:12:20.963Z",
                                     limit=0).revisions_stale)

    def test_report_carries_the_warning_when_stale(self):
        only = build(support.raw_rule("solo"))
        findings = [compare.Finding(kind=ONLY_PRIMARY, key="solo", primary=only, secondary=None)]
        report = make_report("2026-07-20T21:30:30.993Z", "2026-06-09T14:12:20.963Z",
                             findings=findings)
        subject, html, text = Renderer(support.FakeConfig(), support.FakePair(), report).render()
        self.assertIn("[configs 41 days apart]", subject)
        self.assertIn("WARNING: configurations are not from the same time.", text)
        self.assertIn("retrieved 41 days apart", text)
        self.assertIn("current configuration of FW-WEST", text)
        self.assertIn("Configurations are not from the same time.", html)
        self.assertIn("Rules are matched by name.", text)

    def test_no_warning_when_fresh(self):
        report = make_report("2026-07-20T21:30:30.993Z", "2026-07-20T21:31:44.890Z")
        subject, html, text = Renderer(support.FakeConfig(), support.FakePair(), report).render()
        self.assertNotIn("apart", subject)
        self.assertNotIn("WARNING: configurations", text)
        self.assertNotIn("not from the same time", html)

    def test_vendor_id_note_in_report(self):
        report = make_report("2026-07-20T21:30:30.993Z", "2026-07-20T21:31:44.890Z")
        report.match_by = "vendor_id"
        _, html, text = Renderer(support.FakeConfig(), support.FakePair(match_by="vendor_id"),
                                 report).render()
        self.assertIn("matched by the vendor's own rule id", text)
        self.assertIn("rules matched by the vendor's rule id", text)
        self.assertIn("same vendor rule id", html)


class MatchByConfig(unittest.TestCase):
    TEMPLATE = """
[firemon]
base_url = https://fw.example.com
username = svc
password = secret

[compare]
%(compare)s

[pair:ha]
primary = FW-A
secondary = FW-B
%(pair)s

[smtp]
from_address = noreply@example.com

[paths]
template_dir = %(templates)s
"""

    def setUp(self):
        self.work = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def load(self, compare_lines="", pair_lines=""):
        path = os.path.join(self.work, "config.ini")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.TEMPLATE % {
                "compare": compare_lines, "pair": pair_lines,
                "templates": os.path.join(support.ROOT, "templates")})
        return config_module.load(path)

    def test_defaults(self):
        cfg = self.load()
        self.assertEqual(cfg.match_by, "name")
        self.assertEqual(cfg.max_revision_skew_hours, 24)
        self.assertEqual(cfg.pairs[0].match_by, "name")

    def test_global_and_per_pair(self):
        cfg = self.load("match_by = vendor_id\nmax_revision_skew_hours = 0")
        self.assertEqual(cfg.pairs[0].match_by, "vendor_id")
        self.assertEqual(cfg.max_revision_skew_hours, 0)
        cfg = self.load("match_by = name", "match_by = VENDOR_ID")
        self.assertEqual(cfg.pairs[0].match_by, "vendor_id")

    def test_bad_values_are_refused(self):
        with self.assertRaises(config_module.ConfigError):
            self.load("match_by = uuid")
        with self.assertRaises(config_module.ConfigError):
            self.load("", "match_by = guid")
        with self.assertRaises(config_module.ConfigError):
            self.load("max_revision_skew_hours = -1")


if __name__ == "__main__":
    unittest.main()
