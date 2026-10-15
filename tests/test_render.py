"""Rendering: subject, HTML, text, CSV and JSON, against a synthetic report."""

import csv
import io
import json
import unittest

import support

from firemon_drift import compare, normalize
from firemon_drift.model import DeviceInfo, DriftReport
from firemon_drift.render import GMAIL_CLIP_BYTES, RenderError, Renderer, _fmt_date


def build(raw, device="FW-EAST", device_id=1):
    return normalize.build_rule(raw, device_id, device, normalize.NameNormaliser())


def make_report(findings=(), matched=1, identical=0, previous=None, resolved=(),
                policy_pairs=(), filter_lines=(), pair_name="default"):
    return DriftReport(pair_name=pair_name,
        primary=DeviceInfo(id=1, name="FW-EAST", revision_id=10,
                           revision_date="2026-09-17T21:30:30.993Z", rule_total=3, in_scope=2),
        secondary=DeviceInfo(id=2, name="FW-WEST", revision_id=20,
                             revision_date="2026-09-17T22:00:00.000Z", rule_total=3, in_scope=2),
        generated_at=support.RUN_TIME, findings=list(findings), matched=matched,
        identical=identical, policy_pairs=list(policy_pairs),
        filter_lines=list(filter_lines), resolved=list(resolved), previous_run=previous,
    )


def drift_findings():
    web = support.host("WEB-01", "10.1.1.10/32")
    https = support.service("HTTPS", "tcp", 443)
    http = support.service("HTTP", "tcp", 80)
    a = build(support.raw_rule("allow-web & <co>", sources=[web], services=[https],
                               comment="cat:AVD;"))
    b = build(support.raw_rule("allow-web & <co>", sources=[web], services=[https, http],
                               log=False, comment="cat:AVD;"), device="FW-WEST", device_id=2)
    only_a = build(support.raw_rule("east-only", order=2, action="DROP"))
    only_b = build(support.raw_rule("west-only", order=3, disabled=True), device="FW-WEST",
                   device_id=2)
    findings, *_ = compare.compare([a, only_a], [b, only_b])
    return findings


class Rendering(unittest.TestCase):
    def setUp(self):
        self.cfg = support.FakeConfig()
        self.pair = support.FakePair()

    def test_no_drift(self):
        renderer = Renderer(self.cfg, self.pair, make_report(identical=1))
        subject, html_body, text_body = renderer.render()
        self.assertEqual(subject, "Policy drift: FW-EAST vs FW-WEST -- no drift")
        self.assertIn("No drift.", html_body)
        self.assertIn("No drift.", text_body)
        self.assertIn("2026-09-17 21:30 UTC", text_body)
        self.assertNotIn("${", html_body)
        self.assertNotIn("${", text_body)
        self.assertNotIn("<!--", html_body)  # editor note stripped

    def test_drift_subject_and_sections(self):
        findings = drift_findings()
        compare.mark_new(findings, ["only_primary|east-only", "changed|gone-rule|action"])
        report = make_report(findings, matched=1, previous="2026-09-17T06:00:00+00:00",
                             resolved=["changed|gone-rule|action"])
        renderer = Renderer(self.cfg, self.pair, report)
        subject, html_body, text_body = renderer.render()
        self.assertEqual(subject, "Policy drift: FW-EAST vs FW-WEST -- 3 findings (2 new)")
        self.assertNotIn("for pair", html_body)
        # Escaping: the rule name carries & and <.
        self.assertIn("allow-web &amp; &lt;co&gt;", html_body)
        self.assertNotIn("<co>", html_body)
        self.assertIn("allow-web & <co>", text_body)
        # What differs is said in words, per side, not with +/- signs.
        self.assertIn("<strong>HTTP</strong></span>", html_body)
        self.assertIn("HTTP    <- FW-WEST only", text_body)
        self.assertNotIn("+ HTTP", text_body)
        # Count rows jump to their section; device names link to Security Manager.
        self.assertIn('href="#differ"', html_body)
        self.assertIn('id="differ"', html_body)
        self.assertIn('href="#only-primary"', html_body)
        self.assertIn("securitymanager/#/domain/1/device/", html_body)
        self.assertIn("listrules?page=1&amp;count=20&amp;advancedMode=0&amp;siql=domain%20%7B%20id%20%3D%201%20%7D"
                      "%20%20AND%20rule%20%7B%20ruleName%20~%20%27allow-web%20%26%20%3Cco%3E%27%20%7D%20", html_body)
        self.assertIn("NEW", html_body)
        self.assertIn("[NEW]", text_body)
        # Resolved section appears with the readable form.
        self.assertIn("Resolved Since Last Run", html_body)
        self.assertIn("gone-rule -- differed in action", text_body)
        # Disabled marker on the secondary-only rule.
        self.assertIn("(disabled)", html_body)
        self.assertIn("east-only", text_body)

    def test_labels_and_prefix(self):
        pair = support.FakePair(name="us-dr", primary_label="Production", secondary_label="DR",
                                subject_prefix="[TEST]")
        renderer = Renderer(self.cfg, pair, make_report(drift_findings(), pair_name="us-dr"))
        subject, html_body, text_body = renderer.render()
        self.assertTrue(subject.startswith("[TEST] Policy drift [us-dr]: Production vs DR"))
        self.assertIn("for pair &ldquo;us-dr&rdquo;", html_body)
        self.assertIn("(pair us-dr)", text_body)
        self.assertIn("Only On Production", html_body)
        self.assertIn("ONLY ON DR", text_body)

    def test_row_caps_note_the_csv(self):
        cfg = support.FakeConfig(max_rows=1, max_diff_rules=1)
        rules = [build(support.raw_rule("r%d" % i, order=i)) for i in range(3)]
        findings, *_ = compare.compare(rules, [])
        renderer = Renderer(cfg, self.pair, make_report(findings, matched=0))
        _, html_body, text_body = renderer.render()
        self.assertIn("Showing 1 of 3", html_body)
        self.assertIn("2 more in the attached CSV", text_body)

    def test_scope_lines(self):
        report = make_report(policy_pairs=[("Transit East", "Transit West")],
                             filter_lines=["category: AVD"])
        report.normalise_lines = ["\\bUSE\\b -> SITE"]
        _, html_body, text_body = Renderer(self.cfg, self.pair, report).render()
        self.assertIn("Transit East", html_body)
        self.assertIn("category: AVD", text_body)
        self.assertIn("name normalisation", text_body)

    def test_missing_template_is_a_render_error(self):
        cfg = support.FakeConfig(template_dir="/nonexistent")
        with self.assertRaises(RenderError):
            Renderer(cfg, self.pair, make_report()).render()

    def test_large_report_warns_about_clipping(self):
        cfg = support.FakeConfig(max_rows=100000, max_diff_rules=100000)
        rules_a = [build(support.raw_rule("rule-%04d" % i, order=i, log=True)) for i in range(800)]
        rules_b = [build(support.raw_rule("rule-%04d" % i, order=i, log=False), device="FW-WEST")
                   for i in range(800)]
        findings, *_ = compare.compare(rules_a, rules_b)
        with self.assertLogs("firemon_drift.render", level="WARNING"):
            _, html_body, _ = Renderer(cfg, self.pair, make_report(findings)).render()
        self.assertGreater(len(html_body), GMAIL_CLIP_BYTES)

    def test_default_caps_keep_a_wide_report_under_the_clip(self):
        rules_a = [build(support.raw_rule("rule-%04d" % i, order=i, log=True,
                                          sources=[support.host("H%d" % i, "10.0.0.%d/32" % (i % 250))]))
                   for i in range(400)]
        rules_b = [build(support.raw_rule("rule-%04d" % i, order=i, log=False,
                                          sources=[support.host("H%d" % i, "10.0.0.%d/32" % (i % 250)),
                                                   support.host("X%d" % i, "10.0.1.%d/32" % (i % 250))]),
                         device="FW-WEST") for i in range(400)]
        rules_a += [build(support.raw_rule("east-%04d" % i, order=1000 + i)) for i in range(200)]
        findings, *_ = compare.compare(rules_a, rules_b)
        _, html_body, _ = Renderer(self.cfg, self.pair, make_report(findings)).render()
        self.assertLess(len(html_body.encode("utf-8")), GMAIL_CLIP_BYTES)


class Attachments(unittest.TestCase):
    def test_csv_rows_and_json(self):
        cfg = support.FakeConfig(attach_json=True)
        findings = drift_findings()
        renderer = Renderer(cfg, support.FakePair(), make_report(findings))
        items = renderer.attachments()
        self.assertEqual([i[0] for i in items],
                         ["policy-drift-FW-EAST-vs-FW-WEST-20260918.csv",
                          "policy-drift-FW-EAST-vs-FW-WEST-20260918.json"])
        rows = list(csv.reader(io.StringIO(items[0][1].decode("utf-8-sig"))))
        self.assertEqual(rows[0][0], "finding")
        kinds = [(r[0], r[2], r[7]) for r in rows[1:]]
        # The changed rule yields one row per differing field.
        self.assertIn(("differs", "allow-web & <co>", "Logging"), kinds)
        self.assertIn(("differs", "allow-web & <co>", "Services"), kinds)
        self.assertIn(("only on primary", "east-only", ""), kinds)
        self.assertIn(("only on secondary", "west-only", ""), kinds)
        payload = json.loads(items[1][1].decode("utf-8"))
        self.assertEqual(payload["primary"]["name"], "FW-EAST")
        self.assertEqual(len(payload["findings"]), 3)
        changed = [f for f in payload["findings"] if f["kind"] == "changed"][0]
        self.assertEqual({d["field"] for d in changed["differences"]}, {"log", "services"})

    def test_no_csv_when_off(self):
        cfg = support.FakeConfig(attach_csv=False)
        self.assertEqual(Renderer(cfg, support.FakePair(), make_report()).attachments(), [])


class Dates(unittest.TestCase):
    def test_fmt_date(self):
        self.assertEqual(_fmt_date("2026-07-20T21:30:30.993Z"), "2026-07-20 21:30 UTC")
        self.assertEqual(_fmt_date(None), "unknown")
        self.assertEqual(_fmt_date("yesterday"), "yesterday")


if __name__ == "__main__":
    unittest.main()
