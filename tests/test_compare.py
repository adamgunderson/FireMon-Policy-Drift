"""The comparison and the filters, against synthetic rules."""

import unittest

import support  # noqa: F401  (puts the package on sys.path)

from firemon_drift import compare, normalize
from firemon_drift.model import CHANGED, ONLY_PRIMARY, ONLY_SECONDARY, DEFAULT_FIELDS


def build(raw, device="FW-EAST", device_id=1, normaliser=None, **kw):
    return normalize.build_rule(raw, device_id, device, normaliser or normalize.NameNormaliser(), **kw)


class CompareBasics(unittest.TestCase):
    def setUp(self):
        self.web = support.host("WEB-01", "10.1.1.10/32")
        self.db = support.host("DB-01", "10.1.2.20/32")
        self.https = support.service("HTTPS", "tcp", 443)
        self.http = support.service("HTTP", "tcp", 80)

    def test_identical_rules_produce_no_findings(self):
        a = build(support.raw_rule("allow-web", sources=[self.web], destinations=[self.db],
                                   services=[self.https]))
        b = build(support.raw_rule("allow-web", sources=[self.web], destinations=[self.db],
                                   services=[self.https]), device="FW-WEST", device_id=2)
        findings, sa, sb, matched, identical = compare.compare([a], [b])
        self.assertEqual(findings, [])
        self.assertEqual((sa, sb, matched, identical), (1, 1, 1, 1))

    def test_missing_on_each_side(self):
        a1 = build(support.raw_rule("only-east", order=1))
        a2 = build(support.raw_rule("shared", order=2))
        b1 = build(support.raw_rule("shared", order=1), device="FW-WEST")
        b2 = build(support.raw_rule("only-west", order=2), device="FW-WEST")
        findings, sa, sb, matched, identical = compare.compare([a1, a2], [b1, b2])
        kinds = {(f.kind, f.name) for f in findings}
        self.assertEqual(kinds, {(ONLY_PRIMARY, "only-east"), (ONLY_SECONDARY, "only-west")})
        self.assertEqual((sa, sb, matched, identical), (2, 2, 1, 1))

    def test_service_difference_reports_added_and_removed(self):
        a = build(support.raw_rule("allow-web", services=[self.https]))
        b = build(support.raw_rule("allow-web", services=[self.https, self.http]), device="FW-WEST")
        findings, *_ = compare.compare([a], [b])
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.kind, CHANGED)
        self.assertEqual([d.field for d in finding.diffs], ["services"])
        diff = finding.diffs[0]
        self.assertEqual(diff.added, ["HTTP"])
        self.assertEqual(diff.removed, [])
        self.assertEqual(diff.primary, ["HTTPS"])
        self.assertEqual(sorted(diff.secondary), ["HTTP", "HTTPS"])

    def test_scalar_differences(self):
        a = build(support.raw_rule("r", action="ACCEPT", log=True, disabled=False))
        b = build(support.raw_rule("r", action="DROP", log=False, disabled=True), device="FW-WEST")
        findings, *_ = compare.compare([a], [b])
        fields = {d.field: d for d in findings[0].diffs}
        self.assertEqual(set(fields), {"action", "log", "disabled"})
        self.assertEqual(fields["action"].primary, ["ACCEPT"])
        self.assertEqual(fields["action"].secondary, ["DROP"])
        self.assertEqual(fields["disabled"].secondary, ["disabled"])
        self.assertEqual(fields["log"].secondary, ["off"])

    def test_zone_difference(self):
        a = build(support.raw_rule("r", src_zones=["inside"], dst_zones=["outside"]))
        b = build(support.raw_rule("r", src_zones=["inside"], dst_zones=["inside"]), device="FW-WEST")
        findings, *_ = compare.compare([a], [b])
        self.assertEqual([d.field for d in findings[0].diffs], ["destination_zones"])
        self.assertEqual(findings[0].diffs[0].removed, ["outside"])
        self.assertEqual(findings[0].diffs[0].added, ["inside"])

    def test_any_zone_versus_named_zone(self):
        a = build(support.raw_rule("r"))  # any/any
        b = build(support.raw_rule("r", src_zones=["inside"]), device="FW-WEST")
        findings, *_ = compare.compare([a], [b])
        self.assertEqual([d.field for d in findings[0].diffs], ["source_zones"])
        self.assertEqual(findings[0].diffs[0].primary, ["any"])

    def test_fields_not_listed_are_ignored(self):
        a = build(support.raw_rule("r", comment="cat:A;", order=1))
        b = build(support.raw_rule("r", comment="cat:A; extra", order=9), device="FW-WEST")
        findings, *_ = compare.compare([a], [b], fields=DEFAULT_FIELDS)
        self.assertEqual(findings, [])
        findings, *_ = compare.compare([a], [b], fields=("comment", "order"))
        self.assertEqual({d.field for d in findings[0].diffs}, {"comment", "order"})

    def test_category_difference_is_drift_by_default(self):
        a = build(support.raw_rule("r", comment="cat:ESO-DR;"))
        b = build(support.raw_rule("r", comment="cat:ESO;"), device="FW-WEST")
        findings, *_ = compare.compare([a], [b])
        self.assertEqual([d.field for d in findings[0].diffs], ["category"])
        self.assertEqual(findings[0].diffs[0].primary, ["ESO-DR"])

    def test_findings_sorted_by_policy_then_position(self):
        rules_a = [build(support.raw_rule("z", order=1)), build(support.raw_rule("a", order=5))]
        findings, *_ = compare.compare(rules_a, [])
        self.assertEqual([f.name for f in findings], ["z", "a"])

    def test_duplicate_name_keeps_first(self):
        a1 = build(support.raw_rule("dup", order=1, action="ACCEPT"))
        a2 = build(support.raw_rule("dup", order=2, action="DROP", match_id="second"))
        b = build(support.raw_rule("dup", order=1, action="ACCEPT"), device="FW-WEST")
        with self.assertLogs("firemon_drift.compare", level="WARNING"):
            findings, *_ = compare.compare([a1, a2], [b])
        self.assertEqual(findings, [])


class ObjectModes(unittest.TestCase):
    def test_name_mode_treats_renamed_object_as_drift(self):
        a = build(support.raw_rule("r", sources=[support.host("WEB-EAST", "10.1.1.10/32")]))
        b = build(support.raw_rule("r", sources=[support.host("WEB-WEST", "10.1.1.10/32")]),
                  device="FW-WEST")
        findings, *_ = compare.compare([a], [b], object_mode="name")
        self.assertEqual([d.field for d in findings[0].diffs], ["sources"])

    def test_contents_mode_ignores_the_name(self):
        a = build(support.raw_rule("r", sources=[support.host("WEB-EAST", "10.1.1.10/32")]))
        b = build(support.raw_rule("r", sources=[support.host("WEB-WEST", "10.1.1.10/32")]),
                  device="FW-WEST")
        findings, *_ = compare.compare([a], [b], object_mode="contents")
        self.assertEqual(findings, [])

    def test_contents_mode_catches_same_name_different_members(self):
        east = support.group("SERVERS", [support.host("A", "10.0.0.1/32"),
                                        support.host("B", "10.0.0.2/32")])
        west = support.group("SERVERS", [support.host("A", "10.0.0.1/32")])
        a = build(support.raw_rule("r", sources=[east]))
        b = build(support.raw_rule("r", sources=[west]), device="FW-WEST")
        self.assertEqual(compare.compare([a], [b], object_mode="name")[0], [])
        findings, *_ = compare.compare([a], [b], object_mode="contents")
        diff = findings[0].diffs[0]
        self.assertEqual(diff.field, "sources")
        self.assertIn("10.0.0.2/32", diff.primary[0])

    def test_both_mode_needs_name_and_contents(self):
        a = build(support.raw_rule("r", sources=[support.host("WEB", "10.1.1.10/32")]))
        b = build(support.raw_rule("r", sources=[support.host("WEB", "10.1.1.11/32")]),
                  device="FW-WEST")
        self.assertEqual(compare.compare([a], [b], object_mode="name")[0], [])
        self.assertEqual(len(compare.compare([a], [b], object_mode="both")[0]), 1)

    def test_bad_mode_rejected(self):
        with self.assertRaises(ValueError):
            compare.compare([], [], object_mode="fuzzy")


class Normalisation(unittest.TestCase):
    def test_site_token_folded_away(self):
        norm = normalize.NameNormaliser([(r"(?i)\bUSE\b", "SITE"), (r"(?i)\bUSW\b", "SITE")])
        a = build(support.raw_rule("ALLOW-USE-VNET",
                                   sources=[support.network("KF-USE-PROD-VNET", "10.1.0.0/16")]),
                  normaliser=norm)
        b = build(support.raw_rule("ALLOW-USW-VNET",
                                   sources=[support.network("KF-USW-PROD-VNET", "10.2.0.0/16")]),
                  device="FW-WEST", normaliser=norm)
        self.assertEqual(a.key, b.key)
        findings, *_ = compare.compare([a], [b], object_mode="name")
        self.assertEqual(findings, [])
        # ...but in contents mode the different address range is still drift.
        findings, *_ = compare.compare([a], [b], object_mode="contents")
        self.assertEqual([d.field for d in findings[0].diffs], ["sources"])

    def test_case_insensitive_matching(self):
        norm = normalize.NameNormaliser([], case_insensitive=True)
        a = build(support.raw_rule("Allow-Web"), normaliser=norm)
        b = build(support.raw_rule("ALLOW-WEB"), device="FW-WEST", normaliser=norm)
        self.assertEqual(compare.compare([a], [b])[0], [])

    def test_bad_regex_rejected(self):
        with self.assertRaises(ValueError):
            normalize.NameNormaliser([("(unclosed", "x")])

    def test_describe(self):
        norm = normalize.NameNormaliser([(r"\bUSE\b", "")], case_insensitive=True)
        self.assertEqual(norm.describe(), [r"\bUSE\b -> (nothing)",
                                           "names compared case-insensitively"])


class PolicyScoping(unittest.TestCase):
    def test_same_name_in_different_policies_does_not_collide(self):
        a1 = build(support.raw_rule("allow", policy="Transit"), policy_key="Transit",
                   scope_key_by_policy=True)
        a2 = build(support.raw_rule("allow", policy="Prefilter", action="DROP",
                                    match_id="pf"), policy_key="Prefilter",
                   scope_key_by_policy=True)
        b1 = build(support.raw_rule("allow", policy="Transit West"), device="FW-WEST",
                   policy_key="Transit", scope_key_by_policy=True)
        findings, sa, sb, matched, identical = compare.compare([a1, a2], [b1])
        self.assertEqual(matched, 1)
        self.assertEqual([(f.kind, f.rule.policy) for f in findings],
                         [(ONLY_PRIMARY, "Prefilter")])

    def test_policy_name_only_compared_when_asked(self):
        a = build(support.raw_rule("r", policy="Transit East"))
        b = build(support.raw_rule("r", policy="Transit West"), device="FW-WEST")
        self.assertEqual(compare.compare([a], [b])[0], [])
        findings, *_ = compare.compare([a], [b], fields=("policy",))
        self.assertEqual(findings[0].diffs[0].secondary, ["Transit West"])


class Filters(unittest.TestCase):
    def _pair(self, comment_a="cat:AVD;", comment_b="cat:AVD;", props_a=None, props_b=None,
              name="r", apps_b=None):
        a = build(support.raw_rule(name, comment=comment_a))
        b = build(support.raw_rule(name, comment=comment_b, apps=apps_b), device="FW-WEST")
        if props_a:
            normalize.apply_props(a, props_a, "FMC ACP Category")
        if props_b:
            normalize.apply_props(b, props_b, "FMC ACP Category")
        return a, b

    def test_category_filter_scopes_by_either_side(self):
        a, b = self._pair("cat:ESO-DR;", "cat:ESO;")
        other_a = build(support.raw_rule("other", comment="cat:AVD;", order=2))
        flt = compare.RuleFilter(categories=["ESO-DR"])
        findings, sa, sb, matched, identical = compare.compare([a, other_a], [b], flt)
        # 'r' is in scope through its primary side and reports the category
        # drift; 'other' is out of scope so it is NOT reported as only-primary.
        self.assertEqual([(f.kind, f.name) for f in findings], [(CHANGED, "r")])
        self.assertEqual((sa, sb), (1, 1))

    def test_category_glob(self):
        a, b = self._pair("cat:KF-USE-PROD;", "cat:KF-USE-PROD;")
        self.assertTrue(compare.RuleFilter(categories=["kf-use-*"]).matches(a))
        self.assertFalse(compare.RuleFilter(categories=["kf-usw-*"]).matches(a))

    def test_category_property_wins_over_comment(self):
        a, _ = self._pair("cat:FROM-COMMENT;", props_a={"FMC ACP Category": "FROM-PROP"})
        self.assertEqual(a.category, "FROM-PROP")

    def test_change_request_matches_property_or_comment(self):
        a, b = self._pair("CHG0060157 opened ports", "nothing",
                          props_b={"Change Control Number (CR)": "chg0060157"})
        flt = compare.RuleFilter(change_requests=["CHG0060157"])
        self.assertTrue(flt.matches(a))
        self.assertTrue(flt.matches(b))
        self.assertFalse(compare.RuleFilter(change_requests=["CHG9999999"]).matches(a))

    def test_application_matches_property_or_app_object(self):
        a, b = self._pair(props_a={"Application Name": "Cisco Umbrella"},
                          apps_b=[support.named("Office 365")])
        self.assertTrue(compare.RuleFilter(applications=["cisco*"]).matches(a))
        self.assertTrue(compare.RuleFilter(applications=["Office 365"]).matches(b))
        self.assertFalse(compare.RuleFilter(applications=["Office 365"]).matches(a))

    def test_property_filter_is_case_insensitive_on_name(self):
        a, _ = self._pair(props_a={"Business Owner": "netops@example.com"})
        flt = compare.RuleFilter(properties={"business owner": ["NETOPS@*"]})
        self.assertTrue(flt.matches(a))
        self.assertFalse(compare.RuleFilter(properties={"Business Owner": ["security@*"]}).matches(a))
        # An unset property never matches.
        self.assertFalse(compare.RuleFilter(properties={"Nope": ["*"]}).matches(a))

    def test_criteria_are_anded(self):
        a, _ = self._pair("cat:AVD;", props_a={"Application Name": "Umbrella"})
        self.assertTrue(compare.RuleFilter(categories=["AVD"], applications=["Umbrella"]).matches(a))
        self.assertFalse(compare.RuleFilter(categories=["AVD"], applications=["Other"]).matches(a))

    def test_rule_name_glob_and_disabled(self):
        a = build(support.raw_rule("ALLOW_SAP_DB", disabled=True))
        self.assertTrue(compare.RuleFilter(rule_names=["allow_sap*"]).matches(a))
        self.assertFalse(compare.RuleFilter(rule_names=["deny*"]).matches(a))
        self.assertFalse(compare.RuleFilter(include_disabled=False).matches(a))

    def test_needs_ruledoc_and_describe(self):
        self.assertFalse(compare.RuleFilter(rule_names=["x"]).needs_ruledoc)
        self.assertTrue(compare.RuleFilter(change_requests=["x"]).needs_ruledoc)
        flt = compare.RuleFilter(categories=["AVD", "ESO"], change_requests=["CHG1"],
                                 include_disabled=False)
        self.assertEqual(flt.describe(), ["category: AVD, ESO", "change request: CHG1",
                                          "disabled rules excluded"])
        self.assertFalse(compare.RuleFilter().active)


class NewAndResolved(unittest.TestCase):
    def test_first_run_flags_nothing(self):
        a = build(support.raw_rule("r", action="ACCEPT"))
        b = build(support.raw_rule("r", action="DROP"), device="FW-WEST")
        findings, *_ = compare.compare([a], [b])
        resolved = compare.mark_new(findings, None)
        self.assertEqual(resolved, [])
        self.assertFalse(findings[0].new)

    def test_new_and_resolved_against_previous(self):
        a = build(support.raw_rule("r", action="ACCEPT"))
        b = build(support.raw_rule("r", action="DROP"), device="FW-WEST")
        only = build(support.raw_rule("gone", order=2))
        findings, *_ = compare.compare([a, only], [b])
        previous = ["changed|r|action", "only_primary|old-rule"]
        resolved = compare.mark_new(findings, previous)
        by_name = {f.name: f for f in findings}
        self.assertFalse(by_name["r"].new)       # seen last time
        self.assertTrue(by_name["gone"].new)     # not seen last time
        self.assertEqual(resolved, ["only_primary|old-rule"])
        self.assertEqual(compare.describe_fingerprint("only_primary|old-rule"),
                         "old-rule -- was only on primary")
        self.assertEqual(compare.describe_fingerprint("changed|Transit\x00r|services"),
                         "r (Transit) -- differed in services")

    def test_second_field_on_known_rule_is_new(self):
        a = build(support.raw_rule("r", action="ACCEPT", log=True))
        b = build(support.raw_rule("r", action="DROP", log=False), device="FW-WEST")
        findings, *_ = compare.compare([a], [b])
        compare.mark_new(findings, ["changed|r|action"])
        self.assertTrue(findings[0].new)


if __name__ == "__main__":
    unittest.main()
