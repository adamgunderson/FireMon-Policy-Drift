"""Flattening FireMon's rule JSON into Rule objects."""

import unittest

import support  # noqa: F401

from firemon_drift import normalize


class Flattening(unittest.TestCase):
    def setUp(self):
        self.norm = normalize.NameNormaliser()

    def test_group_contents_are_flattened_and_sorted(self):
        inner = support.group("INNER", [support.host("B", "10.0.0.2/32")])
        outer = support.group("OUTER", [support.host("A", "10.0.0.1/32"), inner])
        rule = normalize.build_rule(support.raw_rule("r", sources=[outer]), 1, "FW", self.norm)
        self.assertEqual(len(rule.sources), 1)
        self.assertEqual(rule.sources[0].name, "OUTER")
        self.assertEqual(rule.sources[0].contents, ("10.0.0.1/32", "10.0.0.2/32"))

    def test_any_objects_and_zones(self):
        rule = normalize.build_rule(support.raw_rule("r"), 1, "FW", self.norm)
        self.assertEqual(rule.sources[0].contents, ("any",))
        self.assertEqual(rule.services[0].contents, ("any",))
        self.assertEqual([z.name for z in rule.source_zones], ["any"])
        self.assertEqual(rule.summary(), "Any -> Any : Any")

    def test_service_contents(self):
        grp = support.group("WEB-PORTS", [support.service("HTTPS", "tcp", 443),
                                          support.service("HTTP", "tcp", 80)], kind="service")
        rng = support.service("HIGH", "udp", 1024, 2048)
        rule = normalize.build_rule(support.raw_rule("r", services=[grp, rng]), 1, "FW", self.norm)
        by_name = {s.name: s for s in rule.services}
        self.assertEqual(by_name["WEB-PORTS"].contents, ("tcp/443", "tcp/80"))
        self.assertEqual(by_name["HIGH"].contents, ("udp/1024-2048",))

    def test_zones_carry_interfaces(self):
        rule = normalize.build_rule(support.raw_rule("r", src_zones=["inside"]), 1, "FW", self.norm)
        self.assertEqual(rule.source_zones[0].raw_name, "inside")
        self.assertEqual(rule.source_zones[0].contents, ("Gig0/1-inside",))

    def test_exclusions_are_marked(self):
        raw = support.raw_rule("r", sources=[support.any_network()])
        raw["sourcesExclude"] = [support.host("BAD", "10.9.9.9/32")]
        rule = normalize.build_rule(raw, 1, "FW", self.norm)
        names = sorted(s.name for s in rule.sources)
        self.assertEqual(names, ["-BAD", "Any"])

    def test_scalars_and_category(self):
        raw = support.raw_rule("r", action="reject", disabled=True, log=False,
                               comment="cat:SECURITY;jst:Mandatory;", order=7)
        raw["srcNegated"] = True
        rule = normalize.build_rule(raw, 5, "FW", self.norm)
        self.assertEqual(rule.action, "REJECT")
        self.assertTrue(rule.disabled)
        self.assertFalse(rule.log)
        self.assertEqual(rule.order, 7)
        self.assertEqual(rule.category, "SECURITY")
        self.assertEqual(rule.negation["sources"], True)
        self.assertEqual(rule.device_id, 5)
        self.assertEqual(rule.match_id, "rule-r")

    def test_category_pattern_can_be_off(self):
        raw = support.raw_rule("r", comment="cat:SECURITY;")
        rule = normalize.build_rule(raw, 1, "FW", self.norm, category_pattern=None)
        self.assertEqual(rule.category, "")

    def test_fqdn_object_falls_back_to_name(self):
        fqdn = support.host("login.example.com", "")
        fqdn["addresses"] = []
        fqdn["networkType"] = "FQDN"
        rule = normalize.build_rule(support.raw_rule("r", destinations=[fqdn]), 1, "FW", self.norm)
        self.assertEqual(rule.destinations[0].contents, ("login.example.com",))

    def test_profile_group_members(self):
        member = {"name": "URL: a.example.com", "displayName": "a.example.com",
                  "matchId": "m1", "type": "SINGLE", "members": [],
                  "formattedName": "a.example.com: URL"}
        grp = {"name": "Group: URLS", "displayName": "URLS", "matchId": "g1",
               "type": "GROUP", "members": [member]}
        rule = normalize.build_rule(support.raw_rule("r", profiles=[grp]), 1, "FW", self.norm)
        self.assertEqual(rule.profiles[0].raw_name, "URLS")
        self.assertEqual(rule.profiles[0].contents, ("a.example.com: URL",))


class RuleDoc(unittest.TestCase):
    def test_parse_ruledoc_keeps_populated_values_only(self):
        doc = support.ruledoc("rule-r", **{"Business Owner": "netops@example.com",
                                           "Justification": None})
        doc["props"].append({"ruleId": "rule-r", "dateval": "2026-06-16T00:00:00.000Z",
                             "customProperty": {"name": "Review Date", "type": "DATE"}})
        doc["props"].append({"ruleId": "rule-r", "stringarray": ["a", "b"],
                             "customProperty": {"name": "Tags", "type": "STRING_ARRAY"}})
        props = normalize.parse_ruledoc(doc)
        self.assertEqual(props, {"Business Owner": "netops@example.com",
                                 "Review Date": "2026-06-16T00:00:00.000Z",
                                 "Tags": "a, b"})
        self.assertEqual(normalize.parse_ruledoc({}), {})
        self.assertEqual(normalize.parse_ruledoc(None), {})

    def test_apply_props_sets_category(self):
        rule = normalize.build_rule(support.raw_rule("r", comment="cat:X;"), 1, "FW",
                                    normalize.NameNormaliser())
        normalize.apply_props(rule, {"FMC ACP Category": "Y"}, "FMC ACP Category")
        self.assertEqual(rule.category, "Y")
        normalize.apply_props(rule, {}, "FMC ACP Category")
        self.assertEqual(rule.category, "Y")  # an absent property does not blank it


if __name__ == "__main__":
    unittest.main()
