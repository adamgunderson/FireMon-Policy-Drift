"""Shared test scaffolding: synthetic rules in the shape FireMon's secrule
search returns, and Config/Pair-shaped objects without the file I/O.

Everything here is invented. No customer names, addresses or objects.
"""

import logging
import os
import sys
from datetime import datetime, timezone

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS_DIR)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# The package logs warnings the tests deliberately provoke (no recipients, a
# world-readable config); without a handler Python's last-resort handler
# prints them between the dots. assertLogs still captures them.
logging.getLogger("firemon_drift").addHandler(logging.NullHandler())

RUN_TIME = datetime(2026, 9, 18, 6, 0, 0, tzinfo=timezone.utc)


def host(name, address):
    return {
        "name": name, "displayName": name, "matchId": "net-" + name, "type": "SINGLE",
        "networkType": "HOST", "members": [], "membersExclude": [],
        "addresses": [{"type": "IPV4", "address": address, "objectType": "HOST"}],
        "addressesExclude": [], "negate": False,
    }


def network(name, cidr):
    obj = host(name, cidr)
    obj["networkType"] = "NETWORK"
    obj["addresses"][0]["objectType"] = "NETWORK"
    return obj


def group(name, members, kind="network"):
    obj = {
        "name": name, "displayName": name, "matchId": "grp-" + name, "type": "GROUP",
        "members": members, "membersExclude": [], "negate": False,
    }
    if kind == "network":
        obj["networkType"] = "GROUP"
        obj["addresses"] = []
        obj["addressesExclude"] = []
    else:
        obj["services"] = []
        obj["servicesExclude"] = []
    return obj


def any_network():
    return {"name": "Any", "displayName": "Any", "matchId": "any-net", "type": "ANY",
            "networkType": "ANY", "members": [], "addresses": [], "negate": False}


def any_service():
    return {"name": "Any", "displayName": "Any", "matchId": "any-svc", "type": "ANY",
            "members": [], "services": [], "negate": False}


def service(name, proto, port, end=None):
    return {
        "name": name, "displayName": name, "matchId": "svc-" + name, "type": "SINGLE",
        "members": [], "membersExclude": [], "servicesExclude": [], "negate": False,
        "services": [{"type": proto.upper(), "protocol": 6 if proto == "tcp" else 17,
                      "startPort": port, "endPort": end or port,
                      "formattedValue": "%s/%s" % (proto, port) if not end
                      else "%s/%s-%s" % (proto, port, end)}],
    }


def named(name, kind="app"):
    return {"name": name, "displayName": name, "matchId": "%s-%s" % (kind, name),
            "type": "SINGLE", "members": []}


def zone(name):
    return {"name": name, "displayName": name, "matchId": "zone-" + name, "type": "SINGLE",
            "interfaces": [{"name": "Gig0/1-" + name, "displayName": "Gig0/1-" + name}]}


def raw_rule(name, policy="Transit East", order=1, action="ACCEPT", disabled=False,
             log=True, sources=None, destinations=None, services=None, apps=None,
             profiles=None, src_zones=None, dst_zones=None, comment="",
             match_id=None, **extra):
    rule = {
        "name": "vendor-" + name, "displayName": name, "ruleName": name,
        "matchId": match_id or "rule-" + name, "vendorIdentifier": "vendor-" + name,
        "ruleOrder": order, "ruleNumber": order, "disabled": disabled, "log": log,
        "ruleAction": action, "commentText": comment,
        "policy": {"name": policy, "displayName": policy, "matchId": "pol-" + policy},
        "sources": sources if sources is not None else [any_network()],
        "destinations": destinations if destinations is not None else [any_network()],
        "services": services if services is not None else [any_service()],
        "sourcesExclude": [], "destinationsExclude": [], "servicesExclude": [],
        "apps": apps or [], "users": [], "urlMatchers": [], "profiles": profiles or [],
        "schedules": [],
        "srcContext": {"zones": [zone(z) for z in src_zones], "intfs": [], "any": False}
        if src_zones else {"zones": [], "intfs": [], "any": True},
        "dstContext": {"zones": [zone(z) for z in dst_zones], "intfs": [], "any": False}
        if dst_zones else {"zones": [], "intfs": [], "any": True},
        "srcNegated": False, "dstNegated": False, "svcNegated": False,
        "userNegated": False, "appNegated": False,
        "lastChanged": "2026-09-01T10:00:00.000Z",
    }
    rule.update(extra)
    return rule


def ruledoc(match_id, **props):
    """A rule-doc response holding the given string properties."""
    out = {"ruleId": match_id, "props": []}
    for name, value in props.items():
        entry = {"ruleId": match_id,
                 "customProperty": {"name": name, "key": name.lower().replace(" ", "_"),
                                    "type": "STRING"}}
        if value is not None:
            entry["stringval"] = value
        out["props"].append(entry)
    return out


class FakePair:
    """A PairConfig-shaped object."""

    def __init__(self, **overrides):
        from firemon_drift.model import DEFAULT_FIELDS
        self.name = "default"
        self.primary = "FW-EAST"
        self.secondary = "FW-WEST"
        self.primary_label = ""
        self.secondary_label = ""
        self.policy_pairs = []
        self.fields = DEFAULT_FIELDS
        self.object_mode = "name"
        self.match_by = "name"
        self.normalise_rules = []
        self.categories = []
        self.change_requests = []
        self.applications = []
        self.rule_names = []
        self.include_disabled = True
        self.properties = {}
        self.recipients = ["netops@example.com"]
        self.send_when = "drift"
        self.subject_prefix = ""
        for key, value in overrides.items():
            setattr(self, key, value)


class FakeConfig:
    """Only the attributes the units under test read."""

    def __init__(self, **overrides):
        self.base_url = "https://firemon.example.com"
        self.domain_id = 1
        self.match_case_insensitive = False
        self.match_by = "name"
        self.max_revision_skew_hours = 24
        self.category_property = "FMC ACP Category"
        self.category_comment_pattern = r"cat:\s*([^;]*?)\s*;"
        self.fetch_ruledoc = "auto"
        self.cr_property = "Change Control Number (CR)"
        self.application_property = "Application Name"
        self.attach_csv = True
        self.attach_json = False
        self.max_rows = 50
        self.max_diff_rules = 30
        self.portal_url = "https://firemon.example.com/securitymanager/"
        self.support_email = "netops@example.com"
        self.from_name = "FireMon Policy Drift Monitor"
        self.from_address = "noreply@example.com"
        self.reply_to = ""
        self.smtp_host = "localhost"
        self.smtp_port = 25
        self.smtp_starttls = False
        self.smtp_username = ""
        self.smtp_password = ""
        self.smtp_timeout = 5
        self.template_dir = os.path.join(ROOT, "templates")
        self.output_dir = os.path.join(ROOT, "out")
        self.state_dir = os.path.join(ROOT, "state")
        self.pairs = [FakePair()]
        for key, value in overrides.items():
            setattr(self, key, value)
