"""Command line entry point and run orchestration.

One run authenticates once and then works through every configured pair (or
the ones named with --pair). Each pair is compared, reported and mailed on
its own, with its own recipients and its own last-run state; a pair that
fails -- a device renamed, say -- is reported and the others still run.
"""

import argparse
import logging
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone

from . import __version__, api, compare as compare_module, config as config_module
from . import normalize, state as state_module
from .mailer import Mailer
from .model import MATCH_MODES, DeviceInfo, DriftReport, describe_skew
from .render import RenderError, Renderer

LOG = logging.getLogger("firemon_drift")

EXIT_OK = 0          # ran, no drift on any pair
EXIT_FATAL = 1       # configuration or authentication failure, or a pair failed
EXIT_SEND_FAILED = 2 # compared fine, an email could not be sent
EXIT_DRIFT = 3       # ran, drift found on at least one pair


def build_parser():
    parser = argparse.ArgumentParser(
        prog="run_drift.py",
        description=(
            "Compare the security rules of paired firewalls in FireMon and report "
            "the drift: rules on one side only, and rules on both whose "
            "criteria differ. One report per pair, optionally emailed."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "First run:\n"
            "  python3 run_drift.py --config config.ini --list-devices FTDV\n"
            "  python3 run_drift.py --config config.ini --list-policies\n"
            "  python3 run_drift.py --config config.ini --dry-run --print\n\n"
            "One pair, narrowed to a change request, mailed to yourself:\n"
            "  python3 run_drift.py --config config.ini --pair us-dr --cr CHG0060157 "
            "--to-override you@example.com\n\n"
            "Exit codes: 0 no drift, 1 failed, 2 email not sent, 3 drift found.\n"
        ),
    )
    parser.add_argument("--config", required=True, help="path to config.ini")
    parser.add_argument("--dry-run", action="store_true",
                        help="render the reports to the output directory; send nothing, "
                             "and leave the last-run state alone")
    parser.add_argument("--print", action="store_true", dest="print_report",
                        help="print each plain-text report to stdout")
    parser.add_argument("--to-override", metavar="ADDR",
                        help="send every report to ADDR instead of the configured recipients")
    parser.add_argument("--send-when", choices=config_module.SEND_WHEN,
                        help="override send_when for every pair this run")
    parser.add_argument("--json", metavar="PATH",
                        help="also write the findings as JSON to PATH (one pair) or "
                             "PATH with the pair name inserted (several)")
    parser.add_argument("--update-state", action="store_true",
                        help="record this run's findings as the baseline even under --dry-run")

    scope = parser.add_argument_group("scope overrides (take precedence over config.ini)")
    scope.add_argument("--pair", action="append", default=[], metavar="NAME",
                       help="run only this configured pair (repeatable)")
    scope.add_argument("--primary", metavar="DEVICE",
                       help="with --secondary: compare this ad-hoc pair instead of the configured ones")
    scope.add_argument("--secondary", metavar="DEVICE")
    scope.add_argument("--policy", action="append", default=[], metavar="A[=B]",
                       help="compare policy A on the primary with B on the secondary "
                            "(repeatable; B defaults to A). Replaces the pairs' policies.")
    scope.add_argument("--all-policies", action="store_true",
                       help="ignore configured policies and compare every rule on each device")
    scope.add_argument("--category", action="append", default=[], metavar="GLOB",
                       help="only rules in this category (repeatable; replaces the config value)")
    scope.add_argument("--cr", action="append", default=[], metavar="TEXT",
                       help="only rules whose CR property or comment contains TEXT (repeatable)")
    scope.add_argument("--application", action="append", default=[], metavar="GLOB",
                       help="only rules whose application property or application objects match")
    scope.add_argument("--rule-name", action="append", default=[], metavar="GLOB",
                       help="only rules whose name matches (repeatable)")
    scope.add_argument("--property", action="append", default=[], metavar="NAME=GLOB",
                       help="only rules whose rule-doc property NAME matches GLOB (repeatable)")
    scope.add_argument("--fields", metavar="LIST",
                       help="fields to compare: default, all, or a comma list")
    scope.add_argument("--object-mode", choices=compare_module.OBJECT_MODES,
                       help="compare objects by name, contents, or both")
    scope.add_argument("--match-by", choices=MATCH_MODES,
                       help="pair rules across the two sides by name, or by the vendor's "
                            "rule id (vendor_id: right for an HA pair or two devices sharing "
                            "one policy from the same manager; a rename then reads as a rename)")
    scope.add_argument("--exclude-disabled", action="store_true",
                       help="leave disabled rules out of the comparison")
    scope.add_argument("--no-categories", action="store_true",
                       help="leave categories out: not read, compared, filtered on or shown "
                            "(as [compare] compare_categories = false)")

    diag = parser.add_argument_group("diagnostics (read-only, then exit)")
    diag.add_argument("--list-pairs", action="store_true",
                      help="list the configured pairs with their scope and recipients")
    diag.add_argument("--list-devices", nargs="?", const="", metavar="PATTERN",
                      help="list firewall devices whose name contains PATTERN")
    diag.add_argument("--list-policies", action="store_true",
                      help="list the policies on each device of each pair")
    diag.add_argument("--list-properties", action="store_true",
                      help="list rule-doc properties and categories in use on each pair, "
                           "with counts -- use it to choose filters")

    parser.add_argument("--no-csv", action="store_true", help="do not attach the CSV")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--version", action="version", version="firemon-drift %s" % __version__)
    return parser


def make_output_encoding_safe():
    """cron hands a job the POSIX locale, so stdout may be ASCII; a rule name
    with a non-ASCII character must not turn a finished run into a traceback."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


def setup_logging(level, log_file):
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    for handler in list(root.handlers):
        root.removeHandler(handler)
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(getattr(logging, level))
    console.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))
    root.addHandler(console)
    if log_file:
        try:
            os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
            handler = logging.FileHandler(log_file, encoding="utf-8")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)-8s %(name)s %(message)s"))
            root.addHandler(handler)
        except OSError as exc:
            LOG.warning("could not open log file %s: %s", log_file, exc)


def _select_pairs(cfg, args):
    """The pairs this run covers, after --pair / --primary / --secondary."""
    if args.primary or args.secondary:
        if not (args.primary and args.secondary):
            raise config_module.ConfigError("--primary and --secondary go together")
        if args.primary.strip().lower() == args.secondary.strip().lower():
            raise config_module.ConfigError("primary and secondary are the same device")
        if args.pair:
            raise config_module.ConfigError("--pair cannot be combined with --primary/--secondary")
        return [config_module.PairConfig(
            name="adhoc", primary=args.primary.strip(), secondary=args.secondary.strip(),
            policy_pairs=list(cfg.policy_pairs), fields=cfg.fields,
            object_mode=cfg.object_mode, match_by=cfg.match_by,
            normalise_rules=list(cfg.normalise_rules),
            categories=list(cfg.filter_categories),
            change_requests=list(cfg.filter_change_requests),
            applications=list(cfg.filter_applications),
            rule_names=list(cfg.filter_rule_names), include_disabled=cfg.include_disabled,
            properties=dict(cfg.filter_properties), recipients=list(cfg.recipients),
            send_when=cfg.send_when, subject_prefix=cfg.subject_prefix,
        )]
    if not args.pair:
        return list(cfg.pairs)
    chosen = []
    for name in args.pair:
        pair = cfg.pair(name)
        if pair is None:
            configured = ", ".join(p.name for p in cfg.pairs) or "(none configured)"
            raise config_module.ConfigError(
                "no pair named %r. Configured: %s" % (name, configured))
        if pair not in chosen:
            chosen.append(pair)
    return chosen


def _apply_overrides(cfg, pairs, args):
    """Command-line scope flags replace the matching setting on every
    selected pair."""
    props = None
    if args.property:
        props = {}
        for item in args.property:
            name, sep, value = item.partition("=")
            if not sep or not name.strip():
                raise config_module.ConfigError("--property needs NAME=GLOB (got %r)" % item)
            props.setdefault(name.strip(), []).extend(config_module.split_list(value))
    policy_pairs = None
    if args.policy:
        policy_pairs = []
        for item in args.policy:
            a, _, b = item.partition("=")
            a, b = a.strip(), b.strip()
            if not a:
                raise config_module.ConfigError("--policy needs a policy name")
            policy_pairs.append((a, b or a))
    fields = config_module.parse_fields(args.fields) if args.fields else None

    for pair in pairs:
        if args.all_policies:
            pair.policy_pairs = []
        if policy_pairs is not None:
            pair.policy_pairs = list(policy_pairs)
        if args.category:
            pair.categories = [c for c in args.category if c.strip()]
        if args.cr:
            pair.change_requests = [c for c in args.cr if c.strip()]
        if args.application:
            pair.applications = [c for c in args.application if c.strip()]
        if args.rule_name:
            pair.rule_names = [c for c in args.rule_name if c.strip()]
        if props is not None:
            pair.properties = dict(props)
        if fields is not None:
            pair.fields = fields
        if args.object_mode:
            pair.object_mode = args.object_mode
        if args.match_by:
            pair.match_by = args.match_by
        if args.exclude_disabled:
            pair.include_disabled = False
        if args.send_when:
            pair.send_when = args.send_when
    if args.no_csv:
        cfg.attach_csv = False
    if getattr(args, "no_categories", False):
        cfg.compare_categories = False
    _apply_category_switch(cfg, pairs)


def _apply_category_switch(cfg, pairs):
    """compare_categories = false: no category is read (so no rule
    documentation is fetched for it), compared or filtered on, and the report
    leaves the Category column out."""
    if cfg.compare_categories:
        return
    cfg.category_property = ""
    cfg.category_comment_pattern = ""
    for pair in pairs:
        fields = tuple(f for f in pair.fields if f != "category")
        if not fields:
            raise config_module.ConfigError(
                "[%s] no fields left to compare once category is excluded" % pair.name)
        pair.fields = fields
        if pair.categories:
            LOG.warning("[%s] categories are not compared; ignoring the category filter (%s)",
                        pair.name, ", ".join(pair.categories))
            pair.categories = []


def _build_filter(cfg, pair) -> compare_module.RuleFilter:
    return compare_module.RuleFilter(
        categories=pair.categories,
        change_requests=pair.change_requests,
        applications=pair.applications,
        rule_names=pair.rule_names,
        properties=pair.properties,
        include_disabled=pair.include_disabled,
        cr_property=cfg.cr_property,
        application_property=cfg.application_property,
    )


# -- diagnostics --------------------------------------------------------------

def _print_pairs(pairs):
    print("")
    if not pairs:
        print("No firewall pairs are configured yet.")
        print("Add [pair] primary/secondary, or one or more [pair:NAME] sections.")
        print("")
        return
    print("Configured pairs (%d):" % len(pairs))
    for pair in pairs:
        print("")
        print("  %s" % pair.name)
        print("    primary:    %s%s" % (pair.primary, (" (%s)" % pair.primary_label) if pair.primary_label else ""))
        print("    secondary:  %s%s" % (pair.secondary, (" (%s)" % pair.secondary_label) if pair.secondary_label else ""))
        if pair.policy_pairs:
            for a, b in pair.policy_pairs:
                print("    policy:     %s = %s" % (a, b))
        else:
            print("    policy:     every policy on each device")
        scope = compare_module.RuleFilter(
            categories=pair.categories, change_requests=pair.change_requests,
            applications=pair.applications, rule_names=pair.rule_names,
            properties=pair.properties, include_disabled=pair.include_disabled)
        for line in scope.describe() or ["every rule"]:
            print("    filter:     %s" % line)
        print("    matching:   rules by %s, objects by %s"
              % ("vendor rule id (name as fallback)" if pair.match_by == "vendor_id" else "name",
                 pair.object_mode))
        print("    recipients: %s" % (", ".join(pair.recipients) or "(none -- written to out/ only)"))
        print("    send_when:  %s" % pair.send_when)
    print("")


def _print_devices(client, pattern):
    devices = [d for d in client.list_devices(pattern or None)
               if (d["type"] or "").upper() in ("FIREWALL", "")]
    print("")
    if not devices:
        print("No firewall devices%s." % ((" matching %r" % pattern) if pattern else ""))
        return
    print("Firewall devices%s (%d):" % ((" matching %r" % pattern) if pattern else "", len(devices)))
    print("  %6s  %-40s %-22s %s" % ("ID", "NAME", "PRODUCT", "MANAGEMENT IP"))
    print("  %s  %s %s %s" % ("-" * 6, "-" * 40, "-" * 22, "-" * 15))
    for d in devices:
        print("  %6s  %-40s %-22s %s" % (d["id"], d["name"][:40],
                                         ("%s %s" % (d["vendor"], d["product"])).strip()[:22],
                                         d["managementIp"]))
    print("")
    print("Put the primary and secondary NAMES (or ids) in a [pair:NAME] section of config.ini.")
    print("")


def _print_policies(client, pair, primary, secondary):
    print("")
    print("Pair %s" % pair.name)
    for label, device in (("Primary", primary), ("Secondary", secondary)):
        policies = client.list_policies(device["id"])
        print("  %s: %s (id %s) -- %d %s" % (label, device["name"], device["id"],
                                             len(policies), "policy" if len(policies) == 1 else "policies"))
        for p in policies:
            alias = ""
            if p["name"] and p["name"] != p["displayName"]:
                alias = "   (vendor id %s)" % p["name"]
            print("    %6d rules  %s%s" % (p["ruleCount"], p["displayName"], alias))
    print("")


def _print_properties(pair, rules_a, rules_b, label_a, label_b, categories_on=True):
    print("")
    print("Pair %s" % pair.name)
    for label, rules in ((label_a, rules_a), (label_b, rules_b)):
        counts = Counter()
        values = {}
        categories = Counter(r.category or "(none)" for r in rules)
        for rule in rules:
            for name, value in rule.props.items():
                counts[name] += 1
                values.setdefault(name, Counter())[value] += 1
        print("%s -- %d rules" % (label, len(rules)))
        if categories_on:
            print("  Categories (%d):" % len(categories))
            for name, n in categories.most_common(25):
                print("    %5d  %s" % (n, name))
            if len(categories) > 25:
                print("    ... and %d more" % (len(categories) - 25))
        print("  Rule-doc properties with a value:")
        if not counts:
            print("    (none -- rule documentation was not fetched or is empty)")
        for name, n in counts.most_common():
            top = ", ".join("%s (%d)" % (v[:30], c) for v, c in values[name].most_common(4))
            print("    %5d  %-32s %s" % (n, name, top))
        print("")


# -- one pair -----------------------------------------------------------------

def _policy_key_map(pair):
    mapping = {}
    for a, b in pair.policy_pairs:
        mapping[b.strip().lower()] = a
        mapping[a.strip().lower()] = a
    return mapping


def _load_side(client, cfg, pair, device, side, normaliser):
    policy_names = None
    if pair.policy_pairs:
        policy_names = [a if side == "primary" else b for a, b in pair.policy_pairs]
        policy_names = list(dict.fromkeys(policy_names))
    raw_rules = client.fetch_rules(device["id"], device["name"], policy_names)
    rev_id, rev_date = client.latest_revision(device["id"])
    info = DeviceInfo(id=device["id"], name=device["name"], revision_id=rev_id,
                      revision_date=rev_date, rule_total=len(raw_rules))

    key_map = _policy_key_map(pair)
    rules = []
    for raw in raw_rules:
        policy = raw.get("policy") or {}
        policy_key = ""
        if pair.policy_pairs:
            for candidate in ((policy.get("displayName") or ""), (policy.get("name") or "")):
                if candidate.strip().lower() in key_map:
                    policy_key = key_map[candidate.strip().lower()]
                    break
            if not policy_key:
                continue
        rules.append(normalize.build_rule(
            raw, device["id"], device["name"], normaliser,
            policy_key=policy_key, scope_key_by_policy=bool(pair.policy_pairs),
            category_pattern=cfg.category_comment_pattern or None,
            match_by=pair.match_by))
    LOG.info("[%s] %s: %d rules%s", pair.name, device["name"], len(rules),
             (" in %d paired %s" % (len(pair.policy_pairs),
                                    "policy" if len(pair.policy_pairs) == 1 else "policies"))
             if pair.policy_pairs else "")
    return rules, info


def _attach_ruledocs(client, cfg, device, rules):
    docs = client.fetch_ruledocs(device["id"], device["name"], [r.match_id for r in rules])
    for rule in rules:
        props = normalize.parse_ruledoc(docs.get(rule.match_id) or {})
        normalize.apply_props(rule, props, cfg.category_property)


class PairOutcome:
    def __init__(self, pair):
        self.pair = pair
        self.report = None
        self.error = None
        self.send_result = None
        self.subject = ""
        self.skipped_send_reason = ""

    @property
    def failed(self):
        return self.error is not None


def _run_pair(client, cfg, pair, args, run_time, run_id, want_lists) -> PairOutcome:
    outcome = PairOutcome(pair)
    normaliser = normalize.NameNormaliser(pair.normalise_rules, cfg.match_case_insensitive)

    primary = client.get_device(pair.primary)
    secondary = client.get_device(pair.secondary)
    if primary["id"] == secondary["id"]:
        raise api.ApiError("primary and secondary resolve to the same device (%s)" % primary["name"])
    if args.list_policies:
        _print_policies(client, pair, primary, secondary)
        return outcome

    rules_a, info_a = _load_side(client, cfg, pair, primary, "primary", normaliser)
    rules_b, info_b = _load_side(client, cfg, pair, secondary, "secondary", normaliser)

    rule_filter = _build_filter(cfg, pair)
    want_docs = (cfg.fetch_ruledoc == "always" or args.list_properties or
                 (cfg.fetch_ruledoc == "auto" and
                  (rule_filter.needs_ruledoc or pair.needs_ruledoc_for_compare)))
    if want_docs:
        _attach_ruledocs(client, cfg, primary, rules_a)
        _attach_ruledocs(client, cfg, secondary, rules_b)
    elif cfg.fetch_ruledoc == "auto" and cfg.category_property:
        # The category is parsed from the comment where FMC wrote it there;
        # a rule with an empty comment still has a category in its rule-doc
        # property, so fetch the doc for just those rules.
        for device, rules in ((primary, rules_a), (secondary, rules_b)):
            gaps = [r for r in rules if not r.category]
            if gaps:
                LOG.info("[%s] %s: %d of %d rules carry no category in their comment; "
                         "reading it from rule documentation", pair.name, device["name"],
                         len(gaps), len(rules))
                _attach_ruledocs(client, cfg, device, gaps)

    if args.list_properties:
        _print_properties(pair, rules_a, rules_b, primary["name"], secondary["name"],
                          categories_on=cfg.compare_categories)
        return outcome

    if not rules_a and not rules_b:
        raise api.ApiError("neither device returned any rules in scope -- check the "
                           "pair's policies against --list-policies")

    findings, scope_a, scope_b, matched, identical = compare_module.compare(
        rules_a, rules_b, rule_filter, pair.fields, pair.object_mode, pair.match_by)
    info_a.in_scope, info_b.in_scope = scope_a, scope_b

    state_path = state_module.state_path(cfg.state_dir, pair.name)
    previous, previous_time = state_module.load_previous(state_path)
    resolved = compare_module.mark_new(findings, previous)

    report = DriftReport(
        primary=info_a, secondary=info_b, generated_at=run_time, findings=findings,
        matched=matched, identical=identical, fields=pair.fields,
        object_mode=pair.object_mode, policy_pairs=list(pair.policy_pairs),
        filter_lines=rule_filter.describe(), normalise_lines=normaliser.describe(),
        resolved=resolved, resolved_labels=state_module.load_labels(state_path),
        previous_run=previous_time, ruledoc_fetched=want_docs,
        categories=cfg.compare_categories,
        pair_name=pair.name, match_by=pair.match_by,
        max_revision_skew_hours=cfg.max_revision_skew_hours,
    )
    outcome.report = report
    if report.revisions_stale:
        LOG.warning(
            "[%s] the configurations FireMon holds for %s (%s) and %s (%s) were "
            "retrieved %s apart. Findings may be retrieval lag, not policy drift: "
            "check that FireMon has retrieved the %s's current configuration.",
            pair.name, info_a.name, info_a.revision_date or "unknown",
            info_b.name, info_b.revision_date or "unknown",
            describe_skew(report.revision_skew_hours()), report.older_side)

    renderer = Renderer(cfg, pair, report)
    subject, html_body, text_body = renderer.render()
    outcome.subject = subject

    if args.json:
        path = args.json
        if want_lists > 1:
            root, ext = os.path.splitext(path)
            path = "%s-%s%s" % (root, _slug(pair.name), ext or ".json")
        with open(path, "wb") as handle:
            handle.write(renderer.json_bytes())
        LOG.info("[%s] findings written to %s", pair.name, path)

    if args.print_report:
        print(text_body)

    should_send = {
        "never": False,
        "always": True,
        "drift": report.has_drift,
        "changes": bool(report.new_count or report.resolved),
    }[pair.send_when]
    mailer = Mailer(cfg, "%s-%s" % (_slug(pair.name), run_id),
                    dry_run=args.dry_run, to_override=args.to_override)
    if args.dry_run or should_send:
        outcome.send_result = mailer.deliver(pair.recipients, subject, html_body, text_body,
                                             renderer.attachments())
    else:
        outcome.skipped_send_reason = (
            "send_when=%s and %s" % (pair.send_when,
                                     "no drift was found" if pair.send_when == "drift"
                                     else "nothing changed"))
        LOG.info("[%s] not sending: %s", pair.name, outcome.skipped_send_reason)

    if not args.dry_run or args.update_state:
        try:
            state_module.save(state_path, report.fingerprints(), run_time, {
                "only_primary": len(report.only_primary),
                "only_secondary": len(report.only_secondary),
                "changed": len(report.changed),
            }, labels=report.labels())
        except OSError as exc:
            LOG.warning("[%s] could not write state file %s: %s", pair.name, state_path, exc)
    return outcome


_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _slug(value) -> str:
    return _UNSAFE.sub("_", str(value)).strip("_") or "pair"


# -- the run ------------------------------------------------------------------

def run(args) -> int:
    try:
        cfg = config_module.load(args.config)
    except config_module.ConfigError as exc:
        print("Configuration error: %s" % exc, file=sys.stderr)
        return EXIT_FATAL

    setup_logging(args.log_level, cfg.log_file)
    try:
        pairs = _select_pairs(cfg, args)
        _apply_overrides(cfg, pairs, args)
        for pair in pairs:
            normalize.NameNormaliser(pair.normalise_rules, cfg.match_case_insensitive)
    except (config_module.ConfigError, ValueError) as exc:
        LOG.error("Configuration error: %s", exc)
        return EXIT_FATAL

    if args.list_pairs:
        _print_pairs(pairs)
        return EXIT_OK

    run_time = datetime.now(timezone.utc)
    run_id = run_time.strftime("%Y%m%dT%H%M%SZ")

    client = api.FireMonClient(cfg)
    try:
        client.authenticate()
        if args.list_devices is not None:
            _print_devices(client, args.list_devices)
            return EXIT_OK
    except api.ApiError as exc:
        LOG.error("%s", exc)
        return EXIT_FATAL

    # Past this point every path needs at least one pair to work with.
    # --list-devices (above) and --list-pairs (before authentication) are
    # the only operations that don't, and both already returned.
    if not pairs:
        LOG.error(
            "no firewall pair is configured. Add primary/secondary to [pair], "
            "add one or more [pair:NAME] sections, or pass --primary/--secondary."
        )
        return EXIT_FATAL

    outcomes = []
    for pair in pairs:
        outcome = PairOutcome(pair)
        try:
            outcome = _run_pair(client, cfg, pair, args, run_time, run_id, len(pairs))
        except (api.ApiError, RenderError, OSError) as exc:
            outcome.error = str(exc)
            LOG.error("[%s] %s", pair.name, exc)
        outcomes.append(outcome)

    if args.list_policies or args.list_properties:
        failed = [o for o in outcomes if o.failed]
        return EXIT_FATAL if failed else EXIT_OK

    _print_summary(outcomes, cfg, args.dry_run)

    if any(o.failed for o in outcomes):
        return EXIT_FATAL
    if any(o.send_result is not None and not o.send_result.sent for o in outcomes):
        return EXIT_SEND_FAILED
    if any(o.report is not None and o.report.has_drift for o in outcomes):
        return EXIT_DRIFT
    return EXIT_OK


def _print_summary(outcomes, cfg, dry_run):
    print("")
    print("=" * 72)
    print("Policy drift -- %d %s   (%s)" % (len(outcomes), "pair" if len(outcomes) == 1 else "pairs",
                                            "DRY RUN" if dry_run else "LIVE"))
    print("=" * 72)
    for o in outcomes:
        print("")
        print("[%s]  %s  vs  %s" % (o.pair.name, o.pair.primary, o.pair.secondary))
        if o.failed:
            print("  FAILED            : %s" % o.error)
            continue
        r = o.report
        print("  Rules retrieved   : %d / %d   in scope: %d / %d" % (
            r.primary.rule_total, r.secondary.rule_total, r.primary.in_scope, r.secondary.in_scope))
        print("  Config as of      : %s / %s" % (
            _short_date(r.primary.revision_date), _short_date(r.secondary.revision_date)))
        if r.revisions_stale:
            print("  WARNING           : configurations retrieved %s apart -- findings may "
                  "be retrieval lag, not drift" % describe_skew(r.revision_skew_hours()))
        print("  Matched           : %d   identical: %d" % (r.matched, r.identical))
        print("  Differ            : %d   only primary: %d   only secondary: %d" % (
            len(r.changed), len(r.only_primary), len(r.only_secondary)))
        if r.previous_run is not None:
            print("  New / resolved    : %d / %d   (since %s)" % (
                r.new_count, len(r.resolved), r.previous_run))
        else:
            print("  New / resolved    : first run -- nothing to compare against yet")
        if o.send_result is None:
            print("  Email             : not sent (%s)" % o.skipped_send_reason)
        elif o.send_result.dry_run:
            print("  Email             : rendered to %s (dry run)" % cfg.output_dir)
        elif o.send_result.sent:
            print("  Email             : accepted by the relay for %s"
                  % ", ".join(o.send_result.actual_recipients))
        else:
            print("  Email             : FAILED -- %s" % o.send_result.error)
        print("  Subject           : %s" % o.subject)
    print("")


def _short_date(value) -> str:
    match = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})", str(value or ""))
    return "%s %s UTC" % (match.group(1), match.group(2)) if match else "unknown"


def main(argv=None) -> int:
    make_output_encoding_safe()
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_FATAL
