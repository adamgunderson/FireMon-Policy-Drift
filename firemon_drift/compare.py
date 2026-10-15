"""The comparison itself, and the rule filters that scope it.

Pure functions over Rule objects: no I/O, no server, so every behaviour here
is covered by the unit tests against synthetic rules.

Matching is by rule name (normalised), scoped to a policy pair when the
config lists pairs. Two rules with the same key are compared field by field;
a key present on one side only is a finding of its own.

Filters decide which rules are IN SCOPE. A key is in scope when the rule on
EITHER side matches -- so a rule whose category was changed on one site still
shows up (as a category difference) when the report is filtered to that
category, rather than silently dropping out of one side and appearing as
"missing".
"""

import fnmatch
import logging
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .model import (
    CHANGED,
    DEFAULT_FIELDS,
    LIST_FIELDS,
    MATCH_MODES,
    ONLY_PRIMARY,
    ONLY_SECONDARY,
    DriftReport,
    FieldDiff,
    Finding,
    ObjectRef,
    Rule,
)

LOG = logging.getLogger(__name__)

OBJECT_MODES = ("name", "contents", "both")


# -- filters ------------------------------------------------------------------

def _globs(values: Iterable[str]) -> List[str]:
    return [v.strip() for v in values if v and v.strip()]


def _glob_match(value: str, patterns: Sequence[str]) -> bool:
    value = (value or "").strip().lower()
    for pattern in patterns:
        pattern = pattern.lower()
        if fnmatch.fnmatchcase(value, pattern):
            return True
    return False


def _contains_any(value: str, needles: Sequence[str]) -> bool:
    value = (value or "").lower()
    return any(n.lower() in value for n in needles if n)


class RuleFilter:
    """Which rules the report covers. Every configured criterion must match
    (AND across criteria); within one criterion any listed value will do (OR).

    Values are shell-style globs, case-insensitive: `AVD`, `KF-USE-*`,
    `*restricted*`. Change-request values are substrings, since a CR number
    is usually buried in a longer comment.
    """

    def __init__(self, categories=(), change_requests=(), applications=(),
                 rule_names=(), properties: Optional[Dict[str, Sequence[str]]] = None,
                 policies_only=(), include_disabled=True,
                 cr_property="Change Control Number (CR)",
                 application_property="Application Name"):
        self.categories = _globs(categories)
        self.change_requests = _globs(change_requests)
        self.applications = _globs(applications)
        self.rule_names = _globs(rule_names)
        self.properties = {
            name: _globs(values) for name, values in (properties or {}).items()
            if _globs(values)
        }
        self.include_disabled = include_disabled
        self.cr_property = cr_property
        self.application_property = application_property

    @property
    def needs_ruledoc(self) -> bool:
        """Whether any criterion reads rule-doc properties. Categories can
        usually be read off the comment without one, but the property is the
        authoritative value, so they count too."""
        return bool(self.categories or self.change_requests or
                    self.applications or self.properties)

    @property
    def active(self) -> bool:
        return bool(self.categories or self.change_requests or self.applications
                    or self.rule_names or self.properties or not self.include_disabled)

    def describe(self) -> List[str]:
        lines = []
        if self.rule_names:
            lines.append("rule name matches: %s" % ", ".join(self.rule_names))
        if self.categories:
            lines.append("category: %s" % ", ".join(self.categories))
        if self.change_requests:
            lines.append("change request: %s" % ", ".join(self.change_requests))
        if self.applications:
            lines.append("application: %s" % ", ".join(self.applications))
        for name, values in sorted(self.properties.items()):
            lines.append("%s: %s" % (name, ", ".join(values)))
        if not self.include_disabled:
            lines.append("disabled rules excluded")
        return lines

    def _prop(self, rule: Rule, name: str) -> str:
        if not name:
            return ""
        for key, value in rule.props.items():
            if key.lower() == name.lower():
                return value or ""
        return ""

    def matches(self, rule: Rule) -> bool:
        if not self.include_disabled and rule.disabled:
            return False
        if self.rule_names and not _glob_match(rule.name, self.rule_names):
            return False
        if self.categories and not _glob_match(rule.category, self.categories):
            return False
        if self.change_requests:
            haystack = "%s\n%s" % (self._prop(rule, self.cr_property), rule.comment)
            if not _contains_any(haystack, self.change_requests):
                return False
        if self.applications:
            candidates = [self._prop(rule, self.application_property)]
            candidates.extend(o.raw_name for o in rule.applications)
            if not any(_glob_match(c, self.applications) for c in candidates):
                return False
        for name, patterns in self.properties.items():
            # An unset property never matches, whatever the pattern: '*' means
            # "any value", not "no value".
            value = self._prop(rule, name)
            if not value or not _glob_match(value, patterns):
                return False
        return True


# -- field values -------------------------------------------------------------

def _object_values(refs: Sequence[ObjectRef], mode: str) -> List[Tuple]:
    """The comparable value of an object list under the configured mode.

    name:     the object's (normalised) name.
    contents: what it resolves to, ignoring what it is called -- an object
              renamed but not changed is equal; one with the same name and
              different members is not.
    both:     name and contents together.
    """
    values = []
    for ref in refs:
        prefix = ("!",) if ref.negate else ()
        if mode == "name":
            values.append(prefix + (ref.name,))
        elif mode == "contents":
            values.append(prefix + ref.contents)
        else:
            values.append(prefix + (ref.name,) + ref.contents)
    return sorted(set(values))


def _display(refs: Sequence[ObjectRef], mode: str) -> List[str]:
    """What the report shows for an object list. In contents mode the
    resolved contents are shown beside the name, because the name alone
    cannot explain a difference."""
    out = []
    for ref in refs:
        text = ref.display()
        if mode != "name" and ref.contents and ref.contents != (ref.raw_name,):
            shown = list(ref.contents[:6])
            if len(ref.contents) > 6:
                shown.append("+%d more" % (len(ref.contents) - 6))
            text = "%s [%s]" % (text, ", ".join(shown))
        out.append(text)
    return out


def _prop_value(rule: Rule, name: str) -> str:
    for key, value in rule.props.items():
        if key.lower() == name.lower():
            return (value or "").strip()
    return ""


def _scalar(rule: Rule, field: str):
    if field.startswith("prop:"):
        return _prop_value(rule, field[5:]).lower()
    if field == "name":
        return rule.match_name
    if field == "action":
        return rule.action
    if field == "disabled":
        return rule.disabled
    if field == "log":
        return rule.log
    if field == "negation":
        return tuple(sorted(k for k, v in rule.negation.items() if v))
    if field == "category":
        return (rule.category or "").strip().lower()
    if field == "comment":
        return " ".join((rule.comment or "").split())
    if field == "order":
        return rule.order
    if field == "policy":
        return rule.policy
    raise KeyError(field)


def _scalar_display(rule: Rule, field: str) -> List[str]:
    value = _scalar(rule, field)
    if field.startswith("prop:"):
        return [_prop_value(rule, field[5:]) or "(not set)"]
    if field == "negation":
        return [", ".join(value) if value else "none"]
    if field == "disabled":
        return ["disabled" if value else "enabled"]
    if field == "log":
        return ["on" if value else "off"]
    if field == "category":
        return [rule.category or "(none)"]
    if field == "comment":
        return [rule.comment or "(none)"]
    if field == "name":
        return [rule.name or "(none)"]
    return [str(value) if value not in ("", None) else "(none)"]


def compare_rules(a: Rule, b: Rule, fields: Sequence[str], mode: str) -> List[FieldDiff]:
    diffs = []
    for field in fields:
        if field in LIST_FIELDS:
            refs_a, refs_b = getattr(a, field), getattr(b, field)
            va, vb = _object_values(refs_a, mode), _object_values(refs_b, mode)
            if va == vb:
                continue
            da, db = _display(refs_a, mode), _display(refs_b, mode)
            set_a, set_b = set(va), set(vb)
            # Pair the display strings back to their comparable values so the
            # added/removed lists show what the operator will recognise.
            removed = [d for d, v in zip(da, _object_values_ordered(refs_a, mode)) if v not in set_b]
            added = [d for d, v in zip(db, _object_values_ordered(refs_b, mode)) if v not in set_a]
            diffs.append(FieldDiff(field=field, primary=da, secondary=db,
                                   added=added, removed=removed))
        else:
            if _scalar(a, field) == _scalar(b, field):
                continue
            diffs.append(FieldDiff(field=field,
                                   primary=_scalar_display(a, field),
                                   secondary=_scalar_display(b, field)))
    return diffs


def _object_values_ordered(refs: Sequence[ObjectRef], mode: str) -> List[Tuple]:
    """Like _object_values but in ref order and without deduplication, so it
    lines up with _display()."""
    values = []
    for ref in refs:
        prefix = ("!",) if ref.negate else ()
        if mode == "name":
            values.append(prefix + (ref.name,))
        elif mode == "contents":
            values.append(prefix + ref.contents)
        else:
            values.append(prefix + (ref.name,) + ref.contents)
    return values


# -- the comparison -----------------------------------------------------------

def index(rules: Iterable[Rule]) -> Dict[str, Rule]:
    """Rules by match key. A duplicate key on one side is a data problem the
    report should surface, not hide: the first is kept and the rest logged."""
    out = {}
    for rule in rules:
        if rule.key in out:
            LOG.warning(
                "%s: rule %r matches an earlier rule %r (policy %s); only the "
                "first at position %d is compared. Give [policies] a pair so "
                "keys are scoped per policy, or rename the rule.",
                rule.device_name, rule.name, out[rule.key].name, rule.policy,
                out[rule.key].order,
            )
            continue
        out[rule.key] = rule
    return out


def compare(primary: Iterable[Rule], secondary: Iterable[Rule],
            rule_filter: Optional[RuleFilter] = None,
            fields: Sequence[str] = DEFAULT_FIELDS,
            object_mode: str = "name",
            match_by: str = "name") -> Tuple[List[Finding], int, int, int, int]:
    """Compare two rule sets.

    Returns (findings, in_scope_primary, in_scope_secondary, matched,
    identical). Findings are sorted by policy and rule position on whichever
    side holds the rule, so the report reads in policy order.

    The rules' keys were built by normalize.build_rule according to
    `match_by`; it is passed here only so that, when rules are paired by
    vendor id, the name itself is compared and a rename shows as a rename.
    """
    if object_mode not in OBJECT_MODES:
        raise ValueError("object_mode must be one of %s" % ", ".join(OBJECT_MODES))
    if match_by not in MATCH_MODES:
        raise ValueError("match_by must be one of %s" % ", ".join(MATCH_MODES))
    if match_by == "vendor_id" and "name" not in fields:
        fields = ("name",) + tuple(fields)
    rule_filter = rule_filter or RuleFilter()
    idx_a, idx_b = index(primary), index(secondary)

    keys = set(idx_a) | set(idx_b)
    in_scope = set()
    for key in keys:
        a, b = idx_a.get(key), idx_b.get(key)
        if (a is not None and rule_filter.matches(a)) or \
           (b is not None and rule_filter.matches(b)):
            in_scope.add(key)

    scope_a = sum(1 for k in in_scope if k in idx_a)
    scope_b = sum(1 for k in in_scope if k in idx_b)

    findings = []
    matched = identical = 0
    for key in in_scope:
        a, b = idx_a.get(key), idx_b.get(key)
        if a is not None and b is None:
            findings.append(Finding(kind=ONLY_PRIMARY, key=key, primary=a, secondary=None))
        elif b is not None and a is None:
            findings.append(Finding(kind=ONLY_SECONDARY, key=key, primary=None, secondary=b))
        else:
            matched += 1
            diffs = compare_rules(a, b, fields, object_mode)
            if diffs:
                findings.append(Finding(kind=CHANGED, key=key, primary=a,
                                        secondary=b, diffs=diffs))
            else:
                identical += 1

    findings.sort(key=lambda f: f.sort_key)
    return findings, scope_a, scope_b, matched, identical


def mark_new(findings: List[Finding], previous: Optional[Iterable[str]]) -> List[str]:
    """Flag findings absent from the previous run and return the previous
    fingerprints that no longer occur (resolved drift). With no previous run
    nothing is flagged new: a first report that shouts NEW at every line would
    say nothing."""
    if previous is None:
        return []
    previous = set(previous)
    current = set()
    for finding in findings:
        prints = finding.fingerprints()
        current.update(prints)
        finding.new = any(p not in previous for p in prints)
    return sorted(previous - current)


def describe_fingerprint(fingerprint: str, labels: Optional[Dict[str, str]] = None) -> str:
    """Human form of a fingerprint from the state file, for the 'resolved'
    section. The state file carries a label for each fingerprint it holds
    (needed when the key is a vendor id); older files are parsed instead.
    Keys may be policy-scoped (policy\\x00name)."""
    if labels and fingerprint in labels:
        return labels[fingerprint]
    parts = fingerprint.split("|")
    kind = parts[0] if parts else ""
    key = parts[1] if len(parts) > 1 else ""
    field = parts[2] if len(parts) > 2 else ""
    if "\x00" in key:
        policy, name = key.split("\x00", 1)
        key = "%s (%s)" % (name, policy) if policy else name
    label = {ONLY_PRIMARY: "was only on primary",
             ONLY_SECONDARY: "was only on secondary",
             CHANGED: "differed"}.get(kind, kind)
    if field:
        from .model import field_label
        label += " in %s" % field_label(field).lower()
    return "%s -- %s" % (key, label)
