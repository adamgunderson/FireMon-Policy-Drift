"""Data model for the drift report.

The API layer turns FireMon's rule JSON into `Rule` objects (see
normalize.py); everything downstream -- the comparison, the filters, the
renderer -- works on these and never sees a raw rule dict. That keeps the
shape of a rule stated once, and keeps the comparison testable without a
server.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# The two sides of a comparison. "primary" is the side whose configuration is
# treated as the reference; "secondary" is the one expected to mirror it.
SIDE_PRIMARY = "primary"
SIDE_SECONDARY = "secondary"

# Kinds of finding.
ONLY_PRIMARY = "only_primary"      # rule exists on the primary only
ONLY_SECONDARY = "only_secondary"  # rule exists on the secondary only
CHANGED = "changed"                # rule exists on both, criteria differ

KIND_LABELS = {
    ONLY_PRIMARY: "Only on primary",
    ONLY_SECONDARY: "Only on secondary",
    CHANGED: "Differs",
}

# Every rule field that can be compared, in report order, with its label.
# The keys are what [compare] fields in config.ini names.
FIELD_LABELS = (
    ("name", "Rule name"),
    ("action", "Action"),
    ("disabled", "Disabled"),
    ("log", "Logging"),
    ("sources", "Sources"),
    ("destinations", "Destinations"),
    ("services", "Services"),
    ("applications", "Applications"),
    ("users", "Users"),
    ("urls", "URLs"),
    ("profiles", "Profiles"),
    ("schedules", "Schedules"),
    ("source_zones", "Source zones"),
    ("destination_zones", "Destination zones"),
    ("negation", "Negation"),
    ("category", "Category"),
    ("comment", "Comment"),
    ("order", "Position"),
    ("policy", "Policy"),
)
FIELD_ORDER = tuple(name for name, _ in FIELD_LABELS)
LABELS = dict(FIELD_LABELS)


def field_label(field: str) -> str:
    """Display label for a compared field. Rule-doc properties are compared
    under 'prop:<Property Name>' and labelled with the property name."""
    if field.startswith("prop:"):
        return field[5:]
    return LABELS.get(field, field)

# How rules are paired up across the two sides.
#   name      - by (normalised) rule name. Works for any two policies.
#   vendor_id - by the vendor's own rule id (FireMon's vendorIdentifier: the
#               FMC rule UUID on Firepower). Only meaningful when both sides
#               carry the same policy from the same manager -- an HA pair, or
#               two devices assigned one access control policy -- where it
#               reports a renamed rule as a rename instead of missing + extra.
#               A rule without a vendor id falls back to its name.
MATCH_MODES = ("name", "vendor_id")

# Fields compared when config.ini does not say otherwise. Comment, position and
# policy name are excluded: comments are documentation rather than policy,
# rule position differs between any two policies that have ever diverged and
# then converged, and policy names legitimately differ between sites. The rule
# name is compared only when rules are matched by vendor id (it cannot differ
# otherwise).
DEFAULT_FIELDS = (
    "action", "disabled", "log", "sources", "destinations", "services",
    "applications", "users", "urls", "profiles", "schedules",
    "source_zones", "destination_zones", "negation", "category",
)

# Fields whose value is a set of objects rather than a scalar. These get an
# added/removed breakdown in the report.
LIST_FIELDS = frozenset([
    "sources", "destinations", "services", "applications", "users", "urls",
    "profiles", "schedules", "source_zones", "destination_zones",
])


@dataclass(frozen=True)
class ObjectRef:
    """One object referenced by a rule: a network, service, application...

    `name` is the normalised name used for matching; `raw_name` is what the
    firewall calls it, for display. `contents` is the resolved definition --
    addresses for a network, proto/port for a service -- flattened through
    any group membership, so two objects can be compared by what they contain
    rather than what they are called.
    """

    name: str
    raw_name: str
    contents: Tuple[str, ...] = ()
    negate: bool = False

    def display(self) -> str:
        return ("!" if self.negate else "") + self.raw_name


@dataclass
class Rule:
    """One security rule, flattened to what the comparison needs."""

    key: str                 # match key: normalised name, optionally policy-scoped
    name: str                # rule name as the firewall shows it
    device_id: int
    device_name: str
    policy: str              # policy display name on this device
    policy_key: str          # the pair label the policy maps to ('' = any)
    match_id: str            # FireMon's rule id, for rule-doc lookup
    order: int
    action: str
    disabled: bool
    log: bool
    sources: List[ObjectRef] = field(default_factory=list)
    destinations: List[ObjectRef] = field(default_factory=list)
    services: List[ObjectRef] = field(default_factory=list)
    applications: List[ObjectRef] = field(default_factory=list)
    users: List[ObjectRef] = field(default_factory=list)
    urls: List[ObjectRef] = field(default_factory=list)
    profiles: List[ObjectRef] = field(default_factory=list)
    schedules: List[ObjectRef] = field(default_factory=list)
    source_zones: List[ObjectRef] = field(default_factory=list)
    destination_zones: List[ObjectRef] = field(default_factory=list)
    negation: Dict[str, bool] = field(default_factory=dict)
    comment: str = ""
    props: Dict[str, str] = field(default_factory=dict)  # rule-doc properties
    category: str = ""
    last_changed: str = ""
    match_name: str = ""     # normalised name -- the key when matching by name
    vendor_id: str = ""      # the vendor's rule id (FMC rule UUID), if any

    def summary(self, limit=3) -> str:
        """One-line 'src -> dst : svc' for tables and logs."""
        def few(objs):
            names = [o.display() for o in objs]
            if not names:
                return "any"
            if len(names) > limit:
                return ", ".join(names[:limit]) + " (+%d)" % (len(names) - limit)
            return ", ".join(names)
        return "%s -> %s : %s" % (few(self.sources), few(self.destinations),
                                  few(self.services))


@dataclass
class FieldDiff:
    """One differing field on a rule present on both sides."""

    field: str
    primary: List[str]      # display values on the primary
    secondary: List[str]    # display values on the secondary
    added: List[str] = field(default_factory=list)    # on secondary, not primary
    removed: List[str] = field(default_factory=list)  # on primary, not secondary

    @property
    def label(self) -> str:
        return field_label(self.field)

    @property
    def is_list(self) -> bool:
        return self.field in LIST_FIELDS


@dataclass
class Finding:
    kind: str
    key: str
    primary: Optional[Rule]
    secondary: Optional[Rule]
    diffs: List[FieldDiff] = field(default_factory=list)
    new: bool = False        # not present in the previous run's findings

    @property
    def rule(self) -> Rule:
        """Whichever side has the rule; the primary when both do."""
        return self.primary or self.secondary

    @property
    def name(self) -> str:
        return self.rule.name

    def fingerprints(self) -> List[str]:
        """Stable ids for the state file: one per (rule, field) so that a rule
        that gains a second difference is reported as new for that field only."""
        if self.kind == CHANGED:
            return ["%s|%s|%s" % (self.kind, self.key, d.field) for d in self.diffs]
        return ["%s|%s" % (self.kind, self.key)]

    @property
    def sort_key(self):
        return (self.rule.policy.lower(), self.rule.order, self.key.lower())

    def labels(self) -> Dict[str, str]:
        """Human description of each fingerprint, kept in the state file so
        the 'resolved' section can name a rule even when the key is an opaque
        vendor id."""
        where = ("%s (%s)" % (self.name, self.rule.policy)) if self.rule.policy else self.name
        if self.kind == CHANGED:
            return {fp: "%s -- differed in %s" % (where, field_label(d.field).lower())
                    for fp, d in zip(self.fingerprints(), self.diffs)}
        label = {ONLY_PRIMARY: "was only on primary",
                 ONLY_SECONDARY: "was only on secondary"}[self.kind]
        return {self.fingerprints()[0]: "%s -- %s" % (where, label)}


@dataclass
class DeviceInfo:
    id: int
    name: str
    revision_id: Optional[int] = None
    revision_date: Optional[str] = None
    rule_total: int = 0        # rules retrieved (before filters)
    in_scope: int = 0          # rules after policy and rule filters


@dataclass
class DriftReport:
    primary: DeviceInfo
    secondary: DeviceInfo
    generated_at: datetime
    findings: List[Finding] = field(default_factory=list)
    matched: int = 0           # keys present on both sides, in scope
    identical: int = 0
    fields: Tuple[str, ...] = DEFAULT_FIELDS
    object_mode: str = "name"
    policy_pairs: List[Tuple[str, str]] = field(default_factory=list)
    filter_lines: List[str] = field(default_factory=list)
    normalise_lines: List[str] = field(default_factory=list)
    resolved: List[str] = field(default_factory=list)   # fingerprints gone since last run
    resolved_labels: Dict[str, str] = field(default_factory=dict)  # from the state file
    previous_run: Optional[str] = None
    ruledoc_fetched: bool = False
    pair_name: str = "default"
    match_by: str = "name"
    # Above this many hours between the two sides' configuration dates the
    # report warns that findings may be retrieval lag. 0 disables the check.
    max_revision_skew_hours: int = 24

    def by_kind(self, kind) -> List[Finding]:
        return [f for f in self.findings if f.kind == kind]

    @property
    def only_primary(self) -> List[Finding]:
        return self.by_kind(ONLY_PRIMARY)

    @property
    def only_secondary(self) -> List[Finding]:
        return self.by_kind(ONLY_SECONDARY)

    @property
    def changed(self) -> List[Finding]:
        return self.by_kind(CHANGED)

    @property
    def new_count(self) -> int:
        return sum(1 for f in self.findings if f.new)

    @property
    def has_drift(self) -> bool:
        return bool(self.findings)

    def fingerprints(self) -> List[str]:
        out = []
        for finding in self.findings:
            out.extend(finding.fingerprints())
        return out

    def labels(self) -> Dict[str, str]:
        out = {}
        for finding in self.findings:
            out.update(finding.labels())
        return out

    def revision_skew_hours(self) -> Optional[float]:
        """How far apart the two sides' configuration dates are, in hours,
        or None when either is unknown."""
        a = parse_timestamp(self.primary.revision_date)
        b = parse_timestamp(self.secondary.revision_date)
        if a is None or b is None:
            return None
        return abs((a - b).total_seconds()) / 3600.0

    @property
    def revisions_stale(self) -> bool:
        """True when the two configurations were retrieved so far apart that
        a difference may be retrieval lag rather than policy drift."""
        if not self.max_revision_skew_hours:
            return False
        skew = self.revision_skew_hours()
        return skew is not None and skew > self.max_revision_skew_hours

    @property
    def older_side(self) -> Optional[str]:
        """'primary' or 'secondary': whichever configuration is older."""
        a = parse_timestamp(self.primary.revision_date)
        b = parse_timestamp(self.secondary.revision_date)
        if a is None or b is None or a == b:
            return None
        return SIDE_PRIMARY if a < b else SIDE_SECONDARY


_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?")


def parse_timestamp(value) -> Optional[datetime]:
    """An API timestamp ('2026-07-20T21:30:30.993Z') -> aware datetime, or
    None. Only the date and time matter; the API reports UTC."""
    if not value:
        return None
    match = _ISO.match(str(value).strip())
    if not match:
        return None
    parts = [int(p or 0) for p in match.groups()]
    try:
        return datetime(*parts, tzinfo=timezone.utc)
    except ValueError:
        return None


def describe_skew(hours: float) -> str:
    """'3 hours', '41 days', ..."""
    if hours < 48:
        n = int(round(hours))
        return "%d hour%s" % (n, "" if n == 1 else "s")
    days = int(round(hours / 24.0))
    return "%d day%s" % (days, "" if days == 1 else "s")


@dataclass
class SendResult:
    recipients: List[str]
    actual_recipients: List[str]
    subject: str
    sent: bool
    dry_run: bool
    error: Optional[str] = None
