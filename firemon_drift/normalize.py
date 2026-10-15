"""Turn FireMon's rule JSON into comparable `Rule` objects.

Two things happen here and nowhere else:

* **Flattening.** A rule's sources, services and so on arrive as nested
  objects -- groups holding groups holding hosts. Each is reduced to an
  ObjectRef carrying its name and its resolved contents (every address, every
  proto/port) so the comparison can work on either.

* **Name normalisation.** Two sites that mirror each other often name things
  by site: `KF-USE-PROD-VNET` on one firewall and `KF-USW-PROD-VNET` on the
  other. Compared literally, every such rule reads as drift. The [normalise]
  section of config.ini holds regex substitutions applied to rule, object and
  zone names on BOTH sides before matching, so the site token can be folded
  away. The raw name is kept for display.

The normalisation is applied to names only, never to resolved contents: an
address is an address.
"""

import logging
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .model import ObjectRef, Rule

LOG = logging.getLogger(__name__)

# Autodoc pattern FireMon's own "FMC Category" property uses on Firepower:
# the category is written into the rule comment as `cat:NAME;`.
DEFAULT_CATEGORY_PATTERN = r"cat:\s*([^;]*?)\s*;"


class NameNormaliser:
    """Ordered regex substitutions applied to a name before it is compared."""

    def __init__(self, rules: Sequence[Tuple[str, str]] = (), case_insensitive=False):
        self.rules = []
        for pattern, replacement in rules:
            try:
                self.rules.append((re.compile(pattern), replacement, pattern))
            except re.error as exc:
                raise ValueError("bad [normalise] pattern %r: %s" % (pattern, exc))
        self.case_insensitive = case_insensitive

    def __call__(self, name: Optional[str]) -> str:
        value = (name or "").strip()
        for regex, replacement, _ in self.rules:
            value = regex.sub(replacement, value)
        value = " ".join(value.split())
        if self.case_insensitive:
            value = value.lower()
        return value

    def describe(self) -> List[str]:
        lines = ["%s -> %s" % (pattern, repl or "(nothing)")
                 for _, repl, pattern in self.rules]
        if self.case_insensitive:
            lines.append("names compared case-insensitively")
        return lines


def _name(obj) -> str:
    return (obj.get("displayName") or obj.get("name") or "").strip()


# -- object flattening -------------------------------------------------------

def _network_contents(obj, seen=None) -> List[str]:
    seen = seen if seen is not None else set()
    kind = (obj.get("type") or "").upper()
    if kind == "ANY" or (obj.get("networkType") or "").upper() == "ANY":
        return ["any"]
    out = []
    for address in obj.get("addresses") or []:
        value = address.get("address") or address.get("value")
        if value:
            out.append(str(value))
    for address in obj.get("addressesExclude") or []:
        value = address.get("address") or address.get("value")
        if value:
            out.append("-" + str(value))
    for member in obj.get("members") or []:
        marker = member.get("matchId") or _name(member)
        if marker in seen:
            continue
        seen.add(marker)
        out.extend(_network_contents(member, seen))
    for member in obj.get("membersExclude") or []:
        out.extend("-" + item for item in _network_contents(member, seen))
    if not out:
        # An FQDN object or a vendor type we do not resolve: the name is the
        # only content there is, so it stands in.
        name = _name(obj)
        if name:
            out.append(name)
    return out


def _service_contents(obj, seen=None) -> List[str]:
    seen = seen if seen is not None else set()
    if (obj.get("type") or "").upper() == "ANY":
        return ["any"]
    out = []
    for svc in obj.get("services") or []:
        out.append(_format_service(svc))
    for svc in obj.get("servicesExclude") or []:
        out.append("-" + _format_service(svc))
    for member in obj.get("members") or []:
        marker = member.get("matchId") or _name(member)
        if marker in seen:
            continue
        seen.add(marker)
        out.extend(_service_contents(member, seen))
    for member in obj.get("membersExclude") or []:
        out.extend("-" + item for item in _service_contents(member, seen))
    if not out:
        name = _name(obj)
        if name:
            out.append(name)
    return out


def _format_service(svc) -> str:
    formatted = svc.get("formattedValue")
    if formatted:
        return str(formatted)
    proto = (svc.get("type") or str(svc.get("protocol") or "")).lower()
    start, end = svc.get("startPort"), svc.get("endPort")
    if start is None:
        return proto or "?"
    if end is None or end == start:
        return "%s/%s" % (proto, start)
    return "%s/%s-%s" % (proto, start, end)


def _named_contents(obj, seen=None) -> List[str]:
    """Applications, users, URLs, profiles, schedules: the resolved content is
    the set of leaf names, which for a group means its members."""
    seen = seen if seen is not None else set()
    members = obj.get("members") or []
    if not members:
        return [obj.get("formattedName") or _name(obj)]
    out = []
    for member in members:
        marker = member.get("matchId") or _name(member)
        if marker in seen:
            continue
        seen.add(marker)
        out.extend(_named_contents(member, seen))
    return out


_RESOLVERS = {
    "network": _network_contents,
    "service": _service_contents,
    "named": _named_contents,
}


def _refs(objects, kind, normalise) -> List[ObjectRef]:
    resolver = _RESOLVERS[kind]
    refs = []
    for obj in objects or []:
        raw = _name(obj)
        if not raw and (obj.get("type") or "").upper() == "ANY":
            raw = "Any"
        contents = tuple(sorted(set(resolver(obj))))
        refs.append(ObjectRef(
            name=normalise(raw),
            raw_name=raw,
            contents=contents,
            negate=bool(obj.get("negate")),
        ))
    refs.sort(key=lambda r: (r.name, r.raw_name))
    return refs


def _zones(context, normalise) -> List[ObjectRef]:
    context = context or {}
    if context.get("any"):
        return [ObjectRef(name="any", raw_name="any", contents=("any",))]
    refs = []
    for zone in context.get("zones") or []:
        raw = _name(zone)
        interfaces = tuple(sorted(
            _name(i) for i in zone.get("interfaces") or [] if _name(i)
        ))
        refs.append(ObjectRef(name=normalise(raw), raw_name=raw,
                              contents=interfaces or (raw,)))
    for intf in context.get("intfs") or []:
        raw = _name(intf)
        refs.append(ObjectRef(name=normalise(raw), raw_name=raw, contents=(raw,)))
    refs.sort(key=lambda r: (r.name, r.raw_name))
    return refs


# -- rule ---------------------------------------------------------------------

def category_from_comment(comment: str, pattern: Optional[str]) -> str:
    if not comment or not pattern:
        return ""
    try:
        match = re.search(pattern, comment)
    except re.error:
        return ""
    return (match.group(1) if match and match.groups() else "").strip()


def build_rule(raw: dict, device_id: int, device_name: str, normalise: NameNormaliser,
               policy_key: str = "", scope_key_by_policy: bool = False,
               category_pattern: Optional[str] = DEFAULT_CATEGORY_PATTERN,
               match_by: str = "name") -> Rule:
    """Flatten one rule from the secrule search into a Rule.

    `policy_key` is the pair label the rule's policy maps to (the primary
    side's policy name); it is part of the match key when policies are being
    compared pairwise, so a rule name reused across two policies on the same
    device does not collide.

    `match_by` decides the key: the normalised name, or the vendor's own rule
    id (vendorIdentifier -- the FMC rule UUID) with the name as the fallback
    for a rule that has none.
    """
    policy = raw.get("policy") or {}
    policy_name = (policy.get("displayName") or policy.get("name") or "").strip()
    name = (raw.get("ruleName") or raw.get("displayName") or raw.get("name") or "").strip()
    match_name = normalise(name)
    vendor_id = str(raw.get("vendorIdentifier") or "").strip()
    key = vendor_id if (match_by == "vendor_id" and vendor_id) else match_name
    if scope_key_by_policy:
        key = "%s\x00%s" % (policy_key, key)

    comment = (raw.get("commentText") or "").strip()
    rule = Rule(
        key=key,
        name=name,
        device_id=device_id,
        device_name=device_name,
        policy=policy_name,
        policy_key=policy_key,
        policy_id=str(policy.get("matchId") or ""),
        match_id=str(raw.get("matchId") or ""),
        order=int(raw.get("ruleOrder") or raw.get("ruleNumber") or 0),
        action=(raw.get("ruleAction") or "").upper(),
        disabled=bool(raw.get("disabled")),
        log=bool(raw.get("log")),
        sources=_refs(raw.get("sources"), "network", normalise),
        destinations=_refs(raw.get("destinations"), "network", normalise),
        services=_refs(raw.get("services"), "service", normalise),
        applications=_refs(raw.get("apps"), "named", normalise),
        users=_refs(raw.get("users"), "named", normalise),
        urls=_refs(raw.get("urlMatchers"), "named", normalise),
        profiles=_refs(raw.get("profiles"), "named", normalise),
        schedules=_refs(raw.get("schedules"), "named", normalise),
        source_zones=_zones(raw.get("srcContext"), normalise),
        destination_zones=_zones(raw.get("dstContext"), normalise),
        negation={
            "sources": bool(raw.get("srcNegated")),
            "destinations": bool(raw.get("dstNegated")),
            "services": bool(raw.get("svcNegated")),
            "users": bool(raw.get("userNegated")),
            "applications": bool(raw.get("appNegated")),
        },
        comment=comment,
        category=category_from_comment(comment, category_pattern),
        last_changed=str(raw.get("lastChanged") or ""),
        match_name=match_name,
        vendor_id=vendor_id,
    )
    # Excluded sets are folded into the same list, marked, so a rule with an
    # exclusion is not silently equal to one without.
    for side, field_name in (("sourcesExclude", "sources"),
                             ("destinationsExclude", "destinations"),
                             ("servicesExclude", "services")):
        kind = "service" if field_name == "services" else "network"
        for ref in _refs(raw.get(side), kind, normalise):
            getattr(rule, field_name).append(ObjectRef(
                name="-" + ref.name, raw_name="-" + ref.raw_name,
                contents=tuple("-" + c for c in ref.contents), negate=ref.negate,
            ))
    return rule


def apply_props(rule: Rule, props: Dict[str, str], category_property: str) -> None:
    """Attach rule-doc properties; the configured category property wins over
    the value parsed from the comment, since it is the same data after
    FireMon has parsed it."""
    rule.props = dict(props)
    if category_property:
        value = props.get(category_property)
        if value:
            rule.category = str(value).strip()


def parse_ruledoc(doc: dict) -> Dict[str, str]:
    """Reduce a rule-doc response to {property name: value string}.

    Values live under a type-specific key (stringval, dateval, intval, ...)
    beside the property definition; empty ones carry no value key at all.
    Unset properties are omitted so a filter on them simply does not match.
    """
    out = {}
    for prop in (doc or {}).get("props") or []:
        definition = prop.get("customProperty") or {}
        name = (definition.get("name") or
                (prop.get("ruleCustomPropertyDefinition") or {}).get("name") or "")
        name = name.strip()
        if not name:
            continue
        value = None
        for key, held in prop.items():
            if key.endswith("val") or key.endswith("array"):
                if held not in (None, "", []):
                    value = held
                    break
        if value is None:
            continue
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        out[name] = str(value).strip()
    return out
