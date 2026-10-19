"""Configuration loading and validation.

INI via configparser, so ops staff can read and edit it with nothing
installed. Secrets are read from the environment first so the file need not
hold them. Validation is strict and happens once, at load: a run that will
fail on a missing template or a bad regex should fail before it
authenticates.

Pairs
-----
One config can watch several firewall pairs. Each is a `[pair:NAME]` section
holding the two devices plus, optionally, its own policies, filters,
recipients and send rule; anything a pair leaves unset comes from the global
`[policies]`, `[filter]`, `[property_filters]`, `[email]`, `[compare]` and
`[normalise]` sections. A plain `[pair]` section with primary and secondary
filled in is the single-pair shorthand and is treated as a pair named
"default". Per-pair sections `[policies:NAME]`, `[property_filters:NAME]` and
`[normalise:NAME]` override the inline keys for pairs whose names do not fit
on one line.
"""

import configparser
import logging
import os
import re
import stat
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import model
from .compare import OBJECT_MODES
from .model import MATCH_MODES

LOG = logging.getLogger(__name__)

ENV_FM_PASSWORD = "FMDRIFT_PASSWORD"
ENV_FM_TOKEN = "FMDRIFT_TOKEN"
ENV_SMTP_PASSWORD = "FMDRIFT_SMTP_PASSWORD"

REQUIRED_TEMPLATES = ("drift.html", "drift.txt")

SEND_WHEN = ("drift", "always", "changes", "never")
FETCH_RULEDOC = ("auto", "always", "never")

DEFAULT_PAIR_NAME = "default"
_PAIR_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$")


class ConfigError(Exception):
    """Raised for any unusable configuration. Always fatal."""


def split_list(raw: str) -> List[str]:
    """Comma-separated config value -> list, trimmed, empties dropped. Case
    is preserved: category names and property values are shown back."""
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def parse_fields(raw: str) -> Tuple[str, ...]:
    """[compare] fields: 'default', 'all', or a list. Rule-doc properties
    are compared as prop:<Property Name>."""
    text = (raw or "").strip()
    if not text or text.lower() == "default":
        return model.DEFAULT_FIELDS
    if text.lower() == "all":
        return model.FIELD_ORDER
    fields = []
    for item in split_list(text):
        name = item.strip()
        if name.lower().startswith("prop:"):
            prop = name[5:].strip()
            if not prop:
                raise ConfigError("[compare] fields: 'prop:' needs a property name")
            fields.append("prop:" + prop)
            continue
        name = name.lower().replace(" ", "_").replace("-", "_")
        if name not in model.FIELD_ORDER:
            raise ConfigError(
                "[compare] fields: unknown field %r. Choose from: %s, or "
                "prop:<Property Name>" % (item, ", ".join(model.FIELD_ORDER)))
        fields.append(name)
    if not fields:
        raise ConfigError("[compare] fields must name at least one field")
    return tuple(fields)


def parse_policy_pairs_inline(raw: str, where: str) -> List[Tuple[str, str]]:
    """'A = B, C' -> [(A, B), (C, C)]: the one-line form of [policies]."""
    pairs = []
    for item in split_list(raw):
        a, _, b = item.partition("=")
        a, b = a.strip(), b.strip()
        if not a:
            raise ConfigError("%s policies: %r is not 'primary policy = secondary policy'"
                              % (where, item))
        pairs.append((a, b or a))
    return pairs


def parse_normalise_rules(section, where: str) -> List[Tuple[str, str]]:
    rules = []
    for label in section:
        value = (section.get(label, fallback="") or "").strip()
        if not value:
            continue
        if "=>" not in value:
            raise ConfigError("%s %s must be 'pattern => replacement' (got %r)"
                              % (where, label, value))
        pattern, _, replacement = value.partition("=>")
        pattern, replacement = pattern.strip(), replacement.strip()
        if not pattern:
            raise ConfigError("%s %s has an empty pattern" % (where, label))
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ConfigError("%s %s: bad regex %r: %s" % (where, label, pattern, exc))
        rules.append((pattern, replacement))
    return rules


@dataclass
class PairConfig:
    """One firewall pair and everything that shapes its comparison."""

    name: str
    primary: str
    secondary: str
    primary_label: str = ""
    secondary_label: str = ""
    policy_pairs: List[Tuple[str, str]] = field(default_factory=list)
    fields: Tuple[str, ...] = model.DEFAULT_FIELDS
    object_mode: str = "name"
    match_by: str = "name"
    normalise_rules: List[Tuple[str, str]] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    change_requests: List[str] = field(default_factory=list)
    applications: List[str] = field(default_factory=list)
    rule_names: List[str] = field(default_factory=list)
    include_disabled: bool = True
    properties: Dict[str, List[str]] = field(default_factory=dict)
    recipients: List[str] = field(default_factory=list)
    send_when: str = "drift"
    subject_prefix: str = ""

    @property
    def needs_ruledoc_for_compare(self) -> bool:
        return any(f.startswith("prop:") for f in self.fields)

    @property
    def label(self) -> str:
        """How the pair is referred to in logs and subjects."""
        return self.name


class Config:
    def __init__(self, parser: configparser.ConfigParser, path: str):
        self.path = path
        self._parser = parser

        # -- [firemon] ----------------------------------------------------
        fm = self._section("firemon")
        self.base_url = self._require(fm, "base_url", "firemon").rstrip("/")
        if not self.base_url.startswith(("http://", "https://")):
            raise ConfigError("[firemon] base_url must start with http:// or "
                              "https:// (got %r)" % self.base_url)
        self.domain_id = self._int(fm, "domain_id", 1)
        self.auth_mode = fm.get("auth_mode", fallback="token").strip().lower()
        if self.auth_mode not in ("token", "basic"):
            raise ConfigError("[firemon] auth_mode must be 'token' or 'basic'")
        self.username = fm.get("username", fallback="").strip()
        self.password = os.environ.get(ENV_FM_PASSWORD) or fm.get("password", fallback="")
        self.token = os.environ.get(ENV_FM_TOKEN) or fm.get("token", fallback="")
        if self.auth_mode == "token" and not self.token and not (self.username and self.password):
            raise ConfigError(
                "[firemon] needs a username and password (set %s in the "
                "environment to keep the password out of the file)" % ENV_FM_PASSWORD)
        if self.auth_mode == "basic" and not (self.username and self.password):
            raise ConfigError("[firemon] auth_mode=basic needs username and password")
        self.verify_tls = self._bool(fm, "verify_tls", True)
        self.ca_bundle = fm.get("ca_bundle", fallback="").strip()
        if self.ca_bundle and not os.path.isfile(self.ca_bundle):
            raise ConfigError("[firemon] ca_bundle not found: %s" % self.ca_bundle)
        self.timeout = self._int(fm, "timeout", 60)
        self.max_retries = self._int(fm, "max_retries", 3)
        self.page_size = self._int(fm, "page_size", 200)

        # -- [compare] (global defaults) ----------------------------------
        cmp_ = self._section("compare", required=False)
        self.fields = parse_fields(cmp_.get("fields", fallback=""))
        self.object_mode = cmp_.get("object_mode", fallback="name").strip().lower() or "name"
        if self.object_mode not in OBJECT_MODES:
            raise ConfigError("[compare] object_mode must be one of %s"
                              % ", ".join(OBJECT_MODES))
        self.match_by = cmp_.get("match_by", fallback="name").strip().lower() or "name"
        if self.match_by not in MATCH_MODES:
            raise ConfigError("[compare] match_by must be one of %s"
                              % ", ".join(MATCH_MODES))
        self.max_revision_skew_hours = self._int(cmp_, "max_revision_skew_hours", 24)
        if self.max_revision_skew_hours < 0:
            raise ConfigError("[compare] max_revision_skew_hours must be 0 or more")
        self.match_case_insensitive = self._bool(cmp_, "match_case_insensitive", False)
        # Categories can be left out altogether (they mean nothing where the
        # category property is not populated): see apply_category_switch.
        self.compare_categories = self._bool(cmp_, "compare_categories", True)
        self.category_property = self._str(cmp_, "category_property", "FMC ACP Category")
        self.category_comment_pattern = self._str(
            cmp_, "category_comment_pattern", r"cat:\s*([^;]*?)\s*;")
        if self.category_comment_pattern:
            try:
                re.compile(self.category_comment_pattern)
            except re.error as exc:
                raise ConfigError("[compare] category_comment_pattern: %s" % exc)
        self.fetch_ruledoc = self._str(cmp_, "fetch_ruledoc", "auto").lower()
        if self.fetch_ruledoc not in FETCH_RULEDOC:
            raise ConfigError("[compare] fetch_ruledoc must be one of %s"
                              % ", ".join(FETCH_RULEDOC))

        # -- global [policies] / [normalise] / [filter] / [property_filters]
        self.policy_pairs = self._policy_section("policies")
        self.normalise_rules = parse_normalise_rules(
            self._section("normalise", required=False), "[normalise]")

        flt = self._section("filter", required=False)
        self.filter_categories = split_list(flt.get("categories", fallback=""))
        self.filter_change_requests = split_list(flt.get("change_requests", fallback=""))
        self.filter_applications = split_list(flt.get("applications", fallback=""))
        self.filter_rule_names = split_list(flt.get("rule_names", fallback=""))
        self.include_disabled = self._bool(flt, "include_disabled", True)
        self.cr_property = self._str(flt, "cr_property", "Change Control Number (CR)")
        self.application_property = self._str(flt, "application_property", "Application Name")
        self.filter_properties = self._property_section("property_filters")

        # -- [email] (global defaults) ------------------------------------
        em = self._section("email", required=False)
        self.recipients = [r.lower() for r in split_list(em.get("recipients", fallback=""))]
        self.send_when = self._str(em, "send_when", "drift").lower()
        if self.send_when not in SEND_WHEN:
            raise ConfigError("[email] send_when must be one of %s" % ", ".join(SEND_WHEN))
        self.subject_prefix = em.get("subject_prefix", fallback="").strip()
        self.attach_csv = self._bool(em, "attach_csv", True)
        self.attach_json = self._bool(em, "attach_json", False)
        self.max_rows = self._int(em, "max_rows", 50)
        self.max_diff_rules = self._int(em, "max_diff_rules", 30)
        self.portal_url = em.get("portal_url", fallback="").strip() or (
            self.base_url + "/securitymanager/")
        self.support_email = em.get("support_email", fallback="").strip()

        # -- pairs --------------------------------------------------------
        self.pairs: List[PairConfig] = self._load_pairs()

        # -- [smtp] -------------------------------------------------------
        smtp = self._section("smtp")
        self.smtp_host = smtp.get("host", fallback="localhost").strip()
        self.smtp_port = self._int(smtp, "port", 25)
        self.smtp_starttls = self._bool(smtp, "use_starttls", False)
        self.smtp_username = smtp.get("username", fallback="").strip()
        self.smtp_password = os.environ.get(ENV_SMTP_PASSWORD) or smtp.get("password", fallback="")
        self.from_address = self._require(smtp, "from_address", "smtp")
        self.from_name = smtp.get("from_name", fallback="FireMon Policy Drift Monitor").strip()
        self.reply_to = smtp.get("reply_to", fallback="").strip()
        self.smtp_timeout = self._int(smtp, "timeout", 30)
        if not self.support_email:
            self.support_email = self.reply_to or self.from_address

        # -- [paths] ------------------------------------------------------
        base_dir = os.path.dirname(os.path.abspath(path))
        paths = self._section("paths", required=False)
        self.template_dir = self._resolve(base_dir, paths.get("template_dir", fallback="./templates"))
        self.output_dir = self._resolve(base_dir, paths.get("output_dir", fallback="./out"))
        self.state_dir = self._resolve(base_dir, paths.get("state_dir", fallback="./state"))
        self.log_file = paths.get("log_file", fallback="").strip()
        if not os.path.isdir(self.template_dir):
            raise ConfigError("[paths] template_dir not found: %s" % self.template_dir)
        missing = [n for n in REQUIRED_TEMPLATES
                   if not os.path.isfile(os.path.join(self.template_dir, n))]
        if missing:
            raise ConfigError("[paths] template_dir %s is missing: %s"
                              % (self.template_dir, ", ".join(missing)))

        self._warn_if_world_readable()

    # -- pairs --------------------------------------------------------------

    def _load_pairs(self) -> List[PairConfig]:
        pairs = []
        names = set()

        # The single-pair shorthand: a plain [pair] with both devices set.
        if self._parser.has_section("pair"):
            plain = self._parser["pair"]
            if (plain.get("primary", fallback="") or "").strip() or \
               (plain.get("secondary", fallback="") or "").strip():
                pairs.append(self._build_pair(DEFAULT_PAIR_NAME, plain, "[pair]"))
                names.add(DEFAULT_PAIR_NAME.lower())

        for section_name in self._parser.sections():
            if not section_name.lower().startswith("pair:"):
                continue
            name = section_name[5:].strip()
            if not _PAIR_NAME.match(name):
                raise ConfigError("[%s]: a pair name is 1-64 letters, digits, dots, "
                                  "spaces, hyphens or underscores" % section_name)
            if name.lower() in names:
                raise ConfigError("pair %r is defined twice" % name)
            names.add(name.lower())
            pairs.append(self._build_pair(name, self._parser[section_name],
                                          "[%s]" % section_name))

        # Zero pairs is not an error here: a config being built one pair at a
        # time (the setup wizard) is a legitimate transient state, and
        # --list-devices needs no pair at all. Whether a *run* needs at least
        # one pair is cli.py's call, not the loader's -- it knows whether
        # --primary/--secondary supplied one instead.

        # Sections that name a pair which does not exist are a typo worth
        # stopping on: the operator thinks they are scoping something.
        for prefix in ("policies:", "property_filters:", "normalise:"):
            for section_name in self._parser.sections():
                if section_name.lower().startswith(prefix):
                    target = section_name[len(prefix):].strip().lower()
                    if target not in names:
                        raise ConfigError("[%s] refers to a pair that is not defined"
                                          % section_name)
        return pairs

    def _build_pair(self, name: str, section, where: str) -> PairConfig:
        primary = (section.get("primary", fallback="") or "").strip()
        secondary = (section.get("secondary", fallback="") or "").strip()
        if not primary or not secondary:
            raise ConfigError("%s needs both primary and secondary" % where)
        if primary.lower() == secondary.lower():
            raise ConfigError("%s: primary and secondary are the same device" % where)

        # Policies: a [policies:NAME] section wins over the inline key, which
        # wins over the global [policies].
        policy_pairs = self._policy_section("policies:" + name, exists_only=True)
        if policy_pairs is None:
            raw = (section.get("policies", fallback="") or "").strip()
            if raw:
                policy_pairs = ([] if raw.lower() == "all"
                                else parse_policy_pairs_inline(raw, where))
            else:
                policy_pairs = list(self.policy_pairs)

        properties = self._property_section("property_filters:" + name, exists_only=True)
        if properties is None:
            properties = dict(self.filter_properties)

        if self._parser.has_section("normalise:" + name):
            normalise_rules = parse_normalise_rules(
                self._parser["normalise:" + name], "[normalise:%s]" % name)
        else:
            normalise_rules = list(self.normalise_rules)

        fields = self.fields
        if (section.get("fields", fallback="") or "").strip():
            fields = parse_fields(section.get("fields"))
        object_mode = (section.get("object_mode", fallback="") or "").strip().lower() or self.object_mode
        if object_mode not in OBJECT_MODES:
            raise ConfigError("%s object_mode must be one of %s" % (where, ", ".join(OBJECT_MODES)))
        match_by = (section.get("match_by", fallback="") or "").strip().lower() or self.match_by
        if match_by not in MATCH_MODES:
            raise ConfigError("%s match_by must be one of %s" % (where, ", ".join(MATCH_MODES)))

        def inherit_list(key, default):
            raw = section.get(key, fallback=None)
            if raw is None:
                return list(default)
            raw = raw.strip()
            if raw.lower() in ("all", "none"):
                return []
            return split_list(raw)

        recipients = section.get("recipients", fallback=None)
        if recipients is None:
            recipients = list(self.recipients)
        else:
            recipients = [] if recipients.strip().lower() == "none" else \
                [r.lower() for r in split_list(recipients)]
        send_when = (section.get("send_when", fallback="") or "").strip().lower() or self.send_when
        if send_when not in SEND_WHEN:
            raise ConfigError("%s send_when must be one of %s" % (where, ", ".join(SEND_WHEN)))
        if send_when != "never" and not recipients:
            LOG.warning("%s: no recipients -- the report will be written to the "
                        "output directory and nobody will be mailed", where)

        return PairConfig(
            name=name, primary=primary, secondary=secondary,
            primary_label=(section.get("primary_label", fallback="") or "").strip(),
            secondary_label=(section.get("secondary_label", fallback="") or "").strip(),
            policy_pairs=policy_pairs, fields=fields, object_mode=object_mode,
            match_by=match_by, normalise_rules=normalise_rules,
            categories=inherit_list("categories", self.filter_categories),
            change_requests=inherit_list("change_requests", self.filter_change_requests),
            applications=inherit_list("applications", self.filter_applications),
            rule_names=inherit_list("rule_names", self.filter_rule_names),
            include_disabled=self._bool(section, "include_disabled", self.include_disabled),
            properties=properties,
            recipients=recipients, send_when=send_when,
            subject_prefix=(section.get("subject_prefix", fallback=None)
                            if section.get("subject_prefix", fallback=None) is not None
                            else self.subject_prefix).strip(),
        )

    def _policy_section(self, name, exists_only=False):
        if not self._parser.has_section(name):
            return None if exists_only else []
        section = self._parser[name]
        pairs = []
        for key in section:
            target = (section.get(key, fallback="") or "").strip()
            source = key.strip()
            if source:
                pairs.append((source, target or source))
        return pairs

    def _property_section(self, name, exists_only=False):
        if not self._parser.has_section(name):
            return None if exists_only else {}
        section = self._parser[name]
        out = {}
        for key in section:
            values = split_list(section.get(key, fallback=""))
            if values:
                out[key.strip()] = values
        return out

    def pair(self, name: str) -> Optional[PairConfig]:
        for pair in self.pairs:
            if pair.name.lower() == name.strip().lower():
                return pair
        return None

    # -- helpers ----------------------------------------------------------

    def _section(self, name, required=True):
        if self._parser.has_section(name):
            return self._parser[name]
        if required:
            raise ConfigError("config is missing the [%s] section" % name)
        self._parser.add_section(name)
        return self._parser[name]

    @staticmethod
    def _require(section, key, section_name):
        value = section.get(key, fallback="").strip()
        if not value:
            raise ConfigError("[%s] %s is required" % (section_name, key))
        return value

    @staticmethod
    def _str(section, key, default):
        value = section.get(key, fallback="")
        value = str(value).strip() if value is not None else ""
        return value or default

    @staticmethod
    def _int(section, key, default):
        raw = section.get(key, fallback="")
        if raw is None or not str(raw).strip():
            return default
        try:
            return int(str(raw).strip())
        except ValueError:
            raise ConfigError("%s must be an integer (got %r)" % (key, raw))

    @staticmethod
    def _bool(section, key, default):
        raw = section.get(key, fallback="")
        if raw is None or not str(raw).strip():
            return default
        value = str(raw).strip().lower()
        if value in ("1", "true", "yes", "on"):
            return True
        if value in ("0", "false", "no", "off"):
            return False
        raise ConfigError("%s must be a boolean (got %r)" % (key, raw))

    @staticmethod
    def _resolve(base_dir, value):
        value = (value or "").strip()
        if not value:
            return base_dir
        if os.path.isabs(value):
            return value
        return os.path.normpath(os.path.join(base_dir, value))

    def _warn_if_world_readable(self):
        holds_secret = bool(
            self._parser.get("firemon", "password", fallback="")
            or self._parser.get("firemon", "token", fallback="")
            or self._parser.get("smtp", "password", fallback="")
        )
        if not holds_secret:
            return
        try:
            mode = os.stat(self.path).st_mode
        except OSError:
            return
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            LOG.warning("%s contains secrets and is readable beyond its owner. "
                        "Run: chmod 600 %s", self.path, self.path)


def load(path: str) -> Config:
    if not os.path.isfile(path):
        raise ConfigError("config file not found: %s" % path)
    # optionxform=str keeps the case of keys: [policies] and [property_filters]
    # use policy and property NAMES as keys. delimiters is '=' only, so a
    # policy name containing ':' is not split in two.
    parser = configparser.ConfigParser(inline_comment_prefixes=(";", "#"),
                                       interpolation=None, delimiters=("=",))
    parser.optionxform = str
    try:
        with open(path, "r", encoding="utf-8") as handle:
            parser.read_file(handle)
    except configparser.Error as exc:
        raise ConfigError("could not parse %s: %s" % (path, exc))
    return Config(parser, path)
