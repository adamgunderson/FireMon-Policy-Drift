"""Rendering: the email (HTML and plain text), the CSV and the JSON.

Templates are external files using string.Template placeholders, so the
copy can be edited without touching Python. Every FireMon-sourced value is
HTML-escaped centrally here: rule names and comments are free text out of
firewall configurations and routinely contain '&' and '<'.

Rendering uses strict .substitute(): a typo in a placeholder fails loudly
during --dry-run rather than shipping an email containing '${summary}'.

Styling is inline with no <style> block, no doctype and no images, because
Outlook strips <style> from HTML email. Added and removed items are marked
with a sign as well as a colour, so the meaning never rests on colour alone.
"""

import csv
import html
import io
import json
import logging
import os
import re
from string import Template
from typing import List

from .compare import describe_fingerprint
from .model import (
    CHANGED,
    ONLY_PRIMARY,
    ONLY_SECONDARY,
    DriftReport,
    Finding,
    Rule,
    describe_skew,
    field_label,
)

LOG = logging.getLogger(__name__)

FONT_STACK = "Aptos, 'Segoe UI', sans-serif"
COLOUR_SECTION = "#1f4e79"
COLOUR_ALERT = "#c0392b"
COLOUR_GOOD = "#1e8449"
COLOUR_MUTED = "#767676"
COLOUR_ADDED_BG = "#e8f5e9"
COLOUR_REMOVED_BG = "#fdecea"
COLOUR_NEW = "#b7791f"

_CELL = "padding: 4pt 8pt; border-bottom: 1px solid #d9d9d9; vertical-align: top;"
_HEAD = ("padding: 4pt 8pt; border-bottom: 2px solid %s; color: %s; "
         "font-weight: bold; text-align: left;" % (COLOUR_SECTION, COLOUR_SECTION))
_TABLE = ('<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
          'style="border-collapse: collapse; font-family: %s; font-size: 10pt; '
          'width: 100%%; margin: 4pt 0 10pt 0;">' % FONT_STACK)
_PARA = '<p style="margin: 6pt 0 8pt 0; line-height: 130%%;">%s</p>'


def _section(title: str) -> str:
    return ('<p style="margin: 14pt 0 4pt 0; line-height: 130%%; font-size: 13pt; '
            'font-weight: bold; color: %s; border-bottom: 2px solid %s; '
            'padding-bottom: 3pt;">%s</p>' % (COLOUR_SECTION, COLOUR_SECTION, title))
_LEADING_COMMENT = re.compile(r"\A\s*<!--.*?-->\s*", re.DOTALL)

# Gmail truncates an HTML body over roughly this size and shows "[Message
# clipped]"; the row caps in [email] exist to stay under it.
GMAIL_CLIP_BYTES = 102 * 1024


class RenderError(Exception):
    """A template could not be rendered. Fatal -- never send a broken email."""


def esc(value) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _plural(count, singular, plural=None) -> str:
    return singular if count == 1 else (plural or singular + "s")


def _new_badge_html(finding: Finding) -> str:
    if not finding.new:
        return ""
    return (' <span style="color: %s; font-weight: bold; font-size: 9pt;">NEW</span>'
            % COLOUR_NEW)


def _new_badge_text(finding: Finding) -> str:
    return " [NEW]" if finding.new else ""


class Renderer:
    def __init__(self, config, pair, report: DriftReport):
        self.cfg = config
        self.pair = pair
        self.report = report
        self.label_a = pair.primary_label or report.primary.name
        self.label_b = pair.secondary_label or report.secondary.name
        # The pair name is part of the subject and intro unless it is the
        # single-pair default, which would only add noise.
        self.pair_tag = "" if pair.name.lower() == "default" else pair.name

    # -- templates --------------------------------------------------------

    def _template(self, name) -> Template:
        path = os.path.join(self.cfg.template_dir, name)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                body = handle.read()
        except OSError as exc:
            raise RenderError("cannot read template %s: %s" % (path, exc))
        if name.endswith(".html"):
            body = _LEADING_COMMENT.sub("", body, count=1)
        return Template(body)

    def _render(self, name, context) -> str:
        try:
            return self._template(name).substitute(context)
        except KeyError as exc:
            raise RenderError("template %s uses placeholder %s which is not provided"
                              % (name, exc))
        except ValueError as exc:
            raise RenderError("template %s: %s (a literal $ must be written $$)"
                              % (name, exc))

    # -- pieces: HTML -----------------------------------------------------

    def _summary_table_html(self) -> str:
        r = self.report
        rows = [
            ("Rules retrieved", "%d" % r.primary.rule_total, "%d" % r.secondary.rule_total),
            ("Rules in scope", "%d" % r.primary.in_scope, "%d" % r.secondary.in_scope),
            ("Configuration as of", esc(_fmt_date(r.primary.revision_date)),
             esc(_fmt_date(r.secondary.revision_date))),
        ]
        out = [_TABLE, "<tr><th style=\"%s\"></th><th style=\"%s\">%s</th>"
               "<th style=\"%s\">%s</th></tr>"
               % (_HEAD, _HEAD, esc(self.label_a), _HEAD, esc(self.label_b))]
        for label, a, b in rows:
            out.append('<tr><td style="%s">%s</td><td style="%s">%s</td>'
                       '<td style="%s">%s</td></tr>' % (_CELL, label, _CELL, a, _CELL, b))
        out.append("</table>")
        return "".join(out)

    def _counts_table_html(self) -> str:
        r = self.report
        def row(label, value, alert=False, note=""):
            colour = COLOUR_ALERT if (alert and value) else "#333333"
            return ('<tr><td style="%s">%s</td><td style="%s text-align: right; '
                    'font-weight: bold; color: %s;">%d</td><td style="%s color: %s;">%s</td></tr>'
                    % (_CELL, label, _CELL, colour, value, _CELL, COLOUR_MUTED, note))
        out = [_TABLE]
        out.append(row("Matched on both sides", r.matched, note="same %s%s"
                       % ("vendor rule id" if r.match_by == "vendor_id" else "rule name",
                          " within the paired policy" if r.policy_pairs else "")))
        out.append(row("Identical", r.identical))
        out.append(row("Differ", len(r.changed), alert=True,
                       note="present on both, criteria differ"))
        out.append(row("Only on %s" % esc(self.label_a), len(r.only_primary), alert=True,
                       note="missing from %s" % esc(self.label_b)))
        out.append(row("Only on %s" % esc(self.label_b), len(r.only_secondary), alert=True,
                       note="not on %s" % esc(self.label_a)))
        if r.previous_run is not None:
            out.append(row("New since last run", r.new_count, alert=True,
                           note="last run %s" % esc(_fmt_date(r.previous_run))))
            out.append(row("Resolved since last run", len(r.resolved)))
        out.append("</table>")
        return "".join(out)

    def _rule_table_html(self, findings: List[Finding], side_label: str) -> str:
        if not findings:
            return _PARA % "None."
        shown = findings[: self.cfg.max_rows]
        out = [_TABLE, ('<tr><th style="%s">#</th><th style="%s">Rule</th>'
                        '<th style="%s">Policy</th><th style="%s">Action</th>'
                        '<th style="%s">Category</th><th style="%s">Source &rarr; Destination : Service</th></tr>'
                        % ((_HEAD,) * 6))]
        for finding in shown:
            rule = finding.rule
            out.append(
                '<tr><td style="%s text-align: right;">%d</td><td style="%s"><strong>%s</strong>%s%s</td>'
                '<td style="%s">%s</td><td style="%s">%s</td><td style="%s">%s</td><td style="%s">%s</td></tr>'
                % (_CELL, rule.order, _CELL, esc(rule.name), _new_badge_html(finding),
                   (' <span style="color: %s; font-size: 9pt;">(disabled)</span>' % COLOUR_MUTED)
                   if rule.disabled else "",
                   _CELL, esc(rule.policy), _CELL, esc(rule.action.title()),
                   _CELL, esc(rule.category or "-"), _CELL, esc(rule.summary())))
        out.append("</table>")
        if len(findings) > len(shown):
            out.append(_PARA % ("Showing %d of %d. The full list is in the attached CSV."
                                % (len(shown), len(findings))))
        return "".join(out)

    def _diff_values_html(self, values: List[str], marks: List[str], mark: str,
                          colour: str, bg: str) -> str:
        if not values:
            return '<span style="color: %s;">(none)</span>' % COLOUR_MUTED
        parts = []
        for value in values:
            if value in marks:
                parts.append('<span style="background-color: %s; color: %s;">%s%s</span>'
                             % (bg, colour, mark, esc(value)))
            else:
                parts.append(esc(value))
        return "<br>".join(parts)

    def _changed_html(self, findings: List[Finding]) -> str:
        """One table for every differing rule -- a rule row, then one row per
        differing field -- rather than a table per rule. Same content, about
        a third of the markup, which matters when Gmail clips at ~102 KB."""
        if not findings:
            return _PARA % "None."
        shown = findings[: self.cfg.max_diff_rules]
        rule_row = ('<tr><td colspan="3" style="padding: 8pt 6pt 3pt 6pt; border-bottom: '
                    '1px solid #d9d9d9;"><strong>%s</strong>%s <span style="color: %s; '
                    'font-size: 9pt;">%s #%d &middot; %s #%d</span></td></tr>')
        cell = 'padding: 3pt 6pt; border-bottom: 1px solid #eeeeee; vertical-align: top;'
        out = [_TABLE,
               '<tr><th style="%s width: 18%%;">Field</th><th style="%s width: 41%%;">%s</th>'
               '<th style="%s width: 41%%;">%s</th></tr>'
               % (_HEAD, _HEAD, esc(self.label_a), _HEAD, esc(self.label_b))]
        for finding in shown:
            a, b = finding.primary, finding.secondary
            out.append(rule_row % (esc(a.name), _new_badge_html(finding), COLOUR_MUTED,
                                   esc(a.policy), a.order, esc(b.policy), b.order))
            for diff in finding.diffs:
                if diff.is_list:
                    left = self._diff_values_html(diff.primary, diff.removed, "&minus; ",
                                                  COLOUR_ALERT, COLOUR_REMOVED_BG)
                    right = self._diff_values_html(diff.secondary, diff.added, "+ ",
                                                   COLOUR_GOOD, COLOUR_ADDED_BG)
                else:
                    left = '<span style="background-color: %s;">%s</span>' % (
                        COLOUR_REMOVED_BG, esc("; ".join(diff.primary)))
                    right = '<span style="background-color: %s;">%s</span>' % (
                        COLOUR_ADDED_BG, esc("; ".join(diff.secondary)))
                out.append('<tr><td style="%s">%s</td><td style="%s">%s</td>'
                           '<td style="%s">%s</td></tr>'
                           % (cell, esc(diff.label), cell, left, cell, right))
        out.append("</table>")
        if len(findings) > len(shown):
            out.append(_PARA % ("Showing %d of %d differing rules. Every difference is in "
                                "the attached CSV." % (len(shown), len(findings))))
        return "".join(out)

    def _resolved_html(self) -> str:
        if not self.report.resolved:
            return ""
        items = "".join('<li style="margin-bottom: 3pt;">%s</li>'
                        % esc(describe_fingerprint(fp, self.report.resolved_labels))
                        for fp in self.report.resolved[:50])
        more = ""
        if len(self.report.resolved) > 50:
            more = _PARA % ("and %d more." % (len(self.report.resolved) - 50))
        return (_section("Resolved Since Last Run") +
                (_PARA % "These differences were reported last time and are no longer present.") +
                '<ul style="margin: 4pt 0 10pt 0; padding-left: 18pt; line-height: 130%%;">%s</ul>%s'
                % (items, more))

    def _scope_html(self) -> str:
        r = self.report
        lines = []
        if r.policy_pairs:
            for a, b in r.policy_pairs:
                lines.append("policy <strong>%s</strong> on %s compared with <strong>%s</strong> on %s"
                             % (esc(a), esc(self.label_a), esc(b), esc(self.label_b)))
        else:
            lines.append("every security policy on each device, matched across policies")
        lines.append("rules matched by %s" % esc(self._matching_phrase()))
        if r.filter_lines:
            lines.extend("filter &mdash; %s" % esc(line) for line in r.filter_lines)
        else:
            lines.append("no rule filter: every rule in the policies above")
        lines.append("fields compared: %s" % esc(", ".join(field_label(f).lower() for f in r.fields)))
        lines.append("objects compared by %s" % {
            "name": "name", "contents": "resolved contents (addresses and ports), not name",
            "both": "name and resolved contents"}[r.object_mode])
        for line in r.normalise_lines:
            lines.append("name normalisation &mdash; %s" % esc(line))
        return ('<ul style="margin: 4pt 0 10pt 0; padding-left: 18pt; line-height: 130%%;">%s</ul>'
                % "".join('<li style="margin-bottom: 3pt;">%s</li>' % l for l in lines))

    # -- matching and revision notes ----------------------------------------

    def _matching_phrase(self) -> str:
        if self.report.match_by == "vendor_id":
            return "the vendor's rule id (name where a rule has none)"
        return "name"

    def _matching_note(self) -> str:
        """The 'important information' bullet on how rules were paired."""
        if self.report.match_by == "vendor_id":
            return ("Rules are matched by the vendor's own rule id, so a rule renamed "
                    "on one side is reported as a difference in its name.")
        return ("Rules are matched by name. A rule renamed on one side appears as "
                "missing on that side and extra on the other.")

    def _revision_warning_sentences(self):
        """Empty unless the two configurations FireMon holds were retrieved
        further apart than the configured limit."""
        r = self.report
        if not r.revisions_stale:
            return []
        older_label = self.label_a if r.older_side == "primary" else self.label_b
        skew = describe_skew(r.revision_skew_hours())
        return [
            "Check before acting on this report: the configurations FireMon holds for "
            "the two firewalls were retrieved %s apart (%s on %s, %s on %s)."
            % (skew, _fmt_date(r.primary.revision_date), self.label_a,
               _fmt_date(r.secondary.revision_date), self.label_b),
            "Any difference below may be retrieval lag rather than policy drift. "
            "Confirm that FireMon has retrieved the current configuration of %s "
            "and rerun; the report compares what FireMon holds, not the firewalls."
            % older_label,
        ]

    def _revision_warning_html(self) -> str:
        sentences = self._revision_warning_sentences()
        if not sentences:
            return ""
        return ('<p style="margin: 0 0 10pt 0; padding: 6pt 8pt; line-height: 130%%; '
                'border-left: 4px solid %s; background-color: %s;">'
                '<strong>Configurations are not from the same time.</strong> %s</p>'
                % (COLOUR_ALERT, COLOUR_REMOVED_BG, esc(" ".join(sentences))))

    def _revision_warning_text(self) -> str:
        sentences = self._revision_warning_sentences()
        if not sentences:
            return ""
        lines = ["WARNING: configurations are not from the same time."]
        for sentence in sentences:
            lines.extend("  " + l for l in _wrap(sentence, 72))
        return "\n".join(lines) + "\n"

    def _headline(self) -> str:
        r = self.report
        if not r.has_drift:
            return ("No drift. Every rule in scope on %s has a matching rule on %s "
                    "with identical criteria, and vice versa." % (self.label_a, self.label_b))
        parts = []
        if r.changed:
            parts.append("%d %s on both firewalls with different criteria"
                         % (len(r.changed), _plural(len(r.changed), "rule")))
        if r.only_primary:
            parts.append("%d only on %s" % (len(r.only_primary), self.label_a))
        if r.only_secondary:
            parts.append("%d only on %s" % (len(r.only_secondary), self.label_b))
        text = "Drift found: " + "; ".join(parts) + "."
        if r.previous_run is not None:
            if r.new_count:
                text += " %d %s new since the last run." % (r.new_count, _plural(r.new_count, "finding"))
            else:
                text += " Nothing new since the last run."
        return text

    # -- pieces: text -----------------------------------------------------

    def _summary_text(self) -> str:
        r = self.report
        date_a, date_b = _fmt_date(r.primary.revision_date), _fmt_date(r.secondary.revision_date)
        width = max(len(self.label_a), len(self.label_b), len(date_a), len(date_b), 10)
        lines = [
            "  %-22s %*s  %*s" % ("", width, self.label_a, width, self.label_b),
            "  %-22s %*d  %*d" % ("Rules retrieved", width, r.primary.rule_total, width, r.secondary.rule_total),
            "  %-22s %*d  %*d" % ("Rules in scope", width, r.primary.in_scope, width, r.secondary.in_scope),
            "  %-22s %*s  %*s" % ("Config as of", width, date_a, width, date_b),
            "",
            "  Matched on both sides : %d" % r.matched,
            "  Identical             : %d" % r.identical,
            "  Differ                : %d" % len(r.changed),
            "  Only on %-14s: %d" % (self.label_a[:14], len(r.only_primary)),
            "  Only on %-14s: %d" % (self.label_b[:14], len(r.only_secondary)),
        ]
        if r.previous_run is not None:
            lines.append("  New since last run    : %d  (last run %s)" % (r.new_count, _fmt_date(r.previous_run)))
            lines.append("  Resolved since last   : %d" % len(r.resolved))
        return "\n".join(lines)

    def _rule_list_text(self, findings: List[Finding]) -> str:
        if not findings:
            return "  (none)"
        lines = []
        for finding in findings[: self.cfg.max_rows]:
            rule = finding.rule
            lines.append("  #%-5d %s%s%s" % (rule.order, rule.name, _new_badge_text(finding),
                                             " (disabled)" if rule.disabled else ""))
            lines.append("         policy %s | %s | %s" % (rule.policy, rule.action.title(),
                                                           rule.category or "no category"))
            lines.append("         %s" % rule.summary())
        if len(findings) > self.cfg.max_rows:
            lines.append("  ... %d more in the attached CSV" % (len(findings) - self.cfg.max_rows))
        return "\n".join(lines)

    def _changed_text(self, findings: List[Finding]) -> str:
        if not findings:
            return "  (none)"
        lines = []
        for finding in findings[: self.cfg.max_diff_rules]:
            a, b = finding.primary, finding.secondary
            lines.append("  %s%s   [%s #%d | %s #%d]" % (a.name, _new_badge_text(finding),
                                                         a.policy, a.order, b.policy, b.order))
            for diff in finding.diffs:
                lines.append("    %s:" % diff.label)
                if diff.is_list:
                    for value in diff.primary:
                        lines.append("      %s %s" % ("-" if value in diff.removed else " ", value))
                    for value in diff.added:
                        lines.append("      + %s" % value)
                else:
                    lines.append("      %s: %s" % (self.label_a, "; ".join(diff.primary)))
                    lines.append("      %s: %s" % (self.label_b, "; ".join(diff.secondary)))
        if len(findings) > self.cfg.max_diff_rules:
            lines.append("  ... %d more differing rules in the attached CSV"
                         % (len(findings) - self.cfg.max_diff_rules))
        return "\n".join(lines)

    def _scope_text(self) -> str:
        r = self.report
        lines = []
        if r.policy_pairs:
            for a, b in r.policy_pairs:
                lines.append("  * policy '%s' on %s compared with '%s' on %s"
                             % (a, self.label_a, b, self.label_b))
        else:
            lines.append("  * every security policy on each device, matched across policies")
        lines.append("  * rules matched by %s" % self._matching_phrase())
        if r.filter_lines:
            lines.extend("  * filter - %s" % line for line in r.filter_lines)
        else:
            lines.append("  * no rule filter: every rule in the policies above")
        lines.append("  * fields compared: %s" % ", ".join(field_label(f).lower() for f in r.fields))
        lines.append("  * objects compared by %s" % r.object_mode)
        for line in r.normalise_lines:
            lines.append("  * name normalisation - %s" % line)
        return "\n".join(lines)

    def _resolved_text(self) -> str:
        if not self.report.resolved:
            return ""
        lines = ["", "RESOLVED SINCE LAST RUN", "-----------------------"]
        lines.extend("  * %s" % describe_fingerprint(fp, self.report.resolved_labels)
                     for fp in self.report.resolved[:50])
        if len(self.report.resolved) > 50:
            lines.append("  ... and %d more" % (len(self.report.resolved) - 50))
        return "\n".join(lines)

    # -- the email --------------------------------------------------------

    def subject(self) -> str:
        r = self.report
        head = "Policy drift [%s]" % self.pair_tag if self.pair_tag else "Policy drift"
        if r.has_drift:
            body = "%s: %s vs %s -- %d %s" % (
                head, self.label_a, self.label_b, len(r.findings), _plural(len(r.findings), "finding"))
            if r.previous_run is not None and r.new_count:
                body += " (%d new)" % r.new_count
        else:
            body = "%s: %s vs %s -- no drift" % (head, self.label_a, self.label_b)
        if r.revisions_stale:
            body += " [configs %s apart]" % describe_skew(r.revision_skew_hours())
        if self.pair.subject_prefix:
            body = "%s %s" % (self.pair.subject_prefix, body)
        return body

    def render(self):
        r = self.report
        context = {
            "primary": esc(self.label_a),
            "secondary": esc(self.label_b),
            "primary_device": esc(r.primary.name),
            "secondary_device": esc(r.secondary.name),
            "pair_note": (" for pair &ldquo;%s&rdquo;" % esc(self.pair_tag)) if self.pair_tag else "",
            "headline": esc(self._headline()),
            "revision_warning": self._revision_warning_html(),
            "matching_note": esc(self._matching_note()),
            "summary_table": self._summary_table_html(),
            "counts_table": self._counts_table_html(),
            "scope": self._scope_html(),
            "only_primary_table": self._rule_table_html(r.only_primary, self.label_a),
            "only_secondary_table": self._rule_table_html(r.only_secondary, self.label_b),
            "changed_section": self._changed_html(r.changed),
            "resolved_section": self._resolved_html(),
            "portal_url": esc(self.cfg.portal_url),
            "support_email": esc(self.cfg.support_email),
            "from_name": esc(self.cfg.from_name),
            "generated_at": esc(r.generated_at.strftime("%d %B %Y at %H:%M %Z")),
        }
        html_body = self._render("drift.html", context)

        text_context = {
            "primary": self.label_a,
            "secondary": self.label_b,
            "primary_device": r.primary.name,
            "secondary_device": r.secondary.name,
            "pair_note": (" (pair %s)" % self.pair_tag) if self.pair_tag else "",
            "headline": self._headline(),
            "revision_warning": self._revision_warning_text(),
            "matching_note": self._matching_note(),
            "summary": self._summary_text(),
            "scope": self._scope_text(),
            "only_primary_list": self._rule_list_text(r.only_primary),
            "only_secondary_list": self._rule_list_text(r.only_secondary),
            "changed_list": self._changed_text(r.changed),
            "resolved_section": self._resolved_text(),
            "portal_url": self.cfg.portal_url,
            "support_email": self.cfg.support_email,
            "from_name": self.cfg.from_name,
            "generated_at": r.generated_at.strftime("%d %B %Y at %H:%M %Z"),
        }
        text_body = self._render("drift.txt", text_context)
        if len(html_body.encode("utf-8")) > GMAIL_CLIP_BYTES:
            LOG.warning(
                "the HTML body is %d KB; Gmail clips messages over ~%d KB and hides "
                "the rest. Lower [email] max_rows / max_diff_rules, or narrow the "
                "comparison with a filter -- the CSV always carries everything.",
                len(html_body.encode("utf-8")) // 1024, GMAIL_CLIP_BYTES // 1024)
        return self.subject(), html_body, text_body

    # -- attachments ------------------------------------------------------

    def csv_bytes(self) -> bytes:
        """One row per finding, and per differing field for a changed rule,
        so it pivots in a spreadsheet without reshaping."""
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\r\n")
        writer.writerow([
            "finding", "new", "rule", "primary_policy", "primary_position",
            "secondary_policy", "secondary_position", "field",
            "primary_value", "secondary_value", "removed_on_secondary",
            "added_on_secondary", "action", "category", "primary_last_changed",
            "secondary_last_changed",
        ])
        for finding in self.report.findings:
            a, b = finding.primary, finding.secondary
            rule = finding.rule
            base = [
                {ONLY_PRIMARY: "only on primary", ONLY_SECONDARY: "only on secondary",
                 CHANGED: "differs"}[finding.kind],
                "yes" if finding.new else "",
                rule.name,
                a.policy if a else "", a.order if a else "",
                b.policy if b else "", b.order if b else "",
            ]
            tail = [rule.action, rule.category,
                    a.last_changed if a else "", b.last_changed if b else ""]
            if finding.kind == CHANGED:
                for diff in finding.diffs:
                    writer.writerow(base + [
                        diff.label, " | ".join(diff.primary), " | ".join(diff.secondary),
                        " | ".join(diff.removed), " | ".join(diff.added)] + tail)
            else:
                writer.writerow(base + ["", rule.summary(limit=50) if a else "",
                                        rule.summary(limit=50) if b else "", "", ""] + tail)
        return buf.getvalue().encode("utf-8-sig")

    def json_bytes(self) -> bytes:
        r = self.report
        def rule_dict(rule: Rule):
            if rule is None:
                return None
            return {
                "name": rule.name, "policy": rule.policy, "position": rule.order,
                "action": rule.action, "disabled": rule.disabled, "log": rule.log,
                "category": rule.category, "device": rule.device_name,
                "match_id": rule.match_id, "last_changed": rule.last_changed,
                "sources": [o.display() for o in rule.sources],
                "destinations": [o.display() for o in rule.destinations],
                "services": [o.display() for o in rule.services],
                "applications": [o.display() for o in rule.applications],
                "source_zones": [o.display() for o in rule.source_zones],
                "destination_zones": [o.display() for o in rule.destination_zones],
                "properties": rule.props,
            }
        payload = {
            "generated_at": r.generated_at.isoformat(),
            "primary": {"id": r.primary.id, "name": r.primary.name,
                        "revision": r.primary.revision_id, "as_of": r.primary.revision_date,
                        "rules": r.primary.rule_total, "in_scope": r.primary.in_scope},
            "secondary": {"id": r.secondary.id, "name": r.secondary.name,
                          "revision": r.secondary.revision_id, "as_of": r.secondary.revision_date,
                          "rules": r.secondary.rule_total, "in_scope": r.secondary.in_scope},
            "matched": r.matched, "identical": r.identical,
            "policy_pairs": r.policy_pairs, "filters": r.filter_lines,
            "fields": list(r.fields), "object_mode": r.object_mode,
            "previous_run": r.previous_run, "resolved": r.resolved,
            "findings": [
                {
                    "kind": f.kind, "rule": f.name, "new": f.new,
                    "primary": rule_dict(f.primary), "secondary": rule_dict(f.secondary),
                    "differences": [
                        {"field": d.field, "label": d.label, "primary": d.primary,
                         "secondary": d.secondary, "added": d.added, "removed": d.removed}
                        for d in f.diffs
                    ],
                }
                for f in r.findings
            ],
        }
        return json.dumps(payload, indent=1, ensure_ascii=False).encode("utf-8")

    def attachments(self):
        stem = "policy-drift-%s-vs-%s-%s" % (
            _slug(self.report.primary.name), _slug(self.report.secondary.name),
            self.report.generated_at.strftime("%Y%m%d"))
        items = []
        if self.cfg.attach_csv:
            items.append((stem + ".csv", self.csv_bytes(), "text", "csv"))
        if self.cfg.attach_json:
            items.append((stem + ".json", self.json_bytes(), "application", "json"))
        return items


_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _slug(value) -> str:
    return _UNSAFE.sub("_", str(value)).strip("_") or "device"


def _wrap(text: str, width: int) -> List[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = (current + " " + word) if current else word
    if current:
        lines.append(current)
    return lines


def _fmt_date(value) -> str:
    """ISO timestamp from the API -> 'YYYY-MM-DD HH:MM UTC'; anything else
    is passed through, and None becomes 'unknown'."""
    if not value:
        return "unknown"
    text = str(value)
    match = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})", text)
    if match:
        return "%s %s UTC" % (match.group(1), match.group(2))
    return text
