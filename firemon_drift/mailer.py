"""Delivery: one message to the configured recipients, a dry-run preview, and
a JSON ledger of every attempt.

--to-override redirects the message to a single address and stamps the
intended recipients into the subject: the safe way to test against a system
whose recipient list is a real distribution group.
"""

import json
import logging
import os
import smtplib
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from typing import List

from .model import SendResult

LOG = logging.getLogger(__name__)


class Mailer:
    def __init__(self, config, run_id, dry_run=False, to_override=None):
        self.cfg = config
        self.run_id = run_id
        self.dry_run = dry_run
        self.to_override = (to_override or "").strip()
        self._ledger_path = os.path.join(config.output_dir, "ledger-%s.jsonl" % run_id)
        os.makedirs(config.output_dir, exist_ok=True)

    def _connect(self):
        LOG.debug("connecting to SMTP %s:%d", self.cfg.smtp_host, self.cfg.smtp_port)
        smtp = smtplib.SMTP(self.cfg.smtp_host, self.cfg.smtp_port,
                            timeout=self.cfg.smtp_timeout)
        smtp.ehlo()
        if self.cfg.smtp_starttls:
            smtp.starttls()
            smtp.ehlo()
        if self.cfg.smtp_username:
            smtp.login(self.cfg.smtp_username, self.cfg.smtp_password)
        return smtp

    def _build(self, recipients: List[str], subject, html_body, text_body, attachments):
        actual = [self.to_override] if self.to_override else list(recipients)
        if self.to_override:
            subject = "[TEST -> %s] %s" % (", ".join(recipients) or "nobody", subject)
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = formataddr((self.cfg.from_name, self.cfg.from_address))
        message["To"] = ", ".join(actual)
        message["Date"] = formatdate(localtime=True)
        message["Message-ID"] = make_msgid(domain="firemon-drift")
        if self.cfg.reply_to:
            message["Reply-To"] = self.cfg.reply_to
        message["Auto-Submitted"] = "auto-generated"
        message["X-FireMon-Drift"] = self.run_id
        message.set_content(text_body)
        message.add_alternative(html_body, subtype="html")
        for name, data, maintype, subtype in attachments or ():
            message.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
        return message, actual, subject

    def deliver(self, recipients, subject, html_body, text_body, attachments=None) -> SendResult:
        message, actual, subject = self._build(recipients, subject, html_body,
                                               text_body, attachments)
        result = SendResult(recipients=list(recipients), actual_recipients=actual,
                            subject=subject, sent=False, dry_run=self.dry_run)
        if self.dry_run:
            try:
                self.write_preview(message, html_body, text_body, attachments)
                result.sent = True
            except OSError as exc:
                result.error = "%s: %s" % (type(exc).__name__, exc)
                LOG.error("FAILED to write the dry-run preview: %s", result.error)
            self._append_ledger(result)
            return result

        if not actual:
            result.error = "no recipients configured"
            LOG.error("nobody to send to: [email] recipients is empty")
            self._append_ledger(result)
            return result

        smtp = None
        try:
            smtp = self._connect()
            smtp.send_message(message)
            result.sent = True
            LOG.info("sent to %s", ", ".join(actual))
        except (smtplib.SMTPException, OSError) as exc:
            result.error = "%s: %s" % (type(exc).__name__, exc)
            LOG.error("FAILED to send to %s: %s", ", ".join(actual), result.error)
        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except (smtplib.SMTPException, OSError):
                    pass
        self._append_ledger(result)
        return result

    def write_preview(self, message, html_body, text_body, attachments) -> str:
        """Render the message to output_dir: .html, .txt, the full .eml, and
        each attachment beside them. Returns the .html path."""
        stem = os.path.join(self.cfg.output_dir, "drift-%s" % self.run_id)
        with open(stem + ".html", "w", encoding="utf-8") as handle:
            handle.write(html_body)
        with open(stem + ".txt", "w", encoding="utf-8") as handle:
            handle.write(text_body)
        with open(stem + ".eml", "w", encoding="utf-8") as handle:
            handle.write(message.as_string())
        for name, data, _, _ in attachments or ():
            ext = os.path.splitext(name)[1] or ".dat"
            with open(stem + ext, "wb") as handle:
                handle.write(data)
        LOG.info("[dry-run] rendered the report -> %s.html", stem)
        return stem + ".html"

    def _append_ledger(self, result: SendResult):
        record = {
            "run_id": self.run_id,
            "intended_recipients": result.recipients,
            "actual_recipients": result.actual_recipients,
            "subject": result.subject,
            "sent": result.sent,
            "dry_run": result.dry_run,
            "error": result.error,
        }
        try:
            with open(self._ledger_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
        except OSError as exc:
            LOG.warning("could not write ledger %s: %s", self._ledger_path, exc)

    @property
    def ledger_path(self):
        return self._ledger_path
