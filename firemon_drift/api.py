"""FireMon Security Manager REST client, standard library only.

urllib rather than requests so there is no install step on the appliance.
One session token covers every call.

Rules come from the SIQL security-rule search, which returns each rule with
its policy, its objects (fully expanded, groups included) and its zones in a
single paged query -- everything the comparison needs except the rule
documentation properties, which are one small call per rule.

Verified against FMOS 2026.2.6:
  * /siql/secrule/paged-search with  domain{id=N} and device{id=N}
    optionally  and policy{name='...'}  -- single quotes; double quotes are
    rejected by the parser.
  * /siql/policy/paged-search and /siql/device/paged-search take the same
    domain{} and device{} clauses.
  * /domain/N/device/N/rule/<matchId>/ruledoc returns the rule's custom
    properties. There is no bulk read.
"""

import base64
import json
import logging
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

LOG = logging.getLogger(__name__)


class ApiError(Exception):
    """Any unrecoverable API problem. Always fatal to the run."""


class AuthError(ApiError):
    """Authentication failed. Never proceed: a partial dataset would compare
    a whole policy against nothing and report every rule as drift."""


def _siql_literal(value: str) -> str:
    """Quote a string for a SIQL clause. Single quotes are the form the parser
    accepts; an embedded one is doubled, the SQL way."""
    return "'" + str(value).replace("'", "''") + "'"


class FireMonClient:
    def __init__(self, config):
        self.cfg = config
        self._auth_header = None
        self._ssl_context = self._build_ssl_context()

    # -- transport --------------------------------------------------------

    def _build_ssl_context(self):
        if not self.cfg.verify_tls:
            LOG.warning(
                "TLS verification is DISABLED (verify_tls=false). Fine for "
                "https://localhost on the appliance; do not ship this to a "
                "remote production URL."
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        if self.cfg.ca_bundle:
            return ssl.create_default_context(cafile=self.cfg.ca_bundle)
        return ssl.create_default_context()

    def _request_full(self, method, path, body=None, allow_status=()):
        """One request with retry on transient failure. Returns (status,
        parsed body, headers). 4xx other than 429 is returned, not retried."""
        url = self.cfg.base_url + path
        payload = None
        headers = {"Accept": "application/json"}
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self._auth_header:
            headers[self._auth_header[0]] = self._auth_header[1]

        last_error = None
        for attempt in range(1, self.cfg.max_retries + 1):
            request = urllib.request.Request(
                url, data=payload, headers=headers, method=method
            )
            try:
                with urllib.request.urlopen(
                    request, timeout=self.cfg.timeout, context=self._ssl_context
                ) as response:
                    raw = response.read().decode("utf-8", errors="replace")
                    return response.getcode(), self._parse(raw), response.headers
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8", errors="replace")
                if exc.code in allow_status or (400 <= exc.code < 500 and exc.code != 429):
                    return exc.code, self._parse(raw), exc.headers
                last_error = "HTTP %s: %s" % (exc.code, raw[:300])
            except (urllib.error.URLError, ssl.SSLError, OSError) as exc:
                last_error = str(exc)

            if attempt < self.cfg.max_retries:
                backoff = 2 ** (attempt - 1)
                LOG.warning("%s %s failed (%s); retrying in %ds (attempt %d/%d)",
                            method, path, last_error, backoff, attempt + 1,
                            self.cfg.max_retries)
                time.sleep(backoff)

        raise ApiError("%s %s failed after %d attempts: %s"
                       % (method, path, self.cfg.max_retries, last_error))

    def _request(self, method, path, body=None, allow_status=()):
        status, data, _ = self._request_full(method, path, body, allow_status)
        return status, data

    @staticmethod
    def _parse(raw):
        if not raw.strip():
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return raw

    # -- auth -------------------------------------------------------------

    def authenticate(self):
        if self.cfg.auth_mode == "basic":
            raw = "%s:%s" % (self.cfg.username, self.cfg.password)
            encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
            self._auth_header = ("Authorization", "Basic " + encoded)
            self._probe()
            LOG.info("authenticated with HTTP basic as %s", self.cfg.username)
            return

        supplied_token = bool(self.cfg.token)
        token = self.cfg.token or self._exchange_password_for_token()
        # A login token travels as a cookie; a pre-supplied one is tried as a
        # cookie then as a bearer token, since builds differ.
        self._auth_header = ("Cookie", "authToken=" + token)
        try:
            self._probe()
        except AuthError:
            self._auth_header = ("Authorization", "Bearer " + token)
            try:
                self._probe()
            except AuthError:
                if supplied_token:
                    raise AuthError(
                        "the configured token was rejected (HTTP 401) as a "
                        "cookie and as a bearer token. Remove it and use a "
                        "username with the password in FMDRIFT_PASSWORD."
                    )
                raise
        LOG.info("authenticated with token")

    def _exchange_password_for_token(self):
        """/authentication/login returns the token in the body and as a
        Set-Cookie. The cookie value is already percent-encoded and the body
        value is not, so prefer the header and encode the body on fallback."""
        status, data, headers = self._request_full(
            "POST",
            "/securitymanager/api/authentication/login",
            {"username": self.cfg.username, "password": self.cfg.password},
            allow_status=(401, 403),
        )
        if status != 200:
            raise AuthError("login failed for %s (HTTP %s). Check username/password."
                            % (self.cfg.username, status))
        if isinstance(data, dict) and data.get("authorized") is False:
            raise AuthError("login rejected for %s: %s"
                            % (self.cfg.username,
                               data.get("message") or data.get("authStatus")))
        cookie_token = self._token_from_headers(headers)
        if cookie_token:
            return cookie_token
        raw_token = data.get("token") if isinstance(data, dict) else None
        if raw_token:
            return urllib.parse.quote(str(raw_token), safe="")
        raise AuthError("login succeeded but returned no token")

    @staticmethod
    def _token_from_headers(headers):
        if headers is None:
            return None
        try:
            cookies = headers.get_all("Set-Cookie") or []
        except AttributeError:
            single = headers.get("Set-Cookie")
            cookies = [single] if single else []
        for cookie in cookies:
            for part in str(cookie).split(";"):
                name, sep, value = part.strip().partition("=")
                if sep and name.strip().lower() == "authtoken" and value.strip():
                    return value.strip()
        return None

    def _probe(self):
        status, data = self._request(
            "GET", "/securitymanager/api/user/current", allow_status=(401, 403)
        )
        if status in (401, 403):
            raise AuthError("credentials rejected by FireMon (HTTP %s)" % status)
        if status != 200:
            raise ApiError("auth probe returned HTTP %s" % status)
        if isinstance(data, dict):
            LOG.debug("authenticated as %s", data.get("username"))

    # -- SIQL paging ------------------------------------------------------

    def _siql_path(self, kind, query, page, page_size):
        return "/securitymanager/api/siql/%s/paged-search?q=%s&page=%d&pageSize=%d" % (
            kind, urllib.parse.quote(query, safe=""), page, page_size)

    def siql(self, kind, query, page_size=None, progress_label=None) -> List[dict]:
        """Page through one SIQL query. Dedupes on matchId because a policy
        being retrieved while we page can shift rows between pages."""
        page_size = page_size or self.cfg.page_size
        collected = {}
        order = []
        page = 0
        total = None
        while True:
            status, data = self._request("GET", self._siql_path(kind, query, page, page_size))
            if status != 200 or not isinstance(data, dict):
                detail = ""
                if isinstance(data, dict):
                    detail = data.get("message") or ""
                elif isinstance(data, str):
                    detail = data[:200]
                raise ApiError("SIQL %s search failed on page %d (HTTP %s) for %r%s"
                               % (kind, page, status, query,
                                  (": " + detail) if detail else ""))
            results = data.get("results") or []
            total = int(data.get("total") or 0)
            for row in results:
                marker = row.get("matchId") or row.get("id") or len(order)
                if marker not in collected:
                    collected[marker] = row
                    order.append(marker)
            if progress_label and total > page_size:
                LOG.info("%s: %d of %d", progress_label, min(len(order), total), total)
            if not results or len(order) >= total:
                break
            page += 1
            if page > (total // page_size) + 3:
                LOG.warning("SIQL %s: result set kept growing while paging; "
                            "stopping at %d rows", kind, len(order))
                break
        return [collected[m] for m in order]

    # -- devices ----------------------------------------------------------

    def list_devices(self, pattern: Optional[str] = None) -> List[dict]:
        """Firewall devices, optionally those whose name contains `pattern`.
        SIQL first (server-side filter); falls back to paging the device
        list on a server whose SIQL device search misbehaves."""
        query = "domain{id=%d}" % self.cfg.domain_id
        if pattern:
            query += " and device{name ~ %s}" % _siql_literal(pattern)
        try:
            rows = self.siql("device", query)
        except ApiError as exc:
            LOG.debug("SIQL device search failed (%s); paging the device list", exc)
            rows = self._page_devices()
            if pattern:
                needle = pattern.lower()
                rows = [d for d in rows if needle in (d.get("name") or "").lower()]
        devices = []
        for row in rows:
            pack = row.get("devicePack") or {}
            devices.append({
                "id": row.get("id"),
                "name": row.get("name") or "",
                "managementIp": row.get("managementIp") or "",
                "vendor": pack.get("vendor") or row.get("vendor") or "",
                "product": pack.get("deviceName") or row.get("product") or "",
                "type": pack.get("deviceType") or row.get("deviceType") or "",
                "description": row.get("description") or "",
            })
        devices.sort(key=lambda d: (d["name"].lower(), d["id"] or 0))
        return devices

    def _page_devices(self) -> List[dict]:
        rows = []
        page = 0
        while page < 200:
            status, data = self._request(
                "GET", "/securitymanager/api/domain/%d/device?page=%d&pageSize=100"
                % (self.cfg.domain_id, page))
            if status != 200 or not isinstance(data, dict):
                raise ApiError("could not list devices (HTTP %s)" % status)
            results = data.get("results") or []
            rows.extend(results)
            if not results or len(rows) >= int(data.get("total") or 0):
                break
            page += 1
        return rows

    def get_device(self, name_or_id: str) -> dict:
        """Resolve a device by exact name (case-insensitive) or numeric id.
        Ambiguity is an error, never a guess: comparing the wrong firewall
        produces a confident report about nothing."""
        text = str(name_or_id).strip()
        if text.isdigit():
            status, data = self._request(
                "GET", "/securitymanager/api/domain/%d/device/%s"
                % (self.cfg.domain_id, text), allow_status=(404,))
            if status == 200 and isinstance(data, dict):
                return {"id": data.get("id"), "name": data.get("name") or text}
            raise ApiError("no device with id %s in domain %d" % (text, self.cfg.domain_id))
        candidates = [d for d in self.list_devices(text)
                      if (d["name"] or "").lower() == text.lower()]
        if len(candidates) == 1:
            return candidates[0]
        if not candidates:
            similar = [d["name"] for d in self.list_devices(text)][:8]
            hint = (" Similar names: %s" % ", ".join(similar)) if similar else ""
            raise ApiError("no device named %r in domain %d.%s Use --list-devices."
                           % (text, self.cfg.domain_id, hint))
        raise ApiError("device name %r matches %d devices (ids %s); use the id"
                       % (text, len(candidates), ", ".join(str(c["id"]) for c in candidates)))

    def latest_revision(self, device_id: int) -> Tuple[Optional[int], Optional[str]]:
        """(revision id, retrieval timestamp) of the device's current
        normalised configuration -- the 'as of' the report quotes."""
        status, data = self._request(
            "GET", "/securitymanager/api/domain/%d/device/%d/rev/latest"
            % (self.cfg.domain_id, device_id), allow_status=(404,))
        if status != 200 or not isinstance(data, dict):
            return None, None
        return data.get("id"), data.get("createDate") or data.get("completeDate")

    # -- policies and rules -----------------------------------------------

    def list_policies(self, device_id: int) -> List[dict]:
        rows = self.siql("policy", "domain{id=%d} and device{id=%d}"
                         % (self.cfg.domain_id, device_id))
        policies = []
        for row in rows:
            policies.append({
                "name": row.get("name") or "",
                "displayName": row.get("displayName") or row.get("name") or "",
                "ruleCount": int(row.get("ruleCount") or 0),
                "policyType": row.get("policyType") or "",
                "matchId": row.get("matchId") or "",
            })
        policies.sort(key=lambda p: (-p["ruleCount"], p["displayName"].lower()))
        return policies

    def fetch_rules(self, device_id: int, device_name: str,
                    policy_names: Optional[List[str]] = None) -> List[dict]:
        """Every security rule on a device, or only those in the named
        policies. The policy clause is tried server-side and, if the server
        rejects it, applied client-side over a full fetch -- correct either
        way, just slower on the fallback."""
        base = "domain{id=%d} and device{id=%d}" % (self.cfg.domain_id, device_id)
        if not policy_names:
            return self.siql("secrule", base, progress_label="%s rules" % device_name)

        rows = []
        seen = set()
        everything = None  # full fetch, made once, only if a policy clause fails
        for policy_name in policy_names:
            query = "%s and policy{name=%s}" % (base, _siql_literal(policy_name))
            fetched = None
            if everything is None:
                try:
                    fetched = self.siql("secrule", query,
                                        progress_label="%s / %s rules" % (device_name, policy_name))
                except ApiError as exc:
                    LOG.warning("server rejected the policy clause for %r (%s); "
                                "fetching every rule and filtering here", policy_name, exc)
            if not fetched:
                # Either the clause was rejected, or it matched nothing: on
                # Firepower a policy's SIQL `name` can be a vendor id while
                # the operator knows it by its display name. Match either.
                if everything is None:
                    everything = self.siql("secrule", base,
                                           progress_label="%s rules" % device_name)
                fetched = [r for r in everything if _policy_matches(r, policy_name)]
                if not fetched:
                    LOG.warning("%s: no rules found in a policy named %r",
                                device_name, policy_name)
            for row in fetched:
                marker = row.get("matchId")
                if marker in seen:
                    continue
                seen.add(marker)
                rows.append(row)
        return rows

    def fetch_ruledoc(self, device_id: int, match_id: str) -> dict:
        status, data = self._request(
            "GET", "/securitymanager/api/domain/%d/device/%d/rule/%s/ruledoc"
            % (self.cfg.domain_id, device_id, urllib.parse.quote(str(match_id), safe="")),
            allow_status=(404,))
        if status != 200 or not isinstance(data, dict):
            return {}
        return data

    def fetch_ruledocs(self, device_id: int, device_name: str,
                       match_ids: List[str]) -> Dict[str, dict]:
        """Rule documentation for many rules. One call each -- there is no
        bulk read -- but each is small and, on the appliance, local."""
        out = {}
        total = len(match_ids)
        started = time.time()
        for n, match_id in enumerate(match_ids, 1):
            out[match_id] = self.fetch_ruledoc(device_id, match_id)
            if n % 250 == 0 or n == total:
                LOG.info("%s rule documentation: %d of %d (%.0fs)",
                         device_name, n, total, time.time() - started)
        return out


def _policy_matches(rule: dict, policy_name: str) -> bool:
    policy = rule.get("policy") or {}
    wanted = policy_name.strip().lower()
    return wanted in ((policy.get("name") or "").strip().lower(),
                      (policy.get("displayName") or "").strip().lower())
