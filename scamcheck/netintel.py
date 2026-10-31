"""URL forensics for explicit investigations: redirects, TLS, domain age.

This is the only detector module that *deliberately* goes online, and only when
the user runs an investigate command. Nothing is fetched during a normal
message check. The URL itself is contacted for redirects/TLS; the registered
domain is sent to rdap.org for registration age. No message content is sent.

Public API:
    investigate_url(url, timeout=8, max_redirects=6, want_rdap=True)
        -> dict with redirect chain, final URL, TLS cert, RDAP age, risk notes

Private/loopback targets are refused by default (`allow_private=True` is for
tests and self-hosted debugging).
"""

import ipaddress
import json
import re
import socket
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from .rules import SHORTENERS

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) scamcheck/0.12 (+local investigation)"
MAX_BODY = 65536


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = build_opener(_NoRedirect)


def _public_host(host):
    host = (host or "").strip("[]").lower()
    if not host or host == "localhost" or host.endswith(".local"):
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return not (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast or ip.is_unspecified)
    # Resolve names too: a public-looking hostname can point at 127.0.0.1.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True  # let the request itself report the DNS failure
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return False
    return True


def _normalize(url):
    url = (url or "").strip().strip("<>\"'")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    return url


def _fetch(url, timeout):
    req = Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*"})
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(MAX_BODY) if resp.status == 200 else b""
            return resp.status, headers, resp.geturl(), body
    except HTTPError as exc:
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        return exc.code, headers, url, b""
    except (URLError, OSError, ValueError) as exc:
        raise RuntimeError(str(exc))


def _title(body):
    if not body:
        return ""
    match = re.search(br"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not match:
        return ""
    text = match.group(1).decode("utf-8", "replace")
    return re.sub(r"\s+", " ", text).strip()[:120]


def _tls_info(url, timeout):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                issuer = ""
                for part in cert.get("issuer", ()):
                    for key, value in part:
                        if key == "commonName":
                            issuer = value
                return {
                    "issuer": issuer,
                    "not_after": cert.get("notAfter"),
                    "tls_version": tls.version(),
                }
    except (OSError, ssl.SSLError, ValueError):
        return {"error": "could not inspect certificate"}


def _rdap(domain, timeout):
    if not domain or "." not in domain:
        return None
    try:
        req = Request("https://rdap.org/domain/" + domain,
                      headers={"User-Agent": UA, "Accept": "application/rdap+json"})
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(512 * 1024) or b"{}")
    except (URLError, OSError, ValueError, HTTPError):
        return None
    events = {}
    for event in data.get("events", []):
        action = event.get("eventAction")
        if action in ("registration", "expiration", "last changed"):
            events[action] = event.get("eventDate")
    age_days = None
    if events.get("registration"):
        try:
            stamp = events["registration"].replace("Z", "+00:00")
            from datetime import datetime
            age_days = int((datetime.now().astimezone()
                            - datetime.fromisoformat(stamp)).total_seconds() // 86400)
        except (ValueError, TypeError):
            pass
    return {
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "age_days": age_days,
    }


def investigate_url(url, timeout=8, max_redirects=6, want_rdap=True,
                    allow_private=False):
    """Follow a URL's redirects and collect public-risk facts.

    Returns {"ok": bool, ...}. Never raises for network errors; inspect `error`.
    """
    original = url
    current = _normalize(url)
    parsed = urlparse(current)
    if parsed.scheme not in ("http", "https"):
        return {"ok": False, "input": original, "error": "only http/https URLs are supported"}
    host = parsed.hostname or ""
    if not host:
        return {"ok": False, "input": original, "error": "URL has no host"}
    if not allow_private and not _public_host(host):
        return {"ok": False, "input": original,
                "error": "refusing a private/loopback address (investigate public URLs only)"}

    chain, visited = [], set()
    final_url, final_headers, final_body = current, {}, b""
    for _ in range(max_redirects + 1):
        if current in visited:
            chain.append({"url": current, "status": 0, "note": "redirect loop"})
            break
        visited.add(current)
        try:
            status, headers, effective, body = _fetch(current, timeout)
        except RuntimeError as exc:
            return {"ok": False, "input": original, "error": str(exc),
                    "chain": chain}
        entry = {"url": current, "status": status}
        location = headers.get("location")
        if status in (301, 302, 303, 307, 308) and location:
            nxt = urljoin(current, location)
            entry["to"] = nxt
            chain.append(entry)
            next_host = urlparse(nxt).hostname or ""
            if not allow_private and not _public_host(next_host):
                return {"ok": False, "input": original,
                        "error": "redirect target is a private/loopback address",
                        "chain": chain}
            current = nxt
            continue
        chain.append(entry)
        final_url = effective or current
        final_headers = headers
        final_body = body
        break
    else:
        chain.append({"url": current, "status": 0, "note": "too many redirects"})

    final_parsed = urlparse(final_url)
    domain = (final_parsed.hostname or "").lower()
    notes = []

    if final_parsed.scheme == "http":
        notes.append("not HTTPS - traffic can be read or modified in transit")
    if domain and domain.replace(".", "").isdigit():
        notes.append("final host is a raw IP address")
    if domain.startswith("xn--") or ".xn--" in domain:
        notes.append("punycode domain - check for a lookalike")
    bare = domain[4:] if domain.startswith("www.") else domain
    if bare in SHORTENERS:
        notes.append("shortened link - the visible domain hides the destination")
    if len(chain) >= 4:
        notes.append("multiple redirects (%d hops)" % (len(chain) - 1))
    start_domain = (urlparse(_normalize(original)).hostname or "").lower()
    if start_domain and domain and start_domain != domain:
        notes.append("ends on a different domain (%s -> %s)" % (start_domain, domain))

    rdap = _rdap(bare, timeout) if want_rdap and "." in bare else None
    if rdap and rdap.get("age_days") is not None:
        if rdap["age_days"] < 90:
            notes.append("domain registered %d days ago - very new" % rdap["age_days"])
        else:
            notes.append("domain is %d days old" % rdap["age_days"])

    return {
        "ok": True,
        "input": original,
        "chain": chain,
        "final_url": final_url,
        "domain": domain,
        "https": final_parsed.scheme == "https",
        "title": _title(final_body),
        "server": final_headers.get("server", ""),
        "tls": _tls_info(final_url, timeout),
        "rdap": rdap,
        "notes": notes,
    }
