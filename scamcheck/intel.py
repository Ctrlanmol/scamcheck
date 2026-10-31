"""Indicator / entity extraction for messages, cases and watchlists.

Everything here is deterministic and offline. The same normalized identifiers
are used by local memory, campaign clustering, watchlists and case files, so a
phone number, UPI ID, wallet or domain means the same thing everywhere.

Public API:
    extract_entities(text, result=None) -> [{"kind","value","label"}]
    parse_entity(raw) -> {"kind","value","label"}
    normalize_entity(kind, value) -> {"kind","value","label"}
    kind_label(kind) -> human label
    format_entity(entity) -> "upi: name@bank"
"""

import hashlib
import re
from urllib.parse import urlparse

from . import phones
from .rules import extract_urls

# URLs as written in a message (scheme optional is handled separately).
FULL_URL_RE = re.compile(r"(?:https?://|www\.)[^\s\"'<>\)\]]+", re.I)
BARE_HOST_RE = re.compile(
    r"\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|info|biz|io|co|in|us|uk|au|ca|sg|"
    r"ae|nz|za|app|shop|store|online|site|website|live|pro|dev|ai|xyz|top|tk|"
    r"ml|ga|cf|gq|ru|su|click|link|work|loan|win|bid|download|stream|racing|"
    r"cam|monster|quest|cyou|buzz|icu|rest|surf)\b",
    re.I,
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
UPI_RE = re.compile(r"\b[A-Za-z0-9._\-]{2,}@[A-Za-z][A-Za-z0-9.\-]{1,}\b")
BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TRX_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
TELEGRAM_LINK_RE = re.compile(r"(?:t\.me|telegram\.me)/([A-Za-z0-9_]{4,32})", re.I)
TELEGRAM_HANDLE_RE = re.compile(r"(?<![\w@])@([A-Za-z][A-Za-z0-9_]{4,31})\b")
WHATSAPP_GROUP_RE = re.compile(r"chat\.whatsapp\.com/([A-Za-z0-9]{10,})", re.I)
WHATSAPP_NUMBER_RE = re.compile(r"wa\.me/(\+?\d{7,15})", re.I)

UPI_HANDLES = {
    "okhdfcbank", "okicici", "oksbi", "okaxis", "ybl", "paytm", "ibl",
    "axl", "upi", "sbi", "hdfcbank", "icici", "kotak", "yesbank", "airtel",
    "freecharge", "jio", "amazonpay", "apl", "yapl", "wahdfcbank",
    "waaxis", "waicici", "wasbi", "superyes", "naviaxis", "slice",
}

MONEY_CONTEXT = re.compile(
    r"\b(?:wallet|address|send|deposit|transfer|btc|bitcoin|eth|ethereum|"
    r"usdt|trx|tron|crypto|payment|pay|upi|account)\b", re.I,
)

KIND_LABELS = {
    "message": "message",
    "url": "domain/link",
    "domain": "domain",
    "phone": "phone",
    "sender": "sender",
    "email": "email",
    "upi": "UPI ID",
    "crypto_btc": "Bitcoin address",
    "crypto_eth": "Ethereum address",
    "crypto_trx": "Tron/USDT address",
    "ifsc": "bank IFSC",
    "telegram": "Telegram",
    "whatsapp": "WhatsApp group",
    "apk": "Android APK link",
}


def kind_label(kind):
    return KIND_LABELS.get(kind, (kind or "identifier").replace("_", " "))


def _entity(kind, value, label=None):
    return {"kind": kind, "value": value, "label": label or value}


def _host(value):
    raw = (value or "").strip()
    if not raw:
        return ""
    if not re.match(r"^[a-z][a-z0-9+.\-]*://", raw, re.I):
        raw = "http://" + raw.lstrip("/")
    try:
        host = (urlparse(raw).hostname or "").lower().strip(".")
    except ValueError:
        return ""
    return host


def _is_email(match):
    domain = match.rsplit("@", 1)[-1].lower()
    if "." not in domain:
        return False
    return True


def _crypto_context(text, match):
    window = text[max(0, match.start() - 60):match.end() + 60]
    return bool(MONEY_CONTEXT.search(window)) or text.strip() == match.group(0)


def extract_entities(text, result=None):
    """Return stable, deduped identifiers from a message or case text.

    `result` may be an analyzer result, used to add the sender number and
    phones the analyzer already normalized. No network access.
    """
    text = text or ""
    out = []

    if text.strip():
        out.append(_entity(
            "message",
            hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
            "exact message",
        ))

    for host in extract_urls(text):
        if host:
            out.append(_entity("url", host, host))

    known_hosts = {item["value"] for item in out if item["kind"] == "url"}
    for match in BARE_HOST_RE.finditer(text):
        host = match.group(0).lower().strip(".")
        if host and host not in known_hosts:
            known_hosts.add(host)
            out.append(_entity("url", host, host))

    for match in FULL_URL_RE.finditer(text):
        raw = match.group(0).rstrip(".,;:!?)")
        if ".apk" in raw.lower():
            out.append(_entity("apk", raw.lower(), raw))

    email_spans = []
    for match in EMAIL_RE.finditer(text):
        value = match.group(0).strip(".,;:!?)]").lower()
        if not _is_email(value):
            continue
        email_spans.append(match.span())
        out.append(_entity("email", value, value))

    for match in UPI_RE.finditer(text):
        if any(start <= match.start() < end for start, end in email_spans):
            continue
        value = match.group(0).strip(".,;:!?)]").lower()
        local, _, domain = value.partition("@")
        if not local or not domain:
            continue
        if domain in UPI_HANDLES or "." not in domain:
            out.append(_entity("upi", value, value))

    for match in BTC_RE.finditer(text):
        if _crypto_context(text, match):
            out.append(_entity("crypto_btc", match.group(0), match.group(0)))

    for match in ETH_RE.finditer(text):
        if _crypto_context(text, match):
            value = match.group(0).lower()
            out.append(_entity("crypto_eth", value, value))

    for match in TRX_RE.finditer(text):
        if _crypto_context(text, match):
            out.append(_entity("crypto_trx", match.group(0), match.group(0)))

    for match in IFSC_RE.finditer(text):
        value = match.group(0).upper()
        window = text[max(0, match.start() - 50):match.end() + 50]
        if re.search(r"\bifsc\b", window, re.I) or text.strip().upper() == value:
            out.append(_entity("ifsc", value, value))

    for match in TELEGRAM_LINK_RE.finditer(text):
        handle = match.group(1).lower().lstrip("@")
        out.append(_entity("telegram", handle, "@" + handle))

    for match in TELEGRAM_HANDLE_RE.finditer(text):
        window = text[max(0, match.start() - 40):match.start()]
        if re.search(r"telegram|t\.me|tg\b", window, re.I):
            handle = match.group(1).lower()
            out.append(_entity("telegram", handle, "@" + handle))

    for match in WHATSAPP_GROUP_RE.finditer(text):
        value = match.group(1)
        out.append(_entity("whatsapp", value, "chat.whatsapp.com/" + value))

    for match in WHATSAPP_NUMBER_RE.finditer(text):
        info = phones.normalize_number(match.group(1))
        if info.get("valid"):
            value = info.get("e164") or info.get("national")
            out.append(_entity("phone", value, value))

    for info in phones.extract_numbers(text):
        value = info.get("e164") or info.get("national")
        if value:
            out.append(_entity("phone", value, value))

    number = (result or {}).get("number") or {}
    sender = number.get("sender") or {}
    sinfo = sender.get("number") or {}
    if sinfo.get("e164") or sinfo.get("national"):
        value = sinfo.get("e164") or sinfo.get("national")
        out.append(_entity("sender", value, value))
    for mention in number.get("mentioned") or []:
        info = mention.get("number") or {}
        if info.get("e164") or info.get("national"):
            value = info.get("e164") or info.get("national")
            out.append(_entity("phone", value, value))

    return dedupe(out)


def dedupe(items):
    out, seen = [], set()
    for item in items or []:
        kind = (item or {}).get("kind")
        value = (item or {}).get("value")
        if not kind or value in (None, ""):
            continue
        key = (kind, str(value))
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "kind": kind,
            "value": str(value),
            "label": item.get("label") or str(value),
        })
    return out


def normalize_entity(kind, value):
    """Canonicalize one identifier. Raises ValueError if it is unusable."""
    kind = (kind or "").strip().lower().replace("-", "_")
    aliases = {
        "link": "url", "domain": "url", "host": "url", "site": "url",
        "mobile": "phone", "number": "phone", "tel": "phone",
        "mail": "email", "wallet": "crypto_btc", "tg": "telegram",
        "whatsapp_group": "whatsapp", "apk_link": "apk",
    }
    kind = aliases.get(kind, kind)
    value = (value or "").strip().strip("'\"")
    if not value:
        raise ValueError("empty identifier")

    if kind == "message":
        return _entity("message", hashlib.sha256(value.encode("utf-8", "replace")).hexdigest(), "exact message")

    if kind == "url":
        host = _host(value)
        if not host:
            raise ValueError("not a usable URL/domain: %s" % value)
        return _entity("url", host, host)

    if kind == "phone":
        info = phones.normalize_number(value)
        if not info.get("valid"):
            raise ValueError("not a valid phone number: %s" % value)
        number = info.get("e164") or info.get("national")
        return _entity("phone", number, number)

    if kind in ("email", "upi"):
        value = value.lower()
        if "@" not in value:
            raise ValueError("missing @ in %s" % kind)
        if kind == "email" and "." not in value.rsplit("@", 1)[-1]:
            raise ValueError("not an email address: %s" % value)
        return _entity(kind, value, value)

    if kind == "crypto_eth":
        value = value.lower()
        if not ETH_RE.fullmatch(value):
            raise ValueError("not an Ethereum address")
        return _entity(kind, value, value)

    if kind in ("crypto_btc", "crypto_trx"):
        pattern = BTC_RE if kind == "crypto_btc" else TRX_RE
        if not pattern.fullmatch(value):
            raise ValueError("not a valid %s address" % kind_label(kind))
        return _entity(kind, value, value)

    if kind == "ifsc":
        value = value.upper()
        if not IFSC_RE.fullmatch(value):
            raise ValueError("not a valid IFSC code")
        return _entity(kind, value, value)

    if kind == "telegram":
        handle = value.lower().lstrip("@")
        if not re.fullmatch(r"[a-z][a-z0-9_]{4,31}", handle):
            raise ValueError("not a valid Telegram handle")
        return _entity(kind, handle, "@" + handle)

    if kind == "whatsapp":
        value = re.sub(r"^https?://(?:www\.)?chat\.whatsapp\.com/", "", value, flags=re.I)
        if not re.fullmatch(r"[A-Za-z0-9]{10,}", value):
            raise ValueError("not a WhatsApp group invite code")
        return _entity(kind, value, "chat.whatsapp.com/" + value)

    if kind == "apk":
        return _entity(kind, value.lower(), value)

    return _entity(kind, value, value)


def parse_entity(raw):
    """Parse `kind:value` or auto-detect one identifier from user input."""
    raw = (raw or "").strip().strip("'\"")
    if not raw:
        raise ValueError("empty identifier")

    if ":" in raw:
        prefix, rest = raw.split(":", 1)
        if prefix.strip().lower() in set(KIND_LABELS) | {
            "link", "domain", "host", "site", "mobile", "number", "tel",
            "mail", "wallet", "tg", "whatsapp_group", "apk_link", "crypto",
        }:
            return normalize_entity(prefix, rest)

    if raw.startswith("+") or re.fullmatch(r"[\d\s().\-]{7,}", raw):
        try:
            return normalize_entity("phone", raw)
        except ValueError:
            pass

    match = FULL_URL_RE.fullmatch(raw)
    if match or raw.startswith("www."):
        return normalize_entity("apk" if ".apk" in raw.lower() else "url", raw)

    if raw.startswith("chat.whatsapp.com/"):
        return normalize_entity("whatsapp", raw)
    if raw.startswith("wa.me/"):
        return normalize_entity("phone", raw.split("/", 1)[1])
    if raw.startswith("t.me/") or raw.startswith("telegram.me/"):
        return normalize_entity("telegram", raw.split("/", 1)[1])

    if raw.startswith("@"):
        return normalize_entity("telegram", raw)

    if ETH_RE.fullmatch(raw):
        return normalize_entity("crypto_eth", raw)
    if BTC_RE.fullmatch(raw):
        return normalize_entity("crypto_btc", raw)
    if TRX_RE.fullmatch(raw):
        return normalize_entity("crypto_trx", raw)
    if IFSC_RE.fullmatch(raw.upper()):
        return normalize_entity("ifsc", raw)

    if "@" in raw:
        domain = raw.rsplit("@", 1)[-1].lower()
        if "." in domain:
            return normalize_entity("email", raw)
        return normalize_entity("upi", raw)

    if "." in raw and " " not in raw:
        return normalize_entity("url", raw)

    raise ValueError("could not tell what kind of identifier that is; use KIND:VALUE "
                     "(phone, url, upi, email, telegram, crypto_btc, crypto_eth, "
                     "crypto_trx, ifsc, apk)")


def format_entity(entity):
    kind = (entity or {}).get("kind") or "identifier"
    value = (entity or {}).get("label") or (entity or {}).get("value") or ""
    return "%s: %s" % (kind_label(kind), value)
