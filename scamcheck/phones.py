"""Phone-number intelligence: normalization, range flags, local lists, cached feeds.

Privacy contract
----------------
Analysis NEVER touches the network. Reputation comes from three local places:

  ~/.scamcheck/blocklist.txt   numbers you marked as scams   (one per line)
  ~/.scamcheck/allowlist.txt   numbers you trust            (one per line)
  ~/.scamcheck/feeds.json      cache written ONLY by an explicit `--update-feeds`

`--update-feeds` downloads the public lists *you* configured in
`~/.scamcheck/feeds.conf`. Message content is never sent anywhere, and no
feed is enabled by default (there is no trustworthy, free, global
phone-number blocklist — see README).

List file format (both lists):

    +91 98765 43210, delivery scam
    +1 415 555 2671
    # comments and blank lines are ignored

Override the data directory with SCAMCHECK_HOME (used by the tests).
"""

import csv
import hashlib
import io
import json
import os
import re
import tempfile
import time
from urllib.parse import urlparse
from urllib.request import Request, urlopen

# --------------------------------------------------------------------------
# Country / range data (public numbering plans; no personal data)
# --------------------------------------------------------------------------

# cc -> (ISO, English name, valid national lengths)
COUNTRIES = {
    "1": ("US", "United States / Canada", (10,)),
    "7": ("RU", "Russia", (10,)),
    "20": ("EG", "Egypt", (10,)),
    "27": ("ZA", "South Africa", (9,)),
    "30": ("GR", "Greece", (10,)),
    "31": ("NL", "Netherlands", (9,)),
    "32": ("BE", "Belgium", (9,)),
    "33": ("FR", "France", (9,)),
    "34": ("ES", "Spain", (9,)),
    "39": ("IT", "Italy", (9, 10)),
    "41": ("CH", "Switzerland", (9,)),
    "43": ("AT", "Austria", (10,)),
    "44": ("GB", "United Kingdom", (10,)),
    "45": ("DK", "Denmark", (8,)),
    "46": ("SE", "Sweden", (9,)),
    "47": ("NO", "Norway", (8,)),
    "48": ("PL", "Poland", (9,)),
    "49": ("DE", "Germany", (10, 11)),
    "55": ("BR", "Brazil", (10, 11)),
    "60": ("MY", "Malaysia", (9,)),
    "61": ("AU", "Australia", (9, 10)),
    "62": ("ID", "Indonesia", (9, 10)),
    "63": ("PH", "Philippines", (10,)),
    "64": ("NZ", "New Zealand", (8, 9)),
    "65": ("SG", "Singapore", (8,)),
    "66": ("TH", "Thailand", (9,)),
    "81": ("JP", "Japan", (10,)),
    "82": ("KR", "South Korea", (9, 10)),
    "84": ("VN", "Vietnam", (9, 10)),
    "86": ("CN", "China", (11,)),
    "90": ("TR", "Turkey", (10,)),
    "91": ("IN", "India", (10,)),
    "92": ("PK", "Pakistan", (10,)),
    "94": ("LK", "Sri Lanka", (9,)),
    "351": ("PT", "Portugal", (9,)),
    "353": ("IE", "Ireland", (9,)),
    "358": ("FI", "Finland", (9,)),
    "880": ("BD", "Bangladesh", (10,)),
    "966": ("SA", "Saudi Arabia", (9,)),
    "968": ("OM", "Oman", (8,)),
    "971": ("AE", "United Arab Emirates", (9,)),
    "972": ("IL", "Israel", (9,)),
    "973": ("BH", "Bahrain", (8,)),
    "974": ("QA", "Qatar", (8,)),
    "977": ("NP", "Nepal", (10,)),
}

REGIONS = {}
for _cc, (_iso, _name, _lens) in COUNTRIES.items():
    REGIONS.setdefault(_iso, _cc)
REGIONS.update({"UK": "44", "USA": "1", "UAE": "971", "CA": "1"})

_CC_BY_LENGTH = sorted(COUNTRIES, key=len, reverse=True)

# Numbers that bill the caller / are not ordinary person-to-person lines.
TOLLFREE_NA = ("800", "833", "844", "855", "866", "877", "888")

# Context words that make a bare number in message text worth extracting.
_PHONE_CONTEXT = re.compile(
    r"(?i)\b(call|dial|ring|whatsapp|contact|phone|mobile|helpline|"
    r"sms|reach|report|verify|reply)\b"
)
_NON_PHONE_CONTEXT = re.compile(
    r"(?i)\b(otp|o\.t\.p|pin|code|amount|order|ref|reference|invoice|"
    r"tracking|transaction|txn|account|a/c|id|rs|inr|usd|gbp)\b"
)

_SENDER_ID_RE = re.compile(r"^[A-Za-z]{2,6}-[A-Za-z0-9]{4,10}$")
_CANDIDATE_RE = re.compile(r"(?<![\w])(?:\+|00)?\d(?:[\d\s().\-]{4,20}\d)(?![\w])")
_SENDER_LINE_RE = re.compile(
    r"^\s*(?:from|sender|from number|sender id)\s*[:\-]\s*"
    r"(\+?[\d][\d\s().\-]{4,20}\d|[A-Za-z]{2,6}-[A-Za-z0-9]{4,10})\s*$",
    re.I,
)

# Region-specific cues used only to spot a *foreign* sender impersonating a
# local institution (e.g. a +1 number claiming to be an Indian bank).
_REGION_CUES = {
    "IN": re.compile(
        r"(?i)(₹|\brs\.?\s*\d|\binr\b|upi|aadhaar|aadhar|\bpan\b|kyc|"
        r"hdfc|icici|\bsbi\b|axis bank|paytm|phonepe|gpay|trai|bsnl|jio|airtel|"
        r"income tax|refund)"
    ),
    "US": re.compile(r"(?i)(\$|\busd\b|\birs\b|\bssn\b|zelle|venmo|social security|medicare)"),
    "GB": re.compile(r"(?i)(£|\bgbp\b|hmrc|royal mail|\bnhs\b|barclays|lloyds|natwest)"),
    "AU": re.compile(r"(?i)(\baud\b|\bato\b|mygov|centrelink|commbank|westpac)"),
}

MAX_FEED_BYTES = 25 * 1024 * 1024
MAX_FEED_ENTRIES = 200000
FEED_TIMEOUT = 20
USER_AGENT = "scamcheck/0.7 (local phone-number reputation; opt-in feeds)"


# --------------------------------------------------------------------------
# Paths / config
# --------------------------------------------------------------------------

def data_dir():
    root = os.environ.get("SCAMCHECK_HOME") or "~/.scamcheck"
    return os.path.abspath(os.path.expanduser(root))


def _path(name):
    return os.path.join(data_dir(), name)


def ensure_dir():
    d = data_dir()
    if not os.path.isdir(d):
        os.makedirs(d, mode=0o700)
    return d


def _write_private(path, text):
    ensure_dir()
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def load_config():
    try:
        with open(_path("config.json"), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(cfg):
    _write_private(_path("config.json"), json.dumps(cfg, indent=2, sort_keys=True) + "\n")


def default_region(explicit=None):
    if explicit:
        return str(explicit).upper()
    env = os.environ.get("SCAMCHECK_REGION")
    if env:
        return env.upper()
    return str(load_config().get("region") or "IN").upper()


# --------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------

def _blank(raw, note="not a phone number"):
    return {
        "input": raw, "e164": None, "country": None, "dial_code": None,
        "national": "", "kind": "invalid", "valid": False, "note": note,
    }


def normalize_number(raw, region=None):
    """Return a dict describing one number.

    Accepts international ("+91 98765 43210", "0091..."), national
    ("098765 43210" in IN), or an SMS sender ID ("VM-HDFCBK").
    """
    original = "" if raw is None else str(raw).strip()
    if not original:
        return _blank(original, "empty")

    if _SENDER_ID_RE.match(original):
        return {
            "input": original, "e164": None, "country": None, "dial_code": None,
            "national": original.upper(), "kind": "sender_id", "valid": True,
            "note": "alphanumeric SMS sender ID",
        }

    region = default_region(region)
    plus = original.startswith("+") or original.startswith("00")
    digits = re.sub(r"\D", "", original)
    if not digits:
        return _blank(original)

    if original.startswith("00"):
        digits = digits[2:] if digits.startswith("00") else digits

    if plus:
        cc = None
        for cand in _CC_BY_LENGTH:
            if digits.startswith(cand):
                cc = cand
                break
        if cc is None:
            return _blank(original, "unknown country code")
        national = digits[len(cc):]
    else:
        cc = REGIONS.get(region) or "91"
        national = digits
        info = COUNTRIES.get(cc)
        max_len = max(info[2]) if info else 10
        if national.startswith("0") and len(national) > max_len:
            national = national[1:]
        # "919876543210" typed without '+': if the remainder is a valid
        # national length, treat the leading digits as the country code.
        if (info and national.startswith(cc) and len(national) > max_len
                and len(national) - len(cc) in info[2]):
            national = national[len(cc):]

    if not national:
        return _blank(original, "no subscriber digits")

    info = COUNTRIES.get(cc)
    if info is None:
        if 6 <= len(national) <= 15:
            return {
                "input": original, "e164": "+" + cc + national, "country": "??",
                "dial_code": cc, "national": national, "kind": "international",
                "valid": True, "note": "unrecognized country code",
            }
        return _blank(original, "implausible length")

    iso, name, lengths = info
    if len(national) not in lengths:
        # Sender shortcodes (4-6 digits) are not in any national plan.
        if not plus and 4 <= len(national) <= 6 and len(digits) == len(national):
            return {
                "input": original, "e164": None, "country": iso,
                "dial_code": cc, "national": national, "kind": "shortcode",
                "valid": True, "note": "SMS shortcode",
            }
        return _blank(
            original,
            "unexpected length %d for %s (expects %s)" % (
                len(national), iso, "/".join(str(n) for n in lengths)),
        )

    kind = _classify(iso, national)
    return {
        "input": original,
        "e164": "+" + cc + national,
        "country": iso,
        "country_name": name,
        "dial_code": cc,
        "national": national,
        "kind": kind,
        "valid": True,
        "note": "",
    }


def _classify(iso, n):
    if iso == "IN":
        if n.startswith("1900"):
            return "premium"
        if n.startswith("1800"):
            return "tollfree"
        if n[0] in "6789":
            return "mobile"
        return "fixed"
    if iso in ("US", "CA"):
        if n.startswith("900"):
            return "premium"
        if n[:3] in TOLLFREE_NA:
            return "tollfree"
        return "fixed_or_mobile"
    if iso == "GB":
        if n.startswith("9"):
            return "premium"
        if n.startswith("70"):
            return "personal"
        if n.startswith(("800", "808")):
            return "tollfree"
        if n.startswith("7"):
            return "mobile"
        return "fixed"
    if iso == "AU":
        if n.startswith("190"):
            return "premium"
        if n.startswith("180"):
            return "tollfree"
        if n.startswith("4"):
            return "mobile"
        return "fixed"
    return "mobile" if iso in ("DE", "FR", "IT", "ES", "NL", "SE", "NO", "DK", "FI",
                               "PL", "PT", "IE", "AT", "BE", "CH", "GR") else "fixed_or_mobile"


def extract_numbers(text, region=None, conservative=True):
    """Find phone numbers in message text.

    Conservative mode (default) requires an explicit '+', a phone-context
    word nearby, or a premium-rate number. This keeps amounts, OTPs, years and
    order IDs from being mistaken for calls.
    """
    text = text or ""
    region = default_region(region)
    found, seen = [], set()

    for match in _CANDIDATE_RE.finditer(text):
        raw = match.group(0).strip()
        before = text[max(0, match.start() - 44):match.start()]
        after = text[match.end():match.end() + 44]
        window = before + " " + after

        info = normalize_number(raw, region)
        if not info["valid"] or info["kind"] in ("shortcode", "sender_id"):
            continue

        if conservative:
            has_plus = raw.startswith("+") or raw.startswith("00")
            has_context = bool(_PHONE_CONTEXT.search(window))
            if not (has_plus or has_context or info["kind"] == "premium"):
                continue
            # Only treat an amount/OTP word as disqualifying when it sits right
            # next to the digits (a nearby "Call ..." still wins).
            near = before[-16:] + " " + after[:16]
            if _NON_PHONE_CONTEXT.search(near) and not has_plus and not has_context:
                continue

        key = info["e164"] or raw
        if key in seen:
            continue
        seen.add(key)
        found.append(info)
    return found


# --------------------------------------------------------------------------
# Local reputation
# --------------------------------------------------------------------------

def _clean_label(label):
    return re.sub(r"\s+", " ", str(label or "")).strip()[:120]


def _list_entries(filename):
    """Read a list file -> {key: {label, number, added}}."""
    entries = {}
    try:
        with open(_path(filename), "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split(",")]
                info = normalize_number(parts[0])
                if not info["valid"]:
                    continue
                key = info["e164"] or ("#" + info["national"])
                entries[key] = {
                    "label": _clean_label(parts[1] if len(parts) > 1 else ""),
                    "number": info["e164"] or info["national"],
                }
    except OSError:
        pass
    return entries


def _append_list(filename, number, label=""):
    info = normalize_number(number)
    if not info["valid"]:
        raise ValueError("not a valid phone number: %s" % number)
    key = info["e164"] or ("#" + info["national"])
    current = _list_entries(filename)
    current[key] = {"label": _clean_label(label), "number": info["e164"] or info["national"]}
    lines = ["# scamcheck %s (one number per line; optional ,label)" %
             ("blocklist" if "block" in filename else "allowlist")]
    for k, v in sorted(current.items()):
        lines.append(v["number"] + (", " + v["label"] if v["label"] else ""))
    _write_private(_path(filename), "\n".join(lines) + "\n")
    return info


def add_block(number, label=""):
    return _append_list("blocklist.txt", number, label)


def add_allow(number, label=""):
    return _append_list("allowlist.txt", number, label)


def forget_number(number):
    """Remove a number from both local lists. Returns how many lines changed."""
    info = normalize_number(number)
    if not info["valid"]:
        raise ValueError("not a valid phone number: %s" % number)
    key = info["e164"] or ("#" + info["national"])
    removed = 0
    for filename in ("blocklist.txt", "allowlist.txt"):
        current = _list_entries(filename)
        if key in current:
            del current[key]
            removed += 1
            lines = ["# scamcheck list (one number per line; optional ,label)"]
            for k, v in sorted(current.items()):
                lines.append(v["number"] + (", " + v["label"] if v["label"] else ""))
            _write_private(_path(filename), "\n".join(lines) + "\n")
    return removed


def list_numbers():
    return {"blocked": _list_entries("blocklist.txt"),
            "allowed": _list_entries("allowlist.txt")}


def _load_feed_cache():
    try:
        with open(_path("feeds.json"), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("sources"), dict):
            return data
    except (OSError, ValueError):
        pass
    return {"version": 1, "updated_at": None, "sources": {}}


def _save_feed_cache(cache):
    _write_private(_path("feeds.json"), json.dumps(cache, ensure_ascii=False) + "\n")


def _feed_lookup(number, cache=None):
    """Match one normalized number against cached feeds -> best hit or None."""
    key = number.get("e164") or ("#" + number.get("national", ""))
    cache = cache if cache is not None else _load_feed_cache()
    best = None
    for url, src in cache.get("sources", {}).items():
        entry = (src.get("entries") or {}).get(key)
        if not entry:
            continue
        reports = int(entry.get("reports") or 1)
        if best is None or reports > best["reports"]:
            best = {
                "source": src.get("label") or url,
                "url": url,
                "reports": reports,
                "label": entry.get("label") or "",
                "fetched_at": src.get("fetched_at"),
            }
    return best


def reputation(number, cache=None):
    """Allowlist > blocklist > feeds. Input is a normalize_number() dict."""
    key = number.get("e164") or ("#" + number.get("national", ""))
    allowed = _list_entries("allowlist.txt")
    if key in allowed:
        return {"status": "allowed", "source": "allowlist", "label": allowed[key]["label"],
                "reports": 0}
    blocked = _list_entries("blocklist.txt")
    if key in blocked:
        return {"status": "blocked", "source": "blocklist", "label": blocked[key]["label"],
                "reports": 0}

    hit = _feed_lookup(number, cache)
    if hit:
        return {"status": "reported", "source": hit["source"], "label": hit["label"],
                "reports": hit["reports"], "url": hit["url"],
                "fetched_at": hit["fetched_at"]}
    return {"status": "unknown", "source": None, "label": "", "reports": 0}


# --------------------------------------------------------------------------
# Signals for the analyzer
# --------------------------------------------------------------------------

def check_number(number, region=None):
    """Full intelligence for one number (used by --number and the API)."""
    info = normalize_number(number, region)
    rep = reputation(info) if info["valid"] else {"status": "unknown", "source": None,
                                                  "label": "", "reports": 0}
    flags = []
    if info["kind"] == "premium":
        flags.append("premium-rate (calls/texts cost extra)")
    elif info["kind"] == "tollfree":
        flags.append("toll-free")
    elif info["kind"] == "shortcode":
        flags.append("SMS shortcode (not a personal number)")
    elif info["kind"] == "sender_id":
        flags.append("alphanumeric sender ID (can be spoofed)")
    if rep["status"] == "blocked":
        flags.append("on your blocklist")
    elif rep["status"] == "allowed":
        flags.append("on your allowlist")
    elif rep["status"] == "reported":
        flags.append("reported %d time%s" % (rep["reports"], "" if rep["reports"] == 1 else "s"))

    risk = "none"
    if rep["status"] == "blocked":
        risk = "high"
    elif rep["status"] == "reported" or info["kind"] == "premium":
        risk = "medium"
    elif info["kind"] in ("shortcode", "sender_id"):
        risk = "low"

    return {"number": info, "reputation": rep, "flags": flags, "risk": risk}


def _flag_labels(info, rep, prefix):
    out = []
    if rep["status"] == "blocked":
        out.append(("%s %s is on your blocklist%s" % (
            prefix, info.get("e164") or info.get("national"),
            " (" + rep["label"] + ")" if rep.get("label") else ""), 45))
    elif rep["status"] == "reported":
        out.append(("%s %s was reported %d time%s (%s)" % (
            prefix, info.get("e164") or info.get("national"), rep["reports"],
            "" if rep["reports"] == 1 else "s", rep["source"]), 25))
    elif rep["status"] == "allowed":
        out.append(("%s %s is on your allowlist" % (
            prefix, info.get("e164") or info.get("national")), -20))
    if info["kind"] == "premium":
        out.append(("%s is a premium-rate number (expensive to call/text)" % prefix, 15))
    return out


def number_signals(text, sender=None, region=None):
    """Score contributions + flags for a sender and numbers named in the text.

    Returns {"sender", "mentioned", "score", "reasons", "floor"} where score
    is added to the rules score and floor is a minimum verdict label or None.
    """
    region = default_region(region)
    result = {"sender": None, "mentioned": [], "score": 0,
              "reasons": [], "floor": None}
    reasons, score, floor = [], 0, None
    rank = {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "LIKELY SCAM": 2, "SCAM": 3}

    def bump(label, points, minimum=None):
        nonlocal score, floor
        score += points
        reasons.append((label, points))
        if minimum and (floor is None or rank[minimum] > rank[floor]):
            floor = minimum

    if sender:
        info = normalize_number(sender, region)
        if info["valid"]:
            rep = reputation(info)
            intel = {
                "number": info, "reputation": rep,
                "flags": [],
                "risk": "none",
            }
            if info["kind"] == "premium":
                intel["flags"].append("premium-rate")
            if rep["status"] != "unknown":
                intel["flags"].append(rep["status"])
            intel["risk"] = ("high" if rep["status"] == "blocked"
                             else "medium" if rep["status"] == "reported"
                             or info["kind"] == "premium" else "low")
            result["sender"] = intel

            for label, points in _flag_labels(info, rep, "Sender"):
                bump(label, points, "LIKELY SCAM" if rep["status"] == "blocked"
                     else "SUSPICIOUS" if rep["status"] == "reported" else None)

            # A foreign personal number claiming to be a local institution.
            if (info["kind"] not in ("premium", "tollfree", "shortcode", "sender_id")
                    and info.get("country") not in (None, "??", region)):
                cue = _REGION_CUES.get(region)
                if cue and cue.search(text or ""):
                    bump("Sender country (%s) does not match the local company "
                         "or currency named in the message" % info.get("country"), 12)

    mentions = []
    for info in extract_numbers(text or "", region):
        rep = reputation(info)
        entry = {
            "number": info,
            "reputation": rep,
            "risk": ("high" if rep["status"] == "blocked"
                     else "medium" if rep["status"] == "reported"
                     or info["kind"] == "premium" else "none"),
        }
        mentions.append(entry)
        if rep["status"] in ("blocked", "reported"):
            bump("Number mentioned in the message is %s" % (
                "on your blocklist" if rep["status"] == "blocked"
                else "reported %d times" % rep["reports"]),
                20 if rep["status"] == "blocked" else 12,
                "SUSPICIOUS")
        if info["kind"] == "premium":
            bump("Message asks you to use a premium-rate number (expensive)", 12)
    result["mentioned"] = mentions[:10]

    # Keep number evidence meaningful but bounded: it is supporting evidence,
    # not a replacement for the text rules.
    result["score"] = max(-25, min(65, score))
    result["reasons"] = reasons
    result["floor"] = floor
    return result


# --------------------------------------------------------------------------
# Importing lists
# --------------------------------------------------------------------------

_NUMBER_HEADERS = ("number", "phone", "phone_number", "phone number", "msisdn",
                   "telephone", "mobile", "sender")
_LABEL_HEADERS = ("label", "category", "type", "reason", "description", "name")
_REPORT_HEADERS = ("reports", "report_count", "count", "complaints", "hits")


def _pick_column(header, names):
    lowered = [str(h or "").strip().lower() for h in header]
    for i, h in enumerate(lowered):
        if h in names:
            return i
    return None


def parse_number_file(path):
    """Parse a .txt/.csv list -> list of {number, label, reports}.

    CSV headers are optional; without one, columns 0/1/2 are
    number/label/reports. Lines starting with '#' are comments.
    """
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        raw = fh.read()
    return parse_number_text(raw)


def parse_number_text(raw):
    rows = []
    text = raw or ""
    first = text.strip().splitlines()[0] if text.strip() else ""
    looks_csv = ("," in first and not first.lstrip().startswith("#"))

    if not looks_csv:
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                rows.append({"number": line, "label": "", "reports": 1})
        return rows

    reader = csv.reader(io.StringIO(text))
    cols = None
    for row in reader:
        if not row or not any(str(c).strip() for c in row):
            continue
        if str(row[0]).lstrip().startswith("#"):
            continue
        if cols is None:
            num_col = _pick_column(row, _NUMBER_HEADERS)
            if num_col is not None:
                cols = {
                    "num": num_col,
                    "label": _pick_column(row, _LABEL_HEADERS),
                    "reports": _pick_column(row, _REPORT_HEADERS),
                }
                continue
            cols = {"num": 0, "label": 1, "reports": 2}  # headerless CSV
        num_col, label_col, reports_col = cols["num"], cols["label"], cols["reports"]
        if num_col >= len(row):
            continue
        number = str(row[num_col]).strip().strip('"')
        if not number:
            continue
        label = str(row[label_col]).strip() if label_col is not None and label_col < len(row) else ""
        reports = 1
        if reports_col is not None and reports_col < len(row):
            digits = re.sub(r"\D", "", str(row[reports_col]))
            reports = int(digits) if digits else 1
        rows.append({"number": number, "label": label, "reports": reports})
    return rows


def import_list(path, target="block", label="", region=None):
    """Import a list into the local blocklist/allowlist.

    Returns {"imported", "skipped", "total", "target"}.
    """
    region = default_region(region)
    entries = parse_number_file(path)
    imported = skipped = 0
    for row in entries:
        info = normalize_number(row["number"], region)
        if not info["valid"]:
            skipped += 1
            continue
        try:
            if target == "allow":
                add_allow(info["e164"] or info["national"], label or row.get("label") or "")
            else:
                add_block(info["e164"] or info["national"], label or row.get("label") or "")
            imported += 1
        except ValueError:
            skipped += 1
    return {"imported": imported, "skipped": skipped,
            "total": len(entries), "target": target}


# --------------------------------------------------------------------------
# Opt-in feed refresh
# --------------------------------------------------------------------------

def feeds_conf_path():
    return _path("feeds.conf")


def _parse_feed_line(line):
    """`URL | label | format` (label/format optional)."""
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    parts = [p.strip() for p in line.split("|")]
    url = parts[0]
    label = parts[1] if len(parts) > 1 and parts[1] else urlparse(url).netloc
    fmt = parts[2] if len(parts) > 2 else ""
    return {"url": url, "label": label, "format": fmt.lower()}


def read_feeds_conf():
    out = []
    try:
        with open(feeds_conf_path(), "r", encoding="utf-8") as fh:
            for line in fh:
                item = _parse_feed_line(line)
                if item:
                    out.append(item)
    except OSError:
        pass
    return out


def _url_allowed(url):
    """HTTPS only, except a localhost URL (handy for self-hosted lists/tests)."""
    try:
        p = urlparse(url)
    except ValueError:
        return False
    if p.scheme == "https":
        return bool(p.netloc)
    if p.scheme == "http":
        return (p.hostname or "") in ("127.0.0.1", "localhost", "::1")
    return False


def _fetch(url):
    if not _url_allowed(url):
        raise ValueError("refusing non-HTTPS feed URL (localhost HTTP is allowed): %s" % url)
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/csv, text/plain, */*"})
    with urlopen(req, timeout=FEED_TIMEOUT) as resp:
        length = resp.headers.get("Content-Length")
        if length and int(length) > MAX_FEED_BYTES:
            raise ValueError("feed is larger than %d MB" % (MAX_FEED_BYTES // (1024 * 1024)))
        chunks, total = [], 0
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FEED_BYTES:
                raise ValueError("feed is larger than %d MB" % (MAX_FEED_BYTES // (1024 * 1024)))
            chunks.append(chunk)
    raw = b"".join(chunks)
    return raw, hashlib.sha256(raw).hexdigest()


def _parse_feed_payload(raw, fmt, region):
    text = raw.decode("utf-8-sig", "replace")
    if fmt.startswith("csv") and ":" in fmt:
        cols = [c.strip() for c in fmt.split(":", 1)[1].split(",")]

        def col(name, default):
            return cols.index(name) if name in cols else default

        num_i, label_i, rep_i = col("number", 0), col("label", 1), col("reports", 2)
        rows = []
        for i, row in enumerate(csv.reader(io.StringIO(text))):
            if i == 0 and _pick_column(row, _NUMBER_HEADERS) is not None:
                continue
            if not row or str(row[0]).lstrip().startswith("#") or num_i >= len(row):
                continue
            reports = re.sub(r"\D", "", row[rep_i]) if rep_i < len(row) else ""
            rows.append({"number": row[num_i].strip(),
                         "label": row[label_i].strip() if label_i < len(row) else "",
                         "reports": int(reports) if reports else 1})
    elif fmt in ("txt", "text", "plain"):
        rows = parse_number_text(text)
    else:
        rows = parse_number_text(text)

    entries = {}
    skipped = 0
    for row in rows:
        info = normalize_number(row["number"], region)
        if not info["valid"] or info["kind"] in ("sender_id",):
            skipped += 1
            continue
        key = info["e164"] or ("#" + info["national"])
        prev = entries.get(key)
        reports = max(1, int(row.get("reports") or 1))
        if prev:
            reports = max(prev["reports"], reports)
        entries[key] = {"reports": reports, "label": _clean_label(row.get("label"))}
    return entries, len(rows), skipped


def update_feeds(region=None, progress=None):
    """Download every `feeds.conf` source into the local cache (opt-in only).

    Returns a report list; failures leave the previous cached copy intact.
    """
    region = default_region(region)
    feeds = read_feeds_conf()
    if not feeds:
        return {"sources": [], "configured": 0,
                "hint": "add feed URLs to %s (URL | label | format)" % feeds_conf_path()}

    cache = _load_feed_cache()
    cache.setdefault("sources", {})
    report = []
    for feed in feeds:
        url = feed["url"]
        item = {"url": url, "label": feed["label"], "ok": False}
        try:
            raw, digest = _fetch(url)
            entries, total, skipped = _parse_feed_payload(raw, feed["format"], region)
            if len(entries) > MAX_FEED_ENTRIES:
                keep = sorted(entries.items(), key=lambda kv: kv[1]["reports"], reverse=True)
                entries = dict(keep[:MAX_FEED_ENTRIES])
            cache["sources"][url] = {
                "label": feed["label"],
                "format": feed["format"],
                "fetched_at": int(time.time()),
                "count": len(entries),
                "parsed": total,
                "skipped": skipped,
                "sha256": digest,
                "entries": entries,
            }
            item.update({"ok": True, "count": len(entries), "parsed": total,
                         "skipped": skipped, "sha256": digest[:12]})
        except Exception as exc:  # network, parse, size — keep the old copy
            item["error"] = str(exc)
        report.append(item)
        if progress:
            progress(item)

    if any(i["ok"] for i in report):
        cache["updated_at"] = int(time.time())
        _save_feed_cache(cache)
    return {"sources": report, "configured": len(feeds),
            "updated_at": cache.get("updated_at")}


def feed_status():
    cache = _load_feed_cache()
    return {
        "updated_at": cache.get("updated_at"),
        "sources": [
            {"url": url, "label": src.get("label"), "count": src.get("count"),
             "fetched_at": src.get("fetched_at"), "sha256": (src.get("sha256") or "")[:12]}
            for url, src in (cache.get("sources") or {}).items()
        ],
        "configured": read_feeds_conf(),
        "path": _path("feeds.json"),
    }


# --------------------------------------------------------------------------
# Batch sender auto-detection
# --------------------------------------------------------------------------

def split_sender(block):
    """Pull a leading `From: +91...` line out of a batch message.

    Returns (sender_raw_or_None, message_without_the_line).
    """
    if not block:
        return None, block
    lines = block.splitlines()
    if not lines:
        return None, block
    match = _SENDER_LINE_RE.match(lines[0])
    if not match:
        return None, block
    return match.group(1), "\n".join(lines[1:]).strip()
