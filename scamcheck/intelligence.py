"""Deterministic scam-intelligence layer.

This module answers the questions a good human analyst asks after a verdict:

  * What kind of scam is this?
  * Where are we in the playbook (trust -> money -> extraction -> pressure)?
  * What does the attacker actually want?
  * Which payment rail are they steering me toward?
  * Who are they pretending to be?
  * What will they try next?
  * How do I verify this safely, and what should I preserve as evidence?

Everything here is local and explainable: regexes, entity extraction and the
existing rule/playbook results. No network, no LLM, no hidden model.

Public API:
    deobfuscate(text) -> str
    detect_obfuscation(text) -> dict
    assess(text, result=None) -> dict
    format_briefing(intel) -> str
"""

import re
import unicodedata

from . import recovery
from .intel import dedupe, extract_entities

# ---------------------------------------------------------------------------
# Obfuscation: invisible characters, homoglyphs, spacing and URL disguises
# ---------------------------------------------------------------------------

INVISIBLE_RE = re.compile(
    "[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064"
    "\u2066-\u206f\ufeff]"
)

# Cyrillic/Greek letters that look like Latin ones. Applied globally in the
# deobfuscation *variant* only; detection is stricter (mixed-script tokens).
HOMOGLYPHS = {
    # Cyrillic uppercase
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X",
    "Ѕ": "S", "І": "I", "Ј": "J", "Һ": "H", "Ԛ": "Q", "Ԝ": "W",
    # Cyrillic lowercase
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h",
    "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ԛ": "q",
    "ԝ": "w", "ӏ": "l",
    # Greek uppercase
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X",
    # Greek lowercase
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w",
}
HOMOGLYPH_TABLE = str.maketrans(HOMOGLYPHS)

EMOJI_RE = re.compile(
    "[\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF\uFE0F\u20E3]"
)
SPACED_RE = re.compile(r"(?<!\w)(?:[A-Za-z][ \t]+){3,}[A-Za-z](?!\w)")
SEPARATED_RE = re.compile(
    r"(?<!\w)(?:[A-Za-z][._*•·|/\\\-]){2,}[A-Za-z](?!\w)"
)
EMOJI_PADDING_RE = re.compile(
    r"(?:[A-Za-z][\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF]{1,2}){3,}[A-Za-z]"
)
URL_OBF_RE = re.compile(
    r"\bhxxps?\b|\[\s*\.\s*\]|\(\s*\.\s*\)|\[\s*dot\s*\]|"
    r"\(\s*at\s*\)|\[\s*at\s*\]|\[\s*:\s*\]",
    re.I,
)
URL_DOT_RE = re.compile(
    r"(?<=\w)\s*(?:\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\})\s*(?=\w)|"
    r"(?<=\w)\s+dot\s+(?=(?:com|net|org|info|biz|io|co|in|us|uk|au|ca|sg|"
    r"ae|nz|za|app|shop|store|online|site|live|pro|dev|ai|xyz|top|tk|ml|ga|"
    r"cf|gq|ru|su|click|link|work|loan|win|bid)\b)",
    re.I,
)
URL_AT_RE = re.compile(
    r"(?<=\w)\s*(?:\[\s*at\s*\]|\(\s*at\s*\))\s*(?=\w)", re.I
)

LEET_TABLE = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "8": "b", "9": "g", "@": "a", "$": "s",
})

# Only de-leet words that are actually meaningful to a scam decision. Random
# digit substitutions in prices, OTPs and account numbers are left alone.
LEET_VOCAB = {
    "account", "bank", "banking", "blocked", "verify", "verification",
    "payment", "wallet", "urgent", "scam", "login", "password", "otp",
    "prize", "money", "refund", "kyc", "update", "security", "paypal",
    "amazon", "netflix", "support", "transfer", "deposit", "withdraw",
    "bitcoin", "crypto", "investment", "profit", "loan", "police",
    "customs", "parcel", "delivery", "gift", "card", "upi", "success",
    "winner", "claim", "bonus", "offer", "limited", "expire", "suspend",
    "freeze", "arrest", "court", "tax", "fee", "charge", "recovery",
    "validate", "confirm", "unlock", "reward", "cash", "salary", "job",
    "task", "trading", "block", "alert", "notice", "final", "warning",
}


def _repair_disguised_urls(text):
    text = re.sub(r"\bhxxp(s?)\b", lambda m: "http" + m.group(1), text, flags=re.I)
    text = re.sub(r"\[\s*:\s*\]", ":", text)
    text = re.sub(r"\[\s*/\s*\]", "/", text)
    text = URL_DOT_RE.sub(".", text)
    text = URL_AT_RE.sub("@", text)
    return text


def _collapse_spaced(text):
    return SPACED_RE.sub(lambda m: re.sub(r"\s+", "", m.group(0)), text)


def _collapse_separated(text):
    return SEPARATED_RE.sub(
        lambda m: re.sub(r"[._*•·|/\\\-]", "", m.group(0)), text
    )


def _leet_word(word):
    if not re.search(r"[0-9@$]", word):
        return word
    candidate = word.translate(LEET_TABLE)
    if candidate.lower() in LEET_VOCAB and candidate.lower() != word.lower():
        return candidate
    return word


def deobfuscate(text):
    """Return a matching-friendly variant with common disguises removed.

    Safe transformations (Unicode normalization, invisible-character removal,
    mixed-script homoglyph mapping, URL separators) plus conservative
    letter-spacing/leetspeak repair. This is a *variant*; the original text is
    always kept for evidence and display.
    """
    value = unicodedata.normalize("NFKC", text or "")
    value = INVISIBLE_RE.sub("", value)
    value = value.translate(HOMOGLYPH_TABLE)
    value = _repair_disguised_urls(value)
    value = _collapse_spaced(value)
    value = _collapse_separated(value)
    value = re.sub(r"\b[A-Za-z][A-Za-z0-9@$]*\b", lambda m: _leet_word(m.group(0)), value)
    value = EMOJI_RE.sub(" ", value)
    value = re.sub(r"[ \t]{2,}", " ", value)
    return value.strip()


def _homoglyph_count(text):
    """Count homoglyphs only inside mixed-script tokens (high confidence)."""
    count = 0
    for token in re.findall(r"[^\s]+", text or ""):
        if not re.search(r"[A-Za-z]", token):
            continue
        if any(ch in HOMOGLYPHS for ch in token):
            count += sum(1 for ch in token if ch in HOMOGLYPHS)
    return count


def _leet_hits(text):
    hits = 0
    for word in re.findall(r"\b[A-Za-z][A-Za-z0-9@$]*\b", text or ""):
        if not re.search(r"[0-9@$]", word):
            continue
        candidate = word.translate(LEET_TABLE).lower()
        if candidate in LEET_VOCAB and candidate != word.lower():
            hits += 1
    return hits


def detect_obfuscation(text, normalized=None):
    """Describe deliberate filter-evasion tricks in the raw message."""
    text = text or ""
    signals = []

    def add(key, label, count, weight):
        if count:
            signals.append({
                "key": key,
                "label": label,
                "count": int(count),
                "weight": int(weight),
            })

    # Full-width *letters/digits* are a disguise; full-width punctuation is
    # normal in CJK text, so do not treat it as evasion.
    fullwidth = len(re.findall("[\uff10-\uff19\uff21-\uff3a\uff41-\uff5a]", text))
    add("fullwidth", "Full-width characters used to look normal", fullwidth, 6)

    invisible = INVISIBLE_RE.findall(text)
    bidi = [
        ch for ch in invisible
        if "\u202a" <= ch <= "\u202e" or "\u2066" <= ch <= "\u2069"
    ]
    add("bidi", "Bidirectional control characters", len(bidi), 10)
    add("zero_width", "Zero-width/invisible characters", len(invisible) - len(bidi), 8)

    add("homoglyph",
        "Cyrillic/Greek lookalike letters inside Latin words",
        _homoglyph_count(text), 10)

    spaced = len(SPACED_RE.findall(text))
    add("spacing", "Letters padded with spaces to break matching", spaced, 5)

    separated = len(SEPARATED_RE.findall(text))
    add("separators", "Letters split with dots/dashes/symbols", separated, 6)

    emoji_padding = len(EMOJI_PADDING_RE.findall(text))
    add("emoji_padding", "Emoji inserted between letters", emoji_padding, 5)

    add("leetspeak", "Digit/symbol substitutions in scam words", _leet_hits(text), 4)

    url_hits = len(URL_OBF_RE.findall(text))
    add("url_obfuscation", "Disguised URL/email separators (hxxp, [.], dot)", url_hits, 7)

    score = min(20, sum(s["weight"] for s in signals))
    changed = (deobfuscate(text) != text) if normalized is None else (normalized != text)
    return {
        "detected": bool(signals),
        "signals": signals,
        "score": score,
        "changed": changed,
    }


# ---------------------------------------------------------------------------
# Scam-type inference
# ---------------------------------------------------------------------------

TYPE_PATTERNS = {
    "otp": [
        (r"\b(?:otp|one[- ]time\s+(?:password|code)|verification\s+code)\b", 9),
        (r"\b(?:share|send|tell|read|forward|enter|provide)\b[^.]{0,50}\b(?:otp|code|pin|cvv)\b", 10),
        (r"\b(?:pin|cvv|password)\b[^.]{0,40}\b(?:confirm|verify|update|expire)\b", 6),
        (r"\bdo not share\b[^.]{0,30}\b(?:otp|code|pin)\b", 2),
    ],
    "bank": [
        (r"\b(?:bank|banking)\b", 3),
        (r"\b(?:account|a/c)\b[^.]{0,35}\b(?:block(?:ed|ing)?|suspend(?:ed)?|freeze|frozen|deactivate(?:d)?|closed|limited|locked)\b", 10),
        (r"\b(?:block(?:ed|ing)?|suspend(?:ed)?|freeze|frozen|deactivate(?:d)?|close(?:d)?)\b[^.]{0,30}\b(?:account|card|sim)\b", 8),
        (r"\bkyc\b", 7),
        (r"\b(?:net ?banking|internet banking|mobile banking)\b", 6),
        (r"\b(?:ifsc|neft|imps|rtgs)\b", 6),
        (r"\b(?:bank officer|bank official|relationship manager|branch manager)\b", 5),
        (r"\bsafe account\b|\bsecurity account\b", 9),
    ],
    "upi": [
        (r"\bupi\b", 9),
        (r"\b(?:gpay|google pay|phonepe|paytm|bhim|amazon pay)\b", 7),
        (r"\b(?:vpa|virtual payment address)\b", 7),
        (r"\bcollect request\b|\bpayment request\b", 7),
        (r"@(?:okhdfcbank|okicici|oksbi|okaxis|ybl|paytm|ibl)\b", 6),
        (r"\bscan (?:this|the) qr\b|\bqr code\b", 5),
    ],
    "card": [
        (r"\bcvv\b|\bcvc\b", 10),
        (r"\bcard number\b|\b16[- ]digit\b", 8),
        (r"\b(?:credit|debit)\s+card\b", 5),
        (r"\b(?:card|payment)\b[^.]{0,30}\b(?:blocked|expired|suspended|verify)\b", 7),
        (r"\bexpiry date\b|\bexpiration date\b", 6),
    ],
    "crypto": [
        (r"\b(?:usdt|tether)\b", 10),
        (r"\b(?:bitcoin|btc|ethereum|eth|tron|trx)\b", 8),
        (r"\b(?:wallet address|wallet|blockchain|trc20|erc20)\b", 6),
        (r"\b(?:binance|coinbase|kraken|metamask|trust wallet)\b", 6),
        (r"\b(?:send|transfer|deposit)\b[^.]{0,40}\b(?:btc|usdt|eth|crypto)\b", 8),
    ],
    "investment": [
        (r"\bguaranteed\s+(?:return|profit|income)\b", 11),
        (r"\b(?:double|triple)\s+your\s+(?:money|investment)\b", 11),
        (r"\b(?:investment|investing|trading|trader)\b", 7),
        (r"\b(?:profit|returns?|portfolio|earnings?)\b", 5),
        (r"\b(?:platform|dashboard|mentor|account manager)\b", 4),
        (r"\bwithdraw(?:al)?\b[^.]{0,40}\b(?:fee|tax|profit|blocked)\b", 8),
        (r"\b(?:signal|forex|binary options)\b", 6),
    ],
    "job": [
        (r"\bpart[- ]time\b", 9),
        (r"\bwork from home\b|\bwork-from-home\b", 6),
        (r"\bdaily (?:payout|payment|income|earning)\b", 9),
        (r"\b(?:task|tasks)\b[^.]{0,40}\b(?:pay|commission|reward|telegram|whatsapp)\b", 9),
        (r"\b(?:like|rate|review|subscribe)\b[^.]{0,40}\b(?:hotel|product|video|task)\b", 7),
        (r"\b(?:recruiter|hiring|job offer|salary)\b", 4),
        (r"\b(?:telegram|whatsapp)\b[^.]{0,30}\b(?:job|task|work)\b", 7),
    ],
    "romance": [
        (r"\b(?:my love|my dear|darling|soulmate|future wife|future husband)\b", 7),
        (r"\b(?:love you|i love|falling for you)\b", 6),
        (r"\b(?:marry|marriage|relationship|dating|girlfriend|boyfriend)\b", 5),
        (r"\b(?:dear|honey|sweetheart|baby)\b", 3),
        (r"\b(?:met on|dating app|match)\b", 5),
    ],
    "sextortion": [
        (r"\b(?:nude|naked|intimate|sexual)\b", 9),
        (r"\b(?:webcam|web camera|video call)\b[^.]{0,40}\b(?:record|video|clip)\b", 9),
        (r"\bblackmail\b|\bsextortion\b", 12),
        (r"\b(?:leak|expose|send to)\b[^.]{0,30}\b(?:contacts|friends|family|social media)\b", 9),
        (r"\b(?:pay|send)\b[^.]{0,40}\b(?:or|otherwise)\b[^.]{0,40}\b(?:leak|expose|publish)\b", 9),
    ],
    "tech": [
        (r"\b(?:remote access|remote support|screen shar(?:e|ing))\b", 11),
        (r"\b(?:anydesk|teamviewer|ultraviewer|quick support|screenconnect)\b", 11),
        (r"\b(?:microsoft|windows|apple|google)\s+(?:support|technician|security)\b", 8),
        (r"\b(?:virus|malware|infected|hacked)\b", 6),
        (r"\b(?:your (?:device|computer|pc)|this computer)\b[^.]{0,40}\b(?:infected|risk|error)\b", 8),
        (r"\b(?:technician|tech support|support agent)\b", 5),
    ],
    "digital_arrest": [
        (r"\bdigital arrest\b", 14),
        (r"\b(?:cbi|fbi|ncb|trai|income tax|customs)\b", 6),
        (r"\barrest warrant\b|\bnon[- ]bailable\b", 11),
        (r"\b(?:police case|case officer|investigating officer|criminal case)\b", 8),
        (r"\b(?:money laundering|illegal parcel|drugs? found)\b", 8),
        (r"\b(?:stay on (?:the )?(?:video )?call|do not disconnect|keep the call connected)\b", 9),
        (r"\b(?:video call|skype)\b[^.]{0,40}\b(?:police|officer|verification)\b", 7),
    ],
    "courier": [
        (r"\bparcel\b|\bshipment\b|\bcourier\b", 8),
        (r"\bcustoms?\b", 6),
        (r"\b(?:delivery|redelivery|shipping)\s+(?:fee|charge|failed|pending)\b", 8),
        (r"\b(?:track|tracking)\b[^.]{0,30}\b(?:parcel|package|shipment)\b", 5),
        (r"\b(?:address|doorstep)\b[^.]{0,30}\b(?:update|confirm|incomplete)\b", 5),
    ],
    "loan": [
        (r"\b(?:personal|instant|pre[- ]approved|payday)\s+loan\b", 8),
        (r"\b(?:loan|credit)\b[^.]{0,40}\b(?:approved|offer|sanction)\b", 6),
        (r"\bprocessing fee\b|\badvance fee\b", 8),
        (r"\b(?:disbursal|disbursement)\b", 5),
        (r"\b(?:low interest|no credit check)\b", 6),
    ],
    "identity": [
        (r"\baadhaar\b|\baadhar\b|\buidai\b", 8),
        (r"\bpan card\b|\bpan number\b", 8),
        (r"\bssn\b|\bsocial security number\b", 9),
        (r"\bpassport\b", 5),
        (r"\bidentity theft\b|\bidentity verification\b", 6),
        (r"\b(?:date of birth|mother'?s maiden name|selfie with id)\b", 6),
    ],
}

TYPE_PRIORITY = [
    "digital_arrest", "sextortion", "tech", "otp", "job", "investment",
    "bank", "upi", "card", "crypto", "courier", "loan", "romance",
    "identity", "general",
]

SCRIPT_TYPES = {
    "pig butchering": "investment",
    "task scam": "job",
    "digital arrest": "digital_arrest",
    "tech-support": "tech",
    "grandparent": "identity",
    "courier": "courier",
    "invoice": "bank",
    "sextortion": "sextortion",
    "rental": "general",
    "toll": "card",
    "bank app": "bank",
    "romance": "romance",
    "family": "identity",
}

TYPE_GOALS = {
    "otp": ["credentials", "account_takeover"],
    "bank": ["money_transfer", "account_takeover"],
    "upi": ["money_transfer"],
    "card": ["credentials", "money_transfer"],
    "crypto": ["crypto_deposit"],
    "investment": ["investment", "crypto_deposit", "advance_fee"],
    "job": ["job_task", "advance_fee", "money_transfer"],
    "romance": ["money_transfer", "investment"],
    "sextortion": ["blackmail", "crypto_deposit"],
    "tech": ["remote_access", "account_takeover", "money_transfer"],
    "digital_arrest": ["money_transfer", "account_takeover", "identity"],
    "courier": ["money_transfer", "identity"],
    "loan": ["advance_fee"],
    "identity": ["identity", "account_takeover"],
    "general": ["money_transfer"],
}

_COMPILED_TYPES = {
    kind: [(re.compile(pattern, re.I), weight) for pattern, weight in patterns]
    for kind, patterns in TYPE_PATTERNS.items()
}


def infer_type(text, entities=None, result=None):
    """Score every scam type and return (key, scores, evidence)."""
    scores = {}
    evidence = {}
    for kind, patterns in _COMPILED_TYPES.items():
        total = 0
        hits = []
        for rx, weight in patterns:
            match = rx.search(text)
            if match:
                total += weight
                hits.append(match.group(0).strip()[:60])
        if total:
            scores[kind] = total
            evidence[kind] = hits[:4]

    kinds = {item.get("kind") for item in (entities or [])}
    if "upi" in kinds:
        scores["upi"] = scores.get("upi", 0) + 7
    if kinds & {"crypto_btc", "crypto_eth", "crypto_trx"}:
        scores["crypto"] = scores.get("crypto", 0) + 7
    if "ifsc" in kinds:
        scores["bank"] = scores.get("bank", 0) + 6
    if "apk" in kinds:
        scores["tech"] = scores.get("tech", 0) + 3
        scores["bank"] = scores.get("bank", 0) + 2

    for name in (result or {}).get("scripts") or []:
        low = name.lower()
        for needle, kind in SCRIPT_TYPES.items():
            if needle in low:
                scores[kind] = scores.get(kind, 0) + 12
                break

    if not scores or max(scores.values()) < 5:
        fallback = recovery.infer_type(text)
        if fallback != "general":
            scores[fallback] = scores.get(fallback, 0) + 5

    if not scores:
        return "general", {}, {}

    best = max(TYPE_PRIORITY, key=lambda k: (scores.get(k, 0), -TYPE_PRIORITY.index(k)))
    if scores.get(best, 0) <= 0:
        best = "general"
    return best, scores, evidence


# ---------------------------------------------------------------------------
# Goals, payment rails, impersonation, channels and tactics
# ---------------------------------------------------------------------------

MONEY_GOALS = {
    "money_transfer", "crypto_deposit", "credentials", "account_takeover",
    "blackmail", "advance_fee", "gift_card",
}

GOAL_LABELS = {
    "money_transfer": "Get you to send money",
    "crypto_deposit": "Get crypto into a wallet they control",
    "credentials": "Steal codes, passwords or card data",
    "remote_access": "Get remote control of your device",
    "app_install": "Get you to install their app",
    "identity": "Collect your identity documents",
    "account_takeover": "Take over or freeze your account",
    "blackmail": "Blackmail you with private material",
    "advance_fee": "Extract an advance fee",
    "investment": "Get you to 'invest' in a fake platform",
    "job_task": "Recruit you into a fake job/task scheme",
    "gift_card": "Get untraceable gift-card codes",
}

GOAL_PATTERNS = {
    "money_transfer": [
        r"\b(?:send|transfer|pay|deposit|remit)\b[^.]{0,40}\b(?:money|cash|amount|funds?|\d+)\b",
        r"\b(?:bank transfer|wire transfer|neft|imps|upi|payment)\b",
    ],
    "crypto_deposit": [
        r"\b(?:usdt|btc|bitcoin|eth|ethereum|trx|tron|crypto)\b",
        r"\b(?:wallet address|trc20|erc20)\b",
    ],
    "credentials": [
        r"\b(?:otp|one[- ]time (?:password|code)|verification code)\b",
        r"\b(?:pin|cvv|password|card number|login)\b[^.]{0,40}\b(?:share|send|tell|enter|confirm|verify)\b",
        r"\b(?:share|send|tell|read)\b[^.]{0,40}\b(?:pin|cvv|password|code)\b",
    ],
    "remote_access": [
        r"\b(?:anydesk|teamviewer|ultraviewer|remote access|screen shar(?:e|ing))\b",
    ],
    "app_install": [
        r"\b(?:download|install|sideload)\b[^.]{0,40}\b(?:app|apk|application|software)\b",
        r"\b(?:apk|play store|app store)\b",
    ],
    "identity": [
        r"\b(?:aadhaar|aadhar|pan card|ssn|social security|passport|id card)\b",
        r"\b(?:selfie with id|date of birth|mother'?s maiden name)\b",
        r"\bkyc\b",
    ],
    "account_takeover": [
        r"\b(?:account|card|sim)\b[^.]{0,40}\b(?:blocked|suspended|frozen|locked|deactivated)\b",
        r"\b(?:unauthorized|suspicious)\s+(?:login|activity|transaction)\b",
        r"\bverify your account\b",
    ],
    "blackmail": [
        r"\b(?:blackmail|sextortion|leak|expose)\b",
        r"\b(?:intimate|nude|webcam)\b[^.]{0,40}\b(?:video|photo|recording)\b",
    ],
    "advance_fee": [
        r"\b(?:processing|release|withdrawal|unlock|clearance|customs|service)\s+(?:fee|charge|tax)\b",
        r"\b(?:pay|send|deposit)\b[^.]{0,40}\b(?:to (?:withdraw|release|unlock)|before (?:delivery|release))\b",
    ],
    "investment": [
        r"\b(?:investment|trading|portfolio|guaranteed return|profit)\b",
        r"\b(?:platform|dashboard|mentor|account manager)\b",
    ],
    "job_task": [
        r"\b(?:part[- ]time|work from home|daily payout|task scam)\b",
        r"\b(?:like|rate|review)\b[^.]{0,40}\b(?:hotel|product|video)\b",
    ],
    "gift_card": [
        r"\b(?:gift card|itunes card|google play card|steam card|amazon card)\b",
    ],
}
_COMPILED_GOALS = {
    key: [re.compile(p, re.I) for p in patterns]
    for key, patterns in GOAL_PATTERNS.items()
}


def detect_goals(text, scam_type="general", include_type=True):
    found = []
    seen = set()
    # Type-specific goals lead, so "investment scam" reports the investment
    # goal before the generic "send money" goal. Plain `general` adds nothing:
    # a harmless chat should not be assigned an attacker goal.
    if include_type and scam_type != "general":
        for key in TYPE_GOALS.get(scam_type, []):
            if key not in seen:
                found.append(key)
                seen.add(key)
    for key, patterns in _COMPILED_GOALS.items():
        for rx in patterns:
            if rx.search(text):
                if key not in seen:
                    found.append(key)
                    seen.add(key)
                break
    return [
        {"key": key, "label": GOAL_LABELS.get(key, key.replace("_", " "))}
        for key in found[:4]
    ]


RAIL_PATTERNS = {
    "upi": ("UPI / instant payment", [
        r"\bupi\b", r"\b(?:gpay|google pay|phonepe|paytm|bhim)\b",
        r"\b(?:vpa|collect request)\b", r"@(?:okhdfcbank|okicici|oksbi|okaxis|ybl|paytm|ibl)\b",
    ]),
    "bank_transfer": ("Bank transfer", [
        r"\b(?:bank transfer|wire transfer|neft|imps|rtgs)\b",
        r"\b(?:account number|beneficiary|ifsc|branch)\b",
    ]),
    "card": ("Card payment", [
        r"\b(?:credit|debit)\s+card\b", r"\bcvv\b", r"\bcard number\b",
    ]),
    "crypto": ("Crypto wallet", [
        r"\b(?:btc|bitcoin|eth|ethereum|usdt|trx|tron|crypto)\b",
        r"\b(?:wallet address|trc20|erc20|blockchain)\b",
    ]),
    "gift_card": ("Gift card", [
        r"\b(?:gift card|itunes card|google play card|steam card|amazon card)\b",
    ]),
    "wallet_app": ("Payment app / wallet", [
        r"\b(?:paypal|venmo|cash app|zelle|wise|revolut)\b",
    ]),
}
_COMPILED_RAILS = {
    key: (label, [re.compile(p, re.I) for p in patterns])
    for key, (label, patterns) in RAIL_PATTERNS.items()
}


def detect_rails(text, entities=None):
    found = []
    seen = set()
    for key, (label, patterns) in _COMPILED_RAILS.items():
        evidence = []
        for rx in patterns:
            match = rx.search(text)
            if match:
                evidence.append(match.group(0).strip())
        if key == "wallet_app" and not re.search(
            r"\b(?:pay|send|transfer|receive|request|invoice|payment|refund)\b",
            text, re.I,
        ):
            # A brand mention alone (often in a phishing domain) is not a
            # payment rail.
            continue
        if evidence and key not in seen:
            found.append({"key": key, "label": label, "evidence": evidence[:3]})
            seen.add(key)

    for item in entities or []:
        kind, value = item.get("kind"), item.get("value")
        if kind == "upi":
            found.append({"key": "upi", "label": RAIL_PATTERNS["upi"][0],
                          "evidence": [value]})
        elif kind in ("crypto_btc", "crypto_eth", "crypto_trx"):
            found.append({"key": "crypto", "label": RAIL_PATTERNS["crypto"][0],
                          "evidence": [value]})
        elif kind == "ifsc":
            found.append({"key": "bank_transfer", "label": RAIL_PATTERNS["bank_transfer"][0],
                          "evidence": ["IFSC " + value]})

    out, seen = [], set()
    for rail in found:
        if rail["key"] in seen:
            continue
        seen.add(rail["key"])
        evidence = []
        for value in rail.get("evidence") or []:
            if value and value not in evidence:
                evidence.append(value)
        out.append({
            "key": rail["key"],
            "label": rail["label"],
            "evidence": evidence[:3],
        })
    return out[:4]


IMPERSONATION = [
    ("bank", "HDFC Bank", r"\bhdfc\b"),
    ("bank", "ICICI Bank", r"\bicici\b"),
    ("bank", "State Bank of India", r"\bsbi\b|\bstate bank\b"),
    ("bank", "Axis Bank", r"\baxis bank\b"),
    ("bank", "Kotak Mahindra Bank", r"\bkotak\b"),
    ("bank", "Punjab National Bank", r"\bpnb\b|\bpunjab national\b"),
    ("bank", "Bank of Baroda", r"\bbank of baroda\b"),
    ("bank", "Canara Bank", r"\bcanara\b"),
    ("bank", "Yes Bank", r"\byes bank\b"),
    ("bank", "IDFC First Bank", r"\bidfc\b"),
    ("bank", "Chase", r"\bchase\b"),
    ("bank", "Bank of America", r"\bbank of america\b"),
    ("bank", "Wells Fargo", r"\bwells fargo\b"),
    ("bank", "HSBC", r"\bhsbc\b"),
    ("bank", "Barclays", r"\bbarclays\b"),
    ("bank", "Lloyds Bank", r"\blloyds\b"),
    ("bank", "NatWest", r"\bnatwest\b"),
    ("bank", "DBS Bank", r"\bdbs\b"),
    ("bank", "OCBC", r"\bocbc\b"),
    ("bank", "UOB", r"\buob\b"),
    ("bank", "Standard Chartered", r"\bstandard chartered\b"),
    ("bank", "Citibank", r"\bciti(?:bank)?\b"),
    ("authority", "Police", r"\bpolice\b"),
    ("authority", "CBI", r"\bcbi\b"),
    ("authority", "FBI", r"\bfbi\b"),
    ("authority", "IRS", r"\birs\b"),
    ("authority", "HMRC", r"\bhmrc\b"),
    ("authority", "Social Security Administration", r"\bsocial security\b"),
    ("authority", "UIDAI / Aadhaar", r"\buidai\b|\baadhaar\b|\baadhar\b"),
    ("authority", "TRAI", r"\btrai\b"),
    ("authority", "Customs", r"\bcustoms?\b"),
    ("authority", "Income Tax Department", r"\bincome tax\b"),
    ("authority", "Court", r"\bcourt\b"),
    ("company", "Microsoft", r"\bmicrosoft\b"),
    ("company", "Apple", r"\bapple\b"),
    ("company", "Amazon", r"\bamazon\b"),
    ("company", "Google", r"\bgoogle\b"),
    ("company", "Netflix", r"\bnetflix\b"),
    ("company", "Meta / Facebook", r"\bmeta\b|\bfacebook\b"),
    ("company", "WhatsApp", r"\bwhatsapp\b"),
    ("delivery", "FedEx", r"\bfedex\b"),
    ("delivery", "UPS", r"\bups\b[^.]{0,60}\b(?:tracking|delivery|parcel|shipment|courier)\b"),
    ("delivery", "DHL", r"\bdhl\b"),
    ("delivery", "USPS", r"\busps\b"),
    ("delivery", "Royal Mail", r"\broyal mail\b"),
    ("delivery", "Australia Post", r"\baustralia post\b"),
    ("delivery", "India Post", r"\bindia post\b"),
    ("delivery", "Flipkart", r"\bflipkart\b"),
    ("payment app", "PayPal", r"\bpaypal\b"),
    ("payment app", "Venmo", r"\bvenmo\b"),
    ("payment app", "Cash App", r"\bcash app\b"),
    ("payment app", "Zelle", r"\bzelle\b"),
    ("payment app", "PhonePe", r"\bphonepe\b"),
    ("payment app", "Google Pay", r"\bgoogle pay\b|\bgpay\b"),
    ("payment app", "Paytm", r"\bpaytm\b"),
    ("exchange", "Binance", r"\bbinance\b"),
    ("exchange", "Coinbase", r"\bcoinbase\b"),
    ("exchange", "Kraken", r"\bkraken\b"),
]
_COMPILED_IMPERSONATION = [
    (kind, name, re.compile(pattern, re.I))
    for kind, name, pattern in IMPERSONATION
]


def detect_impersonation(text):
    found = []
    seen = set()
    for kind, name, rx in _COMPILED_IMPERSONATION:
        if rx.search(text) and name not in seen:
            found.append({"kind": kind, "name": name})
            seen.add(name)
    if not found:
        if re.search(r"\byour bank\b|\bthe bank\b|\bbank officer\b", text, re.I):
            found.append({"kind": "bank", "name": "your bank (unnamed)"})
        elif re.search(r"\b(?:officer|government|law enforcement)\b", text, re.I):
            found.append({"kind": "authority", "name": "an authority (unnamed)"})
    return found[:5]


CHANNEL_PATTERNS = [
    ("WhatsApp", r"\bwhatsapp\b|\bwa\.me\b|chat\.whatsapp\.com"),
    ("Telegram", r"\btelegram\b|\bt\.me/"),
    ("email", r"\bemail\b|\bsubject\s*:|\bunsubscribe\b"),
    ("SMS", r"\bsms\b|\btext message\b|\btexted\b"),
    ("phone call", r"\b(?:call|dial|phone)\b[^.]{0,25}\b(?:us|me|now|back|number)\b"),
    ("app", r"\b(?:download|install|app|apk|play store|app store)\b"),
]


def detect_channels(text):
    found = []
    for label, pattern in CHANNEL_PATTERNS:
        if re.search(pattern, text, re.I):
            found.append(label)
    return found or ["SMS / chat (format not stated)"]


TACTICS = {
    "urgency": "Artificial urgency or a countdown",
    "fear": "Threats: block, freeze, fine, arrest or loss",
    "authority": "Authority impersonation",
    "greed": "Too-good-to-be-true gain",
    "secrecy": "Isolation / secrecy",
    "trust": "False familiarity or trust-building",
    "instruction": "Pushes you to follow their instructions",
    "scarcity": "Scarcity or exclusive access",
}
TACTIC_PATTERNS = {
    "urgency": r"\b(?:urgent|immediately|right now|within \d+ (?:minutes?|hours?)|last (?:chance|warning)|final (?:notice|warning)|expires?|deadline|today only)\b",
    "fear": r"\b(?:blocked|suspended|frozen|deactivated|legal action|arrest|warrant|fine|penalty|lose access|permanently)\b",
    "authority": r"\b(?:bank|police|officer|government|official|department|cbi|fbi|irs|hmrc|trai|customs|court)\b",
    "greed": r"\b(?:guaranteed|profit|bonus|prize|lottery|winner|refund|cashback|double your|free|reward)\b",
    "secrecy": r"\b(?:don'?t tell|do not tell|confidential|between us|keep (?:this|it) (?:secret|private)|don'?t contact (?:your )?bank|stay on the (?:line|call))\b",
    "trust": r"\b(?:dear|friend|sir|madam|my love|darling|honey|baby|trust me|i am here to help)\b",
    "instruction": r"\b(?:click|tap|download|install|scan|send|transfer|pay|share|enter|call this number)\b",
    "scarcity": r"\b(?:limited (?:time|slots?|offer)|only \d+ (?:left|spots?)|exclusive|act fast)\b",
}
_COMPILED_TACTICS = {
    key: (label, re.compile(TACTIC_PATTERNS[key], re.I))
    for key, label in TACTICS.items()
}


def detect_tactics(text):
    found = []
    for key, (label, rx) in _COMPILED_TACTICS.items():
        if rx.search(text):
            found.append({"key": key, "label": label})
    return found


# ---------------------------------------------------------------------------
# Stage / kill-chain position
# ---------------------------------------------------------------------------

STAGE_ORDER = ["groom", "pivot", "platform", "deposit", "fee", "pressure", "secrecy"]
STAGE_LABELS = {
    "groom": "building trust / making contact",
    "pivot": "turning the conversation toward money",
    "platform": "moving you onto their platform or app",
    "deposit": "collecting a payment or deposit",
    "fee": "blocking withdrawal and demanding more fees",
    "pressure": "applying urgency, threats or a deadline",
    "secrecy": "isolating you from people who could intervene",
}
STAGE_CUES = {
    "groom": [
        r"\b(?:dear|hello|hi|hey)\b", r"\bhow are you\b",
        r"\b(?:nice to meet|good to meet|friend|baby|my love)\b",
    ],
    "pivot": [
        r"\b(?:investment|trading|profit|returns?|earn|opportunity|job|offer|prize|lottery|refund|compensation)\b",
        r"\b(?:business|project|partnership)\b[^.]{0,30}\b(?:money|profit|earn)\b",
    ],
    "platform": [
        r"\b(?:platform|website|portal|dashboard|register|sign ?up)\b",
        r"\b(?:download|install)\b[^.]{0,40}\b(?:app|apk|application|software)\b",
    ],
    "deposit": [
        r"\b(?:deposit|top ?up|recharge|send|transfer|pay|payment|invest)\b",
        r"\b(?:upi|usdt|btc|bitcoin|wallet|bank transfer|account number)\b",
    ],
    "fee": [
        r"\b(?:withdrawal|release|unlock|processing|clearance|customs|tax|gst|commission|service)\s+(?:fee|charge|tax)\b",
        r"\b(?:pay|deposit|send)\b[^.]{0,50}\b(?:to withdraw|to release|to unlock|before (?:your )?withdrawal)\b",
    ],
    "pressure": [
        r"\b(?:urgent|immediately|right now|within \d+ (?:hours?|minutes?)|last (?:chance|warning)|final notice|expires?|deadline)\b",
        r"\b(?:account|card|sim|number)\b[^.]{0,35}\b(?:block(?:ed|ing)?|suspend(?:ed)?|freeze|frozen|deactivate(?:d)?|disconnect(?:ed)?)\b",
        r"\b(?:verify|confirm|update|validate)\b[^.]{0,30}\b(?:now|immediately|today|within)\b",
    ],
    "secrecy": [
        r"\b(?:don'?t|do not|never)\s+(?:tell|inform|contact)\s+(?:anyone|your (?:family|bank|police)|the police)\b",
        r"\b(?:confidential|between us|keep (?:this|it) (?:secret|private)|stay on the (?:line|call))\b",
    ],
}
_COMPILED_STAGE_CUES = {
    key: [re.compile(p, re.I) for p in patterns]
    for key, patterns in STAGE_CUES.items()
}


def detect_stage(text, conversation=None, score=0):
    stages = (conversation or {}).get("stages") or {}
    if stages:
        present = [
            key for key in STAGE_ORDER
            if (stages.get(key) or {}).get("count", 0) > 0
        ]
        if present:
            monetary = [k for k in present
                        if k in ("groom", "pivot", "platform", "deposit", "fee")]
            if monetary:
                key = monetary[-1]
            elif "pressure" in present:
                key = "pressure"
            elif "secrecy" in present:
                key = "secrecy"
            else:
                key = present[-1]
            return {
                "key": key,
                "label": STAGE_LABELS[key],
                "path": present,
                "detected": present,
                "confidence": "high",
            }

    detected = [
        key for key in STAGE_ORDER
        if any(rx.search(text) for rx in _COMPILED_STAGE_CUES[key])
    ]
    if not detected:
        return {
            "key": None,
            "label": "not enough context",
            "path": [],
            "detected": [],
            "confidence": "low",
        }
    # Pressure and secrecy are tactics that can appear at any point. Prefer
    # the furthest *money* stage when one is present; otherwise report the
    # tactic as the stage.
    monetary = [k for k in detected
                if k in ("groom", "pivot", "platform", "deposit", "fee")]
    if monetary:
        key = monetary[-1]
    elif "pressure" in detected:
        key = "pressure"
    elif "secrecy" in detected:
        key = "secrecy"
    else:
        key = detected[-1]
    confidence = "high" if score >= 60 else "medium" if score >= 35 else "low"
    return {
        "key": key,
        "label": STAGE_LABELS[key],
        "path": detected,
        "detected": detected,
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Predicted next moves
# ---------------------------------------------------------------------------

NEXT_BY_STAGE = {
    "groom": [
        "They will move the chat to WhatsApp or Telegram where moderation is weaker.",
        "They will build rapport before mentioning money at all.",
    ],
    "pivot": [
        "They will introduce a 'guaranteed' investment, job, prize or refund.",
        "They will show fake screenshots of profits or other 'happy customers'.",
        "They will ask for a small first deposit to prove you are serious.",
    ],
    "platform": [
        "They will send a link or APK to a fake dashboard that shows invented gains.",
        "The platform will let you withdraw a small amount once to build trust.",
        "A 'manager' or 'mentor' will take over the chat and push bigger deposits.",
    ],
    "deposit": [
        "They will ask for a second, larger deposit before any withdrawal.",
        "They will claim a 'tax', 'verification' or 'account upgrade' is required.",
        "They will introduce a fake bank/police officer if you resist.",
    ],
    "fee": [
        "They will demand fee after fee; nothing you pay will release the money.",
        "They will threaten account closure, legal action or arrest to force payment.",
        "They may offer a 'recovery agent' who is part of the same operation.",
    ],
    "pressure": [
        "They will shorten the deadline and repeat the threat through another channel.",
        "They will impersonate police, bank fraud staff or a government portal.",
        "They will demand secrecy from family, bank staff or the police.",
    ],
    "secrecy": [
        "They will insist the matter is confidential and that you must not verify it.",
        "They will create a fake emergency so you act before talking to anyone.",
        "They may send a 'courier' or ask you to stay on the call while you pay.",
    ],
}

NEXT_BY_TYPE = {
    "otp": [
        "They will trigger a real OTP and ask you to read it back or type it into a page.",
        "If you shared a code, they will immediately try a transaction or password reset.",
        "They may already know part of your account details to sound convincing.",
    ],
    "bank": [
        "A 'bank officer' may call and ask for your OTP/PIN or a transfer to a 'safe account'.",
        "They may send a fake case ID or freeze notice with a tight deadline.",
        "They may ask you to install a remote-access or 'bank update' app.",
    ],
    "upi": [
        "They may send a 'collect request' that looks like a refund but debits you.",
        "They may ask you to scan a QR code to 'receive' money - scanning can pay them.",
        "They will escalate to a fake bank officer if the first request fails.",
    ],
    "card": [
        "They will ask for the CVV, expiry or the OTP sent to your phone.",
        "They may test a small charge before attempting a larger one.",
        "They may call back as 'fraud prevention' and ask you to move funds.",
    ],
    "crypto": [
        "They will push you to a wallet or exchange address they control.",
        "They will claim the transfer is stuck and needs a fee or 'gas' payment.",
        "They may ask for your seed phrase or exchange login, not just a payment.",
    ],
    "investment": [
        "They will show fake profits and encourage a larger deposit.",
        "They will block withdrawals and demand tax/fees/level-up payments.",
        "A 'manager' will pressure you to recruit friends or take a loan.",
    ],
    "job": [
        "They will pay a small real commission first, then require a deposit for 'premium tasks'.",
        "They will move you to Telegram/WhatsApp and assign a 'mentor'.",
        "They may send an APK or remote-access tool to 'process payments'.",
    ],
    "romance": [
        "They will deepen the relationship, then introduce an investment or emergency.",
        "They will avoid live video or make excuses not to meet.",
        "They will ask for money, gift cards or crypto for 'visa', 'hospital' or 'customs'.",
    ],
    "sextortion": [
        "They will show a fake screenshot or claim they have your contacts.",
        "They will demand crypto within hours and threaten to leak the material.",
        "Paying will increase the demands; the material is often fabricated.",
    ],
    "tech": [
        "They will ask you to install AnyDesk/TeamViewer and share your screen.",
        "They will open your banking app and move money to a 'safe' account.",
        "They may install a remote-access tool that survives a reboot.",
    ],
    "digital_arrest": [
        "They will keep you on a video call and forbid you from contacting anyone.",
        "They will produce fake warrants, case numbers and government letterheads.",
        "They will demand a 'verification transfer' to a government account.",
    ],
    "courier": [
        "They will ask for a small customs/redelivery fee through a link.",
        "They may send a fake courier to collect cash, gold or documents.",
        "They will escalate with a fake police/customs case if you refuse.",
    ],
    "loan": [
        "They will approve the loan instantly, then demand an upfront processing fee.",
        "They will ask for KYC documents and a 'security deposit' before disbursal.",
        "The loan will never arrive, and the fee will not be refunded.",
    ],
    "identity": [
        "They will use your identity documents to open accounts or take loans.",
        "They may ask for a selfie with your ID to bypass KYC checks.",
        "They will combine your data with a fake authority story.",
    ],
    "general": [
        "They will escalate pressure, add a fake authority figure, or move you to another app.",
        "They will ask for a small payment or code to 'verify' you.",
        "Any reply confirms your number is active; silence is safer.",
    ],
}


def predict_next(stage_key, scam_type, limit=5):
    out, seen = [], set()
    for item in (NEXT_BY_STAGE.get(stage_key) or []) + (NEXT_BY_TYPE.get(scam_type) or []):
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out[:limit]


# ---------------------------------------------------------------------------
# Verification, safe replies and evidence guidance
# ---------------------------------------------------------------------------

VERIFY_GENERIC = [
    "Stop. Do not click, pay, install anything, or share a code.",
    "Verify through a channel you find yourself - the number on your card/app or the organisation's official website.",
    "Never use the phone number, link or account details supplied in the message.",
]

VERIFY_BY_TYPE = {
    "otp": [
        "No real bank, police force or company will ask for an OTP, PIN, CVV or password.",
        "If you already shared a code, call your bank's fraud line now and change the password.",
    ],
    "bank": [
        "Open your banking app directly (not through the link) and check for real alerts.",
        "Call the number printed on your card or banking app and ask whether the message is genuine.",
    ],
    "upi": [
        "Open your UPI app directly and check pending collect requests; decline anything you did not initiate.",
        "Remember: receiving money never requires a PIN or a payment.",
    ],
    "card": [
        "Call the number on the back of your card and ask the fraud team to check the alert.",
        "Never read out the CVV or a code from SMS; block the card from the app if unsure.",
    ],
    "crypto": [
        "Do not send crypto to an address that arrived in a chat; verify the recipient independently.",
        "No legitimate platform needs your seed phrase or exchange password.",
    ],
    "investment": [
        "Search the platform name independently and check the regulator's register for a licence.",
        "A recruiter or dating partner who pushes an investment platform is a major red flag.",
        "Do not deposit to 'test' a platform; legitimate firms do not recruit through chat.",
    ],
    "job": [
        "Open the employer's official careers page and call the published HR number.",
        "Legitimate employers never ask you to pay for tasks, training or equipment.",
    ],
    "romance": [
        "Insist on a live video call and verify the person independently before any money talk.",
        "Never send money, gift cards or crypto to someone you have not met.",
    ],
    "sextortion": [
        "Do not pay. Paying increases demands and does not remove the material.",
        "Save the evidence, stop responding, and report to the platform and police.",
    ],
    "tech": [
        "Hang up and call the company using the number on your device, bill or official website.",
        "Do not install remote-access software or let anyone control your screen.",
    ],
    "digital_arrest": [
        "No police force arrests or fines people over a video call. Hang up.",
        "Call your local police station or cybercrime portal directly using a number you find yourself.",
    ],
    "courier": [
        "Track the parcel only through the carrier's official app or website.",
        "Do not pay a 'customs' or 'redelivery' fee from a link in a message.",
    ],
    "loan": [
        "Check the lender's registration with your financial regulator.",
        "Never pay an upfront 'processing' or 'security' fee to get a loan.",
    ],
    "identity": [
        "If you shared ID documents, freeze your credit and change passwords now.",
        "Report identity theft to the relevant authority and keep a copy of the report.",
    ],
    "general": [
        "Ask yourself: why would a stranger need money, codes or secrecy from me?",
    ],
}


def verification_steps(scam_type, limit=5):
    out = list(VERIFY_GENERIC) + list(VERIFY_BY_TYPE.get(scam_type) or [])
    seen, result = set(), []
    for item in out:
        if item not in seen:
            result.append(item)
            seen.add(item)
    return result[:limit]


SAFE_REPLIES_GENERIC = [
    "I'll verify this directly with my bank.",
    "I don't share codes, passwords or card details over chat.",
    "Please send your official website and company registration; I'll check it myself.",
]

SAFE_REPLIES_BY_TYPE = {
    "digital_arrest": [
        "I'm ending this call and will contact my local police station directly.",
        "I don't discuss legal matters over video calls.",
    ],
    "job": [
        "I only deal through the employer's official careers page.",
        "I don't pay for tasks, training or equipment.",
    ],
    "investment": [
        "I don't invest through social-media contacts; I'll verify with a licensed adviser.",
        "I'm not depositing anything until I verify the platform independently.",
    ],
    "romance": [
        "I'm not sending money or images. I'm ending this conversation.",
        "Let's do a live video call before we talk about anything else.",
    ],
    "sextortion": [
        "I'm not paying. I'm saving this conversation and reporting it.",
    ],
    "tech": [
        "I'm hanging up and calling the company using the number on my device.",
        "I don't allow remote access to my devices.",
    ],
    "bank": [
        "I'll call the number on my card and check with the fraud team.",
    ],
    "upi": [
        "I'm not approving any collect request or scanning a QR code to receive money.",
    ],
    "courier": [
        "I'll track the parcel through the carrier's official app.",
    ],
    "loan": [
        "I'm not paying any upfront fee for a loan.",
    ],
}


def safe_replies(scam_type, score):
    out = list(SAFE_REPLIES_BY_TYPE.get(scam_type) or []) + list(SAFE_REPLIES_GENERIC)
    seen, result = set(), []
    for item in out:
        if item not in seen:
            result.append(item)
            seen.add(item)
    return result[:3], ("do_not_reply" if score >= 35 else "verify_first")


EVIDENCE_GENERIC = [
    "Screenshot the full message: sender/number, timestamp, links and any reference IDs.",
    "Export the chat before blocking (WhatsApp: chat > More > Export chat; Telegram: chat > Export chat).",
    "Save the sender ID, phone, UPI ID, account/IFSC, wallet address, URL and app name.",
    "Keep transaction IDs, amounts and times; do not delete the original SMS or email.",
    "If money moved, call your bank's fraud line now and ask for a recall/freeze.",
]

EVIDENCE_BY_TYPE = {
    "bank": [
        "Save the full SMS/email headers and the bank's real alert (if any) for comparison.",
    ],
    "upi": [
        "Open the UPI app and save the collect-request/transaction reference before declining.",
    ],
    "card": [
        "Save the card alert and the merchant descriptor; ask the issuer for the dispute reference.",
    ],
    "crypto": [
        "Copy the wallet address and transaction hash; do not delete the wallet/app.",
    ],
    "investment": [
        "Screenshot the platform URL, dashboard, group chat and every deposit receipt.",
    ],
    "job": [
        "Save the job ad, recruiter profile, task screenshots and any APK/link sent.",
    ],
    "romance": [
        "Save the profile, photos, chat and any payment requests before blocking.",
    ],
    "sextortion": [
        "Save the threat, profile and payment demand; do not delete or pay.",
    ],
    "tech": [
        "Note the remote-access app/ID used and disconnect the device from the network.",
    ],
    "digital_arrest": [
        "Save the caller ID, video-call screenshot, fake warrant/case number and transfer details.",
    ],
    "courier": [
        "Save the tracking number, link, sender ID and any 'customs fee' request.",
    ],
    "loan": [
        "Save the loan offer, fee demand, caller number and any documents you sent.",
    ],
    "identity": [
        "List every document you shared and report the exposure to the issuer/authority.",
    ],
}


def evidence_steps(scam_type, limit=6):
    out = list(EVIDENCE_BY_TYPE.get(scam_type) or []) + list(EVIDENCE_GENERIC)
    seen, result = set(), []
    for item in out:
        if item not in seen:
            result.append(item)
            seen.add(item)
    return result[:limit]


# ---------------------------------------------------------------------------
# Public assessment
# ---------------------------------------------------------------------------

def _confidence(score, result):
    if score >= 60 or (result or {}).get("scripts"):
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _summary(scam_type, title, stage, goals, score, verdict):
    goal = goals[0]["label"].lower() if goals else ""
    if score >= 60:
        text = "This matches %s" % title
        if stage.get("key"):
            text += " (current stage: %s)" % stage["label"]
        text += "."
        if goal:
            text += " Likely goal: %s." % goal
        return text
    if score >= 35:
        text = "Strong %s indicators" % title
        if stage.get("key"):
            text += " (current stage: %s)" % stage["label"]
        text += "."
        if goal:
            text += " Likely goal: %s." % goal
        return text
    if score >= 15:
        text = "Some %s indicators, but not enough to call it a scam." % title
        if goal:
            text += " Be alert to: %s." % goal
        return text
    if title != "no strong scam pattern":
        text = "Possible %s pattern" % title
        if stage.get("key"):
            text += " (current stage: %s)" % stage["label"]
        text += ", but it does not yet meet the scam threshold."
        if goal:
            text += " Watch for: %s." % goal
        return text
    return ("No strong scam pattern in this message. That is not a guarantee of "
            "safety - keep normal caution with links, codes and money.")


def assess(text, result=None):
    """Return the full local intelligence assessment for one message."""
    raw = text or ""
    normalized = deobfuscate(raw)
    analysis = normalized if normalized.strip() else raw

    if result is None:
        from .rules import run_rules
        base = run_rules(analysis)
        result = {
            "score": base["score"],
            "verdict": base["verdict"],
            "final_verdict": base["verdict"],
            "reasons": base["reasons"],
            "scripts": [],
            "conversation": None,
        }

    score = int(result.get("score") or 0)
    verdict = result.get("final_verdict") or result.get("verdict") or "LIKELY SAFE"
    conversation = result.get("conversation")

    entities = dedupe(extract_entities(raw) + extract_entities(analysis))
    scam_type, type_scores, type_evidence = infer_type(
        analysis, entities=entities, result=result
    )
    obfuscation = detect_obfuscation(raw, normalized=normalized)

    # Do not dress up a harmless message as an attack plan. A type only counts
    # as a real hypothesis when the rules agree, its own score is meaningful,
    # or it is paired with an explicit money/credential goal. This keeps a
    # legitimate "part-time job" or "I love you" from becoming a briefing.
    type_strength = max(type_scores.values() or [0])
    explicit_goals = detect_goals(analysis, "general")
    moneyish = any(g["key"] in MONEY_GOALS for g in explicit_goals)
    strong = (
        score >= 15
        or type_strength >= 15
        or (type_strength >= 8 and moneyish)
        or obfuscation["detected"]
    )

    if strong:
        title = recovery.TYPE_TITLES.get(scam_type, recovery.TYPE_TITLES["general"])
        stage = detect_stage(analysis, conversation=conversation, score=score)
        goals = detect_goals(
            analysis, scam_type,
            include_type=(score >= 15 or type_strength >= 15),
        )
        rails = detect_rails(analysis, entities)
        if not rails and scam_type == "bank":
            rails = [{"key": "bank_transfer", "label": "Bank account / transfer",
                      "evidence": []}]
        impersonation = detect_impersonation(analysis)
        channels = detect_channels(analysis)
        tactics = detect_tactics(analysis)
        next_moves = predict_next(stage.get("key"), scam_type)
        verify = verification_steps(scam_type)
        replies, reply_policy = safe_replies(scam_type, score)
        evidence = evidence_steps(scam_type)
    else:
        scam_type = "general"
        title = "no strong scam pattern"
        stage = {
            "key": None,
            "label": "not enough context",
            "path": [],
            "detected": [],
            "confidence": "low",
        }
        goals, rails, impersonation = [], [], []
        channels, tactics, next_moves = [], [], []
        verify, replies, evidence = [], [], []
        reply_policy = "verify_first"

    red_flags = [
        label for label, weight in (result.get("reasons") or []) if weight > 0
    ][:6]

    return {
        "scam_type": scam_type,
        "title": title,
        "confidence": _confidence(score, result),
        "score": score,
        "verdict": verdict,
        "summary": _summary(scam_type, title, stage, goals, score, verdict),
        "stage": stage,
        "goals": goals,
        "payment_rails": rails,
        "impersonation": impersonation,
        "channels": channels,
        "tactics": tactics,
        "next_moves": next_moves,
        "verify": verify,
        "safe_replies": replies,
        "reply_policy": reply_policy,
        "evidence": evidence,
        "obfuscation": obfuscation,
        "red_flags": red_flags,
        "entities": entities,
        "type_scores": type_scores,
        "type_evidence": type_evidence,
    }


def format_briefing(intel):
    """Turn an assess() result into a compact human briefing."""
    if not intel:
        return "No intelligence to show."

    lines = ["🧠 Intelligence briefing", ""]
    if intel.get("summary"):
        lines.append("  " + intel["summary"])
    lines.append("")
    lines.append("Type:        %s (confidence: %s)" % (
        intel.get("title") or "scam / fraud", intel.get("confidence") or "low"))
    stage = intel.get("stage") or {}
    if stage.get("key"):
        lines.append("Stage:       %s" % stage.get("label"))
    if intel.get("goals"):
        lines.append("Goal:        " + "; ".join(
            g["label"] for g in intel["goals"]))
    if intel.get("payment_rails"):
        rails = []
        for rail in intel["payment_rails"]:
            bits = rail.get("label") or rail.get("key")
            evidence = [e for e in (rail.get("evidence") or []) if e]
            if evidence:
                bits += " (%s)" % ", ".join(evidence[:2])
            rails.append(bits)
        lines.append("Payment:     " + "; ".join(rails))
    if intel.get("impersonation"):
        lines.append("Impersonates:" + " " + ", ".join(
            "%s (%s)" % (i["name"], i["kind"]) for i in intel["impersonation"]))
    if intel.get("channels"):
        lines.append("Channel:     " + ", ".join(intel["channels"]))
    if intel.get("tactics"):
        lines.append("Tactics:     " + "; ".join(
            t["label"] for t in intel["tactics"]))

    if intel.get("next_moves"):
        lines += ["", "Likely next moves:"]
        lines += ["  • " + item for item in intel["next_moves"]]

    if intel.get("verify"):
        lines += ["", "Verify independently:"]
        lines += ["  • " + item for item in intel["verify"]]

    if intel.get("safe_replies"):
        lines += ["", "Safe reply" + (
            " (best is no reply; if you must):" if intel.get("reply_policy") == "do_not_reply"
            else ":")]
        lines += ["  • " + item for item in intel["safe_replies"]]

    if intel.get("evidence"):
        lines += ["", "Preserve evidence:"]
        lines += ["  • " + item for item in intel["evidence"]]

    obf = intel.get("obfuscation") or {}
    if obf.get("detected"):
        labels = ", ".join(s["label"] for s in obf.get("signals") or [])
        lines += ["", "⚠ Disguised text: " + labels +
                  ". Treat the evasion itself as a red flag."]

    return "\n".join(lines)
