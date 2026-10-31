"""Rule-based scam heuristics for text messages.

Zero dependencies. Scores a message 0-100 across weighted risk signals
and returns the individual reasons so results are explainable.
"""

import ipaddress
import re
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Signal definitions: (regex, weight, label)
# Weights are rough severity scores; the analyzer clamps the total to 0-100.
# --------------------------------------------------------------------------

SIGNALS = [
    # -- OTP / account-takeover phishing -----------------------------------
    (r"\b(otp|one[- ]?time (code|password|pin)|verification code|security code)\b",
     18, "Asks about OTP / verification codes"),
    (r"\b(do (not|n't) share (this|the|your) (code|otp|pin)\b|never share your (otp|pin|code))",
     22, "Classic 'do not share this code' phishing phrase"),
    (r"\b(cvv|cvc|card security (code|number)|back of (your|the) card)\b",
     20, "Requests card CVV / security code (no legitimate text does this)"),
    (r"\b(reply|respond|text|send|share|provide|confirm|enter)\b.{0,40}(your\s+)?((debit|credit)\s*)?card\s*(number|digits?|details?)|.{0,10}(account\s*(number|details?)|bank\s*(details?|credentials|password))\b",
     18, "Asks you to reply with card/account details"),
    (r"\byour (code|otp|pin) is[: ]?\s*\d{4,8}\b",
     20, "Delivers an unsolicited login code"),

    # -- Impersonating financial institutions / services --------------------
    (r"\b(bank|net\s?banking|mobile\s?banking|debit|credit)\s+(account|card)\b.{0,40}\b(block|suspend|freeze|limited|deactivate|escalat)",
     20, "Claims a bank account/card will be blocked"),
    (r"\b(unauthori[sz]ed|suspicious|fraudulent) (transaction|activity|login|payment|withdrawal)\b",
     18, "Claims unauthorized account activity"),
    (r"\b(verify|confirm|update|validate|reactivate|restore)\s+(your\s+)?(account|details|information|identity|kyc|credentials)\b",
     15, "Urges you to verify/update account details"),
    (r"\bkyc\b|\b(e-?kyc|re-?kyc)\b",
     12, "KYC urgency trick (common bank-scam opener)"),
    (r"\b(account|card|wallet)\s+(will\s+be\s+|has\s+been\s+|is\s+(temporarily\s+|recently\s+|now\s+)?|was\s+(temporarily\s+|recently\s+)?|got\s+)?(suspended|blocked|frozen|deactivated|closed)\b",
     18, "Threatens account suspension"),

    # -- Money, prizes, refunds, taxes --------------------------------------
    (r"\b(you(')?ve?\s+(won|won't?|have won)|winner|congratulations.{0,30}(win|prize|selected|lucky)|lucky draw|lottery|jackpot|prize)\b",
     18, "Lottery / prize notifications"),
    (r"\b(claim|collect)\s+(your|the)\s+(prize|reward|money|refund|cashback|bonus|gift)\b",
     16, "Asks you to claim a prize/refund"),
    (r"\bgift\s?card(s)?\b", 14, "Mentions gift cards (common payment scam)"),
    (r"\bfee\b.{0,40}\bgift\s?card\b|\bgift\s?card\b.{0,40}\bfee\b",
     18, "Asks you to pay a fee with a gift card (near-certain scam)"),
    (r"\b(income\s?tax|tax\s?refund|gst\s?refund|irs|inland revenue)\b.{0,50}(refund|due|pending|credit)",
     14, "Fake tax refund / tax due scam"),
    (r"\bcashback\b|\b(won|get)\s+\$?\s?\d[\d,]*\b.{0,20}(cash|reward|bonus)",
     8, "Unexpected money offers"),

    # -- Payment / transfer pressure ----------------------------------------
    (r"\b(send|transfer|deposit)\s+(money|funds|\$?\d[\d,]*|rs\.?\s?\d|inr)\b.{0,40}(now|immediately|today|urgently|asap|quickly)\b",
     20, "Hurried money-transfer request"),
    (r"\b(wire\s?transfer|western\s?union|money\s?gram|zelle|venmo|cash\s?app|upi|NEFT|IMPS)\b",
     10, "Names instant/irreversible payment methods"),
    (r"\b(bitcoin|btc|usdt|ethereum|eth|crypto)\b", 12, "Mentions cryptocurrency"),
    (r"\b(?:send|transfer|deposit|pay)\b[^.]{0,50}\b(?:btc|bitcoin|usdt|ethereum|eth|trx|crypto|wallet\s+address)\b",
     12, "Asks for a crypto/wallet payment"),
    (r"\bprocessing\s+(fee|charge)|registration\s+(fee|charge)\b.{0,30}(pay|send|deposit|transfer)",
     16, "Asks for a 'small fee' to release money"),

    # -- Delivery / courier scams -------------------------------------------
    (r"\b(parcel|package|shipment|delivery|courier)\b.{0,50}\b(held|hold|stuck|customs|pending fee|failed|address|reschedule)\b",
     14, "Fake courier/delivery problem"),
    (r"\b(fedex|ups|usps|dhl|bluedart|delhivery)\b.{0,40}\b(redeliver|customs|fee|charge|track)\b",
     14, "Impersonates a courier company"),

    # -- Jobs, investments, romance -----------------------------------------
    (r"\b(part[- ]?time job|work from home|earn\s+(money|\$?\d)|daily payout|money making|typing job|data entry)\b",
     12, "Too-good job/work-from-home offer"),
    (r"\b(guaranteed|assured)\s+(return|profit|income|roi)\b|\bfixed\s+return\b",
     14, "Guaranteed-return investment pitch"),
    (r"\b(invest|trading)\b.{0,40}(double|multiply|profit|signals|forex|binary)\b",
     10, "Investment/trading scam pattern"),
    (r"\bi (like|love) (your|ur) (profile|smile|pic)\b|\bdear (friend|beloved|darling)\b",
     8, "Romance-scam opener"),

    # -- Threats, urgency, legal fear ---------------------------------------
    (r"\b(within\s+)?(24|48|12)\s?(hours|hrs|h)\b|\bact\s+now\b|\bimmediately\b|\burgent(ly)?\b",
     8, "Manufactured urgency"),
    (r"\b(final\s+(warning|notice)|last\s+warning)\b|\bexpire[sd]?\b.{0,20}(today|now|soon)",
     10, "Final-warning pressure tactic"),
    (r"\b(police|cops?|arrest|arrested|warrant|lawsuit|legal action|court)\b.{0,60}(you|your (name|number|account|ssn|aadhaar))",
     14, "Threatens police/legal action"),
    (r"\b(ssn|social security|aadhaar|aadhar|pan\s?card|passport)\b.{0,50}(suspend|block|invalid|expired|fraud|verify)",
     16, " Targets national ID / SSN details"),

    # -- Link / contact manipulation ----------------------------------------
    (r"\b(click|tap)\s+(on\s+)?(this|the|here|below|link)\b",
     8, "Tells you to click a link"),
    (r"\b(re[- ]?register|re[- ]?verify)\b|\blink (below|in profile|in bio)\b",
     6, "Suspicious link phrasing"),
    (r"\bcall (this|the) (number|us)\b|\b(((\+|00)\d{1,3})[- ])?(\d[- ]?){8,}\b",
     5, "Prominent phone number to call"),

    # -- Tech-support and device scams --------------------------------------
    (r"\b(virus|malware|infected|hacked|breach(ed)?|compromised)\b.{0,60}(device|phone|computer|laptop|account|network)\b",
     14, "Claims your device/account is compromised"),
    (r"\b(install|download)\s+(any\s+)?(remote|screen\s?(share|access)|teamviewer|anydesk|quick\s?support)\b",
     18, "Asks to install remote-access software"),
    (r"\b(sim\s?card|number)\b.{0,30}(blocked|deactivated|blacklisted|ported)\b",
     12, "SIM-deactivation scare"),

    # -- Gambling / spam engagement -----------------------------------------
    (r"\b(bet|casino|aviator|colour(s)? prediction|slote?|rummy|satta|teen\s?patti)\b.{0,30}(win|earn|platform|app|link)",
     10, "Gambling / color-prediction spam"),
    (r"\b(reply|text|whatsapp|telegram|dm)\s+(yes|hi|hello|'?'|me|us)\b",
     6, "Bait to reply / move the chat"),
    (r"\b(add|message) (me|us) (on )?whatsapp\b|\bw\.me\b|\bt\.me\b",
     8, "Pushes conversation to WhatsApp/Telegram"),

    # -- BEC / invoice fraud ------------------------------------------------
    (r"\b(invoice|remittance|purchase order|beneficiary|wire transfer)\b"
     r"[\s\S]{0,100}\b(bank|account|iban|swift|routing)\b[\s\S]{0,60}"
     r"\b(changed|updated|new|revised|corrected)\b|"
     r"\b(bank|account|iban|swift|routing|beneficiary)\b[\s\S]{0,60}"
     r"\b(changed|updated|new|revised|corrected)\b[\s\S]{0,100}"
     r"\b(invoice|remittance|purchase order|wire transfer)\b",
     16, "Invoice/remittance email with changed bank details (BEC)"),

    # -- Sextortion ---------------------------------------------------------
    (r"\b(webcam|camera|intimate|explicit|compromising)\b[^.]{0,60}"
     r"\b(video|footage|photos?|recording|recorded)\b",
     14, "Claims to hold compromising webcam/intimate material"),
    (r"\b(leak|publish|post|send|share)\b[^.]{0,40}"
     r"\b(video|photos?|footage)\b[^.]{0,60}"
     r"\b(family|friends|contacts|everyone|social media|colleagues)\b",
     16, "Threatens to leak private material to your contacts"),

    # -- Toll / fine smishing ----------------------------------------------
    (r"\b(unpaid|overdue|outstanding)\b[^.]{0,40}\b(toll|fine|violation|"
     r"challan|parking|fastag)\b|\b(toll|fine|violation|challan|parking|"
     r"fastag)\b[^.]{0,40}\b(unpaid|overdue|outstanding)\b",
     14, "Unpaid toll/fine notice (smishing bait)"),

    # -- Rental deposit ------------------------------------------------------
    (r"\b(deposit|booking (amount|fee)|token money|advance)\b[\s\S]{0,60}"
     r"\b(before|without)\b[\s\S]{0,30}\b(viewing|visit|seeing)\b|"
     r"\b(owner|landlord)\b[\s\S]{0,60}\b(abroad|overseas|out of (the )?country|"
     r"dubai|sharjah|abu\s?dhabi|qatar|riyadh|saudi|muscat|kuwait|bahrain|"
     r"london|canada|usa|uk|america|singapore|malaysia|gulf)\b",
     16, "Rental 'pay before viewing' / absent-owner excuse"),

    # -- Family new-number imposter -----------------------------------------
    (r"\b(this is (my|your) (new|other) (number|phone)|my new number|"
     r"changed my number)\b[\s\S]{0,120}\b(send|transfer|pay|need|require)\b"
     r"[\s\S]{0,40}(\$|£|₹|rs\.?|rupees|money|cash|\d{3,})|"
     r"\b(send|transfer|pay|need|require)\b[\s\S]{0,40}(\$|£|₹|rs\.?|rupees|"
     r"money|cash|\d{3,})[\s\S]{0,120}\b(this is my new number|my new number)\b",
     16, "New-number message combined with a money request (family imposter)"),

    # -- APK / fake bank app -------------------------------------------------
    (r"\b(apk|install|download|update)\b[^.]{0,50}\b(app|apk|application)\b"
     r"[^.]{0,80}(https?://|www\.|\.apk|bit\.ly|t\.me/)|\bapk\b[^.]{0,60}"
     r"(https?://|\.apk|link)",
     16, "Pushes an app/APK install from a link (bank-app imposter)"),
]

# Deep-link / protocol-handler forensics (QR-decoded content also lands here).
DEEP_LINKS = [
    (r"\btg:?//login", 25, "Telegram login deep link — grants account takeover to whoever sends it"),
    (r"\btg:?//resolve|t\.me/joinchat|chat id add\b", 10, "Telegram resolve/join manipulation"),
    (r"\b(wa\.me|whatsapp://send)", 8, "WhatsApp direct-message launch link"),
    (r"\bbtc:|ethereum:|bitcoin:1|0x[a-fA-F0-9]{,4}\b.{0,10}(address|wallet)",
     18, "Crypto wallet payment deep link"),
    (r"\bmailto:.{0,80}\?body=", 8, "Mailto deep link smuggling content through your mail app"),
    (r"\bsms:\+?\d", 10, "SMS deep link that pre-fills a message to a number"),
    (r"\.apk\b|apk download|direct (download|apk) link", 20,
     "Direct APK download (bypasses app-store safety checks)"),
    (r"[?&](redirect|url|next|goto|dest(ination)?)=h?t?t?p", 18,
     "Open-redirect style URL hiding the true destination"),
    (r"\b(whatsapp|watsapp|why not upgrade|account (upgrade|verify) (needed|required|to release))",
     12, "Payment-app 'account upgrade' marketplace scam phrasing"),
]
DEEP_LINK_RES = [(re.compile(p, re.I), w, l) for p, w, l in DEEP_LINKS]

SIGNAL_RES = [
    (re.compile(pat, re.IGNORECASE), weight, label) for pat, weight, label in SIGNALS
]

# --- Hindi / Hinglish / India-specific signals ------------------------------
# India is the single biggest scam-victim market (I4C/CERT-In data in the
# research dossier). Most scam SMS reach Hindi speakers in *Hinglish* -- Roman
# script Hindi ("aapka account band ho jayega") -- with Devanagari bait for
# the same schemes. Labels note the language for user-facing reports.
HINDI_SIGNALS = [
    # NOTE: Python's \\b treats Devanagari matras (combining marks) as
    # non-word characters, so \\b is unreliable inside Devanagari. Those
    # patterns use explicit lookarounds (?<![ऀ-ॿ]) instead, and simple
    # alternations instead of bracket classes.

    # -- KYC / bank account closure (domestic India scam SMS king) -----------
    (r"\bkyc\b.{0,80}\b(expire|expired|pending|complete|update|suspend|band|re[- ]?verify|aavshyak)",
     14, "Hinglish KYC-urgency bait (KYC expire / account band)"),
    (r"\b(?:aapka|aapke|apka|apke)\s+(?:(?:bank|sbi|hdfc|icici|axis|kotak|"
     r"pnb|paytm|phonepe|google\s*pay|yes\s*bank)\s+)?(?:account|khata|khaata|card)\b"
     r".{0,60}\b(?:band|block|suspend|seized?|rok)\b",
     16, "Hinglish account-closure threat (aapka account band ho jayega)"),
    (r"(?<![ऀ-ॿ])आपक(?:ा|े)\s+(?:बैंक\s+)?(?:खाता|खाते|कार्ड).{0,70}(?:बंद|ब्लॉक|शील|निलंबित|अवरुद्ध|रोक)",
     16, "Hindi bank account closure threat (aapka khata band)"),
    (r"(?<![ऀ-ॿ])(?:खाता|खाते|कार्ड)\s+(?:बंद|ब्लॉक|शील|निलंबित|अवरुद्ध|रोक)",
     14, "Hindi closure scare wording (khata band)"),
    (r"(?<![ऀ-ॿ])(?:केवाईसी|केवायसी).{0,70}(?:समाप्त|अपडेट|पूर्ण|आवश्यक|अनिवार्य)",
     14, "KYC urgency trick (केवाईसी समाप्त)"),
    (r"\b(band\s+kar\s+diya\s+jaa|block\s+kar\s+diya\s+jaa|band\s+ho\s+jayega)",
     12, "Hinglish 'band kar diya jayega' scare phrase"),

    # -- OTP / credentials in Hinglish ----------------------------------------
    (r"\b(otp|pin|password)\b.{0,50}\b(kisi\s+ko\s+na|kisi\s+ko\s+mat|kisi\s+ko\s+share|mat\s+bata|batayein\s+mat|share\s+na\s+kare)",
     14, "Hinglish OTP-sharing phishing phrase (kisi ko na bataye)"),

    # -- Task / daily-income job scams Hinglish --------------------------------
    (r"\b(rozana\s+(kamai|earning|paise)|roz\s+kamai|daily\s+income\b|paise\s+kama(ne|o))",
     12, "Hinglish daily-income task bait (rozana kamai)"),
    (r"\b(part[- ]?time|part\s+time)\s+(job|kaam|naukri)\b",
     12, "Hinglish part-time job offer"),

    # -- Digital arrest / law-enforcement in Hinglish-Hindi --------------------
    (r"\bdigital\s+arrest\b",
     20, "Claims 'digital arrest' — CERT-In flags this scheme as always-scam"),
    (r"(?<![ऀ-ॿ])डिजिटल\s+गिरफ्तारी",
     20, "'Digital arrest' phrased in Hindi"),
    (r"\b(cyber\s+)?(police|cbi|narcotics|crime\s+branch)\b.{0,110}\b(khilaf|giriftari|parichay\s?patra)\b",
     16, "Hinglish legal-threat against you (aapke khilaf case)"),
    (r"(?<![ऀ-ॿ])((?:साइबर\s+)?पुलिस|सीबीआई|नारकोटिक्स|कस्टम्स).{0,70}(?:गिरफ्तार|सं?क?े?स|कार्रवाई|लॉन्ड्रिंग|नशा|नशे|पार्सल)",
     14, "Hindi police/CBI menace phrasing"),
    (r"\b(skype|video\s+call)\b.{0,50}\b(verification|pareeksha|jaanch)\b",
     12, "Hinglish video-call 'verification' isolation tactic"),
    (r"\b(video\s+call|skype)\b.{0,40}\b(baat\s+karein|pe\s+aa|par\s+connect|pe\s+connect)\b",
     10, "Hinglish push to move to a video call (digital-arrest channel)"),

    # -- Money-transfer demands ------------------------------------------------
    (r"\b(paisa|paise|rupaye)\b.{0,45}\b(bhej|transfer|deposit|recharge|bhar|double)",
     14, "Hinglish money-transfer demand (paise bhejo)"),
    (r"(?<![ऀ-ॿ])(?:पैसा|पैसे|रुपये).{0,45}(?:भेज|जमा|ट्रांसफर|रिचार्ज|डिपोजिट)",
     14, "Hindi money-transfer demand (paise bhejen)"),
    (r"\b(upi\s+id\s+(bhej|do)|\d{3,6}\s+rs\s+bhej)\b",
     12, "Hinglish UPI-transfer instruction"),

    # -- Prize / lucky draw Hinglish-Hindi --------------------------------------
    (r"\b(aap\s+)?(jeet\s+gaye|jackpot|lucky\s+draw|mubarak)\b",
     12, "Hinglish lottery/prize phrasing (aap jeet gaye)"),
    (r"(?<![ऀ-ॿ])(?:लॉटरी|पुरस्कार|इनाम|जैकपॉट|जीत\s?गए)",
     12, "Hindi lottery/prize phrasing"),
    (r"\b(muft|free)\s+recharge\b|\b(?:मुफ़्त|मुफ्त)\s+रिचार्ज\b",
     8, "Free-recharge bait (Hinglish/Hindi)"),

    # -- Telecom / SIM / policy nags Hinglish -----------------------------------
    (r"\bsim\s+(card|ka)\b.{0,40}\b(band|block|deactiv)",
     12, "Hinglish SIM-suspension scare"),
    (r"\b(aapki?\s+)?(policy|bima)\b.{0,50}\b(band|renew|expire|expiry|lapse)",
     8, "Hinglish policy-lapse urgency"),

    # -- Investment bait Hinglish ------------------------------------------------
    (r"\b(paisa\s+double|guaranteed\s+kamai|paisa\s+invest)",
     12, "Hinglish double-money / guaranteed-earnings bait"),
]

HINDI_RES = [(re.compile(p, re.I), w, l) for p, w, l in HINDI_SIGNALS]

# --- URL / domain heuristics ----------------------------------------------

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "goo.gl", "ow.ly",
    "shorturl.at", "rb.gy", "rebrand.ly", "tiny.cc", "bit.do", "shorte.st",
    "adf.ly", "bl.link", "s.id", "lnkd.in", "v.gd",
}

RISKY_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "ru", "su", "click", "link",
    "work", "loan", "win", "bid", "download", "stream", "racing", "cam",
    "monster", "quest", "cyou", "buzz", "icu", "rest", "surf",
}

# well-known brand names to catch lookalike domains e.g. paypa1.com, amaz0n-help.xyz
BRANDS = {
    "paypal": ["paypal"],
    "amazon": ["amazon"],
    "apple": ["apple", "icloud"],
    "google": ["google", "gmail"],
    "microsoft": ["microsoft", "outlook", "office365", "onedrive"],
    "netflix": ["netflix"],
    "facebook": ["facebook", "fb", "instagram", "whatsapp"],
    "linkedin": ["linkedin"],
    "hsbc": ["hsbc"],
    "sbi": ["sbi", "statebank"],
    "hdfc": ["hdfc"],
    "icici": ["icici"],
    "axis": ["axisbank"],
    "chase": ["chase"],
    "wellsfargo": ["wellsfargo", "wells-fargo"],
    "usps": ["usps"],
    "fedex": ["fedex"],
    "dhl": ["dhl"],
}

# cheap de-obfuscation for lookalike domains (0=o 1=l 3=e 4=a 5=s 6=g 7=t 8=b)
LEET = str.maketrans("01345678@$", "oleasgtbas")

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s\"'<>\)\]]+"
    r"|\b[\w-]+(?:\.[\w-]+)+/(?:\S*)?"
    r"|\b[\w-]+(?:\.[\w-]+)+\.(?:"
    + "|".join(sorted(RISKY_TLDS))
    + r")\b",
    re.IGNORECASE,
)


def extract_urls(text: str):
    host_hits = []
    for m in URL_RE.finditer(text):
        raw = m.group(0).rstrip(".,;:!?)")
        if not raw.startswith("http"):
            raw = "http://" + raw.lstrip("/")
        try:
            parsed = urlparse(raw)
        except ValueError:
            continue
        host = (parsed.hostname or "").lower().strip(".")
        if not host or "." not in host and host not in {"localhost"}:
            continue
        host_hits.append(host)
    return host_hits


SCAMMY_WORDS = re.compile(
    r"secure|login|log[- ]?in|verify|update|confirm|support|help|care|service"
    r"|account|refund|notice|alert|recover|unlock|signin|wallet|billing",
    re.IGNORECASE,
)


def is_official_brand_domain(bare: str):
    """Return brand name if bare hosts exactly an official domain (e.g. paypal.com)."""
    for brand, variants in BRANDS.items():
        official = set(brand_domain(brand).split("."))
        for variant in variants:
            # exact 2-label match, e.g. "paypal.com" or "apple.com"
            labels = bare.split(".")
            core = ".".join(labels[-3:])
            if bare == brand_domain(brand) or core == brand_domain(brand):
                return brand
            # official subdomain like mail.google.com
            if len(labels) >= 3 and ".".join(labels[-2:]) == brand_domain(brand) and variant in ".".join(labels[:-2]):
                return brand
    return None


def analyze_urls(text: str):
    reasons, risk = [], 0
    seen_hosts = set()
    for host in extract_urls(text):
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        bare = host[4:] if host.startswith("www.") else host
        labels = bare.split(".")

        if bare in SHORTENERS:
            reasons.append(("Shortened URL hides the real destination: " + bare, 25))
            risk += 25
            continue

        # IP-literal URLs have no legitimate consumer use in SMS
        try:
            ipaddress.ip_address(bare)
            reasons.append(("Raw IP-address link instead of a domain (" + bare + ")", 25))
            risk += 25
            continue
        except ValueError:
            pass

        # punycode / homoglyph domains
        if any(part.startswith("xn--") for part in labels):
            reasons.append(("Punycode (homoglyph) domain: " + bare, 22))
            risk += 22

        tld = labels[-1]
        if tld in RISKY_TLDS:
            reasons.append(("Risky domain suffix ." + tld + " (" + bare + ")", 18))
            risk += 18

        # lookalike brand domains: paypa1.com, secure-apple-login.xyz ...
        official = is_official_brand_domain(bare)
        translit = bare.translate(LEET)  # raise paypa1 -> paypal, etc.
        flagged = False
        if not official:
            for brand, variants in BRANDS.items():
                for v in variants:
                    core = translit.replace("-", "").replace("www", "", 1)
                    if v in core and SCAMMY_WORDS.search(translit):
                        reasons.append(
                            ("Lookalike brand domain: %s (looks like %s)" % (bare, brand), 28)
                        )
                        risk += 28
                        flagged = True
                        break
                    # brand inserted as a fake subdomain of another site,
                    # e.g. paypal.com.untrustedsite.ru
                    if official is None and "." + v + "." in "." + translit:
                        after = translit.split(v, 1)[1].lstrip(".-")
                        if after and SCAMMY_WORDS.search(translit) is None:
                            reasons.append(
                                ("Brand name buried in a foreign domain: %s (brand: %s)" % (bare, brand), 20)
                            )
                            risk += 20
                            flagged = True
                            break
                if flagged:
                    break

    # dedupe, merge
    seen, merged = set(), []
    for r in reasons:
        if r[0] not in seen:
            seen.add(r[0])
            merged.append(r)
    return merged, min(risk, 45)


def brand_domain(brand: str) -> str:
    known = {
        "paypal": "paypal.com", "amazon": "amazon.com", "apple": "apple.com",
        "google": "google.com", "microsoft": "microsoft.com",
        "netflix": "netflix.com", "facebook": "facebook.com",
        "linkedin": "linkedin.com", "hsbc": "hsbc.com", "sbi": "sbi.co.in",
        "hdfc": "hdfcbank.com", "icici": "icicibank.com", "axis": "axisbank.com",
        "chase": "chase.com", "wellsfargo": "wellsfargo.com",
        "usps": "usps.com", "fedex": "fedex.com", "dhl": "dhl.com",
    }
    return known.get(brand, brand + ".com")


# --- Stylistic signals ------------------------------------------------------

def analyze_style(text: str):
    reasons, risk = [], 0
    letters = [c for c in text if c.isalpha()]
    if letters:
        upper_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
        if len(text) > 25 and upper_ratio > 0.55:
            reasons.append(("Text is shouted in ALL CAPS (%d%%)" % int(upper_ratio * 100), 6))
            risk += 6
    if text.count("!") >= 3:
        reasons.append(("Excessive exclamation marks (!!!)", 4))
        risk += 4
    words = re.findall(r"[A-Za-z']+", text)
    if len(words) >= 15 and sum(len(w) for w in words) / len(words) < 3.2:
        reasons.append(("Unusually broken/typed-by-spellchecker wording", 4))
        risk += 4
    if re.search(r"[\u0980-\u09FF\u0900-\u097F]", text) and re.search(r"\b(kyc|otp|bank|refund)\b", text, re.I):
        reasons.append(("Mixed-script bait message", 6))
        risk += 6
    return reasons, risk


# Words worth fuzzy-repairing in OCR noise (concept vocabulary the signal
# patterns care about). Bounded list -- the repair runs ONLY on the OCR
# variant, never on raw user text.
_OCR_VOCAB = (
    "account", "bank", "banking", "blocked", "suspended", "frozen", "verify",
    "urgent", "unauthorized", "transaction", "activity", "alert", "code",
    "password", "otp", "share", "confirm", "update", "winner", "prize",
    "lottery", "parcel", "delivery", "courier", "fee", "gift", "refund",
    "kyc", "police", "arrest", "warrant", "bitcoin", "crypto", "investment",
    "trading", "profit", "suspended", "deactivated", "limited", "invoice",
    "payment", "transfer", "immediately", "warning", "expired", "claim",
)


def normalize_ocr_text(text: str) -> str:
    """Undo common glyph confusions from OCR (0/o, 1/i, 5/s, etc.).

    Used as a secondary matching variant so noisy screenshot text like
    "ACCOUHT 5U5PEMD3D" can still trip the original signal patterns.
    Applied only as a half-weight variant -- real money symbols and
    genuine digits matter, so this is a lenient extra pass, not a rewrite.
    """
    t = text.translate(str.maketrans("01345@8$", "oieasabs"))
    from difflib import get_close_matches

    def repair(w):
        lw = w.lower()
        if len(lw) < 4:
            return w
        m = get_close_matches(lw, _OCR_VOCAB, n=1, cutoff=0.75)
        return m[0] if m and lw != m[0] else w

    return re.sub(r"[A-Za-z0-9']+", lambda m: repair(m.group(0)), t)


def run_rules(text: str, ocr_text=None, extra_text=None):
    """Return {'score', 'verdict', 'reasons': [(label, weight)]} from heuristics.

    ocr_text: optional OCR-normalized variant of the same text; signals that
    match ONLY there get half weight (deduped, best weight wins per label).

    extra_text: optional deobfuscated variant (zero-width/homoglyph/spacing
    repair). Signals found only there get 0.85 weight, so filter evasion is
    seen without letting a lossy transform invent evidence.
    """
    # First-person "my account was blocked" is usually someone *narrating
    # their own* minor trouble (a family text), not an impersonation scare -
    # halve the weight for the scare patterns the narration would trip.
    weaken = {}
    if re.search(r"\b(my|our)\s+(bank\s+|net\s+|card\s+)?(account|card|wallet)\b", text, re.I):
        weaken = {
            "Claims a bank account/card will be blocked",
            "Claims unauthorized account activity",
            "Threatens account suspension",
        }

    reasons = []
    risk = [0]
    variants = [(text, 1.0)]
    if ocr_text and ocr_text.strip() and ocr_text != text:
        variants.append((ocr_text, 0.5))
    if extra_text and extra_text.strip() and extra_text != text:
        variants.append((extra_text, 0.85))
    seen = {}

    def scan(regex_list):
        for regex, weight, label in regex_list:
            if label in weaken:
                weight = weight * 0.4
            best = 0
            for variant, mult in variants:
                try:
                    if regex.search(variant):
                        best = max(best, weight * mult)
                except TypeError:
                    pass
            if best:
                if label in seen:
                    idx, cur = seen[label]
                    if best > cur:
                        risk[0] += best - cur
                        reasons[idx] = (label, best)
                        seen[label] = (idx, best)
                else:
                    reasons.append((label, best))
                    seen[label] = (len(reasons) - 1, best)
                    risk[0] += best

    scan(SIGNAL_RES)
    scan(DEEP_LINK_RES)
    scan(HINDI_RES)
    risk = risk[0]

    url_reasons, url_risk = analyze_urls(text)
    if extra_text and extra_text.strip() and extra_text != text:
        # A disguised URL ("hxxp://bank[.]example") only becomes analysable
        # after deobfuscation. Dedupe by label so the same domain is not
        # counted twice.
        extra_url_reasons, extra_url_risk = analyze_urls(extra_text)
        known = {label for label, _ in url_reasons}
        for label, weight in extra_url_reasons:
            if label not in known:
                url_reasons.append((label, weight * 0.85))
                url_risk += weight * 0.85
    reasons.extend(url_reasons)
    risk += url_risk

    style_reasons, style_risk = analyze_style(text)
    reasons.extend(style_reasons)
    risk += style_risk

    score = int(max(0, min(risk, 100)))

    if score >= 60:
        verdict = "SCAM"
    elif score >= 35:
        verdict = "LIKELY SCAM"
    elif score >= 15:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY SAFE"

    reasons.sort(key=lambda r: -r[1])
    return {"score": score, "verdict": verdict, "reasons": reasons}
