"""Script fingerprints: detect full scam playbooks, not just signals.

Each script is scored by how many of its mandatory beats appear in the text.
Match ALL mandatory markers -> verdict locked to SCAM with the script named.
"""

import re

C = re.compile


class Script:
    def __init__(self, name, description, mandatory, optional=()):
        self.name = name
        self.description = description
        self.mandatory = [(C(p, re.I), label) for p, label in mandatory]
        self.optional = [(C(p, re.I), label) for p, label in optional]

    def match(self, text):
        """Return (mand_hits, opt_hits, labels) for this script."""
        mand, opt, labels = 0, 0, []
        for rx, label in self.mandatory:
            if rx.search(text):
                mand += 1
                labels.append(label)
        for rx, label in self.optional:
            if rx.search(text):
                opt += 1
                labels.append(label)
        return mand, opt, labels


# --- The playbooks from the research (docs/scam-research-dossier.md S4) ----

SCRIPTS = [
    Script(
        "PIG BUTCHERING / CRYPTO ROMANCE-INVESTMENT",
        "Romance-then-investment long con: fake trading platform, wager "
        "deposits, withdrawal blocked by fake fees/taxes.",
        [
            (r"\bromance\b|\blove\b|pyar|meri jaan|relationship|dear\b|dating",
             "romantic/trust element"),
            (r"\b(invest|investment|trading|crypto|bitcoin|usdt|"
             r"forex|binary|wallet|kamai|paisa double)",
             "investment/crypto platform"),
        ],
        [
            (r"(withdraw|withdrawal|release|unlock|tax|fee|commission|"
             r"insurance|credit score|margin|level)",
             "withdrawal-block / fees escalation"),
            (r"(guaranteed|fixed| assured) return|double|profit|roi",
             "guaranteed returns"),
            (r"(profit|earn|income|rich|wealth)",
             "wealth pitch"),
            (r"(screenshot|recharge|deposit|transfer)",
             "payment instructions"),
        ],
    ),
    Script(
        "TASK SCAM (FAKE PART-TIME JOB)",
        "Like/rate hotels or boost Amazon traffic for pay, via "
        "WhatsApp/Telegram, real small payouts, then deposit-based tasks.",
        [
            (r"(task|tasks|part[- ]time|job|work|earn|salary|commission|"
             r"naukri|part\s+time\s+kaam|rozana\s+kamai)",
             "job/offer"),
            (r"(telegram|whatsapp|signal|wechat)",
             "recruitment app"),
        ],
        [
            (r"(prepaid task|deposit|prepay|investment plan|vip (level|"
             r"group)|recharge|paise\s+(bhar|recharge)\w*\s+?k?aro?)",
             "pay-to-work escalation"),
            (r"(rating|review|like|spotify|amazon|boost|data entry|"
             r"hotel\s+rating|task\s+complete)",
             "simple task bait"),
            (r"(withdraw|withdrawal|unfree?ze|release|paisa\s+atka)",
             "withdrawal pressure"),
            (r"(teacher|mentor|receptionist|agent|admin|gems\s+guide|coordinator)",
             "scam-org roles"),
        ],
    ),
    Script(
        "DIGITAL ARREST / LAW-ENFORCEMENT EXTORTION",
        "Courier parcel with drugs/passport, then fake police/CBI/customs "
        "on video; 'you are under digital arrest', isolation, transfers.",
        [
            (r"(police|cbi|narcotics|customs|enforcement|rbi|ed "
             r"director|investigation|court|warrant|arrest|digital arrest|"
             r"cyber\s*cell|aapke\s+khilaf)",
             "law-enforcement pretense"),
            (r"(arrest|detain|charge|case|crime|evidence|warrant|"
             r"aapke\s*khilaf\s*case|giriftari|karyavahi)",
             "legal threat"),
        ],
        [
            (r"(parcel|package|courier|dhl|fedex|sim card|passport|paarsal|parisal)",
             "parcel/SIM pretext"),
            (r"(drugs|contraband|money laundering|terror|fraudulent|"
             r"banned|illegal item|nasha)",
             "contraband story"),
            (r"(skype|video call|whatsapp call|do not tell|don'?t tell|"
             r"confidential|kisi\s*ko\s*(nahi|mat)\s*batana|batana\s*mat)",
             "isolation/continuity"),
            (r"(surety|deposit|verify|clearance|bail|jamanat|settle|transfer|"
             r"paisa?\s*bhej|jurmana)",
             "money demand"),
            (r"(skype|whatsapp|video call)",
             "video-call channel"),
        ],
    ),
    Script(
        "TECH-SUPPORT REMOTE-ACCESS",
        "'Device is infected', installs AnyDesk/TeamViewer/UltraViewer, "
        "bank tech moves money to 'safe' wallets.",
        [
            (r"(virus|malware|hacked|infected|support|technician|"
             r"technical|IT (team|support)|phone\s*(hack|virus|kharab))",
             "device problem claim"),
            (r"(anydesk|teamviewer|ultraviewer|remote|quicksupport|"
             r"screen share|screen sharing|control)",
             "remote-control ask"),
        ],
        [
            (r"(microsoft|apple|geek squad|norton|bank (security)? team)",
             "brand impersonation"),
            (r"(refund|reversal|safe (wallet|account)|transfer funds|"
             r"protect funds|paisa\s*surakshit)",
             "money movement trick"),
        ],
    ),
    Script(
        "GRANDPARENT / VOICE-CLONE FAMILY SCAM",
        "Cloned (or breathless) voice of a loved one: accident/jail, needs "
        "bail/lawyer money immediately, secrecy from family.",
        [
            (r"(bail|jail|hospital|accident|kidnapp|emergency|jamanat|hadsa)",
             "family emergency story"),
            (r"(don'?t tell|do not tell|mom|dad|parent|grandma|relative|"
             r"confidential|alone|kisi\s*ko\s*(nahi|mat)\s*batana|ghar\s*walon\s*ko\s*)",
             "secrecy / family link"),
        ],
        [
            (r"(wire|transfer|courier|deliver|money (now|quickly)|cash)",
             "fast money request"),
            (r"(voice|call|phone|sounding|background)",
             "voice/call medium"),
            (r"(lawyer|police|bondsman|notary)",
             "fake authority chain"),
        ],
    ),
    Script(
        "COURIER / GOLD-CASH HANDOFF",
        "Fake courier/regulator: victim hands cash, gold, or documents to a "
        "courier personally for 'RBI pre-verification' etc.",
        [
            (r"(courier|parcel|package|shipment|gold|cash|documents)",
             "courier/gold/cash element"),
            (r"(deliver|hand over|collect|pick ?up|dispatch|doorstep)",
             "physical handoff"),
        ],
        [
            (r"(rbi|reserve bank|customs|verification (fee|charge)|"
             r"security (fee|deposit)|clearance)",
             "fake authority fee"),
            (r"(7 days|seven days|45 minutes|now|today)",
             " hurried timeline"),
        ],
    ),
    Script(
        "INVOICE / BEC PAYMENT DIVERSION",
        "Business email compromise: vendor 'changes' bank details and asks "
        "for an urgent wire, often blocking verification calls.",
        [
            (r"\b(invoice|remittance|purchase order|payment (details|"
             r"instructions)|wire (transfer|funds)?|swift|iban|ach|"
             r"bank transfer|beneficiary)\b",
             "invoice/payment context"),
            (r"\b(bank|account|iban|swift|routing|remittance|beneficiary)\b"
             r"[^.]{0,50}\b(changed|updated|new|revised|corrected)\b|"
             r"\b(changed|updated|new|revised|corrected)\b[^.]{0,50}\b(bank|"
             r"account|iban|swift|routing|beneficiary)\b",
             "changed payment details"),
        ],
        [
            (r"\b(urgent|immediately|today|asap|close of business|eod|"
             r"overdue|final notice|pending)\b",
             "payment urgency"),
            (r"\b(ceo|director|finance|accounts (team|dept)|vendor|supplier|"
             r"client|cfo)\b",
             "authority/vendor role"),
            (r"\b(do not|don'?t|avoid) (call|verify|confirm|contact)\b|"
             r"\b(only|just) (reply|email)\b|"
             r"\b(out of (office|town)|travelling|in a meeting)\b",
             "verification blocker"),
        ],
    ),
    Script(
        "SEXTORTION / COMPROMISING-MATERIAL BLACKMAIL",
        "'I recorded you on webcam', threatens to leak to contacts unless "
        "crypto is paid; the material is usually faked.",
        [
            (r"(webcam|web cam|screen ?record(ing|ed)?|intimate|explicit|"
             r"nude|compromising (video|photo|footage)|recorded you)",
             "compromising-material claim"),
            (r"(bitcoin|btc|usdt|crypto|ransom|pay|payment|wallet)"
             r"[^.]{0,80}(or (i|we)('| w)?ll|publish|post|leak|send (it|them|"
             r"the (video|photos?)) to|share with|contacts|friends|family)",
             "leak threat / payment demand"),
        ],
        [
            (r"(48 hours|24 hours|72 hours|within \d+ hours|last warning|"
             r"final warning)",
             "countdown deadline"),
            (r"i have your (contacts|contact list|friends|family|emails?|"
             r"social media)",
             "contact-list leverage"),
            (r"(hacked|cracked|remote access|malware|spyware|trojan|"
             r"infected)",
             "technical pretext"),
        ],
    ),
    Script(
        "RENTAL / PROPERTY DEPOSIT",
        "Fake landlord rents a place they don't own: deposit/booking fee "
        "before viewing, owner 'abroad', keys 'couriered' after payment.",
        [
            (r"\b(2bhk|3bhk|1bhk|apartment|flat|house|room|property|rent|"
             r"rental|lease|landlord|owner|pg)\b",
             "rental listing"),
            (r"\b(deposit|booking (amount|fee)|token money|advance payment|"
             r"advance rent|security deposit)\b",
             "deposit demand"),
        ],
        [
            (r"\b(owner|landlord)\b[^.]{0,40}\b(abroad|out of (the )?country|"
             r"overseas|nri|out of town|not in india)\b",
             "absent owner excuse"),
            (r"\b(keys?)\b[^.]{0,40}\b(courier|dispatch|send|deliver|"
             r"after payment)\b",
             "keys-after-payment"),
            (r"\b(before|without) (a )?(viewing|visit|seeing)\b|"
             r"\b(no (viewing|visit)|can'?t show|photos? only)\b",
             "no-viewing pressure"),
        ],
    ),
    Script(
        "TOLL / PARKING / FINE SMISHING",
        "Fake unpaid toll, parking or traffic fine with a countdown and a "
        "payment link (often .top/.xyz); harvests card/UPI data.",
        [
            (r"\b(toll|fastag|parking|violation|challan|speeding|"
             r"congestion (charge|fee)|traffic (ticket|fine))\b",
             "toll/fine context"),
            (r"\b(pay|settle|clear|outstanding|unpaid|due)\b[^.]{0,50}"
             r"\b(fine|toll|violation|fee|amount|balance)\b|"
             r"\b(fine|toll|violation|fee)\b[^.]{0,50}\b(unpaid|due|overdue|"
             r"outstanding)\b",
             "payment owed"),
        ],
        [
            (r"\b(24 hours|48 hours|within \d+ (hours|days)|final notice|"
             r"late fee|avoid|penalty|suspend(ed)? (license|registration))\b",
             "countdown/penalty"),
            (r"(https?://|www\.|\.top\b|\.xyz\b|\.click\b|bit\.ly|tinyurl)",
             "payment link"),
            (r"\b(vehicle|registration|plate|license plate|tag|e-?zpass|"
             r"etc|fastag)\b",
             "vehicle/tag detail"),
        ],
    ),
    Script(
        "FAKE BANK APP / APK INSTALL",
        "Imposter bank SMS pushes an 'update' APK or third-party app from "
        "outside the official app store to steal credentials/OTPs.",
        [
            (r"\b(bank|sbi|hdfc|icici|axis|kotak|pnb|yono|paytm|phonepe|"
             r"gpay|google pay|union bank|net ?banking)\b",
             "bank impersonation"),
            (r"\b(install|download|update|upgrade)\b[^.]{0,40}\b(app|apk|"
             r"application|yono|software|version)\b|"
             r"\b(apk|app)\b[^.]{0,40}\b(install|download|update)\b",
             "app-install instruction"),
        ],
        [
            (r"\b(apk|\.apk\b|sideload|outside (the )?(play ?store|app store)|"
             r"not on play ?store|third[- ]party app)\b",
             "outside-store APK"),
            (r"\b(new (version|update)|mandatory|must update|outdated|"
             r"old version|before \d|today)\b",
             "forced-update pressure"),
            (r"(https?://|www\.|bit\.ly|\.apk|t\.me/|wa\.me/)",
             "install link"),
        ],
    ),
    Script(
        "ROMANCE (NON-INVESTMENT) / MILITARY-DOCTOR",
        "Long-distance 'soldier/doctor/engineer abroad' needs money for a "
        "visa, flight, hospital or customs clearance to finally meet.",
        [
            (r"\b(my (love|darling|sweetheart|dear)|darling|sweetheart|"
             r"meri jaan|love you|miss you|i miss you|my heart)\b",
             "romantic element"),
            (r"\b(visa|flight ticket|air ?ticket|hospital|surgery|medical "
             r"bill|customs|clearance fee|leave (fee|pass|approval)|"
             r"deployment|peacekeeping|oil rig|contract)\b[^.]{0,80}\b"
             r"(money|pay|fee|send|transfer|help|cost|\$|£|€|₹)|"
             r"\b(send|transfer|wire|western union|moneygram|gift card)\b"
             r"[^.]{0,80}\b(visa|ticket|hospital|surgery|bill|customs|"
             r"clearance|emergency)\b",
             "money-need excuse"),
        ],
        [
            (r"\b(military|army|soldier|troops|doctor|surgeon|un peace|"
             r"engineer|oil rig|deployed|stationed)\b",
             "fake profession/deployment"),
            (r"\b(western union|moneygram|gift card|bitcoin|crypto|"
             r"wire transfer|mobile money)\b",
             "hard-to-reverse payment rail"),
            (r"\b(don'?t tell|keep (this|it) secret|between us|no one "
             r"else|our secret)\b",
             "secrecy"),
        ],
    ),
    Script(
        "FAMILY NEW-NUMBER IMPOSTER",
        "'Mum/Dad, this is my new number' + old phone broken + urgent money "
        "request; the sender is not the relative at all.",
        [
            (r"\b(mum|mummy|mom|dad|papa|beta|son|daughter|brother|"
             r"sister|aunty|uncle)\b",
             "family addressee"),
            (r"\b(this is (my|your) (new|other|another) (number|phone|sim)|"
             r"my new number|changed my number|new number|"
             r"message me on this)\b",
             "new-number claim"),
            (r"\b(send|transfer|pay|need|require|help)\b[^.]{0,60}"
             r"(\$|£|₹|rs\.?|rupees|money|cash|\d{3,})",
             "money request"),
        ],
        [
            (r"\b(old (number|phone|sim)|phone (broke|broken|died|lost)|"
             r"lost my phone|no (signal|network)|can'?t (call|talk))\b",
             "old-phone excuse"),
            (r"\b(don'?t call|can'?t call|only (text|whatsapp)|"
             r"message only|whatsapp only)\b",
             "call-avoidance"),
            (r"\b(urgent|immediately|right now|today|asap)\b",
             "urgency"),
        ],
    ),
]

# Rule: a script "matches" when BOTH mandatory beats hit (the floor of the
# playbook) plus at least one optional beat. Stronger matches add more detail
# to the report but one full match is enough to lock the verdict.
def match_scripts(text):
    """Return list of (script, strength, labels); strength 0..1."""
    results = []
    for script in SCRIPTS:
        mand, opt, labels = script.match(text)
        if mand == len(script.mandatory) and opt >= 1:
            strength = 1.0
        elif mand > 0 and (mand + min(opt, 3)) >= 3 and opt >= 1:
            strength = 0.6
        else:
            continue
        results.append((script, strength, labels))
    results.sort(key=lambda r: -r[1])
    return results
