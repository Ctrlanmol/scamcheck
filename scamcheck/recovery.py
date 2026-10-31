"""Country-aware recovery playbooks and complaint templates.

This module intentionally contains no network calls. It gives a victim a
clear, time-ordered checklist and a pre-filled complaint draft, while making
the limits explicit: hotlines and portals change, so verify them locally.

Public API:
    get_authority(country) -> dict
    get_playbook(scam_type, country) -> dict
    format_playbook(playbook) -> str
    complaint_template(case, country=None, scam_type=None) -> str
"""

import time

AUTHORITIES = {
    "IN": {
        "country": "India",
        "cyber": "1930 (24x7 national cyber-fraud helpline)",
        "cyber_url": "https://cybercrime.gov.in",
        "police": "Local police / your bank's fraud line",
        "bank": "Call the number printed on your card or banking app; use the in-app fraud/block option",
        "extra": "Report UPI fraud in the UPI app and to your bank immediately; request a chargeback/dispute.",
    },
    "US": {
        "country": "United States",
        "cyber": "FBI IC3 · https://ic3.gov",
        "cyber_url": "https://ic3.gov",
        "police": "Local police non-emergency line",
        "bank": "Bank/card issuer fraud line (number on the card); ask for the fraud department",
        "extra": "FTC: https://ReportFraud.ftc.gov or 1-877-382-4357. Identity theft: https://IdentityTheft.gov.",
    },
    "GB": {
        "country": "United Kingdom",
        "cyber": "Action Fraud · 0300 123 2040 · https://www.actionfraud.police.uk",
        "cyber_url": "https://www.actionfraud.police.uk",
        "police": "101 (non-emergency) or 999 if someone is in immediate danger",
        "bank": "Bank fraud line; call 159 to be routed to your bank's fraud team",
        "extra": "Report suspicious emails to report@phishing.gov.uk and texts to 7726.",
    },
    "AU": {
        "country": "Australia",
        "cyber": "ReportCyber · https://www.cyber.gov.au/report",
        "cyber_url": "https://www.cyber.gov.au/report",
        "police": "Police Assistance Line 131 444 (000 in an emergency)",
        "bank": "Your bank's fraud line; ask for the scam/fraud team",
        "extra": "Scamwatch: https://www.scamwatch.gov.au. ACCC Infocentre: 1300 302 502.",
    },
    "CA": {
        "country": "Canada",
        "cyber": "Canadian Anti-Fraud Centre · 1-888-495-8501 · https://antifraudcentre-centreantifraude.ca",
        "cyber_url": "https://antifraudcentre-centreantifraude.ca",
        "police": "Local police non-emergency line",
        "bank": "Bank/card fraud line; freeze the account/card",
        "extra": "Equifax/TransUnion for a credit freeze if identity data was exposed.",
    },
    "SG": {
        "country": "Singapore",
        "cyber": "ScamShield app · Anti-Scam Helpline 1800-722-6688",
        "cyber_url": "https://www.scamshield.gov.sg",
        "police": "999 (emergency) or report online at https://www.police.gov.sg",
        "bank": "Bank fraud line; activate the kill switch/freeze in your banking app",
        "extra": "Report the number/message in ScamShield so other users are warned.",
    },
    "AE": {
        "country": "United Arab Emirates",
        "cyber": "Dubai Police 901 · Abu Dhabi Police 8002626",
        "cyber_url": "https://www.dubaipolice.gov.ae",
        "police": "901 (Dubai) / 999 (emergency)",
        "bank": "Bank fraud line; freeze card/account",
        "extra": "Report cybercrime to the police eCrime channel for your emirate.",
    },
    "NZ": {
        "country": "New Zealand",
        "cyber": "Report to Netsafe · 0508 638 723 · https://www.netsafe.org.nz",
        "cyber_url": "https://www.netsafe.org.nz",
        "police": "105 (non-emergency) or 111 (emergency)",
        "bank": "Bank fraud line; freeze the account/card",
        "extra": "Report the scam to Cert NZ: https://www.cert.govt.nz",
    },
    "ZA": {
        "country": "South Africa",
        "cyber": "SAPS 10111 · https://www.saps.gov.za",
        "cyber_url": "https://www.saps.gov.za",
        "police": "10111 (emergency) or your local SAPS station",
        "bank": "Bank fraud line; freeze the account/card",
        "extra": "Report to the bank's fraud department and keep the case number.",
    },
}

GENERIC_AUTHORITY = {
    "country": "your country",
    "cyber": "local cybercrime/police portal",
    "cyber_url": "",
    "police": "local police non-emergency line",
    "bank": "the fraud line printed on your card or banking app",
    "extra": "Ask your bank for the fraud/chargeback process and keep every reference number.",
}

TYPE_ALIASES = {
    "upi": "upi", "bank": "bank", "bank_transfer": "bank", "neft": "bank",
    "card": "card", "credit_card": "card", "debit_card": "card",
    "crypto": "crypto", "bitcoin": "crypto", "usdt": "crypto",
    "investment": "investment", "trading": "investment", "pig_butchering": "investment",
    "job": "job", "task": "job", "part_time": "job",
    "romance": "romance", "sextortion": "sextortion",
    "identity": "identity", "identity_theft": "identity",
    "tech": "tech", "tech_support": "tech", "remote_access": "tech",
    "digital_arrest": "digital_arrest", "police": "digital_arrest",
    "courier": "courier", "parcel": "courier",
    "loan": "loan", "otp": "otp", "general": "general",
}

TYPE_TITLES = {
    "upi": "UPI / instant payment fraud",
    "bank": "bank transfer fraud",
    "card": "card / payment fraud",
    "crypto": "crypto / wallet fraud",
    "investment": "investment or romance-investment fraud",
    "job": "job / task scam",
    "romance": "romance scam",
    "sextortion": "sextortion / blackmail",
    "identity": "identity theft / account takeover",
    "tech": "tech-support / remote-access scam",
    "digital_arrest": "digital arrest / impersonated police",
    "courier": "courier / parcel scam",
    "loan": "loan / advance-fee scam",
    "otp": "OTP / credential theft",
    "general": "scam / fraud",
}

COMMON_NOW = [
    "Stop all contact and do not send more money, gift cards, crypto or codes.",
    "Call your bank's fraud line now and ask them to freeze/block the account or card.",
    "Change passwords for email, banking and any account the scammer touched; enable 2FA.",
    "Preserve the chat, screenshots, phone numbers, UPI IDs, wallet addresses and URLs.",
    "Write down the exact timeline and every payment reference/transaction ID.",
]

COMMON_TODAY = [
    "File a report with the cybercrime/police authority for your country (see below).",
    "Report the sender/number/profile to the platform (bank, WhatsApp, Telegram, email provider).",
    "Ask your bank for the dispute/chargeback process and a written case reference.",
    "Tell a trusted family member or friend; scammers rely on isolation and shame.",
]

COMMON_WEEK = [
    "Follow up with the bank and police; add any new evidence to the case pack.",
    "Check whether your identity data was exposed and consider a credit freeze/alert.",
    "Review privacy settings and remove public phone/email details the scammer used.",
    "Save the case pack somewhere safe; do not delete the original messages.",
]

PLAYBOOKS = {
    "upi": {
        "now": [
            "Open your UPI app and use the fraud/report option for the transaction.",
            "Call your bank and ask them to freeze the beneficiary/account and raise a dispute.",
            "Report to 1930 / the national cyber-fraud portal in India as soon as possible.",
        ],
        "today": [
            "Ask the bank for a chargeback/representation; keep the complaint number.",
            "Report the UPI ID and linked number in your banking app and to the platform used.",
        ],
    },
    "bank": {
        "now": [
            "Call the bank fraud line and ask for an immediate recall/freeze of the transfer.",
            "If the transfer is still pending, ask the bank to stop it before settlement.",
            "Note the beneficiary account, IFSC, amount and transaction reference.",
        ],
        "today": [
            "Submit a written complaint/dispute to the bank and keep the acknowledgement.",
            "File a police/cybercrime report with the bank statement and chat evidence.",
        ],
    },
    "card": {
        "now": [
            "Block the card in the banking app or call the issuer's 24x7 fraud line.",
            "Dispute every unrecognized charge; ask for a new card and new CVV.",
            "Check for other cards/accounts the same details could unlock.",
        ],
        "today": [
            "Review recent statements and set transaction alerts.",
            "Report the merchant/link to the card network and platform.",
        ],
    },
    "crypto": {
        "now": [
            "Do not pay any 'recovery fee', 'tax' or 'unlock fee' — that is a second scam.",
            "Copy the wallet address and transaction hash; do not delete the wallet/app.",
            "Report the address to the exchange/wallet you used and to the police/cybercrime portal.",
        ],
        "today": [
            "Check the address on a public block explorer and record the flow.",
            "Ask a legitimate exchange/compliance team whether the deposit can be frozen.",
            "Beware of 'recovery agents' on social media; verify independently.",
        ],
    },
    "investment": {
        "now": [
            "Stop depositing; withdraw only through the official app/site, never a 'manager'.",
            "Screenshot the platform name, URL, app, group chat and every deposit.",
            "Report the platform and the recruiter to the platform they contacted you on.",
        ],
        "today": [
            "File a cybercrime/police report; include the platform URL and payment rails.",
            "Warn your contacts; pig-butchering operations often reuse the same scripts.",
        ],
    },
    "job": {
        "now": [
            "Stop the 'training tasks' and any deposit/prepaid fee; legitimate jobs do not charge you.",
            "Do not install remote-access or APK files sent by the recruiter.",
            "Preserve the job ad, chat, UPI/bank details and task screenshots.",
        ],
        "today": [
            "Report the recruiter/profile to the job platform and cybercrime portal.",
            "If you installed an APK or granted remote access, disconnect and change passwords.",
        ],
    },
    "romance": {
        "now": [
            "Stop sending money; do not confront or negotiate with the scammer.",
            "Save the profile, photos, chats and payment records before blocking.",
            "Tell someone you trust; romance scams are designed to isolate you.",
        ],
        "today": [
            "Report the profile to the dating/social platform.",
            "File a police/cybercrime report; include the requests for money and any crypto wallet.",
        ],
    },
    "sextortion": {
        "now": [
            "Do not pay and do not send more images; payment rarely stops the demands.",
            "Stop responding, save the threats, then block/report the account.",
            "Report the account to the platform and use its intimate-image abuse channel.",
        ],
        "today": [
            "File a police/cybercrime report; ask about takedown and victim-support options.",
            "Talk to a trusted person or a support service; this is not your fault.",
        ],
    },
    "identity": {
        "now": [
            "Freeze your credit and place a fraud alert (Equifax/TransUnion/Experian in the US).",
            "Change passwords, revoke sessions and enable 2FA on email and banking.",
            "Check for SIM-swap/port-out activity with your mobile carrier.",
        ],
        "today": [
            "Report identity theft to the relevant authority and get an identity-theft report.",
            "Review credit reports, bank statements and account recovery details.",
        ],
    },
    "tech": {
        "now": [
            "Disconnect remote-access software and uninstall anything the caller asked you to install.",
            "Change passwords from a different, trusted device; run a malware scan.",
            "Call the bank if you shared card, OTP or banking details.",
        ],
        "today": [
            "Report the caller/number and the remote-access tool to the platform and police.",
            "Check for new logins, forwarding rules and unauthorized transactions.",
        ],
    },
    "digital_arrest": {
        "now": [
            "Hang up. Real police do not arrest people over a video call or demand payment.",
            "Do not pay, do not share Aadhaar/PAN/bank details, and do not stay isolated.",
            "Call a family member and verify the claim through an official police station number.",
        ],
        "today": [
            "Report the numbers, video-call app and payment demand to cybercrime/police.",
            "Preserve the call recording, chat, IDs shown and any money trail.",
        ],
    },
    "courier": {
        "now": [
            "Do not pay a 'customs', 'parcel' or 'drugs found' fee; verify with the official courier app.",
            "Do not share OTPs or install an APK from the sender.",
            "Report the SMS/number to your carrier and cybercrime portal.",
        ],
        "today": [
            "Check the tracking number only on the official courier website.",
            "Report the domain/link so it can be blocked for other users.",
        ],
    },
    "loan": {
        "now": [
            "Stop paying advance fees/insurance/GST for a loan you have not received.",
            "Do not install the lender's APK or grant contact/photo permissions.",
            "Report the app and number to the police/cybercrime portal and app store.",
        ],
        "today": [
            "Check whether the lender is registered with your financial regulator.",
            "If contacts were harvested, warn them about loan-recovery harassment.",
        ],
    },
    "otp": {
        "now": [
            "Change the password and PIN for the affected account immediately.",
            "Call the bank and ask them to freeze/re-secure the account.",
            "Revoke active sessions and enable 2FA; check for new payees/beneficiaries.",
        ],
        "today": [
            "Report the OTP theft and any unauthorized transaction to the bank and police.",
            "Check email/SMS forwarding rules and recovery phone numbers.",
        ],
    },
    "general": {
        "now": [],
        "today": [],
    },
}


def _normalize_type(scam_type):
    key = (scam_type or "general").strip().lower().replace("-", "_").replace(" ", "_")
    return TYPE_ALIASES.get(key, key if key in PLAYBOOKS else "general")


def infer_type(text):
    low = (text or "").lower()
    checks = [
        ("sextortion", ("sextortion", "nude", "intimate image", "blackmail")),
        ("digital_arrest", ("digital arrest", "cbi", "police case", "arrest warrant")),
        ("tech", ("remote access", "anydesk", "teamviewer", "tech support", "microsoft support")),
        ("courier", ("parcel", "courier", "customs", "delivery fee")),
        ("job", ("part-time job", "task scam", "telegram task", "daily payout")),
        ("investment", ("investment", "trading", "crypto platform", "guaranteed return")),
        ("crypto", ("usdt", "bitcoin", "wallet address", "trc20")),
        ("upi", ("upi", "gpay", "phonepe", "paytm", "vpa")),
        ("card", ("credit card", "debit card", "cvv", "card number")),
        ("romance", ("romance", "dating", "love", "marry")),
        ("loan", ("loan", "advance fee", "processing fee")),
        ("otp", ("otp", "one-time password", "verification code")),
        ("bank", ("bank transfer", "account transfer", "neft", "imps")),
        ("identity", ("aadhaar", "pan card", "ssn", "identity theft")),
    ]
    for kind, words in checks:
        if any(word in low for word in words):
            return kind
    return "general"


def get_authority(country):
    code = (country or "").strip().upper()
    data = dict(AUTHORITIES.get(code) or GENERIC_AUTHORITY)
    data["code"] = code or "??"
    return data


def get_playbook(scam_type="general", country="IN"):
    kind = _normalize_type(scam_type)
    book = PLAYBOOKS.get(kind) or PLAYBOOKS["general"]
    now = list(COMMON_NOW) + list(book.get("now") or [])
    today = list(book.get("today") or []) + list(COMMON_TODAY)
    week = list(COMMON_WEEK)
    return {
        "scam_type": kind,
        "title": TYPE_TITLES.get(kind, TYPE_TITLES["general"]),
        "country": (country or "IN").upper(),
        "authority": get_authority(country),
        "now": now,
        "today": today,
        "week": week,
    }


def format_playbook(playbook):
    auth = playbook.get("authority") or {}
    lines = [
        "🛟 Recovery plan · %s (%s) · %s" % (
            auth.get("country") or "your country", auth.get("code") or "??",
            playbook.get("title") or "fraud"),
        "",
        "Immediate (first hour)",
    ]
    for step in playbook.get("now") or []:
        lines.append("  [ ] " + step)
    lines += ["", "Today"]
    for step in playbook.get("today") or []:
        lines.append("  [ ] " + step)
    lines += ["", "This week"]
    for step in playbook.get("week") or []:
        lines.append("  [ ] " + step)
    lines += [
        "",
        "Report to",
        "  • Cybercrime: " + (auth.get("cyber") or "local police"),
    ]
    if auth.get("cyber_url"):
        lines.append("    " + auth["cyber_url"])
    lines.append("  • Police: " + (auth.get("police") or "local police"))
    lines.append("  • Bank: " + (auth.get("bank") or "your bank's fraud line"))
    if auth.get("extra"):
        lines.append("  • " + auth["extra"])
    lines += [
        "",
        "Keep evidence",
        "  • Screenshots, chat exports, SMS headers, caller numbers, URLs, UPI IDs,",
        "    bank references, wallet addresses and transaction hashes.",
        "  • Add them to a local case: `scamcheck --case-new \"...\"` then `--case-add`.",
        "  • Export a pack with `--case-export CASE_ID`.",
        "",
        "Hotlines and portals change. Verify the numbers on the official website",
        "before sharing personal details. This is guidance, not legal advice.",
    ]
    return "\n".join(lines)


def complaint_template(case, country=None, scam_type=None):
    case = case or {}
    auth = get_authority(country or case.get("country"))
    kind = _normalize_type(scam_type or case.get("scam_type"))
    title = TYPE_TITLES.get(kind, TYPE_TITLES["general"])
    created = case.get("created_ts")
    opened = time.strftime("%Y-%m-%d %H:%M", time.localtime(created)) if created else "[DATE]"
    amount = case.get("loss_amount") or 0
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        amount = 0
    loss = ("%s %.2f" % (case.get("currency") or "", amount)).strip() if amount else "[AMOUNT]"

    entities = case.get("entities") or []
    entity_lines = []
    for item in entities:
        if item.get("kind") == "message":
            continue
        entity_lines.append("- %s: %s" % (
            str(item.get("kind") or "identifier").replace("_", " "),
            item.get("label") or item.get("value")))
    if not entity_lines:
        entity_lines = ["- [ADD PHONE / UPI / URL / WALLET / ACCOUNT]"]

    evidence = case.get("packed_evidence") or case.get("evidence") or []
    evidence_lines = []
    for index, item in enumerate(evidence, start=1):
        evidence_lines.append("- Evidence %d: %s · SHA-256 %s" % (
            index, item.get("packed") or item.get("filename") or item.get("kind") or "text",
            item.get("sha256") or "[HASH]"))
    if not evidence_lines:
        evidence_lines = ["- [ATTACH SCREENSHOTS / CHAT EXPORT / BANK STATEMENT]"]

    timeline = []
    for event in case.get("events") or []:
        timeline.append("- %s — %s" % (
            time.strftime("%Y-%m-%d %H:%M", time.localtime(event.get("ts") or 0)),
            event.get("description") or ""))
    if not timeline:
        timeline = ["- [DATE] — first contact", "- [DATE] — payment / loss"]

    return """To: %(cyber)s
Subject: Fraud complaint — %(title)s — case %(case_id)s

Reporter
- Name: [YOUR FULL NAME]
- Phone: [YOUR PHONE]
- Email: [YOUR EMAIL]
- Address / jurisdiction: [YOUR ADDRESS]

Incident
- Case ID: %(case_id)s
- Scam type: %(title)s
- First contact / case opened: %(opened)s
- Loss: %(loss)s
- Country: %(country)s
- Bank / payment provider: [BANK OR PROVIDER]
- Account / card / wallet: [YOUR ACCOUNT REFERENCE]

Summary
[Describe in 3-6 sentences how contact started, what the scammer claimed,
what you paid or disclosed, and what you have done since.]

Timeline
%(timeline)s

Suspect entities
%(entities)s

Evidence attached
%(evidence)s

Requests
1. Register this complaint and provide a case/reference number.
2. Preserve the attached records and request preservation of relevant account,
   subscriber, domain and transaction records from the service providers.
3. Share the case with the relevant bank/payment provider and, where
   applicable, the platform hosting the scam content.
4. Tell me what additional information or format you need.

I declare that the information above is true to the best of my knowledge.
I understand this template is not a legal filing until I review, complete and
submit it through the official channel.

Signature: [YOUR NAME]
Date: [DATE]

---
Authority: %(cyber)s
Portal: %(cyber_url)s
Police: %(police)s
Bank: %(bank)s
""" % {
        "cyber": auth.get("cyber") or "local cybercrime/police",
        "title": title,
        "case_id": case.get("id") or "[CASE ID]",
        "opened": opened,
        "loss": loss,
        "country": auth.get("country") or "your country",
        "timeline": "\n".join(timeline),
        "entities": "\n".join(entity_lines),
        "evidence": "\n".join(evidence_lines),
        "cyber_url": auth.get("cyber_url") or "",
        "police": auth.get("police") or "local police",
        "bank": auth.get("bank") or "your bank",
    }
