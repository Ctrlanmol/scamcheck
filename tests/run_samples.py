#!/usr/bin/env python3
"""Self-test: rule engine + script fingerprints + conversation analysis."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scamcheck.rules import run_rules  # noqa: E402
from scamcheck.scripts_lib import match_scripts  # noqa: E402
from scamcheck.conversation import analyze_conversation  # noqa: E402

from samples import SAMPLES, CONVERSATIONS  # noqa: E402

RANK = {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "LIKELY SCAM": 2, "SCAM": 3}


def check(name, ok, detail):
    print("[%s] %s" % ("PASS" if ok else "FAIL", name))
    print("      " + detail)
    if not ok:
        return 1
    return 0


def main():
    failures = 0
    for text, expected in SAMPLES:
        result = run_rules(text)
        rank = RANK[result["verdict"]]
        ok = rank >= expected
        detail = "%s (score %2d) expected >= %d | signals: %s" % (
            result["verdict"], result["score"], expected,
            "; ".join(r[0] for r in result["reasons"]) or "none")
        failures += check(text[:60] + "...", ok, detail)
        print()

    # script fingerprints
    script_cases = [
        ("This is FedEx: your parcel is held in customs. Pay the $1.99 fee via gift "
         "card to release. Contact us at t.me/parsellhelpdesk",
         "TASK SCAM (FAKE PART-TIME JOB)", False),  # courier scam is not a task scam
        ("Hi dear, I made $3400 yesterday on this trading platform, join "
         "me. Register at app, recharge with USDT. Good morning!",
         "PIG BUTCHERING / CRYPTO ROMANCE-INVESTMENT", True),
        ("Hello sir, this is Mumbai police cyber cell. A parcel containing "
         "drugs was intercepted, there is a warrant against you. Join video "
         "call on Skype for verification, do not tell anyone, pay surety "
         "deposit." , "DIGITAL ARREST / LAW-ENFORCEMENT EXTORTION", True),
        ("Your computer is infected with virus. Download AnyDesk so our "
         "Microsoft technician can share screen and protect your funds.",
         "TECH-SUPPORT REMOTE-ACCESS", True),
        # Hinglish variants fingerprint the same playbooks
        ("Dada aap digital arrest me ho. Cyber police ka video call par "
         "verification hoga, kisi ko batana mat. Surety ke liye paisa bhejo.",
         "DIGITAL ARREST / LAW-ENFORCEMENT EXTORTION", True),
        ("Beta, maine aaj telegram pe part-time kaam kiya, rozana kamai "
         "₹3000 milti hai. Telegram join karo, task karo recharge karo.",
         "TASK SCAM (FAKE PART-TIME JOB)", True),
        # v0.5 playbooks
        ("Please note our bank details have changed. Kindly remit the "
         "outstanding invoice to the new IBAN before close of business today. "
         "Do not call the office, only reply by email.",
         "INVOICE / BEC PAYMENT DIVERSION", True),
        ("I recorded you through your webcam. I have your contacts. Send 0.05 "
         "BTC within 48 hours or I will leak the video to your family.",
         "SEXTORTION / COMPROMISING-MATERIAL BLACKMAIL", True),
        ("2BHK flat for rent, owner is abroad and keys will be couriered "
         "after payment. Pay the booking amount before viewing.",
         "RENTAL / PROPERTY DEPOSIT", True),
        ("Your vehicle has an unpaid toll violation. Pay within 24 hours or a "
         "late fee applies: http://dmv-toll-pay.top/eztag",
         "TOLL / PARKING / FINE SMISHING", True),
        ("Dear customer, download the new SBI YONO APK from this link, the old "
         "app version is outdated: http://yono-update.apk",
         "FAKE BANK APP / APK INSTALL", True),
        ("My darling, I am a US Army doctor deployed overseas. I need $2,500 "
         "for an emergency leave ticket to finally see you, send via Western "
         "Union.",
         "ROMANCE (NON-INVESTMENT) / MILITARY-DOCTOR", True),
        ("Hi Mum, this is my new number, my old phone is broken. Please send "
         "£850 urgently, don't call just transfer.",
         "FAMILY NEW-NUMBER IMPOSTER", True),
        # ordinary business/family messages must NOT fingerprint a playbook
        ("Hi team, please find attached the July invoice. Payment is due in 30 "
         "days as usual. Thanks, Priya from accounts.",
         "INVOICE / BEC PAYMENT DIVERSION", False),
        ("Hi mum, this is my new number, call me when you are free tonight.",
         "FAMILY NEW-NUMBER IMPOSTER", False),
        ("Your toll balance is low, please recharge online or at any counter.",
         "TOLL / PARKING / FINE SMISHING", False),
        ("2BHK flat for rent, deposit negotiable, call the owner for a viewing.",
         "RENTAL / PROPERTY DEPOSIT", False),
    ]
    for text, expected_script, should_match in script_cases:
        matches = match_scripts(text)
        names = [s.name for s, _, _ in matches]
        ok = (expected_script in names) == should_match
        detail = ("scripts=%s expected: %s%s" % (names, expected_script,
                                                 "" if should_match else " NOT required"))
        failures += check("script: " + text[:50] + "...", ok, detail)
        print()

    # conversation trajectory
    convo_cases = [
        (CONVERSATIONS["pig_butcher"], 2, "pig-butchering trajectory"),
        (CONVERSATIONS["normal_talk"], 0, "normal chat"),
        (CONVERSATIONS["hinglish_task"], 2, "hinglish task-scam trajectory"),
    ]
    for conv_text, expected, name in convo_cases:
        result = analyze_conversation(conv_text)
        rank = RANK.get(result["verdict"].replace(" CONVERSATION", "").replace(" PATTERN", ""), 0)
        ok = rank >= expected
        detail = "%s (score %d, %d messages) expected >= %d" % (
            result["verdict"], result["score"], result["message_count"], expected)
        failures += check(name, ok, detail)
        print()

    if failures:
        print("FAILED: %d checks" % failures)
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
