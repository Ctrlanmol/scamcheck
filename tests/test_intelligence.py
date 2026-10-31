#!/usr/bin/env python3
"""v0.11 tests: deobfuscation, intelligence assessment, CLI/bot/JARVIS routes.

Everything is local and deterministic. Run: python3 tests/test_intelligence.py
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

HOME = tempfile.mkdtemp(prefix="scamcheck-intel-")
os.environ["SCAMCHECK_HOME"] = HOME
os.environ["SCAMCHECK_REGION"] = "IN"
os.environ["SCAMCHECK_JARVIS_AI"] = "never"
os.environ.pop("OPENAI_API_KEY", None)
os.environ.pop("ANTHROPIC_API_KEY", None)

from scamcheck import bot                                    # noqa: E402
from scamcheck.analyzer import analyze                       # noqa: E402
from scamcheck.intelligence import (                        # noqa: E402
    assess, deobfuscate, detect_obfuscation, format_briefing,
)
from scamcheck.jarvis import JarvisSession                    # noqa: E402


def check(name, ok, detail=""):
    print("[%s] %s" % ("PASS" if ok else "FAIL", name))
    if detail:
        print("      " + str(detail))
    return 0 if ok else 1


BANK = (
    "URGENT: Your HDFC Bank account will be blocked in 24 hours. "
    "Complete KYC now and share the OTP with our officer."
)
INVEST = (
    "Hi dear, I can teach you trading with guaranteed returns. "
    "Open an account on our platform and deposit 500 USDT. "
    "Pay 20% tax to withdraw your profit. Don't tell anyone."
)
BENIGN = "Hi mom, I'll be home by 7. Can you pick up milk?"
OBFUSCATED = (
    "Your B\u0430nk \u0430ccount is bl\u043ecked. "
    "Verify n\u043ew: hxxps://hdfc[.]verify-kyz[.]xyz"
)
CONVERSATION = """Hi dear, I like your profile.
I can teach you trading with guaranteed returns.
Open an account on this platform and deposit 500 USDT.
Now pay 20% tax to withdraw your profit.
Don't tell anyone."""


def main():
    failures = 0

    # --------------------------------------------------- 1. deobfuscation
    cases = [
        ("zero-width removal", "B\u200bA\u200bN\u200bK", "BANK"),
        ("full-width normalize", "ＢＡＮＫ", "BANK"),
        ("homoglyph repair", "B\u0430nk \u0430ccount", "Bank account"),
        ("letter spacing", "b a n k", "bank"),
        ("separator letters", "b.a.n.k", "bank"),
        ("leetspeak word", "acc0unt", "account"),
        ("disguised URL", "hxxps://hdfc[.]verify-kyz[.]xyz",
         "https://hdfc.verify-kyz.xyz"),
    ]
    for name, raw, expected in cases:
        got = deobfuscate(raw)
        failures += check(name, got == expected, "got=%r" % got)

    # --------------------------------------------------- 2. obfuscation detector
    hidden = detect_obfuscation("B\u200bA\u200bN\u200bK")
    keys = {s["key"] for s in hidden["signals"]}
    failures += check("detect zero-width", "zero_width" in keys, keys)
    failures += check("obfuscation score is capped",
                      hidden["score"] > 0 and hidden["score"] <= 20, hidden["score"])

    homoglyph = detect_obfuscation("Your B\u0430nk account")
    failures += check("detect mixed-script homoglyph",
                      "homoglyph" in {s["key"] for s in homoglyph["signals"]},
                      homoglyph["signals"])

    url = detect_obfuscation("visit hxxp://bad[.]example[.]com")
    failures += check("detect disguised URL",
                      "url_obfuscation" in {s["key"] for s in url["signals"]},
                      url["signals"])

    for name, text in [
        ("plain English", "Your bank account is blocked. Call the number on your card."),
        ("pure Cyrillic", "Ваш банк заблокирован, позвоните в банк."),
        ("digits are not leetspeak", "Order A12345 shipped on 24/10."),
    ]:
        got = detect_obfuscation(text)
        failures += check("no false obfuscation: " + name, not got["detected"],
                          got["signals"])

    # --------------------------------------------------- 3. analyzer integration
    result = analyze(OBFUSCATED, use_ai="never")
    intel = result.get("intelligence") or {}
    labels = [label for label, _w in result.get("reasons") or []]
    failures += check("analyze attaches intelligence", bool(intel))
    failures += check("obfuscated message is at least suspicious",
                      result["final_verdict"] in ("SUSPICIOUS", "LIKELY SCAM", "SCAM"),
                      result["final_verdict"])
    failures += check("obfuscation appears as a reason",
                      any("Disguised text" in label for label in labels), labels[:3])
    failures += check("obfuscation recorded in intelligence",
                      intel.get("obfuscation", {}).get("detected"))
    failures += check("obfuscated bank type",
                      intel.get("scam_type") in ("bank", "otp"), intel.get("scam_type"))

    # --------------------------------------------------- 4. bank assessment
    i = analyze(BANK, use_ai="never")["intelligence"]
    failures += check("bank/OTP type", i["scam_type"] in ("bank", "otp"), i["scam_type"])
    failures += check("bank impersonation named",
                      any(x["name"] == "HDFC Bank" for x in i["impersonation"]),
                      i["impersonation"])
    failures += check("bank stage detected", bool(i["stage"]["key"]), i["stage"])
    failures += check("bank goals present",
                      any(g["key"] in ("credentials", "money_transfer", "account_takeover")
                          for g in i["goals"]), i["goals"])
    failures += check("bank next moves present", len(i["next_moves"]) >= 2,
                      i["next_moves"])
    failures += check("bank verification steps present", len(i["verify"]) >= 3)
    failures += check("bank evidence steps present", len(i["evidence"]) >= 3)

    # --------------------------------------------------- 5. investment assessment
    inv = analyze(INVEST, use_ai="never")["intelligence"]
    failures += check("investment type", inv["scam_type"] == "investment",
                      (inv["scam_type"], inv["type_scores"]))
    failures += check("investment kill-chain stage is fee",
                      inv["stage"]["key"] == "fee", inv["stage"])
    failures += check("crypto rail detected",
                      any(r["key"] == "crypto" for r in inv["payment_rails"]),
                      inv["payment_rails"])
    failures += check("investment goal first",
                      inv["goals"] and inv["goals"][0]["key"] == "investment",
                      inv["goals"])
    failures += check("investment predicts fee/false-profit moves",
                      any("fee" in m.lower() or "profit" in m.lower()
                          for m in inv["next_moves"]), inv["next_moves"])
    failures += check("investment safe replies",
                      len(inv["safe_replies"]) >= 2 and
                      inv["reply_policy"] == "do_not_reply", inv["reply_policy"])
    failures += check("investment obfuscation clean", not inv["obfuscation"]["detected"])

    # --------------------------------------------------- 6. benign assessment
    ben = analyze(BENIGN, use_ai="never")["intelligence"]
    failures += check("benign type is general", ben["scam_type"] == "general",
                      ben["scam_type"])
    failures += check("benign has no attack goals", ben["goals"] == [], ben["goals"])
    failures += check("benign has no next moves", ben["next_moves"] == [], ben["next_moves"])
    failures += check("benign confidence low", ben["confidence"] == "low",
                      ben["confidence"])
    failures += check("benign no impersonation", ben["impersonation"] == [],
                      ben["impersonation"])

    # --------------------------------------------------- 7. conversation trajectory
    convo = analyze(CONVERSATION, is_conversation=True, use_ai="never")
    ci = convo["intelligence"]
    failures += check("conversation intelligence attached", bool(ci))
    failures += check("conversation type is investment", ci["scam_type"] == "investment",
                      ci["scam_type"])
    failures += check("conversation stage reads fee block",
                      ci["stage"]["key"] == "fee", ci["stage"])
    failures += check("conversation stage path includes deposit/fee",
                      "deposit" in ci["stage"]["path"] and "fee" in ci["stage"]["path"],
                      ci["stage"]["path"])

    # --------------------------------------------------- 8. briefing formatting
    brief = format_briefing(inv)
    failures += check("briefing has header", "Intelligence briefing" in brief)
    failures += check("briefing lists next moves", "Likely next moves:" in brief)
    failures += check("briefing lists verification", "Verify independently:" in brief)
    failures += check("briefing lists evidence", "Preserve evidence:" in brief)
    failures += check("briefing lists payment rail", "Payment:" in brief)
    safe_brief = format_briefing(ben)
    failures += check("safe briefing is quiet",
                      "Likely next moves:" not in safe_brief and
                      "Preserve evidence:" not in safe_brief, safe_brief.splitlines()[:4])

    # --------------------------------------------------- 9. CLI --json / --intel
    env = dict(os.environ)
    env["SCAMCHECK_HOME"] = HOME
    env["SCAMCHECK_JARVIS_AI"] = "never"

    proc = subprocess.run(
        [sys.executable, "-m", "scamcheck", INVEST, "--json", "--ai", "never"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=90,
    )
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        data = {}
    failures += check("CLI JSON includes intelligence",
                      bool((data.get("intelligence") or {}).get("scam_type")),
                      "rc=%d" % proc.returncode)
    failures += check("CLI JSON intelligence type",
                      (data.get("intelligence") or {}).get("scam_type") == "investment",
                      (data.get("intelligence") or {}).get("scam_type"))

    proc = subprocess.run(
        [sys.executable, "-m", "scamcheck", INVEST, "--intel", "--ai", "never"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=90,
    )
    out = proc.stdout
    failures += check("CLI --intel prints briefing",
                      "Intelligence briefing" in out and
                      "Likely next moves:" in out, out.splitlines()[:3])

    # --------------------------------------------------- 10. bot reply
    risky = analyze(INVEST, use_ai="never")
    reply = bot.format_reply(risky, "en")
    failures += check("bot reply includes scam type",
                      "Scam type:" in reply and "Likely next:" in reply,
                      reply.splitlines()[:6])
    hindi = bot.format_reply(risky, "hi")
    failures += check("bot Hindi includes intel label", "ठगी का प्रकार" in hindi)
    safe_reply = bot.format_reply(analyze(BENIGN, use_ai="never"), "en")
    failures += check("bot safe reply omits intel", "Scam type:" not in safe_reply)

    # --------------------------------------------------- 11. JARVIS routes
    s = JarvisSession(ai="never", voice=False, notify=False)
    assessed = s.handle("assess " + INVEST)["text"]
    failures += check("JARVIS assess", "Intelligence briefing" in assessed and
                      "Verdict:" in assessed, assessed.splitlines()[:3])
    failures += check("JARVIS next", "Likely next moves" in s.handle("next")["text"])
    failures += check("JARVIS reply", "respond" in s.handle("reply")["text"].lower())
    failures += check("JARVIS brief", "Preserve evidence" in s.handle("brief")["text"])

    checked = s.handle("check " + BANK)["text"]
    failures += check("JARVIS check shows intel", "Scam type:" in checked,
                      checked.splitlines()[:4])
    last_assess = s.handle("assess")["text"]
    failures += check("JARVIS assess without text uses last",
                      "Intelligence briefing" in last_assess)

    fresh = JarvisSession(ai="never", voice=False, notify=False)
    failures += check("JARVIS next without a check",
                      "Nothing checked yet" in fresh.handle("next")["text"])

    print()
    print("FAILED: %d checks" % failures if failures else "All checks passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
