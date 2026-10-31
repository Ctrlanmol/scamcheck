#!/usr/bin/env python3
"""v0.10 tests: entities, evidence cases, watchlists, campaigns, recovery, CLI.

Everything is local and deterministic. Run: python3 tests/test_cases.py
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

HOME = tempfile.mkdtemp(prefix="scamcheck-cases-")
os.environ["SCAMCHECK_HOME"] = HOME
os.environ["SCAMCHECK_REGION"] = "IN"
os.environ["SCAMCHECK_JARVIS_AI"] = "never"
os.environ.pop("OPENAI_API_KEY", None)
os.environ.pop("ANTHROPIC_API_KEY", None)

from scamcheck import campaigns, intel, recovery          # noqa: E402
from scamcheck.cases import CaseStore                      # noqa: E402
from scamcheck.jarvis import History, JarvisSession         # noqa: E402
from scamcheck.watchlist import Watchlist, format_hits      # noqa: E402


def check(name, ok, detail=""):
    print("[%s] %s" % ("PASS" if ok else "FAIL", name))
    if detail:
        print("      " + str(detail))
    return 0 if ok else 1


def kinds(items):
    return {item["kind"] for item in items}


def main():
    failures = 0

    # ------------------------------------------------------- 1. entities
    text = (
        "URGENT: pay 5000 to victim@okhdfcbank or call +91 98765 43210. "
        "Email help@bank-example.com. Wallet 1BoatSLRHtKNngkdXEeobR76b53LETtpyT. "
        "ETH 0x52908400098527886E0F7030069857D2E4169EE7. "
        "IFSC HDFC0001234. Telegram @scamchannel. "
        "Join https://chat.whatsapp.com/AbCdEfGhIjKlMnOp and install "
        "http://evil-example.xyz/app.apk plus visit evil-example.xyz/login"
    )
    items = intel.extract_entities(text)
    found = kinds(items)
    expected = {"message", "url", "phone", "email", "upi", "crypto_btc",
                "crypto_eth", "ifsc", "telegram", "whatsapp", "apk"}
    ok = expected.issubset(found)
    failures += check("extract entities from one message", ok,
                      "found=%s missing=%s" % (sorted(found), sorted(expected - found)))

    upi = [i for i in items if i["kind"] == "upi"]
    ok = upi and upi[0]["value"] == "victim@okhdfcbank"
    failures += check("UPI identifier normalized", ok, upi[:1])

    ok = any(i["kind"] == "url" and i["value"] == "evil-example.xyz"
             for i in items)
    failures += check("domain extracted without scheme", ok)

    ok = len(items) == len({(i["kind"], i["value"]) for i in items})
    failures += check("entities deduped", ok, "n=%d" % len(items))

    ok = (intel.parse_entity("url:https://Bad-Example.xyz/path?a=1")["value"]
          == "bad-example.xyz")
    failures += check("parse URL entity -> host", ok)

    ok = (intel.parse_entity("+91 98765 43210")["value"] == "+919876543210"
          and intel.parse_entity("@scamchannel")["kind"] == "telegram"
          and intel.parse_entity("HDFC0001234")["kind"] == "ifsc")
    failures += check("parse auto-detects phone/telegram/IFSC", ok)

    try:
        intel.parse_entity("not an identifier at all")
        ok = False
    except ValueError:
        ok = True
    failures += check("parse rejects unusable input", ok)

    ok = "UPI ID" in intel.format_entity({"kind": "upi", "value": "a@okhdfcbank"})
    failures += check("format_entity uses human labels", ok)

    # ------------------------------------------------------- 2. cases
    store = CaseStore()
    try:
        store.create("")
        ok = False
    except ValueError:
        ok = True
    failures += check("case requires a title", ok)

    case = store.create("Bank fraud", scam_type="upi", country="IN",
                        currency="INR", loss_amount=5000, notes="first contact")
    ok = (case["id"].startswith("C-") and case["status"] == "open"
          and case["scam_type"] == "upi" and case["loss_amount"] == 5000)
    failures += check("case create + metadata", ok, case["id"])

    ent = store.add_entity(case["id"], "url:bad-example.xyz")
    store.add_entity(case["id"], {"kind": "phone", "value": "+91 98765 43210"})
    detail = store.add_text(case["id"], "Pay victim@okhdfcbank now", source="sms")
    case = store.get(case["id"])
    ok = (ent["kind"] == "url" and len(case["entities"]) == 4
          and any(e["kind"] == "upi" for e in case["entities"])
          and len(case["evidence"]) == 1 and len(detail["sha256"]) == 64)
    failures += check("case entities + text evidence auto-extraction", ok,
                      [e["kind"] for e in case["entities"]])

    verify = store.verify(case["id"])
    ok = verify["ok"] and verify["evidence"][0]["ok"]
    failures += check("text evidence verifies by SHA-256", ok)

    path = os.path.join(HOME, "screenshot.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("Sender +919876543210 asks for gift cards\n")
    info = store.add_file(case["id"], path, note="chat export")
    verify = store.verify(case["id"])
    ok = (info["kind"] == "text" and os.path.isfile(info["stored"])
          and verify["ok"] and len(verify["evidence"]) == 2)
    failures += check("file evidence stored + verifies", ok, info["sha256"][:16])

    try:
        store.add_file("C-NOPE", path)
        ok = False
    except KeyError:
        ok = True
    failures += check("adding a file to a missing case fails cleanly", ok)

    # Tamper with the stored copy, verify must fail.
    with open(info["stored"], "a", encoding="utf-8") as fh:
        fh.write("tampered\n")
    verify = store.verify(case["id"])
    ok = (not verify["ok"]
          and any(not row["ok"] for row in verify["evidence"]))
    failures += check("tampered evidence is detected", ok)

    # Restore so the export pack is consistent.
    with open(info["stored"], "w", encoding="utf-8") as fh:
        fh.write("Sender +919876543210 asks for gift cards\n")
    ok = store.verify(case["id"])["ok"]
    failures += check("restored evidence verifies again", ok)

    outdir = os.path.join(HOME, "export")
    exported = store.export(case["id"], outdir)
    names = ("case.json", "case.md", "case.html", "SHA256SUMS")
    ok = (exported["case_id"] == case["id"]
          and all(os.path.isfile(os.path.join(outdir, n)) for n in names)
          and os.path.isdir(os.path.join(outdir, "evidence")))
    failures += check("case export writes JSON/MD/HTML/hashes/evidence", ok,
                      exported["outdir"])
    with open(exported["json"], "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    ok = (payload["case"]["id"] == case["id"]
          and payload["case"]["packed_evidence"])
    failures += check("export JSON includes the packed case", ok)
    with open(exported["hashes"], "r", encoding="utf-8") as fh:
        sums = fh.read()
    ok = "case.json" in sums and "evidence/" in sums
    failures += check("SHA256SUMS covers pack + evidence", ok)

    closed = store.set_status(case["id"], "closed")
    updated = store.update(case["id"], notes="bank notified", loss_amount=5100)
    ok = closed["status"] == "closed" and updated["notes"] == "bank notified"
    failures += check("case status + update", ok)
    ok = len(store.list()) >= 1 and store.count() >= 1
    failures += check("case list/count", ok)

    # ------------------------------------------------------- 3. watchlist
    watch = Watchlist()
    watch.clear()
    watch.add("upi:victim@okhdfcbank", label="mule account")
    watch.add("url:https://bad-example.com/login")
    watch.add("+91 98765 43210")
    entries = watch.list()
    ok = len(entries) == 3 and watch.count() == 3
    failures += check("watchlist add/list/count", ok, entries)

    hits = watch.match_text("Send to victim@okhdfcbank or visit bad-example.com")
    ok = len(hits) == 2 and {h["kind"] for h in hits} == {"upi", "url"}
    failures += check("watchlist matches text identifiers", ok,
                      [(h["kind"], h["value"]) for h in hits])

    watch.bump(hits)
    entries = watch.list()
    ok = all(h["hits"] == 1 and h["last_hit_ts"] for h in entries[:2])
    failures += check("watchlist hit counters", ok)
    ok = "Watchlist hit" in format_hits(hits)
    failures += check("watchlist hit formatter", ok)

    removed = watch.remove("url:bad-example.com")
    ok = removed and not watch.match_text("visit bad-example.com")
    failures += check("watchlist remove", ok)

    alias = watch.match([{"kind": "sender", "value": "+919876543210",
                          "label": "+919876543210"}])
    ok = alias and alias[0]["kind"] == "phone"
    failures += check("sender matches a watched phone number", ok)
    watch.clear()
    ok = watch.count() == 0
    failures += check("watchlist clear", ok)

    # ------------------------------------------------------- 4. campaigns
    hist = History()
    hist.clear()
    shared = "http://campaign-test.xyz/pay"
    ids = []
    for i in range(3):
        ids.append(hist.record(
            "text", "SCAM", 70 + i, "message %d %s" % (i, shared),
            identifiers=[{"kind": "url", "value": "campaign-test.xyz",
                          "label": "campaign-test.xyz"}],
        ))
    # Identical plain messages must NOT link (message hashes are excluded).
    for i in range(2):
        hist.record("text", "SUSPICIOUS", 20, "same forwarded text",
                    identifiers=[{"kind": "message", "value": "hash-%d" % i,
                                  "label": "exact message"}])
    # A second cluster via a phone number.
    for i in range(2):
        hist.record("text", "LIKELY SCAM", 50, "call +919876543210",
                    identifiers=[{"kind": "phone", "value": "+919876543210",
                                  "label": "+919876543210"}])

    built = campaigns.build_campaigns()
    sizes = sorted((c["checks"] for c in built), reverse=True)
    ok = sizes == [3, 2]
    failures += check("campaign clustering groups shared indicators", ok,
                      "sizes=%s" % sizes)

    first = next(c for c in built
                 if any(i["kind"] == "url" for i in c["indicators"]))
    ok = (first["id"].startswith("CAM-")
          and {i["kind"] for i in first["indicators"]} == {"url"})
    failures += check("campaign id + shared indicators", ok,
                      [i["kind"] for i in first["indicators"]])

    ok = campaigns.get_campaign(first["id"]) is not None
    failures += check("get_campaign by id", ok)
    ok = "Campaigns" in campaigns.format_campaigns(built)
    ok = ok and "Campaign" in campaigns.format_campaign(first)
    failures += check("campaign formatters", ok)

    # ------------------------------------------------------- 5. recovery
    ok = (recovery.get_authority("IN")["country"] == "India"
          and recovery.get_authority("zz")["code"] == "ZZ")
    failures += check("country authorities + fallback", ok)

    book = recovery.get_playbook("upi", "IN")
    ok = (book["scam_type"] == "upi"
          and any("UPI" in step or "1930" in step for step in book["now"])
          and book["authority"]["code"] == "IN")
    failures += check("recovery playbook for UPI/India", ok)

    ok = (recovery.infer_type("Your parcel has customs fee") == "courier"
          and recovery.infer_type("install AnyDesk remote access") == "tech"
          and recovery.infer_type("innocent note") == "general")
    failures += check("scam-type inference", ok)

    case = store.get(case["id"])
    draft = recovery.complaint_template(case, "IN", "upi")
    ok = (case["id"] in draft and "victim@okhdfcbank" in draft
          and "SHA-256" in draft and "1930" in draft)
    failures += check("complaint template uses case + country", ok)

    # ------------------------------------------------------- 6. CLI
    env = dict(os.environ)
    env["SCAMCHECK_HOME"] = HOME
    env["SCAMCHECK_JARVIS_AI"] = "never"
    env["PYTHONPATH"] = ROOT

    def run(*args, **kwargs):
        return subprocess.run([sys.executable, "-m", "scamcheck"] + list(args),
                              cwd=ROOT, env=env, capture_output=True, text=True,
                              timeout=90, **kwargs)

    proc = run("--version")
    ok = proc.returncode == 0 and "0.13.0" in proc.stdout
    failures += check("CLI version is 0.13.0", ok, proc.stdout.strip())

    proc = run("--case-new", "CLI fraud case", "--scam-type", "bank",
               "--country", "IN", "--currency", "INR", "--loss", "250",
               "--case-notes", "opened from CLI", "--json")
    try:
        made = json.loads(proc.stdout)
    except ValueError:
        made = {}
    ok = (proc.returncode == 0 and made.get("id", "").startswith("C-")
          and made.get("scam_type") == "bank" and made.get("loss_amount") == 250)
    failures += check("CLI --case-new --json", ok, proc.stdout[:120])
    cid = made.get("id")

    proc = run("--case-list", "--json")
    try:
        listed = json.loads(proc.stdout)
    except ValueError:
        listed = []
    ok = proc.returncode == 0 and any(c["id"] == cid for c in listed)
    failures += check("CLI --case-list --json", ok)

    evpath = os.path.join(HOME, "cli-evidence.txt")
    with open(evpath, "w", encoding="utf-8") as fh:
        fh.write("Transfer to victim@okhdfcbank now\n")
    proc = run("--case-add", cid, evpath, "--json")
    try:
        added = json.loads(proc.stdout)
    except ValueError:
        added = {}
    ok = proc.returncode == 0 and added.get("sha256")
    failures += check("CLI --case-add file", ok, proc.stdout[:120])

    proc = run("--case-entity", cid, "url:cli-bad.xyz")
    failures += check("CLI --case-entity", proc.returncode == 0, proc.stdout.strip())
    proc = run("--case-note", cid, "bank reference 123")
    failures += check("CLI --case-note", proc.returncode == 0, proc.stdout.strip())

    proc = run("--case-verify", cid, "--json")
    try:
        verified = json.loads(proc.stdout)
    except ValueError:
        verified = {}
    ok = proc.returncode == 0 and verified.get("ok") is True
    failures += check("CLI --case-verify", ok)

    packdir = os.path.join(HOME, "cli-pack")
    proc = run("--case-export", cid, "--case-out", packdir, "--json")
    try:
        packed = json.loads(proc.stdout)
    except ValueError:
        packed = {}
    ok = (proc.returncode == 0 and packed.get("case_id") == cid
          and os.path.isfile(os.path.join(packdir, "case.html")))
    failures += check("CLI --case-export", ok, packed.get("outdir"))

    proc = run("--watch-add", "upi:victim@okhdfcbank")
    failures += check("CLI --watch-add", proc.returncode == 0, proc.stdout.strip())

    proc = run("--watchlist", "--json")
    try:
        watch_rows = json.loads(proc.stdout)
    except ValueError:
        watch_rows = []
    ok = proc.returncode == 0 and any(
        row["kind"] == "upi" and row["value"] == "victim@okhdfcbank"
        for row in watch_rows)
    failures += check("CLI --watchlist --json", ok)

    proc = run("Pay victim@okhdfcbank now", "--ai", "never", "--json")
    try:
        result = json.loads(proc.stdout)
    except ValueError:
        result = {}
    ok = (proc.returncode in (0, 1, 2)
          and any(h["value"] == "victim@okhdfcbank"
                  for h in result.get("watchlist") or []))
    failures += check("CLI JSON reports watchlist hits", ok,
                      result.get("watchlist"))

    proc = run("Pay victim@okhdfcbank now", "--ai", "never", "--json")
    ok = proc.returncode in (0, 1, 2) and proc.stdout.strip().startswith("{")
    failures += check("CLI JSON stdout stays machine-readable", ok)

    proc = run("--recover", "crypto", "--country", "IN", "--json")
    try:
        playbook = json.loads(proc.stdout)
    except ValueError:
        playbook = {}
    ok = (proc.returncode == 0 and playbook.get("scam_type") == "crypto"
          and playbook.get("authority", {}).get("code") == "IN")
    failures += check("CLI --recover --json", ok)

    proc = run("--report", cid, "--country", "IN", "--json")
    try:
        report = json.loads(proc.stdout)
    except ValueError:
        report = {}
    ok = proc.returncode == 0 and cid in report.get("text", "")
    failures += check("CLI --report --json", ok)

    report_path = os.path.join(HOME, "complaint.txt")
    proc = run("--report", cid, "--country", "IN", "--report-out", report_path)
    ok = proc.returncode == 0 and os.path.isfile(report_path)
    if ok:
        with open(report_path, "r", encoding="utf-8") as fh:
            ok = cid in fh.read()
    failures += check("CLI --report-out writes the draft", ok)

    proc = run("--campaigns", "--json")
    try:
        camps = json.loads(proc.stdout)
    except ValueError:
        camps = []
    ok = proc.returncode == 0 and len(camps) >= 2
    failures += check("CLI --campaigns --json", ok, len(camps))

    proc = run("--campaign", camps[0]["id"], "--json") if camps else None
    ok = proc is not None and proc.returncode == 0
    failures += check("CLI --campaign --json", ok)

    # ------------------------------------------------------- 7. JARVIS routes
    s = JarvisSession(voice=False, notify=False, lang="en", region="IN")
    help_text = s.handle("help")["text"]
    ok = all(word in help_text for word in
             ("case ...", "watch <KIND:VALUE>", "campaigns", "recover", "report"))
    failures += check("JARVIS help lists v0.10 commands", ok)

    status = s.handle("status")["text"]
    ok = "Cases:" in status and "Watchlist:" in status
    failures += check("JARVIS status reports cases/watchlist", ok,
                      status.splitlines()[-5:-3])

    new = s.handle("case new JARVIS case")["text"]
    jid = None
    for token in new.replace(",", " ").split():
        if token.startswith("C-"):
            jid = token
            break
    ok = jid is not None and "Opened case" in new
    failures += check("JARVIS case new", ok, new.splitlines()[0] if new else "")

    shown = s.handle("case show " + (jid or ""))["text"]
    ok = (jid or "") in shown and "Evidence" in shown
    failures += check("JARVIS case show", ok)

    failures += check("JARVIS case note",
                      "Note added" in s.handle("case note %s called bank" % jid)["text"])
    failures += check("JARVIS case entity",
                      "Added" in s.handle("case entity %s url:jarvis-bad.xyz" % jid)["text"])
    failures += check("JARVIS case verify",
                      "OK" in s.handle("case verify " + jid)["text"])
    exported = s.handle("case export %s %s" % (jid, os.path.join(HOME, "jarvis-pack")))["text"]
    failures += check("JARVIS case export", "exported" in exported, exported.splitlines()[0])

    ok = "Watching" in s.handle("watch upi:jarvis@okhdfcbank")["text"]
    failures += check("JARVIS watch add", ok)
    ok = "jarvis@okhdfcbank" in s.handle("watchlist")["text"]
    failures += check("JARVIS watchlist", ok)
    check_text = s.handle("check Pay jarvis@okhdfcbank now")["text"]
    ok = "Watchlist hit" in check_text
    failures += check("JARVIS check reports watchlist hit", ok)
    failures += check("JARVIS unwatch",
                      "Removed" in s.handle("unwatch upi:jarvis@okhdfcbank")["text"])

    rec = s.handle("recover upi")["text"]
    ok = "Recovery plan" in rec and "India" in rec
    failures += check("JARVIS recover", ok)

    rep = s.handle("report " + jid)["text"]
    ok = jid in rep and "Fraud complaint" in rep
    failures += check("JARVIS report", ok)

    camps_text = s.handle("campaigns")["text"]
    ok = "Campaigns" in camps_text
    failures += check("JARVIS campaigns", ok)
    if camps:
        shown_camp = s.handle("campaign " + camps[0]["id"])["text"]
        ok = camps[0]["id"] in shown_camp
        failures += check("JARVIS campaign detail", ok)

    print()
    print("FAILED: %d checks" % failures if failures else "All checks passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
