#!/usr/bin/env python3
"""Phone-number intelligence tests: normalization, lists, feeds, CLI, API.

Everything is local: the feed test runs its own 127.0.0.1 HTTP server.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

HOME = tempfile.mkdtemp(prefix="scamcheck-phones-")
os.environ["SCAMCHECK_HOME"] = HOME

from scamcheck import phones  # noqa: E402
from scamcheck.analyzer import analyze  # noqa: E402


def check(name, ok, detail=""):
    print("[%s] %s" % ("PASS" if ok else "FAIL", name))
    if detail:
        print("      " + detail)
    return 0 if ok else 1


def reset_home():
    shutil.rmtree(HOME, ignore_errors=True)
    os.makedirs(HOME, exist_ok=True)


def run_cli(*args, **kwargs):
    env = dict(os.environ)
    env["SCAMCHECK_HOME"] = HOME
    env.pop("OPENAI_API_KEY", None)
    env.pop("ANTHROPIC_API_KEY", None)
    return subprocess.run(
        [sys.executable, "-m", "scamcheck"] + list(args),
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=60,
    )


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def main():
    failures = 0
    reset_home()

    # ---------------------------------------------------------------- 1. parse
    cases = [
        ("+91 98765 43210", "IN", "+919876543210", "mobile", True),
        ("09876543210", "IN", "+919876543210", "mobile", True),
        ("919876543210", "IN", "+919876543210", "mobile", True),
        ("+1 415 555 2671", "IN", "+14155552671", "fixed_or_mobile", True),
        ("+44 20 7946 0958", "IN", "+442079460958", "fixed", True),
        ("+91 1900 221234", "IN", "+911900221234", "premium", True),
        ("+1 900 555 1234", "IN", "+19005551234", "premium", True),
        ("+61 1902 123 456", "IN", "+611902123456", "premium", True),
        ("57575", "IN", None, "shortcode", True),
        ("VM-HDFCBK", "IN", None, "sender_id", True),
        ("123", "IN", None, "invalid", False),
        ("+999 123456789", "IN", None, "invalid", False),
    ]
    bad = []
    for raw, region, e164, kind, valid in cases:
        info = phones.normalize_number(raw, region)
        if (info["e164"], info["kind"], info["valid"]) != (e164, kind, valid):
            bad.append("%r -> %s/%s/%s (want %s/%s/%s)" % (
                raw, info["e164"], info["kind"], info["valid"], e164, kind, valid))
    failures += check("normalize international, national, shortcode, sender ID",
                      not bad, "; ".join(bad) or "%d cases" % len(cases))
    print()

    # ------------------------------------------------------------ 2. extraction
    text = "Call 1900 22 1234 or +91 98765 43210 now."
    found = [n["e164"] for n in phones.extract_numbers(text)]
    noise = ("Your OTP is 482913. Amount Rs 5,000, order number 1234567890, "
             "account number 9988776655, year 2026. PIN 7788, ref 998877665544332211.")
    noisy = phones.extract_numbers(noise)
    failures += check("extract numbers from text (premium + international)",
                      found == ["+911900221234", "+919876543210"], str(found))
    failures += check("extraction ignores OTPs, amounts, order IDs",
                      not noisy, str([n["e164"] for n in noisy]))
    contextual = phones.extract_numbers("WhatsApp me on 9876543210", region="IN")
    failures += check("extraction keeps a national number with phone context",
                      len(contextual) == 1 and contextual[0]["e164"] == "+919876543210",
                      str([n["e164"] for n in contextual]))
    print()

    # --------------------------------------------------------- 3. local lists
    phones.add_block("+1 415 555 2671", "robocall")
    intel = phones.check_number("+1 415 555 2671")
    ok = (intel["reputation"]["status"] == "blocked"
          and intel["risk"] == "high" and "on your blocklist" in intel["flags"])
    failures += check("blocklist hit -> high risk", ok,
                      "%s / %s" % (intel["reputation"]["status"], intel["risk"]))

    phones.add_allow("+14155552671", "my doctor")
    intel = phones.check_number("+1 415 555 2671")
    ok = intel["reputation"]["status"] == "allowed" and intel["risk"] == "none"
    failures += check("allowlist wins over blocklist", ok,
                      intel["reputation"]["status"])

    removed = phones.forget_number("+1 415 555 2671")
    intel = phones.check_number("+1 415 555 2671")
    ok = removed == 2 and intel["reputation"]["status"] == "unknown"
    failures += check("forget removes from both lists", ok,
                      "removed=%d status=%s" % (removed, intel["reputation"]["status"]))

    try:
        phones.add_block("not-a-number")
        raised = False
    except ValueError:
        raised = True
    failures += check("invalid number is rejected by --block", raised)
    print()

    # ------------------------------------------------------------ 4. import
    txt_path = os.path.join(HOME, "import.txt")
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write("# comment line\n+91 98111 11111, courier scam\n"
                 "garbage\n\n+91 98222 22222\n")
    report = phones.import_list(txt_path, target="block")
    ok = (report["imported"] == 2 and report["skipped"] == 1)
    failures += check("import TXT list", ok, json.dumps(report))

    csv_path = os.path.join(HOME, "import.csv")
    with open(csv_path, "w", encoding="utf-8") as fh:
        fh.write("number,label,reports\n+91 98333 33333,loan spam,7\n"
                 "+1 415 555 0999,other,2\n")
    report = phones.import_list(csv_path, target="allow")
    lists = phones.list_numbers()
    ok = (report["imported"] == 2
          and "+919833333333" in lists["allowed"]
          and "+14155550999" in lists["allowed"])
    failures += check("import CSV into allowlist", ok, json.dumps(report))
    print()

    # -------------------------------------------------------------- 5. feeds
    feed_dir = os.path.join(HOME, "feed-server")
    os.makedirs(feed_dir)
    with open(os.path.join(feed_dir, "numbers.csv"), "w", encoding="utf-8") as fh:
        fh.write("number,label,reports\n+91 98765 43210,kyc scam,4\n"
                 "+1 415 555 2671,robocall,2\n")
    with open(os.path.join(feed_dir, "numbers.txt"), "w", encoding="utf-8") as fh:
        fh.write("+91 98123 45678\n")

    server = ThreadingHTTPServer(("127.0.0.1", 0), lambda *a, **kw: QuietHandler(
        *a, directory=feed_dir, **kw))
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        with open(phones.feeds_conf_path(), "w", encoding="utf-8") as fh:
            fh.write("# test feeds\n"
                     "http://127.0.0.1:%d/numbers.csv | test csv | csv\n"
                     "http://127.0.0.1:%d/numbers.txt | test txt | txt\n" % (port, port))
        report = phones.update_feeds(region="IN")
        ok = (report["configured"] == 2
              and all(s["ok"] for s in report["sources"])
              and phones.feed_status()["sources"][0]["count"] >= 1)
        failures += check("update feeds from local HTTP (opt-in)", ok,
                          json.dumps([(s["label"], s["ok"], s.get("count")) for s in report["sources"]]))

        intel = phones.check_number("+91 98765 43210")
        ok = (intel["reputation"]["status"] == "reported"
              and intel["reputation"]["reports"] == 4
              and intel["risk"] == "medium")
        failures += check("cached feed hit -> reported / medium risk", ok,
                          json.dumps(intel["reputation"], ensure_ascii=False))

        # a broken source must not wipe the good cached entries
        with open(phones.feeds_conf_path(), "w", encoding="utf-8") as fh:
            fh.write("http://127.0.0.1:%d/missing.csv | broken | csv\n" % port)
        report = phones.update_feeds(region="IN")
        still = phones.check_number("+91 98765 43210")
        ok = (not report["sources"][0]["ok"]
              and still["reputation"]["status"] == "reported")
        failures += check("failed refresh keeps the previous cache", ok,
                          "error=%r still=%s" % (report["sources"][0].get("error"),
                                                 still["reputation"]["status"]))

        failures += check("non-HTTPS remote feed is refused",
                          not phones._url_allowed("http://example.com/list.csv")
                          and phones._url_allowed("https://example.com/list.csv")
                          and phones._url_allowed("http://127.0.0.1:9/x"))
    finally:
        server.shutdown()
        server.server_close()
    print()

    # ------------------------------------------------------- 6. analyzer blend
    reset_home()
    phones.add_block("+1 415 555 2671", "robocall")
    result = analyze("Hi, is this the right number?", sender="+1 415 555 2671",
                     use_ai="never", region="IN")
    ok = (result["final_verdict"] == "LIKELY SCAM"
          and result["score"] >= 45
          and result["number"]["sender"]["reputation"]["status"] == "blocked")
    failures += check("blocked sender floors a harmless message at LIKELY SCAM", ok,
                      "%s %d" % (result["final_verdict"], result["score"]))

    phones.add_allow("+14155552671", "my doctor")
    result = analyze("Hi, is this the right number?", sender="+1 415 555 2671",
                     use_ai="never", region="IN")
    ok = result["final_verdict"] == "LIKELY SAFE"
    failures += check("allowlisted sender does not raise the verdict", ok,
                      result["final_verdict"])

    result = analyze("Call this number for your refund: +91 1900 22 1234",
                     use_ai="never", region="IN")
    ok = (result["number"]["mentioned"]
          and result["number"]["mentioned"][0]["number"]["kind"] == "premium"
          and any("premium" in lbl.lower() for lbl, _ in result["reasons"]))
    failures += check("premium-rate number in the message adds a signal", ok,
                      str(result["reasons"][:2]))

    result = analyze("Your HDFC KYC is expiring. Pay Rs 499 today.",
                     sender="+1 415 555 2671", use_ai="never", region="IN")
    ok = any("country" in lbl.lower() for lbl, _ in result["reasons"])
    failures += check("foreign sender + local bank cue -> country mismatch", ok,
                      str(result["reasons"][:3]))
    print()

    # ---------------------------------------------------------- 7. CLI / batch
    reset_home()
    phones.add_block("+91 98765 43210", "kyc scam")
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write("# comment line\n+91 98111 11111, courier scam\n"
                 "garbage\n\n+91 98222 22222\n")
    proc = run_cli("--number", "+91 98765 43210")
    failures += check("CLI --number blocked -> exit 2", proc.returncode == 2,
                      "rc=%d %s" % (proc.returncode, proc.stdout.strip().splitlines()[:1]))

    proc = run_cli("--number", "+1 900 555 1234", "--json")
    data = json.loads(proc.stdout)
    ok = proc.returncode == 1 and data["risk"] == "medium"
    failures += check("CLI --number premium -> exit 1 + JSON", ok,
                      "rc=%d risk=%s" % (proc.returncode, data.get("risk")))

    proc = run_cli("--block", "+91 98111 11111", "--label", "courier")
    ok = proc.returncode == 0 and "+919811111111" in \
        open(phones._path("blocklist.txt"), encoding="utf-8").read()
    failures += check("CLI --block writes the local list", ok, proc.stdout.strip())

    batch = os.path.join(HOME, "batch.txt")
    with open(batch, "w", encoding="utf-8") as fh:
        fh.write("From: +91 98765 43210\nHi, is this the right number?\n\n"
                 "From: +91 90000 00001\nHi mom, reached safely.\n")
    proc = run_cli("--batch", batch, "--region", "IN")
    ok = (proc.returncode == 1 and "LIKELY SCAM" in proc.stdout
          and "sender blocked" in proc.stdout)
    failures += check("batch auto-detects 'From:' sender lines", ok,
                      "rc=%d\n%s" % (proc.returncode, proc.stdout))

    proc = run_cli("--import-list", txt_path, "--json")
    data = json.loads(proc.stdout)
    failures += check("CLI --import-list --json", proc.returncode == 0 and data["imported"] == 2,
                      json.dumps(data))
    print()

    # ------------------------------------------------------------- 8. API
    from scamcheck.api import make_server

    server = make_server("127.0.0.1", 0)
    port = server.server_address[1]
    base = "http://127.0.0.1:%d" % port
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def post(path, payload):
        req = urllib.request.Request(
            base + path, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    try:
        status, data = post("/v1/check-number", {"number": "+91 98765 43210"})
        ok = (status == 200 and data["risk"] == "high"
              and data["reputation"]["status"] == "blocked")
        failures += check("POST /v1/check-number", ok, "status=%d risk=%s" % (status, data.get("risk")))

        status, data = post("/v1/check-number", {"number": "123"})
        failures += check("POST /v1/check-number rejects junk", status == 400,
                          "status=%d" % status)

        status, data = post("/v1/analyze", {
            "text": "Hi, is this the right number?", "sender": "+91 98765 43210"})
        ok = (status == 200 and data["final_verdict"] == "LIKELY SCAM"
              and data["number"]["sender"]["reputation"]["status"] == "blocked")
        failures += check("POST /v1/analyze honors 'sender'", ok,
                          "status=%d verdict=%s" % (status, data.get("final_verdict")))
    finally:
        server.shutdown()
        server.server_close()
    print()

    print("FAILED: %d checks" % failures if failures else "All checks passed.")
    shutil.rmtree(HOME, ignore_errors=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
