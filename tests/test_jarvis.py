#!/usr/bin/env python3
"""JARVIS core tests: memory, intents, tools, voice/notify hooks, CLI.

Everything is local. Link investigation is exercised against a local HTTP
redirect server with `allow_private=True`; QR generation uses macOS CoreImage
and the test skips that check cleanly if it is unavailable.

Run: python3 tests/test_jarvis.py
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

HOME = tempfile.mkdtemp(prefix="scamcheck-jarvis-")
os.environ["SCAMCHECK_HOME"] = HOME
os.environ["SCAMCHECK_REGION"] = "IN"
os.environ["SCAMCHECK_JARVIS_AI"] = "never"
os.environ.pop("OPENAI_API_KEY", None)
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("SCAMCHECK_ANNOUNCE_ALL", None)
os.environ.pop("SCAMCHECK_SAY_CMD", None)

from scamcheck import jarvis, netintel          # noqa: E402
from scamcheck.cli import watch_args            # noqa: E402
from scamcheck.jarvis import History, JarvisSession  # noqa: E402
from make_png import render                    # noqa: E402


def check(name, ok, detail=""):
    print("[%s] %s" % ("PASS" if ok else "FAIL", name))
    if detail:
        print("      " + str(detail))
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_png(text, name, scale=6):
    path = os.path.join(HOME, name)
    render(text, path, scale=scale)
    return path


QR_JS = """
ObjC.import('CoreImage')
ObjC.import('AppKit')
ObjC.import('Foundation')
function run(argv) {
  var out = argv[0], msg = argv[1]
  var data = $(msg).dataUsingEncoding($.NSUTF8StringEncoding)
  var filter = $.CIFilter.filterWithName('CIQRCodeGenerator')
  if (!filter) return 'no-filter'
  filter.setValueForKey(data, $('inputMessage'))
  filter.setValueForKey($('M'), $('inputCorrectionLevel'))
  var img = filter.outputImage.imageByApplyingTransform($.CGAffineTransformMakeScale(12, 12))
  var rep = $.NSBitmapImageRep.alloc.initWithCIImage(img)
  var png = rep.representationUsingTypeProperties($.NSBitmapImageFileTypePNG, $.NSDictionary.dictionary)
  return png.writeToFileAtomically(out, true) ? 'ok' : 'write-failed'
}
"""


def make_qr(payload, name="qr.png"):
    path = os.path.join(HOME, name)
    script = os.path.join(HOME, "make-qr.js")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write(QR_JS)
    try:
        proc = subprocess.run(
            ["osascript", "-l", "JavaScript", script, path, payload],
            capture_output=True, timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not os.path.isfile(path):
        return None
    return path


class RedirectHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"<html><head><title>Fake Bank Login</title></head><body>verify</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_redirect_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:%d/start" % server.server_address[1]


def main():
    failures = 0

    # ------------------------------------------------------- 1. history API
    hist = History()
    ids = [{"kind": "url", "value": "history-test.xyz", "label": "history-test.xyz"}]
    hist.record("text", "SCAM", 71, "URGENT bank suspended", identifiers=ids)
    hits = hist.seen_before(ids)
    ok = (len(hits) == 1 and hits[0]["count"] == 1
          and hits[0]["verdict"] == "SCAM"
          and stat.S_IMODE(os.stat(hist.path).st_mode) == 0o600)
    failures += check("history record + seen_before + 0600", ok,
                      "hits=%r mode=%o" % (hits, stat.S_IMODE(os.stat(hist.path).st_mode)))

    hist.record("text", "SUSPICIOUS", 20, "second", identifiers=ids)
    hits = History().seen_before(ids)
    ok = len(hits) == 1 and hits[0]["count"] == 2 and hist.search("history-test")
    failures += check("history persists and searches across instances", ok,
                      "count=%s" % (hits[0]["count"] if hits else "?"))
    print()

    # ------------------------------------------------------- 2. intents
    s = JarvisSession(voice=False, notify=False, lang="en", region="IN")
    ok = ("image <path>" in s.handle("help")["text"]
          and "url <link>" in s.handle("help")["text"])
    failures += check("help lists the toolset", ok)

    status = s.handle("status")["text"]
    ok = "JARVIS core" in status and "Memory:" in status and "AI:        never" in status
    failures += check("status reports engines and memory", ok,
                      status.splitlines()[:2])

    failures += check("voice toggle", "on" in s.handle("voice on")["text"] and s.voice)
    failures += check("notify toggle", "off" in s.handle("notify off")["text"] and not s.notify)
    failures += check("language toggle", "हिंदी" in s.handle("lang hi")["text"] and s.lang == "hi")
    hindi = s.check_text("Hi mom, reached safely. Love you.")["text"]
    ok = "संभवतः" in hindi or "सुरक्षित" in hindi
    failures += check("Hindi reply path", ok, hindi.splitlines()[0] if hindi else "")
    s.handle("lang en")
    failures += check("region command", s.handle("region IN")["text"].startswith("Region set"))

    saved = s.handle("sender +91 98765 43210")["text"]
    shown = s.handle("sender")["text"]
    cleared = s.handle("sender off")["text"]
    ok = "Sender set" in saved and "98765" in shown and "cleared" in cleared
    failures += check("sender attach/clear", ok, shown)
    print()

    # ------------------------------------------------------- 3. text + memory
    scam = ("URGENT: Your bank account is suspended. Verify now at "
            "bit.ly/hdfc-alert. Do not tell anyone.")
    reply = s.handle("check " + scam)
    text = reply["text"]
    ok = (reply["result"]["final_verdict"] in ("LIKELY SCAM", "SCAM")
          and "Why:" in text and "bit.ly" in text
          and "New to me" in text and "scamcheck" in text)
    failures += check("check text -> verdict + reasons + new-memory note", ok,
                      text.splitlines()[0] if text else "")

    why = s.handle("why")["text"]
    ok = "Signals:" in why and "Shortened URL" in why
    failures += check("why explains the last check", ok)

    rows = s.handle("history")["text"]
    ok = "Recent checks" in rows and "SCAM" in rows
    failures += check("history lists the check", ok)

    found = s.handle("search hdfc")["text"]
    ok = "hdfc" in found.lower()
    failures += check("search finds remembered text", ok)

    repeat = ("KYC alert: verify your account at http://repeat-%d.xyz/login" % os.getpid())
    first = s.handle("check " + repeat)["text"]
    second = s.handle("check " + repeat)["text"]
    ok = ("New to me" in first and "repeat-%d.xyz" % os.getpid() in first
          and "Seen before" in second
          and "this exact message" in second
          and "repeat-%d.xyz" % os.getpid() in second)
    failures += check("repeat check uses memory", ok,
                      second.splitlines()[-3:] if second else "")
    print()

    # ------------------------------------------------------- 4. number tools
    premium = s.handle("number +1 900 555 1234")["text"]
    ok = "premium-rate" in premium and "Number:" in premium
    failures += check("premium number is flagged", ok, premium.splitlines()[:3])

    blocked = s.handle("block +91 98765 43210 KYC scam")["text"]
    after = s.handle("number +91 98765 43210")["text"]
    ok = "Blocked" in blocked and "ON YOUR BLOCKLIST" in after
    failures += check("block affects number checks", ok,
                      "blocked=%r verdict=%r" % (blocked, after.splitlines()[0]))

    s.handle("allow +91 98765 43210 trusted bank")
    allowed = s.handle("number +91 98765 43210")["text"]
    s.handle("forget +91 98765 43210")
    ok = "on your allowlist" in allowed
    failures += check("allowlist wins over blocklist", ok,
                      allowed.splitlines()[1] if allowed else "")
    print()

    # ------------------------------------------------------- 5. link intel
    server, url = start_redirect_server()
    try:
        denied = netintel.investigate_url(url, want_rdap=False)
        report = s.check_url(url, allow_private=True)
        body = report["text"]
        ok = (denied["ok"] is False and "private" in denied["error"]
              and report["report"]["ok"]
              and "Redirects: 1" in body
              and "Fake Bank Login" in body
              and "not HTTPS" in body
              and report["report"]["chain"][0]["status"] == 302)
        failures += check("local redirect + private-address refusal", ok,
                          body.splitlines()[:4])
        why = s.handle("why")["text"]
        ok = "Link verdict" in why and "not HTTPS" in why
        failures += check("why explains a link report", ok)
        hits = s.history.search("127.0.0.1")
        failures += check("link hosts are remembered", bool(hits), "rows=%d" % len(hits))
    finally:
        server.shutdown()
        server.server_close()
    print()

    # ------------------------------------------------------- 6. image + QR
    shot = make_png("URGENT: your bank account is suspended. "
                    "Verify now at bit.ly/hdfc-alert", "shot.png")
    image_reply = s.check_image(shot)
    ok = (image_reply.get("result")
          and image_reply["result"]["ocr"]
          and image_reply["result"]["final_verdict"] in ("LIKELY SCAM", "SCAM")
          and "Read with" in image_reply["text"])
    failures += check("screenshot -> OCR -> verdict", ok,
                      (image_reply.get("result") or {}).get("final_verdict"))

    blank = make_png("", "blank.png", scale=4)
    blank_reply = s.check_image(blank)["text"]
    ok = "couldn't read" in blank_reply.lower()
    failures += check("blank image fails gracefully", ok, blank_reply)

    qr_payload = "https://qr-test-%d.example/kyc" % os.getpid()
    qr_path = make_qr(qr_payload)
    if qr_path:
        qr_reply = s.check_image(qr_path)
        result = qr_reply.get("result") or {}
        ok = (qr_reply["text"].find("QR:") >= 0
              and result.get("qr")
              and result["qr"][0]["payload"] == qr_payload
              and qr_payload in (result.get("message") or ""))
        failures += check("QR-only image -> payload -> analysis", ok,
                          (result.get("qr") or [{}])[0])
        qr_only = s.check_qr(qr_path)["text"]
        ok = qr_payload in qr_only and "offline" in qr_only
        failures += check("qr command decodes without analysis", ok, qr_only)
    else:
        print("[SKIP] QR generation unavailable (CoreImage/osascript)")

    missing = s.check_image(os.path.join(HOME, "nope.png"))["text"]
    failures += check("missing image is a clean error", "No image at" in missing)

    from scamcheck import ocr as ocr_mod
    old_text, old_image = ocr_mod.get_clipboard_text, ocr_mod.get_clipboard_image
    ocr_mod.get_clipboard_text = lambda: ("URGENT: KYC expired, verify at bit.ly/paste-check")
    ocr_mod.get_clipboard_image = lambda: None
    try:
        pasted = s.handle("paste")["text"]
        ok = "Clipboard text" in pasted and "LIKELY SCAM" in pasted.upper()
        failures += check("paste checks clipboard text", ok,
                          pasted.splitlines()[:2])
    finally:
        ocr_mod.get_clipboard_text, ocr_mod.get_clipboard_image = old_text, old_image
    print()

    # ------------------------------------------------------- 7. voice/notify
    say_log = os.path.join(HOME, "say.log")
    say_cmd = os.path.join(HOME, "fake-say.sh")
    with open(say_cmd, "w", encoding="utf-8") as fh:
        fh.write('#!/bin/sh\nprintf "%s\\n" "$*" >> "$SCAMCHECK_SAY_LOG"\n')
    os.chmod(say_cmd, 0o755)
    os.environ["SCAMCHECK_SAY_CMD"] = say_cmd
    os.environ["SCAMCHECK_SAY_LOG"] = say_log
    failures += check("speak uses the configured command", jarvis.speak("hello there"),
                      open(say_log).read().strip() if os.path.exists(say_log) else "")

    calls = []
    original_notify = jarvis.notify
    jarvis.notify = lambda title, body: calls.append((title, body)) or True
    try:
        v = JarvisSession(voice=True, notify=True, lang="en", region="IN")
        if os.path.exists(say_log):
            os.unlink(say_log)
        v.check_text("Hi mom, reached safely. Love you.")
        safe_spoken = open(say_log).read().splitlines() if os.path.exists(say_log) else []
        v.check_text("URGENT: account suspended, verify at bit.ly/voice-test")
        spoken = open(say_log).read().splitlines() if os.path.exists(say_log) else []
        ok = (not safe_spoken and len(spoken) == 1
              and "Likely" in spoken[0] and calls
              and "scamcheck" in calls[0][0])
        failures += check("voice/notify fire for risky results only", ok,
                          "spoken=%r notify=%r" % (spoken, calls[:1]))
    finally:
        jarvis.notify = original_notify
        os.environ.pop("SCAMCHECK_SAY_CMD", None)
        os.environ.pop("SCAMCHECK_SAY_LOG", None)
    print()

    # ------------------------------------------------------- 8. history clear
    cleared = s.handle("history clear")["text"]
    ok = "cleared" in cleared.lower() and s.history.count() == 0
    failures += check("history clear wipes memory", ok, cleared)

    # ------------------------------------------------------- 9. CLI
    cli_home = os.path.join(HOME, "cli-home")
    os.makedirs(cli_home)
    env = dict(os.environ)
    env["SCAMCHECK_HOME"] = cli_home
    env["SCAMCHECK_JARVIS_AI"] = "never"
    env.pop("SCAMCHECK_SAY_CMD", None)
    env.pop("SCAMCHECK_ANNOUNCE_ALL", None)
    proc = subprocess.run(
        [sys.executable, "-m", "scamcheck", "--jarvis"],
        cwd=ROOT, env=env, input="help\ncheck URGENT: bank account suspended, "
        "verify at bit.ly/cli-test\nhistory\nquit\n",
        capture_output=True, text=True, timeout=90,
    )
    ok = (proc.returncode == 0
          and "check <text>" in proc.stdout
          and "SCAM" in proc.stdout.upper()
          and "Recent checks" in proc.stdout
          and "Traceback" not in proc.stderr)
    failures += check("CLI --jarvis reads piped commands", ok,
                      "rc=%d out=%d err=%s" % (
                          proc.returncode, len(proc.stdout), proc.stderr[-120:]))

    if qr_path:
        proc = subprocess.run(
            [sys.executable, "-m", "scamcheck", "--image", qr_path, "--json"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=90,
        )
        try:
            data = json.loads(proc.stdout)
            ok = (proc.returncode == 0 and data.get("qr")
                  and data["qr"][0]["payload"] == qr_payload
                  and "QR code" in data.get("message", ""))
        except ValueError:
            data, ok = {}, False
        failures += check("CLI --image carries QR payloads into JSON", ok,
                          "rc=%d qr=%r" % (proc.returncode, (data.get("qr") or [None])[0]))

    # ------------------------------------------------------- 10. watch AI clamp
    import argparse
    try:
        os.environ.pop("SCAMCHECK_WATCH_AI", None)
        cases = []
        for label, ai, env, expected in [
            ("default local", "auto", None, "never"),
            ("explicit never", "never", None, "never"),
            ("watch auto opt-in", "auto", "auto", "auto"),
            ("watch always opt-in", "auto", "always", "always"),
            ("bogus falls back", "auto", "yes", "never"),
        ]:
            if env is None:
                os.environ.pop("SCAMCHECK_WATCH_AI", None)
            else:
                os.environ["SCAMCHECK_WATCH_AI"] = env
            got = watch_args(argparse.Namespace(ai=ai)).ai
            cases.append((label, got, expected))
        ok = all(got == expected for _l, got, expected in cases)
        failures += check("watch AI is local unless explicitly opted in", ok,
                          ", ".join("%s=%s" % (l, g) for l, g, _e in cases))
    finally:
        os.environ.pop("SCAMCHECK_WATCH_AI", None)

    print()
    print("FAILED: %d checks" % failures if failures else "All checks passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
