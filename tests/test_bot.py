#!/usr/bin/env python3
"""Bot tests: reply formatting, commands, rate limit, Telegram + WhatsApp adapters.

Both adapters talk to local fake APIs; nothing leaves the machine.
"""

import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

HOME = tempfile.mkdtemp(prefix="scamcheck-bot-")
os.environ["SCAMCHECK_HOME"] = HOME
os.environ["SCAMCHECK_REGION"] = "IN"
os.environ.pop("OPENAI_API_KEY", None)
os.environ.pop("ANTHROPIC_API_KEY", None)

from scamcheck import bot, phones  # noqa: E402
from scamcheck.analyzer import analyze  # noqa: E402
from make_png import render  # noqa: E402


def check(name, ok, detail=""):
    print("[%s] %s" % ("PASS" if ok else "FAIL", name))
    if detail:
        print("      " + str(detail))
    return 0 if ok else 1


def make_png_bytes(text):
    fd, path = tempfile.mkstemp(suffix=".png")
    os.close(fd)
    render(text, path, scale=6)
    try:
        with open(path, "rb") as fh:
            return fh.read()
    finally:
        os.unlink(path)


class Quiet(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass


def json_body(handler):
    length = int(handler.headers.get("Content-Length", 0))
    return json.loads(handler.rfile.read(length) or b"{}")


def send_json(handler, obj, code=200):
    raw = json.dumps(obj).encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


# ---------------------------------------------------------------------------
# Fake Telegram API
# ---------------------------------------------------------------------------

class FakeTelegram(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        state = self.server.state
        path = urlparse(self.path).path
        if path.endswith("/getUpdates"):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            send_json(self, {"ok": True, "result": state["updates"]})
        elif path.endswith("/getFile"):
            send_json(self, {"ok": True, "result": {"file_path": "photos/shot.png"}})
        elif path.endswith("/sendMessage"):
            state["sent"].append(json_body(self))
            send_json(self, {"ok": True, "result": {}})
        else:
            send_json(self, {"ok": False, "description": "unknown"}, 404)

    def do_GET(self):
        if urlparse(self.path).path.startswith("/file/bot"):
            raw = self.server.state["png"]
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        else:
            self.send_response(404)
            self.end_headers()


def start_fake_telegram(updates, png):
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeTelegram)
    server.state = {"updates": updates, "sent": [], "png": png}
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


# ---------------------------------------------------------------------------
# Fake WhatsApp Graph API
# ---------------------------------------------------------------------------

class FakeGraph(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        state = self.server.state
        path = urlparse(self.path).path
        if path == "/media123":
            send_json(self, {"url": state["base"] + "/blob"})
        elif path == "/blob":
            raw = state["png"]
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        state = self.server.state
        payload = json_body(self)
        state["sent"].append(payload)
        send_json(self, {"messages": [{"id": "out"}]})


def start_fake_graph(png):
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeGraph)
    base = "http://127.0.0.1:%d" % server.server_address[1]
    server.state = {"sent": [], "png": png, "base": base}
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, base


def wait_for(predicate, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


def http(method, url, payload=None, headers=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=headers or {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def main():
    failures = 0
    bot.reset_rate_limit()

    # ------------------------------------------------------- 1. reply format
    scam = analyze("Congratulations! You have won a $500,000 lottery. "
                   "Send a $2000 processing fee via UPI to claim now.",
                   use_ai="never")
    reply = bot.format_reply(scam, "en")
    ok = ("/100" in reply and "advice" not in reply.lower()
          and "Why" in reply and "scamcheck" in reply)
    failures += check("format_reply (English)", ok, reply.splitlines()[:3])

    hindi = bot.format_reply(scam, "hi")
    failures += check("format_reply (Hindi)", "कारण" in hindi and "ठगी" in hindi,
                      hindi.splitlines()[:2])
    print()

    # ------------------------------------------------------- 2. commands
    bot.reset_rate_limit()
    help_text = bot.handle_message(101, "/help")
    ok = "/lang" in help_text and "/sender" in help_text
    failures += check("/help lists commands", ok)

    set_hi = bot.handle_message(101, "/lang hi")
    hi_reply = bot.handle_message(101, "आपका बैंक खाता बंद हो जाएगा, KYC अपडेट करें")
    ok = "हिंदी" in set_hi and ("ठगी" in hi_reply or "संदिग्ध" in hi_reply)
    failures += check("/lang hi switches replies", ok, "set=%r verdict-line=%r" % (
        set_hi, hi_reply.splitlines()[0] if hi_reply else ""))

    phones.add_block("+91 98765 43210", "kyc scam")
    saved = bot.handle_message(102, "/sender +91 98765 43210")
    blocked = bot.handle_message(102, "Hi, is this the right number?")
    cleared = bot.handle_message(102, "/sender off")
    ok = ("98765" in saved and "scam" in blocked.lower()
          and "cleared" in cleared)
    failures += check("/sender stores a number and affects the verdict", ok,
                      "saved=%r verdict=%r" % (saved, blocked.splitlines()[0]))

    check_reply = bot.handle_message(103, "/check Your parcel is held, pay the fee now")
    ok = "scam" in check_reply.lower() and "/check" not in check_reply
    failures += check("/check analyzes the payload only", ok,
                      check_reply.splitlines()[0])

    usage = bot.handle_message(104, "/lang xx")
    failures += check("/lang validates input", "Usage" in usage)
    print()

    # ------------------------------------------------------- 3. rate limit
    old_limit = bot.RATE_LIMIT
    bot.RATE_LIMIT = 2
    bot.reset_rate_limit()
    try:
        first = bot.handle_message(201, "Hi mom, reached safely.")
        second = bot.handle_message(201, "Hi mom, reached safely.")
        third = bot.handle_message(201, "Hi mom, reached safely.")
        ok = "Slow down" in third and "Slow down" not in first + second
        failures += check("per-chat rate limit", ok, third)
    finally:
        bot.RATE_LIMIT = old_limit
        bot.reset_rate_limit()
    print()

    # ------------------------------------------------------- 4. image path
    png = make_png_bytes("URGENT: your bank account is suspended. "
                         "Verify now at bit.ly/hdfc-alert")
    img_reply = bot.handle_image(301, png)
    ok = "scam" in img_reply.lower() or "सतर्क" in img_reply
    failures += check("screenshot -> OCR -> verdict", ok, img_reply.splitlines()[0])
    print()

    # ------------------------------------------------------- 5. Telegram
    updates = [
        {"update_id": 1, "message": {"chat": {"id": 401}, "text":
            "URGENT: your bank account is suspended. Verify at http://202.51.10.7/hdfc"}},
        {"update_id": 2, "message": {"chat": {"id": 402}, "photo":
            [{"file_id": "small", "width": 10, "height": 10},
             {"file_id": "big", "width": 100, "height": 100}]}},
    ]
    tg, tg_base = start_fake_telegram(updates, png)
    try:
        rc = bot.run_telegram("TESTTOKEN", api_base=tg_base, once=True)
        sent = tg.state["sent"]
        ok = (rc == 0 and len(sent) == 2
              and sent[0]["chat_id"] == 401
              and "scam" in sent[0]["text"].lower()
              and sent[1]["chat_id"] == 402
              and len(sent[1]["text"]) > 20)
        failures += check("Telegram long-poll: text + photo replies", ok,
                          "rc=%d replies=%d" % (rc, len(sent)))
    finally:
        tg.shutdown()
        tg.server_close()
    print()

    # ------------------------------------------------------- 6. WhatsApp
    wa, wa_base = start_fake_graph(png)
    cfg = {"token": "WT", "phone_id": "PHONE", "verify_token": "verify-me",
           "app_secret": None, "api_base": wa_base}
    hook = bot.make_whatsapp_server("127.0.0.1", 0, cfg)
    hook_port = hook.server_address[1]
    threading.Thread(target=hook.serve_forever, daemon=True).start()
    hook_base = "http://127.0.0.1:%d" % hook_port
    try:
        status, body = http("GET", hook_base + "/webhook/whatsapp?hub.mode=subscribe"
                            "&hub.verify_token=verify-me&hub.challenge=abc123")
        ok = status == 200 and body == "abc123"
        failures += check("WhatsApp webhook verification", ok,
                          "status=%d body=%r" % (status, body))

        status, _ = http("GET", hook_base + "/webhook/whatsapp?hub.mode=subscribe"
                         "&hub.verify_token=wrong&hub.challenge=x")
        failures += check("WhatsApp rejects a wrong verify token", status == 403,
                          "status=%d" % status)

        payload = {"entry": [{"changes": [{"value": {"messages": [{
            "id": "wamid.1", "from": "919876543210", "type": "text",
            "text": {"body": "URGENT: KYC expired. Verify at bit.ly/kyc-now"}}]}}]}]}
        status, _ = http("POST", hook_base + "/webhook/whatsapp", payload)
        got = wait_for(lambda: len(wa.state["sent"]) >= 1)
        out = wa.state["sent"][0] if wa.state["sent"] else {}
        ok = (status == 200 and got and out.get("to") == "919876543210"
              and "scam" in out.get("text", {}).get("body", "").lower())
        failures += check("WhatsApp inbound text -> outbound reply", ok,
                          "status=%d to=%s" % (status, out.get("to")))

        status, body = http("POST", hook_base + "/webhook/whatsapp", payload)
        time.sleep(0.6)
        ok = status == 200 and body == "duplicate" and len(wa.state["sent"]) == 1
        failures += check("WhatsApp deduplicates retried messages", ok,
                          "status=%d body=%r replies=%d" % (
                              status, body, len(wa.state["sent"])))

        payload_img = {"entry": [{"changes": [{"value": {"messages": [{
            "id": "wamid.2", "from": "919876543210", "type": "image",
            "image": {"id": "media123", "mime_type": "image/png"}}]}}]}]}
        status, _ = http("POST", hook_base + "/webhook/whatsapp", payload_img)
        got = wait_for(lambda: len(wa.state["sent"]) >= 2)
        ok = status == 200 and got
        failures += check("WhatsApp inbound image -> OCR reply", ok,
                          "replies=%d" % len(wa.state["sent"]))

        status, _ = http("POST", hook_base + "/webhook/whatsapp", {"entry": []})
        failures += check("WhatsApp accepts an empty status event", status == 200,
                          "status=%d" % status)

        # signature checking
        hook2 = bot.make_whatsapp_server("127.0.0.1", 0, dict(cfg, app_secret="s3cr3t"))
        threading.Thread(target=hook2.serve_forever, daemon=True).start()
        base2 = "http://127.0.0.1:%d" % hook2.server_address[1]
        raw = json.dumps({"entry": []}).encode()
        try:
            req = urllib.request.Request(base2 + "/webhook/whatsapp", data=raw, method="POST",
                                         headers={"Content-Type": "application/json",
                                                  "X-Hub-Signature-256": "sha256=deadbeef"})
            try:
                urllib.request.urlopen(req, timeout=10)
                bad = 200
            except urllib.error.HTTPError as exc:
                bad = exc.code
            good_sig = "sha256=" + hmac.new(b"s3cr3t", raw, hashlib.sha256).hexdigest()
            req = urllib.request.Request(base2 + "/webhook/whatsapp", data=raw, method="POST",
                                         headers={"Content-Type": "application/json",
                                                  "X-Hub-Signature-256": good_sig})
            with urllib.request.urlopen(req, timeout=10) as resp:
                good = resp.status
            ok = bad == 403 and good == 200
            failures += check("WhatsApp HMAC signature check", ok,
                              "bad=%d good=%d" % (bad, good))
        finally:
            hook2.shutdown()
            hook2.server_close()
    finally:
        hook.shutdown()
        hook.server_close()
        wa.shutdown()
        wa.server_close()
    print()

    # ------------------------------------------------------- 7. CLI status
    env = dict(os.environ)
    env["SCAMCHECK_HOME"] = HOME
    proc = subprocess.run([sys.executable, "-m", "scamcheck", "--bot-status", "--json"],
                          cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
    try:
        data = json.loads(proc.stdout)
        ok = proc.returncode == 0 and "rate_limit_per_hour" in data
    except ValueError:
        data, ok = {}, False
    failures += check("CLI --bot-status --json", ok,
                      "rc=%d keys=%s" % (proc.returncode, sorted(data)[:4]))

    print()
    print("FAILED: %d checks" % failures if failures else "All checks passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
