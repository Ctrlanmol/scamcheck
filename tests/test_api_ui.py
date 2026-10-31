#!/usr/bin/env python3
"""API + family web UI tests: page serving, headers, analyze, image OCR."""

import base64
import json
import os
import sys
import threading
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

from scamcheck.api import make_server  # noqa: E402
from make_png import render  # noqa: E402


def check(name, ok, detail):
    print("[%s] %s" % ("PASS" if ok else "FAIL", name))
    print("      " + detail)
    return 0 if ok else 1


def main():
    failures = 0
    server = make_server("127.0.0.1", 0)
    port = server.server_address[1]
    base = "http://127.0.0.1:%d" % port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def get(path):
        try:
            with urllib.request.urlopen(base + path, timeout=10) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def post(path, payload, raw=None):
        body = raw if raw is not None else json.dumps(payload).encode()
        req = urllib.request.Request(
            base + path, data=body, headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    try:
        # 1. the family UI page
        status, headers, body = get("/")
        html = body.decode("utf-8", "replace")
        ok = (
            status == 200
            and "text/html" in headers.get("Content-Type", "")
            and "scamcheck" in html
            and "Paste the message" in html
            and "हिंदी" in html
            and 'id="sender"' in html
            and "Sender number" in html
            and headers.get("Content-Security-Policy", "").startswith("default-src 'none'")
            and headers.get("X-Content-Type-Options") == "nosniff"
        )
        failures += check("GET / serves family UI with CSP", ok,
                          "status=%d bytes=%d csp=%s" % (status, len(body),
                                                         headers.get("Content-Security-Policy", "")[:40]))
        print()

        # 2. health
        status, headers, body = get("/health")
        data = json.loads(body)
        ok = status == 200 and data.get("ok") is True and data.get("service") == "scamcheck"
        failures += check("GET /health", ok, "status=%d body=%s" % (status, data))
        print()

        # 3. analyze: Hinglish scam + ordinary message
        status, headers, body = post("/v1/analyze", {
            "text": "Dear customer aapka KYC expire ho gaya hai. KYC update "
                    "karein warna aapka bank account band ho jayega. bit.ly/kyc-now"
        })
        scam = json.loads(body)
        status2, _, body2 = post("/v1/analyze", {
            "text": "Hi mom, reached the airport. Will call you in 2 hours, love you!"
        })
        safe = json.loads(body2)
        rank = {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "LIKELY SCAM": 2, "SCAM": 3}
        ok = (
            status == 200 and status2 == 200
            and rank[scam["final_verdict"]] >= 2
            and safe["final_verdict"] == "LIKELY SAFE"
        )
        failures += check("POST /v1/analyze (scam + normal)", ok,
                          "scam=%s(%d) normal=%s" % (scam["final_verdict"], scam["score"],
                                                     safe["final_verdict"]))
        print()

        # 4. analyze rejects bad payloads
        status, _, body = post("/v1/analyze", None, raw=b"not json")
        status2, _, _ = post("/v1/analyze", {"text": "   "})
        ok = status == 400 and status2 == 400
        failures += check("POST /v1/analyze rejects bad input", ok,
                          "invalid json=%d empty text=%d" % (status, status2))
        print()

        # 5. phone-number endpoint
        status, _, body = post("/v1/check-number", {"number": "+1 900 555 1234"})
        phone = json.loads(body)
        status2, _, _ = post("/v1/check-number", {"number": "123"})
        ok = (
            status == 200
            and phone["number"]["kind"] == "premium"
            and phone["risk"] == "medium"
            and status2 == 400
        )
        failures += check("POST /v1/check-number (premium + junk)", ok,
                          "status=%d kind=%s risk=%s junk=%d" % (
                              status, phone.get("number", {}).get("kind"),
                              phone.get("risk"), status2))
        print()

        # 6. image endpoint: generated scam screenshot -> OCR -> verdict
        png = os.path.join(HERE, "_ui_test_shot.png")
        render("URGENT: your bank account has been suspended. "
               "Verify immediately at bit.ly/verify-now", png, scale=4)
        try:
            with open(png, "rb") as fh:
                b64 = base64.b64encode(fh.read()).decode()
        finally:
            try:
                os.unlink(png)
            except OSError:
                pass
        status, _, body = post("/v1/check-image", {"image_b64": b64})
        data = json.loads(body)
        ok = (
            status == 200
            and data.get("ocr_engine")
            and "extracted_text" in data
            and rank[data["final_verdict"]] >= 1
        )
        failures += check("POST /v1/check-image (base64 OCR)", ok,
                          "status=%d engine=%s verdict=%s text=%r" % (
                              status, data.get("ocr_engine"), data.get("final_verdict"),
                              (data.get("extracted_text") or "")[:60]))
        print()

        # 7. unknown routes
        status, _, _ = get("/nope")
        status2, _, _ = post("/v1/nope", {})
        ok = status == 404 and status2 == 404
        failures += check("unknown routes return 404", ok,
                          "GET /nope=%d POST /v1/nope=%d" % (status, status2))
        print()

        # 8. favicon should not 404 (returns 204)
        status, _, body = get("/favicon.ico")
        failures += check("GET /favicon.ico", status == 204 and body == b"",
                          "status=%d" % status)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    print()
    if failures:
        print("FAILED: %d checks" % failures)
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
