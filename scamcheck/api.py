"""Local HTTP API + family web UI: `python3 -m scamcheck serve`
(default 127.0.0.1:8765).

GET  /                                       family web UI (HTML, EN/HI)
GET  /health

POST /v1/analyze  {"text": "..."}            single message
                  {"conversation": "..."}    chat transcript (multi-line)
                  {"text": "...", "ai": "always", "sender": "+91..."}
-> {"score","verdict","final_verdict","reasons":[[label,weight]],...}

POST /v1/check-number {"number": "+91 98765 43210"}
-> {"number": {...}, "reputation": {...}, "flags": [...], "risk": "..."}

POST /v1/check-image {"path": "/path/shot.png"}          OCR a local file
                     {"image_b64": "<base64 PNG/JPEG>"}  OCR raw bytes
-> same payload as analyze, plus "ocr_engine", "extracted_text", and "qr"
   (decoded barcode payloads when present)

Phone reputation is read from local lists/feeds only; the API never fetches.
Dependency-free (http.server). CORS enabled for the JSON endpoints so local
pages can call it; the bundled UI is same-origin with a strict CSP.
"""

import base64
import json
import os
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import phones
from .analyzer import analyze
from . import __version__
from .webui import PAGE

CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
       "img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'")


class Handler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def _html(self):
        body = PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._html()
        elif self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        elif self.path == "/health":
            body = json.dumps({"ok": True, "service": "scamcheck", "version": __version__}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self._cors()
            self.end_headers()

    def do_POST(self):
        if self.path == "/v1/check-image":
            self._handle_check_image()
            return
        if self.path == "/v1/check-number":
            self._handle_check_number()
            return
        if self.path != "/v1/analyze":
            self.send_response(404)
            self._cors()
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length) or "{}")
        except (ValueError, json.JSONDecodeError):
            self._json(400, {"error": "invalid JSON body"})
            return

        text = data.get("text") or data.get("conversation") or data.get("message")
        if not text or not str(text).strip():
            self._json(400, {"error": "missing 'text' or 'conversation'"})
            return
        use_ai = data.get("ai", "auto")
        if use_ai not in ("auto", "always", "never"):
            use_ai = "auto"

        sender = data.get("sender")
        region = data.get("region")
        result = analyze(str(text), use_ai=use_ai,
                         sender=str(sender) if sender else None,
                         region=str(region) if region else None)
        payload = {k: v for k, v in result.items() if k != "ai_requested"}
        payload["ai_requested"] = use_ai == "always" or (use_ai == "auto" and 15 <= result["score"] < 60)
        self._json(200, payload)

    def _handle_check_number(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length) or "{}")
        except (ValueError, json.JSONDecodeError):
            self._json(400, {"error": "invalid JSON body"})
            return

        raw = data.get("number") or data.get("sender")
        if not raw or not str(raw).strip() or len(str(raw)) > 60:
            self._json(400, {"error": "missing or invalid 'number'"})
            return
        intel = phones.check_number(str(raw), region=data.get("region"))
        if not intel["number"]["valid"]:
            self._json(400, {"error": intel["number"]["note"] or "invalid number",
                             "number": intel["number"]})
            return
        self._json(200, intel)

    def _handle_check_image(self):
        from .ocr import detect_qr, ocr_image, qr_text

        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length) or "{}")
        except (ValueError, json.JSONDecodeError):
            self._json(400, {"error": "invalid JSON body"})
            return

        path = data.get("path")
        image_b64 = data.get("image_b64")
        tmp_path = None
        if not path and not image_b64:
            self._json(400, {"error": "missing 'path' or 'image_b64'"})
            return
        if image_b64:
            try:
                raw = base64.b64decode(image_b64)
                if not raw:
                    raise ValueError
            except (ValueError, TypeError):
                self._json(400, {"error": "invalid base64 image data"})
                return
            fd, tmp_path = tempfile.mkstemp(suffix=".png", prefix="scamcheck-api-")
            with os.fdopen(fd, "wb") as fh:
                fh.write(raw)
            path = tmp_path

        try:
            text, engine = ocr_image(path)
            qr = detect_qr(path)
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        codes = qr.get("codes") or []
        qr_payload = qr_text(codes)
        analysis = (text or "").strip()
        if qr_payload:
            analysis = (analysis + "\n" + qr_payload).strip()
        if not analysis:
            self._json(422, {"error": "no text or QR code could be read from the image",
                             "ocr_engine": engine,
                             "qr_error": qr.get("error")})
            return

        use_ai = data.get("ai", "auto")
        if use_ai not in ("auto", "always", "never"):
            use_ai = "auto"
        sender = data.get("sender")
        region = data.get("region")
        result = analyze(analysis, use_ai=use_ai, ocr=True,
                         sender=str(sender) if sender else None,
                         region=str(region) if region else None)
        payload = {k: v for k, v in result.items() if k != "ai_requested"}
        payload["ocr_engine"] = engine
        payload["extracted_text"] = (text or "").strip() or qr_payload
        if codes:
            payload["qr"] = codes
        self._json(200, payload)

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # quieter logs
        pass


def make_server(host="127.0.0.1", port=8765):
    """Create (but do not start) the HTTP server; used by serve() and tests."""
    return ThreadingHTTPServer((host, port), Handler)


def serve(host="127.0.0.1", port=8765):
    server = make_server(host, port)
    print("scamcheck API v%s listening on http://%s:%d" % (__version__, host, port), file=sys.stderr)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("  ! exposed beyond this machine: anyone on the network can use it "
              "(there is no authentication)", file=sys.stderr)
    print("  GET  /                 family web UI (paste a message or screenshot)", file=sys.stderr)
    print("  POST /v1/analyze       {\"text\": \"...\"} | {\"conversation\": \"...\"} | +\"sender\"", file=sys.stderr)
    print("  POST /v1/check-number  {\"number\": \"+91...\"}", file=sys.stderr)
    print("  POST /v1/check-image   {\"path\": \"...\"} | {\"image_b64\": \"...\"}", file=sys.stderr)
    print("  GET  /health", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
