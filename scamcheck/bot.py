"""Telegram + WhatsApp bots: check a forwarded message or screenshot in chat.

Design notes
------------
* Detection stays local. The bots reuse `analyze()` + `ocr.ocr_image()`; no
  message content is sent anywhere except the reply back to Telegram/WhatsApp.
* Telegram runs by **long polling** (no public URL, no webhook setup).
* WhatsApp uses the **Cloud API** webhook; it needs a public HTTPS URL (tunnel
  or reverse proxy) plus a Meta app. Verification + optional HMAC signature
  checking are implemented here.
* Per-chat language (`en`/`hi`) and an optional sender number are stored in
  `~/.scamcheck/bot_prefs.json`.
* Rate limited per chat (default 20 checks/hour) so a group can't hammer it.
"""

import hashlib
import hmac
import json
import os
import sys
import tempfile
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

from . import phones
from .analyzer import analyze

TELEGRAM_API = os.environ.get("SCAMCHECK_TELEGRAM_API", "https://api.telegram.org")
WHATSAPP_API = os.environ.get("SCAMCHECK_WHATSAPP_API", "https://graph.facebook.com/v20.0")
MAX_DOWNLOAD = 12 * 1024 * 1024


def _int_env(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


RATE_LIMIT = _int_env("SCAMCHECK_BOT_RATE", 20)

VERDICT_STYLE = {
    "LIKELY SAFE": ("✅", "safe"),
    "SUSPICIOUS": ("⚠️", "suspicious"),
    "LIKELY SCAM": ("🚨", "likely_scam"),
    "SCAM": ("🛑", "scam"),
}

TEXT = {
    "en": {
        "safe": "Likely safe",
        "suspicious": "Suspicious",
        "likely_scam": "Likely a scam",
        "scam": "This is a scam",
        "advice_safe": "No scam signals found. Still use normal caution with links and money.",
        "advice_suspicious": "Something looks off. Don't click links or share codes. Verify with a number you already have.",
        "advice_likely_scam": "Very likely a scam. Don't reply or send anything. Verify independently before acting.",
        "advice_scam": "Stop. Don't send money, codes, or personal details. Block the sender and warn your family.",
        "intel": "Scam type",
        "next_move": "Likely next",
        "why": "Why",
        "sender_blocked": "sender is on your blocklist",
        "sender_allowed": "sender is on your allowlist",
        "sender_reported": "sender was reported by a public list",
        "sender_premium": "sender is a premium-rate number",
        "playbook": "Known scam playbook",
        "chat": "Chat pattern",
        "footer": "Checked on this device by scamcheck.",
        "image_empty": "I couldn't read any text in that image. Try a sharper screenshot.",
        "rate": "Slow down a little - too many checks in one hour. Try again later.",
        "help": (
            "Send me any SMS, WhatsApp text, email or screenshot and I'll tell you "
            "if it looks like a scam.\n\n"
            "Commands:\n"
            "/lang en | hi - change language\n"
            "/sender +91... - remember the sender number (or /sender off)\n"
            "/status - current settings\n"
            "/help - this message"
        ),
        "lang_set": "Language set to English.",
        "sender_set": "Sender saved: %s. It will be checked with every message.",
        "sender_off": "Sender number cleared.",
        "status": (
            "Region: %s\nLanguage: %s\nSender: %s\nCached feed sources: %d"
        ),
        "not_number": "That doesn't look like a phone number.",
        "unsupported": "Send text or a screenshot (image), please.",
    },
    "hi": {
        "safe": "संभवतः सुरक्षित",
        "suspicious": "संदिग्ध",
        "likely_scam": "संभवतः ठगी",
        "scam": "यह ठगी है",
        "advice_safe": "ठगी का कोई संकेत नहीं मिला। फिर भी लिंक और पैसे में सावधानी रखें।",
        "advice_suspicious": "कुछ गड़बड़ लग रही है। लिंक पर क्लिक न करें, कोड साझा न करें। उसी नंबर पर जाँचें जो आपके पास पहले से है।",
        "advice_likely_scam": "बहुत संभावना है कि यह ठगी है। जवाब न दें, कुछ न भेजें। पहले स्वयं जाँचें।",
        "advice_scam": "रुकिए। पैसे, OTP/कोड या निजी जानकारी न भेजें। भेजने वाले को ब्लॉक करें और परिवार को बताएँ।",
        "intel": "ठगी का प्रकार",
        "next_move": "अगला कदम",
        "why": "कारण",
        "sender_blocked": "भेजने वाला आपकी ब्लॉकलिस्ट में है",
        "sender_allowed": "भेजने वाला आपकी अनुमति-सूची में है",
        "sender_reported": "भेजने वाला सार्वजनिक सूची में शिकायत किया गया है",
        "sender_premium": "भेजने वाला प्रीमियम-रेट नंबर है",
        "playbook": "ज्ञात ठगी का तरीका",
        "chat": "चैट का पैटर्न",
        "footer": "scamcheck ने इसी डिवाइस पर जाँचा।",
        "image_empty": "इस तस्वीर से कोई टेक्स्ट नहीं पढ़ा जा सका। साफ़ स्क्रीनशॉट भेजें।",
        "rate": "थोड़ा धीरे - एक घंटे में बहुत ज़्यादा जाँच। बाद में फिर कोशिश करें।",
        "help": (
            "कोई भी SMS, WhatsApp संदेश, ईमेल या स्क्रीनशॉट भेजें - मैं बताऊँगा "
            "कि यह ठगी लगती है या नहीं।\n\n"
            "कमांड:\n"
            "/lang en | hi - भाषा बदलें\n"
            "/sender +91... - भेजने वाले का नंबर याद रखें (या /sender off)\n"
            "/status - वर्तमान सेटिंग\n"
            "/help - यह संदेश"
        ),
        "lang_set": "भाषा हिंदी कर दी गई।",
        "sender_set": "भेजने वाला सहेजा गया: %s. अब हर संदेश के साथ जाँचा जाएगा।",
        "sender_off": "भेजने वाले का नंबर हटा दिया।",
        "status": (
            "क्षेत्र: %s\nभाषा: %s\nभेजने वाला: %s\nकैश्ड फ़ीड स्रोत: %d"
        ),
        "not_number": "यह फ़ोन नंबर नहीं लगता।",
        "unsupported": "कृपया टेक्स्ट या स्क्रीनशॉट (तस्वीर) भेजें।",
    },
}


# ---------------------------------------------------------------------------
# Per-chat preferences (language / remembered sender)
# ---------------------------------------------------------------------------

_prefs_lock = threading.Lock()
_hits = {}
_hits_lock = threading.Lock()


def _prefs_path():
    return os.path.join(phones.data_dir(), "bot_prefs.json")


def _load_prefs():
    try:
        with open(_prefs_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_prefs(prefs):
    phones.ensure_dir()
    path = _prefs_path()
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".bot-prefs-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(prefs, fh, ensure_ascii=False, indent=2, sort_keys=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _pref(chat_id, key, default=None):
    with _prefs_lock:
        return _load_prefs().get(str(chat_id), {}).get(key, default)


def _set_pref(chat_id, key, value):
    with _prefs_lock:
        prefs = _load_prefs()
        chat = prefs.setdefault(str(chat_id), {})
        if value is None:
            chat.pop(key, None)
        else:
            chat[key] = value
        _save_prefs(prefs)


def chat_lang(chat_id):
    lang = _pref(chat_id, "lang", "en")
    return lang if lang in TEXT else "en"


def chat_sender(chat_id):
    return _pref(chat_id, "sender") or None


def rate_limited(chat_id, now=None):
    global RATE_LIMIT
    now = time.time() if now is None else now
    with _hits_lock:
        bucket = _hits.setdefault(str(chat_id), deque())
        cutoff = now - 3600
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT:
            return True
        bucket.append(now)
        return False


def reset_rate_limit():
    with _hits_lock:
        _hits.clear()


# ---------------------------------------------------------------------------
# Reply building
# ---------------------------------------------------------------------------

def _t(lang, key):
    return TEXT.get(lang, TEXT["en"]).get(key, TEXT["en"].get(key, key))


def format_reply(result, lang="en"):
    """Turn an analyze() result into a chat-friendly reply."""
    final = result.get("final_verdict", "LIKELY SAFE")
    icon, key = VERDICT_STYLE.get(final, ("⚠️", "suspicious"))
    lines = ["%s %s  (%d/100)" % (icon, _t(lang, key), int(result.get("score", 0)))]
    lines.append("")
    lines.append(_t(lang, "advice_" + key))

    intel = result.get("intelligence") or {}
    if intel.get("scam_type") not in (None, "general"):
        detail = intel.get("title") or intel.get("scam_type")
        stage = intel.get("stage") or {}
        if stage.get("label"):
            detail += " · " + stage["label"]
        lines.append("")
        lines.append(_t(lang, "intel") + ": " + detail)
        if intel.get("next_moves"):
            lines.append(_t(lang, "next_move") + ": " + intel["next_moves"][0])

    reasons = [r for r in (result.get("reasons") or []) if r[1] > 0][:4]
    if reasons:
        lines.append("")
        lines.append(_t(lang, "why") + ":")
        for label, _weight in reasons:
            lines.append("• " + label)

    scripts = result.get("scripts") or []
    if scripts:
        lines.append("")
        lines.append(_t(lang, "playbook") + ": " + ", ".join(scripts[:3]))

    conv = result.get("conversation")
    if conv:
        lines.append("")
        lines.append("%s: %s (%d)" % (
            _t(lang, "chat"), conv.get("verdict", "?"), conv.get("message_count", 0)))

    num = result.get("number") or {}
    sender = num.get("sender")
    if sender:
        n = sender.get("number") or {}
        status = (sender.get("reputation") or {}).get("status")
        label = n.get("e164") or n.get("national") or ""
        if status == "blocked":
            note = _t(lang, "sender_blocked")
        elif status == "allowed":
            note = _t(lang, "sender_allowed")
        elif status == "reported":
            note = _t(lang, "sender_reported")
        elif n.get("kind") == "premium":
            note = _t(lang, "sender_premium")
        else:
            note = None
        if note:
            lines.append("")
            lines.append("📱 %s: %s" % (label, note))

    lines.append("")
    lines.append(_t(lang, "footer"))
    return "\n".join(lines)


def _analyze_text(text, chat_id, sender=None):
    lang = chat_lang(chat_id)
    use_ai = os.environ.get("SCAMCHECK_BOT_AI", "never")
    if use_ai not in ("auto", "always", "never"):
        use_ai = "never"
    result = analyze(text, use_ai=use_ai, sender=sender or chat_sender(chat_id))
    return format_reply(result, lang)


def _analyze_image(raw, chat_id, sender=None):
    from .ocr import ocr_image

    lang = chat_lang(chat_id)
    suffix = ".png" if raw[:8] == b"\x89PNG\r\n\x1a\n" else ".jpg"
    fd, path = tempfile.mkstemp(prefix="scamcheck-bot-", suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
        text, _engine = ocr_image(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if not text or not text.strip():
        return _t(lang, "image_empty")
    use_ai = os.environ.get("SCAMCHECK_BOT_AI", "never")
    if use_ai not in ("auto", "always", "never"):
        use_ai = "never"
    result = analyze(text, use_ai=use_ai, ocr=True,
                     sender=sender or chat_sender(chat_id))
    return format_reply(result, lang)


def _status_reply(chat_id):
    lang = chat_lang(chat_id)
    sender = chat_sender(chat_id) or "-"
    feeds = len(phones.feed_status().get("sources") or [])
    return _t(lang, "status") % (
        phones.default_region(), lang, sender, feeds)


def handle_command(chat_id, text):
    """Handle a /command. Returns (handled, reply)."""
    parts = (text or "").strip().split()
    if not parts or not parts[0].startswith("/"):
        return False, None
    cmd = parts[0].lower().split("@", 1)[0]
    lang = chat_lang(chat_id)

    if cmd in ("/start", "/help"):
        return True, _t(lang, "help")

    if cmd == "/lang":
        if len(parts) < 2 or parts[1].lower() not in ("en", "hi"):
            return True, "Usage: /lang en | hi"
        _set_pref(chat_id, "lang", parts[1].lower())
        return True, _t(parts[1].lower(), "lang_set")

    if cmd == "/sender":
        if len(parts) < 2:
            return True, "Usage: /sender +91... | /sender off"
        if parts[1].lower() in ("off", "none", "clear"):
            _set_pref(chat_id, "sender", None)
            return True, _t(lang, "sender_off")
        info = phones.normalize_number(" ".join(parts[1:]))
        if not info["valid"]:
            return True, _t(lang, "not_number")
        stored = info["e164"] or info["national"]
        _set_pref(chat_id, "sender", stored)
        return True, _t(lang, "sender_set") % stored

    if cmd == "/status":
        return True, _status_reply(chat_id)

    if cmd == "/check":
        rest = text.split(None, 1)
        if len(rest) < 2 or not rest[1].strip():
            return True, "Usage: /check <message>"
        return False, rest[1].strip()  # caller analyzes it as text

    return True, _t(lang, "help")


def handle_message(chat_id, text, sender=None):
    """Reply to a text message (including commands)."""
    handled, out = handle_command(chat_id, text)
    if handled:
        return out
    if out:  # /check <message> payload
        text = out
    if not text or not text.strip():
        return _t(chat_lang(chat_id), "unsupported")
    if rate_limited(chat_id):
        return _t(chat_lang(chat_id), "rate")
    return _analyze_text(text, chat_id, sender=sender)


def handle_image(chat_id, raw, sender=None):
    """Reply to an image/screenshot."""
    if rate_limited(chat_id):
        return _t(chat_lang(chat_id), "rate")
    return _analyze_image(raw, chat_id, sender=sender)


# ---------------------------------------------------------------------------
# Telegram (long polling)
# ---------------------------------------------------------------------------

def _telegram_call(token, method, payload=None, api_base=None, timeout=60):
    base = (api_base or TELEGRAM_API).rstrip("/")
    url = "%s/bot%s/%s" % (base, token, method)
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request(url, data=data, headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read() or b"{}")
    if not body.get("ok"):
        raise RuntimeError("Telegram %s failed: %s" % (method, body.get("description")))
    return body.get("result")


def _telegram_file(token, file_path, api_base=None):
    base = (api_base or TELEGRAM_API).rstrip("/")
    url = "%s/file/bot%s/%s" % (base, token, file_path)
    with urlopen(Request(url, headers={"User-Agent": "scamcheck-bot"}), timeout=60) as resp:
        length = resp.headers.get("Content-Length")
        if length and int(length) > MAX_DOWNLOAD:
            raise ValueError("file too large")
        raw = resp.read(MAX_DOWNLOAD + 1)
    if len(raw) > MAX_DOWNLOAD:
        raise ValueError("file too large")
    return raw


def _telegram_download(token, file_id, api_base=None):
    info = _telegram_call(token, "getFile", {"file_id": file_id}, api_base=api_base)
    path = info.get("file_path")
    if not path:
        return None
    return _telegram_file(token, path, api_base=api_base)


def process_telegram_update(token, update, api_base=None):
    """Handle one Telegram update; returns the reply text (or None)."""
    msg = update.get("message") or update.get("edited_message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    if chat_id is None:
        return None
    text = msg.get("text")
    reply = None

    if text:
        reply = handle_message(chat_id, text)
    else:
        photo = msg.get("photo") or []
        document = msg.get("document") or {}
        file_id = None
        if photo:
            file_id = photo[-1].get("file_id")
        elif str(document.get("mime_type", "")).startswith("image/"):
            file_id = document.get("file_id")
        if file_id:
            try:
                raw = _telegram_download(token, file_id, api_base=api_base)
                reply = handle_image(chat_id, raw) if raw else None
            except Exception as exc:
                reply = "Could not read that image (%s)." % exc
        elif msg.get("audio") or msg.get("voice") or msg.get("video"):
            reply = _t(chat_lang(chat_id), "unsupported")

    if reply:
        _telegram_call(token, "sendMessage", {
            "chat_id": chat_id,
            "text": reply,
            "disable_web_page_preview": True,
        }, api_base=api_base)
    return reply


def run_telegram(token=None, api_base=None, once=False, poll_timeout=30):
    """Long-poll Telegram until Ctrl+C."""
    token = token or os.environ.get("SCAMCHECK_TELEGRAM_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        print("Set SCAMCHECK_TELEGRAM_TOKEN (or TELEGRAM_BOT_TOKEN) first.", file=sys.stderr)
        return 2
    print("scamcheck Telegram bot running (long polling). Ctrl+C to stop.", file=sys.stderr)
    print("  token: ...%s   region: %s" % (token[-4:], phones.default_region()), file=sys.stderr)
    offset = 0
    while True:
        try:
            updates = _telegram_call(token, "getUpdates", {
                "offset": offset,
                "timeout": poll_timeout,
                "allowed_updates": ["message", "edited_message"],
            }, api_base=api_base, timeout=poll_timeout + 15) or []
        except KeyboardInterrupt:
            return 0
        except (HTTPError, URLError, RuntimeError, ValueError) as exc:
            print("Telegram polling error: %s" % exc, file=sys.stderr)
            if once:
                return 1
            time.sleep(3)
            continue

        for update in updates:
            offset = max(offset, int(update.get("update_id", 0)) + 1)
            try:
                process_telegram_update(token, update, api_base=api_base)
            except Exception as exc:
                print("Update %s failed: %s" % (update.get("update_id"), exc), file=sys.stderr)
        if once:
            return 0


# ---------------------------------------------------------------------------
# WhatsApp Cloud API (webhook)
# ---------------------------------------------------------------------------

def whatsapp_config():
    return {
        "token": os.environ.get("WHATSAPP_TOKEN") or os.environ.get("SCAMCHECK_WHATSAPP_TOKEN"),
        "phone_id": os.environ.get("WHATSAPP_PHONE_NUMBER_ID"),
        "verify_token": os.environ.get("WHATSAPP_VERIFY_TOKEN", "scamcheck"),
        "app_secret": os.environ.get("WHATSAPP_APP_SECRET"),
        "api_base": WHATSAPP_API,
    }


def _wa_request(url, cfg, payload=None, method="GET", timeout=60):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Authorization": "Bearer " + (cfg.get("token") or "")}
    if data:
        headers["Content-Type"] = "application/json"
    req = Request(url, data=data, headers=headers, method=method)
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read() or b"{}")


def _wa_send(cfg, to, text):
    base = cfg["api_base"].rstrip("/")
    url = "%s/%s/messages" % (base, cfg["phone_id"])
    _wa_request(url, cfg, {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": to,
        "type": "text",
        "text": {"preview_url": False, "body": text},
    }, method="POST")


def _wa_media(cfg, media_id):
    base = cfg["api_base"].rstrip("/")
    info = _wa_request("%s/%s" % (base, media_id), cfg)
    url = info.get("url")
    if not url:
        return None
    with urlopen(Request(url, headers={"Authorization": "Bearer " + (cfg.get("token") or "")}),
                 timeout=60) as resp:
        raw = resp.read(MAX_DOWNLOAD + 1)
    if len(raw) > MAX_DOWNLOAD:
        raise ValueError("media too large")
    return raw


def _wa_messages(payload):
    out = []
    for entry in payload.get("entry") or []:
        for change in entry.get("changes") or []:
            value = change.get("value") or {}
            for msg in value.get("messages") or []:
                out.append(msg)
    return out


def process_whatsapp_messages(messages, cfg, sender_cb=None):
    """Handle a list of Cloud API message objects; returns [(to, reply)]."""
    out = []
    for msg in messages:
        to = msg.get("from")
        kind = msg.get("type")
        if not to:
            continue
        sender = "+" + to.lstrip("+") if to.isdigit() else None
        try:
            if kind == "text":
                reply = handle_message(to, ((msg.get("text") or {}).get("body") or ""),
                                       sender=sender)
            elif kind == "image":
                media_id = ((msg.get("image") or {}).get("id"))
                raw = _wa_media(cfg, media_id) if media_id else None
                reply = handle_image(to, raw, sender=sender) if raw else \
                    _t(chat_lang(to), "image_empty")
            else:
                reply = _t(chat_lang(to), "unsupported")
        except Exception as exc:
            reply = "Something went wrong: %s" % exc
        if reply:
            _wa_send(cfg, to, reply)
            out.append((to, reply))
            if sender_cb:
                sender_cb(to, reply)
    return out


def process_whatsapp_payload(payload, cfg, sender_cb=None):
    """Handle one Cloud API webhook payload; returns list of (to, reply)."""
    return process_whatsapp_messages(_wa_messages(payload), cfg, sender_cb=sender_cb)


_seen_wa = set()
_seen_wa_lock = threading.Lock()


def _wa_seen(message_id):
    if not message_id:
        return False
    with _seen_wa_lock:
        if message_id in _seen_wa:
            return True
        _seen_wa.add(message_id)
        if len(_seen_wa) > 500:
            _seen_wa.clear()
        return False


class WhatsAppHandler(BaseHTTPRequestHandler):
    def _text(self, code, body, ctype="text/plain; charset=utf-8"):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if urlparse(self.path).path != "/webhook/whatsapp":
            self._text(404, "not found")
            return
        qs = parse_qs(urlparse(self.path).query)
        mode = (qs.get("hub.mode") or [""])[0]
        token = (qs.get("hub.verify_token") or [""])[0]
        challenge = (qs.get("hub.challenge") or [""])[0]
        expected = self.server.cfg.get("verify_token") or ""
        if mode == "subscribe" and expected and hmac.compare_digest(token, expected):
            self._text(200, challenge)
        else:
            self._text(403, "verification failed")

    def do_POST(self):
        if urlparse(self.path).path != "/webhook/whatsapp":
            self._text(404, "not found")
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) or b"{}"
            payload = json.loads(raw)
        except (ValueError, json.JSONDecodeError):
            self._text(400, "bad json")
            return

        secret = self.server.cfg.get("app_secret")
        if secret:
            sig = self.headers.get("X-Hub-Signature-256", "")
            want = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, want):
                self._text(403, "bad signature")
                return

        # Ack immediately (Meta retries if we're slow); process in background.
        messages = _wa_messages(payload)
        if not messages:
            self._text(200, "ok")
            return
        fresh = [m for m in messages if not _wa_seen(m.get("id"))]
        if not fresh:
            self._text(200, "duplicate")
            return
        self._text(200, "ok")
        threading.Thread(target=process_whatsapp_messages,
                         args=(fresh, self.server.cfg), daemon=True).start()

    def log_message(self, fmt, *args):
        pass


def make_whatsapp_server(host="127.0.0.1", port=8766, cfg=None):
    server = ThreadingHTTPServer((host, port), WhatsAppHandler)
    server.cfg = cfg or whatsapp_config()
    return server


def run_whatsapp(host="127.0.0.1", port=8766):
    cfg = whatsapp_config()
    if not cfg.get("token") or not cfg.get("phone_id"):
        print("Set WHATSAPP_TOKEN and WHATSAPP_PHONE_NUMBER_ID first.", file=sys.stderr)
        print("Webhook verify token: WHATSAPP_VERIFY_TOKEN (default: scamcheck)", file=sys.stderr)
        return 2
    server = make_whatsapp_server(host, port, cfg)
    print("scamcheck WhatsApp webhook on http://%s:%d/webhook/whatsapp" % (host, port),
          file=sys.stderr)
    if host in ("127.0.0.1", "localhost", "::1"):
        print("  ! Meta needs a public HTTPS URL: tunnel this port "
              "(cloudflared/ngrok) and set the webhook in the Meta app.", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def bot_status():
    cfg = whatsapp_config()
    tg = os.environ.get("SCAMCHECK_TELEGRAM_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN")
    return {
        "telegram_token": ("..." + tg[-4:]) if tg else None,
        "telegram_api": TELEGRAM_API,
        "whatsapp_token": bool(cfg.get("token")),
        "whatsapp_phone_id": cfg.get("phone_id"),
        "whatsapp_verify_token_set": bool(os.environ.get("WHATSAPP_VERIFY_TOKEN")),
        "whatsapp_app_secret_set": bool(cfg.get("app_secret")),
        "whatsapp_api": cfg.get("api_base"),
        "region": phones.default_region(),
        "rate_limit_per_hour": RATE_LIMIT,
        "prefs": _prefs_path(),
        "cached_feeds": len(phones.feed_status().get("sources") or []),
    }
