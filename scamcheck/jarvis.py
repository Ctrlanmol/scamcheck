"""JARVIS core: a local-first command center with memory, voice and alerts.

The console is deliberately small and scriptable:

    scamcheck --jarvis                 # interactive REPL
    echo "check ..." | scamcheck --jarvis
    scamcheck --jarvis --voice --notify

Everything except `url` is offline. Link investigation only happens when the
user explicitly types a url command. History is stored locally in SQLite
(`~/.scamcheck/history.db`, mode 0600) and is used to answer "have I seen this
link / number / exact message before?".

Public pieces used by the CLI and tests:
    History, JarvisSession, run_repl, speak, notify
"""

import json
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse

from . import __version__, bot, intel, netintel, phones
from .analyzer import analyze

RISKY = ("SUSPICIOUS", "LIKELY SCAM", "SCAM")

NOTIFY_SCRIPT = """on run argv
  display notification (item 2 of argv) with title (item 1 of argv)
end run
"""

HELP = """I can work with text, screenshots, links, QR codes and phone numbers.

  check <text>            check an SMS / email / chat message
  assess <text>           full intel: type, stage, goals, next moves, verification
  brief                   full intel brief for the last check
  next                    likely attacker next moves for the last check
  reply                   safe replies for the last check
  <text>                  bare text is checked directly
  image <path>            OCR a screenshot, decode any QR, then check it
  qr <path>               decode QR/barcodes only (offline)
  paste                   check whatever text/image is on the clipboard
  url <link>              redirect chain, TLS, domain age (this one goes online)
  number <phone>          range facts + your blocklist/allowlist/feeds
  block/allow <phone>     teach me a number (optional label after it)
  forget <phone>          remove a number from both lists
  sender <phone|off>      attach a sender to text checks
  history [n]             recent checks from local memory
  search <term>           search text and remembered links/numbers
  history clear           wipe the local history database
  why                     evidence behind the last check
  voice on|off            spoken verdicts for risky results
  notify on|off           macOS notifications for risky results
  lang en|hi              reply language
  region IN|US|...        default region for national numbers
  feeds                   cached phone-number feed status
  case ...                evidence cases: list, new, show, add, note, export
  watch <KIND:VALUE>      warn me whenever this appears again
  unwatch <KIND:VALUE>    stop warning about an identifier
  watchlist               show everything on the local watchlist
  campaigns [n]           cluster related checks by shared indicators
  campaign <id>           inspect one campaign
  recover [type]          country-aware recovery playbook
  report <case-id>        draft a complaint from a case
  scan device             read-only audit: posture, processes, persistence, browsers, network
  scan device active      also TCP-probe common ports on private-LAN devices you own
  scan network            private-LAN inventory only (add 'active' to probe ports)
  status                  settings, engines and memory
  quit                    leave

Memory is local. `url` is the only command that touches the network, and only
when you ask it to."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _snippet(text, limit=70):
    line = " ".join((text or "").split())
    return line if len(line) <= limit else line[:limit - 3] + "..."


def _ago(ts):
    if not ts:
        return "?"
    delta = max(0, time.time() - float(ts))
    if delta < 60:
        return "just now"
    if delta < 3600:
        return "%dm ago" % int(delta // 60)
    if delta < 86400:
        return "%dh ago" % int(delta // 3600)
    if delta < 7 * 86400:
        return "%dd ago" % int(delta // 86400)
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def _case_money(case):
    amount = (case or {}).get("loss_amount") or 0
    currency = (case or {}).get("currency") or ""
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        amount = 0
    if not amount:
        return "not recorded"
    return ("%s %.2f" % (currency, amount)).strip()


def _dedupe_identifiers(items):
    out, seen = [], set()
    for item in items or []:
        kind = item.get("kind")
        value = item.get("value")
        if not kind or not value or (kind, value) in seen:
            continue
        seen.add((kind, value))
        out.append({"kind": kind, "value": value, "label": item.get("label") or value})
    return out


def _host_label(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def text_identifiers(text, result=None):
    """Stable things worth remembering about one analyzed message."""
    items = intel.extract_entities(text or "", result=result)
    if items and items[0].get("kind") == "message":
        items[0]["label"] = _snippet(text)
    return _dedupe_identifiers(items)


def url_identifiers(report, target):
    hosts = set()
    for entry in report.get("chain") or []:
        host = _host_label(entry.get("url"))
        if host:
            hosts.add(host)
    for key in ("final_url", "input"):
        host = _host_label(report.get(key) or target)
        if host:
            hosts.add(host)
    return [{"kind": "url", "value": host, "label": host} for host in sorted(hosts)]


def format_seen(hits, identifiers):
    """Human summary of prior checks + first-time links/numbers."""
    hits = hits or []
    lines = []
    if hits:
        lines.append("👁 Seen before:")
        for hit in hits[:4]:
            kind = hit.get("kind")
            if kind == "message":
                label = "this exact message"
            elif kind == "sender":
                label = "sender " + (hit.get("label") or hit.get("value"))
            elif kind == "phone":
                label = "number " + (hit.get("label") or hit.get("value"))
            else:
                label = hit.get("label") or hit.get("value")
            n = int(hit.get("count") or 0)
            lines.append("• %s - %d previous check%s, last %s (%s)" % (
                label, n, "" if n == 1 else "s", _ago(hit.get("last_ts")),
                hit.get("verdict") or "?"))

    hit_keys = {(h.get("kind"), h.get("value")) for h in hits}
    fresh = []
    for item in identifiers or []:
        if item["kind"] != "message":
            if (item["kind"], item["value"]) not in hit_keys:
                fresh.append(item.get("label") or item["value"])
    if fresh:
        label = "👁 New to me: " + ", ".join(fresh[:4])
        if len(fresh) > 4:
            label += " (+%d more)" % (len(fresh) - 4)
        lines.append(label)
    return ("\n\n" + "\n".join(lines)) if lines else ""


# ---------------------------------------------------------------------------
# Local history / memory
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    kind    TEXT NOT NULL,
    verdict TEXT NOT NULL,
    score   INTEGER NOT NULL DEFAULT 0,
    text    TEXT NOT NULL DEFAULT '',
    sender  TEXT,
    meta    TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS identifiers (
    check_id INTEGER NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
    kind     TEXT NOT NULL,
    value    TEXT NOT NULL,
    label    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (check_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_identifiers_lookup
    ON identifiers(kind, value);
CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts);
"""


class History:
    """SQLite-backed local memory. No network, no sync, no telemetry."""

    def __init__(self, path=None):
        self.path = path or os.path.join(phones.data_dir(), "history.db")

    def _connect(self):
        phones.ensure_dir()
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.executescript(SCHEMA)
        conn.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return conn

    def record(self, kind, verdict, score, text="", sender=None,
               identifiers=None, meta=None):
        items = _dedupe_identifiers(identifiers)
        now = time.time()
        conn = self._connect()
        try:
            cur = conn.execute(
                "INSERT INTO checks (ts, kind, verdict, score, text, sender, meta) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (now, str(kind), str(verdict), int(score), (text or "")[:8000],
                 sender, json.dumps(meta or {}, ensure_ascii=False)),
            )
            check_id = cur.lastrowid
            conn.executemany(
                "INSERT OR IGNORE INTO identifiers (check_id, kind, value, label) "
                "VALUES (?, ?, ?, ?)",
                [(check_id, i["kind"], i["value"], i["label"]) for i in items],
            )
            conn.commit()
            return check_id
        finally:
            conn.close()

    def seen_before(self, identifiers, exclude_id=None):
        """Return one summary row per identifier previously seen."""
        out = []
        conn = self._connect()
        try:
            for item in _dedupe_identifiers(identifiers):
                sql = (
                    "SELECT COUNT(*) AS n, MIN(c.ts) AS first_ts, MAX(c.ts) AS last_ts "
                    "FROM identifiers i JOIN checks c ON c.id = i.check_id "
                    "WHERE i.kind = ? AND i.value = ?"
                )
                params = [item["kind"], item["value"]]
                if exclude_id:
                    sql += " AND c.id != ?"
                    params.append(exclude_id)
                row = conn.execute(sql, params).fetchone()
                if not row or not row["n"]:
                    continue
                latest = conn.execute(
                    "SELECT c.verdict, c.score, c.ts FROM identifiers i "
                    "JOIN checks c ON c.id = i.check_id "
                    "WHERE i.kind = ? AND i.value = ? "
                    + ("AND c.id != ? " if exclude_id else "")
                    + "ORDER BY c.ts DESC LIMIT 1",
                    params,
                ).fetchone()
                out.append({
                    "kind": item["kind"],
                    "value": item["value"],
                    "label": item["label"],
                    "count": row["n"],
                    "first_ts": row["first_ts"],
                    "last_ts": row["last_ts"],
                    "verdict": latest["verdict"] if latest else "?",
                    "score": latest["score"] if latest else 0,
                })
        finally:
            conn.close()
        out.sort(key=lambda h: h.get("last_ts") or 0, reverse=True)
        return out

    def recent(self, limit=10):
        limit = max(1, min(int(limit or 10), 100))
        conn = self._connect()
        try:
            return [dict(r) for r in conn.execute(
                "SELECT id, ts, kind, verdict, score, text, sender "
                "FROM checks ORDER BY ts DESC LIMIT ?", (limit,))]
        finally:
            conn.close()

    def search(self, term, limit=10):
        needle = "%" + (term or "").strip() + "%"
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT DISTINCT c.id, c.ts, c.kind, c.verdict, c.score, c.text, c.sender "
                "FROM checks c LEFT JOIN identifiers i ON i.check_id = c.id "
                "WHERE c.text LIKE ? OR i.value LIKE ? "
                "ORDER BY c.ts DESC LIMIT ?",
                (needle, needle, max(1, min(int(limit or 10), 50))),
            )
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def count(self):
        conn = self._connect()
        try:
            return int(conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0])
        finally:
            conn.close()

    def clear(self):
        conn = self._connect()
        try:
            n = conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
            conn.execute("DELETE FROM checks")
            conn.commit()
            return int(n)
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Voice + macOS notifications
# ---------------------------------------------------------------------------

def _speech_clean(text, limit=320):
    text = re.sub(r"https?://\S+", "a link", text or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def speak(text, voice=None):
    """Speak through macOS `say` (or $SCAMCHECK_SAY_CMD for tests)."""
    text = _speech_clean(text)
    if not text:
        return False
    custom = os.environ.get("SCAMCHECK_SAY_CMD")
    if custom:
        try:
            cmd = shlex.split(custom)
        except ValueError:
            return False
    elif sys.platform == "darwin" and os.path.exists("/usr/bin/say"):
        cmd = ["/usr/bin/say"]
        voice = voice or os.environ.get("SCAMCHECK_VOICE_NAME")
        if voice:
            cmd += ["-v", voice]
    else:
        return False
    try:
        proc = subprocess.run(cmd + [text], capture_output=True, timeout=60)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _script_file(name, source):
    folder = os.path.join(tempfile.gettempdir(), "scamcheck-%d" % os.getuid())
    try:
        os.makedirs(folder, mode=0o700, exist_ok=True)
        os.chmod(folder, 0o700)
        path = os.path.join(folder, name)
        existing = None
        if os.path.isfile(path) and not os.path.islink(path):
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                existing = fh.read()
        if existing == source:
            return path
        fd, tmp = tempfile.mkstemp(dir=folder, prefix=".applescript-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(source)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        return path
    except OSError:
        return None


def notify(title, message):
    """Show a macOS notification (best effort; never raises)."""
    if sys.platform != "darwin" or not shutil.which("osascript"):
        return False
    script = _script_file("scamcheck-notify.applescript", NOTIFY_SCRIPT)
    if not script:
        return False
    try:
        proc = subprocess.run(
            ["osascript", script, (title or "scamcheck")[:120],
             (message or "")[:400]],
            capture_output=True, timeout=15,
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Preferences
# ---------------------------------------------------------------------------

def prefs_path():
    return os.path.join(phones.data_dir(), "jarvis_prefs.json")


def load_prefs():
    try:
        with open(prefs_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_prefs(prefs):
    phones.ensure_dir()
    path = prefs_path()
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".jarvis-prefs-")
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


# ---------------------------------------------------------------------------
# URL / number reports
# ---------------------------------------------------------------------------

def link_risk(report):
    """Map netintel notes onto the normal 0-100 verdict scale."""
    score = 0
    for note in report.get("notes") or []:
        low = note.lower()
        if "not https" in low:
            score += 20
        elif "raw ip" in low:
            score += 25
        elif "punycode" in low:
            score += 20
        elif "shortened" in low:
            score += 10
        elif "multiple redirects" in low:
            score += 10
        elif "different domain" in low:
            score += 15
        elif "very new" in low:
            score += 25
    score = max(0, min(100, score))
    if score >= 60:
        verdict = "SCAM"
    elif score >= 35:
        verdict = "LIKELY SCAM"
    elif score >= 15:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY SAFE"
    return verdict, score


def link_notes(report):
    """Only the notes that are actually risk flags (not 'domain is N days old')."""
    return [n for n in (report.get("notes") or [])
            if not n.lower().startswith("domain is ")]


def format_link_report(report, lang="en"):
    verdict, score = link_risk(report)
    icon, key = bot.VERDICT_STYLE.get(verdict, ("⚠️", "suspicious"))
    lines = ["%s %s  (%d/100)" % (icon, bot._t(lang, key), score), ""]
    lines.append("Input: " + str(report.get("input") or ""))
    final_url = report.get("final_url") or ""
    if final_url and final_url != report.get("input"):
        lines.append("Final: " + final_url)
    if report.get("domain"):
        lines.append("Domain: " + report["domain"])
    if report.get("title"):
        lines.append("Title: " + report["title"])

    chain = report.get("chain") or []
    redirects = [c for c in chain if c.get("to")]
    if redirects:
        lines.append("Redirects: %d" % len(redirects))
        for hop in redirects[:5]:
            lines.append("  %s -> %s" % (hop.get("status", "?"), hop.get("to", "")))

    tls = report.get("tls") or {}
    if tls.get("issuer"):
        lines.append("TLS: %s (%s)" % (tls["issuer"], tls.get("tls_version") or "?"))
    elif tls.get("error"):
        lines.append("TLS: " + tls["error"])

    rdap = report.get("rdap") or {}
    if rdap.get("age_days") is not None:
        lines.append("Domain age: %d days (registered %s)" % (
            rdap["age_days"], (rdap.get("registered") or "?")[:10]))

    notes = link_notes(report)
    lines.append("")
    if notes:
        lines.append("Why:")
        for note in notes[:8]:
            lines.append("• " + note)
    else:
        lines.append("No obvious link red flags - that is not a guarantee.")

    lines.append("")
    lines.append(bot._t(lang, "advice_" + key))
    lines.append("")
    lines.append("This query fetched the link. It ran only because you asked.")
    return "\n".join(lines)


def number_verdict(intel):
    info = intel.get("number") or {}
    rep = intel.get("reputation") or {}
    if rep.get("status") == "allowed":
        return "LIKELY SAFE", 0
    if rep.get("status") == "blocked":
        return "SCAM", 80
    if rep.get("status") == "reported":
        return "LIKELY SCAM", 40
    if info.get("kind") == "premium":
        return "SUSPICIOUS", 20
    if info.get("kind") in ("shortcode", "sender_id"):
        return "SUSPICIOUS", 15
    return "LIKELY SAFE", 0


def format_number_report(intel, lang="en"):
    verdict, score = number_verdict(intel)
    icon, key = bot.VERDICT_STYLE.get(verdict, ("⚠️", "suspicious"))
    info = intel.get("number") or {}
    rep = intel.get("reputation") or {}
    label = info.get("e164") or info.get("national") or info.get("input") or "?"
    lines = ["%s %s  (%d/100)" % (icon, bot._t(lang, key), score), ""]
    lines.append("Number: " + label)
    kind = info.get("kind") or "number"
    country = info.get("country_name") or info.get("country")
    lines.append("Type: %s%s" % (kind, (" · " + country) if country else ""))
    if rep.get("status") == "blocked":
        lines.append("Local: ON YOUR BLOCKLIST" +
                     (" (%s)" % rep["label"] if rep.get("label") else ""))
    elif rep.get("status") == "allowed":
        lines.append("Local: on your allowlist" +
                     (" (%s)" % rep["label"] if rep.get("label") else ""))
    elif rep.get("status") == "reported":
        lines.append("Local: reported %d time%s via %s" % (
            rep.get("reports", 1), "" if rep.get("reports") == 1 else "s",
            rep.get("source")))
    else:
        lines.append("Local: no reputation data (not a clean bill of health)")
    flags = intel.get("flags") or []
    if flags:
        lines.append("")
        lines.append("Flags:")
        for flag in flags:
            lines.append("• " + flag)
    lines.append("")
    lines.append(bot._t(lang, "advice_" + key))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class JarvisSession:
    """One console session: state, tools, memory, voice and alerts."""

    def __init__(self, voice=None, notify=None, lang=None, region=None,
                 history=None, ai=None, out=None, persist=True):
        prefs = load_prefs()
        self.voice = bool(prefs.get("voice")) if voice is None else bool(voice)
        self.notify = bool(prefs.get("notify")) if notify is None else bool(notify)
        self.lang = (lang or prefs.get("lang") or "en").lower()
        if self.lang not in ("en", "hi"):
            self.lang = "en"
        self.region = (region or prefs.get("region") or phones.default_region()).upper()
        self.sender = prefs.get("sender") or None
        env_ai = (os.environ.get("SCAMCHECK_JARVIS_AI") or "never").lower()
        self.ai = (ai or env_ai) if (ai or env_ai) in ("never", "auto", "always") else "never"
        self.history = history or History()
        self.out = out or print
        self.last = None
        self._persist = bool(persist)
        self._save()

    def _save(self):
        if not getattr(self, "_persist", True):
            return
        try:
            save_prefs({
                "voice": self.voice,
                "notify": self.notify,
                "lang": self.lang,
                "region": self.region,
                "sender": self.sender,
            })
        except OSError:
            pass  # preferences are convenience; never block a check

    # -- announcements ----------------------------------------------------

    def _should_announce(self, verdict):
        if verdict in RISKY:
            return True
        return os.environ.get("SCAMCHECK_ANNOUNCE_ALL", "").lower() in ("1", "true", "yes")

    def _voice_name(self):
        if self.lang == "hi":
            return os.environ.get("SCAMCHECK_VOICE_NAME_HI") or os.environ.get("SCAMCHECK_VOICE_NAME")
        return os.environ.get("SCAMCHECK_VOICE_NAME")

    def _announce(self, verdict, score, spoken, body):
        if not self._should_announce(verdict):
            return
        if self.voice:
            speak(spoken, voice=self._voice_name())
        if self.notify:
            notify("scamcheck · " + verdict, "%d/100 · %s" % (int(score), body))

    def announce_result(self, result):
        verdict = result.get("final_verdict") or "SUSPICIOUS"
        score = int(result.get("score") or 0)
        key = bot.VERDICT_STYLE.get(verdict, ("⚠️", "suspicious"))[1]
        spoken = "%s. %d out of 100. %s" % (
            bot._t(self.lang, key), score, bot._t(self.lang, "advice_" + key))
        reasons = [r[0] for r in (result.get("reasons") or []) if r[1] > 0][:2]
        body = bot._t(self.lang, key) + ": " + ("; ".join(reasons) or "check the details")
        self._announce(verdict, score, spoken, body)

    # -- memory -----------------------------------------------------------

    def _remember(self, kind, verdict, score, text, identifiers, sender=None, meta=None):
        try:
            hits = self.history.seen_before(identifiers)
            self.history.record(kind, verdict, score, text=text, sender=sender,
                                identifiers=identifiers, meta=meta)
        except Exception as exc:
            return "\n\n⚠ Memory unavailable: %s" % exc
        return format_seen(hits, identifiers)

    def _watch_hits(self, identifiers):
        """Return a watchlist-hit block and bump counters (never raises)."""
        try:
            from .watchlist import Watchlist, format_hits
            store = Watchlist()
            hits = store.match(identifiers)
            if hits:
                store.bump(hits)
            return format_hits(hits, self.lang)
        except Exception:
            return ""

    def observe_result(self, result):
        """Record an externally produced analyze() result and announce it."""
        text = result.get("message") or ""
        kind = result.get("kind") or ("image" if result.get("ocr") else "text")
        identifiers = text_identifiers(text, result)
        number = result.get("number") or {}
        sender = ((number.get("sender") or {}).get("number") or {}).get("e164")
        seen = self._remember(
            kind, result.get("final_verdict") or "?", int(result.get("score") or 0),
            text, identifiers, sender=sender,
            meta={"scripts": result.get("scripts") or [],
                  "path": result.get("source_path")},
        )
        seen += self._watch_hits(identifiers)
        self.last = {"kind": kind, "result": result, "text": text}
        self.announce_result(result)
        return seen

    # -- tools ------------------------------------------------------------

    def check_text(self, text, sender=None):
        result = analyze(text, use_ai=self.ai, sender=sender or self.sender,
                         region=self.region)
        result["message"] = text
        result["kind"] = "text"
        seen = self.observe_result(result)
        reply = bot.format_reply(result, self.lang) + seen
        return {"text": reply, "result": result, "quit": False}

    def check_image(self, path):
        from .ocr import detect_qr, ocr_image, qr_text

        raw = (path or "").strip().strip("'\"")
        path = os.path.abspath(os.path.expanduser(raw))
        if not os.path.isfile(path):
            return {"text": "No image at " + path, "quit": False}
        text, engine = ocr_image(path)
        qr = detect_qr(path)
        codes = qr.get("codes") or []
        analysis = (text or "").strip()
        qr_lines = qr_text(codes)
        if qr_lines:
            analysis = (analysis + "\n" + qr_lines).strip()
        if not analysis:
            detail = qr.get("error") if not qr.get("available") else "no QR/barcode found"
            return {"text": "I couldn't read any text or QR code in that image "
                            "(%s OCR; %s)." % (engine or "no", detail or "no decoder"),
                    "quit": False}

        result = analyze(analysis, use_ai=self.ai, ocr=True,
                         sender=self.sender, region=self.region)
        result["message"] = analysis
        result["kind"] = "image"
        result["qr"] = codes
        result["ocr_engine"] = engine
        result["source_path"] = path
        seen = self.observe_result(result)

        lines = []
        if text and text.strip():
            lines.append("🖼 Read with %s OCR (%d chars)." % (engine, len(text)))
        else:
            lines.append("🖼 No OCR text; using the decoded QR payload.")
        if codes:
            lines.append("QR: " + codes[0]["payload"])
            if len(codes) > 1:
                lines.append("(+%d more QR code%s)" % (
                    len(codes) - 1, "" if len(codes) == 2 else "s"))
        lines.append(bot.format_reply(result, self.lang) + seen)
        return {"text": "\n".join(lines), "result": result, "quit": False}

    def check_qr(self, path):
        from .ocr import detect_qr

        raw = (path or "").strip().strip("'\"")
        path = os.path.abspath(os.path.expanduser(raw))
        if not os.path.isfile(path):
            return {"text": "No image at " + path, "quit": False}
        qr = detect_qr(path)
        if not qr.get("available"):
            return {"text": "QR decoder unavailable: %s" % (qr.get("error") or "unknown"),
                    "quit": False}
        codes = qr.get("codes") or []
        if not codes:
            return {"text": "No QR or barcode found in that image.", "quit": False}
        lines = ["QR/barcode codes (%d):" % len(codes)]
        for code in codes[:10]:
            lines.append("• %s (%s)" % (code["payload"], code.get("symbology") or "barcode"))
        urls = [c["payload"] for c in codes if c["payload"].lower().startswith(("http://", "https://"))]
        if urls:
            lines.append("")
            lines.append("This was decoded offline. To inspect the destination, run:")
            lines.append("  url " + urls[0])
        return {"text": "\n".join(lines), "quit": False}

    def check_clipboard(self):
        """One-shot clipboard check (text first, then image)."""
        from .ocr import clipboard_to_tempfile, get_clipboard_image, get_clipboard_text

        text = (get_clipboard_text() or "").strip()
        if text:
            reply = self.check_text(text)
            reply["text"] = "📋 Clipboard text.\n" + reply["text"]
            return reply
        raw = get_clipboard_image()
        if raw:
            path = clipboard_to_tempfile(raw)
            try:
                reply = self.check_image(path)
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            reply["text"] = "📋 Clipboard screenshot.\n" + reply["text"]
            return reply
        return {"text": "The clipboard has no text or image.", "quit": False}

    def check_url(self, target, allow_private=False):
        report = netintel.investigate_url(target, allow_private=allow_private)
        if not report.get("ok"):
            return {"text": "Could not investigate %s: %s" % (
                target, report.get("error") or "unknown error"), "quit": False}
        verdict, score = link_risk(report)
        identifiers = url_identifiers(report, target)
        seen = self._remember("url", verdict, score, target, identifiers)
        seen += self._watch_hits(identifiers)
        reply = format_link_report(report, self.lang) + seen
        key = bot.VERDICT_STYLE.get(verdict, ("⚠️", "suspicious"))[1]
        self._announce(
            verdict, score,
            "%s. Link check. %d out of 100. %s" % (
                bot._t(self.lang, key), score, bot._t(self.lang, "advice_" + key)),
            "link check: " + (report.get("domain") or target),
        )
        self.last = {"kind": "url", "report": report, "text": target}
        return {"text": reply, "report": report, "quit": False}

    def check_number(self, target):
        intel = phones.check_number(target, region=self.region)
        info = intel.get("number") or {}
        if not info.get("valid"):
            return {"text": "That doesn't look like a valid phone number (%s)." % (
                info.get("note") or "invalid"), "quit": False}
        verdict, score = number_verdict(intel)
        label = info.get("e164") or info.get("national") or target
        identifiers = [{"kind": "phone", "value": label, "label": label}]
        seen = self._remember("number", verdict, score, target, identifiers)
        seen += self._watch_hits(identifiers)
        reply = format_number_report(intel, self.lang) + seen
        key = bot.VERDICT_STYLE.get(verdict, ("⚠️", "suspicious"))[1]
        self._announce(
            verdict, score,
            "%s. Number check. %d out of 100. %s" % (
                bot._t(self.lang, key), score, bot._t(self.lang, "advice_" + key)),
            "number check: " + label,
        )
        self.last = {"kind": "number", "intel": intel, "text": target}
        return {"text": reply, "intel": intel, "quit": False}

    # -- history/status ---------------------------------------------------

    def format_history(self, rows, term=None):
        if not rows:
            return "No checks in local memory yet."
        lines = ["🧠 Recent checks:"]
        for row in rows:
            raw_text = row.get("text") or ""
            snippet = _snippet(raw_text, 62)
            if term and term.lower() not in snippet.lower():
                pos = raw_text.lower().find(term.lower())
                if pos >= 0:
                    start = max(0, pos - 24)
                    snippet = ("..." if start else "") + _snippet(raw_text[start:], 70)
            lines.append("• %s · %s (%d) · %s" % (
                _ago(row.get("ts")), row.get("verdict") or "?",
                int(row.get("score") or 0), snippet or "?"))
        return "\n".join(lines)

    def status(self):
        try:
            total = self.history.count()
        except Exception:
            total = 0
        ocr = []
        if sys.platform == "darwin":
            ocr.append("Apple Vision")
        if shutil.which("tesseract"):
            ocr.append("tesseract")
        qr = "Apple Vision" if sys.platform == "darwin" else "unavailable"
        feeds = len(phones.feed_status().get("sources") or [])
        try:
            cases = self._case_store().count()
        except Exception:
            cases = 0
        try:
            watched = self._watch_store().count()
        except Exception:
            watched = 0
        lines = [
            "scamcheck JARVIS core %s" % __version__,
            "Voice:     %s (macOS say)" % ("on" if self.voice else "off"),
            "Notify:    %s (macOS notifications)" % ("on" if self.notify else "off"),
            "Language:  %s" % self.lang,
            "Region:    %s" % self.region,
            "Sender:    %s" % (self.sender or "not set"),
            "AI:        %s" % self.ai,
            "OCR:       %s" % (", ".join(ocr) if ocr else "none available"),
            "QR:        %s" % qr,
            "Device:    audit ready (read-only, no sudo)",
            "Feeds:     %d cached source%s" % (feeds, "" if feeds == 1 else "s"),
            "Cases:     %d open/archived" % cases,
            "Watchlist: %d identifier%s" % (watched, "" if watched == 1 else "s"),
            "Memory:    %d check%s · %s" % (total, "" if total == 1 else "s", self.history.path),
            "Prefs:     %s" % prefs_path(),
        ]
        return "\n".join(lines)

    def why(self):
        if not self.last:
            return "Nothing to explain yet - check a message, link, image or number first."
        kind = self.last.get("kind")
        if kind == "url":
            report = self.last.get("report") or {}
            notes = link_notes(report)
            verdict, score = link_risk(report)
            text = "Link verdict: %s (%d/100)\n" % (verdict, score)
            text += "\n".join("• " + n for n in notes) if notes else "No link red flags."
            return text
        if kind == "number":
            intel = self.last.get("intel") or {}
            flags = intel.get("flags") or []
            verdict, score = number_verdict(intel)
            text = "Number verdict: %s (%d/100)\n" % (verdict, score)
            text += "\n".join("• " + f for f in flags) if flags else "No range/reputation flags."
            return text
        result = self.last.get("result") or {}
        lines = ["Verdict: %s (%d/100)" % (
            result.get("final_verdict") or "?", int(result.get("score") or 0))]
        reasons = result.get("reasons") or []
        if reasons:
            lines.append("Signals:")
            for label, weight in reasons:
                lines.append("• %s (%+d)" % (label, weight))
        else:
            lines.append("No signals fired.")
        if result.get("scripts"):
            lines.append("Playbook: " + ", ".join(result["scripts"]))
        conv = result.get("conversation")
        if conv:
            lines.append("Conversation: %s over %d messages" % (
                conv.get("verdict"), conv.get("message_count", 0)))
        return "\n".join(lines)

    # -- intelligence ----------------------------------------------------

    def _intel_for(self, rest=""):
        """Resolve a full intel briefing from new text or the last check."""
        rest = (rest or "").strip()
        if rest:
            result = analyze(rest, use_ai=self.ai, sender=self.sender,
                             region=self.region)
            result["message"] = rest
            result["kind"] = "text"
            self.last = {"kind": "text", "result": result, "text": rest}
            return result, None
        last = self.last or {}
        result = last.get("result")
        if not result:
            return None, ("Nothing checked yet. Use: assess <text> "
                          "(or check a message first).")
        if not result.get("intelligence"):
            return None, ("The last item was a %s, not a message. "
                          "Use: assess <text>." % (last.get("kind") or "report"))
        return result, None

    def assess_command(self, rest=""):
        from .intelligence import format_briefing
        result, error = self._intel_for(rest)
        if error:
            return error
        intel = result["intelligence"]
        head = "Verdict: %s (%d/100)" % (
            result.get("final_verdict") or "?", int(result.get("score") or 0))
        return head + "\n\n" + format_briefing(intel)

    def next_command(self):
        result, error = self._intel_for("")
        if error:
            return error
        moves = (result["intelligence"].get("next_moves") or [])
        if not moves:
            return "No clear attacker next-move pattern for that message."
        return "Likely next moves:\n" + "\n".join("• " + m for m in moves)

    def reply_command(self):
        result, error = self._intel_for("")
        if error:
            return error
        intel = result["intelligence"]
        replies = intel.get("safe_replies") or []
        if not replies:
            return "No safe reply needed for that message."
        note = ("Best is no reply at all. If you must respond:"
                if intel.get("reply_policy") == "do_not_reply"
                else "If you must respond:")
        return note + "\n" + "\n".join("• " + r for r in replies)

    def brief_command(self):
        result, error = self._intel_for("")
        if error:
            return error
        from .intelligence import format_briefing
        return "Verdict: %s (%d/100)\n\n%s" % (
            result.get("final_verdict") or "?",
            int(result.get("score") or 0),
            format_briefing(result["intelligence"]))

    # -- cases / watchlists / campaigns / recovery -----------------------

    @staticmethod
    def _case_store():
        from .cases import CaseStore
        return CaseStore()

    @staticmethod
    def _watch_store():
        from .watchlist import Watchlist
        return Watchlist()

    def case_list(self, limit=20):
        rows = self._case_store().list(limit=limit)
        if not rows:
            return ("No cases yet. Start one with:\n"
                    "  case new Bank transfer scam\n"
                    "  case add <case-id> screenshot.png")
        lines = ["🗂 Cases (%d):" % len(rows)]
        for row in rows:
            lines.append("• %s · %s · %s · %d evidence / %d entities · updated %s" % (
                row.get("id"), _snippet(row.get("title"), 48) or "?",
                row.get("status") or "?",
                int(row.get("evidence_count") or 0),
                int(row.get("entity_count") or 0),
                _ago(row.get("updated_ts"))))
        return "\n".join(lines)

    def case_show(self, case_id):
        case = self._case_store().get((case_id or "").strip())
        if not case:
            return "No case " + str(case_id)
        lines = [
            "🗂 Case %s — %s" % (case["id"], case["title"]),
            "Status: %s · Type: %s · Country: %s · Loss: %s" % (
                case.get("status"), case.get("scam_type") or "not recorded",
                case.get("country") or "?", _case_money(case)),
            "Opened: %s · Updated: %s" % (
                _ago(case.get("created_ts")), _ago(case.get("updated_ts"))),
        ]
        if case.get("notes"):
            lines += ["", "Notes: " + _snippet(case["notes"], 240)]
        lines += ["", "Entities (%d):" % len(case.get("entities") or [])]
        for item in (case.get("entities") or [])[:15]:
            lines.append("• %s: %s" % (intel.kind_label(item["kind"]),
                                       item.get("label") or item["value"]))
        lines += ["", "Evidence (%d):" % len(case.get("evidence") or [])]
        for index, item in enumerate((case.get("evidence") or [])[:15], start=1):
            lines.append("• #%d %s · %s · %d bytes · sha256 %s…" % (
                index, item.get("kind"), item.get("filename") or "inline text",
                int(item.get("size") or 0), (item.get("sha256") or "")[:16]))
        lines += ["", "Timeline:"]
        for event in (case.get("events") or [])[-12:]:
            lines.append("• %s · %s" % (_ago(event.get("ts")),
                                        event.get("description") or ""))
        lines += ["", "Next: case export %s | case verify %s | report %s" % (
            case["id"], case["id"], case["id"])]
        return "\n".join(lines)

    def case_command(self, rest):
        from . import recovery
        rest = (rest or "").strip()
        if not rest or rest in ("list", "ls", "all"):
            return self.case_list()
        action, _, tail = rest.partition(" ")
        action = action.lower()
        tail = tail.strip()

        if action == "new":
            if not tail:
                return "Use: case new <title>"
            store = self._case_store()
            case = store.create(tail, scam_type=recovery.infer_type(tail),
                                country=self.region)
            return ("Opened case %s — %s\n"
                    "Add evidence with: case add %s <file-or-text>\n"
                    "Export with: case export %s" % (
                        case["id"], case["title"], case["id"], case["id"]))

        if action in ("show", "view", "info"):
            return self.case_show(tail)

        if action in ("add", "attach", "file"):
            case_id, _, payload = tail.partition(" ")
            payload = payload.strip()
            if not case_id or not payload:
                return "Use: case add <case-id> <file-or-text>"
            store = self._case_store()
            try:
                if os.path.isfile(os.path.expanduser(payload.strip("'\""))):
                    info = store.add_file(case_id, payload)
                    return ("Added %s evidence to %s (sha256 %s…).\n"
                            "Verify with: case verify %s" % (
                                info["kind"], case_id, info["sha256"][:16], case_id))
                store.add_text(case_id, payload)
                return "Added text evidence to %s." % case_id
            except (KeyError, ValueError, OSError) as exc:
                return "Could not add evidence: %s" % exc

        if action in ("note", "notes"):
            case_id, _, note = tail.partition(" ")
            if not case_id or not note.strip():
                return "Use: case note <case-id> <text>"
            try:
                self._case_store().add_event(case_id, note.strip(), kind="note")
                return "Note added to %s." % case_id
            except KeyError as exc:
                return str(exc)

        if action in ("entity", "indicator"):
            case_id, _, entity = tail.partition(" ")
            if not case_id or not entity.strip():
                return "Use: case entity <case-id> KIND:VALUE"
            try:
                item = self._case_store().add_entity(case_id, entity.strip())
                return "Added %s: %s to %s." % (
                    intel.kind_label(item["kind"]), item.get("label") or item["value"],
                    case_id)
            except (KeyError, ValueError) as exc:
                return "Could not add entity: %s" % exc

        if action == "export":
            case_id, _, outdir = tail.partition(" ")
            if not case_id:
                return "Use: case export <case-id> [output-directory]"
            try:
                result = self._case_store().export(case_id, outdir.strip() or None)
            except (KeyError, OSError, ValueError) as exc:
                return "Could not export: %s" % exc
            lines = [
                "📦 Case %s exported:" % result["case_id"],
                "• folder: " + result["outdir"],
                "• JSON:   " + result["json"],
                "• HTML:   " + result["html"],
                "• hashes: " + result["hashes"],
            ]
            if result.get("pdf"):
                lines.append("• PDF:    " + result["pdf"])
            else:
                lines.append("• PDF:    not generated (%s)" % result.get("pdf_note"))
            return "\n".join(lines)

        if action in ("verify", "check"):
            try:
                report = self._case_store().verify(tail)
            except (KeyError, OSError) as exc:
                return "Could not verify: %s" % exc
            lines = ["🔐 Case %s evidence integrity: %s" % (
                report["case_id"], "OK" if report["ok"] else "PROBLEMS")]
            for item in report["evidence"]:
                lines.append("• #%s %s · %s%s" % (
                    item["id"], item.get("filename") or "inline text",
                    "ok" if item["ok"] else "FAIL",
                    "" if item["ok"] else " (" + item.get("reason", "changed") + ")"))
            return "\n".join(lines)

        if action in ("close", "reopen", "status"):
            case_id, _, value = tail.partition(" ")
            if not case_id:
                return "Use: case %s <case-id> [status]" % action
            status = value.strip().lower() if value.strip() else (
                "closed" if action == "close" else "open")
            try:
                case = self._case_store().set_status(case_id, status)
                return "Case %s is now %s." % (case["id"], case["status"])
            except (KeyError, ValueError) as exc:
                return str(exc)

        if action in ("report", "complaint"):
            return self.report_command(tail)

        return ("Case commands:\n"
                "  case list | case new <title> | case show <id>\n"
                "  case add <id> <file-or-text> | case note <id> <text>\n"
                "  case entity <id> KIND:VALUE | case export <id> [dir]\n"
                "  case verify <id> | case close <id> | report <id>")

    def watch_command(self, rest):
        from .watchlist import format_list
        rest = (rest or "").strip()
        if not rest or rest in ("list", "show", "all"):
            return format_list(self._watch_store().list())
        action, _, tail = rest.partition(" ")
        action = action.lower()
        if action in ("add", "watch"):
            rest = tail.strip()
        elif action in ("remove", "rm", "delete", "unwatch", "forget"):
            if not tail.strip():
                return "Use: unwatch KIND:VALUE"
            try:
                removed = self._watch_store().remove(tail.strip())
                return ("Removed from watchlist." if removed
                        else "That identifier was not on the watchlist.")
            except ValueError as exc:
                return str(exc)
        elif action in ("clear", "wipe"):
            n = self._watch_store().clear()
            return "Watchlist cleared (%d entries)." % n
        elif action in ("help", "?"):
            return ("watch <KIND:VALUE> | unwatch <KIND:VALUE> | watchlist | watch clear\n"
                    "Kinds: phone, url, upi, email, telegram, crypto_btc, "
                    "crypto_eth, crypto_trx, ifsc, apk")
        try:
            item = self._watch_store().add(rest)
        except ValueError as exc:
            return "Could not add to watchlist: %s" % exc
        return "Watching %s: %s" % (
            intel.kind_label(item["kind"]), item.get("label") or item["value"])

    def campaigns_command(self, rest):
        from . import campaigns
        rest = (rest or "").strip()
        if rest and not rest.isdigit() and rest.lower() not in ("list", "all"):
            camp = campaigns.get_campaign(rest)
            return (campaigns.format_campaign(camp) if camp
                    else "No campaign %s. Run 'campaigns' to list them." % rest)
        limit = int(rest) if rest.isdigit() else 10
        return campaigns.format_campaigns(campaigns.build_campaigns(limit=max(limit, 10)),
                                          limit=limit)

    def recover_command(self, rest):
        from . import recovery
        kind = (rest or "").strip() or "general"
        return recovery.format_playbook(recovery.get_playbook(kind, self.region))

    def device_command(self, arg=""):
        """Read-only device / private-LAN audit, exported as a local report."""
        from . import deviceaudit

        text = " ".join((arg or "").split()).lower()
        if text in ("help", "?", "options"):
            return ("Device audit is read-only and never uses sudo.\n"
                    "  scan device           this machine: posture, processes, persistence, "
                    "browsers, network, files\n"
                    "  scan device full      include every section\n"
                    "  scan device active    also TCP-probe common ports on private-LAN devices\n"
                    "  scan network          private-LAN inventory only\n"
                    "  scan network active   LAN inventory + TCP port probes\n"
                    "No exploitation, no public-IP scanning, no login attempts.")
        lan_only = text.startswith("network") or text.startswith("lan")
        active = any(word in text for word in ("active", "probe", "deep"))
        full = any(word in text for word in ("full", "everything", "all"))
        try:
            auditor = deviceaudit.DeviceAudit(
                active_lan=active,
                include_lan=True,
                include_mobile=not lan_only,
                max_hosts=64,
            )
            if lan_only:
                auditor.collect_lan()
                report = auditor.report()
            else:
                report = auditor.run()
            exported = deviceaudit.export_report(report)
        except Exception as exc:
            return "Device audit failed: %s" % exc
        body = deviceaudit.format_report(report, full=full)
        body += "\n\nReport saved: " + exported["folder"]
        if not active:
            body += ("\nActive LAN port checks are off. Type 'scan device active' "
                     "on a network you own.")
        return body

    def report_command(self, case_id):
        from . import recovery
        case_id = (case_id or "").strip()
        if not case_id:
            return "Use: report <case-id>"
        case = self._case_store().get(case_id)
        if not case:
            return "No case " + case_id
        return recovery.complaint_template(case, self.region, case.get("scam_type"))

    # -- command router ---------------------------------------------------

    def handle(self, line):
        raw = (line or "").strip()
        if not raw:
            return {"text": None, "quit": False}
        raw = re.sub(r"^(?:hey|ok|okay)?\s*jarvis[,: ]+", "", raw, flags=re.I).strip()
        if not raw:
            return {"text": HELP, "quit": False}
        low = raw.lower()

        if low in ("quit", "exit", "bye", "goodbye", "stop"):
            return {"text": "Goodbye.", "quit": True}
        if low in ("help", "?", "commands", "what can you do", "what can you do?"):
            return {"text": HELP, "quit": False}
        if low in ("who are you", "what are you"):
            return {"text": "scamcheck JARVIS core %s - a local scam detector with "
                            "memory, voice and a few sharp tools. Type 'help'." % __version__,
                    "quit": False}
        if low in ("status", "settings"):
            return {"text": self.status(), "quit": False}
        if low in ("feeds", "feed status"):
            status = phones.feed_status()
            sources = status.get("sources") or []
            if not sources:
                return {"text": "No cached feeds. Configure %s and run "
                                "`scamcheck --update-feeds`." % phones.feeds_conf_path(),
                        "quit": False}
            lines = ["Cached phone feeds (%d):" % len(sources)]
            for src in sources:
                lines.append("• %s · %d numbers · updated %s" % (
                    src.get("label") or src.get("url"), src.get("count", 0),
                    _ago(src.get("fetched_at"))))
            return {"text": "\n".join(lines), "quit": False}
        if low == "why":
            return {"text": self.why(), "quit": False}

        if low in ("paste", "clipboard", "clip"):
            return self.check_clipboard()

        if low in ("forget history", "clear history", "wipe history"):
            n = self.history.clear()
            return {"text": "History cleared (%d check%s deleted)." % (
                n, "" if n == 1 else "s"), "quit": False}

        if low in ("check", "image", "screenshot", "qr", "url", "link",
                   "number", "phone", "scan"):
            return {"text": "Give me something to work with - type 'help' for examples.",
                    "quit": False}

        match = re.match(r"^(voice|notify)(?:\s+(on|off|true|false|yes|no))?$", low)
        if match:
            name, value = match.group(1), match.group(2)
            current = getattr(self, name)
            if value is None:
                return {"text": "%s is %s." % (name.capitalize(), "on" if current else "off"),
                        "quit": False}
            new = value in ("on", "true", "yes")
            setattr(self, name, new)
            self._save()
            return {"text": "%s %s." % (name.capitalize(), "on" if new else "off"),
                    "quit": False}

        match = re.match(r"^(?:lang|language)(?:\s+(\S+))?$", low)
        if match:
            value = match.group(1)
            if not value:
                return {"text": "Language is %s. Use: lang en | hi" % self.lang,
                        "quit": False}
            if value not in ("en", "hi"):
                return {"text": "Use: lang en | hi", "quit": False}
            self.lang = value
            self._save()
            return {"text": "Language set to %s." % ("English" if value == "en" else "हिंदी"),
                    "quit": False}

        match = re.match(r"^region(?:\s+([a-zA-Z]{2}))?$", raw)
        if match:
            value = match.group(1)
            if not value:
                return {"text": "Region is %s. Use: region IN | US | GB" % self.region,
                        "quit": False}
            value = value.upper()
            if value not in phones.REGIONS:
                return {"text": "Unknown region %s." % value, "quit": False}
            self.region = value
            cfg = phones.load_config()
            cfg["region"] = value
            phones.save_config(cfg)
            self._save()
            return {"text": "Region set to %s (%s)." % (value, phones.REGIONS[value]),
                    "quit": False}

        match = re.match(r"^sender(?:\s+(.+))?$", raw, re.I)
        if match:
            value = (match.group(1) or "").strip()
            if not value:
                return {"text": "Sender is %s." % (self.sender or "not set"),
                        "quit": False}
            if value.lower() in ("off", "none", "clear"):
                self.sender = None
                self._save()
                return {"text": "Sender cleared.", "quit": False}
            info = phones.normalize_number(value, region=self.region)
            if not info["valid"]:
                return {"text": "That doesn't look like a phone number.", "quit": False}
            self.sender = info["e164"] or info["national"]
            self._save()
            return {"text": "Sender set to %s." % self.sender, "quit": False}

        match = re.match(r"^history(?:\s+(.*))?$", low)
        if match:
            arg = (match.group(1) or "").strip()
            if arg in ("clear", "forget", "wipe"):
                n = self.history.clear()
                return {"text": "History cleared (%d check%s deleted)." % (
                    n, "" if n == 1 else "s"), "quit": False}
            if arg and not arg.isdigit():
                return {"text": "Use: history [n] | history clear | search <term>",
                        "quit": False}
            return {"text": self.format_history(self.history.recent(int(arg or 10))),
                    "quit": False}

        match = re.match(r"^(?:search|find)\s+(.+)$", raw, re.I)
        if match:
            term = match.group(1)
            rows = self.history.search(term)
            if not rows:
                return {"text": "Nothing in memory matches %r." % term,
                        "quit": False}
            return {"text": "🔎 " + self.format_history(rows, term=term),
                    "quit": False}

        match = re.match(r"^(?:cases?)(?:\s+(.*))?$", raw, re.I)
        if match:
            return {"text": self.case_command(match.group(1) or ""),
                    "quit": False}

        match = re.match(r"^(watchlist|watch)$", low)
        if match:
            return {"text": self.watch_command("list"), "quit": False}

        match = re.match(r"^watch\s+(.+)$", raw, re.I)
        if match:
            arg = match.group(1).strip()
            head = arg.split(" ", 1)[0].lower()
            if head in ("list", "show", "all", "clear", "wipe", "help", "?",
                        "add", "remove", "rm", "delete", "forget"):
                return {"text": self.watch_command(arg), "quit": False}
            return {"text": self.watch_command("add " + arg), "quit": False}

        match = re.match(r"^(?:unwatch|unwatchlist|dontwatch)\s+(.+)$", raw, re.I)
        if match:
            return {"text": self.watch_command("remove " + match.group(1)),
                    "quit": False}

        match = re.match(r"^(?:campaigns?)(?:\s+(.*))?$", raw, re.I)
        if match:
            return {"text": self.campaigns_command(match.group(1) or ""),
                    "quit": False}

        match = re.match(r"^(?:recover|recovery)(?:\s+(.*))?$", raw, re.I)
        if match:
            return {"text": self.recover_command(match.group(1) or ""),
                    "quit": False}

        match = re.match(r"^(?:report|complaint)\s+(.+)$", raw, re.I)
        if match:
            return {"text": self.report_command(match.group(1)),
                    "quit": False}

        if low in ("devices", "lan", "network", "local network", "scan devices"):
            return {"text": self.device_command("network"), "quit": False}

        match = re.match(
            r"^(?:scan|audit|check|inspect)\s+(?:my\s+|this\s+)?"
            r"(?:device|mac|macbook|computer|laptop|machine|system)(?:\s+(.*))?$",
            raw, re.I)
        if match:
            return {"text": self.device_command(match.group(1) or ""),
                    "quit": False}

        match = re.match(r"^device\s+(?:audit|scan|check)(?:\s+(.*))?$", raw, re.I)
        if match:
            return {"text": self.device_command(match.group(1) or ""),
                    "quit": False}

        match = re.match(
            r"^(?:scan|audit|check|inspect)\s+(?:the\s+|my\s+)?"
            r"(?:network|lan|wifi|wi-fi|router|routers)(?:\s+(.*))?$",
            raw, re.I)
        if match:
            return {"text": self.device_command("network " + (match.group(1) or "")),
                    "quit": False}

        match = re.match(r"^(?:assess|intel|intelligence)\b[:\s]*(.*)$", raw, re.I)
        if match:
            return {"text": self.assess_command(match.group(1)),
                    "quit": False}

        if low in ("next", "next move", "next moves", "what next"):
            return {"text": self.next_command(), "quit": False}

        if low in ("reply", "safe reply", "safe replies", "what should i say"):
            return {"text": self.reply_command(), "quit": False}

        if low in ("brief", "briefing", "full brief"):
            return {"text": self.brief_command(), "quit": False}

        match = re.match(r"^(?:image|screenshot|photo|check image|scan image)\s+(.+)$",
                         raw, re.I)
        if match:
            return self.check_image(match.group(1))

        match = re.match(r"^(?:qr|barcode|decode qr)\s+(.+)$", raw, re.I)
        if match:
            return self.check_qr(match.group(1))

        match = re.match(r"^(?:url|link|investigate|check link|check url)\s+(.+)$",
                         raw, re.I)
        if match:
            return self.check_url(match.group(1).strip())

        match = re.match(r"^(?:number|phone|check number|check phone)\s+(.+)$",
                         raw, re.I)
        if match:
            return self.check_number(match.group(1).strip())

        match = re.match(r"^(block|allow|forget)\s+(.+)$", raw, re.I)
        if match:
            action, rest = match.group(1).lower(), match.group(2).strip()
            number, label = self._number_and_label(rest)
            if action == "forget":
                removed = phones.forget_number(number)
                return {"text": "Removed %s from %d local list%s." % (
                    number, removed, "" if removed == 1 else "s"), "quit": False}
            try:
                if action == "block":
                    info = phones.add_block(number, label or "blocked in JARVIS")
                else:
                    info = phones.add_allow(number, label or "allowed in JARVIS")
            except ValueError as exc:
                return {"text": str(exc), "quit": False}
            return {"text": "%sed %s locally." % (
                "Block" if action == "block" else "Allow",
                info["e164"] or info["national"]), "quit": False}

        match = re.match(r"^(?:check|analyze|analyse|scan|test)\b[:\s]*(.+)$", raw, re.I)
        if match:
            payload = match.group(1).strip()
            if not payload:
                return {"text": "Give me something to check, e.g. check <message>.",
                        "quit": False}
            return self.check_text(payload)

        match = re.match(r"^(?:is (?:this|that)|does (?:this|that)) (?:a )?scam\b[?:,\s]*(.*)$",
                         raw, re.I)
        if match and match.group(1).strip():
            return self.check_text(match.group(1).strip())

        # Bare text: the console is a message checker first.
        if len(raw) >= 3:
            return self.check_text(raw)
        return {"text": "Type 'help' to see what I can do.", "quit": False}

    @staticmethod
    def _number_and_label(rest):
        """Split ``+91 98765 43210 scam label`` into number + optional label."""
        tokens = (rest or "").split()
        for n in range(len(tokens), 0, -1):
            candidate = " ".join(tokens[:n])
            info = phones.normalize_number(candidate)
            if info["valid"]:
                return candidate, " ".join(tokens[n:])
        return rest, ""


# ---------------------------------------------------------------------------
# REPL
# ---------------------------------------------------------------------------

def run_repl(session=None, instream=None, outstream=None, initial=None):
    """Run the console until quit/EOF. Works for pipes and real terminals."""
    session = session or JarvisSession()
    instream = instream or sys.stdin
    outstream = outstream or sys.stdout
    interactive = bool(getattr(instream, "isatty", lambda: False)())

    if interactive:
        print("scamcheck %s · JARVIS core" % __version__, file=outstream)
        print("Local-first. Type 'help' for tools, 'quit' to exit.", file=outstream)

    def emit(reply):
        if reply and reply.get("text"):
            print(reply["text"], file=outstream)
            outstream.flush()

    def step(text):
        try:
            reply = session.handle(text)
        except KeyboardInterrupt:
            print("", file=outstream)
            return True
        except Exception as exc:  # keep the console alive on a bad tool input
            reply = {"text": "Something went wrong: %s" % exc, "quit": False}
        emit(reply)
        return bool(reply.get("quit"))

    if initial and step(initial):
        return 0

    while True:
        if interactive:
            try:
                line = input("you> ")
            except EOFError:
                break
            except KeyboardInterrupt:
                print("", file=outstream)
                break
        else:
            line = instream.readline()
            if line == "":
                break
        if step(line.rstrip("\n")):
            break

    if interactive:
        print("scamcheck offline.", file=outstream)
    return 0
