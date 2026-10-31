"""Local evidence cases ("case packs") for scam reports.

A case is a small, self-contained investigation folder:

    ~/.scamcheck/cases.db                 metadata (0600)
    ~/.scamcheck/cases/<case-id>/evidence/  collected files (0600/0700)
    ~/.scamcheck/exports/<case-id>/        case.json / .md / .html (+ PDF)

Every piece of evidence stores its SHA-256 at collection time, so `verify`
can detect later edits. Export produces a human-readable pack plus a hashes
file; PDF is generated only when a local HTML→PDF converter is available.
No network, no cloud, no telemetry.
"""

import hashlib
import html
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import time

from . import __version__, intel, phones

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id          TEXT PRIMARY KEY,
    created_ts  REAL NOT NULL,
    updated_ts  REAL NOT NULL,
    title       TEXT NOT NULL,
    scam_type   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'open',
    country     TEXT NOT NULL DEFAULT '',
    currency    TEXT NOT NULL DEFAULT '',
    loss_amount REAL NOT NULL DEFAULT 0,
    notes       TEXT NOT NULL DEFAULT '',
    meta        TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS case_entities (
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    kind    TEXT NOT NULL,
    value   TEXT NOT NULL,
    label   TEXT NOT NULL DEFAULT '',
    ts      REAL NOT NULL,
    PRIMARY KEY (case_id, kind, value)
);
CREATE TABLE IF NOT EXISTS case_evidence (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id  TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    ts       REAL NOT NULL,
    kind     TEXT NOT NULL,
    filename TEXT,
    sha256   TEXT NOT NULL,
    size     INTEGER NOT NULL DEFAULT 0,
    source   TEXT NOT NULL DEFAULT '',
    text     TEXT NOT NULL DEFAULT '',
    meta     TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS case_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    ts          REAL NOT NULL,
    kind        TEXT NOT NULL,
    description TEXT NOT NULL,
    meta        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_case_evidence ON case_evidence(case_id, ts);
CREATE INDEX IF NOT EXISTS idx_case_events ON case_events(case_id, ts);
CREATE INDEX IF NOT EXISTS idx_case_entities ON case_entities(case_id, kind);
"""

IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".heic", ".heif", ".tif",
                    ".tiff", ".webp", ".bmp", ".gif")
TEXT_EXTENSIONS = (".txt", ".md", ".csv", ".log", ".json", ".eml", ".html",
                   ".htm", ".xml", ".yaml", ".yml")


def _now():
    return time.time()


def _safe_name(name, fallback="evidence"):
    base = os.path.basename(name or "").strip() or fallback
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._")
    return (base or fallback)[:90]


def _sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _case_id():
    return "C-%s-%s" % (time.strftime("%Y%m%d"), secrets.token_hex(2).upper())


def _row(row):
    return dict(row) if row is not None else None


class CaseStore:
    """SQLite case metadata + a private evidence folder per case."""

    def __init__(self, path=None, vault=None):
        self.path = path or os.path.join(phones.data_dir(), "cases.db")
        self.vault = vault or os.path.join(phones.data_dir(), "cases")

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

    def _case_dir(self, case_id):
        path = os.path.join(self.vault, _safe_name(case_id, "case"))
        os.makedirs(path, mode=0o700, exist_ok=True)
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
        return path

    # -- create/read ------------------------------------------------------

    def create(self, title, scam_type="", country=None, currency="",
               loss_amount=0, notes=""):
        title = (title or "").strip()
        if not title:
            raise ValueError("case title is required")
        case_id = _case_id()
        now = _now()
        conn = self._connect()
        try:
            while conn.execute("SELECT 1 FROM cases WHERE id = ?", (case_id,)).fetchone():
                case_id = _case_id()
            conn.execute(
                "INSERT INTO cases (id, created_ts, updated_ts, title, scam_type, "
                "status, country, currency, loss_amount, notes, meta) "
                "VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, '{}')",
                (case_id, now, now, title[:300], (scam_type or "")[:80],
                 (country or phones.default_region()).upper(),
                 (currency or "")[:8], float(loss_amount or 0), (notes or "")[:8000]),
            )
            conn.execute(
                "INSERT INTO case_events (case_id, ts, kind, description) "
                "VALUES (?, ?, 'created', ?)",
                (case_id, now, "Case opened: " + title[:200]),
            )
            conn.commit()
        finally:
            conn.close()
        self._case_dir(case_id)
        return self.get(case_id)

    def get(self, case_id):
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
            if not row:
                return None
            case = _row(row)
            case["meta"] = _json(case.get("meta"))
            case["entities"] = [
                _row(r) for r in conn.execute(
                    "SELECT kind, value, label, ts FROM case_entities "
                    "WHERE case_id = ? ORDER BY kind, value", (case_id,))
            ]
            case["evidence"] = [
                _row(r) for r in conn.execute(
                    "SELECT id, ts, kind, filename, sha256, size, source, text, meta "
                    "FROM case_evidence WHERE case_id = ? ORDER BY ts, id", (case_id,))
            ]
            for item in case["evidence"]:
                item["meta"] = _json(item.get("meta"))
            case["events"] = [
                _row(r) for r in conn.execute(
                    "SELECT id, ts, kind, description FROM case_events "
                    "WHERE case_id = ? ORDER BY ts, id", (case_id,))
            ]
            return case
        finally:
            conn.close()

    def list(self, limit=20, status=None):
        conn = self._connect()
        try:
            sql = (
                "SELECT c.*, "
                "(SELECT COUNT(*) FROM case_evidence e WHERE e.case_id = c.id) AS evidence_count, "
                "(SELECT COUNT(*) FROM case_entities x WHERE x.case_id = c.id) AS entity_count "
                "FROM cases c"
            )
            params = []
            if status:
                sql += " WHERE c.status = ?"
                params.append(status)
            sql += " ORDER BY c.updated_ts DESC LIMIT ?"
            params.append(max(1, min(int(limit or 20), 100)))
            return [_row(r) for r in conn.execute(sql, params)]
        finally:
            conn.close()

    def count(self):
        conn = self._connect()
        try:
            return int(conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0])
        finally:
            conn.close()

    # -- writes -----------------------------------------------------------

    def _touch(self, conn, case_id):
        conn.execute("UPDATE cases SET updated_ts = ? WHERE id = ?", (_now(), case_id))

    def _require(self, conn, case_id):
        row = conn.execute("SELECT id FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not row:
            raise KeyError("no case %s" % case_id)

    def add_entity(self, case_id, entity):
        if isinstance(entity, str):
            entity = intel.parse_entity(entity)
        elif isinstance(entity, dict) and not entity.get("kind"):
            raise ValueError("entity needs kind and value")
        else:
            entity = intel.normalize_entity(entity.get("kind"), entity.get("value"))
        now = _now()
        conn = self._connect()
        try:
            self._require(conn, case_id)
            conn.execute(
                "INSERT OR IGNORE INTO case_entities (case_id, kind, value, label, ts) "
                "VALUES (?, ?, ?, ?, ?)",
                (case_id, entity["kind"], entity["value"],
                 entity.get("label") or entity["value"], now),
            )
            self._touch(conn, case_id)
            conn.commit()
        finally:
            conn.close()
        return entity

    def add_event(self, case_id, description, kind="note", meta=None):
        now = _now()
        conn = self._connect()
        try:
            self._require(conn, case_id)
            conn.execute(
                "INSERT INTO case_events (case_id, ts, kind, description, meta) "
                "VALUES (?, ?, ?, ?, ?)",
                (case_id, now, kind or "note", (description or "")[:4000],
                 json.dumps(meta or {}, ensure_ascii=False)),
            )
            self._touch(conn, case_id)
            conn.commit()
        finally:
            conn.close()

    def _add_entities(self, conn, case_id, entities):
        now = _now()
        for entity in intel.dedupe(entities):
            conn.execute(
                "INSERT OR IGNORE INTO case_entities (case_id, kind, value, label, ts) "
                "VALUES (?, ?, ?, ?, ?)",
                (case_id, entity["kind"], entity["value"],
                 entity.get("label") or entity["value"], now),
            )

    def add_text(self, case_id, text, kind="text", source="manual", meta=None):
        text = (text or "").strip()
        if not text:
            raise ValueError("text evidence is empty")
        # Hash exactly what we store so `verify` stays meaningful.
        text = text[:200000]
        raw = text.encode("utf-8", "replace")
        sha = _sha_bytes(raw)
        now = _now()
        conn = self._connect()
        try:
            self._require(conn, case_id)
            cur = conn.execute(
                "INSERT INTO case_evidence (case_id, ts, kind, filename, sha256, "
                "size, source, text, meta) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?)",
                (case_id, now, kind or "text", sha, len(raw), source or "manual",
                 text, json.dumps(meta or {}, ensure_ascii=False)),
            )
            self._add_entities(conn, case_id, intel.extract_entities(text))
            conn.execute(
                "INSERT INTO case_events (case_id, ts, kind, description) "
                "VALUES (?, ?, ?, ?)",
                (case_id, now, kind or "text",
                 "%s evidence added: %s" % ((kind or "text").title(), text[:150])),
            )
            self._touch(conn, case_id)
            conn.commit()
            evidence_id = cur.lastrowid
        finally:
            conn.close()
        return {"id": evidence_id, "sha256": sha, "size": len(raw), "kind": kind or "text"}

    def add_file(self, case_id, path, kind=None, source="", note="", ocr=True):
        path = os.path.abspath(os.path.expanduser((path or "").strip()))
        if not os.path.isfile(path):
            raise ValueError("no such file: %s" % path)
        if self.get(case_id) is None:
            raise KeyError("no case %s" % case_id)
        with open(path, "rb") as fh:
            data = fh.read()
        sha = _sha_bytes(data)
        size = len(data)
        ext = os.path.splitext(path)[1].lower()
        if not kind:
            if ext in IMAGE_EXTENSIONS:
                kind = "image"
            elif ext == ".pdf":
                kind = "pdf"
            elif ext in TEXT_EXTENSIONS:
                kind = "text"
            else:
                kind = "file"
        text = ""
        if kind == "text":
            try:
                text = data.decode("utf-8", "replace")[:200000]
            except Exception:
                text = ""
        if kind == "image" and ocr:
            try:
                from .ocr import ocr_image
                text, _engine = ocr_image(path)
                text = (text or "")[:200000]
            except Exception:
                text = ""

        folder = os.path.join(self._case_dir(case_id), "evidence")
        os.makedirs(folder, mode=0o700, exist_ok=True)
        base = _safe_name(os.path.basename(path))
        filename = "%d-%s" % (int(time.time() * 1000), base)
        counter = 1
        while os.path.exists(os.path.join(folder, filename)):
            filename = "%d-%d-%s" % (int(time.time() * 1000), counter, base)
            counter += 1
        dest = os.path.join(folder, filename)
        with open(dest, "wb") as fh:
            fh.write(data)
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass

        now = _now()
        conn = self._connect()
        try:
            self._require(conn, case_id)
            cur = conn.execute(
                "INSERT INTO case_evidence (case_id, ts, kind, filename, sha256, "
                "size, source, text, meta) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (case_id, now, kind, filename, sha, size, source or path,
                 text, json.dumps({"original": path, "note": note}, ensure_ascii=False)),
            )
            if text:
                self._add_entities(conn, case_id, intel.extract_entities(text))
            conn.execute(
                "INSERT INTO case_events (case_id, ts, kind, description) "
                "VALUES (?, ?, ?, ?)",
                (case_id, now, kind,
                 "%s evidence added: %s%s" % (
                     kind.title(), os.path.basename(path),
                     (" (" + note[:120] + ")") if note else "")),
            )
            self._touch(conn, case_id)
            conn.commit()
            evidence_id = cur.lastrowid
        finally:
            conn.close()
        return {
            "id": evidence_id, "kind": kind, "filename": filename,
            "sha256": sha, "size": size, "stored": dest,
        }

    def set_status(self, case_id, status, note=""):
        status = (status or "").strip().lower()
        if status not in ("open", "closed", "reported", "recovered"):
            raise ValueError("status must be open, closed, reported or recovered")
        conn = self._connect()
        try:
            self._require(conn, case_id)
            conn.execute("UPDATE cases SET status = ?, updated_ts = ? WHERE id = ?",
                         (status, _now(), case_id))
            conn.execute(
                "INSERT INTO case_events (case_id, ts, kind, description) "
                "VALUES (?, ?, 'status', ?)",
                (case_id, _now(), "Status set to %s%s" % (
                    status, (": " + note) if note else "")),
            )
            conn.commit()
        finally:
            conn.close()
        return self.get(case_id)

    def update(self, case_id, **fields):
        allowed = {"title", "scam_type", "country", "currency", "loss_amount", "notes"}
        updates = [(key, value) for key, value in fields.items() if key in allowed]
        if not updates:
            return self.get(case_id)
        conn = self._connect()
        try:
            self._require(conn, case_id)
            for key, value in updates:
                conn.execute("UPDATE cases SET %s = ? WHERE id = ?" % key, (value, case_id))
            self._touch(conn, case_id)
            conn.commit()
        finally:
            conn.close()
        return self.get(case_id)

    # -- verify/export ----------------------------------------------------

    def verify(self, case_id):
        case = self.get(case_id)
        if not case:
            raise KeyError("no case %s" % case_id)
        folder = os.path.join(self._case_dir(case_id), "evidence")
        rows = []
        for item in case["evidence"]:
            expected = item.get("sha256") or ""
            if item.get("filename"):
                path = os.path.join(folder, item["filename"])
                if not os.path.isfile(path):
                    rows.append({"id": item["id"], "filename": item["filename"],
                                 "ok": False, "reason": "missing"})
                    continue
                with open(path, "rb") as fh:
                    actual = _sha_bytes(fh.read())
            else:
                actual = _sha_bytes((item.get("text") or "").encode("utf-8", "replace"))
                path = None
            ok = actual == expected
            rows.append({
                "id": item["id"], "filename": item.get("filename"),
                "ok": ok, "reason": "" if ok else "hash mismatch",
                "expected": expected, "actual": actual,
            })
        return {"case_id": case_id, "ok": all(r["ok"] for r in rows), "evidence": rows}

    def export(self, case_id, outdir=None):
        case = self.get(case_id)
        if not case:
            raise KeyError("no case %s" % case_id)
        outdir = os.path.abspath(os.path.expanduser(
            outdir or os.path.join(phones.data_dir(), "exports", case_id)))
        os.makedirs(outdir, mode=0o700, exist_ok=True)
        try:
            os.chmod(outdir, 0o700)
        except OSError:
            pass
        evdir = os.path.join(outdir, "evidence")
        os.makedirs(evdir, mode=0o700, exist_ok=True)

        src = os.path.join(self._case_dir(case_id), "evidence")
        packed = []
        for index, item in enumerate(case["evidence"], start=1):
            if item.get("filename") and os.path.isfile(os.path.join(src, item["filename"])):
                filename = "%02d-%s" % (index, _safe_name(item["filename"]))
                dest = os.path.join(evdir, filename)
                shutil.copy2(os.path.join(src, item["filename"]), dest)
                try:
                    os.chmod(dest, 0o600)
                except OSError:
                    pass
            else:
                filename = "%02d-%s.txt" % (index, _safe_name(item.get("kind") or "note"))
                dest = os.path.join(evdir, filename)
                with open(dest, "w", encoding="utf-8") as fh:
                    fh.write(item.get("text") or "")
                try:
                    os.chmod(dest, 0o600)
                except OSError:
                    pass
            packed.append(dict(item, packed="evidence/" + filename))
        case["packed_evidence"] = packed

        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload = {
            "tool": "scamcheck",
            "version": __version__,
            "exported_at": stamp,
            "case": case,
        }
        json_path = os.path.join(outdir, "case.json")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")

        md_path = os.path.join(outdir, "case.md")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(_case_markdown(case, stamp))

        html_path = os.path.join(outdir, "case.html")
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(_case_html(case, stamp))

        sums = []
        for item in packed:
            sums.append("%s  %s" % (item.get("sha256") or "", item["packed"]))
        for name in ("case.json", "case.md", "case.html"):
            path = os.path.join(outdir, name)
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    sums.append("%s  %s" % (_sha_bytes(fh.read()), name))
        sums_path = os.path.join(outdir, "SHA256SUMS")
        with open(sums_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sums) + "\n")

        pdf_path = os.path.join(outdir, "case.pdf")
        pdf_ok = _html_to_pdf(html_path, pdf_path)

        return {
            "case_id": case_id,
            "outdir": outdir,
            "json": json_path,
            "markdown": md_path,
            "html": html_path,
            "hashes": sums_path,
            "pdf": pdf_path if pdf_ok else None,
            "pdf_note": None if pdf_ok else "install weasyprint/wkhtmltopdf or Chrome for PDF",
        }


def _json(raw):
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (TypeError, ValueError):
        return {}


def _money(case):
    amount = case.get("loss_amount") or 0
    currency = case.get("currency") or ""
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        amount = 0
    if not amount:
        return "not recorded"
    return ("%s %.2f" % (currency, amount)).strip()


def _case_markdown(case, stamp):
    lines = [
        "# Case %s — %s" % (case["id"], case["title"]),
        "",
        "- **Status:** %s" % case.get("status"),
        "- **Scam type:** %s" % (case.get("scam_type") or "not recorded"),
        "- **Country:** %s" % (case.get("country") or "not recorded"),
        "- **Loss:** %s" % _money(case),
        "- **Opened:** %s" % time.strftime("%Y-%m-%d %H:%M", time.localtime(case.get("created_ts") or 0)),
        "- **Exported:** %s" % stamp,
        "",
        "## Notes",
        "",
        case.get("notes") or "(none)",
        "",
        "## Timeline",
        "",
    ]
    for event in case.get("events") or []:
        lines.append("- **%s** · %s — %s" % (
            time.strftime("%Y-%m-%d %H:%M", time.localtime(event.get("ts") or 0)),
            event.get("kind") or "event", event.get("description") or ""))
    lines += ["", "## Suspect entities", ""]
    if case.get("entities"):
        lines += ["| Kind | Value | Label |", "|---|---|---|"]
        for item in case["entities"]:
            lines.append("| %s | `%s` | %s |" % (
                intel.kind_label(item.get("kind")),
                str(item.get("value") or "").replace("|", "\\|"),
                str(item.get("label") or "").replace("|", "\\|")))
    else:
        lines.append("(none recorded)")
    lines += ["", "## Evidence", ""]
    if case.get("packed_evidence"):
        lines += ["| # | Kind | Packed file | SHA-256 | Size |", "|---|---|---|---|---|"]
        for index, item in enumerate(case["packed_evidence"], start=1):
            lines.append("| %d | %s | `%s` | `%s` | %d |" % (
                index, item.get("kind") or "file", item["packed"],
                item.get("sha256") or "", int(item.get("size") or 0)))
        for index, item in enumerate(case["packed_evidence"], start=1):
            if (item.get("text") or "").strip():
                lines += ["", "### Evidence %d text" % index, "", "```",
                          (item.get("text") or "")[:8000], "```"]
    else:
        lines.append("(none collected)")
    lines += [
        "",
        "## Chain of custody",
        "",
        "Each evidence item was hashed with SHA-256 at collection time. "
        "Re-run `scamcheck --case-verify %s` to check for changes." % case["id"],
        "",
        "> This pack is an investigative aid, not a legal filing or legal advice. "
        "Verify local reporting requirements and preserve originals.",
        "",
    ]
    return "\n".join(lines)


def _case_html(case, stamp):
    def esc(value):
        return html.escape(str(value or ""))

    rows = []
    for index, item in enumerate(case.get("packed_evidence") or [], start=1):
        link = '<a href="%s">%s</a>' % (esc(item["packed"]), esc(item["packed"]))
        rows.append(
            "<tr><td>%d</td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%d</td></tr>"
            % (index, esc(item.get("kind")), link, esc(item.get("sha256")),
               int(item.get("size") or 0)))
    entities = "".join(
        "<tr><td>%s</td><td><code>%s</code></td><td>%s</td></tr>" % (
            esc(intel.kind_label(item.get("kind"))), esc(item.get("value")),
            esc(item.get("label")))
        for item in case.get("entities") or []
    ) or '<tr><td colspan="3">(none recorded)</td></tr>'
    events = "".join(
        "<li><b>%s</b> · %s — %s</li>" % (
            esc(time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("ts") or 0))),
            esc(e.get("kind")), esc(e.get("description")))
        for e in case.get("events") or []
    ) or "<li>(none)</li>"
    texts = "".join(
        "<h3>Evidence %d text</h3><pre>%s</pre>" % (index, esc((item.get("text") or "")[:12000]))
        for index, item in enumerate(case.get("packed_evidence") or [], start=1)
        if (item.get("text") or "").strip()
    )

    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Case %s — %s</title>
<style>
body{font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:960px;margin:32px auto;padding:0 20px;color:#111}
h1{border-bottom:2px solid #222;padding-bottom:8px} h2{margin-top:30px}
table{border-collapse:collapse;width:100%%;margin:10px 0} th,td{border:1px solid #bbb;padding:6px 8px;text-align:left;vertical-align:top}
code{font-size:12px;word-break:break-all} pre{background:#f4f4f4;padding:12px;white-space:pre-wrap;border:1px solid #ddd}
.meta{background:#f7f7f7;border:1px solid #ddd;padding:10px 14px;border-radius:6px}
.warn{border-left:4px solid #b8860b;padding:8px 12px;background:#fff8e1}
@media print{body{margin:0;max-width:none} a{color:#000;text-decoration:none}}
</style></head><body>
<h1>Case %s — %s</h1>
<div class="meta"><b>Status:</b> %s &nbsp; <b>Scam type:</b> %s &nbsp; <b>Country:</b> %s<br>
<b>Loss:</b> %s &nbsp; <b>Opened:</b> %s &nbsp; <b>Exported:</b> %s</div>
<h2>Notes</h2><p>%s</p>
<h2>Timeline</h2><ul>%s</ul>
<h2>Suspect entities</h2>
<table><tr><th>Kind</th><th>Value</th><th>Label</th></tr>%s</table>
<h2>Evidence</h2>
<table><tr><th>#</th><th>Kind</th><th>Packed file</th><th>SHA-256</th><th>Size</th></tr>%s</table>
%s
<p class="warn">This pack is an investigative aid, not a legal filing or legal advice.
Each item was hashed at collection time; re-run <code>scamcheck --case-verify %s</code>
to check for changes. Preserve originals and verify local reporting requirements.</p>
</body></html>
""" % (
        esc(case["id"]), esc(case["title"]),
        esc(case["id"]), esc(case["title"]),
        esc(case.get("status")), esc(case.get("scam_type") or "not recorded"),
        esc(case.get("country") or "not recorded"), esc(_money(case)),
        esc(time.strftime("%Y-%m-%d %H:%M", time.localtime(case.get("created_ts") or 0))),
        esc(stamp), esc(case.get("notes") or "(none)"), events, entities,
        "".join(rows) or '<tr><td colspan="5">(none collected)</td></tr>',
        texts, esc(case["id"]),
    )


def _html_to_pdf(html_path, pdf_path):
    """Best-effort local HTML→PDF. Never raises."""
    attempts = []
    if shutil.which("weasyprint"):
        attempts.append([shutil.which("weasyprint"), html_path, pdf_path])
    if shutil.which("wkhtmltopdf"):
        attempts.append([shutil.which("wkhtmltopdf"), "--quiet", html_path, pdf_path])
    for chrome in (
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        shutil.which("google-chrome"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
    ):
        if chrome and os.path.isfile(chrome):
            attempts.append([chrome, "--headless", "--disable-gpu", "--no-pdf-header-footer",
                             "--print-to-pdf=" + pdf_path, "file://" + html_path])
            break
    for cmd in attempts:
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=90)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0 and os.path.isfile(pdf_path) and os.path.getsize(pdf_path) > 0:
            try:
                os.chmod(pdf_path, 0o600)
            except OSError:
                pass
            return True
    return False
