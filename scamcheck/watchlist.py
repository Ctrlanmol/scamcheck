"""Local watchlists for numbers, domains, UPI IDs, wallets and handles.

A watchlist is deliberately simple: add an identifier, and every later check
that contains it gets a warning. Matching is local and deterministic. Hits
increment a counter so a repeated campaign is visible.
"""

import os
import sqlite3
import time

from . import intel, phones

SCHEMA = """
CREATE TABLE IF NOT EXISTS watchlist (
    kind        TEXT NOT NULL,
    value       TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    created_ts  REAL NOT NULL,
    last_hit_ts REAL,
    hits        INTEGER NOT NULL DEFAULT 0,
    notes       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (kind, value)
);
CREATE INDEX IF NOT EXISTS idx_watchlist_value ON watchlist(value);
"""


class Watchlist:
    def __init__(self, path=None):
        self.path = path or os.path.join(phones.data_dir(), "watchlist.db")

    def _connect(self):
        phones.ensure_dir()
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.executescript(SCHEMA)
        conn.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return conn

    def add(self, entity, label="", notes=""):
        if isinstance(entity, str):
            entity = intel.parse_entity(entity)
        elif isinstance(entity, dict):
            entity = intel.normalize_entity(entity.get("kind"), entity.get("value"))
        else:
            raise ValueError("watchlist entry must be a string or entity dict")
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO watchlist (kind, value, label, created_ts, notes) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(kind, value) DO UPDATE SET label = excluded.label, "
                "notes = excluded.notes",
                (entity["kind"], entity["value"],
                 (label or entity.get("label") or entity["value"])[:200],
                 time.time(), (notes or "")[:1000]),
            )
            conn.commit()
        finally:
            conn.close()
        return entity

    def remove(self, entity):
        if isinstance(entity, str):
            entity = intel.parse_entity(entity)
        elif isinstance(entity, dict):
            entity = intel.normalize_entity(entity.get("kind"), entity.get("value"))
        else:
            raise ValueError("watchlist entry must be a string or entity dict")
        conn = self._connect()
        try:
            cur = conn.execute("DELETE FROM watchlist WHERE kind = ? AND value = ?",
                               (entity["kind"], entity["value"]))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def clear(self):
        conn = self._connect()
        try:
            n = conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]
            conn.execute("DELETE FROM watchlist")
            conn.commit()
            return int(n)
        finally:
            conn.close()

    def list(self):
        conn = self._connect()
        try:
            return [dict(r) for r in conn.execute(
                "SELECT kind, value, label, created_ts, last_hit_ts, hits, notes "
                "FROM watchlist ORDER BY hits DESC, created_ts DESC")]
        finally:
            conn.close()

    def count(self):
        conn = self._connect()
        try:
            return int(conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0])
        finally:
            conn.close()

    def match(self, identifiers):
        """Return watchlist rows matching any identifier (no side effects)."""
        ids = intel.dedupe(identifiers)
        if not ids:
            return []
        conn = self._connect()
        try:
            out, seen = [], set()
            for item in ids:
                pairs = [(item["kind"], item["value"])]
                # A sender number is also a phone number: users watch phones.
                if item["kind"] == "sender":
                    pairs.append(("phone", item["value"]))
                for kind, value in pairs:
                    row = conn.execute(
                        "SELECT kind, value, label, created_ts, last_hit_ts, hits, notes "
                        "FROM watchlist WHERE kind = ? AND value = ?",
                        (kind, value),
                    ).fetchone()
                    if not row:
                        continue
                    key = (row["kind"], row["value"])
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(dict(row))
            return out
        finally:
            conn.close()

    def match_text(self, text, result=None):
        return self.match(intel.extract_entities(text or "", result=result))

    def bump(self, hits):
        if not hits:
            return 0
        now = time.time()
        conn = self._connect()
        try:
            n = 0
            for hit in hits:
                cur = conn.execute(
                    "UPDATE watchlist SET hits = hits + 1, last_hit_ts = ? "
                    "WHERE kind = ? AND value = ?",
                    (now, hit.get("kind"), hit.get("value")),
                )
                n += cur.rowcount
            conn.commit()
            return n
        finally:
            conn.close()


def format_hits(hits, lang="en"):
    if not hits:
        return ""
    lines = []
    for hit in hits[:8]:
        kind = intel.kind_label(hit.get("kind"))
        label = hit.get("label") or hit.get("value")
        count = int(hit.get("hits") or 0)
        suffix = ""
        if count:
            suffix = " · %d previous hit%s" % (count, "" if count == 1 else "s")
        lines.append("• %s: %s%s" % (kind, label, suffix))
    if len(hits) > 8:
        lines.append("• (+%d more)" % (len(hits) - 8))
    title = "⚠️ Watchlist hit" if lang != "hi" else "⚠️ वॉचलिस्ट मिलान"
    return "\n\n" + title + "\n" + "\n".join(lines)


def format_list(entries):
    if not entries:
        return ("Watchlist is empty. Add one with:\n"
                "  scamcheck --watch-add +91 98765 43210\n"
                "  scamcheck --watch-add url:evil-example.xyz")
    lines = ["Watchlist (%d):" % len(entries)]
    for item in entries:
        hits = int(item.get("hits") or 0)
        last = item.get("last_hit_ts")
        when = ""
        if last:
            when = " · last hit %s" % time.strftime("%Y-%m-%d %H:%M", time.localtime(last))
        lines.append("• %-13s %-34s %s%s" % (
            item.get("kind") or "?", (item.get("label") or item.get("value"))[:34],
            ("%d hit%s" % (hits, "" if hits == 1 else "s")) if hits else "no hits",
            when))
    return "\n".join(lines)
