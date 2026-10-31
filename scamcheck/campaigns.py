"""Campaign clustering over local check history.

Checks are linked when they share an identifier: a phone number, domain, UPI
ID, wallet, Telegram handle, etc. Connected checks form a campaign, which is
how one victim's report becomes an early warning for the next.

This is intentionally local and explainable: no ML, no network, just the
identifier table that JARVIS already records. Exact-message hashes are
excluded so duplicate forwards do not connect unrelated campaigns.
"""

import os
import sqlite3
import time

from . import intel, phones

GROUP_KINDS = {
    "url", "phone", "sender", "upi", "email", "telegram", "whatsapp",
    "ifsc", "apk", "crypto_btc", "crypto_eth", "crypto_trx",
}


def _db_path():
    return os.path.join(phones.data_dir(), "history.db")


def _connect():
    path = _db_path()
    if not os.path.isfile(path):
        return None
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


class _Union:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def build_campaigns(min_checks=2, limit=50):
    """Return campaigns as dicts, newest first."""
    conn = _connect()
    if conn is None:
        return []
    try:
        checks = {row["id"]: dict(row) for row in conn.execute(
            "SELECT id, ts, kind, verdict, score, text, sender FROM checks")}
        if not checks:
            return []
        rows = [dict(r) for r in conn.execute(
            "SELECT check_id, kind, value, label FROM identifiers")]
    except sqlite3.Error:
        return []
    finally:
        conn.close()

    groups = {}
    for item in rows:
        if item["kind"] not in GROUP_KINDS:
            continue
        groups.setdefault((item["kind"], item["value"]), []).append(item["check_id"])

    union = _Union()
    for check_id in checks:
        union.find(check_id)
    for ids in groups.values():
        first = ids[0]
        for other in ids[1:]:
            union.union(first, other)

    components = {}
    for check_id in checks:
        components.setdefault(union.find(check_id), []).append(check_id)

    campaigns = []
    for ids in components.values():
        if len(ids) < max(2, int(min_checks or 2)):
            continue
        ids = sorted(ids)
        camp_checks = [checks[i] for i in ids]
        first_ts = min(c["ts"] for c in camp_checks)
        last_ts = max(c["ts"] for c in camp_checks)
        verdicts = {}
        for c in camp_checks:
            verdicts[c["verdict"]] = verdicts.get(c["verdict"], 0) + 1
        indicators = []
        for (kind, value), linked in groups.items():
            inside = [i for i in linked if i in set(ids)]
            if inside:
                label = next((r["label"] for r in rows
                              if r["kind"] == kind and r["value"] == value
                              and r["check_id"] in inside), value)
                indicators.append({
                    "kind": kind, "value": value, "label": label,
                    "checks": len(set(inside)),
                })
        indicators.sort(key=lambda x: (-x["checks"], x["kind"], x["value"]))
        campaigns.append({
            "id": "CAM-%05d" % ids[0],
            "check_ids": ids,
            "checks": len(ids),
            "first_ts": first_ts,
            "last_ts": last_ts,
            "verdicts": verdicts,
            "indicators": indicators,
            "latest": camp_checks[-1],
            "items": sorted(camp_checks, key=lambda c: c["ts"], reverse=True),
        })
    campaigns.sort(key=lambda c: c["last_ts"], reverse=True)
    return campaigns[:max(1, min(int(limit or 50), 500))]


def get_campaign(campaign_id):
    campaign_id = (campaign_id or "").strip().upper()
    for camp in build_campaigns(limit=500):
        if camp["id"] == campaign_id:
            return camp
    return None


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
    return "%dd ago" % int(delta // 86400)


def _snippet(text, limit=76):
    line = " ".join((text or "").split())
    return line if len(line) <= limit else line[:limit - 3] + "..."


def format_campaigns(campaigns, limit=10):
    if not campaigns:
        return ("No campaigns yet. A campaign appears when two or more checks "
                "share a phone number, domain, UPI ID or wallet.")
    lines = ["🕸 Campaigns (%d):" % len(campaigns)]
    for camp in campaigns[:limit]:
        verdicts = ", ".join("%s %d" % (k, v)
                             for k, v in sorted(camp["verdicts"].items()))
        indicators = ", ".join(
            "%s (%d)" % (item["label"], item["checks"])
            for item in camp["indicators"][:3])
        lines.append("• %s · %d check%s · last %s · %s" % (
            camp["id"], camp["checks"], "" if camp["checks"] == 1 else "s",
            _ago(camp["last_ts"]), verdicts or "?"))
        if indicators:
            lines.append("  " + indicators)
        latest = camp.get("latest") or {}
        lines.append("  latest: " + (_snippet(latest.get("text")) or "?"))
    if len(campaigns) > limit:
        lines.append("• (+%d more; run 'campaigns %d')" % (
            len(campaigns) - limit, len(campaigns)))
    return "\n".join(lines)


def format_campaign(camp):
    if not camp:
        return "No such campaign."
    lines = [
        "🕸 Campaign %s" % camp["id"],
        "Checks: %d · first %s · last %s" % (
            camp["checks"], _ago(camp["first_ts"]), _ago(camp["last_ts"])),
        "Verdicts: " + (", ".join("%s %d" % (k, v)
                                 for k, v in sorted(camp["verdicts"].items())) or "?"),
        "",
        "Shared indicators:",
    ]
    for item in camp["indicators"][:12]:
        lines.append("• %s: %s · %d check%s" % (
            intel.kind_label(item["kind"]), item.get("label") or item["value"],
            item["checks"], "" if item["checks"] == 1 else "s"))
    lines += ["", "Timeline:"]
    for check in camp["items"][:15]:
        lines.append("• %s · %s (%d) · %s" % (
            _ago(check.get("ts")), check.get("verdict") or "?",
            int(check.get("score") or 0), _snippet(check.get("text"), 70) or "?"))
    lines += [
        "",
        "Next steps:",
        "• watch the shared indicators so the next appearance alerts you",
        "• open a case and attach the relevant messages/screenshots",
        "• export the case pack for your bank or police report",
    ]
    return "\n".join(lines)
