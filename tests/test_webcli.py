#!/usr/bin/env python3
"""v0.12 tests: the JSON bridge used by the Next.js interface.

Each case spawns ``python3 -m scamcheck.webcli`` exactly as the web server
does, so the tests cover the real stdin/stdout contract, exit codes and error
shapes. Everything is local and deterministic.

Run: python3 tests/test_webcli.py
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

HOME = tempfile.mkdtemp(prefix="scamcheck-webcli-")
os.environ["SCAMCHECK_HOME"] = HOME
os.environ["SCAMCHECK_JARVIS_AI"] = "never"
os.environ.pop("SCAMCHECK_REGION", None)
os.environ.pop("OPENAI_API_KEY", None)
os.environ.pop("ANTHROPIC_API_KEY", None)

from scamcheck import __version__                           # noqa: E402


def check(name, ok, detail=""):
    print("[%s] %s" % ("PASS" if ok else "FAIL", name))
    if detail:
        print("      " + str(detail))
    return 0 if ok else 1


def run_raw(payload):
    """Run the bridge with raw stdin and return (exit_code, stdout, stderr)."""
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env["SCAMCHECK_HOME"] = HOME
    env.pop("SCAMCHECK_REGION", None)
    env["SCAMCHECK_JARVIS_AI"] = "never"
    proc = subprocess.run(
        [sys.executable, "-m", "scamcheck.webcli"],
        input=payload,
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
        timeout=180,
    )
    return proc.returncode, proc.stdout, proc.stderr


def call(tool, **args):
    code, out, err = run_raw(json.dumps({"tool": tool, "args": args}))
    try:
        payload = json.loads(out)
    except ValueError:
        payload = {"ok": False, "error": "non-JSON stdout", "raw": out}
    return code, payload, err


def test_analyze():
    failures = 0
    code, data, err = call(
        "analyze",
        text="URGENT: your bank account is blocked. Verify KYC now: http://bit.ly/x1",
        region="IN",
        ai="never",
    )
    result = (data.get("data") or {}).get("result") or {}
    failures += check(
        "analyze returns a scam verdict",
        code == 0 and data.get("ok") and result.get("final_verdict") == "SCAM"
        and int(result.get("score") or 0) >= 60,
        "%s score=%s" % (result.get("final_verdict"), result.get("score")),
    )
    failures += check(
        "analyze attaches memory and watchlist fields",
        isinstance(data.get("data", {}).get("seen"), list)
        and isinstance(data.get("data", {}).get("watchlist"), list),
    )
    failures += check("analyze reports elapsed time",
                      isinstance(data.get("elapsed_ms"), int))
    failures += check("analyze emits no progress lines", "@@progress" not in err)

    code, data, _ = call("analyze", text="   ")
    failures += check("empty text is a handled error",
                      code == 1 and data.get("ok") is False
                      and "text is required" in data.get("error", ""),
                      data.get("error"))
    return failures


def test_numbers_and_lists():
    failures = 0
    code, data, _ = call("check_number", number="+91 98765 43210", region="IN")
    intel = (data.get("data") or {}).get("intel") or {}
    failures += check("check_number returns range intel",
                      code == 0 and data.get("ok")
                      and bool((intel.get("number") or {}).get("e164")),
                      (intel.get("number") or {}).get("e164"))

    code, data, _ = call("list_add", action="block",
                         number="+91 90000 00001", label="bridge test")
    failures += check("list_add records a block",
                      code == 0 and data.get("ok"), data.get("error"))

    code, data, _ = call("lists")
    lists = data.get("data") or {}
    blocked = [row for row in lists.get("blocked") or []
               if "9000000001" in str(row)]
    failures += check("lists exposes the new block", bool(blocked), blocked[:1])

    code, data, _ = call("list_add", action="forget", number="+91 90000 00001")
    failures += check("list_add action=forget removes it",
                      code == 0 and data.get("ok"), data.get("error"))

    code, data, _ = call("feeds_status")
    failures += check("feeds_status is local-only",
                      code == 0 and data.get("ok")
                      and "sources" in (data.get("data") or {}),
                      data.get("error"))
    return failures


def test_regions_and_status():
    failures = 0
    code, data, _ = call("status")
    status = data.get("data") or {}
    failures += check(
        "status matches the package version",
        code == 0 and status.get("version") == __version__,
        "%s vs %s" % (status.get("version"), __version__),
    )
    failures += check("status reports the temp data directory",
                      status.get("data_dir") == HOME, status.get("data_dir"))

    code, data, _ = call("regions")
    regions = data.get("data") or {}
    failures += check(
        "regions lists every dial code",
        code == 0 and len(regions.get("regions") or []) == 49
        and regions.get("current") == "IN",
        "%s current=%s" % (len(regions.get("regions") or []), regions.get("current")),
    )
    entry = (regions.get("regions") or [{}])[0]
    failures += check("regions entries carry code, dial and label",
                      {"code", "dial", "label"} <= set(entry), entry)

    code, data, _ = call("set_region", region="us")
    failures += check("set_region normalises to upper case",
                      code == 0 and (data.get("data") or {}).get("region") == "US",
                      data.get("data"))

    code, data, _ = call("regions")
    failures += check("regions reflects the saved region",
                      (data.get("data") or {}).get("current") == "US")

    code, data, _ = call("set_region", region="ZZ")
    failures += check("set_region rejects unknown codes",
                      code == 1 and data.get("ok") is False
                      and "unknown region" in data.get("error", ""),
                      data.get("error"))

    # restore the default for later tests
    call("set_region", region="IN")
    return failures


def test_watchlist():
    failures = 0
    code, data, _ = call("watchlist_add", entity="phone:+91 90000 00002",
                         label="bridge watch", notes="test")
    failures += check("watchlist_add stores an identifier",
                      code == 0 and data.get("ok"), data.get("error"))

    code, data, _ = call("watchlist_list")
    rows = data.get("data") or []
    match = [row for row in rows if row.get("value", "").endswith("9000000002")]
    failures += check("watchlist_list returns it", bool(match), match[:1])

    code, data, _ = call("watchlist_add", entity="")
    failures += check("watchlist_add validates the entity",
                      code == 1 and data.get("ok") is False, data.get("error"))

    code, data, _ = call("watchlist_remove", entity="phone:+91 90000 00002")
    failures += check("watchlist_remove deletes it",
                      code == 0 and (data.get("data") or {}).get("removed") is True,
                      data.get("data"))

    code, data, _ = call("watchlist_clear")
    failures += check("watchlist_clear succeeds",
                      code == 0 and data.get("ok"), data.get("error"))
    return failures


def test_cases():
    failures = 0
    code, data, _ = call("case_create", title="Bridge UPI fraud",
                         scam_type="upi", country="IN", currency="INR",
                         loss=5000)
    case = data.get("data") or {}
    case_id = case.get("id")
    failures += check("case_create returns an id",
                      code == 0 and bool(case_id), case.get("id"))

    code, data, _ = call("case_add", case_id=case_id,
                         text="URGENT: pay to scammer@okhdfcbank",
                         source="web-test")
    added = data.get("data") or {}
    failures += check("case_add stores hashed text evidence",
                      code == 0 and len(added.get("sha256") or "") == 64,
                      added.get("sha256"))
    code, data, _ = call("case_get", case_id=case_id)
    evidence = (data.get("data") or {}).get("evidence") or []
    failures += check("case_get exposes the stored evidence",
                      bool(evidence)
                      and all(len(item.get("sha256") or "") == 64 for item in evidence),
                      [item.get("sha256") for item in evidence][:1])

    code, data, _ = call("case_entity", case_id=case_id,
                         entity="upi:scammer@okhdfcbank")
    failures += check("case_entity records the identifier",
                      code == 0 and (data.get("data") or {}).get("kind") == "upi",
                      data.get("data"))
    code, data, _ = call("case_get", case_id=case_id)
    entities = (data.get("data") or {}).get("entities") or []
    failures += check("case_get exposes the recorded entity",
                      bool(entities), entities[:1])

    code, data, _ = call("case_note", case_id=case_id, note="Called the bank")
    events = (data.get("data") or {}).get("events") or []
    failures += check("case_note appends a timeline event",
                      code == 0 and bool(events), events[-1:])

    code, data, _ = call("case_verify", case_id=case_id)
    verified = data.get("data") or {}
    rows = verified.get("rows") or verified.get("evidence") or []
    failures += check("case_verify checks every hash",
                      code == 0 and bool(rows) and all(row.get("ok") for row in rows),
                      rows[:1])

    code, data, _ = call("case_report", case_id=case_id, country="IN")
    text = (data.get("data") or {}).get("text") or ""
    failures += check("case_report drafts a complaint",
                      code == 0 and len(text) > 100, text[:80])

    outdir = os.path.join(HOME, "bridge-export")
    code, data, _ = call("case_export", case_id=case_id, outdir=outdir)
    exported = data.get("data") or {}
    expected = ["case.json", "case.md", "case.html", "SHA256SUMS"]
    present = [name for name in expected
               if os.path.isfile(os.path.join(outdir, name))]
    failures += check("case_export writes the full package",
                      code == 0 and present == expected, present)
    failures += check("case_export returns its paths",
                      all(exported.get(key) for key in
                          ("json", "markdown", "html", "hashes")),
                      exported.get("outdir"))

    code, data, _ = call("case_close", case_id=case_id)
    failures += check("case_close sets the status",
                      code == 0
                      and (data.get("data") or {}).get("status") == "closed",
                      (data.get("data") or {}).get("status"))

    code, data, _ = call("case_get", case_id="case-does-not-exist")
    failures += check("case_get reports a missing case",
                      code == 1 and data.get("ok") is False
                      and data.get("type") == "KeyError", data.get("error"))

    code, data, _ = call("cases_list", limit=10)
    failures += check("cases_list returns the case",
                      code == 0
                      and any(row.get("id") == case_id for row in data.get("data") or []))
    return failures


def test_recovery_and_jarvis():
    failures = 0
    code, data, _ = call("recover", scam_type="upi", country="IN")
    book = data.get("data") or {}
    failures += check(
        "recover returns a country playbook",
        code == 0 and book.get("country") == "IN" and bool(book.get("now"))
        and bool(book.get("today")) and bool(book.get("week")),
        "%s steps=%s" % (book.get("title"), len(book.get("now") or [])),
    )
    failures += check("recover includes an authority block",
                      bool((book.get("authority") or {}).get("cyber")),
                      book.get("authority"))

    code, data, _ = call("jarvis", message="help", region="IN", lang="en")
    reply = data.get("data") or {}
    failures += check("jarvis answers a local command",
                      code == 0 and len(reply.get("text") or "") > 100
                      and reply.get("quit") is False,
                      (reply.get("text") or "")[:80])

    code, data, _ = call("history", action="recent", limit=10)
    rows = data.get("data") or []
    failures += check("history returns recorded checks", code == 0 and bool(rows),
                      len(rows))
    return failures


def test_device_audit_bridge():
    failures = 0
    outdir = os.path.join(HOME, "device-export")
    code, data, err = call("device_audit", include_lan=False,
                           include_mobile=False, active_lan=False,
                           out_dir=outdir)
    report = (data.get("data") or {}).get("report") or {}
    exported = (data.get("data") or {}).get("export") or {}
    summary = report.get("summary") or {}
    failures += check(
        "device_audit returns a report",
        code == 0 and report.get("version") == __version__
        and summary.get("active_lan") is False
        and int(summary.get("checks_run") or 0) > 0,
        "checks=%s risk=%s" % (summary.get("checks_run"), summary.get("risk")),
    )
    failures += check("device_audit skips the LAN by request",
                      summary.get("lan_included") is False)
    failures += check("device_audit streams progress on stderr",
                      "@@progress" in err, err.splitlines()[:2])

    paths = [exported.get("json"), exported.get("markdown"),
             exported.get("sha256sums")]
    failures += check("device_audit exports JSON, Markdown and checksums",
                      all(path and os.path.isfile(path) for path in paths),
                      paths)
    return failures


def test_contract_errors():
    failures = 0
    code, out, _ = run_raw("not json")
    try:
        payload = json.loads(out)
    except ValueError:
        payload = {}
    failures += check("invalid JSON exits 2 with an error object",
                      code == 2 and payload.get("ok") is False
                      and "invalid JSON" in payload.get("error", ""),
                      payload.get("error"))

    code, data, _ = call("no_such_tool")
    failures += check("unknown tool exits 2",
                      code == 2 and data.get("ok") is False
                      and "unknown tool" in data.get("error", ""),
                      data.get("error"))

    code, data, _ = call("url", url="")
    failures += check("missing arguments are a clean failure",
                      code == 1 and data.get("ok") is False, data.get("error"))
    return failures


def main():
    print("scamcheck web bridge tests (v%s)" % __version__)
    print("data dir:", HOME)
    print()
    failures = 0
    for fn in (test_analyze, test_numbers_and_lists, test_regions_and_status,
               test_watchlist, test_cases, test_recovery_and_jarvis,
               test_device_audit_bridge, test_contract_errors):
        failures += fn()
        print()
    print("FAILED: %d checks" % failures if failures else "All checks passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
