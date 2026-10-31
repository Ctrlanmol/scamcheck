"""Read-only device and local-network security audit.

This is deliberately *not* an antivirus engine. It looks for the things a
careful human would check on a machine they own:

  * security posture (SIP, FileVault, firewall, Gatekeeper, updates, MDM)
  * running processes and suspicious command lines
  * persistence (LaunchAgents/Daemons, cron, login items, shell profiles)
  * browser extensions, native-messaging hosts and browser policies
  * listening/established network connections
  * suspicious files in temp/shared/download locations and quarantine events
  * kernel/system extensions and configuration profiles
  * connected Android/iOS devices (only when local tools are present)
  * devices visible on the private LAN, with optional TCP connect checks

No writes, no sudo, no exploitation, no password attacks. Active LAN checks
are limited to RFC1918/link-local IPv4 addresses and plain TCP connects.

Public API:
    audit(active_lan=True, include_lan=True, include_mobile=True, ...) -> dict
    format_report(report, full=False) -> str
    export_report(report, out_dir=None) -> dict
"""

import hashlib
import ipaddress
import json
import os
import plistlib
import re
import shlex
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import phones
from . import __version__

SEVERITY_WEIGHT = {
    "critical": 40,
    "high": 20,
    "medium": 10,
    "low": 3,
    "info": 0,
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

RISK_PORTS = {
    23: ("high", "Telnet is open"),
    2323: ("high", "Telnet-like service is open"),
    445: ("high", "SMB file sharing is exposed"),
    139: ("medium", "NetBIOS file sharing is exposed"),
    3389: ("high", "Remote Desktop is exposed"),
    5900: ("high", "VNC/screen sharing is exposed"),
    5901: ("high", "VNC/screen sharing is exposed"),
    5902: ("high", "VNC/screen sharing is exposed"),
    3283: ("medium", "Apple Remote Desktop is exposed"),
    7547: ("high", "TR-069 router management is exposed"),
    9100: ("medium", "Raw printer port is exposed"),
    631: ("medium", "IPP printer service is exposed"),
    5000: ("medium", "A web/admin service is exposed"),
    8080: ("low", "An alternate web/admin port is exposed"),
    80: ("low", "An HTTP admin service is exposed"),
    443: ("info", "HTTPS is exposed"),
    22: ("low", "SSH is exposed"),
    62078: ("info", "Apple mobile device sync service"),
    7000: ("info", "AirPlay service"),
    7001: ("info", "AirPlay service"),
    8008: ("info", "Google Cast service"),
    8009: ("info", "Google Cast service"),
    32400: ("info", "Plex media server"),
}

COMMON_PORTS = [
    22, 23, 53, 80, 139, 443, 445, 554, 631, 1883, 1900, 2323,
    3389, 5000, 5900, 7000, 7001, 7547, 8008, 8009, 8080, 8443,
    8883, 9100, 32400, 62078,
]

MINER_NAMES = {
    "xmrig", "minerd", "cpuminer", "cpuminer-multi", "ethminer",
    "nbminer", "phoenixminer", "t-rex", "teamredminer", "lolminer",
    "nicehash", "kawpowminer", "gminer", "srbminer", "xmr-stak",
}

SUSPICIOUS_COMMAND_PATTERNS = [
    (r"/dev/tcp/", "reverse-shell / raw TCP shell pattern"),
    (r"\bnc\b[^|;]{0,40}\s-e\b", "netcat execute mode"),
    (r"\bncat\b[^|;]{0,40}\s-e\b", "ncat execute mode"),
    (r"\bsocat\b[^|;]{0,80}\bexec:", "socat execute mode"),
    (r"\bbash\s+-i\b", "interactive shell"),
    (r"\bcurl\b[^|;]{0,120}\|\s*(?:ba)?sh\b", "curl piped into a shell"),
    (r"\bwget\b[^|;]{0,120}\|\s*(?:ba)?sh\b", "wget piped into a shell"),
    (r"\bbase64\b[^|;]{0,40}\s-(?:d|D)\b[^|;]{0,40}\|\s*(?:ba)?sh\b",
     "base64-decoded shell"),
    (r"\bstratum\+tcp://", "crypto-mining pool"),
    (r"\b(?:xmrig|minerd|cpuminer|nicehash)\b", "known miner process name"),
    (r"\bosascript\b[^|;]{0,80}\bdo shell script\b", "AppleScript shell execution"),
]

SUSPICIOUS_PATHS = (
    "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
    "/Users/Shared/", "/dev/shm/",
)

PROFILE_FILES = [
    "~/.zshrc", "~/.zprofile", "~/.zshenv", "~/.bash_profile",
    "~/.bashrc", "~/.profile", "~/.config/fish/config.fish",
    "/etc/zshrc", "/etc/zprofile", "/etc/profile", "/etc/bashrc",
]

DOWNLOAD_EXTS = {
    ".dmg", ".pkg", ".mpkg", ".zip", ".tar", ".gz", ".tgz", ".bz2",
    ".xz", ".sh", ".command", ".app", ".apk", ".exe", ".msi", ".scr",
    ".js", ".jar", ".py", ".pl", ".rb", ".dylib", ".so",
}

HIGH_RISK_EXT_PERMS = {
    "debugger", "nativeMessaging", "proxy", "management",
    "webRequestBlocking", "declarativeNetRequest", "cookies",
    "<all_urls>", "http://*/*", "https://*/*", "*://*/*",
}

BROWSER_ROOTS = [
    ("Chrome", "~/Library/Application Support/Google/Chrome"),
    ("Brave", "~/Library/Application Support/BraveSoftware/Brave-Browser"),
    ("Edge", "~/Library/Application Support/Microsoft Edge"),
    ("Chromium", "~/Library/Application Support/Chromium"),
    ("Vivaldi", "~/Library/Application Support/Vivaldi"),
    ("Opera", "~/Library/Application Support/com.operasoftware.Opera"),
]

OUI_VENDORS = {
    "00:03:93": "Apple", "00:0a:27": "Apple", "00:1b:63": "Apple",
    "00:1e:c2": "Apple", "3c:07:54": "Apple", "a4:83:e7": "Apple",
    "f0:18:98": "Apple", "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi", "00:1a:11": "Google", "f4:f5:d8": "Google",
    "54:60:09": "Google", "00:17:88": "Philips Hue",
    "00:04:20": "Slim Devices", "00:1d:ba": "Sony", "00:13:a9": "Sony",
    "00:1f:80": "Samsung", "8c:77:12": "Samsung", "e8:50:8b": "Samsung",
    "00:1e:10": "LG", "2c:54:91": "LG", "a8:23:fe": "LG",
    "00:0d:93": "TCL/Roku", "b0:a7:37": "Roku", "cc:6d:a0": "Roku",
    "00:1b:a9": "Brother", "00:1e:0b": "HP", "3c:d9:2b": "HP",
    "00:26:ab": "Seiko Epson", "00:00:aa": "Xerox",
    "00:1c:10": "Cisco", "00:1a:a1": "Cisco", "f8:1a:67": "TP-Link",
    "50:c7:bf": "TP-Link", "00:24:b2": "Netgear", "20:4e:7f": "Netgear",
    "00:14:6c": "Netgear", "00:18:e7": "Netgear",
    "00:1f:33": "Netgear", "00:22:6b": "Cisco/Linksys",
}

DEVICE_CHECKLISTS = {
    "macos": [
        "Keep SIP, FileVault, Gatekeeper and the firewall enabled.",
        "Remove browser extensions and login items you do not recognize.",
        "Review LaunchAgents/Daemons, cron jobs and shell profiles after installing software.",
        "Use a standard user account for daily work; keep admin separate.",
        "Install updates promptly and keep XProtect/security responses current.",
    ],
    "android": [
        "Settings > Security > Google Play Protect: run a scan.",
        "Settings > Apps > Special access: review Accessibility, Device admin, Notification access and Usage access.",
        "Remove unknown device-admin apps and disable sideloading unless you need it.",
        "Check Settings > Security > Security update for the patch level.",
        "Use a screen lock, encrypted storage and Play Protect; avoid APKs from chats.",
    ],
    "ios": [
        "Update iOS/iPadOS and enable Lockdown Mode if you are high-risk.",
        "Settings > General > VPN & Device Management: remove unknown profiles.",
        "Settings > Privacy & Security > Analytics: check for unexpected profiles.",
        "Do not jailbreak; only install apps from the App Store.",
        "Use a strong passcode, Stolen Device Protection and two-factor authentication.",
    ],
    "tv": [
        "Install TV updates and remove unknown sideloaded apps.",
        "Disable unused casting, screen mirroring and developer modes.",
        "Change default router/admin passwords and isolate IoT devices on a guest VLAN.",
        "Check the TV's privacy/telemetry settings and revoke unused app permissions.",
    ],
    "router": [
        "Change the default admin password and disable remote/WAN administration.",
        "Disable UPnP and TR-069 unless your ISP requires them.",
        "Update firmware and replace routers that no longer receive security fixes.",
        "Use WPA3/WPA2, a strong Wi-Fi password and a separate guest network for IoT.",
    ],
    "windows": [
        "Run Windows Security/Microsoft Defender full scan and enable ransomware protection.",
        "Review Startup apps, scheduled tasks and browser extensions.",
        "Enable BitLocker, Secure Boot, firewall and automatic updates.",
        "Remove unknown remote-access tools and local admin rights from daily accounts.",
    ],
    "linux": [
        "Review systemd units, cron jobs, authorized_keys and shell profiles.",
        "Keep packages updated and remove unused services.",
        "Use a firewall, full-disk encryption and a non-root daily account.",
        "Check listening services with `ss -lntup` and review unknown outbound connections.",
    ],
}


def _run(cmd, timeout=12, input_text=None):
    """Run a local command without a shell. Returns (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            input=input_text, errors="replace",
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


def _which(name):
    for folder in (os.environ.get("PATH") or "").split(os.pathsep):
        path = os.path.join(folder, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _expand(path):
    return os.path.abspath(os.path.expanduser(path))


def _listdir(path):
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def _read(path, limit=200000):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _sha256(path):
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def _private_ipv4(value):
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if addr.version != 4:
        return False
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_reserved:
        return False
    return addr.is_private or addr.is_link_local


def _redact(text, limit=180):
    text = " ".join((text or "").split())
    text = re.sub(r"(?i)(token|password|passwd|secret|api[_-]?key)=\S+",
                  r"\1=<redacted>", text)
    return text[:limit] + ("..." if len(text) > limit else "")


def _suspicious_command(text):
    hits = []
    for pattern, label in SUSPICIOUS_COMMAND_PATTERNS:
        if re.search(pattern, text or "", re.I):
            hits.append(label)
    return hits


def _path_is_suspicious(path):
    low = (path or "").lower()
    if not low:
        return False
    if any(low.startswith(prefix) for prefix in SUSPICIOUS_PATHS):
        return True
    if "/." in low and "/users/" in low:
        return True
    return False


def _finding(severity, category, title, detail, evidence=None, recommendation=None):
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
        "evidence": evidence or [],
        "recommendation": recommendation or "",
    }


class DeviceAudit:
    def __init__(self, active_lan=True, include_lan=True, include_mobile=True,
                 max_hosts=64, progress=None):
        self.active_lan = bool(active_lan)
        self.include_lan = bool(include_lan)
        self.include_mobile = bool(include_mobile)
        self.max_hosts = max(1, int(max_hosts or 64))
        self.progress = progress or (lambda _msg: None)
        self.findings = []
        self.sections = {}
        self.skipped = []
        self.checks_run = 0

    # -- collection helpers ------------------------------------------------

    def add(self, finding):
        if finding:
            self.findings.append(finding)

    def section(self, name, value):
        self.sections[name] = value

    def skip(self, check, reason):
        self.skipped.append({"check": check, "reason": reason})

    def run(self):
        self.progress("collecting system and security posture")
        self.collect_system()
        self.progress("reviewing processes")
        self.collect_processes()
        self.progress("reviewing persistence")
        self.collect_persistence()
        self.progress("reviewing browsers")
        self.collect_browsers()
        self.progress("reviewing network connections")
        self.collect_network()
        self.progress("reviewing files and downloads")
        self.collect_files()
        self.progress("reviewing extensions and profiles")
        self.collect_extensions()
        if self.include_mobile:
            self.progress("checking connected mobile devices")
            self.collect_mobile()
        if self.include_lan:
            self.progress("inventorying private LAN devices")
            self.collect_lan()
        self.progress("building report")
        return self.report()

    def report(self):
        findings = sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9),
                           f.get("category") or "", f.get("title") or ""),
        )
        counts = {}
        score = 0
        for item in findings:
            sev = item.get("severity") or "info"
            counts[sev] = counts.get(sev, 0) + 1
            score += SEVERITY_WEIGHT.get(sev, 0)
        score = min(100, score)
        severities = {item.get("severity") or "info" for item in findings}
        if "critical" in severities or score >= 60:
            risk = "critical"
        elif "high" in severities or score >= 35:
            risk = "high"
        elif "medium" in severities or score >= 15:
            risk = "medium"
        else:
            risk = "low"
        return {
            "version": __version__,
            "generated_at": time.time(),
            "platform": sys.platform,
            "host": self.sections.get("system", {}).get("host", {}),
            "summary": {
                "risk": risk,
                "score": score,
                "findings": counts,
                "checks_run": self.checks_run,
                "skipped": self.skipped,
                "active_lan": self.active_lan,
                "lan_included": self.include_lan,
            },
            "findings": findings,
            "sections": self.sections,
            "device_checklists": DEVICE_CHECKLISTS,
        }

    # -- 1. system / posture ----------------------------------------------

    def collect_system(self):
        host = {
            "hostname": socket.gethostname(),
            "platform": sys.platform,
            "machine": os.uname().machine if hasattr(os, "uname") else "",
            "user": os.environ.get("USER") or "",
        }
        if sys.platform == "darwin":
            rc, out, _ = _run(["sw_vers"], 6)
            if rc == 0:
                for line in out.splitlines():
                    if ":" in line:
                        key, value = line.split(":", 1)
                        host[key.strip().lower().replace(" ", "_")] = value.strip()
            rc, out, _ = _run(["sysctl", "-n", "hw.model"], 4)
            if rc == 0:
                host["model"] = out.strip()
            rc, out, _ = _run(["scutil", "--get", "ComputerName"], 4)
            if rc == 0 and out.strip():
                host["computer_name"] = out.strip()
            rc, out, _ = _run(["sysctl", "-n", "hw.memsize"], 4)
            if rc == 0:
                try:
                    host["memory_gb"] = round(int(out.strip()) / (1024 ** 3), 1)
                except ValueError:
                    pass
            rc, out, _ = _run(["sysctl", "-n", "kern.boottime"], 4)
            if rc == 0:
                match = re.search(r"sec\s*=\s*(\d+)", out)
                if match:
                    host["boot_time"] = int(match.group(1))
            rc, out, _ = _run(["id", "-Gn"], 4)
            if rc == 0:
                host["groups"] = out.strip().split()
        self.section("system", {"host": host, "security": {}})
        self.checks_run += 1

        security = {}
        if sys.platform != "darwin":
            self.skip("macOS security posture", "not running on macOS")
            self.section("system", {"host": host, "security": security})
            return

        checks = [
            ("sip", ["csrutil", "status"], "System Integrity Protection"),
            ("filevault", ["fdesetup", "status"], "FileVault"),
            ("gatekeeper", ["spctl", "--status"], "Gatekeeper"),
            ("firewall", ["/usr/libexec/ApplicationFirewall/socketfilterfw",
                          "--getglobalstate"], "Application firewall"),
            ("remote_login", ["systemsetup", "-getremotelogin"], "Remote login"),
            ("mdm", ["profiles", "status", "-type", "enrollment"], "MDM enrollment"),
        ]
        for key, cmd, label in checks:
            rc, out, err = _run(cmd, 8)
            text = (out + "\n" + err).strip()
            security[key] = {"output": _redact(text, 300), "ok": rc == 0}
            self.checks_run += 1
            low = text.lower()
            if "administrator access" in low:
                security[key]["ok"] = False
                self.skip(label, "requires administrator access (unprivileged mode)")
                continue
            if key == "sip" and "enabled" not in low:
                self.add(_finding(
                    "high", "security", "System Integrity Protection may be disabled",
                    "SIP is a core macOS protection; disabling it weakens malware resistance.",
                    [text[:200]], "Re-enable SIP from Recovery mode unless you have a specific need."))
            elif key == "filevault" and "on" not in low and "enabled" not in low:
                self.add(_finding(
                    "medium", "security", "FileVault does not appear to be on",
                    "Disk encryption protects data if the Mac is lost or stolen.",
                    [text[:200]], "Turn on FileVault in System Settings > Privacy & Security."))
            elif key == "gatekeeper" and "enabled" not in low:
                self.add(_finding(
                    "medium", "security", "Gatekeeper assessments may be disabled",
                    "Gatekeeper blocks known-malicious and unsigned apps by default.",
                    [text[:200]], "Re-enable Gatekeeper: spctl --master-enable"))
            elif key == "firewall" and "enabled" not in low and "state = 1" not in low:
                self.add(_finding(
                    "medium", "security", "Application firewall may be off",
                    "The macOS firewall limits inbound connections from the network.",
                    [text[:200]], "Enable the firewall in System Settings > Network > Firewall."))
            elif key == "remote_login" and "on" in low:
                self.add(_finding(
                    "medium", "security", "Remote Login (SSH) is enabled",
                    "SSH increases the attack surface if the password or keys are weak.",
                    [text[:200]], "Disable Remote Login if you do not use it."))
            elif key == "mdm" and re.search(r"mdm enrollment:\s*yes", low):
                self.add(_finding(
                    "info", "security", "This Mac is enrolled in MDM",
                    "MDM can legitimately manage the device; verify the organization is yours.",
                    [text[:200]], "Confirm the MDM enrollment is expected."))

        # Guest account / automatic login
        for key, domain, setting, label, severity in [
            ("guest", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled",
             "Guest account is enabled", "low"),
            ("auto_login", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser",
             "Automatic login is configured", "medium"),
        ]:
            rc, out, err = _run(["defaults", "read", domain, setting], 4)
            if rc == 0:
                value = out.strip()
                security[key] = value
                self.checks_run += 1
                if key == "guest" and value.lower() in ("1", "true", "yes"):
                    self.add(_finding(
                        severity, "security", label,
                        "A guest account or automatic login weakens physical security.",
                        [setting + " = " + value],
                        "Disable the guest account and automatic login."))
                elif key == "auto_login" and value and value not in ("0", "false"):
                    self.add(_finding(
                        severity, "security", label,
                        "Anyone with physical access can boot into the account.",
                        [setting + " = " + value],
                        "Disable automatic login and require a password at boot."))

        # Software update settings
        update = {}
        for setting in ("AutomaticCheckEnabled", "AutomaticDownload",
                        "CriticalUpdateInstall", "ConfigDataInstall"):
            rc, out, _ = _run(["defaults", "read",
                               "/Library/Preferences/com.apple.SoftwareUpdate",
                               setting], 4)
            if rc == 0:
                update[setting] = out.strip()
        security["software_update"] = update
        self.checks_run += 1
        if update and any(v.lower() in ("0", "false", "no") for v in update.values()):
            self.add(_finding(
                "low", "security", "Some automatic update settings are off",
                "Automatic security updates reduce exposure time.",
                ["%s=%s" % (k, v) for k, v in sorted(update.items())],
                "Enable automatic security updates in System Settings > General > Software Update."))

        # XProtect / MRT versions
        for name, path in [
            ("XProtect", "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"),
            ("XProtect", "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"),
            ("MRT", "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist"),
            ("MRT", "/System/Library/CoreServices/MRT.app/Contents/Info.plist"),
        ]:
            if os.path.exists(path) and name not in security:
                try:
                    with open(path, "rb") as fh:
                        data = plistlib.load(fh)
                    security[name] = data.get("CFBundleShortVersionString") or "present"
                except (OSError, plistlib.InvalidFileException, ValueError):
                    security[name] = "present"
        self.section("system", {"host": host, "security": security})

    # -- 2. processes ------------------------------------------------------

    def collect_processes(self):
        if sys.platform == "darwin":
            rc, out, err = _run(
                ["ps", "-axo", "pid=,ppid=,user=,etime=,pcpu=,pmem=,command="], 10)
        else:
            rc, out, err = _run(["ps", "-axo", "pid=,ppid=,user=,etime=,pcpu=,pmem=,args="], 10)
        if rc != 0:
            self.skip("process list", err.strip()[:200])
            return

        rows = []
        for line in out.splitlines():
            parts = line.strip().split(None, 6)
            if len(parts) < 7:
                continue
            pid, ppid, user, etime, pcpu, pmem, command = parts
            try:
                pcpu_f = float(pcpu)
            except ValueError:
                pcpu_f = 0.0
            path = ""
            try:
                tokens = shlex.split(command)
                if tokens and tokens[0].startswith("/"):
                    path = tokens[0]
            except ValueError:
                path = ""
            hits = _suspicious_command(command)
            rows.append({
                "pid": int(pid) if pid.isdigit() else pid,
                "ppid": int(ppid) if ppid.isdigit() else ppid,
                "user": user,
                "etime": etime,
                "cpu": pcpu_f,
                "mem": pmem,
                "command": _redact(command, 260),
                "path": path,
                "suspicious": hits,
            })
            if hits:
                severity = "high" if any("reverse" in h or "shell" in h or
                                         "miner" in h for h in hits) else "medium"
                self.add(_finding(
                    severity, "process", "Suspicious process command line",
                    "Process %s (%s) matched: %s" % (pid, user, ", ".join(hits)),
                    [{"pid": pid, "command": _redact(command, 240)}],
                    "Verify the process, its parent and its binary before stopping it. "
                    "If you did not install it, preserve the binary and run a full scan."))
            if path and _path_is_suspicious(path):
                self.add(_finding(
                    "high", "process", "Process running from a temp/shared path",
                    "Executables in /tmp, /var/tmp or /Users/Shared are a common malware location.",
                    [{"pid": pid, "path": path, "command": _redact(command, 200)}],
                    "Identify the parent process and remove the executable only after preserving evidence."))
            if path and "com.apple." in command and "/System/" not in path and "/usr/" not in path:
                self.add(_finding(
                    "medium", "process", "Apple-named process outside an Apple path",
                    "Malware sometimes uses Apple-like names from user-writable folders.",
                    [{"pid": pid, "path": path}],
                    "Inspect the binary signature with codesign and remove it if unknown."))
            if pcpu_f >= 80:
                self.add(_finding(
                    "info", "process", "Process using high CPU",
                    "High CPU can be normal, but sustained 80%+ can indicate a miner or runaway process.",
                    [{"pid": pid, "cpu": pcpu_f, "command": _redact(command, 160)}],
                    "Check whether the process is expected; sample it over time before acting."))
            name = os.path.basename(path or "").lower()
            if name in MINER_NAMES or any(m in command.lower() for m in MINER_NAMES):
                self.add(_finding(
                    "critical", "process", "Crypto-miner process name detected",
                    "The process name or command line matches a known miner.",
                    [{"pid": pid, "command": _redact(command, 240)}],
                    "Stop the process, preserve the binary, and check LaunchAgents/cron for persistence."))
        self.section("processes", {"count": len(rows), "items": rows})
        self.checks_run += 1

    # -- 3. persistence ----------------------------------------------------

    def collect_persistence(self):
        data = {"launch_items": [], "launchctl": [], "cron": [], "profiles": [],
                "ssh": {}, "shell_profiles": []}

        if sys.platform == "darwin":
            dirs = [
                ("user LaunchAgents", "~/Library/LaunchAgents"),
                ("local LaunchAgents", "/Library/LaunchAgents"),
                ("local LaunchDaemons", "/Library/LaunchDaemons"),
            ]
            for label, folder in dirs:
                root = _expand(folder)
                if not os.path.isdir(root):
                    continue
                for name in _listdir(root):
                    if not name.endswith(".plist"):
                        continue
                    path = os.path.join(root, name)
                    item = self._inspect_plist(path, label)
                    if item:
                        data["launch_items"].append(item)
                        if item["suspicious"]:
                            self.add(_finding(
                                "high", "persistence",
                                "Suspicious launch item: " + name,
                                "A LaunchAgent/Daemon runs automatically and matched: %s" %
                                ", ".join(item["suspicious"]),
                                [{"path": path, "program": item.get("program"),
                                  "arguments": item.get("arguments")[:4]}],
                                "Inspect the plist and binary. Disable it only after preserving evidence."))

            rc, out, _ = _run(["launchctl", "list"], 8)
            if rc == 0:
                for line in out.splitlines()[1:]:
                    parts = line.split("\t")
                    if len(parts) >= 3:
                        pid, status, label = parts[0], parts[1], parts[2]
                        if not label.startswith("com.apple."):
                            data["launchctl"].append({
                                "label": label, "pid": pid, "status": status})
                self.checks_run += 1

            # Login items (best effort; may require Automation permission)
            rc, out, err = _run([
                "osascript", "-e",
                'tell application "System Events" to get the name of every login item'
            ], 6)
            if rc == 0 and out.strip():
                data["login_items"] = [x.strip() for x in out.strip().split(",") if x.strip()]
                for item in data["login_items"]:
                    self.add(_finding(
                        "info", "persistence", "Login item: " + item,
                        "This app starts automatically when you log in.",
                        [item], "Remove it if you do not recognize or need it."))
            else:
                self.skip("login items", "Automation permission unavailable")

            # sfltool background task management (best effort)
            rc, out, _ = _run(["sfltool", "dumpbtm"], 10)
            if rc == 0 and out.strip():
                data["background_items"] = [
                    line.strip() for line in out.splitlines()
                    if line.strip() and not line.startswith("Dumping")
                ][:200]
                self.checks_run += 1

        # cron / at
        rc, out, _ = _run(["crontab", "-l"], 5)
        if rc == 0 and out.strip() and "no crontab" not in out.lower():
            data["cron"].append({"source": "user crontab", "lines": out.splitlines()[:50]})
            for line in out.splitlines():
                if line.strip() and not line.strip().startswith("#"):
                    self.add(_finding(
                        "low", "persistence", "User cron job present",
                        "Cron jobs run automatically and should be reviewed.",
                        [line[:200]], "Remove any cron job you did not create."))
        for path in ("/etc/crontab", "/etc/cron.d"):
            if os.path.isdir(path):
                for name in _listdir(path):
                    full = os.path.join(path, name)
                    text = _read(full, 20000)
                    if text.strip():
                        data["cron"].append({"source": full,
                                             "lines": text.splitlines()[:50]})
            elif os.path.isfile(path):
                text = _read(path, 20000)
                if text.strip():
                    data["cron"].append({"source": path,
                                         "lines": text.splitlines()[:50]})
        rc, out, _ = _run(["atq"], 4)
        if rc == 0 and out.strip():
            data["cron"].append({"source": "atq", "lines": out.splitlines()[:50]})
            self.add(_finding(
                "low", "persistence", "Scheduled 'at' jobs present",
                "One-off scheduled jobs can be used for delayed execution.",
                out.splitlines()[:5], "Review with `atq` and remove anything unknown."))
        self.checks_run += 1

        # Shell profiles
        for raw in PROFILE_FILES:
            path = _expand(raw)
            if not os.path.isfile(path):
                continue
            text = _read(path, 60000)
            hits = []
            for idx, line in enumerate(text.splitlines(), 1):
                if line.strip().startswith("#"):
                    continue
                if _suspicious_command(line):
                    hits.append({"line": idx, "text": _redact(line, 220),
                                 "match": _suspicious_command(line)})
            entry = {"path": path, "lines": len(text.splitlines()),
                     "suspicious": hits}
            data["shell_profiles"].append(entry)
            if hits:
                self.add(_finding(
                    "high", "persistence", "Suspicious shell profile entry",
                    "A shell startup file contains commands often used for persistence.",
                    [{"path": path, **hit} for hit in hits[:5]],
                    "Review and remove the line after preserving a copy."))
        self.checks_run += 1

        # SSH keys/config
        ssh_dir = _expand("~/.ssh")
        if os.path.isdir(ssh_dir):
            auth = os.path.join(ssh_dir, "authorized_keys")
            if os.path.isfile(auth):
                lines = [line.strip() for line in _read(auth, 100000).splitlines()
                         if line.strip() and not line.strip().startswith("#")]
                data["ssh"]["authorized_keys"] = len(lines)
                for line in lines[:20]:
                    parts = line.split()
                    kind = parts[0] if parts else "key"
                    comment = parts[-1] if len(parts) > 2 else ""
                    self.add(_finding(
                        "medium", "persistence", "SSH authorized key present",
                        "Anyone with the matching private key can log in as this user.",
                        [{"type": kind, "comment": _redact(comment, 80)}],
                        "Remove keys you do not recognize and rotate your SSH keys."))
            config = os.path.join(ssh_dir, "config")
            if os.path.isfile(config):
                data["ssh"]["config"] = _read(config, 30000)
            known = os.path.join(ssh_dir, "known_hosts")
            if os.path.isfile(known):
                data["ssh"]["known_hosts"] = len(_read(known, 200000).splitlines())
        self.checks_run += 1

        # Configuration profiles (names only, no secrets)
        if sys.platform == "darwin":
            rc, out, _ = _run(["profiles", "show", "-type", "configuration"], 10)
            if rc == 0 and out.strip():
                names = re.findall(r"ProfileDisplayName\s*:\s*(.+)", out)
                data["profiles"] = [n.strip() for n in names][:30]
                if names:
                    self.add(_finding(
                        "medium", "persistence", "Configuration profiles installed",
                        "Profiles can change security and network settings; verify they are yours.",
                        data["profiles"], "Review in System Settings > General > Device Management."))
            else:
                self.skip("configuration profiles", "requires elevated access or none installed")
        self.section("persistence", data)

    def _inspect_plist(self, path, label):
        try:
            with open(path, "rb") as fh:
                data = plistlib.load(fh)
        except (OSError, plistlib.InvalidFileException, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        program = data.get("Program") or ""
        args = data.get("ProgramArguments") or []
        if not isinstance(args, list):
            args = [str(args)]
        command = " ".join([str(program)] + [str(a) for a in args])
        hits = _suspicious_command(command)
        if _path_is_suspicious(program) or any(_path_is_suspicious(str(a)) for a in args):
            hits.append("runs from a temp/shared path")
        return {
            "label": label,
            "path": path,
            "program": program,
            "arguments": [str(a) for a in args],
            "run_at_load": bool(data.get("RunAtLoad")),
            "keep_alive": bool(data.get("KeepAlive")),
            "suspicious": sorted(set(hits)),
            "modified": os.path.getmtime(path) if os.path.exists(path) else None,
        }

    # -- 4. browsers -------------------------------------------------------

    def collect_browsers(self):
        data = {"chromium": [], "firefox": [], "safari": [], "policies": [],
                "native_hosts": []}

        for browser, raw_root in BROWSER_ROOTS:
            root = _expand(raw_root)
            if not os.path.isdir(root):
                continue
            for profile in _listdir(root):
                profile_dir = os.path.join(root, profile)
                ext_root = os.path.join(profile_dir, "Extensions")
                if not os.path.isdir(ext_root):
                    continue
                for ext_id in _listdir(ext_root):
                    ext_dir = os.path.join(ext_root, ext_id)
                    if not os.path.isdir(ext_dir):
                        continue
                    versions = [v for v in _listdir(ext_dir)
                                if os.path.isdir(os.path.join(ext_dir, v))]
                    if not versions:
                        continue
                    manifest_path = os.path.join(ext_dir, versions[-1], "manifest.json")
                    try:
                        with open(manifest_path, "r", encoding="utf-8", errors="replace") as fh:
                            manifest = json.load(fh)
                    except (OSError, ValueError):
                        continue
                    name = manifest.get("name") or ext_id
                    perms = list(manifest.get("permissions") or []) + \
                        list(manifest.get("host_permissions") or [])
                    risky = sorted({p for p in perms if p in HIGH_RISK_EXT_PERMS})
                    item = {
                        "browser": browser, "profile": profile, "id": ext_id,
                        "name": name, "version": manifest.get("version"),
                        "permissions": perms[:30], "risky_permissions": risky,
                        "path": manifest_path,
                    }
                    data["chromium"].append(item)
                    if risky:
                        self.add(_finding(
                            "medium" if len(risky) < 3 else "high",
                            "browser", "Broad-permission browser extension",
                            "%s extension %r has high-risk permissions: %s" %
                            (browser, name, ", ".join(risky)),
                            [{"id": ext_id, "profile": profile,
                              "permissions": risky}],
                            "Remove the extension if you do not recognize it; "
                            "extensions can read pages, cookies and network traffic."))

        # Native messaging hosts (browser extensions can launch these binaries)
        for folder in (
            "~/Library/Application Support/Google/Chrome/NativeMessagingHosts",
            "~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts",
            "~/Library/Application Support/Microsoft Edge/NativeMessagingHosts",
            "~/Library/Application Support/Chromium/NativeMessagingHosts",
            "~/Library/Application Support/Mozilla/NativeMessagingHosts",
            "/Library/Google/Chrome/NativeMessagingHosts",
            "/Library/Application Support/Mozilla/NativeMessagingHosts",
        ):
            root_dir = _expand(folder)
            if not os.path.isdir(root_dir):
                continue
            for name in _listdir(root_dir):
                if not name.endswith(".json"):
                    continue
                full = os.path.join(root_dir, name)
                try:
                    with open(full, "r", encoding="utf-8", errors="replace") as fh:
                        manifest = json.load(fh)
                except (OSError, ValueError):
                    continue
                path = manifest.get("path") or ""
                entry = {"manifest": full, "path": path,
                         "name": manifest.get("name")}
                data["native_hosts"].append(entry)
                if _path_is_suspicious(path):
                    self.add(_finding(
                        "high", "browser", "Native messaging host in a suspicious path",
                        "A browser extension can launch this native binary.",
                        [entry],
                        "Remove the native host and the extension that references it."))

        # Firefox
        ff_root = _expand("~/Library/Application Support/Firefox/Profiles")
        if os.path.isdir(ff_root):
            for profile in _listdir(ff_root):
                ext_file = os.path.join(ff_root, profile, "extensions.json")
                if not os.path.isfile(ext_file):
                    continue
                try:
                    with open(ext_file, "r", encoding="utf-8", errors="replace") as fh:
                        payload = json.load(fh)
                except (OSError, ValueError):
                    continue
                for addon in payload.get("addons") or []:
                    if addon.get("type") != "extension":
                        continue
                    name = addon.get("defaultLocale", {}).get("name") or addon.get("id")
                    perms = addon.get("userPermissions") or {}
                    risky = []
                    if perms.get("permissions"):
                        risky = [p for p in perms["permissions"] if p in HIGH_RISK_EXT_PERMS]
                    item = {
                        "profile": profile, "id": addon.get("id"),
                        "name": name, "active": addon.get("active"),
                        "signed_state": addon.get("signedState"),
                        "risky_permissions": risky,
                    }
                    data["firefox"].append(item)
                    if risky:
                        self.add(_finding(
                            "medium", "browser", "Broad-permission Firefox extension",
                            "%r has high-risk permissions: %s" %
                            (name, ", ".join(risky)),
                            [item],
                            "Review the extension and remove it if you do not need it."))

        # Safari extensions via pluginkit
        if sys.platform == "darwin" and _which("pluginkit"):
            rc, out, _ = _run(
                ["pluginkit", "-m", "-p", "com.apple.Safari.extension"], 8)
            if rc == 0:
                for line in out.splitlines():
                    line = line.strip()
                    if line and "com.apple" not in line:
                        data["safari"].append(line)
                self.checks_run += 1

        # Managed/browser policies (best effort)
        policy_domains = [
            "com.google.Chrome", "com.brave.Browser", "com.microsoft.edgemac",
            "org.mozilla.firefox",
        ]
        for domain in policy_domains:
            rc, out, _ = _run(["defaults", "read", domain], 5)
            if rc == 0 and out.strip():
                data["policies"].append({"domain": domain,
                                         "text": _redact(out, 400)})
        self.checks_run += 1
        self.section("browsers", data)

    # -- 5. network --------------------------------------------------------

    def collect_network(self):
        data = {"interfaces": {}, "dns": [], "proxy": "", "hosts": [],
                "listening": [], "established": []}
        if sys.platform == "darwin":
            rc, out, _ = _run(["ifconfig"], 8)
            if rc == 0:
                current = None
                for line in out.splitlines():
                    if line and not line.startswith((" ", "\t")):
                        current = line.split(":")[0]
                        data["interfaces"].setdefault(current, {"inet": [], "status": ""})
                    elif current:
                        stripped = line.strip()
                        if stripped.startswith("inet "):
                            data["interfaces"][current]["inet"].append(
                                stripped.split()[1])
                        elif stripped.startswith("status:"):
                            data["interfaces"][current]["status"] = stripped.split(":", 1)[1].strip()
            rc, out, _ = _run(["scutil", "--dns"], 8)
            if rc == 0:
                data["dns"] = sorted(set(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", out)))
            rc, out, _ = _run(["scutil", "--proxy"], 5)
            if rc == 0:
                data["proxy"] = _redact(out, 600)
                if re.search(r"(HTTPEnable|HTTPSEnable|SOCKSEnable)\s*:\s*1", out):
                    self.add(_finding(
                        "low", "network", "A system proxy is configured",
                        "A proxy can be legitimate (corporate/VPN) or used to intercept traffic.",
                        [data["proxy"][:300]],
                        "Confirm the proxy belongs to you or your organization."))

        # /etc/hosts entries beyond the defaults
        hosts_text = _read("/etc/hosts", 100000)
        defaults = {
            "127.0.0.1", "localhost", "255.255.255.255", "broadcasthost",
            "::1", "localhost", "fe80::1%lo0",
        }
        for line in hosts_text.splitlines():
            clean = line.split("#", 1)[0].strip()
            if not clean:
                continue
            parts = clean.split()
            if not parts:
                continue
            ip = parts[0]
            names = parts[1:]
            if ip in defaults or (names and set(names) <= defaults):
                continue
            data["hosts"].append({"ip": ip, "names": names})
        if data["hosts"]:
            self.add(_finding(
                "low", "network", "Custom /etc/hosts entries",
                "Hosts entries can redirect domains; verify they are intentional.",
                data["hosts"][:20],
                "Remove entries you did not add (ad blockers and corporate tools are common)."))
        self.checks_run += 1

        # Listening TCP/UDP sockets
        if _which("lsof"):
            for proto, flag in (("tcp", "TCP:LISTEN"), ("udp", "UDP")):
                rc, out, _ = _run(
                    ["lsof", "-nP", "-i" + proto.upper(), "-s" + flag, "-Fpcn"], 10)
                if rc != 0:
                    continue
                current = {}
                for line in out.splitlines():
                    if line.startswith("p"):
                        if current:
                            data["listening"].append(current)
                        current = {"pid": line[1:], "command": "", "name": ""}
                    elif line.startswith("c"):
                        current["command"] = line[1:]
                    elif line.startswith("n"):
                        current["name"] = line[1:]
                        current["proto"] = proto
                if current:
                    data["listening"].append(current)
            self.checks_run += 1
            for item in data["listening"]:
                name = item.get("name") or ""
                match = re.search(r":(\d+)$", name)
                if not match:
                    continue
                port = int(match.group(1))
                if port in RISK_PORTS:
                    sev, why = RISK_PORTS[port]
                    command = (item.get("command") or "").lower()
                    if port == 5000 and command == "controlcenter":
                        sev, why = "info", "macOS AirPlay Receiver"
                    if sev in ("high", "medium"):
                        self.add(_finding(
                            sev, "network", "Exposed network service: %s" % why,
                            "Port %d is listening (%s, pid %s)." %
                            (port, item.get("command") or "unknown", item.get("pid")),
                            [item],
                            "Disable the service if you do not need it, or restrict it to localhost."))
                if name.startswith(("*:", "0.0.0.0:", "[::]:")) and port not in (22, 80, 443):
                    self.add(_finding(
                        "info", "network", "Service listening on all interfaces",
                        "Port %d (%s) is reachable from the network." %
                        (port, item.get("command") or "unknown"),
                        [item], "Restrict it to 127.0.0.1 if it is only for local use."))

            rc, out, _ = _run(
                ["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-Fpcn"], 10)
            if rc == 0:
                current = {}
                for line in out.splitlines():
                    if line.startswith("p"):
                        if current:
                            data["established"].append(current)
                        current = {"pid": line[1:], "command": "", "name": ""}
                    elif line.startswith("c"):
                        current["command"] = line[1:]
                    elif line.startswith("n"):
                        current["name"] = line[1:]
                if current:
                    data["established"].append(current)
                self.checks_run += 1
                for item in data["established"]:
                    name = item.get("name") or ""
                    match = re.search(r":(\d+)$", name)
                    if not match:
                        continue
                    port = int(match.group(1))
                    if port in (4444, 4445, 1337, 31337, 6667, 6668, 9001, 9050, 1080, 3389):
                        self.add(_finding(
                            "medium", "network", "Connection to an unusual remote port",
                            "%s is connected to %s." %
                            (item.get("command") or "process", name),
                            [item],
                            "Verify the destination and process; block it if you do not recognize it."))

        # Default gateway
        rc, out, _ = _run(["route", "-n", "get", "default"], 5)
        gateway = ""
        if rc == 0:
            match = re.search(r"gateway:\s*(\S+)", out)
            if match:
                gateway = match.group(1)
        data["gateway"] = gateway
        self.section("network", data)

    # -- 6. files / downloads ---------------------------------------------

    def collect_files(self):
        data = {"recent_downloads": [], "quarantine": [], "temp_executables": [],
                "applications": []}
        cutoff = time.time() - 30 * 86400

        downloads = _expand("~/Downloads")
        if os.path.isdir(downloads):
            for name in _listdir(downloads):
                path = os.path.join(downloads, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if st.st_mtime < cutoff or not stat.S_ISREG(st.st_mode):
                    continue
                ext = os.path.splitext(name)[1].lower()
                if ext not in DOWNLOAD_EXTS:
                    continue
                item = {"path": path, "size": st.st_size,
                        "modified": st.st_mtime, "extension": ext,
                        "executable": bool(st.st_mode & stat.S_IXUSR)}
                data["recent_downloads"].append(item)
                if item["executable"] or ext in (".sh", ".command", ".app", ".pkg", ".dmg"):
                    self.add(_finding(
                        "low", "files", "Recent executable download",
                        "A recent download can run code or install software.",
                        [{"path": path, "extension": ext, "size": st.st_size}],
                        "Only open it if you expected it and trust the source; scan it before running."))
        self.checks_run += 1

        # Quarantine events (read-only; no file content)
        qpath = _expand("~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")
        if os.path.isfile(qpath):
            try:
                uri = "file:%s?mode=ro" % qpath
                conn = sqlite3.connect(uri, uri=True, timeout=2)
                try:
                    rows = conn.execute(
                        "SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, "
                        "LSQuarantineDataURLString, LSQuarantineOriginURLString "
                        "FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 50"
                    ).fetchall()
                finally:
                    conn.close()
                for ts, agent, data_url, origin in rows:
                    try:
                        when = 978307200 + float(ts)
                    except (TypeError, ValueError):
                        when = None
                    item = {"time": when, "agent": agent,
                            "data_url": _redact(data_url, 300),
                            "origin": _redact(origin, 300)}
                    data["quarantine"].append(item)
                    if data_url and re.search(r"\.(?:dmg|pkg|zip|sh|command|app|apk)(?:\?|$)",
                                              data_url, re.I):
                        self.add(_finding(
                            "low", "files", "Quarantined executable download",
                            "macOS recorded a downloaded file that can run code.",
                            [item],
                            "Verify the source before opening; delete it if unexpected."))
            except (sqlite3.Error, OSError):
                self.skip("quarantine events", "database unavailable or locked")
        self.checks_run += 1

        # Executables in temp/shared locations
        for folder in ("/tmp", "/var/tmp", "/Users/Shared"):
            if not os.path.isdir(folder):
                continue
            try:
                names = os.listdir(folder)
            except OSError:
                continue
            for name in names[:500]:
                path = os.path.join(folder, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode) or st.st_mtime < cutoff:
                    continue
                executable = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                if not executable:
                    continue
                data["temp_executables"].append({
                    "path": path, "size": st.st_size, "modified": st.st_mtime,
                    "sha256": _sha256(path) if st.st_size <= 50 * 1024 * 1024 else "",
                })
                self.add(_finding(
                    "medium", "files", "Executable file in a temp/shared folder",
                    "Executables in temp/shared locations are often dropped by malware.",
                    [{"path": path, "size": st.st_size}],
                    "Identify the owning process and remove it only after preserving a copy."))
        self.checks_run += 1

        # Recently changed applications (signature check)
        for folder in ("/Applications", "~/Applications"):
            root = _expand(folder)
            if not os.path.isdir(root):
                continue
            for name in _listdir(root)[:200]:
                if not name.endswith(".app"):
                    continue
                path = os.path.join(root, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if st.st_mtime < time.time() - 90 * 86400:
                    continue
                rc, out, err = _run(["codesign", "-dv", "--verbose=2", path], 8)
                text = out + "\n" + err
                signed = "Authority=" in text
                item = {"path": path, "modified": st.st_mtime,
                        "signed": signed, "signature": _redact(text, 300)}
                data["applications"].append(item)
                if not signed:
                    self.add(_finding(
                        "medium", "files", "Unsigned or unnotarized application",
                        "A recently changed app has no readable code signature.",
                        [{"path": path}],
                        "Verify the source; remove it if you did not install it."))
        self.checks_run += 1
        self.section("files", data)

    # -- 7. extensions / profiles -----------------------------------------

    def collect_extensions(self):
        data = {"system_extensions": [], "kexts": []}
        if sys.platform != "darwin":
            self.skip("system extensions", "not running on macOS")
            return
        rc, out, _ = _run(["systemextensionsctl", "list"], 8)
        if rc == 0 and out.strip():
            for line in out.splitlines():
                if line.strip() and not line.startswith(("---", "enabled")):
                    data["system_extensions"].append(_redact(line, 240))
            self.checks_run += 1
        rc, out, _ = _run(["kmutil", "showloaded", "--list-only"], 10)
        if rc == 0 and out.strip():
            for line in out.splitlines():
                low = line.lower()
                if "com.apple" in low or not line.strip():
                    continue
                data["kexts"].append(_redact(line, 240))
            if data["kexts"]:
                self.add(_finding(
                    "medium", "extensions", "Third-party kernel extensions loaded",
                    "Kernel extensions run with high privileges and can affect the whole system.",
                    data["kexts"][:10],
                    "Remove extensions you do not recognize; prefer system extensions."))
            self.checks_run += 1
        self.section("extensions", data)

    # -- 8. mobile devices -------------------------------------------------

    def collect_mobile(self):
        data = {"android": [], "ios": [], "usb": []}
        if sys.platform != "darwin":
            self.skip("mobile device checks", "not running on macOS")
            self.section("mobile", data)
            return

        # USB inventory (text output is stable enough and cheap)
        rc, out, _ = _run(["system_profiler", "SPUSBDataType"], 15)
        if rc == 0:
            current = None
            for line in out.splitlines():
                stripped = line.strip()
                if re.search(r"(iPhone|iPad|Android|Pixel|Galaxy|OnePlus|Xiaomi)", stripped, re.I):
                    current = stripped
                    data["usb"].append(current)
            self.checks_run += 1

        # iOS devices via xctrace (no jailbreak or app data access)
        if _which("xcrun"):
            rc, out, _ = _run(["xcrun", "xctrace", "list", "devices"], 20)
            if rc == 0:
                for line in out.splitlines():
                    if re.search(r"\b(iPhone|iPad)\b", line) and "Simulator" not in line:
                        data["ios"].append(_redact(line.strip(), 160))
                self.checks_run += 1

        # Android via ADB, only if the user already authorized the device
        adb = _which("adb")
        if adb:
            rc, out, _ = _run([adb, "devices", "-l"], 10)
            if rc == 0:
                for line in out.splitlines()[1:]:
                    line = line.strip()
                    if not line or "\t" not in line:
                        continue
                    serial, state = line.split("\t", 1)
                    item = {"serial": serial, "state": state}
                    data["android"].append(item)
                    if state.startswith("unauthorized"):
                        self.add(_finding(
                            "info", "mobile", "Android device connected but not authorized",
                            "ADB cannot inspect it until you approve the USB debugging prompt.",
                            [item], "Approve only if you are debugging your own device."))
                        continue
                    if not state.startswith("device"):
                        continue
                    props = {}
                    for prop in ("ro.product.model", "ro.product.manufacturer",
                                 "ro.build.version.release", "ro.build.version.security_patch",
                                 "ro.debuggable", "ro.secure"):
                        prc, pout, _ = _run([adb, "-s", serial, "shell", "getprop", prop], 6)
                        if prc == 0:
                            props[prop] = pout.strip()
                    item["properties"] = props
                    prc, pout, _ = _run([adb, "-s", serial, "shell", "pm", "list", "packages", "-3"], 10)
                    if prc == 0:
                        packages = [p.replace("package:", "") for p in pout.splitlines()
                                    if p.startswith("package:")]
                        item["third_party_packages"] = packages[:200]
                        item["third_party_count"] = len(packages)
                    prc, pout, _ = _run([adb, "-s", serial, "shell", "dumpsys", "device_policy"], 10)
                    if prc == 0:
                        admins = re.findall(r"Package:\s*([^\s]+)", pout)
                        item["device_admins"] = sorted(set(admins))
                        if admins:
                            self.add(_finding(
                                "medium", "mobile", "Android device-admin app present",
                                "Device-admin apps can lock or wipe the device.",
                                [{"device": serial, "admins": sorted(set(admins))}],
                                "Review Settings > Security > Device admin apps."))
                    prc, pout, _ = _run([adb, "-s", serial, "shell", "settings", "get",
                                         "secure", "enabled_accessibility_services"], 6)
                    if prc == 0 and pout.strip() and pout.strip() != "null":
                        item["accessibility_services"] = pout.strip().split(":")
                        self.add(_finding(
                            "medium", "mobile", "Android accessibility services enabled",
                            "Accessibility services can read the screen and automate taps.",
                            [{"device": serial, "services": pout.strip()}],
                            "Review Settings > Accessibility > Downloaded services."))
                    prc, pout, _ = _run([adb, "-s", serial, "shell", "which", "su"], 5)
                    if prc == 0 and pout.strip():
                        self.add(_finding(
                            "high", "mobile", "Android device appears rooted",
                            "A `su` binary is present; root greatly increases malware impact.",
                            [{"device": serial, "su": pout.strip()}],
                            "Remove root if you did not intend it; reflash from a trusted image if unsure."))
                    self.checks_run += 1
        else:
            self.skip("Android ADB checks", "adb not installed")

        # Optional libimobiledevice inventory (no deep scan)
        idevice = _which("ideviceinfo")
        if idevice and data["ios"]:
            rc, out, _ = _run([idevice, "-k", "ProductType"], 8)
            if rc == 0 and out.strip():
                data["ios"].append("ProductType: " + out.strip())
        self.section("mobile", data)

    # -- 9. LAN inventory --------------------------------------------------

    def collect_lan(self):
        data = {"local_ipv4": [], "gateway": "", "devices": [],
                "active": self.active_lan, "notes": [
                    "Active checks are limited to private IPv4 addresses.",
                    "Only TCP connect is used; no exploitation, login attempts or packet capture.",
                ]}
        if sys.platform != "darwin":
            self.skip("LAN inventory", "not running on macOS")
            self.section("lan", data)
            return

        rc, out, _ = _run(["ifconfig"], 8)
        if rc == 0:
            current = None
            for line in out.splitlines():
                if line and not line.startswith((" ", "\t")):
                    current = line.split(":")[0]
                elif current and line.strip().startswith("inet "):
                    parts = line.strip().split()
                    if len(parts) >= 4 and _private_ipv4(parts[1]):
                        data["local_ipv4"].append({
                            "interface": current, "ip": parts[1],
                            "netmask": parts[3] if len(parts) > 3 else "",
                        })

        rc, out, _ = _run(["route", "-n", "get", "default"], 5)
        if rc == 0:
            match = re.search(r"gateway:\s*(\S+)", out)
            if match:
                data["gateway"] = match.group(1)

        arp = {}
        rc, out, _ = _run(["arp", "-an"], 8)
        if rc == 0:
            for line in out.splitlines():
                match = re.search(r"\? \(([\d.]+)\) at ([0-9a-f:]+)", line, re.I)
                if not match:
                    match = re.search(r"(\S+) \(([\d.]+)\) at ([0-9a-f:]+)", line, re.I)
                    if match:
                        hostname, ip, mac = match.group(1), match.group(2), match.group(3)
                    else:
                        continue
                else:
                    ip, mac = match.group(1), match.group(2)
                    hostname = ""
                if not _private_ipv4(ip) or mac in ("(incomplete)", "ff:ff:ff:ff:ff:ff"):
                    continue
                arp[ip] = {"ip": ip, "mac": mac, "hostname": hostname}
        if data["gateway"] and _private_ipv4(data["gateway"]):
            arp.setdefault(data["gateway"], {"ip": data["gateway"], "mac": "",
                                             "hostname": "gateway"})

        own = {entry["ip"] for entry in data["local_ipv4"]}
        hosts = [item for ip, item in arp.items() if ip not in own]
        hosts.sort(key=lambda item: (item["ip"] != data["gateway"], item["ip"]))
        if len(hosts) > self.max_hosts:
            data["notes"].append("Host list capped at %d entries." % self.max_hosts)
            hosts = hosts[:self.max_hosts]

        for item in hosts:
            prefix = (item["mac"] or "").lower()[:8]
            item["vendor"] = OUI_VENDORS.get(prefix, "")
            item["open_ports"] = []
            item["services"] = []
            if self.active_lan:
                item["open_ports"] = self._probe_ports(item["ip"], COMMON_PORTS)
                for port in item["open_ports"]:
                    sev, why = RISK_PORTS.get(port, ("info", "open service"))
                    item["services"].append({"port": port, "risk": sev, "label": why})
                    if sev in ("high", "medium"):
                        self.add(_finding(
                            sev, "lan", "Risky service exposed on the LAN",
                            "%s (%s) has port %d open: %s" %
                            (item["ip"], item.get("vendor") or "unknown device",
                             port, why),
                            [{"ip": item["ip"], "mac": item["mac"], "port": port}],
                            "Disable the service, restrict it to trusted devices, or isolate the device."))
            item["device_type"] = self._guess_device(item)
            data["devices"].append(item)
        self.checks_run += 1
        if "system" not in self.sections:
            host = {"hostname": socket.gethostname(), "platform": sys.platform}
            if sys.platform == "darwin":
                rc, out, _ = _run(["scutil", "--get", "ComputerName"], 4)
                if rc == 0 and out.strip():
                    host["computer_name"] = out.strip()
            self.section("system", {"host": host, "security": {}})
        self.section("lan", data)

    @staticmethod
    def _probe_ports(ip, ports, timeout=0.35, workers=32):
        def one(port):
            try:
                with socket.create_connection((ip, port), timeout=timeout):
                    return port
            except OSError:
                return None

        open_ports = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(one, port) for port in ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        return sorted(set(open_ports))

    @staticmethod
    def _guess_device(item):
        ports = set(item.get("open_ports") or [])
        vendor = (item.get("vendor") or "").lower()
        if 62078 in ports:
            return "iPhone/iPad"
        if ports & {7000, 7001, 8008, 8009, 32400}:
            return "Apple TV / media device"
        if ports & {9100, 631}:
            return "printer"
        if 3389 in ports:
            return "Windows computer"
        if 445 in ports or 139 in ports:
            return "computer / NAS"
        if 7547 in ports or (80 in ports and 443 in ports):
            return "router / network device"
        if "apple" in vendor:
            return "Apple device"
        if "samsung" in vendor or "lg" in vendor or "sony" in vendor:
            return "TV / appliance"
        return "unknown"


# ---------------------------------------------------------------------------
# Report formatting / export
# ---------------------------------------------------------------------------

def _fmt_time(ts):
    if not ts:
        return "?"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))
    except (TypeError, ValueError, OSError):
        return "?"


def _fmt_bytes(value):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return "%.1f %s" % (value, unit)
        value /= 1024
    return "%.1f GB" % value


def format_report(report, full=False):
    """Render a human-readable summary, or the full report with `full=True`."""
    if not report:
        return "No device audit report."
    summary = report.get("summary") or {}
    host = report.get("host") or {}
    lines = [
        "🛡 Device audit — %s" % (host.get("computer_name") or host.get("hostname") or "this device"),
        "",
        "Risk: %s (%d/100) · checks: %d · findings: %s" % (
            (summary.get("risk") or "low").upper(),
            int(summary.get("score") or 0),
            int(summary.get("checks_run") or 0),
            ", ".join("%d %s" % (n, k) for k, n in sorted(
                (summary.get("findings") or {}).items(),
                key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))) or "none",
        ),
        "Generated: %s · active LAN: %s" % (
            _fmt_time(report.get("generated_at")),
            "yes" if summary.get("active_lan") else "no"),
    ]
    version = host.get("productversion") or host.get("product_version")
    build = host.get("buildversion") or host.get("build_version")
    if version:
        lines.append("macOS: %s (%s) · %s" % (
            version, build or "?", host.get("model") or "?"))

    findings = report.get("findings") or []
    top = [f for f in findings if f.get("severity") in ("critical", "high", "medium")][:12]
    if top:
        lines += ["", "Top findings:"]
        for item in top:
            lines.append("  [%s] %s" % (item["severity"].upper(), item["title"]))
            lines.append("      " + _redact(item.get("detail"), 240))
    elif findings:
        lines += ["", "No high/medium findings. Lower-priority notes are in the full report."]
    else:
        lines += ["", "No findings. This is not a guarantee of cleanliness."]

    lan = (report.get("sections") or {}).get("lan") or {}
    devices = lan.get("devices") or []
    if devices:
        lines += ["", "LAN devices (%d):" % len(devices)]
        for dev in devices[:20]:
            ports = ", ".join(str(p) for p in dev.get("open_ports") or []) or "no checked ports open"
            lines.append("  • %s %s %s · %s" % (
                dev.get("ip"), dev.get("vendor") or "", dev.get("device_type") or "",
                ports))

    if not full:
        lines += ["", "Use --device-full for every section, or open the exported report."]
    else:
        lines += ["", "=" * 70]
        for name, value in (report.get("sections") or {}).items():
            lines += ["", "## " + name.replace("_", " ").title()]
            lines += _section_lines(name, value)
        lines += ["", "## Device checklists"]
        for name, items in (report.get("device_checklists") or {}).items():
            lines.append("")
            lines.append(name.upper())
            lines += ["  • " + item for item in items]
    return "\n".join(lines)


def _section_lines(name, value):
    if isinstance(value, dict):
        out = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                out.append("  %s: %s" % (key, json.dumps(item, ensure_ascii=False)[:400]))
            else:
                out.append("  %s: %s" % (key, item))
        return out
    if isinstance(value, list):
        return ["  • " + json.dumps(item, ensure_ascii=False)[:400] for item in value[:200]]
    return ["  " + str(value)]


def _markdown_report(report):
    lines = ["# Device audit report", ""]
    host = report.get("host") or {}
    summary = report.get("summary") or {}
    lines += [
        "- **Host:** %s" % (host.get("computer_name") or host.get("hostname") or "this device"),
        "- **Generated:** %s" % _fmt_time(report.get("generated_at")),
        "- **Risk:** %s (%d/100)" % (
            (summary.get("risk") or "low").upper(), int(summary.get("score") or 0)),
        "- **Checks run:** %d" % int(summary.get("checks_run") or 0),
        "- **Active LAN checks:** %s" % ("yes" if summary.get("active_lan") else "no"),
        "",
        "## Findings",
        "",
    ]
    findings = report.get("findings") or []
    if not findings:
        lines.append("No findings. This is not a guarantee of cleanliness.")
    for item in findings:
        lines += [
            "### [%s] %s" % (item["severity"].upper(), item["title"]),
            "",
            item.get("detail") or "",
            "",
        ]
        if item.get("evidence"):
            lines += ["Evidence: `%s`" % json.dumps(item["evidence"], ensure_ascii=False)[:600], ""]
        if item.get("recommendation"):
            lines += ["Recommendation: " + item["recommendation"], ""]
    lines += ["", "## Sections", ""]
    for name, value in (report.get("sections") or {}).items():
        lines += ["### " + name.replace("_", " ").title(), ""]
        lines += ["```json", json.dumps(value, ensure_ascii=False, indent=2)[:200000], "```", ""]
    lines += ["## Device checklists", ""]
    for name, items in (report.get("device_checklists") or {}).items():
        lines += ["### " + name, ""]
        lines += ["- " + item for item in items]
        lines.append("")
    return "\n".join(lines)


def export_report(report, out_dir=None):
    """Write JSON + Markdown + SHA256SUMS into a private folder."""
    if out_dir:
        folder = os.path.abspath(os.path.expanduser(out_dir))
    else:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        folder = os.path.join(phones.data_dir(), "device-reports", stamp)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    try:
        os.chmod(folder, 0o700)
    except OSError:
        pass
    json_path = os.path.join(folder, "report.json")
    md_path = os.path.join(folder, "report.md")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(_markdown_report(report))
    sums = []
    for path in (json_path, md_path):
        sums.append("%s  %s" % (_sha256(path), os.path.basename(path)))
    with open(os.path.join(folder, "SHA256SUMS"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(sums) + "\n")
    return {"folder": folder, "json": json_path, "markdown": md_path,
            "sha256sums": os.path.join(folder, "SHA256SUMS")}


def audit(active_lan=True, include_lan=True, include_mobile=True,
          max_hosts=64, progress=None):
    return DeviceAudit(active_lan=active_lan, include_lan=include_lan,
                       include_mobile=include_mobile, max_hosts=max_hosts,
                       progress=progress).run()
