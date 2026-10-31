"""scamcheck - check whether an SMS/text message is a scam.

Usage examples:
    python3 -m scamcheck "Your account will be blocked, verify now: bit.ly/x1y2z"
    python3 -m scamcheck -f message.txt
    cat message.txt | python3 -m scamcheck --stdin
    python3 -m scamcheck --image screenshot.png      (OCR: macOS Vision / tesseract / AI)
    python3 -m scamcheck --watch                     (clipboard watcher: any copied text or screenshot auto-checks)
    python3 -m scamcheck --jarvis                    (console: memory, voice, QR, links, numbers)
    python3 -m scamcheck --device-audit              (read-only device + private-LAN audit)
    python3 -m scamcheck "Hi, your parcel arrives tomorrow" --json
"""

import argparse
import hashlib
import json
import os
import sys
import time

from .analyzer import analyze
from .api import serve
from . import phones
from . import __version__


BAR_BLOCKS = 22
BAR_WIDTH = BAR_BLOCKS + 2

COLORS = {
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}

VERDICT_STYLE = {
    "LIKENONE": ("green", None),  # placeholder
    "LIKELY SAFE": ("green", None),
    "SUSPICIOUS": ("yellow", "!"),
    "LIKELY SCAM": ("red", "!!"),
    "SCAM": ("red", "!!!"),
}


def supports_color():
    return sys.stdout.isatty() and (sys.platform != "win32")


def c(color, s, enabled=True):
    if not enabled:
        return s
    return COLORS[color] + s + COLORS["reset"]


def risk_bar(score, use_color):
    filled = round(score / 100 * BAR_BLOCKS)
    bar = "█" * filled + "░" * (BAR_BLOCKS - filled)
    color = "green"
    if score >= 35:
        color = "red"
    elif score >= 15:
        color = "yellow"
    return c(color, bar, use_color)


def print_human(result, use_color, show_intel=True):
    final = result["final_verdict"]
    style, badge = VERDICT_STYLE.get(final, ("yellow", "!"))
    icon = {"LIKELY SAFE": "✅", "SUSPICIOUS": "⚠️", "LIKELY SCAM": "🚨", "SCAM": "🚨"}.get(final, "❓")

    print()
    print(c("bold", icon + "  VERDICT: " + final, use_color))
    print("   Rules score: " + risk_bar(result["score"], use_color) + "  %d/100" % result["score"])

    if result.get("scripts"):
        print("   Playbook: " + " | ".join(result["scripts"]))
    conv = result.get("conversation")
    if conv:
        print("   Conversation: %d messages, trajectory verdict %s" % (conv["message_count"], conv["verdict"]))

    intel = result.get("intelligence") or {}
    if show_intel and intel and intel.get("scam_type") not in (None, "general"):
        print("   Intel: " + intel.get("summary", ""))
        stage = intel.get("stage") or {}
        if stage.get("key"):
            print("   Stage: " + stage.get("label", stage["key"]))
        if intel.get("next_moves"):
            print("   Likely next: " + intel["next_moves"][0])

    num = result.get("number") or {}
    if num.get("sender"):
        s = num["sender"]
        n = s["number"]
        rep = s["reputation"]
        label = n.get("e164") or n.get("national")
        bits = [n.get("kind", "number")]
        if rep.get("status") == "blocked":
            bits.append("ON YOUR BLOCKLIST")
        elif rep.get("status") == "allowed":
            bits.append("on your allowlist")
        elif rep.get("status") == "reported":
            bits.append("reported %dx via %s" % (rep.get("reports", 1), rep.get("source")))
        print("   Sender: %s  (%s)" % (label, ", ".join(bits)))
    for m in (num.get("mentioned") or []):
        n = m["number"]
        rep = m.get("reputation") or {}
        if rep.get("status") == "blocked":
            tag = "ON YOUR BLOCKLIST"
        elif rep.get("status") == "reported":
            tag = "reported %dx" % rep.get("reports", 1)
        elif n.get("kind") == "premium":
            tag = "premium-rate"
        else:
            continue
        print("   Number in message: %s  (%s)" % (n.get("e164") or n.get("national"), tag))

    if result.get("qr"):
        for code in result["qr"][:3]:
            print("   QR code: " + str(code.get("payload") or "")[:120])

    if result.get("ai"):
        ai = result["ai"]
        print(
            "   AI opinion (%s, confidence %d%%): %s"
            % (ai["verdict"], ai["confidence"], ai["summary"])
        )
    want_ai = result.get("ai_requested") and not result.get("ai")
    if want_ai:
        print(
            c("dim", "   (AI check not available - set OPENAI_API_KEY or ANTHROPIC_API_KEY to enable)", use_color)
        )

    if result["reasons"]:
        print()
        print(c("bold", "   Why (%d signal%s):" % (len(result["reasons"]), "s" if len(result["reasons"]) != 1 else ""), use_color))
        for label, weight in result["reasons"]:
            signed = ("+%s" % weight) if weight >= 0 else str(weight)
            print("   %s %s (severity %s [%s points])" % (c("dim", "•", use_color), label, weight, signed))
    if result.get("ai") and result["ai"]["reasons"]:
        for r in result["ai"]["reasons"]:
            print("   %s %s" % (c("dim", "•", use_color), r))
    print()


def watch_hits(result, bump=True):
    """Return local watchlist matches for one result (never raises)."""
    try:
        from . import intel
        from .watchlist import Watchlist
        identifiers = intel.extract_entities(
            result.get("message") or "",
            result=result if isinstance(result, dict) else None,
        )
        store = Watchlist()
        hits = store.match(identifiers)
        if hits and bump:
            store.bump(hits)
        return hits
    except Exception:
        return []


def run_text(text, args, ocr=False, quiet=False, on_result=None,
             qr=None, ocr_engine=None):
    """Shared pipeline: analyze + print, return the exit code."""
    result = analyze(text, use_ai=args.ai, is_conversation=args.chat, ocr=ocr,
                     sender=getattr(args, "sender", None),
                     region=getattr(args, "region", None))
    result["ai_requested"] = args.ai == "always" or (args.ai == "auto" and 15 <= result["score"] < 60)
    result["message"] = text
    result["kind"] = "image" if ocr else "text"
    if qr:
        result["qr"] = qr
    if ocr_engine:
        result["ocr_engine"] = ocr_engine

    # The memory hook (when enabled) bumps watchlist counters itself.
    hits = watch_hits(result, bump=not on_result)
    if hits:
        result["watchlist"] = hits

    if args.json:
        print(json.dumps({k: v for k, v in result.items() if k != "ai_requested"}, ensure_ascii=False, indent=2))
    elif not quiet:
        show_intel = not getattr(args, "intel", False)
        print_human(result, use_color=supports_color(), show_intel=show_intel)
        if getattr(args, "intel", False):
            from .intelligence import format_briefing
            print(format_briefing(result.get("intelligence") or {}))
            print()
        if hits:
            from .watchlist import format_hits
            print(format_hits(hits).strip())
            print()

    if on_result:
        try:
            on_result(result)
        except Exception as exc:
            print("warning: could not record the result (%s)" % exc, file=sys.stderr)

    final = result["final_verdict"]
    if final == "SCAM":
        return 2
    if final in ("SUSPICIOUS", "LIKELY SCAM"):
        return 1
    return 0


def run_image(image_path, args, on_result=None):
    """OCR a screenshot + decode QR codes, then analyze the extracted text."""
    from .ocr import detect_qr, ocr_image, qr_text

    text, engine = ocr_image(image_path)
    qr = detect_qr(image_path)
    codes = qr.get("codes") or []
    payload_text = qr_text(codes)
    analysis = (text or "").strip()
    if payload_text:
        analysis = (analysis + "\n" + payload_text).strip()

    if not analysis:
        detail = qr.get("error") if not qr.get("available") else "no QR/barcode found"
        print("Could not read any text or QR code from %s (OCR: %s; QR: %s)" % (
            image_path, engine, detail or "unavailable"), file=sys.stderr)
        return 2

    if not args.json:
        if text and text.strip():
            print("Read screenshot with %s OCR (%d chars):" % (engine, len(text)))
            for line in text.splitlines()[:8]:
                print("   | " + line)
            if text.count("\n") > 7:
                print("   | ...")
        else:
            print("No OCR text; analyzing the decoded QR payload.")
    return run_text(analysis, args, ocr=True, on_result=on_result,
                    qr=codes, ocr_engine=engine)


def split_batch(blob):
    """Split a batch file into messages on blank lines.

    SMS exports and pasted inbox dumps wrap messages across lines, so the
    blank line is the only reliable separator.
    """
    blob = blob.replace("\r\n", "\n").replace("\r", "\n")
    blocks, cur = [], []
    for line in blob.split("\n"):
        if line.strip() == "":
            if cur:
                blocks.append("\n".join(cur).strip())
                cur = []
        else:
            cur.append(line)
    if cur:
        blocks.append("\n".join(cur).strip())
    return [b for b in blocks if b]


def run_batch(path, args):
    """Check many messages at once (SMS inbox export, pasted dump)."""
    if path == "-":
        blob = sys.stdin.read()
    else:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                blob = fh.read()
        except OSError as exc:
            print("Cannot read batch file: %s" % exc, file=sys.stderr)
            return 2

    blocks = split_batch(blob)
    if not blocks:
        print("Batch file has no messages: %s" % path, file=sys.stderr)
        return 2

    ranks = {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "LIKELY SCAM": 2, "SCAM": 3}
    results, rc = [], 0
    all_hits, seen_hits = [], set()
    for i, block in enumerate(blocks, 1):
        # Each block is ONE message by default: an SMS export wraps lines and
        # auto-conversation would suppress the per-message rules. Use --chat
        # when each block really is a transcript.
        sender, body = phones.split_sender(block)
        result = analyze(body, use_ai=args.ai,
                         is_conversation=True if args.chat else False,
                         sender=sender, region=getattr(args, "region", None))
        result["message"] = body
        result["index"] = i
        if sender:
            result["sender_input"] = sender
        hits = watch_hits(result, bump=False)
        if hits:
            result["watchlist"] = hits
            for hit in hits:
                key = (hit.get("kind"), hit.get("value"))
                if key not in seen_hits:
                    seen_hits.add(key)
                    all_hits.append(hit)
        results.append(result)
        rank = ranks[result["final_verdict"]]
        rc = max(rc, 2 if rank == 3 else 1 if rank >= 1 else 0)

    if all_hits:
        try:
            from .watchlist import Watchlist
            Watchlist().bump(all_hits)
        except Exception:
            pass

    if args.json:
        print(json.dumps({"count": len(results), "messages": results},
                         ensure_ascii=False, indent=2))
        return rc

    use_color = supports_color()
    icons = {"LIKELY SAFE": "✅", "SUSPICIOUS": "⚠️",
             "LIKELY SCAM": "🚨", "SCAM": "🚨"}
    print()
    print(c("bold", "Batch: %d message%s" % (len(results), "" if len(results) == 1 else "s"), use_color))
    for r in results:
        snippet = r["message"].splitlines()[0]
        if len(snippet) > 62:
            snippet = snippet[:59] + "..."
        playbook = ""
        if r.get("scripts"):
            playbook = "  [" + r["scripts"][0] + "]"
        sender_note = ""
        if r.get("number", {}).get("sender"):
            status = r["number"]["sender"]["reputation"].get("status")
            if status in ("blocked", "reported"):
                sender_note = "  <sender %s>" % status
        if r.get("watchlist"):
            sender_note += "  <WATCHLIST>"
        print("  %3d. %s %-12s %3d  %s%s%s" % (
            r["index"], icons.get(r["final_verdict"], "❓"),
            r["final_verdict"], r["score"], snippet, playbook, sender_note))
    counts = {}
    for r in results:
        counts[r["final_verdict"]] = counts.get(r["final_verdict"], 0) + 1
    summary = ", ".join(
        "%d %s" % (counts[k], k) for k in
        ("SCAM", "LIKELY SCAM", "SUSPICIOUS", "LIKELY SAFE") if k in counts
    )
    print()
    print(c("bold", "Summary: " + summary, use_color))
    print()
    return rc


IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".heic", ".heif",
                    ".tif", ".tiff", ".webp", ".bmp")


def _image_files(folder):
    """Return [(path, mtime, size)] for images in a folder, oldest first."""
    out = []
    try:
        names = os.listdir(folder)
    except OSError:
        return out
    for name in names:
        if name.startswith(".") or not name.lower().endswith(IMAGE_EXTENSIONS):
            continue
        path = os.path.join(folder, name)
        try:
            st = os.stat(path)
        except OSError:
            continue
        if os.path.isfile(path):
            out.append((path, st.st_mtime, st.st_size))
    out.sort(key=lambda item: item[1])
    return out


def watch_args(args):
    """Copy of args with ambient AI clamped to local-only unless opted in.

    A watch loop must not silently ship borderline messages to an AI just
    because an API key happens to be present. Explicit `--ai never` always
    wins; otherwise `SCAMCHECK_WATCH_AI=auto|always` is required to opt in.
    """
    local_args = argparse.Namespace(**vars(args))
    mode = (os.environ.get("SCAMCHECK_WATCH_AI") or "never").lower()
    if mode not in ("auto", "always"):
        mode = "never"
    if getattr(local_args, "ai", "never") != "never":
        local_args.ai = mode
    return local_args


def run_watch(args, interval=None):
    """Clipboard + screenshot-folder watcher with optional voice/notify/memory.

    The family workflow: take a screenshot (Cmd+Shift+4 -> file, or
    Cmd+Ctrl+Shift+4 -> straight to clipboard), then just watch the terminal.
    Point ``--screenshot-dir`` at a screenshots folder for ambient checking.
    """
    from .ocr import clipboard_to_tempfile, get_clipboard_image, get_clipboard_text

    interval = interval or 2.5
    folder = getattr(args, "screenshot_dir", None)
    if folder and not os.path.isdir(os.path.expanduser(folder)):
        print("Screenshot folder does not exist: %s" % folder, file=sys.stderr)
        return 2
    folder = os.path.abspath(os.path.expanduser(folder)) if folder else None

    local_args = watch_args(args)

    session, hook = None, None
    try:
        from .jarvis import JarvisSession
        session = JarvisSession(voice=getattr(args, "voice", None),
                                notify=getattr(args, "notify", None),
                                region=getattr(args, "region", None))
        hook = session.observe_result
    except Exception as exc:
        print("warning: memory/voice disabled (%s)" % exc, file=sys.stderr)

    last_text_hash = None
    last_image_hash = None
    file_state = {}
    first_scan = True
    print("Watching the clipboard (Ctrl+C to stop). Copy any message or screenshot...")
    if folder:
        print("Also watching %s for new screenshots." % folder)
    try:
        while True:
            if folder:
                images = _image_files(folder)
                if first_scan:
                    newest = images[-10:]
                    for path, mtime, size in images:
                        file_state[path] = (mtime, size)
                    if newest:
                        print("\n--- checking %d recent screenshot%s in %s ---" % (
                            len(newest), "" if len(newest) == 1 else "s", folder))
                    for path, _mtime, _size in newest:
                        run_image(path, local_args, on_result=hook)
                    first_scan = False
                else:
                    for path, mtime, size in images:
                        stamp = (mtime, size)
                        if file_state.get(path) == stamp:
                            continue
                        file_state[path] = stamp
                        print("\n--- new screenshot at %s: %s ---" % (
                            time.strftime("%H:%M:%S"), os.path.basename(path)))
                        run_image(path, local_args, on_result=hook)

            text = get_clipboard_text()
            image_bytes = get_clipboard_image()

            text_hash = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest() if text else None
            image_hash = hashlib.sha256(image_bytes).hexdigest() if image_bytes else None

            if text_hash and text_hash != last_text_hash:
                print("\n--- new clipboard text at %s ---" % time.strftime("%H:%M:%S"))
                run_text(text, local_args, on_result=hook)
                last_text_hash = text_hash
            if image_hash and image_hash != last_image_hash:
                print("\n--- new clipboard screenshot at %s ---" % time.strftime("%H:%M:%S"))
                tmp = clipboard_to_tempfile(image_bytes)
                try:
                    run_image(tmp, local_args, on_result=hook)
                finally:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
                last_image_hash = image_hash
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped watching.")
        return 0


def run_number(number, args):
    """Check a single number's reputation + range flags (no message needed)."""
    intel = phones.check_number(number, region=getattr(args, "region", None))
    info = intel["number"]
    risk = intel["risk"]
    rc = 2 if risk == "high" else 1 if risk == "medium" else 0
    label = info.get("e164") or info.get("national") or number

    hits = []
    try:
        from .watchlist import Watchlist
        hits = Watchlist().match([{"kind": "phone", "value": label, "label": label}])
        if hits:
            Watchlist().bump(hits)
            intel["watchlist"] = hits
    except Exception:
        hits = []

    if args.json:
        print(json.dumps(intel, ensure_ascii=False, indent=2))
        return rc

    if not info["valid"]:
        print("Not a valid phone number: %s (%s)" % (number, info["note"]), file=sys.stderr)
        return 2
    print()
    print("   Number: %s" % label)
    print("   Type:   %s%s" % (
        info.get("kind"),
        " · " + info.get("country_name", info.get("country") or "") if info.get("country_name") else ""))
    rep = intel["reputation"]
    if rep.get("status") == "blocked":
        print("   Local:  ON YOUR BLOCKLIST" + (" (" + rep["label"] + ")" if rep.get("label") else ""))
    elif rep.get("status") == "allowed":
        print("   Local:  on your allowlist" + (" (" + rep["label"] + ")" if rep.get("label") else ""))
    elif rep.get("status") == "reported":
        print("   Local:  reported %d time%s via %s" % (
            rep.get("reports", 1), "" if rep.get("reports") == 1 else "s", rep.get("source")))
    else:
        print("   Local:  no reputation data (not a clean bill of health)")
    if intel["flags"]:
        print("   Flags:  " + "; ".join(intel["flags"]))
    if hits:
        from .watchlist import format_hits
        print(format_hits(hits).rstrip())
    print()
    return rc


def run_feed_update(args):
    def progress(item):
        if args.json:
            return
        if item["ok"]:
            print("  ok    %-50s %6d numbers" % (item["label"][:50], item["count"]))
        else:
            print("  FAIL  %-50s %s" % (item["label"][:50], item.get("error", "?")))

    if not args.json:
        print("Updating phone-number feeds (opt-in network access; message content is never sent)...")
    report = phones.update_feeds(region=getattr(args, "region", None), progress=progress)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif not report.get("configured"):
        print("No feeds configured. Add one per line to:")
        print("  " + phones.feeds_conf_path())
        print("Format:  URL | label | format     (format: txt, csv, csv:number,label,reports)")
        print("Nothing was downloaded.")
        return 0
    else:
        print("Done. Cache: " + phones.feed_status()["path"])
    return 0 if all(s["ok"] for s in report.get("sources", [])) else 1


def run_feed_status(args):
    status = phones.feed_status()
    if args.json:
        print(json.dumps(status, ensure_ascii=False, indent=2))
        return 0
    print()
    if not status["sources"]:
        print("No cached feeds. Configure " + phones.feeds_conf_path() +
              " then run: scamcheck --update-feeds")
    else:
        print("Cached feeds (%d):" % len(status["sources"]))
        for src in status["sources"]:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(src["fetched_at"])) if src.get("fetched_at") else "?"
            print("  %-40s %8s numbers  updated %s" % (
                (src.get("label") or src["url"])[:40], src.get("count", 0), when))
    configured = [c for c in status["configured"]]
    print()
    print("Configured sources: %d  (%s)" % (len(configured), phones.feeds_conf_path()))
    print()
    return 0


def run_lists(args):
    lists = phones.list_numbers()
    if args.json:
        print(json.dumps(lists, ensure_ascii=False, indent=2))
        return 0
    print()
    for title, key in (("Blocked", "blocked"), ("Allowed", "allowed")):
        entries = lists[key]
        print("%s (%d)" % (title, len(entries)))
        for num, meta in sorted(entries.items()):
            print("  %-20s %s" % (meta["number"], meta["label"]))
        if not entries:
            print("  (empty)")
        print()
    return 0


def make_result_hook(args):
    """Voice/notify + memory callback for one-shot checks (opt-in only)."""
    if not (getattr(args, "voice", None) or getattr(args, "notify", None)):
        return None
    try:
        from .jarvis import JarvisSession
        session = JarvisSession(voice=getattr(args, "voice", None),
                                notify=getattr(args, "notify", None),
                                region=getattr(args, "region", None))
        return session.observe_result
    except Exception as exc:
        print("warning: memory/voice disabled (%s)" % exc, file=sys.stderr)
        return None


def run_case_new(args):
    from . import recovery
    from .cases import CaseStore
    try:
        case = CaseStore().create(
            args.case_new,
            scam_type=args.scam_type or recovery.infer_type(args.case_new),
            country=args.country or args.region,
            currency=args.currency or "",
            loss_amount=args.loss or 0,
            notes=args.case_notes or "",
        )
    except (OSError, ValueError) as exc:
        print("Could not open case: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(case, ensure_ascii=False, indent=2, default=str))
        return 0
    print("Opened case %s — %s" % (case["id"], case["title"]))
    print("  scam type: " + (case.get("scam_type") or "not recorded"))
    print("  country:   " + (case.get("country") or "?"))
    print("  vault:     " + CaseStore().path)
    print()
    print("Add evidence:  scamcheck --case-add %s screenshot.png" % case["id"])
    print("Export:        scamcheck --case-export %s" % case["id"])
    return 0


def run_case_list(args):
    from .cases import CaseStore
    rows = CaseStore().list(limit=args.limit or 20)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2, default=str))
        return 0
    if not rows:
        print("No cases yet. Start one with: scamcheck --case-new \"bank transfer scam\"")
        return 0
    print()
    print("Cases (%d):" % len(rows))
    for row in rows:
        print("  %-18s %-10s %4d evidence  %4d entities  %s" % (
            row.get("id"), row.get("status") or "?",
            int(row.get("evidence_count") or 0),
            int(row.get("entity_count") or 0),
            row.get("title") or "?"))
    print()
    return 0


def run_case_show(args):
    from .cases import CaseStore
    case_id = args.case_show or args.case
    case = CaseStore().get(case_id)
    if not case:
        print("No case %s" % case_id, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(case, ensure_ascii=False, indent=2, default=str))
        return 0
    print()
    print("Case %s — %s" % (case["id"], case["title"]))
    print("  status:   " + str(case.get("status") or "?"))
    print("  type:     " + (case.get("scam_type") or "not recorded"))
    print("  country:  " + (case.get("country") or "?"))
    print("  loss:     " + ("%s %.2f" % (case.get("currency") or "", float(case.get("loss_amount") or 0))).strip())
    print("  opened:   " + time.strftime("%Y-%m-%d %H:%M", time.localtime(case.get("created_ts") or 0)))
    if case.get("notes"):
        print("  notes:    " + case["notes"])
    print()
    print("Entities (%d)" % len(case.get("entities") or []))
    for item in case.get("entities") or []:
        print("  %-12s %s" % (item.get("kind"), item.get("label") or item.get("value")))
    if not case.get("entities"):
        print("  (none)")
    print()
    print("Evidence (%d)" % len(case.get("evidence") or []))
    for index, item in enumerate(case.get("evidence") or [], start=1):
        print("  #%-2d %-7s %-34s %8d bytes  %s" % (
            index, item.get("kind") or "?",
            (item.get("filename") or "inline text")[:34],
            int(item.get("size") or 0), (item.get("sha256") or "")[:16]))
    if not case.get("evidence"):
        print("  (none)")
    print()
    print("Timeline")
    for event in case.get("events") or []:
        print("  %s  %s" % (
            time.strftime("%Y-%m-%d %H:%M", time.localtime(event.get("ts") or 0)),
            event.get("description") or ""))
    print()
    return 0


def run_case_add(args):
    from .cases import CaseStore
    case_id, payload = args.case_add
    store = CaseStore()
    try:
        path = os.path.abspath(os.path.expanduser(payload.strip().strip("'\"")))
        if os.path.isfile(path):
            info = store.add_file(case_id, path)
        else:
            info = store.add_text(case_id, payload)
    except (KeyError, OSError, ValueError) as exc:
        print("Could not add evidence: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2, default=str))
        return 0
    if info.get("filename"):
        print("Added %s evidence to %s (sha256 %s…)" % (
            info.get("kind"), case_id, (info.get("sha256") or "")[:16]))
    else:
        print("Added text evidence to %s (sha256 %s…)" % (
            case_id, (info.get("sha256") or "")[:16]))
    return 0


def run_case_note(args):
    from .cases import CaseStore
    case_id, note = args.case_note
    try:
        CaseStore().add_event(case_id, note, kind="note")
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print("Note added to %s." % case_id)
    return 0


def run_case_entity(args):
    from .cases import CaseStore
    case_id, raw = args.case_entity
    try:
        item = CaseStore().add_entity(case_id, raw)
    except (KeyError, ValueError) as exc:
        print("Could not add entity: %s" % exc, file=sys.stderr)
        return 2
    print("Added %s: %s to %s." % (
        item.get("kind"), item.get("label") or item.get("value"), case_id))
    return 0


def run_case_export(args):
    from .cases import CaseStore
    case_id = args.case_export or args.case
    try:
        result = CaseStore().export(case_id, args.case_out)
    except (KeyError, OSError, ValueError) as exc:
        print("Could not export: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    print()
    print("Case %s exported:" % result["case_id"])
    print("  folder: " + result["outdir"])
    print("  JSON:   " + result["json"])
    print("  MD:     " + result["markdown"])
    print("  HTML:   " + result["html"])
    print("  hashes: " + result["hashes"])
    if result.get("pdf"):
        print("  PDF:    " + result["pdf"])
    else:
        print("  PDF:    not generated (%s)" % result.get("pdf_note"))
    print()
    return 0


def run_case_verify(args):
    from .cases import CaseStore
    case_id = args.case_verify or args.case
    try:
        report = CaseStore().verify(case_id)
    except (KeyError, OSError) as exc:
        print("Could not verify: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["ok"] else 2
    print()
    print("Case %s evidence integrity: %s" % (
        report["case_id"], "OK" if report["ok"] else "PROBLEMS"))
    for item in report["evidence"]:
        print("  #%-2s %-34s %s%s" % (
            item["id"], (item.get("filename") or "inline text")[:34],
            "ok" if item["ok"] else "FAIL",
            "" if item["ok"] else " (" + item.get("reason", "changed") + ")"))
    if not report["evidence"]:
        print("  (no evidence)")
    print()
    return 0 if report["ok"] else 2


def run_case_close(args):
    from .cases import CaseStore
    case_id = args.case_close or args.case
    try:
        case = CaseStore().set_status(case_id, "closed")
    except (KeyError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print("Case %s is now %s." % (case["id"], case["status"]))
    return 0


def run_watch_add(args):
    from .watchlist import Watchlist
    try:
        item = Watchlist().add(args.watch_add, label=args.label)
    except ValueError as exc:
        print("Could not add to watchlist: %s" % exc, file=sys.stderr)
        return 2
    print("Watching %s: %s" % (item.get("kind"), item.get("label") or item.get("value")))
    return 0


def run_watch_remove(args):
    from .watchlist import Watchlist
    try:
        removed = Watchlist().remove(args.watch_remove)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print("Removed from watchlist." if removed else "That identifier was not on the watchlist.")
    return 0 if removed else 1


def run_watch_list(args):
    from .watchlist import Watchlist, format_list
    entries = Watchlist().list()
    if args.json:
        print(json.dumps(entries, ensure_ascii=False, indent=2, default=str))
        return 0
    print()
    print(format_list(entries))
    print()
    return 0


def run_campaigns(args):
    from . import campaigns
    rows = campaigns.build_campaigns(limit=args.campaigns or 20)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2, default=str))
        return 0
    print()
    print(campaigns.format_campaigns(rows, limit=args.campaigns or 20))
    print()
    return 0


def run_campaign(args):
    from . import campaigns
    camp = campaigns.get_campaign(args.campaign)
    if not camp:
        print("No campaign %s" % args.campaign, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(camp, ensure_ascii=False, indent=2, default=str))
        return 0
    print()
    print(campaigns.format_campaign(camp))
    print()
    return 0


def run_recover(args):
    from . import recovery
    kind = args.recover or "general"
    country = args.country or args.region
    book = recovery.get_playbook(kind, country or "IN")
    if args.json:
        print(json.dumps(book, ensure_ascii=False, indent=2))
        return 0
    print()
    print(recovery.format_playbook(book))
    print()
    return 0


def run_report(args):
    from . import recovery
    from .cases import CaseStore
    case = CaseStore().get(args.report)
    if not case:
        print("No case %s" % args.report, file=sys.stderr)
        return 2
    text = recovery.complaint_template(
        case, args.country or args.region, case.get("scam_type"))
    if args.report_out:
        path = os.path.abspath(os.path.expanduser(args.report_out))
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        if args.json:
            print(json.dumps({"case_id": case["id"], "path": path},
                             ensure_ascii=False, indent=2))
        else:
            print("Complaint draft for %s written to %s" % (case["id"], path))
        return 0
    if args.json:
        print(json.dumps({"case_id": case["id"], "text": text},
                         ensure_ascii=False, indent=2))
        return 0
    print()
    print(text)
    print()
    return 0


def run_device_audit(args):
    """Read-only device + private-LAN audit with a local report export."""
    from . import deviceaudit

    if args.json:
        progress = None
    else:
        def progress(message):
            print("  … " + message, file=sys.stderr, flush=True)

    report = deviceaudit.audit(
        active_lan=bool(args.device_active),
        include_lan=not args.device_no_lan,
        include_mobile=not args.device_no_mobile,
        max_hosts=args.device_max_hosts,
        progress=progress,
    )
    exported = deviceaudit.export_report(report, args.device_out)
    if args.json:
        print(json.dumps({"report": report, "export": exported},
                         ensure_ascii=False, indent=2))
        return 0
    print()
    print(deviceaudit.format_report(report, full=args.device_full))
    print()
    print("Report folder: " + exported["folder"])
    print("  report.json · report.md · SHA256SUMS")
    if not args.device_active:
        print("Active LAN port checks were off. Use --device-active on a network you own.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="scamcheck",
        description="Check whether an SMS/text message is a scam.",
        epilog="Set OPENAI_API_KEY or ANTHROPIC_API_KEY for AI-powered second "
               "opinions on suspicious messages (optional).",
    )
    parser.add_argument("message", nargs="*", help="the message text to check")
    parser.add_argument("-f", "--file", help="read the message from a file")
    parser.add_argument("--stdin", action="store_true", help="read the message from stdin (paste, then Ctrl+D)")
    parser.add_argument("--ai", choices=["auto", "always", "never"], default="auto",
                        help="when to consult the AI second opinion (default: auto - only for borderline messages)")
    parser.add_argument("--chat", action="store_true", default=None,
                        help="treat the input as a full chat/conversation transcript (trajectory analysis)")
    parser.add_argument("--image", metavar="FILE",
                        help="check a screenshot: OCR + QR decode (macOS Vision / tesseract / AI) then analyze")
    parser.add_argument("--batch", metavar="FILE",
                        help="check many messages: file of messages separated by blank lines ('-' for stdin)")
    parser.add_argument("--watch", action="store_true", default=None,
                        help="watch the clipboard and auto-check every copied message or screenshot (Ctrl+C to stop)")
    parser.add_argument("--interval", type=float, default=None, metavar="SECONDS",
                        help="polling interval for --watch (default 2.5s)")
    parser.add_argument("--json", action="store_true", help="output machine-readable JSON")
    parser.add_argument("--intel", action="store_true",
                        help="print the full intelligence briefing (type, stage, goals, next moves, verification, evidence)")
    parser.add_argument("--version", action="version", version="scamcheck " + __version__)
    parser.add_argument("--serve", nargs="?", metavar="PORT", const="8765", default=None,
                        help="run as a local HTTP API + family web UI (default port 8765)")
    parser.add_argument("--mcp", action="store_true", default=None,
                        help="run as an MCP server on stdio (for AI agents; offline by default)")
    parser.add_argument("--host", default="127.0.0.1", metavar="ADDR",
                        help="bind address for --serve (default 127.0.0.1; use 0.0.0.0 to share on your Wi-Fi, no auth)")
    parser.add_argument("--sender", metavar="NUMBER",
                        help="sender phone number / SMS sender ID to check against your lists and cached feeds")
    parser.add_argument("--region", metavar="CODE",
                        help="default region for national numbers, e.g. IN, US, GB (default: config, else IN)")
    parser.add_argument("--number", metavar="NUMBER",
                        help="check one phone number's reputation and range flags, then exit")
    parser.add_argument("--block", metavar="NUMBER",
                        help="add a number to your local blocklist, then exit")
    parser.add_argument("--allow", metavar="NUMBER",
                        help="add a number to your local allowlist, then exit")
    parser.add_argument("--forget", metavar="NUMBER",
                        help="remove a number from both local lists, then exit")
    parser.add_argument("--label", default="", metavar="TEXT",
                        help="label to store with --block/--allow/--import-list")
    parser.add_argument("--import-list", metavar="FILE",
                        help="import a .txt/.csv number list into your blocklist, then exit")
    parser.add_argument("--import-allow", action="store_true",
                        help="with --import-list: import as trusted numbers instead")
    parser.add_argument("--update-feeds", action="store_true",
                        help="download the feeds configured in ~/.scamcheck/feeds.conf (opt-in network access)")
    parser.add_argument("--feed-status", action="store_true",
                        help="show configured feeds and the local cache, then exit")
    parser.add_argument("--show-lists", action="store_true",
                        help="show your local blocklist and allowlist, then exit")
    parser.add_argument("--set-region", metavar="CODE",
                        help="save the default region (e.g. IN, US) in ~/.scamcheck/config.json")
    parser.add_argument("--bot", choices=["telegram", "whatsapp"],
                        help="run a chat bot: telegram (long polling) or whatsapp (Cloud API webhook)")
    parser.add_argument("--bot-token", metavar="TOKEN",
                        help="Telegram bot token (or set SCAMCHECK_TELEGRAM_TOKEN)")
    parser.add_argument("--bot-host", default="127.0.0.1", metavar="ADDR",
                        help="WhatsApp webhook bind address (default 127.0.0.1; use a tunnel for Meta)")
    parser.add_argument("--bot-port", type=int, default=8766, metavar="PORT",
                        help="WhatsApp webhook port (default 8766)")
    parser.add_argument("--bot-status", action="store_true",
                        help="show bot configuration and exit (no network)")
    parser.add_argument("--jarvis", action="store_true",
                        help="start the JARVIS console: text, screenshots, QR, links, numbers, memory")
    parser.add_argument("--voice", action="store_true", default=None,
                        help="speak risky verdicts (macOS say; also usable with --watch/--jarvis)")
    parser.add_argument("--notify", action="store_true", default=None,
                        help="show macOS notifications for risky verdicts (also with --watch/--jarvis)")
    parser.add_argument("--screenshot-dir", metavar="DIR",
                        help="watch a folder for new screenshots (with --watch; implies watching)")
    parser.add_argument("--case-new", metavar="TITLE",
                        help="open a local evidence case, then exit")
    parser.add_argument("--case-list", action="store_true",
                        help="list local evidence cases, then exit")
    parser.add_argument("--case", metavar="CASE_ID",
                        help="show one evidence case, then exit")
    parser.add_argument("--case-show", metavar="CASE_ID",
                        help="show one evidence case, then exit")
    parser.add_argument("--case-add", nargs=2, metavar=("CASE_ID", "FILE_OR_TEXT"),
                        help="attach a file or text to a case, then exit")
    parser.add_argument("--case-note", nargs=2, metavar=("CASE_ID", "TEXT"),
                        help="add a timeline note to a case, then exit")
    parser.add_argument("--case-entity", nargs=2, metavar=("CASE_ID", "KIND:VALUE"),
                        help="add a suspect identifier to a case, then exit")
    parser.add_argument("--case-export", nargs="?", const="", metavar="CASE_ID",
                        help="export a case pack (JSON/MD/HTML/hashes, PDF when available)")
    parser.add_argument("--case-out", metavar="DIR",
                        help="output directory for --case-export")
    parser.add_argument("--case-verify", nargs="?", const="", metavar="CASE_ID",
                        help="verify evidence SHA-256 hashes for a case")
    parser.add_argument("--case-close", nargs="?", const="", metavar="CASE_ID",
                        help="mark a case closed")
    parser.add_argument("--case-notes", metavar="TEXT",
                        help="opening notes for --case-new")
    parser.add_argument("--scam-type", metavar="TYPE",
                        help="scam type for --case-new (upi, bank, crypto, job, ...)")
    parser.add_argument("--currency", metavar="CODE",
                        help="currency for --case-new (e.g. INR, USD)")
    parser.add_argument("--loss", type=float, default=0, metavar="AMOUNT",
                        help="recorded loss amount for --case-new")
    parser.add_argument("--limit", type=int, default=20, metavar="N",
                        help="number of rows for --case-list (default 20)")
    parser.add_argument("--watch-add", metavar="KIND:VALUE",
                        help="add an identifier to the local watchlist, then exit")
    parser.add_argument("--watch-remove", metavar="KIND:VALUE",
                        help="remove an identifier from the local watchlist, then exit")
    parser.add_argument("--watchlist", action="store_true",
                        help="show the local watchlist, then exit")
    parser.add_argument("--campaigns", nargs="?", const=20, type=int, metavar="N",
                        help="cluster related checks into campaigns, then exit")
    parser.add_argument("--campaign", metavar="CAM_ID",
                        help="show one campaign (e.g. CAM-00042), then exit")
    parser.add_argument("--recover", nargs="?", const="general", metavar="TYPE",
                        help="show a country-aware recovery playbook, then exit")
    parser.add_argument("--report", metavar="CASE_ID",
                        help="draft a complaint from a case, then exit")
    parser.add_argument("--country", metavar="CODE",
                        help="country code for recovery/report (IN, US, GB, ...)")
    parser.add_argument("--report-out", metavar="FILE",
                        help="write the --report complaint draft to a file")
    parser.add_argument("--device-audit", action="store_true",
                        help="read-only audit of this device + private LAN: posture, processes, "
                             "persistence, browsers, network, files, mobile, LAN inventory")
    parser.add_argument("--device-full", action="store_true",
                        help="with --device-audit: print every section, not just top findings")
    parser.add_argument("--device-active", action="store_true",
                        help="with --device-audit: also TCP-probe common ports on private-LAN "
                             "devices you own (no exploitation, no public IPs)")
    parser.add_argument("--device-no-lan", action="store_true",
                        help="with --device-audit: skip the LAN inventory")
    parser.add_argument("--device-no-mobile", action="store_true",
                        help="with --device-audit: skip connected Android/iOS checks")
    parser.add_argument("--device-max-hosts", type=int, default=64, metavar="N",
                        help="with --device-audit: cap LAN hosts at N (default 64)")
    parser.add_argument("--device-out", metavar="DIR",
                        help="with --device-audit: export the report to DIR "
                             "(default ~/.scamcheck/device-reports/<timestamp>)")
    args = parser.parse_args(argv)

    if args.device_audit:
        return run_device_audit(args)

    if args.bot_status:
        from . import bot as bot_mod
        status = bot_mod.bot_status()
        if args.json:
            print(json.dumps(status, ensure_ascii=False, indent=2))
        else:
            print("Telegram token:  " + (status["telegram_token"] or "not set"))
            print("WhatsApp token:  " + ("set" if status["whatsapp_token"] else "not set"))
            print("WhatsApp phone:  " + (status["whatsapp_phone_id"] or "not set"))
            print("Webhook verify:  " + ("set" if status["whatsapp_verify_token_set"] else "not set"))
            print("Region:          " + status["region"])
            print("Rate limit:      %d checks/hour/chat" % status["rate_limit_per_hour"])
            print("Prefs:           " + status["prefs"])
        return 0

    if args.bot == "telegram":
        from . import bot as bot_mod
        return bot_mod.run_telegram(token=args.bot_token)

    if args.bot == "whatsapp":
        from . import bot as bot_mod
        return bot_mod.run_whatsapp(host=args.bot_host, port=args.bot_port)

    if args.jarvis:
        from .jarvis import JarvisSession, run_repl
        session = JarvisSession(voice=args.voice, notify=args.notify,
                                region=args.region)
        initial = " ".join(args.message) if args.message else None
        return run_repl(session, initial=initial)

    if args.case_new:
        return run_case_new(args)
    if args.case_list:
        return run_case_list(args)
    if args.case_add:
        return run_case_add(args)
    if args.case_note:
        return run_case_note(args)
    if args.case_entity:
        return run_case_entity(args)
    if args.watch_add:
        return run_watch_add(args)
    if args.watch_remove:
        return run_watch_remove(args)
    if args.watchlist:
        return run_watch_list(args)
    if args.campaigns is not None:
        return run_campaigns(args)
    if args.campaign:
        return run_campaign(args)
    if args.recover is not None:
        return run_recover(args)
    if args.report:
        return run_report(args)
    if args.case_export is not None:
        if not (args.case_export or args.case):
            parser.error("--case-export needs a CASE_ID (or --case CASE_ID)")
        return run_case_export(args)
    if args.case_verify is not None:
        if not (args.case_verify or args.case):
            parser.error("--case-verify needs a CASE_ID (or --case CASE_ID)")
        return run_case_verify(args)
    if args.case_close is not None:
        if not (args.case_close or args.case):
            parser.error("--case-close needs a CASE_ID (or --case CASE_ID)")
        return run_case_close(args)
    if args.case_show or args.case:
        return run_case_show(args)

    if args.set_region:
        code = args.set_region.upper()
        if code not in phones.REGIONS:
            parser.error("unknown region %s (examples: %s)" % (
                code, ", ".join(sorted(set(phones.REGIONS))[:12])))
        cfg = phones.load_config()
        cfg["region"] = code
        phones.save_config(cfg)
        print("Default region set to %s (%s)." % (code, phones.REGIONS[code]))
        return 0

    if args.update_feeds:
        return run_feed_update(args)

    if args.feed_status:
        return run_feed_status(args)

    if args.show_lists:
        return run_lists(args)

    if args.block or args.allow or args.forget:
        try:
            if args.block:
                info = phones.add_block(args.block, args.label)
                action = "Blocked"
            elif args.allow:
                info = phones.add_allow(args.allow, args.label)
                action = "Allowed"
            else:
                removed = phones.forget_number(args.forget)
                print("Removed %s from %d local list%s." % (
                    args.forget, removed, "" if removed == 1 else "s"))
                return 0
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print("%s %s locally." % (action, info["e164"] or info["national"]))
        return 0

    if args.import_list:
        target = "allow" if args.import_allow else "block"
        try:
            report = phones.import_list(args.import_list, target=target,
                                        label=args.label, region=args.region)
        except (OSError, ValueError) as exc:
            print("Cannot import %s: %s" % (args.import_list, exc), file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print("Imported %d number%s into the %slist (%d skipped, %d rows)." % (
                report["imported"], "" if report["imported"] == 1 else "s",
                "allow" if target == "allow" else "block",
                report["skipped"], report["total"]))
        return 0

    if args.number:
        return run_number(args.number, args)

    if args.mcp:
        from .mcp import serve as serve_mcp
        return serve_mcp()

    if args.serve is not None:
        serve(host=args.host, port=int(args.serve))
        return 0

    if args.watch or args.screenshot_dir:
        return run_watch(args, interval=args.interval or 2.5)

    hook = make_result_hook(args)

    if args.image:
        return run_image(args.image, args, on_result=hook)

    if args.batch:
        return run_batch(args.batch, args)

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    elif args.stdin:
        text = sys.stdin.read()
    elif args.message:
        text = " ".join(args.message)
    else:
        parser.error("provide a message, use -f FILE, or pass --stdin")

    text = text.strip()
    if not text:
        parser.error("message is empty")
        return 2

    return run_text(text, args, on_result=hook)


if __name__ == "__main__":
    sys.exit(main())
