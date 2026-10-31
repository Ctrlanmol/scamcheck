"""JSON bridge between the Next.js interface and scamcheck's Python core.

The web app never re-implements detection logic. Each request is one JSON
object on stdin and each response is one JSON object on stdout:

    {"tool": "analyze", "args": {"text": "..."}}
    {"ok": true, "data": {...}}

Long-running tools (device audit, feed update) emit progress lines on stderr
prefixed with ``@@progress `` so the web server can stream them.

This module is stdlib-only, local-only and never opens a network listener.
"""

import base64
import json
import os
import sys
import tempfile
import time


def _progress(message):
    try:
        sys.stderr.write("@@progress " + str(message) + "\n")
        sys.stderr.flush()
    except OSError:
        pass


def _temp_image(args):
    raw = args.get("image_b64") or ""
    if not raw:
        raise ValueError("image_b64 is required")
    try:
        data = base64.b64decode(raw, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid image data: %s" % exc)
    if len(data) > 20 * 1024 * 1024:
        raise ValueError("image is larger than 20 MB")
    suffix = os.path.splitext(args.get("filename") or "")[1].lower()
    if suffix not in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".tiff", ".bmp"):
        suffix = ".png"
    fd, path = tempfile.mkstemp(prefix="scamcheck-web-", suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


def _remember(result, kind="text"):
    """Record a check in local memory and attach watchlist hits."""
    from .jarvis import History, text_identifiers
    from .watchlist import Watchlist

    text = result.get("message") or ""
    identifiers = text_identifiers(text, result)
    try:
        seen = History().seen_before(identifiers)
        History().record(
            kind,
            result.get("final_verdict") or "?",
            int(result.get("score") or 0),
            text=text,
            sender=result.get("sender_input"),
            identifiers=identifiers,
            meta={"scripts": result.get("scripts") or [],
                  "source": result.get("source_name") or ""},
        )
    except Exception:
        seen = []
    hits = []
    try:
        store = Watchlist()
        hits = store.match(identifiers)
        if hits:
            store.bump(hits)
    except Exception:
        hits = []
    return {"result": result, "seen": seen, "watchlist": hits}


def tool_analyze(args):
    from .analyzer import analyze

    text = str(args.get("text") or "").strip()
    if not text:
        raise ValueError("text is required")
    ai = args.get("ai") or "auto"
    if ai not in ("auto", "always", "never"):
        ai = "auto"
    result = analyze(
        text,
        use_ai=ai,
        is_conversation=bool(args.get("chat")),
        sender=args.get("sender") or None,
        region=args.get("region") or None,
    )
    result["message"] = text
    result["kind"] = "text"
    return _remember(result, "text")


def tool_analyze_image(args):
    from .analyzer import analyze
    from .ocr import detect_qr, ocr_image, qr_text

    path = _temp_image(args)
    try:
        text, engine = ocr_image(path)
        qr = detect_qr(path)
        codes = qr.get("codes") or []
        payload = qr_text(codes)
        analysis = (text or "").strip()
        if payload:
            analysis = (analysis + "\n" + payload).strip()
        if not analysis:
            detail = qr.get("error") if not qr.get("available") else "no QR/barcode found"
            raise ValueError("no readable text or QR code (%s OCR; %s)" %
                             (engine or "no", detail or "no decoder"))
        ai = args.get("ai") or "auto"
        if ai not in ("auto", "always", "never"):
            ai = "auto"
        result = analyze(analysis, use_ai=ai, ocr=True,
                         sender=args.get("sender") or None,
                         region=args.get("region") or None)
        result["message"] = analysis
        result["kind"] = "image"
        result["qr"] = codes
        result["ocr_engine"] = engine
        result["extracted_text"] = text or ""
        result["source_name"] = args.get("filename") or os.path.basename(path)
        data = _remember(result, "image")
        data["qr_available"] = bool(qr.get("available"))
        return data
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def tool_decode_image(args):
    from .ocr import detect_qr

    path = _temp_image(args)
    try:
        qr = detect_qr(path)
        return {"available": bool(qr.get("available")),
                "codes": qr.get("codes") or [],
                "error": qr.get("error")}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def tool_check_number(args):
    from . import phones
    from .jarvis import History
    from .watchlist import Watchlist

    number = str(args.get("number") or "").strip()
    if not number:
        raise ValueError("number is required")
    intel = phones.check_number(number, region=args.get("region") or None)
    info = intel.get("number") or {}
    label = info.get("e164") or info.get("national") or number
    identifiers = [{"kind": "phone", "value": label, "label": label}]
    try:
        seen = History().seen_before(identifiers)
        History().record("number",
                         "SCAM" if intel.get("risk") == "high" else
                         "SUSPICIOUS" if intel.get("risk") == "medium" else "LIKELY SAFE",
                         {"high": 70, "medium": 40}.get(intel.get("risk"), 5),
                         text=number, identifiers=identifiers)
    except Exception:
        seen = []
    hits = []
    try:
        store = Watchlist()
        hits = store.match(identifiers)
        if hits:
            store.bump(hits)
    except Exception:
        hits = []
    return {"intel": intel, "seen": seen, "watchlist": hits}


def tool_lists(args):
    from . import phones
    return phones.list_numbers()


def tool_list_add(args):
    from . import phones

    action = args.get("action") or "block"
    number = str(args.get("number") or "").strip()
    label = str(args.get("label") or "").strip()
    if not number:
        raise ValueError("number is required")
    if action == "forget":
        return {"removed": phones.forget_number(number)}
    if action == "allow":
        return {"entry": phones.add_allow(number, label)}
    if action == "block":
        return {"entry": phones.add_block(number, label)}
    raise ValueError("unknown action: " + action)


def tool_import_list(args):
    from . import phones

    blob = str(args.get("text") or "")
    target = args.get("target") or "block"
    if not blob.strip():
        raise ValueError("text is required")
    fd, path = tempfile.mkstemp(prefix="scamcheck-import-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(blob)
        return phones.import_list(path, target=target,
                                  label=args.get("label") or "",
                                  region=args.get("region") or None)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def tool_feeds_status(args):
    from . import phones
    return phones.feed_status()


def tool_feeds_update(args):
    from . import phones
    return phones.update_feeds(region=args.get("region") or None,
                               progress=_progress)


def tool_cases_list(args):
    from .cases import CaseStore
    return CaseStore().list(limit=int(args.get("limit") or 50),
                            status=args.get("status") or None)


def tool_case_create(args):
    from . import recovery
    from .cases import CaseStore

    title = str(args.get("title") or "").strip()
    if not title:
        raise ValueError("title is required")
    return CaseStore().create(
        title,
        scam_type=args.get("scam_type") or recovery.infer_type(title),
        country=args.get("country") or None,
        currency=args.get("currency") or "",
        loss_amount=float(args.get("loss") or 0),
        notes=args.get("notes") or "",
    )


def tool_case_get(args):
    from .cases import CaseStore

    case_id = str(args.get("case_id") or "").strip()
    case = CaseStore().get(case_id)
    if not case:
        raise KeyError("No case %s" % case_id)
    return case


def tool_case_add(args):
    from .cases import CaseStore

    case_id = str(args.get("case_id") or "").strip()
    store = CaseStore()
    if args.get("file_b64"):
        path = _temp_image({"image_b64": args["file_b64"],
                            "filename": args.get("filename")})
        try:
            return store.add_file(case_id, path,
                                  source=args.get("source") or "web",
                                  note=args.get("note") or "",
                                  ocr=bool(args.get("ocr", True)))
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
    text = str(args.get("text") or "").strip()
    if not text:
        raise ValueError("text or file_b64 is required")
    return store.add_text(case_id, text, source=args.get("source") or "web")


def tool_case_note(args):
    from .cases import CaseStore

    case_id = str(args.get("case_id") or "").strip()
    note = str(args.get("note") or "").strip()
    if not note:
        raise ValueError("note is required")
    CaseStore().add_event(case_id, note, kind="note")
    return CaseStore().get(case_id)


def tool_case_entity(args):
    from .cases import CaseStore

    case_id = str(args.get("case_id") or "").strip()
    entity = str(args.get("entity") or "").strip()
    if not entity:
        raise ValueError("entity is required (KIND:VALUE)")
    return CaseStore().add_entity(case_id, entity)


def tool_case_export(args):
    from .cases import CaseStore
    return CaseStore().export(str(args.get("case_id") or "").strip(),
                              args.get("outdir") or None)


def tool_case_verify(args):
    from .cases import CaseStore
    return CaseStore().verify(str(args.get("case_id") or "").strip())


def tool_case_close(args):
    from .cases import CaseStore
    return CaseStore().set_status(str(args.get("case_id") or "").strip(), "closed")


def tool_case_report(args):
    from . import recovery
    from .cases import CaseStore

    case = CaseStore().get(str(args.get("case_id") or "").strip())
    if not case:
        raise KeyError("No such case")
    text = recovery.complaint_template(
        case, args.get("country") or None, case.get("scam_type"))
    return {"case_id": case["id"], "text": text}


def tool_watchlist_list(args):
    from .watchlist import Watchlist
    return Watchlist().list()


def tool_watchlist_add(args):
    from .watchlist import Watchlist
    entity = str(args.get("entity") or "").strip()
    if not entity:
        raise ValueError("entity is required (KIND:VALUE)")
    return Watchlist().add(entity, label=args.get("label") or "",
                           notes=args.get("notes") or "")


def tool_watchlist_remove(args):
    from .watchlist import Watchlist
    return {"removed": Watchlist().remove(str(args.get("entity") or "").strip())}


def tool_watchlist_clear(args):
    from .watchlist import Watchlist
    return {"removed": Watchlist().clear()}


def tool_campaigns(args):
    from . import campaigns
    return campaigns.build_campaigns(limit=int(args.get("limit") or 30))


def tool_campaign_get(args):
    from . import campaigns
    camp = campaigns.get_campaign(str(args.get("campaign_id") or "").strip())
    if not camp:
        raise KeyError("No such campaign")
    return camp


def tool_recover(args):
    from . import recovery
    return recovery.get_playbook(args.get("scam_type") or "general",
                                 args.get("country") or "IN")


def tool_url(args):
    from . import netintel
    from .jarvis import History, link_notes, link_risk, url_identifiers
    from .watchlist import Watchlist

    target = str(args.get("url") or "").strip()
    if not target:
        raise ValueError("url is required")
    report = netintel.investigate_url(target, allow_private=False)
    if not report.get("ok"):
        raise ValueError(report.get("error") or "could not investigate URL")
    verdict, score = link_risk(report)
    identifiers = url_identifiers(report, target)
    try:
        History().record("url", verdict, score, text=target,
                         identifiers=identifiers)
    except Exception:
        pass
    hits = []
    try:
        store = Watchlist()
        hits = store.match(identifiers)
        if hits:
            store.bump(hits)
    except Exception:
        hits = []
    return {"report": report, "verdict": verdict, "score": score,
            "notes": link_notes(report), "watchlist": hits}


def tool_history(args):
    from .jarvis import History

    action = args.get("action") or "recent"
    history = History()
    if action == "clear":
        return {"cleared": history.clear()}
    if action == "search":
        return history.search(str(args.get("term") or ""),
                              limit=int(args.get("limit") or 20))
    return history.recent(limit=int(args.get("limit") or 30))


def tool_jarvis(args):
    from .jarvis import JarvisSession

    message = str(args.get("message") or "").strip()
    if not message:
        raise ValueError("message is required")
    session = JarvisSession(voice=False, notify=False, persist=False,
                            region=args.get("region") or None,
                            lang=args.get("lang") or None)
    reply = session.handle(message)
    return {"text": reply.get("text"), "quit": bool(reply.get("quit")),
            "result": reply.get("result"), "intel": reply.get("intel"),
            "report": reply.get("report")}


def tool_batch(args):
    from .analyzer import analyze
    from .cli import split_batch

    blob = str(args.get("text") or "")
    blocks = split_batch(blob)
    if not blocks:
        raise ValueError("no messages found (separate them with a blank line)")
    if len(blocks) > 50:
        raise ValueError("batch is capped at 50 messages per request")
    rows = []
    for index, block in enumerate(blocks, start=1):
        from . import phones
        sender, body = phones.split_sender(block)
        result = analyze(body, use_ai=args.get("ai") or "auto",
                         is_conversation=bool(args.get("chat")),
                         sender=sender or None,
                         region=args.get("region") or None)
        result["message"] = body
        result["index"] = index
        if sender:
            result["sender_input"] = sender
        rows.append(result)
    return {"messages": rows, "count": len(rows)}


def tool_status(args):
    from . import __version__, bot, phones
    from .cases import CaseStore
    from .jarvis import History
    from .watchlist import Watchlist

    try:
        history_count = History().count()
    except Exception:
        history_count = 0
    try:
        case_count = CaseStore().count()
    except Exception:
        case_count = 0
    try:
        watch_count = Watchlist().count()
    except Exception:
        watch_count = 0
    return {
        "version": __version__,
        "platform": sys.platform,
        "data_dir": phones.data_dir(),
        "region": phones.default_region(),
        "history": history_count,
        "cases": case_count,
        "watchlist": watch_count,
        "feeds": phones.feed_status(),
        "bot": bot.bot_status(),
        "ai": bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")),
        "device_audit": {"supported": sys.platform == "darwin",
                         "active_lan": sys.platform == "darwin"},
    }


def tool_set_region(args):
    from . import phones

    code = str(args.get("region") or "").upper()
    if code not in phones.REGIONS:
        raise ValueError("unknown region: " + code)
    cfg = phones.load_config()
    cfg["region"] = code
    phones.save_config(cfg)
    return {"region": code, "label": phones.REGIONS[code]}


def tool_regions(args):
    from . import phones

    return {
        "current": phones.default_region(),
        "regions": [
            {
                "code": code,
                "dial": dial,
                "label": (phones.COUNTRIES.get(dial) or (code, code))[1],
            }
            for code, dial in sorted(phones.REGIONS.items())
        ],
    }


def tool_bot_status(args):
    from . import bot
    return bot.bot_status()


def tool_device_audit(args):
    from . import deviceaudit

    report = deviceaudit.audit(
        active_lan=bool(args.get("active_lan")),
        include_lan=bool(args.get("include_lan", True)),
        include_mobile=bool(args.get("include_mobile", True)),
        max_hosts=int(args.get("max_hosts") or 64),
        progress=_progress,
    )
    exported = deviceaudit.export_report(report, args.get("out_dir") or None)
    return {"report": report, "export": exported}


TOOLS = {
    "analyze": tool_analyze,
    "analyze_image": tool_analyze_image,
    "decode_image": tool_decode_image,
    "check_number": tool_check_number,
    "lists": tool_lists,
    "list_add": tool_list_add,
    "import_list": tool_import_list,
    "feeds_status": tool_feeds_status,
    "feeds_update": tool_feeds_update,
    "cases_list": tool_cases_list,
    "case_create": tool_case_create,
    "case_get": tool_case_get,
    "case_add": tool_case_add,
    "case_note": tool_case_note,
    "case_entity": tool_case_entity,
    "case_export": tool_case_export,
    "case_verify": tool_case_verify,
    "case_close": tool_case_close,
    "case_report": tool_case_report,
    "watchlist_list": tool_watchlist_list,
    "watchlist_add": tool_watchlist_add,
    "watchlist_remove": tool_watchlist_remove,
    "watchlist_clear": tool_watchlist_clear,
    "campaigns": tool_campaigns,
    "campaign_get": tool_campaign_get,
    "recover": tool_recover,
    "url": tool_url,
    "history": tool_history,
    "jarvis": tool_jarvis,
    "batch": tool_batch,
    "status": tool_status,
    "set_region": tool_set_region,
    "regions": tool_regions,
    "bot_status": tool_bot_status,
    "device_audit": tool_device_audit,
}


def main():
    started = time.time()
    try:
        request = json.loads(sys.stdin.read() or "{}")
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": "invalid JSON request: %s" % exc}))
        return 2
    tool = request.get("tool")
    args = request.get("args") or {}
    handler = TOOLS.get(tool)
    if not handler:
        print(json.dumps({"ok": False, "error": "unknown tool: %s" % tool}))
        return 2
    try:
        data = handler(args)
    except (KeyError, ValueError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc),
                          "type": exc.__class__.__name__}, ensure_ascii=False))
        return 1
    except Exception as exc:  # keep the interface alive; log the detail
        import traceback
        traceback.print_exc(file=sys.stderr)
        print(json.dumps({"ok": False, "error": str(exc),
                          "type": exc.__class__.__name__}, ensure_ascii=False))
        return 1
    payload = {"ok": True, "data": data, "elapsed_ms": int((time.time() - started) * 1000)}
    print(json.dumps(payload, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
