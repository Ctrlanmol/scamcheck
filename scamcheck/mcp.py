"""MCP server: expose scamcheck as tools for AI agents.

Run it as a stdio MCP server:

    python3 -m scamcheck --mcp

or point any MCP client at it:

    {"command": "scamcheck", "args": ["--mcp"]}

Transport is newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP stdio
transport). stdout carries protocol frames only; every diagnostic goes to
stderr so a client can never choke on a stray print().

Design rules, same as the rest of the package:

- stdlib only, Python 3.9+
- analysis is offline: ``check_message``, ``check_number``,
  ``extract_entities`` and ``open_case`` never touch the network
- ``check_url`` is the single networked tool and says so in its description
- results are returned twice: a short human-readable ``text`` block for the
  model, and the full ``structuredContent`` for the client

The server is read-mostly on purpose. ``open_case`` is the only tool that
writes, and it writes where the CLI writes (``~/.scamcheck``), so an agent
cannot invent a second storage location.
"""

import json
import sys
import traceback

from . import __version__, intel, phones
from .analyzer import analyze

SERVER_NAME = "scamcheck"

# Newest first. The client's requested version is echoed when we support it.
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL = SUPPORTED_PROTOCOLS[0]

MAX_TEXT = 200_000  # characters; a chat export, not a corpus

TOOLS = [
    {
        "name": "check_message",
        "title": "Check a message for scam signals",
        "description": (
            "Analyze an SMS, chat message, email body or full conversation "
            "transcript for scam signals. Runs fully offline and returns an "
            "explainable verdict (LIKELY SAFE / SUSPICIOUS / LIKELY SCAM / "
            "SCAM) with a 0-100 score, the exact matched signals, the matched "
            "scam playbook, and a deterministic intelligence briefing (scam "
            "type, kill-chain stage, attacker goals, payment rail, likely next "
            "moves, verification steps). Use this before advising a user to "
            "act on any unsolicited message."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The message or transcript to analyze.",
                },
                "sender": {
                    "type": "string",
                    "description": (
                        "Optional originating phone number or SMS sender ID "
                        "(e.g. '+919876543210' or 'VM-HDFCBK'). Reputation is "
                        "read from local lists and cached feeds only."
                    ),
                },
                "region": {
                    "type": "string",
                    "description": "Default region for national numbers, e.g. IN, US, GB.",
                },
                "conversation": {
                    "type": "boolean",
                    "description": (
                        "Treat the text as a multi-turn transcript and score "
                        "the kill-chain trajectory. Auto-detected for "
                        "multi-line input when omitted."
                    ),
                },
                "ai": {
                    "type": "string",
                    "enum": ["never", "auto", "always"],
                    "default": "never",
                    "description": (
                        "Consult the optional LLM second opinion. Defaults to "
                        "'never' so the tool stays offline and deterministic."
                    ),
                },
            },
            "required": ["text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "check_url",
        "title": "Investigate a link (network)",
        "description": (
            "Fetch public HTTP(S) metadata for one link: redirect chain, final "
            "URL and page title, TLS issuer/version, RDAP domain age, and flags "
            "for plain HTTP, raw IP hosts, punycode lookalikes and shorteners. "
            "This is the ONLY scamcheck tool that touches the network. Private, "
            "loopback and link-local targets are refused. It reads metadata; it "
            "is not a sandbox and does not execute page content."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Public http(s) URL."},
                "rdap": {
                    "type": "boolean",
                    "default": True,
                    "description": "Look up domain registration data (RDAP).",
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "check_number",
        "title": "Check a phone number",
        "description": (
            "Parse and classify a phone number or SMS sender ID offline: "
            "validity, E.164 form, country, line type, premium-rate ranges, "
            "country mismatch, and local blocklist/allowlist reputation. No "
            "network access."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "number": {"type": "string", "description": "Number or sender ID."},
                "region": {"type": "string", "description": "Region for national numbers, e.g. IN."},
            },
            "required": ["number"],
            "additionalProperties": False,
        },
    },
    {
        "name": "extract_entities",
        "title": "Extract indicators from text",
        "description": (
            "Extract stable, deduplicated indicators from a scam message or "
            "case: URLs/domains, phone numbers, sender IDs, emails, UPI IDs, "
            "BTC/ETH/TRX wallets, IFSC codes, Telegram handles, WhatsApp "
            "invites and APK links. Offline; useful for building blocklists or "
            "a case file."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Message or case text."},
            },
            "required": ["text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "open_case",
        "title": "Open an evidence case",
        "description": (
            "Open a local evidence case and optionally attach the analysed "
            "text. Evidence is SHA-256 hashed at collection time and stored "
            "under ~/.scamcheck (mode 0700). Use this when a user wants to "
            "report a scam or preserve proof; the case can later be exported "
            "with the CLI (--case-export) or turned into a complaint draft "
            "(--report)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Short case title."},
                "scam_type": {
                    "type": "string",
                    "description": "e.g. upi, bank, crypto, job, romance, sextortion.",
                },
                "currency": {"type": "string", "description": "e.g. INR, USD."},
                "loss_amount": {"type": "number", "description": "Reported loss, if any."},
                "notes": {"type": "string", "description": "Opening notes."},
                "evidence_text": {
                    "type": "string",
                    "description": "Message text to attach as hashed evidence.",
                },
            },
            "required": ["title"],
            "additionalProperties": False,
        },
    },
    {
        "name": "scamcheck_info",
        "title": "Server capabilities",
        "description": (
            "Return the scamcheck version, whether analysis is offline, where "
            "local data lives, and which capabilities this build has."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


# ---------------------------------------------------------------------------
# Result shaping
# ---------------------------------------------------------------------------


def _text_result(payload, summary):
    return {
        "content": [{"type": "text", "text": summary}],
        "structuredContent": payload,
        "isError": False,
    }


def _error_result(message, **extra):
    payload = {"error": message}
    payload.update(extra)
    return {
        "content": [{"type": "text", "text": "scamcheck error: " + message}],
        "structuredContent": payload,
        "isError": True,
    }


def _clean(obj):
    """Make a result JSON-safe without losing structure."""
    if isinstance(obj, dict):
        return {str(k): _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _message_summary(result):
    intel_info = result.get("intelligence") or {}
    verdict = result.get("final_verdict") or result.get("verdict") or "UNKNOWN"
    score = result.get("score", 0)
    lines = ["%s (%d/100)" % (verdict, score)]

    scripts = result.get("scripts") or []
    if scripts:
        lines.append("Playbook: " + ", ".join(scripts))

    stage = (intel_info.get("stage") or {}).get("label")
    scam_type = intel_info.get("title") or intel_info.get("scam_type")
    if scam_type or stage:
        lines.append(
            "Type: %s%s" % (scam_type or "unknown", " | stage: " + stage if stage else "")
        )

    reasons = result.get("reasons") or []
    if reasons:
        lines.append("Signals:")
        for label, weight in reasons[:8]:
            lines.append("  - %s (+%s)" % (label, weight))

    next_moves = intel_info.get("next_moves") or []
    if next_moves:
        lines.append("Likely next move: " + next_moves[0])

    verify = intel_info.get("verify") or []
    if verify:
        lines.append("Verify: " + verify[0])

    policy = intel_info.get("reply_policy")
    if policy:
        lines.append("Reply policy: " + str(policy))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def _tool_check_message(args):
    text = args.get("text")
    if not isinstance(text, str) or not text.strip():
        return _error_result("'text' is required and must be a non-empty string")
    if len(text) > MAX_TEXT:
        return _error_result("'text' is too long (limit %d characters)" % MAX_TEXT)

    ai = args.get("ai", "never")
    if ai not in ("never", "auto", "always"):
        return _error_result("'ai' must be one of: never, auto, always")

    conversation = args.get("conversation")
    if conversation is not None and not isinstance(conversation, bool):
        return _error_result("'conversation' must be a boolean")

    result = analyze(
        text,
        use_ai=ai,
        is_conversation=conversation,
        sender=args.get("sender") or None,
        region=args.get("region") or None,
    )
    return _text_result(_clean(result), _message_summary(result))


def _tool_check_url(args):
    from .netintel import investigate_url

    url = args.get("url")
    if not isinstance(url, str) or not url.strip():
        return _error_result("'url' is required and must be a non-empty string")

    rdap = args.get("rdap", True)
    if not isinstance(rdap, bool):
        return _error_result("'rdap' must be a boolean")

    info = investigate_url(url.strip(), want_rdap=rdap)
    if not info.get("ok"):
        return _error_result(
            info.get("error") or "could not investigate that URL", url=url
        )

    notes = info.get("notes") or []
    chain = info.get("chain") or []
    summary = ["URL: %s" % info.get("final_url", url)]
    if info.get("title"):
        summary.append("Title: " + str(info["title"]))
    summary.append("Redirects: %d" % max(0, len(chain) - 1))
    if notes:
        summary.append("Flags:")
        summary.extend("  - " + str(n) for n in notes)
    else:
        summary.append("Flags: none from public metadata (this is not a safety verdict)")
    return _text_result(_clean(info), "\n".join(summary))


def _tool_check_number(args):
    raw = args.get("number")
    if not isinstance(raw, str) or not raw.strip():
        return _error_result("'number' is required and must be a non-empty string")
    if len(raw) > 60:
        return _error_result("'number' is too long")

    info = phones.check_number(raw.strip(), region=args.get("region"))
    number = info.get("number") or {}
    if not number.get("valid"):
        return _error_result(
            number.get("note") or "not a valid phone number", number=number
        )

    flags = info.get("flags") or []
    summary = ["%s (%s)" % (number.get("e164") or raw, number.get("country") or "?")]
    if number.get("kind"):
        summary.append("Line type: " + str(number["kind"]))
    summary.append("Risk: " + str(info.get("risk") or "unknown"))
    if flags:
        summary.append("Flags:")
        summary.extend("  - " + str(f) for f in flags)
    return _text_result(_clean(info), "\n".join(summary))


def _tool_extract_entities(args):
    text = args.get("text")
    if not isinstance(text, str) or not text.strip():
        return _error_result("'text' is required and must be a non-empty string")
    if len(text) > MAX_TEXT:
        return _error_result("'text' is too long (limit %d characters)" % MAX_TEXT)

    entities = intel.extract_entities(text)
    payload = {"count": len(entities), "entities": entities}
    if entities:
        lines = ["%d indicators:" % len(entities)]
        lines.extend("  - %s: %s" % (e.get("kind"), e.get("value")) for e in entities)
    else:
        lines = ["No indicators found."]
    return _text_result(_clean(payload), "\n".join(lines))


def _tool_open_case(args):
    from .cases import CaseStore

    title = args.get("title")
    if not isinstance(title, str) or not title.strip():
        return _error_result("'title' is required and must be a non-empty string")

    loss = args.get("loss_amount", 0) or 0
    try:
        loss = float(loss)
    except (TypeError, ValueError):
        return _error_result("'loss_amount' must be a number")

    store = CaseStore()
    case = store.create(
        title.strip(),
        scam_type=args.get("scam_type") or "",
        currency=args.get("currency") or "",
        loss_amount=loss,
        notes=args.get("notes") or "",
    )

    evidence_text = args.get("evidence_text")
    if isinstance(evidence_text, str) and evidence_text.strip():
        store.add_text(case["id"], evidence_text, kind="text", source="mcp")
        case = store.get(case["id"])

    summary = [
        "Case %s opened: %s" % (case["id"], case["title"]),
        "Evidence items: %d" % len(case.get("evidence") or []),
        "Entities: %d" % len(case.get("entities") or []),
        "Next: scamcheck --case-export %s  (or --report %s for a complaint draft)"
        % (case["id"], case["id"]),
    ]
    return _text_result(_clean(case), "\n".join(summary))


def _tool_info(_args):
    payload = {
        "name": SERVER_NAME,
        "version": __version__,
        "offline_by_default": True,
        "network_tools": ["check_url"],
        "data_dir": phones.data_dir(),
        "protocols": list(SUPPORTED_PROTOCOLS),
        "python": sys.version.split()[0],
        "capabilities": {
            "message_analysis": True,
            "conversation_trajectory": True,
            "playbook_fingerprinting": True,
            "intelligence_briefing": True,
            "entity_extraction": True,
            "url_metadata": True,
            "phone_reputation_local": True,
            "evidence_cases": True,
            "ocr": "via CLI (--image), not exposed over MCP",
        },
    }
    summary = (
        "scamcheck %s — offline-first scam triage and evidence kit. "
        "Only check_url uses the network. Data lives in %s."
        % (__version__, payload["data_dir"])
    )
    return _text_result(payload, summary)


HANDLERS = {
    "check_message": _tool_check_message,
    "check_url": _tool_check_url,
    "check_number": _tool_check_number,
    "extract_entities": _tool_extract_entities,
    "open_case": _tool_open_case,
    "scamcheck_info": _tool_info,
}


# ---------------------------------------------------------------------------
# JSON-RPC plumbing
# ---------------------------------------------------------------------------


class RpcError(Exception):
    def __init__(self, code, message, data=None):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.data = data


def _ok(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id, code, message, data=None):
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": msg_id, "error": error}


def handle(message):
    """Dispatch one JSON-RPC message. Returns a response dict or None."""
    if not isinstance(message, dict):
        return _err(None, -32600, "invalid request")

    method = message.get("method")
    msg_id = message.get("id")
    params = message.get("params") or {}

    if not isinstance(method, str):
        # A response from the client, not a request. Ignore.
        return None

    is_notification = "id" not in message

    if method == "initialize":
        requested = params.get("protocolVersion") if isinstance(params, dict) else None
        version = requested if requested in SUPPORTED_PROTOCOLS else DEFAULT_PROTOCOL
        result = {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": __version__},
            "instructions": (
                "Offline-first scam triage. Call check_message before advising a "
                "user on an unsolicited message; only check_url uses the network."
            ),
        }
        return None if is_notification else _ok(msg_id, result)

    if method in ("notifications/initialized", "initialized"):
        return None

    if method == "ping":
        return None if is_notification else _ok(msg_id, {})

    if method == "tools/list":
        return None if is_notification else _ok(msg_id, {"tools": TOOLS})

    if method == "resources/list":
        return None if is_notification else _ok(msg_id, {"resources": []})

    if method == "prompts/list":
        return None if is_notification else _ok(msg_id, {"prompts": []})

    if method == "logging/setLevel":
        return None if is_notification else _ok(msg_id, {})

    if method == "tools/call":
        if not isinstance(params, dict):
            return _err(msg_id, -32602, "invalid params")
        name = params.get("name")
        arguments = params.get("arguments") or {}
        handler = HANDLERS.get(name)
        if handler is None:
            return _err(msg_id, -32602, "unknown tool: %s" % name)
        if not isinstance(arguments, dict):
            return _err(msg_id, -32602, "tool arguments must be an object")
        try:
            result = handler(arguments)
        except Exception as exc:  # keep the server alive for the next call
            traceback.print_exc(file=sys.stderr)
            return _ok(
                msg_id,
                _error_result("%s: %s" % (type(exc).__name__, exc)),
            )
        return None if is_notification else _ok(msg_id, result)

    return None if is_notification else _err(
        msg_id, -32601, "method not found: %s" % method
    )


def serve(stdin=None, stdout=None):
    """Run the stdio loop until EOF."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout

    print(
        "scamcheck %s MCP server on stdio (%d tools, offline by default)"
        % (__version__, len(TOOLS)),
        file=sys.stderr,
    )

    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            response = _err(None, -32700, "parse error")
        else:
            try:
                response = handle(message)
            except RpcError as exc:
                response = _err(
                    message.get("id") if isinstance(message, dict) else None,
                    exc.code,
                    exc.message,
                    exc.data,
                )
            except Exception as exc:
                traceback.print_exc(file=sys.stderr)
                response = _err(
                    message.get("id") if isinstance(message, dict) else None,
                    -32603,
                    "internal error: %s" % exc,
                )

        if response is None:
            continue
        try:
            stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            stdout.flush()
        except BrokenPipeError:
            return 0

    return 0


def main(argv=None):
    return serve()


if __name__ == "__main__":
    sys.exit(main())
