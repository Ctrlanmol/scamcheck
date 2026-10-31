#!/usr/bin/env python3
"""v0.13 tests: the MCP stdio server.

Everything is local: the server runs as a subprocess and speaks
newline-delimited JSON-RPC 2.0, exactly as an MCP client would.

Run: python3 tests/test_mcp.py
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

HOME = tempfile.mkdtemp(prefix="scamcheck-mcp-")
os.environ["SCAMCHECK_HOME"] = HOME
os.environ["SCAMCHECK_REGION"] = "IN"
os.environ.pop("OPENAI_API_KEY", None)
os.environ.pop("ANTHROPIC_API_KEY", None)

failures = 0


def check(name, condition, detail=""):
    global failures
    if condition:
        print("  ok   %s" % name)
    else:
        failures += 1
        print("  FAIL %s%s" % (name, (": " + str(detail)) if detail else ""))


def rpc_session(messages, timeout=120):
    """Run the server once, feed messages, return (responses, stderr, raw)."""
    payload = "\n".join(json.dumps(m) for m in messages) + "\n"
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    proc = subprocess.run(
        [sys.executable, "-m", "scamcheck", "--mcp"],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
        cwd=ROOT,
    )
    responses = []
    raw_lines = [line for line in proc.stdout.splitlines() if line.strip()]
    for line in raw_lines:
        responses.append(json.loads(line))  # raises if stdout is polluted
    return responses, proc.stderr, raw_lines


def by_id(responses, msg_id):
    for item in responses:
        if item.get("id") == msg_id:
            return item
    return None


def text_of(response):
    return (response.get("result") or {}).get("content", [{}])[0].get("text", "")


def main():
    print("scamcheck MCP server")

    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "scamcheck-tests", "version": "1.0"},
        },
    }
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    tools_list = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    ping = {"jsonrpc": "2.0", "id": 3, "method": "ping"}

    responses, stderr, raw = rpc_session([init, initialized, tools_list, ping])

    print("\n[1] handshake")
    r = by_id(responses, 1)
    check("initialize responds", r is not None and "result" in r, r)
    if r:
        result = r["result"]
        check("protocol echoed", result["protocolVersion"] == "2025-06-18", result)
        check("serverInfo name", result["serverInfo"]["name"] == "scamcheck", result)
        check("tools capability", "tools" in result["capabilities"], result)
    check("ping responds", by_id(responses, 3) is not None)
    check(
        "notification gets no reply (4 requests, 3 responses)",
        len(responses) == 3,
        len(responses),
    )
    check("stdout is pure JSON", len(raw) == 3, raw)

    print("\n[2] tools/list")
    r = by_id(responses, 2)
    tools = (r or {}).get("result", {}).get("tools", [])
    names = [t["name"] for t in tools]
    check("six tools", len(tools) == 6, names)
    for expected in (
        "check_message",
        "check_url",
        "check_number",
        "extract_entities",
        "open_case",
        "scamcheck_info",
    ):
        check("has %s" % expected, expected in names, names)
    for tool in tools:
        check(
            "%s has schema" % tool["name"],
            tool.get("inputSchema", {}).get("type") == "object",
            tool.get("inputSchema"),
        )
        check("%s has description" % tool["name"], bool(tool.get("description")))

    print("\n[3] check_message")
    scam = (
        "Dear customer, your KYC is expiring today. Verify now at "
        "http://bit.ly/x1y2z or your account will be blocked within 24 hours."
    )
    benign = "Hi mom, I'll be home by 8. Do you need anything from the shop?"
    chat = (
        "Hey, is this Priya?\n"
        "Yes who is this?\n"
        "I got your number from the group. I trade crypto, my uncle taught me.\n"
        "You can start with 5000 and double it in a week.\n"
        "Send the money to this UPI id and I'll set up your account.\n"
        "Why is my withdrawal blocked?\n"
        "You need to pay 18% tax first, then it releases.\n"
        "Please don't tell anyone, they will ruin it."
    )

    responses, stderr, raw = rpc_session(
        [
            init,
            {"jsonrpc": "2.0", "id": 10, "method": "tools/call",
             "params": {"name": "check_message", "arguments": {"text": scam}}},
            {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
             "params": {"name": "check_message", "arguments": {"text": benign}}},
            {"jsonrpc": "2.0", "id": 12, "method": "tools/call",
             "params": {"name": "check_message",
                        "arguments": {"text": chat, "conversation": True}}},
            {"jsonrpc": "2.0", "id": 13, "method": "tools/call",
             "params": {"name": "check_message", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 14, "method": "tools/call",
             "params": {"name": "check_message", "arguments": {"text": "x", "ai": "maybe"}}},
        ]
    )

    r = by_id(responses, 10)
    check("scam call ok", r is not None and r["result"]["isError"] is False, r)
    if r:
        payload = r["result"]["structuredContent"]
        check("scam verdict", payload["final_verdict"] == "SCAM", payload.get("final_verdict"))
        check("score present", isinstance(payload["score"], int), payload.get("score"))
        check("signals present", len(payload["reasons"]) > 0)
        check("intelligence attached", "scam_type" in payload.get("intelligence", {}))
        check("text block is readable", "SCAM" in text_of(r), text_of(r))
        check("no AI used", payload.get("ai") is None)

    r = by_id(responses, 11)
    check("benign call ok", r is not None and r["result"]["isError"] is False, r)
    if r:
        verdict = r["result"]["structuredContent"]["final_verdict"]
        check("benign not SCAM", verdict != "SCAM", verdict)

    r = by_id(responses, 12)
    if r and not r["result"]["isError"]:
        payload = r["result"]["structuredContent"]
        check(
            "conversation scores as scam",
            payload["final_verdict"] in ("SCAM", "LIKELY SCAM"),
            payload["final_verdict"],
        )
        check("conversation object present", payload.get("conversation") is not None)
    else:
        check("conversation call ok", False, r)

    r = by_id(responses, 13)
    check("missing text is a tool error", r and r["result"]["isError"] is True, r)
    r = by_id(responses, 14)
    check("bad ai enum is a tool error", r and r["result"]["isError"] is True, r)

    print("\n[4] check_number + extract_entities")
    responses, stderr, raw = rpc_session(
        [
            init,
            {"jsonrpc": "2.0", "id": 20, "method": "tools/call",
             "params": {"name": "check_number", "arguments": {"number": "+91 98765 43210"}}},
            {"jsonrpc": "2.0", "id": 21, "method": "tools/call",
             "params": {"name": "check_number", "arguments": {"number": "not a number"}}},
            {"jsonrpc": "2.0", "id": 22, "method": "tools/call",
             "params": {"name": "extract_entities",
                        "arguments": {"text": "Pay to scammer@okhdfcbank or visit evil-example.xyz, call +919876543210"}}},
        ]
    )

    r = by_id(responses, 20)
    check("valid number ok", r is not None and r["result"]["isError"] is False, r)
    if r:
        payload = r["result"]["structuredContent"]
        check("number normalized", payload["number"]["e164"] == "+919876543210", payload["number"])

    r = by_id(responses, 21)
    check("invalid number errors", r and r["result"]["isError"] is True, r)

    r = by_id(responses, 22)
    check("entities ok", r is not None and r["result"]["isError"] is False, r)
    if r:
        entities = r["result"]["structuredContent"]["entities"]
        kinds = {e["kind"] for e in entities}
        check("found upi", "upi" in kinds, kinds)
        check("found url", "url" in kinds, kinds)
        check("found phone", "phone" in kinds, kinds)

    print("\n[5] open_case")
    responses, stderr, raw = rpc_session(
        [
            init,
            {"jsonrpc": "2.0", "id": 30, "method": "tools/call",
             "params": {"name": "open_case",
                        "arguments": {"title": "MCP test case", "scam_type": "upi",
                                      "currency": "INR", "loss_amount": 5000,
                                      "evidence_text": scam}}},
        ]
    )
    r = by_id(responses, 30)
    check("case created", r is not None and r["result"]["isError"] is False, r)
    if r:
        case = r["result"]["structuredContent"]
        check("case has id", bool(case.get("id")), case)
        check("evidence hashed", len(case.get("evidence") or []) == 1, case.get("evidence"))
        if case.get("evidence"):
            check("sha256 present", len(case["evidence"][0]["sha256"]) == 64, case["evidence"][0])
        check("loss recorded", case.get("loss_amount") == 5000, case.get("loss_amount"))

    print("\n[6] protocol errors stay protocol errors")
    responses, stderr, raw = rpc_session(
        [
            {"jsonrpc": "2.0", "id": 40, "method": "no/such/method"},
            {"jsonrpc": "2.0", "id": 41, "method": "tools/call",
             "params": {"name": "no_such_tool", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 42, "method": "tools/call",
             "params": {"name": "check_message", "arguments": "not-an-object"}},
        ]
    )
    r = by_id(responses, 40)
    check("unknown method -32601", r and r.get("error", {}).get("code") == -32601, r)
    r = by_id(responses, 41)
    check("unknown tool -32602", r and r.get("error", {}).get("code") == -32602, r)
    r = by_id(responses, 42)
    check("bad arguments -32602", r and r.get("error", {}).get("code") == -32602, r)

    # A malformed line must not kill the loop.
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    payload = (
        "{not json}\n"
        + json.dumps(init) + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 50, "method": "ping"}) + "\n"
    )
    proc = subprocess.run(
        [sys.executable, "-m", "scamcheck", "--mcp"],
        input=payload, capture_output=True, text=True, env=env, timeout=60, cwd=ROOT,
    )
    lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    check("parse error -32700", any(l.get("error", {}).get("code") == -32700 for l in lines), lines)
    check("loop survives parse error", any(l.get("id") == 50 for l in lines), lines)

    print("\n[7] unsupported protocol version falls back")
    responses, stderr, raw = rpc_session(
        [{"jsonrpc": "2.0", "id": 60, "method": "initialize",
          "params": {"protocolVersion": "1999-01-01", "capabilities": {}}}]
    )
    r = by_id(responses, 60)
    check("fallback version", r and r["result"]["protocolVersion"] in
          ("2025-06-18", "2025-03-26", "2024-11-05"), r)

    print("\n[8] stderr carries the banner, stdout stays clean")
    check("banner on stderr", "MCP server on stdio" in stderr, stderr[:200])

    print()
    print("FAILED: %d checks" % failures if failures else "All checks passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
