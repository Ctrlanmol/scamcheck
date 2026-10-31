"""Optional AI second opinion.

Uses an OpenAI-compatible endpoint (OPENAI_API_KEY) or Anthropic
(ANTHROPIC_API_KEY) via the standard library only. Returns None whenever no
key is configured or the request fails, so the CLI always degrades
gracefully to rule-only mode.
"""

import json
import os
import urllib.error
import urllib.request

SYSTEM_PROMPT = (
    "You are a scam-detection analyst for SMS messages. Decide whether the "
    "message is a scam, phishing, or fraudulent. Reply ONLY with compact JSON: "
    '{"verdict": "SCAM" | "SUSPICIOUS" | "SAFE", '
    '"confidence": 0-100, "summary": "<max 25 words>", '
    '"reasons": ["<short reason>", ...]}.\n'
    "Be cautious but not paranoid: legitimate delivery notifications, OTP codes "
    "from services the user just used, and bank alerts that ask to check the "
    "official app (not a link) are SAFE. Messages combining urgency + a link + "
    "personal/financial info requests are SCAM."
)


def _post_json(url, headers, payload, timeout=20):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers=headers, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _call_openai(text, rules_summary):
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None
    base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("SCAMCHECK_AI_MODEL", "gpt-4o-mini")
    resp = _post_json(
        base + "/chat/completions",
        {
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
        },
        {
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _user_prompt(text, rules_summary)},
            ],
            "temperature": 0,
            "max_tokens": 400,
        },
    )
    return resp["choices"][0]["message"]["content"]


def _call_anthropic(text, rules_summary):
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    model = os.environ.get("SCAMCHECK_AI_MODEL", "claude-sonnet-4-5")
    resp = _post_json(
        "https://api.anthropic.com/v1/messages",
        {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        {
            "model": model,
            "max_tokens": 400,
            "system": SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": _user_prompt(text, rules_summary)}
            ],
        },
    )
    return resp["content"][0]["text"]


def _user_prompt(text, rules_summary):
    return (
        "Message to analyze:\n---\n" + text[:4000] + "\n---\n"
        "Rule-based engine preliminary finding (may be wrong, use as a hint only): "
        + rules_summary
    )


def ai_opinion(text, rules_summary):
    """Return dict {'verdict','confidence','summary','reasons'} or None."""
    for caller in (_call_openai, _call_anthropic):
        try:
            raw = caller(text, rules_summary)
        except (urllib.error.URLError, urllib.error.HTTPError, KeyError, TimeoutError, json.JSONDecodeError, OSError):
            continue
        if not raw:
            continue
        try:
            # strip possible markdown fences
            raw = raw.strip()
            if raw.startswith("```"):
                raw = raw.strip("`")
                if raw.lower().startswith("json"):
                    raw = raw[4:]
            data = json.loads(raw[raw.index("{"): raw.rindex("}") + 1])
            verdict = str(data.get("verdict", "")).upper()
            if verdict not in {"SCAM", "SUSPICIOUS", "SAFE"}:
                continue
            return {
                "verdict": verdict,
                "confidence": int(data.get("confidence", 50)),
                "summary": str(data.get("summary", ""))[:200],
                "reasons": [str(r) for r in data.get("reasons", [])][:8],
            }
        except (ValueError, KeyError, TypeError):
            continue
    return None
