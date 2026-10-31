"""Conversation-trajectory analysis -- the kill-chain shape detector.

The research's #1 defence gap: pig butchering & task scams live across
dozens of benign-looking messages; no single message is the tell. This
module reads a whole transcript and scores thepai shape:

    Hook (intimacy/vulnerability bait) -> Groom (fake closeness) ->
    Pivot (money/investment) -> Extraction (fees, pressure, secrecy)

Usage: CLI --chat transcript.txt (one message per line, "label: text"
optional) or POST /v1/analyze {"conversation": [...]}.

Stages:
  S1 Hook:            rapid-friendship, wrong-number 'hook'
  S2 Groom:           daily greeting spam, love/affection, secrets,
                      'never found love like this', moving to private chat
  S3 Pivot:           investments/crypto trading platforms/jobs offered,
                      'mentor/teacher', 'guaranteed'
  S4 Extraction:      deposits, 'withdraw blocked by fees', urgency,
                      secrecy, abusive pressure ('you will lose everything')
"""

import re

C = re.compile

# Stage regexes cover English as before; Hinglish (Roman Hindi) alternates
# are appended to the same patterns -- India's task scams & pig butchering
# run almost entirely in Hinglish (research dossier S4).
GREETINGS = C(
    r"\b(good morning|gm|goodnight|good evening|how are you (doing|today)\b|"
    r"\bhow was your day\b|take care\b|stay safe\b|thinking of you\b|"
    r"shubh\s+(prabhat|sandhya|ratri)|kais(e|i|a)\s+(ho|hain)|kaise\s+ho\b|"
    r"aaj\s+kal\b|khaana\s+khaya)",
    re.I,
)
AFFECTION = C(
    r"\b(dear|love|beloved|my love|baby|beautiful|darling|"
    r"I (really )?(like|love) (your|the) (profile|smile|voice)\b|"
    r"I have (never )?(felt|found) (this |such )?(love|connection) like this\b|"
    r"meri\s+jaan|mera\s+pyar|pyar\s+(karta|karti)|tum\s+meri|dil\s+mein|tera\s+intezaar)\b",
    re.I,
)
HOOK = C(
    r"\b(wrong number|we can be (friends|more)|you (seem|look) (cute|nice|interesting)\b|"
    r"can we (be|chat|talk)\b|hello stranger\b|new (here|friend)\b|"
    r"galat\s*number|ghalat\s*number|pehli\s*baar\s*(message|baat)|pehla\s*message|namaste\s*ji|hello\s*ji)\b",
    re.I,
)
PRIVATE_MOVE = C(
    r"\b(whatsapp|telegram|signal|wechat|let'?s (chat|talk) (there|on)\b|"
    r"switch to|add me on|my number\b|"
    r"number\s*de\s*do|apna\s*number|baat\s*karein\s*(wahin|yahi)|whatsapp\s*karo)\b",
    re.I,
)
PIVOT_MONEY = C(
    r"\b(invest|investment|trade|trading|crypto|forex|stocks|usdt|bitcoin\b|"
    r"mentor\b|teacher\b|coach\b|guaranteed|financial freedom|make money|"
    r"earn\b|income:\s|earning app|"
    r"kamai|kama\b|invest\s?karo|paisa\s*double|monthly\s*income|share\s*market)\b",
    re.I,
)
PLATFORM = C(
    r"\b(platform|dashboard|account manager|app download|register|sign up|"
    r"my (trading|earning) account\b|link below|qr code|"
    r"link\s*par\s*click|register\s*karein|dashboard\s*me)\b",
    re.I,
)
EXTRACT_DEPOSIT = C(
    r"\b(send|transfer|recharge|pay|deposit|invest) (\$|rs\.?|₹|\d){0,20}\b|"
    r"\b(gift|btc|usdt) address\b|upi\b|"
    r"\b(paise?\s*bhej|paisa\s*transfer|recharge\s*(karo|karein)|deposit\s*(karo|karein)|upi\s*id)\b",
    re.I,
)
FEE_BLOCK = C(
    r"\b(withdrawal (fee|blocked|pending|frozen)|tax(es)?|insurance|margin|"
    r"credit score|level (up|upgrade)|unlock|release funds|kyc\b|pay to (get|withdraw|release)\b|"
    r"top ?up|vip group|"
    r"paisa\s*atka|paisa\s*fanse|atka\s*hua|freeze\s*ho\s*gaya|gst\s*bharna|verification\s*ke\s*liye|processing\s*fee)\b",
    re.I,
)
PRESSURE = C(
    r"\b(opportunity (won'?t|will not) (wait|come)|last chance|deadline|"
    r"you (will )?(lose|miss)\b|time is running out|my (uncle|friend) (did|earned)\b|"
    r"sirf\s*aaj|waqt\s*nahi|akhri\s*mauka|spot\s*confirm|jaldi\s*karo)\b",
    re.I,
)
SECRECY = C(
    r"\b(keep this (between us|secret)|don'?t tell|do not tell anyone|"
    r"kisi\s*ko\s*(nahi|mat)\s*batana|chupke\s*raho|batana\s*mat)\b",
    re.I,
)
EXIT_PREDATOR = C(
    r"\b(i need the (money|cash) (back|now)\b|do you love me|prove yourself\b)", re.I,
)

STAGE_WEIGHTS = {
    "hook": 6,
    "groom": 8,
    "pivot": 14,
    "platform": 8,
    "extract": 16,
    "fee_block": 14,
    "pressure": 10,
    "secrecy": 8,
    "exit": 6,
}


def parse_conversation(raw):
    """Messages: split on newline; 'Sender: text' prefix stripped to the text part."""
    messages = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^\s*[\[\(]?\d{1,2}:\d{2}[\] \)]?\s*", line)  # timestamp
        if m:
            line = line[len(m.group(0)):].strip()
        m = re.match(r"^\s*[A-Za-z\u0900-\u097F\u0980-\u09FF .'\-]{1,20}:\s+(.*)$", line)
        if m and not re.match(r"^\s*(note|warning|see)?: .*$", line, re.I):
            line = m.group(1)
        messages.append(line)
    return messages


def detect_stage_hits(messages):
    """Count which stage patterns occur, and where (first seen index / len)."""
    n = len(messages) or 1
    hit_map = {}
    for name, rx in [("hook", HOOK), ("greet", GREETINGS), ("groom", AFFECTION),
                     ("move", PRIVATE_MOVE), ("pivot", PIVOT_MONEY),
                     ("platform", PLATFORM), ("deposit", EXTRACT_DEPOSIT),
                     ("fee", FEE_BLOCK), ("pressure", PRESSURE),
                     ("secrecy", SECRECY), ("exit", EXIT_PREDATOR)]:
        idxs = [i for i, m in enumerate(messages) if rx.search(m)]
        if idxs:
            # earliest occurrence position (0..1), tells ordering of the chain
            hit_map[name] = {
                "count": len(idxs),
                "earliest": min(idxs) / n,
                "latest": max(idxs) / n,
            }
    return hit_map


def analyze_conversation(text):
    messages = parse_conversation(text)
    if len(messages) < 2:
        return None  # not a conversation

    hits = detect_stage_hits(messages)

    # --- scoring: shape of the kill chain matters, not the sum of words ---
    score = 0
    reasons = []
    notes = []

    # Groom AFTER hook, pivot AFTER groom, extract AFTER pivot -> chain order
    order = [k for k in ["hook", "greet", "groom", "move", "pivot",
                          "platform", "deposit", "fee", "pressure"] if k in hits]
    ordered_chain = sorted(order, key=lambda k: hits[k]["earliest"])
    if {"groom", "pivot", "extract" if "extract" in hits else "deposit"} <= set(ordered_chain):
        pass

    if "greet" in hits and hits["greet"]["count"] >= 3:
        score += 5
        reasons.append(("Greeting-message grooming (%d 'good morning'-type messages)"
                        % hits["greet"]["count"], 5))
    if "groom" in hits and (hits["groom"]["count"] >= 2 or len(hits) > 1):
        # A single affectionate word is just family ("love you mom"); romance
        # grooming shows repeated endearments or affection + another stage.
        score += STAGE_WEIGHTS["groom"]
        reasons.append(("Affection/love language typical of romance grooming", 8))
        notes.append("groom")
    if "move" in hits:
        score += 6
        reasons.append(("Pushes chat off-platform (WhatsApp/Telegram/Signal)", 6))
        notes.append("move")
    if "pivot" in hits:
        score += STAGE_WEIGHTS["pivot"]
        reasons.append(("The conversation pivots to investments/crypto/earnings", 14))
    if "platform" in hits:
        score += STAGE_WEIGHTS["platform"]
        reasons.append(("Directs you to an external platform/app/dashboard", 8))
    if "deposit" in hits:
        score += STAGE_WEIGHTS["extract"]
        reasons.append(("Asks for money transfers/deposits/crypto addresses", 16))
    if "fee" in hits:
        score += STAGE_WEIGHTS["fee_block"]
        reasons.append(("Withdrawal-block extraction: taxes/fees/level-ups to release money", 14))
    if "pressure" in hits:
        score += STAGE_WEIGHTS["pressure"]
        reasons.append(("FOMO/deadline pressure (don't lose your spot)", 10))
    if "secrecy" in hits:
        score += STAGE_WEIGHTS["secrecy"]
        reasons.append(("Demands secrecy (don't tell anyone)", 8))

    # Kill-chain shape bonus: intimacy came BEFORE money, and extraction is late
    if set(["groom", "pivot", "deposit"]) <= set(hits):
        score += 15
        reasons.append(("FULL KILL-CHAIN SHAPE: intimacy built first, then money pivot, then deposits "
                        "(pig-butchering pattern)", 15))
    elif "pivot" in hits and "deposit" in hits:
        score += 6
        reasons.append(("Chained money-pivot + deposits (task-scam or invest-scam shape)", 6))

    if messages and any(len(m) > 200 for m in messages[:2]):
        score -= 5  # long opening block = often forward/copy-paste, weaker groom signal
        reasons = [r for r in reasons if r[0] != "Affection/love language typical of romance grooming"] or reasons

    score = max(0, min(score, 100))

    if score >= 60:
        verdict = "SCAM CONVERSATION"
    elif score >= 35:
        verdict = "LIKELY SCAM CONVERSATION"
    elif score >= 15:
        verdict = "SUSPICIOUS PATTERN"
    else:
        verdict = "LOOKS LIKE NORMAL TALK"

    reasons.sort(key=lambda r: -r[1])
    return {
        "score": score,
        "verdict": verdict,
        "message_count": len(messages),
        "stages": hits,
        "reasons": reasons,
    }
