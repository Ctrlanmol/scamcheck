"""Orchestration: scripts -> rules -> optional conversation -> AI blending."""

from . import ai as ai_mod
from . import phones
from .conversation import analyze_conversation
from .intelligence import assess, deobfuscate, detect_obfuscation
from .rules import run_rules
from .scripts_lib import match_scripts


def decide(score, verdict, ai_info):
    """Blend rule verdict + AI verdict into final decision.

    The AI can escalate (e.g. SUSPICIOUS -> SCAM) or soften one level, but a
    high rule score is kept as-is: heuristics are a strong floor.
    """
    rank = {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "LIKELY SCAM": 2, "SCAM": 3}
    ai_to_rank = {"SAFE": 0, "SUSPICIOUS": 1, "SCAM": 3}

    if not ai_info:
        return verdict

    ai_v = min(ai_to_rank[ai_info["verdict"]], 1 if ai_to_rank[ai_info["verdict"]] == 0 and score >= 15 else ai_to_rank[ai_info["verdict"]])
    ai_conf = ai_info.get("confidence", 50)

    if ai_conf >= 75:
        if ai_v > rank[verdict]:
            return ai_rank_to_label(ai_v)
        if ai_v < rank[verdict] and rank[verdict] <= 1:
            # only soften borderline rules verdicts (SAFE/SUSPICIOUS)
            return ai_rank_to_label(ai_v)
    return verdict


def ai_rank_to_label(r):
    return {0: "LIKELY SAFE", 1: "SUSPICIOUS", 2: "LIKELY SCAM", 3: "SCAM"}[r]


def analyze(text: str, use_ai="auto", is_conversation=None, ocr=False,
            sender=None, region=None):
    """Analyze one message, or a full conversation transcript.

    use_ai: 'auto' (only borderline), 'always', 'never'.
    is_conversation: None = auto-detect (multi-line input with >1 message).
    ocr: True when text came from a screenshot (adds a noise-tolerant
    half-weight matching variant).
    sender: optional originating phone number / SMS sender ID. Reputation is
    read from local lists and cached feeds only — analysis never goes online.
    region: default region for national numbers (default from config, 'IN').
    Returns enlarged result dict with 'scripts', 'conversation', 'ai', 'ocr',
    and (when a sender or number was seen) 'number'.
    """
    from .rules import normalize_ocr_text

    ocr_variant = normalize_ocr_text(text) if ocr else None
    normalized = deobfuscate(text)
    obfuscation = detect_obfuscation(text, normalized=normalized)
    auto_convo = is_conversation is None and "\n" in text
    conversation = analyze_conversation(text) if (
        is_conversation or auto_convo
    ) else None

    rules = run_rules(text, ocr_text=ocr_variant, extra_text=normalized) if conversation is None else {"score": 0, "verdict": "LIKELY SAFE", "reasons": []}

    # merge conversation findings into rules when analyzing a chat
    if conversation:
        rules["reasons"] = conversation["reasons"]
        rules["score"] = conversation["score"]
        rules["verdict"] = (
            "SCAM" if conversation["verdict"] == "SCAM CONVERSATION"
            else "LIKELY SCAM" if conversation["verdict"] == "LIKELY SCAM CONVERSATION"
            else "SUSPICIOUS" if conversation["verdict"] == "SUSPICIOUS PATTERN"
            else "LIKELY SAFE"
        )
        if ocr:
            # Screenshot text is noisy (blocky fonts, chat-bubble clipping):
            # a garbled-but-real red flag in the rules engine deserves to
            # survive even when the conversation trajectory stays quiet.
            # Merge both sources: best score wins, reasons are combined.
            extra = run_rules(text, ocr_text=ocr_variant, extra_text=normalized)
            rank = {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "LIKELY SCAM": 2, "SCAM": 3}
            final_rank = max(rank[rules["verdict"]], rank[extra["verdict"]])
            rules["score"] = int(max(rules["score"], extra["score"]))
            labels = {lbl for lbl, _ in rules["reasons"]}
            rules["reasons"] = rules["reasons"] + [r for r in extra["reasons"] if r[0] not in labels]
            rules["verdict"] = {3: "SCAM", 2: "LIKELY SCAM", 1: "SUSPICIOUS", 0: "LIKELY SAFE"}[final_rank]

    # full-script lock: a recognized playbook beats threshold tuning
    scripts = match_scripts(text)
    script_names = []
    for script, strength, labels in scripts:
        script_names.append(script.name)
        rules["reasons"].insert(0, ("Matches known scam playbook: " + script.name, 35))
        rules["score"] = min(100, rules["score"] + 35 * strength)
        if rules["verdict"] == "LIKELY SAFE":
            rules["verdict"] = "SUSPICIOUS"
        if rules["score"] >= 60:
            rules["verdict"] = "SCAM"
        elif rules["score"] >= 35:
            rules["verdict"] = max(rules["verdict"], "LIKELY SCAM", key=lambda v: {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "LIKELY SCAM": 2, "SCAM": 3}[v])

    # Phone-number evidence (local lists + cached feeds; zero network access).
    # Support evidence only: it can raise a verdict, never lower a text verdict.
    number = phones.number_signals(text, sender=sender, region=region)
    number["region"] = phones.default_region(region)
    if number["reasons"]:
        rules["score"] = max(0, min(100, rules["score"] + number["score"]))
        rules["reasons"] = number["reasons"] + rules["reasons"]
        ranks = {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "LIKELY SCAM": 2, "SCAM": 3}
        labels = {0: "LIKELY SAFE", 1: "SUSPICIOUS", 2: "LIKELY SCAM", 3: "SCAM"}
        target = ranks[rules["verdict"]]
        if rules["score"] >= 60:
            target = max(target, 3)
        elif rules["score"] >= 35:
            target = max(target, 2)
        elif rules["score"] >= 15:
            target = max(target, 1)
        if number["floor"]:
            target = max(target, ranks[number["floor"]])
        rules["verdict"] = labels[target]

    # Deliberate filter evasion is itself evidence. Zero-width characters,
    # mixed-script homoglyphs, letter-spacing and disguised URLs are not
    # ordinary formatting; keep the boost capped so it cannot alone fake a
    # SCAM verdict.
    if obfuscation["detected"] and obfuscation["score"] > 0:
        penalty = int(obfuscation["score"])
        rules["score"] = min(100, rules["score"] + penalty)
        keys = ", ".join(s["key"] for s in obfuscation["signals"][:3])
        rules["reasons"].insert(0, (
            "Disguised text used to evade filters (%s)" % keys, penalty,
        ))
        ranks = {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "LIKELY SCAM": 2, "SCAM": 3}
        labels = {0: "LIKELY SAFE", 1: "SUSPICIOUS", 2: "LIKELY SCAM", 3: "SCAM"}
        target = ranks[rules["verdict"]]
        if rules["score"] >= 60:
            target = max(target, 3)
        elif rules["score"] >= 35:
            target = max(target, 2)
        elif rules["score"] >= 15:
            target = max(target, 1)
        rules["verdict"] = labels[target]

    result = dict(rules)
    result["scripts"] = script_names
    result["conversation"] = conversation
    result["ai"] = None
    result["ocr"] = bool(ocr)
    if sender or number["mentioned"] or number["reasons"]:
        result["number"] = number

    should_ai = (use_ai == "always") or (
        use_ai == "auto" and 15 <= rules["score"] < 60
    )
    if should_ai and ai_mod.ai_opinion is not None:
        summary = "%s (score %d/100); signals: %s; playbook: %s" % (
            rules["verdict"], rules["score"],
            "; ".join(r[0] for r in rules["reasons"][:8]) or "none",
            ", ".join(script_names) or "none",
        )
        info = ai_mod.ai_opinion(text, summary)
        if info:
            result["ai"] = info
            result["final_verdict"] = decide(rules["score"], rules["verdict"], info)
        else:
            result["final_verdict"] = rules["verdict"]
    else:
        result["final_verdict"] = rules["verdict"]

    result["intelligence"] = assess(text, result)
    return result
