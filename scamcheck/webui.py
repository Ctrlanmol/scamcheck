"""Family web UI, served at GET / by the local API (no external assets).

Design goals for the family-guardian path (teen/elder "check this for me"):
- one obvious action, huge type, high contrast, keyboard/paste friendly
- verdict in plain language + what to do next, never just a score
- English/Hindi toggle (detection itself is language-agnostic)
- screenshots via file picker, drag-drop or clipboard paste (POST /v1/check-image)
- strict same-origin CSP; everything stays on the machine
"""

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>scamcheck — is this message a scam?</title>
<style>
  :root {
    --bg: #f5f6f8; --card: #ffffff; --ink: #111827; --muted: #5b6472;
    --line: #e2e5ea; --accent: #1d4ed8; --accent-ink: #ffffff;
    --scam: #c81e1e; --likely: #b45309; --warn: #8a6d00; --safe: #15803d;
    --tint-scam: #fdecec; --tint-likely: #fff4e5; --tint-warn: #fffbe6;
    --tint-safe: #ecfdf3; --shadow: 0 1px 2px rgba(16,24,40,.06), 0 8px 24px rgba(16,24,40,.06);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0f1115; --card: #171a21; --ink: #f3f4f6; --muted: #a7afbd;
      --line: #2a2f3a; --accent: #6d9bff; --accent-ink: #0b1020;
      --scam: #ff7b7b; --likely: #ffb86b; --warn: #ffe08a; --safe: #7ee2a8;
      --tint-scam: #2a1616; --tint-likely: #2a1e12; --tint-warn: #262213;
      --tint-safe: #12251a; --shadow: none;
    }
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    background: var(--bg); color: var(--ink); font-size: 18px; line-height: 1.55;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 "Noto Sans", "Noto Sans Devanagari", Arial, sans-serif;
  }
  main { max-width: 780px; margin: 0 auto; padding: 28px 18px 60px; }
  header { display: flex; align-items: flex-start; gap: 14px; flex-wrap: wrap; margin-bottom: 20px; }
  .brand { flex: 1 1 320px; }
  h1 { font-size: 34px; line-height: 1.15; margin: 0 0 6px; letter-spacing: -0.5px; }
  h1 span { color: var(--accent); }
  .tagline { margin: 0; color: var(--muted); font-size: 17px; }
  .lang-switch { display: flex; gap: 6px; }
  .lang-btn {
    font: inherit; font-size: 15px; padding: 8px 12px; border-radius: 999px;
    border: 1px solid var(--line); background: var(--card); color: var(--muted);
    cursor: pointer; min-height: 40px;
  }
  .lang-btn.active { border-color: var(--accent); color: var(--accent); font-weight: 700; }
  .card {
    background: var(--card); border: 1px solid var(--line); border-radius: 16px;
    padding: 20px; margin: 0 0 16px; box-shadow: var(--shadow);
  }
  .field-label { display: block; font-weight: 700; font-size: 19px; margin-bottom: 10px; }
  .sender-label { margin-top: 18px; font-size: 17px; }
  .sender-input {
    width: 100%; padding: 12px 14px; font: inherit; font-size: 17px; color: var(--ink);
    background: var(--bg); border: 1.5px solid var(--line); border-radius: 12px;
  }
  .sender-input:focus { outline: 3px solid color-mix(in srgb, var(--accent) 55%, transparent); outline-offset: 2px; }
  textarea {
    width: 100%; min-height: 150px; resize: vertical; padding: 14px;
    font: inherit; font-size: 19px; line-height: 1.5; color: var(--ink);
    background: var(--bg); border: 1.5px solid var(--line); border-radius: 12px;
  }
  textarea:focus, button:focus-visible, .drop:focus-visible {
    outline: 3px solid color-mix(in srgb, var(--accent) 55%, transparent);
    outline-offset: 2px;
  }
  .row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 14px; }
  button { font: inherit; cursor: pointer; border-radius: 12px; }
  .primary {
    background: var(--accent); color: var(--accent-ink); border: 1px solid var(--accent);
    font-size: 20px; font-weight: 700; padding: 14px 22px; min-height: 56px; flex: 1 1 220px;
  }
  .primary:disabled { opacity: .6; cursor: progress; }
  .secondary {
    background: var(--card); color: var(--accent); border: 1.5px solid var(--accent);
    font-size: 17px; font-weight: 600; padding: 10px 16px; min-height: 48px;
  }
  .ghost {
    background: transparent; color: var(--muted); border: 1px solid var(--line);
    font-size: 17px; padding: 10px 16px; min-height: 48px;
  }
  .hint { color: var(--muted); font-size: 15px; margin: 10px 0 0; }
  .drop {
    margin-top: 18px; padding: 18px; border: 2px dashed var(--line); border-radius: 14px;
    display: flex; flex-direction: column; gap: 10px; align-items: flex-start;
  }
  .drop.over { border-color: var(--accent); background: color-mix(in srgb, var(--accent) 8%, transparent); }
  .drop .drop-title { font-weight: 700; font-size: 18px; }
  h2 { font-size: 20px; margin: 0 0 12px; }
  .examples { display: flex; gap: 10px; flex-wrap: wrap; }
  .chip {
    background: var(--bg); border: 1px solid var(--line); color: var(--ink);
    font-size: 16px; padding: 10px 14px; min-height: 46px;
  }
  .chip:hover { border-color: var(--accent); color: var(--accent); }
  #error {
    background: var(--tint-scam); color: var(--scam); border: 1px solid var(--scam);
    border-radius: 12px; padding: 12px 14px; margin: 0 0 16px; font-weight: 600;
  }
  .result { border-width: 2px; }
  .result.safe { background: var(--tint-safe); border-color: var(--safe); }
  .result.warn, .result.likely { background: var(--tint-warn); border-color: var(--warn); }
  .result.likely { background: var(--tint-likely); border-color: var(--likely); }
  .result.scam { background: var(--tint-scam); border-color: var(--scam); }
  .verdict-icon { font-size: 44px; line-height: 1; }
  .verdict { font-size: 30px; margin: 6px 0 4px; }
  .result.safe .verdict { color: var(--safe); }
  .result.warn .verdict { color: var(--warn); }
  .result.likely .verdict { color: var(--likely); }
  .result.scam .verdict { color: var(--scam); }
  .advice { font-size: 19px; margin: 6px 0 0; font-weight: 600; }
  .score { display: flex; align-items: center; gap: 12px; margin-top: 16px; }

  .bar { flex: 1 1 180px; height: 10px; background: var(--line); border-radius: 999px; overflow: hidden; }
  .bar > div { height: 100%; width: 0; background: var(--muted); border-radius: 999px; transition: width .35s ease; }
  .score span { font-size: 15px; color: var(--muted); white-space: nowrap; }
  .playbook { margin: 14px 0 0; font-size: 17px; font-weight: 700; }
  .playbook:empty { display: none; }
  .number-info { margin: 10px 0 0; font-size: 17px; font-weight: 600; }
  .number-info:empty { display: none; }
  details { margin-top: 14px; }
  summary { cursor: pointer; font-weight: 700; font-size: 17px; min-height: 40px; }
  ul { margin: 10px 0 0; padding-left: 22px; }
  li { margin: 0 0 8px; }
  li .w { color: var(--muted); font-size: 14px; }
  pre {
    white-space: pre-wrap; word-break: break-word; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 15px; background: var(--bg); padding: 12px; border-radius: 10px; margin: 10px 0 0;
  }
  footer { color: var(--muted); font-size: 15px; margin-top: 26px; }
  footer p { margin: 0 0 8px; }
  .small { font-size: 14px; opacity: .8; }
  @media (max-width: 520px) {
    h1 { font-size: 28px; }
    .verdict { font-size: 25px; }
    main { padding: 20px 12px 50px; }
    .card { padding: 16px; }
  }
</style>
</head>
<body>
<main>
  <header>
    <div class="brand">
      <h1>scam<span>check</span></h1>
      <p class="tagline" data-i18n="tagline">Free, private, and runs on your device. Nothing is uploaded.</p>
    </div>
    <div class="lang-switch" role="group" aria-label="Language / भाषा">
      <button id="lang-en" class="lang-btn" type="button">English</button>
      <button id="lang-hi" class="lang-btn" type="button">हिंदी</button>
    </div>
  </header>

  <p id="error" role="alert" hidden></p>

  <section class="card">
    <label class="field-label" for="msg" data-i18n="pasteLabel">Paste the message you received</label>
    <textarea id="msg" rows="6" data-i18n-placeholder="placeholder"
      placeholder="Paste an SMS, WhatsApp message, or email here…"></textarea>
    <label class="field-label sender-label" for="sender" data-i18n="senderLabel">Sender number (optional)</label>
    <input id="sender" class="sender-input" type="text" inputmode="tel" autocomplete="off"
      data-i18n-placeholder="senderPlaceholder" placeholder="+91 98765 43210 or VM-HDFCBK">
    <div class="row">
      <button id="check" class="primary" type="button" data-i18n="checkBtn">Check message</button>
      <button id="clear" class="ghost" type="button" data-i18n="clearBtn">Clear</button>
    </div>
    <p class="hint" data-i18n="keyHint">Tip: press Ctrl/⌘ + Enter to check.</p>

    <div id="drop" class="drop" tabindex="0" role="button" aria-describedby="drop-hint">
      <span class="drop-title" data-i18n="imageLabel">Or check a screenshot</span>
      <button id="pick" class="secondary" type="button" data-i18n="chooseImage">Choose image…</button>
      <span id="drop-hint" class="hint" data-i18n="pasteImageHint">You can also paste a screenshot (⌘/Ctrl+V) anywhere on this page.</span>
      <input id="file" type="file" accept="image/*" hidden>
    </div>
  </section>

  <section class="card">
    <h2 data-i18n="examplesTitle">Try an example</h2>
    <div class="examples">
      <button class="chip" type="button" data-example="hinglish" data-i18n="exHinglish">Hinglish SMS</button>
      <button class="chip" type="button" data-example="bec" data-i18n="exScam">Scam email</button>
      <button class="chip" type="button" data-example="safe" data-i18n="exSafe">Normal message</button>
    </div>
  </section>

  <section id="result" class="card result" aria-live="polite" hidden>
    <div id="verdict-icon" class="verdict-icon" aria-hidden="true"></div>
    <h2 id="verdict" class="verdict"></h2>
    <p id="advice" class="advice"></p>
    <div class="score">
      <div class="bar" aria-hidden="true"><div id="bar-fill"></div></div>
      <span id="score-label"></span>
    </div>
    <p id="playbook" class="playbook"></p>
    <p id="number-info" class="number-info" hidden></p>
    <details id="why">
      <summary data-i18n="why">Why this result</summary>
      <ul id="reasons"></ul>
    </details>
    <details id="extracted" hidden>
      <summary data-i18n="extracted">Text read from the screenshot</summary>
      <pre id="extracted-text"></pre>
    </details>
    <div class="row">
      <button id="again" class="ghost" type="button" data-i18n="again">Check another</button>
    </div>
  </section>

  <footer>
    <p data-i18n="disclaimer">This is a helper, not a guarantee. If money or personal details are involved, verify with a number you already have — never the one in the message.</p>
    <p class="small" data-i18n="privacy">scamcheck runs locally — no data leaves this device.</p>
  </footer>
</main>

<script>
(function () {
  "use strict";

  var STRINGS = {
    en: {
      tagline: "Free, private, and runs on your device. Nothing is uploaded.",
      pasteLabel: "Paste the message you received",
      placeholder: "Paste an SMS, WhatsApp message, or email here…",
      senderLabel: "Sender number (optional)",
      senderPlaceholder: "+91 98765 43210 or VM-HDFCBK",
      senderBlocked: "Sender is on your blocklist:",
      senderAllowed: "Sender is on your allowlist:",
      senderReported: "Sender was reported by a public list:",
      senderPremium: "Sender is a premium-rate number:",
      senderNeutral: "Sender:",
      mentionedNumber: "Message mentions a risky number:",
      checkBtn: "Check message",
      clearBtn: "Clear",
      keyHint: "Tip: press Ctrl/⌘ + Enter to check.",
      imageLabel: "Or check a screenshot",
      chooseImage: "Choose image…",
      pasteImageHint: "You can also paste a screenshot (⌘/Ctrl+V) anywhere on this page.",
      examplesTitle: "Try an example",
      exHinglish: "Hinglish SMS",
      exScam: "Scam email",
      exSafe: "Normal message",
      why: "Why this result",
      extracted: "Text read from the screenshot",
      again: "Check another",
      checking: "Checking…",
      imageChecking: "Reading screenshot…",
      verdict_safe: "Likely safe",
      verdict_suspicious: "Suspicious",
      verdict_likely_scam: "Likely a scam",
      verdict_scam: "This is a scam",
      advice_safe: "No scam signals found. Still use normal caution with links and money.",
      advice_suspicious: "Something looks off. Don't click links or share codes. Check with the company or person using a number you already have.",
      advice_likely_scam: "Very likely a scam. Don't reply or send anything. Verify independently before acting.",
      advice_scam: "Stop. Don't send money, codes, or personal details. Block the sender and warn your family.",
      score: "Risk score",
      playbook: "Known scam playbook",
      chat: "Chat pattern",
      imageError: "Couldn't read any text from that image.",
      errorPrefix: "Something went wrong: ",
      disclaimer: "This is a helper, not a guarantee. If money or personal details are involved, verify with a number you already have — never the one in the message. India: report at 1930. US: ReportFraud.ftc.gov.",
      privacy: "scamcheck runs locally — no data leaves this device."
    },
    hi: {
      tagline: "मुफ़्त, निजी, और आपके ही डिवाइस पर चलता है। कुछ भी अपलोड नहीं होता।",
      pasteLabel: "जो संदेश मिला है उसे यहाँ चिपकाएँ",
      placeholder: "SMS, WhatsApp संदेश या ईमेल यहाँ चिपकाएँ…",
      senderLabel: "भेजने वाले का नंबर (वैकल्पिक)",
      senderPlaceholder: "+91 98765 43210 या VM-HDFCBK",
      senderBlocked: "यह नंबर आपकी ब्लॉकलिस्ट में है:",
      senderAllowed: "यह नंबर आपकी अनुमति-सूची में है:",
      senderReported: "यह नंबर सार्वजनिक सूची में शिकायत किया गया है:",
      senderPremium: "यह प्रीमियम-रेट नंबर है (महँगा):",
      senderNeutral: "भेजने वाला:",
      mentionedNumber: "संदेश में जोखिम भरा नंबर है:",
      checkBtn: "संदेश जाँचें",
      clearBtn: "साफ़ करें",
      keyHint: "सुझाव: जाँचने के लिए Ctrl/⌘ + Enter दबाएँ।",
      imageLabel: "या स्क्रीनशॉट जाँचें",
      chooseImage: "तस्वीर चुनें…",
      pasteImageHint: "आप इस पेज पर कहीं भी स्क्रीनशॉट पेस्ट (⌘/Ctrl+V) कर सकते हैं।",
      examplesTitle: "उदाहरण देखें",
      exHinglish: "हिंग्लिश SMS",
      exScam: "ठगी वाला ईमेल",
      exSafe: "सामान्य संदेश",
      why: "यह नतीजा क्यों",
      extracted: "स्क्रीनशॉट से पढ़ा गया टेक्स्ट",
      again: "दूसरा संदेश जाँचें",
      checking: "जाँच हो रही है…",
      imageChecking: "स्क्रीनशॉट पढ़ा जा रहा है…",
      verdict_safe: "संभवतः सुरक्षित",
      verdict_suspicious: "संदिग्ध",
      verdict_likely_scam: "संभवतः ठगी",
      verdict_scam: "यह ठगी है",
      advice_safe: "ठगी का कोई संकेत नहीं मिला। फिर भी लिंक और पैसे के मामले में सामान्य सावधानी रखें।",
      advice_suspicious: "कुछ गड़बड़ लग रही है। लिंक पर क्लिक न करें, कोड साझा न करें। कंपनी या व्यक्ति से उसी नंबर पर संपर्क करें जो आपके पास पहले से है।",
      advice_likely_scam: "बहुत संभावना है कि यह ठगी है। जवाब न दें, कुछ न भेजें। कुछ भी करने से पहले स्वयं जाँचें।",
      advice_scam: "रुकिए। पैसे, OTP/कोड या निजी जानकारी न भेजें। भेजने वाले को ब्लॉक करें और परिवार को बताएँ।",
      score: "जोखिम स्कोर",
      playbook: "ज्ञात ठगी का तरीका",
      chat: "चैट का पैटर्न",
      imageError: "इस तस्वीर से कोई टेक्स्ट नहीं पढ़ा जा सका।",
      errorPrefix: "कुछ गलत हो गया: ",
      disclaimer: "यह टूल मदद के लिए है, गारंटी नहीं। पैसे या निजी जानकारी का मामला हो तो उसी नंबर पर जाँचें जो आपके पास पहले से है — संदेश वाले नंबर पर कभी नहीं। भारत में साइबर ठगी की शिकायत 1930 पर करें।",
      privacy: "scamcheck आपके डिवाइस पर चलता है — कोई डेटा बाहर नहीं जाता।"
    }
  };

  var EXAMPLES = {
    hinglish: "Dear customer aapka KYC expire ho gaya hai. KYC update karein warna aapka bank account band ho jayega. bit.ly/kyc-now",
    bec: "Please note our bank details have changed. Kindly remit the outstanding invoice to the new IBAN before close of business today. Do not call the office, only reply by email.",
    safe: "Hi mom, reached the airport. Will call you in 2 hours, love you!"
  };

  var VERDICT_KEYS = {
    "LIKELY SAFE": "safe",
    "SUSPICIOUS": "suspicious",
    "LIKELY SCAM": "likely_scam",
    "SCAM": "scam"
  };
  var CLASSES = { safe: "safe", suspicious: "warn", likely_scam: "likely", scam: "scam" };
  var ICONS = { safe: "✅", suspicious: "⚠️", likely_scam: "🚨", scam: "🛑" };

  var lang = localStorage.getItem("scamcheck-lang") || "en";
  var lastResult = null;
  var lastImageText = null;
  var busy = false;

  function t(key) {
    return (STRINGS[lang] && STRINGS[lang][key]) || STRINGS.en[key] || key;
  }

  var els = {
    msg: document.getElementById("msg"),
    sender: document.getElementById("sender"),
    check: document.getElementById("check"),
    clear: document.getElementById("clear"),
    file: document.getElementById("file"),
    pick: document.getElementById("pick"),
    drop: document.getElementById("drop"),
    error: document.getElementById("error"),
    result: document.getElementById("result"),
    icon: document.getElementById("verdict-icon"),
    verdict: document.getElementById("verdict"),
    advice: document.getElementById("advice"),
    bar: document.getElementById("bar-fill"),
    scoreLabel: document.getElementById("score-label"),
    playbook: document.getElementById("playbook"),
    why: document.getElementById("why"),
    reasons: document.getElementById("reasons"),
    extracted: document.getElementById("extracted"),
    extractedText: document.getElementById("extracted-text"),
    numberInfo: document.getElementById("number-info"),
    again: document.getElementById("again")
  };

  function applyLang() {
    document.documentElement.lang = lang === "hi" ? "hi" : "en";
    document.querySelectorAll("[data-i18n]").forEach(function (el) {
      el.textContent = t(el.getAttribute("data-i18n"));
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach(function (el) {
      el.placeholder = t(el.getAttribute("data-i18n-placeholder"));
    });
    document.getElementById("lang-en").classList.toggle("active", lang === "en");
    document.getElementById("lang-hi").classList.toggle("active", lang === "hi");
    if (lastResult) render(lastResult, lastImageText);
    if (busy) els.check.textContent = t("checking");
  }

  function setBusy(state, kind) {
    busy = state;
    els.check.disabled = state;
    els.pick.disabled = state;
    if (state) {
      els.check.textContent = kind === "image" ? t("imageChecking") : t("checking");
    } else {
      els.check.textContent = t("checkBtn");
    }
  }

  function showError(message) {
    els.error.textContent = t("errorPrefix") + message;
    els.error.hidden = false;
  }

  function clearError() {
    els.error.hidden = true;
    els.error.textContent = "";
  }

  function describeNumber(num) {
    if (!num) return "";
    var parts = [];
    var s = num.sender;
    if (s) {
      var n = s.number || {};
      var label = n.e164 || n.national || "";
      var status = (s.reputation || {}).status;
      if (status === "blocked") parts.push(t("senderBlocked") + " " + label);
      else if (status === "reported") parts.push(t("senderReported") + " " + label);
      else if (status === "allowed") parts.push(t("senderAllowed") + " " + label);
      else if (n.kind === "premium") parts.push(t("senderPremium") + " " + label);
      else if (label) parts.push(t("senderNeutral") + " " + label);
    }
    (num.mentioned || []).forEach(function (m) {
      var mn = m.number || {};
      var ms = (m.reputation || {}).status;
      if (ms === "blocked" || ms === "reported" || mn.kind === "premium") {
        parts.push(t("mentionedNumber") + " " + (mn.e164 || mn.national || ""));
      }
    });
    return parts.join(" · ");
  }

  function render(res, imageText) {
    lastResult = res;
    lastImageText = imageText || null;
    var key = VERDICT_KEYS[res.final_verdict] || "suspicious";
    var cls = CLASSES[key];

    els.result.hidden = false;
    els.result.className = "card result " + cls;
    els.icon.textContent = ICONS[key];
    els.verdict.textContent = t("verdict_" + key);
    els.advice.textContent = t("advice_" + key);

    var score = typeof res.score === "number" ? Math.max(0, Math.min(100, res.score)) : 0;
    els.bar.style.width = score + "%";
    els.scoreLabel.textContent = t("score") + " " + score + "/100";

    if (res.scripts && res.scripts.length) {
      els.playbook.textContent = t("playbook") + ": " + res.scripts.join(" · ");
    } else if (res.conversation) {
      els.playbook.textContent = t("chat") + ": " + res.conversation.verdict +
        " (" + res.conversation.message_count + ")";
    } else {
      els.playbook.textContent = "";
    }

    var numText = describeNumber(res.number);
    els.numberInfo.textContent = numText;
    els.numberInfo.hidden = !numText;

    els.reasons.textContent = "";
    (res.reasons || []).forEach(function (pair) {
      var li = document.createElement("li");
      li.textContent = pair[0];
      if (pair[1]) {
        var w = document.createElement("span");
        w.className = "w";
        w.textContent = "  +" + pair[1];
        li.appendChild(w);
      }
      els.reasons.appendChild(li);
    });
    els.why.hidden = !(res.reasons && res.reasons.length);

    if (imageText) {
      els.extracted.hidden = false;
      els.extractedText.textContent = imageText;
    } else {
      els.extracted.hidden = true;
      els.extractedText.textContent = "";
    }

    els.result.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function postJSON(path, body) {
    return fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (resp) {
      return resp.json().catch(function () { return {}; }).then(function (data) {
        if (!resp.ok) {
          throw new Error(data.error || ("HTTP " + resp.status));
        }
        return data;
      });
    });
  }

  function checkText(text) {
    if (!text || !text.trim()) {
      els.msg.focus();
      return Promise.resolve();
    }
    clearError();
    setBusy(true, "text");
    var body = { text: text };
    var sender = els.sender.value.trim();
    if (sender) body.sender = sender;
    return postJSON("/v1/analyze", body)
      .then(function (data) { render(data, null); })
      .catch(function (err) { showError(err.message || String(err)); })
      .then(function () { setBusy(false); });
  }

  function fileToBase64(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onerror = function () { reject(new Error("read failed")); };
      reader.onload = function () {
        var s = String(reader.result || "");
        var comma = s.indexOf(",");
        resolve(comma >= 0 ? s.slice(comma + 1) : s);
      };
      reader.readAsDataURL(file);
    });
  }

  function checkImage(file) {
    if (!file || !/^image\//.test(file.type || "")) {
      return Promise.resolve();
    }
    clearError();
    setBusy(true, "image");
    return fileToBase64(file)
      .then(function (b64) {
        var body = { image_b64: b64 };
        var sender = els.sender.value.trim();
        if (sender) body.sender = sender;
        return postJSON("/v1/check-image", body);
      })
      .then(function (data) { render(data, data.extracted_text || ""); })
      .catch(function (err) { showError(err.message || t("imageError")); })
      .then(function () { setBusy(false); });
  }

  els.check.addEventListener("click", function () { checkText(els.msg.value); });
  els.clear.addEventListener("click", function () {
    els.msg.value = "";
    els.sender.value = "";
    els.result.hidden = true;
    lastResult = null;
    lastImageText = null;
    clearError();
    els.msg.focus();
  });
  els.again.addEventListener("click", function () {
    els.result.hidden = true;
    lastResult = null;
    lastImageText = null;
    els.msg.value = "";
    els.sender.value = "";
    els.msg.focus();
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
  els.msg.addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      checkText(els.msg.value);
    }
  });

  document.querySelectorAll("[data-example]").forEach(function (chip) {
    chip.addEventListener("click", function () {
      var name = chip.getAttribute("data-example");
      els.msg.value = EXAMPLES[name] || "";
      els.sender.value = "";
      checkText(els.msg.value);
    });
  });

  document.getElementById("lang-en").addEventListener("click", function () {
    lang = "en"; localStorage.setItem("scamcheck-lang", lang); applyLang();
  });
  document.getElementById("lang-hi").addEventListener("click", function () {
    lang = "hi"; localStorage.setItem("scamcheck-lang", lang); applyLang();
  });

  els.pick.addEventListener("click", function (e) {
    e.stopPropagation();
    els.file.click();
  });
  els.drop.addEventListener("click", function (e) {
    if (e.target === els.pick) return;
    els.file.click();
  });
  els.drop.addEventListener("keydown", function (e) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      els.file.click();
    }
  });
  els.file.addEventListener("change", function () {
    if (els.file.files && els.file.files[0]) {
      checkImage(els.file.files[0]);
      els.file.value = "";
    }
  });

  ["dragenter", "dragover"].forEach(function (name) {
    els.drop.addEventListener(name, function (e) {
      e.preventDefault();
      els.drop.classList.add("over");
    });
  });
  ["dragleave", "drop"].forEach(function (name) {
    els.drop.addEventListener(name, function (e) {
      e.preventDefault();
      els.drop.classList.remove("over");
    });
  });
  els.drop.addEventListener("drop", function (e) {
    var dt = e.dataTransfer;
    if (dt && dt.files && dt.files[0]) {
      checkImage(dt.files[0]);
    }
  });

  document.addEventListener("paste", function (e) {
    if (!e.clipboardData) return;
    var items = e.clipboardData.items || [];
    for (var i = 0; i < items.length; i++) {
      if (items[i].type && items[i].type.indexOf("image/") === 0) {
        var file = items[i].getAsFile();
        if (file) {
          e.preventDefault();
          checkImage(file);
        }
        return;
      }
    }
  });

  applyLang();
})();
</script>
</body>
</html>
"""
