# scamcheck Roadmap

Research base: `docs/scam-research-dossier.md` (global scam taxonomy, 2025-26).

## v0.1 ✅ Shipped
- Rule engine (~50 weighted signals), URL/domain forensics (shorteners, IP links,
  punycode, lookalike brands, risky TLDs), verdicts + exit codes, JSON mode,
  optional AI second opinion (OpenAI/Anthropic), self-test suite.

## v0.2 ✅ Shipped — Detection Engine
- **Playbook fingerprinting** (`scamcheck/scripts_lib.py`): 6 full scam
  scripts — pig butchering, task scam, digital arrest, tech-support remote
  access, grandparent/voice-clone, courier/gold handoff.
- **Conversation trajectory analysis** (`scamcheck/conversation.py`): whole-chat
  kill-chain detection (groom → money pivot → deposit extraction →
  withdrawal-block fees → secrecy/pressure). `--chat` flag.
- **URL/QR/deep-link forensics v2**: Telegram login-link takeover, crypto
  payment deep links, SMS/mailto deep links, direct-APK downloads,
  open-redirect URLs, "account upgrade" payment-app phrasing.
- **Local REST API** (`--serve`): `POST /v1/analyze` (single text or full
  conversation), CORS-enabled, `/health`. Foundation for future UIs.

## v0.3 ✅ Shipped — Screenshot & Watcher layer
- **Screenshot → OCR → verdict** (`scamcheck/ocr.py`, `scamcheck --image`):
  three-tier fallback (macOS Apple Vision via JXA → tesseract → AI vision),
  auto-routes multi-line chat screenshots into conversation-trajectory mode,
  OCR-noise tolerance via a half-weight glyph-confusion + fuzzy-vocabulary
  matching pass (`normalize_ocr_text` in rules.py).
- **Clipboard watcher** (`scamcheck --watch`): auto-checks every copied message
  OR pasted screenshot (AppleScript-ObjC for NSPasteboard image access);
  independent dedupe per channel; perfect for assisted family checks.
- **API image endpoint** (`POST /v1/check-image`): file path or base64 body,
  returns verdict + engine + extracted text.
- **Fixes this version**: suspension regex now accepts real-world wording
  ("account is temporarily suspended"); first-person narratives ("my account
  got blocked") no longer score like impersonation scams; "love you mom" is
  family, not romance grooming (affection signal needs repetition or a second
  stage).
- Synthetic screenshot generator (`tests/make_png.py`, stdlib-only bitmap
  font) + honors tests (`tests/test_ocr.py`).

## v0.4 ✅ Shipped — Hindi/Hinglish engine
- **24 new Hindi/Hinglish signals** (`HINDI_SIGNALS` in rules.py): KYC-expiry/
  account-band SMS bait, digital arrest (both scripts), part-time rozana-kamai
  task scams, paise-bhejo extraction, lucky-draw/prize, UPI-transfer demands,
  SIM-blocks, free recharge. Devanagari patterns use explicit lookaround word
  edges — Python's `\b` treats Devanagari matras as non-word chars.
- **Hinglish conversation stages** (conversation.py): greetings, grooming,
  hook ("galat number"), private-move, pivot ("paisa double"), platform,
  deposit ("recharge karo", "upi id"), fee-block ("paisa atka", "GST bharna"),
  pressure ("waqt nahi", "jaldi karo"), secrecy ("kisi ko batana mat") — all
  unioned into the English stage patterns; the kill-chain shape detector now
  reads Indian task-scam transcripts end to end.
- **Playbook beats in Hinglish** (scripts_lib.py): DIGITAL ARREST
  ("aapke khilaf case", "jamanat", "kisi ko batana mat"), TASK SCAM
  ("part-time kaam", "rozana kamai", "paisa atka"), PIG BUTCHERING
  ("pyar", "meri jaan", "kamai"), tech-support & grandparent variants.
- **OCR language packs**: tesseract `-l` now auto-includes every installed
  Indian pack (`hin`, `mr`, `ben`, ...) via `--list-langs`; AI-vision prompt
  pins "do not translate, keep original script". Verified: this machine's
  Apple Vision lists hi-IN but has **no usable Devanagari model** — devanagari
  screenshots must ride tesseract (`brew install tesseract-lang`) or the AI
  tier; English OCR unaffected.
- Tests: Hindi/Hinglish samples + `hinglish_task` trajectory added to the
  regression suite; Devanagari benign-family texts stay LIKELY SAFE.

## v0.5 ✅ Shipped — Playbook depth + batch mode
- **7 new playbooks** (scripts_lib.py): INVOICE/BEC payment diversion,
  SEXTORTION blackmail, RENTAL/PROPERTY deposit, TOLL/PARKING/FINE smishing,
  FAKE BANK APP/APK install, ROMANCE (non-investment) military-doctor, and
  FAMILY NEW-NUMBER imposter (three mandatory beats so a genuine
  "this is my new number" cannot match).
- **Rule signals to match**: changed-bank-details BEC, compromising-material +
  leak-threat pair, unpaid toll/fine, pay-before-viewing/absent-owner rental,
  new-number + money-request pair, APK-install-from-link. All weight 14–16,
  so a lone signal is SUSPICIOUS and the playbook lock supplies SCAM.
- **Batch mode** (`--batch FILE`): blank-line-separated messages (SMS export
  friendly), `-` for stdin, `--json` array, `--chat` for transcript blocks;
  summary table + exit code driven by the worst message.
- **Guard against false positives**: negative test cases (ordinary invoice
  email, ordinary new-number text, toll balance reminder, normal rental ad)
  must NOT fingerprint any playbook — that is now regression-tested.

## v0.6 ✅ Shipped — Family web UI
- **One-page family UI at `GET /`** (`scamcheck/webui.py`, served by
  `--serve`): paste a message or a screenshot (file picker, drag-drop, or
  Ctrl/⌘+V anywhere), get a plain-language verdict plus what to do next.
- **Built for the guardian moment**: 19px base type, 56px primary button,
  high contrast + dark mode, keyboard shortcuts, ARIA live result, nothing
  auto-submitted.
- **English / हिंदी toggle** (remembered in localStorage) for UI labels,
  verdicts, guidance and reporting info — the detector is language-agnostic.
- **Screenshots stay local**: paste → `/v1/check-image` → OCR on-device;
  the extracted text is shown so the user can see what was read.
- **Security**: strict same-origin CSP (`default-src 'none'`), no external
  assets, `nosniff`, localhost by default; `--host 0.0.0.0` opt-in warns about
  no authentication.
- Tests (`tests/test_api_ui.py`): page + CSP headers, health, analyze
  (Hinglish scam vs normal), 400s, base64 image OCR, 404s, favicon; plus a
  headless CDP interaction pass (example click, Hindi switch, clear, keyboard).

## v0.7 ✅ Shipped — Phone-number intelligence
- **Number parsing & range facts** (`scamcheck/phones.py`): international /
  national / `00` / bare-digit input, SMS shortcodes (`57575`), alphanumeric
  sender IDs (`VM-HDFCBK`), E.164 output, per-country length validation, and
  premium-rate detection (IN 1900, US/CA 900, UK 09, AU 190x).
- **Local reputation, zero network on analyze**: `~/.scamcheck/blocklist.txt`,
  `allowlist.txt` (allow wins), labels, `--block/--allow/--forget`,
  `--show-lists`, `--import-list` (TXT/CSV, `--import-allow`).
- **Opt-in cached feeds**: feed-agnostic `feeds.conf` (`URL | label | format`),
  `--update-feeds` is the only network-touching command, HTTPS-only (localhost
  HTTP allowed for self-hosting), 25 MB / 200k-entry caps, failed refreshes keep
  the previous cache, `--feed-status`. **No default feeds** — there is no
  trustworthy free bulk phone-number list; OpenPhish/PhishTank are URL feeds.
- **Analyzer integration**: `--sender`, `--number`, batch auto-detects
  `From:`/`Sender:` lines; signals for blocklist (+45, LIKELY SCAM floor),
  feed reports (+25, SUSPICIOUS floor), premium numbers (+15), foreign sender
  vs local bank/currency cues (+12), allowlist (−20). Number evidence can raise
  a verdict, never lower a text verdict.
- **API + UI**: `POST /v1/check-number`, `sender`/`region` on
  `/v1/analyze` and `/v1/check-image`; optional sender field in the family UI
  (EN/HI) showing blocklist / reported / premium status inline.
- Region config (`--set-region`, `SCAMCHECK_REGION`, default IN).
- Tests (`tests/test_phones.py`): 12 normalization cases, extraction noise
  (OTPs/amounts/order IDs), list precedence, TXT/CSV import, local-HTTP feed
  refresh + cache retention on failure, HTTPS enforcement, analyzer floors,
  CLI modes, batch sender detection, API endpoints.

## v0.8 ✅ Shipped — Telegram + WhatsApp bots
- **Shared bot core** (`scamcheck/bot.py`): one `analyze()` path for text and
  screenshots, verdict/advice/signal replies in English or हिंदी, per-chat
  language + remembered sender, local prefs (`bot_prefs.json`), per-chat rate
  limit (20/hour, `SCAMCHECK_BOT_RATE`). AI stays off by default
  (`SCAMCHECK_BOT_AI`); checks are local.
- **Telegram** (`--bot telegram`): long polling (`getUpdates`), no public URL,
  text + photos/photo documents (`getFile` → OCR), commands `/lang`, `/sender`,
  `/check`, `/status`, `/help`. Token via `SCAMCHECK_TELEGRAM_TOKEN` or
  `--bot-token`.
- **WhatsApp Cloud API** (`--bot whatsapp`): `GET/POST /webhook/whatsapp`,
  challenge verification, optional `X-Hub-Signature-256` HMAC, immediate ack +
  background processing, message-ID dedupe, text + image media download, reply
  via Graph API. Defaults to `127.0.0.1:8766` (tunnel/reverse proxy for Meta).
- **`--bot-status --json`**: shows configured tokens (masked), phone id, region,
  rate limit, prefs path, cached feeds — no network.
- **Tests** (`tests/test_bot.py`): reply formatting EN/HI, commands, sender
  effect, `/check`, rate limit, screenshot OCR, fake Telegram API (text + photo,
  getUpdates/getFile/sendMessage), fake Graph API + webhook verification, wrong
  token, text/image replies, retry dedupe, HMAC accept/reject, CLI status.

## v0.9 ✅ Shipped — JARVIS core
- **Console** (`scamcheck --jarvis`, `scamcheck/jarvis.py`): one intent router
  for text checks, screenshots, QR/barcodes, URL investigation, number intel,
  block/allow/forget, sender attach, history/search/why, language, region,
  voice, notifications and status. Bare text is checked directly; piped stdin
  works for scripting.
- **Local memory** (`~/.scamcheck/history.db`, SQLite, `0600`): every console
  and `--watch` check stores verdict/score/text plus identifier rows (exact
  message hash, URL hosts, phone/sender numbers). `seen_before` powers
  "seen this before" / "new to me" notes across sessions; `history [n]`,
  `search`, `history clear` and `--why` expose it. No sync, no telemetry.
- **Voice + alerts**: macOS `say` speaks risky verdicts, Notification Center
  shows macOS notifications; both are opt-in (`--voice`, `--notify`) and
  default to SUSPICIOUS or worse. `SCAMCHECK_VOICE_NAME[_HI]`,
  `SCAMCHECK_SAY_CMD` (tests/custom TTS), `SCAMCHECK_ANNOUNCE_ALL` overrides.
- **URL forensics on demand** (`scamcheck/netintel.py`): redirect chain,
  final URL/title, TLS issuer/version, RDAP registration age, notes for HTTP,
  raw IP, punycode, shorteners, multi-hop and cross-domain redirects. Explicit
  `url` command only; private/loopback targets (including DNS that resolves
  private) are refused. Normal checks stay offline.
- **QR/barcode decoding** (`ocr.py`, Vision `VNDetectBarcodesRequest`): QR-only
  screenshots work, payloads feed the normal analyzer, `--image --json`
  carries a `qr` array, and `qr <path>` decodes without following anything.
- **Ambient watch**: `--watch` records to memory and honors voice/notify;
  `--screenshot-dir DIR` additionally checks the 10 newest existing images and
  then every new/changed screenshot in that folder. Ambient AI is local-only
  by default (`SCAMCHECK_WATCH_AI=auto|always` is the explicit opt-in).
- **Tests** (`tests/test_jarvis.py`): SQLite persistence + `0600`, intents,
  Hindi replies, sender/list flows, repeat detection, local HTTP redirect +
  private-address refusal, screenshot OCR, blank-image grace, CoreImage QR
  generation → decode → analysis, fake `say` + notify hooks, history clear, and
  piped `--jarvis` / `--image --json` CLI runs.

### Known boundaries
- Voice/notifications and QR decoding are macOS-native (Apple Vision / `say` /
  Notification Center); the console and all detection work elsewhere.
- No always-listening wake word, call monitoring or cloud sync yet. `url` reads
  public HTTP(S) metadata but is not a malware sandbox.

## v0.10 ✅ Shipped — Guardian + evidence
- **Evidence cases** (`scamcheck/cases.py`, `--case-*`): SQLite case store
  (`cases.db`, `0600`) plus a private vault (`cases/<id>/`, `0700`); text and
  file evidence hashed with SHA-256 at collection time, automatic entity
  extraction from evidence, timeline events, status/loss/notes, and `verify`
  to detect later edits.
- **Case packs** (`--case-export`): `case.json`, `case.md`, `case.html`,
  `SHA256SUMS` and an `evidence/` folder; best-effort `case.pdf` through
  weasyprint / wkhtmltopdf / local Chrome. Complaint drafts via `--report`
  and JARVIS `report <case-id>`.
- **Richer entity extraction** (`scamcheck/intel.py`): URLs/domains, phone
  numbers, senders, emails, UPI IDs, BTC/ETH/TRX wallets, IFSC codes, Telegram
  handles, WhatsApp invites and APK links; one normalizer shared by memory,
  cases, watchlists and campaigns.
- **Watchlists** (`scamcheck/watchlist.py`, `--watch-add/--watchlist`): local
  exact-match indicators with hit counters; one-shot CLI results and JARVIS
  checks append a warning (JSON gets a `watchlist` array; stdout stays valid).
- **Campaign clustering** (`scamcheck/campaigns.py`, `--campaigns`): union-find
  over `history.db` identifier rows, grouping checks that share a phone, domain,
  UPI ID, wallet, email, Telegram/WhatsApp handle, IFSC or APK. Exact-message
  hashes are excluded so forwards do not link unrelated campaigns.
- **Recovery playbooks** (`scamcheck/recovery.py`, `--recover`): country-aware
  authorities for IN/US/GB/AU/CA/SG/AE/NZ/ZA, scam-type playbooks (UPI, bank,
  card, crypto, investment, job, romance, sextortion, identity, tech support,
  digital arrest, courier, loan, OTP) and an editable complaint template.
- **JARVIS integration**: `case`, `watch`, `watchlist`, `campaigns`,
  `campaign`, `recover` and `report` routes; status shows case/watchlist counts.
- **Tests** (`tests/test_cases.py`): entities, case lifecycle/hash/tamper
  detection/export, watchlists, campaigns, recovery/report, CLI JSON and
  JARVIS routes.

### Known boundaries
- PDF export depends on an external local converter; HTML/MD/JSON always work.
- The vault and databases are unencrypted (`0600`); full-disk encryption or an
  encrypted volume is recommended for sensitive cases.
- Campaigns/watchlists are per-machine only; there is no shared indicator feed.

## v0.11 ✅ Shipped — Intelligence layer
- **Explainable intelligence** (`scamcheck/intelligence.py`, `--intel`): scam
  type + confidence, kill-chain stage, attacker goals, payment rails (UPI,
  bank/IFSC, card, crypto, gift card, payment app), named impersonation,
  channels, tactics, likely next moves, verification steps, safe replies and
  evidence guidance. Fully deterministic and offline; attached to every JSON
  result as `intelligence`.
- **Deobfuscation + evasion scoring**: removes zero-width/bidi controls,
  normalizes full-width text, repairs Cyrillic/Greek homoglyphs inside Latin
  words, collapses letter-spacing/separator tricks, conservatively de-leets
  scam words and repairs disguised URLs (`hxxp`, `[.]`, `(dot)`). The repaired
  variant is a secondary rules pass; deliberate evasion also adds a capped
  score penalty and an explicit reason.
- **Stage model**: whole chats use the conversation trajectory (groom → pivot →
  platform → deposit → fee → pressure → secrecy); single messages infer the
  furthest money stage from cues. Pressure/isolation are treated as tactics
  when a monetary stage is present.
- **Safe guidance, not just a score**: type-aware verification, non-committal
  replies, "best is no reply" policy on high-risk messages, and type-specific
  evidence preservation.
- **Surfaces**: concise intel lines in CLI human output and bot replies; full
  briefings via `--intel`, JARVIS `assess <text>`, `brief`, `next`, `reply`;
  the Telegram/WhatsApp bots add type + first next move.
- **Tests** (`tests/test_intelligence.py`): obfuscation transformations and
  false-positive guards, bank/investment/benign assessments, conversation
  stage, next moves, safe replies, CLI JSON/`--intel`, bot and JARVIS routes.

### Known boundaries
- Patterns are English-first; Hindi/Hinglish detection still works through the
  rule and conversation layers, but the intel labels themselves are English.
- Attackers adapt wording; next-move prediction is a playbook prior, not a
  guarantee. Verification advice remains the safety-critical part.
- Deobfuscation is conservative by design: it repairs known disguises rather
  than rewriting arbitrary text.

## v0.12 ✅ Shipped — Device & LAN audit
- **Read-only device audit** (`scamcheck/deviceaudit.py`, `--device-audit`):
  macOS security posture (SIP, FileVault, Gatekeeper, firewall, Remote Login,
  MDM, guest/auto-login, updates, XProtect/MRT), processes, persistence
  (LaunchAgents/Daemons, login items, background tasks, cron/`at`, shell
  profiles, SSH keys, configuration profiles), browser extensions and
  native-messaging hosts, network state, recent downloads/quarantine events,
  temp/shared executables, unsigned apps, system/kernel extensions.
- **Mobile best effort**: connected iOS inventory and optional Android ADB
  checks (properties, third-party packages, device admins, accessibility
  services, root indicator); per-platform checklists for iOS, Android, TV,
  router, Windows and Linux when deep access is unavailable.
- **Private-LAN inventory**: ARP-based device list with vendor/device guessing;
  opt-in `--device-active` TCP connect probes to common ports on RFC1918/
  link-local IPv4 only, capped at 64 hosts. No exploitation, logins, packet
  capture or public-IP scanning.
- **Local report export**: JSON + Markdown + SHA256SUMS under
  `~/.scamcheck/device-reports/<timestamp>/` (mode `0700`), or `--device-out`.
- **Surfaces**: CLI flags (`--device-audit`, `--device-full`, `--device-active`,
  `--device-no-lan`, `--device-no-mobile`, `--device-max-hosts`,
  `--device-out`, `--json`) and JARVIS routes (`scan device`,
  `scan device full|active`, `scan network [active]`); status shows audit
  readiness.
- **Tests** (`tests/test_deviceaudit.py`): private-IP guard, command/path
  parsers, scoring/sorting, device guessing, TCP probe, report formatting,
  private export + hash verification, passive CLI JSON, JARVIS routes.

### Known boundaries
- Not an antivirus: no signature engine, memory scanning, quarantine or
  remediation. It reports suspicious state for a human to review.
- Deep iOS/iPadOS/tvOS/Android inspection needs a per-device agent or
  authorized ADB; without it those devices get inventory + checklists only.
- Unprivileged mode skips protected logs, some system daemons and firewall
  internals. LAN results depend on ARP visibility and are connect-only.

## v0.13 — Planned
- [ ] Multilingual expansion beyond Hindi (Tamil/Telugu/Bengali bait, per
  I4C loss leaders) — needs native-speaker specimens
- [ ] OCR robustness on real-world screenshots: dark mode, Devanagari/Tamil/
  emoji-heavy chats, mixed scripts (needs real specimens to tune against)
- [ ] Non-Apple QR fallback
- [ ] Encrypted case vault and an encrypted/retention-limited `history.db`
- [ ] Investigator export presets (bank vs police vs platform) and redaction
- [ ] Opt-in local wake-word mode (explicit microphone consent, no cloud)

## Launch track — open source (v0.13 → v1.0)

Market research, competitive analysis and the 90-day plan live in
[`LAUNCH.md`](LAUNCH.md). This section tracks only the engineering work.

### Shipped
- [x] **MCP stdio server** (`scamcheck --mcp`, `scamcheck/mcp.py`): six tools —
  `check_message`, `check_url`, `check_number`, `extract_entities`,
  `open_case`, `scamcheck_info`. Offline by default; `check_url` is the only
  networked tool and refuses private/loopback targets. Results returned as both
  model-readable text and `structuredContent`. Covered by `tests/test_mcp.py`.
- [x] **Repository hygiene**: MIT `LICENSE`, `.gitignore`, GitHub Actions CI
  (Python 3.9/3.11/3.13 on Linux, 3.13 on macOS, plus the Next.js build),
  `SECURITY.md`, `CONTRIBUTING.md`.
- [x] **README repositioned** around the triage-and-evidence pipeline instead
  of "SMS checker", with MCP, a cheat sheet, personas and explicit limits.

### Next (in order)
- [ ] Publish to PyPI; reserve `scamcheck` on PyPI and npm
- [ ] Homebrew tap + `Dockerfile`
- [ ] Versioned `--json` schema document (`docs/json-schema.md`)
- [ ] **Benchmark harness** — precision/recall on scam specimens *and*
  false-positive rate on legitimate bank/OTP/delivery messages; results table
  in the README
- [ ] MCP directory listings (Smithery, mcp.so, awesome-mcp-servers)
- [ ] Demo recording (asciinema + 90s video)
- [ ] `good first issue` seeds: translations, playbooks, Docker, Homebrew,
  STIX stub

### Later
- [ ] Rule/playbook pack SDK (YAML/JSON + `scamcheck rules validate`), signed
  packs, `--import-pack`
- [ ] STIX 2.1 export + MISP/OpenCTI connector
- [ ] IMAP ingestion for BEC
- [ ] Thin browser extension over the localhost API
- [ ] Android (Termux guide first, native app later)
- [ ] Encrypted case vault; auth for `--serve`
- [ ] Local LLM adapter (Ollama / llama.cpp) for a fully offline second opinion
- [ ] Opt-in community indicator packs (hashed indicators, never message text)

## v1.0 — Product shapes
- [ ] Family guardian flow beyond one device: shared checks, "ask a guardian"
  hand-off (server-side consent, no message content leaves the LAN)
- [ ] Long-horizon bot-detection heuristics (per USENIX 26: fine-motor
  challenge tasks humans still beat LLMs at)

## Ideas parking lot
- Voice-clone detection: short-audio spectral heuristics (research shows humans
  detect ~cold); family safe-word protocol as UX feature
- Sharing campaign indicators between trusted devices without a central server
  (signed bundles, explicit import/export)
