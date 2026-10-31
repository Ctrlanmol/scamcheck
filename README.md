# scamcheck

**Offline-first scam triage and evidence kit.**

One message in → an explainable verdict, the exact signals that fired, the scam
playbook, what the attacker will try next, and a tamper-evident case file out.

No API keys. No dependencies. No telemetry. Python 3.9+ and nothing else.

[![CI](https://github.com/Ctrlanmol/scamcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Ctrlanmol/scamcheck/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](pyproject.toml)
[![Network](https://img.shields.io/badge/network-off%20by%20default-brightgreen)](#what-it-is-not)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Most scam tools ask you to upload the victim's messages to someone else's
server. scamcheck runs the analysis where the message already is — on your
machine — and keeps the evidence there too. That makes it usable on material
you would never paste into a website: a family member's SMS, a leaked chat
export, a client's complaint file.

```text
message ──▶ normalize ──▶ signals + playbook ──▶ verdict (explained)
                              │
                              ├──▶ intelligence: type, stage, next move, verify
                              ├──▶ indicators: phones, UPI, wallets, domains
                              └──▶ case: SHA-256 custody, timeline, export
```

## Why it is different

1. **Deterministic and explainable.** Every verdict lists the signals that
   produced it, with weights. Same input → same output, every time. No model
   drift, no API dependency, no "trust me". You can diff two versions of the
   engine and see exactly what changed.
2. **Offline by default.** Analysis never opens a socket. The only networked
   actions are explicit and opt-in: `--update-feeds`, `url <link>`,
   `check_url` over MCP, the chat bots, and an AI key you set yourself.
3. **Evidence-grade.** Cases hash every artefact at collection time
   (SHA-256), record a timeline, extract entities, and export a pack with a
   `SHA256SUMS` file. `--case-verify` detects later tampering. Very few
   open-source detection tools go past "here is a score".

## Install

```bash
git clone https://github.com/Ctrlanmol/scamcheck.git
cd scamcheck
python3 -m pip install -e .
scamcheck --version
```

There is nothing else to install — the Python core is standard library only.
If you would rather not install anything, every command below also works as
`python3 -m scamcheck ...` from the repo root.

## Demo

```console
$ scamcheck "Dear customer, your KYC is expiring today. Verify now at http://bit.ly/x1y2z or your account will be blocked within 24 hours."

🚨  VERDICT: SCAM
   Rules score: ██████████████░░░░░░░░  63/100
   Intel: This matches bank transfer fraud (current stage: building trust / making contact). Likely goal: get you to send money.
   Stage: building trust / making contact
   Likely next: They will move the chat to WhatsApp or Telegram where moderation is weaker.

   Why (4 signals):
   • Shortened URL hides the real destination: bit.ly (severity 25 [+25 points])
   • Threatens account suspension (severity 18.0 [+18.0 points])
   • KYC urgency trick (common bank-scam opener) (severity 12.0 [+12.0 points])
   • Manufactured urgency (severity 8.0 [+8.0 points])
```

`--intel` adds the full briefing: scam type and confidence, kill-chain stage,
attacker goals, payment rail, impersonated brand, five likely next moves,
independent verification steps, safe replies, and what evidence to preserve.

```console
$ scamcheck --intel "..." | head -20

🧠 Intelligence briefing

  This matches bank transfer fraud (current stage: building trust / making contact). Likely goal: get you to send money.

Type:        bank transfer fraud (confidence: high)
Stage:       building trust / making contact
Goal:        Get you to send money; Take over or freeze your account; Collect your identity documents
Payment:     Bank account / transfer
Channel:     SMS / chat (format not stated)
Tactics:     Artificial urgency or a countdown; Threats: block, freeze, fine, arrest or loss; False familiarity or trust-building

Likely next moves:
  • They will move the chat to WhatsApp or Telegram where moderation is weaker.
  • They will build rapport before mentioning money at all.
  • A 'bank officer' may call and ask for your OTP/PIN or a transfer to a 'safe account'.
  • They may send a fake case ID or freeze notice with a tight deadline.
  • They may ask you to install a remote-access or 'bank update' app.
```

## Use it from an AI agent (MCP)

scamcheck ships a stdio MCP server, so any agent that speaks Model Context
Protocol can triage a message without shipping it to a cloud model.

```bash
scamcheck --mcp
```

```json
{
  "mcpServers": {
    "scamcheck": { "command": "scamcheck", "args": ["--mcp"] }
  }
}
```

| Tool | Network | What it returns |
|---|---|---|
| `check_message` | no | verdict, score, signals, playbook, full intelligence briefing |
| `check_url` | **yes** | redirect chain, TLS, RDAP age, punycode/raw-IP flags |
| `check_number` | no | E.164, country, line type, premium ranges, local reputation |
| `extract_entities` | no | phones, UPI IDs, wallets, domains, emails, handles, APK links |
| `open_case` | no | a local case with SHA-256 hashed evidence |
| `scamcheck_info` | no | version, capabilities, data directory |

`check_url` is the only tool that touches the network, and it refuses private,
loopback and link-local targets. Everything else is deterministic and local.

## Cheat sheet

```bash
# one message
scamcheck "Your account will be blocked in 24 hours. Verify now: bit.ly/x1y2z"
scamcheck --intel "..."                 # full intelligence briefing

# a whole conversation (pig butchering / task scams)
scamcheck --chat chat_transcript.txt

# files, clipboard, screenshots
scamcheck -f message.txt
pbpaste | scamcheck --stdin
scamcheck --image ~/Desktop/screenshot.png      # OCR + QR decode

# senders and numbers (local lists + cached feeds)
scamcheck "Hi, is this the right number?" --sender "+91 98765 43210"
scamcheck --number "+1 900 555 1234"
scamcheck --block "+91 98765 43210" --label "KYC scam"
scamcheck --allow "+91 98765 43210" --label "my bank"

# watch everything you copy, or a screenshot folder
scamcheck --watch
scamcheck --watch --screenshot-dir ~/Desktop

# machine-readable
scamcheck "..." --json
scamcheck --batch inbox.txt --json      # blank-line separated messages

# local REST API + family web UI
scamcheck --serve                       # http://127.0.0.1:8765

# chat bots
scamcheck --bot telegram                # needs SCAMCHECK_TELEGRAM_TOKEN
scamcheck --bot whatsapp                # needs WHATSAPP_TOKEN + phone id
scamcheck --bot-status

# JARVIS console: text, screenshots, QR, links, numbers, memory
scamcheck --jarvis --voice --notify

# evidence cases + complaint draft (all local)
scamcheck --case-new "UPI fraud" --scam-type upi --loss 5000 --currency INR
scamcheck --case-add CASE_ID screenshot.png
scamcheck --case-verify CASE_ID
scamcheck --case-export CASE_ID
scamcheck --report CASE_ID --country IN --report-out complaint.txt

# watchlists + campaign clustering
scamcheck --watch-add "upi:scammer@okhdfcbank"
scamcheck --watch-add "url:evil-example.xyz"
scamcheck --watchlist
scamcheck --campaigns

# recovery checklist for a scam type and country
scamcheck --recover upi --country IN

# read-only device + private-LAN audit (no sudo)
scamcheck --device-audit --device-full
scamcheck --device-audit --device-active        # TCP probes, own LAN only

# AI agent server
scamcheck --mcp
```

Prefer the browser? `cd web && npm install && npm run dev` starts the full
Next.js interface and documentation site at `http://127.0.0.1:3000`.

To run the test suite:

```bash
python3 tests/run_samples.py
python3 tests/test_batch.py
python3 tests/test_intelligence.py
python3 tests/test_phones.py
python3 tests/test_cases.py
python3 tests/test_webcli.py
python3 tests/test_mcp.py

# macOS only
python3 tests/test_ocr.py
python3 tests/test_deviceaudit.py
```

## Who it is for

| You are | You get |
|---|---|
| **A developer** | `--json`, stable exit codes, a local HTTP API, an MCP server. Filter contact-form spam or support tickets without a vendor. |
| **A security analyst** | IOC extraction, URL metadata (redirects, TLS, RDAP), case packs with hash custody you can attach to a ticket. |
| **Trust & safety / fraud ops** | `--batch` over an inbox export, `--campaigns` to cluster, `--report` for complaint drafts. |
| **An OSINT researcher, journalist or NGO** | Analysis of victim material that never leaves the machine. Works air-gapped. |
| **A privacy-minded individual** | A clipboard watcher and a family web UI with no account, no cloud, no telemetry. |
| **Someone looking after a parent** | `--watch --voice --notify`, a LAN web UI, and a Telegram bot. |
| **An AI agent builder** | `--mcp`: six tools, one of which touches the network. |

## What it is not

Read this before trusting a verdict.

- **Not a threat-intel network.** Reputation comes from your local lists and
  feeds you configure. There is no telemetry, so it cannot know that a number
  was reported by ten thousand other people.
- **Not a browser extension or a mobile app.** It runs where Python runs. A
  thin browser client and an Android build are on the roadmap.
- **Not a malware sandbox.** `url` reads public HTTP(S) metadata. Never open a
  suspect file because a tool said it was "probably fine".
- **Not encrypted at rest.** Case vaults and databases are `0600`/`0700`
  plaintext. Use FileVault or LUKS for sensitive cases; encrypted vaults are
  planned.
- **Not authenticated.** `--serve --host 0.0.0.0` is unauthenticated by design
  (it is meant for your own LAN). Do not expose it to an untrusted network.
- **Not a replacement for a human decision.** A verdict is evidence to reason
  with, not proof of a crime.

## Docs

| File | Contents |
|---|---|
| [`docs/LAUNCH.md`](docs/LAUNCH.md) | Market research, competitive positioning, launch plan, 90-day roadmap |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Shipped history and planned work, version by version |
| [`docs/scam-research-dossier.md`](docs/scam-research-dossier.md) | Scam taxonomy and 2025–26 research base |
| [`SECURITY.md`](SECURITY.md) | Guarantees, limits, safe evidence handling |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to add a playbook, a language or a specimen |

## Contributing

The most useful contributions are small: a new playbook with two mandatory
beats, a new language's signals, a redacted specimen that breaks the engine, or
a translation of the family UI. Start with
[`CONTRIBUTING.md`](CONTRIBUTING.md) and the `good first issue` label.

Please do not open a public issue for a detection bypass that would help a
scammer evade the tool — see [`SECURITY.md`](SECURITY.md).

## License

MIT. Use it, fork it, ship it inside your bank if you like. Attribution is
appreciated, not required.

## How it works

Four layers:

1. **Rule engine (always on, instant, offline)** — ~45 weighted signals covering:
   - urgency & final-warning pressure ("act now", "suspended in 24 hours")
   - banking / OTP / KYC phishing scripts ("verify your account", "do not share this code")
   - lottery, prize, tax-refund, courier-fee and fake-job rackets
   - payment tricks (gift cards, "small processing fee", crypto, wire transfers)
   - link forensics: shortened URLs, raw IP links, punycode/homoglyph domains,
     lookalike brands (`paypa1-secure.xyz`), risky TLDs (`.xyz`, `.top`, `.ru`, …)
   - impersonation of banks & couriers, remote-access app installs (TeamViewer/AnyDesk)

   These combine into a score 0–100 and a verdict:

   | Score | Verdict | Exit code |
   |---|---|---|
   | 0–14 | LIKELY SAFE | 0 |
   | 15–34 | SUSPICIOUS | 1 |
   | 35–59 | LIKELY SCAM | 1 |
   | 60–100 | SCAM | 2 |

2. **Intelligence layer (always on, deterministic)** — maps the signals to a
   scam type, kill-chain stage, attacker goals, payment rails, impersonation,
   likely next moves and a verification/evidence plan. It also repairs common
   obfuscation (zero-width characters, homoglyphs, spacing, disguised URLs) for
   a secondary matching pass. See `--intel` below.

3. **AI second opinion (optional)** — when a message lands in the borderline
   band (or you pass `--ai always`), it's sent to an LLM with the rule findings
   as a hint. High-confidence AI answers can escalate or soften the verdict.

4. **Phone-number evidence (optional)** — a sender number adds range facts
   (premium-rate, shortcode, foreign country vs local bank cues) and local
   reputation hits. It can raise a verdict, never lower the text verdict, and
   is read entirely from disk.

## Intelligence briefing (`--intel`)

A verdict tells you *whether* a message is risky. The intelligence layer tells
you **what kind of operation it is, where it is in the playbook, and what to do
next**. It is deterministic, local and explainable — no LLM and no network — and
it is attached to every `--json` result as `intelligence`.

```bash
python3 -m scamcheck --intel "Hi dear, guaranteed returns on our platform. Deposit 500 USDT. Pay 20% tax to withdraw."
```

The briefing includes:

- **Scam type** and confidence — bank/OTP, UPI, card, crypto, investment/job,
  romance, sextortion, tech support, digital arrest, courier, loan, identity
- **Kill-chain stage** — trust → money pivot → platform → deposit → withdrawal
  fee → pressure → isolation (whole-chat transcripts use the trajectory engine)
- **Attacker goals** — money transfer, crypto deposit, credentials/OTP, remote
  access, identity documents, account takeover, blackmail, advance fee
- **Payment rails** — UPI ID, bank/IFSC, card, crypto address, gift card or
  payment app, with the exact value found in the message
- **Impersonation** — named banks, authorities, delivery firms and payment apps
- **Likely next moves** — the specific escalation this script usually takes
- **Verification steps** — how to check independently, using a channel you find
  yourself rather than the one supplied by the sender
- **Safe replies** — neutral lines if you must respond (with a clear "no reply
  is best" policy on high-risk messages)
- **Evidence guidance** — what to screenshot, export and preserve before blocking
- **Obfuscation report** — zero-width characters, Cyrillic/Greek lookalikes,
  full-width letters, letter-spacing, leetspeak and disguised URLs (`hxxp`,
  `[.]`, `(dot)`)

In JARVIS, `assess <text>` shows the full briefing; `next`, `reply` and `brief`
explain the last check without re-sending the message.

## Enabling the AI layer

Any one of these is enough, then it activates automatically:

```bash
export OPENAI_API_KEY="sk-..."        # OpenAI, or any OpenAI-compatible service
# optional for alternatives / self-hosting:
export OPENAI_BASE_URL="https://api.your-proxy.com/v1"
export SCAMCHECK_AI_MODEL="gpt-4o-mini"

export ANTHROPIC_API_KEY="sk-ant-..."  # or Anthropic
```

No key set, network down, or bad response? The tool silently keeps going with
rules only — it never blocks on AI.

For `--image` OCR, the AI-vision fallback tier uses the same key
(`SCAMCHECK_VISION_MODEL`, default `gpt-4o-mini`) but is only tried when both
local engines are unavailable or produce nothing.

## Screenshot checking (`--image`, `--watch`)

The OCR fallback chain — first available wins:

1. **Apple Vision** (macOS 10.15+): built in, zero installs
2. **Tesseract**: if `tesseract` is on PATH (`brew install tesseract`)
3. **AI vision**: only if an API key is set and both local engines failed

Noisy OCR (OCR-mangled glyphs like `5U5PENDED`, `RCCOUNT`) is matched against
the signals through a separate normalized pass at half weight, so screenshots
still scan even on ugly fonts. QR/barcodes are decoded with Apple Vision too:
a QR-only screenshot works, and the payload is fed through the normal link
analysis (offline — decoding does not open the link). Clipboard HTML/images are
read via AppleScript-ObjC.

## Languages: Hindi / Hinglish / Devanagari

India is the biggest victim market and most of that bait arrives in
**Hinglish** ("aapka account band ho jayega", "rozana kamai") or Devanagari.
v0.4 ships 24 targeted signals, all playbook fingerprints, and the full
conversation-trajectory detector in both scripts — a Hinglish part-time
task-scam WhatsApp transcript scores SCAM end to end.

One OCR caveat: Apple Vision on current macOS lists Hindi as supported but
ships no usable Devanagari model (verified — Devanagari test images OCR as
garbage). For Hindi screenshots either install tesseract's Hindi pack
(`brew install tesseract-lang`, picked up automatically) or enable the AI
vision tier; English/Hinglish-in-Roman OCR is unaffected.

## Batch checking (`--batch`)

Checking a whole inbox export or a pile of forwarded messages:

```bash
scamcheck --batch messages.txt          # blocks separated by blank lines
cat messages.txt | scamcheck --batch -  # or from stdin
scamcheck --batch messages.txt --json   # machine-readable array
scamcheck --batch chats.txt --chat      # each block is a full transcript
```

Each blank-line-separated block is one message by default (SMS exports wrap
lines, and conversation mode would suppress per-message rules). `--chat`
switches to trajectory analysis per block. Exit code is 2 if *any* message is
SCAM/LIKELY SCAM, 1 if any is SUSPICIOUS, else 0 — so it slots into scripts.

## Tuning

Everything lives in `scamcheck/rules.py`:

- `SIGNAL_RES` — add/remove `(regex, weight, label)` lines for scam patterns you
  meet locally (weights are points added to the score)
- `_OCR_VOCAB` — the word list used for fuzzy repair of OCR-noisy screenshots
- `SHORTENERS`, `RISKY_TLDS`, `BRANDS` — extend the link forensics lists
- verdict thresholds live at the bottom of `run_rules()`

## Phone-number intelligence

Attach the sender (`--sender`) and scamcheck folds number evidence into the
message verdict; `--number` checks one number on its own:

```bash
python3 -m scamcheck "Hi, is this the right number?" --sender "+91 98765 43210"
python3 -m scamcheck --number "+1 900 555 1234" --json
```

It understands:

- **premium-rate numbers** — IN `1900`, US/CA `900`, UK `09`, AU `190x`:
  calling or texting them costs extra
- **SMS shortcodes and alphanumeric sender IDs** (`VM-HDFCBK`) — not personal
  lines, and sender IDs are spoofable
- **country mismatch** — e.g. a `+1` personal number claiming to be HDFC while
  the message talks in ₹/UPI/KYC terms
- **your blocklist / allowlist** and **cached feed reports**

Everything lives under `~/.scamcheck/` (override with `SCAMCHECK_HOME`):

| File | Purpose |
|---|---|
| `blocklist.txt` | numbers you marked as scams (one per line, optional `,label`) |
| `allowlist.txt` | numbers you trust — wins over the blocklist |
| `feeds.json` | cache written **only** by an explicit `--update-feeds` |
| `feeds.conf` | the public list URLs *you* choose |
| `config.json` | default region |
| `history.db` | JARVIS local memory (SQLite, `0600`) |
| `cases.db` | evidence-case metadata, entities, evidence hashes and timeline (`0600`) |
| `cases/` | private evidence vault: one folder per case (`0700`, files `0600`) |
| `exports/` | default case-pack exports (JSON/MD/HTML/SHA256SUMS, optional PDF) |
| `watchlist.db` | local watchlist identifiers + hit counters (`0600`) |
| `jarvis_prefs.json` | voice/notify/language/sender preferences |

```bash
scamcheck --block "+91 98765 43210" --label "KYC scam"
scamcheck --allow "+91 98765 43210" --label "my bank"
scamcheck --forget "+91 98765 43210"
scamcheck --show-lists

scamcheck --import-list spam.csv              # TXT or CSV (blocklist)
scamcheck --import-list trusted.csv --import-allow

scamcheck --set-region US                     # national-number interpretation
scamcheck --help                              # all flags
```

### Feeds (opt-in, never automatic)

There is **no bundled blocklist**, on purpose. Free, trustworthy, bulk
*phone-number* feeds barely exist: OpenPhish/PhishTank are URL lists,
Truecaller has no public API, and regulator data is unverified complaint
reports. So scamcheck is feed-agnostic and starts empty:

```bash
# ~/.scamcheck/feeds.conf
# URL | label | format        (txt, csv, csv:number,label,reports)
https://example.org/spam-numbers.csv | Community list | csv
```

```bash
scamcheck --update-feeds       # the ONLY command that touches the network
scamcheck --feed-status
```

- HTTPS only (plain HTTP allowed only for `127.0.0.1` self-hosting)
- 25 MB / 200k entries per feed; a failed refresh keeps the previous cache
- only the configured list URLs are fetched — message text is never uploaded
- no automatic refresh: analysis reads the cache and nothing else

One real-world option is the US FTC's daily Do-Not-Call complaint CSVs
(unverified consumer reports, not proof; US numbers only, ~1 MB/day) — usable
through `feeds.conf`, but deliberately not enabled for you.

The default region is `IN`. Change it with `--set-region US` or
`SCAMCHECK_REGION=GB`; national numbers are interpreted in that region.

## Family web UI

`python3 -m scamcheck --serve` also serves a one-page UI at
**http://127.0.0.1:8765/** — built for the "check this for me" moment with a
teen or an elder:

- one big paste box + one big button, 19px text, high contrast, keyboard and
  screen-reader friendly (Ctrl/⌘+Enter also checks)
- screenshots: choose a file, drag-drop, or just paste a screenshot anywhere
  on the page — OCR runs locally, extracted text is shown
- verdicts in plain language with *what to do next*, not just a score
- optional **sender number** field — shows "sender is on your blocklist" and
  premium-rate warnings inline
- English / हिंदी toggle (choice is remembered)
- no external fonts, scripts, or analytics; strict CSP (`default-src 'none'`);
  page and API are same-origin and localhost-only by default

To let another device on your Wi-Fi use it:

```bash
python3 -m scamcheck --serve 8765 --host 0.0.0.0
```

That exposes the API to your network with **no authentication** — only do it on
a network you trust, and stop the server when you're done.

## Next.js interface (`web/`)

`web/` is the full local interface: an editorial, documentation-backed app that
exposes **every** scamcheck tool — message and screenshot checks, numbers and
feeds, JARVIS, evidence cases, watchlist, campaigns, recovery, device audit and
settings. It is a shell over the Python core, not a reimplementation: the
browser calls a JSON bridge (`scamcheck/webcli.py`) which imports the same
modules as the CLI, so verdicts, hashes and audit results are identical in both
places.

```bash
cd web
npm install
npm run dev        # http://127.0.0.1:3000
```

Production build:

```bash
cd web
npm run build
npm start
```

Requirements: Node.js 20+ for the interface. The Python core still needs only
Python 3.9+ and the standard library — no Python packages are installed.

### Pages

| Page | Path | What it does |
|---|---|---|
| Overview | `/` | Runtime status, recent checks, quick check |
| Message check | `/check` | Message, conversation, screenshot, batch, link and QR |
| Numbers & feeds | `/numbers` | Number intel, local block/allow lists, imports, feeds |
| JARVIS | `/jarvis` | The terminal command grammar in a chat console |
| Evidence cases | `/cases` | Create cases, add hashed evidence, verify, export, report |
| Watchlist | `/watchlist` | Watch phones, domains, UPI IDs, wallets and handles |
| Campaigns | `/campaigns` | Related checks clustered by shared indicators |
| Recovery | `/recovery` | Country-aware playbooks for 15 scam types |
| Device audit | `/device` | Read-only machine + private-LAN audit, streamed live |
| Settings | `/settings` | Region, local memory, bot status, data files |
| Documentation | `/docs` | Overview, install, CLI, web, API, device, cases, privacy, FAQ |

### How the bridge works

- `POST /api/tool` takes `{"tool": "...", "args": {...}}`, validates the tool
  against a whitelist, spawns `python3 -m scamcheck.webcli` in the project root
  and returns `{"ok": true, "data": ...}` or an error.
- `POST /api/device-audit` streams progress over Server-Sent Events, then a
  single `result` event with the report and export paths.
- The bridge finds the project root by walking up from `web/` looking for
  `scamcheck/__init__.py` and `pyproject.toml`. Override it with
  `SCAMCHECK_ROOT` if the app runs from elsewhere.

### Environment variables

| Variable | Used by | Purpose |
|---|---|---|
| `SCAMCHECK_HOME` | Core + web | Data directory (default `~/.scamcheck`) |
| `SCAMCHECK_REGION` | Core + web | Default region, e.g. `IN` |
| `SCAMCHECK_ROOT` | Web | Project root containing `scamcheck/` |
| `SCAMCHECK_PYTHON` | Web | Python binary to spawn (default `python3`) |

The web app has **no authentication** and no database of its own. Keep it on
loopback; do not expose it to a LAN or the internet. It does not touch an
existing service on port `8765` — the built-in API and family UI stay separate.

Full documentation lives in the app at `/docs` (install, CLI reference, web
interface, HTTP API, device audit, cases and recovery, privacy model, FAQ).

## Chat bots (Telegram / WhatsApp)

The detector, in chat: send a message or a screenshot and get a plain-language
verdict. The analysis runs on the machine hosting the bot; the only outbound
traffic is the reply itself (and, for WhatsApp, normal Cloud API calls).

### Telegram — long polling, no public URL

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy the token.
2. Run:

```bash
export SCAMCHECK_TELEGRAM_TOKEN="123456:ABC..."
python3 -m scamcheck --bot telegram
# or: scamcheck --bot telegram --bot-token "..."
```

Send text, a photo/screenshot, or an image file. Commands:

| Command | Effect |
|---|---|
| `/lang en` / `/lang hi` | reply language (per chat, remembered) |
| `/sender +91 98765 43210` | remember a sender number for this chat |
| `/sender off` | forget it |
| `/check <text>` | check one message explicitly |
| `/status` | region, language, sender, cached feed count |
| `/help` | usage |

Limits and privacy:

- 20 checks/hour/chat by default (`SCAMCHECK_BOT_RATE`), so a group can't spam it
- text/screenshots are analyzed locally; nothing is sent to an AI unless you set
  `SCAMCHECK_BOT_AI=auto|always` **and** an API key
- Telegram doesn't expose the original sender number when you forward a message,
  so set `/sender` manually when that matters
- the bot process must stay running; long polling needs no ports or certificates

### WhatsApp — Cloud API + public HTTPS webhook

1. Create a Meta app with the WhatsApp product and a test number. Collect
   `WHATSAPP_TOKEN` and `WHATSAPP_PHONE_NUMBER_ID`.
2. Start the webhook locally:

```bash
export WHATSAPP_TOKEN="EAAG..."
export WHATSAPP_PHONE_NUMBER_ID="1234567890"
export WHATSAPP_VERIFY_TOKEN="choose-a-random-string"
export WHATSAPP_APP_SECRET="..."        # optional, recommended (HMAC checks)
python3 -m scamcheck --bot whatsapp     # 127.0.0.1:8766/webhook/whatsapp
```

3. Give Meta a public HTTPS URL with a tunnel:

```bash
cloudflared tunnel --url http://127.0.0.1:8766
```

4. In Meta → WhatsApp → Configuration, set the callback URL to
   `https://<your-tunnel-host>/webhook/whatsapp` and the verify token to the
   same value. Subscribe to `messages`.

Notes:

- the webhook acknowledges Meta immediately and processes the message in the
  background, so retries don't double-reply (message IDs are deduplicated)
- images are downloaded through the Graph API, OCR'd locally, and answered
- `WHATSAPP_APP_SECRET` enables `X-Hub-Signature-256` verification on every POST
- bind defaults to `127.0.0.1`; put it behind a tunnel/reverse proxy rather than
  exposing the port. There is no user authentication on the webhook itself.

`python3 -m scamcheck --bot-status` prints what is configured without making any
network calls (tokens are masked).

## JARVIS console (`--jarvis`)

One local command center for everything the detector can do, with memory and
optional voice/notifications:

```bash
scamcheck --jarvis                      # interactive console
scamcheck --jarvis --voice --notify     # spoken + desktop alerts for risky results
printf 'check URGENT: verify at bit.ly/x\nquit\n' | scamcheck --jarvis
```

| Command | What it does |
|---|---|
| `check <text>` (or just paste text) | analyze an SMS/email/chat message |
| `assess <text>` | full intelligence brief: type, stage, goals, next moves, verification, evidence |
| `brief` / `next` / `reply` | briefing, attacker next moves, or safe replies for the last check |
| `image <path>` | OCR a screenshot, decode QR codes, then analyze |
| `qr <path>` | decode QR/barcodes only; never opens them |
| `paste` | check the current clipboard (text or screenshot) |
| `url <link>` | redirect chain, TLS, domain age, final page title |
| `number <phone>` | range facts, premium-rate, local lists, cached feeds |
| `block/allow/forget <phone> [label]` | edit your local number lists |
| `sender <phone\|off>` | attach a sender number to subsequent checks |
| `history [n]` / `search <term>` / `history clear` | local memory |
| `case ...` | `list`, `new <title>`, `show`, `add`, `note`, `entity`, `export`, `verify`, `close` |
| `watch <KIND:VALUE>` / `unwatch <KIND:VALUE>` / `watchlist` | local watchlist |
| `campaigns [n]` / `campaign <id>` | cluster related checks by shared indicators |
| `recover [type]` | country-aware recovery playbook |
| `report <case-id>` | draft a complaint from a case |
| `scan device` / `scan device full` | read-only device audit (posture, processes, persistence, browsers, network, files) |
| `scan device active` | same audit plus TCP port probes on private-LAN devices you own |
| `scan network [active]` | private-LAN inventory only |
| `why` | signals behind the last check |
| `voice on\|off`, `notify on\|off` | spoken verdicts and macOS alerts |
| `lang en\|hi`, `region IN\|US\|...` | reply language and number region |
| `feeds`, `status`, `help`, `quit` | settings and help |

**Memory.** Every console check is stored in `~/.scamcheck/history.db` (SQLite,
mode `0600`, local only). Before recording, scamcheck looks up the link hosts,
phone numbers and an exact-message hash, so a repeat gets a "seen before" line
and a new link/number gets "new to me". Message text is stored to make `search`
and `why` useful; `history clear` wipes it. Nothing is synced or uploaded.

**Voice and alerts.** `--voice` uses macOS `say`; `--notify` uses Notification
Center. Both fire only for SUSPICIOUS or worse by default (`SCAMCHECK_ANNOUNCE_ALL=1`
announces safe results too). Set `SCAMCHECK_VOICE_NAME` (or
`SCAMCHECK_VOICE_NAME_HI` for Hindi) to pick a system voice. The Hindi voice is
not installed on every Mac; English always works. On other platforms the
console still runs, just without local speech/notification.

**Link investigation is the only online tool.** `url` intentionally fetches the
link (redirects, certificate) and asks `rdap.org` for the registration date —
only when you type the command. Private/loopback targets are refused, including
hostnames that resolve to private addresses. A normal text/screenshot/QR check
never uses the network. AI stays off here by default; set
`SCAMCHECK_JARVIS_AI=auto|always` plus an API key if you want the optional
second opinion.

**Ambient screenshots.** `--watch --screenshot-dir ~/Desktop` watches both the
clipboard and that folder. On startup it checks the 10 newest images already
there, then every new or changed screenshot. Combine with `--voice`/`--notify`.
Watch results go into the same local memory.

Watch checks stay local even if an AI key is configured: the watcher forces
`ai=never` unless you explicitly opt in with `SCAMCHECK_WATCH_AI=auto|always`
(a literal `--ai never` always wins). This is deliberate — an ambient loop
should not upload whatever happens to be copied.

## Cases, watchlists and recovery

A **case** is a private investigation folder for one scam. Every text or file
is hashed with SHA-256 at collection time; case exports include a hashes file
so you can show that evidence was not changed afterwards.

```bash
# open a case (case IDs look like C-20261024-4A7F)
scamcheck --case-new "Bank transfer fraud" --scam-type bank \
  --country IN --currency INR --loss 25000 --case-notes "first contact 10:20"

# attach screenshots, chat exports, PDFs or pasted text
scamcheck --case-add C-20261024-4A7F ~/Desktop/whatsapp.png
scamcheck --case-add C-20261024-4A7F "He asked me to send USDT to T..."

# record a suspect identifier or a timeline note
scamcheck --case-entity C-20261024-4A7F "wallet:T..."
scamcheck --case-note C-20261024-4A7F "Bank complaint reference 99881"

# inspect, check for tampering, and export
scamcheck --case-list
scamcheck --case C-20261024-4A7F
scamcheck --case-verify C-20261024-4A7F
scamcheck --case-export C-20261024-4A7F --case-out ~/Desktop/case-pack
scamcheck --case-close C-20261024-4A7F

# complaint draft (edit it before submitting; this is not a legal filing)
scamcheck --report C-20261024-4A7F --country IN --report-out complaint.txt
```

An export contains `case.json`, `case.md`, `case.html`, `SHA256SUMS` and an
`evidence/` folder. A PDF is generated only when `weasyprint`, `wkhtmltopdf`
or a local Chrome/Chromium is installed; otherwise use the HTML/Markdown.

**Watchlists** warn you the next time a known indicator appears in any check:

```bash
scamcheck --watch-add "upi:scammer@okhdfcbank"
scamcheck --watch-add "url:evil-example.xyz"
scamcheck --watch-add "+91 98765 43210"
scamcheck --watchlist
scamcheck --watch-remove "url:evil-example.xyz"
```

Matches appear in human output and in `--json` under `watchlist` (stdout stays
valid JSON). Supported kinds include `phone`, `url`, `upi`, `email`, `telegram`,
`whatsapp`, `crypto_btc`, `crypto_eth`, `crypto_trx`, `ifsc` and `apk`.

**Campaigns** group prior checks that share a phone, domain, UPI ID, wallet,
handle or APK — so one victim's report becomes an early warning for the next:

```bash
scamcheck --campaigns
scamcheck --campaign CAM-00042
```

**Recovery playbooks** give an ordered, country-aware checklist (immediate,
today, this week) and the right reporting channels:

```bash
scamcheck --recover upi --country IN
scamcheck --recover crypto --country US
scamcheck --recover job --country GB
```

Supported country profiles: IN, US, GB, AU, CA, SG, AE, NZ, ZA (generic
fallback elsewhere). Hotlines and portals change — verify them on the official
site before sharing personal details. These playbooks are guidance, not legal
advice, and the evidence pack is for lawful reporting, not self-prosecution.

## Device & LAN audit (`--device-audit`)

A read-only security check for the machine scamcheck runs on, plus an inventory
of the private network it is attached to. It is **not an antivirus engine**: it
checks the things a careful person would check, without sudo, writes or
exploitation.

```bash
python3 -m scamcheck --device-audit                  # local audit + passive LAN inventory
python3 -m scamcheck --device-audit --device-full    # print every section
python3 -m scamcheck --device-audit --device-active  # + TCP port probes on your private LAN
python3 -m scamcheck --device-audit --device-out DIR # choose the export folder
python3 -m scamcheck --device-audit --device-no-lan --device-no-mobile
python3 -m scamcheck --device-audit --json           # report + export paths as JSON
```

What it looks at (macOS first; other platforms skip unsupported checks):

- **Posture**: SIP, FileVault, Gatekeeper, firewall, Remote Login, MDM,
  guest/automatic login, update settings, XProtect/MRT versions.
- **Processes**: reverse shells, miners, `curl | sh`, temp/shared-path
  binaries, Apple-lookalike names outside Apple paths, sustained high CPU.
- **Persistence**: LaunchAgents/Daemons, login items, background task items,
  cron/`at`, shell profiles, SSH authorized keys, configuration profiles.
- **Browsers**: Chromium-family and Firefox extensions with high-risk
  permissions, native-messaging hosts, Safari extensions, managed policies.
- **Network**: interfaces, DNS, proxy, custom `/etc/hosts`, listening
  services, established connections and unusual remote ports.
- **Files**: recent downloads, quarantine events, executables in temp/shared
  folders, unsigned recently-changed applications.
- **Extensions**: system extensions and third-party kernel extensions.
- **Mobile**: connected Android (only with an authorized `adb`) and iOS
  inventory; per-platform checklists when no agent exists.
- **LAN**: devices already visible in the ARP table, vendor lookup, device
  guessing, and optional TCP connects to common ports.

Every run writes `report.json`, `report.md` and `SHA256SUMS` to
`~/.scamcheck/device-reports/<timestamp>/` (mode `0700`); `--device-out` picks
another folder. Reports stay local. `--device-active` is opt-in, only connects
to RFC1918/link-local IPv4 addresses, caps the host list at 64, and never
attempts logins, exploitation, packet capture or public-IP scanning.

## MCP server

`scamcheck --mcp` speaks newline-delimited JSON-RPC 2.0 on stdin/stdout (the
MCP stdio transport). stdout carries protocol frames only; diagnostics go to
stderr. Tools are listed in the [MCP section](#use-it-from-an-ai-agent-mcp)
above; the implementation is `scamcheck/mcp.py` and the contract is covered by
`tests/test_mcp.py`.

Design choices worth knowing:

- `check_message` defaults to `ai: "never"` so an agent cannot silently make a
  network call on a victim's message.
- `check_url` is the only networked tool, and it refuses private, loopback and
  link-local targets (including via redirect).
- Tool failures are returned as `isError: true` with a readable message, so the
  model can recover; protocol failures stay JSON-RPC errors.
- `open_case` writes to the same `~/.scamcheck` store as the CLI, so a case
  opened by an agent can be exported with `--case-export`.

## Local API

`python3 -m scamcheck --serve` (CORS-enabled, localhost only):

| Endpoint | Body | Returns |
|---|---|---|
| `GET /` | — | family web UI (HTML) |
| `POST /v1/analyze` | `{"text": "..."}` or `{"conversation": "..."}`, optional `"sender"`, `"region"`, `"ai": "always"` | full verdict payload |
| `POST /v1/check-number` | `{"number": "+91 98765 43210"}`, optional `"region"` | number intel + reputation + risk |
| `POST /v1/check-image` | `{"path": "..."}` or `{"image_b64": "..."}` | verdict + `ocr_engine` + `extracted_text` + `qr` (when codes are present) |
| `GET /health` | — | `{"ok": true, "version": "0.13.0"}` |


## What it can't do (yet)

- Always-listening "Hey JARVIS" wake word or call monitoring — the console,
  clipboard watcher and screenshot folder are the ambient surfaces for now
- Voice calls — feed it a call transcript and it already works; automatic
  call-log speaker-to-text would need OS-level integration
- A bundled global spam-number database — no free, trustworthy bulk feed
  exists; the tool is feed-agnostic and starts empty (import your own lists)
- Trained on *synthetic* screenshots only — real chat-app screenshot quirks
  (dark mode, emoji-heavy text, mixed scripts like Devanagari/Tamil) may need
  engine-specific tweaks
- URL investigation is not a malware sandbox: it follows public HTTP(S)
  redirects and reads metadata, it does not execute or download files
- Case packs are an investigative aid, not a legal filing; court-ready PDF
  output needs a local HTML→PDF converter, and the vault is unencrypted at
  mode `0600` (full-disk encryption is your friend)
- Campaign clustering and watchlists are local to this machine; there is no
  shared/community indicator database
- Device audit is not an antivirus: no signature engine, memory scanning or
  quarantine/remediation. It reports suspicious state; you decide what to remove
- iOS/iPadOS/tvOS/Android cannot be deeply inspected from this Mac without a
  per-device agent or authorized ADB; remote devices get inventory + checklists
- LAN checks are connect-only and depend on ARP visibility; they do not exploit,
  log in, capture packets or scan public IP addresses
- Memory is per-machine and unencrypted (mode `0600`); there is no cloud sync
- Intelligence labels and next-move text are English-first; Hindi/Hinglish
  detection still works through the rules and conversation layers, but the
  briefing prose is not fully translated yet
- MCP exposes analysis, numbers, entities and cases — not OCR, the bots or the
  device audit; those stay on the CLI where a human is in the loop
- It's a *helper*, not gospel — always double-check urgent messages with the
  official app or hotline before acting

## Layout

```
scamcheck/
├── scamcheck/          # the Python package (rules, analyzer, AI, CLI)
│   ├── __init__.py
│   ├── __main__.py     # python3 -m scamcheck entry
│   ├── cli.py
│   ├── analyzer.py
│   ├── intelligence.py # scam type, stage, goals, next moves, deobfuscation
│   ├── ocr.py          # screenshot OCR + QR decode + clipboard helpers
│   ├── conversation.py # chat-trajectory engine
│   ├── scripts_lib.py  # scam playbook fingerprints
│   ├── intel.py        # shared identifier/entity extraction
│   ├── cases.py        # evidence cases + SHA-256 custody
│   ├── watchlist.py    # local indicator watchlist
│   ├── campaigns.py    # campaign clustering over history
│   ├── recovery.py     # country-aware recovery + complaint templates
│   ├── api.py          # local REST API + web UI server (--serve)
│   ├── mcp.py          # MCP stdio server (--mcp)
│   ├── webui.py        # family web UI (single-file HTML/CSS/JS, EN/HI)
│   ├── webcli.py       # JSON bridge used by the Next.js interface
│   ├── phones.py       # number normalization, local lists, opt-in feeds
│   ├── bot.py          # Telegram long polling + WhatsApp Cloud API webhook
│   ├── jarvis.py       # console, local memory, voice/alerts, tool router
│   ├── deviceaudit.py  # read-only device + private-LAN security audit
│   ├── netintel.py     # on-demand URL redirects/TLS/RDAP investigation
│   ├── rules.py        # the heuristic engine (tune here)
│   └── ai.py
├── tests/
│   ├── samples.py      # curated scam & legit specimens
│   ├── make_png.py     # synthetic screenshot generator (stdlib-only)
│   ├── test_ocr.py     # OCR pipeline honors test (macOS / tesseract)
│   ├── test_batch.py   # --batch splitting + CLI behavior
│   ├── test_api_ui.py  # API + family UI page/endpoints
│   ├── test_mcp.py     # MCP stdio protocol + tool contract
│   ├── test_phones.py  # number parsing, lists, feeds, CLI, API
│   ├── test_bot.py     # bots: formatting, commands, Telegram + WhatsApp
│   ├── test_cases.py   # cases, watchlists, campaigns, recovery
│   ├── test_intelligence.py # deobfuscation + intel briefing + routes
│   ├── test_deviceaudit.py # device audit guards, export, CLI + JARVIS routes
│   ├── test_webcli.py  # JSON bridge contract, tools, errors, streaming
│   ├── test_jarvis.py  # memory, intents, URL/QR/image tools, voice, CLI
│   └── run_samples.py  # regression self-test
├── web/                # Next.js interface + documentation site
│   ├── app/            # pages, docs and API routes
│   ├── components/     # workbenches, shell, verdict panels
│   ├── lib/            # Python bridge spawner and shared types
│   └── package.json
├── pyproject.toml      # packaging metadata + `scamcheck` entry point
├── setup.py            # shim for Apple's old pip/setuptools
└── README.md
```

Plus `~/bin/scamcheck` — a launcher that turns this into a global command.
