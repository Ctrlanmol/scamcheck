# Launch strategy

Why scamcheck exists in public, who it is for, who it competes with, and what
the next 90 days look like.

Written October 2026, against the state of the market at that point. Numbers
below are sourced and dated; re-check them before reusing this document in a
pitch.

---

## 1. Thesis

**Do not compete as a consumer scam detector. Compete as the open-source,
offline triage and evidence layer that other things plug into.**

Consumer detection is a data-network business. Truecaller, Hiya, Google Safe
Browsing and the banks win because they see billions of messages and can tell
you what ten thousand other people reported. A single-maintainer project cannot
win that race and should not try.

What nobody owns is the layer underneath:

- a **deterministic, explainable verdict** you can audit and diff,
- that runs **entirely offline** on data you would never upload,
- and produces **evidence with chain of custody** instead of a score.

That is a smaller market with no incumbent, and it is the part that developers,
analysts, NGOs and AI-agent builders actually lack.

---

## 2. Market evidence

| Claim | Source | Date |
|---|---|---|
| `$442B` lost worldwide to online scams in the past year | [GASA](https://gasa.org/) | 2026 |
| `57%` of adults experienced a scam in 12 months; `59%` of victims never report | GASA | 2026 |
| `45%` of people saw more scams than the year before | GASA | 2026 |
| `71%` of 17,460 adults across 13 Asian markets encountered a scam; est. `$136.5B` lost | GASA Asia report | 2026 |
| `66%` are confident they can recognise scams, yet `62%` of exposed users engaged the scammer and `9%` lost money or data | GASA Asia | 2026 |
| Only `4%` reported to authorities | GASA Asia | 2026 |
| Google Safe Browsing had flagged 41 of 254 confirmed phishing sites at discovery → **83.9% missed** | [Norn Labs, Huginn report](https://www.norn-labs.com/blog/huginn-report-feb-2026) | Feb 2026 |
| `58.7%` of those phishing sites were hosted on trusted platforms (Weebly, Vercel, GitHub, Google Docs/Forms/Sites/Apps Script, IPFS) | Norn Labs | Feb 2026 |
| Some of those pages came back **clean on VirusTotal** | Norn Labs | Feb 2026 |
| MCP "tool poisoning" lets a malicious server steer an agent via tool descriptions; rug pulls and cross-server shadowing follow | [Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | Apr 2025 |
| Prompt injection is now a shipping-product vulnerability class (GitLab Duo source theft, Copilot RCE `CVE-2025-53773`, Antigravity exfiltration) | Hacker News front page, multiple | 2025–26 |
| Meta projected `10%` of 2024 revenue came from scams | Hacker News (749 pts) | Nov 2025 |

### What the numbers actually say

1. **The confidence gap is the market.** Two thirds of people think they can
   spot a scam; a third of those who engage one lose something. People do not
   need more awareness content — they need a second opinion at the moment of
   doubt, with a reason attached.
2. **Blocklists are structurally late.** If 84% of confirmed phishing is
   unflagged at discovery, and more than half lives on domains you cannot
   block, then reputation is the wrong primitive for novel attacks. Content and
   behaviour analysis is the right one — which is what this project already
   does, deterministically.
3. **Reporting is broken.** `4%` report. The friction is not willingness, it is
   paperwork: assembling screenshots, hashes, timelines and a complaint. That
   is a software problem, and it is the one scamcheck's case layer solves.
4. **The agent surface is new and adjacent.** Scam triage for humans and
   security scanning for agents are different products, but they share a
   delivery mechanism (MCP) and an audience (people building with agents).

---

## 3. Competitive landscape

Snapshot of GitHub stars, October 2026.

### Consumer detection

| Product | Owns | Why we are not competing |
|---|---|---|
| Truecaller, Hiya, RoboKiller | Caller-ID network, default install | Cloud, closed, no evidence trail |
| Google Safe Browsing | Browser-level URL reputation | Reactive by construction; misses novel and trusted-host phishing |
| ScamAdviser, Norn Muninn | Domain/page scoring, extensions | Cloud or browser-bound; not usable on private material |
| Bank in-app warnings | Distribution to the account holder | Narrow to that bank's rails |

### Open-source security infrastructure

| Project | Stars | Role | Gap we fill |
|---|---|---|---|
| [MISP](https://github.com/MISP/MISP) | 6.6k | Threat sharing platform | Infrastructure for teams; no message-level triage |
| [IntelOwl](https://github.com/intelowlproject/IntelOwl) | 4.8k | Enrichment at scale | Needs API keys and a deployment; not offline |
| [Rspamd](https://github.com/rspamd/rspamd) | 2.6k | Mail filtering | Email only, server-side, rule language not a case tool |
| [ThePhish](https://github.com/emalderson/ThePhish) | 1.4k | Phishing email analysis | Last pushed Aug 2024; email-only |
| phishdestroy/destroylist | 2.1k | Phishing domain blocklist | A feed, not an analyzer |
| hagezi DNS blocklists | 28k | DNS blocking | Network-level, no explanation |

### Scam-specific projects on GitHub

GitHub search, October 2026: `scam detection` 4,505 repos, `phishing
detection` 23,270, `smishing` 627, `fraud detection` 122,870.

The long tail is blocklists, ML notebooks, region-specific Android apps
(Linklow coachguard, SafeSignal, LegitURL) and thin LLM wrappers. Almost none
combine detection + explanation + evidence + offline operation.

### AI-agent security

| Project | Stars | Focus |
|---|---|---|
| [promptfoo](https://github.com/promptfoo/promptfoo) | 26.7k | Prompt/agent testing and red teaming |
| NVIDIA SkillSpector | 23.6k | Scanning agent skills for malicious patterns |
| [garak](https://github.com/NVIDIA/garak) | 9.8k | LLM vulnerability scanning |
| [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) | 3.2k | MCP server and agent-skill security |

Crowded and fast-moving. Do not fight here. Ship an MCP *server* (distribution)
rather than an MCP *scanner* (competition).

### Where scamcheck wins

- Deterministic, explainable, diffable output.
- Offline by default; usable on material that must not leave the machine.
- Evidence with SHA-256 custody and exportable case packs.
- Playbook breadth, conversation trajectory, Hindi/Hinglish.
- Zero runtime dependencies → embeds anywhere, audits easily.

### Where it loses, honestly

- No telemetry, therefore no network effect and no "10,000 reports" signal.
- No browser or mobile coverage; victims live on phones.
- macOS-leaning extras (Vision OCR, `say`, notifications).
- No auth, no encryption at rest, no team sync.
- No published benchmark yet, so no measured credibility.
- Bus factor of one.

---

## 4. Positioning

**One line:** *Offline-first scam triage and evidence kit — one message in, an
explainable verdict and a tamper-evident case file out.*

**Three claims, in order of defensibility:**

1. *Explainable* — every verdict lists the signals and weights that produced
   it, and the engine is deterministic, so results are reproducible and
   reviewable.
2. *Offline* — the analysis path never opens a socket. Opt-in network actions
   are named in `SECURITY.md`.
3. *Evidence-grade* — hashes at collection, timeline, entity extraction,
   exportable pack, tamper detection.

**What we explicitly are not:** a caller-ID network, a browser extension, a
malware sandbox, an enterprise platform.

**Audience priority for launch:** developers and security analysts first
(they evaluate, star and contribute), OSINT/NGO second (they generate the most
compelling stories), families third (they generate the most gratitude).

---

## 5. The 90-day plan

### Phase 0 — repository hygiene (before the first push)

- [x] `LICENSE` (MIT), `.gitignore`, CI (3.9 / 3.11 / 3.13 + macOS), web build
- [x] `SECURITY.md`, `CONTRIBUTING.md`
- [x] README rewritten around the evidence kit, not "SMS checker"
- [x] MCP server with tests
- [ ] Reserve the name on PyPI and npm (both currently free)
- [ ] Add a 60–90 second demo recording (asciinema or GIF) to the README
- [ ] Add `good first issue` labels and 8–12 seeded issues

### Phase 1 — distribution (weeks 1–4)

| Task | Why | Effort |
|---|---|---|
| Publish to PyPI (`pip install scamcheck`) | Removes the clone step; the single highest-leverage launch action | S |
| Homebrew tap + Docker image | Meets people where they already install things | S |
| Versioned `--json` schema in `docs/` | Makes the CLI a contract, not a script | S |
| MCP directory listings (Smithery, mcp.so, awesome-mcp-servers) | Free distribution to the agent audience | S |
| Benchmark harness + published table | Converts claims into measurements; what security people actually check | M |

**Benchmark must report both directions.** Precision/recall on scam specimens
*and* false-positive rate on legitimate bank/OTP/delivery messages. A tool that
flags a real bank SMS as `SCAM` is worse than no tool.

### Phase 2 — contribution surface (months 2–3)

| Task | Why |
|---|---|
| Rule/playbook pack SDK (YAML or JSON, `scamcheck rules validate`) | Turns users into contributors without them editing Python |
| Signed packs + `--import-pack` | Trust model for community rules |
| STIX 2.1 export, MISP/OpenCTI connector | Makes cases useful to SOCs |
| IMAP ingestion | Email is still where BEC lives |
| Thin browser extension calling `localhost` | Closes the "I am on my phone/browser" gap without a cloud backend |
| Android via Termux guide, then a native app | Victims are on phones |

### Phase 3 — depth (months 3–6)

- Encrypted case vault; encrypted `history.db`.
- Auth for `--serve`; optional multi-user.
- Local LLM adapter (Ollama / llama.cpp) to replace the cloud AI second opinion.
- Opt-in community indicator packs (hashed indicators only, no message content).
- Translations: Hindi, Bengali, Tamil, Indonesian, Spanish, Portuguese.
- Voice-clone heuristics and a family safe-word protocol.

---

## 6. Launch playbook

**Channels, in order:**

1. **Show HN** — Tuesday or Wednesday, 06:00–08:00 PT. Title leads with the
   problem, not the stack: *"Show HN: Offline scam triage that produces
   evidence, not just a score"*. Expect the "why not just use an LLM" question;
   the answer is determinism, privacy and cost, and it should be in the README
   before launch.
2. **r/netsec, r/cybersecurity, r/privacy, r/developersIndia, r/India** —
   tailored posts, not one copy-paste. r/India cares about UPI and digital
   arrest; r/netsec cares about the engine and the evidence model.
3. **Product Hunt** — low priority for a CLI, but cheap.
4. **Awesome lists** — PRs to awesome-privacy, awesome-osint,
   awesome-selfhosted, awesome-mcp-servers, awesome-fraud-detection.
5. **MCP directories** — Smithery, mcp.so, Glama.

**Assets to have ready before the first post:**

- 20-second terminal GIF at the top of the README.
- A 90-second video walking one real (redacted) scam end to end.
- The benchmark table, with the false-positive number visible.
- A "scam of the month" teardown post — this is both content marketing and
  how the specimen corpus grows.
- A submission template that forces redaction (`CONTRIBUTING.md` has the table).

**Community mechanics:**

- Seed 8–12 `good first issue`s: translations, a new playbook, Windows OCR
  notes, a Homebrew formula, a Dockerfile, a STIX exporter stub.
- Label and answer every issue within 72 hours for the first month. Early
  responsiveness is what turns a star into a contributor.
- Monthly release notes that read like a changelog of *user-visible* changes.

**Sustainability:**

- GitHub Sponsors / Open Collective from day one, framed as "keep the offline
  path free".
- Grants: GASA, NLnet, Prototype Fund, Internews, Google.org, Mozilla.
- Consulting for banks, cooperatives and NGOs that want a private deployment.
- Do **not** put the core behind a paid API. The licence and the offline
  guarantee are the moat.

---

## 7. What success looks like

| Horizon | Signal | Target |
|---|---|---|
| 30 days | Distribution works | 300+ stars, 5+ external issues, PyPI installs trending up |
| 90 days | Contribution works | 3+ merged external PRs, 2+ community playbooks/languages, 1 benchmark citation |
| 180 days | Adoption works | one NGO/newsroom/bank pilot, a conference or podcast mention, sponsors covering hosting |

Stars are a vanity metric. The real early signal is **someone you do not know
opening an issue with a specimen that breaks the engine** — that means the tool
is being used on real material.

---

## 8. Risks

| Risk | Mitigation |
|---|---|
| A false `SCAM` on a legitimate bank SMS destroys trust | Publish the FP rate; add a "why this might be wrong" line to risky verdicts; keep a benign regression suite |
| Scope creep across bots, UI, device audit, MCP | Treat CLI → JSON → API → MCP → cases as the spine; everything else is a satellite |
| Rule rot as scam scripts change | Playbook SDK + specimen corpus + monthly teardown |
| Watchlists used for doxxing | Acceptable-use note in `SECURITY.md`; keep lists local |
| `--serve --host 0.0.0.0` exposed without auth | Loud warning (already implemented); document in README and SECURITY |
| Single maintainer burn-out | Narrow the spine, accept contributions aggressively, publish a "what I will not build" list |

---

## 9. Open questions

- Does the benchmark belong in-repo (reproducible, adversarial to us) or as a
  separate dataset repo (easier to cite)? *Leaning in-repo with a stable seed.*
- Should the browser extension ship before the Android build? *Browser first —
  it can reuse the localhost API; Android needs a new detection path for
  on-device notifications.*
- Is a hosted "community pack" service worth the trust cost? *Only if it ships
  hashes, never message text, and stays opt-in.*
