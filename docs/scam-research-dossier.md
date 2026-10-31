# Global Scam & Fraud Research Dossier (compiled Oct 2026)

Sources: FBI IC3 2025 Annual Report, FTC Consumer Sentinel data (2025-26),
GASA State of Scams 2026, CFPB, Consumer Federation of America "Scam Economy",
Pew Research 2025, Palo Alto Unit 42, Zscaler ThreatLabz 2026, Group-IB,
F-Secure, Singapore Police Force, India I4C/MHA advisories, USENIX Security 26,
Journal of Cybersecurity, FinCEN.

---

## 1. The big picture (numbers, 2025-2026)

- FBI IC3 2025: **1,008,597 complaints, $20.9B reported losses** (+25.8% YoY).
  Estimated true cost (underreporting multiplier 7.1x): **~$148B/year in the US alone**.
- FTC 2025: **$15.9B reported consumer fraud losses** (+25% YoY; +430% since 2020).
  Imposter scams = #1 category for the 9th straight year ($3.5B).
- **Investment fraud is the costliest**: ~$8.6B reported (half of all losses);
  crypto-investment scams alone: **$7.2B**.
- Top loss categories (IC3 2025): Investment > BEC ($3.0B) > Tech support
  ($2.1B) > Confidence/romance ($929M) > Government impersonation ($798M).
- Almost all of this runs on **industrial scam compounds** in Southeast Asia
  (Cambodia, Myanmar, Laos, Philippines) staffed by trafficked forced labor
  (UNODC; USENIX found 500+ compounds, ~87% of staff do initial
  contact/trust-building, senior "closers" execute the financial extraction).
- Scams are now multi-channel: the same victim is worked via SMS → WhatsApp →
  video call → investment site.

## 2. The universal con: psychology (why anyone can fall)

Modern scam manuals (recovered from syndicates) are built on formal psychology:

| Lever | Used for | Examples |
|---|---|---|
| Urgency | short-circuit thinking | "act in 24h", "account suspends today", "grandchild in jail NOW" |
| Authority | bypass skepticism | bank/police/CBI/IRS/CEO/Courier, fake warrant, spoofed ID |
| Fear + shame (compliance pressure) | isolate victim | "you're implicated in a crime", "don't tell anyone / it's confidential", illegal-drugs parcel |
| Greed / FOMO | open the wallet | crypto doubling, lottery, guaranteed returns, exclusive early access |
| Trust & intimacy | pig-butcher grooming | weeks of daily "good morning" messages, persona with wealth + empathy |
| Secrecy & isolation | protect the con | "the investigation is confidential", "criminals are watching your house" |
| Sunk cost | escalate deposits | small withdrawal allowed first ("controlled wins"), then fees/taxes/level-up just to "release" funds |

Pig-butchering stage model: **Hunt → Groom → Butcher**
1. Wrong-number/dating-app "Hook", filtered for financial capacity + susceptibility
2. Long trust-building ("Line"), personas, deepfakes for video calls
3. Fake trading platform ("Sinker"): fake profits, real small withdrawals,
   then escalating "taxes/fees" until money is gone

Neuro-diverse, lonely, elderly, financially stressed, and *young* users are
filtered in; everyone else is a target the day their guard is down
("victim doesn't need a profile flaw — needs a bad day").

## 3. Delivery channels (attack surface = everything)

1. **Phone calls (vishing)** — spoofed caller ID (SIP abuse), robocalls,
   "callback phishing" (email says: call support). 442% surge in vishing H2 2024.
   People 80+: 40%+ of money-loss scams start with a call.
2. **SMS (smishing)** — top contact method overall in 2025 FTC data. Toll
   scams (E-ZPass etc., +40% gov-impersonation), bank fraud alerts, package
   delivery fees, fake OTP messages.
3. **QR code (quishing)** — +400% between 2023-25; 11,000 malicious QR
   detections/day (Unit 42); beats email scanners because code = image;
   QR-shortener destination swapping; in-app deep links (Telegram login theft:
   `tg://login?token=` — 97% of malicious Telegram QRs); payment deep links;
   silent APK downloads; sticker overlays on parking meters; "brushing"
   packages with QR.
4. **Email** — 2B+ phishing hits/yr industry-wide but shrinking as delivery;
   now: AiTM (adversary-in-the-middle) kits like **BlackForce** capture
   credentials AND live MFA codes during active sessions; BitB fake browser
   windows; QR embedded in PDF attachments; ClickFix fake CAPTCHA lures.
5. **Messaging apps** — WhatsApp & Telegram: #1 move-off-platform vector.
   Task/job scams run entirely inside Telegram groups with "teachers" and
   "receptionists"; WhatsApp video used for "digital arrest"; Sim-slots scams.
6. **Social media** — $2.1B US losses in 2025 (8x in 5 yrs); **Facebook = #1
   origin (all ages except 80+), then WhatsApp, then Instagram.** 60% of romance
   losses start there. Shopping scams most common; investment scams biggest loss.
   Tactics: hijacked accounts ("vote for me", "is this you?"), fake shops with
   aged accounts, bio links, influencer/celebrity deepfake endorsements
   (Musk, Taylor Swift x Le Creuset), fake groups with paid shills.
7. **Dating apps** — romance baiting → crypto investment ("pig butchering");
   account creation kits ($70-100/ID), move to encrypted chat within days.
8. **Professional networks (LinkedIn)** — fake recruiters, fake job roles,
   BEC broker recruitment, freelancer file-share scams (malware).
9. **Marketplaces / e-commerce** — Facebook Marketplace/Craigslist/OLX:
   overpayment refund scam, Zelle "upgrade" scam, shipping/mover fee
   interception, bait-and-switch, non-delivery, verification-code account theft
   (Google Voice), rental deposit scams (fake landlord = copy of real listing).
10. **Payments rails themselves** — bank transfers, Zelle/P2P, crypto ATMs,
    gift cards, wire, cash/gold courier handoffs, UPI in India. Chase blocks
    Zelle payments originating on social media (~50% of reported scams).
11. **Search & ad networks** — malvertising, fake "support" numbers ranked in
    search results, fake AI tools/deepfake detector sites, typosquats.
12. **Gaming** — Roblox/Fortnite scam items, fake game trade links, gambling
    "colour prediction" apps (huge in South Asia).
13. **Offline/physical** — fake QR stickers, gold/cash couriers to your door
    ($311.8M gold-courier scam), fake ATMs, WhatsApp-number stickers on taxis.

## 4. The scam catalog (type-by-type)

### A. Impersonation scams (biggest category overall)
1. **Bank/financial imposter** — "unauthorized transaction spotted", fake
   fraud dept, victim moves money to "safe account". ~$1B to bank imposters 2025.
   Now: fake bank app on the phone + person on the line ("live double-imposter").
2. **Government imposter** (+40% YoY) — IRS/tax, social security, immigration,
   customs, toll agencies, municipal fines, health-insurance offers
   (MediaAlpha case), Chinese law enforcement to Chinese diaspora.
3. **Tech support** ($2.1B, 60% of victims 60+) — pop-up "your PC is infected",
   fake support site/number from search, remote-control install (AnyDesk/
   TeamViewer/UltraViewer/QuickSupport), fake "refund" reversal trick,
   escalation: "child porn found on your machine → transfer to safe wallet",
   gift cards → crypto ATMs.
4. **Government/agent "digital arrest"** (India-origin, rapidly spreading) —
   courier call → parcel with drugs/passport → fake police/CBI/ED on Skype/
   WhatsApp video, fake police-station sets, "you are under arrest, don't tell
   family", 8h-6month surveillance, hundreds of transfers; single victims:
   ₹10.3 crore, ₹32 crore (187 transfers). No such thing as "digital arrest".
5. **Courier + gold/cash handoff** — victims deliver cash/gold to fake
   couriers ("RBI pre-verification"); $311.8M in 2025.
6. **Family/friend imposter ("grandparent" scam)** — voice-clone or
   breathless-muffled voice: "I'm in jail, need bail, don't tell mom".
7. **Boss/CEO imposter (BEC + deepfake)** — $25M Arup Hong Kong video-call
   deepfake; $35M UAE bank voice clone; recruiter/HR Q&A data harvesting.

### B. Investment scams (~half of all losses)
- **Crypto "pig butchering"** (hybrid romance+investment; 78% of notified
  victims were unaware they were being scammed) — details above.
- **Fake trading/doubling platforms** with real-looking dashboards,
  "guaranteed 10-20%/day returns".
- **Fake celebrity endorsement** deepfakes, fake news-page-redirect funnels,
  Telegram/Facebook "trading groups" with paid shills.
- **Withdrawal-fee escalation**: taxes, insurance, "credit score" unlock.

### C. Romance scams
- Traditional (money for emergencies/tickets) → investment pivot; 60%+ start
  on social; average loss $2,020+/victim per FTC (report), far higher in
  crypto hybrids ($50k-500k common); AI chatbots increasingly run the
  grooming stage (UNODC: one scammer now runs pools of victims).

### D. Job & task scams
- "Like YouTube videos / rate hotels / boost Amazon traffic" part-time work on
  Telegram/WhatsApp → small real payouts → "paid tasks" requiring deposits →
  frozen withdrawals → "error correction payments" up to lakhs/crores.
- Fully fake onboarding: real-looking website, interviews, offer letters, then
  training/equipment/laptop-deposit fees; freelance-platform fake clients.
- Target: youths/students/homemakers/job-seekers (ages 18-34 highest rates).

### E. E-commerce/marketplace scams (most *reported* type)
- Fake shops via social ads (site clone, aged accounts), non-delivery,
  counterfeit switch, off-platform payment demand, overpayment with fake
  check, "mover fee" refund interception, Zelle "account upgrade", shipment
  SMS with fake link, review-buying recruitment.

### F. Account takeover & credential theft
- Phishing → AiTM/BitB (beat MFA, real-time), quishing, otp/SIM-swap
  ( SIM-swap + remote access = full bank drain; $350k Budapest cases),
  "verification code" scams (code they send you = login code; "I sent you a
  code by accident"), fake support sites ranked in search.

### G. Phishing infrastructure mechanics (how the site works)
- Open-redirect chains (legit redirectors), Cloudflare Turnstile bot checks,
  ISP/crawler filtering (researchers blocked), victim-email prefill
  (looks "already logged in"), per-victim credential allowlists (rejects
  wrong targets = confirms victim), Telegram C2 relay of stolen creds,
  HTTPS everywhere (95%+ → invisible to old filters), text-to-site AI page
  generators (Lovable abuse), domain-rotating ephemeral infra.

### H. Application/device compromise
- Malicious APKs direct-download via QR (bypassing app stores), fake banking
  apps, screen-sharing abuse, screen-recording overlays, accessibility-
  permission abuse (banking trojans), remote control (AnyDesk abuse).

### I. Money-movement & laundering layer (why recovery is hard)
- Money mules (often recruited via job scams), layered transfers, hawala,
  crypto peel chains, stablecoins (USDT), gold/cash couriers, P2P networks,
  fake invoices (BEC). 50%+ of reported losses involve crypto.

### J. Secondary/aftermath scams (cruelty layer)
- **Recovery scams** ("we can get your money back — pay the fee", fake
  lawyers/agencies; reinjures the same victims list from data breaches)
- Fake charity, fake support groups, fake legal services, blackmail with
  intimate images + deepfakes (sextortion — top killer of teen boys),
  fake arrest-warrant threats to relatives of victims.

### K. Special vectors
- **Toll/fine scams** (E-ZPass etc.), **jury duty**, **Medicare cards**,
  **student-loan forgiveness**, **utilities disconnection**, **e SIM port-out**,
  **UV "**brushing" packages, **fake tenant/landlord** (rental deposit),
  **fake tickets/resale**, **pet adoption deposits**, **sugar-daddy scams**,
  **charitable disaster scams**, **election disinformation robocalls**
  (AI Biden robocall), **carbon-credit/green investment**, **forex magnet**,
  **binary options**, **diamond/gold** ["commodity"] schemes, **HELOC drain**
  (victims take home loans to "invest"), **insurance-policy takeover**.

## 5. AI-era techniques (2025-26 state of the art)

1. **Voice cloning ("family & friends fraud")** — 3 seconds of audio
   (voicemail, Reels, podcast) → ElevenLabs/Resemble/PlayHT/Coqui clone;
   80% of listeners can't distinguish (UC study); real-time conversion
   during live calls is here (kills voice-authentication controls).
2. **Real-time deepfake video calls** — Arup-style multi-person fake
   meetings; face-swap microservices sold on Telegram ("1,000 compounds
   installed", 24/7 support, door-to-door in Cambodia).
3. **AI-written everything** — 89% of AI-enhanced scams use content
   generation; perfect English kills the grammar red flag; idiomatic local
   dialects ("cattle rancher in Texas" persona run from Burma via ChatGPT).
4. **AI-built phishing infrastructure** — text-to-site generators spin up
   brand-perfect fake portals in minutes; domain-rotating; Role-specific
   spear-phish assembled from scraped social data (Beazley/eBay warnings).
5. **AI target selection & scaling** — scraping to score victims by wealth /
   susceptibility; auto-dialers with LLM personas; UNODC: one operator now
   does what a team did.
6. **AI chatbot victims handlers** — romance grooming at scale;
   "long-horizon" empathy abuse; safety guardrails bypassed trivially.
7. **First IC3 AI-enabled fraud tracking (2025)**: 22,364 complaints,
   $893M reported, est. $6.3B true cost — first-year benchmark, will grow.
8. **Deepfake celebrity ads** for scams (Taylor Swift cookware, Musk crypto);
   TAKE IT DOWN Act / DEFIANCE Act respond (deepfake-specific law).

## 6. Age-group targeting (who gets hit, how, and how much)

US (FTC/IC3/BBB/CFA) and Singapore (SPF 2025) patterns:

| Age group | Most-hit scam types | Main channels | Pattern |
|---|---|---|---|
| Teens (<20) | sextortion, gaming items, shopping | social/games | +198% losses YoY (2025); high frequency, low value; blackmail-driven |
| 18-29 (Gen Z) | job/task scams, shopping fake ads, crypto, account takeover, "sell your account" | Instagram, TikTok, Telegram, Discord | get scammed MOST OFTEN (2x boomers by ~17% vs 7%, Deloitte; BBB: 18-24 lose the most $200 median); high trust in platforms |
| 30-49 | investment, BEC-adjacent, marketplace, phishing | email, LinkedIn, FB, WhatsApp | biggest victim share (36% SG); avg loss $22k |
| 50-64 | investment, phishing, romance; business owners | email, FB, phone | avg $33k (SG) |
| 60-79 (seniors) | tech support, gov imposter, prize/sweepstakes, romance, grandparent | PHONE (esp. 80+), mail, FB | 60+ = largest total losses (+60% YoY), avg $38.5k |
| 80+ | phone scams above all (41% start by call), prize sweepstakes ($47M) | landline, mail | lowest tech exposure; rely on voice trust |

Myths to drop:
- "Old people get scammed most" — they lose the MOST money, but
  **young adults get scammed 2x as often** (Digital-first, no skepticism).
- "It won't happen to smart/people with education" — 73% of US adults have
  been hit; engineers/doctors lose millions to pig butchering; the con is
  emotional, not IQ-based.
- "Password/OTP rules protect them" — 2025-26 scams extract AUTHORIZED
  transfers (victim does the sending under manipulation) → bank reimbursement
  gap; MFA bypass kits curve this.

## 7. What defenders already have (and the gaps)

Existing tools:
- Number/community intelligence: Truecaller (68B spam calls identified in
  2025; new Scam Checker web tool Sep 2026), Nomorobo, Robokiller, scam.org
- In-app AI assistants: Norton Genie, McAfee Scam Detector, Bitdefender
  Scamio, Avast Assistant — screenshot/message analysis, mostly subscription
- URL reputation: Google Safe Browsing, PhishTank, APWG feeds, WHOIS/age
- Bank-side behavioral: Chase blocks Zelle-from-social-origin; SBI "kill
  switch"; Ask-your-bank confirmations; AARP fraud watch etc.
- Community reporting: FTC ReportFraud, IC3, Scamwatch, Scamfeed;
  7726 (SPAM) forwarding in the US; the 1930 in India
- Telecom flags: STIR/SHAKEN, US "Scam Likely", India's Caller Name
  Presentation (CNAP) rollout (government-backed caller ID pressuring apps)

Structural gaps (the opportunity):
1. **Conversational scams** are invisible to per-message filters — pig
   butchering lives 3 weeks of "good morning" texts; no consumer tool does
   long-horizon conversation-trajectory detection (USENIX 26 explicitly
   calls this the missing piece).
2. **Cross-channel stitching** — same victim: FB ad → WhatsApp → telegram
   trading site → Zelle; defense tools are per-platform bunkers.
3. **Video/voice trust** is broken (deepfakes) with no consumer-grade
   real-time verification challenge-response (e.g. "touch your nose and
   count 7 buttons" — humans still beat LLMs at fine-grained motion/task
   things; Starling: family safe-word).
4. **Age-specific interfaces** — tools are written for tech-literate users;
   grandma & teens need radically simpler, push-based, watch-guardian modes
   (family protection features are early: Truecaller Family, etc.).
5. **Recovery-speed** — money moves in minutes (UPI/Zelle instant); victims
   realize days later; FFKC freezing works but requires immediate report.
6. **Local-language coverage** — scams localize fast; detection remains mostly
   English/west-centric.
7. **Sender/authenticiy IDs verifiable for humans** — CNAP exists for calls;
   nothing comparable for messages/links/QR codes at a glance.
