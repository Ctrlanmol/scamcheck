# Security policy

scamcheck handles scam messages, which often contain victim data. It is built
to keep that data on the machine it was opened on. This document explains the
guarantees, the known limits, and how to report problems.

## Reporting a vulnerability

Open a **private** security advisory on GitHub
(`Security` → `Advisories` → `Report a vulnerability`), or email the maintainer
listed in `pyproject.toml`.

Please do **not** open a public issue for:

- a rule or playbook bypass that would help a scammer evade detection,
- a way to make `--serve` or the bots execute code or read arbitrary files,
- a case-vault or hash-custody integrity flaw,
- anything that leaks evidence outside the machine.

We aim to acknowledge within 7 days. There is no bounty; this is a
volunteer project.

## What scamcheck promises

| Area | Guarantee |
|---|---|
| Analysis | Runs offline. No telemetry, no analytics, no crash reporting. |
| Network | Only four things ever open a socket: `--update-feeds`, `url <link>` / `check_url`, the bots, and an explicitly enabled AI key. All are opt-in. |
| Storage | `~/.scamcheck/` (override with `SCAMCHECK_HOME`), created `0700`; databases and lists `0600`; case vaults `0700`. |
| Evidence | Files are hashed with SHA-256 at collection; `--case-verify` detects later modification. |
| Local API | Binds `127.0.0.1` by default. `--host 0.0.0.0` is opt-in and **unauthenticated** — do not expose it to an untrusted network. |
| Outbound URL checks | Refuses private, loopback and link-local targets, and refuses redirects into them. |

## What it does not promise

- **Encryption at rest.** Databases and case files are plaintext with
  restrictive permissions. Use FileVault / LUKS / an encrypted volume for
  sensitive cases. Encrypted vaults are on the roadmap.
- **Authentication.** `--serve` has no login. The Telegram and WhatsApp bots
  authenticate to their platforms, not to end users.
- **Sandboxing.** `--device-audit` is read-only but runs with your privileges
  and reads system state.
- **Malware analysis.** `url` reads public HTTP(S) metadata. It is not a
  sandbox, a detonator or a malware scanner. Never open a suspect file because
  a tool said it was "probably fine".

## Safe handling of real scam evidence

1. Work inside a case (`--case-new`) so everything is hashed on arrival.
2. Do not forward raw evidence to third-party "check this link" services — that
   is exactly the data leak this project exists to avoid.
3. Share the **case pack** (`--case-export`), not the vault directory.
4. Redact before posting anything publicly: phone numbers, UPI IDs, wallet
   addresses, names, and any URL that still resolves.

## Acceptable use

Watchlists and blocklists are local and personal. Do not use scamcheck to
build public dossiers on individuals, to harass, or to dox. Detection results
are evidence for a human decision, not proof of a crime.
