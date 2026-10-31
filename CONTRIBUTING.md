# Contributing to scamcheck

Thanks for helping. scamcheck is deliberately boring infrastructure: **stdlib-only,
offline by default, deterministic output.** Most contributions are small and
self-contained, which is exactly how we want to keep it.

## Ground rules

1. **No new runtime dependencies** in the Python core. `pyproject.toml` has no
   `dependencies` and that is a feature. Use the standard library.
2. **No network calls on the analysis path.** Anything that touches the network
   must be an explicit, documented command (`--update-feeds`, `url <link>`,
   `--mcp` → `check_url`) and must be off by default.
3. **Deterministic output.** Same input, same verdict, same signal list, same
   score. No timestamps or randomness inside analysis results.
4. **Explainability.** A new signal must produce a human-readable reason string.
   A verdict without a reason is a bug.
5. **False positives are worse than false negatives** for a tool people run on
   their real bank messages. Every new rule needs a benign counter-example.

## Good first contributions

- **New scam playbook** in `scamcheck/scripts_lib.py` (with 2+ mandatory beats
  so a legitimate message cannot match).
- **New language signals** in `scamcheck/rules.py` (`HINDI_SIGNALS` shows the
  pattern; Tamil, Telugu, Bengali, Indonesian, Spanish and Portuguese are open).
- **Redacted scam specimens** for `tests/` — remove names, numbers, UPI IDs and
  links, keep the wording and structure.
- **Translation** of the family web UI (`scamcheck/webui.py`) or the docs.
- **Platform support** notes for Windows/Linux (`--image` OCR, notifications).

## Adding a scam specimen

Do **not** submit real victim data. Redact:

| Keep | Replace with |
|---|---|
| wording, structure, timing cues | `+91 90000 00000` |
| scam type and payment rail | `scammer@okhdfcbank` |
| brand impersonated (generic) | `example.xyz` |

Then add it to `tests/samples.py` (or a new file) and assert the expected
verdict **and** the expected playbook name.

## Running the tests

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

Each script is self-contained and exits non-zero on failure. CI runs the
portable set on Linux for Python 3.9, 3.11 and 3.13, plus the macOS set on
macOS.

## Pull requests

- One logical change per PR.
- Include the test that would have caught the bug.
- Update `docs/ROADMAP.md` only for shipped work; new ideas go in
  `docs/LAUNCH.md` or the parking lot at the bottom of the roadmap.
- If behaviour changes, update `README.md` in the same PR.

## Security

Please read `SECURITY.md` before reporting anything that could be abused.
Do not open a public issue for a detection bypass that would help scammers.
