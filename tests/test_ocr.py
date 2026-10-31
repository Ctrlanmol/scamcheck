#!/usr/bin/env python3
"""OCR-to-verdict honors test (macOS).

Generates synthetic screenshots with tests/make_png.py (pure stdlib, no
third-party deps), runs the real OCR fallback chain, and asserts the
analysis verdict. Skips cleanly if no OCR engine is available (e.g. non-macOS
machines without tesseract), so the suite stays green everywhere.

Run: python3 tests/test_ocr.py
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scamcheck.ocr import ocr_image              # noqa: E402
from tests.make_png import render                # noqa: E402

SCAM_SCREENSHOT = (
    "URGENT: Your bank account is suspended.\n"
    "Unauthorized transaction detected!\n"
    "Verify now: bit.ly/hdfc-alert\n"
    "Do not share this with anyone."
)
SAFE_SCREENSHOT = (
    "Hi mom, reached successfully.\n"
    "Will call you in 2 hours, love you!"
)

RANK = {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "LIKELY SCAM": 2, "SCAM": 3}


def main():
    from scamcheck.analyzer import analyze

    tmpdir = tempfile.mkdtemp(prefix="scamcheck-ocr-test-")
    scam_png = os.path.join(tmpdir, "scam.png")
    safe_png = os.path.join(tmpdir, "safe.png")
    render(SCAM_SCREENSHOT, scam_png, scale=8)
    render(SAFE_SCREENSHOT, safe_png, scale=8)

    ocr_scam, engine = ocr_image(scam_png)
    if not (ocr_scam or "").strip():
        print("[SKIP] no OCR engine available (install tesseract or run on macOS)")
        return 0

    print("[info] OCR engine:", engine)

    res = analyze(ocr_scam, ocr=True)
    ok = RANK[res["final_verdict"]] >= RANK["SUSPICIOUS"]
    print("[%s] scam screenshot -> %s (score %d)" % (
        "PASS" if ok else "FAIL", res["final_verdict"], res["score"]))

    ocr_safe, _ = ocr_image(safe_png)
    res2 = analyze(ocr_safe, ocr=True)
    ok2 = res2["final_verdict"] == "LIKELY SAFE"
    print("[%s] safe screenshot -> %s (score %d)" % (
        "PASS" if ok2 else "FAIL", res2["final_verdict"], res2["score"]))

    return 0 if (ok and ok2) else 1


if __name__ == "__main__":
    sys.exit(main())
