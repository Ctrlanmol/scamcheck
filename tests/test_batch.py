#!/usr/bin/env python3
"""Batch-mode test: blank-line splitting + CLI batch run (JSON + exit code)."""

import contextlib
import io
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scamcheck import cli  # noqa: E402


def check(name, ok, detail):
    print("[%s] %s" % ("PASS" if ok else "FAIL", name))
    print("      " + detail)
    return 0 if ok else 1


def main():
    failures = 0

    # 1. splitter: blank lines separate, wrapped lines stay one message
    blob = (
        "Your parcel is held in customs\r\n"
        "pay the fee via gift card to release.\r\n"
        "\r\n"
        "Hi mom, reached safely. Will call tonight!\r\n"
        "\r\n"
        "\r\n"
        "   \r\n"
        "URGENT: your account will be blocked, verify at bit.ly/x1y2z\r\n"
    )
    blocks = cli.split_batch(blob)
    ok = (len(blocks) == 3 and blocks[1] == "Hi mom, reached safely. Will call tonight!"
          and "parcel" in blocks[0] and blocks[0].count("\n") == 1)
    failures += check("split_batch blank-line splitting", ok,
                      "%d blocks, wrapped = %s" % (len(blocks), blocks[0].replace("\n", " | ")))
    print()

    # 2. CLI batch on a real file, JSON output, exit code
    fd, path = tempfile.mkstemp(suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(
                "Congratulations! You've won a lottery of $500,000. Claim your "
                "prize now! Send $2000 processing fee via UPI to "
                "receiver9021@ibl\n\n"
                "Hi mom, reached the airport. Will call in 2 hours.\n\n"
                "I recorded you through your webcam. Send 0.05 BTC within 48 "
                "hours or I will leak the video to your contacts.\n"
            )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(["--batch", path, "--json"])
        payload = json.loads(out.getvalue())
        rank = {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "LIKELY SCAM": 2, "SCAM": 3}
        verdicts = [m["final_verdict"] for m in payload["messages"]]
        ok = (
            rc == 2
            and payload["count"] == 3
            and rank[verdicts[0]] >= 2
            and verdicts[1] == "LIKELY SAFE"
            and rank[verdicts[2]] >= 2
        )
        failures += check("CLI --batch JSON", ok,
                          "rc=%d count=%d verdicts=%s" % (rc, payload["count"], verdicts))
    finally:
        os.unlink(path)
    print()

    # 3. human output + exit code for a single harmless message
    fd, path = tempfile.mkstemp(suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("Hi mom, reached the airport. Will call in 2 hours.\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(["--batch", path])
        text = out.getvalue()
        ok = rc == 0 and "Batch: 1 message" in text and "LIKELY SAFE" in text
        failures += check("CLI --batch human output", ok,
                          "rc=%d output=%s" % (rc, text.strip().splitlines()[1:3]))
    finally:
        os.unlink(path)

    print()
    if failures:
        print("FAILED: %d checks" % failures)
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
