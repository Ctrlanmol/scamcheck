"use client";

import Link from "next/link";
import { useState } from "react";
import { callTool, errorMessage } from "@/lib/client";
import { VerdictPanel } from "@/components/VerdictPanel";
import { ErrorBox } from "@/components/PageHeader";
import type { AnalyzeData } from "@/lib/types";

const SAMPLES = [
  {
    label: "Bank KYC",
    text: "URGENT: Your HDFC Bank account will be blocked in 24 hours. Complete KYC now and share the OTP with our officer: http://bit.ly/kyc-verify",
  },
  {
    label: "Parcel",
    text: "Your parcel is held at customs. Pay the 25 rupee clearance fee here: http://bit.ly/parcel-fee",
  },
  {
    label: "Safe",
    text: "Hi mom, I'll be home by 7. Can you pick up milk on the way?",
  },
];

export function QuickCheck() {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState<AnalyzeData | null>(null);

  async function run() {
    if (!text.trim()) {
      setError("Paste a message first.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const payload = await callTool<AnalyzeData>("analyze", { text });
      setData(payload);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="quick-check">
      <div className="between row">
        <div>
          <h2>Check a message now.</h2>
          <div className="sub">Rules + intelligence run locally. Nothing is uploaded.</div>
        </div>
        <span className="badge info">offline</span>
      </div>

      <div className="field">
        <label htmlFor="quick-text">Message or chat transcript</label>
        <textarea
          id="quick-text"
          className="textarea"
          value={text}
          onChange={(event) => setText(event.target.value)}
          placeholder="Paste an SMS, email, DM or full chat transcript…"
        />
      </div>

      <div className="btn-row" style={{ marginTop: 12 }}>
        <button className="btn" onClick={run} disabled={loading}>
          {loading ? <span className="spinner" /> : null}
          {loading ? "Analyzing" : "Analyze"}
        </button>
        <Link className="btn ghost small" href="/check">
          Full workbench
        </Link>
        <div className="row" style={{ marginLeft: "auto" }}>
          {SAMPLES.map((sample) => (
            <button
              key={sample.label}
              className="btn ghost small"
              onClick={() => {
                setText(sample.text);
                setData(null);
                setError("");
              }}
            >
              {sample.label}
            </button>
          ))}
        </div>
      </div>

      {error ? (
        <div style={{ marginTop: 14 }}>
          <ErrorBox>{error}</ErrorBox>
        </div>
      ) : null}

      {data ? (
        <div style={{ marginTop: 22, borderTop: "1px solid var(--line)", paddingTop: 20 }}>
          <VerdictPanel
            result={data.result}
            seen={data.seen}
            watchlist={data.watchlist}
            compact
          />
          <div className="btn-row" style={{ marginTop: 14 }}>
            <Link className="btn small" href="/check">
              Open full analysis
            </Link>
            <button
              className="btn ghost small"
              onClick={() => {
                setData(null);
                setText("");
              }}
            >
              Clear
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
