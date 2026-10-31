"use client";

import { useEffect, useRef, useState } from "react";
import { callTool, errorMessage } from "@/lib/client";
import { ErrorBox, SectionHead } from "@/components/PageHeader";
import { JsonPanel } from "@/components/JsonPanel";
import { VerdictPanel } from "@/components/VerdictPanel";
import type { AnalyzeResult } from "@/lib/types";

type JarvisReply = {
  text: string;
  quit: boolean;
  result?: AnalyzeResult;
  intel?: Record<string, unknown>;
  report?: Record<string, unknown>;
};

type Turn = {
  who: "user" | "jarvis";
  text: string;
  reply?: JarvisReply;
};

const SUGGESTIONS = [
  "help",
  "scan this: URGENT: your account is blocked, verify KYC at http://bit.ly/x1",
  "check number +91 98765 43210",
  "check link https://example.com",
  "campaigns",
  "watchlist",
  "recover upi",
  "history",
];

export function JarvisConsole({ defaultRegion }: { defaultRegion: string }) {
  const [turns, setTurns] = useState<Turn[]>([]);
  const [input, setInput] = useState("");
  const [region, setRegion] = useState(defaultRegion);
  const [lang, setLang] = useState("en");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [openJson, setOpenJson] = useState<number | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [turns, busy]);

  async function send(text?: string) {
    const message = (text ?? input).trim();
    if (!message) return;
    setInput("");
    setError("");
    setBusy(true);
    setTurns((prev) => [...prev, { who: "user", text: message }]);
    try {
      const reply = await callTool<JarvisReply>("jarvis", {
        message,
        region: region.trim() || undefined,
        lang,
      });
      setTurns((prev) => [
        ...prev,
        { who: "jarvis", text: reply.text || "(no reply)", reply },
      ]);
    } catch (err) {
      const messageText = errorMessage(err);
      setError(messageText);
      setTurns((prev) => [
        ...prev,
        { who: "jarvis", text: `Error: ${messageText}` },
      ]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="section" style={{ borderBottom: 0 }}>
      <SectionHead
        index="01"
        title="Console"
        note="The same command language as `python3 -m scamcheck --jarvis`, without the terminal."
      />

      <div className="split">
        <div>
          <div className="chat">
            {turns.length === 0 ? (
              <div className="empty" style={{ border: 0, margin: "auto" }}>
                Ask JARVIS to check a message, a number, a link, a case or this device.
              </div>
            ) : null}
            {turns.map((turn, index) => (
              <div className={`msg ${turn.who === "user" ? "user" : "bot"}`} key={index}>
                <span className="who">{turn.who === "user" ? "you" : "jarvis"}</span>
                <div className="body">{turn.text}</div>
                {turn.reply?.result ? (
                  <button
                    className="btn ghost small"
                    onClick={() => setOpenJson(openJson === index ? null : index)}
                  >
                    {openJson === index ? "Hide analysis" : "Show analysis"}
                  </button>
                ) : null}
                {openJson === index && turn.reply?.result ? (
                  <div style={{ marginTop: 10, width: "100%" }}>
                    <VerdictPanel
                      result={turn.reply.result}
                      compact
                    />
                  </div>
                ) : null}
                {turn.reply && !turn.reply.result && (turn.reply.intel || turn.reply.report) ? (
                  <div style={{ marginTop: 8, width: "100%" }}>
                    <JsonPanel
                      value={turn.reply.intel ?? turn.reply.report}
                      label="Raw payload"
                    />
                  </div>
                ) : null}
              </div>
            ))}
            {busy ? (
              <div className="msg bot">
                <span className="who">jarvis</span>
                <div className="body pulse">thinking…</div>
              </div>
            ) : null}
            <div ref={endRef} />
          </div>

          <form
            className="chat-form"
            onSubmit={(event) => {
              event.preventDefault();
              send();
            }}
          >
            <input
              className="input"
              value={input}
              onChange={(event) => setInput(event.target.value)}
              placeholder="scan this: … · check number … · check link … · recover upi · help"
              aria-label="JARVIS command"
            />
            <button className="btn" type="submit" disabled={busy}>
              {busy ? <span className="spinner" /> : null}
              {busy ? "Working" : "Send"}
            </button>
          </form>

          {error ? (
            <div style={{ marginTop: 12 }}>
              <ErrorBox>{error}</ErrorBox>
            </div>
          ) : null}

          <div className="tag-list" style={{ marginTop: 14 }}>
            {SUGGESTIONS.map((suggestion) => (
              <button
                className="tag"
                key={suggestion}
                onClick={() => send(suggestion)}
                disabled={busy}
                style={{ cursor: "pointer", background: "transparent" }}
              >
                {suggestion}
              </button>
            ))}
          </div>
        </div>

        <div className="stack">
          <div className="card">
            <div className="card-head">
              <div className="card-title">Session</div>
              <span className={`badge ${busy ? "caution" : "safe"}`}>
                {busy ? "busy" : "ready"}
              </span>
            </div>
            <div className="grid grid-2">
              <div className="field">
                <label htmlFor="jarvis-region">Region</label>
                <input
                  id="jarvis-region"
                  className="input"
                  value={region}
                  onChange={(event) => setRegion(event.target.value.toUpperCase())}
                  maxLength={2}
                />
              </div>
              <div className="field">
                <label htmlFor="jarvis-lang">Language</label>
                <select
                  id="jarvis-lang"
                  className="select"
                  value={lang}
                  onChange={(event) => setLang(event.target.value)}
                >
                  <option value="en">English</option>
                  <option value="hi">हिन्दी</option>
                </select>
              </div>
            </div>
            <div className="btn-row" style={{ marginTop: 14 }}>
              <button
                className="btn ghost small"
                onClick={() => {
                  setTurns([]);
                  setError("");
                }}
                disabled={!turns.length}
              >
                Clear transcript
              </button>
            </div>
          </div>

          <div className="card dark">
            <div className="card-head">
              <div className="card-title">Command map</div>
              <span className="card-kicker">local grammar</span>
            </div>
            <dl className="kv">
              <dt>scan this</dt>
              <dd>Analyze a message or transcript</dd>
              <dt>check number</dt>
              <dd>Phone range + local reputation</dd>
              <dt>check link</dt>
              <dd>Fetch and inspect a URL</dd>
              <dt>check image</dt>
              <dd>OCR a local path (CLI only)</dd>
              <dt>watchlist</dt>
              <dd>List watched identifiers</dd>
              <dt>campaigns</dt>
              <dd>Cluster related checks</dd>
              <dt>recover</dt>
              <dd>Recovery playbook by type</dd>
              <dt>history</dt>
              <dd>Recent local checks</dd>
              <dt>scan device</dt>
              <dd>Read-only device audit</dd>
              <dt>help</dt>
              <dd>Full command list</dd>
            </dl>
            <div className="note" style={{ marginTop: 14 }}>
              Voice, notifications and image-path commands are CLI-only. This console
              intentionally keeps the browser session quiet and stateless.
            </div>
          </div>

          <div className="card">
            <div className="card-head">
              <div className="card-title">Signal legend</div>
            </div>
            <div className="stack" style={{ gap: 8 }}>
              {[
                ["safe", "0–14", "No strong signals"],
                ["caution", "15–34", "Worth a second look"],
                ["warn", "35–59", "Multiple scam signals"],
                ["danger", "60–100", "Strong scam pattern"],
              ].map(([tone, range, text]) => (
                <div className="row between" key={tone}>
                  <span className={`badge ${tone}`}>{range}</span>
                  <span className="small muted">{text}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
