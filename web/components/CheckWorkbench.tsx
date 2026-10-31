"use client";

import { useRef, useState } from "react";
import { callTool, errorMessage } from "@/lib/client";
import { fileToBase64 } from "@/lib/file";
import { scoreTone, snippet, verdictLabel } from "@/lib/format";
import { ErrorBox, Note, SectionHead } from "@/components/PageHeader";
import { JsonPanel } from "@/components/JsonPanel";
import { ScoreDial } from "@/components/ScoreDial";
import { VerdictPanel } from "@/components/VerdictPanel";
import type {
  AnalyzeData,
  AnalyzeResult,
  BatchData,
  UrlData,
} from "@/lib/types";

const TABS = [
  ["message", "Message"],
  ["conversation", "Conversation"],
  ["screenshot", "Screenshot"],
  ["batch", "Batch"],
  ["link", "Link"],
  ["qr", "QR / barcode"],
] as const;

type Tab = (typeof TABS)[number][0];

const SAMPLE_SCAM =
  "URGENT: Your HDFC Bank account will be blocked in 24 hours. Complete KYC now and share the OTP with our officer: http://bit.ly/kyc-verify";
const SAMPLE_CHAT = `Hi dear, I like your profile.
I can teach you trading with guaranteed returns.
Open an account on our platform and deposit 500 USDT.
Now pay 20% tax to withdraw your profit.
Don't tell anyone.`;

function MessageForm({
  defaultRegion,
  chatMode,
}: {
  defaultRegion: string;
  chatMode: boolean;
}) {
  const [text, setText] = useState("");
  const [sender, setSender] = useState("");
  const [region, setRegion] = useState(defaultRegion);
  const [ai, setAi] = useState("auto");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState<AnalyzeData | null>(null);

  async function run() {
    if (!text.trim()) {
      setError("Paste a message or transcript first.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      setData(
        await callTool<AnalyzeData>("analyze", {
          text,
          chat: chatMode,
          sender: sender.trim() || undefined,
          region: region.trim() || undefined,
          ai,
        }),
      );
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="stack">
      <div className="card">
        <div className="card-head">
          <div className="card-title">{chatMode ? "Full conversation" : "Single message"}</div>
          <span className="card-kicker">{chatMode ? "trajectory mode" : "message mode"}</span>
        </div>
        <div className="field">
          <label htmlFor="check-text">
            {chatMode ? "Chat transcript — one message per line" : "Message text"}
          </label>
          <textarea
            id="check-text"
            className={`textarea${chatMode ? " tall" : ""}`}
            value={text}
            onChange={(event) => setText(event.target.value)}
            placeholder={
              chatMode
                ? "Paste the whole chat. The engine scores the shape over time: grooming → money pivot → deposit → fee → pressure → secrecy."
                : "Paste an SMS, email, DM or notification…"
            }
          />
        </div>
        <div className="grid grid-3" style={{ marginTop: 14 }}>
          <div className="field">
            <label htmlFor="check-sender">Sender number (optional)</label>
            <input
              id="check-sender"
              className="input"
              value={sender}
              onChange={(event) => setSender(event.target.value)}
              placeholder="+91 98765 43210"
            />
          </div>
          <div className="field">
            <label htmlFor="check-region">Region</label>
            <input
              id="check-region"
              className="input"
              value={region}
              onChange={(event) => setRegion(event.target.value.toUpperCase())}
              placeholder="IN"
              maxLength={2}
            />
          </div>
          <div className="field">
            <label htmlFor="check-ai">AI second opinion</label>
            <select
              id="check-ai"
              className="select"
              value={ai}
              onChange={(event) => setAi(event.target.value)}
            >
              <option value="auto">Auto · borderline only</option>
              <option value="never">Never · offline only</option>
              <option value="always">Always · needs a key</option>
            </select>
          </div>
        </div>
        <div className="btn-row" style={{ marginTop: 16 }}>
          <button className="btn" onClick={run} disabled={loading}>
            {loading ? <span className="spinner" /> : null}
            {loading ? "Analyzing" : chatMode ? "Analyze conversation" : "Analyze message"}
          </button>
          <button
            className="btn ghost small"
            onClick={() => {
              setText(chatMode ? SAMPLE_CHAT : SAMPLE_SCAM);
              setData(null);
              setError("");
            }}
          >
            Load sample
          </button>
          <button
            className="btn ghost small"
            onClick={() => {
              setText("");
              setSender("");
              setData(null);
              setError("");
            }}
          >
            Clear
          </button>
          <span className="tiny muted" style={{ marginLeft: "auto" }}>
            {chatMode ? "Uses the conversation trajectory engine" : "Uses weighted rules + intel"}
          </span>
        </div>
        {error ? (
          <div style={{ marginTop: 14 }}>
            <ErrorBox>{error}</ErrorBox>
          </div>
        ) : null}
      </div>

      {data ? (
        <div className="card">
          <VerdictPanel result={data.result} seen={data.seen} watchlist={data.watchlist} />
        </div>
      ) : null}
    </div>
  );
}

function ScreenshotForm({ defaultRegion }: { defaultRegion: string }) {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState("");
  const [region, setRegion] = useState(defaultRegion);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState<AnalyzeData | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  function choose(next: File | null) {
    setFile(next);
    setData(null);
    setError("");
    if (preview) URL.revokeObjectURL(preview);
    setPreview(next ? URL.createObjectURL(next) : "");
  }

  async function run() {
    if (!file) {
      setError("Choose a screenshot first.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const image_b64 = await fileToBase64(file);
      setData(
        await callTool<AnalyzeData>("analyze_image", {
          image_b64,
          filename: file.name,
          region: region.trim() || undefined,
        }),
      );
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="stack">
      <div className="card">
        <div className="card-head">
          <div className="card-title">Screenshot → OCR → verdict</div>
          <span className="card-kicker">Apple Vision · tesseract · QR</span>
        </div>
        <div className="split">
          <div className="stack">
            <div className="field">
              <label htmlFor="shot-file">Image file</label>
              <input
                ref={inputRef}
                id="shot-file"
                className="input"
                type="file"
                accept="image/*"
                onChange={(event) => choose(event.target.files?.[0] ?? null)}
              />
            </div>
            <div className="field">
              <label htmlFor="shot-region">Region</label>
              <input
                id="shot-region"
                className="input"
                value={region}
                onChange={(event) => setRegion(event.target.value.toUpperCase())}
                maxLength={2}
              />
            </div>
            <div className="btn-row">
              <button className="btn" onClick={run} disabled={loading || !file}>
                {loading ? <span className="spinner" /> : null}
                {loading ? "Reading image" : "Read & analyze"}
              </button>
              <button
                className="btn ghost small"
                onClick={() => {
                  choose(null);
                  if (inputRef.current) inputRef.current.value = "";
                }}
              >
                Clear
              </button>
            </div>
            <Note>
              Images are sent to the local Python bridge only. OCR runs on this machine; no
              image leaves the device.
            </Note>
          </div>
          <div>
            {preview ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                src={preview}
                alt="Selected screenshot preview"
                style={{
                  width: "100%",
                  maxHeight: 340,
                  objectFit: "contain",
                  border: "1px solid var(--line)",
                  background: "#080807",
                }}
              />
            ) : (
              <div className="empty">No image selected</div>
            )}
          </div>
        </div>
        {error ? (
          <div style={{ marginTop: 14 }}>
            <ErrorBox>{error}</ErrorBox>
          </div>
        ) : null}
      </div>

      {data ? (
        <div className="card">
          <VerdictPanel result={data.result} seen={data.seen} watchlist={data.watchlist} />
        </div>
      ) : null}
    </div>
  );
}

function BatchForm({ defaultRegion }: { defaultRegion: string }) {
  const [text, setText] = useState("");
  const [region, setRegion] = useState(defaultRegion);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState<BatchData | null>(null);
  const [selected, setSelected] = useState<number | null>(null);

  async function run() {
    if (!text.trim()) {
      setError("Paste messages separated by blank lines.");
      return;
    }
    setLoading(true);
    setError("");
    setSelected(null);
    try {
      setData(
        await callTool<BatchData>("batch", {
          text,
          region: region.trim() || undefined,
        }),
      );
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  const active: AnalyzeResult | null =
    data && selected !== null ? data.messages[selected] ?? null : null;

  return (
    <div className="stack">
      <div className="card">
        <div className="card-head">
          <div className="card-title">Batch check</div>
          <span className="card-kicker">blank line = one message</span>
        </div>
        <div className="field">
          <label htmlFor="batch-text">Inbox dump or pasted messages</label>
          <textarea
            id="batch-text"
            className="textarea tall"
            value={text}
            onChange={(event) => setText(event.target.value)}
            placeholder={"First message…\n\nSecond message…\n\nThird message…"}
          />
        </div>
        <div className="row" style={{ marginTop: 12 }}>
          <div className="field" style={{ width: 110 }}>
            <label htmlFor="batch-region">Region</label>
            <input
              id="batch-region"
              className="input"
              value={region}
              onChange={(event) => setRegion(event.target.value.toUpperCase())}
              maxLength={2}
            />
          </div>
          <button className="btn" onClick={run} disabled={loading} style={{ alignSelf: "flex-end" }}>
            {loading ? <span className="spinner" /> : null}
            {loading ? "Checking" : "Check batch"}
          </button>
          <span className="tiny muted">capped at 50 messages per request</span>
        </div>
        {error ? (
          <div style={{ marginTop: 14 }}>
            <ErrorBox>{error}</ErrorBox>
          </div>
        ) : null}
      </div>

      {data ? (
        <div className="card flush">
          <div className="table-wrap" style={{ border: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Verdict</th>
                  <th>Score</th>
                  <th>Message</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.messages.map((row, index) => (
                  <tr key={index}>
                    <td className="mono">{index + 1}</td>
                    <td>
                      <span className={`badge ${scoreTone(row.score)}`}>{row.final_verdict}</span>
                    </td>
                    <td className="mono">{row.score}</td>
                    <td>{snippet(row.message, 100)}</td>
                    <td>
                      <button className="btn ghost small" onClick={() => setSelected(index)}>
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      {active ? (
        <div className="card">
          <div className="card-head">
            <div className="card-title">Message {selected! + 1}</div>
            <button className="btn ghost small" onClick={() => setSelected(null)}>
              Close
            </button>
          </div>
          <VerdictPanel result={active} compact />
          <div style={{ marginTop: 14 }}>
            <JsonPanel value={active} label="Message JSON" />
          </div>
        </div>
      ) : null}
    </div>
  );
}

function LinkForm() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState<UrlData | null>(null);

  async function run() {
    if (!url.trim()) {
      setError("Enter a URL first.");
      return;
    }
    setLoading(true);
    setError("");
    setData(null);
    try {
      setData(await callTool<UrlData>("url", { url }));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  const report = data?.report;
  return (
    <div className="stack">
      <div className="card">
        <div className="card-head">
          <div className="card-title">Link investigation</div>
          <span className="card-kicker">the only online tool</span>
        </div>
        <Note tone="warn">
          This fetches the URL, follows redirects, inspects TLS and asks RDAP for the domain
          registration date. Only use it on links you are willing to contact. Private and
          loopback targets are refused.
        </Note>
        <div className="row" style={{ marginTop: 14 }}>
          <input
            className="input"
            style={{ flex: 1, minWidth: 260 }}
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="https://suspicious.example/path"
            onKeyDown={(event) => {
              if (event.key === "Enter") run();
            }}
          />
          <button className="btn" onClick={run} disabled={loading}>
            {loading ? <span className="spinner" /> : null}
            {loading ? "Investigating" : "Investigate"}
          </button>
        </div>
        {error ? (
          <div style={{ marginTop: 14 }}>
            <ErrorBox>{error}</ErrorBox>
          </div>
        ) : null}
      </div>

      {data && report ? (
        <div className="card">
          <div className="verdict-top">
            <ScoreDial score={data.score} label="link risk" />
            <div className="verdict-copy">
              <div className="row">
                <span className={`badge ${scoreTone(data.score)}`}>{data.verdict}</span>
                <span className="badge info">{report.https ? "https" : "http"}</span>
              </div>
              <div className={`verdict-name ${scoreTone(data.score)}`}>
                {verdictLabel(data.verdict)}
              </div>
              <div className="verdict-sub mono">{report.domain || report.final_url}</div>
              {report.title ? <div className="verdict-sub">{report.title}</div> : null}
            </div>
          </div>

          <dl className="kv" style={{ marginTop: 18 }}>
            <dt>Final URL</dt>
            <dd className="mono">{report.final_url || "—"}</dd>
            <dt>Server</dt>
            <dd>{report.server || "—"}</dd>
            <dt>TLS</dt>
            <dd>
              {report.tls
                ? `${report.tls.tls_version || "TLS"} · ${report.tls.issuer || "unknown issuer"} · expires ${
                    report.tls.not_after || "?"
                  }`
                : "no TLS metadata"}
            </dd>
            <dt>RDAP</dt>
            <dd className="mono" style={{ fontSize: 11 }}>
              {report.rdap ? JSON.stringify(report.rdap) : "no registration data"}
            </dd>
          </dl>

          {data.notes.length ? (
            <div className="stack" style={{ marginTop: 16 }}>
              {data.notes.map((note, index) => (
                <div className="note" key={index}>
                  {note}
                </div>
              ))}
            </div>
          ) : (
            <div className="note" style={{ marginTop: 16 }}>
              No link red flags from the local checks. This is not a guarantee.
            </div>
          )}

          {report.chain?.length ? (
            <div className="table-wrap" style={{ marginTop: 16 }}>
              <table>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Redirect chain</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {report.chain.map((hop, index) => (
                    <tr key={index}>
                      <td className="mono">{index + 1}</td>
                      <td className="mono" style={{ wordBreak: "break-all" }}>
                        {hop.url}
                      </td>
                      <td className="mono">{hop.status ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}

          <div style={{ marginTop: 16 }}>
            <JsonPanel value={data} label="Link report JSON" />
          </div>
        </div>
      ) : null}
    </div>
  );
}

function QrForm() {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState<{
    available: boolean;
    codes: { payload: string; symbology?: string }[];
    error?: string;
  } | null>(null);

  async function run() {
    if (!file) {
      setError("Choose an image first.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const image_b64 = await fileToBase64(file);
      setData(
        await callTool<{
          available: boolean;
          codes: { payload: string; symbology?: string }[];
          error?: string;
        }>("decode_image", { image_b64, filename: file.name }),
      );
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="stack">
      <div className="card">
        <div className="card-head">
          <div className="card-title">QR / barcode decode</div>
          <span className="card-kicker">offline · no execution</span>
        </div>
        <div className="row">
          <input
            className="input"
            type="file"
            accept="image/*"
            onChange={(event) => {
              setFile(event.target.files?.[0] ?? null);
              setData(null);
              setError("");
            }}
          />
          <button className="btn" onClick={run} disabled={loading || !file}>
            {loading ? <span className="spinner" /> : null}
            {loading ? "Decoding" : "Decode"}
          </button>
        </div>
        {error ? (
          <div style={{ marginTop: 14 }}>
            <ErrorBox>{error}</ErrorBox>
          </div>
        ) : null}
        {data ? (
          <div style={{ marginTop: 16 }}>
            {data.codes.length ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Payload</th>
                      <th>Symbology</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.codes.map((code, index) => (
                      <tr key={index}>
                        <td className="mono">{index + 1}</td>
                        <td className="mono" style={{ wordBreak: "break-all" }}>
                          {code.payload}
                        </td>
                        <td className="mono">{code.symbology || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty">
                {data.available ? "No QR or barcode found." : data.error || "Decoder unavailable."}
              </div>
            )}
            <div style={{ marginTop: 12 }}>
              <JsonPanel value={data} label="Decode JSON" />
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function CheckWorkbench({ defaultRegion }: { defaultRegion: string }) {
  const [tab, setTab] = useState<Tab>("message");

  return (
    <section className="section" style={{ borderBottom: 0 }}>
      <SectionHead
        index="01"
        title="Workbench"
        note="Message, conversation, screenshot, batch, link or QR — all through one local bridge."
      />
      <div className="tabs" role="tablist" aria-label="Check type">
        {TABS.map(([key, label]) => (
          <button
            key={key}
            role="tab"
            aria-selected={tab === key}
            className={`tab${tab === key ? " active" : ""}`}
            onClick={() => setTab(key)}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "message" ? (
        <MessageForm defaultRegion={defaultRegion} chatMode={false} />
      ) : null}
      {tab === "conversation" ? (
        <MessageForm defaultRegion={defaultRegion} chatMode />
      ) : null}
      {tab === "screenshot" ? <ScreenshotForm defaultRegion={defaultRegion} /> : null}
      {tab === "batch" ? <BatchForm defaultRegion={defaultRegion} /> : null}
      {tab === "link" ? <LinkForm /> : null}
      {tab === "qr" ? <QrForm /> : null}
    </section>
  );
}
