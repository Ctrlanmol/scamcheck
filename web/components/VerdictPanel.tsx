import { ScoreDial } from "@/components/ScoreDial";
import { JsonPanel } from "@/components/JsonPanel";
import { scoreTone, verdictLabel } from "@/lib/format";
import type { AnalyzeResult, Intelligence, Reason, WatchHit } from "@/lib/types";

function labelOf(item: unknown): string {
  if (typeof item === "string") return item;
  if (item && typeof item === "object") {
    const record = item as Record<string, unknown>;
    return String(record.label ?? record.name ?? record.value ?? record.key ?? "");
  }
  return "";
}

function labels(items?: unknown[]): string[] {
  return (items ?? []).map(labelOf).filter(Boolean);
}

function IntelBlock({ title, items }: { title: string; items: string[] }) {
  if (!items.length) return null;
  return (
    <div className="intel-block">
      <h4>{title}</h4>
      <ul>
        {items.map((item, index) => (
          <li key={`${title}-${index}`}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

function IntelText({ title, text }: { title: string; text?: string }) {
  if (!text) return null;
  return (
    <div className="intel-block">
      <h4>{title}</h4>
      <p>{text}</p>
    </div>
  );
}

export function VerdictPanel({
  result,
  seen = [],
  watchlist = [],
  compact = false,
}: {
  result: AnalyzeResult;
  seen?: WatchHit[];
  watchlist?: WatchHit[];
  compact?: boolean;
}) {
  const tone = scoreTone(result.score ?? 0);
  const intel: Intelligence = result.intelligence ?? {};
  const reasons: Reason[] = (result.reasons ?? []).filter((item) => item[1] > 0);
  const maxWeight = Math.max(1, ...reasons.map((item) => item[1]));
  const stage = intel.stage?.label || intel.stage?.key || "";

  return (
    <div className="verdict-panel">
      <div className="verdict-top">
        <ScoreDial score={result.score ?? 0} />
        <div className="verdict-copy">
          <div className="row">
            <span className={`badge ${tone}`}>{tone === "safe" ? "low risk" : tone}</span>
            <span className="badge">{result.kind === "image" ? "screenshot" : "message"}</span>
            {intel.scam_type ? <span className="badge info">{intel.scam_type}</span> : null}
          </div>
          <div className={`verdict-name ${tone}`}>{verdictLabel(result.final_verdict)}</div>
          <div className="verdict-sub">
            {intel.summary ||
              (result.scripts?.length
                ? `Playbook: ${result.scripts.join(" · ")}`
                : "Deterministic rule engine result.")}
          </div>
          {result.scripts?.length ? (
            <div className="tag-list">
              {result.scripts.map((script) => (
                <span className="tag acid" key={script}>
                  {script}
                </span>
              ))}
            </div>
          ) : null}
        </div>
      </div>

      {reasons.length ? (
        <div>
          <div className="card-kicker" style={{ marginBottom: 6 }}>
            Signals · {reasons.length}
          </div>
          {reasons.slice(0, compact ? 4 : 14).map(([label, weight], index) => (
            <div className="reason" key={`${label}-${index}`}>
              <div>{label}</div>
              <div className="reason-bar">
                <span
                  style={{
                    width: `${Math.max(4, (weight / maxWeight) * 100)}%`,
                    animationDelay: `${Math.min(index, 12) * 45}ms`,
                  }}
                />
              </div>
              <div className="reason-weight">+{weight}</div>
            </div>
          ))}
        </div>
      ) : null}

      {!compact && (intel.summary || intel.goals || intel.next_moves) ? (
        <div className="intel-grid">
          {stage ? <IntelText title="Kill-chain stage" text={stage} /> : null}
          {intel.reply_policy ? (
            <IntelText
              title="Reply policy"
              text={
                intel.reply_policy === "do_not_reply"
                  ? "Do not reply. Engagement confirms the number is live."
                  : String(intel.reply_policy).replaceAll("_", " ")
              }
            />
          ) : null}
          <IntelBlock title="Attacker goals" items={labels(intel.goals)} />
          <IntelBlock title="Payment rails" items={labels(intel.payment_rails)} />
          <IntelBlock
            title="Impersonation"
            items={(intel.impersonation ?? []).map((item) => {
              if (typeof item === "string") return item;
              const record = item as Record<string, unknown>;
              return [record.kind, record.name].filter(Boolean).join(": ");
            })}
          />
          <IntelBlock title="Tactics" items={labels(intel.tactics)} />
          <IntelBlock title="Channels" items={labels(intel.channels)} />
          <IntelBlock title="Likely next moves" items={labels(intel.next_moves)} />
          <IntelBlock title="Verify independently" items={labels(intel.verify)} />
          <IntelBlock title="Safe replies" items={labels(intel.safe_replies)} />
          <IntelBlock title="Evidence to preserve" items={labels(intel.evidence)} />
        </div>
      ) : null}

      {result.qr?.length ? (
        <div className="intel-block">
          <h4>QR / barcode payloads</h4>
          <ul>
            {result.qr.map((code, index) => (
              <li key={index}>
                <span className="mono">{code.payload}</span>
                {code.symbology ? <span className="muted"> · {code.symbology}</span> : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {result.extracted_text ? (
        <details className="raw">
          <summary>Extracted text · {result.ocr_engine || "OCR"}</summary>
          <div>
            <pre>{result.extracted_text}</pre>
          </div>
        </details>
      ) : null}

      {watchlist.length ? (
        <div className="note warn">
          <strong>Watchlist hit.</strong>{" "}
          {watchlist.map((hit) => `${hit.kind}:${hit.value}`).join(", ")} reappeared in this check.
        </div>
      ) : null}

      {seen.length ? (
        <div className="note">
          <strong>Seen before.</strong>{" "}
          {seen.map((hit) => `${hit.kind}:${hit.value} (${hit.count ?? 1}×)`).join(", ")}
        </div>
      ) : null}

      {!compact ? <JsonPanel value={result} label="Full result JSON" /> : null}
    </div>
  );
}
