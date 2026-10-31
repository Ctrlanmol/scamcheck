"use client";

import { useEffect, useState } from "react";
import { callTool, errorMessage } from "@/lib/client";
import { ago, formatDate, scoreTone, snippet } from "@/lib/format";
import { Empty, ErrorBox, Note, SectionHead, Stat } from "@/components/PageHeader";
import { JsonPanel } from "@/components/JsonPanel";
import type { Campaign, HistoryRow } from "@/lib/types";

function CampaignDetail({ campaign }: { campaign: Campaign }) {
  return (
    <div className="stack">
      <div className="card">
        <div className="card-head">
          <div>
            <div className="card-title">{campaign.id}</div>
            <div className="tiny muted mono" style={{ marginTop: 4 }}>
              first {formatDate(campaign.first_ts)} · last {formatDate(campaign.last_ts)}
            </div>
          </div>
          <span className="badge info">{campaign.checks} checks</span>
        </div>

        <div className="grid grid-4">
          {Object.entries(campaign.verdicts).map(([verdict, count]) => (
            <Stat key={verdict} label={verdict} value={count} />
          ))}
        </div>

        <div className="card-kicker" style={{ margin: "20px 0 10px" }}>
          Shared indicators · {campaign.indicators.length}
        </div>
        <div className="tag-list">
          {campaign.indicators.map((indicator) => (
            <span className="tag acid" key={`${indicator.kind}:${indicator.value}`}>
              {indicator.kind}: {indicator.label || indicator.value} · {indicator.checks}
            </span>
          ))}
        </div>
      </div>

      <div className="card flush">
        <div className="card-head" style={{ padding: "14px 16px", marginBottom: 0 }}>
          <div className="card-title">Checks in this cluster</div>
          <span className="card-kicker">newest first</span>
        </div>
        <div className="table-wrap" style={{ border: 0 }}>
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Kind</th>
                <th>Verdict</th>
                <th>Score</th>
                <th>Text</th>
              </tr>
            </thead>
            <tbody>
              {campaign.items.map((row: HistoryRow) => (
                <tr key={row.id}>
                  <td className="mono muted">{ago(row.ts)}</td>
                  <td className="mono">{row.kind}</td>
                  <td>
                    <span className={`badge ${scoreTone(row.score)}`}>{row.verdict}</span>
                  </td>
                  <td className="mono">{row.score}</td>
                  <td>{snippet(row.text, 120)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <JsonPanel value={campaign} label="Campaign JSON" />
    </div>
  );
}

export function CampaignsWorkbench() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function refresh() {
    setLoading(true);
    setError("");
    try {
      const rows = await callTool<Campaign[]>("campaigns", { limit: 100 });
      setCampaigns(rows);
      setSelected((current) =>
        current && rows.some((row) => row.id === current)
          ? current
          : rows[0]?.id ?? null,
      );
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  const active = campaigns.find((row) => row.id === selected) ?? null;
  const totalChecks = campaigns.reduce((sum, row) => sum + row.checks, 0);
  const totalIndicators = campaigns.reduce(
    (sum, row) => sum + row.indicators.length,
    0,
  );

  return (
    <>
      <section className="section">
        <SectionHead
          index="01"
          title="Cluster overview"
          action={
            <button className="btn ghost small" onClick={refresh} disabled={loading}>
              {loading ? <span className="spinner light" /> : null}
              Rebuild clusters
            </button>
          }
        />
        <div className="grid grid-3">
          <Stat label="Campaigns" value={campaigns.length} hint="2+ shared checks" />
          <Stat label="Checks clustered" value={totalChecks} hint="across all campaigns" />
          <Stat label="Indicators" value={totalIndicators} hint="phones · URLs · wallets" />
        </div>
        {error ? (
          <div style={{ marginTop: 14 }}>
            <ErrorBox>{error}</ErrorBox>
          </div>
        ) : null}
      </section>

      <section className="section" style={{ borderBottom: 0 }}>
        <div className="split">
          <div className="stack">
            <div className="card flush">
              <div className="card-head" style={{ padding: "14px 16px", marginBottom: 0 }}>
                <div className="card-title">Campaigns</div>
                <span className="card-kicker">{campaigns.length}</span>
              </div>
              {campaigns.length ? (
                <div className="table-wrap" style={{ border: 0 }}>
                  <table>
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Checks</th>
                        <th>Indicators</th>
                        <th>Last seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {campaigns.map((campaign) => (
                        <tr
                          key={campaign.id}
                          onClick={() => setSelected(campaign.id)}
                          style={{
                            cursor: "pointer",
                            background:
                              campaign.id === selected
                                ? "rgba(216,255,62,0.055)"
                                : undefined,
                          }}
                        >
                          <td className="mono">{campaign.id}</td>
                          <td className="mono">{campaign.checks}</td>
                          <td className="mono">{campaign.indicators.length}</td>
                          <td className="mono muted">{ago(campaign.last_ts)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty>
                  {loading
                    ? "Building clusters…"
                    : "No campaigns yet — two checks must share a phone, URL, UPI ID or wallet."}
                </Empty>
              )}
            </div>
            <Note>
              Campaigns are derived, not stored. They are rebuilt from local check
              memory each time, so deleting history removes the cluster too.
            </Note>
          </div>

          <div>
            {active ? (
              <CampaignDetail campaign={active} />
            ) : (
              <div className="card dark">
                <div className="card-head">
                  <div className="card-title">No cluster selected</div>
                </div>
                <p className="small muted">
                  Run two or more checks that share an identifier. A campaign
                  appears automatically.
                </p>
              </div>
            )}
          </div>
        </div>
      </section>
    </>
  );
}
