"use client";

import { useEffect, useState } from "react";
import { callTool, errorMessage } from "@/lib/client";
import { ago, formatDate, scoreTone, snippet } from "@/lib/format";
import { Empty, ErrorBox, Note, SectionHead, Stat } from "@/components/PageHeader";
import { JsonPanel } from "@/components/JsonPanel";
import type { HistoryRow, StatusData } from "@/lib/types";

type Regions = {
  current: string;
  regions: { code: string; dial: string; label: string }[];
};

type BotStatus = Record<string, unknown>;

export function SettingsWorkbench() {
  const [status, setStatus] = useState<StatusData | null>(null);
  const [regions, setRegions] = useState<Regions | null>(null);
  const [history, setHistory] = useState<HistoryRow[]>([]);
  const [bot, setBot] = useState<BotStatus | null>(null);
  const [region, setRegion] = useState("");
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [search, setSearch] = useState("");

  async function refresh() {
    try {
      const [nextStatus, nextRegions, nextHistory, nextBot] = await Promise.all([
        callTool<StatusData>("status", {}),
        callTool<Regions>("regions", {}),
        callTool<HistoryRow[]>("history", { action: "recent", limit: 20 }),
        callTool<BotStatus>("bot_status", {}),
      ]);
      setStatus(nextStatus);
      setRegions(nextRegions);
      setRegion(nextRegions.current);
      setHistory(nextHistory);
      setBot(nextBot);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function saveRegion() {
    setBusy(true);
    setError("");
    setNote("");
    try {
      const result = await callTool<{ region: string; label: string }>("set_region", {
        region,
      });
      setNote(`Region set to ${result.region} (${result.label}).`);
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function clearHistory() {
    setBusy(true);
    setError("");
    setNote("");
    try {
      const result = await callTool<{ cleared: number }>("history", { action: "clear" });
      setNote(`Removed ${result.cleared} checks from local memory.`);
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function searchHistory() {
    if (!search.trim()) {
      await refresh();
      return;
    }
    setBusy(true);
    setError("");
    try {
      setHistory(
        await callTool<HistoryRow[]>("history", { action: "search", term: search, limit: 50 }),
      );
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <section className="section">
        <SectionHead
          index="01"
          title="Runtime"
          note="Everything below is read from the local Python bridge and the ~/.scamcheck directory."
          action={
            <button className="btn ghost small" onClick={refresh} disabled={busy}>
              Refresh
            </button>
          }
        />
        <div className="grid grid-4">
          <Stat label="Version" value={status?.version ?? "—"} hint="scamcheck core" />
          <Stat label="Platform" value={status?.platform ?? "—"} hint="audit coverage varies" />
          <Stat label="Checks" value={status?.history ?? 0} hint="local memory" />
          <Stat label="Cases" value={status?.cases ?? 0} hint="evidence vault" />
        </div>
        {status ? (
          <div className="card" style={{ marginTop: 16 }}>
            <dl className="kv">
              <dt>Data directory</dt>
              <dd className="mono" style={{ fontSize: 11 }}>{status.data_dir}</dd>
              <dt>Region</dt>
              <dd>{status.region}</dd>
              <dt>AI layer</dt>
              <dd>{status.ai ? "API key detected — still opt-in per request" : "off (no API key)"}</dd>
              <dt>Cached feeds</dt>
              <dd>
                {status.feeds.sources.length} sources ·{" "}
                {status.feeds.updated_at ? ago(status.feeds.updated_at) : "never updated"}
              </dd>
              <dt>Watchlist</dt>
              <dd>{status.watchlist} identifiers</dd>
              <dt>Device audit</dt>
              <dd>
                {status.device_audit.supported ? "full" : "inventory only"} · active LAN{" "}
                {status.device_audit.active_lan ? "available" : "unavailable"}
              </dd>
            </dl>
          </div>
        ) : null}
        {error ? (
          <div style={{ marginTop: 14 }}>
            <ErrorBox>{error}</ErrorBox>
          </div>
        ) : null}
        {note ? (
          <div className="note" style={{ marginTop: 14 }}>
            {note}
          </div>
        ) : null}
      </section>

      <section className="section">
        <SectionHead
          index="02"
          title="Region"
          note="Used for number parsing, recovery contacts and default country context."
        />
        <div className="split">
          <div className="card">
            <div className="card-head">
              <div className="card-title">Default region</div>
              <span className="card-kicker">{regions?.regions.length ?? 0} available</span>
            </div>
            <div className="row">
              <select
                className="select"
                style={{ maxWidth: 380 }}
                value={region}
                onChange={(event) => setRegion(event.target.value)}
              >
                {(regions?.regions ?? []).map((item) => (
                  <option value={item.code} key={item.code}>
                    {item.code} · {item.label} (+{item.dial})
                  </option>
                ))}
              </select>
              <button className="btn" onClick={saveRegion} disabled={busy || !region}>
                Save region
              </button>
            </div>
            <Note>
              The region is stored in <span className="mono">config.json</span> with mode
              0600. It never leaves the machine.
            </Note>
          </div>
          <div className="card dark">
            <div className="card-head">
              <div className="card-title">Environment overrides</div>
            </div>
            <dl className="kv">
              <dt>SCAMCHECK_HOME</dt>
              <dd>Move the data directory (tests use this)</dd>
              <dt>SCAMCHECK_REGION</dt>
              <dd>Override the saved region</dd>
              <dt>SCAMCHECK_PYTHON</dt>
              <dd>Python binary used by the web bridge</dd>
              <dt>SCAMCHECK_ROOT</dt>
              <dd>Project root if the app is run elsewhere</dd>
            </dl>
          </div>
        </div>
      </section>

      <section className="section">
        <SectionHead
          index="03"
          title="Local memory"
          note="Checks power the dashboard, campaigns and watchlist hits. Clearing is irreversible."
        />
        <div className="split">
          <div className="card">
            <div className="card-head">
              <div className="card-title">Recent checks</div>
              <div className="btn-row">
                <input
                  className="input"
                  style={{ maxWidth: 200 }}
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search text…"
                  onKeyDown={(event) => {
                    if (event.key === "Enter") searchHistory();
                  }}
                />
                <button className="btn ghost small" onClick={searchHistory} disabled={busy}>
                  Search
                </button>
                <button
                  className="btn ghost small"
                  onClick={() => {
                    setSearch("");
                    refresh();
                  }}
                  disabled={busy}
                >
                  Reset
                </button>
              </div>
            </div>
            {history.length ? (
              <div className="table-wrap">
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
                    {history.map((row) => (
                      <tr key={row.id}>
                        <td className="mono muted">{ago(row.ts)}</td>
                        <td className="mono">{row.kind}</td>
                        <td>
                          <span className={`badge ${scoreTone(row.score)}`}>{row.verdict}</span>
                        </td>
                        <td className="mono">{row.score}</td>
                        <td>{snippet(row.text, 90)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty>No checks recorded.</Empty>
            )}
            <div className="btn-row" style={{ marginTop: 14 }}>
              <button className="btn danger" onClick={clearHistory} disabled={busy || !status?.history}>
                Clear all history
              </button>
              <span className="tiny muted">
                This also removes campaign clusters derived from it.
              </span>
            </div>
          </div>

          <div className="stack">
            <Note tone="danger">
              <strong>Irreversible.</strong> Clearing history deletes every stored check,
              its identifiers and campaign links. Cases and evidence files are separate and
              are not touched.
            </Note>
            <div className="card dark">
              <div className="card-head">
                <div className="card-title">Data files</div>
              </div>
              <dl className="kv">
                <dt>history.db</dt>
                <dd>Checks, identifiers, campaigns</dd>
                <dt>cases.db</dt>
                <dd>Case metadata and hashes</dd>
                <dt>cases/</dt>
                <dd>Evidence files and exports</dd>
                <dt>watchlist.db</dt>
                <dd>Watched identifiers</dd>
                <dt>device-reports/</dt>
                <dd>Device audit exports</dd>
                <dt>feeds.json</dt>
                <dd>Opt-in phone feeds cache</dd>
                <dt>config.json</dt>
                <dd>Region and preferences</dd>
              </dl>
            </div>
          </div>
        </div>
      </section>

      <section className="section">
        <SectionHead
          index="04"
          title="Bots"
          note="Chat bots are configured with environment variables and run from the CLI. This page only reports status."
        />
        <div className="split">
          <div className="card">
            <div className="card-head">
              <div className="card-title">Bot status</div>
              <span className={`badge ${bot?.telegram_token || bot?.whatsapp_token ? "safe" : "info"}`}>
                {bot?.telegram_token || bot?.whatsapp_token ? "configured" : "not configured"}
              </span>
            </div>
            <dl className="kv">
              <dt>Telegram token</dt>
              <dd className="mono">{String(bot?.telegram_token ?? "not set")}</dd>
              <dt>Telegram API</dt>
              <dd className="mono" style={{ fontSize: 11 }}>{String(bot?.telegram_api ?? "—")}</dd>
              <dt>WhatsApp token</dt>
              <dd>{bot?.whatsapp_token ? "set" : "not set"}</dd>
              <dt>WhatsApp phone ID</dt>
              <dd className="mono">{String(bot?.whatsapp_phone_id ?? "—")}</dd>
              <dt>Verify token</dt>
              <dd>{bot?.whatsapp_verify_token_set ? "set" : "not set"}</dd>
              <dt>App secret</dt>
              <dd>{bot?.whatsapp_app_secret_set ? "set" : "not set"}</dd>
              <dt>Rate limit</dt>
              <dd>{String(bot?.rate_limit_per_hour ?? "—")} / hour</dd>
            </dl>
            {bot ? (
              <div style={{ marginTop: 14 }}>
                <JsonPanel value={bot} label="Bot status JSON" />
              </div>
            ) : null}
          </div>
          <div className="stack">
            <div className="card dark">
              <div className="card-head">
                <div className="card-title">Start a bot</div>
              </div>
              <pre className="code">{`# Telegram (long polling, no public URL)
SCAMCHECK_TELEGRAM_TOKEN=... \\
  python3 -m scamcheck --bot telegram

# WhatsApp Cloud API (needs a public webhook)
WHATSAPP_TOKEN=... WHATSAPP_PHONE_ID=... \\
  python3 -m scamcheck --bot whatsapp`}</pre>
            </div>
            <Note>
              Bots are not started by the web app. This keeps the interface a pure local
              client with no inbound listeners.
            </Note>
          </div>
        </div>
      </section>
    </>
  );
}
