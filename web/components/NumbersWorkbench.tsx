"use client";

import { useEffect, useState } from "react";
import { callTool, errorMessage } from "@/lib/client";
import { ErrorBox, Note, SectionHead } from "@/components/PageHeader";
import { JsonPanel } from "@/components/JsonPanel";
import { ago } from "@/lib/format";
import type { FeedStatus, NumberData } from "@/lib/types";

type Lists = {
  blocked: Record<string, { number: string; label: string }>;
  allowed: Record<string, { number: string; label: string }>;
};

function riskTone(risk?: string): string {
  if (risk === "high") return "danger";
  if (risk === "medium") return "warn";
  return "safe";
}

export function NumbersWorkbench({ defaultRegion }: { defaultRegion: string }) {
  const [number, setNumber] = useState("");
  const [region, setRegion] = useState(defaultRegion);
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState("");
  const [data, setData] = useState<NumberData | null>(null);

  const [lists, setLists] = useState<Lists | null>(null);
  const [feeds, setFeeds] = useState<FeedStatus | null>(null);
  const [entryNumber, setEntryNumber] = useState("");
  const [entryLabel, setEntryLabel] = useState("");
  const [listError, setListError] = useState("");
  const [listBusy, setListBusy] = useState(false);
  const [importText, setImportText] = useState("");
  const [importTarget, setImportTarget] = useState("block");
  const [importBusy, setImportBusy] = useState(false);
  const [importResult, setImportResult] = useState("");
  const [feedBusy, setFeedBusy] = useState(false);
  const [feedNote, setFeedNote] = useState("");

  async function refreshLists() {
    try {
      setLists(await callTool<Lists>("lists", {}));
    } catch (err) {
      setListError(errorMessage(err));
    }
  }

  async function refreshFeeds() {
    try {
      setFeeds(await callTool<FeedStatus>("feeds_status", {}));
    } catch (err) {
      setFeedNote(errorMessage(err));
    }
  }

  useEffect(() => {
    refreshLists();
    refreshFeeds();
  }, []);

  async function check() {
    if (!number.trim()) {
      setCheckError("Enter a phone number.");
      return;
    }
    setChecking(true);
    setCheckError("");
    try {
      setData(
        await callTool<NumberData>("check_number", {
          number,
          region: region.trim() || undefined,
        }),
      );
    } catch (err) {
      setCheckError(errorMessage(err));
    } finally {
      setChecking(false);
    }
  }

  async function add(action: "block" | "allow" | "forget") {
    if (!entryNumber.trim()) {
      setListError("Enter a number for the list.");
      return;
    }
    setListBusy(true);
    setListError("");
    try {
      await callTool("list_add", {
        action,
        number: entryNumber,
        label: entryLabel,
      });
      setEntryNumber("");
      setEntryLabel("");
      await refreshLists();
    } catch (err) {
      setListError(errorMessage(err));
    } finally {
      setListBusy(false);
    }
  }

  async function importList() {
    if (!importText.trim()) {
      setImportResult("Paste at least one number.");
      return;
    }
    setImportBusy(true);
    setImportResult("");
    try {
      const result = await callTool<{
        imported: number;
        skipped: number;
        total: number;
      }>("import_list", {
        text: importText,
        target: importTarget,
        region: region.trim() || undefined,
      });
      setImportResult(
        `Imported ${result.imported} of ${result.total} (${result.skipped} skipped).`,
      );
      setImportText("");
      await refreshLists();
    } catch (err) {
      setImportResult(errorMessage(err));
    } finally {
      setImportBusy(false);
    }
  }

  async function updateFeeds() {
    setFeedBusy(true);
    setFeedNote("");
    try {
      await callTool("feeds_update", { region: region.trim() || undefined });
      await refreshFeeds();
      setFeedNote("Feed update finished. Previous cache is kept for failed sources.");
    } catch (err) {
      setFeedNote(errorMessage(err));
    } finally {
      setFeedBusy(false);
    }
  }

  const info = data?.intel.number;
  const reputation = data?.intel.reputation;

  return (
    <>
      <section className="section">
        <div className="split">
          <div className="card">
            <div className="card-head">
              <div className="card-title">Check a number</div>
              <span className="card-kicker">range + local reputation</span>
            </div>
            <div className="stack">
              <div className="field">
                <label htmlFor="num-input">Phone number or sender ID</label>
                <input
                  id="num-input"
                  className="input"
                  value={number}
                  onChange={(event) => setNumber(event.target.value)}
                  placeholder="+91 98765 43210"
                  onKeyDown={(event) => {
                    if (event.key === "Enter") check();
                  }}
                />
              </div>
              <div className="field" style={{ maxWidth: 120 }}>
                <label htmlFor="num-region">Region</label>
                <input
                  id="num-region"
                  className="input"
                  value={region}
                  onChange={(event) => setRegion(event.target.value.toUpperCase())}
                  maxLength={2}
                />
              </div>
              <div className="btn-row">
                <button className="btn" onClick={check} disabled={checking}>
                  {checking ? <span className="spinner" /> : null}
                  {checking ? "Checking" : "Check number"}
                </button>
              </div>
              {checkError ? <ErrorBox>{checkError}</ErrorBox> : null}
            </div>
          </div>

          <div className="stack">
            {data && info ? (
              <div className="card">
                <div className="card-head">
                  <div className="card-title">{info.e164 || info.national || number}</div>
                  <span className={`badge ${riskTone(data.intel.risk)}`}>
                    {data.intel.risk} risk
                  </span>
                </div>
                <dl className="kv">
                  <dt>Type</dt>
                  <dd>{info.kind || "—"}</dd>
                  <dt>Country</dt>
                  <dd>{info.country_name || info.country || "—"}</dd>
                  <dt>Valid</dt>
                  <dd>{info.valid ? "yes" : `no · ${info.note || "invalid"}`}</dd>
                  <dt>Local list</dt>
                  <dd>
                    {reputation?.status === "blocked"
                      ? `blocked${reputation.label ? ` · ${reputation.label}` : ""}`
                      : reputation?.status === "allowed"
                        ? `allowed${reputation.label ? ` · ${reputation.label}` : ""}`
                        : reputation?.status === "reported"
                          ? `reported ${reputation.reports}× · ${reputation.source}`
                          : "no reputation data"}
                  </dd>
                </dl>
                {data.intel.flags?.length ? (
                  <div className="tag-list" style={{ marginTop: 14 }}>
                    {data.intel.flags.map((flag) => (
                      <span className="tag acid" key={flag}>
                        {flag}
                      </span>
                    ))}
                  </div>
                ) : null}
                {data.watchlist.length ? (
                  <div className="note warn" style={{ marginTop: 14 }}>
                    Watchlist hit:{" "}
                    {data.watchlist.map((hit) => `${hit.kind}:${hit.value}`).join(", ")}
                  </div>
                ) : null}
                {data.seen.length ? (
                  <div className="note" style={{ marginTop: 14 }}>
                    Seen before:{" "}
                    {data.seen.map((hit) => `${hit.value} (${hit.count ?? 1}×)`).join(", ")}
                  </div>
                ) : null}
                <div style={{ marginTop: 14 }}>
                  <JsonPanel value={data} label="Number intel JSON" />
                </div>
              </div>
            ) : (
              <div className="card dark">
                <div className="card-head">
                  <div className="card-title">What this checks</div>
                </div>
                <p className="small muted">
                  Number validity, country, premium-rate and shortcode flags, your local
                  block/allow lists and any cached feed reputation. A clean result is not a
                  clean bill of health.
                </p>
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="section">
        <SectionHead
          index="02"
          title="Local lists"
          note="Stored on this machine only. Blocked numbers raise sender risk; allowed numbers lower it."
        />
        <div className="grid grid-2">
          <div className="card">
            <div className="card-head">
              <div className="card-title">Teach a number</div>
              <span className="card-kicker">block · allow · forget</span>
            </div>
            <div className="grid grid-2">
              <div className="field">
                <label htmlFor="list-number">Number</label>
                <input
                  id="list-number"
                  className="input"
                  value={entryNumber}
                  onChange={(event) => setEntryNumber(event.target.value)}
                  placeholder="+91 98765 43210"
                />
              </div>
              <div className="field">
                <label htmlFor="list-label">Label</label>
                <input
                  id="list-label"
                  className="input"
                  value={entryLabel}
                  onChange={(event) => setEntryLabel(event.target.value)}
                  placeholder="KYC scam"
                />
              </div>
            </div>
            <div className="btn-row" style={{ marginTop: 14 }}>
              <button className="btn" onClick={() => add("block")} disabled={listBusy}>
                Block
              </button>
              <button className="btn ghost" onClick={() => add("allow")} disabled={listBusy}>
                Allow
              </button>
              <button className="btn danger" onClick={() => add("forget")} disabled={listBusy}>
                Forget
              </button>
            </div>
            {listError ? (
              <div style={{ marginTop: 12 }}>
                <ErrorBox>{listError}</ErrorBox>
              </div>
            ) : null}

            <div className="field" style={{ marginTop: 20 }}>
              <label htmlFor="import-list">Import list (one number per line, optional ,label)</label>
              <textarea
                id="import-list"
                className="textarea"
                value={importText}
                onChange={(event) => setImportText(event.target.value)}
                placeholder={"+91 98765 43210, KYC scam\n+1 900 555 1234, premium"}
              />
            </div>
            <div className="row" style={{ marginTop: 10 }}>
              <select
                className="select"
                style={{ width: 150 }}
                value={importTarget}
                onChange={(event) => setImportTarget(event.target.value)}
              >
                <option value="block">Blocklist</option>
                <option value="allow">Allowlist</option>
              </select>
              <button className="btn ghost small" onClick={importList} disabled={importBusy}>
                {importBusy ? <span className="spinner light" /> : null}
                Import
              </button>
              {importResult ? <span className="tiny muted">{importResult}</span> : null}
            </div>
          </div>

          <div className="stack">
            {(["blocked", "allowed"] as const).map((key) => {
              const entries = lists?.[key] ?? {};
              const rows = Object.values(entries);
              return (
                <div className="card flush" key={key}>
                  <div className="card-head" style={{ padding: "14px 16px", marginBottom: 0 }}>
                    <div className="card-title" style={{ textTransform: "capitalize" }}>
                      {key}
                    </div>
                    <span className="card-kicker">{rows.length}</span>
                  </div>
                  {rows.length ? (
                    <div className="table-wrap" style={{ border: 0 }}>
                      <table>
                        <thead>
                          <tr>
                            <th>Number</th>
                            <th>Label</th>
                            <th />
                          </tr>
                        </thead>
                        <tbody>
                          {rows.map((entry) => (
                            <tr key={entry.number}>
                              <td className="mono">{entry.number}</td>
                              <td className="muted">{entry.label || "—"}</td>
                              <td style={{ textAlign: "right" }}>
                                <button
                                  className="btn ghost small"
                                  onClick={async () => {
                                    await callTool("list_add", {
                                      action: "forget",
                                      number: entry.number,
                                    });
                                    await refreshLists();
                                  }}
                                >
                                  Remove
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="empty" style={{ border: 0 }}>
                      empty
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <section className="section">
        <SectionHead
          index="03"
          title="Number feeds"
          note="Opt-in network access. Message content is never sent; only configured feed URLs are fetched."
        />
        <div className="split">
          <div className="card">
            <div className="card-head">
              <div className="card-title">Cached sources</div>
              <span className="card-kicker">
                {feeds ? `${feeds.sources.length} cached` : "loading"}
              </span>
            </div>
            {feeds?.sources.length ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Source</th>
                      <th>Numbers</th>
                      <th>Updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {feeds.sources.map((source) => (
                      <tr key={source.url}>
                        <td>
                          <div>{source.label || source.url}</div>
                          <div className="tiny muted mono" style={{ marginTop: 3 }}>
                            {source.url}
                          </div>
                        </td>
                        <td className="mono">{source.count ?? 0}</td>
                        <td className="mono muted">{ago(source.fetched_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty">
                No cached feeds. Configure feeds.conf on the CLI, then update here.
              </div>
            )}
            <div className="btn-row" style={{ marginTop: 14 }}>
              <button className="btn" onClick={updateFeeds} disabled={feedBusy}>
                {feedBusy ? <span className="spinner" /> : null}
                {feedBusy ? "Updating" : "Update feeds"}
              </button>
              <span className="tiny muted">
                {feeds ? `${feeds.configured.length} configured` : ""}
              </span>
            </div>
            {feedNote ? (
              <div style={{ marginTop: 12 }} className="note">
                {feedNote}
              </div>
            ) : null}
          </div>
          <div className="stack">
            <Note tone="warn">
              Feeds are the only phone-number data that leaves this machine. Add only sources
              you trust. A missing reputation result is not evidence that a number is safe.
            </Note>
            {feeds ? (
              <div className="card dark">
                <div className="card-head">
                  <div className="card-title">Paths</div>
                </div>
                <dl className="kv">
                  <dt>Cache</dt>
                  <dd className="mono" style={{ fontSize: 11 }}>
                    {feeds.path}
                  </dd>
                  <dt>Updated</dt>
                  <dd>{ago(feeds.updated_at)}</dd>
                </dl>
              </div>
            ) : null}
          </div>
        </div>
      </section>
    </>
  );
}
