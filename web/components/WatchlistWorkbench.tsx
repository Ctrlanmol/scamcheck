"use client";

import { useEffect, useState } from "react";
import { callTool, errorMessage } from "@/lib/client";
import { ago, formatDate } from "@/lib/format";
import { Empty, ErrorBox, Note, SectionHead } from "@/components/PageHeader";
import type { WatchEntry } from "@/lib/types";

const KINDS = [
  { value: "phone", label: "Phone number" },
  { value: "url", label: "Domain / link" },
  { value: "upi", label: "UPI ID" },
  { value: "email", label: "Email" },
  { value: "crypto_btc", label: "Bitcoin address" },
  { value: "crypto_eth", label: "Ethereum address" },
  { value: "crypto_trx", label: "Tron / USDT" },
  { value: "telegram", label: "Telegram handle" },
  { value: "whatsapp", label: "WhatsApp group" },
  { value: "apk", label: "APK link" },
  { value: "ifsc", label: "Bank IFSC" },
];

export function WatchlistWorkbench() {
  const [entries, setEntries] = useState<WatchEntry[]>([]);
  const [kind, setKind] = useState("phone");
  const [value, setValue] = useState("");
  const [label, setLabel] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const [filter, setFilter] = useState("");

  async function refresh() {
    try {
      setEntries(await callTool<WatchEntry[]>("watchlist_list", {}));
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function add() {
    if (!value.trim()) {
      setError("Enter an identifier value.");
      return;
    }
    setBusy(true);
    setError("");
    setNote("");
    try {
      await callTool("watchlist_add", {
        entity: `${kind}:${value.trim()}`,
        label: label.trim(),
        notes: notes.trim(),
      });
      setValue("");
      setLabel("");
      setNotes("");
      setNote("Identifier added. Future checks containing it will raise a warning.");
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function remove(entry: WatchEntry) {
    setBusy(true);
    setError("");
    try {
      await callTool("watchlist_remove", {
        entity: `${entry.kind}:${entry.value}`,
      });
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function clear() {
    setBusy(true);
    setError("");
    try {
      await callTool("watchlist_clear", {});
      await refresh();
      setNote("Watchlist cleared.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const filtered = entries.filter((entry) => {
    if (!filter.trim()) return true;
    const term = filter.toLowerCase();
    return `${entry.kind} ${entry.value} ${entry.label ?? ""} ${entry.notes ?? ""}`
      .toLowerCase()
      .includes(term);
  });

  return (
    <>
      <section className="section">
        <div className="split">
          <div className="card">
            <div className="card-head">
              <div className="card-title">Watch an identifier</div>
              <span className="card-kicker">exact local match</span>
            </div>
            <div className="stack">
              <div className="field">
                <label htmlFor="watch-kind">Kind</label>
                <select
                  id="watch-kind"
                  className="select"
                  value={kind}
                  onChange={(event) => setKind(event.target.value)}
                >
                  {KINDS.map((item) => (
                    <option value={item.value} key={item.value}>
                      {item.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="field">
                <label htmlFor="watch-value">Value</label>
                <input
                  id="watch-value"
                  className="input"
                  value={value}
                  onChange={(event) => setValue(event.target.value)}
                  placeholder="+91 98765 43210 · scammer@okhdfcbank · evil.xyz"
                  onKeyDown={(event) => {
                    if (event.key === "Enter") add();
                  }}
                />
              </div>
              <div className="grid grid-2">
                <div className="field">
                  <label htmlFor="watch-label">Label</label>
                  <input
                    id="watch-label"
                    className="input"
                    value={label}
                    onChange={(event) => setLabel(event.target.value)}
                    placeholder="KYC scam caller"
                  />
                </div>
                <div className="field">
                  <label htmlFor="watch-notes">Notes</label>
                  <input
                    id="watch-notes"
                    className="input"
                    value={notes}
                    onChange={(event) => setNotes(event.target.value)}
                    placeholder="where it appeared"
                  />
                </div>
              </div>
              <div className="btn-row">
                <button className="btn" onClick={add} disabled={busy}>
                  {busy ? <span className="spinner" /> : null}
                  Add to watchlist
                </button>
                <button
                  className="btn danger small"
                  onClick={clear}
                  disabled={busy || !entries.length}
                >
                  Clear all
                </button>
              </div>
              {note ? <Note>{note}</Note> : null}
              {error ? <ErrorBox>{error}</ErrorBox> : null}
            </div>
          </div>

          <div className="stack">
            <Note>
              A watchlist is a memory aid, not a blocklist. A hit means the same
              identifier appeared again in a check you ran — it is evidence of
              repetition, not proof of guilt.
            </Note>
            <div className="card dark">
              <div className="card-head">
                <div className="card-title">How matching works</div>
              </div>
              <ol className="small muted" style={{ paddingLeft: 18, lineHeight: 1.7 }}>
                <li>Every check extracts identifiers: phones, domains, UPI IDs, wallets, handles, emails, IFSC codes.</li>
                <li>Identifiers are canonicalised (case, scheme, normalisation) before comparison.</li>
                <li>An exact match raises a warning and increments the hit counter.</li>
                <li>Counters and timestamps show a repeated campaign over time.</li>
              </ol>
            </div>
            <div className="card dark">
              <div className="card-head">
                <div className="card-title">Privacy</div>
              </div>
              <p className="small muted">
                The watchlist lives in <span className="mono">~/.scamcheck/watchlist.db</span>{" "}
                with mode 0600. It is never synchronised or uploaded.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="section">
        <SectionHead
          index="02"
          title="Watched identifiers"
          action={
            <input
              className="input"
              style={{ maxWidth: 280 }}
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              placeholder="Filter by value or label…"
              aria-label="Filter watchlist"
            />
          }
        />
        {filtered.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Kind</th>
                  <th>Value</th>
                  <th>Label</th>
                  <th>Hits</th>
                  <th>Last hit</th>
                  <th>Added</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {filtered.map((entry) => (
                  <tr key={`${entry.kind}:${entry.value}`}>
                    <td className="mono">{entry.kind}</td>
                    <td className="mono" style={{ wordBreak: "break-all" }}>
                      {entry.value}
                    </td>
                    <td>{entry.label || "—"}</td>
                    <td className="mono">{entry.hits ?? 0}</td>
                    <td className="mono muted">{ago(entry.last_hit_ts)}</td>
                    <td className="mono muted">{formatDate(entry.created_ts)}</td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        className="btn ghost small"
                        onClick={() => remove(entry)}
                        disabled={busy}
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
          <Empty>
            {entries.length ? "No identifiers match that filter." : "Watchlist is empty."}
          </Empty>
        )}
      </section>
    </>
  );
}
