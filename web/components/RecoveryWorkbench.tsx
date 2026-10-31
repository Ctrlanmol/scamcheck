"use client";

import { useEffect, useState } from "react";
import { callTool, errorMessage } from "@/lib/client";
import { ErrorBox, Note, SectionHead } from "@/components/PageHeader";
import { JsonPanel } from "@/components/JsonPanel";
import type { Playbook } from "@/lib/types";

const TYPES = [
  "general",
  "upi",
  "bank",
  "card",
  "crypto",
  "investment",
  "job",
  "romance",
  "sextortion",
  "tech",
  "digital_arrest",
  "courier",
  "loan",
  "otp",
  "identity",
];

const COUNTRIES = ["IN", "US", "GB", "CA", "AU", "NZ", "SG", "AE", "ZA"];

function Steps({ title, items, tone }: { title: string; items: string[]; tone?: string }) {
  return (
    <div className="card">
      <div className="card-head">
        <div className="card-title">{title}</div>
        <span className={`badge ${tone ?? "info"}`}>{items.length} steps</span>
      </div>
      <ol style={{ margin: 0, paddingLeft: 20, color: "var(--paper-dim)", lineHeight: 1.65 }}>
        {items.map((item, index) => (
          <li key={index} style={{ marginBottom: 8 }}>
            {item}
          </li>
        ))}
      </ol>
    </div>
  );
}

export function RecoveryWorkbench({ defaultRegion }: { defaultRegion: string }) {
  const [type, setType] = useState("upi");
  const [country, setCountry] = useState(
    COUNTRIES.includes(defaultRegion) ? defaultRegion : "IN",
  );
  const [book, setBook] = useState<Playbook | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      setBook(await callTool<Playbook>("recover", { scam_type: type, country }));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const authority = book?.authority;

  return (
    <>
      <section className="section">
        <div className="card">
          <div className="card-head">
            <div className="card-title">Build a recovery plan</div>
            <span className="card-kicker">country-aware</span>
          </div>
          <div className="grid grid-3">
            <div className="field">
              <label htmlFor="recover-type">Scam type</label>
              <select
                id="recover-type"
                className="select"
                value={type}
                onChange={(event) => setType(event.target.value)}
              >
                {TYPES.map((item) => (
                  <option value={item} key={item}>
                    {item.replaceAll("_", " ")}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="recover-country">Country</label>
              <select
                id="recover-country"
                className="select"
                value={country}
                onChange={(event) => setCountry(event.target.value)}
              >
                {COUNTRIES.map((item) => (
                  <option value={item} key={item}>
                    {item}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <span className="label">Run</span>
              <button className="btn" onClick={load} disabled={loading}>
                {loading ? <span className="spinner" /> : null}
                {loading ? "Loading" : "Get playbook"}
              </button>
            </div>
          </div>
          {error ? (
            <div style={{ marginTop: 14 }}>
              <ErrorBox>{error}</ErrorBox>
            </div>
          ) : null}
        </div>
      </section>

      {book ? (
        <>
          <section className="section">
            <SectionHead
              index="01"
              title={book.title}
              note={`${book.country} · ${book.scam_type.replaceAll("_", " ")}`}
            />
            <div className="split">
              <div className="stack">
                <Steps title="First hour" items={book.now} tone="danger" />
                <Steps title="Today" items={book.today} tone="warn" />
                <Steps title="This week" items={book.week} tone="info" />
              </div>
              <div className="stack">
                <div className="card acid">
                  <div className="card-head">
                    <div className="card-title">Report here</div>
                    <span className="card-kicker">{authority?.code || book.country}</span>
                  </div>
                  <dl className="kv">
                    <dt>Country</dt>
                    <dd>{authority?.country || "—"}</dd>
                    <dt>Cyber / fraud</dt>
                    <dd>{authority?.cyber || "—"}</dd>
                    <dt>Portal</dt>
                    <dd className="mono" style={{ fontSize: 11 }}>
                      {authority?.cyber_url ? (
                        <a
                          href={authority.cyber_url}
                          target="_blank"
                          rel="noreferrer"
                          style={{ textDecoration: "underline" }}
                        >
                          {authority.cyber_url}
                        </a>
                      ) : (
                        "—"
                      )}
                    </dd>
                    <dt>Police</dt>
                    <dd>{authority?.police || "—"}</dd>
                    <dt>Bank</dt>
                    <dd>{authority?.bank || "—"}</dd>
                    <dt>Extra</dt>
                    <dd>{authority?.extra || "—"}</dd>
                  </dl>
                </div>
                <Note tone="warn">
                  This is guidance, not legal advice. Deadlines and reimbursement rules
                  differ by bank and country. Call your bank directly using the number on
                  your card — never a number from the suspected message.
                </Note>
                <JsonPanel value={book} label="Playbook JSON" />
              </div>
            </div>
          </section>
        </>
      ) : null}
    </>
  );
}
