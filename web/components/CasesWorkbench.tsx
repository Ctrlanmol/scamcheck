"use client";

import { useEffect, useState } from "react";
import { callTool, errorMessage } from "@/lib/client";
import { fileToBase64 } from "@/lib/file";
import { bytes, formatDate, snippet } from "@/lib/format";
import { Empty, ErrorBox, Note, SectionHead } from "@/components/PageHeader";
import { JsonPanel } from "@/components/JsonPanel";
import type { CaseDetail, CaseRow } from "@/lib/types";

const SCAM_TYPES = [
  "general",
  "upi",
  "bank",
  "card",
  "crypto",
  "investment",
  "job",
  "romance",
  "sextortion",
  "tech_support",
  "digital_arrest",
  "courier",
  "loan",
  "otp",
  "identity",
];

type ExportResult = {
  case_id: string;
  outdir: string;
  json: string;
  markdown: string;
  html: string;
  hashes: string;
  pdf?: string;
  pdf_note?: string;
};

type VerifyResult = {
  ok: boolean;
  case_id: string;
  evidence: { id: number; filename?: string; ok: boolean; reason?: string }[];
};

export function CasesWorkbench({ defaultRegion }: { defaultRegion: string }) {
  const [cases, setCases] = useState<CaseRow[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const [title, setTitle] = useState("");
  const [scamType, setScamType] = useState("general");
  const [country, setCountry] = useState(defaultRegion);
  const [currency, setCurrency] = useState("");
  const [loss, setLoss] = useState("");
  const [notes, setNotes] = useState("");

  const [note, setNote] = useState("");
  const [entity, setEntity] = useState("");
  const [evidenceText, setEvidenceText] = useState("");
  const [evidenceFile, setEvidenceFile] = useState<File | null>(null);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [exported, setExported] = useState<ExportResult | null>(null);
  const [report, setReport] = useState("");
  const [actionNote, setActionNote] = useState("");

  async function refreshCases(select?: string) {
    try {
      const rows = await callTool<CaseRow[]>("cases_list", { limit: 100 });
      setCases(rows);
      const next = select ?? selectedId ?? rows[0]?.id ?? null;
      if (next) {
        setSelectedId(next);
        await openCase(next);
      } else {
        setSelectedId(null);
        setDetail(null);
      }
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function openCase(id: string) {
    setSelectedId(id);
    setVerify(null);
    setExported(null);
    setReport("");
    try {
      setDetail(await callTool<CaseDetail>("case_get", { case_id: id }));
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  useEffect(() => {
    refreshCases();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function runAction(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    setActionNote("");
    try {
      await action();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function createCase() {
    await runAction(async () => {
      if (!title.trim()) throw new Error("Give the case a title.");
      const created = await callTool<CaseRow>("case_create", {
        title,
        scam_type: scamType,
        country,
        currency,
        loss: Number(loss || 0),
        notes,
      });
      setTitle("");
      setNotes("");
      setLoss("");
      await refreshCases(created.id);
    });
  }

  async function addNote() {
    await runAction(async () => {
      if (!detail) return;
      if (!note.trim()) throw new Error("Write a note first.");
      const updated = await callTool<CaseDetail>("case_note", {
        case_id: detail.id,
        note,
      });
      setDetail(updated);
      setNote("");
      setActionNote("Note added to the timeline.");
    });
  }

  async function addEntity() {
    await runAction(async () => {
      if (!detail) return;
      if (!entity.trim()) throw new Error("Use KIND:VALUE, e.g. upi:scammer@okhdfcbank.");
      await callTool("case_entity", { case_id: detail.id, entity });
      setDetail(await callTool<CaseDetail>("case_get", { case_id: detail.id }));
      setEntity("");
      setActionNote("Entity recorded.");
    });
  }

  async function addEvidence() {
    await runAction(async () => {
      if (!detail) return;
      if (evidenceFile) {
        const file_b64 = await fileToBase64(evidenceFile);
        await callTool("case_add", {
          case_id: detail.id,
          file_b64,
          filename: evidenceFile.name,
        });
        setEvidenceFile(null);
      } else if (evidenceText.trim()) {
        await callTool("case_add", { case_id: detail.id, text: evidenceText });
        setEvidenceText("");
      } else {
        throw new Error("Add a file or paste text evidence.");
      }
      setDetail(await callTool<CaseDetail>("case_get", { case_id: detail.id }));
      setActionNote("Evidence added and hashed.");
    });
  }

  async function verifyCase() {
    await runAction(async () => {
      if (!detail) return;
      setVerify(await callTool<VerifyResult>("case_verify", { case_id: detail.id }));
    });
  }

  async function exportCase() {
    await runAction(async () => {
      if (!detail) return;
      setExported(await callTool<ExportResult>("case_export", { case_id: detail.id }));
    });
  }

  async function makeReport() {
    await runAction(async () => {
      if (!detail) return;
      const result = await callTool<{ case_id: string; text: string }>("case_report", {
        case_id: detail.id,
        country,
      });
      setReport(result.text);
    });
  }

  async function closeCase() {
    await runAction(async () => {
      if (!detail) return;
      await callTool("case_close", { case_id: detail.id });
      await refreshCases(detail.id);
      setActionNote("Case closed.");
    });
  }

  function download(name: string, text: string) {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = name;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <section className="section">
        <SectionHead
          index="01"
          title="Case vault"
          note="Every file is hashed on entry. Exports include JSON, Markdown, HTML and a SHA-256 manifest."
        />
        <div className="split">
          <div className="stack">
            <div className="card flush">
              <div className="card-head" style={{ padding: "14px 16px", marginBottom: 0 }}>
                <div className="card-title">Cases</div>
                <span className="card-kicker">{cases.length}</span>
              </div>
              {cases.length ? (
                <div className="table-wrap" style={{ border: 0 }}>
                  <table>
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Title</th>
                        <th>Status</th>
                        <th>Evidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {cases.map((row) => (
                        <tr
                          key={row.id}
                          onClick={() => openCase(row.id)}
                          style={{
                            cursor: "pointer",
                            background:
                              row.id === selectedId ? "rgba(216,255,62,0.055)" : undefined,
                          }}
                        >
                          <td className="mono">{row.id}</td>
                          <td>
                            <div>{snippet(row.title, 52)}</div>
                            <div className="tiny muted">{row.scam_type || "general"}</div>
                          </td>
                          <td>
                            <span className={`badge ${row.status === "closed" ? "info" : "safe"}`}>
                              {row.status || "open"}
                            </span>
                          </td>
                          <td className="mono">{row.evidence_count ?? 0}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty" style={{ border: 0 }}>
                  No cases yet
                </div>
              )}
            </div>

            <div className="card">
              <div className="card-head">
                <div className="card-title">Open a case</div>
                <span className="card-kicker">new</span>
              </div>
              <div className="stack">
                <div className="field">
                  <label htmlFor="case-title">Title</label>
                  <input
                    id="case-title"
                    className="input"
                    value={title}
                    onChange={(event) => setTitle(event.target.value)}
                    placeholder="UPI fraud — fake investment platform"
                  />
                </div>
                <div className="grid grid-2">
                  <div className="field">
                    <label htmlFor="case-type">Scam type</label>
                    <select
                      id="case-type"
                      className="select"
                      value={scamType}
                      onChange={(event) => setScamType(event.target.value)}
                    >
                      {SCAM_TYPES.map((type) => (
                        <option value={type} key={type}>
                          {type.replaceAll("_", " ")}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="field">
                    <label htmlFor="case-country">Country</label>
                    <input
                      id="case-country"
                      className="input"
                      value={country}
                      onChange={(event) => setCountry(event.target.value.toUpperCase())}
                      maxLength={2}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="case-currency">Currency</label>
                    <input
                      id="case-currency"
                      className="input"
                      value={currency}
                      onChange={(event) => setCurrency(event.target.value.toUpperCase())}
                      placeholder="INR"
                      maxLength={4}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="case-loss">Loss</label>
                    <input
                      id="case-loss"
                      className="input"
                      value={loss}
                      onChange={(event) => setLoss(event.target.value)}
                      inputMode="decimal"
                      placeholder="0"
                    />
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="case-notes">Opening notes</label>
                  <textarea
                    id="case-notes"
                    className="textarea"
                    value={notes}
                    onChange={(event) => setNotes(event.target.value)}
                  />
                </div>
                <div className="btn-row">
                  <button className="btn" onClick={createCase} disabled={busy}>
                    Open case
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div className="stack">
            {error ? <ErrorBox>{error}</ErrorBox> : null}
            {detail ? (
              <>
                <div className="card">
                  <div className="card-head">
                    <div>
                      <div className="card-title">{detail.title}</div>
                      <div className="tiny muted mono" style={{ marginTop: 4 }}>
                        {detail.id} · {detail.scam_type || "general"} · {detail.status || "open"}
                      </div>
                    </div>
                    <div className="btn-row">
                      <button className="btn ghost small" onClick={verifyCase} disabled={busy}>
                        Verify
                      </button>
                      <button className="btn ghost small" onClick={exportCase} disabled={busy}>
                        Export
                      </button>
                      <button className="btn ghost small" onClick={makeReport} disabled={busy}>
                        Report
                      </button>
                      {detail.status !== "closed" ? (
                        <button className="btn danger small" onClick={closeCase} disabled={busy}>
                          Close
                        </button>
                      ) : null}
                    </div>
                  </div>
                  <dl className="kv">
                    <dt>Opened</dt>
                    <dd>{formatDate(detail.created_ts)}</dd>
                    <dt>Country</dt>
                    <dd>{detail.country || "—"}</dd>
                    <dt>Loss</dt>
                    <dd>
                      {detail.currency || ""} {detail.loss_amount ?? 0}
                    </dd>
                    <dt>Evidence</dt>
                    <dd>{detail.evidence?.length ?? 0} items</dd>
                    <dt>Entities</dt>
                    <dd>{detail.entities?.length ?? 0} recorded</dd>
                    {detail.notes ? (
                      <>
                        <dt>Notes</dt>
                        <dd>{detail.notes}</dd>
                      </>
                    ) : null}
                  </dl>
                  {actionNote ? (
                    <div className="note" style={{ marginTop: 14 }}>
                      {actionNote}
                    </div>
                  ) : null}
                </div>

                {verify ? (
                  <div className="card">
                    <div className="card-head">
                      <div className="card-title">Integrity check</div>
                      <span className={`badge ${verify.ok ? "safe" : "danger"}`}>
                        {verify.ok ? "hashes match" : "problems"}
                      </span>
                    </div>
                    {verify.evidence.length ? (
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr>
                              <th>#</th>
                              <th>Evidence</th>
                              <th>Result</th>
                            </tr>
                          </thead>
                          <tbody>
                            {verify.evidence.map((item) => (
                              <tr key={item.id}>
                                <td className="mono">{item.id}</td>
                                <td>{item.filename || "inline text"}</td>
                                <td>
                                  <span className={`badge ${item.ok ? "safe" : "danger"}`}>
                                    {item.ok ? "ok" : item.reason || "changed"}
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <Empty>No evidence to verify</Empty>
                    )}
                  </div>
                ) : null}

                {exported ? (
                  <div className="card">
                    <div className="card-head">
                      <div className="card-title">Export</div>
                      <span className="badge safe">written</span>
                    </div>
                    <dl className="kv">
                      <dt>Folder</dt>
                      <dd className="mono">{exported.outdir}</dd>
                      <dt>JSON</dt>
                      <dd className="mono">{exported.json}</dd>
                      <dt>Markdown</dt>
                      <dd className="mono">{exported.markdown}</dd>
                      <dt>HTML</dt>
                      <dd className="mono">{exported.html}</dd>
                      <dt>Hashes</dt>
                      <dd className="mono">{exported.hashes}</dd>
                      <dt>PDF</dt>
                      <dd className="mono">{exported.pdf || exported.pdf_note || "not generated"}</dd>
                    </dl>
                  </div>
                ) : null}

                <div className="card">
                  <div className="card-head">
                    <div className="card-title">Add evidence</div>
                    <span className="card-kicker">file or text</span>
                  </div>
                  <div className="stack">
                    <div className="field">
                      <label htmlFor="evidence-file">File</label>
                      <input
                        id="evidence-file"
                        className="input"
                        type="file"
                        onChange={(event) => setEvidenceFile(event.target.files?.[0] ?? null)}
                      />
                    </div>
                    <div className="field">
                      <label htmlFor="evidence-text">Or paste text</label>
                      <textarea
                        id="evidence-text"
                        className="textarea"
                        value={evidenceText}
                        onChange={(event) => setEvidenceText(event.target.value)}
                        placeholder="Paste the message, email headers, transaction reference…"
                      />
                    </div>
                    <div className="btn-row">
                      <button className="btn" onClick={addEvidence} disabled={busy}>
                        Add evidence
                      </button>
                    </div>
                  </div>
                </div>

                <div className="card">
                  <div className="card-head">
                    <div className="card-title">Entities & timeline</div>
                  </div>
                  <div className="grid grid-2">
                    <div className="field">
                      <label htmlFor="case-entity">Entity</label>
                      <input
                        id="case-entity"
                        className="input"
                        value={entity}
                        onChange={(event) => setEntity(event.target.value)}
                        placeholder="upi:scammer@okhdfcbank"
                      />
                      <button className="btn ghost small" onClick={addEntity} disabled={busy}>
                        Add entity
                      </button>
                    </div>
                    <div className="field">
                      <label htmlFor="case-note">Timeline note</label>
                      <textarea
                        id="case-note"
                        className="textarea"
                        style={{ minHeight: 80 }}
                        value={note}
                        onChange={(event) => setNote(event.target.value)}
                        placeholder="Called the bank; complaint number…"
                      />
                      <button className="btn ghost small" onClick={addNote} disabled={busy}>
                        Add note
                      </button>
                    </div>
                  </div>

                  {detail.entities?.length ? (
                    <div className="tag-list" style={{ marginTop: 16 }}>
                      {detail.entities.map((item, index) => (
                        <span className="tag" key={index}>
                          {item.kind}: {item.label || item.value}
                        </span>
                      ))}
                    </div>
                  ) : null}

                  <div className="table-wrap" style={{ marginTop: 16 }}>
                    <table>
                      <thead>
                        <tr>
                          <th>When</th>
                          <th>Event</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(detail.events ?? []).slice().reverse().map((event, index) => (
                          <tr key={index}>
                            <td className="mono muted">{formatDate(event.ts)}</td>
                            <td>{event.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="card flush">
                  <div className="card-head" style={{ padding: "14px 16px", marginBottom: 0 }}>
                    <div className="card-title">Evidence</div>
                    <span className="card-kicker">{detail.evidence?.length ?? 0}</span>
                  </div>
                  {detail.evidence?.length ? (
                    <div className="table-wrap" style={{ border: 0 }}>
                      <table>
                        <thead>
                          <tr>
                            <th>#</th>
                            <th>Kind</th>
                            <th>File</th>
                            <th>Size</th>
                            <th>SHA-256</th>
                          </tr>
                        </thead>
                        <tbody>
                          {detail.evidence.map((item) => (
                            <tr key={item.id}>
                              <td className="mono">{item.id}</td>
                              <td className="mono">{item.kind}</td>
                              <td>{item.filename || "inline text"}</td>
                              <td className="mono">{bytes(item.size)}</td>
                              <td className="mono" style={{ fontSize: 10 }}>
                                {(item.sha256 || "").slice(0, 24)}…
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="empty" style={{ border: 0 }}>
                      No evidence yet
                    </div>
                  )}
                </div>

                {report ? (
                  <div className="card">
                    <div className="card-head">
                      <div className="card-title">Complaint draft</div>
                      <div className="btn-row">
                        <button
                          className="btn ghost small"
                          onClick={() => download(`${detail.id}-complaint.txt`, report)}
                        >
                          Download
                        </button>
                        <button className="btn ghost small" onClick={() => setReport("")}>
                          Close
                        </button>
                      </div>
                    </div>
                    <pre className="code">{report}</pre>
                    <Note>
                      This is an editable draft, not a legal filing. Verify every detail before
                      submitting it to a bank, platform or police portal.
                    </Note>
                  </div>
                ) : null}

                <JsonPanel value={detail} label="Case JSON" />
              </>
            ) : (
              <div className="card dark">
                <div className="card-head">
                  <div className="card-title">Select or open a case</div>
                </div>
                <p className="small muted">
                  A case is a local folder with hashed evidence, a timeline, suspect entities and
                  an export pack. Nothing is uploaded.
                </p>
              </div>
            )}
          </div>
        </div>
      </section>
    </>
  );
}
