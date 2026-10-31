"use client";

import { useMemo, useRef, useState } from "react";
import { ago, formatDate, scoreTone } from "@/lib/format";
import { Empty, ErrorBox, Note, SectionHead, Stat } from "@/components/PageHeader";
import { JsonPanel } from "@/components/JsonPanel";
import { ScoreDial } from "@/components/ScoreDial";
import type { DeviceAuditData, DeviceReport, Finding } from "@/lib/types";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

type Options = {
  active_lan: boolean;
  include_lan: boolean;
  include_mobile: boolean;
  max_hosts: number;
};

function severityTone(severity: string): string {
  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (severity === "medium") return "medium";
  if (severity === "low") return "low";
  return "info";
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className={`finding ${severityTone(finding.severity)}`}>
      <div className="finding-head">
        <h4>{finding.title}</h4>
        <span className={`badge ${severityTone(finding.severity)}`}>
          {finding.severity}
        </span>
      </div>
      <p>{finding.detail}</p>
      <div className="tiny muted mono">{finding.category}</div>
      {finding.recommendation ? <div className="rec">{finding.recommendation}</div> : null}
      {finding.evidence && finding.evidence.length ? (
        <details className="raw" style={{ marginTop: 4 }}>
          <summary>Evidence</summary>
          <div>
            <pre>{JSON.stringify(finding.evidence, null, 2)}</pre>
          </div>
        </details>
      ) : null}
    </div>
  );
}

function ReportView({ data }: { data: DeviceAuditData }) {
  const report: DeviceReport = data.report;
  const summary = report.summary;
  const lan = report.sections.lan;
  const findings = report.findings ?? [];
  const grouped = useMemo(() => {
    const map: Record<string, Finding[]> = {};
    for (const finding of findings) {
      const key = finding.severity || "info";
      map[key] = map[key] ?? [];
      map[key].push(finding);
    }
    return map;
  }, [findings]);
  const checklistKey =
    report.platform === "darwin"
      ? "macos"
      : report.platform === "win32"
        ? "windows"
        : "macos";
  const checklists = report.device_checklists ?? {};

  return (
    <div className="stack">
      <div className="card">
        <div className="verdict-top">
          <ScoreDial score={summary.score} label="device risk" />
          <div className="verdict-copy">
            <div className="row">
              <span className={`badge ${scoreTone(summary.score)}`}>{summary.risk} risk</span>
              <span className="badge info">{summary.checks_run} checks</span>
              <span className="badge info">
                {summary.active_lan ? "active LAN" : "passive"}
              </span>
            </div>
            <div className={`verdict-name ${scoreTone(summary.score)}`}>
              {(summary.risk || "low").toUpperCase()}
            </div>
            <div className="verdict-sub">
              {findings.length} findings · {summary.skipped.length} skipped checks ·{" "}
              {formatDate(report.generated_at)}
            </div>
            <div className="tag-list">
              {SEVERITY_ORDER.filter((key) => grouped[key]?.length).map((key) => (
                <span className={`tag ${key === "info" ? "" : "acid"}`} key={key}>
                  {grouped[key].length} {key}
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="grid grid-4" style={{ marginTop: 18 }}>
          <Stat
            label="Host"
            value={
              <span style={{ fontSize: 15 }}>
                {String(report.host.computer_name || report.host.hostname || "this device")}
              </span>
            }
            hint={String(report.host.productname || report.platform)}
          />
          <Stat
            label="LAN devices"
            value={lan?.devices?.length ?? 0}
            hint={lan?.gateway ? `gateway ${lan.gateway}` : "no LAN scan"}
          />
          <Stat
            label="Checks run"
            value={summary.checks_run}
            hint={`${summary.skipped.length} skipped`}
          />
          <Stat
            label="Report"
            value={<span style={{ fontSize: 13 }}>local</span>}
            hint={data.export.folder}
          />
        </div>
      </div>

      {findings.length ? (
        <div className="stack">
          {SEVERITY_ORDER.map((severity) => {
            const rows = grouped[severity];
            if (!rows?.length) return null;
            return (
              <div key={severity}>
                <div className="card-kicker" style={{ marginBottom: 10 }}>
                  {severity} · {rows.length}
                </div>
                <div className="stack">
                  {rows.map((finding, index) => (
                    <FindingCard finding={finding} key={`${severity}-${index}`} />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <Empty>No findings at this level of inspection.</Empty>
      )}

      {lan ? (
        <div className="card">
          <div className="card-head">
            <div className="card-title">Private LAN inventory</div>
            <span className="card-kicker">
              {lan.active ? "TCP connect probes" : "passive ARP only"}
            </span>
          </div>
          {lan.devices?.length ? (
            <div className="grid grid-2">
              {lan.devices.map((device) => (
                <div className="lan-device" key={device.ip}>
                  <div className="row between">
                    <span className="ip">{device.ip}</span>
                    <span className="badge info">{device.device_type || "unknown"}</span>
                  </div>
                  <div className="muted">
                    {device.hostname || "no hostname"} · {device.vendor || "unknown vendor"}
                  </div>
                  <div className="muted" style={{ fontSize: 10 }}>
                    {device.mac || "no MAC"}
                  </div>
                  {device.open_ports?.length ? (
                    <div className="tag-list" style={{ marginTop: 4 }}>
                      {device.open_ports.map((port) => (
                        <span className="tag" key={port}>
                          :{port}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div className="tiny muted">no probed ports open</div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <Empty>No other devices found on this private network.</Empty>
          )}
          {lan.notes?.length ? (
            <div className="note" style={{ marginTop: 14 }}>
              {lan.notes.join(" ")}
            </div>
          ) : null}
        </div>
      ) : null}

      {summary.skipped.length ? (
        <div className="card">
          <div className="card-head">
            <div className="card-title">Skipped checks</div>
            <span className="card-kicker">{summary.skipped.length}</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Check</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {summary.skipped.map((item) => (
                  <tr key={`${item.check}-${item.reason}`}>
                    <td>{item.check}</td>
                    <td className="muted">{item.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      {checklists[checklistKey]?.length ? (
        <div className="card">
          <div className="card-head">
            <div className="card-title">Manual checklist · {checklistKey}</div>
            <span className="card-kicker">do these by hand</span>
          </div>
          <ol style={{ margin: 0, paddingLeft: 20, color: "var(--paper-dim)", lineHeight: 1.7 }}>
            {checklists[checklistKey].map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ol>
        </div>
      ) : null}

      <div className="card">
        <div className="card-head">
          <div className="card-title">Export</div>
          <span className="badge safe">written</span>
        </div>
        <dl className="kv">
          <dt>Folder</dt>
          <dd className="mono" style={{ fontSize: 11 }}>{data.export.folder}</dd>
          <dt>JSON</dt>
          <dd className="mono" style={{ fontSize: 11 }}>{data.export.json}</dd>
          <dt>Markdown</dt>
          <dd className="mono" style={{ fontSize: 11 }}>{data.export.markdown}</dd>
          <dt>Checksums</dt>
          <dd className="mono" style={{ fontSize: 11 }}>{data.export.sha256sums}</dd>
        </dl>
        <Note>
          The folder is created with mode 0700. Verify it later with{" "}
          <span className="mono">shasum -a 256 -c SHA256SUMS</span>.
        </Note>
      </div>

      <JsonPanel value={report} label="Full device report JSON" />
    </div>
  );
}

export function DeviceAudit() {
  const [options, setOptions] = useState<Options>({
    active_lan: false,
    include_lan: true,
    include_mobile: true,
    max_hosts: 64,
  });
  const [running, setRunning] = useState(false);
  const [stages, setStages] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [data, setData] = useState<DeviceAuditData | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  async function start() {
    setRunning(true);
    setStages([]);
    setError("");
    setData(null);
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const response = await fetch("/api/device-audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(options),
        signal: controller.signal,
      });
      if (!response.ok || !response.body) {
        throw new Error(`The audit endpoint returned ${response.status}.`);
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let finished = false;
      while (!finished) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const blocks = buffer.split("\n\n");
        buffer = blocks.pop() ?? "";
        for (const block of blocks) {
          const lines = block.split("\n");
          let event = "message";
          const payload: string[] = [];
          for (const line of lines) {
            if (line.startsWith("event:")) event = line.slice(6).trim();
            else if (line.startsWith("data:")) payload.push(line.slice(5).trim());
          }
          if (!payload.length) continue;
          let parsed: unknown;
          try {
            parsed = JSON.parse(payload.join("\n"));
          } catch {
            continue;
          }
          if (event === "progress") {
            const message = (parsed as { message?: string }).message || "";
            setStages((prev) => [...prev, message]);
          } else if (event === "result") {
            setData(parsed as DeviceAuditData);
            finished = true;
          } else if (event === "error") {
            setError((parsed as { message?: string }).message || "The audit failed.");
            finished = true;
          }
        }
      }
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setRunning(false);
      abortRef.current = null;
    }
  }

  function stop() {
    abortRef.current?.abort();
    setRunning(false);
  }

  return (
    <>
      <section className="section">
        <div className="split">
          <div className="card">
            <div className="card-head">
              <div className="card-title">Audit configuration</div>
              <span className="card-kicker">read-only · unprivileged</span>
            </div>
            <div className="stack">
              <label className="check">
                <input
                  type="checkbox"
                  checked={options.include_lan}
                  onChange={(event) =>
                    setOptions((prev) => ({ ...prev, include_lan: event.target.checked }))
                  }
                />
                <span>
                  <strong>Include private-LAN inventory.</strong> Read the ARP table and list
                  other devices on the local network.
                </span>
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={options.active_lan}
                  disabled={!options.include_lan}
                  onChange={(event) =>
                    setOptions((prev) => ({ ...prev, active_lan: event.target.checked }))
                  }
                />
                <span>
                  <strong>Actively probe the LAN (opt-in).</strong> TCP connect only, private
                  IPv4 only, capped at {options.max_hosts} hosts. Only use this on a network
                  you own or are authorised to test.
                </span>
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={options.include_mobile}
                  onChange={(event) =>
                    setOptions((prev) => ({ ...prev, include_mobile: event.target.checked }))
                  }
                />
                <span>
                  <strong>Inspect connected phones.</strong> Uses ADB / libimobiledevice when
                  already installed; never installs anything.
                </span>
              </label>
              <div className="field" style={{ maxWidth: 200 }}>
                <label htmlFor="device-hosts">Maximum LAN hosts</label>
                <input
                  id="device-hosts"
                  className="input"
                  type="number"
                  min={1}
                  max={256}
                  value={options.max_hosts}
                  onChange={(event) =>
                    setOptions((prev) => ({
                      ...prev,
                      max_hosts: Math.max(1, Math.min(256, Number(event.target.value) || 64)),
                    }))
                  }
                />
              </div>
              <div className="btn-row">
                <button className="btn" onClick={start} disabled={running}>
                  {running ? <span className="spinner" /> : null}
                  {running ? "Auditing" : "Start audit"}
                </button>
                {running ? (
                  <button className="btn danger" onClick={stop}>
                    Stop
                  </button>
                ) : null}
                {data ? (
                  <button
                    className="btn ghost small"
                    onClick={() => {
                      setData(null);
                      setStages([]);
                      setError("");
                    }}
                  >
                    Reset
                  </button>
                ) : null}
              </div>
            </div>
          </div>

          <div className="stack">
            <Note tone={options.active_lan ? "warn" : "default"}>
              {options.active_lan
                ? "Active probes are enabled. This sends TCP connection attempts to hosts on your private network. Only run it on networks you control."
                : "Passive mode. The audit reads local state and the ARP table but does not probe other hosts."}
            </Note>
            <div className="card dark">
              <div className="card-head">
                <div className="card-title">What it never does</div>
              </div>
              <ul className="small muted" style={{ paddingLeft: 18, lineHeight: 1.7 }}>
                <li>No sudo, no privilege escalation, no password prompts.</li>
                <li>No exploitation, login attempts or packet capture.</li>
                <li>No writes outside the local report folder.</li>
                <li>No public IP scanning — RFC1918 and link-local only.</li>
                <li>No file deletion, quarantine or app removal.</li>
              </ul>
            </div>
            <div className="card dark">
              <div className="card-head">
                <div className="card-title">Platform coverage</div>
              </div>
              <dl className="kv">
                <dt>macOS</dt>
                <dd>Full posture, processes, persistence, browsers, network, files, LAN</dd>
                <dt>Android</dt>
                <dd>Optional ADB inventory and high-signal checks</dd>
                <dt>iOS</dt>
                <dd>Optional device inventory + manual checklist</dd>
                <dt>Other</dt>
                <dd>Inventory and checklists</dd>
              </dl>
            </div>
          </div>
        </div>
      </section>

      {running || stages.length ? (
        <section className="section">
          <SectionHead
            index="02"
            title="Progress"
            note={running ? "Streaming from the local Python bridge." : "Audit finished."}
          />
          <div className="stage-list">
            {stages.length ? (
              stages.map((stage, index) => (
                <div
                  className={`stage ${index === stages.length - 1 && running ? "active" : "done"}`}
                  key={`${stage}-${index}`}
                >
                  <span className={`dot ${index === stages.length - 1 && running ? "" : "offline"}`} />
                  <span>{stage}</span>
                </div>
              ))
            ) : (
              <div className="stage active">
                <span className="dot" />
                <span>starting audit</span>
              </div>
            )}
          </div>
        </section>
      ) : null}

      {error ? (
        <section className="section">
          <ErrorBox>{error}</ErrorBox>
        </section>
      ) : null}

      {data ? (
        <section className="section" style={{ borderBottom: 0 }}>
          <SectionHead
            index="03"
            title="Report"
            note={`Generated ${ago(data.report.generated_at)} · v${data.report.version}`}
          />
          <ReportView data={data} />
        </section>
      ) : null}
    </>
  );
}
