import Link from "next/link";
import { QuickCheck } from "@/components/QuickCheck";
import { CountUp } from "@/components/CountUp";
import { SectionHead, Stat } from "@/components/PageHeader";
import { runTool } from "@/lib/scamcheck";
import { ago, scoreTone, snippet } from "@/lib/format";
import type { HistoryRow, StatusData } from "@/lib/types";

export const dynamic = "force-dynamic";

const TOOLS = [  {
    href: "/check",
    num: "01",
    title: "Message check",
    body: "SMS, email, DM or a full chat transcript. Rules, playbooks and an intelligence briefing.",
  },
  {
    href: "/numbers",
    num: "02",
    title: "Numbers & feeds",
    body: "Premium-rate and country mismatch flags, local block/allow lists and opt-in feeds.",
  },
  {
    href: "/jarvis",
    num: "03",
    title: "JARVIS console",
    body: "One local command line for text, links, images, numbers, cases and device checks.",
  },
  {
    href: "/cases",
    num: "04",
    title: "Evidence cases",
    body: "Hash evidence, build a timeline, record entities and export a case pack.",
  },
  {
    href: "/watchlist",
    num: "05",
    title: "Watchlist",
    body: "Get warned when a known number, UPI ID, wallet, domain or handle reappears.",
  },
  {
    href: "/campaigns",
    num: "06",
    title: "Campaigns",
    body: "Cluster related checks that share indicators into one operation view.",
  },
  {
    href: "/recovery",
    num: "07",
    title: "Recovery",
    body: "Country-aware first-hour steps, bank escalation and reporting contacts.",
  },
  {
    href: "/device",
    num: "08",
    title: "Device audit",
    body: "Read-only posture, process, persistence, browser, network and private-LAN audit.",
  },
];

const TICKER = [
  "Bank KYC",
  "Pig butchering",
  "Digital arrest",
  "Task scam",
  "Courier fraud",
  "Sextortion",
  "Romance",
  "Tech support",
  "Invoice BEC",
  "UPI fraud",
  "Gold handoff",
  "Toll smishing",
];

export default async function HomePage() {
  let status: StatusData | null = null;
  let history: HistoryRow[] = [];
  try {
    status = await runTool<StatusData>("status", {}, 20_000);
  } catch {
    status = null;
  }
  try {
    history = await runTool<HistoryRow[]>("history", { action: "recent", limit: 6 }, 20_000);
  } catch {
    history = [];
  }

  return (
    <>
      <section className="hero">
        <div className="hero-copy">
          <div className="eyebrow">Local-first scam defense · v{status?.version ?? "0.12"}</div>
          <h1 className="display">
            Know the message.
            <br />
            Know the <em>machine.</em>
          </h1>
          <p className="lead">
            A deterministic scam detector, evidence vault, recovery console and read-only
            device audit — running entirely on your machine. No accounts, no cloud, no
            telemetry.
          </p>
          <div className="btn-row">
            <Link className="btn" href="/check">
              Check a message
            </Link>
            <Link className="btn ghost" href="/device">
              Audit this device
            </Link>
            <Link className="btn ghost" href="/docs">
              Read the docs
            </Link>
          </div>
        </div>

        <div className="hero-side">
          <div className="hero-stat">
            <span className="k">Engine</span>
            <span className="v">rules + intel</span>
          </div>
          <div className="hero-stat">
            <span className="k">Memory</span>
            <span className="v">
              {status ? (
                <>
                  <CountUp value={status.history} /> checks
                </>
              ) : (
                "—"
              )}
            </span>
          </div>
          <div className="hero-stat">
            <span className="k">Cases</span>
            <span className="v">
              {status ? <CountUp value={status.cases} /> : "—"}
            </span>
          </div>
          <div className="hero-stat">
            <span className="k">Watchlist</span>
            <span className="v">
              {status ? <CountUp value={status.watchlist} /> : "—"}
            </span>
          </div>
          <div className="hero-stat">
            <span className="k">Region</span>
            <span className="v">{status?.region ?? "—"}</span>
          </div>
          <div className="hero-stat">
            <span className="k">AI layer</span>
            <span className="v">{status?.ai ? "key present" : "off"}</span>
          </div>
        </div>
      </section>

      <div className="ticker" aria-hidden="true">
        <div className="ticker-track">
          {[0, 1].map((copy) => (
            <div className="ticker-group" key={copy}>
              {TICKER.map((item) => (
                <span className="ticker-item" key={`${copy}-${item}`}>
                  {item}
                  <i />
                </span>
              ))}
            </div>
          ))}
        </div>
      </div>

      <section className="section">
        <div className="split">
          <QuickCheck />
          <div className="stack">
            <div className="card dark">
              <div className="card-head">
                <div className="card-title">What this console is</div>
                <span className="card-kicker">01 / posture</span>
              </div>
              <p className="small muted" style={{ lineHeight: 1.65 }}>
                The web interface is a shell over the same Python engine used by the
                <span className="mono"> scamcheck </span> CLI and JARVIS. Every check, case and
                audit is written to your local data directory, never to a server.
              </p>
              <div className="grid grid-2" style={{ marginTop: 16 }}>
                <div>
                  <div className="stat-label">Runtime</div>
                  <div className="mono" style={{ fontSize: 12 }}>
                    Python 3.9+ · stdlib
                  </div>
                </div>
                <div>
                  <div className="stat-label">Data</div>
                  <div className="mono" style={{ fontSize: 12, overflowWrap: "anywhere" }}>
                    {status?.data_dir ?? "~/.scamcheck"}
                  </div>
                </div>
                <div>
                  <div className="stat-label">Platform</div>
                  <div className="mono" style={{ fontSize: 12 }}>
                    {status?.platform ?? "—"}
                  </div>
                </div>
                <div>
                  <div className="stat-label">Feeds</div>
                  <div className="mono" style={{ fontSize: 12 }}>
                    {status ? `${status.feeds.sources.length} cached` : "—"}
                  </div>
                </div>
              </div>
            </div>

            <div className="note">
              <strong>Privacy by construction.</strong> Link investigation is the only tool
              that goes online, and only when you ask. AI review stays off unless you set an
              API key and opt in.
            </div>
          </div>
        </div>
      </section>

      <section className="section">
        <SectionHead
          index="02"
          title="Every tool, one console"
          note="The full scamcheck surface, wired to the local Python bridge."
        />
        <div className="grid grid-4">
          {TOOLS.map((tool) => (
            <Link href={tool.href} className="tool-card" key={tool.href}>
              <span className="tool-num">{tool.num}</span>
              <h3>{tool.title}</h3>
              <p>{tool.body}</p>
            </Link>
          ))}
        </div>
      </section>

      <section className="section">
        <SectionHead
          index="03"
          title="Recent memory"
          action={
            <Link className="btn ghost small" href="/jarvis">
              Open console
            </Link>
          }
        />
        {history.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Kind</th>
                  <th>Verdict</th>
                  <th>Score</th>
                  <th>Message</th>
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
                    <td>{snippet(row.text, 110)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty">No checks recorded yet. Start with the message box above.</div>
        )}
      </section>

      <section className="section">
        <div className="grid grid-3">
          <Stat label="Engine" value="100%" hint="deterministic rules" />
          <Stat label="Cloud calls" value="0" hint="unless you opt in" />
          <Stat label="Device writes" value="read-only" hint="audit never changes state" />
        </div>
        <div className="note" style={{ marginTop: 16 }}>
          <strong>Not an antivirus.</strong> The device audit reports suspicious state for a
          human to review. It does not remove files, quarantine apps or exploit anything.
        </div>
      </section>
    </>
  );
}
