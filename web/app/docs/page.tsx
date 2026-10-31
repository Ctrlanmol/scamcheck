import Link from "next/link";

export const metadata = { title: "Documentation" };

export default function DocsPage() {
  return (
    <>
      <div className="eyebrow">Documentation · v0.12</div>
      <h1>scamcheck, end to end.</h1>
      <p>
        scamcheck is a local-first scam defense toolkit. It checks messages,
        conversations, screenshots, links and phone numbers; keeps an evidence
        case file; remembers identifiers; and audits this machine without
        changing it. The web interface you are using is a shell over the same
        Python engine as the CLI.
      </p>

      <h2>Design principles</h2>
      <ul>
        <li>
          <strong>Offline by default.</strong> Detection is deterministic and
          local. Nothing is uploaded unless you explicitly investigate a link or
          opt into a feed or AI review.
        </li>
        <li>
          <strong>Explainable.</strong> Every score is the sum of named signals
          with weights. There is no opaque model in the default path.
        </li>
        <li>
          <strong>Stdlib Python 3.9+.</strong> No required dependencies. Optional
          OCR and AI paths degrade gracefully.
        </li>
        <li>
          <strong>Read-only where it matters.</strong> The device audit never
          uses sudo, never writes outside its report folder and never removes
          files.
        </li>
        <li>
          <strong>Local memory, not a cloud account.</strong> History, cases and
          watchlists live in <span className="mono">~/.scamcheck</span> with
          private file modes.
        </li>
      </ul>

      <h2>Architecture</h2>
      <table>
        <thead>
          <tr>
            <th>Layer</th>
            <th>Path</th>
            <th>Role</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Detection core</td>
            <td className="mono">scamcheck/analyzer.py</td>
            <td>Weighted rules, playbooks, conversation trajectory</td>
          </tr>
          <tr>
            <td>Intelligence</td>
            <td className="mono">scamcheck/intelligence.py</td>
            <td>Scam type, stage, goals, rails, next moves</td>
          </tr>
          <tr>
            <td>Evidence</td>
            <td className="mono">scamcheck/cases.py</td>
            <td>Hashed evidence, timeline, exports, complaint drafts</td>
          </tr>
          <tr>
            <td>Device audit</td>
            <td className="mono">scamcheck/deviceaudit.py</td>
            <td>Read-only posture and private-LAN inventory</td>
          </tr>
          <tr>
            <td>JSON bridge</td>
            <td className="mono">scamcheck/webcli.py</td>
            <td>One request in, one JSON response out</td>
          </tr>
          <tr>
            <td>Web shell</td>
            <td className="mono">web/</td>
            <td>Next.js interface and API routes</td>
          </tr>
        </tbody>
      </table>

      <p>
        The browser never re-implements detection. Each interaction becomes a
        JSON request to the local bridge, which imports the same modules the CLI
        uses. That keeps verdicts, cases and audit results identical across the
        terminal, JARVIS and the web app.
      </p>

      <h2>Start here</h2>
      <div className="grid grid-2" style={{ marginTop: 16 }}>
        {[
          ["/docs/install", "Install & run", "Python requirements, the Next.js app, environment variables."],
          ["/docs/cli", "CLI reference", "Every flag, grouped by task, with examples."],
          ["/docs/web", "Web interface", "What each page does and which bridge tool it calls."],
          ["/docs/api", "HTTP API", "The local REST API and its JSON shapes."],
          ["/docs/device", "Device audit", "Scope, safety model, checks and report format."],
          ["/docs/cases", "Cases & recovery", "Evidence workflow, exports and country playbooks."],
          ["/docs/privacy", "Privacy model", "Exactly what can leave the machine and when."],
          ["/docs/faq", "FAQ", "Limits, false positives, platform support."],
        ].map(([href, title, body]) => (
          <Link href={href} className="card hover" key={href}>
            <div className="card-title" style={{ marginBottom: 8 }}>{title}</div>
            <p className="small muted">{body}</p>
          </Link>
        ))}
      </div>
    </>
  );
}
