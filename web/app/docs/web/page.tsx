export const metadata = { title: "Web interface" };

export default function WebDocs() {
  return (
    <>
      <div className="eyebrow">Documentation · interface</div>
      <h1>Web interface</h1>
      <p>
        The Next.js app is a local client. It has no database of its own and no
        authentication, because it is designed to run on{" "}
        <span className="mono">127.0.0.1</span>. Every result comes from the
        Python core through a JSON bridge.
      </p>

      <h2>Pages and bridge tools</h2>
      <table>
        <thead>
          <tr>
            <th>Page</th>
            <th>Bridge tools</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Overview</td>
            <td className="mono">status, history, analyze</td>
          </tr>
          <tr>
            <td>Message check</td>
            <td className="mono">analyze, analyze_image, decode_image, batch, url</td>
          </tr>
          <tr>
            <td>Numbers &amp; feeds</td>
            <td className="mono">check_number, lists, list_add, import_list, feeds_status, feeds_update</td>
          </tr>
          <tr>
            <td>JARVIS console</td>
            <td className="mono">jarvis</td>
          </tr>
          <tr>
            <td>Evidence cases</td>
            <td className="mono">cases_list, case_create, case_get, case_add, case_note, case_entity, case_verify, case_export, case_close, case_report</td>
          </tr>
          <tr>
            <td>Watchlist</td>
            <td className="mono">watchlist_list, watchlist_add, watchlist_remove, watchlist_clear</td>
          </tr>
          <tr>
            <td>Campaigns</td>
            <td className="mono">campaigns, campaign_get</td>
          </tr>
          <tr>
            <td>Recovery</td>
            <td className="mono">recover</td>
          </tr>
          <tr>
            <td>Device audit</td>
            <td className="mono">device_audit (streaming)</td>
          </tr>
          <tr>
            <td>Settings</td>
            <td className="mono">status, regions, set_region, history, bot_status</td>
          </tr>
        </tbody>
      </table>

      <h2>How a request works</h2>
      <ol>
        <li>The browser posts to <span className="mono">/api/tool</span> with a tool name and arguments.</li>
        <li>The route validates the tool against a whitelist.</li>
        <li>The server spawns <span className="mono">python3 -m scamcheck.webcli</span> in the project root.</li>
        <li>The bridge reads one JSON object from stdin and writes one JSON object to stdout.</li>
        <li>The route returns <span className="mono">ok: true, data</span> or an error with a status code.</li>
      </ol>

      <pre><code>{`POST /api/tool
{ "tool": "analyze", "args": { "text": "..." } }

200 OK
{ "ok": true, "data": { "result": { ... }, "seen": [], "watchlist": [] } }`}</code></pre>

      <h2>Streaming device audit</h2>
      <p>
        The audit can take minutes, so it uses a separate endpoint that streams
        Server-Sent Events. Progress lines from the Python bridge are forwarded
        as <span className="mono">progress</span> events; the final payload is a
        single <span className="mono">result</span> event.
      </p>
      <pre><code>{`POST /api/device-audit
{ "active_lan": false, "include_lan": true, "include_mobile": true, "max_hosts": 64 }

event: progress
data: {"message":"collecting system and security posture"}

event: result
data: {"report": {...}, "export": {...}}`}</code></pre>

      <h2>Safety defaults</h2>
      <ul>
        <li>The device audit starts passive. Active LAN probes are an explicit checkbox.</li>
        <li>Link investigation is the only page that contacts the internet without an opt-in setting.</li>
        <li>AI review is off unless a key exists and the request asks for it.</li>
        <li>Feed updates only fetch URLs you configured in <span className="mono">feeds.conf</span>.</li>
        <li>There is no telemetry, analytics script or remote font.</li>
      </ul>

      <h2>Motion and accessibility</h2>
      <p>
        Animation is decorative: reveals, the ticker, card tilt and the reading
        rail never carry information that is not also in the text. The interface
        respects <span className="mono">prefers-reduced-motion</span> — reveals,
        marquees, pointer effects and counting animations are disabled, while the
        documentation progress rail stays available because it is navigational.
      </p>
      <p>
        Without JavaScript the server-rendered pages remain readable: stat values
        are rendered as real numbers, and reveal targets are only hidden once the
        motion controller is active.
      </p>

      <h2>Running it safely</h2>
      <p>
        Keep the server bound to loopback. Do not expose the Next.js app to a
        network interface: it has no login and can read local history and case
        files. If you need remote access, use an SSH tunnel, not a reverse proxy.
      </p>
      <pre><code>{`# local only
npm run dev

# explicit loopback bind
npx next dev -H 127.0.0.1 -p 3000`}</code></pre>
    </>
  );
}
