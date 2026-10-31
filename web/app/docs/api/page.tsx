export const metadata = { title: "HTTP API" };

export default function ApiDocs() {
  return (
    <>
      <div className="eyebrow">Documentation · API</div>
      <h1>HTTP API</h1>
      <p>
        There are two HTTP surfaces: the built-in local REST API on port 8765,
        and the Next.js route on port 3000 that exposes the full tool set. Both
        are intended for loopback use.
      </p>

      <h2>Built-in REST API</h2>
      <pre><code>{`python3 -m scamcheck --serve            # http://127.0.0.1:8765
python3 -m scamcheck --serve 9000 --host 127.0.0.1`}</code></pre>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Purpose</th>
          </tr>
        </thead>
        <tbody>
          <tr><td className="mono">GET</td><td className="mono">/</td><td>Family web UI (EN/HI)</td></tr>
          <tr><td className="mono">GET</td><td className="mono">/health</td><td>Liveness and version</td></tr>
          <tr><td className="mono">POST</td><td className="mono">/v1/analyze</td><td>Analyse text or a conversation</td></tr>
          <tr><td className="mono">POST</td><td className="mono">/v1/check-number</td><td>Phone range and local reputation</td></tr>
          <tr><td className="mono">POST</td><td className="mono">/v1/check-image</td><td>OCR and analyse a local image or base64 bytes</td></tr>
        </tbody>
      </table>

      <h3>Analyze a message</h3>
      <pre><code>{`curl -s http://127.0.0.1:8765/v1/analyze \\
  -H 'Content-Type: application/json' \\
  -d '{"text":"Your account is blocked. Verify KYC: bit.ly/x1"}'

{
  "score": 98,
  "verdict": "SCAM",
  "final_verdict": "SCAM",
  "reasons": [["Urgency or a deadline", 18], ["Link shortener", 12]],
  "scripts": ["bank_kyc"],
  "intelligence": { "scam_type": "bank", "stage": { ... } }
}`}</code></pre>

      <p>
        Send <span className="mono">conversation</span> instead of{" "}
        <span className="mono">text</span> for a transcript. Optional fields are{" "}
        <span className="mono">ai</span> (auto, always, never),{" "}
        <span className="mono">sender</span> and <span className="mono">region</span>.
      </p>

      <h3>Check a number</h3>
      <pre><code>{`curl -s http://127.0.0.1:8765/v1/check-number \\
  -H 'Content-Type: application/json' \\
  -d '{"number":"+91 98765 43210","region":"IN"}'

{
  "number": { "valid": true, "e164": "+919876543210", "kind": "mobile" },
  "reputation": { "status": "unknown" },
  "flags": [],
  "risk": "low"
}`}</code></pre>

      <h3>Check an image</h3>
      <pre><code>{`curl -s http://127.0.0.1:8765/v1/check-image \\
  -H 'Content-Type: application/json' \\
  -d '{"path":"/Users/you/Desktop/shot.png"}'

# or raw bytes
curl -s http://127.0.0.1:8765/v1/check-image \\
  -H 'Content-Type: application/json' \\
  -d "{\\"image_b64\\":\\"$(base64 -i shot.png)\\"}"`}</code></pre>

      <p>
        The response has the same shape as analyze, plus{" "}
        <span className="mono">ocr_engine</span>,{" "}
        <span className="mono">extracted_text</span> and{" "}
        <span className="mono">qr</span> when a barcode is present.
      </p>

      <h2>Web bridge API</h2>
      <p>
        The Next.js app exposes a single JSON route. It validates the tool name
        and spawns the Python bridge. This is how the interface reaches tools
        that the REST API does not cover, such as cases and device audit.
      </p>
      <pre><code>{`POST /api/tool
{
  "tool": "check_number",
  "args": { "number": "+91 98765 43210", "region": "IN" }
}

{ "ok": true, "data": { ... } }`}</code></pre>

      <p>
        Errors return a non-2xx status with{" "}
        <span className="mono">ok: false</span> and a human-readable{" "}
        <span className="mono">error</span>. The bridge also supports streaming
        for long tasks:
      </p>
      <pre><code>{`POST /api/device-audit
{ "active_lan": false, "include_lan": true }

event: progress
data: {"message":"reviewing persistence"}

event: result
data: {"report": {...}, "export": {...}}`}</code></pre>

      <h2>Bridge tools</h2>
      <table>
        <thead>
          <tr>
            <th>Tool</th>
            <th>Arguments</th>
          </tr>
        </thead>
        <tbody>
          <tr><td className="mono">analyze</td><td>text, chat, sender, region, ai</td></tr>
          <tr><td className="mono">analyze_image</td><td>image_b64, filename, region, ai</td></tr>
          <tr><td className="mono">decode_image</td><td>image_b64, filename</td></tr>
          <tr><td className="mono">batch</td><td>text, region, ai, chat</td></tr>
          <tr><td className="mono">check_number</td><td>number, region</td></tr>
          <tr><td className="mono">lists / list_add / import_list</td><td>action, number, label, text, target</td></tr>
          <tr><td className="mono">feeds_status / feeds_update</td><td>region</td></tr>
          <tr><td className="mono">cases_list / case_create / case_get</td><td>case_id, title, scam_type, country, currency, loss</td></tr>
          <tr><td className="mono">case_add / case_note / case_entity</td><td>case_id, text, file_b64, filename, note, entity</td></tr>
          <tr><td className="mono">case_verify / case_export / case_close</td><td>case_id, outdir</td></tr>
          <tr><td className="mono">case_report</td><td>case_id, country</td></tr>
          <tr><td className="mono">watchlist_list / watchlist_add / watchlist_remove / watchlist_clear</td><td>entity, label, notes</td></tr>
          <tr><td className="mono">campaigns / campaign_get</td><td>limit, campaign_id</td></tr>
          <tr><td className="mono">recover</td><td>scam_type, country</td></tr>
          <tr><td className="mono">url</td><td>url</td></tr>
          <tr><td className="mono">history</td><td>action, term, limit</td></tr>
          <tr><td className="mono">jarvis</td><td>message, region, lang</td></tr>
          <tr><td className="mono">status / regions / set_region / bot_status</td><td>region</td></tr>
          <tr><td className="mono">device_audit</td><td>active_lan, include_lan, include_mobile, max_hosts, out_dir</td></tr>
        </tbody>
      </table>

      <h2>CORS and security</h2>
      <ul>
        <li>The built-in API enables CORS for local pages and JSON endpoints.</li>
        <li>The bundled family UI uses a strict Content-Security-Policy.</li>
        <li>The Next.js app does not enable CORS; it is same-origin only.</li>
        <li>Neither service has authentication. Keep both on loopback.</li>
      </ul>
    </>
  );
}
