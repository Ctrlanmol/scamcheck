export const metadata = { title: "CLI reference" };

export default function CliDocs() {
  return (
    <>
      <div className="eyebrow">Documentation · reference</div>
      <h1>CLI reference</h1>
      <p>
        The CLI is the reference implementation. Every web action maps to a
        function in the same modules. Run <span className="mono">python3 -m scamcheck --help</span>{" "}
        for the live list.
      </p>

      <h2>Checking text</h2>
      <table>
        <thead>
          <tr>
            <th>Flag</th>
            <th>Meaning</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td className="mono">message</td>
            <td>Message text as positional arguments</td>
          </tr>
          <tr>
            <td className="mono">-f, --file FILE</td>
            <td>Read the message from a file</td>
          </tr>
          <tr>
            <td className="mono">--stdin</td>
            <td>Read until EOF (for clipboard pipes)</td>
          </tr>
          <tr>
            <td className="mono">--chat</td>
            <td>Treat input as a multi-line conversation transcript</td>
          </tr>
          <tr>
            <td className="mono">--image FILE</td>
            <td>OCR a screenshot, then analyse it</td>
          </tr>
          <tr>
            <td className="mono">--batch FILE</td>
            <td>Check many messages separated by blank lines</td>
          </tr>
          <tr>
            <td className="mono">--json</td>
            <td>Machine-readable output</td>
          </tr>
          <tr>
            <td className="mono">--intel</td>
            <td>Full intelligence briefing</td>
          </tr>
          <tr>
            <td className="mono">--ai auto|always|never</td>
            <td>Optional AI second opinion policy</td>
          </tr>
          <tr>
            <td className="mono">--sender NUMBER</td>
            <td>Attach sender reputation to the analysis</td>
          </tr>
          <tr>
            <td className="mono">--region CODE</td>
            <td>Region context for number parsing</td>
          </tr>
        </tbody>
      </table>

      <pre><code>{`python3 -m scamcheck "Your account will be blocked in 24 hours. Verify now: bit.ly/x1y2z"
python3 -m scamcheck --intel "URGENT: complete KYC and share the OTP"
python3 -m scamcheck --chat transcript.txt
pbpaste | python3 -m scamcheck --stdin
python3 -m scamcheck --image ~/Desktop/shot.png
python3 -m scamcheck --batch inbox.txt --json`}</code></pre>

      <h2>Phone numbers and lists</h2>
      <table>
        <thead>
          <tr>
            <th>Flag</th>
            <th>Meaning</th>
          </tr>
        </thead>
        <tbody>
          <tr><td className="mono">--number NUMBER</td><td>Check range facts and local reputation</td></tr>
          <tr><td className="mono">--block NUMBER</td><td>Add to the local blocklist</td></tr>
          <tr><td className="mono">--allow NUMBER</td><td>Add to the local allowlist</td></tr>
          <tr><td className="mono">--forget NUMBER</td><td>Remove from both lists</td></tr>
          <tr><td className="mono">--label TEXT</td><td>Label for the list entry</td></tr>
          <tr><td className="mono">--show-lists</td><td>Print both local lists</td></tr>
          <tr><td className="mono">--import-list FILE</td><td>Bulk import numbers</td></tr>
          <tr><td className="mono">--import-allow</td><td>Import into the allowlist instead</td></tr>
          <tr><td className="mono">--set-region CODE</td><td>Save the default region</td></tr>
          <tr><td className="mono">--feed-status</td><td>Show cached feed sources</td></tr>
          <tr><td className="mono">--update-feeds</td><td>Fetch configured feeds (opt-in network)</td></tr>
        </tbody>
      </table>

      <h2>Memory, watchlists and campaigns</h2>
      <table>
        <thead>
          <tr>
            <th>Flag</th>
            <th>Meaning</th>
          </tr>
        </thead>
        <tbody>
          <tr><td className="mono">--watch-add KIND:VALUE</td><td>Watch a phone, URL, UPI ID, wallet or handle</td></tr>
          <tr><td className="mono">--watch-remove KIND:VALUE</td><td>Stop watching an identifier</td></tr>
          <tr><td className="mono">--watchlist</td><td>List watched identifiers</td></tr>
          <tr><td className="mono">--campaigns [N]</td><td>Cluster related checks</td></tr>
          <tr><td className="mono">--campaign CAM_ID</td><td>Show one campaign</td></tr>
        </tbody>
      </table>

      <h2>Evidence cases</h2>
      <table>
        <thead>
          <tr>
            <th>Flag</th>
            <th>Meaning</th>
          </tr>
        </thead>
        <tbody>
          <tr><td className="mono">--case-new TITLE</td><td>Create a case</td></tr>
          <tr><td className="mono">--case-list</td><td>List cases</td></tr>
          <tr><td className="mono">--case ID</td><td>Select a case for follow-up flags</td></tr>
          <tr><td className="mono">--case-show ID</td><td>Show one case</td></tr>
          <tr><td className="mono">--case-add ID FILE_OR_TEXT</td><td>Add evidence</td></tr>
          <tr><td className="mono">--case-note ID TEXT</td><td>Add a timeline note</td></tr>
          <tr><td className="mono">--case-entity ID KIND:VALUE</td><td>Record a suspect identifier</td></tr>
          <tr><td className="mono">--case-verify ID</td><td>Verify stored hashes</td></tr>
          <tr><td className="mono">--case-export ID</td><td>Write JSON, Markdown, HTML and hashes</td></tr>
          <tr><td className="mono">--case-close ID</td><td>Close a case</td></tr>
          <tr><td className="mono">--report ID</td><td>Generate a complaint draft</td></tr>
          <tr><td className="mono">--report-out FILE</td><td>Write the draft to a file</td></tr>
          <tr><td className="mono">--scam-type TYPE</td><td>Case type, e.g. upi, bank, crypto</td></tr>
          <tr><td className="mono">--loss AMOUNT</td><td>Recorded loss</td></tr>
          <tr><td className="mono">--currency CODE</td><td>Loss currency</td></tr>
        </tbody>
      </table>

      <h2>Recovery and device audit</h2>
      <table>
        <thead>
          <tr>
            <th>Flag</th>
            <th>Meaning</th>
          </tr>
        </thead>
        <tbody>
          <tr><td className="mono">--recover [TYPE]</td><td>Recovery playbook for a scam type</td></tr>
          <tr><td className="mono">--country CODE</td><td>Country for recovery and reports</td></tr>
          <tr><td className="mono">--device-audit</td><td>Read-only device and LAN audit</td></tr>
          <tr><td className="mono">--device-full</td><td>Full audit detail</td></tr>
          <tr><td className="mono">--device-active</td><td>Enable TCP probes on the private LAN</td></tr>
          <tr><td className="mono">--device-no-lan</td><td>Skip LAN inventory</td></tr>
          <tr><td className="mono">--device-no-mobile</td><td>Skip connected phones</td></tr>
          <tr><td className="mono">--device-max-hosts N</td><td>Cap LAN hosts (default 64)</td></tr>
          <tr><td className="mono">--device-out DIR</td><td>Choose the report folder</td></tr>
        </tbody>
      </table>

      <h2>Interfaces</h2>
      <table>
        <thead>
          <tr>
            <th>Flag</th>
            <th>Meaning</th>
          </tr>
        </thead>
        <tbody>
          <tr><td className="mono">--serve [PORT]</td><td>Local REST API plus family web UI (default 8765)</td></tr>
          <tr><td className="mono">--host ADDR</td><td>Bind address for the API</td></tr>
          <tr><td className="mono">--jarvis</td><td>Interactive command console</td></tr>
          <tr><td className="mono">--voice</td><td>Speak verdicts in JARVIS</td></tr>
          <tr><td className="mono">--notify</td><td>macOS notifications in JARVIS</td></tr>
          <tr><td className="mono">--watch</td><td>Watch the clipboard</td></tr>
          <tr><td className="mono">--interval SECONDS</td><td>Clipboard polling interval</td></tr>
          <tr><td className="mono">--screenshot-dir DIR</td><td>Also watch a screenshots folder</td></tr>
          <tr><td className="mono">--bot telegram|whatsapp</td><td>Run a chat bot</td></tr>
          <tr><td className="mono">--bot-status</td><td>Show bot configuration</td></tr>
          <tr><td className="mono">--version</td><td>Print the version</td></tr>
        </tbody>
      </table>

      <h2>Exit codes</h2>
      <table>
        <thead>
          <tr>
            <th>Code</th>
            <th>Meaning</th>
          </tr>
        </thead>
        <tbody>
          <tr><td className="mono">0</td><td>Likely safe / low risk</td></tr>
          <tr><td className="mono">1</td><td>Suspicious / medium risk</td></tr>
          <tr><td className="mono">2</td><td>Scam / high risk or invalid input</td></tr>
        </tbody>
      </table>
      <p>
        Exit codes make the CLI usable in shell scripts and mail filters. Use
        <span className="mono"> --json</span> when you need the full result.
      </p>
    </>
  );
}
