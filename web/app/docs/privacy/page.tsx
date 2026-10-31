export const metadata = { title: "Privacy model" };

export default function PrivacyDocs() {
  return (
    <>
      <div className="eyebrow">Documentation · trust</div>
      <h1>Privacy model</h1>
      <p>
        The privacy claim is specific, not absolute: message analysis is
        offline, local memory stays local, and only a short list of explicit
        actions can contact the network.
      </p>

      <h2>What stays local</h2>
      <ul>
        <li>Message, conversation and screenshot text.</li>
        <li>Verdicts, scores, signals and intelligence briefings.</li>
        <li>History, watchlists, cases, evidence and exports.</li>
        <li>Phone numbers, blocklists and allowlists.</li>
        <li>Device audit reports.</li>
        <li>Region, preferences and bot tokens.</li>
      </ul>

      <h2>What can leave the machine</h2>
      <table>
        <thead>
          <tr>
            <th>Action</th>
            <th>What is sent</th>
            <th>Default</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Link investigation</td>
            <td>The URL you entered; normal HTTP/TLS metadata; an RDAP domain query</td>
            <td>Off until you submit a URL</td>
          </tr>
          <tr>
            <td>AI second opinion</td>
            <td>The message text and prompt context</td>
            <td>Off unless a key exists and the request opts in</td>
          </tr>
          <tr>
            <td>Phone feed update</td>
            <td>Requests to feed URLs you configured</td>
            <td>Off; no feeds configured by default</td>
          </tr>
          <tr>
            <td>Chat bots</td>
            <td>Messages delivered through Telegram or WhatsApp</td>
            <td>Off unless you start a bot</td>
          </tr>
          <tr>
            <td>Device audit</td>
            <td>Nothing; it reads local state</td>
            <td>Local only</td>
          </tr>
        </tbody>
      </table>

      <p>
        There is no analytics, crash reporting, remote configuration, remote
        font or update check. The web app ships no third-party scripts.
      </p>

      <h2>AI review</h2>
      <p>
        AI review is a second opinion for borderline scores. It is never used
        for the primary verdict. When enabled, the message text is sent to the
        configured provider. If that is unacceptable for a message, choose{" "}
        <span className="mono">Never</span> in the workbench or pass{" "}
        <span className="mono">--ai never</span>.
      </p>

      <h2>Link investigation</h2>
      <p>
        Link investigation fetches the URL, follows redirects, reads TLS
        metadata, inspects headers and may query RDAP for registration data. It
        refuses loopback, link-local and private targets. Treat any URL as
        hostile: the fetcher does not execute JavaScript, but the remote server
        still learns your IP address and request time.
      </p>

      <h2>Files and permissions</h2>
      <pre><code>{`~/.scamcheck/                 0700
├── config.json              0600
├── history.db               0600
├── cases.db                 0600
├── watchlist.db             0600
├── feeds.json               0600
├── cases/                   0700
└── device-reports/          0700`}</code></pre>
      <p>
        On macOS and Linux these modes keep other local users out. They do not
        protect against malware running as your user, full-disk access by an
        administrator, or an unlocked machine. Use FileVault or equivalent disk
        encryption.
      </p>

      <h2>Threat model</h2>
      <h3>In scope</h3>
      <ul>
        <li>Scam messages, conversations and screenshots you choose to check.</li>
        <li>Accidental disclosure through a cloud service: avoided by local processing.</li>
        <li>Evidence integrity after collection: addressed with SHA-256 manifests.</li>
        <li>Unprivileged device hygiene: addressed with a read-only audit.</li>
      </ul>
      <h3>Out of scope</h3>
      <ul>
        <li>A compromised operating system or kernel-level attacker.</li>
        <li>Nation-state surveillance or physical device access.</li>
        <li>Guaranteed detection of every scam. False negatives are possible.</li>
        <li>Legal advice or guaranteed financial recovery.</li>
      </ul>

      <h2>Network binding</h2>
      <p>
        The built-in API and the Next.js app are designed for loopback. Neither
        has authentication. Binding either to a LAN address exposes local
        history, cases and device reports to anyone who can reach the port. Use
        an SSH tunnel for remote access.
      </p>
    </>
  );
}
