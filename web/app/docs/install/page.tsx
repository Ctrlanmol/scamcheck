export const metadata = { title: "Install & run" };

export default function InstallDocs() {
  return (
    <>
      <div className="eyebrow">Documentation · setup</div>
      <h1>Install &amp; run</h1>
      <p>
        The core has no required dependencies beyond Python 3.9+. The web
        interface adds Node.js and Next.js, but it still calls the Python core
        for every result.
      </p>

      <h2>Requirements</h2>
      <table>
        <thead>
          <tr>
            <th>Component</th>
            <th>Requirement</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>scamcheck core</td>
            <td>Python 3.9 or newer, standard library only</td>
          </tr>
          <tr>
            <td>Web interface</td>
            <td>Node.js 20+ and npm</td>
          </tr>
          <tr>
            <td>OCR (optional)</td>
            <td>macOS Apple Vision, or tesseract, or an AI vision model</td>
          </tr>
          <tr>
            <td>QR (optional)</td>
            <td>macOS Vision, zbar, or another supported decoder</td>
          </tr>
          <tr>
            <td>Android audit (optional)</td>
            <td>adb already installed and authorised</td>
          </tr>
        </tbody>
      </table>

      <h2>Core</h2>
      <pre><code>{`cd scam-detector

# verify the engine
python3 -m scamcheck "Your account will be blocked in 24 hours. Verify now: bit.ly/x1y2z"

# run the tests
python3 tests/run_samples.py
python3 tests/test_phones.py
python3 tests/test_cases.py
python3 tests/test_deviceaudit.py
python3 tests/test_webcli.py`}</code></pre>

      <p>
        Optional: install a shell wrapper so <span className="mono">scamcheck</span>{" "}
        works from any directory. The README includes a ready-made wrapper.
      </p>

      <h2>Web interface</h2>
      <pre><code>{`cd scam-detector/web
npm install
npm run dev        # http://127.0.0.1:3000

# production
npm run build
npm start`}</code></pre>

      <p>
        The Next.js server spawns <span className="mono">python3 -m scamcheck.webcli</span>{" "}
        from the project root for each request. It finds the root automatically
        when it is started inside <span className="mono">web/</span>. Otherwise,
        set <span className="mono">SCAMCHECK_ROOT</span>.
      </p>

      <h2>Environment variables</h2>
      <table>
        <thead>
          <tr>
            <th>Variable</th>
            <th>Used by</th>
            <th>Purpose</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td className="mono">SCAMCHECK_HOME</td>
            <td>Core</td>
            <td>Override the data directory (default <span className="mono">~/.scamcheck</span>)</td>
          </tr>
          <tr>
            <td className="mono">SCAMCHECK_REGION</td>
            <td>Core</td>
            <td>Default region code, e.g. IN</td>
          </tr>
          <tr>
            <td className="mono">SCAMCHECK_ROOT</td>
            <td>Web</td>
            <td>Project root containing <span className="mono">scamcheck/</span> and <span className="mono">pyproject.toml</span></td>
          </tr>
          <tr>
            <td className="mono">SCAMCHECK_PYTHON</td>
            <td>Web</td>
            <td>Python binary to spawn (default <span className="mono">python3</span>)</td>
          </tr>
          <tr>
            <td className="mono">OPENAI_API_KEY</td>
            <td>Core</td>
            <td>Enables the optional AI second opinion</td>
          </tr>
          <tr>
            <td className="mono">ANTHROPIC_API_KEY</td>
            <td>Core</td>
            <td>Alternative AI provider</td>
          </tr>
          <tr>
            <td className="mono">SCAMCHECK_TELEGRAM_TOKEN</td>
            <td>Core</td>
            <td>Telegram bot long polling</td>
          </tr>
          <tr>
            <td className="mono">WHATSAPP_TOKEN</td>
            <td>Core</td>
            <td>WhatsApp Cloud API bot</td>
          </tr>
        </tbody>
      </table>

      <h2>Data directory</h2>
      <pre><code>{`~/.scamcheck/
├── config.json          region and preferences (0600)
├── history.db           checks and identifiers (0600)
├── cases.db             case metadata (0600)
├── cases/               evidence files and exports (0700)
├── watchlist.db         watched identifiers (0600)
├── feeds.conf           opt-in feed configuration
├── feeds.json           cached feed reputation (0600)
└── device-reports/      timestamped audit folders (0700)`}</code></pre>

      <h2>Troubleshooting</h2>
      <h3>Bridge cannot find the project root</h3>
      <p>
        Start the app from <span className="mono">scam-detector/web</span>, or
        export <span className="mono">SCAMCHECK_ROOT=/absolute/path/to/scam-detector</span>.
      </p>
      <h3>Python not found</h3>
      <p>
        Set <span className="mono">SCAMCHECK_PYTHON</span> to an absolute path.
        The bridge passes <span className="mono">PYTHONPATH</span> automatically.
      </p>
      <h3>Port 8765 is already in use</h3>
      <p>
        That port belongs to the older built-in family web UI. The Next.js app
        uses 3000 by default and does not touch an existing service on 8765.
      </p>
      <h3>OCR or QR unavailable</h3>
      <p>
        Screenshot checks need an OCR backend. On macOS, Apple Vision is used
        automatically. Elsewhere, install tesseract. QR decoding likewise needs
        a supported decoder; the rest of the app still works.
      </p>
    </>
  );
}
