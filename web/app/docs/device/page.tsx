export const metadata = { title: "Device audit" };

export default function DeviceDocs() {
  return (
    <>
      <div className="eyebrow">Documentation · machine</div>
      <h1>Device audit</h1>
      <p>
        The device audit answers a narrow question: what is the observable
        security state of this machine and the private network around it? It is
        a reporting tool for a human, not an antivirus engine and not an
        exploitation framework.
      </p>

      <h2>Safety contract</h2>
      <ul>
        <li>No sudo, no privilege escalation and no password prompts.</li>
        <li>No exploitation, credential attacks, login attempts or packet capture.</li>
        <li>No file deletion, quarantine or application removal.</li>
        <li>No writes outside the chosen report folder.</li>
        <li>Active LAN checks only target RFC1918 and link-local IPv4 addresses.</li>
        <li>Active probes use TCP connect only and stop at the configured host cap.</li>
        <li>Connected-phone checks use tools that are already installed; nothing is installed automatically.</li>
      </ul>

      <h2>What it checks on macOS</h2>
      <table>
        <thead>
          <tr>
            <th>Section</th>
            <th>Examples</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>System posture</td>
            <td>SIP, FileVault, Gatekeeper, firewall, guest account, MDM, XProtect, software-update settings</td>
          </tr>
          <tr>
            <td>Processes</td>
            <td>Running processes, users, parent PIDs, paths and suspicious command patterns</td>
          </tr>
          <tr>
            <td>Persistence</td>
            <td>LaunchAgents and LaunchDaemons, launchctl entries, cron, configuration profiles, SSH keys, shell profiles</td>
          </tr>
          <tr>
            <td>Browsers</td>
            <td>Chromium-family and Firefox extensions, Safari extensions, managed policies, native messaging hosts</td>
          </tr>
          <tr>
            <td>Network</td>
            <td>Interfaces, DNS, proxy settings, hosts file, listening sockets, established connections</td>
          </tr>
          <tr>
            <td>Files</td>
            <td>Recent downloads, quarantine events, executable files in temp, installed applications and signatures</td>
          </tr>
          <tr>
            <td>Extensions</td>
            <td>System extensions and kernel extensions</td>
          </tr>
          <tr>
            <td>Private LAN</td>
            <td>Local IPv4 addresses, gateway, ARP inventory, optional TCP port probes</td>
          </tr>
          <tr>
            <td>Mobile</td>
            <td>ADB inventory and high-signal Android checks, or libimobiledevice inventory for iOS</td>
          </tr>
        </tbody>
      </table>

      <h2>Active versus passive</h2>
      <p>
        Passive mode reads local state and the ARP table. It does not send
        packets to other hosts. Active mode adds TCP connection attempts to a
        fixed list of common ports on hosts already seen in the ARP table. It is
        opt-in in both the CLI and the web app.
      </p>
      <pre><code>{`# passive (default)
python3 -m scamcheck --device-audit

# active probes on your own private LAN
python3 -m scamcheck --device-audit --device-active --device-max-hosts 32

# web
# Device audit → tick "Actively probe the LAN"`}</code></pre>

      <p>
        Only probe networks you own or have explicit permission to test.
        Neighbour discovery and port probing can violate policy on shared,
        corporate or public networks even when the traffic is benign.
      </p>

      <h2>Report format</h2>
      <p>
        Each audit writes a timestamped folder under{" "}
        <span className="mono">~/.scamcheck/device-reports/</span> unless you
        choose another directory. The folder contains:
      </p>
      <ul>
        <li><span className="mono">report.json</span> — the complete structured report.</li>
        <li><span className="mono">report.md</span> — a human-readable summary and full detail.</li>
        <li><span className="mono">SHA256SUMS</span> — checksums for both files.</li>
      </ul>
      <pre><code>{`shasum -a 256 -c SHA256SUMS`}</code></pre>

      <h2>Severity model</h2>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Meaning</th>
          </tr>
        </thead>
        <tbody>
          <tr><td className="mono">critical</td><td>Immediate, high-confidence risk such as a known malicious persistence item</td></tr>
          <tr><td className="mono">high</td><td>Strong indicator that needs prompt review</td></tr>
          <tr><td className="mono">medium</td><td>Weak or contextual signal, or a risky exposure</td></tr>
          <tr><td className="mono">low</td><td>Hardening opportunity</td></tr>
          <tr><td className="mono">info</td><td>Inventory fact with no direct risk</td></tr>
        </tbody>
      </table>

      <h2>Limitations</h2>
      <ul>
        <li>Unprivileged checks cannot see everything. Some items are skipped and listed explicitly.</li>
        <li>Unsigned software is not automatically malicious; signature status is evidence, not a verdict.</li>
        <li>ARP is a snapshot. Devices that are asleep or off-network will not appear.</li>
        <li>Port probes show reachability, not exploitability.</li>
        <li>The audit cannot detect a compromised firmware or a kernel-level attacker with full control.</li>
      </ul>

      <h2>Platform coverage</h2>
      <p>
        macOS receives the deepest checks. Windows and Linux receive inventory
        and selected posture checks. Android and iOS are inspected only through
        already-installed tooling, plus a manual checklist for each platform.
        Routers and TVs are covered by checklists rather than remote access.
      </p>
    </>
  );
}
