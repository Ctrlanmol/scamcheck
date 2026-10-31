export const metadata = { title: "FAQ" };

export default function FaqDocs() {
  return (
    <>
      <div className="eyebrow">Documentation · questions</div>
      <h1>FAQ</h1>

      <h2>Is this an antivirus?</h2>
      <p>
        No. The device audit is a read-only reporting tool. It does not remove
        files, quarantine applications, block traffic or repair anything. Use a
        real endpoint-protection product for automatic response.
      </p>

      <h2>Does it work offline?</h2>
      <p>
        Yes, for everything except link investigation, AI review, feed updates
        and chat bots. Those four are opt-in. OCR and QR decoding work offline
        when a local backend is available.
      </p>

      <h2>Why does a safe message get a high score?</h2>
      <p>
        The score is a sum of signals. Marketing language, urgency, shortened
        links and payment requests can appear in legitimate messages. Read the
        signal list and the intelligence briefing before acting. The tool is
        designed to be explainable so you can judge the reason, not just the
        number.
      </p>

      <h2>Why did a scam get a low score?</h2>
      <p>
        Novel wording, images with little text, voice notes and social-only
        grooming can evade rules. Use conversation mode for multi-message scams
        and add known identifiers to the watchlist. A low score is not a
        guarantee of safety.
      </p>

      <h2>Does it send messages to a server?</h2>
      <p>
        Not by default. The web app spawns a local Python process. Only the
        explicit opt-ins listed in the privacy model can contact the network.
      </p>

      <h2>Can I use it on Windows or Linux?</h2>
      <p>
        The detector, cases, watchlists, recovery and web interface are
        cross-platform. The device audit is deepest on macOS; other platforms
        receive inventory and selected posture checks plus manual checklists.
      </p>

      <h2>Why is the device audit sometimes incomplete?</h2>
      <p>
        It runs unprivileged. Some checks require administrator access or
        macOS automation permission, so they are skipped and listed explicitly.
        The report never hides a skip.
      </p>

      <h2>Is active LAN scanning safe?</h2>
      <p>
        It sends TCP connection attempts to devices on your private network.
        That is benign on a network you own, but it can violate policy on a
        shared or corporate network. It is opt-in and capped at 64 hosts by
        default. Only use it with authorisation.
      </p>

      <h2>Can I trust the hashes in a case export?</h2>
      <p>
        They prove that the stored bytes have not changed since collection.
        They do not prove that the content is true or that the original source
        was authentic. Preserve the original device and files as well.
      </p>

      <h2>Is the complaint draft legal advice?</h2>
      <p>
        No. It is a structured starting point. Verify names, dates, amounts and
        reference numbers, and follow the process of your bank and local
        authority.
      </p>

      <h2>What about a recovery agent who contacted me?</h2>
      <p>
        Treat unsolicited recovery offers as a second scam. Legitimate banks and
        police do not ask for an upfront fee to recover funds.
      </p>

      <h2>Where is my data?</h2>
      <p>
        In <span className="mono">~/.scamcheck</span> unless you set{" "}
        <span className="mono">SCAMCHECK_HOME</span>. Settings shows the exact
        path and lets you clear check history. Cases and evidence are separate
        and must be removed deliberately.
      </p>

      <h2>Can I run the web app on another machine?</h2>
      <p>
        You can, but it has no authentication. Keep it on loopback and use an
        SSH tunnel. Do not expose it to a LAN or the public internet.
      </p>

      <h2>How do I contribute or report a bug?</h2>
      <p>
        The project is a normal Python package with tests under{" "}
        <span className="mono">tests/</span>. Add a failing test first, keep the
        runtime stdlib-only, and avoid new network calls in the default path.
      </p>
    </>
  );
}
