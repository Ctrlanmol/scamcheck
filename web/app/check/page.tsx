import { CheckWorkbench } from "@/components/CheckWorkbench";
import { PageHeader } from "@/components/PageHeader";
import { runTool } from "@/lib/scamcheck";
import type { StatusData } from "@/lib/types";

export const dynamic = "force-dynamic";

export const metadata = { title: "Message check" };

export default async function CheckPage() {
  let region = "IN";
  try {
    const status = await runTool<StatusData>("status", {}, 15_000);
    region = status.region || "IN";
  } catch {
    region = "IN";
  }

  return (
    <>
      <PageHeader
        index="01"
        kicker="Detection workbench"
        title={
          <>
            Read the signal.
            <br />
            Not the noise.
          </>
        }
        lead="Weighted rules, full scam playbooks and a deterministic intelligence briefing for messages, whole chats, screenshots and inbox dumps."
        meta={["Rules + intel", "Offline by default", "OCR · QR · batch"]}
      />
      <CheckWorkbench defaultRegion={region} />
    </>
  );
}
