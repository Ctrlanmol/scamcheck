import { PageHeader } from "@/components/PageHeader";
import { RecoveryWorkbench } from "@/components/RecoveryWorkbench";
import { runTool } from "@/lib/scamcheck";
import type { StatusData } from "@/lib/types";

export const dynamic = "force-dynamic";
export const metadata = { title: "Recovery" };

export default async function RecoveryPage() {
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
        index="07"
        kicker="After the loss"
        title={
          <>
            The first hour
            <br />
            matters most.
          </>
        }
        lead="Country-aware, step-by-step recovery: freeze accounts, preserve evidence, escalate to the bank, and report to the right authority before deadlines close."
        meta={["9 countries", "First hour → week", "Bank escalation"]}
      />
      <RecoveryWorkbench defaultRegion={region} />
    </>
  );
}
