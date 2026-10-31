import { NumbersWorkbench } from "@/components/NumbersWorkbench";
import { PageHeader } from "@/components/PageHeader";
import { runTool } from "@/lib/scamcheck";
import type { StatusData } from "@/lib/types";

export const dynamic = "force-dynamic";
export const metadata = { title: "Numbers & feeds" };

export default async function NumbersPage() {
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
        index="02"
        kicker="Phone intelligence"
        title={
          <>
            Numbers leave
            <br />
            fingerprints.
          </>
        }
        lead="Range facts, premium-rate flags, country mismatch, your own block and allow lists, and opt-in cached feeds — matched locally."
        meta={["Range + reputation", "Local lists", "Opt-in feeds"]}
      />
      <NumbersWorkbench defaultRegion={region} />
    </>
  );
}
