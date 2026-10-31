import { CampaignsWorkbench } from "@/components/CampaignsWorkbench";
import { PageHeader } from "@/components/PageHeader";

export const metadata = { title: "Campaigns" };

export default function CampaignsPage() {
  return (
    <>
      <PageHeader
        index="06"
        kicker="Pattern clustering"
        title={
          <>
            One scam.
            <br />
            Many messages.
          </>
        }
        lead="Related checks that share a phone number, domain, UPI ID or wallet collapse into a single campaign view — so a repeated operation is visible at a glance."
        meta={["Derived, not stored", "Local history", "Union-find clusters"]}
      />
      <CampaignsWorkbench />
    </>
  );
}
