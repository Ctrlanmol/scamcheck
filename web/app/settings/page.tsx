import { PageHeader } from "@/components/PageHeader";
import { SettingsWorkbench } from "@/components/SettingsWorkbench";

export const metadata = { title: "Settings" };

export default function SettingsPage() {
  return (
    <>
      <PageHeader
        index="10"
        kicker="Runtime & data"
        title={
          <>
            Own the
            <br />
            machine.
          </>
        }
        lead="Region, local memory, feeds, bot status and the files scamcheck keeps on disk. Every setting is local and reversible — except deleting history."
        meta={["~/.scamcheck", "0600 files", "No telemetry"]}
      />
      <SettingsWorkbench />
    </>
  );
}
