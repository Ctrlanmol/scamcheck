import { DeviceAudit } from "@/components/DeviceAudit";
import { PageHeader } from "@/components/PageHeader";

export const metadata = { title: "Device audit" };

export default function DevicePage() {
  return (
    <>
      <PageHeader
        index="08"
        kicker="Machine posture"
        title={
          <>
            Know the
            <br />
            machine.
          </>
        }
        lead="A deterministic, read-only audit of this computer and the private network around it: security posture, processes, persistence, browsers, network, files and connected phones."
        meta={["No sudo", "Read-only", "Passive by default"]}
      />
      <DeviceAudit />
    </>
  );
}
