import { JarvisConsole } from "@/components/JarvisConsole";
import { PageHeader } from "@/components/PageHeader";
import { runTool } from "@/lib/scamcheck";
import type { StatusData } from "@/lib/types";

export const dynamic = "force-dynamic";
export const metadata = { title: "JARVIS console" };

export default async function JarvisPage() {
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
        index="03"
        kicker="Conversational console"
        title={
          <>
            One line.
            <br />
            Every tool.
          </>
        }
        lead="A single local command surface for messages, numbers, links, cases, campaigns and device checks. The same grammar as the terminal, kept on this machine."
        meta={["Local grammar", "No voice in browser", "EN · हिन्दी"]}
      />
      <JarvisConsole defaultRegion={region} />
    </>
  );
}
