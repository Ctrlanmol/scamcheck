import { spawnBridge } from "@/lib/scamcheck";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type AuditArgs = {
  active_lan?: boolean;
  include_lan?: boolean;
  include_mobile?: boolean;
  max_hosts?: number;
  out_dir?: string;
};

export async function POST(request: Request) {
  let args: AuditArgs = {};
  try {
    args = (await request.json()) as AuditArgs;
  } catch {
    return new Response("Invalid JSON body.", { status: 400 });
  }

  const encoder = new TextEncoder();
  const child = spawnBridge("device_audit", args as Record<string, unknown>);
  let closed = false;
  let timer: NodeJS.Timeout | undefined;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      const send = (event: string, data: unknown) => {
        if (closed) return;
        controller.enqueue(
          encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`),
        );
      };
      const finish = () => {
        if (closed) return;
        closed = true;
        if (timer) clearTimeout(timer);
        controller.close();
      };

      let stdout = "";
      let stderrBuffer = "";

      timer = setTimeout(() => {
        send("error", { message: "The device audit timed out after 10 minutes." });
        child.kill("SIGKILL");
        finish();
      }, 10 * 60 * 1000);

      child.stderr?.on("data", (chunk: Buffer) => {
        stderrBuffer += chunk.toString("utf8");
        const lines = stderrBuffer.split("\n");
        stderrBuffer = lines.pop() ?? "";
        for (const line of lines) {
          if (line.startsWith("@@progress ")) {
            send("progress", { message: line.slice("@@progress ".length) });
          }
        }
      });

      child.stdout?.on("data", (chunk: Buffer) => {
        stdout += chunk.toString("utf8");
      });

      child.on("error", (error) => {
        send("error", { message: `Could not start Python: ${error.message}` });
        finish();
      });

      child.on("close", () => {
        const line = stdout.trim().split("\n").filter(Boolean).pop();
        if (!line) {
          send("error", { message: "The audit returned no output." });
          finish();
          return;
        }
        try {
          const payload = JSON.parse(line) as
            | { ok: true; data: unknown }
            | { ok: false; error: string };
          if (payload.ok) {
            send("result", payload.data);
          } else {
            send("error", { message: payload.error || "The audit failed." });
          }
        } catch {
          send("error", { message: "The audit returned invalid JSON." });
        }
        finish();
      });
    },
    cancel() {
      closed = true;
      if (timer) clearTimeout(timer);
      child.kill("SIGKILL");
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
