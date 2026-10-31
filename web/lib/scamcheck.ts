import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export const TOOL_NAMES = [
  "analyze",
  "analyze_image",
  "decode_image",
  "check_number",
  "lists",
  "list_add",
  "import_list",
  "feeds_status",
  "feeds_update",
  "cases_list",
  "case_create",
  "case_get",
  "case_add",
  "case_note",
  "case_entity",
  "case_export",
  "case_verify",
  "case_close",
  "case_report",
  "watchlist_list",
  "watchlist_add",
  "watchlist_remove",
  "watchlist_clear",
  "campaigns",
  "campaign_get",
  "recover",
  "url",
  "history",
  "jarvis",
  "batch",
  "status",
  "set_region",
  "regions",
  "bot_status",
  "device_audit",
] as const;

export type ToolName = (typeof TOOL_NAMES)[number];

export class ToolError extends Error {
  status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.name = "ToolError";
    this.status = status;
  }
}

function findProjectRoot(): string {
  const candidates = [
    process.env.SCAMCHECK_ROOT,
    process.cwd(),
    path.resolve(process.cwd(), ".."),
    path.resolve(process.cwd(), "../.."),
  ].filter(Boolean) as string[];
  for (const candidate of candidates) {
    if (
      fs.existsSync(path.join(candidate, "scamcheck", "__init__.py")) &&
      fs.existsSync(path.join(candidate, "pyproject.toml"))
    ) {
      return candidate;
    }
  }
  throw new ToolError(
    "Could not find the scamcheck project root. Set SCAMCHECK_ROOT.",
    500,
  );
}

export function projectRoot(): string {
  return findProjectRoot();
}

export function pythonBinary(): string {
  return process.env.SCAMCHECK_PYTHON || "python3";
}

export function bridgeEnv(root: string): NodeJS.ProcessEnv {
  const pythonPath = [root, process.env.PYTHONPATH].filter(Boolean).join(path.delimiter);
  return {
    ...process.env,
    PYTHONPATH: pythonPath,
    PYTHONUNBUFFERED: "1",
    PYTHONIOENCODING: "utf-8",
  };
}

export type BridgeResponse<T = unknown> =
  | { ok: true; data: T; elapsed_ms?: number }
  | { ok: false; error: string; type?: string };

export async function runTool<T = unknown>(
  tool: ToolName,
  args: Record<string, unknown> = {},
  timeoutMs = 180_000,
): Promise<T> {
  const root = findProjectRoot();
  return new Promise<T>((resolve, reject) => {
    const child = spawn(/*turbopackIgnore: true*/ pythonBinary(), ["-m", "scamcheck.webcli"], {
      cwd: root,
      env: bridgeEnv(root),
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill("SIGKILL");
      reject(new ToolError(`The tool timed out after ${Math.round(timeoutMs / 1000)}s.`, 504));
    }, timeoutMs);

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
      if (stderr.length > 80_000) stderr = stderr.slice(-80_000);
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new ToolError(`Could not start Python: ${error.message}`, 500));
    });
    child.on("close", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const line = stdout.trim().split("\n").filter(Boolean).pop();
      if (!line) {
        reject(new ToolError(stderr.trim() || "The Python bridge returned no output.", 500));
        return;
      }
      try {
        const payload = JSON.parse(line) as BridgeResponse<T>;
        if (!payload.ok) {
          reject(new ToolError(payload.error || "The tool failed.", 400));
          return;
        }
        resolve(payload.data);
      } catch {
        reject(new ToolError(stderr.trim() || "The Python bridge returned invalid JSON.", 500));
      }
    });

    child.stdin.write(JSON.stringify({ tool, args }));
    child.stdin.end();
  });
}

export function spawnBridge(
  tool: ToolName,
  args: Record<string, unknown>,
): ReturnType<typeof spawn> {
  const root = findProjectRoot();
  const child = spawn(/*turbopackIgnore: true*/ pythonBinary(), ["-m", "scamcheck.webcli"], {
    cwd: root,
    env: bridgeEnv(root),
    stdio: ["pipe", "pipe", "pipe"],
  });
  child.stdin.write(JSON.stringify({ tool, args }));
  child.stdin.end();
  return child;
}
