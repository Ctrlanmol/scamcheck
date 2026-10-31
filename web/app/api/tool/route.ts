import { NextResponse } from "next/server";
import {
  TOOL_NAMES,
  ToolError,
  runTool,
  type ToolName,
} from "@/lib/scamcheck";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  let body: { tool?: string; args?: Record<string, unknown> };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid JSON body." }, { status: 400 });
  }
  const tool = body.tool as ToolName | undefined;
  if (!tool || !TOOL_NAMES.includes(tool)) {
    return NextResponse.json({ ok: false, error: "Unknown tool." }, { status: 400 });
  }
  try {
    const data = await runTool(tool, body.args ?? {});
    return NextResponse.json({ ok: true, data });
  } catch (error) {
    const status = error instanceof ToolError ? error.status : 500;
    const message = error instanceof Error ? error.message : "Unexpected error.";
    return NextResponse.json({ ok: false, error: message }, { status });
  }
}
