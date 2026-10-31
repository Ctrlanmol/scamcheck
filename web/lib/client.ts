export async function callTool<T>(
  tool: string,
  args: Record<string, unknown> = {},
): Promise<T> {
  const response = await fetch("/api/tool", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tool, args }),
  });
  let payload: { ok?: boolean; data?: T; error?: string };
  try {
    payload = await response.json();
  } catch {
    throw new Error(`The server returned ${response.status} without JSON.`);
  }
  if (!response.ok || !payload.ok) {
    throw new Error(payload.error || `Request failed (${response.status}).`);
  }
  return payload.data as T;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
