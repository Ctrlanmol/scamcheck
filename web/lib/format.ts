export function formatDate(ts?: number | null): string {
  if (!ts) return "—";
  const date = new Date(ts * 1000);
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatDay(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
  });
}

export function ago(ts?: number | null): string {
  if (!ts) return "—";
  const delta = Math.max(0, Date.now() / 1000 - ts);
  if (delta < 60) return "just now";
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  if (delta < 7 * 86400) return `${Math.floor(delta / 86400)}d ago`;
  return formatDay(ts);
}

export function scoreTone(score: number): string {
  if (score >= 60) return "danger";
  if (score >= 35) return "warn";
  if (score >= 15) return "caution";
  return "safe";
}

export function verdictLabel(verdict?: string): string {
  return (verdict || "UNKNOWN").replaceAll("_", " ");
}

export function snippet(text?: string, limit = 96): string {
  const clean = (text || "").replace(/\s+/g, " ").trim();
  return clean.length > limit ? `${clean.slice(0, limit - 1)}…` : clean;
}

export function bytes(value?: number): string {
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unit]}`;
}
