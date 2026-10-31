export type Reason = [string, number];

export type Finding = {
  severity: "critical" | "high" | "medium" | "low" | "info" | string;
  category: string;
  title: string;
  detail: string;
  evidence?: unknown[];
  recommendation?: string;
};

export type Intelligence = {
  scam_type?: string;
  title?: string;
  confidence?: string;
  score?: number;
  verdict?: string;
  summary?: string;
  stage?: { key?: string; label?: string; description?: string; confidence?: string };
  goals?: unknown[];
  payment_rails?: unknown[];
  impersonation?: unknown[];
  channels?: unknown[];
  tactics?: unknown[];
  next_moves?: unknown[];
  verify?: unknown[];
  safe_replies?: unknown[];
  evidence?: unknown[];
  reply_policy?: string;
  [key: string]: unknown;
};

export type AnalyzeResult = {
  score: number;
  final_verdict: string;
  reasons?: Reason[];
  scripts?: string[];
  intelligence?: Intelligence;
  message?: string;
  kind?: string;
  number?: Record<string, unknown>;
  qr?: { payload?: string; symbology?: string }[];
  ocr_engine?: string;
  extracted_text?: string;
  source_name?: string;
  watchlist?: WatchHit[];
  [key: string]: unknown;
};

export type WatchHit = {
  kind: string;
  value: string;
  label?: string;
  count?: number;
  last_ts?: number;
  verdict?: string;
  score?: number;
};

export type SeenHit = WatchHit;

export type AnalyzeData = {
  result: AnalyzeResult;
  seen: SeenHit[];
  watchlist: WatchHit[];
};

export type NumberData = {
  intel: {
    number: {
      valid: boolean;
      e164?: string;
      national?: string;
      kind?: string;
      country?: string;
      country_name?: string;
      note?: string;
      [key: string]: unknown;
    };
    reputation: {
      status: string;
      label?: string;
      reports?: number;
      source?: string;
    };
    flags: string[];
    risk: string;
    [key: string]: unknown;
  };
  seen: SeenHit[];
  watchlist: WatchHit[];
};

export type HistoryRow = {
  id: number;
  ts: number;
  kind: string;
  verdict: string;
  score: number;
  text: string;
  sender?: string | null;
};

export type CaseRow = {
  id: string;
  title: string;
  status?: string;
  scam_type?: string;
  country?: string;
  currency?: string;
  loss_amount?: number;
  created_ts?: number;
  updated_ts?: number;
  evidence_count?: number;
  entity_count?: number;
  notes?: string;
};

export type CaseDetail = CaseRow & {
  evidence?: {
    id: number;
    kind: string;
    filename?: string;
    size?: number;
    sha256?: string;
    added_ts?: number;
  }[];
  entities?: { kind: string; value: string; label?: string }[];
  events?: { ts: number; kind?: string; description: string }[];
};

export type WatchEntry = {
  kind: string;
  value: string;
  label?: string;
  notes?: string;
  hits?: number;
  created_ts?: number;
  last_hit_ts?: number;
};

export type Campaign = {
  id: string;
  checks: number;
  first_ts: number;
  last_ts: number;
  verdicts: Record<string, number>;
  indicators: { kind: string; value: string; label?: string; checks: number }[];
  items: HistoryRow[];
};

export type Playbook = {
  scam_type: string;
  title: string;
  country: string;
  authority: {
    country?: string;
    code?: string;
    cyber?: string;
    cyber_url?: string;
    police?: string;
    bank?: string;
    extra?: string;
  };
  now: string[];
  today: string[];
  week: string[];
};

export type FeedStatus = {
  updated_at?: number | null;
  sources: { url: string; label?: string; count?: number; fetched_at?: number; sha256?: string }[];
  configured: { url: string; label?: string; format?: string }[];
  path: string;
};

export type StatusData = {
  version: string;
  platform: string;
  data_dir: string;
  region: string;
  history: number;
  cases: number;
  watchlist: number;
  feeds: FeedStatus;
  bot: Record<string, unknown>;
  ai: boolean;
  device_audit: { supported: boolean; active_lan: boolean };
};

export type DeviceReport = {
  version: string;
  generated_at: number;
  platform: string;
  host: Record<string, unknown>;
  summary: {
    risk: string;
    score: number;
    findings: Record<string, number>;
    checks_run: number;
    skipped: { check: string; reason: string }[];
    active_lan: boolean;
    lan_included: boolean;
  };
  findings: Finding[];
  sections: {
    lan?: {
      local_ipv4: { interface: string; ip: string; netmask?: string }[];
      gateway?: string;
      devices: {
        ip: string;
        mac?: string;
        hostname?: string;
        vendor?: string;
        device_type?: string;
        open_ports?: number[];
        services?: { port: number; risk: string; label: string }[];
      }[];
      active?: boolean;
      notes?: string[];
    };
    mobile?: Record<string, unknown>;
    [key: string]: unknown;
  };
  device_checklists: Record<string, string[]>;
};

export type DeviceAuditData = {
  report: DeviceReport;
  export: {
    folder: string;
    json: string;
    markdown: string;
    sha256sums: string;
  };
};

export type BatchData = {
  messages: AnalyzeResult[];
  count: number;
};

export type UrlData = {
  report: {
    ok: boolean;
    input?: string;
    final_url?: string;
    domain?: string;
    https?: boolean;
    title?: string;
    server?: string;
    chain?: { url: string; status?: number }[];
    tls?: { issuer?: string; not_after?: string; tls_version?: string };
    rdap?: Record<string, unknown> | null;
    notes?: string[];
    [key: string]: unknown;
  };
  verdict: string;
  score: number;
  notes: string[];
  watchlist: WatchHit[];
};
