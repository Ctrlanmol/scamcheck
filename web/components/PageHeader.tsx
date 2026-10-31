import type { ReactNode } from "react";
import { CountUp } from "@/components/CountUp";

export function PageHeader({
  index,
  kicker,
  title,
  lead,
  meta = [],
}: {
  index: string;
  kicker: string;
  title: ReactNode;
  lead?: ReactNode;
  meta?: string[];
}) {
  return (
    <header className="page-head">
      <div className="head-copy">
        <div className="eyebrow">{kicker}</div>
        <h1 className="display">{title}</h1>
        {lead ? <p className="lead">{lead}</p> : null}
      </div>
      <div className="page-meta">
        <div className="page-index">{index}</div>
        {meta.map((line) => (
          <div key={line}>{line}</div>
        ))}
      </div>
    </header>
  );
}

export function SectionHead({
  index,
  title,
  note,
  action,
}: {
  index: string;
  title: ReactNode;
  note?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="section-head">
      <div className="section-title">
        <span className="idx">{index}</span>
        <h2>{title}</h2>
      </div>
      {action ?? (note ? <div className="section-note">{note}</div> : null)}
    </div>
  );
}

export function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
}) {
  return (
    <div className="stat">
      <div className="stat-value">
        {typeof value === "number" ? <CountUp value={value} /> : value}
      </div>
      <div>
        <div className="stat-label">{label}</div>
        {hint ? <div className="tiny muted" style={{ marginTop: 4 }}>{hint}</div> : null}
      </div>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function ErrorBox({ children }: { children: ReactNode }) {
  return <div className="error">{children}</div>;
}

export function Note({
  children,
  tone = "default",
}: {
  children: ReactNode;
  tone?: "default" | "warn" | "danger";
}) {
  return <div className={`note${tone === "default" ? "" : ` ${tone}`}`}>{children}</div>;
}
