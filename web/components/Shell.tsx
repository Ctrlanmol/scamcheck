"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Motion } from "@/components/Motion";

const GROUPS: { label: string; items: { href: string; label: string; num: string }[] }[] = [
  {
    label: "Operate",
    items: [
      { href: "/", label: "Overview", num: "00" },
      { href: "/check", label: "Message check", num: "01" },
      { href: "/numbers", label: "Numbers & feeds", num: "02" },
      { href: "/jarvis", label: "JARVIS console", num: "03" },
    ],
  },
  {
    label: "Investigate",
    items: [
      { href: "/cases", label: "Evidence cases", num: "04" },
      { href: "/watchlist", label: "Watchlist", num: "05" },
      { href: "/campaigns", label: "Campaigns", num: "06" },
      { href: "/recovery", label: "Recovery", num: "07" },
    ],
  },
  {
    label: "Machine",
    items: [{ href: "/device", label: "Device audit", num: "08" }],
  },
  {
    label: "Reference",
    items: [
      { href: "/docs", label: "Documentation", num: "09" },
      { href: "/settings", label: "Settings", num: "10" },
    ],
  },
];

function isActive(pathname: string, href: string): boolean {
  if (href === "/") return pathname === "/";
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  return (
    <div className="shell">
      <Motion />
      <aside className={`sidebar${open ? " open" : ""}`}>
        <Link href="/" className="brand">
          <div>
            <div className="brand-mark">
              SCAM<span>/</span>CHECK
            </div>
            <div className="brand-sub">Local-first scam defense</div>
          </div>
          <span className="brand-version">v0.12</span>
        </Link>

        <nav className="nav" aria-label="Primary">
          {GROUPS.map((group) => (
            <div className="nav-group" key={group.label}>
              <div className="nav-label">{group.label}</div>
              {group.items.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`nav-link${isActive(pathname, item.href) ? " active" : ""}`}
                >
                  <span className="num">{item.num}</span>
                  <span>{item.label}</span>
                </Link>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-foot">
          <div className="status-line">
            <span className="dot" />
            <span>Python bridge online</span>
          </div>
          <div>Local only · no telemetry</div>
          <div>~/.scamcheck</div>
          <div style={{ marginTop: 8 }}>
            <a href="/docs/privacy" style={{ textDecoration: "underline" }}>
              Privacy model
            </a>
          </div>
        </div>
      </aside>

      {open ? (
        <button
          className="scrim"
          aria-label="Close navigation"
          onClick={() => setOpen(false)}
        />
      ) : null}

      <div className="main-area">
        <div className="mobile-bar">
          <Link href="/" className="brand-mark">
            SCAM<span>/</span>CHECK
          </Link>
          <button className="menu-btn" onClick={() => setOpen(true)}>
            Menu
          </button>
        </div>
        <main className="main">{children}</main>
      </div>
    </div>
  );
}
