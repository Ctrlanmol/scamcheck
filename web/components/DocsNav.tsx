"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const LINKS = [
  { href: "/docs", label: "Overview" },
  { href: "/docs/install", label: "Install & run" },
  { href: "/docs/cli", label: "CLI reference" },
  { href: "/docs/web", label: "Web interface" },
  { href: "/docs/api", label: "HTTP API" },
  { href: "/docs/device", label: "Device audit" },
  { href: "/docs/cases", label: "Cases & recovery" },
  { href: "/docs/privacy", label: "Privacy model" },
  { href: "/docs/faq", label: "FAQ" },
];

export function DocsNav() {
  const pathname = usePathname();
  return (
    <nav className="docs-nav" aria-label="Documentation">
      {LINKS.map((link) => (
        <Link
          key={link.href}
          href={link.href}
          className={pathname === link.href ? "active" : ""}
        >
          {link.label}
        </Link>
      ))}
    </nav>
  );
}
