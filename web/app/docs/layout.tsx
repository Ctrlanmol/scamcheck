import { DocsNav } from "@/components/DocsNav";

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="docs-shell">
      <DocsNav />
      <article className="docs-body">{children}</article>
    </div>
  );
}
