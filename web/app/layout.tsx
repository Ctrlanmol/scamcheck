import type { Metadata } from "next";
import "./globals.css";
import { Shell } from "@/components/Shell";

export const metadata: Metadata = {
  title: {
    default: "scamcheck — local-first scam defense",
    template: "%s · scamcheck",
  },
  description:
    "A local-first toolkit for scam messages, conversations, screenshots, phone numbers, evidence cases and device security. No cloud. No telemetry.",
  applicationName: "scamcheck",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
