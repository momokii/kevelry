import { cookies } from "next/headers";
import type { Metadata } from "next";

import { DisplayPrefsProvider } from "@/components/ledger/DisplayPrefs";
import "./globals.css";

export const metadata: Metadata = {
  title: "CVE Change Radar",
  description: "App shell. No app behavior yet.",
};

const SUPPORTED_ZONES = [
  "Asia/Jakarta",
  "Asia/Singapore",
  "UTC",
  "Europe/London",
  "America/New_York",
  "America/Los_Angeles",
] as const;

function initialZoneFromCookies(header: string): (typeof SUPPORTED_ZONES)[number] {
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index === -1) {
      continue;
    }
    if (part.slice(0, index).trim() !== "ledger-timezone") {
      continue;
    }
    const value = decodeURIComponent(part.slice(index + 1).trim());
    if ((SUPPORTED_ZONES as readonly string[]).includes(value)) {
      return value as (typeof SUPPORTED_ZONES)[number];
    }
  }
  return "Asia/Jakarta";
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const store = await cookies();
  const initialTimeZone = initialZoneFromCookies(store.toString());
  return (
    <html lang="en">
      <body>
        <a className="ledger-skip-link" href="#main-content">
          Skip to main content
        </a>
        <DisplayPrefsProvider initialTimeZone={initialTimeZone}>{children}</DisplayPrefsProvider>
      </body>
    </html>
  );
}
