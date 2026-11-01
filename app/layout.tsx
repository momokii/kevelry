import { cookies } from "next/headers";
import type { Metadata } from "next";

import { DisplayPrefsProvider } from "@/components/ledger/DisplayPrefs";
import { Shell } from "@/components/shell/Shell";
import "./globals.css";
import "./ui.css";

// Blank counts as unset (never `new URL("")`, which throws): without a public
// origin the sitemap/cards fall back to loopback, which is correct for
// private deployments and harmless otherwise. Public deploys set SITE_URL.
const SITE_URL = (process.env.SITE_URL ?? "").trim().replace(/\/+$/, "") || "http://localhost:3000";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: "Kevelry",
  description: "Explainable CVE intelligence: volume, severity, KEV, EPSS, and change history.",
  openGraph: {
    type: "website",
    siteName: "Kevelry",
    title: "Kevelry",
    description: "Explainable CVE intelligence: volume, severity, KEV, EPSS, and change history.",
  },
  twitter: {
    card: "summary",
    title: "Kevelry",
    description: "Explainable CVE intelligence: volume, severity, KEV, EPSS, and change history.",
  },
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

function initialThemeFromCookies(header: string): string {
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index === -1) {
      continue;
    }
    if (part.slice(0, index).trim() !== "ui-theme") {
      continue;
    }
    const value = decodeURIComponent(part.slice(index + 1).trim());
    // Inline allow-list (mirrors isSupportedTheme, which lives in a client
    // module and cannot be imported into this server layout).
    if (value === "light" || value === "dark") {
      return value;
    }
  }
  return "light";
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const store = await cookies();
  const initialTimeZone = initialZoneFromCookies(store.toString());
  const initialTheme = initialThemeFromCookies(store.toString());
  return (
    <html lang="en" data-theme={initialTheme}>
      <body>
        <a className="ledger-skip-link" href="#main-content">
          Skip to main content
        </a>
        <DisplayPrefsProvider initialTimeZone={initialTimeZone} initialTheme={initialTheme}>
          <Shell>{children}</Shell>
        </DisplayPrefsProvider>
      </body>
    </html>
  );
}
