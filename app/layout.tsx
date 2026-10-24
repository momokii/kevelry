import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "CVE Change Radar",
  description: "App shell. No app behavior yet.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <a className="ledger-skip-link" href="#main-content">
          Skip to main content
        </a>
        {children}
      </body>
    </html>
  );
}
