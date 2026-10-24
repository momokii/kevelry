import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "CVE Change Radar",
  description: "App shell. No app behavior yet.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
