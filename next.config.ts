import type { NextConfig } from "next";

// Page hardening headers. The API routes set their own stricter set
// (strict JSON CSP included) in app/api/v1/_lib/shared.ts, so pages are
// matched here with an /api exclusion to avoid duplicate headers.
//
// Deliberately no page-level Content-Security-Policy: Next.js ships inline
// runtime chunks that would force `unsafe-inline`, neutering most of the
// benefit on a cookie-less, account-less, read-only site with React-escaped
// output. Revisit with nonce middleware if the page ever handles sessions
// or user content. Frame-busting + nosniff + no-referrer stand on their own.

const PAGE_SECURITY_HEADERS = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "no-referrer" },
];

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/((?!api/).*)",
        headers: PAGE_SECURITY_HEADERS,
      },
    ];
  },
};

export default nextConfig;
