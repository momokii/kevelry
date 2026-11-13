import type { NextConfig } from "next";

// Page hardening headers. The API routes set their own stricter set
// (strict JSON CSP included) in app/api/v1/_lib/guardrails.ts, so pages are
// matched here with an /api exclusion to avoid duplicate headers.
//
// The page-level Content-Security-Policy lives in `middleware.ts`, because it
// needs a per-request nonce: Next.js stamps that nonce onto the inline scripts
// it emits, so `script-src` does not fall back to `'unsafe-inline'`. The headers
// below are static and cost nothing per request.

const PAGE_SECURITY_HEADERS = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "no-referrer" },
  // The console uses no camera, microphone, geolocation, or payment APIs.
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
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
