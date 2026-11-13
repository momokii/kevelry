import { NextResponse, type NextRequest } from "next/server";

import { buildContentSecurityPolicy, createCspNonce } from "./src/lib/csp";

// Page-level Content-Security-Policy with a per-request nonce. The policy text and
// the nonce live in `src/lib/csp.ts` so they can be unit-tested; this file only
// wires them onto the request (for Next) and the response (for the browser).
//
// API routes keep their own stricter policy (`default-src 'none'`) in
// `app/api/v1/_lib/guardrails.ts`; the matcher below leaves them alone so a response
// never carries two policies.

export const CSP_NONCE_HEADER = "x-csp-nonce";

export function middleware(request: NextRequest): NextResponse {
  const nonce = createCspNonce();
  const policy = buildContentSecurityPolicy(nonce, {
    development: process.env.NODE_ENV === "development",
  });

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set(CSP_NONCE_HEADER, nonce);
  requestHeaders.set("Content-Security-Policy", policy);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", policy);
  return response;
}

export const config = {
  // Pages only: API routes set their own policy, and static assets do not need
  // a document policy. `_next/static` and `_next/image` are excluded so the CDN
  // path stays cacheable.
  matcher: ["/((?!api/|_next/static|_next/image|favicon.ico).*)"],
};
