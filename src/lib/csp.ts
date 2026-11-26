// Content-Security-Policy for rendered pages.
//
// Next.js reads the nonce out of the policy it finds on the request and stamps it
// onto the inline bootstrap/chunk scripts it emits, which is what lets
// `script-src` stay nonce-based in production instead of `'unsafe-inline'`.
// The dev server compiles modules with eval and injects inline HMR code, so its
// policy is deliberately looser — that branch never ships.
//
// `style-src` keeps `'unsafe-inline'` on purpose: React writes inline `style`
// attributes for chart geometry, and style attributes cannot be nonce-scoped.
//
// `img-src` allows `data:` and `blob:` because both are sources this app generates
// itself and never a remote host: the attached screenshot is staged as a `data:`
// URL and the turn's record keeps a downscaled copy of it, also `data:`. `blob:`
// is kept for an image held as an object URL, which is the same local picture by
// another route. Nothing wider is allowed — no `*`, no bare `https:` — so an image
// from anywhere else is still refused.

export interface CspOptions {
  /** True when serving `next dev`; production never sets this. */
  development?: boolean;
}

export function buildContentSecurityPolicy(nonce: string, options: CspOptions = {}): string {
  const scriptSrc = options.development
    ? `'self' 'nonce-${nonce}' 'unsafe-eval' 'unsafe-inline'`
    : `'self' 'nonce-${nonce}' 'strict-dynamic'`;
  return [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "worker-src 'self' blob:",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "object-src 'none'",
  ].join("; ");
}

/** Nonce for one response. Hyphens stripped so it is a valid CSP nonce literal. */
export function createCspNonce(): string {
  return crypto.randomUUID().replace(/-/g, "");
}
