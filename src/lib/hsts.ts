// Strict-Transport-Security, opt-in for plain-HTTP self-hosting.
//
// A self-hosted instance reached over `http://localhost:3000` (the documented
// local path) must not be pinned to HTTPS by its own headers: a browser that
// cached HSTS for that host would then refuse the only URL the operator has.
// So the header is sent only when the request itself arrived over TLS, or when
// `HSTS_ENABLED=true` says a TLS terminator in front of the app guarantees it.
//
// No `includeSubDomains`: the app cannot know whether a sibling subdomain of
// the deployment host is HTTPS, and the directive would take it down for a year.

export const HSTS_MAX_AGE_SECONDS = 31_536_000;

export const HSTS_HEADER_VALUE = `max-age=${HSTS_MAX_AGE_SECONDS}`;

/**
 * Explicit opt-in flag, fail-closed: only `true` (trimmed, any case) enables it.
 * `1`, `yes`, a typo or an empty string all leave HSTS off, so a malformed
 * environment never pins a deployment the operator did not ask to pin.
 */
export function hstsEnabled(env: Record<string, string | undefined> = process.env): boolean {
  return env.HSTS_ENABLED?.trim().toLowerCase() === "true";
}

/**
 * True when the request itself arrived over TLS: either the URL scheme is
 * https, or a trusted proxy in front set `X-Forwarded-Proto`. Only the first
 * comma-separated entry counts (the scheme the client used), and a header the
 * app cannot parse is not evidence of TLS.
 */
export function isHttpsRequest(request: Request): boolean {
  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return false;
  }
  if (url.protocol === "https:") return true;
  const forwarded = request.headers.get("x-forwarded-proto");
  if (forwarded === null) return false;
  const first = forwarded.split(",")[0]?.trim().toLowerCase();
  return first === "https";
}

/** The header value this request should carry, or null when it must not be sent. */
export function hstsHeaderValue(
  request: Request,
  env: Record<string, string | undefined> = process.env,
): string | null {
  if (hstsEnabled(env)) return HSTS_HEADER_VALUE;
  return isHttpsRequest(request) ? HSTS_HEADER_VALUE : null;
}
