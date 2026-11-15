// Public base URL resolution for absolute links (v3 epic E5). The standalone
// server binds 0.0.0.0, so `new URL(request.url).origin` is the bind address —
// `http://0.0.0.0:3000` — which no subscriber can open. This module turns the
// operator's configuration or the proxy headers into an origin, or reports
// "unknown" so the caller omits the link instead of emitting a dead one.
//
// Pure and testable: no request object, no database, no network, never throws.

/** Environment shape the resolver reads; `process.env` satisfies it. */
export type SiteUrlEnv = Readonly<Record<string, string | undefined>>;

/**
 * Hosts a subscriber cannot reach: the wildcard bind address, loopback in IPv4
 * and IPv6 (bracketed as `URL.hostname` reports it), and the empty host.
 */
const UNUSABLE_HOSTNAMES = new Set([
  "",
  "0.0.0.0",
  "127.0.0.1",
  "localhost",
  "::",
  "[::]",
  "0:0:0:0:0:0:0:0",
  "::1",
  "[::1]",
]);

function isUsableHostname(hostname: string): boolean {
  return !UNUSABLE_HOSTNAMES.has(hostname.trim().toLowerCase());
}

/**
 * Normalizes a candidate base URL: it must parse, use `http:`/`https:`, carry a
 * usable host and no credentials or query, and lose its trailing slash so the
 * caller can append `/path` without producing `//`. Returns null when any of
 * that fails; the caller omits the link rather than publishing the raw value.
 */
function normalizeBaseUrl(candidate: string): string | null {
  let url: URL;
  try {
    url = new URL(candidate.trim());
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (url.hostname === "" || !isUsableHostname(url.hostname)) return null;
  if (url.username !== "" || url.password !== "") return null;
  if (url.search !== "" || url.hash !== "") return null;
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

/** First entry of a possibly comma-separated proxy header, trimmed. */
function firstHeaderValue(headers: Headers, name: string): string | null {
  const raw = headers.get(name);
  if (raw === null) return null;
  const first = (raw.split(",")[0] ?? "").trim();
  return first === "" ? null : first;
}

/**
 * The scheme `x-forwarded-proto` names, defaulting to https. A present but
 * non-HTTP scheme is returned as-is so the base never claims a scheme the
 * proxy did not: normalization then rejects it and the link is omitted.
 */
function forwardedProto(headers: Headers): string {
  return (firstHeaderValue(headers, "x-forwarded-proto") ?? "https").toLowerCase();
}

/**
 * Candidate public base URL for this deployment, in priority order:
 *
 * 1. `SITE_URL` when set — the operator's explicit origin, trailing slash
 *    stripped. A set value that is not a usable http(s) origin resolves to
 *    null: a misconfigured override must not be silently replaced by headers.
 * 2. `x-forwarded-proto` (default `https`) + `x-forwarded-host` — what a
 *    reverse proxy reports the client actually asked for.
 * 3. `x-forwarded-proto` + `host` — a direct request's own host.
 *
 * The wildcard bind address, loopback, and an empty host are rejected at every
 * step; `null` means "the public origin is unknown", and callers must omit the
 * absolute link instead of falling back to the bind address.
 */
export function resolvePublicBaseUrl(
  headers: Headers,
  env: SiteUrlEnv = process.env,
): string | null {
  try {
    const configured = (env.SITE_URL ?? "").trim();
    if (configured !== "") return normalizeBaseUrl(configured);

    const proto = forwardedProto(headers);
    if (proto !== "http" && proto !== "https") return null;

    const hosts = [
      firstHeaderValue(headers, "x-forwarded-host"),
      firstHeaderValue(headers, "host"),
    ];
    for (const host of hosts) {
      // A host header is a host, never a path or credentials: reject anything
      // that would smuggle one into the base URL.
      if (host === null || /[/\\@?#\s]/.test(host)) continue;
      const base = normalizeBaseUrl(`${proto}://${host}`);
      if (base !== null) return base;
    }
    return null;
  } catch {
    return null;
  }
}
