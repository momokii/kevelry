import { ApiError } from "./errors";
import { hstsHeaderValue } from "../../../../src/lib/hsts";

/** Public rate budget surfaced on every response. */
export const RATE_LIMIT_MAX = 600;
export const RATE_LIMIT_WINDOW_SECONDS = 60;

/** Request bounds: oversized request lines and param floods are rejected. */
export const MAX_URL_CHARS = 4096;
export const MAX_QUERY_PARAMS = 25;

/** Concurrency bound: in-flight route executions past this get a 429. */
export const MAX_CONCURRENT_REQUESTS = 32;

/** Default wall-clock budget for the unbounded search fan-out loop. */
export const SEARCH_TIME_BUDGET_MS = 3000;

interface RateBucket {
  count: number;
  resetAt: number;
}

const rateBuckets = new Map<string, RateBucket>();

/**
 * Insertion-ordered expiry queue for the buckets above. Every window that
 * starts pushes one marker; `evictExpiredBuckets` drains markers off the front
 * once their window has fully elapsed, so each marker is pushed and popped at
 * most once and a request pays O(1) amortised — never a full-map scan. Map
 * insertion order is the FIFO, and the window length is constant, so markers
 * are ordered by `resetAt` while the clock moves forward; a backwards clock
 * jump can only delay a drain, never leak one permanently.
 */
const rateBucketExpiries = new Map<number, { key: string; resetAt: number }>();
let expirySequence = 0;
/** `resetAt` of the oldest pending marker; `Infinity` when the queue is empty. */
let expiryFrontier = Number.POSITIVE_INFINITY;

function recordBucketExpiry(key: string, resetAt: number): void {
  expirySequence += 1;
  rateBucketExpiries.set(expirySequence, { key, resetAt });
  expiryFrontier = Math.min(expiryFrontier, resetAt);
}

function evictExpiredBuckets(nowMs: number): void {
  if (nowMs < expiryFrontier) return;
  for (const [sequence, marker] of rateBucketExpiries) {
    if (marker.resetAt > nowMs) {
      expiryFrontier = marker.resetAt;
      return;
    }
    rateBucketExpiries.delete(sequence);
    const bucket = rateBuckets.get(marker.key);
    // The marker can be stale: the same key may have started a newer window.
    // Delete only the bucket that is itself finished, never a live budget.
    if (bucket !== undefined && bucket.resetAt <= nowMs) rateBuckets.delete(marker.key);
  }
  expiryFrontier = Number.POSITIVE_INFINITY;
}

/**
 * Test hook: live buckets, so eviction is observable without waiting on a
 * timer. Reads the same map the limiter uses; writes nothing.
 */
export function rateBucketCount(): number {
  return rateBuckets.size;
}

/**
 * Test hook: pending expiry markers. Must stay proportional to active windows;
 * a marker per request would mean the queue itself is the new leak.
 */
export function rateExpiryQueueDepth(): number {
  return rateBucketExpiries.size;
}

export function clientKeyFor(request: Request): string {
  // Proxies append the observed peer address; the client-supplied leftmost
  // entries are spoofable, so the rate-limit identity is the LAST entry —
  // the one added by our own edge proxy. Deployments must put a proxy in
  // front that overwrites (never blindly trusts) these headers, and must
  // never expose the app port directly. See README deployment notes.
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded !== null && forwarded.trim() !== "") {
    const entries = forwarded
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry !== "");
    const last = entries[entries.length - 1];
    if (last !== undefined && last !== "") return last;
  }
  const realIp = request.headers.get("x-real-ip");
  if (realIp !== null && realIp.trim() !== "") return realIp.trim();
  return "local";
}

export function checkRateLimit(
  key: string,
  nowMs: number = Date.now(),
): { allowed: boolean; remaining: number; reset: number } {
  // Amortised sweep: only expired markers past the frontier are touched, so a
  // request never walks the whole map. The map is deliberately not capped by a
  // ceiling that drops live buckets — an attacker who can churn client keys
  // would then evict other clients' live budgets (a rate-limit bypass), and
  // refusing to track new keys either grants unlimited requests or denies
  // legitimate clients. Expiry is the only safe eviction.
  evictExpiredBuckets(nowMs);
  const entry = rateBuckets.get(key);
  if (entry === undefined || nowMs >= entry.resetAt) {
    const resetAt = nowMs + RATE_LIMIT_WINDOW_SECONDS * 1000;
    rateBuckets.set(key, { count: 1, resetAt });
    recordBucketExpiry(key, resetAt);
    return { allowed: true, remaining: RATE_LIMIT_MAX - 1, reset: RATE_LIMIT_WINDOW_SECONDS };
  }
  if (entry.count >= RATE_LIMIT_MAX) {
    return {
      allowed: false,
      remaining: 0,
      reset: Math.max(0, Math.ceil((entry.resetAt - nowMs) / 1000)),
    };
  }
  entry.count += 1;
  return {
    allowed: true,
    remaining: RATE_LIMIT_MAX - entry.count,
    reset: Math.max(0, Math.ceil((entry.resetAt - nowMs) / 1000)),
  };
}

export function applyRateHeaders(
  response: Response,
  limit: { remaining: number; reset: number },
): Response {
  response.headers.set("X-RateLimit-Limit", String(RATE_LIMIT_MAX));
  response.headers.set("X-RateLimit-Remaining", String(limit.remaining));
  response.headers.set("X-RateLimit-Reset", String(limit.reset));
  return response;
}

let activeRequests = 0;
let maxConcurrentRequests = MAX_CONCURRENT_REQUESTS;
let searchBudgetMs = SEARCH_TIME_BUDGET_MS;
let allowedOrigins: string[] = [];

export function setMaxConcurrentRequests(value: number): void {
  maxConcurrentRequests = value;
}

export function setSearchBudgetMs(value: number): void {
  searchBudgetMs = value;
}

export function setAllowedOrigins(origins: string[]): void {
  allowedOrigins = [...origins];
}

export function resetHardeningState(): void {
  activeRequests = 0;
  maxConcurrentRequests = MAX_CONCURRENT_REQUESTS;
  searchBudgetMs = SEARCH_TIME_BUDGET_MS;
  allowedOrigins = [];
  rateBuckets.clear();
  rateBucketExpiries.clear();
  expirySequence = 0;
  expiryFrontier = Number.POSITIVE_INFINITY;
}

export function acquireConcurrencySlot(): boolean {
  if (activeRequests >= maxConcurrentRequests) return false;
  activeRequests += 1;
  return true;
}

export function releaseConcurrencySlot(): void {
  activeRequests = Math.max(0, activeRequests - 1);
}

export function searchBudgetExceeded(startedAtMs: number, nowMs: number = Date.now()): boolean {
  return nowMs - startedAtMs >= searchBudgetMs;
}

/**
 * Security headers every API response carries. `request` decides whether
 * Strict-Transport-Security may be added: see `src/lib/hsts.ts` for the rule
 * (already-HTTPS request, or the explicit `HSTS_ENABLED` flag).
 */
export function applySecurityHeaders(response: Response, request: Request): Response {
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set(
    "Content-Security-Policy",
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  );
  response.headers.set("Referrer-Policy", "no-referrer");
  const hsts = hstsHeaderValue(request);
  if (hsts !== null) response.headers.set("Strict-Transport-Security", hsts);
  return response;
}

export function applyCorsHeaders(request: Request, response: Response): Response {
  const origin = request.headers.get("origin");
  if (origin === null || origin === "") return response;
  response.headers.set("Vary", "Origin");
  if (allowedOrigins.includes(origin)) {
    response.headers.set("Access-Control-Allow-Origin", origin);
    response.headers.set("Access-Control-Allow-Methods", "GET, OPTIONS");
    response.headers.set("Access-Control-Max-Age", "600");
  }
  return response;
}

/**
 * The 204 preflight every v1 route answers for `OPTIONS`.
 *
 * It spends one hit from the same per-IP budget a GET spends. Leaving it free
 * made every `OPTIONS` an unthrottled request: a client could loop preflights
 * at line rate while the GET budget stayed untouched. The caller reserves the
 * hit, so the 204 carries the same `X-RateLimit-*` headers as any other
 * response and a spent budget answers `429` instead of `204`.
 *
 * It deliberately takes no concurrency slot: that cap bounds in-flight
 * database work, and a preflight reads nothing.
 */
export function preflightResponse(request: Request, rate: RateReservation): Response {
  const response = new Response(null, { status: 204 });
  applySecurityHeaders(response, request);
  applyCorsHeaders(request, response);
  applyRateHeaders(response, rate);
  return response;
}

export function assertRequestBounds(request: Request): void {
  if (request.url.length > MAX_URL_CHARS) {
    throw new ApiError("BAD_REQUEST", 400, "Request is too large to handle.");
  }
  const count = new URL(request.url).searchParams.size;
  if (count > MAX_QUERY_PARAMS) {
    throw new ApiError("BAD_REQUEST", 400, "Too many query parameters.");
  }
}

export interface RateReservation {
  allowed: boolean;
  remaining: number;
  reset: number;
}
