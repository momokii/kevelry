import { ApiError } from "./errors";

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
  const entry = rateBuckets.get(key);
  if (entry === undefined || nowMs >= entry.resetAt) {
    const resetAt = nowMs + RATE_LIMIT_WINDOW_SECONDS * 1000;
    rateBuckets.set(key, { count: 1, resetAt });
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

export function applySecurityHeaders(response: Response): Response {
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set(
    "Content-Security-Policy",
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  );
  response.headers.set("Referrer-Policy", "no-referrer");
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

export function preflightResponse(request: Request): Response {
  const response = new Response(null, { status: 204 });
  applySecurityHeaders(response);
  applyCorsHeaders(request, response);
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
