// The assistant's own rate budget: 10 requests/minute and 60/hour per IP.
//
// Why not the v1 limiter: its window is 600/minute, sized for a read API that
// answers in milliseconds. One assistant request can spend four model rounds and
// real money, so it needs a budget an order of magnitude tighter — and the two
// budgets must not share a bucket, or a chat loop would exhaust the read API's
// headroom (and vice versa).
//
// Two windows, both checked and both consumed: 10/minute stops a burst, and
// 60/hour stops a slow drip that stays under the minute cap. The identity is
// `clientKeyFor` from the v1 guardrails — one definition of "the client" for the
// whole app, including its rule that only the last `x-forwarded-for` entry is
// trusted.
//
// The clock is injectable so a test can cross both window boundaries without
// waiting an hour. State is process-local, like the v1 limiter: a multi-instance
// deployment gets a per-instance budget, which is the same trade-off the read API
// already makes.

import { clientKeyFor } from "../../v1/_lib/guardrails";

/** Burst budget: requests per IP per rolling minute window. */
export const ASSISTANT_RATE_PER_MINUTE = 10;
/** Sustained budget: requests per IP per hour window. */
export const ASSISTANT_RATE_PER_HOUR = 60;

const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;

/** Which window ran out; the UI names the wait, so it needs the reason. */
export type AssistantRateWindow = "minute" | "hour";

export interface AssistantRateState {
  allowed: boolean;
  /** Limit of the window that decided this request. */
  limit: number;
  remaining: number;
  /** Seconds until the deciding window resets. */
  reset: number;
  window: AssistantRateWindow;
}

interface WindowState {
  count: number;
  resetAt: number;
}

interface ClientState {
  minute: WindowState | null;
  hour: WindowState | null;
}

const clients = new Map<string, ClientState>();
let clock: (() => number) | null = null;

/** Test seam: replace the clock, or pass `null` to use `Date.now`. */
export function setAssistantRateLimitClock(now: (() => number) | null): void {
  clock = now;
}

/** Test seam: forget every client's budget. */
export function resetAssistantRateLimitState(): void {
  clients.clear();
  clock = null;
}

function nowMs(): number {
  return clock === null ? Date.now() : clock();
}

function consume(
  state: WindowState | null,
  limit: number,
  windowMs: number,
  now: number,
): WindowState & { allowed: boolean } {
  if (state === null || now >= state.resetAt) {
    return { count: 1, resetAt: now + windowMs, allowed: true };
  }
  if (state.count >= limit) {
    return { ...state, allowed: false };
  }
  return { count: state.count + 1, resetAt: state.resetAt, allowed: true };
}

function secondsUntil(resetAt: number, now: number): number {
  return Math.max(0, Math.ceil((resetAt - now) / 1000));
}

/**
 * Consumes one request from both windows. A refused request spends neither the
 * other window nor a retry budget, so a throttled client recovers exactly when
 * the deciding window rolls over.
 */
export function checkAssistantRateLimit(key: string, now: number = nowMs()): AssistantRateState {
  let state = clients.get(key);
  if (state === undefined) {
    state = { minute: null, hour: null };
    clients.set(key, state);
  }
  const minute = consume(state.minute, ASSISTANT_RATE_PER_MINUTE, MINUTE_MS, now);
  const hour = consume(state.hour, ASSISTANT_RATE_PER_HOUR, HOUR_MS, now);
  state.minute = { count: minute.count, resetAt: minute.resetAt };
  state.hour = { count: hour.count, resetAt: hour.resetAt };

  // The minute window decides first: it is the tighter budget and the more
  // useful wait to report.
  if (!minute.allowed) {
    return {
      allowed: false,
      limit: ASSISTANT_RATE_PER_MINUTE,
      remaining: 0,
      reset: secondsUntil(minute.resetAt, now),
      window: "minute",
    };
  }
  if (!hour.allowed) {
    return {
      allowed: false,
      limit: ASSISTANT_RATE_PER_HOUR,
      remaining: 0,
      reset: secondsUntil(hour.resetAt, now),
      window: "hour",
    };
  }
  return {
    allowed: true,
    limit: ASSISTANT_RATE_PER_MINUTE,
    remaining: Math.min(
      Math.max(0, ASSISTANT_RATE_PER_MINUTE - minute.count),
      Math.max(0, ASSISTANT_RATE_PER_HOUR - hour.count),
    ),
    reset: secondsUntil(minute.resetAt, now),
    window: "minute",
  };
}

/** One reservation, threaded through the route's every response. */
export function reserveAssistantRateLimit(request: Request): AssistantRateState {
  return checkAssistantRateLimit(clientKeyFor(request));
}
