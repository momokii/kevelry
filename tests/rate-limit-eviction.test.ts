// New-test justification (plan P0.3): `rateBuckets` in
// `app/api/v1/_lib/guardrails.ts` is module-level and was only ever cleared by
// `resetHardeningState`, so a scraped port or an IPv6 /64 grew it for the life
// of the process. The eviction is time- and size-sensitive and cannot be proven
// from a route test, so it is exercised directly with simulated time: every
// `checkRateLimit` call takes `nowMs`, which makes expiry deterministic without
// timers. `rateBucketCount` / `rateExpiryQueueDepth` are the read-only hooks
// that make the internal maps observable.

import { afterEach, describe, expect, it } from "vitest";

import {
  RATE_LIMIT_MAX,
  RATE_LIMIT_WINDOW_SECONDS,
  checkRateLimit,
  rateBucketCount,
  rateExpiryQueueDepth,
  resetHardeningState,
} from "../app/api/v1/_lib/guardrails";

const WINDOW_MS = RATE_LIMIT_WINDOW_SECONDS * 1000;
const T0 = 1_700_000_000_000;

afterEach(() => {
  resetHardeningState();
});

describe("rate-limit bucket eviction", () => {
  it("drops every bucket whose window has fully elapsed, on the next call", () => {
    for (let n = 0; n < 50; n += 1) checkRateLimit(`198.51.100.${n}`, T0);
    expect(rateBucketCount()).toBe(50);
    expect(rateExpiryQueueDepth()).toBe(50);

    // Inside the window nothing is evicted: the budget is still being spent,
    // and this probe starts a window of its own that outlives the first 50.
    checkRateLimit("203.0.113.1", T0 + WINDOW_MS - 1);
    expect(rateBucketCount()).toBe(51);

    // The first call past the window drains the 50 finished buckets and keeps
    // only the probe (still open) plus the new key.
    checkRateLimit("203.0.113.2", T0 + WINDOW_MS);
    expect(rateBucketCount()).toBe(2);

    // One window later even the probes are gone: only the newest bucket stays.
    checkRateLimit("203.0.113.3", T0 + 2 * WINDOW_MS);
    expect(rateBucketCount()).toBe(1);
    expect(rateExpiryQueueDepth()).toBe(1);
  });

  it("evicts only the finished window and preserves a live neighbour's budget", () => {
    const now = T0;
    checkRateLimit("192.0.2.10", now); // window A: expires at T0 + 60s
    checkRateLimit("192.0.2.20", now + WINDOW_MS / 2); // window B: T0 + 90s

    // A is expired, B is not: B's bucket must survive with its spent hit intact.
    checkRateLimit("192.0.2.30", now + WINDOW_MS + 1);
    expect(rateBucketCount()).toBe(2); // B and the C probe

    const neighbour = checkRateLimit("192.0.2.20", now + WINDOW_MS + 2);
    expect(neighbour.allowed).toBe(true);
    // 1 hit spent earlier + this one = 2, not a fresh window of 599 remaining.
    expect(neighbour.remaining).toBe(RATE_LIMIT_MAX - 2);
  });

  it("keeps one marker per window, not one per request", () => {
    for (let n = 0; n < 5 * RATE_LIMIT_MAX; n += 1) checkRateLimit("198.51.100.77", T0);
    expect(rateExpiryQueueDepth()).toBe(1);
    expect(rateBucketCount()).toBe(1);

    checkRateLimit("198.51.100.77", T0 + WINDOW_MS);
    expect(rateExpiryQueueDepth()).toBe(1);
    expect(rateBucketCount()).toBe(1);
  });

  it("stays bounded under per-window key churn instead of growing forever", () => {
    // A fresh sweep of distinct keys every window for ten windows. Only the
    // current window's keys may remain; 10 x 40 = 400 would be the leak.
    for (let window = 0; window < 10; window += 1) {
      const now = T0 + window * WINDOW_MS;
      for (let n = 0; n < 40; n += 1) checkRateLimit(`2001:db8::${window}:${n}`, now);
      expect(rateBucketCount()).toBe(40);
      expect(rateExpiryQueueDepth()).toBe(40);
    }
    expect(rateBucketCount()).toBe(40);
  });

  it("returns the same allow/deny answers while evicting", () => {
    const ip = "203.0.113.9";
    for (let n = 0; n < RATE_LIMIT_MAX; n += 1) {
      expect(checkRateLimit(ip, T0).allowed).toBe(true);
    }
    expect(checkRateLimit(ip, T0 + 1).allowed).toBe(false);

    // A new window after expiry is full budget again, with other keys swept.
    checkRateLimit("203.0.113.99", T0 + WINDOW_MS + 1);
    const fresh = checkRateLimit(ip, T0 + WINDOW_MS + 2);
    expect(fresh.allowed).toBe(true);
    expect(fresh.remaining).toBe(RATE_LIMIT_MAX - 1);
  });
});
