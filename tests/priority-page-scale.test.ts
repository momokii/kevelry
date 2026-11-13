// Regression test (priority-page crash): GET /priority called five priority
// getters WITHOUT a limit on a ~395k-row corpus, materializing ~2M objects
// until the Next server aborted (SIGABRT in better-sqlite3). Seeds a synthetic
// 50,000-row scored corpus in a temp DB (same approach as
// tests/overview-scale.test.ts; invented CVE-2099 IDs, no network) and proves:
// (a) the page source passes an explicit limit to all five getters, (b) the
// bounded loads complete under a generous 5s ceiling with every list capped at
// the page limit, (c) each bounded call equals full-order-then-slice exactly
// (no ranking-semantics change from bounding).

import { readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { openDatabase } from "../src/lib/db";
import {
  getDefaultPriority,
  getHighestForecast,
  getKnownExploited,
  getNewCritical,
  getRisingForecast,
} from "../src/lib/priority";
import {
  makeScaleDir,
  SCALE_STAMP as STAMP,
  seedScaleCorpus,
  sparsePublishedAt,
} from "./helpers/scale-corpus";

const tempDirs: string[] = [];

const PAGE_SOURCE = readFileSync(path.join(__dirname, "..", "app", "priority", "page.tsx"), "utf8");
const PAGE_LIMIT = Number(/export const PRIORITY_PAGE_LIMIT = (\d+);/.exec(PAGE_SOURCE)?.[1]);

let sharedDir = "";

beforeAll(() => {
  sharedDir = makeScaleDir(tempDirs, "cve-priority-page-scale-");
  seedScaleCorpus(sharedDir, { publishedAtFor: sparsePublishedAt });
}, 60000);

afterAll(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

describe("priority page at production scale (display-limit regression)", () => {
  it("bounds every getter call in app/priority/page.tsx and loads one mode per request", () => {
    expect(Number.isSafeInteger(PAGE_LIMIT) && PAGE_LIMIT >= 1 && PAGE_LIMIT <= 1000).toBe(true);
    expect(PAGE_SOURCE).toMatch(/env\.PRIORITY_PAGE_LIMIT/);
    expect(PAGE_SOURCE).toMatch(/getKnownExploited\(\s*db\s*,/);
    expect(PAGE_SOURCE).not.toMatch(/getKnownExploited\(\s*db\s*\)/);
    expect(PAGE_SOURCE).toMatch(/getHighestForecast\(\s*db\s*,/);
    expect(PAGE_SOURCE).not.toMatch(/getHighestForecast\(\s*db\s*\)/);
    expect(PAGE_SOURCE).toMatch(/getNewCritical\(\s*db\s*,\s*nowIso\s*,/);
    expect(PAGE_SOURCE).not.toMatch(/getNewCritical\(\s*db\s*,\s*nowIso\s*\)/);
    expect(PAGE_SOURCE).toMatch(/getRisingForecast\(\s*db\s*,/);
    expect(PAGE_SOURCE).not.toMatch(/getRisingForecast\(\s*db\s*\)/);
    // getDefaultPriority is not called at all: its only page use was corpus
    // gap counts, which now come from indexed COUNT queries, and even its
    // bounded SQL (multi-join sort over the full corpus) cost ~2s per request.
    expect(PAGE_SOURCE).not.toMatch(/getDefaultPriority\(/);
    expect(PAGE_SOURCE).toMatch(/unfilteredCohortCoverage\(/);
    expect(PAGE_SOURCE).toMatch(
      /loadSnapshot\(\s*db\s*,\s*new Date\(\)\.toISOString\(\)\s*,\s*mode\s*,/,
    );
    expect(PAGE_SOURCE).toMatch(/showing top/i);
  });

  it("bounded page loads complete under 5s with every list capped at the limit", () => {
    const db = openDatabase({ dataDir: sharedDir });
    try {
      const started = performance.now();
      const known = getKnownExploited(db, PAGE_LIMIT);
      const highest = getHighestForecast(db, PAGE_LIMIT);
      const critical = getNewCritical(db, STAMP, PAGE_LIMIT);
      const rising = getRisingForecast(db, undefined, PAGE_LIMIT);
      const corpus = getDefaultPriority(db, PAGE_LIMIT);
      const elapsedMs = performance.now() - started;
      expect(known.length).toBeLessThanOrEqual(PAGE_LIMIT);
      expect(highest.length).toBeLessThanOrEqual(PAGE_LIMIT);
      expect(critical.length).toBeLessThanOrEqual(PAGE_LIMIT);
      expect(rising.length).toBeLessThanOrEqual(PAGE_LIMIT);
      expect(corpus.length).toBeLessThanOrEqual(PAGE_LIMIT);
      expect(highest.length).toBe(PAGE_LIMIT);
      expect(corpus.length).toBe(PAGE_LIMIT);
      expect(elapsedMs).toBeLessThan(5000);
    } finally {
      db.close();
    }
  });

  it("bounded calls equal full-order-then-slice for every list", () => {
    const db = openDatabase({ dataDir: sharedDir });
    try {
      const fullKnown = getKnownExploited(db);
      expect(getKnownExploited(db, PAGE_LIMIT).map((row) => row.id)).toEqual(
        fullKnown.slice(0, PAGE_LIMIT).map((row) => row.id),
      );
      const fullHighest = getHighestForecast(db);
      expect(fullHighest.length).toBeGreaterThan(PAGE_LIMIT);
      expect(getHighestForecast(db, PAGE_LIMIT).map((row) => row.id)).toEqual(
        fullHighest.slice(0, PAGE_LIMIT).map((row) => row.id),
      );
      const fullCritical = getNewCritical(db, STAMP);
      expect(getNewCritical(db, STAMP, PAGE_LIMIT).map((row) => row.id)).toEqual(
        fullCritical.slice(0, PAGE_LIMIT).map((row) => row.id),
      );
      const fullRising = getRisingForecast(db);
      expect(fullRising.length).toBeGreaterThan(0);
      const cappedRising = getRisingForecast(db, undefined, PAGE_LIMIT);
      expect(cappedRising.map((row) => row.item.id)).toEqual(
        fullRising.slice(0, PAGE_LIMIT).map((row) => row.item.id),
      );
      expect(cappedRising.map((row) => row.deltaPp)).toEqual(
        fullRising.slice(0, PAGE_LIMIT).map((row) => row.deltaPp),
      );
      const fullCorpus = getDefaultPriority(db);
      expect(fullCorpus.length).toBeGreaterThan(PAGE_LIMIT);
      expect(getDefaultPriority(db, PAGE_LIMIT).map((row) => row.id)).toEqual(
        fullCorpus.slice(0, PAGE_LIMIT).map((row) => row.id),
      );
    } finally {
      db.close();
    }
  }, 180000);
});
