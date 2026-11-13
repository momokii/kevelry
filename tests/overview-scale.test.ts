// Regression test (task 36): the overview page blocked the event loop on a
// ~395k-row corpus because toSummaryItems built one 395k-placeholder IN (...)
// query (SqliteError: too many SQL variables) plus a huge per-request
// allocation. Seeds a synthetic 50,000-row scored corpus in a temp DB (no
// network, invented CVE-2099 IDs) and proves: (a) the overview summary builds
// without a SqliteError, (b) readTitles stays chunked for multi-thousand id
// lists, (c) the summary build stays within a generous 5s ceiling, and
// (d) the limit param preserves exact ordering semantics.

import { rmSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import {
  getHighestForecast,
  getKnownExploited,
  getNewCritical,
  getRisingForecast,
} from "../src/lib/priority";
import {
  loadOverviewData,
  OVERVIEW_SUMMARY_LIMIT,
  readTitles,
} from "../src/components/overview/loadOverview";
import {
  cveIdAt,
  makeScaleDir,
  SCALE_DAY as DAY,
  SCALE_DAY_MINUS_7 as DAY_MINUS_7,
  SCALE_ROWS as ROWS,
  SCALE_STAMP as STAMP,
  seedScaleCorpus,
  sparsePublishedAt,
} from "./helpers/scale-corpus";

const tempDirs: string[] = [];

// This suite's corpus is the shared 50k scale corpus plus dirty-row fixtures
// the assertions below depend on: a KEV row with an unusable date (still
// counted, sorted last), two CVSS metrics that the primary-CNA policy must
// ignore, a superseded model version, and a malformed EPSS value.
function seedOverviewCorpus(dir: string): void {
  seedScaleCorpus(dir, {
    publishedAtFor: sparsePublishedAt,
    extra: ({ cvss, epss, kev }) => {
      kev.run(cveIdAt(11), "not-a-date", STAMP, STAMP);
      cvss.run(cveIdAt(150), "ADP", "3.1", "9.9", "CVSS:3.1/AV:N", 0);
      cvss.run(cveIdAt(151), "CNA", "2.0", "9.8", "AV:N", 0);
      for (let index = 2000; index < 2010; index += 1) {
        epss.run(cveIdAt(index), DAY_MINUS_7, "v1999.01.01", "0.90000", "0.80000");
      }
      epss.run(cveIdAt(3000), DAY, "v2099", "0.00001", "0.80000");
      epss.run(cveIdAt(3000), DAY_MINUS_7, "v2099", "0.00000", "0.80000");
      epss.run(cveIdAt(ROWS - 1), DAY, "v2099", "garbage", "0.80000");
    },
  });
}

let sharedDir = "";

beforeAll(() => {
  sharedDir = makeScaleDir(tempDirs, "cve-overview-scale-");
  seedOverviewCorpus(sharedDir);
}, 60000);

afterAll(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

describe("overview at production scale (task 36)", () => {
  it("builds the summary over 50k scored rows without SqliteError and under 5s", () => {
    const dir = sharedDir;
    const started = performance.now();
    const data = loadOverviewData(dir, STAMP);
    const elapsedMs = performance.now() - started;
    expect(data).not.toBeNull();
    expect(data?.publishedTotal).toBe(ROWS);
    for (const summary of data?.summaries ?? []) {
      expect(summary.items.length).toBeLessThanOrEqual(OVERVIEW_SUMMARY_LIMIT);
    }
    const highest = (data?.summaries ?? []).find((s) => s.key === "highest-forecast");
    expect(highest?.items.length).toBe(OVERVIEW_SUMMARY_LIMIT);
    expect(elapsedMs).toBeLessThan(5000);
  });

  it("readTitles stays chunked for a 5,000-id call", () => {
    const dir = sharedDir;
    const db: CveDatabase = openDatabase({ dataDir: dir });
    try {
      const ids = Array.from({ length: 5000 }, (_, index) => cveIdAt(index));
      ids.push("CVE-2099-99999");
      const titles = readTitles(db, ids);
      expect(titles.size).toBe(5001);
      expect(titles.get(cveIdAt(0))).toBe(`Title for ${cveIdAt(0)}`);
      expect(titles.get(cveIdAt(4999))).toBe(`Title for ${cveIdAt(4999)}`);
      expect(titles.get("CVE-2099-99999")).toBe("CVE-2099-99999");
    } finally {
      db.close();
    }
  });

  it("limit param matches slice-after-full-order exactly", () => {
    const dir = sharedDir;
    const db: CveDatabase = openDatabase({ dataDir: dir });
    try {
      const fullHighest = getHighestForecast(db);
      expect(fullHighest.length).toBeGreaterThan(ROWS - 10);
      expect(getHighestForecast(db, OVERVIEW_SUMMARY_LIMIT).map((row) => row.id)).toEqual(
        fullHighest.slice(0, OVERVIEW_SUMMARY_LIMIT).map((row) => row.id),
      );
      const fullKev = getKnownExploited(db);
      expect(fullKev.length).toBe(10);
      expect(fullKev[fullKev.length - 1]?.id).toBe(cveIdAt(11));
      expect(getKnownExploited(db, OVERVIEW_SUMMARY_LIMIT).map((row) => row.id)).toEqual(
        fullKev.slice(0, OVERVIEW_SUMMARY_LIMIT).map((row) => row.id),
      );
      const fullCritical = getNewCritical(db, STAMP);
      expect(fullCritical.length).toBeGreaterThan(0);
      expect(getNewCritical(db, STAMP, OVERVIEW_SUMMARY_LIMIT).map((row) => row.id)).toEqual(
        fullCritical.slice(0, OVERVIEW_SUMMARY_LIMIT).map((row) => row.id),
      );
      expect(fullCritical.map((row) => row.id)).not.toContain(cveIdAt(150));
      expect(fullCritical.map((row) => row.id)).not.toContain(cveIdAt(151));
      const fullRising = getRisingForecast(db);
      expect(fullRising.length).toBeGreaterThan(0);
      const cappedRising = getRisingForecast(db, undefined, OVERVIEW_SUMMARY_LIMIT);
      expect(cappedRising.map((row) => row.item.id)).toEqual(
        fullRising.slice(0, OVERVIEW_SUMMARY_LIMIT).map((row) => row.item.id),
      );
      expect(cappedRising.map((row) => row.deltaPp)).toEqual(
        fullRising.slice(0, OVERVIEW_SUMMARY_LIMIT).map((row) => row.deltaPp),
      );
    } finally {
      db.close();
    }
  }, 120000);
});
