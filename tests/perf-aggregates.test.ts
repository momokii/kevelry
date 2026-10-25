// Task 43 perf tests: aggregate cache correctness and HTTP caching.
//
// Proves against the real SQLite store (50k-row synthetic CVE corpus, no
// network) that refreshAggregates matches direct-SQL truth: day counts,
// month derivation, totals, the SQL severity-band mirror vs
// selectPrimaryCvss, the EPSS histogram, and KEV monthly counts. Proves the
// hot path avoids full scans (query-plan assertion on the cache point
// lookup), that overview/status/health serve identical shapes from cache vs
// live fallback, and that success GETs carry Cache-Control + strong ETag
// with 304 on If-None-Match while error responses stay uncacheable.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { GET as getHealth } from "../app/api/v1/health/route";
import { GET as getOverview } from "../app/api/v1/overview/route";
import { GET as getStatus } from "../app/api/v1/status/route";
import { resetDbOverride, setDbOverride } from "../app/api/v1/_lib/shared";
import {
  getAggregates,
  monthCountsFromDays,
  refreshAggregates,
  severityBandsSql,
  type AggregateSnapshot,
} from "../src/lib/aggregates";
import { openDatabase, openReadDatabase, resetReadDatabaseCache, type CveDatabase } from "../src/lib/db";
import { getHighestForecast, getRisingForecast } from "../src/lib/priority";
import { selectPrimaryCvss } from "../src/lib/ranking";
import { severityBandFor } from "../src/lib/search";
import { ensureAggregates } from "../src/worker";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

const STAMP = "2026-10-24T00:00:00.000Z";
const MODEL = "v2026.06.15";
const OLD_MODEL = "v2026.06.14";
const SCORE_DATE = "2026-10-23";
const PREV_DATE = "2026-10-16";
const ROWS = 50_000;

function makeDb(): { db: CveDatabase; dir: string } {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-perf-test-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openDbs.push(db);
  setDbOverride(db);
  return { db, dir };
}

afterEach(() => {
  resetDbOverride();
  resetReadDatabaseCache();
  while (openDbs.length > 0) {
    try {
      (openDbs.pop() as CveDatabase).close();
    } catch {
      // Best-effort close before directory removal.
    }
  }
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

function cveId(index: number): string {
  return `CVE-2099-${String(index + 1).padStart(6, "0")}`;
}

function dayFor(index: number): string {
  const base = Date.parse("2024-01-01T00:00:00.000Z");
  const day = new Date(base + (index % 1028) * 86_400_000).toISOString().slice(0, 10);
  return day;
}

/** Deterministic 50k corpus with every band, null dates, rejects, KEV, EPSS. */
function seedCorpus(db: CveDatabase): void {
  const ids: string[] = [];
  for (let index = 0; index < ROWS; index += 1) ids.push(cveId(index));
  db.executeBatched(
    ids,
    1000,
    (batch) => {
      const insert = db.handle.prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, title, description, description_lang, source_revision, created_at, updated_at) VALUES (?, '5.1', 'PUBLISHED', ?, ?, ?, ?, 'en', 'rev-test', ?, ?)",
      );
      for (const id of batch) {
        const index = Number(id.slice(-6)) - 1;
        const published = index % 500 === 0 ? null : `${dayFor(index)}T00:00:00.000Z`;
        insert.run(id, published, published, `Title ${id}`, `Description ${id}`, STAMP, STAMP);
      }
    },
  );
  db.executeBatched(ids, 1000, (batch) => {
    const insert = db.handle.prepare(
      "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, 'V', 0)",
    );
    for (const id of batch) {
      const index = Number(id.slice(-6)) - 1;
      const kind = index % 5;
      if (kind === 0) insert.run(id, "CNA", "3.1", "9.8");
      else if (kind === 1) {
        insert.run(id, "CNA", "4.0", "5.3");
        insert.run(id, "ADP", "3.1", "9.0");
      } else if (kind === 2) insert.run(id, "CNA", "2.0", "7.5");
      else if (kind === 3) insert.run(id, "ADP", "3.1", "8.1");
      if (index % 7 === 0) insert.run(id, "CNA", "3.1", index % 5 === 0 ? "9.8" : "4.2");
    }
  });
  db.executeBatched(ids, 1000, (batch) => {
    const insert = db.handle.prepare(
      "INSERT INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, '0.5')",
    );
    for (const id of batch) {
      const index = Number(id.slice(-6)) - 1;
      if (index % 2 === 0) {
        insert.run(id, SCORE_DATE, MODEL, `${(index % 10) / 10}`);
        if (index % 8 === 0) insert.run(id, SCORE_DATE, OLD_MODEL, "0.9");
      }
      if (index % 4 === 0) insert.run(id, PREV_DATE, MODEL, "0.1");
    }
  });
  const kevIds = ids.filter((_, index) => index % 97 === 0);
  db.executeBatched(kevIds, 500, (batch) => {
    const insert = db.handle.prepare(
      "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, '2026.10.23', ?)",
    );
    for (const id of batch) {
      const index = Number(id.slice(-6)) - 1;
      insert.run(id, `${dayFor(index * 3)}T00:00:00.000Z`, STAMP);
    }
  });
  db.runBoundedWrite(() => {
    const insert = db.handle.prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, description, created_at, updated_at) VALUES (?, '5.1', 'REJECTED', 'rejected', ?, ?)",
    );
    for (let index = 0; index < 200; index += 1) {
      insert.run(`CVE-2098-${String(index + 1).padStart(6, "0")}`, STAMP, STAMP);
    }
    const tomb = db.handle.prepare(
      "INSERT INTO cve_tombstones (cve_id, last_state, reason, recorded_at) VALUES (?, 'REJECTED', 'test', ?)",
    );
    for (let index = 0; index < 5; index += 1) {
      tomb.run(`CVE-2097-${String(index + 1).padStart(6, "0")}`, STAMP);
    }
    const sync = db.handle.prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) VALUES (?, ?, ?, 'succeeded', ?, 'h', NULL)",
    );
    sync.run("cve", STAMP, STAMP, "rev-test");
    sync.run("kev", STAMP, STAMP, "2026.10.23");
    sync.run("epss", STAMP, STAMP, `${SCORE_DATE}@${MODEL}`);
  });
}

function expectedBandsJs(db: CveDatabase): Record<string, number> {
  const out: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    none: 0,
    legacy: 0,
    unknown: 0,
  };
  const ids = db.handle
    .prepare("SELECT cve_id FROM cve_records WHERE state = 'PUBLISHED' ORDER BY cve_id ASC")
    .all() as Array<{ cve_id: string }>;
  const chunkSize = 1000;
  for (let index = 0; index < ids.length; index += chunkSize) {
    const group = ids.slice(index, index + chunkSize).map((row) => row.cve_id);
    const placeholders = group.map(() => "?").join(", ");
    const metrics = db.handle
      .prepare(
        `SELECT cve_id, origin, version, base_score, vector, source_order FROM cvss_metrics WHERE cve_id IN (${placeholders}) ORDER BY rowid`,
      )
      .all(...group) as Array<{
      cve_id: string;
      origin: string;
      version: string;
      base_score: string;
      vector: string;
      source_order: number;
    }>;
    const byId = new Map<string, Array<Record<string, unknown>>>();
    for (const metric of metrics) {
      const list = byId.get(metric.cve_id) ?? [];
      list.push({
        origin: metric.origin,
        version: metric.version,
        baseScore: metric.base_score,
        vector: metric.vector,
        sourceOrder: metric.source_order,
      });
      byId.set(metric.cve_id, list);
    }
    for (const row of group) {
      const primary = selectPrimaryCvss(byId.get(row) ?? []);
      out[severityBandFor(primary)] = (out[severityBandFor(primary)] ?? 0) + 1;
    }
  }
  return out;
}

describe("task 43 aggregate cache (50k fixture)", () => {
  it("applies migration 002 additively with all indexes and the cache table", () => {
    const { db } = makeDb();
    const applied = db.appliedVersions();
    expect(applied).toContain(2);
    const objects = db.handle
      .prepare("SELECT name FROM sqlite_master WHERE name IN ('aggregate_cache', 'idx_cve_records_state_published', 'idx_cve_records_published_date', 'idx_cve_records_source_revision', 'idx_cvss_metrics_cve_origin_version', 'idx_epss_daily_score_cve')")
      .all() as Array<{ name: string }>;
    expect(objects.map((row) => row.name).sort()).toEqual(
      [
        "aggregate_cache",
        "idx_cvss_metrics_cve_origin_version",
        "idx_cve_records_source_revision",
        "idx_cve_records_state_published",
        "idx_cve_records_published_date",
        "idx_epss_daily_score_cve",
      ].sort(),
    );
    const reverted = db.revertTo(1);
    expect(reverted).toEqual([2]);
    const after = db.handle
      .prepare("SELECT name FROM sqlite_master WHERE name = 'aggregate_cache'")
      .all();
    expect(after).toHaveLength(0);
    expect(db.migrate()).toEqual([2]);
  });

  it("refresh matches direct-SQL truth for every aggregate section", { timeout: 180_000 }, () => {
    const { db } = makeDb();
    seedCorpus(db);
    const snapshot = refreshAggregates(db);

    const published = (db.handle.prepare("SELECT COUNT(*) AS n FROM cve_records WHERE state = 'PUBLISHED'").get() as { n: number }).n;
    expect(snapshot.publishedTotal).toBe(published);
    expect(snapshot.totals.published).toBe(published);
    expect(snapshot.unknownDateCount).toBe(Math.floor(ROWS / 500));
    expect(snapshot.totals.unknownDate).toBe(Math.floor(ROWS / 500));
    expect(snapshot.totals.tombstones).toBe(5);
    expect(snapshot.tombstones).toBe(5);

    const daySum = Object.values(snapshot.dayCounts).reduce((a, b) => a + b, 0);
    expect(daySum + snapshot.unknownDateCount).toBe(published);
    const monthSum = Object.values(monthCountsFromDays(snapshot.dayCounts)).reduce((a, b) => a + b, 0);
    expect(monthSum).toBe(daySum);

    expect(snapshot.epssScoreDate).toBe(SCORE_DATE);
    const scored = (db.handle.prepare("SELECT COUNT(DISTINCT cve_id) AS n FROM epss_daily WHERE score_date = ?").get(SCORE_DATE) as { n: number }).n;
    expect(snapshot.totals.epssScored).toBe(scored);
    const histSum = snapshot.epssHistogram.reduce((a, b) => a + b, 0);
    expect(snapshot.epssHistogram).toHaveLength(10);
    expect(histSum).toBe(scored);

    const kevMonths = (db.handle.prepare("SELECT COUNT(DISTINCT substr(date_added, 1, 7)) AS n FROM kev_entries").get() as { n: number }).n;
    expect(snapshot.kevByMonth.length).toBeLessThanOrEqual(12);
    expect(snapshot.kevByMonth.length).toBe(Math.min(12, kevMonths));
    const kevSum = snapshot.kevByMonth.reduce((a, row) => a + row.count, 0);
    const kevTotal = (db.handle.prepare("SELECT COUNT(*) AS n FROM kev_entries").get() as { n: number }).n;
    expect(snapshot.totals.kev).toBe(kevTotal);
    if (snapshot.kevByMonth.length === kevMonths) expect(kevSum).toBe(kevTotal);

    expect(snapshot.severityBands).toEqual(expectedBandsJs(db));
    expect(severityBandsSql(db)).toEqual(expectedBandsJs(db));
    const bandSum = Object.values(snapshot.severityBands).reduce((a, b) => a + b, 0);
    expect(bandSum).toBe(published);

    // Cached top-N heads equal the live heads on a fresh refresh.
    expect(snapshot.topHighest.slice(0, 3)).toEqual(
      getHighestForecast(db, 3).map((item) => item.id),
    );
    expect(snapshot.topRising.slice(0, 3)).toEqual(
      getRisingForecast(db, undefined, 3).map(({ item, deltaPp }) => ({ id: item.id, deltaPp })),
    );

    // Idempotent: a second refresh rewrites the same values.
    const again = refreshAggregates(db);
    expect(again).toEqual({ ...snapshot, computedAt: again.computedAt });
    expect(getAggregates(db)).toEqual(again);
  });

  it("serves the cache from a primary-key point lookup (no full scan)", { timeout: 180_000 }, () => {
    const { db } = makeDb();
    seedCorpus(db);
    refreshAggregates(db);
    const planRows = db.handle
      .prepare("EXPLAIN QUERY PLAN SELECT value_json FROM aggregate_cache WHERE key = ?")
      .all("x") as Array<Record<string, unknown>>;
    const detail = JSON.stringify(planRows);
    expect(detail).toMatch(/SEARCH/i);
    expect(detail).not.toMatch(/SCAN/i);
    const started = Date.now();
    const snapshot = getAggregates(db) as AggregateSnapshot;
    expect(Date.now() - started).toBeLessThan(2000);
    expect(snapshot.publishedTotal).toBe(ROWS);
  });

  it("overview/status/health keep identical shapes from cache vs live fallback", { timeout: 180_000 }, async () => {
    const { db } = makeDb();
    seedCorpus(db);
    refreshAggregates(db);
    const fromCache = (await (await getOverview(new Request("http://x/api/v1/overview?bucket=month&months=24"))).json()) as Record<string, unknown>;
    const statusCache = (await (await getStatus(new Request("http://x/api/v1/status"))).json()) as Record<string, unknown>;
    const healthCache = (await (await getHealth(new Request("http://x/api/v1/health"))).json()) as Record<string, unknown>;
    db.handle.prepare("DELETE FROM aggregate_cache").run();
    expect(getAggregates(db)).toBeNull();
    const fromLive = (await (await getOverview(new Request("http://x/api/v1/overview?bucket=month&months=24"))).json()) as Record<string, unknown>;
    const statusLive = (await (await getStatus(new Request("http://x/api/v1/status"))).json()) as Record<string, unknown>;
    const healthLive = (await (await getHealth(new Request("http://x/api/v1/health"))).json()) as Record<string, unknown>;
    const normalize = (value: unknown): unknown =>
      JSON.parse(
        JSON.stringify(value, (key, entry) =>
          key === "generatedAt" || key === "lastCheckedAt" || key === "lastAcceptedAt" ? "TS" : (entry as unknown),
        ),
      );
    expect(Object.keys(fromCache).sort()).toEqual(Object.keys(fromLive).sort());
    expect(normalize(fromCache)).toEqual(normalize(fromLive));
    expect(normalize(statusCache)).toEqual(normalize(statusLive));
    expect(normalize(healthCache)).toEqual(normalize(healthLive));
  });

  it("sets Cache-Control + ETag on success and returns 304 on repeat; errors stay uncacheable", { timeout: 180_000 }, async () => {
    const { db } = makeDb();
    seedCorpus(db);
    refreshAggregates(db);
    const first = await getOverview(new Request("http://x/api/v1/overview?bucket=day&months=3"));
    expect(first.status).toBe(200);
    const etag = first.headers.get("ETag");
    expect(etag).toMatch(/^"[0-9a-f]{64}"$/);
    expect(first.headers.get("Cache-Control")).toBe(
      "public, max-age=30, s-maxage=60, stale-while-revalidate=300",
    );
    const repeat = await getOverview(
      new Request("http://x/api/v1/overview?bucket=day&months=3", {
        headers: { "If-None-Match": etag as string },
      }),
    );
    expect(repeat.status).toBe(304);
    expect(repeat.headers.get("ETag")).toBe(etag);
    const statusRes = await getStatus(new Request("http://x/api/v1/status"));
    expect(statusRes.headers.get("ETag")).toMatch(/^"[0-9a-f]{64}"$/);
    const statusRepeat = await getStatus(
      new Request("http://x/api/v1/status", {
        headers: { "If-None-Match": statusRes.headers.get("ETag") as string },
      }),
    );
    expect(statusRepeat.status).toBe(304);
    const bad = await getOverview(new Request("http://x/api/v1/overview?bucket=fortnight"));
    expect(bad.status).toBe(400);
    expect(bad.headers.get("ETag")).toBeNull();
    expect(bad.headers.get("Cache-Control")).toBeNull();
  });

  it("reuses one read-only handle per process and isolates tests", () => {
    const { dir } = makeDb();
    const first = openReadDatabase(dir);
    const second = openReadDatabase(dir);
    expect(second).toBe(first);
    resetReadDatabaseCache();
    const third = openReadDatabase(dir);
    expect(third).not.toBe(first);
  });

  it("worker ensureAggregates fills an empty cache and skips a filled one", { timeout: 180_000 }, () => {
    const { db } = makeDb();
    seedCorpus(db);
    expect(getAggregates(db)).toBeNull();
    const logs: Array<Record<string, unknown>> = [];
    expect(ensureAggregates(db, (entry) => logs.push(entry as Record<string, unknown>))).toBe(true);
    expect(getAggregates(db)).not.toBeNull();
    expect(logs.some((entry) => entry.event === "aggregate-refresh")).toBe(true);
    expect(ensureAggregates(db, (entry) => logs.push(entry as Record<string, unknown>))).toBe(false);
  });
});
