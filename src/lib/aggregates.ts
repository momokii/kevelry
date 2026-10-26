// Precomputed aggregate read-model for the hot paths (plan task 43).
//
// The overview page, /api/v1/overview, /api/v1/status and /api/v1/health
// used to recompute GROUP BY / COUNT(*) / full-corpus sorts per request
// (4-5s on a 395k-row volume). This module computes those numbers once per
// import cycle into `aggregate_cache` (migration 002) with bounded GROUP BY
// queries — result sets are per-day (~10k rows max), per-month, per-band, or
// single scalars — never the full corpus in JS memory.
//
// Readers use getAggregates() (one point lookup) and fall back to live
// queries when the cache is absent, so an empty cache is never an outage.
// refreshAggregates() is idempotent: recompute + INSERT OR REPLACE.

import type { CveDatabase } from "./db";
import { getHighestForecast, getRisingForecast } from "./priority";

export const AGGREGATE_KEY = "aggregates:v1";
export const AGGREGATE_VERSION = 3;

/** Bounded prefix stored per ranked list: exact full-order-then-slice head. */
export const TOP_LIST_LIMIT = 100;

/** Valid stored CNA metric predicate, mirroring selectPrimaryCvss. */
const VALID_CNA_SCORE_SQL = [
  "m.origin = 'CNA'",
  "m.version IN ('4.0', '3.1', '3.0', '2.0')",
  "m.base_score GLOB '[0-9]*'",
  "m.base_score NOT GLOB '*[^0-9.]*'",
  "m.base_score NOT GLOB '*.*.*'",
  "m.base_score NOT GLOB '*.'",
  "LENGTH(m.base_score) <= 64",
  "CAST(m.base_score AS REAL) >= 0",
  "CAST(m.base_score AS REAL) <= 10",
].join(" AND ");

const VALID_EPSS_SQL = [
  "c.epss GLOB '[0-9]*'",
  "c.epss NOT GLOB '*[^0-9.]*'",
  "c.epss NOT GLOB '*.*.*'",
  "c.epss NOT GLOB '*.'",
  "LENGTH(c.epss) <= 64",
  "CAST(c.epss AS REAL) >= 0",
  "CAST(c.epss AS REAL) <= 1",
].join(" AND ");

export interface CorpusTotals {
  published: number;
  kev: number;
  epssScored: number;
  epssRows: number;
  unscored: number;
  unknownEpss: number;
  unknownDate: number;
  tombstones: number;
  unmatchedKev: number;
  unmatchedEpss: number;
}

export const EPSS_LOG_BUCKET_COUNT = 9;

export interface SeverityEpssCell {
  band: string;
  bin: number;
  count: number;
  kev: number;
}

export interface AggregateSnapshot {
  version: number;
  computedAt: string;
  sourceRevision: string | null;
  epssScoreDate: string | null;
  /** Full day -> count map (bounded ~10k entries); months derived by prefix. */
  dayCounts: Record<string, number>;
  unknownDateCount: number;
  publishedTotal: number;
  tombstones: number;
  severityBands: Record<string, number>;
  epssHistogram: number[];
  epssLogHistogram: number[];
  severityEpssMatrix: SeverityEpssCell[];
  kevByMonth: Array<{ month: string; count: number }>;
  totals: CorpusTotals;
  /**
   * Exact heads of the two slowest ranked lists, computed at refresh with the
   * same bounded getters the pages use (full-order-then-slice prefix, so the
   * cached head equals a live head while the cache is fresh). The overview
   * page hydrates display rows for these ids instead of re-sorting 395k rows
   * per render; live fallback when the cache is absent.
   */
  topHighest: string[];
  topRising: Array<{ id: string; deltaPp: string }>;
}

export interface AggregateMeta {
  computedAt: string;
  sourceRevision: string | null;
  epssScoreDate: string | null;
}

function ensureCacheTable(db: CveDatabase): void {
  db.handle
    .prepare(
      "CREATE TABLE IF NOT EXISTS aggregate_cache (" +
        "key TEXT PRIMARY KEY, value_json TEXT NOT NULL, computed_at TEXT NOT NULL, " +
        "source_revision TEXT NULL, epss_score_date TEXT NULL) STRICT",
    )
    .run();
}

function singleScalar(db: CveDatabase, sql: string, params: unknown[] = []): number {
  const row = db.handle.prepare(sql).get(...params) as Record<string, unknown> | undefined;
  if (row === undefined) return 0;
  const value = Object.values(row)[0];
  return typeof value === "number" ? value : 0;
}

function singleText(db: CveDatabase, sql: string, params: unknown[] = []): string | null {
  const row = db.handle.prepare(sql).get(...params) as Record<string, unknown> | undefined;
  if (row === undefined) return null;
  const value = Object.values(row)[0];
  return typeof value === "string" ? value : null;
}

function acceptedEpssDate(db: CveDatabase): string | null {
  return singleText(db, "SELECT MAX(score_date) AS d FROM epss_daily");
}

/**
 * SQL mirror of selectPrimaryCvss for band counting. The JS policy picks the
 * preferred version (4.0 > 3.1 > 3.0 > 2.0) then the max base within it;
 * vector/sourceOrder tie-breaks cannot change the band (same version + same
 * max score), so per-version MAX scores grouped in SQL band identically.
 * Proven equal by tests/perf-aggregates.test.ts on a 50k fixture.
 */
export function severityBandsSql(db: CveDatabase): Record<string, number> {
  const rows = db.handle
    .prepare(
      "SELECT " +
        "CASE " +
        "WHEN best.score IS NULL THEN 'unknown' " +
        "WHEN best.version = '2.0' THEN 'legacy' " +
        "WHEN best.score = 0 THEN 'none' " +
        "WHEN best.score <= 3.9 THEN 'low' " +
        "WHEN best.score <= 6.9 THEN 'medium' " +
        "WHEN best.score <= 8.9 THEN 'high' " +
        "ELSE 'critical' END AS band, COUNT(*) AS n " +
        "FROM cve_records r LEFT JOIN (" +
        "SELECT cve_id, " +
        "CASE WHEN MAX(s40) IS NOT NULL THEN '4.0' " +
        "WHEN MAX(s31) IS NOT NULL THEN '3.1' " +
        "WHEN MAX(s30) IS NOT NULL THEN '3.0' " +
        "WHEN MAX(s20) IS NOT NULL THEN '2.0' ELSE NULL END AS version, " +
        "COALESCE(MAX(s40), MAX(s31), MAX(s30), MAX(s20)) AS score " +
        "FROM (SELECT cve_id, " +
        "CASE WHEN version = '4.0' THEN CAST(base_score AS REAL) ELSE NULL END AS s40, " +
        "CASE WHEN version = '3.1' THEN CAST(base_score AS REAL) ELSE NULL END AS s31, " +
        "CASE WHEN version = '3.0' THEN CAST(base_score AS REAL) ELSE NULL END AS s30, " +
        "CASE WHEN version = '2.0' THEN CAST(base_score AS REAL) ELSE NULL END AS s20 " +
        `FROM cvss_metrics m WHERE ${VALID_CNA_SCORE_SQL}) GROUP BY cve_id` +
        ") best ON best.cve_id = r.cve_id " +
        "WHERE r.state = 'PUBLISHED' GROUP BY band",
    )
    .all() as Array<{ band: string; n: number }>;
  const out: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    none: 0,
    legacy: 0,
    unknown: 0,
  };
  for (const row of rows) {
    if (row.band in out) out[row.band] = row.n;
  }
  return out;
}

function epssHistogramSql(db: CveDatabase, scoreDate: string | null): number[] {
  const buckets = new Array<number>(10).fill(0);
  if (scoreDate === null) return buckets;
  const rows = db.handle
    .prepare(
      "SELECT CASE WHEN CAST(c.epss AS REAL) >= 1 THEN 9 " +
        "ELSE CAST(CAST(c.epss AS REAL) * 10 AS INTEGER) END AS b, COUNT(*) AS n " +
        "FROM (SELECT cve_id, MAX(model_version) AS m FROM epss_daily WHERE score_date = ? GROUP BY cve_id) cm " +
        "JOIN epss_daily c ON c.cve_id = cm.cve_id AND c.score_date = ? AND c.model_version = cm.m " +
        `WHERE ${VALID_EPSS_SQL} GROUP BY b`,
    )
    .all(scoreDate, scoreDate) as Array<{ b: number; n: number }>;
  for (const row of rows) {
    if (Number.isInteger(row.b) && row.b >= 0 && row.b < 10) buckets[row.b] = row.n;
  }
  return buckets;
}

function epssLogBin(column: string): string {
  return (
    `CASE WHEN ${column} < 0.001 THEN 0 ` +
    `WHEN ${column} < 0.005 THEN 1 ` +
    `WHEN ${column} < 0.01 THEN 2 ` +
    `WHEN ${column} < 0.02 THEN 3 ` +
    `WHEN ${column} < 0.05 THEN 4 ` +
    `WHEN ${column} < 0.1 THEN 5 ` +
    `WHEN ${column} < 0.2 THEN 6 ` +
    `WHEN ${column} < 0.5 THEN 7 ELSE 8 END`
  );
}

export function severityEpssMatrixSql(
  db: CveDatabase,
  scoreDate: string | null,
): { cells: SeverityEpssCell[]; histogram: number[] } {
  if (scoreDate === null) {
    return { cells: [], histogram: new Array<number>(EPSS_LOG_BUCKET_COUNT).fill(0) };
  }
  const rows = db.handle
    .prepare(
      "WITH best AS (" +
        "SELECT cve_id, " +
        "CASE WHEN MAX(s40) IS NOT NULL THEN '4.0' " +
        "WHEN MAX(s31) IS NOT NULL THEN '3.1' " +
        "WHEN MAX(s30) IS NOT NULL THEN '3.0' " +
        "WHEN MAX(s20) IS NOT NULL THEN '2.0' ELSE NULL END AS version, " +
        "COALESCE(MAX(s40), MAX(s31), MAX(s30), MAX(s20)) AS score " +
        "FROM (SELECT cve_id, " +
        "CASE WHEN version = '4.0' THEN CAST(base_score AS REAL) ELSE NULL END AS s40, " +
        "CASE WHEN version = '3.1' THEN CAST(base_score AS REAL) ELSE NULL END AS s31, " +
        "CASE WHEN version = '3.0' THEN CAST(base_score AS REAL) ELSE NULL END AS s30, " +
        "CASE WHEN version = '2.0' THEN CAST(base_score AS REAL) ELSE NULL END AS s20 " +
        `FROM cvss_metrics m WHERE ${VALID_CNA_SCORE_SQL}) GROUP BY cve_id` +
        "), banded AS (" +
        "SELECT r.cve_id, CASE " +
        "WHEN b.score IS NULL THEN 'unknown' " +
        "WHEN b.version = '2.0' THEN 'legacy' " +
        "WHEN b.score = 0 THEN 'none' " +
        "WHEN b.score <= 3.9 THEN 'low' " +
        "WHEN b.score <= 6.9 THEN 'medium' " +
        "WHEN b.score <= 8.9 THEN 'high' ELSE 'critical' END AS band " +
        "FROM cve_records r LEFT JOIN best b ON b.cve_id = r.cve_id WHERE r.state = 'PUBLISHED'" +
        "), epss AS (" +
        "SELECT cm.cve_id, CAST(c.epss AS REAL) AS p FROM " +
        "(SELECT cve_id, MAX(model_version) AS m FROM epss_daily WHERE score_date = ? GROUP BY cve_id) cm " +
        "JOIN epss_daily c ON c.cve_id = cm.cve_id AND c.score_date = ? AND c.model_version = cm.m " +
        `WHERE ${VALID_EPSS_SQL}` +
        ") SELECT banded.band AS band, " +
        epssLogBin("epss.p") +
        " AS bin, COUNT(*) AS n, " +
        "SUM(CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END) AS kev " +
        "FROM banded JOIN epss ON epss.cve_id = banded.cve_id " +
        "LEFT JOIN kev_entries k ON k.cve_id = banded.cve_id " +
        "GROUP BY banded.band, bin",
    )
    .all(scoreDate, scoreDate) as Array<{ band: string; bin: number; n: number; kev: number }>;
  const cells: SeverityEpssCell[] = [];
  const histogram = new Array<number>(EPSS_LOG_BUCKET_COUNT).fill(0);
  for (const row of rows) {
    if (!Number.isInteger(row.bin) || row.bin < 0 || row.bin >= EPSS_LOG_BUCKET_COUNT) continue;
    cells.push({ band: row.band, bin: row.bin, count: row.n, kev: row.kev });
    histogram[row.bin] = (histogram[row.bin] ?? 0) + row.n;
  }
  return { cells, histogram };
}

function kevByMonthSql(db: CveDatabase, months = 12): Array<{ month: string; count: number }> {
  const rows = db.handle
    .prepare(
      "SELECT substr(date_added, 1, 7) AS month, COUNT(*) AS n FROM kev_entries " +
        "WHERE date_added GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]*' " +
        "GROUP BY month ORDER BY month DESC LIMIT ?",
    )
    .all(months) as Array<{ month: string; n: number }>;
  return rows
    .slice()
    .reverse()
    .map((row) => ({ month: row.month, count: row.n }));
}

function computeSnapshot(db: CveDatabase, nowIso: string): AggregateSnapshot {
  const scoreDate = acceptedEpssDate(db);
  const dayRows = db.handle
    .prepare(
      "SELECT substr(date_published, 1, 10) AS day, COUNT(*) AS n FROM cve_records " +
        "WHERE state = 'PUBLISHED' AND date_published IS NOT NULL GROUP BY day ORDER BY day ASC",
    )
    .all() as Array<{ day: string; n: number }>;
  const dayCounts: Record<string, number> = {};
  for (const row of dayRows) dayCounts[row.day] = row.n;
  const publishedTotal = singleScalar(
    db,
    "SELECT COUNT(*) AS n FROM cve_records WHERE state = 'PUBLISHED'",
  );
  const unknownDateCount = singleScalar(
    db,
    "SELECT COUNT(*) AS n FROM cve_records WHERE state = 'PUBLISHED' AND date_published IS NULL",
  );
  const tombstones = singleScalar(db, "SELECT COUNT(*) AS n FROM cve_tombstones");
  const kev = singleScalar(db, "SELECT COUNT(*) AS n FROM kev_entries");
  const epssRows = singleScalar(db, "SELECT COUNT(*) AS n FROM epss_daily");
  const epssScored =
    scoreDate === null
      ? 0
      : singleScalar(
          db,
          "SELECT COUNT(DISTINCT cve_id) AS n FROM epss_daily WHERE score_date = ?",
          [scoreDate],
        );
  const bands = severityBandsSql(db);
  const unscored = bands.unknown ?? 0;
  const unknownEpss =
    scoreDate === null ? publishedTotal : Math.max(0, publishedTotal - epssScored);
  const unmatchedKev = singleScalar(
    db,
    "SELECT COUNT(*) AS n FROM kev_entries k LEFT JOIN cve_records r " +
      "ON r.cve_id = k.cve_id AND r.state = 'PUBLISHED' WHERE r.cve_id IS NULL",
  );
  const unmatchedEpss =
    scoreDate === null
      ? 0
      : singleScalar(
          db,
          "SELECT COUNT(DISTINCT e.cve_id) AS n FROM epss_daily e LEFT JOIN cve_records r " +
            "ON r.cve_id = e.cve_id AND r.state = 'PUBLISHED' WHERE e.score_date = ? AND r.cve_id IS NULL",
          [scoreDate],
        );
  const sourceRevision = singleText(db, "SELECT MAX(source_revision) AS r FROM cve_records");
  const topHighest = getHighestForecast(db, TOP_LIST_LIMIT).map((item) => item.id);
  const topRising = getRisingForecast(db, undefined, TOP_LIST_LIMIT).map(({ item, deltaPp }) => ({
    id: item.id,
    deltaPp,
  }));
  const joint = severityEpssMatrixSql(db, scoreDate);
  return {
    version: AGGREGATE_VERSION,
    computedAt: nowIso,
    sourceRevision,
    epssScoreDate: scoreDate,
    dayCounts,
    unknownDateCount,
    publishedTotal,
    tombstones,
    severityBands: bands,
    epssHistogram: epssHistogramSql(db, scoreDate),
    epssLogHistogram: joint.histogram,
    severityEpssMatrix: joint.cells,
    kevByMonth: kevByMonthSql(db, 12),
    totals: {
      published: publishedTotal,
      kev,
      epssScored,
      epssRows,
      unscored,
      unknownEpss,
      unknownDate: unknownDateCount,
      tombstones,
      unmatchedKev,
      unmatchedEpss,
    },
    topHighest,
    topRising,
  };
}

/** Read the cached snapshot; null when absent or corrupt (callers fall back live). */
export function getAggregates(db: CveDatabase): AggregateSnapshot | null {
  try {
    ensureCacheTable(db);
  } catch {
    return null;
  }
  let row: { value_json: string } | undefined;
  try {
    row = db.handle
      .prepare("SELECT value_json FROM aggregate_cache WHERE key = ?")
      .get(AGGREGATE_KEY) as { value_json: string } | undefined;
  } catch {
    return null;
  }
  if (row === undefined) return null;
  try {
    const parsed = JSON.parse(row.value_json) as AggregateSnapshot;
    if (parsed === null || typeof parsed !== "object" || parsed.version !== AGGREGATE_VERSION) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

/** Revision seed for ETags; null when the cache is empty. */
export function getAggregateMeta(db: CveDatabase): AggregateMeta | null {
  try {
    ensureCacheTable(db);
    const row = db.handle
      .prepare(
        "SELECT computed_at, source_revision, epss_score_date FROM aggregate_cache WHERE key = ?",
      )
      .get(AGGREGATE_KEY) as
      | { computed_at: string; source_revision: string | null; epss_score_date: string | null }
      | undefined;
    if (row === undefined) return null;
    return {
      computedAt: row.computed_at,
      sourceRevision: row.source_revision,
      epssScoreDate: row.epss_score_date,
    };
  } catch {
    return null;
  }
}

/**
 * Recompute every aggregate in bounded GROUP BY passes and store one row.
 * Idempotent: recompute + INSERT OR REPLACE, safe to rerun after every cycle.
 */
export function refreshAggregates(db: CveDatabase, nowIso?: string): AggregateSnapshot {
  ensureCacheTable(db);
  const snapshot = computeSnapshot(db, nowIso ?? new Date().toISOString());
  const body = JSON.stringify(snapshot);
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT OR REPLACE INTO aggregate_cache (key, value_json, computed_at, source_revision, epss_score_date) " +
          "VALUES (?, ?, ?, ?, ?)",
      )
      .run(
        AGGREGATE_KEY,
        body,
        snapshot.computedAt,
        snapshot.sourceRevision,
        snapshot.epssScoreDate,
      );
  });
  return snapshot;
}

/** Derive month buckets from cached day counts (prefix sum, no rescan). */
export function monthCountsFromDays(dayCounts: Record<string, number>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [day, count] of Object.entries(dayCounts)) {
    const month = day.slice(0, 7);
    out[month] = (out[month] ?? 0) + count;
  }
  return out;
}
