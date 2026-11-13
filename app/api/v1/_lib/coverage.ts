import { getAggregates } from "../../../../src/lib/aggregates";
import type { CveDatabase } from "../../../../src/lib/db";
import { getAcceptedEpssDate } from "../../../../src/lib/priority";

export function countRows(db: CveDatabase, sql: string, params: unknown[] = []): number {
  const row = db.handle.prepare(sql).get(...params) as Record<string, unknown> | undefined;
  if (row === undefined) return 0;
  const value = Object.values(row)[0];
  return typeof value === "number" ? value : 0;
}

/**
 * Exact cohort coverage over the full unfiltered PUBLISHED corpus from cheap
 * indexed COUNT queries — no priority list is materialized. `unscored` counts
 * rows with no valid original CNA metric (the exact condition making
 * selectPrimaryCvss return null: origin, version preference set, and a plain
 * decimal base score in [0, 10]); `unknownEpss` counts rows with no accepted
 * EPSS observation. Matches coverageFor(loadItems(...)) on the same corpus
 * for clean stored values, at a fraction of the cost on 395k rows.
 */
export function unfilteredCohortCoverage(
  db: CveDatabase,
  returned: number,
): {
  eligibleCohort: number;
  returned: number;
  unscored: number;
  unknownEpss: number;
  unknownDate: number;
} {
  // One pass over the PUBLISHED corpus: the three bucket counts ride along
  // as correlated EXISTS probes instead of three separate full scans (~1s
  // instead of ~1.9s warm on 395k rows). Values match the three-query form
  // exactly; the CVSS validity predicate mirrors selectPrimaryCvss.
  const epssDate = getAcceptedEpssDate(db);
  const cached = epssDate === null ? null : getAggregates(db);
  if (cached !== null && cached.epssScoreDate === epssDate) {
    return {
      eligibleCohort: cached.publishedTotal,
      returned,
      unscored: cached.totals.unscored,
      unknownEpss: cached.totals.unknownEpss,
      unknownDate: cached.totals.unknownDate,
    };
  }
  const row =
    epssDate === null
      ? (db.handle
          .prepare(
            "SELECT COUNT(*) AS n, " +
              "SUM(CASE WHEN date_published IS NULL THEN 1 ELSE 0 END) AS u, " +
              "SUM(CASE WHEN NOT EXISTS " +
              "(SELECT 1 FROM cvss_metrics m WHERE m.cve_id = r.cve_id AND m.origin = 'CNA' " +
              "AND m.version IN ('4.0', '3.1', '3.0', '2.0') " +
              "AND m.base_score GLOB '[0-9]*' AND m.base_score NOT GLOB '*[^0-9.]*' " +
              "AND m.base_score NOT GLOB '*.*.*' AND m.base_score NOT GLOB '*.' " +
              "AND LENGTH(m.base_score) <= 64 AND CAST(m.base_score AS REAL) >= 0 AND CAST(m.base_score AS REAL) <= 10) " +
              "THEN 1 ELSE 0 END) AS s " +
              "FROM cve_records r WHERE state = ?",
          )
          .get("PUBLISHED") as { n: number; u: number; s: number })
      : (db.handle
          .prepare(
            "SELECT COUNT(*) AS n, " +
              "SUM(CASE WHEN date_published IS NULL THEN 1 ELSE 0 END) AS u, " +
              "SUM(CASE WHEN NOT EXISTS " +
              "(SELECT 1 FROM epss_daily e WHERE e.cve_id = r.cve_id AND e.score_date = ?) " +
              "THEN 1 ELSE 0 END) AS e, " +
              "SUM(CASE WHEN NOT EXISTS " +
              "(SELECT 1 FROM cvss_metrics m WHERE m.cve_id = r.cve_id AND m.origin = 'CNA' " +
              "AND m.version IN ('4.0', '3.1', '3.0', '2.0') " +
              "AND m.base_score GLOB '[0-9]*' AND m.base_score NOT GLOB '*[^0-9.]*' " +
              "AND m.base_score NOT GLOB '*.*.*' AND m.base_score NOT GLOB '*.' " +
              "AND LENGTH(m.base_score) <= 64 AND CAST(m.base_score AS REAL) >= 0 AND CAST(m.base_score AS REAL) <= 10) " +
              "THEN 1 ELSE 0 END) AS s " +
              "FROM cve_records r WHERE state = ?",
          )
          .get(epssDate, "PUBLISHED") as { n: number; u: number; e: number; s: number });
  const eligibleCohort = row.n ?? 0;
  return {
    eligibleCohort,
    returned,
    unscored: row.s ?? 0,
    unknownEpss: epssDate === null ? eligibleCohort : ((row as { e?: number }).e ?? 0),
    unknownDate: row.u ?? 0,
  };
}
