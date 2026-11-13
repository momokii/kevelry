import { chunk, type CveDatabase } from "../../../../src/lib/db";

/** One dated EPSS observation for the per-record trend series. Values are
 * the stored decimal strings (exact, never floats); unknown dates have no
 * point at all, never a zero. */
export interface EpssHistoryPoint {
  scoreDate: string;
  epss: string;
  modelVersion: string;
}

/**
 * Maximum EPSS observations returned per record. Retention keeps exactly this
 * many days (see `src/lib/retention.ts`), so stored history and returned history
 * cannot drift apart. 45 days is six weeks of trend; the sparkline downsamples
 * and the rising view only needs `d` and `d-7`.
 */
export const EPSS_HISTORY_CAP = 45;

/** Latest model observation per score date, oldest first, capped at the most
 * recent `cap` points. One chunked query for all ids (500 per chunk, same
 * batching as loadFullRecords); ids without observations are simply absent
 * from the map, so callers render unknown as null. */
export function loadEpssHistory(
  db: CveDatabase,
  ids: readonly string[],
  cap: number = EPSS_HISTORY_CAP,
): Map<string, EpssHistoryPoint[]> {
  const out = new Map<string, EpssHistoryPoint[]>();
  const unique = [...new Set(ids)];
  if (unique.length === 0 || cap <= 0) return out;
  for (const group of chunk(unique, 500)) {
    const placeholders = group.map(() => "?").join(", ");
    const rows = db.handle
      .prepare(
        `SELECT cve_id, score_date, epss, model_version FROM epss_daily WHERE cve_id IN (${placeholders}) ORDER BY cve_id ASC, score_date ASC, model_version ASC`,
      )
      .all(...group) as Array<{
      cve_id: string;
      score_date: string;
      epss: string;
      model_version: string;
    }>;
    // Latest model wins per date (rows arrive model-ascending, so overwrite).
    const byId = new Map<string, Map<string, EpssHistoryPoint>>();
    for (const row of rows) {
      let series = byId.get(row.cve_id);
      if (series === undefined) {
        series = new Map<string, EpssHistoryPoint>();
        byId.set(row.cve_id, series);
      }
      series.set(row.score_date, {
        scoreDate: row.score_date,
        epss: row.epss,
        modelVersion: row.model_version,
      });
    }
    for (const [cveId, series] of byId) {
      const points = [...series.values()].slice(-cap);
      if (points.length > 0) out.set(cveId, points);
    }
  }
  return out;
}
