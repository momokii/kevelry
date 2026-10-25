// Deterministic priority services on the real SQLite layer (plan todo 11).
//
// Reads the accepted local snapshots (PUBLISHED CVE records, KEV membership,
// dated EPSS observations, preserved CVSS metrics) and orders the five named
// views with the pure contract functions from `./ranking`. No composite
// score is produced, no CVSSxEPSS multiplication happens, and no popularity
// label exists anywhere here. Missing values stay unknown (never zero); an
// empty corpus yields empty lists, never errors. Every value-bearing
// statement is parameterized with `?` placeholders.

import type { CveDatabase } from "./db";
import {
  orderDefaultPriority,
  orderHighestForecast,
  orderKnownExploited,
  selectNewCritical,
  selectPrimaryCvss,
  selectRisingForecast,
  type CvssMetricInput,
  type PrimaryCvss,
  type RisingResult,
} from "./ranking";

export type { PrimaryCvss, RisingResult };

export interface PriorityItem {
  id: string;
  kevMember: boolean;
  epss: string | null;
  publishedAt: string | null;
  dateAdded: string | null;
  primary: PrimaryCvss | null;
}

interface RisingCandidate extends PriorityItem {
  currentEpss: string | null;
  currentDate: string | null;
  currentModel: string | null;
  previousEpss: string | null;
  previousDate: string | null;
  previousModel: string | null;
}

/**
 * Optional display cap for the ranked getters below. Ordering runs first over
 * the full eligible set with the documented keys, then the first N rows are
 * returned, so `getHighestForecast(db, 3)` is exactly
 * `getHighestForecast(db).slice(0, 3)`. The overview passes its small display
 * limit here so callers that only render the top rows never hold the full
 * sorted array longer than needed. Ranking semantics are unchanged.
 */
function take<T>(rows: T[], limit?: number): T[] {
  if (limit === undefined) return rows;
  if (!Number.isInteger(limit) || limit < 0) return rows;
  return rows.slice(0, limit);
}

function hasLimit(limit?: number): limit is number {
  return limit !== undefined && Number.isInteger(limit) && limit >= 0;
}

const OVERVIEW_LOOKUP_CHUNK = 500;

function chunkIds(ids: readonly string[]): string[][] {
  const out: string[][] = [];
  for (let index = 0; index < ids.length; index += OVERVIEW_LOOKUP_CHUNK) {
    out.push(ids.slice(index, index + OVERVIEW_LOOKUP_CHUNK));
  }
  return out;
}

/**
 * SQL predicate matching isValidEpss in ./ranking (plain decimal literal,
 * at most 64 chars, within [0, 1]). Import validation only ever stores such
 * values; the guard keeps malformed rows out of the SQL-ordered fast paths
 * exactly as the JS filters do. Ordering by CAST(x AS REAL) then agrees with
 * the exact decimal-string comparison for stored values: distinct short
 * decimals in [0, 1] never collide as doubles.
 */
function epssValidSql(column: string): string {
  return (
    `${column} GLOB '[0-9]*' AND ${column} NOT GLOB '*[^0-9.]*' AND ` +
    `${column} NOT GLOB '*.*.*' AND ${column} NOT GLOB '*.' AND ` +
    `LENGTH(${column}) <= 64 AND CAST(${column} AS REAL) >= 0 AND CAST(${column} AS REAL) <= 1`
  );
}

interface OverviewBase {
  id: string;
  publishedAt: string | null;
  epss: string | null;
}

/**
 * Hydrate display items for a small pre-selected id set (a top-N page or a
 * bounded candidate cohort). KEV membership, greatest-model EPSS text, and
 * per-id CVSS metrics come from chunked IN queries so the variable cap is
 * never hit; per-id metric lists keep rowid order, matching primaryMap, so
 * selectPrimaryCvss resolves identically to the full-corpus path.
 */
function hydrateOverviewItems(
  db: CveDatabase,
  epssDate: string | null,
  bases: readonly OverviewBase[],
): PriorityItem[] {
  if (bases.length === 0) return [];
  const ids = bases.map((base) => base.id);
  const kevDates = new Map<string, string>();
  const epssById = new Map<string, string>();
  const metricsById = new Map<string, CvssMetricInput[]>();
  for (const group of chunkIds(ids)) {
    const placeholders = group.map(() => "?").join(", ");
    const kevRows = db.handle
      .prepare(`SELECT cve_id, date_added FROM kev_entries WHERE cve_id IN (${placeholders})`)
      .all(...group) as Array<{ cve_id: string; date_added: string }>;
    for (const row of kevRows) kevDates.set(row.cve_id, row.date_added);
    if (epssDate !== null) {
      const epssRows = db.handle
        .prepare(
          `SELECT cve_id, epss, model_version FROM epss_daily WHERE score_date = ? AND cve_id IN (${placeholders})`,
        )
        .all(epssDate, ...group) as Array<{ cve_id: string; epss: string; model_version: string }>;
      const best = new Map<string, { epss: string; model: string }>();
      for (const row of epssRows) {
        const prior = best.get(row.cve_id);
        if (prior === undefined || row.model_version > prior.model) {
          best.set(row.cve_id, { epss: row.epss, model: row.model_version });
        }
      }
      for (const [cveId, entry] of best) epssById.set(cveId, entry.epss);
    }
    const metricRows = db.handle
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
    for (const row of metricRows) {
      const list = metricsById.get(row.cve_id) ?? [];
      list.push({
        origin: row.origin,
        version: row.version,
        baseScore: row.base_score,
        vector: row.vector,
        sourceOrder: row.source_order,
      });
      metricsById.set(row.cve_id, list);
    }
  }
  return bases.map((base) => ({
    id: base.id,
    kevMember: kevDates.has(base.id),
    epss: base.epss ?? epssById.get(base.id) ?? null,
    publishedAt: base.publishedAt,
    dateAdded: kevDates.get(base.id) ?? null,
    primary: selectPrimaryCvss(metricsById.get(base.id) ?? []) ?? null,
  }));
}

/** Accepted current EPSS score date: MAX(score_date), or null when empty. */
export function getAcceptedEpssDate(db: CveDatabase): string | null {
  const row = db.handle.prepare("SELECT MAX(score_date) AS score_date FROM epss_daily").get() as {
    score_date: string | null;
  };
  return row.score_date;
}

function publishedRecords(db: CveDatabase): Array<{ cveId: string; publishedAt: string | null }> {
  const rows = db.handle
    .prepare("SELECT cve_id, date_published FROM cve_records WHERE state = ? ORDER BY cve_id ASC")
    .all("PUBLISHED") as Array<{ cve_id: string; date_published: string | null }>;
  return rows.map((row) => ({ cveId: row.cve_id, publishedAt: row.date_published }));
}

function kevDateMap(db: CveDatabase): Map<string, string> {
  const rows = db.handle.prepare("SELECT cve_id, date_added FROM kev_entries").all() as Array<{
    cve_id: string;
    date_added: string;
  }>;
  return new Map(rows.map((row) => [row.cve_id, row.date_added]));
}

/**
 * Current EPSS text per CVE for one score date, keyed by CVE ID. When several
 * model versions share a date, the lexicographically greatest model wins,
 * matching the single-row lookup convention in `./epss-import`.
 */
function epssTextMap(db: CveDatabase, scoreDate: string): Map<string, string> {
  const rows = db.handle
    .prepare("SELECT cve_id, epss, model_version FROM epss_daily WHERE score_date = ?")
    .all(scoreDate) as Array<{ cve_id: string; epss: string; model_version: string }>;
  const best = new Map<string, { epss: string; model: string }>();
  for (const row of rows) {
    const prior = best.get(row.cve_id);
    if (prior === undefined || row.model_version > prior.model) {
      best.set(row.cve_id, { epss: row.epss, model: row.model_version });
    }
  }
  const out = new Map<string, string>();
  for (const [cveId, entry] of best) {
    out.set(cveId, entry.epss);
  }
  return out;
}

function modelTextMap(db: CveDatabase, scoreDate: string): Map<string, string> {
  const rows = db.handle
    .prepare("SELECT cve_id, model_version FROM epss_daily WHERE score_date = ?")
    .all(scoreDate) as Array<{ cve_id: string; model_version: string }>;
  const best = new Map<string, string>();
  for (const row of rows) {
    const prior = best.get(row.cve_id);
    if (prior === undefined || row.model_version > prior) {
      best.set(row.cve_id, row.model_version);
    }
  }
  return best;
}

function primaryMap(db: CveDatabase): Map<string, PrimaryCvss> {
  const rows = db.handle
    .prepare("SELECT cve_id, origin, version, base_score, vector, source_order FROM cvss_metrics")
    .all() as Array<{
    cve_id: string;
    origin: string;
    version: string;
    base_score: string;
    vector: string;
    source_order: number;
  }>;
  const grouped = new Map<string, CvssMetricInput[]>();
  for (const row of rows) {
    const list = grouped.get(row.cve_id) ?? [];
    list.push({
      origin: row.origin,
      version: row.version,
      baseScore: row.base_score,
      vector: row.vector,
      sourceOrder: row.source_order,
    });
    grouped.set(row.cve_id, list);
  }
  const out = new Map<string, PrimaryCvss>();
  for (const [cveId, metrics] of grouped) {
    const primary = selectPrimaryCvss(metrics);
    if (primary !== null) {
      out.set(cveId, primary);
    }
  }
  return out;
}

function minus7Days(day: string): string | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return null;
  const ms = Date.parse(`${day}T00:00:00.000Z`);
  if (!Number.isFinite(ms)) return null;
  if (new Date(ms).toISOString().slice(0, 10) !== day) return null;
  return new Date(ms - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

function getRisingForecastTop(
  db: CveDatabase,
  current: string,
  previous: string,
  limit: number,
): RisingResult<PriorityItem>[] {
  if (limit === 0) return [];
  const rows = db.handle
    .prepare(
      "SELECT c.cve_id AS id, c.epss AS cur, c.model_version AS curModel, p.epss AS prev, " +
        "r.date_published AS publishedAt " +
        "FROM (SELECT cve_id, MAX(model_version) AS m FROM epss_daily WHERE score_date = ? GROUP BY cve_id) cm " +
        "JOIN epss_daily c ON c.cve_id = cm.cve_id AND c.score_date = ? AND c.model_version = cm.m " +
        "JOIN (SELECT cve_id, MAX(model_version) AS m FROM epss_daily WHERE score_date = ? GROUP BY cve_id) pm " +
        "ON pm.cve_id = cm.cve_id AND pm.m = cm.m " +
        "JOIN epss_daily p ON p.cve_id = pm.cve_id AND p.score_date = ? AND p.model_version = pm.m " +
        "JOIN cve_records r ON r.cve_id = c.cve_id AND r.state = 'PUBLISHED' " +
        `WHERE ${epssValidSql("c.epss")} AND ${epssValidSql("p.epss")} AND CAST(c.epss AS REAL) > CAST(p.epss AS REAL)`,
    )
    .all(current, current, previous, previous) as Array<{
    id: string;
    cur: string;
    curModel: string;
    prev: string;
    publishedAt: string | null;
  }>;
  const items = hydrateOverviewItems(
    db,
    null,
    rows.map((row) => ({ id: row.id, publishedAt: row.publishedAt, epss: row.cur })),
  );
  const byId = new Map(items.map((item) => [item.id, item]));
  const candidates: RisingCandidate[] = [];
  for (const row of rows) {
    const item = byId.get(row.id);
    if (item === undefined) continue;
    candidates.push({
      ...item,
      currentEpss: row.cur,
      currentDate: current,
      currentModel: row.curModel,
      previousEpss: row.prev,
      previousDate: previous,
      previousModel: row.curModel,
    });
  }
  return selectRisingForecast(candidates, current).map(({ item, deltaPp }) => ({
    item: {
      id: item.id,
      kevMember: item.kevMember,
      epss: item.epss,
      publishedAt: item.publishedAt,
      dateAdded: item.dateAdded,
      primary: item.primary,
    },
    deltaPp,
  }));
}

function loadItems(db: CveDatabase, epssDate: string | null): PriorityItem[] {
  const records = publishedRecords(db);
  if (records.length === 0) return [];
  const kevDates = kevDateMap(db);
  const epssTexts = epssDate === null ? new Map<string, string>() : epssTextMap(db, epssDate);
  const primaries = primaryMap(db);
  return records.map((record) => ({
    id: record.cveId,
    kevMember: kevDates.has(record.cveId),
    epss: epssTexts.get(record.cveId) ?? null,
    publishedAt: record.publishedAt,
    dateAdded: kevDates.get(record.cveId) ?? null,
    primary: primaries.get(record.cveId) ?? null,
  }));
}

/**
 * Default priority over the current PUBLISHED corpus. With a limit, ordering
 * runs in SQL over the same cascade (KEV tier, EPSS known-then-descending,
 * known publication date, publication descending, ASCII ID) and only the top
 * rows are hydrated, so a request for 5 rows never materializes 395k items.
 * Exact decimal ties cannot collide as doubles for stored short decimals, so
 * the SQL order matches orderDefaultPriority().slice(0, limit) exactly.
 */
export function getDefaultPriority(db: CveDatabase, limit?: number): PriorityItem[] {
  if (!hasLimit(limit)) {
    return orderDefaultPriority(loadItems(db, getAcceptedEpssDate(db)));
  }
  if (limit === 0) return [];
  const epssDate = getAcceptedEpssDate(db);
  const rows = db.handle
    .prepare(
      "SELECT r.cve_id AS id, r.date_published AS publishedAt, c.epss AS epss FROM cve_records r " +
        "LEFT JOIN kev_entries k ON k.cve_id = r.cve_id " +
        "LEFT JOIN (SELECT cve_id, MAX(model_version) AS m FROM epss_daily WHERE score_date = ? GROUP BY cve_id) cm " +
        "ON cm.cve_id = r.cve_id " +
        "LEFT JOIN epss_daily c ON c.cve_id = cm.cve_id AND c.score_date = ? AND c.model_version = cm.m " +
        "WHERE r.state = 'PUBLISHED' " +
        "ORDER BY (k.cve_id IS NULL) ASC, " +
        `CASE WHEN ${epssValidSql("c.epss")} THEN 0 ELSE 1 END ASC, ` +
        `CASE WHEN ${epssValidSql("c.epss")} THEN CAST(c.epss AS REAL) ELSE -1 END DESC, ` +
        "(r.date_published IS NULL) ASC, r.date_published DESC, r.cve_id ASC " +
        "LIMIT ?",
    )
    .all(epssDate, epssDate, limit) as Array<{
    id: string;
    publishedAt: string | null;
    epss: string | null;
  }>;
  return hydrateOverviewItems(
    db,
    null,
    rows.map((row) => ({ id: row.id, publishedAt: row.publishedAt, epss: row.epss })),
  );
}

/** Known-exploited members ordered by catalog dateAdded desc, then ID. */
export function getKnownExploited(db: CveDatabase, limit?: number): PriorityItem[] {
  if (!hasLimit(limit)) {
    return orderKnownExploited(loadItems(db, getAcceptedEpssDate(db)));
  }
  if (limit === 0) return [];
  const rows = db.handle
    .prepare(
      "SELECT k.cve_id AS id, r.date_published AS publishedAt FROM kev_entries k " +
        "JOIN cve_records r ON r.cve_id = k.cve_id AND r.state = 'PUBLISHED' ORDER BY k.cve_id ASC",
    )
    .all() as Array<{ id: string; publishedAt: string | null }>;
  const items = hydrateOverviewItems(
    db,
    getAcceptedEpssDate(db),
    rows.map((row) => ({ id: row.id, publishedAt: row.publishedAt, epss: null })),
  );
  return take(orderKnownExploited(items), limit);
}

/** Highest forecast: known EPSS only, raw probability desc. */
export function getHighestForecast(db: CveDatabase, limit?: number): PriorityItem[] {
  if (!hasLimit(limit)) {
    return orderHighestForecast(loadItems(db, getAcceptedEpssDate(db)));
  }
  const epssDate = getAcceptedEpssDate(db);
  if (epssDate === null || limit === 0) return [];
  const rows = db.handle
    .prepare(
      "SELECT c.cve_id AS id, c.epss AS epss, r.date_published AS publishedAt " +
        "FROM (SELECT cve_id, MAX(model_version) AS m FROM epss_daily WHERE score_date = ? GROUP BY cve_id) cm " +
        "JOIN epss_daily c ON c.cve_id = cm.cve_id AND c.score_date = ? AND c.model_version = cm.m " +
        "JOIN cve_records r ON r.cve_id = c.cve_id AND r.state = 'PUBLISHED' " +
        `WHERE ${epssValidSql("c.epss")} ` +
        "ORDER BY CAST(c.epss AS REAL) DESC, (r.date_published IS NULL) ASC, r.date_published DESC, c.cve_id ASC " +
        "LIMIT ?",
    )
    .all(epssDate, epssDate, limit) as Array<{
    id: string;
    epss: string;
    publishedAt: string | null;
  }>;
  return hydrateOverviewItems(db, epssDate, rows);
}

/**
 * New critical: PUBLISHED records published in [T - 30d, T) whose primary
 * CNA metric is modern (v3/v4) with base >= 9.0. ADP-only, legacy-only,
 * unknown, and malformed-date records are ineligible by construction.
 */
export function getNewCritical(db: CveDatabase, cutoffT: string, limit?: number): PriorityItem[] {
  if (!hasLimit(limit)) {
    return selectNewCritical(loadItems(db, getAcceptedEpssDate(db)), cutoffT);
  }
  const cutoffMs = Date.parse(cutoffT);
  if (!Number.isFinite(cutoffMs) || limit === 0) return [];
  const lowerIso = new Date(cutoffMs - 30 * 24 * 60 * 60 * 1000).toISOString();
  const upperIso = new Date(cutoffMs).toISOString();
  // SQL superset prefilter: eligibility needs a valid original CNA modern
  // metric scoring >= 9.0 (exact decimal policy in selectNewCritical), so any
  // row without such a metric is definitely ineligible and skipped before
  // hydration. Rows passing the filter are still decided in JS, keeping the
  // exact version-preference/max-score policy; the filter only shrinks the
  // hydrated set (to zero on a corpus with no recent criticals).
  const rows = db.handle
    .prepare(
      "SELECT cve_id AS id, date_published AS publishedAt FROM cve_records r " +
        "WHERE state = 'PUBLISHED' AND date_published >= ? AND date_published < ? " +
        "AND EXISTS (SELECT 1 FROM cvss_metrics m WHERE m.cve_id = r.cve_id AND m.origin = 'CNA' " +
        "AND m.version IN ('4.0', '3.1', '3.0') " +
        "AND m.base_score GLOB '[0-9]*' AND m.base_score NOT GLOB '*[^0-9.]*' " +
        "AND m.base_score NOT GLOB '*.*.*' AND m.base_score NOT GLOB '*.' " +
        "AND LENGTH(m.base_score) <= 64 AND CAST(m.base_score AS REAL) >= 9 AND CAST(m.base_score AS REAL) <= 10) " +
        "ORDER BY cve_id ASC",
    )
    .all(lowerIso, upperIso) as Array<{ id: string; publishedAt: string | null }>;
  const items = hydrateOverviewItems(
    db,
    getAcceptedEpssDate(db),
    rows.map((row) => ({ id: row.id, publishedAt: row.publishedAt, epss: null })),
  );
  return take(selectNewCritical(items, cutoffT), limit);
}

/**
 * Rising forecast: exact current/previous-day same-model positive deltas.
 * Defaults to the accepted EPSS date; an unknown current date yields [].
 */
export function getRisingForecast(
  db: CveDatabase,
  currentDate?: string,
  limit?: number,
): RisingResult<PriorityItem>[] {
  const current = currentDate ?? getAcceptedEpssDate(db);
  if (current === null || !/^\d{4}-\d{2}-\d{2}$/.test(current)) return [];
  const previous = minus7Days(current);
  if (previous === null) return [];
  // Exact short-circuit: rising needs observations on exactly d and d-7, so
  // a missing previous-date snapshot means [] without the multi-table join.
  // Point lookup on the (score_date, model_version) index; milliseconds.
  const hasPrevious =
    db.handle
      .prepare("SELECT 1 AS one FROM epss_daily WHERE score_date = ? LIMIT 1")
      .get(previous) !== undefined;
  if (!hasPrevious) return [];
  if (hasLimit(limit)) {
    return take(getRisingForecastTop(db, current, previous, limit), limit);
  }
  const records = publishedRecords(db);
  if (records.length === 0) return [];
  const kevDates = kevDateMap(db);
  const currentEpss = epssTextMap(db, current);
  const currentModels = modelTextMap(db, current);
  const previousEpss = epssTextMap(db, previous);
  const previousModels = modelTextMap(db, previous);
  const primaries = primaryMap(db);
  const candidates: RisingCandidate[] = records.map((record) => ({
    id: record.cveId,
    kevMember: kevDates.has(record.cveId),
    epss: currentEpss.get(record.cveId) ?? null,
    publishedAt: record.publishedAt,
    dateAdded: kevDates.get(record.cveId) ?? null,
    primary: primaries.get(record.cveId) ?? null,
    currentEpss: currentEpss.get(record.cveId) ?? null,
    currentDate: current,
    currentModel: currentModels.get(record.cveId) ?? null,
    previousEpss: previousEpss.get(record.cveId) ?? null,
    previousDate: previous,
    previousModel: previousModels.get(record.cveId) ?? null,
  }));
  return take(
    selectRisingForecast(candidates, current).map(({ item, deltaPp }) => ({
      item: {
        id: item.id,
        kevMember: item.kevMember,
        epss: item.epss,
        publishedAt: item.publishedAt,
        dateAdded: item.dateAdded,
        primary: item.primary,
      },
      deltaPp,
    })),
    limit,
  );
}
