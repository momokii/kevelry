import { buildProvenance, type Provenance } from "../../../app/api/v1/_lib/shared";
import { getAggregates, type AggregateSnapshot } from "../../lib/aggregates";
import { openReadDatabase, type CveDatabase } from "../../lib/db";
import {
  getAcceptedEpssDate,
  getHighestForecast,
  getKnownExploited,
  getNewCritical,
  getRisingForecast,
  type PriorityItem,
} from "../../lib/priority";
import { selectPrimaryCvss, type CvssMetricInput } from "../../lib/ranking";
import { officialCveLink } from "../../lib/search";

export const OVERVIEW_CHART_DAYS = 14;
export const OVERVIEW_SUMMARY_LIMIT = 3;

export interface DayBucket {
  bucketStart: string;
  count: number;
}

export interface PrioritySummaryItem {
  cveId: string;
  title: string;
  signal: string;
  officialUrl: string;
}

export interface PrioritySummary {
  key: string;
  title: string;
  href: string;
  ordering: string;
  items: PrioritySummaryItem[];
  emptyNote: string;
}

export interface OverviewData {
  generatedAt: string;
  empty: boolean;
  publishedTotal: number;
  anchorDay: string | null;
  buckets: DayBucket[];
  unknownDateCount: number;
  correctionNotes: string[];
  provenance: Provenance;
  summaries: PrioritySummary[];
}

function trailingDays(anchorDay: string, count: number): string[] {
  const base = Date.parse(`${anchorDay}T00:00:00.000Z`);
  const days: string[] = [];
  for (let index = count - 1; index >= 0; index -= 1) {
    days.push(new Date(base - index * 86_400_000).toISOString().slice(0, 10));
  }
  return days;
}

function readDayCounts(db: CveDatabase): {
  counts: Map<string, number>;
  anchorDay: string | null;
  unknownDateCount: number;
  publishedTotal: number;
} {
  // One full scan serves buckets, anchor, unknown dates, and the total: the
  // dated GROUP BY plus a NULL-date rollup row. Separate COUNT queries would
  // rescan the 395k-row table for the same pages.
  const rows = db.handle
    .prepare(
      "SELECT substr(date_published, 1, 10) AS day, COUNT(*) AS n FROM cve_records " +
        "WHERE state = ? AND date_published IS NOT NULL GROUP BY day " +
        "UNION ALL SELECT NULL AS day, COUNT(*) AS n FROM cve_records " +
        "WHERE state = ? AND date_published IS NULL",
    )
    .all("PUBLISHED", "PUBLISHED") as Array<{ day: string | null; n: number }>;
  const counts = new Map<string, number>();
  let unknownDateCount = 0;
  let anchorDay: string | null = null;
  for (const row of rows) {
    if (row.day === null) {
      unknownDateCount = row.n;
      continue;
    }
    counts.set(row.day, row.n);
    if (anchorDay === null || row.day > anchorDay) anchorDay = row.day;
  }
  let publishedTotal = unknownDateCount;
  for (const n of counts.values()) publishedTotal += n;
  return { counts, anchorDay, unknownDateCount, publishedTotal };
}

function readCorrectionNotes(db: CveDatabase): string[] {
  const row = db.handle.prepare("SELECT COUNT(*) AS n FROM cve_tombstones").get() as { n: number };
  return tombstoneNotes(row.n <= 0 ? 0 : row.n);
}

function tombstoneNotes(tombstones: number): string[] {
  if (tombstones <= 0) return [];
  return [
    `${tombstones} removed or rejected record(s) retained as tombstones; history reflects the accepted corpus.`,
  ];
}

function signalFor(item: PriorityItem, list: string, epssDate: string | null): string {
  if (list === "known-exploited") {
    const dateAdded =
      item.dateAdded !== null && /^\d{4}-\d{2}-\d{2}T/.test(item.dateAdded)
        ? item.dateAdded.slice(0, 10)
        : (item.dateAdded ?? "unknown");
    return `KEV catalog date ${dateAdded}.`;
  }
  if (list === "highest-forecast") {
    return item.epss === null
      ? "EPSS unavailable for this snapshot"
      : `EPSS probability ${item.epss}, score date ${epssDate ?? "unknown"}.`;
  }
  if (list === "new-critical") {
    return item.primary === null
      ? "Unscored under this view's policy"
      : `Primary CNA CVSS ${item.primary.version} base score ${item.primary.baseScore}.`;
  }
  return "Forecast detail unavailable for this snapshot";
}

function toSummaryItems(
  db: CveDatabase,
  items: readonly PriorityItem[],
  list: string,
  epssDate: string | null,
): PrioritySummaryItem[] {
  const top = items.slice(0, OVERVIEW_SUMMARY_LIMIT);
  const titles = readTitles(
    db,
    top.map((item) => item.id),
  );
  return top.map((item) => ({
    cveId: item.id,
    title: titles.get(item.id) ?? item.id,
    signal: signalFor(item, list, epssDate),
    officialUrl: officialCveLink(item.id),
  }));
}

export const TITLE_LOOKUP_CHUNK_SIZE = 500;

export function readTitles(db: CveDatabase, cveIds: readonly string[]): Map<string, string> {
  const titles = new Map<string, string>();
  for (const cveId of cveIds) titles.set(cveId, cveId);
  if (cveIds.length === 0) return titles;
  const unique = [...new Set(cveIds)];
  for (let index = 0; index < unique.length; index += TITLE_LOOKUP_CHUNK_SIZE) {
    const group = unique.slice(index, index + TITLE_LOOKUP_CHUNK_SIZE);
    const placeholders = group.map(() => "?").join(", ");
    const rows = db.handle
      .prepare(`SELECT cve_id, title FROM cve_records WHERE cve_id IN (${placeholders})`)
      .all(...group) as Array<{ cve_id: string; title: string | null }>;
    for (const row of rows) {
      if (typeof row.title === "string" && row.title.trim() !== "") {
        titles.set(row.cve_id, row.title);
      }
    }
  }
  return titles;
}

/**
 * Hydrate display items for a small precomputed id list (cached top-N head).
 * Same fields as the live getters, from chunked PK lookups only — no corpus
 * scan. Order follows the input ids.
 */
function hydrateTopIds(
  db: CveDatabase,
  epssDate: string | null,
  ids: readonly string[],
): PriorityItem[] {
  const unique = [...new Set(ids)];
  if (unique.length === 0) return [];
  const publishedById = new Map<string, string | null>();
  const kevDates = new Map<string, string>();
  const epssById = new Map<string, string>();
  const metricsById = new Map<string, CvssMetricInput[]>();
  for (let index = 0; index < unique.length; index += TITLE_LOOKUP_CHUNK_SIZE) {
    const group = unique.slice(index, index + TITLE_LOOKUP_CHUNK_SIZE);
    const placeholders = group.map(() => "?").join(", ");
    const recordRows = db.handle
      .prepare(`SELECT cve_id, date_published FROM cve_records WHERE cve_id IN (${placeholders})`)
      .all(...group) as Array<{ cve_id: string; date_published: string | null }>;
    for (const row of recordRows) publishedById.set(row.cve_id, row.date_published);
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
  return unique.map((id) => ({
    id,
    kevMember: kevDates.has(id),
    epss: epssById.get(id) ?? null,
    publishedAt: publishedById.get(id) ?? null,
    dateAdded: kevDates.get(id) ?? null,
    primary: selectPrimaryCvss(metricsById.get(id) ?? []) ?? null,
  }));
}

function buildSummaries(
  db: CveDatabase,
  nowIso: string,
  epssDate: string | null,
  cached: AggregateSnapshot | null,
): PrioritySummary[] {
  // The cached top-N heads equal the live heads while the EPSS score date is
  // unchanged (guarded by the caller); hydrating 3 ids costs point lookups
  // instead of two full-corpus sorts. Known-exploited and new-critical stay
  // live: both are already sub-second bounded queries.
  const useCache = cached !== null && cached.epssScoreDate === epssDate;
  const highestForecast = useCache
    ? hydrateTopIds(db, epssDate, (cached as AggregateSnapshot).topHighest.slice(0, OVERVIEW_SUMMARY_LIMIT))
    : getHighestForecast(db, OVERVIEW_SUMMARY_LIMIT);
  const rising = useCache
    ? (cached as AggregateSnapshot).topRising
        .slice(0, OVERVIEW_SUMMARY_LIMIT)
        .map(({ id, deltaPp }) => ({ id, deltaPp }))
    : getRisingForecast(db, undefined, OVERVIEW_SUMMARY_LIMIT).map(({ item, deltaPp }) => ({
        id: item.id,
        deltaPp,
      }));
  const knownExploited = getKnownExploited(db, OVERVIEW_SUMMARY_LIMIT);
  const newCritical = getNewCritical(db, nowIso, OVERVIEW_SUMMARY_LIMIT);
  const risingTitles = readTitles(
    db,
    rising.slice(0, OVERVIEW_SUMMARY_LIMIT).map(({ id }) => id),
  );
  return [
    {
      key: "known-exploited",
      title: "Known exploited",
      href: "/priority",
      ordering: "KEV catalog date descending, then CVE ID.",
      items: toSummaryItems(db, knownExploited, "known-exploited", epssDate),
      emptyNote: "No KEV-listed records in the retained snapshot.",
    },
    {
      key: "highest-forecast",
      title: "Highest forecast",
      href: "/priority",
      ordering: "Raw EPSS probability descending; unknown sorts after every known value.",
      items: toSummaryItems(db, highestForecast, "highest-forecast", epssDate),
      emptyNote: "No scored forecasts in the retained snapshot.",
    },
    {
      key: "new-critical",
      title: "New critical",
      href: "/priority",
      ordering: "Published in the trailing 30 days with a primary CNA CVSS of 9.0 or higher.",
      items: toSummaryItems(db, newCritical, "new-critical", epssDate),
      emptyNote: "No new critical records in the retained window.",
    },
    {
      key: "rising-forecast",
      title: "Rising forecast",
      href: "/priority",
      ordering: "Same-model 7-day probability rise; cross-model comparisons are ineligible.",
      items: rising.slice(0, OVERVIEW_SUMMARY_LIMIT).map(({ id, deltaPp }) => ({
        cveId: id,
        title: risingTitles.get(id) ?? id,
        signal: `7-day rise of ${deltaPp} percentage points, same model.`,
        officialUrl: officialCveLink(id),
      })),
      emptyNote: "No rising forecasts in the retained window.",
    },
  ];
}

/**
 * Reads the retained local snapshot for the overview page through the
 * shared read-only handle (no open/close + migrateUp per request) and the
 * precomputed aggregate cache (no full-corpus scans). Falls back to live
 * queries when the cache is empty so a seeded volume works immediately.
 * A missing or unusable data directory yields an explicit unavailable
 * payload instead of a throw.
 */
export function loadOverviewData(dataDir: string, nowIso: string): OverviewData | null {
  let db: CveDatabase | null = null;
  try {
    db = openReadDatabase(dataDir);
  } catch {
    return null;
  }
  try {
    const cached = getAggregates(db);
    const { counts, anchorDay, unknownDateCount, publishedTotal } =
      cached === null
        ? readDayCounts(db)
        : {
            counts: new Map(Object.entries(cached.dayCounts)),
            anchorDay:
              Object.keys(cached.dayCounts).length === 0
                ? null
                : Object.keys(cached.dayCounts).reduce((a, b) => (a > b ? a : b)),
            unknownDateCount: cached.unknownDateCount,
            publishedTotal: cached.publishedTotal,
          };
    const buckets: DayBucket[] =
      anchorDay === null
        ? []
        : trailingDays(anchorDay, OVERVIEW_CHART_DAYS).map((bucketStart) => ({
            bucketStart,
            count: counts.get(bucketStart) ?? 0,
          }));
    const epssDate = getAcceptedEpssDate(db);
    const correctionNotes =
      cached === null ? readCorrectionNotes(db) : tombstoneNotes(cached.tombstones);
    return {
      generatedAt: nowIso,
      empty: publishedTotal === 0,
      publishedTotal,
      anchorDay,
      buckets,
      unknownDateCount,
      correctionNotes,
      provenance: buildProvenance(db, nowIso),
      summaries: buildSummaries(db, nowIso, epssDate, cached),
    };
  } finally {
    // Shared read handle stays open for the process; never close per request.
  }
}

export function resolveDataDir(env: NodeJS.ProcessEnv = process.env): string {
  const raw = env.DATA_DIR;
  return raw === undefined || raw === "" ? "./data" : raw;
}
