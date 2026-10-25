import { buildProvenance, type Provenance } from "../../../app/api/v1/_lib/shared";
import { openDatabase, type CveDatabase } from "../../lib/db";
import {
  getAcceptedEpssDate,
  getHighestForecast,
  getKnownExploited,
  getNewCritical,
  getRisingForecast,
  type PriorityItem,
} from "../../lib/priority";
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
  if (row.n <= 0) return [];
  return [
    `${row.n} removed or rejected record(s) retained as tombstones; history reflects the accepted corpus.`,
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

function buildSummaries(
  db: CveDatabase,
  nowIso: string,
  epssDate: string | null,
): PrioritySummary[] {
  const knownExploited = getKnownExploited(db, OVERVIEW_SUMMARY_LIMIT);
  const highestForecast = getHighestForecast(db, OVERVIEW_SUMMARY_LIMIT);
  const newCritical = getNewCritical(db, nowIso, OVERVIEW_SUMMARY_LIMIT);
  const rising = getRisingForecast(db, undefined, OVERVIEW_SUMMARY_LIMIT);
  const risingTitles = readTitles(
    db,
    rising.slice(0, OVERVIEW_SUMMARY_LIMIT).map(({ item }) => item.id),
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
      items: rising.slice(0, OVERVIEW_SUMMARY_LIMIT).map(({ item, deltaPp }) => ({
        cveId: item.id,
        title: risingTitles.get(item.id) ?? item.id,
        signal: `7-day rise of ${deltaPp} percentage points, same model.`,
        officialUrl: officialCveLink(item.id),
      })),
      emptyNote: "No rising forecasts in the retained window.",
    },
  ];
}

/**
 * Reads the retained local snapshot for the overview page. Opens the database
 * at DATA_DIR, reads every section, then closes the handle so Playwright
 * seeding between requests never meets a held lock. A missing or unusable
 * data directory yields an explicit unavailable payload instead of a throw.
 */
export function loadOverviewData(dataDir: string, nowIso: string): OverviewData | null {
  let db: CveDatabase | null = null;
  try {
    db = openDatabase({ dataDir });
  } catch {
    return null;
  }
  try {
    const { counts, anchorDay, unknownDateCount, publishedTotal } = readDayCounts(db);
    const buckets: DayBucket[] =
      anchorDay === null
        ? []
        : trailingDays(anchorDay, OVERVIEW_CHART_DAYS).map((bucketStart) => ({
            bucketStart,
            count: counts.get(bucketStart) ?? 0,
          }));
    const epssDate = getAcceptedEpssDate(db);
    return {
      generatedAt: nowIso,
      empty: publishedTotal === 0,
      publishedTotal,
      anchorDay,
      buckets,
      unknownDateCount,
      correctionNotes: readCorrectionNotes(db),
      provenance: buildProvenance(db, nowIso),
      summaries: buildSummaries(db, nowIso, epssDate),
    };
  } finally {
    db.close();
  }
}

export function resolveDataDir(env: NodeJS.ProcessEnv = process.env): string {
  const raw = env.DATA_DIR;
  return raw === undefined || raw === "" ? "./data" : raw;
}
