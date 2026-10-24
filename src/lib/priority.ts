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
    .prepare(
      "SELECT cve_id, origin, version, base_score, vector, source_order FROM cvss_metrics",
    )
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

/** Default priority over the current PUBLISHED corpus. */
export function getDefaultPriority(db: CveDatabase): PriorityItem[] {
  return orderDefaultPriority(loadItems(db, getAcceptedEpssDate(db)));
}

/** Known-exploited members ordered by catalog dateAdded desc, then ID. */
export function getKnownExploited(db: CveDatabase): PriorityItem[] {
  return orderKnownExploited(loadItems(db, getAcceptedEpssDate(db)));
}

/** Highest forecast: known EPSS only, raw probability desc. */
export function getHighestForecast(db: CveDatabase): PriorityItem[] {
  return orderHighestForecast(loadItems(db, getAcceptedEpssDate(db)));
}

/**
 * New critical: PUBLISHED records published in [T - 30d, T) whose primary
 * CNA metric is modern (v3/v4) with base >= 9.0. ADP-only, legacy-only,
 * unknown, and malformed-date records are ineligible by construction.
 */
export function getNewCritical(db: CveDatabase, cutoffT: string): PriorityItem[] {
  return selectNewCritical(loadItems(db, getAcceptedEpssDate(db)), cutoffT);
}

/**
 * Rising forecast: exact current/previous-day same-model positive deltas.
 * Defaults to the accepted EPSS date; an unknown current date yields [].
 */
export function getRisingForecast(
  db: CveDatabase,
  currentDate?: string,
): RisingResult<PriorityItem>[] {
  const current = currentDate ?? getAcceptedEpssDate(db);
  if (current === null || !/^\d{4}-\d{2}-\d{2}$/.test(current)) return [];
  const previous = minus7Days(current);
  if (previous === null) return [];
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
