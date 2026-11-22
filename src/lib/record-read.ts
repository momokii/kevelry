// The one database walk that turns CVE ids into display records.
//
// This used to live in `app/api/v1/_lib/records.ts`. The AI tool layer reads
// records too, and a library module may not import route code, so the walk
// moved here and the route module re-exports it — every existing import path
// still resolves, and `src/lib/**` stays free of `app/**` dependencies.
//
// Contract: read-only, parameterized SQL only, chunked IN lists (500 per
// chunk), unknown values stay null, and order/duplicates of the input ids are
// normalized (dedupe, input order, gaps skipped).

import { chunk, type CveDatabase } from "./db";
import { projectSecondaryCvss, type CvssSecondary } from "./cvss-projection";
import { getAcceptedEpssDate } from "./priority";
import {
  exploitReferencesOf,
  kevRansomwareUseOf,
  legacyRansomwareKnown,
  type ExploitReference,
  type FullRecord,
  type KevRansomwareUse,
} from "./record-display";
import { selectPrimaryCvss, type PrimaryCvss } from "./ranking";

/** Absent catalog text is null, never an empty string. */
function catalogText(value: string | null): string | null {
  if (value === null || value.trim() === "") return null;
  return value;
}

interface RecordRow {
  cve_id: string;
  state: string;
  date_published: string | null;
  date_updated: string | null;
  title: string | null;
  description: string;
  description_lang: string | null;
  raw_json: string | null;
}

interface KevRow {
  cve_id: string;
  date_added: string;
  due_date: string | null;
  required_action: string | null;
  vulnerability_name: string | null;
  ransomware_known: number | null;
}

interface EpssRow {
  cve_id: string;
  epss: string;
  percentile: string;
  model_version: string;
}

interface MetricRow {
  cve_id: string;
  origin: string;
  provider: string | null;
  version: string;
  base_score: string;
  vector: string;
  source_order: number;
}

/**
 * The 001 schema predates `provider` (the importer adds it additively), so a
 * freshly migrated but never-imported database has no such column. Probe once
 * per handle and fall back to NULL instead of failing the read path.
 */
const metricProviderColumnByDb = new WeakMap<CveDatabase, boolean>();

function hasMetricProviderColumn(db: CveDatabase): boolean {
  const cached = metricProviderColumnByDb.get(db);
  if (cached !== undefined) return cached;
  let present = false;
  try {
    const columns = db.handle.prepare("PRAGMA table_info(cvss_metrics)").all() as Array<{
      name: string;
    }>;
    present = columns.some((column) => column.name === "provider");
  } catch {
    present = false;
  }
  metricProviderColumnByDb.set(db, present);
  return present;
}

/** Load full display records for ids, preserving input order and skipping gaps. */
export function loadFullRecords(db: CveDatabase, ids: readonly string[]): FullRecord[] {
  if (ids.length === 0) return [];
  const unique = [...new Set(ids)];
  const records = new Map<string, RecordRow>();
  const kevDates = new Map<string, string>();
  const kevEnrichment = new Map<
    string,
    {
      dueDate: string | null;
      requiredAction: string | null;
      vulnerabilityName: string | null;
      ransomwareUse: KevRansomwareUse;
    }
  >();
  const kevCwes = new Map<string, string[]>();
  const ssvcById = new Map<
    string,
    {
      exploitation: string;
      automatable: string;
      technicalImpact: string;
      version: string | null;
      timestamp: string | null;
    }
  >();
  const epssById = new Map<string, EpssRow>();
  const metricsById = new Map<string, MetricRow[]>();
  const acceptedDate = getAcceptedEpssDate(db);

  for (const group of chunk(unique, 500)) {
    const placeholders = group.map(() => "?").join(", ");
    const rows = db.handle
      .prepare(
        `SELECT cve_id, state, date_published, date_updated, title, description, description_lang, raw_json FROM cve_records WHERE cve_id IN (${placeholders})`,
      )
      .all(...group) as RecordRow[];
    for (const row of rows) records.set(row.cve_id, row);
    const kevRows = db.handle
      .prepare(
        `SELECT cve_id, date_added, due_date, required_action, vulnerability_name, ransomware_known FROM kev_entries WHERE cve_id IN (${placeholders})`,
      )
      .all(...group) as KevRow[];
    for (const row of kevRows) {
      kevDates.set(row.cve_id, row.date_added);
      kevEnrichment.set(row.cve_id, {
        dueDate: catalogText(row.due_date),
        requiredAction: catalogText(row.required_action),
        vulnerabilityName: catalogText(row.vulnerability_name),
        ransomwareUse: kevRansomwareUseOf(row.ransomware_known),
      });
    }
    const ssvcRows = db.handle
      .prepare(
        `SELECT cve_id, exploitation, automatable, technical_impact, ssvc_version, source_timestamp FROM ssvc_records WHERE cve_id IN (${placeholders})`,
      )
      .all(...group) as Array<{
      cve_id: string;
      exploitation: string;
      automatable: string;
      technical_impact: string;
      ssvc_version: string | null;
      source_timestamp: string | null;
    }>;
    for (const row of ssvcRows) {
      ssvcById.set(row.cve_id, {
        exploitation: row.exploitation,
        automatable: row.automatable,
        technicalImpact: row.technical_impact,
        version: row.ssvc_version,
        timestamp: row.source_timestamp,
      });
    }
    const cweRows = db.handle
      .prepare(
        `SELECT cve_id, cwe_id FROM kev_cwes WHERE cve_id IN (${placeholders}) ORDER BY cve_id ASC, cwe_id ASC`,
      )
      .all(...group) as Array<{ cve_id: string; cwe_id: string }>;
    for (const row of cweRows) {
      const list = kevCwes.get(row.cve_id);
      if (list === undefined) kevCwes.set(row.cve_id, [row.cwe_id]);
      else list.push(row.cwe_id);
    }
    if (acceptedDate !== null) {
      const epssRows = db.handle
        .prepare(
          `SELECT cve_id, epss, percentile, model_version FROM epss_daily WHERE score_date = ? AND cve_id IN (${placeholders})`,
        )
        .all(acceptedDate, ...group) as EpssRow[];
      for (const row of epssRows) {
        const prior = epssById.get(row.cve_id);
        if (prior === undefined || row.model_version > prior.model_version) {
          epssById.set(row.cve_id, row);
        }
      }
    }
    const providerColumn = hasMetricProviderColumn(db) ? "provider" : "NULL AS provider";
    const metricRows = db.handle
      .prepare(
        `SELECT cve_id, origin, ${providerColumn}, version, base_score, vector, source_order FROM cvss_metrics WHERE cve_id IN (${placeholders})`,
      )
      .all(...group) as MetricRow[];
    for (const row of metricRows) {
      const list = metricsById.get(row.cve_id);
      if (list === undefined) metricsById.set(row.cve_id, [row]);
      else list.push(row);
    }
  }

  const out: FullRecord[] = [];
  for (const cveId of unique) {
    const row = records.get(cveId);
    if (row === undefined) continue;
    const metrics = metricsById.get(cveId) ?? [];
    const metricInputs = metrics.map((metric, index) => ({
      origin: metric.origin,
      provider: metric.provider,
      version: metric.version,
      baseScore: metric.base_score,
      vector: metric.vector,
      sourceOrder: Number.isInteger(metric.source_order) ? metric.source_order : index,
    }));
    const primary = selectPrimaryCvss(metricInputs);
    const epss = epssById.get(cveId);
    const kev = kevEnrichment.get(cveId);
    const ransomwareUse = kev?.ransomwareUse ?? "unstated";
    out.push({
      cveId: row.cve_id,
      state: row.state,
      publishedAt: row.date_published,
      dateUpdated: row.date_updated,
      title: row.title,
      description: row.description,
      descriptionLang: row.description_lang,
      rawJson: row.raw_json,
      kevDateAdded: kevDates.get(cveId) ?? null,
      kevDueDate: kev?.dueDate ?? null,
      kevRequiredAction: kev?.requiredAction ?? null,
      kevVulnerabilityName: kev?.vulnerabilityName ?? null,
      kevRansomwareUse: ransomwareUse,
      kevRansomwareKnown: legacyRansomwareKnown(ransomwareUse),
      kevCwes: kevCwes.get(cveId) ?? [],
      exploitReferences: exploitReferencesOf(row.raw_json),
      ssvc: ssvcById.get(cveId) ?? null,
      epssText: epss?.epss ?? null,
      epssPercentile: epss?.percentile ?? null,
      epssModel: epss?.model_version ?? null,
      primary,
      cvssSecondary: projectSecondaryCvss(metricInputs, primary),
      hasAdp: metrics.some((metric) => metric.origin === "ADP"),
    });
  }
  return out;
}

// The projection helpers are re-exported so a caller that only needs the type
// never has to reach into the route module for it.
export type { CvssSecondary, ExploitReference, FullRecord, KevRansomwareUse, PrimaryCvss };
