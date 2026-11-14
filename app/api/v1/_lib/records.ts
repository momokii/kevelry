import { chunk, type CveDatabase } from "../../../../src/lib/db";
import { projectSecondaryCvss, type CvssSecondary } from "../../../../src/lib/cvss-projection";
import { exploitReferenceUrls } from "../../../../src/lib/exploit-ref";
import { getAcceptedEpssDate, type PriorityItem } from "../../../../src/lib/priority";
import { selectPrimaryCvss } from "../../../../src/lib/ranking";
import {
  DESCRIPTION_MISSING_LABEL,
  excerptDescription,
  officialCveLink,
  severityBandFor,
} from "../../../../src/lib/search";
import type { EpssParam, KevParam, SeverityParam } from "./params";

/**
 * References the record itself tags as exploit material.
 *
 * Source: the CVE record's own `references[].tags` (CNA or ADP). A tag is the
 * publisher's classification, not proof that a working exploit exists, so the
 * UI always says "tagged", never "verified". Only http(s) URLs are kept.
 */
export function exploitReferencesOf(rawJson: string | null, cap = 5): Array<{ url: string }> {
  if (rawJson === null || rawJson === "") return [];
  try {
    // Same walker as the stored flag: CNA object plus the ADP array, so a record
    // that is tagged only in an ADP container still links to its references.
    return exploitReferenceUrls(JSON.parse(rawJson) as unknown, cap).map((url) => ({ url }));
  } catch {
    // Unparseable payloads carry no tagged references, never a throw.
    return [];
  }
}

/**
 * Catalog-stated ransomware use, as the catalog itself words it.
 *
 * `known`   - the catalog says Known.
 * `unknown` - the catalog says Unknown (its own value, not our inference).
 * `unstated` - the catalog states nothing (stored NULL).
 *
 * `unknown` and `unstated` are distinct states and are never collapsed:
 * neither is ever negated into a claim that ransomware use is absent.
 */
export type KevRansomwareUse = "known" | "unknown" | "unstated";

/**
 * The one mapping from the stored `kev_entries.ransomware_known` integer:
 * `1` -> "known", `0` -> "unknown", `NULL` -> "unstated".
 *
 * Any other non-null integer keeps the legacy reading (non-zero is Known), so
 * the old boolean alias below cannot drift from this switch.
 */
export function kevRansomwareUseOf(value: number | null | undefined): KevRansomwareUse {
  if (value === null || value === undefined) return "unstated";
  return value === 0 ? "unknown" : "known";
}

/**
 * Legacy `ransomwareKnown` boolean alias, derived from the tri-state above:
 * known -> true, unknown -> false, unstated -> null. Kept for back-compat with
 * consumers that predate `ransomwareUse`.
 */
export function legacyRansomwareKnown(use: KevRansomwareUse): boolean | null {
  if (use === "known") return true;
  if (use === "unknown") return false;
  return null;
}

/** Absent catalog text is null, never an empty string. */
function catalogText(value: string | null): string | null {
  if (value === null || value.trim() === "") return null;
  return value;
}

export interface FullRecord {
  cveId: string;
  state: string;
  publishedAt: string | null;
  dateUpdated: string | null;
  title: string | null;
  description: string;
  descriptionLang: string | null;
  rawJson: string | null;
  kevDateAdded: string | null;
  kevDueDate: string | null;
  kevRequiredAction: string | null;
  kevVulnerabilityName: string | null;
  /** Catalog-stated ransomware use; the single source for the KEV block. */
  kevRansomwareUse: KevRansomwareUse;
  /** Legacy alias derived from `kevRansomwareUse`, never a second mapping. */
  kevRansomwareKnown: boolean | null;
  kevCwes: string[];
  /** References the record tags as exploit material (never "verified PoC"). */
  exploitReferences: Array<{ url: string }>;
  /** CISA SSVC decision points, or null when the source publishes none. */
  ssvc: {
    exploitation: string;
    automatable: string;
    technicalImpact: string;
    version: string | null;
    timestamp: string | null;
  } | null;
  epssText: string | null;
  epssPercentile: string | null;
  epssModel: string | null;
  primary: { version: string; baseScore: string; vector: string } | null;
  /**
   * Every other preserved metric, bounded and labeled "context only".
   * Never a second primary: ranking/eligibility read `primary` alone.
   */
  cvssSecondary: CvssSecondary;
  /** Legacy flag kept additive; `cvssSecondary.status` supersedes it. */
  hasAdp: boolean;
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
      primary:
        primary === null
          ? null
          : { version: primary.version, baseScore: primary.baseScore, vector: primary.vector },
      cvssSecondary: projectSecondaryCvss(metricInputs, primary),
      hasAdp: metrics.some((metric) => metric.origin === "ADP"),
    });
  }
  return out;
}

export interface ApiCoverage {
  eligibleCohort: number;
  returned: number;
  unscored: number;
  unknownEpss: number;
  unknownDate: number;
}

export function coverageFor(items: readonly PriorityItem[], returned: number): ApiCoverage {
  let unscored = 0;
  let unknownEpss = 0;
  let unknownDate = 0;
  for (const item of items) {
    if (item.primary === null) unscored += 1;
    if (item.epss === null) unknownEpss += 1;
    if (item.publishedAt === null) unknownDate += 1;
  }
  return { eligibleCohort: items.length, returned, unscored, unknownEpss, unknownDate };
}

function excerptFields(record: FullRecord): {
  excerpt: string | null;
  excerptTruncated: boolean;
  excerptLanguage: string | null;
  excerptStatus: "present" | "fallback-language" | "not-supplied";
} {
  const shaped = excerptDescription(record.description, record.descriptionLang);
  if (shaped.excerpt === DESCRIPTION_MISSING_LABEL) {
    return {
      excerpt: null,
      excerptTruncated: false,
      excerptLanguage: null,
      excerptStatus: "not-supplied",
    };
  }
  if (shaped.langLabel === "en") {
    return {
      excerpt: shaped.excerpt,
      excerptTruncated: shaped.truncated,
      excerptLanguage: "en",
      excerptStatus: "present",
    };
  }
  return {
    excerpt: shaped.excerpt,
    excerptTruncated: shaped.truncated,
    excerptLanguage: shaped.langLabel,
    excerptStatus: "fallback-language",
  };
}

export function toCveItem(
  record: FullRecord,
  epssScoreDate: string | null,
  epssModel: string | null,
): Record<string, unknown> {
  const excerpt = excerptFields(record);
  const title =
    typeof record.title === "string" && record.title.trim() !== "" ? record.title : record.cveId;
  const epss =
    record.epssText === null
      ? { status: "unknown", value: null, percentile: null, scoreDate: null, modelVersion: null }
      : {
          status: "known",
          value: Number(record.epssText),
          percentile: record.epssPercentile === null ? null : Number(record.epssPercentile),
          scoreDate: epssScoreDate,
          modelVersion: record.epssModel ?? epssModel,
        };
  const cvssPrimary =
    record.primary !== null && record.primary.version !== "2.0"
      ? {
          status: "known",
          source: "cna",
          version: record.primary.version,
          baseScore: Number(record.primary.baseScore),
          vector: record.primary.vector,
        }
      : record.primary !== null
        ? {
            status: "legacy",
            source: "cna",
            version: record.primary.version,
            baseScore: Number(record.primary.baseScore),
            vector: record.primary.vector,
          }
        : record.hasAdp
          ? { status: "adp-only", source: null, version: null, baseScore: null, vector: null }
          : { status: "unknown", source: null, version: null, baseScore: null, vector: null };
  return {
    cveId: record.cveId,
    title,
    state: record.state,
    publishedAt: record.publishedAt,
    officialUrl: officialCveLink(record.cveId),
    excerpt: excerpt.excerpt,
    excerptTruncated: excerpt.excerptTruncated,
    excerptLanguage: excerpt.excerptLanguage,
    excerptStatus: excerpt.excerptStatus,
    kev: {
      listed: record.kevDateAdded !== null,
      dateAdded: record.kevDateAdded,
      dueDate: record.kevDueDate,
      requiredAction: record.kevRequiredAction,
      vulnerabilityName: record.kevVulnerabilityName,
      // Catalog-stated use: 1 -> known, 0 -> unknown (the catalog's own value),
      // NULL -> unstated. Neither state is ever negated into an absence claim.
      ransomwareUse: record.kevRansomwareUse,
      // Legacy alias for the same fact; unknown is false, unstated is null.
      ransomwareKnown: record.kevRansomwareKnown,
      cwes: record.kevCwes,
    },
    epss,
    cvssPrimary,
    cvssSecondary: record.cvssSecondary,
    ssvc: record.ssvc,
    exploitReferenceStatus: record.exploitReferences.length > 0 ? "tagged" : "none",
    exploitReferences: record.exploitReferences,
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value === "object" && value !== null) return value as Record<string, unknown>;
  return {};
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

export function detailExtras(
  rawJson: string | null,
  descriptionLang: string | null,
): {
  descriptionLanguages: string[];
  references: Array<{ url: string; container: string; provider: string | null }>;
} {
  const languages: string[] = [];
  const references: Array<{ url: string; container: string; provider: string | null }> = [];
  if (rawJson !== null) {
    try {
      const root = asRecord(JSON.parse(rawJson) as unknown);
      const containers = asRecord(root.containers);
      for (const container of ["cna", "adp"] as const) {
        const section = asRecord(containers[container]);
        const descriptions = Array.isArray(section.descriptions) ? section.descriptions : [];
        for (const entry of descriptions) {
          const lang = asString(asRecord(entry).lang);
          if (lang !== null && !languages.includes(lang)) languages.push(lang);
        }
        const refs = Array.isArray(section.references) ? section.references : [];
        for (const entry of refs) {
          const row = asRecord(entry);
          const url = asString(row.url);
          if (url === null || (!url.startsWith("https://") && !url.startsWith("http://"))) continue;
          references.push({ url, container, provider: asString(row.provider) });
        }
      }
    } catch {
      // Unparseable raw payloads degrade to the stored fields, never a throw.
    }
  }
  if (languages.length === 0 && descriptionLang !== null && descriptionLang !== "") {
    languages.push(descriptionLang);
  }
  return { descriptionLanguages: languages, references };
}

/** In-memory filter matching the explore-view semantics behind searchCves. */
export function filterPriorityItems(
  items: readonly PriorityItem[],
  filters: {
    severity: SeverityParam | null;
    kev: KevParam;
    epss: EpssParam;
    start: string | null;
    end: string | null;
  },
): PriorityItem[] {
  return items.filter((item) => {
    if (filters.kev === "listed" && !item.kevMember) return false;
    if (filters.kev === "not-listed" && item.kevMember) return false;
    if (filters.epss === "scored" && item.epss === null) return false;
    if (filters.epss === "unscored" && item.epss !== null) return false;
    if (filters.start !== null || filters.end !== null) {
      if (item.publishedAt === null) return false;
      if (filters.start !== null && item.publishedAt < filters.start) return false;
      if (filters.end !== null && item.publishedAt >= filters.end) return false;
    }
    if (filters.severity !== null && severityBandFor(item.primary) !== filters.severity)
      return false;
    return true;
  });
}

export function todayUtcDay(nowIso: string): string {
  return nowIso.slice(0, 10);
}
