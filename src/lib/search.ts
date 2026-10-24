// Local FTS5-backed CVE search over the accepted SQLite corpus.
//
// Reads current PUBLISHED records only: no nickname index, no upstream
// fallback queries. Every value-bearing statement is parameterized with `?`
// placeholders; hostile query text is tokenized into quoted FTS phrases and
// never interpolated, so a hostile input degrades to an empty result while
// the schema stays intact.
//
// Field contracts follow docs/DATA_WORKFLOW.md: UTC [start, end) date
// intervals, unknown dates in an explicit bucket, primary-CNA severity bands
// with legacy/unknown kept separate, 320-code-point excerpts with language
// fallback labels, and official CVE links built from validated IDs.

import type { CveDatabase } from "./db";
import { compareDecimalStrings, selectPrimaryCvss, type PrimaryCvss } from "./ranking";

export const DEFAULT_SEARCH_LIMIT = 20;
export const MAX_SEARCH_LIMIT = 100;
export const MAX_QUERY_LENGTH = 200;
export const MAX_FTS_TERMS = 10;
export const EXCERPT_MAX_CODE_POINTS = 320;
export const DESCRIPTION_MISSING_LABEL = "Description not supplied";

export type SeverityBand =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "none"
  | "legacy"
  | "unknown";

const SEVERITY_BANDS: ReadonlySet<string> = new Set([
  "critical",
  "high",
  "medium",
  "low",
  "none",
  "legacy",
  "unknown",
]);

export type KevFilter = "only" | "excluded" | "all";
export type EpssFilter = "present" | "absent" | "all";

export interface SearchFilters {
  q?: string;
  dateStart?: string;
  dateEnd?: string;
  severity?: readonly SeverityBand[];
  kev?: KevFilter;
  epss?: EpssFilter;
  limit?: number;
  cursor?: string | null;
}

export interface SearchResultItem {
  cveId: string;
  title: string;
  excerpt: string;
  excerptTruncated: boolean;
  langLabel: string;
  officialLink: string;
  datePublished: string | null;
  dateUpdated: string | null;
  kevMember: boolean;
  epssKnown: boolean;
  primary: PrimaryCvss | null;
  severityBand: SeverityBand;
}

export interface SearchCoverage {
  total: number;
  unknownDate: number;
  unknownSeverity: number;
  legacySeverity: number;
  kevMembers: number;
  epssKnown: number;
  bySeverity: Record<SeverityBand, number>;
}

export interface SearchResponse {
  items: SearchResultItem[];
  total: number;
  coverage: SearchCoverage;
  nextCursor: string | null;
  limit: number;
  offset: number;
}

/** A filter value failed validation: malformed date, range, page size, cursor, or band. */
export class SearchValidationError extends Error {
  readonly name = "SearchValidationError";
}

interface CandidateRow {
  cve_id: string;
  date_published: string | null;
  date_updated: string | null;
  title: string | null;
  description: string;
  description_lang: string | null;
  kev_member: number;
  epss_known: number;
}

interface MetricRow {
  cve_id: string;
  origin: string;
  version: string;
  base_score: string;
  vector: string;
  source_order: number;
}

function emptyCoverage(): SearchCoverage {
  return {
    total: 0,
    unknownDate: 0,
    unknownSeverity: 0,
    legacySeverity: 0,
    kevMembers: 0,
    epssKnown: 0,
    bySeverity: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      none: 0,
      legacy: 0,
      unknown: 0,
    },
  };
}

function emptyResponse(limit: number): SearchResponse {
  return { items: [], total: 0, coverage: emptyCoverage(), nextCursor: null, limit, offset: 0 };
}

function fail(message: string): never {
  throw new SearchValidationError(message);
}

/** Map a selected primary CNA metric to its display severity band. */
export function severityBandFor(primary: PrimaryCvss | null): SeverityBand {
  if (primary === null) return "unknown";
  if (primary.version === "2.0") return "legacy";
  const score = primary.baseScore;
  if (compareDecimalStrings(score, "0") === 0) return "none";
  if ((compareDecimalStrings(score, "3.9") ?? 1) <= 0) return "low";
  if ((compareDecimalStrings(score, "6.9") ?? 1) <= 0) return "medium";
  if ((compareDecimalStrings(score, "8.9") ?? 1) <= 0) return "high";
  return "critical";
}

/** Build the official CVE record link from a validated stored ID. */
export function officialCveLink(cveId: string): string {
  return `https://www.cve.org/CVERecord?id=${cveId}`;
}

function normalizeLangLabel(lang: unknown): string {
  if (typeof lang !== "string") return "unknown";
  const trimmed = lang.trim();
  if (trimmed === "" || trimmed.length > 32) return "unknown";
  if (/^en(-|$)/i.test(trimmed)) return "en";
  return trimmed;
}

/**
 * Truncate a description to 320 Unicode code points plus an ellipsis when
 * shortened. Missing text reports "Description not supplied" with an
 * "unknown" language label; a non-English supplied language keeps its label.
 */
export function excerptDescription(
  description: unknown,
  lang: unknown,
): { excerpt: string; langLabel: string; truncated: boolean } {
  if (typeof description !== "string" || description.trim() === "") {
    return { excerpt: DESCRIPTION_MISSING_LABEL, langLabel: "unknown", truncated: false };
  }
  const points = Array.from(description);
  if (points.length <= EXCERPT_MAX_CODE_POINTS) {
    return { excerpt: description, langLabel: normalizeLangLabel(lang), truncated: false };
  }
  return {
    excerpt: `${points.slice(0, EXCERPT_MAX_CODE_POINTS).join("")}…`,
    langLabel: normalizeLangLabel(lang),
    truncated: true,
  };
}

function normalizeDateBound(value: unknown, field: string): string | null {
  if (value === undefined) return null;
  if (typeof value !== "string" || value.trim() === "") {
    fail(`Search filter "${field}" must be a non-empty ISO date string.`);
  }
  const ms = Date.parse(value as string);
  if (!Number.isFinite(ms)) {
    fail(`Search filter "${field}" is not a parseable date: ${(value as string).slice(0, 64)}.`);
  }
  return new Date(ms).toISOString();
}

function normalizeLimit(value: unknown): number {
  if (value === undefined) return DEFAULT_SEARCH_LIMIT;
  if (!Number.isInteger(value) || (value as number) < 1 || (value as number) > MAX_SEARCH_LIMIT) {
    fail(`Search "limit" must be an integer in [1, ${MAX_SEARCH_LIMIT}].`);
  }
  return value as number;
}

function decodeOffset(cursor: unknown): number {
  if (cursor === undefined || cursor === null) return 0;
  if (typeof cursor !== "string" || cursor === "") {
    fail('Search "cursor" must be an opaque cursor returned by a previous search.');
  }
  try {
    const parsed: unknown = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
    const offset = (parsed as { offset?: unknown }).offset;
    if (!Number.isInteger(offset) || (offset as number) < 0) fail("Bad cursor offset.");
    return offset as number;
  } catch (error) {
    if (error instanceof SearchValidationError) throw error;
    fail('Search "cursor" is not a cursor returned by a previous search.');
  }
}

function encodeOffset(offset: number): string {
  return Buffer.from(JSON.stringify({ offset }), "utf8").toString("base64url");
}

function normalizeQuery(value: unknown): string {
  if (value === undefined) return "";
  if (typeof value !== "string") fail('Search "q" must be a string.');
  const trimmed = (value as string).trim();
  if (trimmed.length > MAX_QUERY_LENGTH) {
    fail(`Search "q" exceeds ${MAX_QUERY_LENGTH} characters.`);
  }
  return trimmed;
}

function normalizeSeverity(value: unknown): ReadonlySet<SeverityBand> | null {
  if (value === undefined) return null;
  if (!Array.isArray(value)) fail('Search "severity" must be an array of band names.');
  const bands = new Set<SeverityBand>();
  for (const entry of value as unknown[]) {
    if (typeof entry !== "string" || !SEVERITY_BANDS.has(entry)) {
      fail(`Unknown severity band: ${String(entry).slice(0, 32)}.`);
    }
    bands.add(entry as SeverityBand);
  }
  return bands.size === 0 ? null : bands;
}

/** True when the query is shaped like a CVE ID or ID prefix (letters/digits/hyphens only). */
function idPrefixOf(query: string): string | null {
  if (!/^cve[-\d]*$/i.test(query.replace(/\s+/g, ""))) return null;
  const compact = query.replace(/\s+/g, "").toUpperCase();
  if (!compact.startsWith("CVE")) return null;
  if (!/^CVE(-\d{0,4}(-\d{0,7})?)?$/.test(compact)) return null;
  return compact;
}

function escapeLikePattern(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
}

/**
 * Reduce hostile input to safe FTS phrases: keep up to 10 alphanumeric
 * tokens, quote each as a phrase so operators stay literal. Returns null
 * when no searchable token remains (safe empty result, never a throw).
 */
function buildSafeFtsMatch(query: string): string | null {
  const tokens = query.match(/[A-Za-z0-9]+/g);
  if (tokens === null || tokens.length === 0) return null;
  const terms = tokens.slice(0, MAX_FTS_TERMS);
  return terms.map((term) => `"${term}"`).join(" AND ");
}

/**
 * FTS5-backed ID/text search over PUBLISHED records with UTC date-range,
 * primary-CNA severity-band, KEV-membership, and EPSS-presence filters.
 * Results carry 320-code-point excerpts, coverage counts with unknown
 * buckets, and an opaque cursor for the next page.
 */
export function searchCves(db: CveDatabase, filters: SearchFilters): SearchResponse {
  const normalized = filters ?? {};
  const q = normalizeQuery(normalized.q);
  const dateStart = normalizeDateBound(normalized.dateStart, "dateStart");
  const dateEnd = normalizeDateBound(normalized.dateEnd, "dateEnd");
  if (dateStart !== null && dateEnd !== null && dateStart >= dateEnd) {
    fail('Search "dateStart" must be earlier than "dateEnd" (UTC [start, end)).');
  }
  const severityFilter = normalizeSeverity(normalized.severity);
  if (normalized.kev !== undefined && !["only", "excluded", "all"].includes(normalized.kev)) {
    fail('Search "kev" must be "only", "excluded", or "all".');
  }
  if (normalized.epss !== undefined && !["present", "absent", "all"].includes(normalized.epss)) {
    fail('Search "epss" must be "present", "absent", or "all".');
  }
  const kev = normalized.kev ?? "all";
  const epss = normalized.epss ?? "all";
  const limit = normalizeLimit(normalized.limit);
  const offset = decodeOffset(normalized.cursor);

  const idPrefix = q === "" ? null : idPrefixOf(q);
  let ftsMatch: string | null = null;
  if (q !== "" && idPrefix === null) {
    ftsMatch = buildSafeFtsMatch(q);
    if (ftsMatch === null) return emptyResponse(limit);
  }

  const where: string[] = ["r.state = ?"];
  const params: unknown[] = ["PUBLISHED"];
  if (idPrefix !== null) {
    if (/^CVE-\d{4}-\d{4,}$/.test(idPrefix)) {
      where.push("r.cve_id = ?");
      params.push(idPrefix);
    } else {
      where.push("r.cve_id LIKE ? ESCAPE '\\'");
      params.push(`${escapeLikePattern(idPrefix)}%`);
    }
  }
  if (dateStart !== null) {
    where.push("r.date_published >= ?");
    params.push(dateStart);
  }
  if (dateEnd !== null) {
    where.push("r.date_published < ?");
    params.push(dateEnd);
  }
  if (kev === "only") {
    where.push("EXISTS (SELECT 1 FROM kev_entries k WHERE k.cve_id = r.cve_id)");
  } else if (kev === "excluded") {
    where.push("NOT EXISTS (SELECT 1 FROM kev_entries k WHERE k.cve_id = r.cve_id)");
  }
  if (epss === "present") {
    where.push("EXISTS (SELECT 1 FROM epss_daily e WHERE e.cve_id = r.cve_id)");
  } else if (epss === "absent") {
    where.push("NOT EXISTS (SELECT 1 FROM epss_daily e WHERE e.cve_id = r.cve_id)");
  }

  const selectList =
    "r.cve_id AS cve_id, r.date_published AS date_published, " +
    "r.date_updated AS date_updated, r.title AS title, r.description AS description, " +
    "r.description_lang AS description_lang, " +
    "EXISTS (SELECT 1 FROM kev_entries k WHERE k.cve_id = r.cve_id) AS kev_member, " +
    "EXISTS (SELECT 1 FROM epss_daily e WHERE e.cve_id = r.cve_id) AS epss_known";

  let sql: string;
  if (ftsMatch !== null) {
    sql =
      `SELECT ${selectList}, bm25(cve_fts) AS fts_rank FROM cve_records r ` +
      `JOIN cve_fts ON cve_fts.cve_id = r.cve_id ` +
      `WHERE cve_fts MATCH ? AND ${where.join(" AND ")} ` +
      `ORDER BY fts_rank ASC, r.cve_id ASC`;
    params.unshift(ftsMatch);
  } else {
    sql =
      `SELECT ${selectList} FROM cve_records r WHERE ${where.join(" AND ")} ` +
      `ORDER BY (r.date_published IS NULL) ASC, r.date_published DESC, r.cve_id ASC`;
  }

  let candidates: CandidateRow[];
  try {
    candidates = db.handle.prepare(sql).all(...params) as CandidateRow[];
  } catch {
    return emptyResponse(limit);
  }

  const metricsById = loadPrimaryById(db, candidates.map((row) => row.cve_id));

  const items: SearchResultItem[] = [];
  const coverage = emptyCoverage();
  for (const row of candidates) {
    const primary = metricsById.get(row.cve_id) ?? null;
    const band = severityBandFor(primary);
    if (severityFilter !== null && !severityFilter.has(band)) continue;
    const excerpt = excerptDescription(row.description, row.description_lang);
    items.push({
      cveId: row.cve_id,
      title:
        typeof row.title === "string" && row.title.trim() !== "" ? row.title : row.cve_id,
      excerpt: excerpt.excerpt,
      excerptTruncated: excerpt.truncated,
      langLabel: excerpt.langLabel,
      officialLink: officialCveLink(row.cve_id),
      datePublished: row.date_published,
      dateUpdated: row.date_updated,
      kevMember: row.kev_member === 1,
      epssKnown: row.epss_known === 1,
      primary,
      severityBand: band,
    });
    coverage.total += 1;
    coverage.bySeverity[band] += 1;
    if (row.date_published === null) coverage.unknownDate += 1;
    if (band === "unknown") coverage.unknownSeverity += 1;
    if (band === "legacy") coverage.legacySeverity += 1;
    if (row.kev_member === 1) coverage.kevMembers += 1;
    if (row.epss_known === 1) coverage.epssKnown += 1;
  }

  const page = items.slice(offset, offset + limit);
  const nextCursor = offset + limit < items.length ? encodeOffset(offset + limit) : null;
  return { items: page, total: coverage.total, coverage, nextCursor, limit, offset };
}

function loadPrimaryById(
  db: CveDatabase,
  cveIds: readonly string[],
): Map<string, PrimaryCvss | null> {
  const result = new Map<string, PrimaryCvss | null>();
  for (const cveId of cveIds) result.set(cveId, null);
  if (cveIds.length === 0) return result;
  const placeholders = cveIds.map(() => "?").join(", ");
  const rows = db.handle
    .prepare(
      `SELECT cve_id, origin, version, base_score, vector, source_order FROM cvss_metrics ` +
        `WHERE cve_id IN (${placeholders}) ORDER BY cve_id ASC, source_order ASC`,
    )
    .all(...cveIds) as MetricRow[];
  const grouped = new Map<string, MetricRow[]>();
  for (const row of rows) {
    const list = grouped.get(row.cve_id);
    if (list === undefined) grouped.set(row.cve_id, [row]);
    else list.push(row);
  }
  for (const [cveId, metrics] of grouped) {
    result.set(
      cveId,
      selectPrimaryCvss(
        metrics.map((metric, index) => ({
          origin: metric.origin,
          version: metric.version,
          baseScore: metric.base_score,
          vector: metric.vector,
          sourceOrder:
            Number.isInteger(metric.source_order) ? (metric.source_order as number) : index,
        })),
      ),
    );
  }
  return result;
}
