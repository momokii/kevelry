// Shared helpers for the versioned read-only v1 API routes.
//
// Every helper reads the same accepted local snapshots the site reads: the
// priority/ranking/search/radar services over SQLite. No route issues its own
// SQL for cohorts or ordering except through those services or through the
// small loaders below that reuse the services' selection rules
// (selectPrimaryCvss, severityBandFor, excerptDescription). No upstream fetch
// happens here; every success and every error carries provenance with
// per-source dates plus the ranking policy version, and every response
// carries the rate-limit headers.

import { loadConfig } from "../../../../src/lib/config";
import { type CveDatabase, openDatabase } from "../../../../src/lib/db";
import { getAcceptedEpssDate, type PriorityItem } from "../../../../src/lib/priority";
import {
  diffCheckpoints,
  type RadarChangeKind,
  type RadarItemSnapshot,
  type StoredRadarCheckpoint,
} from "../../../../src/lib/radar";
import {
  excerptDescription,
  officialCveLink,
  severityBandFor,
  DESCRIPTION_MISSING_LABEL,
} from "../../../../src/lib/search";
import { selectPrimaryCvss } from "../../../../src/lib/ranking";

/** Ranking policy version pinned into every provenance envelope. */
export const RANKING_POLICY_VERSION = "ranking-v1";

/** Public rate budget surfaced on every response. */
export const RATE_LIMIT_MAX = 600;
export const RATE_LIMIT_WINDOW_SECONDS = 60;

/** Request bounds: oversized request lines and param floods are rejected. */
export const MAX_URL_CHARS = 4096;
export const MAX_QUERY_PARAMS = 25;
export const MAX_CURSOR_CHARS = 512;

/** Concurrency bound: in-flight route executions past this get a 429. */
export const MAX_CONCURRENT_REQUESTS = 32;

/** Default wall-clock budget for the unbounded search fan-out loop. */
export const SEARCH_TIME_BUDGET_MS = 3000;

/** API page default and hard cap. Oversized values are rejected, never clamped. */
export const API_DEFAULT_LIMIT = 50;
export const API_MAX_LIMIT = 200;

/** Validated CVE ID shape shared by path and query params. */
export const CVE_ID_RE = /^CVE-[0-9]{4}-[0-9]{4,}$/;

const DAY_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;

export const REUSE_NOTICES: readonly string[] = [
  "CVE content reproduced per MITRE CVE Terms of Use.",
  "KEV catalog data under CC0 1.0; third-party links and CISA/DHS marks not covered.",
  "EPSS scores by FIRST.org; attribution retained per services terms.",
];

// ---------------------------------------------------------------------------
// Database handle (override seam for hermetic tests).
// ---------------------------------------------------------------------------

let dbOverride: CveDatabase | null = null;
let cached: { dir: string; db: CveDatabase } | null = null;

export function setDbOverride(db: CveDatabase): void {
  dbOverride = db;
}

export function resetDbOverride(): void {
  dbOverride = null;
}

export function getDb(): CveDatabase {
  if (dbOverride !== null) return dbOverride;
  const config = loadConfig(process.env);
  if (cached !== null && cached.dir === config.dataDir) return cached.db;
  const db = openDatabase({ dataDir: config.dataDir });
  cached = { dir: config.dataDir, db };
  return db;
}

// ---------------------------------------------------------------------------
// Rate limiting (in-memory fixed window per client key).
// ---------------------------------------------------------------------------

interface RateBucket {
  count: number;
  resetAt: number;
}

const rateBuckets = new Map<string, RateBucket>();

export function resetRateLimits(): void {
  rateBuckets.clear();
}

export function clientKeyFor(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded !== null && forwarded.trim() !== "") {
    const first = forwarded.split(",")[0]?.trim();
    if (first !== undefined && first !== "") return first;
  }
  const realIp = request.headers.get("x-real-ip");
  if (realIp !== null && realIp.trim() !== "") return realIp.trim();
  return "local";
}

export function checkRateLimit(
  key: string,
  nowMs: number = Date.now(),
): { allowed: boolean; remaining: number; reset: number } {
  const entry = rateBuckets.get(key);
  if (entry === undefined || nowMs >= entry.resetAt) {
    const resetAt = nowMs + RATE_LIMIT_WINDOW_SECONDS * 1000;
    rateBuckets.set(key, { count: 1, resetAt });
    return { allowed: true, remaining: RATE_LIMIT_MAX - 1, reset: RATE_LIMIT_WINDOW_SECONDS };
  }
  if (entry.count >= RATE_LIMIT_MAX) {
    return {
      allowed: false,
      remaining: 0,
      reset: Math.max(0, Math.ceil((entry.resetAt - nowMs) / 1000)),
    };
  }
  entry.count += 1;
  return {
    allowed: true,
    remaining: RATE_LIMIT_MAX - entry.count,
    reset: Math.max(0, Math.ceil((entry.resetAt - nowMs) / 1000)),
  };
}

function applyRateHeaders(
  response: Response,
  limit: { remaining: number; reset: number },
): Response {
  response.headers.set("X-RateLimit-Limit", String(RATE_LIMIT_MAX));
  response.headers.set("X-RateLimit-Remaining", String(limit.remaining));
  response.headers.set("X-RateLimit-Reset", String(limit.reset));
  return response;
}

let activeRequests = 0;
let maxConcurrentRequests = MAX_CONCURRENT_REQUESTS;
let searchBudgetMs = SEARCH_TIME_BUDGET_MS;
let allowedOrigins: string[] = [];

export function setMaxConcurrentRequests(value: number): void {
  maxConcurrentRequests = value;
}

export function setSearchBudgetMs(value: number): void {
  searchBudgetMs = value;
}

export function setAllowedOrigins(origins: string[]): void {
  allowedOrigins = [...origins];
}

export function resetHardeningState(): void {
  activeRequests = 0;
  maxConcurrentRequests = MAX_CONCURRENT_REQUESTS;
  searchBudgetMs = SEARCH_TIME_BUDGET_MS;
  allowedOrigins = [];
  rateBuckets.clear();
}

export function getSearchBudgetMs(): number {
  return searchBudgetMs;
}

export function acquireConcurrencySlot(): boolean {
  if (activeRequests >= maxConcurrentRequests) return false;
  activeRequests += 1;
  return true;
}

export function releaseConcurrencySlot(): void {
  activeRequests = Math.max(0, activeRequests - 1);
}

export function searchBudgetExceeded(startedAtMs: number, nowMs: number = Date.now()): boolean {
  return nowMs - startedAtMs >= searchBudgetMs;
}

function applySecurityHeaders(response: Response): Response {
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set(
    "Content-Security-Policy",
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  );
  response.headers.set("Referrer-Policy", "no-referrer");
  return response;
}

function applyCorsHeaders(request: Request, response: Response): Response {
  const origin = request.headers.get("origin");
  if (origin === null || origin === "") return response;
  response.headers.set("Vary", "Origin");
  if (allowedOrigins.includes(origin)) {
    response.headers.set("Access-Control-Allow-Origin", origin);
    response.headers.set("Access-Control-Allow-Methods", "GET, OPTIONS");
    response.headers.set("Access-Control-Max-Age", "600");
  }
  return response;
}

export function preflightResponse(request: Request): Response {
  const response = new Response(null, { status: 204 });
  applySecurityHeaders(response);
  applyCorsHeaders(request, response);
  return response;
}

export function assertRequestBounds(request: Request): void {
  if (request.url.length > MAX_URL_CHARS) {
    throw new ApiError("BAD_REQUEST", 400, "Request is too large to handle.");
  }
  const count = new URL(request.url).searchParams.size;
  if (count > MAX_QUERY_PARAMS) {
    throw new ApiError("BAD_REQUEST", 400, "Too many query parameters.");
  }
}

// ---------------------------------------------------------------------------
// Provenance.
// ---------------------------------------------------------------------------

export interface SourceProvenance {
  revision?: string | null;
  catalogVersion?: string | null;
  scoreDate?: string | null;
  modelVersion?: string | null;
  lastCheckedAt: string | null;
  lastAcceptedAt: string | null;
  stale: boolean;
  error: string | null;
}

export interface Provenance {
  rankingPolicyVersion: string;
  generatedAt: string;
  sources: {
    cve: SourceProvenance;
    kev: SourceProvenance;
    epss: SourceProvenance;
  };
}

interface SyncRun {
  started_at: string;
  finished_at: string | null;
  status: string;
  revision: string | null;
  error: string | null;
}

function latestRun(db: CveDatabase, source: string): SyncRun | undefined {
  return db.handle
    .prepare(
      "SELECT started_at, finished_at, status, revision, error FROM sync_runs WHERE source = ? ORDER BY id DESC LIMIT 1",
    )
    .get(source) as SyncRun | undefined;
}

function latestSucceeded(db: CveDatabase, source: string): SyncRun | undefined {
  return db.handle
    .prepare(
      "SELECT started_at, finished_at, status, revision, error FROM sync_runs WHERE source = ? AND status = ? ORDER BY id DESC LIMIT 1",
    )
    .get(source, "succeeded") as SyncRun | undefined;
}

function singleText(db: CveDatabase, sql: string, params: unknown[] = []): string | null {
  const row = db.handle.prepare(sql).get(...params) as Record<string, unknown> | undefined;
  if (row === undefined) return null;
  const value = Object.values(row)[0];
  return typeof value === "string" ? value : null;
}

function parseEpssRevision(revision: string | null): {
  scoreDate: string | null;
  modelVersion: string | null;
} {
  if (revision === null) return { scoreDate: null, modelVersion: null };
  const at = revision.indexOf("@");
  if (at <= 0) return { scoreDate: null, modelVersion: null };
  const scoreDate = revision.slice(0, at);
  const modelVersion = revision.slice(at + 1);
  if (!DAY_RE.test(scoreDate) || modelVersion === "")
    return { scoreDate: null, modelVersion: null };
  return { scoreDate, modelVersion };
}

function staleAfterHours(lastAcceptedAt: string | null, nowMs: number, hours: number): boolean {
  if (lastAcceptedAt === null) return false;
  const acceptedMs = Date.parse(lastAcceptedAt);
  if (!Number.isFinite(acceptedMs)) return false;
  return nowMs - acceptedMs > hours * 3_600_000;
}

function epssStale(scoreDate: string | null, nowIso: string): boolean {
  if (scoreDate === null || !DAY_RE.test(scoreDate)) return false;
  const today = nowIso.slice(0, 10);
  if (!DAY_RE.test(today)) return false;
  const ageDays =
    (Date.parse(`${today}T00:00:00.000Z`) - Date.parse(`${scoreDate}T00:00:00.000Z`)) / 86_400_000;
  return ageDays > 2;
}

function sourceError(run: SyncRun | undefined): string | null {
  if (run === undefined || run.status !== "failed") return null;
  return typeof run.error === "string" && run.error !== "" ? run.error : "refresh failed";
}

export function buildProvenance(db: CveDatabase | null, nowIso: string): Provenance {
  const nowMs = Date.parse(nowIso);
  const safeNowMs = Number.isFinite(nowMs) ? nowMs : Date.now();
  const fallback = {
    lastCheckedAt: null as string | null,
    lastAcceptedAt: null as string | null,
    stale: false,
    error: null as string | null,
  };
  if (db === null) {
    return {
      rankingPolicyVersion: RANKING_POLICY_VERSION,
      generatedAt: nowIso,
      sources: {
        cve: { revision: null, ...fallback },
        kev: { catalogVersion: null, ...fallback },
        epss: { scoreDate: null, modelVersion: null, ...fallback },
      },
    };
  }
  const cveRun = latestRun(db, "cve");
  const cveOk = latestSucceeded(db, "cve");
  const kevRun = latestRun(db, "kev");
  const kevOk = latestSucceeded(db, "kev");
  const epssRun = latestRun(db, "epss");
  const epssOk = latestSucceeded(db, "epss");

  const cveRevision =
    cveOk?.revision ?? singleText(db, "SELECT MAX(source_revision) FROM cve_records") ?? null;
  const kevCatalog =
    kevOk?.revision ?? singleText(db, "SELECT MAX(catalog_date) FROM kev_entries") ?? null;
  const parsed = parseEpssRevision(epssOk?.revision ?? null);
  const acceptedDate = parsed.scoreDate ?? getAcceptedEpssDate(db);
  const acceptedModel =
    parsed.modelVersion ??
    (acceptedDate === null
      ? null
      : (singleText(
          db,
          "SELECT model_version FROM epss_daily WHERE score_date = ? ORDER BY model_version DESC LIMIT 1",
          [acceptedDate],
        ) ?? null));
  const epssScoreDate = parsed.scoreDate ?? acceptedDate;
  const epssModel = parsed.modelVersion ?? (parsed.scoreDate !== null ? null : acceptedModel);

  const cveAccepted = cveOk?.finished_at ?? cveOk?.started_at ?? null;
  const kevAccepted = kevOk?.finished_at ?? kevOk?.started_at ?? null;
  const epssAccepted = epssOk?.finished_at ?? epssOk?.started_at ?? null;
  return {
    rankingPolicyVersion: RANKING_POLICY_VERSION,
    generatedAt: nowIso,
    sources: {
      cve: {
        revision: cveRevision,
        lastCheckedAt: cveRun?.finished_at ?? cveRun?.started_at ?? null,
        lastAcceptedAt: cveAccepted,
        stale: staleAfterHours(cveAccepted, safeNowMs, 3),
        error: sourceError(cveRun),
      },
      kev: {
        catalogVersion: kevCatalog,
        lastCheckedAt: kevRun?.finished_at ?? kevRun?.started_at ?? null,
        lastAcceptedAt: kevAccepted,
        stale: staleAfterHours(kevAccepted, safeNowMs, 3),
        error: sourceError(kevRun),
      },
      epss: {
        scoreDate: epssScoreDate,
        modelVersion: epssModel,
        lastCheckedAt: epssRun?.finished_at ?? epssRun?.started_at ?? null,
        lastAcceptedAt: epssAccepted,
        stale: epssStale(epssScoreDate, nowIso),
        error: sourceError(epssRun),
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Errors and responses.
// ---------------------------------------------------------------------------

export type ErrorCode =
  | "BAD_REQUEST"
  | "BAD_CURSOR"
  | "BAD_LIMIT"
  | "BAD_QUERY"
  | "BAD_FILTER"
  | "BAD_DATE_RANGE"
  | "CVE_NOT_FOUND"
  | "LIST_NOT_FOUND"
  | "CHECKPOINT_UNAVAILABLE"
  | "REPLAY_UNAVAILABLE"
  | "RATE_LIMITED"
  | "INTERNAL";

export class ApiError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly details?: Record<string, unknown>;

  constructor(code: ErrorCode, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

function requestId(): string {
  return `req-${Date.now().toString(36)}${Math.floor(Math.random() * 0xffffff)
    .toString(36)
    .padStart(4, "0")}`;
}

function errorStatus(code: ErrorCode): number {
  switch (code) {
    case "CVE_NOT_FOUND":
    case "LIST_NOT_FOUND":
    case "CHECKPOINT_UNAVAILABLE":
    case "REPLAY_UNAVAILABLE":
      return 404;
    case "RATE_LIMITED":
      return 429;
    case "INTERNAL":
      return 500;
    default:
      return 400;
  }
}

export interface RateReservation {
  allowed: boolean;
  remaining: number;
  reset: number;
}

export function errorResponse(
  request: Request,
  code: ErrorCode,
  message: string,
  db: CveDatabase | null,
  details?: Record<string, unknown>,
  reservation?: RateReservation,
): Response {
  const provenance = buildProvenance(db, new Date().toISOString());
  const status = errorStatus(code);
  const body: Record<string, unknown> = { code, message, requestId: requestId(), provenance };
  if (details !== undefined) body.details = details;
  const response = Response.json(body, { status });
  const rate = reservation ?? checkRateLimit(clientKeyFor(request));
  applyRateHeaders(response, rate);
  applySecurityHeaders(response);
  applyCorsHeaders(request, response);
  if (status === 429) {
    response.headers.set("Retry-After", String(Math.max(rate.reset, 1)));
  }
  return response;
}

export function okResponse(
  request: Request,
  payload: Record<string, unknown>,
  reservation?: RateReservation,
): Response {
  const response = Response.json(payload);
  applyRateHeaders(response, reservation ?? checkRateLimit(clientKeyFor(request)));
  applySecurityHeaders(response);
  applyCorsHeaders(request, response);
  return response;
}

/**
 * Reserve one hit from the per-IP fixed window. Handlers call this first and
 * thread the reservation through every ok/error response so each request is
 * counted exactly once. Returns null when the budget is spent.
 */
export function reserveRateLimit(
  request: Request,
  db: CveDatabase | null,
): RateReservation | Response {
  const rate = checkRateLimit(clientKeyFor(request));
  if (!rate.allowed) {
    return errorResponse(
      request,
      "RATE_LIMITED",
      "Rate limit exceeded. Retry after 60 seconds.",
      db,
      undefined,
      rate,
    );
  }
  return rate;
}

// ---------------------------------------------------------------------------
// Pagination and shared param parsing.
// ---------------------------------------------------------------------------

export function parseLimit(raw: string | null): number {
  if (raw === null || raw === "") return API_DEFAULT_LIMIT;
  if (!/^[0-9]+$/.test(raw)) {
    throw new ApiError("BAD_LIMIT", 400, "limit must be an integer between 1 and 200.");
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > API_MAX_LIMIT) {
    throw new ApiError("BAD_LIMIT", 400, "limit must be an integer between 1 and 200.");
  }
  return value;
}

export function encodeCursor(offset: number): string {
  return Buffer.from(JSON.stringify({ offset }), "utf8").toString("base64url");
}

export function parseCursor(raw: string | null): number {
  if (raw === null || raw === "") return 0;
  if (raw.length > MAX_CURSOR_CHARS) {
    throw new ApiError(
      "BAD_CURSOR",
      400,
      "cursor is not a cursor returned by a previous response.",
    );
  }
  try {
    const text = Buffer.from(raw, "base64url").toString("utf8");
    const parsed: unknown = JSON.parse(text);
    const offset = (parsed as { offset?: unknown }).offset;
    if (!Number.isInteger(offset) || (offset as number) < 0) {
      throw new ApiError(
        "BAD_CURSOR",
        400,
        "cursor is not a cursor returned by a previous response.",
      );
    }
    return offset as number;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      "BAD_CURSOR",
      400,
      "cursor is not a cursor returned by a previous response.",
    );
  }
}

export function paginate<T>(
  items: readonly T[],
  offset: number,
  limit: number,
): { page: T[]; hasMore: boolean; nextCursor: string | null } {
  const page = items.slice(offset, offset + limit);
  const hasMore = offset + limit < items.length;
  return { page, hasMore, nextCursor: hasMore ? encodeCursor(offset + limit) : null };
}

/**
 * Pagination over a bounded fetch of `offset + limit + 1` rows (one-row
 * probe). The extra row proves a next page exists without materializing the
 * full corpus; callers fetch the cap via the limit-aware priority getters.
 * Edge: when the total is exactly offset+limit+1 the probe reports one more
 * page that returns empty — a bounded-fetch artifact, never wrong data.
 */
export function paginateCapped<T>(
  items: readonly T[],
  offset: number,
  limit: number,
): { page: T[]; hasMore: boolean; nextCursor: string | null } {
  const page = items.slice(offset, offset + limit);
  const hasMore = items.length > offset + limit;
  return { page, hasMore, nextCursor: hasMore ? encodeCursor(offset + limit) : null };
}

export type KevParam = "listed" | "not-listed" | "any";
export type EpssParam = "scored" | "unscored" | "any";
export type SeverityParam = "critical" | "high" | "medium" | "low" | "unknown" | "legacy";

const SEVERITIES: readonly string[] = ["critical", "high", "medium", "low", "unknown", "legacy"];

export function parseSeverity(raw: string | null): SeverityParam | null {
  if (raw === null || raw === "") return null;
  if (!SEVERITIES.includes(raw)) {
    throw new ApiError("BAD_FILTER", 400, `severity must be one of ${SEVERITIES.join(", ")}.`);
  }
  return raw as SeverityParam;
}

export function parseKev(raw: string | null): KevParam {
  if (raw === null || raw === "" || raw === "any") return "any";
  if (raw !== "listed" && raw !== "not-listed") {
    throw new ApiError("BAD_FILTER", 400, "kev must be listed, not-listed, or any.");
  }
  return raw;
}

export function parseEpss(raw: string | null): EpssParam {
  if (raw === null || raw === "" || raw === "any") return "any";
  if (raw !== "scored" && raw !== "unscored") {
    throw new ApiError("BAD_FILTER", 400, "epss must be scored, unscored, or any.");
  }
  return raw;
}

export function parseDateBound(raw: string | null, name: string): string | null {
  if (raw === null || raw === "") return null;
  const ms = Date.parse(raw);
  if (!Number.isFinite(ms)) {
    throw new ApiError("BAD_DATE_RANGE", 400, `${name} is not a parseable RFC 3339 timestamp.`);
  }
  return new Date(ms).toISOString();
}

export function parseDay(raw: string | null, name: string, required: boolean): string {
  if (raw === null || raw === "") {
    if (required) throw new ApiError("BAD_REQUEST", 400, `${name} is required as YYYY-MM-DD.`);
    throw new ApiError("BAD_REQUEST", 400, `${name} is required as YYYY-MM-DD.`);
  }
  if (!DAY_RE.test(raw)) {
    throw new ApiError("BAD_FILTER", 400, `${name} must be a UTC date shaped YYYY-MM-DD.`);
  }
  const ms = Date.parse(`${raw}T00:00:00.000Z`);
  if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 10) !== raw) {
    throw new ApiError("BAD_FILTER", 400, `${name} must be a real UTC calendar date.`);
  }
  return raw;
}

const HOSTILE_QUERY_TOKENS: readonly string[] = [
  "--",
  "/*",
  "*/",
  "drop table",
  "union select",
  "' or '",
  '" or "',
  ";",
];

function hasControlChars(value: string): boolean {
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 32 || code === 127) return true;
  }
  return false;
}

const SSRF_SHAPED_PATTERNS: readonly RegExp[] = [
  /[a-z][a-z0-9+.-]*:\/\//,
  /\blocalhost\b/,
  /(^|[^0-9])0\.0\.0\.0([^0-9]|$)/,
  /(^|[^0-9])(10|127)\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)/,
  /(^|[^0-9])192\.168\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)/,
  /(^|[^0-9])172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)/,
  /(^|[^0-9])169\.254\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)/,
  /\[::|::ffff|::1/,
];

/** Validate the search query; injection-shaped input is rejected, never run. */
export function parseQuery(raw: string | null): string {
  if (raw === null) {
    throw new ApiError("BAD_QUERY", 400, "q is required and must be 2 to 200 characters.");
  }
  const trimmed = raw.trim();
  if (trimmed.length < 2 || trimmed.length > 200) {
    throw new ApiError("BAD_QUERY", 400, "q must be 2 to 200 characters.");
  }
  if (hasControlChars(trimmed)) {
    throw new ApiError("BAD_QUERY", 400, "q contains unsupported control characters.");
  }
  const lowered = trimmed.toLowerCase();
  for (const pattern of SSRF_SHAPED_PATTERNS) {
    if (pattern.test(lowered)) {
      throw new ApiError("BAD_QUERY", 400, "q looks like a network address and was rejected.");
    }
  }
  for (const token of HOSTILE_QUERY_TOKENS) {
    if (lowered.includes(token)) {
      throw new ApiError("BAD_QUERY", 400, "q looks like an injection attempt and was rejected.");
    }
  }
  return trimmed;
}

// ---------------------------------------------------------------------------
// Full record loading over the accepted tables.
// ---------------------------------------------------------------------------

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
  epssText: string | null;
  epssPercentile: string | null;
  epssModel: string | null;
  primary: { version: string; baseScore: string; vector: string } | null;
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
  version: string;
  base_score: string;
  vector: string;
  source_order: number;
}

function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    out.push(items.slice(index, index + size));
  }
  return out;
}

/** Load full display records for ids, preserving input order and skipping gaps. */
export function loadFullRecords(db: CveDatabase, ids: readonly string[]): FullRecord[] {
  if (ids.length === 0) return [];
  const unique = [...new Set(ids)];
  const records = new Map<string, RecordRow>();
  const kevDates = new Map<string, string>();
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
      .prepare(`SELECT cve_id, date_added FROM kev_entries WHERE cve_id IN (${placeholders})`)
      .all(...group) as KevRow[];
    for (const row of kevRows) kevDates.set(row.cve_id, row.date_added);
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
    const metricRows = db.handle
      .prepare(
        `SELECT cve_id, origin, version, base_score, vector, source_order FROM cvss_metrics WHERE cve_id IN (${placeholders})`,
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
    const primary = selectPrimaryCvss(
      metrics.map((metric, index) => ({
        origin: metric.origin,
        version: metric.version,
        baseScore: metric.base_score,
        vector: metric.vector,
        sourceOrder: Number.isInteger(metric.source_order) ? metric.source_order : index,
      })),
    );
    const epss = epssById.get(cveId);
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
      epssText: epss?.epss ?? null,
      epssPercentile: epss?.percentile ?? null,
      epssModel: epss?.model_version ?? null,
      primary:
        primary === null
          ? null
          : { version: primary.version, baseScore: primary.baseScore, vector: primary.vector },
      hasAdp: metrics.some((metric) => metric.origin === "ADP"),
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Response shaping (CveItem / CveDetail per openapi/v1.yaml).
// ---------------------------------------------------------------------------

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
    kev: { listed: record.kevDateAdded !== null, dateAdded: record.kevDateAdded },
    epss,
    cvssPrimary,
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

export type RadarApiKind =
  | "kev-added"
  | "kev-removed"
  | "cna-changed"
  | "forecast-changed"
  | "corrected"
  | "rejected"
  | "list-entered"
  | "list-exited"
  | "rank-moved";

export const RADAR_API_KINDS: readonly RadarApiKind[] = [
  "kev-added",
  "kev-removed",
  "cna-changed",
  "forecast-changed",
  "corrected",
  "rejected",
  "list-entered",
  "list-exited",
  "rank-moved",
];

export interface RadarApiEvent {
  eventId: string;
  checkpointDate: string;
  observedAt: string;
  kind: RadarApiKind;
  cveId: string;
  title: string;
  changes: Array<{ field: string; before: string | null; after: string | null }>;
  sourceRevision: string;
  reason: string;
}

const KIND_PRIORITY: readonly RadarApiKind[] = [
  "kev-added",
  "kev-removed",
  "cna-changed",
  "forecast-changed",
  "corrected",
  "rejected",
  "list-entered",
  "list-exited",
  "rank-moved",
];

function mapServiceKinds(kinds: readonly RadarChangeKind[]): RadarApiKind[] {
  const mapped = kinds.map((kind): RadarApiKind => {
    switch (kind) {
      case "kev-added":
        return "kev-added";
      case "kev-removed":
        return "kev-removed";
      case "cna-changed":
        return "cna-changed";
      case "forecast-changed":
        return "forecast-changed";
      case "model-changed":
        return "forecast-changed";
      case "corrected":
        return "corrected";
      case "rejected":
        return "rejected";
      case "added":
        return "list-entered";
      case "removed":
        return "list-exited";
      case "rank-only-move":
        return "rank-moved";
    }
  });
  const seen = new Set<RadarApiKind>();
  const ordered: RadarApiKind[] = [];
  for (const kind of KIND_PRIORITY) {
    if (mapped.includes(kind) && !seen.has(kind)) {
      seen.add(kind);
      ordered.push(kind);
    }
  }
  return ordered;
}

function snapshotPrimaryText(item: RadarItemSnapshot): string {
  if (item.primaryVersion === null) return "unknown";
  return `${item.primaryVersion} ${item.primaryBaseScore ?? "unknown"} ${item.primaryVector ?? ""}`.trim();
}

function kindChanges(
  kind: RadarApiKind,
  before: RadarItemSnapshot | undefined,
  after: RadarItemSnapshot | undefined,
): Array<{ field: string; before: string | null; after: string | null }> {
  switch (kind) {
    case "kev-added":
      return [
        { field: "kev.listed", before: "false", after: "true" },
        { field: "kev.dateAdded", before: null, after: after?.dateAdded ?? null },
      ];
    case "kev-removed":
      return [
        { field: "kev.listed", before: "true", after: "false" },
        { field: "kev.dateAdded", before: before?.dateAdded ?? null, after: null },
      ];
    case "cna-changed":
      return [
        {
          field: "cna.primary",
          before: before === undefined ? null : snapshotPrimaryText(before),
          after: after === undefined ? null : snapshotPrimaryText(after),
        },
      ];
    case "forecast-changed":
      return [
        {
          field: "epss.value",
          before: before?.epss ?? null,
          after: after?.epss ?? null,
        },
      ];
    case "corrected":
      return [
        {
          field: "record.state",
          before: before?.state ?? null,
          after: after?.state ?? null,
        },
      ];
    case "rejected":
      return [
        {
          field: "record.state",
          before: before?.state ?? null,
          after: after?.state ?? null,
        },
      ];
    case "list-entered":
      return [{ field: "record.firstSeen", before: null, after: after?.publishedAt ?? null }];
    case "list-exited":
      return [{ field: "record.lastSeen", before: before?.publishedAt ?? null, after: null }];
    case "rank-moved":
      return [];
  }
}

function kindSourceRevision(kind: RadarApiKind, after: StoredRadarCheckpoint): string {
  switch (kind) {
    case "kev-added":
    case "kev-removed":
      return `kev-${after.sourcePins.kevCatalogDate}`;
    case "forecast-changed":
      return `epss-${after.sourcePins.epssScoreDate}`;
    case "rank-moved":
      return `ranking-${after.policyVersion}`;
    default:
      return `cve-${after.sourcePins.cveRevision}`;
  }
}

export function buildRadarEvents(checkpoints: readonly StoredRadarCheckpoint[]): RadarApiEvent[] {
  const events: RadarApiEvent[] = [];
  let seq = 0;
  for (let index = 1; index < checkpoints.length; index += 1) {
    const before = checkpoints[index - 1];
    const after = checkpoints[index];
    if (before === undefined || after === undefined) continue;
    const diff = diffCheckpoints(before, after);
    for (const change of diff.itemChanges) {
      for (const kind of mapServiceKinds(change.kinds)) {
        seq += 1;
        events.push({
          eventId: `radar-${after.checkpointDate}-${String(seq).padStart(4, "0")}`,
          checkpointDate: after.checkpointDate,
          observedAt: after.observedAt,
          kind,
          cveId: change.cveId,
          title: change.cveId,
          changes: kindChanges(kind, before.items[change.cveId], after.items[change.cveId]),
          sourceRevision: kindSourceRevision(kind, after),
          reason: change.detail,
        });
      }
    }
  }
  events.sort((a, b) => {
    if (a.checkpointDate !== b.checkpointDate) return a.checkpointDate < b.checkpointDate ? 1 : -1;
    return a.eventId < b.eventId ? 1 : -1;
  });
  return events;
}

export function parseRadarKind(raw: string | null): RadarApiKind | null {
  if (raw === null || raw === "") return null;
  if (!(RADAR_API_KINDS as readonly string[]).includes(raw)) {
    throw new ApiError("BAD_FILTER", 400, `kind must be one of ${RADAR_API_KINDS.join(", ")}.`);
  }
  return raw as RadarApiKind;
}

export function parseCveIdParam(raw: string | null): string | null {
  if (raw === null || raw === "") return null;
  if (!CVE_ID_RE.test(raw)) {
    throw new ApiError("BAD_FILTER", 400, "cveId must look like CVE-YYYY-NNNN+.");
  }
  return raw;
}

export function mapReplayReason(reason: string): string {
  const lowered = reason.toLowerCase();
  if (lowered.includes("expired")) return "expired";
  if (lowered.includes("model-changed")) return "model-changed";
  if (lowered.includes("pre-launch")) return "pre-launch";
  if (lowered.includes("no checkpoint retained")) return "missing-day";
  if (lowered.includes("baseline") && lowered.includes("no longer retained"))
    return "baseline-released";
  if (lowered.includes("validation") || lowered.includes("corrupt") || lowered.includes("tamper")) {
    return "invalid-manifest";
  }
  return "unavailable";
}

export function toReplayItem(
  cveId: string,
  snapshot: RadarItemSnapshot,
  pins: StoredRadarCheckpoint["sourcePins"],
): Record<string, unknown> {
  const epss =
    snapshot.epss === null
      ? { status: "unknown", value: null, percentile: null, scoreDate: null, modelVersion: null }
      : {
          status: "known",
          value: Number(snapshot.epss),
          percentile: null,
          scoreDate: pins.epssScoreDate,
          modelVersion: snapshot.epssModel ?? pins.epssModelVersion,
        };
  const cvssPrimary =
    snapshot.primaryVersion === null
      ? { status: "unknown", source: null, version: null, baseScore: null, vector: null }
      : snapshot.primaryVersion === "2.0"
        ? {
            status: "legacy",
            source: "cna",
            version: snapshot.primaryVersion,
            baseScore:
              snapshot.primaryBaseScore === null ? null : Number(snapshot.primaryBaseScore),
            vector: snapshot.primaryVector,
          }
        : {
            status: "known",
            source: "cna",
            version: snapshot.primaryVersion,
            baseScore:
              snapshot.primaryBaseScore === null ? null : Number(snapshot.primaryBaseScore),
            vector: snapshot.primaryVector,
          };
  return {
    cveId,
    title: cveId,
    state: snapshot.state,
    publishedAt: snapshot.publishedAt,
    officialUrl: officialCveLink(cveId),
    excerpt: null,
    excerptTruncated: false,
    excerptLanguage: null,
    excerptStatus: "not-supplied",
    kev: { listed: snapshot.kevMember, dateAdded: snapshot.dateAdded },
    epss,
    cvssPrimary,
  };
}

export function coverageForSnapshots(
  ids: readonly string[],
  snapshots: Record<string, RadarItemSnapshot>,
  returned: number,
): ApiCoverage {
  let unscored = 0;
  let unknownEpss = 0;
  let unknownDate = 0;
  for (const id of ids) {
    const item = snapshots[id];
    if (item === undefined) continue;
    if (item.primaryVersion === null) unscored += 1;
    if (item.epss === null) unknownEpss += 1;
    if (item.publishedAt === null) unknownDate += 1;
  }
  return { eligibleCohort: ids.length, returned, unscored, unknownEpss, unknownDate };
}

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
    unknownEpss: epssDate === null ? eligibleCohort : (row as { e?: number }).e ?? 0,
    unknownDate: row.u ?? 0,
  };
}
