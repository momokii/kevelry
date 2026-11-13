import { decodeOffsetCursor, encodeOffsetCursor } from "../../../../src/lib/search";
import { ApiError } from "./errors";

/** API page default and hard cap. Oversized values are rejected, never clamped. */
export const API_DEFAULT_LIMIT = 50;
export const API_MAX_LIMIT = 200;

/** Validated CVE ID shape shared by path and query params. */
export const CVE_ID_RE = /^CVE-[0-9]{4}-[0-9]{4,}$/;

export const DAY_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;

export const MAX_CURSOR_CHARS = 512;

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

/**
 * Cursor encode/decode delegate to the single codec in src/lib/search, so the
 * API and the search service issue and accept byte-identical cursors. The
 * length bound and the ApiError contract stay here because they are the API's.
 */
export function encodeCursor(offset: number): string {
  return encodeOffsetCursor(offset);
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
  const decoded = decodeOffsetCursor(raw);
  if (decoded.ok) return decoded.offset;
  throw new ApiError("BAD_CURSOR", 400, "cursor is not a cursor returned by a previous response.");
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
/** `tagged` = the record's own references carry the publisher's `exploit` tag. */
export type ExploitParam = "tagged" | "any";

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

export function parseExploit(raw: string | null): ExploitParam {
  if (raw === null || raw === "" || raw === "any") return "any";
  if (raw !== "tagged") {
    throw new ApiError("BAD_FILTER", 400, "exploit must be tagged or any.");
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

/** Optional vendor/product substring filter (KEV catalog labels only).
 * Same hostile-input discipline as q: LIKE is parameterized with ESCAPE so
 * wildcards stay literal, but control characters and overlong values are
 * rejected at the boundary. Null/empty means unfiltered. */
export function parseVendor(raw: string | null): string | null {
  if (raw === null || raw.trim() === "") return null;
  const trimmed = raw.trim();
  if (trimmed.length < 2 || trimmed.length > 100) {
    throw new ApiError("BAD_FILTER", 400, "vendor must be 2 to 100 characters.");
  }
  if (hasControlChars(trimmed)) {
    throw new ApiError("BAD_FILTER", 400, "vendor contains unsupported control characters.");
  }
  const lowered = trimmed.toLowerCase();
  for (const token of HOSTILE_QUERY_TOKENS) {
    if (lowered.includes(token)) {
      throw new ApiError(
        "BAD_FILTER",
        400,
        "vendor looks like an injection attempt and was rejected.",
      );
    }
  }
  return trimmed;
}
