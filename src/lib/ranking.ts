// Pure ranking/selection contract for the CVE priority views.
//
// DATA_WORKFLOW.md: no composite score, no CVSSxEPSS multiplication. Every
// ordering below is a deterministic cascade of source keys with ASCII-ID
// final tie-breaks. Probability/delta comparisons use exact decimal-string
// arithmetic (scaled BigInt); binary floating point is never used for a
// comparison. Scalar string params (vectors, models, dates) pass through
// as-is. Malformed inputs degrade to unknown/ineligible; nothing here throws
// on hostile data.

export type CvssVersion = "4.0" | "3.1" | "3.0" | "2.0";
export type MetricOrigin = "CNA" | "ADP";

export interface CvssMetricInput {
  origin: unknown;
  version: unknown;
  baseScore: unknown;
  vector?: unknown;
  sourceOrder?: unknown;
}

export interface PrimaryCvss {
  origin: "CNA";
  version: CvssVersion;
  baseScore: string;
  vector: string;
  label: "worst CNA-provided scenario";
}

const VERSION_PREFERENCE: readonly CvssVersion[] = ["4.0", "3.1", "3.0", "2.0"];
const MODERN_VERSIONS: ReadonlySet<string> = new Set(["4.0", "3.1", "3.0"]);

// ---------------------------------------------------------------------------
// Exact decimal arithmetic. A decimal string "12.340" parses to
// { digits: 12340n, scale: 3 }. Comparisons pad the shorter fraction with
// zeros, so they are exact for any finite decimal length. Anything that is
// not a plain decimal literal (exponents, whitespace, NaN, empty) is
// rejected: Number() would accept "1e-3", the contract must not.
// ---------------------------------------------------------------------------

interface DecimalParts {
  digits: bigint;
  scale: number;
}

const DECIMAL_RE = /^(\d+)(?:\.(\d+))?$/;

function parseDecimalParts(value: unknown): DecimalParts | null {
  if (typeof value !== "string" || value.length === 0 || value.length > 64) return null;
  const match = DECIMAL_RE.exec(value);
  if (match === null) return null;
  const intPart: string = match[1] ?? "";
  const fracPart: string = match[2] ?? "";
  try {
    const combined = intPart + fracPart;
    return { digits: BigInt(combined === "" ? "0" : combined), scale: fracPart.length };
  } catch {
    return null;
  }
}

/** Exact three-way comparison of two decimal strings. Null when either is invalid. */
export function compareDecimalStrings(a: unknown, b: unknown): -1 | 0 | 1 | null {
  const pa = parseDecimalParts(a);
  const pb = parseDecimalParts(b);
  if (pa === null || pb === null) return null;
  const scale = Math.max(pa.scale, pb.scale);
  const na = pa.digits * 10n ** BigInt(scale - pa.scale);
  const nb = pb.digits * 10n ** BigInt(scale - pb.scale);
  if (na < nb) return -1;
  if (na > nb) return 1;
  return 0;
}

function isInRange(value: unknown, max: string): boolean {
  const cmpLo = compareDecimalStrings(value, "0");
  const cmpHi = compareDecimalStrings(value, max);
  return cmpLo !== null && cmpHi !== null && cmpLo >= 0 && cmpHi <= 0;
}

function isValidEpss(value: unknown): value is string {
  return typeof value === "string" && isInRange(value, "1");
}

function isValidCvssScore(value: unknown): value is string {
  return typeof value === "string" && isInRange(value, "10");
}

function formatScaled(digits: bigint, scale: number): string {
  const negative = digits < 0n;
  const abs = negative ? -digits : digits;
  const text = abs.toString().padStart(scale + 1, "0");
  if (scale === 0) return (negative ? "-" : "") + text;
  const head = text.slice(0, text.length - scale);
  const tail = text.slice(text.length - scale).replace(/0+$/, "");
  const body = tail === "" ? head : `${head}.${tail}`;
  return (negative ? "-" : "") + body;
}

/** `display_probability_percent = 100 * epss` (display only, never a sort key). */
export function displayProbabilityPercent(epss: unknown): string | null {
  if (!isValidEpss(epss)) return null;
  const parts = parseDecimalParts(epss);
  if (parts === null) return null;
  return formatScaled(parts.digits * 100n, parts.scale);
}

/** Exact delta in percentage points: `100 * (current - previous)`. Null when invalid. */
export function risingDeltaPp(current: unknown, previous: unknown): string | null {
  const pc = parseDecimalParts(current);
  const pp = parseDecimalParts(previous);
  if (pc === null || pp === null) return null;
  if (!isValidEpss(current) || !isValidEpss(previous)) return null;
  const scale = Math.max(pc.scale, pp.scale);
  const nc = pc.digits * 10n ** BigInt(scale - pc.scale);
  const np = pp.digits * 10n ** BigInt(scale - pp.scale);
  return formatScaled((nc - np) * 100n, scale);
}

// ---------------------------------------------------------------------------
// Small tolerant accessors: every sorter accepts unknown rows and degrades
// malformed fields to unknown instead of throwing.
// ---------------------------------------------------------------------------

function asRecord(row: unknown): Record<string, unknown> {
  if (typeof row === "object" && row !== null) return row as Record<string, unknown>;
  return {};
}

function idOf(row: unknown): string {
  const id = asRecord(row).id;
  return typeof id === "string" ? id : "";
}

function asciiCompare(a: string, b: string): -1 | 0 | 1 {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

/** Publication timestamp in ms, or null when missing/malformed (unknown). */
function timeMs(value: unknown): number | null {
  if (typeof value !== "string" || value === "") return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

function epssOf(row: unknown): string | null {
  const value = asRecord(row).epss;
  return isValidEpss(value) ? value : null;
}

function kevOf(row: unknown): boolean {
  return asRecord(row).kevMember === true;
}

// ---------------------------------------------------------------------------
// Primary CVSS selection: valid original CNA metrics only; version
// preference 4.0 > 3.1 > 3.0 > 2.0; highest base within the version labeled
// "worst CNA-provided scenario"; vector ASCII tie-break; source order final.
// ADP-only (or empty/invalid) means unknown primary: null.
// ---------------------------------------------------------------------------

interface ValidCnaMetric {
  version: CvssVersion;
  baseScore: string;
  vector: string;
  sourceOrder: number;
}

function toValidCnaMetric(metric: unknown, index: number): ValidCnaMetric | null {
  const row = asRecord(metric);
  if (row.origin !== "CNA") return null;
  if (typeof row.version !== "string") return null;
  if (!VERSION_PREFERENCE.includes(row.version as CvssVersion)) return null;
  if (!isValidCvssScore(row.baseScore)) return null;
  const order =
    typeof row.sourceOrder === "number" && Number.isFinite(row.sourceOrder)
      ? row.sourceOrder
      : index;
  return {
    version: row.version as CvssVersion,
    baseScore: row.baseScore as string,
    vector: typeof row.vector === "string" ? row.vector : "",
    sourceOrder: order,
  };
}

export function selectPrimaryCvss(metrics: unknown): PrimaryCvss | null {
  if (!Array.isArray(metrics)) return null;
  const valid: ValidCnaMetric[] = [];
  for (let index = 0; index < metrics.length; index += 1) {
    const metric = toValidCnaMetric(metrics[index], index);
    if (metric !== null) valid.push(metric);
  }
  if (valid.length === 0) return null;
  const bestVersion = VERSION_PREFERENCE.find((version) => valid.some((m) => m.version === version));
  if (bestVersion === undefined) return null;
  const pool = valid.filter((m) => m.version === bestVersion);
  pool.sort((a, b) => {
    const score = compareDecimalStrings(b.baseScore, a.baseScore);
    if (score !== 0) return (score ?? 0) as number;
    const vector = asciiCompare(a.vector, b.vector);
    if (vector !== 0) return vector;
    return a.sourceOrder - b.sourceOrder;
  });
  const winner = pool[0];
  if (winner === undefined) return null;
  return {
    origin: "CNA",
    version: winner.version,
    baseScore: winner.baseScore,
    vector: winner.vector,
    label: "worst CNA-provided scenario",
  };
}

// ---------------------------------------------------------------------------
// Default priority: KEV tier > EPSS present > raw probability desc (real
// zero stays scored) > known timestamp > timestamp desc > ASCII ID.
// ---------------------------------------------------------------------------

export function orderDefaultPriority<T>(items: readonly T[]): T[] {
  const rows = (Array.isArray(items) ? [...items] : []) as T[];
  rows.sort((ra, rb) => {
    const a = ra as unknown;
    const b = rb as unknown;
    const kevA = kevOf(a) ? 0 : 1;
    const kevB = kevOf(b) ? 0 : 1;
    if (kevA !== kevB) return kevA - kevB;
    const ea = epssOf(a);
    const eb = epssOf(b);
    const knownA = ea === null ? 1 : 0;
    const knownB = eb === null ? 1 : 0;
    if (knownA !== knownB) return knownA - knownB;
    if (ea !== null && eb !== null) {
      const prob = compareDecimalStrings(eb, ea);
      if (prob !== 0) return (prob ?? 0) as number;
    }
    const ta = timeMs(asRecord(a).publishedAt);
    const tb = timeMs(asRecord(b).publishedAt);
    const dateKnownA = ta === null ? 1 : 0;
    const dateKnownB = tb === null ? 1 : 0;
    if (dateKnownA !== dateKnownB) return dateKnownA - dateKnownB;
    if (ta !== null && tb !== null && ta !== tb) return tb - ta;
    return asciiCompare(idOf(a), idOf(b));
  });
  return rows;
}

// ---------------------------------------------------------------------------
// KEV due-soon: KEV members with a valid calendar remediation due date.
// Due date ascending (overdue first; no upper cutoff — a real deadline six
// months out still outranks no deadline at all), then ASCII ID. Day strings
// in YYYY-MM-DD shape compare lexicographically; malformed or missing due
// dates are ineligible, never throw. Non-members are excluded.
// ---------------------------------------------------------------------------

const DUE_DAY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

function isDueDay(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = DUE_DAY_RE.exec(value);
  if (match === null) return false;
  const ms = Date.parse(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(ms)) return false;
  return new Date(ms).toISOString().slice(0, 10) === value;
}

export function orderKevDueSoon<T>(items: readonly T[]): T[] {
  const rows = ((Array.isArray(items) ? items : []) as unknown[]).filter((row) =>
    kevOf(row) ? isDueDay(asRecord(row).kevDueDate) : false,
  ) as T[];
  rows.sort((ra, rb) => {
    const da = asRecord(ra as unknown).kevDueDate as string;
    const db = asRecord(rb as unknown).kevDueDate as string;
    if (da !== db) return da < db ? -1 : 1;
    return asciiCompare(idOf(ra), idOf(rb));
  });
  return rows;
}

// ---------------------------------------------------------------------------
// Known exploited: KEV members only, dateAdded desc then ASCII ID.
// Invalid dateAdded sorts after valid dates (unknown), never throws.
// ---------------------------------------------------------------------------

export function orderKnownExploited<T>(items: readonly T[]): T[] {
  const rows = ((Array.isArray(items) ? items : []) as unknown[]).filter((row) =>
    kevOf(row),
  ) as T[];
  rows.sort((ra, rb) => {
    const da = timeMs(asRecord(ra as unknown).dateAdded);
    const db = timeMs(asRecord(rb as unknown).dateAdded);
    const knownA = da === null ? 1 : 0;
    const knownB = db === null ? 1 : 0;
    if (knownA !== knownB) return knownA - knownB;
    if (da !== null && db !== null && da !== db) return db - da;
    return asciiCompare(idOf(ra), idOf(rb));
  });
  return rows;
}

// ---------------------------------------------------------------------------
// Highest forecast: known EPSS only; raw probability desc; known
// publication before unknown; publication desc; ASCII ID.
// ---------------------------------------------------------------------------

export function orderHighestForecast<T>(items: readonly T[]): T[] {
  const rows = ((Array.isArray(items) ? items : []) as unknown[]).filter(
    (row) => epssOf(row) !== null,
  ) as T[];
  rows.sort((ra, rb) => {
    const ea = epssOf(ra) ?? "";
    const eb = epssOf(rb) ?? "";
    const prob = compareDecimalStrings(eb, ea);
    if (prob !== 0) return (prob ?? 0) as number;
    const ta = timeMs(asRecord(ra as unknown).publishedAt);
    const tb = timeMs(asRecord(rb as unknown).publishedAt);
    const knownA = ta === null ? 1 : 0;
    const knownB = tb === null ? 1 : 0;
    if (knownA !== knownB) return knownA - knownB;
    if (ta !== null && tb !== null && ta !== tb) return tb - ta;
    return asciiCompare(idOf(ra), idOf(rb));
  });
  return rows;
}

// ---------------------------------------------------------------------------
// New critical: publication in [T - 30d, T) with a primary modern
// (v3/v4 CNA) CVSS >= 9.0. Order publication desc, then ASCII ID.
// Unknown, legacy-only, ADP-only, and malformed dates are ineligible.
// ---------------------------------------------------------------------------

const WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

function primaryIsModernCritical(primary: unknown): boolean {
  const row = asRecord(primary);
  if (row.origin !== "CNA") return false;
  if (typeof row.version !== "string" || !MODERN_VERSIONS.has(row.version)) return false;
  if (!isValidCvssScore(row.baseScore)) return false;
  const cmp = compareDecimalStrings(row.baseScore, "9.0");
  return cmp !== null && cmp >= 0;
}

export function selectNewCritical<T>(items: readonly T[], cutoffT: unknown): T[] {
  const cutoff = timeMs(cutoffT);
  if (cutoff === null) return [];
  const lower = cutoff - WINDOW_MS;
  const eligible = ((Array.isArray(items) ? items : []) as unknown[]).filter((row) => {
    const published = timeMs(asRecord(row).publishedAt);
    if (published === null || published < lower || published >= cutoff) return false;
    return primaryIsModernCritical(asRecord(row).primary);
  }) as T[];
  eligible.sort((ra, rb) => {
    const ta = timeMs(asRecord(ra as unknown).publishedAt) ?? 0;
    const tb = timeMs(asRecord(rb as unknown).publishedAt) ?? 0;
    if (ta !== tb) return tb - ta;
    return asciiCompare(idOf(ra), idOf(rb));
  });
  return eligible;
}

// ---------------------------------------------------------------------------
// Rising forecast: accepted current EPSS date d; require observations on
// exactly d and d-7 with the same model version. Positive deltas only;
// delta desc, current raw probability desc, ASCII ID. Missing dates and
// model transitions are ineligible, never interpolated.
// ---------------------------------------------------------------------------

export interface RisingResult<T> {
  item: T;
  deltaPp: string;
}

const DAY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

function minus7Days(day: string): string | null {
  if (!DAY_RE.test(day)) return null;
  const ms = Date.parse(`${day}T00:00:00.000Z`);
  if (!Number.isFinite(ms)) return null;
  if (new Date(ms).toISOString().slice(0, 10) !== day) return null;
  return new Date(ms - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

function isValidDay(value: unknown): value is string {
  if (typeof value !== "string" || !DAY_RE.test(value)) return false;
  const ms = Date.parse(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(ms)) return false;
  return new Date(ms).toISOString().slice(0, 10) === value;
}

export function selectRisingForecast<T>(
  items: readonly T[],
  currentDate: unknown,
): RisingResult<T>[] {
  if (!isValidDay(currentDate)) return [];
  const expectedPrevious = minus7Days(currentDate);
  if (expectedPrevious === null) return [];
  const eligible: { item: T; deltaPp: string; currentEpss: string }[] = [];
  for (const row of Array.isArray(items) ? items : []) {
    const record = asRecord(row);
    if (record.currentDate !== currentDate) continue;
    if (record.previousDate !== expectedPrevious) continue;
    if (typeof record.currentModel !== "string" || record.currentModel === "") continue;
    if (record.previousModel !== record.currentModel) continue;
    if (!isValidEpss(record.currentEpss) || !isValidEpss(record.previousEpss)) continue;
    const delta = risingDeltaPp(record.currentEpss, record.previousEpss);
    if (delta === null) continue;
    if ((compareDecimalStrings(delta, "0") ?? 0) <= 0) continue;
    eligible.push({ item: row as T, deltaPp: delta, currentEpss: record.currentEpss as string });
  }
  eligible.sort((a, b) => {
    const delta = compareDecimalStrings(b.deltaPp, a.deltaPp);
    if (delta !== 0) return (delta ?? 0) as number;
    const prob = compareDecimalStrings(b.currentEpss, a.currentEpss);
    if (prob !== 0) return (prob ?? 0) as number;
    return asciiCompare(idOf(a.item), idOf(b.item));
  });
  return eligible.map(({ item, deltaPp }) => ({ item, deltaPp }));
}
