// EPSS daily CSV importer with dated history archive (plan todo 10).
//
// Reads the complete FIRST EPSS daily CSV: leading `#` comment metadata
// (model_version, score_date), the required `cve,epss,percentile` header, and
// one row per CVE. Validation is all-or-nothing before any write, so a
// malformed or truncated file aborts with the accepted snapshot untouched.
// Exact source decimals are stored as TEXT; comparisons elsewhere must use
// the stored strings with exact decimal arithmetic, never binary floats.
// A CVE with no row for the accepted score date is unknown: this module
// never backfills from older dates and never zero-fills. Cross-model
// deltas are reported ineligible, never computed.

import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";

import type { CveDatabase } from "./db";

export class EpssImportError extends Error {
  readonly name = "EpssImportError";
}

export const EPSS_CURRENT_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
export const EPSS_SOURCE_NAME = "epss" as const;

const CVE_ID_PATTERN = /^CVE-(19|20)\d{2}-\d{4,}$/;
const SCORE_DAY_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
const PLAIN_DECIMAL_PATTERN = /^\d+(\.\d+)?$/;
const SCIENTIFIC_DECIMAL_PATTERN = /^(\d+(?:\.\d+)?)[eE]([+-]?\d+)$/;
// Hard cap on exponent-driven digit expansion so a hostile `1e-1000000`
// cannot force a megabyte string; real EPSS values are tiny decimals.
const MAX_EXPONENT_MAGNITUDE = 10_000;
const REQUIRED_HEADER = "cve,epss,percentile";
const GZIP_MAGIC_0 = 0x1f;
const GZIP_MAGIC_1 = 0x8b;

export interface EpssCsvRow {
  cveId: string;
  epssText: string;
  percentileText: string;
}

export interface EpssCsvDocument {
  modelVersion: string;
  scoreDate: string;
  rows: EpssCsvRow[];
}

export interface EpssImportOptions {
  knownCveIds?: readonly string[];
}

export interface EpssImportResult {
  scoreDate: string;
  modelVersion: string;
  rowCount: number;
  unmatched: string[];
  contentHash: string;
}

export interface EpssObservation {
  cveId: string;
  scoreDate: string;
  modelVersion: string;
  epssText: string;
  percentileText: string;
}

export type RisingEligibility =
  | { eligible: true; modelVersion: string; deltaPpText: string }
  | { eligible: false; reason: string };

function fail(message: string): never {
  throw new EpssImportError(message);
}

function normalizeScoreDay(raw: string): string {
  const day = raw.includes("T") ? (raw.split("T")[0] ?? "") : raw;
  if (!SCORE_DAY_PATTERN.test(day) || Number.isNaN(Date.parse(`${day}T00:00:00.000Z`))) {
    fail(`malformed EPSS score_date "${raw}": expected a UTC calendar day (YYYY-MM-DD)`);
  }
  return day;
}

function parseCommentMetadata(commentLines: string[]): { modelVersion: string; scoreDate: string } {
  let modelVersion: string | null = null;
  let scoreDateRaw: string | null = null;
  for (const line of commentLines) {
    const body = line.replace(/^#/, "");
    for (const piece of body.split(",")) {
      const separator = piece.indexOf(":");
      if (separator < 0) {
        continue;
      }
      const key = piece.slice(0, separator).trim();
      const value = piece.slice(separator + 1).trim();
      if (key === "model_version" && value !== "") {
        modelVersion = value;
      } else if (key === "score_date" && value !== "") {
        scoreDateRaw = value;
      }
    }
  }
  if (modelVersion === null) {
    fail("malformed EPSS CSV: leading comment is missing model_version");
  }
  if (scoreDateRaw === null) {
    fail("malformed EPSS CSV: leading comment is missing score_date");
  }
  return { modelVersion, scoreDate: normalizeScoreDay(scoreDateRaw) };
}

function canonicalizeScientificDecimal(value: string): string {
  const match = SCIENTIFIC_DECIMAL_PATTERN.exec(value);
  if (match === null) {
    fail(`invalid EPSS decimal "${value}": expected a plain decimal or exponent notation`);
  }
  const mantissa = match[1] as string;
  const exponentRaw = match[2] as string;
  const exponent = Number(exponentRaw);
  if (!Number.isInteger(exponent) || Math.abs(exponent) > MAX_EXPONENT_MAGNITUDE) {
    fail(`invalid EPSS decimal "${value}": exponent out of range`);
  }
  const dot = mantissa.indexOf(".");
  const intPart = dot < 0 ? mantissa : mantissa.slice(0, dot);
  const fracPart = dot < 0 ? "" : mantissa.slice(dot + 1);
  const fracLen = fracPart.length;
  const combined = `${intPart}${fracPart}`.replace(/^0+(?=\d)/, "");
  const stripped = combined === "" ? "0" : combined;
  let digits: bigint;
  try {
    digits = BigInt(stripped);
  } catch {
    fail(`invalid EPSS decimal "${value}": malformed mantissa`);
  }
  if (digits === 0n) {
    return "0";
  }
  const shift = exponent - fracLen;
  if (shift >= 0) {
    const scaled = digits * 10n ** BigInt(shift);
    if (scaled > 1n) {
      fail(`invalid EPSS decimal "${value}": expected a finite value in [0,1]`);
    }
    return scaled.toString();
  }
  const scale = -shift;
  const denominator = 10n ** BigInt(scale);
  const whole = digits / denominator;
  const rest = digits % denominator;
  if (whole > 1n) {
    fail(`invalid EPSS decimal "${value}": expected a finite value in [0,1]`);
  }
  if (whole === 1n && rest !== 0n) {
    fail(`invalid EPSS decimal "${value}": expected a finite value in [0,1]`);
  }
  if (rest === 0n) {
    return whole.toString();
  }
  const frac = rest.toString().padStart(scale, "0").replace(/0+$/, "");
  return `${whole.toString()}.${frac}`;
}

function canonicalizeDecimalText(field: string, value: string, cveId: string): string {
  if (value === "") {
    fail(`invalid EPSS ${field} "${value}" for ${cveId}: expected a plain decimal`);
  }
  if (PLAIN_DECIMAL_PATTERN.test(value)) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric) || numeric < 0 || numeric > 1) {
      fail(`invalid EPSS ${field} "${value}" for ${cveId}: expected a finite value in [0,1]`);
    }
    return value;
  }
  if (/[eE]/.test(value)) {
    try {
      const canonical = canonicalizeScientificDecimal(value);
      const numeric = Number(canonical);
      if (!Number.isFinite(numeric) || numeric < 0 || numeric > 1) {
        fail(`invalid EPSS ${field} "${value}" for ${cveId}: expected a finite value in [0,1]`);
      }
      return canonical;
    } catch (error) {
      if (error instanceof EpssImportError) {
        const detail = error.message.replace(
          /^invalid EPSS decimal /,
          `invalid EPSS ${field} `,
        );
        const withId = detail.includes(" for ") ? detail : `${detail} for ${cveId}`;
        fail(withId);
      }
      throw error;
    }
  }
  fail(`invalid EPSS ${field} "${value}" for ${cveId}: expected a plain decimal`);
}

function validateDecimalText(field: string, value: string, cveId: string): string {
  return canonicalizeDecimalText(field, value, cveId);
}

export function parseEpssCsv(csvText: string): EpssCsvDocument {
  if (csvText.trim() === "") {
    fail("malformed EPSS CSV: input is empty");
  }
  const lines = csvText.split("\n");
  const commentLines: string[] = [];
  let headerSeen = false;
  let header: string | null = null;
  const rows: EpssCsvRow[] = [];
  const seen = new Set<string>();

  for (const rawLine of lines) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (!headerSeen && line.startsWith("#")) {
      commentLines.push(line);
      continue;
    }
    if (line.trim() === "") {
      continue;
    }
    if (!headerSeen) {
      headerSeen = true;
      header = line.trim();
      if (header !== REQUIRED_HEADER) {
        fail(`malformed EPSS CSV: expected header "${REQUIRED_HEADER}", got "${header}"`);
      }
      continue;
    }
    const fields = line.split(",");
    if (fields.length !== 3) {
      fail(`malformed EPSS CSV: expected 3 columns, got ${fields.length} in "${line.trim()}"`);
    }
    const cveId = (fields[0] ?? "").trim();
    const epssText = (fields[1] ?? "").trim();
    const percentileText = (fields[2] ?? "").trim();
    if (!CVE_ID_PATTERN.test(cveId)) {
      fail(`invalid EPSS CVE ID "${cveId}"`);
    }
    if (seen.has(cveId)) {
      fail(`duplicate EPSS ID "${cveId}"`);
    }
    const canonicalEpss = validateDecimalText("epss", epssText, cveId);
    const canonicalPercentile = validateDecimalText("percentile", percentileText, cveId);
    seen.add(cveId);
    rows.push({ cveId, epssText: canonicalEpss, percentileText: canonicalPercentile });
  }

  if (!headerSeen || header === null) {
    fail("malformed EPSS CSV: missing header row");
  }
  const { modelVersion, scoreDate } = parseCommentMetadata(commentLines);
  if (rows.length === 0) {
    fail("malformed EPSS CSV: no data rows after the header");
  }
  return { modelVersion, scoreDate, rows };
}

export function decodeEpssPayload(bytes: Uint8Array): string {
  if (bytes.length >= 2 && bytes[0] === GZIP_MAGIC_0 && bytes[1] === GZIP_MAGIC_1) {
    return gunzipSync(bytes).toString("utf8");
  }
  return Buffer.from(bytes).toString("utf8");
}

export function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

export async function fetchEpssCsvText(
  url: string = EPSS_CURRENT_CSV_URL,
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    fail(`refusing EPSS download: "${url}" is not a valid URL`);
  }
  if (parsed.protocol !== "https:") {
    fail(`refusing EPSS download: "${url}" is not an https URL`);
  }
  const response = await fetchImpl(url, { redirect: "follow" });
  if (!response.ok) {
    fail(`EPSS download failed: HTTP ${response.status} from ${parsed.host}`);
  }
  return decodeEpssPayload(new Uint8Array(await response.arrayBuffer()));
}

function readKnownCveIds(db: CveDatabase): Set<string> {
  const rows = db.handle.prepare("SELECT cve_id FROM cve_records").all() as Array<{
    cve_id: string;
  }>;
  return new Set(rows.map((row) => row.cve_id));
}

function recordSyncRun(
  db: CveDatabase,
  status: "succeeded" | "failed",
  revision: string | null,
  contentHash: string,
  error: string | null,
  startedAt: string,
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        EPSS_SOURCE_NAME,
        startedAt,
        new Date().toISOString(),
        status,
        revision,
        contentHash,
        error,
      );
  });
}

export function importEpssCsv(
  db: CveDatabase,
  csvText: string,
  options: EpssImportOptions = {},
): EpssImportResult {
  const startedAt = new Date().toISOString();
  const contentHash = sha256Hex(csvText);
  let document: EpssCsvDocument;
  try {
    document = parseEpssCsv(csvText);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    recordSyncRun(db, "failed", null, contentHash, detail, startedAt);
    throw error;
  }

  const known =
    options.knownCveIds !== undefined ? new Set(options.knownCveIds) : readKnownCveIds(db);
  const unmatched = document.rows
    .map((row) => row.cveId)
    .filter((cveId) => !known.has(cveId))
    .sort();

  db.executeBatched(document.rows, (batch) => {
    const insert = db.handle.prepare(
      "INSERT OR REPLACE INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
    );
    for (const row of batch) {
      insert.run(
        row.cveId,
        document.scoreDate,
        document.modelVersion,
        row.epssText,
        row.percentileText,
      );
    }
  });
  recordSyncRun(
    db,
    "succeeded",
    `${document.scoreDate}@${document.modelVersion}`,
    contentHash,
    null,
    startedAt,
  );
  return {
    scoreDate: document.scoreDate,
    modelVersion: document.modelVersion,
    rowCount: document.rows.length,
    unmatched,
    contentHash,
  };
}

export function getAcceptedEpssDate(db: CveDatabase): string | null {
  const row = db.handle.prepare("SELECT MAX(score_date) AS score_date FROM epss_daily").get() as {
    score_date: string | null;
  };
  return row.score_date;
}

function toObservation(row: {
  cve_id: string;
  score_date: string;
  model_version: string;
  epss: string;
  percentile: string;
}): EpssObservation {
  return {
    cveId: row.cve_id,
    scoreDate: row.score_date,
    modelVersion: row.model_version,
    epssText: row.epss,
    percentileText: row.percentile,
  };
}

export function readEpssObservation(
  db: CveDatabase,
  cveId: string,
  scoreDate: string,
): EpssObservation | undefined {
  const row = db.handle
    .prepare(
      "SELECT cve_id, score_date, model_version, epss, percentile FROM epss_daily WHERE cve_id = ? AND score_date = ? ORDER BY model_version DESC LIMIT 1",
    )
    .get(cveId, scoreDate) as
    | {
        cve_id: string;
        score_date: string;
        model_version: string;
        epss: string;
        percentile: string;
      }
    | undefined;
  return row === undefined ? undefined : toObservation(row);
}

export function lookupEpss(db: CveDatabase, cveId: string): EpssObservation | undefined {
  const accepted = getAcceptedEpssDate(db);
  if (accepted === null) {
    return undefined;
  }
  return readEpssObservation(db, cveId, accepted);
}

export function getEpssHistory(db: CveDatabase, cveId: string): EpssObservation[] {
  const rows = db.handle
    .prepare(
      "SELECT cve_id, score_date, model_version, epss, percentile FROM epss_daily WHERE cve_id = ? ORDER BY score_date ASC",
    )
    .all(cveId) as Array<{
    cve_id: string;
    score_date: string;
    model_version: string;
    epss: string;
    percentile: string;
  }>;
  return rows.map(toObservation);
}

function parsePlainDecimal(text: string): { digits: bigint; fracLen: number } {
  const dot = text.indexOf(".");
  if (dot < 0) {
    return { digits: BigInt(text), fracLen: 0 };
  }
  const intPart = text.slice(0, dot) === "" ? "0" : text.slice(0, dot);
  const fracPart = text.slice(dot + 1);
  return { digits: BigInt(`${intPart}${fracPart}`), fracLen: fracPart.length };
}

// Exact percentage-point delta: 100 * (current - previous), computed on
// scaled integers so equal decimal deltas never split on binary float error.
export function computeDeltaPpText(currentText: string, previousText: string): string {
  const current = parsePlainDecimal(currentText);
  const previous = parsePlainDecimal(previousText);
  const scale = Math.max(current.fracLen, previous.fracLen);
  const up = (part: { digits: bigint; fracLen: number }): bigint =>
    part.digits * 10n ** BigInt(scale - part.fracLen);
  const numerator = (up(current) - up(previous)) * 100n;
  const denominator = 10n ** BigInt(scale);
  const negative = numerator < 0n;
  const magnitude = negative ? -numerator : numerator;
  const whole = magnitude / denominator;
  const rest = magnitude % denominator;
  const sign = negative ? "-" : "";
  if (rest === 0n) {
    return `${sign}${whole.toString()}`;
  }
  const frac = rest.toString().padStart(scale, "0").replace(/0+$/, "");
  return `${sign}${whole.toString()}.${frac}`;
}

export function checkRisingEligible(
  db: CveDatabase,
  cveId: string,
  currentDate: string,
  daysBackDate: string,
): RisingEligibility {
  const current = readEpssObservation(db, cveId, currentDate);
  if (current === undefined) {
    return { eligible: false, reason: `no EPSS observation for ${cveId} on ${currentDate}` };
  }
  const baseline = readEpssObservation(db, cveId, daysBackDate);
  if (baseline === undefined) {
    return { eligible: false, reason: `no EPSS observation for ${cveId} on ${daysBackDate}` };
  }
  if (current.modelVersion !== baseline.modelVersion) {
    return {
      eligible: false,
      reason: `model transition ${baseline.modelVersion} to ${current.modelVersion}: ineligible, no cross-model comparison`,
    };
  }
  return {
    eligible: true,
    modelVersion: current.modelVersion,
    deltaPpText: computeDeltaPpText(current.epssText, baseline.epssText),
  };
}
