// CWE CSV acquisition: parsing half (v3 E3 step 2a) plus the ingest half
// (step 2b).
//
// MITRE publishes each CWE view as a zip containing one RFC 4180 CSV. The
// parsing half turns those bytes' text into rows and rows into `CweEntry`
// values: `parseCsvRows` -> `mapCweCsv`, with `extractSingleEntryZip`
// (./zip) feeding them. The ingest half (`refreshCweCatalog`) composes
// fetch -> unzip -> parse -> map -> one transactional publish, and is the only
// code that writes `cwe_catalog_meta` / `cwe_entries`.
//
// Ingest contract:
// - The URL is pinned (`CWE_CSV_URL_DEFAULT`) and may only be overridden by an
//   https `CWE_CSV_URL`, so a misconfigured environment cannot point the
//   worker at plaintext or at an arbitrary scheme.
// - Acquisition is bounded twice: `CWE_ZIP_MAX_BYTES` on the downloaded
//   archive and `CWE_ENTRY_MAX_BYTES` on the extracted CSV entry, plus the
//   30s fetch timeout and the parser's own `CWE_CSV_MAX_BYTES` text cap.
// - The publish is conditional: when the downloaded bytes hash to the accepted
//   `source_hash`, nothing is parsed and nothing is written. A hash match on a
//   non-ready row whose entries are still intact re-marks the accepted catalog
//   `ready` instead, so one transient failure does not pin the catalog stale.
// - Publication is ONE transaction (`DELETE` + inserts + meta upsert), so a
//   reader never sees a half-replaced taxonomy and a failure mid-publish leaves
//   the previous catalog byte-for-byte intact.
// - Failure is last-known-good: entries are never deleted, the meta row is
//   marked `stale` with a sanitised `notes` reason, and the rejection is
//   returned as `{ status: "failed", reason }` instead of thrown, so a worker
//   cycle can log it without failing.
//
// Parsing contract:
// - `parseCsvRows` is a small RFC 4180 reader: quoted fields, embedded commas
//   and line breaks, doubled quotes, CRLF or LF, and a final line without a
//   newline. It is bounded by `CWE_CSV_MAX_BYTES` and reports malformed input
//   (unterminated quote, text after a closing quote) as a typed
//   `CweImportError` instead of returning a silently truncated table. Blank
//   lines are dropped, and a quote in the middle of an unquoted field is kept
//   literally, because the published packs are data, not hand-typed CSV.
// - `mapCweCsv` maps by header name, never by position: upstream view packs
//   disagree on column order and carry extra columns (Extended Description,
//   Related Weaknesses, ...), so unknown columns are ignored. Ids are
//   normalized with the same `normalizeCweId` the read path uses, rows with an
//   unusable id or a blank name are skipped and counted rather than thrown on,
//   and `summary`/`mitigation` are truncated at 600 code points with an
//   ellipsis so a very long published description cannot bloat a row.

import { createHash } from "node:crypto";

import { CWE_CATALOG_SOURCE, normalizeCweId } from "./cwe-catalog";
import type { CveDatabase } from "./db";
import { extractSingleEntryZip } from "./zip";

/**
 * Pinned upstream: the "Research Concepts" view (view 1000) as `CSV.zip`,
 * verified on 2026-11-14 as HTTP 200 / `application/zip` / 644,612 bytes with a
 * single 3.3 MB `1000.csv` entry. View 1000 is the full research taxonomy, so
 * it covers the ids that travel with CVE/KEV rows; the narrower development
 * view (699) omits many of them.
 */
export const CWE_CSV_URL_DEFAULT = "https://cwe.mitre.org/data/csv/1000.csv.zip";

/** View id of the pinned pack; part of the published `version` token. */
export const CWE_CSV_VIEW = "1000";

/** Cap on the downloaded zip; the published pack is ~0.6 MiB. */
export const CWE_ZIP_MAX_BYTES = 8 * 1024 * 1024;

/** Cap on the extracted CSV entry (64 MiB); the published CSV is ~3.2 MiB. */
export const CWE_ENTRY_MAX_BYTES = 64 * 1024 * 1024;

/** Fetch timeout for the pinned zip. */
export const CWE_FETCH_TIMEOUT_MS = 30_000;

/** Cadence gate for the worker's scheduled refresh; MITRE releases are rare. */
export const CWE_REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000;

/** Longest sanitised failure reason kept in `notes` and in logs. */
export const CWE_REASON_MAX_CHARS = 300;

/** Cap on CSV text handed to `parseCsvRows`; the widest MITRE pack is far below it. */
export const CWE_CSV_MAX_BYTES = 16 * 1024 * 1024;

/** Longest stored `summary`/`mitigation` text, in Unicode code points. */
export const CWE_SUMMARY_MAX_CHARS = 600;
export const CWE_MITIGATION_MAX_CHARS = 600;

export type CweImportErrorCode =
  | "input-too-large"
  | "malformed-csv"
  | "invalid-url"
  | "fetch-failed"
  | "timeout"
  | "empty-catalog";

export class CweImportError extends Error {
  readonly name = "CweImportError";
  readonly code: CweImportErrorCode;

  constructor(code: CweImportErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

/** One catalog entry, shaped for the `cwe_entries` columns of migration 009. */
export interface CweEntry {
  id: string;
  name: string;
  abstraction: string | null;
  status: string | null;
  summary: string | null;
  mitigation: string | null;
}

export interface CweCsvMapping {
  entries: CweEntry[];
  /** Rows not yielded: unusable id, blank name, or a duplicate normalized id. */
  skipped: number;
}

function fail(code: CweImportErrorCode, message: string): never {
  throw new CweImportError(code, message);
}

/**
 * Split RFC 4180 CSV text into rows of raw fields.
 *
 * No trimming happens here: whitespace is data, and the mapper decides what to
 * keep. Rows are returned exactly as delimited, minus blank lines, so a CSV
 * that ends with a newline does not gain a phantom row.
 */
export function parseCsvRows(text: string): string[][] {
  if (typeof text !== "string") {
    fail("malformed-csv", "CSV input must be a string");
  }
  const bytes = Buffer.byteLength(text, "utf8");
  if (bytes > CWE_CSV_MAX_BYTES) {
    fail(
      "input-too-large",
      `CSV input is ${bytes} byte(s); the ${CWE_CSV_MAX_BYTES}-byte cap was exceeded`,
    );
  }

  const source = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let fieldStart = true;
  let inQuotes = false;
  let quoteClosed = false;

  const endRow = (): void => {
    row.push(field);
    // A single empty field is a blank line, not a row.
    if (!(row.length === 1 && row[0] === "")) rows.push(row);
    row = [];
    field = "";
    fieldStart = true;
    quoteClosed = false;
  };

  for (let i = 0; i < source.length; i += 1) {
    const ch = source.charAt(i);

    if (inQuotes) {
      if (ch === '"') {
        if (source.charAt(i + 1) === '"') {
          field += '"';
          i += 1;
        } else {
          inQuotes = false;
          quoteClosed = true;
        }
      } else {
        field += ch;
      }
      continue;
    }

    if (quoteClosed) {
      if (ch === ",") {
        row.push(field);
        field = "";
        fieldStart = true;
        quoteClosed = false;
        continue;
      }
      if (ch === "\r" || ch === "\n") {
        if (ch === "\r" && source.charAt(i + 1) === "\n") i += 1;
        endRow();
        continue;
      }
      fail(
        "malformed-csv",
        `unexpected ${JSON.stringify(ch)} after a closing quote at character offset ${i}; RFC 4180 allows only a comma or a line break there`,
      );
    }

    if (ch === '"' && fieldStart) {
      inQuotes = true;
      fieldStart = false;
      continue;
    }
    if (ch === ",") {
      row.push(field);
      field = "";
      fieldStart = true;
      continue;
    }
    if (ch === "\r" || ch === "\n") {
      if (ch === "\r" && source.charAt(i + 1) === "\n") i += 1;
      endRow();
      continue;
    }
    field += ch;
    fieldStart = false;
  }

  if (inQuotes) {
    fail(
      "malformed-csv",
      `unterminated quoted field: input ends inside a quoted value (character offset ${source.length})`,
    );
  }
  if (row.length > 0 || field !== "" || !fieldStart || quoteClosed) endRow();
  return rows;
}

function normalizeHeader(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, " ");
}

function isBlankRow(row: readonly string[]): boolean {
  return row.every((cell) => cell.trim() === "");
}

function findIdColumn(headers: readonly string[]): number {
  let index = headers.findIndex(
    (header) => header === "cwe-id" || header === "cwe id" || header === "cweid",
  );
  if (index >= 0) return index;
  index = headers.findIndex((header) => header === "id");
  if (index >= 0) return index;
  return headers.findIndex((header) => header.includes("cwe") && header.includes("id"));
}

function findNameColumn(headers: readonly string[]): number {
  const exact = headers.findIndex((header) => header === "name");
  return exact >= 0 ? exact : headers.findIndex((header) => header.includes("name"));
}

function findDescriptionColumn(headers: readonly string[]): number {
  let index = headers.findIndex((header) => header === "description");
  if (index >= 0) return index;
  index = headers.findIndex((header) => header === "summary");
  if (index >= 0) return index;
  return headers.findIndex((header) => header.includes("description"));
}

function findColumn(headers: readonly string[], needle: string): number {
  const exact = headers.findIndex((header) => header === needle);
  return exact >= 0 ? exact : headers.findIndex((header) => header.includes(needle));
}

/** Strip CR/LF inside a field to single spaces, then trim the result. */
function cleanText(value: string): string {
  return value.replace(/[ \t]*[\r\n]+[ \t]*/g, " ").trim();
}

function optionalText(value: string): string | null {
  const cleaned = cleanText(value);
  return cleaned === "" ? null : cleaned;
}

/**
 * Truncate at `max` Unicode code points, appending an ellipsis when the text
 * was longer. Returns null for blank text so an absent published field stays
 * absent instead of becoming "".
 */
function truncateText(value: string, max: number): string | null {
  if (value === "") return null;
  const points = Array.from(value);
  if (points.length <= max) return value;
  return `${points.slice(0, max).join("")}…`;
}

/** Read a cell by column index, tolerating short rows. */
function cell(row: readonly string[], index: number): string {
  return index >= 0 ? (row[index] ?? "") : "";
}

/**
 * Map parsed CSV rows to catalog entries.
 *
 * The first non-blank row is the header. Columns are matched case-insensitively
 * by name (`cwe-id`/`id`, `name`, `abstraction`, `status`, `description`,
 * `mitigation`); extra columns are ignored. A row with no usable id, a blank
 * name, or a repeated normalized id is counted in `skipped` and never thrown
 * on, so one bad upstream row cannot abort a whole catalog.
 */
export function mapCweCsv(rows: string[][]): CweCsvMapping {
  const headerIndex = rows.findIndex((row) => !isBlankRow(row));
  if (headerIndex === -1) return { entries: [], skipped: 0 };

  const headerRow = rows[headerIndex] ?? [];
  const headers = headerRow.map(normalizeHeader);
  const idColumn = findIdColumn(headers);
  const nameColumn = findNameColumn(headers);
  const abstractionColumn = findColumn(headers, "abstraction");
  const statusColumn = findColumn(headers, "status");
  const descriptionColumn = findDescriptionColumn(headers);
  const mitigationColumn = findColumn(headers, "mitigation");

  const entries: CweEntry[] = [];
  const seen = new Set<string>();
  let skipped = 0;

  for (const row of rows.slice(headerIndex + 1)) {
    if (isBlankRow(row)) continue;
    const id = normalizeCweId(cell(row, idColumn).trim());
    const name = cleanText(cell(row, nameColumn));
    if (id === null || name === "") {
      skipped += 1;
      continue;
    }
    if (seen.has(id)) {
      skipped += 1;
      continue;
    }
    seen.add(id);
    entries.push({
      id,
      name,
      abstraction: optionalText(cell(row, abstractionColumn)),
      status: optionalText(cell(row, statusColumn)),
      summary: truncateText(cleanText(cell(row, descriptionColumn)), CWE_SUMMARY_MAX_CHARS),
      mitigation: truncateText(cleanText(cell(row, mitigationColumn)), CWE_MITIGATION_MAX_CHARS),
    });
  }

  return { entries, skipped };
}

// ---------------------------------------------------------------------------
// Ingest half (step 2b): fetch, unzip, parse, publish one accepted catalog.
// ---------------------------------------------------------------------------

export interface CweRefreshOptions {
  /** Injected transport; defaults to the global `fetch`. Tests never use network. */
  fetcher?: typeof fetch;
  /** Injectable clock; defaults to `new Date()`. */
  now?: () => Date;
  /** Pinned zip URL override (must be https); defaults to `CWE_CSV_URL`, then the constant. */
  url?: string;
  /** Fetch timeout override; defaults to `CWE_FETCH_TIMEOUT_MS`. */
  timeoutMs?: number;
}

export type CweRefreshResult =
  | { status: "unchanged"; version: string; sourceHash: string; recordCount: number }
  | {
      status: "refreshed";
      version: string;
      sourceHash: string;
      recordCount: number;
      retrievedAt: string;
      /** True when only the meta status was repaired, with no re-parse. */
      recovered: boolean;
    }
  | { status: "failed"; reason: string };

/** `CWE_CSV_URL` when set and non-blank, else the pinned default. */
export function resolveCweCsvUrl(env: Record<string, string | undefined> = process.env): string {
  const raw = env.CWE_CSV_URL?.trim();
  return raw === undefined || raw === "" ? CWE_CSV_URL_DEFAULT : raw;
}

/**
 * Collapse a failure to one sanitised line: first line only (no stack traces),
 * credentials stripped from any URL, whitespace collapsed, hard length cap.
 * Used for both the stored `notes` and the logged reason, so neither can leak a
 * secret or grow without bound.
 */
export function sanitizeCweReason(raw: string): string {
  const firstLine = raw.split(/\r?\n/, 1)[0] ?? "";
  const withoutCredentials = firstLine.replace(/[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/gi, (match) => {
    try {
      const parsed = new URL(match);
      // `host` never carries userinfo, so `https://user:pass@host/x` -> `https://host/x`.
      return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
    } catch {
      return "<url>";
    }
  });
  const collapsed = withoutCredentials.replace(/\s+/g, " ").trim();
  if (collapsed === "") return "unspecified failure";
  return collapsed.length > CWE_REASON_MAX_CHARS
    ? `${collapsed.slice(0, CWE_REASON_MAX_CHARS - 1)}…`
    : collapsed;
}

/**
 * Cadence gate: an attempt is due unless one already happened within
 * `intervalMs`. A missing or unparseable timestamp is always due, so a fresh
 * volume (and a clock that moved backwards) never suppresses the first try.
 */
export function isCweRefreshDue(
  lastAttemptAt: string | null,
  now: Date,
  intervalMs: number = CWE_REFRESH_INTERVAL_MS,
): boolean {
  if (lastAttemptAt === null || lastAttemptAt === "") return true;
  const lastMs = Date.parse(lastAttemptAt);
  if (Number.isNaN(lastMs)) return true;
  return now.getTime() - lastMs >= intervalMs;
}

function sha256Hex(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function fetchZip(fetcher: typeof fetch, url: string, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new CweImportError("timeout", `upstream fetch timed out after ${timeoutMs} ms`));
    }, timeoutMs);
    timer.unref?.();
  });
  try {
    return await Promise.race([
      fetcher(url, {
        redirect: "follow",
        signal: controller.signal,
        headers: { accept: "application/zip" },
      }),
      timeout,
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** Read the response body with a hard byte cap, streamed when the body allows it. */
async function readCappedBody(response: Response, cap: number): Promise<Buffer> {
  const declared = response.headers?.get("content-length");
  if (declared !== null && declared !== undefined && declared.trim() !== "") {
    const size = Number(declared);
    if (Number.isSafeInteger(size) && size > cap) {
      fail(
        "input-too-large",
        `upstream payload declares ${size} byte(s), above the ${cap}-byte download cap`,
      );
    }
  }

  const body = response.body;
  if (body !== null && body !== undefined && typeof body.getReader === "function") {
    const reader = body.getReader();
    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > cap) {
        await reader.cancel().catch(() => undefined);
        fail(
          "input-too-large",
          `upstream payload exceeds the ${cap}-byte download cap (read ${total} byte(s))`,
        );
      }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks, total);
  }

  const buffer = Buffer.from(await response.arrayBuffer());
  if (buffer.length > cap) {
    fail(
      "input-too-large",
      `upstream payload is ${buffer.length} byte(s), above the ${cap}-byte download cap`,
    );
  }
  return buffer;
}

function readCatalogMetaRow(db: CveDatabase):
  | {
      source_hash: string | null;
      status: string | null;
      version: string | null;
      record_count: number | null;
      retrieved_at: string | null;
    }
  | undefined {
  return db.handle
    .prepare(
      "SELECT source_hash, status, version, record_count, retrieved_at FROM cwe_catalog_meta WHERE id = 1",
    )
    .get() as
    | {
        source_hash: string | null;
        status: string | null;
        version: string | null;
        record_count: number | null;
        retrieved_at: string | null;
      }
    | undefined;
}

function countEntries(db: CveDatabase): number {
  const row = db.handle.prepare("SELECT COUNT(*) AS c FROM cwe_entries").get() as { c: number };
  return row.c;
}

function markStale(db: CveDatabase, reason: string, nowIso: string): void {
  // Entries are deliberately left untouched: the previous accepted catalog is
  // last-known-good. Only the pointer's status and note move.
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cwe_catalog_meta (id, version, source, source_hash, retrieved_at, status, record_count, notes) " +
          "VALUES (1, ?, ?, ?, ?, 'stale', 0, ?) " +
          "ON CONFLICT(id) DO UPDATE SET status = 'stale', notes = excluded.notes",
      )
      .run("", CWE_CATALOG_SOURCE, "", nowIso, reason);
  });
}

/**
 * Publish one accepted catalog in a single transaction: replace every entry,
 * then point the meta row at the new (version, hash, retrieved_at, count).
 * Any throw rolls the whole transaction back, leaving the previous catalog.
 */
function publish(
  db: CveDatabase,
  args: { entries: readonly CweEntry[]; version: string; sourceHash: string; retrievedAt: string },
): void {
  db.runBoundedWrite(() => {
    db.handle.prepare("DELETE FROM cwe_entries").run();
    const insert = db.handle.prepare(
      "INSERT INTO cwe_entries (cwe_id, name, abstraction, status, summary, mitigation, version, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    );
    for (const entry of args.entries) {
      insert.run(
        entry.id,
        entry.name,
        entry.abstraction,
        entry.status,
        entry.summary,
        entry.mitigation,
        args.version,
        args.retrievedAt,
      );
    }
    db.handle
      .prepare(
        "INSERT INTO cwe_catalog_meta (id, version, source, source_hash, retrieved_at, status, record_count, notes) " +
          "VALUES (1, ?, ?, ?, ?, 'ready', ?, NULL) " +
          "ON CONFLICT(id) DO UPDATE SET version = excluded.version, source = excluded.source, " +
          "source_hash = excluded.source_hash, retrieved_at = excluded.retrieved_at, " +
          "status = excluded.status, record_count = excluded.record_count, notes = excluded.notes",
      )
      .run(
        args.version,
        CWE_CATALOG_SOURCE,
        args.sourceHash,
        args.retrievedAt,
        args.entries.length,
      );
  });
}

/**
 * Fetch the pinned CWE view pack and publish it as the accepted catalog.
 *
 * Never throws: every failure — bad URL, HTTP error, timeout, oversize
 * payload, unreadable zip, malformed CSV, empty catalog, database error — is
 * sanitised, recorded as a `stale` meta note, and returned as
 * `{ status: "failed", reason }`. Existing entries always survive, so the read
 * path keeps its last-known-good catalog and only loses the `ready` claim.
 */
export async function refreshCweCatalog(
  db: CveDatabase,
  options: CweRefreshOptions = {},
): Promise<CweRefreshResult> {
  const fetcher = options.fetcher ?? fetch;
  const clock = options.now ?? (() => new Date());
  const nowIso = clock().toISOString();
  const timeoutMs = options.timeoutMs ?? CWE_FETCH_TIMEOUT_MS;
  const url = options.url ?? resolveCweCsvUrl();

  try {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      fail("invalid-url", `CWE_CSV_URL is not a valid URL`);
    }
    if (parsed.protocol !== "https:") {
      fail("invalid-url", `CWE_CSV_URL must be an https URL, got ${parsed.protocol}`);
    }

    const response = await fetchZip(fetcher, parsed.toString(), timeoutMs);
    if (!response.ok) {
      fail("fetch-failed", `CWE download failed: HTTP ${response.status} from ${parsed.host}`);
    }

    const zipBytes = await readCappedBody(response, CWE_ZIP_MAX_BYTES);
    const sourceHash = sha256Hex(zipBytes);

    const previous = readCatalogMetaRow(db);
    if (previous !== undefined && previous.source_hash === sourceHash) {
      const previousCount = previous.record_count ?? 0;
      const entriesIntact = previousCount > 0 && previousCount === countEntries(db);
      if (previous.status === "ready" || !entriesIntact || previous.version === null) {
        // Identical bytes: no parse, no write, nothing to report beyond the pin.
        return {
          status: "unchanged",
          version: previous.version ?? "",
          sourceHash,
          recordCount: previousCount,
        };
      }
      // The accepted bytes are still upstream and the rows are still here, so a
      // recorded failure was transient: restore the pointer without re-parsing.
      db.runBoundedWrite(() => {
        db.handle
          .prepare(
            "UPDATE cwe_catalog_meta SET status = 'ready', notes = NULL, retrieved_at = ? WHERE id = 1",
          )
          .run(nowIso);
      });
      return {
        status: "refreshed",
        version: previous.version,
        sourceHash,
        recordCount: previousCount,
        retrievedAt: nowIso,
        recovered: true,
      };
    }

    const extracted = extractSingleEntryZip(zipBytes, {
      maxUncompressedBytes: CWE_ENTRY_MAX_BYTES,
    });
    const mapped = mapCweCsv(parseCsvRows(extracted.data.toString("utf8")));
    if (mapped.entries.length === 0) {
      fail("empty-catalog", "upstream CSV yielded no usable CWE entries");
    }

    // The published pack carries no version marker, so the pin is the view id
    // plus the accepted entry count; `source_hash` is the exact byte pin.
    const version = `${CWE_CSV_VIEW}-${mapped.entries.length}`;
    publish(db, { entries: mapped.entries, version, sourceHash, retrievedAt: nowIso });
    return {
      status: "refreshed",
      version,
      sourceHash,
      recordCount: mapped.entries.length,
      retrievedAt: nowIso,
      recovered: false,
    };
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    const reason = sanitizeCweReason(detail);
    try {
      markStale(db, reason, nowIso);
    } catch {
      // A store that cannot record the failure must not turn a refresh problem
      // into an exception the worker cycle has to handle.
    }
    return { status: "failed", reason };
  }
}
