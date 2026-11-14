// CWE CSV acquisition parsing half (v3 E3 step 2a).
//
// MITRE publishes each CWE view as a zip containing one RFC 4180 CSV. This
// module turns those bytes' text into rows and rows into `CweEntry` values; it
// performs no network access, no unzip, and no database write. The future
// importer composes `extractSingleEntryZip` (./zip) -> `parseCsvRows` ->
// `mapCweCsv` -> its own staging/write step.
//
// Contract:
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

import { normalizeCweId } from "./cwe-catalog";

/** Cap on CSV text handed to `parseCsvRows`; the widest MITRE pack is far below it. */
export const CWE_CSV_MAX_BYTES = 16 * 1024 * 1024;

/** Longest stored `summary`/`mitigation` text, in Unicode code points. */
export const CWE_SUMMARY_MAX_CHARS = 600;
export const CWE_MITIGATION_MAX_CHARS = 600;

export type CweImportErrorCode = "input-too-large" | "malformed-csv";

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
