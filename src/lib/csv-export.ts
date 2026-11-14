// RFC 4180 CSV serialization for page-bounded export (v3 epic E5).
//
// Pure formatting: no database, no Request, no paging. The route hands this
// module exactly the records of one page, so nothing here can widen a result
// set — there is no scan, no cursor and no total to serialize.
//
// The file is a header row plus data rows, and nothing else. Provenance and
// coverage stay in the JSON export envelope and in the UI next to the control:
// a `#` comment row would be read as data by spreadsheet and SQL importers, so
// it is never written. Column order is a contract (docs/api/search.md).

import type { PrimaryCvss } from "./ranking";
import { officialCveLink, severityBandFor } from "./search";

/** Stable documented column order; additive changes only, never reordering. */
export const SEARCH_EXPORT_COLUMNS = [
  "cveId",
  "title",
  "state",
  "publishedAt",
  "updatedAt",
  "severityBand",
  "primaryCvssVersion",
  "primaryCvssScore",
  "kevListed",
  "kevDateAdded",
  "epssValue",
  "epssPercentile",
  "exploitTagged",
  "officialUrl",
] as const;

export type SearchExportColumn = (typeof SEARCH_EXPORT_COLUMNS)[number];

/** One export row: every cell is text, or null for an absent value. */
export type SearchExportRow = Record<SearchExportColumn, string | null>;

/**
 * The fields an export row reads. `FullRecord` satisfies this shape, so the
 * route passes records straight in without duplicating the mapping.
 */
export interface SearchExportRecord {
  cveId: string;
  title: string | null;
  state: string;
  publishedAt: string | null;
  dateUpdated: string | null;
  kevDateAdded: string | null;
  epssText: string | null;
  epssPercentile: string | null;
  exploitReferences: ReadonlyArray<unknown>;
  primary: { version: string; baseScore: string; vector: string } | null;
}

export const CSV_RECORD_SEPARATOR = "\r\n";

/** RFC 4180 field: quote when it carries a comma, quote, CR or LF; double quotes. */
export function csvField(value: string | null): string {
  if (value === null || value === "") return "";
  if (!/[",\r\n]/.test(value)) return value;
  return `"${value.replace(/"/g, '""')}"`;
}

/**
 * One page as CSV text: header row, then one row per record, CRLF-terminated.
 *
 * Null and empty values are empty cells — never `null`, `-`, or `0` — so an
 * unknown KEV date or EPSS value is visibly absent instead of looking measured.
 */
export function serializeSearchCsv(rows: readonly SearchExportRow[]): string {
  const lines: string[] = [SEARCH_EXPORT_COLUMNS.join(",")];
  for (const row of rows) {
    lines.push(SEARCH_EXPORT_COLUMNS.map((column) => csvField(row[column])).join(","));
  }
  return `${lines.join(CSV_RECORD_SEPARATOR)}${CSV_RECORD_SEPARATOR}`;
}

/**
 * Map one stored record to its export row. The title falls back to the CVE ID
 * exactly as the JSON item does, and the severity band is the same primary-CNA
 * band the UI renders — never a second, export-only classification.
 */
export function searchExportRow(record: SearchExportRecord): SearchExportRow {
  const title =
    record.title !== null && record.title.trim() !== "" ? record.title : record.cveId;
  return {
    cveId: record.cveId,
    title,
    state: record.state,
    publishedAt: record.publishedAt,
    updatedAt: record.dateUpdated,
    // The band function reads only the version and score; stored versions are
    // the validated CVSS set, so the structural record satisfies it.
    severityBand: severityBandFor(record.primary as PrimaryCvss | null),
    primaryCvssVersion: record.primary === null ? null : record.primary.version,
    primaryCvssScore: record.primary === null ? null : record.primary.baseScore,
    kevListed: record.kevDateAdded === null ? "false" : "true",
    kevDateAdded: record.kevDateAdded,
    epssValue: record.epssText,
    epssPercentile: record.epssPercentile,
    exploitTagged: record.exploitReferences.length > 0 ? "true" : "false",
    officialUrl: officialCveLink(record.cveId),
  };
}

/**
 * Attachment filename: `kevelry-<scope>-<UTC date>-<n>rows.<ext>`. The row
 * count in the name makes a saved file self-describing as one page, not a dump.
 */
export function exportFilename(
  scope: string,
  extension: "csv" | "json",
  now: Date,
  rowCount: number,
): string {
  return `kevelry-${scope}-${now.toISOString().slice(0, 10)}-${String(rowCount)}rows.${extension}`;
}
