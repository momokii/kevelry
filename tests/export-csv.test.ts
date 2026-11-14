// New-test justification (v3 epic E5): the CSV export is a public file format,
// so its contract is pinned here rather than inferred from a route test — the
// exact column order, the exact header row, RFC 4180 quoting for commas,
// embedded quotes and newlines, null/absent values as empty cells, and the
// absence of any `#` comment row (importers would read such a row as data).
// Everything is pure formatting: no database, no Request.

import { describe, expect, it } from "vitest";

import {
  CSV_RECORD_SEPARATOR,
  SEARCH_EXPORT_COLUMNS,
  csvField,
  exportFilename,
  searchExportRow,
  serializeSearchCsv,
  type SearchExportRow,
} from "../src/lib/csv-export";

const HEADER =
  "cveId,title,state,publishedAt,updatedAt,severityBand,primaryCvssVersion,primaryCvssScore,kevListed,kevDateAdded,epssValue,epssPercentile,exploitTagged,officialUrl";

function row(overrides: Partial<SearchExportRow> = {}): SearchExportRow {
  const base = {} as SearchExportRow;
  for (const column of SEARCH_EXPORT_COLUMNS) base[column] = null;
  base.cveId = "CVE-2099-0001";
  base.title = "Title for CVE-2099-0001";
  base.state = "PUBLISHED";
  base.officialUrl = "https://www.cve.org/CVERecord?id=CVE-2099-0001";
  return { ...base, ...overrides };
}

/** CSV text as records, honouring quoted newlines (a naive split would not). */
function records(csv: string): string[] {
  const out: string[] = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < csv.length; index += 1) {
    const char = csv[index] as string;
    if (char === '"') {
      quoted = !quoted;
      current += char;
      continue;
    }
    if (!quoted && csv.startsWith(CSV_RECORD_SEPARATOR, index)) {
      out.push(current);
      current = "";
      index += CSV_RECORD_SEPARATOR.length - 1;
      continue;
    }
    current += char;
  }
  if (current !== "") out.push(current);
  return out;
}

describe("search export CSV", () => {
  it("uses the documented column order and an exact header row", () => {
    expect([...SEARCH_EXPORT_COLUMNS]).toEqual([
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
    ]);
    expect(serializeSearchCsv([])).toBe(`${HEADER}${CSV_RECORD_SEPARATOR}`);
  });

  it("quotes commas, doubles embedded quotes, and quotes newlines", () => {
    expect(csvField("plain")).toBe("plain");
    expect(csvField("a,b")).toBe('"a,b"');
    expect(csvField('say "hi"')).toBe('"say ""hi"""');
    expect(csvField("line one\nline two")).toBe('"line one\nline two"');
    expect(csvField("line one\r\nline two")).toBe('"line one\r\nline two"');
    expect(csvField("")).toBe("");
    expect(csvField(null)).toBe("");
  });

  it("writes null values as empty cells and keeps the row count exact", () => {
    const csv = serializeSearchCsv([row(), row({ cveId: "CVE-2099-0002" })]);
    const lines = records(csv);
    expect(lines).toHaveLength(3);
    expect(lines[0]).toBe(HEADER);

    const cells = (lines[1] as string).split(",");
    expect(cells).toHaveLength(SEARCH_EXPORT_COLUMNS.length);
    // publishedAt, updatedAt, primaryCvssVersion/Score, kevDateAdded, EPSS,
    // and the exploit flag are all null in this row: empty cells, not "null".
    expect(cells).toEqual([
      "CVE-2099-0001",
      "Title for CVE-2099-0001",
      "PUBLISHED",
      "",
      "",
      "",
      "",
      "",
      "",
      "",
      "",
      "",
      "",
      "https://www.cve.org/CVERecord?id=CVE-2099-0001",
    ]);
    expect(csv).not.toContain("null");
  });

  it("quotes a title with a comma and a quote inside the data row", () => {
    const csv = serializeSearchCsv([row({ title: 'Parser, "fragmented" datagrams' })]);
    const lines = records(csv);
    expect(lines[1]).toContain('"Parser, ""fragmented"" datagrams"');
    // The quoted comma must not create an extra cell.
    expect(records(csv)[1]?.split('",').length).toBeGreaterThan(1);
  });

  it("never starts a line with a comment marker", () => {
    const csv = serializeSearchCsv([
      row({ title: "# not a comment" }),
      row({ cveId: "CVE-2099-0002" }),
    ]);
    for (const line of records(csv)) {
      expect(line.startsWith("#"), `line starts with #: ${line}`).toBe(false);
    }
  });

  it("maps a stored record to the documented cells", () => {
    const mapped = searchExportRow({
      cveId: "CVE-2099-0007",
      title: null,
      state: "PUBLISHED",
      publishedAt: "2026-10-20T14:02:00.000Z",
      dateUpdated: "2026-10-22T00:00:00.000Z",
      kevDateAdded: "2026-10-23",
      epssText: "0.1162",
      epssPercentile: "0.96047",
      exploitReferences: [{ url: "https://example.test/poc" }],
      primary: { version: "4.0", baseScore: "9.2", vector: "CVSS:4.0/AV:N" },
    });
    expect(mapped).toEqual({
      cveId: "CVE-2099-0007",
      title: "CVE-2099-0007",
      state: "PUBLISHED",
      publishedAt: "2026-10-20T14:02:00.000Z",
      updatedAt: "2026-10-22T00:00:00.000Z",
      severityBand: "critical",
      primaryCvssVersion: "4.0",
      primaryCvssScore: "9.2",
      kevListed: "true",
      kevDateAdded: "2026-10-23",
      epssValue: "0.1162",
      epssPercentile: "0.96047",
      exploitTagged: "true",
      officialUrl: "https://www.cve.org/CVERecord?id=CVE-2099-0007",
    });
  });

  it("names the file with its UTC date and row count", () => {
    expect(exportFilename("search", "csv", new Date("2026-10-24T05:06:07.000Z"), 20)).toBe(
      "kevelry-search-2026-10-24-20rows.csv",
    );
    expect(exportFilename("search", "json", new Date("2026-10-24T05:06:07.000Z"), 0)).toBe(
      "kevelry-search-2026-10-24-0rows.json",
    );
  });
});
