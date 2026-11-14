// Unit coverage for the dependency-free zip reader and CWE CSV parser
// (v3 E3 step 2a).
//
// Every zip fixture is built in this file (local headers, central directory,
// EOCD) so no binary blob is committed and the tests stay readable: each case
// states exactly which part of the framing it is exercising. No network, no
// worker, no database: the parsing half only.

import { deflateRawSync } from "node:zlib";
import { describe, expect, it } from "vitest";

import {
  CWE_CSV_MAX_BYTES,
  CWE_MITIGATION_MAX_CHARS,
  CWE_SUMMARY_MAX_CHARS,
  CweImportError,
  mapCweCsv,
  parseCsvRows,
} from "../src/lib/cwe-import";
import { ZipExtractError, extractSingleEntryZip } from "../src/lib/zip";

interface ZipFixtureEntry {
  name: string;
  data: Buffer;
  method?: number;
  encrypted?: boolean;
  /** Override the size advertised in both headers (used to lie to the reader). */
  declaredUncompressedSize?: number;
}

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;

/** Minimal single-or-multi-entry zip writer for fixtures. */
function buildZip(entries: readonly ZipFixtureEntry[]): Buffer {
  const pieces: Buffer[] = [];
  const centrals: Buffer[] = [];
  let localOffset = 0;

  for (const entry of entries) {
    const method = entry.method ?? 0;
    const stored = method === 8 ? deflateRawSync(entry.data) : entry.data;
    const uncompressedSize = entry.declaredUncompressedSize ?? entry.data.length;
    const flags = entry.encrypted === true ? 1 : 0;
    const name = Buffer.from(entry.name, "utf8");

    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(SIG_LOCAL, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(stored.length, 18);
    local.writeUInt32LE(uncompressedSize, 22);
    local.writeUInt16LE(name.length, 26);
    // CRC-32 stays zero: the reader deliberately does not verify it.
    name.copy(local, 30);

    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(SIG_CENTRAL, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(stored.length, 20);
    central.writeUInt32LE(uncompressedSize, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(localOffset, 42);
    name.copy(central, 46);

    pieces.push(local, stored);
    centrals.push(central);
    localOffset += local.length + stored.length;
  }

  const centralDirectory = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(SIG_EOCD, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirectory.length, 12);
  eocd.writeUInt32LE(localOffset, 16);

  return Buffer.concat([...pieces, centralDirectory, eocd]);
}

function zipFailure(run: () => unknown): ZipExtractError {
  try {
    run();
  } catch (error) {
    if (error instanceof ZipExtractError) return error;
    throw error;
  }
  throw new Error("expected extractSingleEntryZip to throw");
}

function csvFailure(run: () => unknown): CweImportError {
  try {
    run();
  } catch (error) {
    if (error instanceof CweImportError) return error;
    throw error;
  }
  throw new Error("expected a CweImportError");
}

const CSV = "CWE-ID,Name,Weakness Abstraction,Status,Description,Potential Mitigations\n";
const CAP = 64 * 1024;

describe("extractSingleEntryZip", () => {
  it("extracts a stored entry with its name and bytes", () => {
    const content = Buffer.from("cwe,x\r\n79,Cross-site Scripting\r\n", "utf8");
    const zip = buildZip([{ name: "cwe-1000.csv", data: content, method: 0 }]);

    const result = extractSingleEntryZip(zip, { maxUncompressedBytes: CAP });

    expect(result.name).toBe("cwe-1000.csv");
    expect(result.data.equals(content)).toBe(true);
  });

  it("extracts a deflated entry", () => {
    const content = Buffer.from(CSV + '79,"Cross-site scripting, stored"\n', "utf8");
    const zip = buildZip([{ name: "cwec_v4.17.csv", data: content, method: 8 }]);
    // The payload must really be compressed, or this test proves nothing.
    expect(zip.length).toBeLessThan(content.length + 200);

    const result = extractSingleEntryZip(zip, { maxUncompressedBytes: CAP });

    expect(result.name).toBe("cwec_v4.17.csv");
    expect(result.data.toString("utf8")).toBe(content.toString("utf8"));
  });

  it("rejects an archive with no entries", () => {
    const error = zipFailure(() =>
      extractSingleEntryZip(buildZip([]), { maxUncompressedBytes: CAP }),
    );
    expect(error.code).toBe("entry-count");
    expect(error.message).toMatch(/no entries/);
  });

  it("rejects an archive with more than one entry", () => {
    const zip = buildZip([
      { name: "a.csv", data: Buffer.from("a") },
      { name: "b.csv", data: Buffer.from("b") },
    ]);
    const error = zipFailure(() => extractSingleEntryZip(zip, { maxUncompressedBytes: CAP }));
    expect(error.code).toBe("entry-count");
    expect(error.message).toMatch(/2 entries/);
  });

  it("rejects an encrypted entry", () => {
    const zip = buildZip([{ name: "a.csv", data: Buffer.from("a"), encrypted: true }]);
    const error = zipFailure(() => extractSingleEntryZip(zip, { maxUncompressedBytes: CAP }));
    expect(error.code).toBe("encrypted");
  });

  it("rejects a compression method other than stored or deflate", () => {
    const zip = buildZip([{ name: "a.csv", data: Buffer.from("a"), method: 12 }]);
    const error = zipFailure(() => extractSingleEntryZip(zip, { maxUncompressedBytes: CAP }));
    expect(error.code).toBe("unsupported-method");
    expect(error.message).toMatch(/method 12/);
  });

  it("rejects a declared uncompressed size above the cap", () => {
    const zip = buildZip([
      { name: "a.csv", data: Buffer.from("short"), method: 0, declaredUncompressedSize: 4096 },
    ]);
    const error = zipFailure(() => extractSingleEntryZip(zip, { maxUncompressedBytes: 1024 }));
    expect(error.code).toBe("declared-size");
    expect(error.message).toMatch(/4096/);
  });

  it("stops a deflate stream that expands past the cap", () => {
    const bomb = Buffer.alloc(1024 * 1024, 0x61);
    // Declares 10 bytes so the pre-check passes; actually inflates to 1 MiB.
    const zip = buildZip([
      { name: "bomb.csv", data: bomb, method: 8, declaredUncompressedSize: 10 },
    ]);
    const error = zipFailure(() => extractSingleEntryZip(zip, { maxUncompressedBytes: 1024 }));
    expect(error.code).toBe("inflated-size");
    expect(error.message).toMatch(/exceeds the 1024-byte cap/);
  });

  it("rejects bytes that are not a zip archive", () => {
    const error = zipFailure(() =>
      extractSingleEntryZip(Buffer.from("this is plainly not a zip file"), {
        maxUncompressedBytes: CAP,
      }),
    );
    expect(error.code).toBe("not-zip");
    expect(error.message).toMatch(/not a zip archive/);
  });

  it("rejects a missing or non-positive cap instead of reading unbounded", () => {
    const zip = buildZip([{ name: "a.csv", data: Buffer.from("a") }]);
    expect(zipFailure(() => extractSingleEntryZip(zip, { maxUncompressedBytes: 0 })).code).toBe(
      "invalid-cap",
    );
    expect(
      zipFailure(() => extractSingleEntryZip(zip, { maxUncompressedBytes: Number.NaN })).code,
    ).toBe("invalid-cap");
  });

  it("feeds a deflated archive through CSV parsing and mapping", () => {
    const csv = `${CSV}79,Cross-site Scripting,Base,Stable,"Does not neutralize input.","Encode output."\n`;
    const zip = buildZip([{ name: "cwec_v4.17.csv", data: Buffer.from(csv, "utf8"), method: 8 }]);

    const extracted = extractSingleEntryZip(zip, { maxUncompressedBytes: CAP });
    const mapped = mapCweCsv(parseCsvRows(extracted.data.toString("utf8")));

    expect(mapped.skipped).toBe(0);
    expect(mapped.entries).toHaveLength(1);
    expect(mapped.entries[0]).toMatchObject({
      id: "CWE-79",
      name: "Cross-site Scripting",
      abstraction: "Base",
      status: "Stable",
      summary: "Does not neutralize input.",
      mitigation: "Encode output.",
    });
  });
});

describe("parseCsvRows", () => {
  it("keeps a quoted field containing a comma in one cell", () => {
    expect(parseCsvRows('a,b\n1,"x,y"\n')).toEqual([
      ["a", "b"],
      ["1", "x,y"],
    ]);
  });

  it("unescapes doubled quotes inside a quoted field", () => {
    expect(parseCsvRows('header\n"He said ""hi"""\n')).toEqual([["header"], ['He said "hi"']]);
  });

  it("returns the same rows for CRLF and LF input", () => {
    const lf = 'id,name\n79,"Cross-site scripting, stored"\n89,"SQL, injection"\n';
    const crlf = lf.replace(/\n/g, "\r\n");
    expect(parseCsvRows(crlf)).toEqual(parseCsvRows(lf));
    expect(parseCsvRows(lf)).toHaveLength(3);
  });

  it("keeps a final line that has no trailing newline", () => {
    expect(parseCsvRows("a,b\n1,2")).toEqual([
      ["a", "b"],
      ["1", "2"],
    ]);
  });

  it("drops blank lines and a leading UTF-8 BOM", () => {
    expect(parseCsvRows("\ufeffa,b\r\n\r\n1,2\r\n\r\n")).toEqual([
      ["a", "b"],
      ["1", "2"],
    ]);
  });

  it("rejects input above the size cap", () => {
    const oversized = "a".repeat(CWE_CSV_MAX_BYTES + 1);
    const error = csvFailure(() => parseCsvRows(oversized));
    expect(error.code).toBe("input-too-large");
    expect(error.message).toContain(String(CWE_CSV_MAX_BYTES));
  });

  it("rejects an unterminated quoted field", () => {
    const error = csvFailure(() => parseCsvRows('a,b\n1,"never closed\n'));
    expect(error.code).toBe("malformed-csv");
    expect(error.message).toMatch(/unterminated quoted field/);
  });

  it("rejects text after a closing quote", () => {
    const error = csvFailure(() => parseCsvRows('a,b\n1,"closed"then\n'));
    expect(error.code).toBe("malformed-csv");
    expect(error.message).toMatch(/after a closing quote/);
  });
});

describe("mapCweCsv", () => {
  it("maps a realistic two-row MITRE sample by header name", () => {
    const csv = [
      "CWE-ID,Name,Weakness Abstraction,Status,Description,Potential Mitigations,Extended Description",
      `79,"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",Base,Stable,"The software does not neutralize user-controllable input before it is placed in output that is used as a web page.","Implement input validation and context-aware output encoding, e.g. ""escape"" all untrusted values.","ignored extended text"`,
      `CWE-89,SQL Injection,Base,Draft,"The software constructs part of an SQL command using externally-influenced input.","Use parameterized queries (prepared statements) instead of string concatenation.","ignored extended text"`,
    ].join("\r\n");

    const { entries, skipped } = mapCweCsv(parseCsvRows(csv));

    expect(skipped).toBe(0);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toEqual({
      id: "CWE-79",
      name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
      abstraction: "Base",
      status: "Stable",
      summary:
        "The software does not neutralize user-controllable input before it is placed in output that is used as a web page.",
      mitigation:
        'Implement input validation and context-aware output encoding, e.g. "escape" all untrusted values.',
    });
    expect(entries[1]).toEqual({
      id: "CWE-89",
      name: "SQL Injection",
      abstraction: "Base",
      status: "Draft",
      summary: "The software constructs part of an SQL command using externally-influenced input.",
      mitigation:
        "Use parameterized queries (prepared statements) instead of string concatenation.",
    });
    // Unknown columns are ignored, not carried through under any name.
    for (const entry of entries) {
      expect(Object.keys(entry).sort()).toEqual([
        "abstraction",
        "id",
        "mitigation",
        "name",
        "status",
        "summary",
      ]);
    }
  });

  it("maps by header name when columns are reordered", () => {
    const csv = [
      "Status,Description,CWE-ID,Name,Weakness Abstraction,Potential Mitigations",
      'Stable,"Summary text.",79,Cross-site Scripting,Base,"Mitigation text."',
    ].join("\n");

    const { entries } = mapCweCsv(parseCsvRows(csv));

    expect(entries).toHaveLength(1);
    expect(entries[0]).toEqual({
      id: "CWE-79",
      name: "Cross-site Scripting",
      abstraction: "Base",
      status: "Stable",
      summary: "Summary text.",
      mitigation: "Mitigation text.",
    });
  });

  it("matches header names case-insensitively", () => {
    const csv = "cwe-id,NAME,Weakness Abstraction,STATUS\n79,Cross-site Scripting,Base,Stable";

    const { entries } = mapCweCsv(parseCsvRows(csv));

    expect(entries[0]).toMatchObject({
      id: "CWE-79",
      name: "Cross-site Scripting",
      abstraction: "Base",
      status: "Stable",
    });
  });

  it("skips and counts rows with an unusable id", () => {
    const csv = [
      "CWE-ID,Name",
      "79,Good row",
      ",Missing id",
      "not-a-cwe,Bad id",
      "CWE-0,Zero",
    ].join("\n");

    const { entries, skipped } = mapCweCsv(parseCsvRows(csv));

    expect(entries.map((entry) => entry.id)).toEqual(["CWE-79"]);
    expect(skipped).toBe(3);
  });

  it("normalizes 79, cwe-79, and CWE-79 to CWE-79", () => {
    for (const raw of ["79", "cwe-79", "CWE-79", "0079"]) {
      const { entries } = mapCweCsv([
        ["CWE-ID", "Name"],
        [raw, "Cross-site Scripting"],
      ]);
      expect(entries).toHaveLength(1);
      expect(entries[0]?.id).toBe("CWE-79");
    }
  });

  it("collapses duplicate normalized ids and counts the duplicates", () => {
    const csv = ["CWE-ID,Name", "79,First", "cwe-79,Second", "CWE-79,Third"].join("\n");

    const { entries, skipped } = mapCweCsv(parseCsvRows(csv));

    expect(entries).toHaveLength(1);
    expect(entries[0]?.name).toBe("First");
    expect(skipped).toBe(2);
  });

  it("truncates summary and mitigation at 600 code points with an ellipsis", () => {
    const longSummary = "a".repeat(CWE_SUMMARY_MAX_CHARS + 100);
    const longMitigation = "b".repeat(CWE_MITIGATION_MAX_CHARS + 1);
    const csv = [
      "CWE-ID,Name,Description,Potential Mitigations",
      `79,Cross-site Scripting,${longSummary},${longMitigation}`,
    ].join("\n");

    const { entries } = mapCweCsv(parseCsvRows(csv));
    const entry = entries[0];

    expect(entry?.summary).toHaveLength(CWE_SUMMARY_MAX_CHARS + 1);
    expect(entry?.summary?.endsWith("…")).toBe(true);
    expect(entry?.summary?.slice(0, CWE_SUMMARY_MAX_CHARS)).toBe(longSummary.slice(0, 600));
    expect(entry?.mitigation).toHaveLength(CWE_MITIGATION_MAX_CHARS + 1);
    expect(entry?.mitigation?.endsWith("…")).toBe(true);
  });

  it("keeps text of exactly 600 code points without an ellipsis", () => {
    const exact = "c".repeat(CWE_SUMMARY_MAX_CHARS);
    const { entries } = mapCweCsv([
      ["CWE-ID", "Name", "Description"],
      ["79", "Cross-site Scripting", exact],
    ]);

    expect(entries[0]?.summary).toBe(exact);
    expect(entries[0]?.summary).not.toContain("…");
  });

  it("strips CR/LF inside fields to single spaces and nulls absent optionals", () => {
    const csv = [
      "CWE-ID,Name,Description",
      '79,"Cross-site Scripting","Line one.\nLine two."',
    ].join("\n");

    const { entries } = mapCweCsv(parseCsvRows(csv));

    expect(entries[0]?.summary).toBe("Line one. Line two.");
    expect(entries[0]?.abstraction).toBeNull();
    expect(entries[0]?.status).toBeNull();
    expect(entries[0]?.mitigation).toBeNull();
  });

  it("counts every data row when the id column is absent", () => {
    const { entries, skipped } = mapCweCsv([
      ["Name", "Description"],
      ["Cross-site Scripting", "text"],
    ]);

    expect(entries).toEqual([]);
    expect(skipped).toBe(1);
  });
});
