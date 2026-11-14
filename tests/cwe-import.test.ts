// Unit coverage for the dependency-free zip reader, CWE CSV parser, and the
// catalog ingest half (v3 E3 steps 2a-2b).
//
// Every zip fixture is built in this file (local headers, central directory,
// EOCD) so no binary blob is committed and the tests stay readable: each case
// states exactly which part of the framing it is exercising. Zip fixtures are
// in-process. The ingest tests use a real migrated SQLite file in a temp dir
// and an injected fetcher, so no test ever reaches cwe.mitre.org.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";

import {
  CWE_CSV_MAX_BYTES,
  CWE_CSV_URL_DEFAULT,
  CWE_CSV_VIEW,
  CWE_MITIGATION_MAX_CHARS,
  CWE_REASON_MAX_CHARS,
  CWE_REFRESH_INTERVAL_MS,
  CWE_SUMMARY_MAX_CHARS,
  CWE_ZIP_MAX_BYTES,
  CweImportError,
  isCweRefreshDue,
  mapCweCsv,
  parseCsvRows,
  refreshCweCatalog,
  resolveCweCsvUrl,
  sanitizeCweReason,
} from "../src/lib/cwe-import";
import { getCweCatalogMeta, resolveCweIds } from "../src/lib/cwe-catalog";
import { openDatabase, type CveDatabase } from "../src/lib/db";
import { ZipExtractError, extractSingleEntryZip } from "../src/lib/zip";
import {
  type SourceJobDeps,
  type WorkerLog,
  resolveRefreshCweOnce,
  runCweRefreshOnce,
  runWorker,
} from "../src/worker";

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

// ---------------------------------------------------------------------------
// Ingest half (step 2b): fetch -> unzip -> parse -> publish, with
// last-known-good semantics. Every fetch is injected; no real network.
// ---------------------------------------------------------------------------

const tempDirs: string[] = [];
const databases: CveDatabase[] = [];

function makeDatabase(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-cwe-ingest-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  databases.push(db);
  return db;
}

afterEach(() => {
  while (databases.length > 0) {
    try {
      (databases.pop() as CveDatabase).close();
    } catch {
      /* best effort */
    }
  }
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

const INGEST_CSV = [
  "CWE-ID,Name,Weakness Abstraction,Status,Description,Potential Mitigations",
  '79,"Cross-site Scripting",Base,Stable,"Does not neutralize input.","Encode output."',
  '89,"SQL Injection",Base,Stable,"Builds SQL from untrusted input.","Use prepared statements."',
].join("\n");

function ingestZip(csv: string = INGEST_CSV): Buffer {
  return buildZip([{ name: "1000.csv", data: Buffer.from(csv, "utf8"), method: 8 }]);
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

interface FakeFetch {
  fetcher: typeof fetch;
  calls: () => number;
}

function fakeFetch(handler: () => Response | Promise<Response>): FakeFetch {
  let calls = 0;
  const fetcher = (async () => {
    calls += 1;
    return handler();
  }) as unknown as typeof fetch;
  return { fetcher, calls: () => calls };
}

function okBytes(bytes: Buffer): FakeFetch {
  return fakeFetch(() => new Response(new Uint8Array(bytes), { status: 200 }));
}

function entryRows(
  db: CveDatabase,
): Array<{ cwe_id: string; name: string; updated_at: string; version: string }> {
  return db.handle
    .prepare("SELECT cwe_id, name, updated_at, version FROM cwe_entries ORDER BY cwe_id")
    .all() as Array<{ cwe_id: string; name: string; updated_at: string; version: string }>;
}

const AT = new Date("2026-11-14T10:00:00.000Z");
const LATER = new Date("2026-11-15T10:00:00.000Z");

describe("refreshCweCatalog", () => {
  it("publishes entries and a ready meta row with the hash and record count", async () => {
    const db = makeDatabase();
    const zip = ingestZip();
    const fake = okBytes(zip);

    const result = await refreshCweCatalog(db, { fetcher: fake.fetcher, now: () => AT });

    expect(result).toMatchObject({
      status: "refreshed",
      version: `${CWE_CSV_VIEW}-2`,
      recordCount: 2,
      sourceHash: sha256(zip),
      retrievedAt: AT.toISOString(),
      recovered: false,
    });
    expect(fake.calls()).toBe(1);

    const meta = getCweCatalogMeta(db);
    expect(meta).toMatchObject({
      status: "ready",
      version: `${CWE_CSV_VIEW}-2`,
      sourceHash: sha256(zip),
      retrievedAt: AT.toISOString(),
    });
    const notes = db.handle
      .prepare("SELECT notes, record_count FROM cwe_catalog_meta WHERE id = 1")
      .get() as { notes: string | null; record_count: number };
    expect(notes.record_count).toBe(2);
    expect(notes.notes).toBeNull();

    expect(entryRows(db).map((row) => row.cwe_id)).toEqual(["CWE-79", "CWE-89"]);
    // The published catalog is what the read path serves.
    const refs = resolveCweIds(db, ["79", "89"]);
    expect(refs.get("CWE-79")).toMatchObject({ status: "known", name: "Cross-site Scripting" });
  });

  it("treats identical bytes as unchanged and writes nothing a second time", async () => {
    const db = makeDatabase();
    const zip = ingestZip();
    const first = okBytes(zip);
    const second = okBytes(zip);

    await refreshCweCatalog(db, { fetcher: first.fetcher, now: () => AT });
    const rowsAfterFirst = entryRows(db);
    const metaAfterFirst = getCweCatalogMeta(db);

    const result = await refreshCweCatalog(db, { fetcher: second.fetcher, now: () => LATER });

    expect(result).toEqual({
      status: "unchanged",
      version: `${CWE_CSV_VIEW}-2`,
      sourceHash: sha256(zip),
      recordCount: 2,
    });
    expect(second.calls()).toBe(1);
    // No second write: same rows (same per-row updated_at) and same meta pin.
    expect(entryRows(db)).toEqual(rowsAfterFirst);
    expect(getCweCatalogMeta(db)).toEqual(metaAfterFirst);
    expect(entryRows(db)).toHaveLength(2);
  });

  const failures: Array<{ name: string; handler: () => Response; reason: RegExp }> = [
    {
      name: "HTTP 500",
      handler: () => new Response("upstream exploded", { status: 500 }),
      reason: /HTTP 500 from cwe\.mitre\.org/,
    },
    {
      name: "a payload that is not a zip",
      handler: () =>
        new Response(new Uint8Array(Buffer.from("plainly not a zip")), { status: 200 }),
      reason: /not a zip archive/,
    },
    {
      name: "a payload declaring more bytes than the download cap",
      handler: () =>
        new Response(new Uint8Array(ingestZip()), {
          status: 200,
          headers: { "content-length": String(CWE_ZIP_MAX_BYTES + 1) },
        }),
      reason: /above the 8388608-byte download cap/,
    },
  ];

  for (const failure of failures) {
    it(`keeps the last-known-good catalog on ${failure.name} and marks meta stale`, async () => {
      const db = makeDatabase();
      const zip = ingestZip();
      await refreshCweCatalog(db, { fetcher: okBytes(zip).fetcher, now: () => AT });
      const before = entryRows(db);
      const hashBefore = getCweCatalogMeta(db).sourceHash;

      const result = await refreshCweCatalog(db, {
        fetcher: fakeFetch(failure.handler).fetcher,
        now: () => LATER,
      });

      expect(result.status).toBe("failed");
      const reason = (result as { reason: string }).reason;
      expect(reason).toMatch(failure.reason);
      expect(reason).not.toContain("\n");
      expect(reason.length).toBeLessThanOrEqual(CWE_REASON_MAX_CHARS);

      // Entries survive untouched; only the `ready` claim is withdrawn.
      expect(entryRows(db)).toEqual(before);
      const meta = getCweCatalogMeta(db);
      expect(meta.status).toBe("stale");
      expect(meta.sourceHash).toBe(hashBefore);
      const note = db.handle.prepare("SELECT notes FROM cwe_catalog_meta WHERE id = 1").get() as {
        notes: string | null;
      };
      expect(note.notes).toBe(reason);
      // A stale catalog serves no labels, even though the rows are still there.
      expect(resolveCweIds(db, ["79"]).get("CWE-79")?.status).toBe("taxonomy-unavailable");
    });
  }

  it("fails a hung fetch on the timeout without touching the catalog", async () => {
    const db = makeDatabase();
    await refreshCweCatalog(db, { fetcher: okBytes(ingestZip()).fetcher, now: () => AT });
    const before = entryRows(db);

    const result = await refreshCweCatalog(db, {
      fetcher: fakeFetch(() => new Promise<Response>(() => {})).fetcher,
      timeoutMs: 20,
      now: () => LATER,
    });

    expect(result.status).toBe("failed");
    expect((result as { reason: string }).reason).toMatch(/timed out after 20 ms/);
    expect(entryRows(db)).toEqual(before);
    expect(getCweCatalogMeta(db).status).toBe("stale");
  });

  it("rejects a payload above the download cap while streaming it", async () => {
    const db = makeDatabase();
    await refreshCweCatalog(db, { fetcher: okBytes(ingestZip()).fetcher, now: () => AT });

    const oversize = Buffer.alloc(CWE_ZIP_MAX_BYTES + 1, 0x61);
    const result = await refreshCweCatalog(db, {
      fetcher: okBytes(oversize).fetcher,
      now: () => LATER,
    });

    expect(result.status).toBe("failed");
    expect((result as { reason: string }).reason).toMatch(/download cap/);
    expect(entryRows(db)).toHaveLength(2);
    expect(getCweCatalogMeta(db).status).toBe("stale");
  });

  it("rolls the whole publish back when a failure lands mid-transaction", async () => {
    const db = makeDatabase();
    await refreshCweCatalog(db, { fetcher: okBytes(ingestZip()).fetcher, now: () => AT });
    const before = entryRows(db);

    // Fail the entry insert after the DELETE in the same transaction, so the
    // test proves the transaction boundary (not just the ordering).
    const handle = new Proxy(db.handle, {
      get(target, property, receiver) {
        if (property === "prepare") {
          return (sql: string) => {
            if (sql.includes("INSERT INTO cwe_entries")) {
              throw new Error("simulated publish failure");
            }
            return target.prepare(sql);
          };
        }
        return Reflect.get(target, property, receiver) as unknown;
      },
    });
    const failingDb = {
      handle,
      runBoundedWrite: <T>(fn: () => T): T => db.runBoundedWrite(fn),
      databaseFilePath: db.databaseFilePath,
    } as unknown as CveDatabase;

    const newCsv = [INGEST_CSV, "CWE-20,Improper Input Validation,Class,Stable,text,text"].join(
      "\n",
    );
    const result = await refreshCweCatalog(failingDb, {
      fetcher: okBytes(ingestZip(newCsv)).fetcher,
      now: () => LATER,
    });

    expect(result.status).toBe("failed");
    expect((result as { reason: string }).reason).toMatch(/simulated publish failure/);
    // The DELETE rolled back with the rest: the previous catalog is intact, and
    // the new run's entry never landed.
    expect(entryRows(db)).toEqual(before);
    expect(entryRows(db).some((row) => row.cwe_id === "CWE-20")).toBe(false);
    const meta = getCweCatalogMeta(db);
    expect(meta.status).toBe("stale");
    expect(meta.version).toBe(`${CWE_CSV_VIEW}-2`);
  });

  it("restores a stale catalog when the accepted bytes are still upstream", async () => {
    const db = makeDatabase();
    const zip = ingestZip();
    await refreshCweCatalog(db, { fetcher: okBytes(zip).fetcher, now: () => AT });
    await refreshCweCatalog(db, {
      fetcher: fakeFetch(() => new Response("nope", { status: 503 })).fetcher,
      now: () => LATER,
    });
    expect(getCweCatalogMeta(db).status).toBe("stale");
    const before = entryRows(db);

    const result = await refreshCweCatalog(db, {
      fetcher: okBytes(zip).fetcher,
      now: () => new Date("2026-11-16T10:00:00.000Z"),
    });

    expect(result).toMatchObject({ status: "refreshed", recovered: true, recordCount: 2 });
    expect(getCweCatalogMeta(db).status).toBe("ready");
    expect(entryRows(db)).toEqual(before);
  });

  it("refuses a non-https URL before any request is made", async () => {
    const db = makeDatabase();
    const fake = okBytes(ingestZip());

    const result = await refreshCweCatalog(db, {
      fetcher: fake.fetcher,
      url: "http://cwe.mitre.org/data/csv/1000.csv.zip",
    });

    expect(result.status).toBe("failed");
    expect((result as { reason: string }).reason).toMatch(/must be an https URL/);
    expect(fake.calls()).toBe(0);
    expect(getCweCatalogMeta(db).status).toBe("stale");
    expect(entryRows(db)).toEqual([]);
  });
});

describe("resolveCweCsvUrl", () => {
  it("defaults to the pinned view pack and ignores blank overrides", () => {
    expect(resolveCweCsvUrl({})).toBe(CWE_CSV_URL_DEFAULT);
    expect(CWE_CSV_URL_DEFAULT).toBe("https://cwe.mitre.org/data/csv/1000.csv.zip");
    expect(resolveCweCsvUrl({ CWE_CSV_URL: "" })).toBe(CWE_CSV_URL_DEFAULT);
    expect(resolveCweCsvUrl({ CWE_CSV_URL: "   " })).toBe(CWE_CSV_URL_DEFAULT);
  });

  it("honours an explicit override", () => {
    expect(resolveCweCsvUrl({ CWE_CSV_URL: "https://example.test/1000.csv.zip" })).toBe(
      "https://example.test/1000.csv.zip",
    );
  });
});

describe("sanitizeCweReason", () => {
  it("strips credentials from URLs and drops stack frames", () => {
    const reason = sanitizeCweReason(
      "CWE download failed at https://user:s3cret@cwe.mitre.org/data/x.zip?token=abc\n    at fetchZip (worker.mjs:1:1)",
    );

    expect(reason).toBe("CWE download failed at https://cwe.mitre.org/data/x.zip");
    expect(reason).not.toContain("s3cret");
    expect(reason).not.toContain("at fetchZip");
  });

  it("caps the length and never returns an empty reason", () => {
    expect(sanitizeCweReason("x".repeat(1000))).toHaveLength(CWE_REASON_MAX_CHARS);
    expect(sanitizeCweReason("\n\n")).toBe("unspecified failure");
  });
});

describe("isCweRefreshDue", () => {
  it("is due for a missing, empty, or unparseable anchor", () => {
    expect(isCweRefreshDue(null, AT)).toBe(true);
    expect(isCweRefreshDue("", AT)).toBe(true);
    expect(isCweRefreshDue("not-a-date", AT)).toBe(true);
  });

  it("is not due inside the interval and due after it", () => {
    const anchor = AT.toISOString();
    expect(isCweRefreshDue(anchor, new Date(AT.getTime() + 60_000))).toBe(false);
    expect(isCweRefreshDue(anchor, new Date(AT.getTime() + CWE_REFRESH_INTERVAL_MS - 1))).toBe(
      false,
    );
    expect(isCweRefreshDue(anchor, new Date(AT.getTime() + CWE_REFRESH_INTERVAL_MS))).toBe(true);
  });
});

describe("REFRESH_CWE_ONCE one-off path", () => {
  it("resolves the gate and runs exactly one refresh with the injected fetcher", async () => {
    const db = makeDatabase();
    const zip = ingestZip();
    const fake = okBytes(zip);
    const logs: WorkerLog[] = [];

    expect(resolveRefreshCweOnce({ REFRESH_CWE_ONCE: "true" })).toBe(true);
    expect(resolveRefreshCweOnce({})).toBe(false);
    expect(resolveRefreshCweOnce({ REFRESH_CWE_ONCE: "1" })).toBe(false);

    const result = await runCweRefreshOnce({
      db,
      fetcher: fake.fetcher,
      log: (entry) => {
        logs.push(entry);
      },
    });

    expect(result.status).toBe("refreshed");
    expect(fake.calls()).toBe(1);
    expect(logs).toEqual([
      {
        event: "cwe-refresh",
        version: `${CWE_CSV_VIEW}-2`,
        recordCount: 2,
        sourceHash: sha256(zip),
        recovered: false,
      },
    ]);

    // A second run with the same bytes is the conditional no-op, logged as such.
    const second = await runCweRefreshOnce({
      db,
      fetcher: okBytes(zip).fetcher,
      log: (entry) => {
        logs.push(entry);
      },
    });
    expect(second.status).toBe("unchanged");
    expect(logs[1]).toMatchObject({ event: "cwe-refresh-unchanged", recordCount: 2 });
  });

  it("logs and returns a failed result instead of throwing", async () => {
    const db = makeDatabase();
    const logs: WorkerLog[] = [];

    const result = await runCweRefreshOnce({
      db,
      refresh: async () => {
        throw new Error("boom at https://user:pw@example.test/x\nstack");
      },
      log: (entry) => {
        logs.push(entry);
      },
    });

    expect(result).toEqual({ status: "failed", reason: "boom at https://example.test/x" });
    expect(logs).toEqual([
      { event: "cwe-refresh-failed", reason: "boom at https://example.test/x" },
    ]);
  });
});

describe("worker CWE refresh hook", () => {
  const KEV_RESULT = {
    ok: true as const,
    catalogVersion: "2026.10.25",
    catalogDate: "2026-10-25T00:00:00.000Z",
    total: 0,
    added: [],
    removed: [],
    unmatched: [],
  };
  const EPSS_RESULT = {
    scoreDate: "2026-10-24",
    modelVersion: "v2025.03.14",
    rowCount: 0,
    unmatched: [],
    contentHash: "cafef00d",
    prunedRows: 0,
    oldestKept: null,
    alreadyCurrent: true,
  };

  function workerDeps(cweCalls: { count: number }): SourceJobDeps {
    return {
      cveImport: () => ({
        ok: true,
        revision: "abc123def456",
        reconciledFull: true,
        alreadyCurrent: true,
        transitions: { added: [], changed: [], deleted: [], rejected: [] },
        quarantined: [],
        contentHash: "deadbeef",
      }),
      kevImport: async () => KEV_RESULT,
      epssImport: async () => EPSS_RESULT,
      ssvcImport: async () => ({ revision: "rev-ssvc", parsed: 0 }),
      cweRefreshEnabled: true,
      cweRefresh: async () => {
        cweCalls.count += 1;
        return { status: "unchanged", version: "", sourceHash: "", recordCount: 0 };
      },
    };
  }

  it("runs at most once per cadence window while the cycle keeps succeeding", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "cve-worker-cwe-"));
    tempDirs.push(dir);
    const calls = { count: 0 };
    const logs: WorkerLog[] = [];

    const { db, scheduler, cweSettled } = await runWorker({
      dataDir: dir,
      scheduleEnabled: false,
      deps: workerDeps(calls),
      installHandlers: false,
      log: (entry) => {
        logs.push(entry);
      },
    });
    databases.push(db);

    try {
      await cweSettled();
      expect(calls.count).toBe(1);

      await scheduler.runCycle();
      await cweSettled();
      // The gate suppresses the second attempt, so there is exactly one log.
      expect(calls.count).toBe(1);
      expect(logs.filter((entry) => entry.event === "cwe-refresh-unchanged")).toHaveLength(1);
    } finally {
      await scheduler.shutdown();
    }
  });

  it("keeps the cycle green when the CWE refresh fails", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "cve-worker-cwe-fail-"));
    tempDirs.push(dir);
    const logs: WorkerLog[] = [];

    const { db, scheduler, cweSettled } = await runWorker({
      dataDir: dir,
      scheduleEnabled: false,
      deps: {
        ...workerDeps({ count: 0 }),
        cweRefresh: async () => {
          throw new Error("upstream said no");
        },
      },
      installHandlers: false,
      log: (entry) => {
        logs.push(entry);
      },
    });
    databases.push(db);

    try {
      await cweSettled();
      const cycles = logs.filter((entry) => entry.event === "ingest-cycle");
      expect(cycles).toHaveLength(4);
      for (const cycle of cycles) {
        expect(cycle.ok).toBe(true);
      }
      expect(logs.some((entry) => entry.event === "cwe-refresh-failed")).toBe(true);
    } finally {
      await scheduler.shutdown();
    }
  });
});
