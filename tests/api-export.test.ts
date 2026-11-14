// New-test justification (v3 epic E5): `format=` is a new serialization of the
// search page, so it must be proven against the real handler that (a) CSV is
// RFC 4180-safe and carries exactly the header plus the page's rows, (b) the
// JSON export is the same envelope the route already served and still carries
// attachment headers, (c) an unknown format is a 400 instead of a silent
// fallback, (d) the export honours filters (so `exploit=tagged` can never leak
// the unfiltered set), and (e) `limit` still bounds the file — export is the
// current page, never a dump. Fixture IDs are invented CVE-2099 values.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import { resetDbOverride, setDbOverride } from "../app/api/v1/_lib/db-handle";
import { resetHardeningState } from "../app/api/v1/_lib/guardrails";
import { GET as getSearch } from "../app/api/v1/search/route";
import { SEARCH_EXPORT_COLUMNS } from "../src/lib/csv-export";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

const STAMP = "2026-10-24T00:00:00.000Z";
const MODEL = "v2026.06.15";
const SCORE_DATE = "2026-10-23";
const BASE = "https://radar.test/api/v1/search";

const TAGGED_RAW = JSON.stringify({
  containers: {
    cna: { references: [{ url: "https://example.test/poc", tags: ["exploit"] }] },
  },
});

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-api-export-test-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openDbs.push(db);
  setDbOverride(db);
  return db;
}

afterEach(() => {
  resetDbOverride();
  resetHardeningState();
  while (openDbs.length > 0) {
    try {
      (openDbs.pop() as CveDatabase).close();
    } catch {
      // Best-effort close before directory removal.
    }
  }
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

function seedRecord(
  db: CveDatabase,
  cveId: string,
  opts: {
    title: string | null;
    published: string | null;
    score?: string | null;
    kev?: string | null;
    epss?: { value: string; percentile: string } | null;
    tagged?: boolean;
  },
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, description_lang, source_revision, raw_json, created_at, updated_at, has_exploit_ref) VALUES (?, '5.1', 'PUBLISHED', ?, ?, 'packet parser fragmentation in the fragment queue', 'en', 'rev-export', ?, ?, ?, ?)",
      )
      .run(
        cveId,
        opts.published,
        opts.title,
        opts.tagged === true ? TAGGED_RAW : null,
        STAMP,
        STAMP,
        opts.tagged === true ? 1 : 0,
      );
    if (opts.score !== undefined && opts.score !== null) {
      db.handle
        .prepare(
          "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, 'CNA', '3.1', ?, 'CVSS:3.1/AV:N', 0)",
        )
        .run(cveId, opts.score);
    }
    if (opts.kev !== undefined && opts.kev !== null) {
      db.handle
        .prepare(
          "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, '2026.10.23', ?)",
        )
        .run(cveId, opts.kev, STAMP);
    }
    if (opts.epss !== undefined && opts.epss !== null) {
      db.handle
        .prepare(
          "INSERT INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
        )
        .run(cveId, SCORE_DATE, MODEL, opts.epss.value, opts.epss.percentile);
    }
  });
}

/** Three records: one tagged with a comma/quote title, two untagged. */
function seedExportCorpus(db: CveDatabase): void {
  seedRecord(db, "CVE-2099-0101", {
    title: 'Parser, "fragmented" datagrams',
    published: "2026-10-20T14:02:00.000Z",
    score: "9.2",
    kev: "2026-10-23",
    epss: { value: "0.1162", percentile: "0.96047" },
    tagged: true,
  });
  seedRecord(db, "CVE-2099-0102", {
    title: "Second record",
    published: "2026-10-19T09:30:00.000Z",
    score: "5.0",
  });
  seedRecord(db, "CVE-2099-0103", {
    title: null,
    published: null,
  });
}

function csvRecords(body: string): string[] {
  // Exports here never embed a newline inside a field, so CRLF is a safe split.
  return body.split("\r\n").filter((line) => line !== "");
}

function csvColumn(body: string, index: number): string[] {
  return csvRecords(body).map((line) => line.split(",")[index] ?? "");
}

async function textOf(response: Response): Promise<string> {
  return response.text();
}

describe("search export format", () => {
  it("serializes exactly the current page as text/csv with attachment headers", async () => {
    const db = makeDb();
    seedExportCorpus(db);

    const response = await getSearch(new Request(`${BASE}?q=packet&format=csv`));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/csv; charset=utf-8");
    expect(response.headers.get("content-disposition")).toMatch(
      /^attachment; filename="kevelry-search-\d{4}-\d{2}-\d{2}-3rows\.csv"$/,
    );
    expect(response.headers.get("x-ratelimit-limit")).toBe("600");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");

    const body = await textOf(response);
    const lines = csvRecords(body);
    expect(lines[0]).toBe(SEARCH_EXPORT_COLUMNS.join(","));
    expect(lines).toHaveLength(4);
    for (const line of lines) {
      expect(line.startsWith("#")).toBe(false);
    }
    // The CSV must carry the page's IDs, including the tagged row.
    expect(csvColumn(body, 0).slice(1).sort()).toEqual([
      "CVE-2099-0101",
      "CVE-2099-0102",
      "CVE-2099-0103",
    ]);
    // RFC 4180 quoting survives on the data row.
    expect(body).toContain('"Parser, ""fragmented"" datagrams"');
  });

  it("honours limit so the file is one page, not the whole cohort", async () => {
    const db = makeDb();
    seedExportCorpus(db);

    const response = await getSearch(new Request(`${BASE}?q=packet&limit=1&format=csv`));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-disposition")).toMatch(/-1rows\.csv"$/);
    expect(csvRecords(await textOf(response))).toHaveLength(2);
  });

  it("honours filters, so a filtered view cannot leak the unfiltered set", async () => {
    const db = makeDb();
    seedExportCorpus(db);

    const response = await getSearch(
      new Request(`${BASE}?q=packet&exploit=tagged&format=csv`),
    );
    expect(response.status).toBe(200);
    const ids = csvColumn(await textOf(response), 0).slice(1);
    expect(ids).toEqual(["CVE-2099-0101"]);

    const json = await getSearch(new Request(`${BASE}?q=packet&exploit=tagged&format=json`));
    const body = (await json.json()) as { data: Array<{ cveId: string }> };
    expect(body.data.map((row) => row.cveId)).toEqual(ids);
  });

  it("returns the unchanged JSON envelope plus attachment headers for format=json", async () => {
    const db = makeDb();
    seedExportCorpus(db);

    const plain = await getSearch(new Request(`${BASE}?q=packet`));
    const plainBody = (await plain.json()) as Record<string, unknown>;
    expect(plain.headers.get("content-disposition")).toBeNull();

    const exported = await getSearch(new Request(`${BASE}?q=packet&format=json`));
    expect(exported.status).toBe(200);
    expect(exported.headers.get("content-type")).toContain("application/json");
    expect(exported.headers.get("content-disposition")).toMatch(
      /^attachment; filename="kevelry-search-\d{4}-\d{2}-\d{2}-3rows\.json"$/,
    );
    const exportedBody = (await exported.json()) as Record<string, unknown>;
    // Same envelope; `generatedAt` is per-request, so the substantive keys are
    // compared rather than the whole object.
    expect(exportedBody.data).toEqual(plainBody.data);
    expect(exportedBody.pagination).toEqual(plainBody.pagination);
    expect(exportedBody.coverage).toEqual(plainBody.coverage);
    expect(exportedBody.q).toBe(plainBody.q);
    expect(exportedBody.vendor).toBe(plainBody.vendor);
    expect(exportedBody.provenance).toBeDefined();
  });

  it("rejects an unknown format instead of falling back", async () => {
    const db = makeDb();
    seedExportCorpus(db);

    const response = await getSearch(new Request(`${BASE}?q=packet&format=xml`));
    expect(response.status).toBe(400);
    const body = (await response.json()) as { code: string };
    expect(body.code).toBe("BAD_FILTER");

    const empty = await getSearch(new Request(`${BASE}?q=packet&format=`));
    expect(empty.status).toBe(200);
    expect(empty.headers.get("content-type")).toContain("application/json");
  });

  it("keeps the CSV empty page as a header row only", async () => {
    const db = makeDb();
    seedExportCorpus(db);

    const response = await getSearch(new Request(`${BASE}?q=nomatchxyz&format=csv`));
    expect(response.status).toBe(200);
    expect(await textOf(response)).toBe(`${SEARCH_EXPORT_COLUMNS.join(",")}\r\n`);
    expect(response.headers.get("content-disposition")).toMatch(/-0rows\.csv"$/);
  });
});
