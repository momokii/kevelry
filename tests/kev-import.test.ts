// New-test justification (plan todo 9): the KEV snapshot importer is the
// first feed that flips a current-membership flag with separate history, so
// tests must prove what the contract stubs cannot: validation rejects a
// tampered/partial catalog before any write, membership replacement is
// atomic, removals keep history rows, and unmatched IDs never manufacture
// CVE records. Fixtures use synthetic CVE-2099 IDs; the live URL appears
// only in the skipped-by-default smoke test below.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import {
  KEV_FEED_URL,
  KevImportError,
  fetchKevCatalog,
  importKevCatalog,
} from "../src/lib/kev-import";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-kev-test-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openDbs.push(db);
  return db;
}

afterEach(() => {
  while (openDbs.length > 0) {
    (openDbs.pop() as CveDatabase).close();
  }
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

const STAMP_A = "2026-10-20T19:30:00.000Z";
const STAMP_B = "2026-10-21T19:30:00.000Z";
const NOW_A = "2026-10-20T20:00:00.000Z";
const NOW_B = "2026-10-21T20:00:00.000Z";

function kevEntry(cveId: string, dateAdded = "2026-10-18") {
  return { cveID: cveId, dateAdded, vendorProject: "Vendor", product: "Product" };
}

function catalog(catalogVersion: string, dateReleased: string, entries: unknown[]) {
  return {
    catalogVersion,
    dateReleased,
    count: entries.length,
    vulnerabilities: entries,
  };
}

function seedCve(db: CveDatabase, cveId: string): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(cveId, "5.1", "PUBLISHED", "Seed record", NOW_A, NOW_A);
  });
}

function membership(db: CveDatabase): string[] {
  const rows = db.handle
    .prepare("SELECT cve_id FROM kev_entries ORDER BY cve_id ASC")
    .all() as Array<{ cve_id: string }>;
  return rows.map((row) => row.cve_id);
}

function history(db: CveDatabase) {
  return db.handle
    .prepare(
      "SELECT cve_id, date_added, catalog_date, removed_in_catalog FROM kev_history ORDER BY cve_id ASC, id ASC",
    )
    .all() as Array<{
    cve_id: string;
    date_added: string;
    catalog_date: string;
    removed_in_catalog: string | null;
  }>;
}

describe("KEV snapshot importer (todo 9)", () => {
  it("publishes a first catalog and diffs a second one with history preserved", () => {
    const db = makeDb();
    seedCve(db, "CVE-2099-0001");
    seedCve(db, "CVE-2099-0002");

    const first = importKevCatalog(
      db,
      catalog("2026.10.20", STAMP_A, [kevEntry("CVE-2099-0001"), kevEntry("CVE-2099-0002")]),
      { now: NOW_A },
    );
    expect(first.ok).toBe(true);
    expect(first.total).toBe(2);
    expect(first.added).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
    expect(membership(db)).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);

    const second = importKevCatalog(
      db,
      catalog("2026.10.21", STAMP_B, [kevEntry("CVE-2099-0002"), kevEntry("CVE-2099-0003")]),
      { now: NOW_B },
    );
    expect(second.added).toEqual(["CVE-2099-0003"]);
    expect(second.removed).toEqual(["CVE-2099-0001"]);
    // Removal flips current membership but keeps the history row.
    expect(membership(db)).toEqual(["CVE-2099-0002", "CVE-2099-0003"]);
    const removedRow = history(db).find((row) => row.cve_id === "CVE-2099-0001");
    expect(removedRow).toMatchObject({
      cve_id: "CVE-2099-0001",
      catalog_date: STAMP_A,
      removed_in_catalog: "2026.10.21",
    });
    // dateAdded stays catalog-entry metadata; no first-exploit inference column exists.
    const columns = db.handle.prepare("PRAGMA table_info(kev_entries)").all() as Array<{
      name: string;
    }>;
    expect(columns.map((c) => c.name).sort()).toEqual(
      ["catalog_date", "cve_id", "date_added", "product", "recorded_at", "vendor_project"].sort(),
    );
  });

  it("aborts on a tampered declared count with last-known-good intact", () => {
    const db = makeDb();
    const good = catalog("2026.10.20", STAMP_A, [kevEntry("CVE-2099-0001")]);
    expect(importKevCatalog(db, good, { now: NOW_A }).ok).toBe(true);

    const tampered = {
      catalogVersion: "2026.10.21",
      dateReleased: STAMP_B,
      count: 3,
      vulnerabilities: [kevEntry("CVE-2099-0001"), kevEntry("CVE-2099-0002")],
    };
    expect(() => importKevCatalog(db, tampered, { now: NOW_B })).toThrowError(KevImportError);
    expect(membership(db)).toEqual(["CVE-2099-0001"]);
    expect(history(db)).toHaveLength(1);
    const runs = db.handle
      .prepare("SELECT status, revision FROM sync_runs WHERE source = ? ORDER BY id ASC")
      .all("kev") as Array<{ status: string; revision: string | null }>;
    expect(runs).toEqual([
      { status: "succeeded", revision: "2026.10.20" },
      { status: "failed", revision: null },
    ]);
  });

  it("rejects duplicate IDs, invalid IDs, and malformed dates without partial writes", () => {
    const db = makeDb();
    expect(
      importKevCatalog(db, catalog("2026.10.20", STAMP_A, [kevEntry("CVE-2099-0001")]), {
        now: NOW_A,
      }).ok,
    ).toBe(true);

    const badCatalogs = [
      catalog("2026.10.21", STAMP_B, [kevEntry("CVE-2099-0001"), kevEntry("CVE-2099-0001")]),
      catalog("2026.10.21", STAMP_B, [kevEntry("NOTACVE")]),
      catalog("2026.10.21", STAMP_B, [kevEntry("CVE-2099-0002", "October 21st, 2026")]),
      { catalogVersion: "", dateReleased: STAMP_B, count: 0, vulnerabilities: [] },
      { catalogVersion: "2026.10.21", dateReleased: "not-a-date", count: 0, vulnerabilities: [] },
      { catalogVersion: "2026.10.21", dateReleased: STAMP_B, count: 0 },
    ];
    for (const bad of badCatalogs) {
      expect(() => importKevCatalog(db, bad, { now: NOW_B })).toThrowError(KevImportError);
    }
    // Stale-state guarantee: every failure preserved the accepted snapshot.
    expect(membership(db)).toEqual(["CVE-2099-0001"]);
    expect(history(db)).toHaveLength(1);
  });

  it("reports unmatched IDs without manufacturing CVE records", () => {
    const db = makeDb();
    seedCve(db, "CVE-2099-0001");
    const outcome = importKevCatalog(
      db,
      catalog("2026.10.20", STAMP_A, [kevEntry("CVE-2099-0001"), kevEntry("CVE-2099-0777")]),
      { now: NOW_A },
    );
    expect(outcome.unmatched).toEqual(["CVE-2099-0777"]);
    const cveRows = db.handle.prepare("SELECT COUNT(*) AS n FROM cve_records").get() as {
      n: number;
    };
    expect(cveRows.n).toBe(1);
  });

  it("reimporting the identical catalog is a no-op diff", () => {
    const db = makeDb();
    const fixture = catalog("2026.10.20", STAMP_A, [kevEntry("CVE-2099-0001")]);
    const first = importKevCatalog(db, fixture, { now: NOW_A });
    const second = importKevCatalog(db, fixture, { now: NOW_B });
    expect(first.added).toEqual(["CVE-2099-0001"]);
    expect(second.added).toEqual([]);
    expect(second.removed).toEqual([]);
    expect(membership(db)).toEqual(["CVE-2099-0001"]);
    expect(history(db)).toHaveLength(1);
  });

  it("accepts full-timestamp dateAdded values alongside calendar dates", () => {
    const db = makeDb();
    const outcome = importKevCatalog(
      db,
      catalog("2026.10.20", STAMP_A, [
        kevEntry("CVE-2099-0001", "2026-10-18T00:00:00.000Z"),
        kevEntry("CVE-2099-0002", "2026-10-19"),
      ]),
      { now: NOW_A },
    );
    expect(outcome.ok).toBe(true);
    expect(membership(db)).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it.skip("live smoke: fetches and validates the real KEV catalog (needs network)", async () => {
    expect(KEV_FEED_URL).toMatch(/^https:\/\/www\.cisa\.gov\//);
    const raw = await fetchKevCatalog();
    const db = makeDb();
    const outcome = importKevCatalog(db, raw, { now: new Date().toISOString() });
    expect(outcome.ok).toBe(true);
    expect(outcome.total).toBeGreaterThan(0);
  });
});
