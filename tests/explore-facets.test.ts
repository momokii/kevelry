import type Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { openDatabase, type CveDatabase } from "../src/lib/db";
import { searchCves, searchFacets, type SearchFilters } from "../src/lib/search";

const tempDirs: string[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-facets-test-"));
  tempDirs.push(dir);
  return openDatabase({ dataDir: dir });
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop() as string;
    rmSync(dir, { recursive: true, force: true });
  }
});

const STAMP = "2026-10-24T00:00:00.000Z";

interface Fixture {
  cveId: string;
  description: string;
  state?: string;
  published?: string | null;
  metrics?: Array<{ origin: string; version: string; baseScore: string }>;
  kev?: boolean;
  epss?: boolean;
}

function seed(db: CveDatabase, fixtures: Fixture[]): void {
  db.runBoundedWrite(() => {
    const handle: Database.Database = db.handle;
    for (const fixture of fixtures) {
      handle
        .prepare(
          "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, title, description, description_lang, source_revision, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          fixture.cveId,
          "5.1",
          fixture.state ?? "PUBLISHED",
          fixture.published ?? null,
          null,
          fixture.cveId,
          fixture.description,
          "en",
          "rev-test",
          STAMP,
          STAMP,
        );
      for (const [index, metric] of (fixture.metrics ?? []).entries()) {
        handle
          .prepare(
            "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
          )
          .run(
            fixture.cveId,
            metric.origin,
            metric.version,
            metric.baseScore,
            "CVSS:3.1/AV:N",
            index,
          );
      }
      if (fixture.kev === true) {
        handle
          .prepare(
            "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
          )
          .run(fixture.cveId, "2026-10-20T00:00:00.000Z", "2026-10-22", STAMP);
      }
      if (fixture.epss === true) {
        handle
          .prepare(
            "INSERT INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
          )
          .run(fixture.cveId, "2026-10-23", "v1", "0.42", "0.91");
      }
    }
  });
}

function facetFixtures(): Fixture[] {
  return [
    {
      cveId: "CVE-2099-1001",
      description: "Remote heap overflow in the parser service",
      published: "2026-08-10T00:00:00.000Z",
      metrics: [{ origin: "CNA", version: "3.1", baseScore: "9.8" }],
      kev: true,
      epss: true,
    },
    {
      cveId: "CVE-2099-1002",
      description: "Parser service privilege escalation flaw",
      published: "2026-08-15T00:00:00.000Z",
      metrics: [{ origin: "CNA", version: "3.1", baseScore: "7.5" }],
      epss: true,
    },
    {
      cveId: "CVE-2099-1003",
      description: "Kernel memory disclosure via crafted ioctl",
      published: "2026-09-02T00:00:00.000Z",
      metrics: [{ origin: "CNA", version: "3.1", baseScore: "5.0" }],
      kev: true,
    },
    {
      cveId: "CVE-2099-1004",
      description: "Minor log file information leak on restart",
      published: "2026-09-20T00:00:00.000Z",
      metrics: [{ origin: "CNA", version: "3.0", baseScore: "2.1" }],
    },
    {
      cveId: "CVE-2099-1005",
      description: "Hardening note with no security impact scored zero",
      published: "2026-10-01T00:00:00.000Z",
      metrics: [{ origin: "CNA", version: "3.1", baseScore: "0.0" }],
    },
    {
      cveId: "CVE-2099-1006",
      description: "Legacy boundary check from the old module",
      published: "2026-10-05T00:00:00.000Z",
      metrics: [{ origin: "CNA", version: "2.0", baseScore: "7.5" }],
      epss: true,
    },
    {
      cveId: "CVE-2099-1007",
      description: "Undated parser crash with no metric supplied",
      published: null,
      metrics: [],
      kev: true,
    },
    {
      cveId: "CVE-2099-1008",
      description: "ADP-only scored parser reflog issue",
      published: "2026-10-12T00:00:00.000Z",
      metrics: [{ origin: "ADP", version: "3.1", baseScore: "9.9" }],
    },
    {
      cveId: "CVE-2099-1009",
      description: "Early summer cache poisoning weakness",
      published: "2026-07-01T00:00:00.000Z",
      metrics: [],
    },
    {
      cveId: "CVE-2099-1010",
      description: "Rejected parser record that must stay out",
      state: "REJECTED",
      published: "2026-08-10T00:00:00.000Z",
      metrics: [{ origin: "CNA", version: "3.1", baseScore: "9.9" }],
    },
  ];
}

function directMonthCounts(
  db: CveDatabase,
  extraWhere: string,
  extraParams: unknown[],
): Array<{ month: string; count: number }> {
  const rows = db.handle
    .prepare(
      `SELECT substr(r.date_published, 1, 7) AS month, COUNT(*) AS n FROM cve_records r ` +
        `WHERE r.state = ? AND r.date_published IS NOT NULL ${extraWhere} GROUP BY month ORDER BY month ASC`,
    )
    .all("PUBLISHED", ...extraParams) as Array<{ month: string; n: number }>;
  return rows.map((row) => ({ month: row.month, count: row.n }));
}

describe("explore cohort facets (task 48)", () => {
  it("matches direct SQL truth on a seeded fixture across months, bands, KEV, and EPSS", () => {
    const db = makeDb();
    try {
      seed(db, facetFixtures());
      const facets = searchFacets(db, {});

      expect(facets.total).toBe(9);
      expect(facets.bySeverity).toEqual({
        critical: 1,
        high: 1,
        medium: 1,
        low: 1,
        none: 1,
        legacy: 1,
        unknown: 3,
      });
      expect(facets.kevMembers).toBe(3);
      expect(facets.epssKnown).toBe(3);
      expect(facets.unknownDate).toBe(1);
      expect(facets.byMonth).toEqual([
        { month: "2026-07", count: 1 },
        { month: "2026-08", count: 2 },
        { month: "2026-09", count: 2 },
        { month: "2026-10", count: 3 },
      ]);
      expect(facets.byMonth).toEqual(directMonthCounts(db, "", []));

      const directTotals = db.handle
        .prepare(
          "SELECT COUNT(*) AS total, COUNT(CASE WHEN r.date_published IS NULL THEN 1 END) AS u FROM cve_records r WHERE r.state = ?",
        )
        .get("PUBLISHED") as { total: number; u: number };
      expect(facets.total).toBe(directTotals.total);
      expect(facets.unknownDate).toBe(directTotals.u);
    } finally {
      db.close();
    }
  });

  it("is null-safe and empty on a cohort with no matches", () => {
    const db = makeDb();
    try {
      seed(db, facetFixtures());
      const facets = searchFacets(db, { q: "nomatchingtermxyz" });
      expect(facets).toEqual({
        total: 0,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0, none: 0, legacy: 0, unknown: 0 },
        kevMembers: 0,
        epssKnown: 0,
        unknownDate: 0,
        byMonth: [],
      });
    } finally {
      db.close();
    }
  });

  it("stays identical to listing coverage across filter combinations", () => {
    const db = makeDb();
    try {
      seed(db, facetFixtures());
      const combos: SearchFilters[] = [
        { kev: "only" },
        { kev: "excluded" },
        { epss: "present" },
        { epss: "absent" },
        { severity: ["critical", "high"] },
        { severity: ["unknown"] },
        { dateStart: "2026-09-01T00:00:00.000Z", dateEnd: "2026-10-01T00:00:00.000Z" },
        { q: "parser" },
        { q: "CVE-2099-100" },
        { kev: "only", epss: "present", severity: ["critical"] },
        { q: "parser", kev: "excluded", dateStart: "2026-08-01T00:00:00.000Z" },
      ];
      for (const filters of combos) {
        const facets = searchFacets(db, filters);
        const response = searchCves(db, { ...filters, limit: 2 });
        expect(facets.total, `total ${JSON.stringify(filters)}`).toBe(response.coverage.total);
        expect(facets.bySeverity, `bySeverity ${JSON.stringify(filters)}`).toEqual(
          response.coverage.bySeverity,
        );
        expect(facets.kevMembers, `kev ${JSON.stringify(filters)}`).toBe(
          response.coverage.kevMembers,
        );
        expect(facets.epssKnown, `epss ${JSON.stringify(filters)}`).toBe(
          response.coverage.epssKnown,
        );
        expect(facets.unknownDate, `unknownDate ${JSON.stringify(filters)}`).toBe(
          response.coverage.unknownDate,
        );
        const dated = facets.byMonth.reduce((sum, entry) => sum + entry.count, 0);
        expect(dated + facets.unknownDate, `months+unknown ${JSON.stringify(filters)}`).toBe(
          facets.total,
        );
      }
    } finally {
      db.close();
    }
  });

  it("caps the monthly histogram at 24 buckets", () => {
    const db = makeDb();
    try {
      const fixtures: Fixture[] = [];
      for (let index = 0; index < 30; index += 1) {
        const year = 2024 + Math.floor(index / 12);
        const month = String((index % 12) + 1).padStart(2, "0");
        fixtures.push({
          cveId: `CVE-2099-2${String(index).padStart(3, "0")}`,
          description: "Monthly histogram cap probe record",
          published: `${year}-${month}-15T00:00:00.000Z`,
          metrics: [{ origin: "CNA", version: "3.1", baseScore: "5.0" }],
        });
      }
      seed(db, fixtures);
      const facets = searchFacets(db, {});
      expect(facets.total).toBe(30);
      expect(facets.byMonth.length).toBeLessThanOrEqual(24);
      expect(facets.byMonth[facets.byMonth.length - 1]?.month).toBe("2026-06");
    } finally {
      db.close();
    }
  });

  it("reuses listing coverage for the fast path without changing any figure", () => {
    const db = makeDb();
    try {
      seed(db, facetFixtures());
      const response = searchCves(db, { limit: 5 });
      const full = searchFacets(db, {});
      const fast = searchFacets(db, {}, response.coverage);
      expect(fast).toEqual(full);
    } finally {
      db.close();
    }
  });
});
