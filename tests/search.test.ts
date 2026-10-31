// New-test justification (plan todo 13): the search service is the first
// reader-facing query path over the real SQLite layer, so tests must prove
// what unit checks cannot: FTS5 text search and ID/prefix search on a real
// file, UTC [start, end) date bucketing with unknown dates kept explicit,
// primary-CNA severity bands with legacy/unknown kept separate, KEV/EPSS
// join filters with coverage counts, cursor pagination, and hostile input
// that stays inert (no throw, no leak, schema intact). Fixtures are
// synthetic CVE-2099 IDs; nothing here touches the network.

import type Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { openDatabase, type CveDatabase } from "../src/lib/db";
import {
  DESCRIPTION_MISSING_LABEL,
  MAX_QUERY_LENGTH,
  MAX_SEARCH_LIMIT,
  excerptDescription,
  officialCveLink,
  searchCves,
  SearchValidationError,
  severityBandFor,
} from "../src/lib/search";

const tempDirs: string[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-search-test-"));
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
  title?: string | null;
  description?: string;
  lang?: string | null;
  state?: string;
  published?: string | null;
  updated?: string | null;
  metrics?: Array<{ origin: string; version: string; baseScore: string; vector?: string }>;
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
          fixture.updated ?? null,
          fixture.title ?? null,
          fixture.description ?? "",
          fixture.lang ?? null,
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
            metric.vector ?? "",
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

function baseFixtures(): Fixture[] {
  return [
    {
      cveId: "CVE-2099-0001",
      title: "Heap overflow",
      description: "A heap overflow in the parser allows remote code execution",
      lang: "en",
      published: "2026-10-20T00:00:00.000Z",
      metrics: [{ origin: "CNA", version: "3.1", baseScore: "9.8", vector: "CVSS:3.1/AV:N" }],
      kev: true,
      epss: true,
    },
    {
      cveId: "CVE-2099-0002",
      title: "Use after free",
      description: "A use-after-free in the renderer with moderate impact",
      lang: "en",
      published: "2026-10-21T00:00:00.000Z",
      metrics: [{ origin: "CNA", version: "3.1", baseScore: "5.4" }],
      epss: true,
    },
    {
      cveId: "CVE-2099-0003",
      description: "Une faille critique du parseur distant",
      lang: "fr",
      published: null,
      metrics: [{ origin: "ADP", version: "3.1", baseScore: "9.1" }],
    },
    {
      cveId: "CVE-2099-0004",
      title: "Legacy issue",
      description: "An old boundary issue in the legacy module",
      lang: "en",
      published: "2026-10-19T00:00:00.000Z",
      metrics: [{ origin: "CNA", version: "2.0", baseScore: "10.0" }],
      kev: true,
    },
    {
      cveId: "CVE-2099-0005",
      title: "Rejected record",
      description: "This record was rejected and must stay out of search",
      lang: "en",
      state: "REJECTED",
      published: "2026-10-20T00:00:00.000Z",
      metrics: [{ origin: "CNA", version: "3.1", baseScore: "9.9" }],
    },
    {
      cveId: "CVE-2099-0006",
      description: "",
      lang: null,
      published: "2026-10-22T00:00:00.000Z",
      metrics: [],
    },
  ];
}

function tableNames(db: CveDatabase): string[] {
  const rows = db.handle
    .prepare("SELECT name FROM sqlite_master WHERE type = ? ORDER BY name ASC")
    .all("table") as Array<{ name: string }>;
  return rows.map((row) => row.name);
}

describe("vendor/product filter over KEV catalog labels", () => {
  function seedVendorDb(db: CveDatabase): void {
    seed(db, baseFixtures());
    db.runBoundedWrite(() => {
      db.handle
        .prepare("UPDATE kev_entries SET vendor_project = ?, product = ? WHERE cve_id = ?")
        .run("Microsoft", "Windows Kernel", "CVE-2099-0001");
      db.handle
        .prepare("UPDATE kev_entries SET vendor_project = ?, product = ? WHERE cve_id = ?")
        .run("Cisco", "100% Switch", "CVE-2099-0004");
    });
  }

  it("matches vendor and product substrings case-insensitively", () => {
    const db = makeDb();
    try {
      seedVendorDb(db);
      expect(searchCves(db, { vendor: "micro" }).items.map((item) => item.cveId)).toEqual([
        "CVE-2099-0001",
      ]);
      expect(searchCves(db, { vendor: "KERNEL" }).items.map((item) => item.cveId)).toEqual([
        "CVE-2099-0001",
      ]);
      expect(searchCves(db, { vendor: "cisco" }).items.map((item) => item.cveId)).toEqual([
        "CVE-2099-0004",
      ]);
      expect(searchCves(db, { vendor: "no-such-vendor-xyz" }).items).toEqual([]);
    } finally {
      db.close();
    }
  });

  it("keeps LIKE wildcards literal and scopes to KEV-listed records", () => {
    const db = makeDb();
    try {
      seedVendorDb(db);
      // % and _ match literally, never as wildcards (100% Switch is found
      // by "100%", not by everything).
      expect(searchCves(db, { vendor: "100%" }).items.map((item) => item.cveId)).toEqual([
        "CVE-2099-0004",
      ]);
      expect(searchCves(db, { vendor: "%%" }).items).toEqual([]);
      // CVE-2099-0002 is PUBLISHED but not KEV-listed: no vendor labels exist.
      expect(searchCves(db, { vendor: "renderer" }).items).toEqual([]);
    } finally {
      db.close();
    }
  });

  it("combines with text search and rejects bad input", () => {
    const db = makeDb();
    try {
      seedVendorDb(db);
      expect(
        searchCves(db, { q: "parser", vendor: "microsoft" }).items.map((item) => item.cveId),
      ).toEqual(["CVE-2099-0001"]);
      expect(searchCves(db, { q: "renderer", vendor: "microsoft" }).items).toEqual([]);
      expect(() => searchCves(db, { vendor: "x" })).toThrowError(/2 to 100/);
      expect(() => searchCves(db, { vendor: "a".repeat(101) })).toThrowError(/100/);
      expect(() => searchCves(db, { vendor: 42 as unknown as string })).toThrowError(/string/);
    } finally {
      db.close();
    }
  });
});

describe("local FTS5 search (todo 13)", () => {
  it("lists PUBLISHED records and excludes REJECTED rows", () => {
    const db = makeDb();
    try {
      seed(db, baseFixtures());
      const result = searchCves(db, {});
      expect(result.total).toBe(5);
      expect(result.items.map((item) => item.cveId)).not.toContain("CVE-2099-0005");
    } finally {
      db.close();
    }
  });

  it("finds records by FTS text across title and description", () => {
    const db = makeDb();
    try {
      seed(db, baseFixtures());
      expect(searchCves(db, { q: "parser" }).items.map((item) => item.cveId)).toContain(
        "CVE-2099-0001",
      );
      expect(searchCves(db, { q: "HEAP" }).items.map((item) => item.cveId)).toContain(
        "CVE-2099-0001",
      );
      expect(searchCves(db, { q: "renderer" }).items.map((item) => item.cveId)).toEqual([
        "CVE-2099-0002",
      ]);
      expect(searchCves(db, { q: "nomatchingtermxyz" }).items).toEqual([]);
    } finally {
      db.close();
    }
  });

  it("resolves exact IDs case-insensitively and supports ID prefixes", () => {
    const db = makeDb();
    try {
      seed(db, baseFixtures());
      expect(searchCves(db, { q: "cve-2099-0002" }).items.map((item) => item.cveId)).toEqual([
        "CVE-2099-0002",
      ]);
      const prefix = searchCves(db, { q: "CVE-2099-000" });
      expect(prefix.total).toBe(6 - 1);
      expect(prefix.items.map((item) => item.cveId)).toContain("CVE-2099-0001");
    } finally {
      db.close();
    }
  });

  it("applies UTC [start, end) date ranges and buckets unknown dates", () => {
    const db = makeDb();
    try {
      seed(db, baseFixtures());
      const result = searchCves(db, {
        dateStart: "2026-10-20T00:00:00.000Z",
        dateEnd: "2026-10-22T00:00:00.000Z",
      });
      expect(result.items.map((item) => item.cveId).sort()).toEqual([
        "CVE-2099-0001",
        "CVE-2099-0002",
      ]);
      const unfiltered = searchCves(db, {});
      expect(unfiltered.coverage.unknownDate).toBe(1);
      expect(
        unfiltered.items.find((item) => item.cveId === "CVE-2099-0003")?.datePublished,
      ).toBeNull();
    } finally {
      db.close();
    }
  });

  it("filters by primary-CNA severity bands with legacy/unknown kept separate", () => {
    const db = makeDb();
    try {
      seed(db, baseFixtures());
      expect(
        searchCves(db, { severity: ["critical"] }).items.map((item) => item.cveId),
      ).toEqual(["CVE-2099-0001"]);
      expect(
        searchCves(db, { severity: ["legacy"] }).items.map((item) => item.cveId),
      ).toEqual(["CVE-2099-0004"]);
      const unknown = searchCves(db, { severity: ["unknown"] });
      expect(unknown.items.map((item) => item.cveId).sort()).toEqual([
        "CVE-2099-0003",
        "CVE-2099-0006",
      ]);
      const coverage = searchCves(db, {}).coverage;
      expect(coverage.bySeverity.critical).toBe(1);
      expect(coverage.bySeverity.medium).toBe(1);
      expect(coverage.legacySeverity).toBe(1);
      expect(coverage.unknownSeverity).toBe(2);
    } finally {
      db.close();
    }
  });

  it("filters KEV membership and EPSS presence with join coverage", () => {
    const db = makeDb();
    try {
      seed(db, baseFixtures());
      expect(
        searchCves(db, { kev: "only" }).items.map((item) => item.cveId).sort(),
      ).toEqual(["CVE-2099-0001", "CVE-2099-0004"]);
      expect(searchCves(db, { kev: "excluded" }).total).toBe(3);
      expect(
        searchCves(db, { epss: "present" }).items.map((item) => item.cveId).sort(),
      ).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
      expect(searchCves(db, { epss: "absent" }).total).toBe(3);
      const coverage = searchCves(db, {}).coverage;
      expect(coverage.kevMembers).toBe(2);
      expect(coverage.epssKnown).toBe(2);
    } finally {
      db.close();
    }
  });

  it("paginates with opaque cursors and a stable order", () => {
    const db = makeDb();
    try {
      seed(db, baseFixtures());
      const first = searchCves(db, { limit: 2 });
      expect(first.items).toHaveLength(2);
      expect(first.total).toBe(5);
      expect(first.nextCursor).not.toBeNull();
      const second = searchCves(db, { limit: 2, cursor: first.nextCursor });
      const third = searchCves(db, { limit: 2, cursor: second.nextCursor });
      expect(second.items).toHaveLength(2);
      expect(third.items).toHaveLength(1);
      expect(third.nextCursor).toBeNull();
      const seen = [...first.items, ...second.items, ...third.items].map((item) => item.cveId);
      expect(new Set(seen).size).toBe(5);
    } finally {
      db.close();
    }
  });

  it("rejects oversized pages and malformed filters without querying", () => {
    const db = makeDb();
    try {
      seed(db, baseFixtures());
      expect(() => searchCves(db, { limit: 0 })).toThrowError(SearchValidationError);
      expect(() => searchCves(db, { limit: MAX_SEARCH_LIMIT + 1 })).toThrowError(
        SearchValidationError,
      );
      expect(() => searchCves(db, { limit: 1.5 })).toThrowError(SearchValidationError);
      expect(() => searchCves(db, { dateStart: "not-a-date" })).toThrowError(
        SearchValidationError,
      );
      expect(() =>
        searchCves(db, {
          dateStart: "2026-10-22T00:00:00.000Z",
          dateEnd: "2026-10-20T00:00:00.000Z",
        }),
      ).toThrowError(SearchValidationError);
      expect(() => searchCves(db, { cursor: "bogus" })).toThrowError(SearchValidationError);
      expect(() => searchCves(db, { severity: ["nope"] as never })).toThrowError(
        SearchValidationError,
      );
      expect(() => searchCves(db, { q: "x".repeat(MAX_QUERY_LENGTH + 1) })).toThrowError(
        SearchValidationError,
      );
    } finally {
      db.close();
    }
  });

  it("keeps SQL/FTS injection-shaped input inert with the schema intact", () => {
    const db = makeDb();
    try {
      seed(db, baseFixtures());
      const hostile = [
        "' OR '1'='1'; --",
        '"; DROP TABLE cve_records; --',
        "CVE-2099-0001' OR '1'='1",
        "* OR *",
        '" OR "1"="1',
        "AND OR NOT NEAR",
        "(((((unbalanced",
      ];
      for (const q of hostile) {
        const result = searchCves(db, { q });
        expect(result.total).toBeLessThanOrEqual(5);
        expect(result.items.map((item) => item.cveId)).not.toContain("CVE-2099-0005");
      }
      db.runBoundedWrite(() => {
        db.handle
          .prepare("UPDATE cve_records SET description = ? WHERE cve_id = ?")
          .run("' OR '1'='1'; --", "CVE-2099-0002");
      });
      const stored = searchCves(db, { q: "renderer" });
      expect(stored.items.map((item) => item.cveId)).toEqual([]);
      expect(tableNames(db)).toContain("cve_records");
      expect(tableNames(db)).toContain("cve_fts");
    } finally {
      db.close();
    }
  });

  it("handles an unbroken 200-char string safely at the query level", () => {
    const db = makeDb();
    try {
      seed(db, baseFixtures());
      const result = searchCves(db, { q: "a".repeat(MAX_QUERY_LENGTH) });
      expect(result.items).toEqual([]);
      expect(result.total).toBe(0);
      expect(result.nextCursor).toBeNull();
      expect(tableNames(db)).toContain("cve_records");
    } finally {
      db.close();
    }
  });

  it("emits 320-code-point excerpts with language fallback labels", () => {
    expect(excerptDescription("short text", "en-US").excerpt).toBe("short text");
    expect(excerptDescription("short text", "en-US").langLabel).toBe("en");
    expect(excerptDescription("short text", "en-US").truncated).toBe(false);
    expect(excerptDescription("texte court", "fr").langLabel).toBe("fr");
    expect(excerptDescription("", null).excerpt).toBe(DESCRIPTION_MISSING_LABEL);
    expect(excerptDescription("", null).langLabel).toBe("unknown");

    const long = `x${"é".repeat(400)}`;
    const truncated = excerptDescription(long, "en");
    expect(Array.from(truncated.excerpt.replace(/…$/, "")).length).toBe(320);
    expect(truncated.excerpt.endsWith("…")).toBe(true);
    expect(truncated.truncated).toBe(true);

    const emoji = "😀".repeat(400);
    const emojiExcerpt = excerptDescription(emoji, "en");
    expect(Array.from(emojiExcerpt.excerpt.replace(/…$/, "")).length).toBe(320);
    expect(emojiExcerpt.truncated).toBe(true);

    const db = makeDb();
    try {
      seed(db, baseFixtures());
      const missing = searchCves(db, {}).items.find((item) => item.cveId === "CVE-2099-0006");
      expect(missing?.excerpt).toBe(DESCRIPTION_MISSING_LABEL);
      const french = searchCves(db, {}).items.find((item) => item.cveId === "CVE-2099-0003");
      expect(french?.langLabel).toBe("fr");
    } finally {
      db.close();
    }
  });

  it("builds official links from stored IDs and titles fall back to the ID", () => {
    expect(officialCveLink("CVE-2099-0001")).toBe(
      "https://www.cve.org/CVERecord?id=CVE-2099-0001",
    );
    expect(severityBandFor(null)).toBe("unknown");
    const db = makeDb();
    try {
      seed(db, baseFixtures());
      const result = searchCves(db, { q: "CVE-2099-0003" });
      expect(result.items[0]?.title).toBe("CVE-2099-0003");
      expect(result.items[0]?.officialLink).toBe(
        "https://www.cve.org/CVERecord?id=CVE-2099-0003",
      );
    } finally {
      db.close();
    }
  });
});
