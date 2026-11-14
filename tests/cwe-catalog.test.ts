// Unit coverage for the local CWE taxonomy reader (v3 E3 step 1).
//
// The suite proves the read contract only: a seeded catalog resolves known ids
// with their published fields, absent ids are explicitly unmapped, an empty or
// non-ready catalog never fabricates a name, input normalization/dedup keeps
// one entry per id, and no caller-supplied shape throws. No network, no
// importer: every fixture is written straight into fresh migrated tables.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  CWE_CATALOG_SOURCE,
  CWE_RESOLUTION_CHUNK,
  type CweRef,
  getCweCatalogMeta,
  normalizeCweId,
  resolveCweIds,
} from "../src/lib/cwe-catalog";
import { type CveDatabase, openDatabase } from "../src/lib/db";

const tempDirs: string[] = [];
const databases: CveDatabase[] = [];

function makeDatabase(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-cwe-catalog-"));
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
  while (tempDirs.length > 0) rmSync(tempDirs.pop() as string, { recursive: true, force: true });
});

const VERSION = "4.17";
const RETRIEVED = "2026-11-02T00:00:00.000Z";
const HASH = "a".repeat(64);

function seedMeta(db: CveDatabase, status = "ready"): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        `INSERT OR REPLACE INTO cwe_catalog_meta
          (id, version, source, source_hash, retrieved_at, status, record_count, notes)
         VALUES (1, ?, ?, ?, ?, ?, ?, NULL)`,
      )
      .run(VERSION, CWE_CATALOG_SOURCE, HASH, RETRIEVED, status, 2);
  });
}

interface EntrySeed {
  id: string;
  name: string;
  abstraction?: string | null;
  status?: string | null;
  summary?: string | null;
  mitigation?: string | null;
}

function seedEntry(db: CveDatabase, entry: EntrySeed): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        `INSERT OR REPLACE INTO cwe_entries
          (cwe_id, name, abstraction, status, summary, mitigation, version, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        entry.id,
        entry.name,
        entry.abstraction ?? null,
        entry.status ?? null,
        entry.summary ?? null,
        entry.mitigation ?? null,
        VERSION,
        RETRIEVED,
      );
  });
}

function seedKnownCatalog(db: CveDatabase): void {
  seedMeta(db);
  seedEntry(db, {
    id: "CWE-79",
    name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    abstraction: "Base",
    status: "Stable",
    summary:
      "The product does not neutralize user-controllable input before it is placed in output.",
    mitigation: null,
  });
  seedEntry(db, {
    id: "CWE-94",
    name: "Improper Control of Generation of Code ('Code Injection')",
    abstraction: "Class",
    status: "Draft",
    summary: "The product constructs code segments from externally-influenced input.",
    mitigation: "Use a vetted library or framework that does not allow this weakness to occur.",
  });
}

describe("getCweCatalogMeta", () => {
  it("reports empty before any catalog load", () => {
    const db = makeDatabase();
    expect(getCweCatalogMeta(db)).toEqual({
      status: "empty",
      version: null,
      sourceHash: null,
      retrievedAt: null,
      source: CWE_CATALOG_SOURCE,
    });
  });

  it("reports provenance and status from the accepted meta row", () => {
    const db = makeDatabase();
    seedMeta(db);
    expect(getCweCatalogMeta(db)).toEqual({
      status: "ready",
      version: VERSION,
      sourceHash: HASH,
      retrievedAt: RETRIEVED,
      source: CWE_CATALOG_SOURCE,
    });
  });
});

describe("resolveCweIds", () => {
  it("resolves a known id with its name, abstraction, and summary", () => {
    const db = makeDatabase();
    seedKnownCatalog(db);

    const ref = resolveCweIds(db, ["CWE-79"]).get("CWE-79") as CweRef;
    expect(ref.status).toBe("known");
    expect(ref.id).toBe("CWE-79");
    expect(ref.name).toContain("Cross-site Scripting");
    expect(ref.abstraction).toBe("Base");
    expect(ref.summary).toContain("does not neutralize");
    expect(ref.url).toBe("https://cwe.mitre.org/data/definitions/79.html");
  });

  it("keeps a missing mitigation undefined while the id is still known", () => {
    const db = makeDatabase();
    seedKnownCatalog(db);

    const ref = resolveCweIds(db, ["CWE-79"]).get("CWE-79") as CweRef;
    expect(ref.status).toBe("known");
    expect(ref.mitigation).toBeUndefined();

    const withMitigation = resolveCweIds(db, ["CWE-94"]).get("CWE-94") as CweRef;
    expect(withMitigation.status).toBe("known");
    expect(withMitigation.mitigation).toContain("vetted library");
  });

  it("marks a valid but absent id unmapped with its canonical url", () => {
    const db = makeDatabase();
    seedKnownCatalog(db);

    const ref = resolveCweIds(db, ["CWE-9999"]).get("CWE-9999") as CweRef;
    expect(ref).toEqual({
      id: "CWE-9999",
      status: "unmapped",
      url: "https://cwe.mitre.org/data/definitions/9999.html",
    });
  });

  it("resolves every id as taxonomy-unavailable when the catalog is empty", () => {
    const db = makeDatabase();
    const resolved = resolveCweIds(db, ["CWE-79", "CWE-94", "79"]);

    expect(resolved.size).toBe(2);
    for (const ref of resolved.values()) {
      expect(ref.status).toBe("taxonomy-unavailable");
      expect(ref.name).toBeUndefined();
      expect(ref.url).toMatch(/^https:\/\/cwe\.mitre\.org\/data\/definitions\/\d+\.html$/);
    }
  });

  it("resolves every id as taxonomy-unavailable when status is not ready", () => {
    const db = makeDatabase();
    seedKnownCatalog(db);
    seedMeta(db, "stale");

    const resolved = resolveCweIds(db, ["CWE-79", "CWE-94"]);
    expect([...resolved.values()].every((ref) => ref.status === "taxonomy-unavailable")).toBe(true);
  });

  it("normalizes CWE-79, cwe-79, and 79 to one canonical entry", () => {
    const db = makeDatabase();
    seedKnownCatalog(db);

    const resolved = resolveCweIds(db, ["CWE-79", "cwe-79", "79"]);
    expect(resolved.size).toBe(1);
    expect(resolved.get("CWE-79")?.status).toBe("known");
    expect(normalizeCweId("CWE-079")).toBe("CWE-79");
    expect(normalizeCweId("  cwe-94  ")).toBe("CWE-94");
  });

  it("dedupes repeated ids without an extra entry or query result", () => {
    const db = makeDatabase();
    seedKnownCatalog(db);

    expect(resolveCweIds(db, ["CWE-79", "CWE-79", "79"]).size).toBe(1);
  });

  it("does not throw on invalid ids and reports them as unmapped", () => {
    const db = makeDatabase();
    seedKnownCatalog(db);

    const invalid = ["", "   ", "not-a-cwe", "CWE-", "CWE-0", "CWE-1234567", "79.5"];
    let resolved: Map<string, CweRef> | undefined;
    expect(() => {
      resolved = resolveCweIds(db, invalid);
    }).not.toThrow();

    const refs = [...(resolved as Map<string, CweRef>).values()];
    expect(refs).toHaveLength(new Set(invalid.map((id) => id.trim())).size);
    for (const ref of refs) {
      expect(ref.status).toBe("unmapped");
      expect(ref.url).toBe("");
    }
  });

  it("looks up ids across chunk boundaries", () => {
    const db = makeDatabase();
    seedKnownCatalog(db);
    const ids = Array.from({ length: CWE_RESOLUTION_CHUNK + 1 }, (_, index) =>
      index === CWE_RESOLUTION_CHUNK ? "CWE-94" : `CWE-${10_000 + index}`,
    );

    const resolved = resolveCweIds(db, ids);
    expect(resolved.size).toBe(ids.length);
    expect(resolved.get("CWE-94")?.status).toBe("known");
    expect(resolved.get("CWE-10000")?.status).toBe("unmapped");
  });
});
