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
  stripCweMarkers,
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

describe("stripCweMarkers", () => {
  // The published grammar, taken from the catalog itself:
  //   ::PHASE:<phase>[:STRATEGY:<strategy>]:DESCRIPTION:<prose>::
  // The prose sits INSIDE the marker run, so it is the part that must survive.
  // Every fixture below is shaped after a real stored value.

  const FIXTURES = [
    "::PHASE:System Configuration:DESCRIPTION:Use TLS for access-controlled pages.::",
    "::PHASE:Architecture and Design:DESCRIPTION:Design it.::PHASE:Implementation:DESCRIPTION:Then build it.::",
    "::PHASE:Implementation:STRATEGY:Input Validation:DESCRIPTION:Validate every input.::",
    "::PHASE::DESCRIPTION:Pre-design: use a bounds-checked language.::",
    "::PHASE:Architecture and Design::Design it. ::PHASE:Implementation::Then build it.",
    "::PHASE:Implementation:DESCRIPTION:Prefer std::unique_ptr over raw pointers.::",
    "::PHASE:Implementation:DESCRIPTION:Use a vetted library.::P…",
    "::PHASE:Architecture and Design:STRATE…",
    "::PHASE:",
    "::PHASE:Implementation::",
    "::",
    "",
    "Use a vetted library or framework.",
  ];

  it("returns the prose of a single phase run", () => {
    expect(
      stripCweMarkers(
        "::PHASE:System Configuration:DESCRIPTION:Use TLS for access-controlled pages.::",
      ),
    ).toBe("Use TLS for access-controlled pages.");
  });

  it("joins the prose of every phase run", () => {
    expect(
      stripCweMarkers(
        "::PHASE:Architecture and Design:DESCRIPTION:Design it.::PHASE:Implementation:DESCRIPTION:Then build it.::",
      ),
    ).toBe("Design it. Then build it.");
  });

  it("drops the optional STRATEGY field and keeps the prose behind it", () => {
    expect(
      stripCweMarkers(
        "::PHASE:Implementation:STRATEGY:Input Validation:DESCRIPTION:Validate every input.::",
      ),
    ).toBe("Validate every input.");
  });

  it("keeps the prose of a run whose phase name is empty", () => {
    expect(stripCweMarkers("::PHASE::DESCRIPTION:Pre-design: use a bounds-checked language.::")).toBe(
      "Pre-design: use a bounds-checked language.",
    );
  });

  it("drops a tag-only segment and keeps the prose around it", () => {
    expect(stripCweMarkers("Review the code ::PHASE:Implementation:: before shipping.")).toBe(
      "Review the code before shipping.",
    );
    expect(stripCweMarkers("::PHASE:Implementation::")).toBe("");
    expect(stripCweMarkers("  ::PHASE:A:: ::PHASE:B::  ")).toBe("");
    expect(
      stripCweMarkers(
        "::PHASE:Architecture and Design::Design it. ::PHASE:Implementation::Then build it.",
      ),
    ).toBe("Design it. Then build it.");
  });

  it("keeps the prose before a marker the cap cut in half, and drops the remnant", () => {
    expect(stripCweMarkers("Design throttling into the architecture.::PHASE:")).toBe(
      "Design throttling into the architecture.",
    );
    expect(stripCweMarkers("::PHASE:Implementation:DESCRIPTION:Use a vetted library.::P…")).toBe(
      "Use a vetted library.",
    );
    expect(stripCweMarkers("::PHASE:Implementation:DESCRIPTION:Use a vetted library.::PHAS…")).toBe(
      "Use a vetted library.",
    );
    // A run cut off before its DESCRIPTION carries no prose at all.
    expect(stripCweMarkers("::PHASE:Architecture and Design:STRATE…")).toBe("");
  });

  it("keeps prose that itself contains a doubled colon", () => {
    // Real values describe `std::auto_ptr`; the split must not lose the tail.
    expect(
      stripCweMarkers("::PHASE:Implementation:DESCRIPTION:Prefer std::unique_ptr over raw pointers.::"),
    ).toBe("Prefer std unique_ptr over raw pointers.");
  });

  it("never returns a marker field, whatever the input", () => {
    for (const fixture of FIXTURES) {
      const prose = stripCweMarkers(fixture);
      expect(prose).not.toContain("PHASE");
      expect(prose).not.toContain("DESCRIPTION");
      expect(prose).not.toContain("::");
    }
  });

  it("returns an empty string for marker-only and empty input", () => {
    expect(stripCweMarkers("::PHASE:Implementation:DESCRIPTION:")).toBe("");
    expect(stripCweMarkers("::")).toBe("");
    expect(stripCweMarkers("")).toBe("");
  });

  it("leaves text without markers unchanged", () => {
    expect(stripCweMarkers("Use a vetted library or framework.")).toBe(
      "Use a vetted library or framework.",
    );
    // No marker, nothing dropped, and a single colon is not a marker.
    expect(stripCweMarkers("Phase: implementation. Ratio 1:2.")).toBe(
      "Phase: implementation. Ratio 1:2.",
    );
  });

  it("collapses whitespace and trims", () => {
    expect(stripCweMarkers("  multiple   spaces\tand\nnewlines  ")).toBe(
      "multiple spaces and newlines",
    );
  });
});

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

  it("strips MITRE phase markers from summary and mitigation at projection time", () => {
    const db = makeDatabase();
    seedMeta(db);
    seedEntry(db, {
      id: "CWE-79",
      name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
      summary: "The product ::PHASE:Implementation:: fails to neutralize input.",
      mitigation:
        "::PHASE:Architecture and Design::Use structure. ::PHASE:Implementation::Encode output.",
    });

    const ref = resolveCweIds(db, ["CWE-79"]).get("CWE-79") as CweRef;
    expect(ref.summary).toBe("The product fails to neutralize input.");
    expect(ref.mitigation).toBe("Use structure. Encode output.");
    expect(JSON.stringify(ref)).not.toContain("::");
  });

  it("projects the prose a stored phase marker carries, at projection time", () => {
    // The shape the catalog actually stores: prose inside `::PHASE:…:DESCRIPTION:`,
    // followed by a run the 600-code-point cap cut inside its marker.
    const db = makeDatabase();
    seedMeta(db);
    seedEntry(db, {
      id: "CWE-79",
      name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
      summary: "::PHASE:Implementation:DESCRIPTION:The product fails to neutralize input.::",
      mitigation:
        "::PHASE:Architecture and Design:DESCRIPTION:Use structure.::PHASE:Implementation:STRATEGY:Input Validation:DESCRIPTION:Encode output.::P…",
    });

    const ref = resolveCweIds(db, ["CWE-79"]).get("CWE-79") as CweRef;
    expect(ref.summary).toBe("The product fails to neutralize input.");
    expect(ref.mitigation).toBe("Use structure. Encode output.");
    expect(JSON.stringify(ref)).not.toContain("::");
    expect(JSON.stringify(ref)).not.toContain("PHASE");
    expect(JSON.stringify(ref)).not.toContain("DESCRIPTION");
  });

  it("omits a marker-only field instead of projecting empty text", () => {
    const db = makeDatabase();
    seedMeta(db);
    seedEntry(db, {
      id: "CWE-79",
      name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
      summary: null,
      mitigation: "::PHASE:Implementation::",
    });

    const ref = resolveCweIds(db, ["CWE-79"]).get("CWE-79") as CweRef;
    expect(ref.status).toBe("known");
    expect(ref.mitigation).toBeUndefined();
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
