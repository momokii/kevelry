// v3 E2: the KEV block must state ransomware use the way the catalog does.
// `kev_entries.ransomware_known` is an INTEGER: 1 (Known), 0 (Unknown), or
// NULL (unstated). These tests pin the single tri-state mapping, prove that 0
// and NULL never collapse, prove the legacy `ransomwareKnown` boolean keeps its
// old 1/0/null reading, and prove the payload never invents a negated
// ransomware-free claim out of an Unknown or unstated catalog value.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import {
  kevRansomwareUseOf,
  legacyRansomwareKnown,
  loadFullRecords,
  toCveItem,
} from "../app/api/v1/_lib/records";

const STAMP = "2026-10-24T00:00:00.000Z";
const tempDirs: string[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-kev-ransomware-test-"));
  tempDirs.push(dir);
  return openDatabase({ dataDir: dir });
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

interface KevSeed {
  dateAdded?: string;
  dueDate?: string | null;
  requiredAction?: string | null;
  vulnerabilityName?: string | null;
  ransomwareKnown?: number | null;
  cwes?: string[];
}

function seedRecord(db: CveDatabase, cveId: string): void {
  db.handle
    .prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, description_lang, source_revision, raw_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .run(
      cveId,
      "5.1",
      "PUBLISHED",
      "2026-10-20T00:00:00.000Z",
      `Title for ${cveId}`,
      `Description for ${cveId}`,
      "en",
      "rev-kev-test",
      null,
      STAMP,
      STAMP,
    );
}

function seedKev(db: CveDatabase, cveId: string, kev: KevSeed): void {
  db.handle
    .prepare(
      "INSERT INTO kev_entries (cve_id, date_added, catalog_date, vendor_project, product, due_date, required_action, vulnerability_name, ransomware_known, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .run(
      cveId,
      kev.dateAdded ?? "2026-10-23",
      "2026.10.23",
      "Vendor",
      "Product",
      kev.dueDate === undefined ? "2026-11-13" : kev.dueDate,
      kev.requiredAction === undefined
        ? "Apply mitigations per vendor instructions."
        : kev.requiredAction,
      kev.vulnerabilityName === undefined ? "Example flaw" : kev.vulnerabilityName,
      kev.ransomwareKnown === undefined ? null : kev.ransomwareKnown,
      STAMP,
    );
  for (const cwe of kev.cwes ?? []) {
    db.handle.prepare("INSERT INTO kev_cwes (cve_id, cwe_id) VALUES (?, ?)").run(cveId, cwe);
  }
}

function kevBlockOf(db: CveDatabase, cveId: string): Record<string, unknown> {
  const [record] = loadFullRecords(db, [cveId]);
  expect(record, `record ${cveId} exists`).toBeDefined();
  const item = toCveItem(record!, "2026-10-23", "v2026.06.15");
  return item.kev as Record<string, unknown>;
}

/** Phrases that would claim the catalog said something it did not. */
const FORBIDDEN = [
  ["no", "ransomware"],
  ["not", "ransomware"],
].map((words) => words.join(" "));

describe("kevRansomwareUseOf mapping", () => {
  it("maps 1 -> known, 0 -> unknown, NULL -> unstated", () => {
    expect(kevRansomwareUseOf(1)).toBe("known");
    expect(kevRansomwareUseOf(0)).toBe("unknown");
    expect(kevRansomwareUseOf(null)).toBe("unstated");
  });

  it("treats a missing column value as unstated, never unknown", () => {
    expect(kevRansomwareUseOf(undefined)).toBe("unstated");
    expect(kevRansomwareUseOf(null)).not.toBe(kevRansomwareUseOf(0));
  });

  it("keeps the legacy boolean alias identical to the old 1/0/null reading", () => {
    expect(legacyRansomwareKnown("known")).toBe(true);
    expect(legacyRansomwareKnown("unknown")).toBe(false);
    expect(legacyRansomwareKnown("unstated")).toBeNull();
  });
});

describe("KEV block ransomware tri-state", () => {
  it.each([
    { stored: 1, use: "known", legacy: true },
    { stored: 0, use: "unknown", legacy: false },
    { stored: null, use: "unstated", legacy: null },
  ] as const)("stored $stored -> ransomwareUse $use", ({ stored, use, legacy }) => {
    const db = makeDb();
    const cveId = "CVE-2099-0701";
    db.runBoundedWrite(() => {
      seedRecord(db, cveId);
      seedKev(db, cveId, { ransomwareKnown: stored, cwes: ["CWE-78", "CWE-20"] });
    });

    const kev = kevBlockOf(db, cveId);
    expect(kev.ransomwareUse).toBe(use);
    // Legacy alias unchanged for consumers that predate the tri-state.
    expect(kev.ransomwareKnown).toBe(legacy);
    // The rest of the block stays self-describing and byte-stable.
    expect(kev).toMatchObject({
      listed: true,
      dateAdded: "2026-10-23",
      dueDate: "2026-11-13",
      requiredAction: "Apply mitigations per vendor instructions.",
      vulnerabilityName: "Example flaw",
      cwes: ["CWE-20", "CWE-78"],
    });
  });

  it("never collapses Unknown (0) into unstated (NULL)", () => {
    const db = makeDb();
    db.runBoundedWrite(() => {
      seedRecord(db, "CVE-2099-0702");
      seedKev(db, "CVE-2099-0702", { ransomwareKnown: 0 });
      seedRecord(db, "CVE-2099-0703");
      seedKev(db, "CVE-2099-0703", { ransomwareKnown: null });
    });

    const unknown = kevBlockOf(db, "CVE-2099-0702");
    const unstated = kevBlockOf(db, "CVE-2099-0703");
    expect(unknown.ransomwareUse).toBe("unknown");
    expect(unstated.ransomwareUse).toBe("unstated");
    expect(unknown.ransomwareKnown).toBe(false);
    expect(unstated.ransomwareKnown).toBeNull();
    expect(unknown.ransomwareUse).not.toBe(unstated.ransomwareUse);
  });

  it("a record with no KEV row yields nulls and unstated", () => {
    const db = makeDb();
    const cveId = "CVE-2099-0704";
    db.runBoundedWrite(() => seedRecord(db, cveId));

    expect(kevBlockOf(db, cveId)).toEqual({
      listed: false,
      dateAdded: null,
      dueDate: null,
      requiredAction: null,
      vulnerabilityName: null,
      ransomwareUse: "unstated",
      ransomwareKnown: null,
      cwes: [],
    });
  });

  it("absent catalog text is null, never an empty string", () => {
    const db = makeDb();
    const cveId = "CVE-2099-0705";
    db.runBoundedWrite(() => {
      seedRecord(db, cveId);
      seedKev(db, cveId, {
        dueDate: "",
        requiredAction: "   ",
        vulnerabilityName: "",
        ransomwareKnown: 1,
      });
    });

    const kev = kevBlockOf(db, cveId);
    expect(kev.listed).toBe(true);
    expect(kev.dueDate).toBeNull();
    expect(kev.requiredAction).toBeNull();
    expect(kev.vulnerabilityName).toBeNull();
    for (const value of Object.values(kev)) {
      expect(value).not.toBe("");
    }
  });

  it("never renders a negated ransomware claim for unknown or unstated", () => {
    const db = makeDb();
    db.runBoundedWrite(() => {
      seedRecord(db, "CVE-2099-0706");
      seedKev(db, "CVE-2099-0706", { ransomwareKnown: 0 });
      seedRecord(db, "CVE-2099-0707");
      seedKev(db, "CVE-2099-0707", { ransomwareKnown: null });
      seedRecord(db, "CVE-2099-0708");
    });

    for (const cveId of ["CVE-2099-0706", "CVE-2099-0707", "CVE-2099-0708"]) {
      const serialised = JSON.stringify(kevBlockOf(db, cveId)).toLowerCase();
      for (const phrase of FORBIDDEN) {
        expect(serialised).not.toContain(phrase);
      }
      expect(serialised).not.toContain('"none"');
    }
  });

  it("keeps the KEV block keys additive: no renames, no removals", () => {
    const db = makeDb();
    const cveId = "CVE-2099-0709";
    db.runBoundedWrite(() => {
      seedRecord(db, cveId);
      seedKev(db, cveId, { ransomwareKnown: 1 });
    });

    const keys = Object.keys(kevBlockOf(db, cveId)).sort();
    expect(keys).toEqual(
      [
        "listed",
        "dateAdded",
        "dueDate",
        "requiredAction",
        "vulnerabilityName",
        "ransomwareKnown",
        "ransomwareUse",
        "cwes",
      ].sort(),
    );
  });
});
