// v3 E1: the secondary-CVSS projection owns one deterministic, bounded,
// explicitly-labeled view over every metric the primary did not select.
// These tests pin the state matrix, ordering, cap, malformed-input tolerance,
// determinism, and the additive API shape (`cvssPrimary` byte-identical,
// `cvssSecondary` added, `hasAdp` still present).

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { openDatabase, type CveDatabase } from "../src/lib/db";
import {
  MAX_SECONDARY_METRICS,
  projectSecondaryCvss,
  SECONDARY_LABEL,
  type CvssSecondary,
} from "../src/lib/cvss-projection";
import { selectPrimaryCvss } from "../src/lib/ranking";
import { loadFullRecords, toCveItem } from "../app/api/v1/_lib/records";

const STAMP = "2026-10-24T00:00:00.000Z";

const tempDirs: string[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-cvss-projection-test-"));
  tempDirs.push(dir);
  return openDatabase({ dataDir: dir });
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

function metric(
  origin: "CNA" | "ADP",
  version: string,
  baseScore: string,
  provider: string | null = null,
  sourceOrder = 0,
  vector = `CVSS:${version}/AV:N`,
) {
  return { origin, version, baseScore, provider, sourceOrder, vector };
}

function expectContextNote(secondary: CvssSecondary): void {
  expect(secondary.coverageNote.toLowerCase()).toContain("context only");
  expect(secondary.coverageNote.toLowerCase()).toContain("not used for ranking or eligibility");
}

function assertNoSeverityColour(secondary: CvssSecondary): void {
  for (const view of secondary.metrics) {
    expect(view.label).toBe(SECONDARY_LABEL);
    expect(view.label).toContain("context");
  }
}

describe("projectSecondaryCvss state matrix", () => {
  it("ADP-only: no primary, the ADP metric is secondary context", () => {
    const metrics = [metric("ADP", "3.1", "7.5", "cisa-adp", 0)];
    const primary = selectPrimaryCvss(metrics);
    expect(primary).toBeNull();
    const secondary = projectSecondaryCvss(metrics, primary);
    expect(secondary.status).toBe("present");
    expect(secondary.metrics).toEqual([
      {
        origin: "ADP",
        provider: "cisa-adp",
        version: "3.1",
        baseScore: "7.5",
        vector: "CVSS:3.1/AV:N",
        label: "secondary (context only)",
      },
    ]);
    expectContextNote(secondary);
    assertNoSeverityColour(secondary);
  });

  it("CNA+ADP: the selected primary is excluded, the ADP metric is kept", () => {
    const metrics = [
      metric("CNA", "3.1", "9.8", null, 0),
      metric("ADP", "3.1", "7.5", "cisa-adp", 1),
    ];
    const primary = selectPrimaryCvss(metrics);
    expect(primary?.baseScore).toBe("9.8");
    const secondary = projectSecondaryCvss(metrics, primary);
    expect(secondary.status).toBe("present");
    expect(secondary.metrics.map((view) => `${view.origin}:${view.baseScore}`)).toEqual([
      "ADP:7.5",
    ]);
    expectContextNote(secondary);
  });

  it("excludes a non-selected CNA metric too (it is secondary, never primary)", () => {
    const metrics = [
      metric("CNA", "4.0", "9.8", null, 0),
      metric("CNA", "4.0", "4.4", null, 1),
      metric("ADP", "3.1", "6.0", "cisa-adp", 2),
    ];
    const primary = selectPrimaryCvss(metrics);
    const secondary = projectSecondaryCvss(metrics, primary);
    // ADP first, then the remaining CNA metric.
    expect(secondary.metrics.map((view) => `${view.origin}:${view.baseScore}`)).toEqual([
      "ADP:6.0",
      "CNA:4.4",
    ]);
  });

  it("multiple ADP: ADP first, version preference, exact score descending, source order, cap 4", () => {
    const metrics = [
      metric("CNA", "3.1", "5.0", null, 0),
      metric("ADP", "2.0", "9.0", "adp-a", 1),
      metric("ADP", "3.0", "8.0", "adp-a", 2),
      metric("ADP", "4.0", "6.0", "adp-b", 3),
      metric("ADP", "3.1", "9.5", "adp-a", 5),
      metric("ADP", "3.1", "9.5", "adp-a", 4),
      metric("ADP", "3.1", "9.10", "adp-a", 6),
    ];
    const primary = selectPrimaryCvss(metrics);
    const secondary = projectSecondaryCvss(metrics, primary);
    expect(secondary.status).toBe("present");
    expect(secondary.metrics).toHaveLength(MAX_SECONDARY_METRICS);
    // 4.0 wins on version preference even with a lower score; within 3.1 the
    // exact decimals order 9.5, 9.5 (source order 4 then 5), then 9.10.
    expect(secondary.metrics.map((view) => `${view.version}:${view.baseScore}`)).toEqual([
      "4.0:6.0",
      "3.1:9.5",
      "3.1:9.5",
      "3.1:9.10",
    ]);
    // The 3.0 and 2.0 metrics exist but fall past the cap.
    expect(secondary.metrics.some((view) => view.version === "2.0")).toBe(false);
  });

  it("legacy-only: a v2 primary excludes itself and leaves no secondary", () => {
    const metrics = [metric("CNA", "2.0", "10.0", null, 0)];
    const primary = selectPrimaryCvss(metrics);
    expect(primary?.version).toBe("2.0");
    const secondary = projectSecondaryCvss(metrics, primary);
    expect(secondary).toEqual({ status: "none", coverageNote: expect.any(String), metrics: [] });
    expectContextNote(secondary);
  });

  it("none: empty, non-array, and all-malformed inputs degrade to an explicit none", () => {
    const primary = null;
    for (const input of [[], null, undefined, "metrics", 42, {}]) {
      const secondary = projectSecondaryCvss(input, primary);
      expect(secondary.status).toBe("none");
      expect(secondary.metrics).toEqual([]);
      expectContextNote(secondary);
    }
    const malformed = [
      metric("ADP", "3.1", "NaN"),
      metric("ADP", "3.1", "11"),
      metric("ADP", "3.1", "-1"),
      metric("ADP", "3.1", "1e3"),
      metric("ADP", "3.1", ""),
      metric("ADP", "3.1", "9.8.1"),
      { origin: "NVD", version: "3.1", baseScore: "9.0" },
      { origin: "ADP", version: "3.2", baseScore: "9.0" },
      "not-a-metric",
    ];
    const secondary = projectSecondaryCvss(malformed, primary);
    expect(secondary.status).toBe("none");
    expect(secondary.metrics).toEqual([]);
  });

  it("malformed rows are ignored while the valid ones are still shown", () => {
    const metrics = [
      metric("ADP", "3.1", "bogus"),
      metric("ADP", "3.1", "7.5", "cisa-adp", 0),
      { origin: "ADP", version: "4.0" },
    ];
    const secondary = projectSecondaryCvss(metrics, null);
    expect(secondary.status).toBe("present");
    expect(secondary.metrics).toHaveLength(1);
    expect(secondary.metrics[0]?.baseScore).toBe("7.5");
  });

  it("treats a missing provider as null, never an invented label", () => {
    const secondary = projectSecondaryCvss([metric("ADP", "3.1", "7.5", null, 0)], null);
    expect(secondary.metrics[0]?.provider).toBeNull();
  });
});

describe("projectSecondaryCvss determinism", () => {
  it("same input twice yields the same output and never mutates the input", () => {
    const metrics = [
      metric("CNA", "3.1", "9.8", null, 0),
      metric("ADP", "3.1", "7.5", "cisa-adp", 1),
      metric("ADP", "4.0", "7.0", "cisa-adp", 2),
    ];
    const snapshot = JSON.stringify(metrics);
    const primary = selectPrimaryCvss(metrics);
    const first = projectSecondaryCvss(metrics, primary);
    const second = projectSecondaryCvss(metrics, primary);
    expect(first).toEqual(second);
    expect(JSON.stringify(metrics)).toBe(snapshot);
  });

  it("excludes the primary by exact decimal value, not string shape", () => {
    const metrics = [
      metric("CNA", "3.1", "9.80", null, 0, "CVSS:3.1/AV:N"),
      metric("ADP", "3.1", "7.5", "cisa-adp", 1),
    ];
    const primary = { origin: "CNA", version: "3.1", baseScore: "9.8", vector: "CVSS:3.1/AV:N" };
    const secondary = projectSecondaryCvss(metrics, primary);
    expect(secondary.metrics.map((view) => view.baseScore)).toEqual(["7.5"]);
  });
});

// ---------------------------------------------------------------------------
// API shape: additive field, primary untouched.
// ---------------------------------------------------------------------------

function ensureProviderColumn(db: CveDatabase): void {
  const columns = db.handle.prepare("PRAGMA table_info(cvss_metrics)").all() as Array<{
    name: string;
  }>;
  if (!columns.some((column) => column.name === "provider")) {
    db.handle.exec("ALTER TABLE cvss_metrics ADD COLUMN provider TEXT NULL");
  }
}

function seedRecordWithMetrics(
  db: CveDatabase,
  cveId: string,
  metrics: Array<{
    origin: string;
    provider: string | null;
    version: string;
    baseScore: string;
    vector: string;
  }>,
): void {
  ensureProviderColumn(db);
  db.runBoundedWrite(() => {
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
        "rev-test",
        null,
        STAMP,
        STAMP,
      );
    for (const [index, row] of metrics.entries()) {
      db.handle
        .prepare(
          "INSERT INTO cvss_metrics (cve_id, origin, provider, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .run(cveId, row.origin, row.provider, row.version, row.baseScore, row.vector, index);
    }
  });
}

describe("CveItem cvssSecondary shape", () => {
  it("adds cvssSecondary without changing cvssPrimary, and keeps hasAdp", () => {
    const db = makeDb();
    // The importer adds `provider` additively; a real imported volume has it.
    seedRecordWithMetrics(db, "CVE-2099-0500", [
      {
        origin: "CNA",
        provider: null,
        version: "3.1",
        baseScore: "9.8",
        vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      },
      {
        origin: "ADP",
        provider: "cisa-adp",
        version: "3.1",
        baseScore: "7.5",
        vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      },
      {
        origin: "ADP",
        provider: "cisa-adp",
        version: "4.0",
        baseScore: "8.1",
        vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      },
    ]);

    const record = loadFullRecords(db, ["CVE-2099-0500"])[0];
    expect(record).toBeDefined();
    const item = toCveItem(record!, "2026-10-23", "v2026.06.15");

    // cvssPrimary is byte-identical to the pre-E1 shape.
    expect(item.cvssPrimary).toEqual({
      status: "known",
      source: "cna",
      version: "3.1",
      baseScore: 9.8,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    });
    // The secondary block is additive and ordered ADP 4.0 then 3.1.
    expect(item.cvssSecondary).toEqual({
      status: "present",
      coverageNote: expect.any(String),
      metrics: [
        {
          origin: "ADP",
          provider: "cisa-adp",
          version: "4.0",
          baseScore: "8.1",
          vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
          label: "secondary (context only)",
        },
        {
          origin: "ADP",
          provider: "cisa-adp",
          version: "3.1",
          baseScore: "7.5",
          vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
          label: "secondary (context only)",
        },
      ],
    });
    expect((item.cvssSecondary as CvssSecondary).coverageNote.toLowerCase()).toContain(
      "context only",
    );
    expect(record?.hasAdp).toBe(true);
  });

  it("a CNA-only record reports an explicit secondary none", () => {
    const db = makeDb();
    seedRecordWithMetrics(db, "CVE-2099-0501", [
      {
        origin: "CNA",
        provider: null,
        version: "4.0",
        baseScore: "6.0",
        vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
      },
    ]);
    const record = loadFullRecords(db, ["CVE-2099-0501"])[0];
    expect(record?.hasAdp).toBe(false);
    const item = toCveItem(record!, null, null);
    expect(item.cvssSecondary).toMatchObject({ status: "none", metrics: [] });
    expect(item.cvssPrimary).toMatchObject({ status: "known", baseScore: 6 });
  });

  it("a legacy schema without the provider column still projects (provider null)", () => {
    const db = makeDb();
    db.runBoundedWrite(() => {
      db.handle
        .prepare(
          "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, description_lang, source_revision, raw_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          "CVE-2099-0502",
          "5.1",
          "PUBLISHED",
          null,
          null,
          "",
          null,
          "rev-test",
          null,
          STAMP,
          STAMP,
        );
      // The 001 schema has no provider column; the importer normally adds it.
      db.handle
        .prepare(
          "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .run("CVE-2099-0502", "ADP", "3.1", "7.5", "CVSS:3.1/AV:N", 0);
    });
    const record = loadFullRecords(db, ["CVE-2099-0502"])[0];
    const item = toCveItem(record!, null, null);
    expect(item.cvssPrimary).toMatchObject({ status: "adp-only" });
    expect(item.cvssSecondary).toMatchObject({
      status: "present",
      metrics: [{ origin: "ADP", provider: null, version: "3.1", baseScore: "7.5" }],
    });
  });
});
