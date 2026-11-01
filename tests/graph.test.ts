import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import { buildKevGraph, GRAPH_DEFAULT_NODE_LIMIT, GRAPH_MAX_EDGES } from "../src/lib/graph";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-graph-test-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openDbs.push(db);
  return db;
}

afterEach(() => {
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

const STAMP = "2026-10-24T00:00:00.000Z";

function seedRecord(db: CveDatabase, cveId: string, title: string | null = null): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        cveId,
        "5.1",
        "PUBLISHED",
        "2026-10-20T00:00:00.000Z",
        title,
        "Description",
        nowIso(),
        nowIso(),
      );
  });
}

function nowIso(): string {
  return STAMP;
}

function seedKev(
  db: CveDatabase,
  cveId: string,
  opts: { vendor?: string | null; cwes?: string[]; due?: string | null } = {},
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO kev_entries (cve_id, date_added, catalog_date, vendor_project, due_date, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(cveId, "2026-10-20", STAMP, opts.vendor ?? null, opts.due ?? null, STAMP);
    for (const cwe of opts.cwes ?? []) {
      db.handle
        .prepare("INSERT OR IGNORE INTO kev_cwes (cve_id, cwe_id) VALUES (?, ?)")
        .run(cveId, cwe);
    }
  });
}

function seedEpss(db: CveDatabase, cveId: string, epss: string): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
      )
      .run(cveId, "2026-10-23", "v1", epss, "0.90");
  });
}

describe("bounded KEV relationship graph", () => {
  it("links records by shared CWE, vendor, and reference domain", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001", "First");
    seedRecord(db, "CVE-2099-0002", "Second");
    seedRecord(db, "CVE-2099-0003", "Third");
    seedKev(db, "CVE-2099-0001", { vendor: "Acme", cwes: ["CWE-78"] });
    seedKev(db, "CVE-2099-0002", { vendor: "acme ", cwes: ["CWE-78", "CWE-89"] });
    seedKev(db, "CVE-2099-0003", { vendor: "Other" });
    seedEpss(db, "CVE-2099-0001", "0.50");
    seedEpss(db, "CVE-2099-0002", "0.10");

    const graph = buildKevGraph(db, { nodeLimit: 10 });
    expect(graph.focus).toBeNull();
    expect(graph.eligibleCohort).toBe(3);
    expect(graph.truncated).toBe(false);
    expect(graph.nodes.map((node) => node.id)).toContain("CVE-2099-0001");
    // Top-EPSS first in the default cohort.
    expect(graph.nodes[0]?.id).toBe("CVE-2099-0001");
    const edge = graph.edges.find(
      (entry) => entry.from === "CVE-2099-0001" && entry.to === "CVE-2099-0002",
    );
    // Shared CWE-78 (deduped) plus normalized vendor "acme".
    expect(edge?.kinds).toEqual(["cwe", "vendor"]);
    expect(
      graph.edges.some((entry) => entry.from === "CVE-2099-0001" && entry.to === "CVE-2099-0003"),
    ).toBe(false);
    expect(graph.nodes.find((node) => node.id === "CVE-2099-0001")?.degree).toBe(1);
  });

  it("returns an ego neighborhood for a focus record", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedRecord(db, "CVE-2099-0002");
    seedRecord(db, "CVE-2099-0003");
    seedKev(db, "CVE-2099-0001", { cwes: ["CWE-78"] });
    seedKev(db, "CVE-2099-0002", { cwes: ["CWE-78"] });
    seedKev(db, "CVE-2099-0003", { cwes: ["CWE-89"] });

    const graph = buildKevGraph(db, { focus: "CVE-2099-0001", nodeLimit: 10 });
    expect(graph.focus).toBe("CVE-2099-0001");
    expect(graph.nodes.map((node) => node.id).sort()).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
    expect(graph.truncated).toBe(false);
  });

  it("rejects a focus outside the cohort and caps deterministically", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedRecord(db, "CVE-2099-0002");
    seedKev(db, "CVE-2099-0001", {});
    seedKev(db, "CVE-2099-0002", {});
    expect(() => buildKevGraph(db, { focus: "CVE-2099-9999" })).toThrowError(RangeError);
    expect(() => buildKevGraph(db, { focus: "CVE-2099-0001", nodeLimit: 0 })).not.toThrow();

    const first = buildKevGraph(db, { nodeLimit: 1 });
    const second = buildKevGraph(db, { nodeLimit: 1 });
    expect(first.nodes).toHaveLength(1);
    expect(first.truncated).toBe(true);
    expect(second).toEqual(first);
    expect(buildKevGraph(db, {}).truncated).toBe(false);
    expect(GRAPH_DEFAULT_NODE_LIMIT).toBe(120);
    expect(GRAPH_MAX_EDGES).toBe(1500);
  });

  it("orders the default cohort by EPSS descending, unknown last", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedRecord(db, "CVE-2099-0002");
    seedRecord(db, "CVE-2099-0003");
    seedKev(db, "CVE-2099-0001", {});
    seedKev(db, "CVE-2099-0002", {});
    seedKev(db, "CVE-2099-0003", {});
    seedEpss(db, "CVE-2099-0002", "0.10");
    seedEpss(db, "CVE-2099-0001", "0.50");
    const graph = buildKevGraph(db, { nodeLimit: 10 });
    expect(graph.nodes.map((node) => node.id)).toEqual([
      "CVE-2099-0001",
      "CVE-2099-0002",
      "CVE-2099-0003",
    ]);
  });

  it("ignores malformed references and empty cohorts without throwing", () => {
    const db = makeDb();
    const empty = buildKevGraph(db, {});
    expect(empty.nodes).toEqual([]);
    expect(empty.edges).toEqual([]);
    expect(empty.eligibleCohort).toBe(0);
    expect(empty.truncated).toBe(false);
  });
});
