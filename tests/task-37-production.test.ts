// Task-37 production readiness: bounded checkpoints, bounded list routes, and
// the /api/v1/search 500 fix, proven on a synthetic 50,000-row scored corpus
// (invented CVE-2099 IDs, no network). Every description mentions "php", so
// q=php matches all 50,000 rows — past the 32,766 SQLite variable limit that
// turned the old unbounded fan-out + unbounded IN clause into a 500.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import { getDefaultPriority, getHighestForecast, getKnownExploited } from "../src/lib/priority";
import {
  CHECKPOINT_TOP_N_DEFAULT,
  CHECKPOINT_TOP_N_MAX,
  readCheckpoint,
  replayCheckpoint,
  resolveCheckpointTopN,
  writeCheckpoint,
} from "../src/lib/radar";
import { resolveIngestOnStart } from "../src/worker";
import { resetDbOverride, setDbOverride } from "../app/api/v1/_lib/shared";
import { GET as getCves } from "../app/api/v1/cves/route";
import { GET as getSearch } from "../app/api/v1/search/route";
import { GET as getPriority } from "../app/api/v1/priority/[listName]/route";
import { GET as getOverview } from "../app/api/v1/overview/route";
import { GET as getReplay } from "../app/api/v1/replay/route";

const tempDirs: string[] = [];

const STAMP = "2026-10-24T00:00:00.000Z";
const DAY = "2026-10-24";
const DAY_MINUS_7 = "2026-10-17";
const MODEL = "v2026.06.15";
const ROWS = 50_000;

const PINS = {
  cveRevision: "rev-scale-37",
  kevCatalogDate: "2026-10-23T00:00:00.000Z",
  epssScoreDate: DAY,
  epssModelVersion: MODEL,
};

function epssFor(index: number): string {
  if (index % 5000 === 0) return "0.99999";
  return (0.00001 + ((index * 7919) % 99999) / 100000).toFixed(5);
}

function cveIdAt(index: number): string {
  return `CVE-2099-${String(index).padStart(5, "0")}`;
}

function makeDir(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-task37-scale-"));
  tempDirs.push(dir);
  return dir;
}

function seedScaleCorpus(dir: string): void {
  const db = openDatabase({ dataDir: dir });
  try {
    const insertRecord = db.handle.prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    );
    const insertEpss = db.handle.prepare(
      "INSERT INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
    );
    const insertCvss = db.handle.prepare(
      "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
    );
    const insertKev = db.handle.prepare(
      "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
    );
    const tx = db.handle.transaction(() => {
      for (let index = 0; index < ROWS; index += 1) {
        const cveId = cveIdAt(index);
        insertRecord.run(
          cveId,
          "5.1",
          "PUBLISHED",
          "2026-10-20T00:00:00.000Z",
          `Title for ${cveId}`,
          `php security flaw in the packet parser handling fragmented datagrams for ${cveId}`,
          STAMP,
          STAMP,
        );
        insertEpss.run(cveId, DAY, MODEL, epssFor(index), "0.80000");
        if (index < 2000) {
          const prev = (Number(epssFor(index)) - 0.01).toFixed(5);
          insertEpss.run(cveId, DAY_MINUS_7, MODEL, prev, "0.80000");
        }
        if (index % 7 === 0) {
          insertCvss.run(cveId, "CNA", "3.1", "9.8", "CVSS:3.1/AV:N", 0);
        }
      }
      for (let index = 1; index <= 10; index += 1) {
        insertKev.run(
          cveIdAt(index),
          `2026-10-${String(10 + index).padStart(2, "0")}`,
          STAMP,
          STAMP,
        );
      }
    });
    tx();
  } finally {
    db.close();
  }
}

let sharedDir = "";

beforeAll(() => {
  sharedDir = makeDir();
  seedScaleCorpus(sharedDir);
}, 180000);

afterAll(() => {
  resetDbOverride();
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

async function bodyOf(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

describe("bounded radar checkpoints at scale (task 37.1)", () => {
  it("writes a 50k-row manifest in bounded time with a bounded payload", () => {
    const db = openDatabase({ dataDir: sharedDir });
    try {
      const started = performance.now();
      const stored = writeCheckpoint(db, {
        checkpointDate: DAY,
        observedAt: `${DAY}T08:00:00.000Z`,
        sourcePins: PINS,
      });
      const elapsedMs = performance.now() - started;
      expect(elapsedMs).toBeLessThan(90000);
      expect(stored.boundedTopN).toBe(CHECKPOINT_TOP_N_DEFAULT);
      expect(stored.cohortCount).toBe(ROWS);
      for (const ids of Object.values(stored.views)) {
        expect(ids.length).toBeLessThanOrEqual(CHECKPOINT_TOP_N_DEFAULT);
      }
      expect(stored.views.defaultPriority.length).toBe(CHECKPOINT_TOP_N_DEFAULT);
      const payload = db.handle
        .prepare(
          "SELECT LENGTH(materialized_results_json) AS n FROM checkpoints WHERE checkpoint_date = ?",
        )
        .get(DAY) as { n: number };
      expect(payload.n).toBeLessThan(8 * 1024 * 1024);
      expect(readCheckpoint(db, DAY)).toEqual(stored);
    } finally {
      db.close();
    }
  }, 180000);

  it("honors an explicit topN and env override, and validates the bound", () => {
    const previous = process.env.CHECKPOINT_TOP_N;
    try {
      process.env.CHECKPOINT_TOP_N = "50";
      expect(resolveCheckpointTopN()).toBe(50);
      process.env.CHECKPOINT_TOP_N = "";
      expect(resolveCheckpointTopN()).toBe(CHECKPOINT_TOP_N_DEFAULT);
      process.env.CHECKPOINT_TOP_N = "abc";
      expect(() => resolveCheckpointTopN()).toThrowError(/CHECKPOINT_TOP_N/);
      process.env.CHECKPOINT_TOP_N = "0";
      expect(() => resolveCheckpointTopN()).toThrowError(/CHECKPOINT_TOP_N/);
      process.env.CHECKPOINT_TOP_N = String(CHECKPOINT_TOP_N_MAX + 1);
      expect(() => resolveCheckpointTopN()).toThrowError(/CHECKPOINT_TOP_N/);
      expect(() => resolveCheckpointTopN({}, 0)).toThrowError(/topN/);
      expect(resolveCheckpointTopN({}, 50)).toBe(50);

      const db = openDatabase({ dataDir: makeDir() });
      try {
        db.runBoundedWrite(() => {
          const insert = db.handle.prepare(
            "INSERT INTO cve_records (cve_id, data_version, state, date_published, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
          );
          for (let index = 0; index < 5; index += 1) {
            insert.run(
              `CVE-2099-1000${index}`,
              "5.1",
              "PUBLISHED",
              "2026-10-20T00:00:00.000Z",
              "php flaw",
              STAMP,
              STAMP,
            );
          }
        });
        const stored = writeCheckpoint(db, {
          checkpointDate: DAY,
          observedAt: `${DAY}T08:00:00.000Z`,
          sourcePins: PINS,
          topN: 3,
        });
        expect(stored.boundedTopN).toBe(3);
        expect(stored.cohortCount).toBe(5);
        expect(stored.views.defaultPriority.length).toBe(3);
        const replayed = replayCheckpoint(db, DAY, { asOfDate: DAY });
        expect(replayed.status).toBe("available");
        if (replayed.status !== "available") throw new Error("replay unavailable");
        expect(replayed.manifest.boundedTopN).toBe(3);
        expect(replayed.results).toEqual(stored.views);
      } finally {
        db.close();
      }
    } finally {
      if (previous === undefined) delete process.env.CHECKPOINT_TOP_N;
      else process.env.CHECKPOINT_TOP_N = previous;
    }
  });

  it("replays byte-equal results with boundedTopN surfaced", async () => {
    const db = openDatabase({ dataDir: sharedDir });
    try {
      setDbOverride(db);
      const stored = readCheckpoint(db, DAY);
      expect(stored).toBeDefined();
      if (stored === undefined) throw new Error("missing checkpoint");
      const replayed = replayCheckpoint(db, DAY, { asOfDate: DAY });
      expect(replayed.status).toBe("available");
      if (replayed.status !== "available") return;
      expect(replayed.manifest.boundedTopN).toBe(CHECKPOINT_TOP_N_DEFAULT);
      expect(replayed.results).toEqual(stored.views);
      expect(JSON.stringify(replayed.results)).toBe(JSON.stringify(stored.views));

      const response = await getReplay(
        new Request(
          "https://radar.test/api/v1/replay?date=2026-10-24&view=highest-forecast&limit=5",
        ),
      );
      expect(response.status).toBe(200);
      const body = await bodyOf(response);
      expect(body.boundedTopN).toBe(CHECKPOINT_TOP_N_DEFAULT);
      expect(typeof body.boundedNotice).toBe("string");
      expect(body.checkpointDate).toBe(DAY);
    } finally {
      resetDbOverride();
      db.close();
    }
  });
});

describe("bounded list routes at scale (task 37.2)", () => {
  it("matches limit-after-full-order exactly for the default priority getter", () => {
    const db = openDatabase({ dataDir: sharedDir });
    try {
      const full = getDefaultPriority(db);
      expect(full.length).toBe(ROWS);
      expect(getDefaultPriority(db, 5).map((row) => row.id)).toEqual(
        full.slice(0, 5).map((row) => row.id),
      );
      expect(getDefaultPriority(db, 0)).toEqual([]);
    } finally {
      db.close();
    }
  }, 180000);

  it("serves bounded priority, cves, and overview pages with unchanged shapes", async () => {
    const db = openDatabase({ dataDir: sharedDir });
    try {
      setDbOverride(db);

      const highest = await getPriority(
        new Request("https://radar.test/api/v1/priority/highest-forecast?limit=5"),
        { params: Promise.resolve({ listName: "highest-forecast" }) },
      );
      expect(highest.status).toBe(200);
      const highestBody = await bodyOf(highest);
      const highestData = highestBody.data as Array<{ cveId: string }>;
      expect(highestData.length).toBe(5);
      const siteHighest = getHighestForecast(db, 5).map((row) => row.id);
      expect(highestData.map((row) => row.cveId)).toEqual(siteHighest);

      const kev = await getPriority(
        new Request("https://radar.test/api/v1/priority/known-exploited?limit=5"),
        { params: Promise.resolve({ listName: "known-exploited" }) },
      );
      expect(kev.status).toBe(200);
      const kevData = (await bodyOf(kev)).data as Array<{ cveId: string }>;
      expect(kevData.map((row) => row.cveId)).toEqual(
        getKnownExploited(db, 5).map((row) => row.id),
      );

      const cves = await getCves(new Request("https://radar.test/api/v1/cves?limit=2"));
      expect(cves.status).toBe(200);
      const cvesBody = await bodyOf(cves);
      const cvesData = cvesBody.data as Array<{ cveId: string }>;
      expect(cvesData.length).toBe(2);
      expect(cvesData.map((row) => row.cveId)).toEqual(
        getDefaultPriority(db, 3)
          .slice(0, 2)
          .map((row) => row.id),
      );
      const cvesCoverage = cvesBody.coverage as Record<string, number>;
      expect(cvesCoverage.eligibleCohort).toBe(ROWS);
      expect(cvesCoverage.returned).toBe(2);

      const overview = await getOverview(
        new Request("https://radar.test/api/v1/overview?bucket=month&months=2"),
      );
      expect(overview.status).toBe(200);
      const overviewBody = await bodyOf(overview);
      const overviewCoverage = overviewBody.coverage as Record<string, number>;
      expect(overviewCoverage.eligibleCohort).toBe(ROWS);
      expect(overviewCoverage.unknownDate).toBe(0);
    } finally {
      resetDbOverride();
      db.close();
    }
  }, 180000);
});

describe("search 500 regression at scale (task 37.3)", () => {
  it("serves q=php&limit=3 with 200 and full-cohort total on 50k FTS matches", async () => {
    const db = openDatabase({ dataDir: sharedDir });
    try {
      setDbOverride(db);
      const response = await getSearch(
        new Request("https://radar.test/api/v1/search?q=php&limit=3"),
      );
      expect(response.status).toBe(200);
      const body = await bodyOf(response);
      const data = body.data as Array<{ cveId: string }>;
      expect(data.length).toBe(3);
      const coverage = body.coverage as Record<string, number>;
      expect(coverage.eligibleCohort).toBe(ROWS);
      expect(body.q).toBe("php");
    } finally {
      resetDbOverride();
      db.close();
    }
  }, 120000);
});

describe("ingest-on-start gate (task 37.4)", () => {
  it("resolves INGEST_ON_START with a true default and rejects garbage", () => {
    expect(resolveIngestOnStart({})).toBe(true);
    expect(resolveIngestOnStart({ INGEST_ON_START: "" })).toBe(true);
    expect(resolveIngestOnStart({ INGEST_ON_START: "true" })).toBe(true);
    expect(resolveIngestOnStart({ INGEST_ON_START: "false" })).toBe(false);
    expect(() => resolveIngestOnStart({ INGEST_ON_START: "yes" })).toThrowError(/INGEST_ON_START/);
  });
});
