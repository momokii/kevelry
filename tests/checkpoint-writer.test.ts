// New-test justification (v3 epic E5, step 1b): the RSS feed and the radar
// route read only retained `checkpoints` rows, and nothing used to write them,
// so the feed was a permanently empty channel. These tests prove against the
// real SQLite layer that one settled cycle writes exactly ONE checkpoint for
// the current UTC date, that a second cycle on that date writes none, that an
// all-failed cycle writes none, and that a rejected write is logged as
// `checkpoint-write-failed` without throwing into the cycle. Fixture IDs are
// invented CVE-2099 values; nothing here touches the network.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { resolveSourcePins, writeDailyCheckpoint } from "../src/lib/checkpoint-writer";
import { type CveDatabase, openDatabase } from "../src/lib/db";
import { readCheckpoint } from "../src/lib/radar";
import type { SourceName } from "../src/lib/schedule";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-checkpoint-writer-test-"));
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

const DAY = "2026-11-14";
const NOW = new Date(`${DAY}T09:30:00.000Z`);
const KEV_CATALOG_DATE = `${DAY}T03:00:00.000Z`;

const ALL_OK: Record<SourceName, string | null> = {
  cve: null,
  kev: null,
  epss: null,
  ssvc: null,
};

function allFailed(): Record<SourceName, string | null> {
  return {
    cve: "cve refresh failed: HTTP 503",
    kev: "kev refresh failed: HTTP 503",
    epss: "epss refresh failed: HTTP 503",
    ssvc: "ssvc refresh failed: timeout",
  };
}

function recordSyncRun(
  db: CveDatabase,
  source: SourceName,
  revision: string,
  status: "succeeded" | "failed" = "succeeded",
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(source, `${DAY}T03:00:00.000Z`, `${DAY}T03:05:00.000Z`, status, revision, null, null);
  });
}

/**
 * Accepted versions exactly as the importers record them: CVE revision, KEV
 * catalog version (not a date), EPSS `scoreDate@model`. The KEV catalog date
 * the accepted snapshot observed lives in `kev_entries`.
 */
function seedAcceptedSources(db: CveDatabase): void {
  recordSyncRun(db, "cve", "rev-aaa111");
  recordSyncRun(db, "kev", "2026.11.14");
  recordSyncRun(db, "epss", `${DAY}@v2026.06.15`);
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        "CVE-2099-0001",
        "5.1",
        "PUBLISHED",
        `${DAY}T00:00:00.000Z`,
        "Checkpoint writer fixture",
        `${DAY}T00:00:00.000Z`,
        `${DAY}T00:00:00.000Z`,
      );
    db.handle
      .prepare(
        "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
      )
      .run("CVE-2099-0001", DAY, KEV_CATALOG_DATE, KEV_CATALOG_DATE);
    db.handle
      .prepare(
        "INSERT OR REPLACE INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
      )
      .run("CVE-2099-0001", DAY, "v2026.06.15", "0.90000", "0.99000");
  });
}

function checkpointCount(db: CveDatabase): number {
  return (db.handle.prepare("SELECT COUNT(*) AS n FROM checkpoints").get() as { n: number }).n;
}

describe("daily checkpoint writer", () => {
  it("writes exactly one checkpoint for the UTC date after a cycle with an accepted source", () => {
    const db = makeDb();
    seedAcceptedSources(db);
    const logs: Array<{ event: string; [key: string]: unknown }> = [];

    const result = writeDailyCheckpoint(db, {
      now: NOW,
      failed: ALL_OK,
      topN: 25,
      log: (entry) => logs.push(entry),
    });

    expect(result).toEqual({
      written: true,
      checkpointDate: DAY,
      reason: "written",
      boundedTopN: 25,
      error: null,
    });
    expect(checkpointCount(db)).toBe(1);

    const stored = readCheckpoint(db, DAY);
    expect(stored?.observedAt).toBe(NOW.toISOString());
    expect(stored?.sourcePins).toEqual({
      cveRevision: "rev-aaa111",
      // The accepted KEV revision is a version, so the observed catalog date
      // the same accepted snapshot wrote is the pin.
      kevCatalogDate: KEV_CATALOG_DATE,
      epssScoreDate: DAY,
      epssModelVersion: "v2026.06.15",
    });
    expect(stored?.boundedTopN).toBe(25);

    const written = logs.filter((entry) => entry.event === "checkpoint-written");
    expect(written).toHaveLength(1);
    expect(written[0]?.boundedTopN).toBe(25);
    expect(logs.some((entry) => entry.event === "checkpoint-write-failed")).toBe(false);
  });

  it("writes none on a second cycle for the same UTC date (checkpoints are immutable)", () => {
    const db = makeDb();
    seedAcceptedSources(db);
    writeDailyCheckpoint(db, { now: NOW, failed: ALL_OK, topN: 10 });

    const second = writeDailyCheckpoint(db, {
      now: new Date(`${DAY}T23:45:00.000Z`),
      failed: ALL_OK,
      topN: 10,
    });

    expect(second.written).toBe(false);
    expect(second.reason).toBe("already-exists");
    expect(checkpointCount(db)).toBe(1);
    // The retained row is still the first observation, never overwritten.
    expect(readCheckpoint(db, DAY)?.observedAt).toBe(NOW.toISOString());
  });

  it("writes none when every source in the cycle failed", () => {
    const db = makeDb();
    seedAcceptedSources(db);
    const logs: Array<{ event: string; [key: string]: unknown }> = [];

    const result = writeDailyCheckpoint(db, {
      now: NOW,
      failed: allFailed(),
      topN: 10,
      log: (entry) => logs.push(entry),
    });

    expect(result.written).toBe(false);
    expect(result.reason).toBe("no-source-succeeded");
    expect(checkpointCount(db)).toBe(0);
    expect(logs).toEqual([]);
  });

  it("logs checkpoint-write-failed instead of throwing when the write is rejected", () => {
    const db = makeDb();
    seedAcceptedSources(db);
    const logs: Array<{ event: string; [key: string]: unknown }> = [];

    let result: ReturnType<typeof writeDailyCheckpoint> | undefined;
    expect(() => {
      result = writeDailyCheckpoint(db, {
        now: NOW,
        failed: ALL_OK,
        // Rejected by the existing CHECKPOINT_TOP_N resolver (bound validation).
        topN: 0,
        log: (entry) => logs.push(entry),
      });
    }).not.toThrow();

    expect(result?.written).toBe(false);
    expect(result?.reason).toBe("failed");
    expect(result?.error).toMatch(/topN/);
    expect(checkpointCount(db)).toBe(0);
    const failed = logs.filter((entry) => entry.event === "checkpoint-write-failed");
    expect(failed).toHaveLength(1);
    expect(String(failed[0]?.error)).toMatch(/topN/);
  });

  it("reports missing accepted pins as a logged failure, never a cycle error", () => {
    const db = makeDb();
    seedAcceptedSources(db);
    // A cve source that never succeeded leaves the checkpoint unpinnable.
    db.runBoundedWrite(() => {
      db.handle.prepare("DELETE FROM sync_runs WHERE source = ?").run("cve");
    });
    const logs: Array<{ event: string; [key: string]: unknown }> = [];

    expect(resolveSourcePins(db)).toBeNull();
    const result = writeDailyCheckpoint(db, {
      now: NOW,
      failed: ALL_OK,
      topN: 10,
      log: (entry) => logs.push(entry),
    });

    expect(result.written).toBe(false);
    expect(result.reason).toBe("missing-pins");
    expect(checkpointCount(db)).toBe(0);
    expect(logs.map((entry) => entry.event)).toEqual(["checkpoint-write-failed"]);
  });
});
