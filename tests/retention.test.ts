import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { openDatabase } from "../src/lib/db";
import { epssCutoffDay, pruneEpssHistory, resolveEpssRetentionDays } from "../src/lib/retention";

const tempDirs: string[] = [];

function makeDb(): ReturnType<typeof openDatabase> {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-retention-test-"));
  tempDirs.push(dir);
  return openDatabase({ dataDir: dir });
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function seedEpss(db: ReturnType<typeof openDatabase>, days: readonly string[]): void {
  const insert = db.handle.prepare(
    "INSERT INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
  );
  for (const day of days) insert.run("CVE-2026-0001", day, "v2025.03.14", "0.5", "0.9");
}

describe("EPSS retention policy", () => {
  it("uses the documented default when unset and rejects malformed values", () => {
    expect(resolveEpssRetentionDays({})).toBe(45);
    expect(resolveEpssRetentionDays({ EPSS_RETENTION_DAYS: "365" })).toBe(365);
    expect(() => resolveEpssRetentionDays({ EPSS_RETENTION_DAYS: "0" })).toThrow(
      /EPSS_RETENTION_DAYS/,
    );
    expect(() => resolveEpssRetentionDays({ EPSS_RETENTION_DAYS: "1.5" })).toThrow(
      /EPSS_RETENTION_DAYS/,
    );
    expect(() => resolveEpssRetentionDays({ EPSS_RETENTION_DAYS: "99999" })).toThrow(
      /EPSS_RETENTION_DAYS/,
    );
  });

  it("counts the window back from the anchor day inclusively", () => {
    expect(epssCutoffDay("2026-11-07", 1)).toBe("2026-11-07");
    expect(epssCutoffDay("2026-11-07", 30)).toBe("2026-10-09");
    expect(epssCutoffDay("2026-03-01", 2)).toBe("2026-02-28");
    expect(epssCutoffDay("2024-03-01", 2)).toBe("2024-02-29");
  });

  it("deletes only rows older than the window and keeps it idempotent", () => {
    const db = makeDb();
    seedEpss(db, ["2026-09-01", "2026-10-08", "2026-10-09", "2026-11-07"]);

    const first = pruneEpssHistory(db, { anchorDay: "2026-11-07", keepDays: 30 });
    expect(first.deleted).toBe(2);
    expect(first.oldestKept).toBe("2026-10-09");

    const second = pruneEpssHistory(db, { anchorDay: "2026-11-07", keepDays: 30 });
    expect(second.deleted).toBe(0);
    expect(second.skipped).toBe(true);
    expect(second.oldestKept).toBe("2026-10-09");

    const rows = db.handle.prepare("SELECT COUNT(*) AS c FROM epss_daily").get() as { c: number };
    expect(rows.c).toBe(2);
    db.close();
  });

  it("reports an empty table without failing", () => {
    const db = makeDb();
    const result = pruneEpssHistory(db, { anchorDay: "2026-11-07", keepDays: 30 });
    expect(result).toMatchObject({ oldestKept: null, deleted: 0, skipped: true });
    expect(result.cutoff).toBe("2026-10-09");
    db.close();
  });

  it("ledgers the prune, including the run that deleted nothing", () => {
    // Before this the prune only spoke through a log line, so "did retention
    // actually run?" was unanswerable from the database: the newest
    // maintenance_runs row was the exploit-ref backfill.
    const db = makeDb();
    seedEpss(db, ["2026-09-01", "2026-10-08", "2026-10-09"]);

    const first = pruneEpssHistory(db, {
      anchorDay: "2026-11-07",
      keepDays: 30,
      now: new Date("2026-11-07T05:56:57.000Z"),
    });
    expect(first.deleted).toBe(2);

    const row = db.handle
      .prepare("SELECT name, completed_at, detail FROM maintenance_runs WHERE name = ?")
      .get("epss-retention") as { name: string; completed_at: string; detail: string };
    expect(row.name).toBe("epss-retention");
    expect(row.completed_at).toBe("2026-11-07T05:56:57.000Z");
    expect(JSON.parse(row.detail)).toEqual({
      keepDays: 30,
      cutoffDate: "2026-10-09",
      rowsDeleted: 2,
      skipped: false,
    });

    // Nothing left to delete, still one honest row for this run.
    const second = pruneEpssHistory(db, {
      anchorDay: "2026-11-07",
      keepDays: 30,
      now: new Date("2026-11-08T05:56:57.000Z"),
    });
    expect(second.skipped).toBe(true);
    const after = db.handle
      .prepare("SELECT completed_at, detail FROM maintenance_runs WHERE name = ?")
      .get("epss-retention") as { completed_at: string; detail: string };
    expect(after.completed_at).toBe("2026-11-08T05:56:57.000Z");
    expect(JSON.parse(after.detail)).toEqual({
      keepDays: 30,
      cutoffDate: "2026-10-09",
      rowsDeleted: 0,
      skipped: true,
    });
    const count = db.handle
      .prepare("SELECT COUNT(*) AS n FROM maintenance_runs WHERE name = ?")
      .get("epss-retention") as { n: number };
    expect(count.n).toBe(1);
    db.close();
  });
});
