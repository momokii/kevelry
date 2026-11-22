import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { buildProvenance } from "../app/api/v1/_lib/provenance";
import { acceptedVersions } from "../src/lib/aggregates";
import { type CveDatabase, openDatabase } from "../src/lib/db";
import { sweepAbandonedSyncRuns } from "../src/lib/sync-run-sweep";

const tempDirs: string[] = [];
const openHandles: CveDatabase[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-sweep-test-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openHandles.push(db);
  return db;
}

afterEach(() => {
  while (openHandles.length > 0) {
    const handle = openHandles.pop() as CveDatabase;
    try {
      handle.close();
    } catch {
      // Best-effort close before directory removal.
    }
  }
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

interface SeedRun {
  source: "cve" | "kev" | "epss" | "ssvc";
  startedAt: string;
  status: "running" | "succeeded" | "failed";
  revision: string | null;
  finishedAt?: string | null;
  error?: string | null;
}

function seedRun(db: CveDatabase, run: SeedRun): number {
  const info = db.handle
    .prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .run(
      run.source,
      run.startedAt,
      run.finishedAt ?? null,
      run.status,
      run.revision,
      null,
      run.error ?? null,
    );
  return Number(info.lastInsertRowid);
}

interface RunRow {
  id: number;
  status: string;
  started_at: string;
  finished_at: string | null;
  error: string | null;
}

function readRun(db: CveDatabase, id: number): RunRow {
  return db.handle
    .prepare("SELECT id, status, started_at, finished_at, error FROM sync_runs WHERE id = ?")
    .get(id) as RunRow;
}

describe("abandoned sync_runs sweep", () => {
  it("marks a run older than two hours interrupted and leaves younger or closed runs alone", () => {
    const db = makeDb();
    const now = new Date("2026-11-09T12:00:00.000Z");
    const abandoned = seedRun(db, {
      source: "epss",
      startedAt: "2026-11-09T09:00:00.000Z",
      status: "running",
      revision: null,
    });
    const inFlight = seedRun(db, {
      source: "cve",
      startedAt: "2026-11-09T11:55:00.000Z",
      status: "running",
      revision: null,
    });
    const accepted = seedRun(db, {
      source: "kev",
      startedAt: "2026-11-08T09:00:00.000Z",
      finishedAt: "2026-11-08T09:04:00.000Z",
      status: "succeeded",
      revision: "2026.11.08",
    });

    const swept = sweepAbandonedSyncRuns(db, { now });
    expect(swept).toEqual({ interrupted: 1, ids: [abandoned] });

    // Marked, not deleted; the timestamps still say when it started.
    const marked = readRun(db, abandoned);
    expect(marked.status).toBe("interrupted");
    expect(marked.started_at).toBe("2026-11-09T09:00:00.000Z");
    expect(marked.finished_at).toBeNull();
    expect(marked.error).toMatch(/^interrupted:/);

    // Five minutes old is an import in flight, not an abandoned one.
    expect(readRun(db, inFlight)).toMatchObject({ status: "running", error: null });
    expect(readRun(db, accepted)).toMatchObject({
      status: "succeeded",
      finished_at: "2026-11-08T09:04:00.000Z",
    });

    // Idempotent: a second boot finds nothing left to sweep.
    expect(sweepAbandonedSyncRuns(db, { now }).interrupted).toBe(0);
  });

  it("never lets an abandoned attempt masquerade as an accepted version", () => {
    // Freshness is derived from `status = 'succeeded'` rows only
    // (src/lib/aggregates.ts acceptedVersions, src/lib/checkpoint-writer.ts
    // lastSucceededRevision, src/lib/provenance.ts latestSucceeded). This pins
    // that, so the sweep can never move an accepted pin.
    const db = makeDb();
    const now = new Date("2026-11-09T12:00:00.000Z");
    seedRun(db, {
      source: "cve",
      startedAt: "2026-11-09T08:00:00.000Z",
      finishedAt: "2026-11-09T08:10:00.000Z",
      status: "succeeded",
      revision: "rev-accepted",
    });
    seedRun(db, {
      source: "cve",
      startedAt: "2026-11-09T09:00:00.000Z",
      status: "running",
      revision: "rev-abandoned",
    });

    expect(acceptedVersions(db).cveRevision).toBe("rev-accepted");
    sweepAbandonedSyncRuns(db, { now });
    expect(acceptedVersions(db).cveRevision).toBe("rev-accepted");

    const provenance = buildProvenance(db, now.toISOString());
    expect(provenance.sources.cve.revision).toBe("rev-accepted");
    // `interrupted` is not an import failure, so it must not read as an error.
    expect(provenance.sources.cve.error).toBeNull();
  });
});
