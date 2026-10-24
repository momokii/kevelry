// New-test justification (plan todo 12): the Radar diff and snapshot replay
// services are the first code that turns retained daily checkpoints into
// historical truthfulness, so tests must prove against the real SQLite layer
// (not the todo-6 in-memory stubs) that the checkpoint writer freezes the
// observed cohort, policy version, and materialized list results; that the
// change detector labels source changes (KEV added, CNA changed, forecast
// changed, corrected/rejected) apart from rank-only/cohort/window/policy
// movement with no causal claims about EPSS internals; and that replay
// reproduces the retained results or fails explicitly unavailable (expired,
// missing, pre-launch, model-changed, baseline released, tampered manifest)
// without ever substituting current data. Fixtures use invented CVE-2099 IDs;
// nothing here touches the network.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import {
  RADAR_POLICY_VERSION,
  RADAR_RETENTION_DAYS,
  diffCheckpoints,
  isCheckpointExpired,
  isBaselineRetained,
  launchDay,
  listCheckpoints,
  pruneExpiredCheckpoints,
  readCheckpoint,
  releaseBaseline,
  replayCheckpoint,
  writeCheckpoint,
} from "../src/lib/radar";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-radar-test-"));
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
const MODEL = "v2026.06.15";
const DAY_ONE = "2026-10-23";
const DAY_TWO = "2026-10-24";

const PINS = {
  cveRevision: "rev-aaa111",
  kevCatalogDate: "2026-10-23T00:00:00.000Z",
  epssScoreDate: "2026-10-23",
  epssModelVersion: MODEL,
};

function seedRecord(
  db: CveDatabase,
  cveId: string,
  opts: {
    datePublished?: string | null;
    dateUpdated?: string | null;
    description?: string;
    state?: string;
  } = {},
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        cveId,
        "5.1",
        opts.state ?? "PUBLISHED",
        opts.datePublished === undefined ? "2026-10-20T00:00:00.000Z" : opts.datePublished,
        opts.dateUpdated === undefined ? "2026-10-20T00:00:00.000Z" : opts.dateUpdated,
        opts.description ?? `Description for ${cveId}`,
        STAMP,
        STAMP,
      );
  });
}

function seedKev(db: CveDatabase, cveId: string, dateAdded = "2026-10-18"): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
      )
      .run(cveId, dateAdded, PINS.kevCatalogDate, STAMP);
  });
}

function seedEpss(
  db: CveDatabase,
  cveId: string,
  scoreDate: string,
  epss: string,
  model: string = MODEL,
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT OR REPLACE INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
      )
      .run(cveId, scoreDate, model, epss, "0.80000");
  });
}

function seedCvss(
  db: CveDatabase,
  cveId: string,
  opts: { version?: string; baseScore?: string; vector?: string } = {},
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(
        cveId,
        "CNA",
        opts.version ?? "3.1",
        opts.baseScore ?? "9.8",
        opts.vector ?? "CVSS:3.1/AV:N",
        0,
      );
  });
}

function updateDescription(db: CveDatabase, cveId: string, description: string): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare("UPDATE cve_records SET description = ? WHERE cve_id = ?")
      .run(description, cveId);
  });
}

function rejectRecord(db: CveDatabase, cveId: string): void {
  db.runBoundedWrite(() => {
    db.handle.prepare("UPDATE cve_records SET state = ? WHERE cve_id = ?").run("REJECTED", cveId);
  });
}

describe("radar checkpoint writer on SQLite (todo 12)", () => {
  it("freezes cohort, policy version, and materialized results for the observed day", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedRecord(db, "CVE-2099-0002");
    seedKev(db, "CVE-2099-0001");
    seedEpss(db, "CVE-2099-0002", PINS.epssScoreDate, "0.90");

    const stored = writeCheckpoint(db, {
      checkpointDate: DAY_ONE,
      observedAt: `${DAY_ONE}T08:15:00.000Z`,
      sourcePins: PINS,
    });

    expect(stored.checkpointDate).toBe(DAY_ONE);
    expect(stored.policyVersion).toBe(RADAR_POLICY_VERSION);
    expect(stored.cohortCount).toBe(2);
    expect(stored.sourcePins).toEqual(PINS);
    expect(stored.views.defaultPriority).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
    expect(isBaselineRetained(db, PINS.cveRevision)).toBe(true);

    const reread = readCheckpoint(db, DAY_ONE);
    expect(reread).toEqual(stored);
    expect(listCheckpoints(db).map((row) => row.checkpointDate)).toEqual([DAY_ONE]);
    expect(launchDay(db)).toBe(DAY_ONE);
  });

  it("refuses an observed timestamp outside the checkpoint date (never invents midnight)", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    expect(() =>
      writeCheckpoint(db, {
        checkpointDate: DAY_ONE,
        observedAt: `${DAY_TWO}T00:05:00.000Z`,
        sourcePins: PINS,
      }),
    ).toThrowError(/outside checkpoint date/);
    expect(readCheckpoint(db, DAY_ONE)).toBeUndefined();
  });

  it("refuses empty pins, empty policy version, and malformed dates", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    expect(() =>
      writeCheckpoint(db, {
        checkpointDate: DAY_ONE,
        observedAt: `${DAY_ONE}T08:00:00.000Z`,
        sourcePins: { ...PINS, cveRevision: "" },
      }),
    ).toThrowError(/revision/);
    expect(() =>
      writeCheckpoint(db, {
        checkpointDate: DAY_ONE,
        observedAt: `${DAY_ONE}T08:00:00.000Z`,
        sourcePins: PINS,
        policyVersion: "",
      }),
    ).toThrowError(/policy version/);
    expect(() =>
      writeCheckpoint(db, {
        checkpointDate: "not-a-day",
        observedAt: `${DAY_ONE}T08:00:00.000Z`,
        sourcePins: PINS,
      }),
    ).toThrowError(/checkpoint date/);
  });

  it("refuses a second checkpoint for the same date (checkpoints are immutable)", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    writeCheckpoint(db, {
      checkpointDate: DAY_ONE,
      observedAt: `${DAY_ONE}T08:00:00.000Z`,
      sourcePins: PINS,
    });
    expect(() =>
      writeCheckpoint(db, {
        checkpointDate: DAY_ONE,
        observedAt: `${DAY_ONE}T20:00:00.000Z`,
        sourcePins: PINS,
      }),
    ).toThrowError(/already exists/);
  });

  it("writes a zero-count checkpoint for an empty corpus instead of failing", () => {
    const db = makeDb();
    const stored = writeCheckpoint(db, {
      checkpointDate: DAY_ONE,
      observedAt: `${DAY_ONE}T08:00:00.000Z`,
      sourcePins: PINS,
    });
    expect(stored.cohortCount).toBe(0);
    expect(stored.views.defaultPriority).toEqual([]);
  });
});

describe("radar change detector (todo 12)", () => {
  function twoCheckpoints(
    mutate: (db: CveDatabase) => void,
    secondPins = PINS,
  ): { db: CveDatabase; before: string; after: string } {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedRecord(db, "CVE-2099-0002");
    seedEpss(db, "CVE-2099-0001", PINS.epssScoreDate, "0.80");
    seedEpss(db, "CVE-2099-0002", PINS.epssScoreDate, "0.20");
    writeCheckpoint(db, {
      checkpointDate: DAY_ONE,
      observedAt: `${DAY_ONE}T08:00:00.000Z`,
      sourcePins: PINS,
    });
    mutate(db);
    writeCheckpoint(db, {
      checkpointDate: DAY_TWO,
      observedAt: `${DAY_TWO}T08:00:00.000Z`,
      sourcePins: secondPins,
    });
    return { db, before: DAY_ONE, after: DAY_TWO };
  }

  it("labels a KEV addition as a source change, not a rank move", () => {
    const { db, before, after } = twoCheckpoints((inner) =>
      seedKev(inner, "CVE-2099-0002", "2026-10-24"),
    );
    const diff = diffCheckpoints(
      readCheckpoint(db, before) ?? expect.fail("missing before"),
      readCheckpoint(db, after) ?? expect.fail("missing after"),
    );
    const kevChange = diff.itemChanges.find((row) => row.cveId === "CVE-2099-0002");
    expect(kevChange?.kinds).toContain("kev-added");
    expect(kevChange?.kinds).not.toContain("rank-only-move");
    expect(diff.summary.sourceChanges).toBeGreaterThan(0);
  });

  it("labels a pure reorder as rank-only and never as a source change", () => {
    const { db, before, after } = twoCheckpoints((inner) => {
      seedRecord(inner, "CVE-2099-0003");
      seedEpss(inner, "CVE-2099-0003", PINS.epssScoreDate, "0.95");
    });
    const diff = diffCheckpoints(
      readCheckpoint(db, before) ?? expect.fail("missing before"),
      readCheckpoint(db, after) ?? expect.fail("missing after"),
    );
    const added = diff.itemChanges.find((row) => row.cveId === "CVE-2099-0003");
    expect(added?.kinds).toContain("added");
    const shifted = diff.itemChanges.find((row) => row.cveId === "CVE-2099-0001");
    expect(shifted?.kinds).toEqual(["rank-only-move"]);
    for (const row of diff.itemChanges.filter((entry) => entry.cveId !== "CVE-2099-0003")) {
      expect(row.kinds).toEqual(["rank-only-move"]);
    }
    expect(diff.summary.rankOnlyMoves).toBeGreaterThan(0);
  });

  it("labels CNA metric, forecast, correction, and rejection changes distinctly", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedRecord(db, "CVE-2099-0002");
    seedRecord(db, "CVE-2099-0003");
    seedRecord(db, "CVE-2099-0004");
    seedEpss(db, "CVE-2099-0001", PINS.epssScoreDate, "0.10");
    seedCvss(db, "CVE-2099-0002", { baseScore: "9.1" });
    writeCheckpoint(db, {
      checkpointDate: DAY_ONE,
      observedAt: `${DAY_ONE}T08:00:00.000Z`,
      sourcePins: PINS,
    });
    db.runBoundedWrite(() => {
      db.handle
        .prepare("UPDATE cvss_metrics SET base_score = ? WHERE cve_id = ?")
        .run("9.8", "CVE-2099-0002");
    });
    db.runBoundedWrite(() => {
      db.handle
        .prepare("UPDATE epss_daily SET epss = ? WHERE cve_id = ? AND score_date = ?")
        .run("0.40", "CVE-2099-0001", PINS.epssScoreDate);
    });
    updateDescription(db, "CVE-2099-0003", "Corrected description for CVE-2099-0003");
    rejectRecord(db, "CVE-2099-0004");
    writeCheckpoint(db, {
      checkpointDate: DAY_TWO,
      observedAt: `${DAY_TWO}T08:00:00.000Z`,
      sourcePins: PINS,
    });
    const diff = diffCheckpoints(
      readCheckpoint(db, DAY_ONE) ?? expect.fail("missing before"),
      readCheckpoint(db, DAY_TWO) ?? expect.fail("missing after"),
    );
    const kinds = new Map(diff.itemChanges.map((row) => [row.cveId, row.kinds]));
    expect(kinds.get("CVE-2099-0001")).toContain("forecast-changed");
    expect(kinds.get("CVE-2099-0002")).toContain("cna-changed");
    expect(kinds.get("CVE-2099-0003")).toContain("corrected");
    expect(kinds.get("CVE-2099-0004")).toContain("rejected");
  });

  it("flags model transitions as model-changed, never as forecast spikes", () => {
    const { db, before, after } = twoCheckpoints(
      (inner) => {
        seedEpss(inner, "CVE-2099-0001", PINS.epssScoreDate, "0.99", "v2099.01.01");
      },
      { ...PINS, epssModelVersion: "v2099.01.01" },
    );
    const diff = diffCheckpoints(
      readCheckpoint(db, before) ?? expect.fail("missing before"),
      readCheckpoint(db, after) ?? expect.fail("missing after"),
    );
    const changed = diff.itemChanges.find((row) => row.cveId === "CVE-2099-0001");
    expect(changed?.kinds).toContain("model-changed");
    expect(changed?.kinds).not.toContain("forecast-changed");
    for (const row of diff.itemChanges) {
      expect(row.detail).not.toMatch(/because|caused by|due to/i);
    }
  });

  it("flags policy, cohort, and window movement at the diff level", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    writeCheckpoint(db, {
      checkpointDate: DAY_ONE,
      observedAt: `${DAY_ONE}T08:00:00.000Z`,
      sourcePins: PINS,
    });
    seedRecord(db, "CVE-2099-0002");
    writeCheckpoint(db, {
      checkpointDate: DAY_TWO,
      observedAt: `${DAY_TWO}T08:00:00.000Z`,
      sourcePins: { ...PINS, epssScoreDate: "2026-10-24" },
      policyVersion: "v2",
    });
    const diff = diffCheckpoints(
      readCheckpoint(db, DAY_ONE) ?? expect.fail("missing before"),
      readCheckpoint(db, DAY_TWO) ?? expect.fail("missing after"),
    );
    expect(diff.policyChanged).toBe(true);
    expect(diff.cohortChanged).toBe(true);
    expect(diff.windowChanged).toBe(true);
  });

  it("returns an empty diff for identical checkpoints and empty corpora", () => {
    const db = makeDb();
    const stored = writeCheckpoint(db, {
      checkpointDate: DAY_ONE,
      observedAt: `${DAY_ONE}T08:00:00.000Z`,
      sourcePins: PINS,
    });
    const diff = diffCheckpoints(stored, stored);
    expect(diff.itemChanges).toEqual([]);
    expect(diff.policyChanged).toBe(false);
    expect(diff.cohortChanged).toBe(false);
    expect(diff.windowChanged).toBe(false);
  });
});

describe("radar snapshot replay (todo 12)", () => {
  it("reproduces retained results after current data changes (never current data)", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    seedRecord(db, "CVE-2099-0002");
    seedEpss(db, "CVE-2099-0001", PINS.epssScoreDate, "0.80");
    seedEpss(db, "CVE-2099-0002", PINS.epssScoreDate, "0.20");
    writeCheckpoint(db, {
      checkpointDate: DAY_ONE,
      observedAt: `${DAY_ONE}T08:00:00.000Z`,
      sourcePins: PINS,
    });

    db.runBoundedWrite(() => {
      db.handle
        .prepare("UPDATE epss_daily SET epss = ? WHERE cve_id = ? AND score_date = ?")
        .run("0.01", "CVE-2099-0001", PINS.epssScoreDate);
    });
    rejectRecord(db, "CVE-2099-0002");

    const replayed = replayCheckpoint(db, DAY_ONE, { asOfDate: DAY_ONE });
    expect(replayed.status).toBe("available");
    if (replayed.status !== "available") return;
    expect(replayed.results.defaultPriority).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
    expect(replayed.manifest.cohortCount).toBe(2);
  });

  it("returns explicit unavailable for expired, missing, and pre-launch dates", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    writeCheckpoint(db, {
      checkpointDate: DAY_ONE,
      observedAt: `${DAY_ONE}T08:00:00.000Z`,
      sourcePins: PINS,
    });

    const expired = replayCheckpoint(db, DAY_ONE, { asOfDate: "2026-12-01" });
    expect(expired.status).toBe("unavailable");
    if (expired.status === "unavailable") {
      expect(expired.reason).toMatch(/expired/);
      expect(expired.reason).not.toMatch(/substitut/);
    } else {
      expect.fail("expired checkpoint must be unavailable");
    }

    const missing = replayCheckpoint(db, DAY_TWO, { asOfDate: DAY_TWO });
    expect(missing.status).toBe("unavailable");
    if (missing.status === "unavailable") {
      expect(missing.reason).toMatch(/no checkpoint retained/);
    }

    const prelaunch = replayCheckpoint(db, "2026-10-01", { asOfDate: DAY_ONE });
    expect(prelaunch.status).toBe("unavailable");
    if (prelaunch.status === "unavailable") {
      expect(prelaunch.reason).toMatch(/pre-launch/);
    }
    expect(RADAR_RETENTION_DAYS).toBe(30);
    expect(isCheckpointExpired(DAY_ONE, "2026-11-23", RADAR_RETENTION_DAYS)).toBe(true);
    expect(isCheckpointExpired(DAY_ONE, "2026-11-22", RADAR_RETENTION_DAYS)).toBe(false);
  });

  it("refuses replay when the referenced baseline is released instead of substituting", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    writeCheckpoint(db, {
      checkpointDate: DAY_ONE,
      observedAt: `${DAY_ONE}T08:00:00.000Z`,
      sourcePins: PINS,
    });

    releaseBaseline(db, PINS.cveRevision, DAY_ONE);
    expect(isBaselineRetained(db, PINS.cveRevision)).toBe(false);

    const replayed = replayCheckpoint(db, DAY_ONE, { asOfDate: DAY_ONE });
    expect(replayed.status).toBe("unavailable");
    if (replayed.status === "unavailable") {
      expect(replayed.reason).toMatch(/baseline .* no longer retained/);
    }
  });

  it("refuses replay on model mismatch and on a tampered manifest", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    writeCheckpoint(db, {
      checkpointDate: DAY_ONE,
      observedAt: `${DAY_ONE}T08:00:00.000Z`,
      sourcePins: PINS,
    });

    const mismatched = replayCheckpoint(db, DAY_ONE, {
      asOfDate: DAY_ONE,
      expectedModelVersion: "v2099.01.01",
    });
    expect(mismatched.status).toBe("unavailable");
    if (mismatched.status === "unavailable") {
      expect(mismatched.reason).toMatch(/model-changed/);
    }

    db.runBoundedWrite(() => {
      db.handle
        .prepare("UPDATE checkpoints SET cohort_count = ? WHERE checkpoint_date = ?")
        .run(99, DAY_ONE);
    });
    const tampered = replayCheckpoint(db, DAY_ONE, { asOfDate: DAY_ONE });
    expect(tampered.status).toBe("unavailable");
    if (tampered.status === "unavailable") {
      expect(tampered.reason).toMatch(/validation/);
    }
  });

  it("prunes expired checkpoints and drops their baseline references", () => {
    const db = makeDb();
    seedRecord(db, "CVE-2099-0001");
    writeCheckpoint(db, {
      checkpointDate: DAY_ONE,
      observedAt: `${DAY_ONE}T08:00:00.000Z`,
      sourcePins: PINS,
    });
    writeCheckpoint(db, {
      checkpointDate: DAY_TWO,
      observedAt: `${DAY_TWO}T08:00:00.000Z`,
      sourcePins: { ...PINS, cveRevision: "rev-bbb222" },
    });

    const pruned = pruneExpiredCheckpoints(db, "2026-11-23");
    expect(pruned).toEqual([DAY_ONE]);
    expect(readCheckpoint(db, DAY_ONE)).toBeUndefined();
    expect(isBaselineRetained(db, PINS.cveRevision)).toBe(false);
    expect(isBaselineRetained(db, "rev-bbb222")).toBe(true);
  });

  it("replays an empty-corpus checkpoint as available with empty results", () => {
    const db = makeDb();
    writeCheckpoint(db, {
      checkpointDate: DAY_ONE,
      observedAt: `${DAY_ONE}T08:00:00.000Z`,
      sourcePins: PINS,
    });
    const replayed = replayCheckpoint(db, DAY_ONE, { asOfDate: DAY_ONE });
    expect(replayed.status).toBe("available");
    if (replayed.status !== "available") return;
    expect(replayed.results.defaultPriority).toEqual([]);
  });
});
