import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import {
  IngestionScheduler,
  type SourceJob,
  type SourceJobs,
  type SourceRefreshOutcome,
} from "../src/lib/schedule";

const tempDirs: string[] = [];
const openHandles: CveDatabase[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "sched-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openHandles.push(db);
  return db;
}

function makeSharedPair(): { first: CveDatabase; second: CveDatabase } {
  const dir = mkdtempSync(path.join(tmpdir(), "sched-shared-"));
  tempDirs.push(dir);
  const first = openDatabase({ dataDir: dir });
  const second = openDatabase({ dataDir: dir });
  openHandles.push(first, second);
  return { first, second };
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
    const dir = tempDirs.pop() as string;
    rmSync(dir, { recursive: true, force: true });
  }
});

function okOutcome(version: string): SourceRefreshOutcome {
  return { ok: true, version };
}

function okJob(version: string): SourceJob {
  return async () => okOutcome(version);
}

function failJob(error: string): SourceJob {
  return async () => ({ ok: false, version: null, error });
}

function goodJobs(): SourceJobs {
  return {
    cve: okJob("rev-a"),
    kev: okJob("2026.10.24"),
    epss: okJob("2026-10-24"),
  };
}

function makeClock(startIso: string): { now: () => Date; advance: (ms: number) => void } {
  let current = Date.parse(startIso);
  return {
    now: () => new Date(current),
    advance: (ms: number) => {
      current += ms;
    },
  };
}

describe("scheduler lease: single authoritative owner", () => {
  it("refuses a second concurrent scheduler on the same database", async () => {
    const clock = makeClock("2026-10-24T00:00:00.000Z");
    const shared = makeSharedPair();
    const first = new IngestionScheduler({
      db: shared.first,
      jobs: goodJobs(),
      manual: true,
      holderId: "scheduler-a",
      now: clock.now,
    });
    expect(first.start()).toBe(true);

    const second = new IngestionScheduler({
      db: shared.second,
      jobs: goodJobs(),
      manual: true,
      holderId: "scheduler-b",
      now: clock.now,
    });
    expect(second.start()).toBe(false);
    expect(second.hasLease).toBe(false);
    expect(second.getStatus().leaseHeld).toBe(false);

    await second.shutdown();
    await first.shutdown();
  });

  it("lets a second scheduler take over after the first releases the lease", async () => {
    const clock = makeClock("2026-10-24T00:00:00.000Z");
    const shared = makeDb();
    const first = new IngestionScheduler({
      db: shared,
      jobs: goodJobs(),
      manual: true,
      holderId: "scheduler-a",
      now: clock.now,
    });
    expect(first.start()).toBe(true);
    await first.runCycle();
    expect(first.getStatus().ready).toBe(true);
    await first.shutdown();

    const second = new IngestionScheduler({
      db: shared,
      jobs: goodJobs(),
      manual: true,
      holderId: "scheduler-b",
      now: clock.now,
    });
    expect(second.start()).toBe(true);
    await second.runCycle();
    expect(second.getStatus().ready).toBe(true);
    await second.shutdown();
  });

  it("recovers the lease after expiry when the previous holder never released it", () => {
    const clock = makeClock("2026-10-24T00:00:00.000Z");
    const shared = makeDb();
    const crashed = new IngestionScheduler({
      db: shared,
      jobs: goodJobs(),
      manual: true,
      holderId: "crashed-holder",
      leaseTtlMs: 60_000,
      now: clock.now,
    });
    expect(crashed.start()).toBe(true);

    clock.advance(61_000);
    const replacement = new IngestionScheduler({
      db: shared,
      jobs: goodJobs(),
      manual: true,
      holderId: "replacement-holder",
      leaseTtlMs: 60_000,
      now: clock.now,
    });
    expect(replacement.start()).toBe(true);
    expect(replacement.hasLease).toBe(true);
  });
});

describe("scheduler cycles: overlap and independence", () => {
  it("never runs two cycles concurrently (overlap protection)", async () => {
    const clock = makeClock("2026-10-24T00:00:00.000Z");
    let cveCalls = 0;
    let releaseCve: () => void = () => {
      throw new Error("test setup failed: release gate not installed");
    };
    const gate = new Promise<void>((resolve) => {
      releaseCve = resolve;
    });
    const jobs: SourceJobs = {
      cve: async () => {
        cveCalls += 1;
        await gate;
        return okOutcome("rev-a");
      },
      kev: okJob("2026.10.24"),
      epss: okJob("2026-10-24"),
    };
    const scheduler = new IngestionScheduler({
      db: makeDb(),
      jobs,
      manual: true,
      holderId: "overlap",
      now: clock.now,
    });
    expect(scheduler.start()).toBe(true);

    const first = scheduler.runCycle();
    const second = scheduler.runCycle();
    releaseCve();
    await Promise.all([first, second]);
    expect(cveCalls).toBe(1);
    expect(scheduler.getStatus().ready).toBe(true);
    await scheduler.shutdown();
  });

  it("a failed source keeps last-known-good while valid sources advance", async () => {
    const clock = makeClock("2026-10-24T12:00:00.000Z");
    let epssShouldFail = false;
    const jobs: SourceJobs = {
      cve: okJob("rev-b"),
      kev: okJob("2026.10.25"),
      epss: async () => {
        if (epssShouldFail) {
          return { ok: false, version: null, error: "truncated CSV: import aborted" };
        }
        return okOutcome("2026-10-24");
      },
    };
    const scheduler = new IngestionScheduler({
      db: makeDb(),
      jobs,
      manual: true,
      holderId: "independent",
      now: clock.now,
    });
    expect(scheduler.start()).toBe(true);
    await scheduler.runCycle();

    epssShouldFail = true;
    jobs.cve = okJob("rev-c");
    clock.advance(60_000);
    await scheduler.runCycle();

    const health = scheduler.getStatus();
    expect(health.ready).toBe(true);
    expect(health.manifest).toEqual({
      cveRevision: "rev-c",
      kevVersion: "2026.10.25",
      epssDate: "2026-10-24",
    });
    expect(health.sources.epss.lastError).toMatch(/truncated CSV/);
    expect(health.sources.epss.acceptedVersion).toBe("2026-10-24");
    expect(health.sources.cve.acceptedVersion).toBe("rev-c");
    await scheduler.shutdown();
  });

  it("requires every core source before reporting ready (liveness vs readiness)", async () => {
    const clock = makeClock("2026-10-24T00:00:00.000Z");
    const scheduler = new IngestionScheduler({
      db: makeDb(),
      jobs: goodJobs(),
      manual: true,
      holderId: "gates",
      now: clock.now,
    });
    expect(scheduler.start()).toBe(true);
    const before = scheduler.getStatus();
    expect(before.live).toBe(true);
    expect(before.ready).toBe(false);

    await scheduler.runCycle();
    const after = scheduler.getStatus();
    expect(after.live).toBe(true);
    expect(after.ready).toBe(true);
    await scheduler.shutdown();
  });
});

describe("scheduler lifecycle: interruption, staleness, fatal failure", () => {
  it("an interrupted import publishes nothing and recovery resumes from checkpoint", async () => {
    const clock = makeClock("2026-10-24T00:00:00.000Z");
    const shared = makeDb();
    let releaseImport: () => void = () => {
      throw new Error("test setup failed: release gate not installed");
    };
    const gate = new Promise<void>((resolve) => {
      releaseImport = resolve;
    });
    const interrupterJobs: SourceJobs = {
      cve: async ({ signal }) => {
        await gate;
        if (signal.aborted) {
          throw new Error("aborted before publish");
        }
        return okOutcome("rev-interrupted");
      },
      kev: okJob("2026.10.24"),
      epss: okJob("2026-10-24"),
    };
    const first = new IngestionScheduler({
      db: shared,
      jobs: interrupterJobs,
      manual: true,
      holderId: "interrupted",
      now: clock.now,
    });
    expect(first.start()).toBe(true);

    const cycle = first.runCycle();
    await new Promise((resolve) => setTimeout(resolve, 0));
    const stopping = first.shutdown();
    await new Promise((resolve) => setTimeout(resolve, 0));
    releaseImport();
    await cycle;
    await stopping;

    const afterInterrupt = first.getStatus();
    expect(afterInterrupt.manifest).toEqual({ cveRevision: null, kevVersion: null, epssDate: null });
    expect(afterInterrupt.ready).toBe(false);
    expect(afterInterrupt.sources.cve.acceptedVersion).toBe(null);

    const recovery = new IngestionScheduler({
      db: shared,
      jobs: goodJobs(),
      manual: true,
      holderId: "recovery",
      now: clock.now,
    });
    expect(recovery.start()).toBe(true);
    await recovery.runCycle();
    const health = recovery.getStatus();
    expect(health.ready).toBe(true);
    expect(health.manifest).toEqual({
      cveRevision: "rev-a",
      kevVersion: "2026.10.24",
      epssDate: "2026-10-24",
    });
    await recovery.shutdown();
  });

  it("flags per-source staleness without dropping last-known-good data", async () => {
    const clock = makeClock("2026-10-24T12:00:00.000Z");
    const scheduler = new IngestionScheduler({
      db: makeDb(),
      jobs: goodJobs(),
      manual: true,
      holderId: "staleness",
      now: clock.now,
    });
    expect(scheduler.start()).toBe(true);
    await scheduler.runCycle();

    clock.advance(4 * 60 * 60 * 1000);
    const health = scheduler.getStatus();
    expect(health.sources.cve.stale).toBe(true);
    expect(health.sources.kev.stale).toBe(true);
    expect(health.sources.cve.acceptedVersion).toBe("rev-a");
    expect(health.ready).toBe(true);

    clock.advance(3 * 24 * 60 * 60 * 1000);
    const later = scheduler.getStatus();
    expect(later.sources.epss.stale).toBe(true);
    expect(later.sources.epss.acceptedVersion).toBe("2026-10-24");
    await scheduler.shutdown();
  });

  it("a fatal worker failure never reports healthy and refuses new jobs", async () => {
    const clock = makeClock("2026-10-24T00:00:00.000Z");
    const jobs: SourceJobs = {
      cve: okJob("rev-a"),
      kev: async () => {
        throw new Error("worker segfault simulation");
      },
      epss: okJob("2026-10-24"),
    };
    const scheduler = new IngestionScheduler({
      db: makeDb(),
      jobs,
      manual: true,
      holderId: "fatal",
      now: clock.now,
    });
    expect(scheduler.start()).toBe(true);
    await scheduler.runCycle();

    const health = scheduler.getStatus();
    expect(health.live).toBe(false);
    expect(health.ready).toBe(false);
    expect(health.fatalError).toMatch(/kev worker crashed/);

    await scheduler.runCycle();
    expect(scheduler.getStatus().fatalError).toMatch(/kev worker crashed/);
    expect(await scheduler.triggerSource("cve")).toBe(null);
    await scheduler.shutdown();
  });

  it("shutdown stops new jobs and triggerSource is refused without a lease", async () => {
    const clock = makeClock("2026-10-24T00:00:00.000Z");
    const scheduler = new IngestionScheduler({
      db: makeDb(),
      jobs: goodJobs(),
      manual: true,
      holderId: "shutdown",
      now: clock.now,
    });
    expect(await scheduler.triggerSource("cve")).toBe(null);

    expect(scheduler.start()).toBe(true);
    const outcome = await scheduler.triggerSource("cve");
    expect(outcome).toEqual(okOutcome("rev-a"));
    expect(scheduler.getStatus().sources.cve.acceptedVersion).toBe("rev-a");

    await scheduler.shutdown();
    expect(scheduler.isShuttingDown).toBe(true);
    expect(scheduler.hasLease).toBe(false);
    expect(await scheduler.triggerSource("kev")).toBe(null);
    await scheduler.runCycle();
    expect(scheduler.getStatus().sources.kev.acceptedVersion).toBe(null);
  });

  it("uses failing job results, not throws, for ordinary refresh failures", async () => {
    const clock = makeClock("2026-10-24T00:00:00.000Z");
    const scheduler = new IngestionScheduler({
      db: makeDb(),
      jobs: { cve: failJob("network down"), kev: okJob("2026.10.24"), epss: okJob("2026-10-24") },
      manual: true,
      holderId: "ordinary-failure",
      now: clock.now,
    });
    expect(scheduler.start()).toBe(true);
    await scheduler.runCycle();
    const health = scheduler.getStatus();
    expect(health.live).toBe(true);
    expect(health.ready).toBe(false);
    expect(health.sources.cve.lastError).toMatch(/network down/);
    expect(health.sources.cve.consecutiveFailures).toBe(1);
    await scheduler.shutdown();
  });
});
