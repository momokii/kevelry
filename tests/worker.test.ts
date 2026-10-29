import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import type { CveImportOutcome } from "../src/lib/cve-import";
import type { CveDatabase } from "../src/lib/db";
import { openDatabase } from "../src/lib/db";
import type { EpssImportResult } from "../src/lib/epss-import";
import type { KevImportResult } from "../src/lib/kev-import";
import { IngestionScheduler } from "../src/lib/schedule";
import {
  acquireLeaseWithRetry,
  createSourceJobs,
  resolveCvePin,
  resolveIngestOnStart,
  runWorker,
  type SourceJobDeps,
  type WorkerLog,
} from "../src/worker";

const tempDirs: string[] = [];
const openHandles: CveDatabase[] = [];
const schedulers: IngestionScheduler[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "worker-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openHandles.push(db);
  return db;
}

function track(scheduler: IngestionScheduler): IngestionScheduler {
  schedulers.push(scheduler);
  return scheduler;
}

afterEach(async () => {
  while (schedulers.length > 0) {
    const scheduler = schedulers.pop() as IngestionScheduler;
    try {
      await scheduler.shutdown();
    } catch {
      // Best-effort shutdown before directory removal.
    }
  }
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

const CVE_OUTCOME: CveImportOutcome = {
  ok: true,
  revision: "abc123def456",
  reconciledFull: true,
  alreadyCurrent: false,
  transitions: { added: [], changed: [], deleted: [], rejected: [] },
  quarantined: [],
  contentHash: "deadbeef",
};

const KEV_RESULT: KevImportResult = {
  ok: true,
  catalogVersion: "2026.10.25",
  catalogDate: "2026-10-25T00:00:00.000Z",
  total: 2,
  added: [],
  removed: [],
  unmatched: [],
};

const EPSS_RESULT: EpssImportResult = {
  scoreDate: "2026-10-24",
  modelVersion: "v2025.03.14",
  rowCount: 10,
  unmatched: [],
  contentHash: "cafef00d",
};

function okDeps(): SourceJobDeps & { calls: Record<"cve" | "kev" | "epss", number> } {
  const calls = { cve: 0, kev: 0, epss: 0 };
  return {
    calls,
    cveImport: () => {
      calls.cve += 1;
      return CVE_OUTCOME;
    },
    kevImport: async () => {
      calls.kev += 1;
      return KEV_RESULT;
    },
    epssImport: async () => {
      calls.epss += 1;
      return EPSS_RESULT;
    },
  };
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

describe("createSourceJobs", () => {
  it("resolves the CVE pin with configurable clone timeout and depth", () => {
    expect(resolveCvePin({})).toMatchObject({ cloneTimeoutMs: 3_600_000, cloneDepth: 1 });
    expect(resolveCvePin({ CVE_GIT_TIMEOUT_MS: "60000", CVE_CLONE_DEPTH: "0" })).toMatchObject({
      cloneTimeoutMs: 60_000,
      cloneDepth: 0,
    });
  });
  it("maps each importer result to its SourceRefreshOutcome version pin", async () => {
    const db = makeDb();
    const jobs = createSourceJobs(db, okDeps());
    const now = new Date();
    await expect(jobs.cve({ signal: new AbortController().signal, now })).resolves.toEqual({
      ok: true,
      version: CVE_OUTCOME.revision,
    });
    await expect(jobs.kev({ signal: new AbortController().signal, now })).resolves.toEqual({
      ok: true,
      version: KEV_RESULT.catalogVersion,
    });
    await expect(jobs.epss({ signal: new AbortController().signal, now })).resolves.toEqual({
      ok: true,
      version: EPSS_RESULT.scoreDate,
    });
  });

  it("maps a failed CVE import (ok:false) to a failed outcome, never a false success", async () => {
    const db = makeDb();
    const failedOutcome: CveImportOutcome = {
      ...CVE_OUTCOME,
      ok: false,
      quarantined: [{ source: "cve", reason: "boom", identifier: "cves/x.json" }],
    };
    const jobs = createSourceJobs(db, {
      cveImport: () => failedOutcome,
      kevImport: async () => KEV_RESULT,
      epssImport: async () => EPSS_RESULT,
    });
    const ctx = { signal: new AbortController().signal, now: new Date() };
    await expect(jobs.cve(ctx)).resolves.toMatchObject({ ok: false, version: null });
    const outcome = await jobs.cve(ctx);
    expect(outcome.error).toContain("quarantined 1 record(s)");
  });

  it("converts importer throws into failed outcomes instead of throwing", async () => {
    const db = makeDb();
    const jobs = createSourceJobs(db, {
      cveImport: () => {
        throw new Error("clone exploded");
      },
      kevImport: async () => {
        throw new Error("kev down");
      },
      epssImport: async () => {
        throw new Error("epss down");
      },
    });
    const now = new Date();
    const ctx = { signal: new AbortController().signal, now };
    await expect(jobs.cve(ctx)).resolves.toMatchObject({ ok: false, version: null });
    await expect(jobs.kev(ctx)).resolves.toMatchObject({ ok: false, version: null });
    await expect(jobs.epss(ctx)).resolves.toMatchObject({ ok: false, version: null });
    const cveOutcome = await jobs.cve(ctx);
    expect(cveOutcome.error).toContain("clone exploded");
  });

  it("a failing source does not prevent the other sources from advancing", async () => {
    const db = makeDb();
    const deps = okDeps();
    deps.cveImport = () => {
      deps.calls.cve += 1;
      throw new Error("cve clone failed");
    };
    const jobs = createSourceJobs(db, deps);
    const scheduler = track(
      new IngestionScheduler({ db, jobs, manual: true, holderId: "worker-test" }),
    );
    expect(scheduler.start()).toBe(true);
    await scheduler.runCycle();
    const health = scheduler.getStatus();
    expect(health.sources.cve.lastError).toContain("cve clone failed");
    expect(health.sources.cve.acceptedVersion).toBeNull();
    expect(health.sources.kev.acceptedVersion).toBe(KEV_RESULT.catalogVersion);
    expect(health.sources.epss.acceptedVersion).toBe(EPSS_RESULT.scoreDate);
  });
});

describe("runWorker", () => {
  it("runs exactly one initial cycle and logs per-source results", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "worker-init-"));
    tempDirs.push(dir);
    const deps = okDeps();
    const logs: WorkerLog[] = [];
    const { db, scheduler, scheduleEnabled } = await runWorker({
      dataDir: dir,
      scheduleEnabled: false,
      deps,
      installHandlers: false,
      log: (entry) => {
        logs.push(entry);
      },
    });
    openHandles.push(db);
    track(scheduler);
    expect(scheduleEnabled).toBe(false);
    expect(deps.calls).toEqual({ cve: 1, kev: 1, epss: 1 });

    const cycles = logs.filter((entry) => entry.event === "ingest-cycle");
    expect(cycles).toHaveLength(3);
    expect(new Set(cycles.map((entry) => entry.source))).toEqual(new Set(["cve", "kev", "epss"]));
    for (const entry of cycles) {
      expect(entry.ok).toBe(true);
    }
    expect(logs.some((entry) => entry.event === "worker-idle")).toBe(true);
  });

  it("emits source-start for each source before its job runs", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "worker-start-"));
    tempDirs.push(dir);
    const events: string[] = [];
    const logs: WorkerLog[] = [];
    const { db, scheduler } = await runWorker({
      dataDir: dir,
      scheduleEnabled: false,
      deps: {
        cveImport: () => {
          events.push("job:cve");
          return CVE_OUTCOME;
        },
        kevImport: async () => {
          events.push("job:kev");
          return KEV_RESULT;
        },
        epssImport: async () => {
          events.push("job:epss");
          return EPSS_RESULT;
        },
      },
      installHandlers: false,
      log: (entry) => {
        logs.push(entry);
        if (entry.event === "source-start") {
          events.push(`start:${String(entry.source)}`);
        }
      },
    });
    openHandles.push(db);
    track(scheduler);

    const starts = logs.filter((entry) => entry.event === "source-start");
    expect(starts).toHaveLength(3);
    expect(new Set(starts.map((entry) => entry.source))).toEqual(new Set(["cve", "kev", "epss"]));
    expect(events).toEqual([
      "start:cve",
      "job:cve",
      "start:kev",
      "job:kev",
      "start:epss",
      "job:epss",
    ]);
  });

  it("keeps cycling on intervals only when scheduling is enabled", async () => {
    const enabledDir = mkdtempSync(path.join(tmpdir(), "worker-on-"));
    const disabledDir = mkdtempSync(path.join(tmpdir(), "worker-off-"));
    tempDirs.push(enabledDir, disabledDir);
    const enabledDeps = okDeps();
    const disabledDeps = okDeps();
    const intervalsMs = { cve: 50, kev: 50, epss: 50 };

    const enabled = await runWorker({
      dataDir: enabledDir,
      scheduleEnabled: true,
      deps: enabledDeps,
      schedulerOptions: { intervalsMs, holderId: "worker-test-on" },
      installHandlers: false,
      log: () => {},
    });
    openHandles.push(enabled.db);
    track(enabled.scheduler);

    const disabled = await runWorker({
      dataDir: disabledDir,
      scheduleEnabled: false,
      deps: disabledDeps,
      schedulerOptions: { intervalsMs, holderId: "worker-test-off" },
      installHandlers: false,
      log: () => {},
    });
    openHandles.push(disabled.db);
    track(disabled.scheduler);

    expect(enabledDeps.calls).toEqual({ cve: 1, kev: 1, epss: 1 });
    expect(disabledDeps.calls).toEqual({ cve: 1, kev: 1, epss: 1 });

    await sleep(350);

    expect(enabledDeps.calls.cve).toBeGreaterThan(1);
    expect(enabledDeps.calls.kev).toBeGreaterThan(1);
    expect(enabledDeps.calls.epss).toBeGreaterThan(1);
    expect(disabledDeps.calls).toEqual({ cve: 1, kev: 1, epss: 1 });
  });
});

describe("lease-acquire retry (TASK-012)", () => {
  const idleJobs = {
    cve: () => Promise.resolve({ ok: true, version: null }),
    kev: () => Promise.resolve({ ok: true, version: null }),
    epss: () => Promise.resolve({ ok: true, version: null }),
  };

  it("starts immediately when the lease is free", async () => {
    const db = makeDb();
    const scheduler = track(new IngestionScheduler({ db, jobs: idleJobs, manual: true }));
    const logs: WorkerLog[] = [];
    const acquired = await acquireLeaseWithRetry(scheduler, {
      retries: 3,
      delayMs: 1,
      sleep: () => Promise.resolve(),
      log: (entry) => logs.push(entry),
    });
    expect(acquired).toBe(true);
    expect(logs.filter((entry) => entry.event === "worker-lease-wait")).toHaveLength(0);
  });

  it("out-waits a dead holder instead of failing at once", async () => {
    const db = makeDb();
    const dead = track(new IngestionScheduler({ db, jobs: idleJobs, manual: true }));
    expect(dead.start()).toBe(true);
    const replacement = track(new IngestionScheduler({ db, jobs: idleJobs, manual: true }));
    expect(replacement.start()).toBe(false);
    const logs: WorkerLog[] = [];
    let sleeps = 0;
    const acquired = await acquireLeaseWithRetry(replacement, {
      retries: 3,
      delayMs: 1,
      sleep: () => {
        sleeps += 1;
        // The dead holder's shutdown releases the lease mid-wait.
        if (sleeps === 1) dead.releaseLease();
        return Promise.resolve();
      },
      log: (entry) => logs.push(entry),
    });
    expect(acquired).toBe(true);
    expect(sleeps).toBe(1);
    expect(logs.filter((entry) => entry.event === "worker-lease-wait")).toHaveLength(1);
  });

  it("still fails loudly when a live holder keeps renewing", async () => {
    const db = makeDb();
    const live = track(new IngestionScheduler({ db, jobs: idleJobs, manual: true }));
    expect(live.start()).toBe(true);
    const replacement = track(new IngestionScheduler({ db, jobs: idleJobs, manual: true }));
    const logs: WorkerLog[] = [];
    let sleeps = 0;
    const acquired = await acquireLeaseWithRetry(replacement, {
      retries: 2,
      delayMs: 1,
      sleep: () => {
        sleeps += 1;
        return Promise.resolve();
      },
      log: (entry) => logs.push(entry),
    });
    expect(acquired).toBe(false);
    expect(sleeps).toBe(2);
    expect(logs.filter((entry) => entry.event === "worker-lease-wait")).toHaveLength(2);
  });
});

describe("INGEST_ON_START boot gate (task 37)", () => {
  it("resolves the gate from the environment with a true default", () => {
    expect(resolveIngestOnStart({})).toBe(true);
    expect(resolveIngestOnStart({ INGEST_ON_START: "" })).toBe(true);
    expect(resolveIngestOnStart({ INGEST_ON_START: "true" })).toBe(true);
    expect(resolveIngestOnStart({ INGEST_ON_START: "false" })).toBe(false);
    expect(() => resolveIngestOnStart({ INGEST_ON_START: "yes" })).toThrowError(/INGEST_ON_START/);
  });

  it("skips the initial cycle and logs worker-idle when disabled", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "worker-no-ingest-"));
    tempDirs.push(dir);
    const deps = okDeps();
    const logs: WorkerLog[] = [];
    const { db, scheduler, scheduleEnabled, ingestOnStart } = await runWorker({
      dataDir: dir,
      scheduleEnabled: false,
      ingestOnStart: false,
      deps,
      installHandlers: false,
      log: (entry) => {
        logs.push(entry);
      },
    });
    openHandles.push(db);
    track(scheduler);
    expect(scheduleEnabled).toBe(false);
    expect(ingestOnStart).toBe(false);
    expect(deps.calls).toEqual({ cve: 0, kev: 0, epss: 0 });
    expect(logs.some((entry) => entry.event === "ingest-cycle")).toBe(false);
    const idle = logs.find((entry) => entry.event === "worker-idle");
    expect(idle).toBeDefined();
    expect(idle).toMatchObject({ ingestOnStart: false });
  });

  it("still runs exactly one initial cycle when enabled", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "worker-ingest-"));
    tempDirs.push(dir);
    const deps = okDeps();
    const logs: WorkerLog[] = [];
    const { db, scheduler, ingestOnStart } = await runWorker({
      dataDir: dir,
      scheduleEnabled: false,
      ingestOnStart: true,
      deps,
      installHandlers: false,
      log: (entry) => {
        logs.push(entry);
      },
    });
    openHandles.push(db);
    track(scheduler);
    expect(ingestOnStart).toBe(true);
    expect(deps.calls).toEqual({ cve: 1, kev: 1, epss: 1 });
    expect(logs.filter((entry) => entry.event === "ingest-cycle")).toHaveLength(3);
  });
});
