// Ingestion worker entrypoint (plan todo 32).
//
// This is the ONLY process that fetches upstream feeds. It opens the SQLite
// store (running migrations), builds real SourceJobs from the three importers
// in src/lib/cve-import.ts, kev-import.ts and epss-import.ts, runs ONE
// initial IngestionScheduler cycle immediately (so first boot populates data
// instead of serving an empty corpus forever), then keeps running on the
// scheduler's intervals while SCHEDULE_ENABLED=true.
//
// When SCHEDULE_ENABLED=false the worker still runs the single initial cycle
// (so `docker compose up` populates once) and then stays alive idle WITHOUT
// scheduling further cycles. Rationale: exiting cleanly here would make the
// supervisor (`restart: unless-stopped` / entrypoint reap rules) restart the
// container in a hot ingest loop; idling keeps the container up, the lease
// held, and the web UI serving the just-imported snapshot.
//
// INGEST_ON_START=false skips even that single initial cycle: the worker
// acquires the lease, logs worker-idle, and parks. A seeded deployment (named
// volume already populated) can therefore serve immediately with zero import
// contention against the web server. Default true preserves first-boot
// population for empty volumes.
//
// Must NOT do: no importer logic lives here (thin wrappers only), no partial
// snapshots (importers publish atomically), no secrets in logs. Exit non-zero
// only on fatal init failure (config / database).

import { setDefaultResultOrder } from "node:dns";
import { mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

// IPv6 egress is unavailable in this environment and Node prefers IPv6 by
// default, so outbound fetches (KEV/EPSS) die without this. Prefer IPv4 at
// startup, before any fetch. Optional override: NODE_OPTIONS=--dns-result-order=ipv4first.
setDefaultResultOrder("ipv4first");

import { loadConfig } from "./lib/config";
import {
  cloneAndImportCveRevision,
  getCveCloneDepth,
  getCveCloneTimeoutMs,
  type CveImportOutcome,
} from "./lib/cve-import";
import { openDatabase, type CveDatabase } from "./lib/db";
import {
  EPSS_CURRENT_CSV_URL,
  fetchEpssCsvText,
  importEpssCsv,
  type EpssImportResult,
} from "./lib/epss-import";
import { importKevFromUrl, type KevImportResult } from "./lib/kev-import";
import {
  IngestionScheduler,
  installShutdownHandlers,
  type SourceJob,
  type SourceJobs,
  type SourceRefreshOutcome,
} from "./lib/schedule";

export const CVE_REPO_URL_DEFAULT = "https://github.com/CVEProject/cvelistV5.git";
export const CVE_REVISION_DEFAULT = "main";

/**
 * Resolve whether the worker runs an import cycle immediately on boot.
 * Default true (first boot populates an empty volume). False skips the
 * initial cycle AND, combined with SCHEDULE_ENABLED=false, any further
 * cycles: the worker holds the lease and idles so a seeded volume serves
 * with zero import contention. Malformed values throw (fail closed).
 */
export function resolveIngestOnStart(
  env: Record<string, string | undefined> = process.env,
): boolean {
  const raw = env.INGEST_ON_START;
  if (raw === undefined || raw === "") return true;
  if (raw !== "true" && raw !== "false") {
    throw new Error(`Invalid INGEST_ON_START ${JSON.stringify(raw)}. Expected true or false.`);
  }
  return raw === "true";
}

/** Resolve the CVE upstream pin. Env overrides exist for pinning/tests; no secrets. */
export function resolveCvePin(env: Record<string, string | undefined> = process.env): {
  repoUrl: string;
  revision: string;
  cloneTimeoutMs: number;
  cloneDepth: number;
} {
  const repoUrl = env.CVE_REPO_URL?.trim() === "" ? undefined : env.CVE_REPO_URL;
  const revision = env.CVE_REVISION?.trim() === "" ? undefined : env.CVE_REVISION;
  return {
    repoUrl: repoUrl ?? CVE_REPO_URL_DEFAULT,
    revision: revision ?? CVE_REVISION_DEFAULT,
    cloneTimeoutMs: getCveCloneTimeoutMs(env),
    cloneDepth: getCveCloneDepth(env),
  };
}

/**
 * Injectable seams for the three source jobs. Defaults wire the real
 * importers; tests inject fakes so no network is touched.
 */
export interface SourceJobDeps {
  cveImport?: (db: CveDatabase) => CveImportOutcome | Promise<CveImportOutcome>;
  kevImport?: (db: CveDatabase) => Promise<KevImportResult>;
  epssImport?: (db: CveDatabase) => Promise<EpssImportResult>;
  repoUrl?: string;
  revision?: string;
  workDir?: string;
  kevFetcher?: typeof fetch;
  epssUrl?: string;
  epssFetcher?: typeof fetch;
}

function errorDetail(error: unknown): string {
  const detail = error instanceof Error ? error.message : String(error);
  return detail.slice(0, 2000);
}

function failure(source: string, error: unknown): SourceRefreshOutcome {
  return {
    ok: false,
    version: null,
    error: `${source} refresh failed: ${errorDetail(error)}`.slice(0, 2000),
  };
}

function lowerWorkerPriority(): void {
  try {
    const setPriority = (
      os as unknown as { setPriority?: (pid: number, priority: number) => void }
    ).setPriority;
    if (typeof setPriority === "function") {
      setPriority.call(os, 0, 10);
    }
  } catch {
    // Best effort only: keep serving even when niceness is unavailable.
  }
}

/**
 * Pure job factory: maps each importer's result onto SourceRefreshOutcome and
 * converts throws into failed outcomes (never rethrows), so one failing
 * source cannot prevent the other sources' jobs from running in the cycle.
 */
export function createSourceJobs(db: CveDatabase, deps: SourceJobDeps = {}): SourceJobs {
  const defaults = resolveCvePin();
  const pin = {
    repoUrl: deps.repoUrl ?? defaults.repoUrl,
    revision: deps.revision ?? defaults.revision,
    cloneTimeoutMs: defaults.cloneTimeoutMs,
    cloneDepth: defaults.cloneDepth,
  };
  const workDir = deps.workDir;
  const kevFetcher = deps.kevFetcher;
  const epssUrl = deps.epssUrl ?? EPSS_CURRENT_CSV_URL;
  const epssFetcher = deps.epssFetcher;

  const cve: SourceJob = async () => {
    try {
      const outcome: CveImportOutcome =
        deps.cveImport !== undefined
          ? await deps.cveImport(db)
          : (() => {
              const scratchParent = deps.workDir ?? path.join(dbDirOf(db), "tmp");
              mkdirSync(scratchParent, { recursive: true });
              return cloneAndImportCveRevision(db, pin.repoUrl, pin.revision, {
                parentTmpDir: scratchParent,
                cloneTimeoutMs: pin.cloneTimeoutMs,
                cloneDepth: pin.cloneDepth,
                onLog: (entry) => defaultLog({ source: "cve", ...entry }),
              });
            })();
      if (!outcome.ok) {
        const quarantined = outcome.quarantined
          .slice(0, 3)
          .map((entry) => `${entry.identifier}: ${entry.reason}`)
          .join("; ");
        const detail =
          quarantined === ""
            ? `cve import failed at revision ${outcome.revision}`
            : `cve import failed at revision ${outcome.revision}: quarantined ${outcome.quarantined.length} record(s): ${quarantined}`;
        return { ok: false, version: null, error: detail.slice(0, 2000) };
      }
      return { ok: true, version: outcome.revision };
    } catch (error) {
      return failure("cve", error);
    }
  };

  const kev: SourceJob = async () => {
    try {
      const result: KevImportResult =
        deps.kevImport !== undefined
          ? await deps.kevImport(db)
          : await importKevFromUrl(db, { fetcher: kevFetcher });
      return { ok: true, version: result.catalogVersion };
    } catch (error) {
      return failure("kev", error);
    }
  };

  const epss: SourceJob = async () => {
    try {
      const result: EpssImportResult =
        deps.epssImport !== undefined
          ? await deps.epssImport(db)
          : await (async () => {
              const csvText = await fetchEpssCsvText(epssUrl, epssFetcher);
              return importEpssCsv(db, csvText);
            })();
      return { ok: true, version: result.scoreDate };
    } catch (error) {
      return failure("epss", error);
    }
  };

  return { cve, kev, epss };
}

function dbDirOf(db: CveDatabase): string {
  return path.dirname(db.databaseFilePath);
}

export interface WorkerLog {
  event: string;
  [key: string]: unknown;
}

export type LogFn = (entry: WorkerLog) => void;

export function defaultLog(entry: WorkerLog): void {
  // Structured single-line JSON, no secrets: versions/dates/errors only.
  process.stdout.write(`${JSON.stringify(entry)}\n`);
}

export interface CreateSchedulerOptions {
  intervalsMs?: { cve: number; kev: number; epss: number };
  holderId?: string;
}

/**
 * Build the IngestionScheduler for the worker. `manual` mirrors the schedule
 * toggle: enabled workers run on timers, disabled workers run only the single
 * initial cycle driven explicitly by runInitialCycle().
 */
export function createWorkerScheduler(
  db: CveDatabase,
  jobs: SourceJobs,
  scheduleEnabled: boolean,
  options: CreateSchedulerOptions = {},
): IngestionScheduler {
  return new IngestionScheduler({
    db,
    jobs,
    manual: !scheduleEnabled,
    intervalsMs: options.intervalsMs,
    holderId: options.holderId,
  });
}

export interface RunWorkerOptions {
  dataDir?: string;
  scheduleEnabled?: boolean;
  ingestOnStart?: boolean;
  deps?: SourceJobDeps;
  schedulerOptions?: CreateSchedulerOptions;
  log?: LogFn;
  installHandlers?: boolean;
}

/**
 * Full worker flow minus process.exit: open DB + migrate, build jobs, start
 * the scheduler, run exactly one cycle immediately (unless INGEST_ON_START is
 * false, in which case the cycle is skipped and worker-idle is logged), log
 * per-source results. Returns the running scheduler; the caller keeps the
 * process alive (timers when enabled, idle park when disabled) until shutdown.
 */
export async function runWorker(options: RunWorkerOptions = {}): Promise<{
  db: CveDatabase;
  scheduler: IngestionScheduler;
  releaseHandlers: () => void;
  scheduleEnabled: boolean;
  ingestOnStart: boolean;
}> {
  const log = options.log ?? defaultLog;
  lowerWorkerPriority();
  const config = loadConfig();
  const dataDir = options.dataDir ?? config.dataDir;
  const scheduleEnabled = options.scheduleEnabled ?? config.scheduleEnabled;
  const ingestOnStart = options.ingestOnStart ?? resolveIngestOnStart();

  let db: CveDatabase;
  try {
    db = openDatabase({ dataDir });
  } catch (error) {
    log({ event: "worker-fatal", reason: "database-open-failed", error: errorDetail(error) });
    throw error;
  }
  log({ event: "worker-start", dataDir, scheduleEnabled });

  const jobs = createSourceJobs(db, {
    ...options.deps,
    workDir: options.deps?.workDir ?? path.join(dataDir, "tmp"),
  });
  const wrappedJobs: SourceJobs = {
    cve: async (ctx) => {
      log({ event: "source-start", source: "cve" });
      return jobs.cve(ctx);
    },
    kev: async (ctx) => {
      log({ event: "source-start", source: "kev" });
      return jobs.kev(ctx);
    },
    epss: async (ctx) => {
      log({ event: "source-start", source: "epss" });
      return jobs.epss(ctx);
    },
  };
  const scheduler = createWorkerScheduler(db, wrappedJobs, scheduleEnabled, options.schedulerOptions);
  const releaseHandlers =
    options.installHandlers === false ? () => {} : installShutdownHandlers(scheduler);

  if (!scheduler.start()) {
    const health = scheduler.getStatus();
    log({
      event: "worker-fatal",
      reason: "lease-not-acquired",
      holder: scheduler.holder,
      leaseHeld: health.leaseHeld,
    });
    releaseHandlers();
    db.close();
    throw new Error("worker could not acquire the scheduler lease; another worker holds it.");
  }

  if (ingestOnStart) {
    await scheduler.runCycle();
    const health = scheduler.getStatus();
    for (const source of ["cve", "kev", "epss"] as const) {
      const status = health.sources[source];
      log({
        event: "ingest-cycle",
        source,
        ok: status.lastError === null,
        acceptedVersion: status.acceptedVersion,
        error: status.lastError,
      });
    }
    log({
      event: scheduleEnabled ? "worker-scheduled" : "worker-idle",
      scheduleEnabled,
      ingestOnStart,
      manifest: health.manifest,
    });
  } else {
    const health = scheduler.getStatus();
    log({
      event: "worker-idle",
      scheduleEnabled,
      ingestOnStart,
      manifest: health.manifest,
    });
  }
  return { db, scheduler, releaseHandlers, scheduleEnabled, ingestOnStart };
}

async function main(): Promise<void> {
  let scheduler: IngestionScheduler;
  let releaseHandlers: () => void;
  try {
    // main() owns shutdown-then-exit itself, so runWorker must NOT install
    // the scheduler-only handlers (they would swallow the signal without
    // ever exiting the parked process).
    ({ scheduler, releaseHandlers } = await runWorker({ installHandlers: false }));
  } catch {
    // runWorker already logged the structured fatal; exit non-zero.
    process.exitCode = 1;
    return;
  }
  let exiting = false;
  const shutdownAndExit = (signal: string): void => {
    if (exiting) {
      return;
    }
    exiting = true;
    defaultLog({ event: "worker-shutdown", signal });
    void scheduler
      .shutdown()
      .catch((error: unknown) => {
        defaultLog({ event: "worker-shutdown-error", error: errorDetail(error) });
      })
      .finally(() => {
        releaseHandlers();
        process.exit(0);
      });
  };
  process.once("SIGTERM", () => shutdownAndExit("SIGTERM"));
  process.once("SIGINT", () => shutdownAndExit("SIGINT"));
  // Stay alive: a bare pending promise does NOT keep the node event loop
  // alive, so park on a ref'd timer. With scheduling timers keep the loop
  // busy; otherwise this park prevents a supervisor restart-loop while the
  // worker serves the just-imported snapshot idle.
  await new Promise<void>(() => {
    setInterval(() => {}, 60_000);
  });
}

function isMainModule(): boolean {
  const invoked = process.argv[1];
  if (invoked === undefined) {
    return false;
  }
  try {
    return pathToFileURL(path.resolve(invoked)).href === import.meta.url;
  } catch {
    return false;
  }
}

// Importing this module (tests, bundling) must NOT start ingestion; only run
// main() when executed directly as `node worker.mjs`.
if (isMainModule()) {
  void main();
}
