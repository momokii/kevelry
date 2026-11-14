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

import { createBackup, restoreBackup, verifyBackup } from "./lib/backup";
import { writeDailyCheckpoint } from "./lib/checkpoint-writer";
import { loadConfig } from "./lib/config";
import { aggregatesAreCurrent, getAggregates, refreshAggregates } from "./lib/aggregates";
import {
  cloneAndImportCveRevision,
  getCveCloneDepth,
  getCveCloneTimeoutMs,
  resolveCveCacheDir,
  type CveImportOutcome,
} from "./lib/cve-import";
import { openDatabase, type CveDatabase } from "./lib/db";
import { getCweCatalogMeta } from "./lib/cwe-catalog";
import {
  CWE_REFRESH_INTERVAL_MS,
  isCweRefreshDue,
  refreshCweCatalog,
  sanitizeCweReason,
  type CweRefreshResult,
} from "./lib/cwe-import";
import { importSsvcFromCheckout, resolveSsvcCacheDir, syncSsvcCache } from "./lib/ssvc-import";
import {
  EPSS_CURRENT_CSV_URL,
  fetchEpssCsvText,
  importEpssCsv,
  type EpssImportResult,
} from "./lib/epss-import";
import { resolveEpssRetentionDays } from "./lib/retention";
import { EXPLOIT_REF_BACKFILL, backfillExploitRefsOnce } from "./lib/exploit-ref";
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
  /** Stable CVE checkout path; defaults to `<DATA_DIR>/cve-repo` (persistent cache). */
  cacheDir?: string;
  kevFetcher?: typeof fetch;
  epssUrl?: string;
  epssFetcher?: typeof fetch;
  /** Override for the EPSS history window; defaults to `EPSS_RETENTION_DAYS`. */
  epssRetentionDays?: number;
  /** Called after an EPSS import pruned history, so the cycle can log it. */
  onEpssReport?: (report: {
    scoreDate: string;
    alreadyCurrent: boolean;
    prunedRows: number;
    oldestKept: string | null;
    keepDays: number;
  }) => void;
  /** SSVC enrichment: injectable for tests (avoids a 380 MB clone). */
  ssvcImport?: (db: CveDatabase) => Promise<{ revision: string | null; parsed: number }>;
  ssvcCacheDir?: string;
  /** CWE catalog refresh: injectable so tests never touch the network. */
  cweRefresh?: (db: CveDatabase) => Promise<CweRefreshResult>;
  /** Scheduled CWE refresh toggle; defaults to `CWE_REFRESH_ENABLED` (true). */
  cweRefreshEnabled?: boolean;
  cweFetcher?: typeof fetch;
  cweUrl?: string;
}

/**
 * Default SSVC job: sync the vulnrichment checkout, then read only the rows
 * for the KEV cohort we already hold. Daily cadence; failures keep the last
 * accepted enrichment (the scheduler handles that, not this job).
 */
async function defaultSsvcImport(
  db: CveDatabase,
  cacheDirOverride?: string,
): Promise<{ revision: string | null; parsed: number }> {
  const cacheDir = cacheDirOverride ?? resolveSsvcCacheDir(dbDirOf(db));
  const wanted = new Set(
    (db.handle.prepare("SELECT cve_id FROM kev_entries").all() as Array<{ cve_id: string }>).map(
      (row) => row.cve_id,
    ),
  );
  if (wanted.size === 0) {
    return { revision: null, parsed: 0 };
  }
  const sync = syncSsvcCache({ cacheDir });
  const result = importSsvcFromCheckout(db, {
    checkoutDir: cacheDir,
    wanted,
    revision: sync.revision,
  });
  return { revision: sync.revision, parsed: result.parsed };
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

/**
 * Refresh the precomputed aggregate cache (task 43). Called once after a
 * successful import cycle and on boot when the cache is empty, so a seeded
 * volume serves fast reads without waiting for an import. Never throws: a
 * refresh failure is logged and the next cycle retries.
 */
export function ensureAggregates(db: CveDatabase, log: LogFn = defaultLog): boolean {
  try {
    // "Is there a row?" is not the question: a stale row makes every page fall
    // back to live full-corpus queries. Refresh whenever the accepted inputs
    // moved, and skip the work when they did not.
    if (aggregatesAreCurrent(db)) return false;
    const snapshot = refreshAggregates(db);
    log({
      event: "aggregate-refresh",
      computedAt: snapshot.computedAt,
      published: snapshot.publishedTotal,
    });
    return true;
  } catch (error) {
    log({ event: "aggregate-refresh-failed", error: errorDetail(error) });
    return false;
  }
}

function refreshAggregatesForced(db: CveDatabase, log: LogFn = defaultLog): boolean {
  try {
    const snapshot = refreshAggregates(db);
    log({
      event: "aggregate-refresh",
      computedAt: snapshot.computedAt,
      published: snapshot.publishedTotal,
    });
    return true;
  } catch (error) {
    log({ event: "aggregate-refresh-failed", error: errorDetail(error) });
    return false;
  }
}

/**
 * Resolve whether the worker keeps the local CWE catalog fresh.
 *
 * Default true: the refresh is one conditional HTTP request per day at most.
 * Deliberately lenient like the other `*_ONCE` toggles — only the exact string
 * `false` disables it. A typo must not crash the worker over an optional
 * maintenance job, which would defeat the fail-soft contract it exists for.
 */
export function resolveCweRefreshEnabled(
  env: Record<string, string | undefined> = process.env,
): boolean {
  const raw = env.CWE_REFRESH_ENABLED?.trim();
  if (raw === undefined || raw === "") return true;
  return raw !== "false";
}

export interface CweRefreshRunOptions {
  db: CveDatabase;
  fetcher?: typeof fetch;
  url?: string;
  now?: () => Date;
  /** Fully injected refresh; overrides fetcher/url/now. */
  refresh?: (db: CveDatabase) => Promise<CweRefreshResult>;
  log?: LogFn;
}

/**
 * One CWE refresh attempt with structured logging. Never throws: a rejected
 * refresh is logged as `cwe-refresh-failed` and returned as a failed result, so
 * a taxonomy problem can never fail an ingest cycle or block an import.
 * Owns no scheduling; callers decide whether an attempt is due.
 */
export async function runCweRefreshOnce(options: CweRefreshRunOptions): Promise<CweRefreshResult> {
  const log = options.log ?? defaultLog;
  const refresh =
    options.refresh ??
    ((handle: CveDatabase) =>
      refreshCweCatalog(handle, {
        fetcher: options.fetcher,
        url: options.url,
        now: options.now,
      }));

  let result: CweRefreshResult;
  try {
    result = await refresh(options.db);
  } catch (error) {
    const reason = sanitizeCweReason(errorDetail(error));
    log({ event: "cwe-refresh-failed", reason });
    return { status: "failed", reason };
  }

  if (result.status === "refreshed") {
    log({
      event: "cwe-refresh",
      version: result.version,
      recordCount: result.recordCount,
      sourceHash: result.sourceHash,
      recovered: result.recovered,
    });
  } else if (result.status === "unchanged") {
    log({
      event: "cwe-refresh-unchanged",
      version: result.version,
      recordCount: result.recordCount,
      sourceHash: result.sourceHash,
    });
  } else {
    log({ event: "cwe-refresh-failed", reason: result.reason });
  }
  return result;
}

/**
 * Gate anchor for the in-process cadence check: the accepted catalog's
 * `retrieved_at` when it is `ready`, else null (always due). A failed or absent
 * catalog must never suppress the next attempt.
 */
function cweGateAnchor(db: CveDatabase): string | null {
  try {
    const meta = getCweCatalogMeta(db);
    return meta.status === "ready" ? meta.retrievedAt : null;
  } catch {
    return null;
  }
}

function lowerWorkerPriority(): void {
  try {
    const setPriority = (os as unknown as { setPriority?: (pid: number, priority: number) => void })
      .setPriority;
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
  const epssRetentionDays = deps.epssRetentionDays ?? resolveEpssRetentionDays(process.env);
  const onEpssReport = deps.onEpssReport;
  const epssFetcher = deps.epssFetcher;

  const cve: SourceJob = async () => {
    try {
      const outcome: CveImportOutcome =
        deps.cveImport !== undefined
          ? await deps.cveImport(db)
          : (() => {
              const dataDir = dbDirOf(db);
              const scratchParent = deps.workDir ?? path.join(dataDir, "tmp");
              mkdirSync(scratchParent, { recursive: true });
              // Persistent cache: first boot clones shallow into
              // `<DATA_DIR>/cve-repo`; later refreshes fetch incrementally in
              // that same tree instead of re-cloning gigabytes of scratch.
              const cacheDir = deps.cacheDir ?? resolveCveCacheDir(dataDir);
              return cloneAndImportCveRevision(db, pin.repoUrl, pin.revision, {
                parentTmpDir: scratchParent,
                cacheDir,
                dataDir,
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
              return importEpssCsv(db, csvText, { retentionDays: epssRetentionDays });
            })();
      // The cycle owns logging, so hand the report over instead of logging here.
      onEpssReport?.({
        scoreDate: result.scoreDate,
        alreadyCurrent: result.alreadyCurrent,
        prunedRows: result.prunedRows,
        oldestKept: result.oldestKept,
        keepDays: epssRetentionDays,
      });
      return { ok: true, version: result.scoreDate };
    } catch (error) {
      return failure("epss", error);
    }
  };

  const ssvc: SourceJob = async () => {
    try {
      if (deps.ssvcImport !== undefined) {
        const injected = await deps.ssvcImport(db);
        return { ok: true, version: injected.revision };
      }
      const result = await defaultSsvcImport(db, deps.ssvcCacheDir);
      return { ok: true, version: result.revision };
    } catch (error) {
      return failure("ssvc", error);
    }
  };

  return { cve, kev, epss, ssvc };
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
  /** Called after every settled cycle; the worker refreshes derived aggregates. */
  onCycleComplete?: (outcome: { failed: Record<string, string | null> }) => void;
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
    onCycleComplete: options.onCycleComplete,
  });
}

export interface LeaseRetryOptions {
  /** Additional acquire attempts after the first try. Default 10. */
  retries?: number;
  /** Wait between attempts. Default 15s (covers the 60s lease TTL). */
  delayMs?: number;
  /** Injectable clock for tests. */
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Lease-acquire with bounded waiting (TASK-012). A worker killed mid-import
 * (SIGKILL during a blocking git call skips shutdown handlers) leaves its
 * 60s lease behind; the replacement must out-wait the TTL instead of
 * exiting immediately — an immediate exit kills the web server too (the
 * entrypoint exits when any child dies), turning one restart into a crash
 * loop. A genuinely live second worker keeps renewing, so sustained failure
 * still fatals loudly instead of running two importers on one volume.
 */
export async function acquireLeaseWithRetry(
  scheduler: IngestionScheduler,
  options: LeaseRetryOptions & { log?: LogFn } = {},
): Promise<boolean> {
  const log = options.log ?? defaultLog;
  const retries = options.retries ?? 10;
  const delayMs = options.delayMs ?? 15_000;
  const sleep =
    options.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    if (scheduler.start()) return true;
    if (attempt === retries) break;
    log({ event: "worker-lease-wait", holder: scheduler.holder, attempt: attempt + 1, retries });
    await sleep(delayMs);
  }
  return false;
}

export interface RunWorkerOptions {
  dataDir?: string;
  scheduleEnabled?: boolean;
  ingestOnStart?: boolean;
  deps?: SourceJobDeps;
  schedulerOptions?: CreateSchedulerOptions;
  leaseRetry?: LeaseRetryOptions;
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
  /** Resolves once every background CWE refresh this worker started has settled. */
  cweSettled: () => Promise<void>;
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

  // One-off passes that must complete before the first cycle computes totals.
  try {
    const backfill = backfillExploitRefsOnce(db);
    if (backfill.ran) {
      log({
        event: "maintenance-backfill",
        name: EXPLOIT_REF_BACKFILL,
        scanned: backfill.scanned,
        updated: backfill.updated,
      });
    }
  } catch (error) {
    log({
      event: "maintenance-backfill-failed",
      name: EXPLOIT_REF_BACKFILL,
      error: errorDetail(error),
    });
  }

  const jobs = createSourceJobs(db, {
    ...options.deps,
    workDir: options.deps?.workDir ?? path.join(dataDir, "tmp"),
    onEpssReport: (report) => {
      if (report.alreadyCurrent) {
        // Same CSV as the accepted run: no rows rewritten this cycle.
        log({ event: "epss-unchanged", scoreDate: report.scoreDate });
      }
      if (report.prunedRows > 0) {
        log({ event: "epss-retention", ...report });
      }
    },
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
    ssvc: async (ctx) => {
      log({ event: "source-start", source: "ssvc" });
      return jobs.ssvc(ctx);
    },
  };
  // CWE catalog maintenance rides the ingest cycle instead of being a fifth
  // source: it is reference data with no fact-table impact, so it must never
  // contribute to `failed`/readiness or block an import. The gate keeps the
  // scheduled cost at one conditional HTTP request per 24h in this process; a
  // restart re-checks at most once. Failures are logged and swallowed.
  const cweRefreshEnabled = options.deps?.cweRefreshEnabled ?? resolveCweRefreshEnabled();
  let cweLastAttemptAt: string | null = cweRefreshEnabled ? cweGateAnchor(db) : null;
  let cweInFlight: Promise<void> | null = null;
  const kickCweRefresh = (): Promise<void> => {
    if (!cweRefreshEnabled) return Promise.resolve();
    if (cweInFlight !== null) return cweInFlight;
    const now = new Date();
    if (!isCweRefreshDue(cweLastAttemptAt, now, CWE_REFRESH_INTERVAL_MS)) {
      return Promise.resolve();
    }
    cweLastAttemptAt = now.toISOString();
    cweInFlight = runCweRefreshOnce({
      db,
      fetcher: options.deps?.cweFetcher,
      url: options.deps?.cweUrl,
      refresh: options.deps?.cweRefresh,
      log,
    })
      .then(() => undefined)
      .catch(() => undefined)
      .finally(() => {
        cweInFlight = null;
      });
    return cweInFlight;
  };
  const cweSettled = (): Promise<void> => cweInFlight ?? Promise.resolve();

  // Assigned right after construction so the cycle hook can tell a settling
  // cycle from a shutdown-interrupted one.
  let schedulerRef: IngestionScheduler | null = null;
  const scheduler = createWorkerScheduler(db, wrappedJobs, scheduleEnabled, {
    ...options.schedulerOptions,
    // Every cycle, not just the boot one, can change the accepted data.
    onCycleComplete: (outcome) => {
      ensureAggregates(db, log);
      // One retained checkpoint per UTC date, after a cycle in which at least
      // one source was accepted. Fail-soft: the writer logs
      // `checkpoint-write-failed` and returns, so a checkpoint problem can
      // never fail the cycle or block the next import.
      if (schedulerRef?.getStatus().shuttingDown === true) return;
      writeDailyCheckpoint(db, { failed: outcome.failed, log });
      // Taxonomy maintenance is independent of the fact sources: it runs after
      // the cycle settled, unawaited, and its result never reaches `failed`.
      void kickCweRefresh();
    },
  });
  schedulerRef = scheduler;
  const releaseHandlers =
    options.installHandlers === false ? () => {} : installShutdownHandlers(scheduler);

  if (!(await acquireLeaseWithRetry(scheduler, { ...options.leaseRetry, log }))) {
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
    // Let the boot cycle's taxonomy refresh land before the worker reports its
    // manifest, so a first boot logs `cwe-refresh` (or its failure) exactly
    // once and in order. Bounded by the fetch timeout, and fail-soft.
    await kickCweRefresh();
    const health = scheduler.getStatus();
    for (const source of ["cve", "kev", "epss", "ssvc"] as const) {
      const status = health.sources[source];
      log({
        event: "ingest-cycle",
        source,
        ok: status.lastError === null,
        acceptedVersion: status.acceptedVersion,
        error: status.lastError,
      });
    }
    // Fold the WAL after every cycle: a long import plus concurrent readers can
    // starve auto-checkpointing, and a multi-hundred-MB WAL makes reads crawl.
    try {
      const folded = db.checkpointStatus();
      log({
        event: "wal-checkpoint",
        busy: folded.busy,
        logFrames: folded.logFrames,
        checkpointedFrames: folded.checkpointedFrames,
      });
    } catch (error) {
      log({ event: "wal-checkpoint-failed", error: errorDetail(error) });
    }
    // The scheduler's `onCycleComplete` hook already refreshed the cache when
    // this cycle settled — including when a source failed — so the boot path
    // does not refresh again (that would pay the ~8 s recompute twice).
    log({
      event: scheduleEnabled ? "worker-scheduled" : "worker-idle",
      scheduleEnabled,
      ingestOnStart,
      manifest: health.manifest,
    });
  } else {
    ensureAggregates(db, log);
    // No cycle runs in this mode, so a seeded volume still gets its taxonomy
    // (one conditional request, gated by the accepted catalog's timestamp).
    await kickCweRefresh();
    const health = scheduler.getStatus();
    log({
      event: "worker-idle",
      scheduleEnabled,
      ingestOnStart,
      manifest: health.manifest,
    });
  }
  return { db, scheduler, releaseHandlers, scheduleEnabled, ingestOnStart, cweSettled };
}

/**
 * One-off CWE catalog refresh without running an import cycle:
 * `REFRESH_CWE_ONCE=true node dist/worker.mjs`. Opens the store, runs one
 * fetch/parse/publish attempt (no cadence gate), logs `cwe-refresh`,
 * `cwe-refresh-unchanged`, or `cwe-refresh-failed`, and exits 0 unless the
 * attempt failed. Used to seed a live volume without waiting for the daily
 * gate, or to retry a `stale` catalog on demand.
 */
export function resolveRefreshCweOnce(
  env: Record<string, string | undefined> = process.env,
): boolean {
  return env.REFRESH_CWE_ONCE === "true";
}

/**
 * One-off aggregate refresh without running an import cycle:
 * `REFRESH_AGGREGATES_ONCE=true node dist/worker.mjs`. Opens the store,
 * recomputes the cache, logs aggregate-refresh, exits 0. Used after stack
 * upgrades on a live volume instead of waiting for the next import.
 */
export function resolveRefreshAggregatesOnce(
  env: Record<string, string | undefined> = process.env,
): boolean {
  return env.REFRESH_AGGREGATES_ONCE === "true";
}

/**
 * One-off verified backup without running an import cycle:
 * `RUN_BACKUP_ONCE=true BACKUP_DIR=/backups/2026-10-29 node dist/worker.mjs`.
 * Opens the store, writes a hash-verified backup image plus manifest, then
 * re-verifies the promoted files and exits 0. Used by the nightly host cron
 * (scripts/nightly-backup.sh) through a one-off container on the same
 * volume, so the running worker is never disturbed. BACKUP_DIR is required.
 */
export function resolveRunBackupOnce(
  env: Record<string, string | undefined> = process.env,
): boolean {
  return env.RUN_BACKUP_ONCE === "true";
}

/**
 * One-off restore drill: `RUN_RESTORE_ONCE=true RESTORE_DIR=/backups/<date>`
 * restores a verified backup image into DATA_DIR, then reports the row counts.
 * Exists so the runbook's "restore into a fresh volume" is a documented command
 * instead of ad-hoc code, and so the drill can be rehearsed without touching the
 * production volume.
 */
export function resolveRunRestoreOnce(
  env: Record<string, string | undefined> = process.env,
): boolean {
  return env.RUN_RESTORE_ONCE === "true";
}

export function resolveRestoreDir(
  env: Record<string, string | undefined> = process.env,
): string | null {
  const raw = env.RESTORE_DIR;
  if (raw === undefined || raw.trim() === "") return null;
  return raw;
}

export function resolveBackupDir(
  env: Record<string, string | undefined> = process.env,
): string | null {
  const raw = env.BACKUP_DIR;
  if (raw === undefined || raw.trim() === "") return null;
  return raw;
}

async function main(): Promise<void> {
  if (resolveRunBackupOnce()) {
    const backupDir = resolveBackupDir();
    if (backupDir === null) {
      defaultLog({ event: "worker-fatal", reason: "backup-dir-missing" });
      process.exitCode = 1;
      return;
    }
    try {
      const config = loadConfig();
      const manifest = createBackup({ dataDir: config.dataDir, backupDir });
      const verification = verifyBackup(backupDir);
      defaultLog({
        event: "backup-done",
        backupDir,
        createdAt: manifest.createdAt,
        rowCounts: verification.rowCounts,
      });
      process.exitCode = 0;
    } catch (error) {
      defaultLog({
        event: "worker-fatal",
        reason: "backup-failed",
        error: errorDetail(error),
      });
      process.exitCode = 1;
    }
    return;
  }
  if (resolveRunRestoreOnce()) {
    const restoreDir = resolveRestoreDir();
    if (restoreDir === null) {
      defaultLog({ event: "worker-fatal", reason: "restore-dir-missing" });
      process.exitCode = 1;
      return;
    }
    try {
      const config = loadConfig();
      const manifest = restoreBackup({ backupDir: restoreDir, dataDir: config.dataDir });
      const verification = verifyBackup(restoreDir);
      defaultLog({
        event: "restore-done",
        dataDir: config.dataDir,
        sourceCreatedAt: manifest.createdAt,
        rowCounts: verification.rowCounts,
      });
      process.exitCode = 0;
    } catch (error) {
      defaultLog({
        event: "worker-fatal",
        reason: "restore-failed",
        error: errorDetail(error),
      });
      process.exitCode = 1;
    }
    return;
  }
  if (resolveRefreshAggregatesOnce()) {
    try {
      const config = loadConfig();
      const db = openDatabase({ dataDir: config.dataDir });
      try {
        refreshAggregatesForced(db, defaultLog);
      } finally {
        db.close();
      }
      process.exitCode = 0;
    } catch (error) {
      defaultLog({
        event: "worker-fatal",
        reason: "aggregate-refresh-failed",
        error: errorDetail(error),
      });
      process.exitCode = 1;
    }
    return;
  }
  if (resolveRefreshCweOnce()) {
    try {
      const config = loadConfig();
      const db = openDatabase({ dataDir: config.dataDir });
      try {
        const result = await runCweRefreshOnce({ db, log: defaultLog });
        // A taxonomy refresh that failed must be visible to a shell script, so
        // the one-off command reports it through the exit code. The scheduled
        // path stays fail-soft and never does this.
        process.exitCode = result.status === "failed" ? 1 : 0;
      } finally {
        db.close();
      }
    } catch (error) {
      defaultLog({
        event: "worker-fatal",
        reason: "cwe-refresh-failed",
        error: errorDetail(error),
      });
      process.exitCode = 1;
    }
    return;
  }
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
