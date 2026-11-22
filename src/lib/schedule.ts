// In-container ingestion scheduler with single-lease ownership, overlap
// protection, graceful shutdown, and liveness/readiness separation
// (plan todo 26).
//
// Single-container rule: no host cron, no second container, no second
// process fleet. One process owns timed ingestion through a
// database-backed scheduler lease; every other instance refuses to run
// jobs while the lease is held. Each source refresh is independent:
// a failed source keeps serving its last-known-good snapshot with an
// explicit stale/error flag while valid sources still advance.
//
// Each source is gated on its OWN interval, not on the cycle tick. The tick is
// the wake-up cadence (the shortest configured interval, 60 min in production);
// a cycle then runs only the sources whose own interval has elapsed. Without the
// gate one cycle ran all four every 60 min, so the 24 h EPSS/SSVC intervals in
// DEFAULT_INTERVALS_MS were decorative and EPSS was re-imported 24 times a day.
//
// The retry rule is what keeps the gate safe for "always latest": an attempt
// that accepted NO new version (a failure such as today's EPSS 403 before the
// file is published, or an unchanged feed) does not spend the source's whole
// interval — it becomes due again after SOURCE_RETRY_MS. Waiting a full 24 h
// after an early 403 would skip a publication by a day.
//
// Must NOT do: no importer logic lives here. Callers inject per-source
// jobs (thin wrappers around src/lib/cve-import.ts, kev-import.ts,
// epss-import.ts). This module only orders, guards, and reports them.
// Every database statement is parameterized; lease and status writes go
// through CveDatabase.runBoundedWrite so no transaction is unbounded.

import { randomUUID } from "node:crypto";

import type { CveDatabase } from "./db";

export type SourceName = "cve" | "kev" | "epss" | "ssvc";

export const CORE_SOURCES: readonly SourceName[] = ["cve", "kev", "epss", "ssvc"];

/** Staleness bounds from docs/DATA_WORKFLOW.md Freshness Proposal. */
export const CVE_KEV_STALE_AFTER_MS = 3 * 60 * 60 * 1000;
export const EPSS_STALE_AFTER_CALENDAR_DAYS = 2;
/** SSVC enrichment is daily; flag it stale after two days without a success. */
export const SSVC_STALE_AFTER_CALENDAR_DAYS = 2;

export interface SourceRefreshOutcome {
  ok: boolean;
  /** Accepted version pin on success: revision / catalog version / score date. */
  version: string | null;
  error?: string | null;
}

export interface SourceJobContext {
  signal: AbortSignal;
  now: Date;
}

export type SourceJob = (ctx: SourceJobContext) => Promise<SourceRefreshOutcome>;

export type SourceJobs = Record<SourceName, SourceJob>;

export interface SourceIntervalsMs {
  cve: number;
  kev: number;
  epss: number;
  ssvc: number;
}

/**
 * Retry delay after an attempt that accepted nothing new. It is one tick, not
 * the source's interval: a no-op attempt says nothing about when the next
 * publication lands, so it must never park the source for a whole day.
 */
export const SOURCE_RETRY_MS = 60 * 60 * 1000;

/** Why a source is due this cycle. */
export type GateDueReason = "first" | "interval-elapsed" | "retry-elapsed";
/** Why a source was skipped: still inside its own interval, or inside the retry window. */
export type GateSkipReason = "interval" | "retry";

/**
 * Per-cycle gate decision. Emitted once per cycle, before any job runs, so the
 * log answers "which sources did this cycle consider, and why was each one
 * skipped?" without inference from per-source start lines.
 */
export interface CycleGateReport {
  at: string;
  ran: SourceName[];
  due: Partial<Record<SourceName, GateDueReason>>;
  skipped: Partial<Record<SourceName, { reason: GateSkipReason; nextDueAt: string }>>;
}

export interface SchedulerOptions {
  db: CveDatabase;
  jobs: SourceJobs;
  /** Per-source cadence. Defaults follow the freshness targets. */
  intervalsMs?: Partial<SourceIntervalsMs>;
  /** Stable identity for this process; defaults to a random UUID. */
  holderId?: string;
  /** Lease time-to-live; heartbeat renews it. */
  leaseTtlMs?: number;
  heartbeatMs?: number;
  /** Clock injection for tests. */
  now?: () => Date;
  /** Skip real timers (tests drive runCycle manually). */
  manual?: boolean;
  /** Called once per cycle with the per-source due/skip decision. */
  onGate?: (report: CycleGateReport) => void;
  /**
   * Called after every cycle settles, with the per-source failures of that
   * cycle and the sources it actually attempted. The worker uses it to refresh
   * the derived aggregate cache: the boot cycle is not the only one that changes
   * data, and a cache that only follows boots makes every page fall back to live
   * full-corpus queries until the next restart.
   */
  onCycleComplete?: (outcome: {
    failed: Record<SourceName, string | null>;
    attempted: SourceName[];
  }) => void;
}

export interface SourceStatus {
  source: SourceName;
  acceptedVersion: string | null;
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  consecutiveFailures: number;
  stale: boolean;
}

export interface PublicationManifest {
  cveRevision: string | null;
  kevVersion: string | null;
  epssDate: string | null;
  ssvcRevision: string | null;
}

export interface SchedulerHealth {
  /** Process alive and worker not fatally failed. */
  live: boolean;
  /** Live AND every core source has an accepted snapshot. */
  ready: boolean;
  fatalError: string | null;
  shuttingDown: boolean;
  leaseHeld: boolean;
  sources: Record<SourceName, SourceStatus>;
  manifest: PublicationManifest;
}

const DEFAULT_INTERVALS_MS: SourceIntervalsMs = {
  cve: 60 * 60 * 1000,
  kev: 60 * 60 * 1000,
  // EPSS publishes once a day; the 24 h gate is what stops the hourly tick from
  // re-downloading and re-hashing the same CSV 24 times.
  epss: 24 * 60 * 60 * 1000,
  // Enrichment rides the KEV cohort and changes slowly; daily is honest and
  // keeps the 380 MB checkout fetch off the hourly path.
  ssvc: 24 * 60 * 60 * 1000,
};

function isoNow(now: () => Date): string {
  return now().toISOString();
}

function isEpssScoreDateStale(acceptedDate: string | null, now: Date): boolean {
  if (acceptedDate === null) {
    return true;
  }
  if (/^(\d{4})-(\d{2})-(\d{2})$/.exec(acceptedDate) === null) {
    return true;
  }
  const acceptedMs = Date.parse(`${acceptedDate}T00:00:00.000Z`);
  if (Number.isNaN(acceptedMs)) {
    return true;
  }
  const nowMidnightMs = Date.parse(`${now.toISOString().slice(0, 10)}T00:00:00.000Z`);
  const diffDays = Math.floor((nowMidnightMs - acceptedMs) / 86_400_000);
  return diffDays > EPSS_STALE_AFTER_CALENDAR_DAYS;
}

function isCheckStaleAfterDays(lastSuccessAt: string | null, now: Date, days: number): boolean {
  if (lastSuccessAt === null) return true;
  const successMs = Date.parse(lastSuccessAt);
  if (Number.isNaN(successMs)) return true;
  return now.getTime() - successMs > days * 86_400_000;
}

function isCheckStale(lastSuccessAt: string | null, now: Date): boolean {
  if (lastSuccessAt === null) {
    return true;
  }
  const successMs = Date.parse(lastSuccessAt);
  if (Number.isNaN(successMs)) {
    return true;
  }
  return now.getTime() - successMs > CVE_KEV_STALE_AFTER_MS;
}

/** Pure freshness predicate shared by status reporting and health gates. */
export function isSourceStale(
  source: SourceName,
  status: Pick<SourceStatus, "acceptedVersion" | "lastSuccessAt">,
  now: Date,
): boolean {
  if (source === "epss") {
    return isEpssScoreDateStale(status.acceptedVersion, now);
  }
  if (source === "ssvc") {
    // Daily enrichment: three hours would flag every night's run as stale.
    return isCheckStaleAfterDays(status.lastSuccessAt, now, SSVC_STALE_AFTER_CALENDAR_DAYS);
  }
  return isCheckStale(status.lastSuccessAt, now);
}

/**
 * Pure publication rule (mirrors tests/contracts/ingestion.test.ts):
 * failed sources retain the previous manifest pin, valid sources advance,
 * and initial publication requires every core source accepted.
 */
export function buildPublicationManifest(args: {
  updates: Partial<PublicationManifest>;
  previous: PublicationManifest;
  failed: Record<SourceName, string | null>;
}): {
  manifest: PublicationManifest;
  published: boolean;
  stale: Record<SourceName, string | null>;
} {
  const manifest: PublicationManifest = {
    cveRevision:
      args.failed.cve !== null
        ? args.previous.cveRevision
        : (args.updates.cveRevision ?? args.previous.cveRevision),
    kevVersion:
      args.failed.kev !== null
        ? args.previous.kevVersion
        : (args.updates.kevVersion ?? args.previous.kevVersion),
    epssDate:
      args.failed.epss !== null
        ? args.previous.epssDate
        : (args.updates.epssDate ?? args.previous.epssDate),
    ssvcRevision:
      args.failed.ssvc !== null
        ? args.previous.ssvcRevision
        : (args.updates.ssvcRevision ?? args.previous.ssvcRevision),
  };
  const published =
    manifest.cveRevision !== null && manifest.kevVersion !== null && manifest.epssDate !== null;
  return { manifest, published, stale: args.failed };
}

function emptyStatus(source: SourceName): SourceStatus {
  return {
    source,
    acceptedVersion: null,
    lastAttemptAt: null,
    lastSuccessAt: null,
    lastError: null,
    consecutiveFailures: 0,
    stale: true,
  };
}

function ensureLeaseTable(db: CveDatabase): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "CREATE TABLE IF NOT EXISTS scheduler_lease (" +
          "id INTEGER PRIMARY KEY CHECK (id = 1), " +
          "holder TEXT NOT NULL, " +
          "acquired_at TEXT NOT NULL, " +
          "expires_at TEXT NOT NULL" +
          ") STRICT",
      )
      .run();
  });
}

export class IngestionScheduler {
  private readonly db: CveDatabase;
  private readonly jobs: SourceJobs;
  private readonly intervalsMs: SourceIntervalsMs;
  private readonly holderId: string;
  private readonly leaseTtlMs: number;
  private readonly heartbeatMs: number;
  private readonly clock: () => Date;
  private readonly manual: boolean;

  private readonly statuses: Record<SourceName, SourceStatus> = {
    cve: emptyStatus("cve"),
    kev: emptyStatus("kev"),
    epss: emptyStatus("epss"),
    ssvc: emptyStatus("ssvc"),
  };
  private manifest: PublicationManifest = {
    cveRevision: null,
    kevVersion: null,
    epssDate: null,
    ssvcRevision: null,
  };

  /**
   * When each source is next due, and what that pending gate is waiting for.
   * In-memory on purpose: a restart re-reads the world from scratch, and the
   * first cycle after boot must not inherit a gate it cannot verify.
   */
  private readonly nextDueAtMs: Record<SourceName, number> = {
    cve: 0,
    kev: 0,
    epss: 0,
    ssvc: 0,
  };
  private readonly pendingGate: Record<SourceName, "first" | "interval" | "retry"> = {
    cve: "first",
    kev: "first",
    epss: "first",
    ssvc: "first",
  };

  private timer: ReturnType<typeof setInterval> | null = null;
  private heartbeat: ReturnType<typeof setInterval> | null = null;
  private started = false;
  private shuttingDown = false;
  private leaseHeld = false;
  private cycleInProgress = false;
  private inFlight: Promise<void> | null = null;
  private aborter: AbortController | null = null;
  private fatalError: string | null = null;

  constructor(options: SchedulerOptions) {
    this.db = options.db;
    this.jobs = options.jobs;
    this.intervalsMs = { ...DEFAULT_INTERVALS_MS, ...options.intervalsMs };
    for (const name of CORE_SOURCES) {
      const value = this.intervalsMs[name];
      if (!Number.isFinite(value) || value <= 0) {
        throw new Error(`IngestionScheduler requires a positive interval for "${name}".`);
      }
    }
    this.holderId = options.holderId ?? randomUUID();
    this.leaseTtlMs = options.leaseTtlMs ?? 60_000;
    this.heartbeatMs = options.heartbeatMs ?? 20_000;
    if (!Number.isFinite(this.leaseTtlMs) || this.leaseTtlMs <= 0) {
      throw new Error("IngestionScheduler requires a positive leaseTtlMs.");
    }
    this.clock = options.now ?? (() => new Date());
    this.manual = options.manual ?? false;
    this.onCycleComplete = options.onCycleComplete;
    this.onGate = options.onGate;
    ensureLeaseTable(this.db);
  }

  get holder(): string {
    return this.holderId;
  }

  get isStarted(): boolean {
    return this.started;
  }

  get isShuttingDown(): boolean {
    return this.shuttingDown;
  }

  get hasLease(): boolean {
    return this.leaseHeld;
  }

  acquireLease(): boolean {
    const now = this.clock();
    const nowIso = now.toISOString();
    const expiresIso = new Date(now.getTime() + this.leaseTtlMs).toISOString();
    let acquired = false;
    this.db.runBoundedWrite(() => {
      const row = this.db.handle
        .prepare("SELECT holder, expires_at FROM scheduler_lease WHERE id = ?")
        .get(1) as { holder: string; expires_at: string } | undefined;
      if (row !== undefined && row.holder !== this.holderId && row.expires_at > nowIso) {
        acquired = false;
        return;
      }
      this.db.handle
        .prepare(
          "INSERT INTO scheduler_lease (id, holder, acquired_at, expires_at) VALUES (1, ?, ?, ?) " +
            "ON CONFLICT(id) DO UPDATE SET holder = excluded.holder, " +
            "acquired_at = excluded.acquired_at, expires_at = excluded.expires_at",
        )
        .run(this.holderId, nowIso, expiresIso);
      acquired = true;
    });
    this.leaseHeld = acquired;
    return acquired;
  }

  releaseLease(): void {
    if (!this.leaseHeld) {
      return;
    }
    this.db.runBoundedWrite(() => {
      const row = this.db.handle
        .prepare("SELECT holder FROM scheduler_lease WHERE id = ?")
        .get(1) as { holder: string } | undefined;
      if (row !== undefined && row.holder === this.holderId) {
        this.db.handle.prepare("DELETE FROM scheduler_lease WHERE id = ?").run(1);
      }
    });
    this.leaseHeld = false;
  }

  private renewLease(): void {
    if (!this.leaseHeld || this.shuttingDown) {
      return;
    }
    const now = this.clock();
    const expiresIso = new Date(now.getTime() + this.leaseTtlMs).toISOString();
    this.db.runBoundedWrite(() => {
      const row = this.db.handle
        .prepare("SELECT holder FROM scheduler_lease WHERE id = ?")
        .get(1) as { holder: string } | undefined;
      if (row?.holder === this.holderId) {
        this.db.handle
          .prepare("UPDATE scheduler_lease SET expires_at = ? WHERE id = ?")
          .run(expiresIso, 1);
      } else {
        this.leaseHeld = false;
      }
    });
  }

  start(): boolean {
    if (this.started || this.shuttingDown || this.fatalError !== null) {
      return false;
    }
    if (!this.acquireLease()) {
      return false;
    }
    this.started = true;
    if (!this.manual) {
      // Wake-up cadence only: the shortest configured interval. What actually
      // runs is decided per source by the gate in runCycle.
      const tick = Math.min(
        this.intervalsMs.cve,
        this.intervalsMs.kev,
        this.intervalsMs.epss,
        this.intervalsMs.ssvc,
      );
      this.timer = setInterval(() => {
        void this.runCycle();
      }, tick);
      this.timer.unref?.();
      this.heartbeat = setInterval(() => {
        this.renewLease();
      }, this.heartbeatMs);
      this.heartbeat.unref?.();
    }
    return true;
  }

  private readonly onCycleComplete?: (outcome: {
    failed: Record<SourceName, string | null>;
    attempted: SourceName[];
  }) => void;
  private readonly onGate?: (report: CycleGateReport) => void;

  /**
   * Delay before a source is due again. `acceptedFresh` means the attempt pinned
   * a version that differs from the previous accepted one; only then does the
   * source spend its own interval. Anything else (failure, unchanged feed, no
   * version) retries on the next tick.
   */
  private nextDueDelayMs(source: SourceName, acceptedFresh: boolean): number {
    const interval = this.intervalsMs[source];
    if (acceptedFresh) return interval;
    // `interval` can be shorter than one tick under test configuration; the
    // retry must never be longer than the source's own cadence.
    return Math.min(SOURCE_RETRY_MS, interval);
  }

  /** Records what the next gate waits for, after an attempt settled. */
  private armGate(source: SourceName, acceptedFresh: boolean): void {
    this.pendingGate[source] = acceptedFresh ? "interval" : "retry";
    this.nextDueAtMs[source] = this.clock().getTime() + this.nextDueDelayMs(source, acceptedFresh);
  }

  /** Builds the cycle's per-source decision without touching any job. */
  private planCycle(nowMs: number): {
    report: CycleGateReport;
    due: Record<SourceName, boolean>;
  } {
    const report: CycleGateReport = {
      at: new Date(nowMs).toISOString(),
      ran: [],
      due: {},
      skipped: {},
    };
    const due: Record<SourceName, boolean> = { cve: false, kev: false, epss: false, ssvc: false };
    for (const source of CORE_SOURCES) {
      const dueAtMs = this.nextDueAtMs[source];
      const pending = this.pendingGate[source];
      if (nowMs >= dueAtMs) {
        due[source] = true;
        report.ran.push(source);
        report.due[source] =
          pending === "first"
            ? "first"
            : pending === "interval"
              ? "interval-elapsed"
              : "retry-elapsed";
        continue;
      }
      report.skipped[source] = {
        reason: pending === "interval" ? "interval" : "retry",
        nextDueAt: new Date(dueAtMs).toISOString(),
      };
    }
    return { report, due };
  }

  async runCycle(): Promise<void> {
    if (!this.leaseHeld || this.shuttingDown || this.fatalError !== null) {
      return;
    }
    if (this.cycleInProgress) {
      return;
    }
    this.cycleInProgress = true;
    this.aborter = new AbortController();
    const isShutdown = (): boolean => this.aborter?.signal.aborted ?? false;
    const run: Promise<void> = (async () => {
      const failed: Record<SourceName, string | null> = {
        cve: null,
        kev: null,
        epss: null,
        ssvc: null,
      };
      const updates: Partial<PublicationManifest> = {};
      const plan = this.planCycle(this.clock().getTime());
      this.onGate?.(plan.report);
      const attempted: SourceName[] = [];
      for (const source of CORE_SOURCES) {
        // Not due: the source keeps its accepted snapshot and is not attempted.
        // It is deliberately not reported as a failure, so the publication
        // manifest keeps its previous pin for it.
        if (!plan.due[source]) {
          continue;
        }
        if (isShutdown()) {
          failed[source] = "cancelled during shutdown: last-known-good preserved";
          continue;
        }
        attempted.push(source);
        const status = this.statuses[source];
        const previousVersion = status.acceptedVersion;
        const attemptAt = isoNow(this.clock);
        status.lastAttemptAt = attemptAt;
        let outcome: SourceRefreshOutcome;
        try {
          outcome = await this.jobs[source]({
            signal: this.aborter?.signal ?? new AbortController().signal,
            now: this.clock(),
          });
        } catch (error) {
          if (isShutdown()) {
            failed[source] = "cancelled during shutdown: last-known-good preserved";
            status.lastError = failed[source];
            status.consecutiveFailures += 1;
            status.stale = isSourceStale(source, status, this.clock());
            continue;
          }
          const detail = error instanceof Error ? error.message : String(error);
          this.fatalError = `${source} worker crashed: ${detail}`.slice(0, 2000);
          failed[source] = this.fatalError;
          status.lastError = this.fatalError;
          status.consecutiveFailures += 1;
          status.stale = isSourceStale(source, status, this.clock());
          // Nothing was accepted, so the next cycle may retry rather than park
          // the source for its full interval.
          this.armGate(source, false);
          break;
        }
        if (isShutdown()) {
          failed[source] = "cancelled during shutdown: last-known-good preserved";
          continue;
        }
        const acceptedFresh =
          outcome.ok && outcome.version !== null && outcome.version !== previousVersion;
        this.armGate(source, acceptedFresh);
        if (outcome.ok) {
          status.acceptedVersion = outcome.version ?? status.acceptedVersion;
          status.lastSuccessAt = attemptAt;
          status.lastError = null;
          status.consecutiveFailures = 0;
          if (source === "cve") {
            updates.cveRevision = status.acceptedVersion;
          } else if (source === "kev") {
            updates.kevVersion = status.acceptedVersion;
          } else if (source === "epss") {
            updates.epssDate = status.acceptedVersion;
          } else {
            updates.ssvcRevision = status.acceptedVersion;
          }
        } else {
          const message = (outcome.error ?? `${source} refresh failed`).slice(0, 2000);
          failed[source] = message;
          status.lastError = message;
          status.consecutiveFailures += 1;
        }
        status.stale = isSourceStale(source, status, this.clock());
      }
      const built = buildPublicationManifest({ updates, previous: this.manifest, failed });
      if (!isShutdown()) {
        this.manifest = built.manifest;
      }
      // Reported even when a source failed: the sources that did succeed moved
      // the data, and the derived cache must follow them. `attempted` excludes
      // gated sources so a skipped source is never mistaken for a success.
      this.onCycleComplete?.({ failed: { ...failed }, attempted: [...attempted] });
    })();
    this.inFlight = run;
    try {
      await run;
    } finally {
      this.cycleInProgress = false;
      this.inFlight = null;
    }
  }

  async triggerSource(source: SourceName): Promise<SourceRefreshOutcome | null> {
    if (!this.leaseHeld || this.shuttingDown || this.fatalError !== null || this.cycleInProgress) {
      return null;
    }
    const status = this.statuses[source];
    const previousVersion = status.acceptedVersion;
    const attemptAt = isoNow(this.clock);
    status.lastAttemptAt = attemptAt;
    try {
      const outcome = await this.jobs[source]({
        signal: this.aborter?.signal ?? new AbortController().signal,
        now: this.clock(),
      });
      // A manual trigger is an operator override of the gate, but it still
      // re-arms it: the interval only starts once something is accepted.
      this.armGate(
        source,
        outcome.ok && outcome.version !== null && outcome.version !== previousVersion,
      );
      if (outcome.ok) {
        status.acceptedVersion = outcome.version ?? status.acceptedVersion;
        status.lastSuccessAt = attemptAt;
        status.lastError = null;
        status.consecutiveFailures = 0;
        const failed: Record<SourceName, string | null> = {
          cve: null,
          kev: null,
          epss: null,
          ssvc: null,
        };
        const updates: Partial<PublicationManifest> =
          source === "cve"
            ? { cveRevision: status.acceptedVersion }
            : source === "kev"
              ? { kevVersion: status.acceptedVersion }
              : source === "epss"
                ? { epssDate: status.acceptedVersion }
                : { ssvcRevision: status.acceptedVersion };
        this.manifest = buildPublicationManifest({
          updates,
          previous: this.manifest,
          failed,
        }).manifest;
      } else {
        const message = (outcome.error ?? `${source} refresh failed`).slice(0, 2000);
        status.lastError = message;
        status.consecutiveFailures += 1;
      }
      status.stale = isSourceStale(source, status, this.clock());
      return outcome;
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      this.fatalError = `${source} worker crashed: ${detail}`.slice(0, 2000);
      status.lastError = this.fatalError;
      status.consecutiveFailures += 1;
      status.stale = isSourceStale(source, status, this.clock());
      this.armGate(source, false);
      return null;
    }
  }

  getStatus(): SchedulerHealth {
    const now = this.clock();
    for (const source of CORE_SOURCES) {
      this.statuses[source].stale = isSourceStale(source, this.statuses[source], now);
    }
    // Readiness keeps its original meaning: the three core feeds published.
    // SSVC is enrichment, so a missing enrichment cycle must not make the site
    // "not ready" — it reports its own status instead.
    const ready =
      this.fatalError === null &&
      this.statuses.cve.acceptedVersion !== null &&
      this.statuses.kev.acceptedVersion !== null &&
      this.statuses.epss.acceptedVersion !== null;
    return {
      live: this.fatalError === null,
      ready,
      fatalError: this.fatalError,
      shuttingDown: this.shuttingDown,
      leaseHeld: this.leaseHeld,
      sources: {
        cve: { ...this.statuses.cve },
        kev: { ...this.statuses.kev },
        epss: { ...this.statuses.epss },
        ssvc: { ...this.statuses.ssvc },
      },
      manifest: { ...this.manifest },
    };
  }

  async shutdown(): Promise<void> {
    if (this.shuttingDown) {
      await this.inFlight?.catch(() => undefined);
      return;
    }
    this.shuttingDown = true;
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.heartbeat !== null) {
      clearInterval(this.heartbeat);
      this.heartbeat = null;
    }
    this.aborter?.abort();
    try {
      await this.inFlight?.catch(() => undefined);
    } finally {
      this.releaseLease();
      this.started = false;
    }
  }
}

export function installShutdownHandlers(
  scheduler: IngestionScheduler,
  signals: readonly NodeJS.Signals[] = ["SIGTERM", "SIGINT"],
): () => void {
  const handlers = new Map<NodeJS.Signals, () => void>();
  for (const signal of signals) {
    const handler = (): void => {
      void scheduler.shutdown();
    };
    handlers.set(signal, handler);
    process.once(signal, handler);
  }
  return () => {
    for (const [signal, handler] of handlers) {
      process.removeListener(signal, handler);
    }
  };
}
