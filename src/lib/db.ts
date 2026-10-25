// SQLite storage layer for the CVE radar: open, pragmas, migrations,
// guarded writes, and checkpoint monitoring.
//
// No importer logic lives here: no network, no upstream clones, no seed
// data. Every value-bearing statement is parameterized with `?`
// placeholders; the only multi-statement batches are the static migration
// scripts on disk. WAL gives concurrent readers alongside a single writer;
// the in-process writer queue plus busy mapping below keep the one-writer
// contract explicit instead of leaking raw lock errors.

import Database from "better-sqlite3";
import { accessSync, constants, mkdirSync, statSync } from "node:fs";
import path from "node:path";

import { getAppliedVersions, migrateDown, migrateUp } from "./migrations";

export const DB_FILENAME = "cve.db";
export const DEFAULT_BUSY_TIMEOUT_MS = 5000;
export const DEFAULT_WRITE_BATCH_SIZE = 500;

/** Startup/configuration failure: the data directory or database file is unusable. */
export class DbConfigError extends Error {
  readonly name = "DbConfigError";
}

/** A write lost a lock race after the busy timeout. Callers should retry or report busy. */
export class DbBusyError extends Error {
  readonly name = "DbBusyError";
}

export interface OpenDatabaseOptions {
  dataDir: string;
  filename?: string;
  busyTimeoutMs?: number;
  readOnly?: boolean;
}

export interface CheckpointStatus {
  busy: boolean;
  logFrames: number;
  checkpointedFrames: number;
  dbBytes: number;
  walBytes: number;
  shmBytes: number;
}

function isBusyFailure(error: unknown): boolean {
  const code =
    error instanceof Error
      ? (error as Error & { code?: unknown }).code
      : (error as { code?: unknown } | null)?.code;
  if (
    typeof code === "string" &&
    (code === "SQLITE_BUSY" || code.startsWith("SQLITE_BUSY_") || code === "SQLITE_LOCKED")
  ) {
    return true;
  }
  if (error instanceof Error) {
    return error.message.includes("SQLITE_BUSY") || error.message.includes("SQLITE_LOCKED");
  }
  return false;
}

function fileBytes(filePath: string): number {
  try {
    return statSync(filePath).size;
  } catch {
    return 0;
  }
}

export class CveDatabase {
  private readonly db: Database.Database;
  private readonly filePath: string;
  private writerQueue: Promise<void> = Promise.resolve();
  private closed = false;

  private constructor(db: Database.Database, filePath: string) {
    this.db = db;
    this.filePath = filePath;
  }

  static open(options: OpenDatabaseOptions): CveDatabase {
    const dataDir = options.dataDir;
    if (dataDir === undefined || dataDir === "") {
      throw new DbConfigError(
        "Refusing to open the CVE database: DATA_DIR is missing or empty. Set DATA_DIR to a writable local directory.",
      );
    }
    let dirStats;
    try {
      dirStats = statSync(dataDir);
    } catch {
      dirStats = undefined;
    }
    if (dirStats === undefined) {
      try {
        mkdirSync(dataDir, { recursive: true });
        dirStats = statSync(dataDir);
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        throw new DbConfigError(
          `Refusing to open the CVE database: data directory "${dataDir}" cannot be created: ${detail}`,
        );
      }
    }
    if (!dirStats.isDirectory()) {
      throw new DbConfigError(
        `Refusing to open the CVE database: "${dataDir}" is not a directory. Set DATA_DIR to a writable local directory.`,
      );
    }
    try {
      accessSync(dataDir, constants.W_OK);
    } catch {
      throw new DbConfigError(
        `Refusing to open the CVE database: data directory "${dataDir}" is not writable (read-only?). Check volume permissions; running without a writable data dir would silently lose every import checkpoint.`,
      );
    }

    const filename = options.filename ?? DB_FILENAME;
    const filePath = path.join(dataDir, filename);
    let db: Database.Database;
    try {
      db = new Database(filePath, { readonly: options.readOnly ?? false });
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new DbConfigError(
        `Refusing to open the CVE database: cannot open "${filePath}": ${detail}`,
      );
    }

    const busyTimeoutMs = options.busyTimeoutMs ?? DEFAULT_BUSY_TIMEOUT_MS;
    try {
      db.pragma(`busy_timeout = ${Math.trunc(busyTimeoutMs)}`);
      db.pragma("foreign_keys = ON");
      db.pragma("synchronous = NORMAL");
      if (!(options.readOnly ?? false)) {
        const mode = db.pragma("journal_mode = WAL", { simple: true });
        if (mode !== "wal") {
          throw new Error(`journal_mode request returned "${String(mode)}", not WAL.`);
        }
        migrateUp(db);
      }
    } catch (error) {
      try {
        db.close();
      } catch {
        // Best-effort close before reporting the startup failure.
      }
      if (error instanceof DbConfigError) {
        throw error;
      }
      const detail = error instanceof Error ? error.message : String(error);
      throw new DbConfigError(`Refusing to open the CVE database: startup failed: ${detail}`);
    }
    return new CveDatabase(db, filePath);
  }

  get databaseFilePath(): string {
    return this.filePath;
  }

  /** Raw handle for parameterized reads/writes owned by the caller. */
  get handle(): Database.Database {
    return this.db;
  }

  appliedVersions(): number[] {
    return getAppliedVersions(this.db);
  }

  revertTo(targetVersion: number): number[] {
    return migrateDown(this.db, targetVersion);
  }

  migrate(): number[] {
    return migrateUp(this.db);
  }

  /**
   * Runs `fn` inside a single BEGIN IMMEDIATE / COMMIT transaction. Lock
   * contention that survives the busy timeout surfaces as a typed
   * DbBusyError, never a raw driver throw. Rolls back on any failure.
   */
  runBoundedWrite<T>(fn: () => T): T {
    this.assertOpen();
    try {
      // BEGIN sits inside the guarded region so a lock race on acquiring
      // the RESERVED lock maps to DbBusyError like any other busy outcome.
      // ROLLBACK with no open transaction is a defined no-op, so the
      // catch path is safe even when BEGIN itself failed.
      this.db.prepare("BEGIN IMMEDIATE").run();
      const result = fn();
      this.db.prepare("COMMIT").run();
      return result;
    } catch (error) {
      try {
        this.db.prepare("ROLLBACK").run();
      } catch {
        // Best-effort; the original error carries the cause.
      }
      if (isBusyFailure(error)) {
        const detail = error instanceof Error ? error.message : String(error);
        throw new DbBusyError(
          `Writer lost a lock race and the busy timeout expired; retry the write. Detail: ${detail}`,
        );
      }
      throw error;
    }
  }

  /**
   * Single-writer guard for async callers: chains write transactions so at
   * most one logical writer holds the database at a time in this process.
   * Queued writers wait their turn; lock failures still surface as
   * DbBusyError for the caller to handle.
   */
  runWriteExclusive<T>(fn: () => T): Promise<T> {
    this.assertOpen();
    const turn = this.writerQueue.then(
      () =>
        new Promise<T>((resolve, reject) => {
          try {
            resolve(this.runBoundedWrite(fn));
          } catch (error) {
            reject(error);
          }
        }),
    );
    this.writerQueue = turn.then(
      () => undefined,
      () => undefined,
    );
    return turn;
  }

  /**
   * Bounded bulk writes: commits `items` in batches of at most `batchSize`
   * rows so no single transaction grows the WAL without limit. Importers
   * (plan todos 8-10) must use this instead of one giant transaction.
   */
  executeBatched<T>(items: readonly T[], apply: (batch: readonly T[]) => void): void;
  executeBatched<T>(
    items: readonly T[],
    batchSize: number,
    apply: (batch: readonly T[]) => void,
  ): void;
  executeBatched<T>(
    items: readonly T[],
    batchSizeOrApply: number | ((batch: readonly T[]) => void),
    maybeApply?: (batch: readonly T[]) => void,
  ): void {
    const batchSize =
      typeof batchSizeOrApply === "number" ? batchSizeOrApply : DEFAULT_WRITE_BATCH_SIZE;
    const apply = typeof batchSizeOrApply === "function" ? batchSizeOrApply : maybeApply;
    if (apply === undefined) {
      throw new Error("executeBatched requires an apply callback.");
    }
    if (!Number.isInteger(batchSize) || batchSize <= 0) {
      throw new Error(`executeBatched requires a positive batch size, got ${batchSize}.`);
    }
    for (let index = 0; index < items.length; index += batchSize) {
      const batch = items.slice(index, index + batchSize);
      this.runBoundedWrite(() => apply(batch));
    }
  }

  /**
   * TRUNCATE-checkpoints the WAL and reports frame/file growth so scheduled
   * jobs can watch for an unhealthy WAL. Never throws on a busy checkpoint:
   * a busy result is reported, not raised.
   */
  checkpointStatus(): CheckpointStatus {
    this.assertOpen();
    let busy = false;
    let logFrames = 0;
    let checkpointedFrames = 0;
    try {
      const row = this.db.pragma("wal_checkpoint(TRUNCATE)") as unknown as
        | { busy: number; log: number; checkpointed: number }
        | Array<{ busy: number; log: number; checkpointed: number }>;
      const status = Array.isArray(row) ? row[0] : row;
      busy = (status?.busy ?? 0) !== 0;
      logFrames = status?.log ?? 0;
      checkpointedFrames = status?.checkpointed ?? 0;
    } catch (error) {
      if (isBusyFailure(error)) {
        busy = true;
      } else {
        throw error;
      }
    }
    return {
      busy,
      logFrames,
      checkpointedFrames,
      dbBytes: fileBytes(this.filePath),
      walBytes: fileBytes(`${this.filePath}-wal`),
      shmBytes: fileBytes(`${this.filePath}-shm`),
    };
  }

  close(): void {
    if (!this.closed) {
      this.closed = true;
      this.db.close();
    }
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new Error("CveDatabase is closed; open a new handle before use.");
    }
  }
}

export function openDatabase(options: OpenDatabaseOptions): CveDatabase {
  return CveDatabase.open(options);
}

// ---------------------------------------------------------------------------
// Cached read-only handles for page renders (task 43).
//
// Pages used to openDatabase()+migrateUp()+close() per request. On a 4.3GB
// volume that open/migrate handshake dominates latency, so page renders
// share one read-only handle per data directory for the process lifetime.
// Read-only opens never run migrations and never take the writer lock.
// Tests stay isolated via resetReadDatabaseCache().
// ---------------------------------------------------------------------------

const readHandles = new Map<string, CveDatabase>();

function resolveReadKey(dataDir: string, filename: string): string {
  return `${dataDir}::${filename}`;
}

/** Reuse one read-only connection per data directory (never migrates, never writes). */
export function openReadDatabase(
  dataDir: string,
  filename: string = DB_FILENAME,
  busyTimeoutMs: number = DEFAULT_BUSY_TIMEOUT_MS,
): CveDatabase {
  if (dataDir === undefined || dataDir === "") {
    throw new DbConfigError(
      "Refusing to open the CVE database: DATA_DIR is missing or empty. Set DATA_DIR to a writable local directory.",
    );
  }
  const key = resolveReadKey(dataDir, filename);
  const cached = readHandles.get(key);
  if (cached !== undefined) return cached;
  const db = CveDatabase.open({ dataDir, filename, busyTimeoutMs, readOnly: true });
  // Read-path tuning for the 395k-row volume, applied once per process:
  // a roomy page cache plus mmap keeps the hot covering indexes and probe
  // pages resident so per-request renders never touch disk. Read-only only;
  // the writer keeps its defaults.
  try {
    db.handle.pragma("cache_size = -64000");
    db.handle.pragma("mmap_size = 268435456");
  } catch {
    // Tuning is best-effort; a platform that rejects a pragma still serves.
  }
  readHandles.set(key, db);
  return db;
}

/** Close and forget every cached read handle (test isolation; never call per request). */
export function resetReadDatabaseCache(): void {
  for (const db of readHandles.values()) {
    try {
      db.close();
    } catch {
      // Best-effort close during test teardown.
    }
  }
  readHandles.clear();
}
