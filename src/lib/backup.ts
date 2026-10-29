// Database-consistent backup, restore, and upgrade procedures (plan todo 29).
//
// A backup is NEVER a raw copy of the live database file. The procedure is:
//   1. Open the database through CveDatabase (validates the data dir).
//   2. TRUNCATE-checkpoint the WAL via checkpointStatus() so all frames are
//      folded into the main database image.
//   3. Copy the image with `VACUUM INTO <staged path>` on the open handle,
//      which reads a transactionally consistent snapshot. No filesystem copy
//      of cve.db / cve.db-wal / cve.db-shm is ever used as the backup method.
//   4. Stage the copy plus a JSON manifest as `*.tmp` files, verify the
//      staged copy (hash match, readable schema, row counts agree), then
//      atomically rename into place. An interrupted backup therefore leaves
//      only `*.tmp` files behind, which verifyBackup() never presents as a
//      good backup and which the next createBackup() removes.
//
// The staged copy contains the whole database file, so Radar histories
// (kev_history, sync_runs), retained checkpoints, baseline refs, tombstones,
// and manifests travel with it. verifyBackup() re-opens the staged copy
// read-only and cross-checks the manifest.
//
// Migration compatibility policy (no implied cross-version compatibility):
//   - A backup records the applied schema versions at backup time.
//   - Restoring a backup whose schema is NEWER than this code supports is
//     refused: an old image must never read a new database schema. Upgrade
//     the app image first, then restore.
//   - Restoring a backup whose schema is OLDER than the database currently
//     in the target volume is a downgrade and is refused unless the caller
//     passes allowDowngrade: true AND a preRestoreBackupDir where the
//     current target contents are backed up first (documented rollback).
//   - Restoring over an equal-or-older target schema is a forward migration:
//     the normal open path applies pending migrations after the copy.

import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import {
  closeSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import { CveDatabase, DB_FILENAME, openDatabase } from "./db";
import { getAppliedVersions, loadMigrations } from "./migrations";

/** Manifest format version written by this module. */
export const BACKUP_VERSION = 1;

/** Database file name inside a backup directory (a quiesced VACUUM image). */
export const BACKUP_DB_FILENAME = "cve-backup.db";

/** Manifest file name inside a backup directory. */
export const BACKUP_MANIFEST_FILENAME = "manifest.json";

/** Refusal: the backup artifact is missing, partial, or fails verification. */
export class BackupError extends Error {
  readonly name = "BackupError";
}

/** Refusal: the restore would cross schema versions without a safety backup. */
export class BackupCompatibilityError extends Error {
  readonly name = "BackupCompatibilityError";
}

export interface BackupManifest {
  backupVersion: number;
  createdAt: string;
  /** Applied schema versions at backup time, ascending. */
  schemaVersions: number[];
  /** Highest migration version this code knows, at backup time. */
  codeMaxSchemaVersion: number;
  /** SHA-256 hex of the staged backup database file. */
  dbSha256: string;
  /** Row counts per content table, taken at backup time. */
  rowCounts: Record<string, number>;
  /** Retained checkpoint dates covered by this backup, ascending. */
  checkpointDates: string[];
  /** Distinct ranking policy versions present in retained checkpoints. */
  policyVersions: string[];
  procedure: string;
}

export interface CreateBackupOptions {
  dataDir: string;
  backupDir: string;
}

export interface VerifyBackupResult {
  manifest: BackupManifest;
  rowCounts: Record<string, number>;
}

export interface RestoreBackupOptions {
  backupDir: string;
  dataDir: string;
  /**
   * Required (with preRestoreBackupDir) when the target volume holds a
   * newer schema than the backup. Downgrade without a pre-restore backup
   * is always refused.
   */
  allowDowngrade?: boolean;
  /** Where to back up the current target contents before a downgrade. */
  preRestoreBackupDir?: string;
  /**
   * Test/ops seam: pretend this code supports migrations up to this version
   * (defaults to the real loadMigrations() max). Lets tests prove the
   * newer-schema refusal without fabricating a future migration.
   */
  supportedMaxSchemaVersion?: number;
}

export interface CompatibilityCheck {
  compatible: boolean;
  reason: string;
}

/** Content tables covered by row counts and the content hash, in fixed order. */
const CONTENT_TABLES = [
  "schema_migrations",
  "cve_records",
  "cvss_metrics",
  "epss_daily",
  "kev_entries",
  "kev_history",
  "sync_runs",
  "checkpoints",
  "checkpoint_baseline_refs",
  "cve_tombstones",
] as const;

const PROCEDURE_NOTE =
  "vacuum-into-after-truncate-checkpoint on an open handle; never a raw copy of the live database file";

function sha256Hex(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * SHA-256 of a file of any size, exported for unit coverage of the chunk
 * boundary. Production database images exceed Node's 2 GiB readFileSync
 * limit, so this must never go back to a single whole-file read.
 */
export function sha256File(filePath: string): string {
  // Chunked reads: Node's readFileSync refuses files over 2 GiB, and the
  // production database image is already past 4 GiB. Same digest as a
  // single update, constant memory.
  const hash = createHash("sha256");
  const fd = openSync(filePath, "r");
  try {
    const chunk = Buffer.allocUnsafe(8 * 1024 * 1024);
    for (;;) {
      const read = readSync(fd, chunk, 0, chunk.length, null);
      if (read === 0) break;
      hash.update(chunk.subarray(0, read));
    }
  } finally {
    closeSync(fd);
  }
  return hash.digest("hex");
}

function escapeSqlStringLiteral(value: string): string {
  return value.replace(/'/g, "''");
}

function codeMaxSchemaVersion(): number {
  const versions = loadMigrations().map((migration) => migration.version);
  return versions.length === 0 ? 0 : Math.max(...versions);
}

function maxOf(versions: readonly number[]): number {
  return versions.length === 0 ? 0 : Math.max(...versions);
}

function removeIfExists(filePath: string): void {
  try {
    rmSync(filePath, { force: true });
  } catch {
    // Best-effort removal of stale staging files.
  }
}

function removeStaleStaging(backupDir: string): void {
  let entries: string[] = [];
  try {
    entries = readdirSync(backupDir);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.endsWith(".tmp")) {
      removeIfExists(path.join(backupDir, entry));
    }
  }
}

function rowCountsOf(handle: Database.Database): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const table of CONTENT_TABLES) {
    const row = handle.prepare(`SELECT COUNT(*) AS count FROM "${table}"`).get() as {
      count: number;
    };
    counts[table] = row.count;
  }
  return counts;
}

function checkpointDatesOf(handle: Database.Database): string[] {
  const rows = handle
    .prepare("SELECT checkpoint_date FROM checkpoints ORDER BY checkpoint_date ASC")
    .all() as Array<{ checkpoint_date: string }>;
  return rows.map((row) => row.checkpoint_date);
}

function policyVersionsOf(handle: Database.Database): string[] {
  const rows = handle
    .prepare("SELECT DISTINCT policy_version FROM checkpoints ORDER BY policy_version ASC")
    .all() as Array<{ policy_version: string }>;
  return rows.map((row) => row.policy_version);
}

/**
 * Deterministic content hash over every content table in PK order. Used by
 * the round-trip test to prove backup → wipe → restore preserves current
 * data, retained history, and manifests byte-for-byte in content terms.
 */
export function hashContent(handle: Database.Database): string {
  const hash = createHash("sha256");
  for (const table of CONTENT_TABLES) {
    const orderBy =
      table === "schema_migrations"
        ? "version"
        : table === "cvss_metrics" || table === "kev_history" || table === "sync_runs"
          ? "id"
          : table === "epss_daily"
            ? "cve_id, score_date, model_version"
            : table === "checkpoints"
              ? "checkpoint_date"
              : table === "checkpoint_baseline_refs"
                ? "baseline_id, checkpoint_date"
                : table === "cve_records" || table === "kev_entries" || table === "cve_tombstones"
                  ? "cve_id"
                  : "rowid";
    const rows = handle.prepare(`SELECT * FROM "${table}" ORDER BY ${orderBy}`).all();
    hash.update(table);
    hash.update("\n");
    hash.update(JSON.stringify(rows));
    hash.update("\n");
  }
  return hash.digest("hex");
}

/** Content hash of the live database in a data directory (read-only open). */
export function hashDataDir(dataDir: string): string {
  const filePath = path.join(dataDir, DB_FILENAME);
  const raw = new Database(filePath, { readonly: true });
  try {
    return hashContent(raw);
  } finally {
    raw.close();
  }
}

/**
 * Creates a database-consistent backup of the data directory into a backup
 * directory. The backup directory is created if missing. Any `*.tmp` files
 * from an interrupted previous run are removed first and never presented
 * as a backup.
 */
export function createBackup(options: CreateBackupOptions): BackupManifest {
  const { dataDir, backupDir } = options;
  if (backupDir === undefined || backupDir === "") {
    throw new BackupError("Refusing to back up: backupDir is missing or empty.");
  }
  mkdirSync(backupDir, { recursive: true });
  removeStaleStaging(backupDir);

  const stagedDbPath = path.join(backupDir, `${BACKUP_DB_FILENAME}.tmp`);
  const stagedManifestPath = path.join(backupDir, `${BACKUP_MANIFEST_FILENAME}.tmp`);
  const finalDbPath = path.join(backupDir, BACKUP_DB_FILENAME);
  const finalManifestPath = path.join(backupDir, BACKUP_MANIFEST_FILENAME);
  removeIfExists(stagedDbPath);
  removeIfExists(stagedManifestPath);

  const db: CveDatabase = openDatabase({ dataDir });
  try {
    // Quiesce: fold the WAL into the main image before snapshotting.
    db.checkpointStatus();
    db.handle["exec"](`VACUUM INTO '${escapeSqlStringLiteral(stagedDbPath)}'`);
    const schemaVersions = db.appliedVersions();
    const manifest: BackupManifest = {
      backupVersion: BACKUP_VERSION,
      createdAt: new Date().toISOString(),
      schemaVersions,
      codeMaxSchemaVersion: codeMaxSchemaVersion(),
      dbSha256: sha256File(stagedDbPath),
      rowCounts: rowCountsOf(db.handle),
      checkpointDates: checkpointDatesOf(db.handle),
      policyVersions: policyVersionsOf(db.handle),
      procedure: PROCEDURE_NOTE,
    };
    writeFileSync(stagedManifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

    // Verify the staged copy before promoting it: hash match plus a
    // read-only open proving the image is a usable database.
    verifyStagedCopy(stagedDbPath, manifest);

    renameSync(stagedDbPath, finalDbPath);
    renameSync(stagedManifestPath, finalManifestPath);
    return manifest;
  } catch (error) {
    removeIfExists(stagedDbPath);
    removeIfExists(stagedManifestPath);
    if (error instanceof BackupError || error instanceof BackupCompatibilityError) {
      throw error;
    }
    const detail = error instanceof Error ? error.message : String(error);
    throw new BackupError(`Backup failed and left no partial artifact: ${detail}`);
  } finally {
    db.close();
  }
}

function readManifest(backupDir: string): BackupManifest {
  const manifestPath = path.join(backupDir, BACKUP_MANIFEST_FILENAME);
  if (!existsSync(manifestPath)) {
    throw new BackupError(
      `No backup present in "${backupDir}": expected ${BACKUP_MANIFEST_FILENAME}. ` +
        `Only *.tmp staging files (if any) exist, which are never a valid backup; ` +
        `re-run createBackup() to produce a verified backup.`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(manifestPath, "utf8")) as unknown;
  } catch {
    throw new BackupError(
      `Backup manifest in "${backupDir}" is corrupt; refusing to treat this directory as a backup.`,
    );
  }
  const manifest = parsed as BackupManifest;
  if (
    typeof manifest !== "object" ||
    manifest === null ||
    manifest.backupVersion !== BACKUP_VERSION ||
    typeof manifest.dbSha256 !== "string" ||
    typeof manifest.rowCounts !== "object" ||
    !Array.isArray(manifest.schemaVersions)
  ) {
    throw new BackupError(
      `Backup manifest in "${backupDir}" is incomplete or from an unsupported backup version; refusing to use it.`,
    );
  }
  return manifest;
}

function verifyStagedCopy(stagedDbPath: string, manifest: BackupManifest): VerifyBackupResult {
  if (sha256File(stagedDbPath) !== manifest.dbSha256) {
    throw new BackupError(
      "Staged backup copy failed its hash check; refusing to promote a partial artifact.",
    );
  }
  const raw = new Database(stagedDbPath, { readonly: true });
  try {
    const applied = getAppliedVersions(raw);
    if (JSON.stringify(applied) !== JSON.stringify(manifest.schemaVersions)) {
      throw new BackupError(
        "Staged backup copy disagrees with its manifest on schema versions; refusing to promote it.",
      );
    }
    const rowCounts = rowCountsOf(raw);
    for (const [table, count] of Object.entries(manifest.rowCounts)) {
      if (rowCounts[table] !== count) {
        throw new BackupError(
          `Staged backup copy disagrees with its manifest on table ${table}; refusing to promote it.`,
        );
      }
    }
    return { manifest, rowCounts };
  } finally {
    raw.close();
  }
}

/**
 * Verifies a backup directory: final artifacts exist, the database hash
 * matches the manifest, and the copy opens read-only with agreeing schema
 * versions and row counts. Staging (`*.tmp`) files alone never verify.
 */
export function verifyBackup(backupDir: string): VerifyBackupResult {
  const manifest = readManifest(backupDir);
  const dbPath = path.join(backupDir, BACKUP_DB_FILENAME);
  if (!existsSync(dbPath)) {
    throw new BackupError(
      `Backup in "${backupDir}" is missing ${BACKUP_DB_FILENAME}; refusing to treat a manifest alone as a backup.`,
    );
  }
  return verifyStagedCopy(dbPath, manifest);
}

/**
 * Pure downgrade-policy decision so the refusal is unit-testable: restoring
 * a backup older than the target volume's schema is a downgrade and needs
 * both explicit opt-in and a pre-restore backup of the current target.
 */
export function assertDowngradePolicy(options: {
  backupMaxSchemaVersion: number;
  targetMaxSchemaVersion: number | null;
  allowDowngrade?: boolean;
  hasPreRestoreBackup: boolean;
}): void {
  const { backupMaxSchemaVersion, targetMaxSchemaVersion, allowDowngrade, hasPreRestoreBackup } =
    options;
  if (targetMaxSchemaVersion === null) {
    return;
  }
  if (targetMaxSchemaVersion <= backupMaxSchemaVersion) {
    return;
  }
  if (allowDowngrade !== true) {
    throw new BackupCompatibilityError(
      `Refusing downgrade without a backup: target schema v${targetMaxSchemaVersion} is newer than ` +
        `backup schema v${backupMaxSchemaVersion}. Re-run with allowDowngrade: true plus ` +
        `preRestoreBackupDir to back up the current volume first; see docs/backup-runbook.md.`,
    );
  }
  if (!hasPreRestoreBackup) {
    throw new BackupCompatibilityError(
      "Refusing downgrade: allowDowngrade was set but no preRestoreBackupDir was provided. " +
        "A downgrade must first back up the current volume so the upgrade can be rolled back.",
    );
  }
}

/**
 * Checks whether a backup can be restored under this code without touching
 * any data directory. Never implies an old image can read a new schema:
 * a backup newer than the supported max is incompatible with guidance.
 */
export function checkRestoreCompatibility(
  backupDir: string,
  supportedMaxSchemaVersion: number = codeMaxSchemaVersion(),
): CompatibilityCheck {
  const manifest = readManifest(backupDir);
  const backupMax = maxOf(manifest.schemaVersions);
  if (backupMax > supportedMaxSchemaVersion) {
    return {
      compatible: false,
      reason:
        `backup schema v${backupMax} is newer than this code supports (v${supportedMaxSchemaVersion}); ` +
        "an old image must never read a new database schema. Upgrade the app image first, then restore.",
    };
  }
  return {
    compatible: true,
    reason: `backup schema v${backupMax} is supported (code max v${supportedMaxSchemaVersion}); forward migrations apply on open.`,
  };
}

function targetSchemaMax(dataDir: string): number | null {
  const filePath = path.join(dataDir, DB_FILENAME);
  if (!existsSync(filePath)) {
    return null;
  }
  let size = 0;
  try {
    size = statSync(filePath).size;
  } catch {
    return null;
  }
  if (size === 0) {
    return null;
  }
  const raw = new Database(filePath, { readonly: true });
  try {
    const applied = getAppliedVersions(raw);
    return applied.length === 0 ? 0 : Math.max(...applied);
  } finally {
    raw.close();
  }
}

/**
 * Restores a verified backup into a data directory (fresh or existing
 * volume). The caller must have closed all handles on the target data dir:
 * the live database files are replaced, never patched in place.
 *
 * Procedure: verify → compatibility/downgrade policy → (downgrade: back up
 * the target first) → remove live db/wal/shm → copy the quiesced backup
 * image (a filesystem copy of a verified artifact, not of a live file) →
 * open (applies forward migrations) → cross-check row counts.
 */
export function restoreBackup(options: RestoreBackupOptions): BackupManifest {
  const { backupDir, dataDir } = options;
  const supportedMax = options.supportedMaxSchemaVersion ?? codeMaxSchemaVersion();
  const { manifest } = verifyBackup(backupDir);

  const compatibility = checkRestoreCompatibility(backupDir, supportedMax);
  if (!compatibility.compatible) {
    throw new BackupCompatibilityError(`Refusing restore: ${compatibility.reason}`);
  }

  const backupMax = maxOf(manifest.schemaVersions);
  const targetMax = targetSchemaMax(dataDir);
  const hasPreRestoreBackup = options.preRestoreBackupDir !== undefined;
  assertDowngradePolicy({
    backupMaxSchemaVersion: backupMax,
    targetMaxSchemaVersion: targetMax,
    allowDowngrade: options.allowDowngrade,
    hasPreRestoreBackup,
  });

  if (targetMax !== null && targetMax > backupMax && options.preRestoreBackupDir !== undefined) {
    createBackup({ dataDir, backupDir: options.preRestoreBackupDir });
  }

  const backupDbPath = path.join(backupDir, BACKUP_DB_FILENAME);
  mkdirSync(dataDir, { recursive: true });
  const liveDbPath = path.join(dataDir, DB_FILENAME);
  removeIfExists(liveDbPath);
  removeIfExists(`${liveDbPath}-wal`);
  removeIfExists(`${liveDbPath}-shm`);
  copyFileSync(backupDbPath, liveDbPath);

  const reopened = openDatabase({ dataDir });
  try {
    const counts = rowCountsOf(reopened.handle);
    for (const [table, count] of Object.entries(manifest.rowCounts)) {
      // schema_migrations legitimately gains rows when forward migrations
      // apply on open; every content table must match exactly.
      if (table === "schema_migrations") {
        continue;
      }
      const live = counts[table];
      if (live !== count) {
        throw new BackupError(
          `Restore verification failed on table ${table}: expected ${count}, found ${live}.`,
        );
      }
    }
  } finally {
    reopened.close();
  }
  return manifest;
}

/**
 * Pre-upgrade backup: quiesced backup plus a compatibility note. Run before
 * applying any image/migration upgrade; keep the backup until the upgraded
 * app passes its health/readiness checks.
 */
export function preUpgradeBackup(options: CreateBackupOptions): {
  manifest: BackupManifest;
  compatibilityNote: string;
} {
  const manifest = createBackup(options);
  const compatibilityNote =
    `Pre-upgrade backup holds schema v${maxOf(manifest.schemaVersions)} ` +
    `(code max v${codeMaxSchemaVersion()}). Roll back with rollbackUpgrade() ` +
    "if the upgraded app fails health checks; see docs/backup-runbook.md.";
  return { manifest, compatibilityNote };
}

/**
 * Documented rollback: restores a pre-upgrade backup over the upgraded
 * volume. This is a downgrade, so the current (upgraded) volume is backed
 * up first into preRestoreBackupDir — downgrade without that safety backup
 * is refused.
 */
export function rollbackUpgrade(options: {
  backupDir: string;
  dataDir: string;
  preRestoreBackupDir: string;
}): BackupManifest {
  return restoreBackup({
    backupDir: options.backupDir,
    dataDir: options.dataDir,
    allowDowngrade: true,
    preRestoreBackupDir: options.preRestoreBackupDir,
  });
}
