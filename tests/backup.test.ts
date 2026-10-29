// New-test justification (plan todo 29): backup/restore/upgrade is the
// first destructive-path code in the repo, so tests must prove what unit
// checks cannot: a VACUUM-based backup round-trips current data, retained
// history, and checkpoint manifests byte-identical in content; an
// interrupted (staged *.tmp only) backup never verifies as good; a restore
// newer than the running code is refused with guidance; and a downgrade
// without a pre-restore backup is refused. Fixtures are synthetic CVE-2099
// IDs; nothing here touches the network.

import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  assertDowngradePolicy,
  BACKUP_DB_FILENAME,
  BACKUP_MANIFEST_FILENAME,
  BackupCompatibilityError,
  BackupError,
  checkRestoreCompatibility,
  createBackup,
  hashDataDir,
  preUpgradeBackup,
  restoreBackup,
  rollbackUpgrade,
  sha256File,
  verifyBackup,
} from "../src/lib/backup";
import { type CveDatabase, DB_FILENAME, openDatabase } from "../src/lib/db";
import { writeCheckpoint } from "../src/lib/radar";

const tempDirs: string[] = [];
const openHandles: CveDatabase[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function openTracked(dataDir: string): CveDatabase {
  const db = openDatabase({ dataDir });
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
    const dir = tempDirs.pop() as string;
    rmSync(dir, { recursive: true, force: true });
  }
});

function seedCorpus(db: CveDatabase): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, title, description, description_lang, source_revision, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        "CVE-2099-0001",
        "5.1",
        "PUBLISHED",
        "2026-10-20T00:00:00.000Z",
        "2026-10-21T00:00:00.000Z",
        "Synthetic fixture record",
        "Synthetic description for backup round-trip testing.",
        "en",
        "rev-backup-test",
        "2026-10-24T00:00:00.000Z",
        "2026-10-24T00:00:00.000Z",
      );
    db.handle
      .prepare(
        "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run("CVE-2099-0001", "CNA", "3.1", "9.8", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0);
    db.handle
      .prepare(
        "INSERT INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
      )
      .run("CVE-2099-0001", "2026-10-24", "2026.10.24", "0.12344", "0.95");
    db.handle
      .prepare(
        "INSERT INTO kev_entries (cve_id, date_added, catalog_date, vendor_project, product, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(
        "CVE-2099-0001",
        "2026-10-22",
        "2026-10-24",
        "Synthetic vendor",
        "Synthetic product",
        "2026-10-24T00:00:00.000Z",
      );
    db.handle
      .prepare(
        "INSERT INTO kev_history (cve_id, date_added, catalog_date, removed_in_catalog, recorded_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run("CVE-2099-0001", "2026-10-22", "2026-10-24", null, "2026-10-24T00:00:00.000Z");
    db.handle
      .prepare(
        "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        "cve",
        "2026-10-24T00:00:00.000Z",
        "2026-10-24T00:05:00.000Z",
        "succeeded",
        "rev-backup-test",
        "hash-fixture",
        null,
      );
  });
  writeCheckpoint(db, {
    checkpointDate: "2026-10-24",
    observedAt: "2026-10-24T12:00:00.000Z",
    sourcePins: {
      cveRevision: "rev-backup-test",
      kevCatalogDate: "2026-10-24",
      epssScoreDate: "2026-10-24",
      epssModelVersion: "2026.10.24",
    },
    cutoffT: "2026-10-24T00:00:00.000Z",
  });
}

describe("sha256File chunked hashing", () => {
  it("matches a single-update digest across chunk boundaries", async () => {
    const { createHash } = await import("node:crypto");
    const dir = makeTempDir("cve-backup-hash-");
    const file = path.join(dir, "nine.bin");
    // 9 MiB crosses the 8 MiB read chunk; deterministic fill keeps it fast.
    const bytes = Buffer.alloc(9 * 1024 * 1024, 0x5a);
    writeFileSync(file, bytes);
    expect(sha256File(file)).toBe(createHash("sha256").update(bytes).digest("hex"));
    const tiny = path.join(dir, "tiny.bin");
    writeFileSync(tiny, "abc");
    expect(sha256File(tiny)).toBe(createHash("sha256").update("abc").digest("hex"));
  });
});

describe("backup, restore, and upgrade procedures (todo 29)", () => {
  it("round-trips backup, wipe, and restore with identical data, history, and manifests", () => {
    const dataDir = makeTempDir("cve-backup-src-");
    const backupDir = makeTempDir("cve-backup-artifact-");
    const db = openTracked(dataDir);
    seedCorpus(db);
    const beforeHash = hashDataDir(dataDir);
    db.close();
    openHandles.pop();

    const manifest = createBackup({ dataDir, backupDir });
    expect(manifest.backupVersion).toBe(1);
    expect(manifest.checkpointDates).toEqual(["2026-10-24"]);
    expect(manifest.rowCounts["cve_records"]).toBe(1);
    expect(manifest.rowCounts["kev_history"]).toBe(1);
    expect(manifest.rowCounts["checkpoints"]).toBe(1);

    const verification = verifyBackup(backupDir);
    expect(verification.rowCounts).toEqual(manifest.rowCounts);

    rmSync(path.join(dataDir, DB_FILENAME), { force: true });
    rmSync(path.join(dataDir, `${DB_FILENAME}-wal`), { force: true });
    rmSync(path.join(dataDir, `${DB_FILENAME}-shm`), { force: true });

    restoreBackup({ backupDir, dataDir });
    expect(hashDataDir(dataDir)).toBe(beforeHash);

    const restored = openTracked(dataDir);
    const checkpoints = restored.handle
      .prepare("SELECT manifest_hash FROM checkpoints ORDER BY checkpoint_date ASC")
      .all() as Array<{ manifest_hash: string }>;
    expect(checkpoints).toHaveLength(1);
    expect(checkpoints[0]?.manifest_hash).toEqual(expect.any(String));
    const history = restored.handle.prepare("SELECT COUNT(*) AS count FROM kev_history").get() as {
      count: number;
    };
    expect(history.count).toBe(1);
  });

  it("never presents an interrupted (staged *.tmp only) backup as good", () => {
    const backupDir = makeTempDir("cve-backup-interrupted-");
    writeFileSync(path.join(backupDir, `${BACKUP_DB_FILENAME}.tmp`), "partial-bytes");
    writeFileSync(path.join(backupDir, `${BACKUP_MANIFEST_FILENAME}.tmp`), '{"backupVersion":1}');
    expect(() => verifyBackup(backupDir)).toThrow(BackupError);

    const dataDir = makeTempDir("cve-backup-recovery-");
    openTracked(dataDir).close();
    openHandles.pop();
    const manifest = createBackup({ dataDir, backupDir });
    expect(manifest.backupVersion).toBe(1);
    const entries = readdirSync(backupDir);
    expect(entries.filter((entry) => entry.endsWith(".tmp"))).toEqual([]);
    verifyBackup(backupDir);
  });

  it("refuses to restore a backup newer than the running code, with guidance", () => {
    const dataDir = makeTempDir("cve-backup-newer-src-");
    const backupDir = makeTempDir("cve-backup-newer-artifact-");
    const db = openTracked(dataDir);
    seedCorpus(db);
    db.close();
    openHandles.pop();
    const manifest = createBackup({ dataDir, backupDir });
    const backupMax = Math.max(...manifest.schemaVersions);

    const check = checkRestoreCompatibility(backupDir, backupMax - 1);
    expect(check.compatible).toBe(false);
    expect(check.reason).toMatch(/Upgrade the app image first/);

    const freshDir = makeTempDir("cve-backup-newer-target-");
    expect(() =>
      restoreBackup({ backupDir, dataDir: freshDir, supportedMaxSchemaVersion: backupMax - 1 }),
    ).toThrow(BackupCompatibilityError);
  });

  it("refuses a downgrade without a pre-restore backup, and rolls back when one is given", () => {
    expect(() =>
      assertDowngradePolicy({
        backupMaxSchemaVersion: 1,
        targetMaxSchemaVersion: 2,
        allowDowngrade: undefined,
        hasPreRestoreBackup: false,
      }),
    ).toThrow(/Downgrade without a backup/i);
    expect(() =>
      assertDowngradePolicy({
        backupMaxSchemaVersion: 1,
        targetMaxSchemaVersion: 2,
        allowDowngrade: true,
        hasPreRestoreBackup: false,
      }),
    ).toThrow(/preRestoreBackupDir/);
    expect(() =>
      assertDowngradePolicy({
        backupMaxSchemaVersion: 2,
        targetMaxSchemaVersion: 1,
        allowDowngrade: undefined,
        hasPreRestoreBackup: false,
      }),
    ).not.toThrow();

    const dataDir = makeTempDir("cve-backup-downgrade-src-");
    const backupDir = makeTempDir("cve-backup-downgrade-artifact-");
    const db = openTracked(dataDir);
    seedCorpus(db);
    const beforeHash = hashDataDir(dataDir);
    db.close();
    openHandles.pop();

    const { manifest, compatibilityNote } = preUpgradeBackup({ dataDir, backupDir });
    expect(manifest.backupVersion).toBe(1);
    expect(compatibilityNote).toMatch(/Roll back/);

    // Simulate an upgraded volume: a newer schema than the backup holds, as
    // a future migration row would leave it. The row is wiped by the restore
    // copy; it only drives the downgrade-policy decision.
    const upgraded = openTracked(dataDir);
    upgraded.runBoundedWrite(() => {
      upgraded.handle
        .prepare("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)")
        .run(9000, "future_probe", "2026-10-24T00:00:00.000Z");
    });
    upgraded.close();
    openHandles.pop();

    expect(() => restoreBackup({ backupDir, dataDir })).toThrow(/downgrade without a backup/i);
    expect(() => restoreBackup({ backupDir, dataDir, allowDowngrade: true })).toThrow(
      /preRestoreBackupDir/,
    );

    const safetyDir = makeTempDir("cve-backup-downgrade-safety-");
    rollbackUpgrade({ backupDir, dataDir, preRestoreBackupDir: safetyDir });
    expect(hashDataDir(dataDir)).toBe(beforeHash);
    const safety = verifyBackup(safetyDir);
    expect(safety.manifest.schemaVersions).toContain(9000);
  });
});
