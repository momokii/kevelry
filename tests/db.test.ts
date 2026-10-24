// New-test justification (plan todo 7): the sqlite schema is the first
// durable-state code in the repo, so tests must prove what unit checks
// cannot: FTS5 is really compiled in, migrations round-trip on a real file,
// WAL readers stay usable while a writer holds a transaction, and lock or
// permission failures surface as typed errors instead of raw throws.
// Fixtures are synthetic CVE-2099 IDs; nothing here touches the network.

import Database from "better-sqlite3";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { CveDatabase, DbBusyError, DbConfigError, openDatabase } from "../src/lib/db";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop() as string;
    try {
      chmodSync(dir, 0o700);
    } catch {
      // Best-effort permission restore before removal.
    }
    rmSync(dir, { recursive: true, force: true });
  }
});

const RECORD_COLUMNS =
  "cve_id, data_version, state, date_published, date_updated, title, description, description_lang, source_revision, created_at, updated_at";

const MINIMAL_INSERT =
  "INSERT INTO cve_records (cve_id, data_version, state, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)";
const FIXTURE_STAMP = "2026-10-24T00:00:00.000Z";

function runMinimalInsert(handle: Database.Database, cveId: string, description: string): void {
  handle
    .prepare(MINIMAL_INSERT)
    .run(cveId, "5.1", "PUBLISHED", description, FIXTURE_STAMP, FIXTURE_STAMP);
}

function insertRecord(db: CveDatabase, cveId: string, title: string, description: string): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        `INSERT INTO cve_records (${RECORD_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        cveId,
        "5.1",
        "PUBLISHED",
        "2026-10-20T00:00:00.000Z",
        "2026-10-21T00:00:00.000Z",
        title,
        description,
        "en",
        "rev-test",
        "2026-10-24T00:00:00.000Z",
        "2026-10-24T00:00:00.000Z",
      );
  });
}

function tableNames(db: CveDatabase): string[] {
  const rows = db.handle
    .prepare("SELECT name FROM sqlite_master WHERE type = ? ORDER BY name ASC")
    .all("table") as Array<{ name: string }>;
  return rows.map((row) => row.name);
}

describe("sqlite storage (todo 7)", () => {
  it("opens with WAL mode and applies the versioned schema", () => {
    const db = openDatabase({ dataDir: makeTempDir("cve-db-test-") });
    try {
      expect(db.appliedVersions()).toEqual([1]);
      expect(db.handle.pragma("journal_mode", { simple: true })).toBe("wal");
      for (const table of [
        "cve_records",
        "cvss_metrics",
        "epss_daily",
        "kev_entries",
        "kev_history",
        "sync_runs",
        "checkpoints",
        "checkpoint_baseline_refs",
        "cve_tombstones",
        "cve_fts",
        "schema_migrations",
      ]) {
        expect(tableNames(db)).toContain(table);
      }
    } finally {
      db.close();
    }
  });

  it("proves FTS5 is compiled in: insert, MATCH, update reindex, delete", () => {
    const db = openDatabase({ dataDir: makeTempDir("cve-db-test-") });
    try {
      const fts = db.handle.prepare(
        "SELECT cve_id FROM cve_fts WHERE cve_fts MATCH ? ORDER BY rank",
      );
      insertRecord(db, "CVE-2099-0001", "Heap overflow", "A heap overflow in the parser");
      expect(fts.all("overflow")).toEqual([{ cve_id: "CVE-2099-0001" }]);

      db.runBoundedWrite(() => {
        db.handle
          .prepare("UPDATE cve_records SET description = ? WHERE cve_id = ?")
          .run("A use-after-free in the renderer", "CVE-2099-0001");
      });
      expect(fts.all("parser")).toEqual([]);
      expect(fts.all("renderer")).toEqual([{ cve_id: "CVE-2099-0001" }]);

      db.runBoundedWrite(() => {
        db.handle.prepare("DELETE FROM cve_records WHERE cve_id = ?").run("CVE-2099-0001");
      });
      expect(fts.all("renderer")).toEqual([]);
    } finally {
      db.close();
    }
  });

  it("round-trips migrations down to zero and back up on a temp volume", () => {
    const db = openDatabase({ dataDir: makeTempDir("cve-db-test-") });
    try {
      expect(db.migrate()).toEqual([]);
      expect(db.revertTo(0)).toEqual([1]);
      expect(db.appliedVersions()).toEqual([]);
      expect(tableNames(db)).not.toContain("cve_records");
      expect(tableNames(db)).not.toContain("cve_fts");

      expect(db.migrate()).toEqual([1]);
      expect(tableNames(db)).toContain("cve_records");
      insertRecord(db, "CVE-2099-0002", "Round trip", "Schema works after re-migration");
      const rows = db.handle
        .prepare("SELECT cve_id FROM cve_fts WHERE cve_fts MATCH ?")
        .all("round") as Array<{ cve_id: string }>;
      expect(rows).toEqual([{ cve_id: "CVE-2099-0002" }]);
    } finally {
      db.close();
    }
  });

  it("lets readers query while a bounded writer holds its transaction", () => {
    const dir = makeTempDir("cve-db-test-");
    const db = openDatabase({ dataDir: dir });
    const writer = new Database(path.join(dir, "cve.db"));
    try {
      insertRecord(db, "CVE-2099-0010", "Reader test", "Committed before the writer begins");
      writer.prepare("BEGIN IMMEDIATE").run();
      runMinimalInsert(writer, "CVE-2099-0011", "Uncommitted writer row");

      const visible = db.handle.prepare("SELECT COUNT(*) AS n FROM cve_records").get() as {
        n: number;
      };
      expect(visible.n).toBe(1);

      writer.prepare("COMMIT").run();
      const after = db.handle.prepare("SELECT COUNT(*) AS n FROM cve_records").get() as {
        n: number;
      };
      expect(after.n).toBe(2);
    } finally {
      try {
        writer.prepare("ROLLBACK").run();
      } catch {
        // No open transaction; nothing to roll back.
      }
      writer.close();
      db.close();
    }
  });

  it("serializes the single-writer guard and maps lock races to DbBusyError", async () => {
    const dir = makeTempDir("cve-db-test-");
    const db = openDatabase({ dataDir: dir, busyTimeoutMs: 50 });
    const blocker = new Database(path.join(dir, "cve.db"));
    blocker.pragma("busy_timeout = 0");
    try {
      const order: string[] = [];
      await db.runWriteExclusive(() => order.push("first"));
      await db.runWriteExclusive(() => order.push("second"));
      expect(order).toEqual(["first", "second"]);

      blocker.prepare("BEGIN IMMEDIATE").run();
      runMinimalInsert(blocker, "CVE-2099-0020", "Lock holder");

      let failure: unknown;
      try {
        db.runBoundedWrite(() => {
          runMinimalInsert(db.handle, "CVE-2099-0021", "Contended writer");
        });
      } catch (error) {
        failure = error;
      }
      expect(failure).toBeInstanceOf(DbBusyError);

      blocker.prepare("ROLLBACK").run();
      db.runBoundedWrite(() => {
        runMinimalInsert(db.handle, "CVE-2099-0021", "Writer after the lock clears");
      });
      const count = db.handle.prepare("SELECT COUNT(*) AS n FROM cve_records").get() as {
        n: number;
      };
      expect(count.n).toBe(1);
    } finally {
      try {
        blocker.prepare("ROLLBACK").run();
      } catch {
        // No open transaction; nothing to roll back.
      }
      blocker.close();
      db.close();
    }
  });

  it("fails closed with a clear error when the data dir is read-only", () => {
    const dir = makeTempDir("cve-db-test-ro-");
    chmodSync(dir, 0o555);
    expect(() => openDatabase({ dataDir: dir })).toThrowError(DbConfigError);
    expect(() => openDatabase({ dataDir: dir })).toThrowError(/not writable/);
  });

  it("fails closed with a clear error when the data dir is not a directory", () => {
    const dir = makeTempDir("cve-db-test-");
    const filePath = path.join(dir, "not-a-dir");
    writeFileSync(filePath, "x");
    expect(() => openDatabase({ dataDir: filePath })).toThrowError(/not a directory/);
  });

  it("reports WAL checkpoint and file growth without throwing", () => {
    const db = openDatabase({ dataDir: makeTempDir("cve-db-test-") });
    try {
      insertRecord(db, "CVE-2099-0030", "Checkpoint probe", "Growth stays observable");
      const status = db.checkpointStatus();
      expect(status.busy).toBe(false);
      expect(status.dbBytes).toBeGreaterThan(0);
      expect(status.walBytes).toBeGreaterThanOrEqual(0);
      expect(status.shmBytes).toBeGreaterThanOrEqual(0);
    } finally {
      db.close();
    }
  });

  it("writes bulk rows in bounded batches and keeps hostile text inert", () => {
    const db = openDatabase({ dataDir: makeTempDir("cve-db-test-") });
    try {
      const ids = Array.from({ length: 1200 }, (_, index) => `CVE-2099-${String(1000 + index)}`);
      db.executeBatched(ids, 500, (batch) => {
        for (const cveId of batch) {
          runMinimalInsert(db.handle, cveId, "Batch row");
        }
      });
      const count = db.handle.prepare("SELECT COUNT(*) AS n FROM cve_records").get() as {
        n: number;
      };
      expect(count.n).toBe(1200);

      db.runBoundedWrite(() => {
        db.handle
          .prepare("UPDATE cve_records SET description = ? WHERE cve_id = ?")
          .run("' OR '1'='1'; --", "CVE-2099-1000");
      });
      const hostileQuery = db.handle.prepare("SELECT cve_id FROM cve_fts WHERE cve_fts MATCH ?");
      let hostileRows: Array<{ cve_id: string }> = [];
      let hostileRejected = false;
      try {
        hostileRows = hostileQuery.all("'; DROP TABLE cve_records; --") as Array<{
          cve_id: string;
        }>;
      } catch {
        hostileRejected = true;
      }
      if (!hostileRejected) {
        expect(hostileRows).toEqual([]);
      }
      expect(tableNames(db)).toContain("cve_records");
    } finally {
      db.close();
    }
  });
});
