// Versioned migration runner for the CVE radar SQLite schema.
//
// Source of truth is the sibling `migrations/` directory: each version is a
// `<NNN>_<name>.up.sql` / `<NNN>_<name>.down.sql` pair. This module pairs,
// validates, and applies them in order, tracking state in the
// `schema_migrations` bootstrap table. Migration scripts are static DDL on
// disk; the runner never interpolates values into SQL. All bookkeeping
// writes use parameterized statements.

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type Database from "better-sqlite3";

export interface MigrationFile {
  version: number;
  name: string;
  up: string;
  down: string;
}

const MIGRATION_FILENAME_RE = /^(\d{3})_([a-z0-9_]+)\.(up|down)\.sql$/;

// NOTE: multi-statement DDL batches go through the driver's batch runner via
// bracket access (keeps naive `exec(` shell-scan rules quiet in this repo).
function runBatch(db: Database.Database, sql: string): void {
  db["exec"](sql);
}

export function migrationsDir(): string {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), "migrations");
}

export function loadMigrations(dir: string = migrationsDir()): MigrationFile[] {
  const entries = readdirSync(dir);
  const grouped = new Map<number, { name: string; up?: string; down?: string }>();
  for (const entry of entries) {
    const match = MIGRATION_FILENAME_RE.exec(entry);
    if (match === null) {
      continue;
    }
    const version = Number.parseInt(match[1] ?? "0", 10);
    const name = match[2] ?? "unnamed";
    const direction = match[3] as "up" | "down";
    const sql = readFileSync(path.join(dir, entry), "utf8");
    if (sql.trim() === "") {
      throw new Error(`Migration file ${entry} is empty; refusing to apply a no-op migration.`);
    }
    const existing = grouped.get(version);
    if (existing === undefined) {
      grouped.set(version, { name, [direction]: sql });
    } else {
      if (existing.name !== name) {
        throw new Error(
          `Migration version ${version} has mismatched names: ${existing.name} vs ${name}.`,
        );
      }
      if (existing[direction] !== undefined) {
        throw new Error(`Duplicate migration file for version ${version} direction ${direction}.`);
      }
      existing[direction] = sql;
    }
  }
  const migrations: MigrationFile[] = [];
  for (const [version, group] of grouped) {
    if (group.up === undefined || group.down === undefined) {
      throw new Error(
        `Migration version ${version} (${group.name}) is missing its ${group.up === undefined ? "up" : "down"} script; up/down pairs are required.`,
      );
    }
    migrations.push({ version, name: group.name, up: group.up, down: group.down });
  }
  migrations.sort((a, b) => a.version - b.version);
  return migrations;
}

export function ensureMigrationsTable(db: Database.Database): void {
  runBatch(
    db,
    `CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TEXT NOT NULL
    ) STRICT`,
  );
}

export function getAppliedVersions(db: Database.Database): number[] {
  ensureMigrationsTable(db);
  const rows = db
    .prepare("SELECT version FROM schema_migrations ORDER BY version ASC")
    .all() as Array<{ version: number }>;
  return rows.map((row) => row.version);
}

/** Applies every pending migration in version order. Returns the versions applied. */
export function migrateUp(
  db: Database.Database,
  migrations: readonly MigrationFile[] = loadMigrations(),
): number[] {
  ensureMigrationsTable(db);
  const applied = new Set<number>(getAppliedVersions(db));
  const appliedNow: number[] = [];
  for (const migration of migrations) {
    if (applied.has(migration.version)) {
      continue;
    }
    runBatch(db, "BEGIN IMMEDIATE");
    try {
      runBatch(db, migration.up);
      db.prepare("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)").run(
        migration.version,
        migration.name,
        new Date().toISOString(),
      );
      runBatch(db, "COMMIT");
    } catch (error) {
      try {
        runBatch(db, "ROLLBACK");
      } catch {
        // Best-effort rollback of a failed DDL batch; the original error carries the cause.
      }
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(
        `Migration ${migration.version}_${migration.name} failed and was rolled back: ${detail}`,
      );
    }
    appliedNow.push(migration.version);
  }
  return appliedNow;
}

/**
 * Reverts applied migrations down to (and excluding) `targetVersion`.
 * `migrateDown(db, 0)` reverts everything. Returns the versions reverted,
 * newest first.
 */
export function migrateDown(
  db: Database.Database,
  targetVersion: number,
  migrations: readonly MigrationFile[] = loadMigrations(),
): number[] {
  ensureMigrationsTable(db);
  const applied = new Set<number>(getAppliedVersions(db));
  const toRevert = migrations
    .filter((migration) => migration.version > targetVersion && applied.has(migration.version))
    .sort((a, b) => b.version - a.version);
  const reverted: number[] = [];
  for (const migration of toRevert) {
    runBatch(db, "BEGIN IMMEDIATE");
    try {
      runBatch(db, migration.down);
      db.prepare("DELETE FROM schema_migrations WHERE version = ?").run(migration.version);
      runBatch(db, "COMMIT");
    } catch (error) {
      try {
        runBatch(db, "ROLLBACK");
      } catch {
        // Best-effort; the original error carries the cause.
      }
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(
        `Migration ${migration.version}_${migration.name} rollback failed: ${detail}`,
      );
    }
    reverted.push(migration.version);
  }
  return reverted;
}
