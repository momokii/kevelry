import { loadConfig } from "../../../../src/lib/config";
import { openDatabase, type CveDatabase } from "../../../../src/lib/db";

let dbOverride: CveDatabase | null = null;
let cached: { dir: string; db: CveDatabase } | null = null;

export function setDbOverride(db: CveDatabase): void {
  dbOverride = db;
}

export function resetDbOverride(): void {
  dbOverride = null;
}

export function getDb(): CveDatabase {
  if (dbOverride !== null) return dbOverride;
  const config = loadConfig(process.env);
  if (cached !== null && cached.dir === config.dataDir) return cached.db;
  const db = openDatabase({ dataDir: config.dataDir });
  cached = { dir: config.dataDir, db };
  return db;
}
