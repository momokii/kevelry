import { loadConfig } from "../../../../src/lib/config";
import { openDatabase, readDatabaseSignature, type CveDatabase } from "../../../../src/lib/db";

let dbOverride: CveDatabase | null = null;
let cached: { dir: string; signature: string; db: CveDatabase } | null = null;

export function setDbOverride(db: CveDatabase): void {
  dbOverride = db;
}

export function resetDbOverride(): void {
  dbOverride = null;
}

/**
 * One writable handle per data directory, rebound when the database file is
 * replaced. File identity matters: an import/restore swaps `cve.db` in place,
 * and a handle cached by directory alone would keep reading the old inode. The
 * page opens its own read handle and already rebinds on the signature, so
 * without this check the page and an export could describe two snapshots.
 */
export function getDb(): CveDatabase {
  if (dbOverride !== null) return dbOverride;
  const config = loadConfig(process.env);
  const signature = readDatabaseSignature(config.dataDir);
  if (cached !== null && cached.dir === config.dataDir && cached.signature === signature) {
    return cached.db;
  }
  if (cached !== null) {
    try {
      cached.db.close();
    } catch {
      // A replaced file can leave the old handle unusable; the fresh open below is authoritative.
    }
  }
  const db = openDatabase({ dataDir: config.dataDir });
  cached = { dir: config.dataDir, signature: readDatabaseSignature(config.dataDir), db };
  return db;
}
