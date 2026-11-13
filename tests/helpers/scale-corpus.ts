// Shared seeder for the three production-scale regression suites:
// tests/overview-scale.test.ts, tests/priority-page-scale.test.ts, and
// tests/task-37-production.test.ts. All three prove bounded behaviour on the
// same shape of corpus — 50,000 synthetic scored CVE-2099 rows in a temp
// SQLite file, invented ids, no network — and each carried its own
// copy-pasted clone of the seeder, the id/score generators, and the temp-dir
// bookkeeping. One definition lives here.
//
// The differences the assertions depend on stay explicit in
// ScaleCorpusOptions, so each suite still seeds exactly the corpus it was
// written against: nothing here changes a row count, a score, a date, or a
// description. Not a test file — vitest collects tests/**/*.test.ts only.

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type Database from "better-sqlite3";

import { openDatabase } from "../../src/lib/db";

/** Corpus size every scale suite seeds. */
export const SCALE_ROWS = 50_000;

/** Fixed timestamps. Suites assert against these, so they never move. */
export const SCALE_STAMP = "2026-10-24T00:00:00.000Z";
export const SCALE_DAY = "2026-10-24";
export const SCALE_DAY_MINUS_7 = "2026-10-17";
export const SCALE_MODEL = "v2026.06.15";
export const SCALE_PUBLISHED_AT = "2026-10-20T00:00:00.000Z";

/** Rows that also get an observation one week before SCALE_DAY. */
export const SCALE_HISTORY_ROWS = 2000;

/** Deterministic EPSS in [0.00001, 1), with a spike every 5,000th row. */
export function epssFor(index: number): string {
  if (index % 5000 === 0) return "0.99999";
  return (0.00001 + ((index * 7919) % 99999) / 100000).toFixed(5);
}

/** The week-earlier observation for a row: its score minus 0.01. */
export function epssWeekBefore(index: number): string {
  return (Number(epssFor(index)) - 0.01).toFixed(5);
}

/** Invented CVE-2099 id for a corpus row. */
export function cveIdAt(index: number): string {
  return `CVE-2099-${String(index).padStart(5, "0")}`;
}

/** date_published that is null every 7,000th row, modelling missing dates. */
export function sparsePublishedAt(index: number): string | null {
  return index % 7000 === 0 ? null : SCALE_PUBLISHED_AT;
}

/**
 * Temp data dir registered in the caller's own cleanup list, so each suite's
 * afterAll removes exactly the dirs it created and keeps its own prefix.
 */
export function makeScaleDir(tempDirs: string[], prefix: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

/** Prepared inserts handed to ScaleCorpusOptions.extra for dirty-row fixtures. */
export interface ScaleCorpusInserts {
  record: Database.Statement;
  epss: Database.Statement;
  cvss: Database.Statement;
  kev: Database.Statement;
}

export interface ScaleCorpusOptions {
  /**
   * Row description. The task-37 corpus needs "php" in every description so
   * `q=php` matches all 50,000 rows past the SQLite variable limit.
   */
  descriptionFor?: (cveId: string) => string;
  /** date_published per row; null models a record with no published date. */
  publishedAtFor?: (index: number) => string | null;
  /** Which rows also get a CNA CVSS 3.1 metric. Default: the first 100. */
  hasCvss?: (index: number) => boolean;
  /** KEV rows written for ids 1..kevCount. Default: 9. */
  kevCount?: number;
  /** Dirty-row fixtures appended last, inside the same transaction. */
  extra?: (inserts: ScaleCorpusInserts) => void;
}

/**
 * Seed one 50,000-row scored corpus into a fresh database at `dir`. Row order,
 * per-table insert order, and every value match the suites' original inline
 * seeders; only the per-suite variants are parameterized.
 */
export function seedScaleCorpus(dir: string, options: ScaleCorpusOptions = {}): void {
  const descriptionFor = options.descriptionFor ?? ((cveId: string) => `Description for ${cveId}`);
  const publishedAtFor = options.publishedAtFor ?? ((): string | null => SCALE_PUBLISHED_AT);
  const hasCvss = options.hasCvss ?? ((index: number) => index < 100);
  const kevCount = options.kevCount ?? 9;

  const db = openDatabase({ dataDir: dir });
  try {
    const insertRecord = db.handle.prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    );
    const insertEpss = db.handle.prepare(
      "INSERT INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
    );
    const insertCvss = db.handle.prepare(
      "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
    );
    const insertKev = db.handle.prepare(
      "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
    );
    const tx = db.handle.transaction(() => {
      for (let index = 0; index < SCALE_ROWS; index += 1) {
        const cveId = cveIdAt(index);
        insertRecord.run(
          cveId,
          "5.1",
          "PUBLISHED",
          publishedAtFor(index),
          `Title for ${cveId}`,
          descriptionFor(cveId),
          SCALE_STAMP,
          SCALE_STAMP,
        );
        insertEpss.run(cveId, SCALE_DAY, SCALE_MODEL, epssFor(index), "0.80000");
        if (hasCvss(index)) {
          insertCvss.run(cveId, "CNA", "3.1", "9.8", "CVSS:3.1/AV:N", 0);
        }
        if (index < SCALE_HISTORY_ROWS) {
          insertEpss.run(cveId, SCALE_DAY_MINUS_7, SCALE_MODEL, epssWeekBefore(index), "0.80000");
        }
      }
      for (let index = 1; index <= kevCount; index += 1) {
        insertKev.run(
          cveIdAt(index),
          `2026-10-${String(10 + index).padStart(2, "0")}`,
          SCALE_STAMP,
          SCALE_STAMP,
        );
      }
      if (options.extra !== undefined) {
        options.extra({
          record: insertRecord,
          epss: insertEpss,
          cvss: insertCvss,
          kev: insertKev,
        });
      }
    });
    tx();
  } finally {
    db.close();
  }
}
