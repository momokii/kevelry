// The e2e suite's corpus lives under .e2e/, never in the checkout's data/.
//
// Why: Playwright's webServer starts with DATA_DIR=<repo>/.e2e/data. Fixture
// specs deploy their own corpus there, so a suite run cannot read or overwrite
// data/cve.db — the file the deployed instance keeps open. Before this split
// every fixture spec swapped data/cve.db mid-run, so a spec could assert
// against whatever residue the previous one left behind: graph.spec's skip
// branches flipped between a standalone run and a full-suite run for that
// reason alone, with no data change of its own.
//
// Deploys are staged and renamed into place, so a request that lands between
// two deploys reads either the old complete file or the new one, never a
// half-copied database.
//
// The baseline below is deterministic: same rows, same ids, same relative
// dates on every run. Read-only specs assert against it, so their passed and
// skipped counts are a function of this fixture, not of what ran before them.

import { copyFileSync, mkdirSync, mkdtempSync, renameSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { openDatabase, type CveDatabase } from "../../src/lib/db";

export const PROJECT_ROOT = process.cwd();
export const E2E_ROOT = path.resolve(PROJECT_ROOT, ".e2e");
export const E2E_DATA_DIR = path.join(E2E_ROOT, "data");
export const E2E_DB_PATH = path.join(E2E_DATA_DIR, "cve.db");

const STAMP = "2026-10-24T00:00:00.000Z";

/**
 * The EPSS model version the fixture labels its observations with. Real EPSS
 * releases are dated strings (`v2026.06.15`); an abbreviated `v4` in a fixture
 * makes every surface that prints the stored version look truncated, so the
 * fixture carries the same full form the live corpus does.
 */
const EPSS_MODEL = "v2026.06.15";

/**
 * Cohort size. Four linked KEV records give the graph a hub leaderboard, a
 * real ego drawing and two shared-attribute groups while staying under the
 * drawing cap (beyond it the view collapses a group behind "+N more", which
 * graph.spec skips by design when the corpus does not have one).
 */
export const BASELINE_COHORT_SIZE = 4;

/**
 * Cohort large enough that the ego drawing hides records behind "+N more".
 * The graph caps drawn children at five per attribute, so a spec that needs the
 * "+N more" trigger must deploy more records per group than the baseline.
 */
export const DENSE_COHORT_SIZE = 12;

function dayAgo(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
}

/** Remove the deployed corpus and its WAL sidecars (never touches data/). */
export function clearE2eCorpus(): void {
  for (const suffix of ["", "-wal", "-shm"]) {
    rmSync(`${E2E_DB_PATH}${suffix}`, { force: true });
  }
}

/**
 * Deploy `sourceFile` as the corpus the dev server reads.
 *
 * Staged then renamed: a reader either opens the previous complete file or the
 * new one, never a partially copied database.
 */
export function deployE2eCorpus(sourceFile: string): void {
  mkdirSync(E2E_DATA_DIR, { recursive: true });
  const staging = `${E2E_DB_PATH}.next`;
  copyFileSync(sourceFile, staging);
  // A swapped-in file is a standalone database, so stale sidecars from the
  // replaced inode must not be paired with it.
  for (const suffix of ["-wal", "-shm"]) {
    rmSync(`${E2E_DB_PATH}${suffix}`, { force: true });
  }
  renameSync(staging, E2E_DB_PATH);
}

/**
 * Put the deterministic baseline back. Every spec that mutates the corpus ends
 * with this, so the next spec always starts from the same rows regardless of
 * file order or of which specs ran before it.
 */
export function resetToBaseline(): void {
  deployE2eCorpus(buildBaselineDbFile());
}

/** Remove .e2e/ entirely (suite teardown). Only ever targets .e2e/. */
export function removeE2eRoot(): void {
  rmSync(E2E_ROOT, { recursive: true, force: true });
}

function seedSyncRun(
  db: CveDatabase,
  source: string,
  startedAt: string,
  revision: string | null,
): void {
  db.handle
    .prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .run(source, startedAt, startedAt, "succeeded", revision, null, null);
}

/**
 * Standard e2e corpus: PUBLISHED KEV records sharing one vendor and one CWE, so
 * the graph has a hub leaderboard and real shared-attribute groups without any
 * fixture-by-fixture patching. `cohortSize` exists only for specs that need a
 * group above the drawing cap; every row is otherwise identical.
 */
export function buildBaselineDbFile(cohortSize: number = BASELINE_COHORT_SIZE): string {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-e2e-baseline-"));
  const db = openDatabase({ dataDir: dir });
  const epssPrevious = dayAgo(6);
  const epssCurrent = dayAgo(1);
  db.runBoundedWrite(() => {
    for (let index = 1; index <= cohortSize; index += 1) {
      const id = `CVE-2099-${String(index).padStart(4, "0")}`;
      const published = `${dayAgo(index + 1)}T12:00:00.000Z`;
      db.handle
        .prepare(
          "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, " +
            "title, description, description_lang, source_revision, created_at, updated_at) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          id,
          "5.1",
          "PUBLISHED",
          published,
          published,
          `Fixture record ${id} in the demonstration service`,
          `A demonstration flaw in ${id} reported by the fixture publisher`,
          "en",
          "rev-e2e-baseline",
          STAMP,
          STAMP,
        );
      db.handle
        .prepare(
          "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) " +
            "VALUES (?, 'CNA', '3.1', '9.8', 'CVSS:3.1/AV:N', 0)",
        )
        .run(id);
      db.handle
        .prepare(
          "INSERT INTO kev_entries (cve_id, date_added, catalog_date, vendor_project, product, recorded_at) " +
            "VALUES (?, ?, ?, 'DemoVendor', 'DemoOS', ?)",
        )
        .run(id, `${dayAgo(2)}T00:00:00.000Z`, dayAgo(3), STAMP);
      db.handle.prepare("INSERT INTO kev_cwes (cve_id, cwe_id) VALUES (?, 'CWE-79')").run(id);
      for (const [date, value] of [
        [epssPrevious, `0.${40 + index}`],
        [epssCurrent, `0.${50 + index}`],
      ] as const) {
        db.handle
          .prepare(
            "INSERT INTO epss_daily (cve_id, score_date, model_version, epss, percentile) " +
              "VALUES (?, ?, ?, ?, '0.9000')",
          )
          .run(id, date, EPSS_MODEL, value);
      }
    }
    const accepted = new Date(Date.now() - 2 * 3_600_000).toISOString();
    seedSyncRun(db, "cve", accepted, "rev-e2e-baseline");
    seedSyncRun(db, "kev", accepted, dayAgo(2));
    seedSyncRun(db, "epss", accepted, `${epssCurrent}@${EPSS_MODEL}`);
  });
  db.checkpointStatus();
  db.close();
  return path.join(dir, "cve.db");
}
