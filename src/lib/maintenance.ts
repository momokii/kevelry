// The maintenance ledger (`maintenance_runs`, migration 006).
//
// A one-off pass records itself so a restart never repeats it
// (`exploit-ref-backfill:v2`). A recurring pass records itself so "did it
// actually run, and when?" is answerable from the database instead of from a
// log line that scrolls away: the EPSS retention prune deleted rows for months
// while the ledger stayed empty, so nothing outside the worker's stdout could
// tell a prune that removed 400k rows from one that never ran.
//
// One row per `name`, and the latest run wins: `name` is the primary key, so an
// upsert keeps the ledger bounded while `completed_at` always describes the last
// run. `detail` is free text by convention — the backfill stores a compact
// `scanned=… updated=…` summary, the prune stores a JSON object.

import type { CveDatabase } from "./db";

export interface MaintenanceRun {
  name: string;
  completedAt: string;
  detail: string | null;
}

/** Records a completed maintenance pass; the newest run replaces the previous row. */
export function recordMaintenanceRun(
  db: CveDatabase,
  run: { name: string; ranAt?: string; detail?: string | null },
): void {
  const ranAt = run.ranAt ?? new Date().toISOString();
  const detail = run.detail ?? null;
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO maintenance_runs (name, completed_at, detail) VALUES (?, ?, ?) " +
          "ON CONFLICT(name) DO UPDATE SET completed_at = excluded.completed_at, detail = excluded.detail",
      )
      .run(run.name, ranAt, detail);
  });
}

/** Reads the last recorded run for `name`, or null when it has never run. */
export function readMaintenanceRun(db: CveDatabase, name: string): MaintenanceRun | null {
  const row = db.handle
    .prepare("SELECT name, completed_at, detail FROM maintenance_runs WHERE name = ?")
    .get(name) as { name: string; completed_at: string; detail: string | null } | undefined;
  return row === undefined
    ? null
    : { name: row.name, completedAt: row.completed_at, detail: row.detail };
}
