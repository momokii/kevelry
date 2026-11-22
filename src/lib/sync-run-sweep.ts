// Abandoned `sync_runs` rows are a fact of process life, not a data fact.
//
// The CVE importer opens a `status = 'running'` row before it clones (it needs
// the id to close the same row later) and finishes it on success or failure. KEV,
// EPSS and SSVC write one row with a final status. A process killed mid-import
// (deploy, OOM, host reboot) never reaches the close, so the CVE row stays
// `running` forever: five such rows sat in the production ledger from 2026-11-08,
// and from the outside a hung import is indistinguishable from a ledger nobody
// swept.
//
// The sweep runs once at worker boot, before the first cycle, and marks only rows
// older than ABANDONED_RUN_AGE_MS as `interrupted`. It never deletes a row and
// never rewrites `started_at`/`finished_at`: the ledger keeps saying when the run
// began, and the note explains why it never closed. `interrupted` is a distinct
// status so this can never be mistaken for an import failure that lost data — and
// because freshness readers pin on `status = 'succeeded'` (`acceptedVersions` in
// src/lib/aggregates.ts, `lastSucceededRevision` in src/lib/checkpoint-writer.ts,
// `latestSucceeded` in src/lib/provenance.ts), an abandoned attempt cannot
// advance an accepted version or a checkpoint no matter what status it is given
// here.
//
// The 2 h threshold is deliberately longer than any healthy import (the CVE
// clone is the slow one, measured in minutes) and longer than the scheduler
// lease, so a live import in another process is never mistaken for a dead one.

import type { CveDatabase } from "./db";

/** A `running` row older than this cannot belong to a live import. */
export const ABANDONED_SYNC_RUN_AGE_MS = 2 * 60 * 60 * 1000;

/** Appended to `error`; an existing note is preserved. */
export const ABANDONED_SYNC_RUN_NOTE =
  "interrupted: the process exited before this run finished; not an import failure";

export interface SyncRunSweepResult {
  /** Rows moved from `running` to `interrupted` by this call. */
  interrupted: number;
  /** Their ids, newest last, for the boot log. */
  ids: number[];
}

/**
 * Marks abandoned `running` rows `interrupted`. Idempotent: a swept row is no
 * longer `running`, so a second boot finds nothing to do.
 */
export function sweepAbandonedSyncRuns(
  db: CveDatabase,
  options: { now?: Date; maxAgeMs?: number } = {},
): SyncRunSweepResult {
  const now = options.now ?? new Date();
  const maxAgeMs = options.maxAgeMs ?? ABANDONED_SYNC_RUN_AGE_MS;
  const cutoffIso = new Date(now.getTime() - maxAgeMs).toISOString();
  let ids: number[] = [];
  db.runBoundedWrite(() => {
    const abandoned = db.handle
      .prepare("SELECT id FROM sync_runs WHERE status = 'running' AND started_at < ? ORDER BY id")
      .all(cutoffIso) as Array<{ id: number }>;
    if (abandoned.length === 0) return;
    const mark = db.handle.prepare(
      "UPDATE sync_runs SET status = 'interrupted', error = COALESCE(error, ?) " +
        "WHERE id = ? AND status = 'running'",
    );
    for (const row of abandoned) mark.run(ABANDONED_SYNC_RUN_NOTE, row.id);
    ids = abandoned.map((row) => row.id);
  });
  return { interrupted: ids.length, ids };
}
