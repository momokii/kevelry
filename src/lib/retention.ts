// Retention policy for the append-only tables.
//
// `epss_daily` gains one row per scored CVE per accepted score date, so it is
// the only table that grows without a natural bound: ~400k rows per day at the
// current corpus size. Without a window it would reach tens of millions of rows
// within months, and every index scan behind the trend view and the aggregate
// refresh would carry that cost forever.
//
// The window is expressed in whole UTC calendar days ending at the accepted
// score date, so pruning is deterministic and testable: the same accepted date
// always keeps the same set of days. Nothing here deletes a record row, a KEV
// entry, or a tombstone; those tables are bounded by the corpus, not by time.

import type { CveDatabase } from "./db";

/**
 * Default window. It matches `EPSS_HISTORY_CAP` (the per-record observation cap
 * in `app/api/v1/_lib/shared.ts`), so retention never truncates a series the API
 * is allowed to return, and never stores rows no endpoint can reach. The
 * methodology page reads both constants, so the stated numbers track the code.
 */
export const EPSS_RETENTION_DAYS_DEFAULT = 90;

/** Floor: below a month the per-record trend stops being a trend. */
export const EPSS_RETENTION_DAYS_MIN = 30;

/** Ceiling: ten years, well past any useful comparison. */
export const EPSS_RETENTION_DAYS_MAX = 3650;

const DAY_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

export class RetentionConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RetentionConfigError";
  }
}

/**
 * Reads `EPSS_RETENTION_DAYS`. Unset means the default; a malformed or
 * out-of-range value is rejected rather than clamped, so a typo can never
 * silently shorten the history a reader depends on.
 */
export function resolveEpssRetentionDays(env: Record<string, string | undefined>): number {
  const raw = env.EPSS_RETENTION_DAYS;
  if (raw === undefined || raw === "") return EPSS_RETENTION_DAYS_DEFAULT;
  if (!/^\d+$/.test(raw)) {
    throw new RetentionConfigError(
      `Invalid EPSS_RETENTION_DAYS ${JSON.stringify(raw)}. Expected an integer between ${EPSS_RETENTION_DAYS_MIN} and ${EPSS_RETENTION_DAYS_MAX}.`,
    );
  }
  const value = Number(raw);
  if (value < EPSS_RETENTION_DAYS_MIN || value > EPSS_RETENTION_DAYS_MAX) {
    throw new RetentionConfigError(
      `Invalid EPSS_RETENTION_DAYS ${value}. Expected an integer between ${EPSS_RETENTION_DAYS_MIN} and ${EPSS_RETENTION_DAYS_MAX}.`,
    );
  }
  return value;
}

function shiftDay(day: string, offsetDays: number): string {
  const base = Date.parse(`${day}T00:00:00.000Z`);
  return new Date(base + offsetDays * 86_400_000).toISOString().slice(0, 10);
}

/** Oldest score date that stays inside a window of `keepDays` ending at `anchorDay`. */
export function epssCutoffDay(anchorDay: string, keepDays: number): string {
  if (!DAY_PATTERN.test(anchorDay) || !Number.isFinite(Date.parse(`${anchorDay}T00:00:00.000Z`))) {
    throw new Error(`Invalid anchor day ${JSON.stringify(anchorDay)}. Expected YYYY-MM-DD.`);
  }
  if (!Number.isInteger(keepDays) || keepDays < 1) {
    throw new Error(`Invalid keepDays ${keepDays}. Expected a positive integer.`);
  }
  return shiftDay(anchorDay, -(keepDays - 1));
}

export interface EpssPruneResult {
  /** Oldest score date still present after pruning. */
  oldestKept: string | null;
  /** Rows removed by this call. */
  deleted: number;
  /** Rows already at or above the cutoff; nothing to do. */
  skipped: boolean;
}

/**
 * Deletes EPSS rows older than the window. Idempotent: a second call on the same
 * accepted date deletes nothing, so a restart mid-import is harmless.
 */
export function pruneEpssHistory(
  db: CveDatabase,
  options: { anchorDay: string; keepDays: number },
): EpssPruneResult {
  const cutoff = epssCutoffDay(options.anchorDay, options.keepDays);
  const oldest = db.handle.prepare("SELECT MIN(score_date) AS day FROM epss_daily").get() as {
    day: string | null;
  };
  if (oldest.day === null || oldest.day >= cutoff) {
    return { oldestKept: oldest.day, deleted: 0, skipped: true };
  }
  const info = db.handle.prepare("DELETE FROM epss_daily WHERE score_date < ?").run(cutoff);
  const after = db.handle.prepare("SELECT MIN(score_date) AS day FROM epss_daily").get() as {
    day: string | null;
  };
  return { oldestKept: after.day, deleted: info.changes, skipped: false };
}
