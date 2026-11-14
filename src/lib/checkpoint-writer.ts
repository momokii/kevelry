// Daily Change Radar checkpoint scheduling (v3 epic E5).
//
// The RSS feed and the JSON radar route read only retained `checkpoints`
// rows. Without a writer the table stays empty forever and the feed is a
// valid but permanently empty channel, which a subscriber can misread as
// "no changes". This module owns the single rule that fills the table:
//
//   after every ingestion cycle where at least one source was accepted,
//   freeze exactly ONE checkpoint for the current UTC date.
//
// The second cycle of the same UTC date is a cheap no-op: checkpoints are
// immutable, so the existing row is kept and nothing is overwritten. A cycle
// where every source failed writes nothing, because an all-failed cycle moved
// no accepted data. Both rules keep the retained history honest instead of
// padding it with duplicate or invented days.
//
// Source pins come from the accepted versions the importers already recorded
// in `sync_runs` (last succeeded run per source), so a checkpoint always names
// the revisions the frozen lists were built from. The pins are last-known-good
// when one source failed this cycle, which matches what the tables hold.
//
// Bounded and fail-soft: the per-view cap is the existing
// `CHECKPOINT_TOP_N` resolver (default 500), and any failure — missing pins,
// malformed env, write error — is logged as `checkpoint-write-failed` and
// returned. It never throws into the cycle, never fails the import, and never
// blocks the next source.

import type { CveDatabase } from "./db";
import { writeCheckpoint, type RadarSourcePins } from "./radar";
import type { SourceName } from "./schedule";

/** Structured log sink; the worker's `LogFn` is assignable to this shape. */
export type CheckpointLogFn = (entry: { event: string; [key: string]: unknown }) => void;

export type DailyCheckpointReason =
  "written" | "already-exists" | "no-source-succeeded" | "missing-pins" | "failed";

export interface DailyCheckpointResult {
  written: boolean;
  /** UTC date the checkpoint would cover (always resolved, even on a skip). */
  checkpointDate: string;
  reason: DailyCheckpointReason;
  /** Per-view cap actually applied by the write, or null when nothing was written. */
  boundedTopN: number | null;
  error: string | null;
}

export interface WriteDailyCheckpointOptions {
  /** Injectable clock; defaults to now. The UTC date is derived from it. */
  now?: Date;
  /**
   * Per-source failure record of the cycle that just settled (null = accepted).
   * Omit to attempt the write regardless (explicit maintenance call).
   */
  failed?: Record<SourceName, string | null>;
  /** Explicit per-view cap; defaults to the CHECKPOINT_TOP_N resolver. */
  topN?: number;
  log?: CheckpointLogFn;
}

const SOURCES: readonly SourceName[] = ["cve", "kev", "epss", "ssvc"];

function errorDetail(error: unknown): string {
  const detail = error instanceof Error ? error.message : String(error);
  return detail.slice(0, 2000);
}

function utcDay(now: Date): string {
  return now.toISOString().slice(0, 10);
}

/** Last accepted (`succeeded`) revision recorded for one source, or null. */
function lastSucceededRevision(db: CveDatabase, source: SourceName): string | null {
  const row = db.handle
    .prepare(
      "SELECT revision FROM sync_runs WHERE source = ? AND status = 'succeeded' ORDER BY id DESC LIMIT 1",
    )
    .get(source) as { revision: string | null } | undefined;
  const revision = row?.revision?.trim() ?? "";
  return revision === "" ? null : revision;
}

/**
 * KEV pin. `sync_runs.revision` for KEV is the catalog version ("2026.11.14"),
 * so a date-shaped revision is used verbatim; otherwise the observed catalog
 * date the accepted catalog wrote into `kev_entries` is the pin, and the
 * version string is the last resort.
 */
function resolveKevCatalogPin(db: CveDatabase, revision: string | null): string | null {
  if (revision !== null && /^\d{4}-\d{2}-\d{2}(?:T[0-9:.]+Z)?$/.test(revision)) return revision;
  const row = db.handle.prepare("SELECT MAX(catalog_date) AS pin FROM kev_entries").get() as
    { pin: string | null } | undefined;
  const catalogDate = row?.pin?.trim() ?? "";
  if (catalogDate !== "") return catalogDate;
  return revision;
}

/**
 * EPSS pin. `sync_runs.revision` is `<scoreDate>@<modelVersion>`; the date is
 * matched inside the revision so older/garbled prefixes stay tolerable.
 */
function parseEpssRevision(
  revision: string | null,
): { scoreDate: string; modelVersion: string } | null {
  if (revision === null) return null;
  const match = /^(?:.*@)?(\d{4}-\d{2}-\d{2})@(.+)$/.exec(revision);
  if (match === null) return null;
  const scoreDate = match[1];
  const modelVersion = match[2];
  if (scoreDate === undefined || modelVersion === undefined || modelVersion === "") return null;
  return { scoreDate, modelVersion };
}

/** Fallback EPSS pin: the newest accepted score row already in the store. */
function latestEpssPin(db: CveDatabase): { scoreDate: string; modelVersion: string } | null {
  const row = db.handle
    .prepare(
      "SELECT score_date, model_version FROM epss_daily ORDER BY score_date DESC, model_version DESC LIMIT 1",
    )
    .get() as { score_date: string; model_version: string } | undefined;
  if (row === undefined) return null;
  if (row.score_date === "" || row.model_version === "") return null;
  return { scoreDate: row.score_date, modelVersion: row.model_version };
}

/**
 * Accepted source pins for a checkpoint, or null when any required pin is
 * missing. SSVC has no checkpoint column and no pin field in the manifest
 * shape, so it is deliberately not part of the frozen identity.
 */
export function resolveSourcePins(db: CveDatabase): RadarSourcePins | null {
  const cveRevision = lastSucceededRevision(db, "cve");
  const kevCatalogDate = resolveKevCatalogPin(db, lastSucceededRevision(db, "kev"));
  const epss = parseEpssRevision(lastSucceededRevision(db, "epss")) ?? latestEpssPin(db);
  if (cveRevision === null || kevCatalogDate === null || epss === null) return null;
  return {
    cveRevision,
    kevCatalogDate,
    epssScoreDate: epss.scoreDate,
    epssModelVersion: epss.modelVersion,
  };
}

/** True when a checkpoint row already covers this UTC date. */
export function hasCheckpointFor(db: CveDatabase, checkpointDate: string): boolean {
  const row = db.handle
    .prepare("SELECT 1 AS present FROM checkpoints WHERE checkpoint_date = ?")
    .get(checkpointDate) as { present: number } | undefined;
  return row !== undefined;
}

/**
 * Write the current UTC date's checkpoint when the just-settled cycle
 * accepted at least one source and the date has no checkpoint yet. Never
 * throws: every failure path is logged and returned.
 */
export function writeDailyCheckpoint(
  db: CveDatabase,
  options: WriteDailyCheckpointOptions = {},
): DailyCheckpointResult {
  const now = options.now ?? new Date();
  const checkpointDate = utcDay(now);
  const log: CheckpointLogFn = options.log ?? (() => {});
  const skip = (
    reason: DailyCheckpointReason,
    error: string | null = null,
  ): DailyCheckpointResult => ({
    written: false,
    checkpointDate,
    reason,
    boundedTopN: null,
    error,
  });

  // An all-failed cycle accepted nothing, so it must not add a day to the
  // retained history.
  if (options.failed !== undefined) {
    const anySucceeded = SOURCES.some((source) => options.failed?.[source] === null);
    if (!anySucceeded) return skip("no-source-succeeded");
  }

  if (hasCheckpointFor(db, checkpointDate)) return skip("already-exists");

  const sourcePins = resolveSourcePins(db);
  if (sourcePins === null) {
    const error = "no accepted source pins in sync_runs (cve/kev/epss); checkpoint not written";
    log({ event: "checkpoint-write-failed", checkpointDate, error });
    return skip("missing-pins", error);
  }

  try {
    const stored = writeCheckpoint(db, {
      checkpointDate,
      observedAt: now.toISOString(),
      sourcePins,
      topN: options.topN,
    });
    log({
      event: "checkpoint-written",
      checkpointDate,
      observedAt: stored.observedAt,
      boundedTopN: stored.boundedTopN,
      cohortCount: stored.cohortCount,
      policyVersion: stored.policyVersion,
      sourcePins: stored.sourcePins,
    });
    return {
      written: true,
      checkpointDate,
      reason: "written",
      boundedTopN: stored.boundedTopN,
      error: null,
    };
  } catch (error) {
    const detail = errorDetail(error);
    log({ event: "checkpoint-write-failed", checkpointDate, error: detail });
    return skip("failed", detail);
  }
}
