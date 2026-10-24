// Radar diff and snapshot replay services on the real SQLite layer (plan todo 12).
//
// The checkpoint writer freezes one daily observed manifest per UTC date: the
// caller-supplied source pins (owned by the importers), the observed
// PUBLISHED cohort, the ranking policy version, the new-critical time cutoff,
// and the materialized public list results plus a per-record source snapshot
// read from the accepted tables. The change detector compares two retained
// manifests and labels source changes (KEV added/removed, CNA metric changed,
// forecast changed, corrected, rejected, added, removed) apart from
// rank-only/cohort/window/policy movement. Detail strings state observed
// before/after values only; no claim about EPSS internals or first
// exploitation is ever made here. The replay evaluator returns the retained
// materialized results after validation, or an explicit unavailable reason
// (expired, missing, pre-launch, model-changed, baseline released, tampered
// manifest). Replay reads only the checkpoints tables, never the current CVE
// tables, so it cannot substitute current data.
//
// No pre-launch backfill is created: a checkpoint exists only for a date the
// writer actually observed, and replay of an earlier date stays unavailable.

import { createHash } from "node:crypto";

import type { CveDatabase } from "./db";
import {
  getDefaultPriority,
  getHighestForecast,
  getKnownExploited,
  getNewCritical,
  getRisingForecast,
} from "./priority";
import { selectPrimaryCvss, type CvssMetricInput } from "./ranking";

/** Pinned ranking-policy implementation version frozen into every checkpoint. */
export const RADAR_POLICY_VERSION = "v1";

/** Retained daily checkpoints cover the preceding 30 UTC calendar days. */
export const RADAR_RETENTION_DAYS = 30;

export interface RadarSourcePins {
  cveRevision: string;
  kevCatalogDate: string;
  epssScoreDate: string;
  epssModelVersion: string;
}

export interface RadarViews {
  defaultPriority: string[];
  knownExploited: string[];
  highestForecast: string[];
  newCritical: string[];
  risingForecast: string[];
}

export interface RadarItemSnapshot {
  state: string;
  kevMember: boolean;
  dateAdded: string | null;
  epss: string | null;
  epssModel: string | null;
  primaryVersion: string | null;
  primaryBaseScore: string | null;
  primaryVector: string | null;
  publishedAt: string | null;
  dateUpdated: string | null;
  descriptionHash: string;
}

export interface StoredRadarCheckpoint {
  checkpointDate: string;
  observedAt: string;
  sourcePins: RadarSourcePins;
  cohortId: string;
  cohortCount: number;
  policyVersion: string;
  cutoffT: string;
  views: RadarViews;
  items: Record<string, RadarItemSnapshot>;
  manifestHash: string;
}

export interface WriteCheckpointInput {
  checkpointDate: string;
  observedAt: string;
  sourcePins: RadarSourcePins;
  policyVersion?: string;
  cutoffT?: string;
}

export type ReplayResult =
  | { status: "available"; manifest: StoredRadarCheckpoint; results: RadarViews }
  | { status: "unavailable"; reason: string };

export interface ReplayOptions {
  asOfDate: string;
  retentionDays?: number;
  expectedModelVersion?: string;
}

export type RadarChangeKind =
  | "kev-added"
  | "kev-removed"
  | "cna-changed"
  | "forecast-changed"
  | "model-changed"
  | "corrected"
  | "rejected"
  | "added"
  | "removed"
  | "rank-only-move";

export interface RadarItemChange {
  cveId: string;
  kinds: RadarChangeKind[];
  beforeRank: number | null;
  afterRank: number | null;
  detail: string;
}

export interface RadarDiff {
  beforeDate: string;
  afterDate: string;
  policyChanged: boolean;
  cohortChanged: boolean;
  windowChanged: boolean;
  itemChanges: RadarItemChange[];
  summary: {
    sourceChanges: number;
    rankOnlyMoves: number;
    added: number;
    removed: number;
  };
}

const DAY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

const SOURCE_KINDS: ReadonlySet<RadarChangeKind> = new Set([
  "kev-added",
  "kev-removed",
  "cna-changed",
  "forecast-changed",
  "corrected",
  "rejected",
  "added",
  "removed",
]);

function isValidDay(value: unknown): value is string {
  if (typeof value !== "string" || !DAY_RE.test(value)) return false;
  const ms = Date.parse(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(ms)) return false;
  return new Date(ms).toISOString().slice(0, 10) === value;
}

function observedDay(iso: string): string | null {
  if (typeof iso !== "string" || iso === "") return null;
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString().slice(0, 10);
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function describeHash(description: string): string {
  return sha256Hex(description);
}

interface CorpusRow {
  cve_id: string;
  state: string;
  date_published: string | null;
  date_updated: string | null;
  description: string;
}

function readCorpus(db: CveDatabase): CorpusRow[] {
  return db.handle
    .prepare(
      "SELECT cve_id, state, date_published, date_updated, description FROM cve_records ORDER BY cve_id ASC",
    )
    .all() as CorpusRow[];
}

function readKevDates(db: CveDatabase): Map<string, string> {
  const rows = db.handle.prepare("SELECT cve_id, date_added FROM kev_entries").all() as Array<{
    cve_id: string;
    date_added: string;
  }>;
  return new Map(rows.map((row) => [row.cve_id, row.date_added]));
}

function readEpssForDate(db: CveDatabase, scoreDate: string): Map<string, { epss: string; model: string }> {
  const rows = db.handle
    .prepare("SELECT cve_id, epss, model_version FROM epss_daily WHERE score_date = ?")
    .all(scoreDate) as Array<{ cve_id: string; epss: string; model_version: string }>;
  const best = new Map<string, { epss: string; model: string }>();
  for (const row of rows) {
    const prior = best.get(row.cve_id);
    if (prior === undefined || row.model_version > prior.model) {
      best.set(row.cve_id, { epss: row.epss, model: row.model_version });
    }
  }
  return best;
}

function readPrimaries(
  db: CveDatabase,
): Map<string, { version: string; baseScore: string; vector: string }> {
  const rows = db.handle
    .prepare(
      "SELECT cve_id, origin, version, base_score, vector, source_order FROM cvss_metrics",
    )
    .all() as Array<{
    cve_id: string;
    origin: string;
    version: string;
    base_score: string;
    vector: string;
    source_order: number;
  }>;
  const grouped = new Map<string, CvssMetricInput[]>();
  for (const row of rows) {
    const list = grouped.get(row.cve_id) ?? [];
    list.push({
      origin: row.origin,
      version: row.version,
      baseScore: row.base_score,
      vector: row.vector,
      sourceOrder: row.source_order,
    });
    grouped.set(row.cve_id, list);
  }
  const out = new Map<string, { version: string; baseScore: string; vector: string }>();
  for (const [cveId, metrics] of grouped) {
    const primary = selectPrimaryCvss(metrics);
    if (primary !== null) {
      out.set(cveId, {
        version: primary.version,
        baseScore: primary.baseScore,
        vector: primary.vector,
      });
    }
  }
  return out;
}

function buildItems(db: CveDatabase, epssScoreDate: string): Record<string, RadarItemSnapshot> {
  const corpus = readCorpus(db);
  const kevDates = readKevDates(db);
  const epss = epssScoreDate === "" ? new Map() : readEpssForDate(db, epssScoreDate);
  const primaries = readPrimaries(db);
  const items: Record<string, RadarItemSnapshot> = {};
  for (const row of corpus) {
    const entry = epss.get(row.cve_id);
    const primary = primaries.get(row.cve_id);
    items[row.cve_id] = {
      state: row.state,
      kevMember: kevDates.has(row.cve_id),
      dateAdded: kevDates.get(row.cve_id) ?? null,
      epss: entry?.epss ?? null,
      epssModel: entry?.model ?? null,
      primaryVersion: primary?.version ?? null,
      primaryBaseScore: primary?.baseScore ?? null,
      primaryVector: primary?.vector ?? null,
      publishedAt: row.date_published,
      dateUpdated: row.date_updated,
      descriptionHash: describeHash(row.description ?? ""),
    };
  }
  return items;
}

function buildViews(db: CveDatabase, cutoffT: string): RadarViews {
  return {
    defaultPriority: getDefaultPriority(db).map((row) => row.id),
    knownExploited: getKnownExploited(db).map((row) => row.id),
    highestForecast: getHighestForecast(db).map((row) => row.id),
    newCritical: getNewCritical(db, cutoffT).map((row) => row.id),
    risingForecast: getRisingForecast(db).map((row) => row.item.id),
  };
}

function canonicalManifestJson(manifest: Omit<StoredRadarCheckpoint, "manifestHash">): string {
  const sortedItems: Record<string, RadarItemSnapshot> = {};
  for (const cveId of Object.keys(manifest.items).sort()) {
    const item = manifest.items[cveId];
    if (item !== undefined) sortedItems[cveId] = item;
  }
  return JSON.stringify({
    checkpointDate: manifest.checkpointDate,
    observedAt: manifest.observedAt,
    sourcePins: manifest.sourcePins,
    cohortId: manifest.cohortId,
    cohortCount: manifest.cohortCount,
    policyVersion: manifest.policyVersion,
    cutoffT: manifest.cutoffT,
    views: manifest.views,
    items: sortedItems,
  });
}

function validateInput(input: WriteCheckpointInput): {
  policyVersion: string;
  cutoffT: string;
} {
  if (!isValidDay(input.checkpointDate)) {
    throw new Error(
      `Refusing to write radar checkpoint: invalid checkpoint date ${JSON.stringify(input.checkpointDate)}; expected UTC YYYY-MM-DD.`,
    );
  }
  const day = observedDay(input.observedAt);
  if (day === null) {
    throw new Error(
      "Refusing to write radar checkpoint: observedAt is not a parseable timestamp; record the actual observation time.",
    );
  }
  if (day !== input.checkpointDate) {
    throw new Error(
      `Refusing to write radar checkpoint: observed timestamp ${input.observedAt} falls outside checkpoint date ${input.checkpointDate}; never invent a midnight capture.`,
    );
  }
  const pins = input.sourcePins;
  if (
    pins === undefined ||
    pins.cveRevision === "" ||
    pins.kevCatalogDate === "" ||
    pins.epssScoreDate === "" ||
    pins.epssModelVersion === ""
  ) {
    throw new Error(
      "Refusing to write radar checkpoint: manifest missing source revision/date pins.",
    );
  }
  const policyVersion = input.policyVersion ?? RADAR_POLICY_VERSION;
  if (policyVersion === "") {
    throw new Error("Refusing to write radar checkpoint: manifest missing ranking policy version.");
  }
  const cutoffT = input.cutoffT ?? input.observedAt;
  if (observedDay(cutoffT) === null) {
    throw new Error(
      "Refusing to write radar checkpoint: cutoffT is not a parseable timestamp.",
    );
  }
  return { policyVersion, cutoffT };
}

/**
 * Freezes the daily observed manifest for `checkpointDate` from the accepted
 * SQLite tables. One checkpoint per date; a second write for the same date
 * fails instead of overwriting history. Records a reference-counted baseline
 * hold on the pinned CVE revision.
 */
export function writeCheckpoint(db: CveDatabase, input: WriteCheckpointInput): StoredRadarCheckpoint {
  const { policyVersion, cutoffT } = validateInput(input);
  const items = buildItems(db, input.sourcePins.epssScoreDate);
  const publishedIds = Object.keys(items)
    .filter((cveId) => items[cveId]?.state === "PUBLISHED")
    .sort();
  const cohortId = `published-sha256:${sha256Hex(publishedIds.join("\n"))}`;
  const views = buildViews(db, cutoffT);
  const core = {
    checkpointDate: input.checkpointDate,
    observedAt: input.observedAt,
    sourcePins: { ...input.sourcePins },
    cohortId,
    cohortCount: publishedIds.length,
    policyVersion,
    cutoffT,
    views,
    items,
  };
  const manifestHash = sha256Hex(canonicalManifestJson(core));
  const stored: StoredRadarCheckpoint = { ...core, manifestHash };
  db.runBoundedWrite(() => {
    try {
      db.handle
        .prepare(
          "INSERT INTO checkpoints (checkpoint_date, observed_at, cve_revision, kev_catalog_date, epss_score_date, epss_model_version, cohort_id, cohort_count, policy_version, materialized_results_json, manifest_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          stored.checkpointDate,
          stored.observedAt,
          stored.sourcePins.cveRevision,
          stored.sourcePins.kevCatalogDate,
          stored.sourcePins.epssScoreDate,
          stored.sourcePins.epssModelVersion,
          stored.cohortId,
          stored.cohortCount,
          stored.policyVersion,
          canonicalManifestJson(core),
          stored.manifestHash,
          new Date().toISOString(),
        );
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      if (detail.includes("UNIQUE constraint failed")) {
        throw new Error(
          `Refusing to write radar checkpoint: a checkpoint for ${stored.checkpointDate} already exists; checkpoints are immutable.`,
        );
      }
      throw error;
    }
    db.handle
      .prepare(
        "INSERT OR IGNORE INTO checkpoint_baseline_refs (baseline_id, checkpoint_date, retained_at) VALUES (?, ?, ?)",
      )
      .run(stored.sourcePins.cveRevision, stored.checkpointDate, new Date().toISOString());
  });
  return stored;
}

interface CheckpointRow {
  checkpoint_date: string;
  observed_at: string;
  cve_revision: string;
  kev_catalog_date: string;
  epss_score_date: string;
  epss_model_version: string;
  cohort_id: string;
  cohort_count: number;
  policy_version: string;
  materialized_results_json: string;
  manifest_hash: string | null;
}

function parseStoredRow(row: CheckpointRow): StoredRadarCheckpoint {
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.materialized_results_json) as unknown;
  } catch {
    throw new Error(
      `Radar checkpoint for ${row.checkpoint_date} has a corrupt materialized payload; refusing to replay it.`,
    );
  }
  const body = (parsed ?? {}) as {
    cutoffT?: unknown;
    views?: unknown;
    items?: unknown;
  };
  if (typeof body.cutoffT !== "string" || typeof body.views !== "object" || body.views === null) {
    throw new Error(
      `Radar checkpoint for ${row.checkpoint_date} has a corrupt materialized payload; refusing to replay it.`,
    );
  }
  const views = body.views as RadarViews;
  for (const key of ["defaultPriority", "knownExploited", "highestForecast", "newCritical", "risingForecast"] as const) {
    if (!Array.isArray(views[key])) {
      throw new Error(
        `Radar checkpoint for ${row.checkpoint_date} has a corrupt materialized payload; refusing to replay it.`,
      );
    }
  }
  const items = (body.items ?? {}) as Record<string, RadarItemSnapshot>;
  return {
    checkpointDate: row.checkpoint_date,
    observedAt: row.observed_at,
    sourcePins: {
      cveRevision: row.cve_revision,
      kevCatalogDate: row.kev_catalog_date,
      epssScoreDate: row.epss_score_date,
      epssModelVersion: row.epss_model_version,
    },
    cohortId: row.cohort_id,
    cohortCount: row.cohort_count,
    policyVersion: row.policy_version,
    cutoffT: body.cutoffT,
    views: {
      defaultPriority: [...views.defaultPriority],
      knownExploited: [...views.knownExploited],
      highestForecast: [...views.highestForecast],
      newCritical: [...views.newCritical],
      risingForecast: [...views.risingForecast],
    },
    items: { ...items },
    manifestHash: row.manifest_hash ?? "",
  };
}

/** Reads one retained checkpoint, or undefined when no checkpoint exists for the date. */
export function readCheckpoint(db: CveDatabase, checkpointDate: string): StoredRadarCheckpoint | undefined {
  const row = db.handle
    .prepare("SELECT * FROM checkpoints WHERE checkpoint_date = ?")
    .get(checkpointDate) as CheckpointRow | undefined;
  if (row === undefined) return undefined;
  return parseStoredRow(row);
}

/** Lists retained checkpoints in ascending date order. */
export function listCheckpoints(db: CveDatabase): StoredRadarCheckpoint[] {
  const rows = db.handle
    .prepare("SELECT * FROM checkpoints ORDER BY checkpoint_date ASC")
    .all() as CheckpointRow[];
  return rows.map((row) => parseStoredRow(row));
}

/** Earliest retained checkpoint date, or null when no checkpoint has been observed. */
export function launchDay(db: CveDatabase): string | null {
  const row = db.handle
    .prepare("SELECT MIN(checkpoint_date) AS launch_day FROM checkpoints")
    .get() as { launch_day: string | null };
  return row.launch_day;
}

/** Reference-counted baseline retention: the baseline survives while a holder needs it. */
export function isBaselineRetained(db: CveDatabase, baselineId: string): boolean {
  const row = db.handle
    .prepare("SELECT COUNT(*) AS n FROM checkpoint_baseline_refs WHERE baseline_id = ?")
    .get(baselineId) as { n: number };
  return row.n > 0;
}

export function releaseBaseline(db: CveDatabase, baselineId: string, checkpointDate: string): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare("DELETE FROM checkpoint_baseline_refs WHERE baseline_id = ? AND checkpoint_date = ?")
      .run(baselineId, checkpointDate);
  });
}

/** True when the checkpoint age in UTC days exceeds the retention window. */
export function isCheckpointExpired(
  checkpointDate: string,
  asOfDate: string,
  retentionDays: number = RADAR_RETENTION_DAYS,
): boolean {
  if (!isValidDay(checkpointDate) || !isValidDay(asOfDate)) return false;
  const ageDays =
    (Date.parse(`${asOfDate}T00:00:00.000Z`) - Date.parse(`${checkpointDate}T00:00:00.000Z`)) /
    86_400_000;
  return ageDays > retentionDays;
}

/**
 * Deletes checkpoints older than the retention window. Baseline references
 * attached to pruned checkpoints cascade away; baselines still referenced by
 * retained checkpoints survive. Returns the pruned dates in ascending order.
 */
export function pruneExpiredCheckpoints(
  db: CveDatabase,
  asOfDate: string,
  retentionDays: number = RADAR_RETENTION_DAYS,
): string[] {
  const expired = listCheckpoints(db)
    .filter((row) => isCheckpointExpired(row.checkpointDate, asOfDate, retentionDays))
    .map((row) => row.checkpointDate);
  for (const checkpointDate of expired) {
    db.runBoundedWrite(() => {
      db.handle
        .prepare("DELETE FROM checkpoints WHERE checkpoint_date = ?")
        .run(checkpointDate);
    });
  }
  return expired;
}

function manifestValidationError(manifest: StoredRadarCheckpoint): string | null {
  const published = Object.values(manifest.items).filter((item) => item.state === "PUBLISHED");
  if (published.length !== manifest.cohortCount) {
    return (
      `stored manifest fails validation: cohort count ${manifest.cohortCount} disagrees ` +
      `with ${published.length} retained PUBLISHED items`
    );
  }
  const { manifestHash: _ignored, ...core } = manifest;
  void _ignored;
  const recomputed = sha256Hex(canonicalManifestJson(core));
  if (recomputed !== manifest.manifestHash) {
    return "stored manifest fails validation: manifest hash disagrees with retained payload";
  }
  return null;
}

/**
 * Reproduces the retained materialized results for a checkpoint, or fails
 * with an explicit unavailable reason. Reads only the checkpoints tables;
 * current CVE/KEV/EPSS tables are never consulted, so current data can
 * neither leak into replay nor stand in for a missing baseline.
 */
export function replayCheckpoint(
  db: CveDatabase,
  checkpointDate: string,
  options: ReplayOptions,
): ReplayResult {
  const retentionDays = options.retentionDays ?? RADAR_RETENTION_DAYS;
  const launch = launchDay(db);
  if (launch === null) {
    return {
      status: "unavailable",
      reason: "no checkpoints retained; missing days are ineligible, never interpolated",
    };
  }
  if (checkpointDate < launch) {
    return {
      status: "unavailable",
      reason: `pre-launch: no checkpoint exists before initial operation on ${launch}; history is never backfilled`,
    };
  }
  const manifest = readCheckpoint(db, checkpointDate);
  if (manifest === undefined) {
    return {
      status: "unavailable",
      reason: `no checkpoint retained for ${checkpointDate}; missing days are ineligible, never interpolated`,
    };
  }
  if (isCheckpointExpired(checkpointDate, options.asOfDate, retentionDays)) {
    return {
      status: "unavailable",
      reason: `checkpoint ${checkpointDate} expired after ${retentionDays} days; historical access removed, current data never used as a replacement`,
    };
  }
  if (
    options.expectedModelVersion !== undefined &&
    manifest.sourcePins.epssModelVersion !== options.expectedModelVersion
  ) {
    return {
      status: "unavailable",
      reason:
        `model-changed: checkpoint uses ${manifest.sourcePins.epssModelVersion}, ` +
        `replay requires ${options.expectedModelVersion}; cross-model comparisons are ineligible`,
    };
  }
  if (!isBaselineRetained(db, manifest.sourcePins.cveRevision)) {
    return {
      status: "unavailable",
      reason: `referenced baseline ${manifest.sourcePins.cveRevision} no longer retained; replay refuses rather than reading current data`,
    };
  }
  const invalid = manifestValidationError(manifest);
  if (invalid !== null) {
    return { status: "unavailable", reason: invalid };
  }
  return { status: "available", manifest, results: manifest.views };
}

function rankMap(ids: readonly string[]): Map<string, number> {
  const ranks = new Map<string, number>();
  ids.forEach((id, index) => {
    if (!ranks.has(id)) ranks.set(id, index);
  });
  return ranks;
}

function primaryText(item: RadarItemSnapshot): string {
  if (item.primaryVersion === null) return "unknown";
  return `${item.primaryVersion} ${item.primaryBaseScore ?? "unknown"} ${item.primaryVector ?? ""}`.trim();
}

function epssText(value: string | null): string {
  return value ?? "unknown";
}

/**
 * Compares two retained manifests. Source changes name the observed
 * before/after values; rank-only movement is reported only when no source
 * signal changed, so a reorder is never presented as a source change.
 */
export function diffCheckpoints(
  before: StoredRadarCheckpoint,
  after: StoredRadarCheckpoint,
): RadarDiff {
  const beforeRanks = rankMap(before.views.defaultPriority);
  const afterRanks = rankMap(after.views.defaultPriority);
  const cveIds = new Set([...Object.keys(before.items), ...Object.keys(after.items)]);
  const itemChanges: RadarItemChange[] = [];

  for (const cveId of [...cveIds].sort()) {
    const previous = before.items[cveId];
    const current = after.items[cveId];
    const beforeRank = beforeRanks.get(cveId) ?? null;
    const afterRank = afterRanks.get(cveId) ?? null;
    if (previous === undefined && current !== undefined) {
      itemChanges.push({
        cveId,
        kinds: ["added"],
        beforeRank,
        afterRank,
        detail: `first observed in checkpoint ${after.checkpointDate}`,
      });
      continue;
    }
    if (previous !== undefined && current === undefined) {
      itemChanges.push({
        cveId,
        kinds: ["removed"],
        beforeRank,
        afterRank,
        detail: `absent from checkpoint ${after.checkpointDate}; deleted or moved out of the retained corpus`,
      });
      continue;
    }
    if (previous === undefined || current === undefined) continue;
    const kinds: RadarChangeKind[] = [];
    const notes: string[] = [];
    if (previous.state === "PUBLISHED" && current.state === "REJECTED") {
      kinds.push("rejected");
      notes.push("state moved from PUBLISHED to REJECTED");
    } else if (previous.state === "REJECTED" && current.state === "PUBLISHED") {
      kinds.push("corrected");
      notes.push("state returned from REJECTED to PUBLISHED");
    }
    if (!previous.kevMember && current.kevMember) {
      kinds.push("kev-added");
      notes.push(`KEV membership added (catalog date ${current.dateAdded ?? "unknown"})`);
    } else if (previous.kevMember && !current.kevMember) {
      kinds.push("kev-removed");
      notes.push("KEV membership removed (absent from the new catalog)");
    }
    if (
      previous.primaryVersion !== current.primaryVersion ||
      previous.primaryBaseScore !== current.primaryBaseScore ||
      previous.primaryVector !== current.primaryVector
    ) {
      kinds.push("cna-changed");
      notes.push(`primary CNA metric moved from ${primaryText(previous)} to ${primaryText(current)}`);
    }
    if (
      previous.epssModel !== null &&
      current.epssModel !== null &&
      previous.epssModel !== current.epssModel
    ) {
      kinds.push("model-changed");
      notes.push(
        `EPSS model moved from ${previous.epssModel} to ${current.epssModel}; values not compared across models`,
      );
    } else if (previous.epss !== current.epss) {
      kinds.push("forecast-changed");
      notes.push(
        `forecast moved from ${epssText(previous.epss)} to ${epssText(current.epss)} ` +
          `(model ${current.epssModel ?? previous.epssModel ?? "unknown"})`,
      );
    }
    if (
      kinds.length === 0 &&
      (previous.descriptionHash !== current.descriptionHash ||
        previous.dateUpdated !== current.dateUpdated ||
        previous.publishedAt !== current.publishedAt)
    ) {
      kinds.push("corrected");
      notes.push("record corrected (description or dates changed); severity and signals unchanged");
    }
    if (kinds.length === 0 && beforeRank !== null && afterRank !== null && beforeRank !== afterRank) {
      kinds.push("rank-only-move");
      notes.push(`rank moved from ${beforeRank} to ${afterRank} with unchanged source signals`);
    }
    if (kinds.length > 0) {
      itemChanges.push({ cveId, kinds, beforeRank, afterRank, detail: notes.join("; ") });
    }
  }

  const sourceChanges = itemChanges.filter((row) => row.kinds.some((kind) => SOURCE_KINDS.has(kind)));
  return {
    beforeDate: before.checkpointDate,
    afterDate: after.checkpointDate,
    policyChanged: before.policyVersion !== after.policyVersion,
    cohortChanged: before.cohortId !== after.cohortId,
    windowChanged:
      before.cutoffT !== after.cutoffT ||
      before.sourcePins.epssScoreDate !== after.sourcePins.epssScoreDate,
    itemChanges,
    summary: {
      sourceChanges: sourceChanges.length,
      rankOnlyMoves: itemChanges.filter(
        (row) => row.kinds.length === 1 && row.kinds[0] === "rank-only-move",
      ).length,
      added: itemChanges.filter((row) => row.kinds.includes("added")).length,
      removed: itemChanges.filter((row) => row.kinds.includes("removed")).length,
    },
  };
}
