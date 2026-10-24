// Retention/replay contract stub types for TDD todo 6.
//
// Fixture-driven in-memory stubs only. There is no database, no network, and
// no real replay logic here: resolveReplay echoes the checkpoint's own
// materialized results after eligibility checks, and every ineligible case
// returns an explicit unavailable reason. Real replay (todo 12) must
// reproduce results from retained baselines plus the pinned policy
// implementation; it must never substitute current data.

export interface SourcePins {
  cveRevision: string;
  kevCatalogDate: string;
  epssScoreDate: string;
  epssModelVersion: string;
}

export interface CheckpointCohort {
  id: string;
  count: number;
}

export interface CheckpointManifest {
  checkpointDate: string;
  observedAt: string;
  sourcePins: SourcePins;
  cohort: CheckpointCohort;
  policyVersion: string;
  materializedResults: readonly string[];
}

export type ManifestCheck = { complete: true } | { complete: false; reason: string };

export type ReplayResult =
  | { status: "available"; results: readonly string[] }
  | { status: "unavailable"; reason: string };

export interface ReplayOptions {
  asOfDate: string;
  currentData?: readonly string[];
  expectedModelVersion?: string;
}

export interface StubStoreOptions {
  launchDay: string;
  retentionDays: number;
}

function utcDay(s: string): number {
  return Date.parse(`${s}T00:00:00.000Z`);
}

function observedUtcDay(iso: string): string {
  return new Date(iso).toISOString().slice(0, 10);
}

export function checkManifestComplete(manifest: CheckpointManifest): ManifestCheck {
  if (manifest.policyVersion === "") {
    return { complete: false, reason: "manifest missing ranking policy version" };
  }
  if (observedUtcDay(manifest.observedAt) !== manifest.checkpointDate) {
    return {
      complete: false,
      reason: `observed timestamp ${manifest.observedAt} falls outside checkpoint date ${manifest.checkpointDate}; never invent a midnight capture`,
    };
  }
  if (manifest.cohort.count !== manifest.materializedResults.length) {
    return {
      complete: false,
      reason: `cohort count ${manifest.cohort.count} disagrees with materialized result length ${manifest.materializedResults.length}`,
    };
  }
  const pins = manifest.sourcePins;
  if (
    pins.cveRevision === "" ||
    pins.kevCatalogDate === "" ||
    pins.epssScoreDate === "" ||
    pins.epssModelVersion === ""
  ) {
    return { complete: false, reason: "manifest missing source revision/date pins" };
  }
  return { complete: true };
}

export class StubBaselineRegistry {
  private refs = new Map<string, Set<string>>();

  retain(baselineId: string, checkpointDate: string): void {
    const holders = this.refs.get(baselineId) ?? new Set<string>();
    holders.add(checkpointDate);
    this.refs.set(baselineId, holders);
  }

  release(baselineId: string, checkpointDate: string): void {
    const holders = this.refs.get(baselineId);
    if (holders === undefined) {
      return;
    }
    holders.delete(checkpointDate);
    if (holders.size === 0) {
      this.refs.delete(baselineId);
    }
  }

  isRetained(baselineId: string): boolean {
    return this.refs.has(baselineId);
  }
}

export class StubCheckpointStore {
  private checkpoints = new Map<string, CheckpointManifest>();

  constructor(private readonly options: StubStoreOptions) {}

  save(manifest: CheckpointManifest): void {
    this.checkpoints.set(manifest.checkpointDate, manifest);
  }

  get(checkpointDate: string): CheckpointManifest | undefined {
    return this.checkpoints.get(checkpointDate);
  }

  isExpired(checkpointDate: string, asOfDate: string): boolean {
    const ageDays = (utcDay(asOfDate) - utcDay(checkpointDate)) / 86_400_000;
    return ageDays > this.options.retentionDays;
  }

  get launchDay(): string {
    return this.options.launchDay;
  }
}

export function resolveReplay(
  store: StubCheckpointStore,
  checkpointDate: string,
  options: ReplayOptions,
): ReplayResult {
  const manifest = store.get(checkpointDate);
  if (manifest === undefined) {
    if (checkpointDate < store.launchDay) {
      return {
        status: "unavailable",
        reason: `pre-launch: no checkpoint exists before initial operation on ${store.launchDay}; history is never backfilled`,
      };
    }
    return {
      status: "unavailable",
      reason: `no checkpoint retained for ${checkpointDate}; missing days are ineligible, never interpolated or substituted`,
    };
  }
  if (store.isExpired(checkpointDate, options.asOfDate)) {
    return {
      status: "unavailable",
      reason: `checkpoint ${checkpointDate} expired; historical access removed, current data never substituted`,
    };
  }
  if (
    options.expectedModelVersion !== undefined &&
    manifest.sourcePins.epssModelVersion !== options.expectedModelVersion
  ) {
    return {
      status: "unavailable",
      reason: `model-changed: checkpoint uses ${manifest.sourcePins.epssModelVersion}, comparison requires ${options.expectedModelVersion}; cross-model deltas are ineligible`,
    };
  }
  if (manifest.cohort.count !== manifest.materializedResults.length) {
    return {
      status: "unavailable",
      reason: "cohort/materialized mismatch: reconstructed results fail validation",
    };
  }
  return { status: "available", results: manifest.materializedResults };
}
