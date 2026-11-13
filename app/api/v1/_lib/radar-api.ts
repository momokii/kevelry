import {
  diffCheckpoints,
  type RadarChangeKind,
  type RadarItemSnapshot,
  type StoredRadarCheckpoint,
} from "../../../../src/lib/radar";
import { officialCveLink } from "../../../../src/lib/search";
import { ApiError } from "./errors";
import { CVE_ID_RE } from "./params";
import type { ApiCoverage } from "./records";

export type RadarApiKind =
  | "kev-added"
  | "kev-removed"
  | "cna-changed"
  | "forecast-changed"
  | "corrected"
  | "rejected"
  | "list-entered"
  | "list-exited"
  | "rank-moved";

export const RADAR_API_KINDS: readonly RadarApiKind[] = [
  "kev-added",
  "kev-removed",
  "cna-changed",
  "forecast-changed",
  "corrected",
  "rejected",
  "list-entered",
  "list-exited",
  "rank-moved",
];

export interface RadarApiEvent {
  eventId: string;
  checkpointDate: string;
  observedAt: string;
  kind: RadarApiKind;
  cveId: string;
  title: string;
  changes: Array<{ field: string; before: string | null; after: string | null }>;
  sourceRevision: string;
  reason: string;
}

const KIND_PRIORITY: readonly RadarApiKind[] = [
  "kev-added",
  "kev-removed",
  "cna-changed",
  "forecast-changed",
  "corrected",
  "rejected",
  "list-entered",
  "list-exited",
  "rank-moved",
];

function mapServiceKinds(kinds: readonly RadarChangeKind[]): RadarApiKind[] {
  const mapped = kinds.map((kind): RadarApiKind => {
    switch (kind) {
      case "kev-added":
        return "kev-added";
      case "kev-removed":
        return "kev-removed";
      case "cna-changed":
        return "cna-changed";
      case "forecast-changed":
        return "forecast-changed";
      case "model-changed":
        return "forecast-changed";
      case "corrected":
        return "corrected";
      case "rejected":
        return "rejected";
      case "added":
        return "list-entered";
      case "removed":
        return "list-exited";
      case "rank-only-move":
        return "rank-moved";
    }
  });
  const seen = new Set<RadarApiKind>();
  const ordered: RadarApiKind[] = [];
  for (const kind of KIND_PRIORITY) {
    if (mapped.includes(kind) && !seen.has(kind)) {
      seen.add(kind);
      ordered.push(kind);
    }
  }
  return ordered;
}

function snapshotPrimaryText(item: RadarItemSnapshot): string {
  if (item.primaryVersion === null) return "unknown";
  return `${item.primaryVersion} ${item.primaryBaseScore ?? "unknown"} ${item.primaryVector ?? ""}`.trim();
}

function kindChanges(
  kind: RadarApiKind,
  before: RadarItemSnapshot | undefined,
  after: RadarItemSnapshot | undefined,
): Array<{ field: string; before: string | null; after: string | null }> {
  switch (kind) {
    case "kev-added":
      return [
        { field: "kev.listed", before: "false", after: "true" },
        { field: "kev.dateAdded", before: null, after: after?.dateAdded ?? null },
      ];
    case "kev-removed":
      return [
        { field: "kev.listed", before: "true", after: "false" },
        { field: "kev.dateAdded", before: before?.dateAdded ?? null, after: null },
      ];
    case "cna-changed":
      return [
        {
          field: "cna.primary",
          before: before === undefined ? null : snapshotPrimaryText(before),
          after: after === undefined ? null : snapshotPrimaryText(after),
        },
      ];
    case "forecast-changed":
      return [
        {
          field: "epss.value",
          before: before?.epss ?? null,
          after: after?.epss ?? null,
        },
      ];
    case "corrected":
      return [
        {
          field: "record.state",
          before: before?.state ?? null,
          after: after?.state ?? null,
        },
      ];
    case "rejected":
      return [
        {
          field: "record.state",
          before: before?.state ?? null,
          after: after?.state ?? null,
        },
      ];
    case "list-entered":
      return [{ field: "record.firstSeen", before: null, after: after?.publishedAt ?? null }];
    case "list-exited":
      return [{ field: "record.lastSeen", before: before?.publishedAt ?? null, after: null }];
    case "rank-moved":
      return [];
  }
}

function kindSourceRevision(kind: RadarApiKind, after: StoredRadarCheckpoint): string {
  switch (kind) {
    case "kev-added":
    case "kev-removed":
      return `kev-${after.sourcePins.kevCatalogDate}`;
    case "forecast-changed":
      return `epss-${after.sourcePins.epssScoreDate}`;
    case "rank-moved":
      return `ranking-${after.policyVersion}`;
    default:
      return `cve-${after.sourcePins.cveRevision}`;
  }
}

export function buildRadarEvents(checkpoints: readonly StoredRadarCheckpoint[]): RadarApiEvent[] {
  const events: RadarApiEvent[] = [];
  let seq = 0;
  for (let index = 1; index < checkpoints.length; index += 1) {
    const before = checkpoints[index - 1];
    const after = checkpoints[index];
    if (before === undefined || after === undefined) continue;
    const diff = diffCheckpoints(before, after);
    for (const change of diff.itemChanges) {
      for (const kind of mapServiceKinds(change.kinds)) {
        seq += 1;
        events.push({
          eventId: `radar-${after.checkpointDate}-${String(seq).padStart(4, "0")}`,
          checkpointDate: after.checkpointDate,
          observedAt: after.observedAt,
          kind,
          cveId: change.cveId,
          title: change.cveId,
          changes: kindChanges(kind, before.items[change.cveId], after.items[change.cveId]),
          sourceRevision: kindSourceRevision(kind, after),
          reason: change.detail,
        });
      }
    }
  }
  events.sort((a, b) => {
    if (a.checkpointDate !== b.checkpointDate) return a.checkpointDate < b.checkpointDate ? 1 : -1;
    return a.eventId < b.eventId ? 1 : -1;
  });
  return events;
}

export function parseRadarKind(raw: string | null): RadarApiKind | null {
  if (raw === null || raw === "") return null;
  if (!(RADAR_API_KINDS as readonly string[]).includes(raw)) {
    throw new ApiError("BAD_FILTER", 400, `kind must be one of ${RADAR_API_KINDS.join(", ")}.`);
  }
  return raw as RadarApiKind;
}

export function parseCveIdParam(raw: string | null): string | null {
  if (raw === null || raw === "") return null;
  if (!CVE_ID_RE.test(raw)) {
    throw new ApiError("BAD_FILTER", 400, "cveId must look like CVE-YYYY-NNNN+.");
  }
  return raw;
}

export function mapReplayReason(reason: string): string {
  const lowered = reason.toLowerCase();
  if (lowered.includes("expired")) return "expired";
  if (lowered.includes("model-changed")) return "model-changed";
  if (lowered.includes("pre-launch")) return "pre-launch";
  if (lowered.includes("no checkpoint retained")) return "missing-day";
  if (lowered.includes("baseline") && lowered.includes("no longer retained"))
    return "baseline-released";
  if (lowered.includes("validation") || lowered.includes("corrupt") || lowered.includes("tamper")) {
    return "invalid-manifest";
  }
  return "unavailable";
}

export function toReplayItem(
  cveId: string,
  snapshot: RadarItemSnapshot,
  pins: StoredRadarCheckpoint["sourcePins"],
): Record<string, unknown> {
  const epss =
    snapshot.epss === null
      ? { status: "unknown", value: null, percentile: null, scoreDate: null, modelVersion: null }
      : {
          status: "known",
          value: Number(snapshot.epss),
          percentile: null,
          scoreDate: pins.epssScoreDate,
          modelVersion: snapshot.epssModel ?? pins.epssModelVersion,
        };
  const cvssPrimary =
    snapshot.primaryVersion === null
      ? { status: "unknown", source: null, version: null, baseScore: null, vector: null }
      : snapshot.primaryVersion === "2.0"
        ? {
            status: "legacy",
            source: "cna",
            version: snapshot.primaryVersion,
            baseScore:
              snapshot.primaryBaseScore === null ? null : Number(snapshot.primaryBaseScore),
            vector: snapshot.primaryVector,
          }
        : {
            status: "known",
            source: "cna",
            version: snapshot.primaryVersion,
            baseScore:
              snapshot.primaryBaseScore === null ? null : Number(snapshot.primaryBaseScore),
            vector: snapshot.primaryVector,
          };
  return {
    cveId,
    title: cveId,
    state: snapshot.state,
    publishedAt: snapshot.publishedAt,
    officialUrl: officialCveLink(cveId),
    excerpt: null,
    excerptTruncated: false,
    excerptLanguage: null,
    excerptStatus: "not-supplied",
    kev: { listed: snapshot.kevMember, dateAdded: snapshot.dateAdded },
    epss,
    cvssPrimary,
  };
}

export function coverageForSnapshots(
  ids: readonly string[],
  snapshots: Record<string, RadarItemSnapshot>,
  returned: number,
): ApiCoverage {
  let unscored = 0;
  let unknownEpss = 0;
  let unknownDate = 0;
  for (const id of ids) {
    const item = snapshots[id];
    if (item === undefined) continue;
    if (item.primaryVersion === null) unscored += 1;
    if (item.epss === null) unknownEpss += 1;
    if (item.publishedAt === null) unknownDate += 1;
  }
  return { eligibleCohort: ids.length, returned, unscored, unknownEpss, unknownDate };
}
