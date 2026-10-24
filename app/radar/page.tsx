import { RadarFeed } from "@/components/radar/RadarFeed";
import {
  RADAR_CHECKPOINTS,
  type RadarFieldRow,
  type RadarUiDay,
  type RadarUiEvent,
  type RadarUiKind,
} from "@/components/radar/radar-fixtures";
import { diffCheckpoints, type RadarChangeKind, type RadarItemSnapshot } from "@/lib/radar";

export const metadata = {
  title: "Change Radar — Evidence Ledger",
  description:
    "What changed between retained daily CVE snapshots, with before/after evidence for every entry.",
};

const KIND_PRIORITY: RadarUiKind[] = [
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

function mapKind(kind: RadarChangeKind): RadarUiKind {
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
}

function primaryText(snapshot: RadarItemSnapshot | undefined): string | null {
  if (snapshot === undefined || snapshot === null) return null;
  if (snapshot.primaryVersion === null) return "unknown";
  return `${snapshot.primaryVersion} ${snapshot.primaryBaseScore ?? "unknown"} ${snapshot.primaryVector ?? ""}`.trim();
}

function rankPosition(rank: number | null): string {
  return rank === null ? "not listed" : `#${String(rank + 1)}`;
}

function kindFields(
  kind: RadarUiKind,
  before: RadarItemSnapshot | undefined,
  after: RadarItemSnapshot | undefined,
  beforeRank: number | null,
  afterRank: number | null,
): RadarFieldRow[] {
  switch (kind) {
    case "kev-added":
      return [
        { field: "kev.listed", before: "false", after: "true", change: "changed" },
        { field: "kev.dateAdded", before: null, after: after?.dateAdded ?? null, change: "added" },
      ];
    case "kev-removed":
      return [
        { field: "kev.listed", before: "true", after: "false", change: "changed" },
        {
          field: "kev.dateAdded",
          before: before?.dateAdded ?? null,
          after: null,
          change: "removed",
        },
      ];
    case "cna-changed":
      return [
        {
          field: "cna.primary",
          before: primaryText(before),
          after: primaryText(after),
          change: "changed",
        },
      ];
    case "forecast-changed":
      return [
        {
          field: "epss.value",
          before: before?.epss ?? null,
          after: after?.epss ?? null,
          change: before?.epss == null || after?.epss == null ? "unknown" : "changed",
        },
        {
          field: "epss.model",
          before: before?.epssModel ?? null,
          after: after?.epssModel ?? null,
          change: before?.epssModel === after?.epssModel ? "unchanged" : "changed",
        },
      ];
    case "corrected":
      return [
        {
          field: "record.state",
          before: before?.state ?? null,
          after: after?.state ?? null,
          change: before?.state === after?.state ? "unchanged" : "changed",
        },
        {
          field: "record.dateUpdated",
          before: before?.dateUpdated ?? null,
          after: after?.dateUpdated ?? null,
          change: before?.dateUpdated === after?.dateUpdated ? "unchanged" : "changed",
        },
      ];
    case "rejected":
      return [
        {
          field: "record.state",
          before: before?.state ?? null,
          after: after?.state ?? null,
          change: "changed",
        },
      ];
    case "list-entered":
      return [
        {
          field: "record.firstSeen",
          before: null,
          after: after?.publishedAt ?? null,
          change: "added",
        },
      ];
    case "list-exited":
      return [
        {
          field: "record.lastSeen",
          before: before?.publishedAt ?? null,
          after: null,
          change: "removed",
        },
      ];
    case "rank-moved":
      return [
        {
          field: "defaultPriority.position",
          before: rankPosition(beforeRank),
          after: rankPosition(afterRank),
          change: "changed",
        },
      ];
  }
}

function revisionLabel(pins: {
  cveRevision: string;
  kevCatalogDate: string;
  epssScoreDate: string;
  epssModelVersion: string;
}): string {
  return `CVE ${pins.cveRevision}, KEV ${pins.kevCatalogDate}, EPSS ${pins.epssScoreDate} ${pins.epssModelVersion}`;
}

function sourceRevisionFor(
  kind: RadarUiKind,
  pins: {
    cveRevision: string;
    kevCatalogDate: string;
    epssScoreDate: string;
    epssModelVersion: string;
  },
  policyVersion: string,
): string {
  switch (kind) {
    case "kev-added":
    case "kev-removed":
      return `KEV catalog ${pins.kevCatalogDate}`;
    case "forecast-changed":
      return `EPSS ${pins.epssScoreDate} model ${pins.epssModelVersion}`;
    case "rank-moved":
      return `ranking policy ${policyVersion}`;
    default:
      return `CVE revision ${pins.cveRevision}`;
  }
}

function buildDays(): RadarUiDay[] {
  const days: RadarUiDay[] = [];
  for (let index = 1; index < RADAR_CHECKPOINTS.length; index += 1) {
    const before = RADAR_CHECKPOINTS[index - 1];
    const after = RADAR_CHECKPOINTS[index];
    if (before === undefined || after === undefined) continue;
    const diff = diffCheckpoints(before, after);
    const events: RadarUiEvent[] = [];
    let seq = 0;
    for (const change of diff.itemChanges) {
      const mapped = KIND_PRIORITY.filter((kind) =>
        change.kinds.some((service) => mapKind(service) === kind),
      );
      for (const kind of mapped) {
        seq += 1;
        events.push({
          eventId: `radar-${after.checkpointDate}-${String(seq).padStart(4, "0")}`,
          kind,
          cveId: change.cveId,
          beforeRank: change.beforeRank,
          afterRank: change.afterRank,
          detail: change.detail,
          fields: kindFields(
            kind,
            before.items[change.cveId],
            after.items[change.cveId],
            change.beforeRank,
            change.afterRank,
          ),
          sourceRevision: sourceRevisionFor(kind, after.sourcePins, after.policyVersion),
        });
      }
    }
    events.sort((a, b) => (a.eventId < b.eventId ? 1 : -1));
    days.push({
      beforeDate: diff.beforeDate,
      afterDate: diff.afterDate,
      beforeObservedAt: before.observedAt,
      afterObservedAt: after.observedAt,
      beforeRevisionLabel: revisionLabel(before.sourcePins),
      afterRevisionLabel: revisionLabel(after.sourcePins),
      policyChanged: diff.policyChanged,
      cohortChanged: diff.cohortChanged,
      windowChanged: diff.windowChanged,
      cohortBefore: before.cohortCount,
      cohortAfter: after.cohortCount,
      events,
    });
  }
  return days;
}

export default function RadarPage() {
  return <RadarFeed days={buildDays()} />;
}
