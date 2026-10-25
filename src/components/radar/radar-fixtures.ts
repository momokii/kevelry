import type { RadarItemSnapshot, StoredRadarCheckpoint } from "@/lib/radar";

// Retained-snapshot fixtures for the Radar feed (route /radar).
//
// Three daily observed checkpoints: 2026-10-23, 2026-10-24 (source changes),
// and 2026-10-25 (byte-identical items and ordering to 2026-10-24, so the
// detector reports a quiet day instead of fabricated activity). CVE IDs are
// invented CVE-2099 fixtures; nothing here touches the network. The page
// diffs these snapshots with the real diffCheckpoints service, so the feed
// labels come from retained observations, never from current data.

const MODEL = "v2026.06.15";

function item(
  overrides: Partial<RadarItemSnapshot> & { descriptionHash: string },
): RadarItemSnapshot {
  return {
    state: "PUBLISHED",
    kevMember: false,
    dateAdded: null,
    epss: null,
    epssModel: null,
    primaryVersion: null,
    primaryBaseScore: null,
    primaryVector: null,
    publishedAt: null,
    dateUpdated: null,
    ...overrides,
  };
}

const DAY_ONE_ITEMS: Record<string, RadarItemSnapshot> = {
  "CVE-2099-0001": item({
    kevMember: false,
    epss: "0.1200",
    epssModel: MODEL,
    primaryVersion: "3.1",
    primaryBaseScore: "7.5",
    primaryVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    publishedAt: "2026-10-10",
    dateUpdated: "2026-10-20",
    descriptionHash: "fixture-h1a",
  }),
  "CVE-2099-0002": item({
    epss: "0.0510",
    epssModel: MODEL,
    primaryVersion: "3.1",
    primaryBaseScore: "8.2",
    primaryVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    publishedAt: "2026-09-28",
    dateUpdated: "2026-10-19",
    descriptionHash: "fixture-h2a",
  }),
  "CVE-2099-0003": item({
    epss: "0.0410",
    epssModel: MODEL,
    primaryVersion: "4.0",
    primaryBaseScore: "6.9",
    primaryVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N",
    publishedAt: "2026-10-05",
    dateUpdated: "2026-10-18",
    descriptionHash: "fixture-h3a",
  }),
  "CVE-2099-0004": item({
    epss: "0.0020",
    epssModel: MODEL,
    primaryVersion: "3.1",
    primaryBaseScore: "5.4",
    primaryVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
    publishedAt: "2026-10-01",
    dateUpdated: "2026-10-15",
    descriptionHash: "fixture-h4a",
  }),
  "CVE-2099-0005": item({
    epss: "0.0080",
    epssModel: MODEL,
    primaryVersion: "3.1",
    primaryBaseScore: "6.1",
    primaryVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
    publishedAt: "2026-09-20",
    dateUpdated: "2026-10-12",
    descriptionHash: "fixture-h5a",
  }),
  "CVE-2099-0006": item({
    epss: "0.0150",
    epssModel: MODEL,
    primaryVersion: "3.1",
    primaryBaseScore: "4.3",
    primaryVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    publishedAt: "2026-10-11",
    dateUpdated: "2026-10-21",
    descriptionHash: "fixture-h6",
  }),
  "CVE-2099-0008": item({
    epss: "0.0030",
    epssModel: MODEL,
    primaryVersion: "3.1",
    primaryBaseScore: "3.7",
    primaryVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    publishedAt: "2026-09-30",
    dateUpdated: "2026-10-14",
    descriptionHash: "fixture-h8a",
  }),
  "CVE-2099-0009": item({
    kevMember: true,
    dateAdded: "2026-10-18",
    epss: "0.3100",
    epssModel: MODEL,
    primaryVersion: "3.1",
    primaryBaseScore: "9.1",
    primaryVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    publishedAt: "2026-09-15",
    dateUpdated: "2026-10-19",
    descriptionHash: "fixture-h9a",
  }),
};

function cloneItems(source: Record<string, RadarItemSnapshot>): Record<string, RadarItemSnapshot> {
  const out: Record<string, RadarItemSnapshot> = {};
  for (const [cveId, snapshot] of Object.entries(source)) {
    out[cveId] = { ...snapshot };
  }
  return out;
}

const DAY_TWO_ITEMS: Record<string, RadarItemSnapshot> = cloneItems(DAY_ONE_ITEMS);
// KEV added: listed in the new catalog, nothing else changed.
DAY_TWO_ITEMS["CVE-2099-0001"] = {
  ...DAY_TWO_ITEMS["CVE-2099-0001"],
  kevMember: true,
  dateAdded: "2026-10-24",
} as RadarItemSnapshot;
// CNA changed: primary metric revised by the source.
DAY_TWO_ITEMS["CVE-2099-0002"] = {
  ...DAY_TWO_ITEMS["CVE-2099-0002"],
  primaryBaseScore: "9.8",
  primaryVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
} as RadarItemSnapshot;
// Forecast changed: observed EPSS value moved under the same model.
DAY_TWO_ITEMS["CVE-2099-0003"] = {
  ...DAY_TWO_ITEMS["CVE-2099-0003"],
  epss: "0.1820",
} as RadarItemSnapshot;
// Corrected: description and update date revised, severity and signals unchanged.
DAY_TWO_ITEMS["CVE-2099-0004"] = {
  ...DAY_TWO_ITEMS["CVE-2099-0004"],
  dateUpdated: "2026-10-24",
  descriptionHash: "fixture-h4b",
} as RadarItemSnapshot;
// Rejected: source withdrew the record.
DAY_TWO_ITEMS["CVE-2099-0005"] = {
  ...DAY_TWO_ITEMS["CVE-2099-0005"],
  state: "REJECTED",
} as RadarItemSnapshot;
// List entered: first observed in this checkpoint.
DAY_TWO_ITEMS["CVE-2099-0007"] = item({
  epss: "0.0060",
  epssModel: MODEL,
  primaryVersion: "3.1",
  primaryBaseScore: "5.0",
  primaryVector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
  publishedAt: "2026-10-24",
  dateUpdated: "2026-10-24",
  descriptionHash: "fixture-h7a",
});
// List exited: absent from the retained corpus.
delete DAY_TWO_ITEMS["CVE-2099-0008"];
// KEV removed: absent from the new catalog (absence is not proof of no exploitation).
DAY_TWO_ITEMS["CVE-2099-0009"] = {
  ...DAY_TWO_ITEMS["CVE-2099-0009"],
  kevMember: false,
  dateAdded: null,
} as RadarItemSnapshot;
// CVE-2099-0006 is untouched: identical snapshot, rank moves only.

const DAY_ONE_VIEWS = {
  defaultPriority: [
    "CVE-2099-0001",
    "CVE-2099-0002",
    "CVE-2099-0003",
    "CVE-2099-0004",
    "CVE-2099-0006",
    "CVE-2099-0005",
    "CVE-2099-0008",
    "CVE-2099-0009",
  ],
  knownExploited: ["CVE-2099-0009"],
  highestForecast: ["CVE-2099-0009", "CVE-2099-0001"],
  newCritical: [],
  risingForecast: ["CVE-2099-0003"],
};

const DAY_TWO_VIEWS = {
  defaultPriority: [
    "CVE-2099-0002",
    "CVE-2099-0001",
    "CVE-2099-0003",
    "CVE-2099-0006",
    "CVE-2099-0004",
    "CVE-2099-0009",
    "CVE-2099-0005",
    "CVE-2099-0007",
  ],
  knownExploited: ["CVE-2099-0001"],
  highestForecast: ["CVE-2099-0001", "CVE-2099-0003"],
  newCritical: ["CVE-2099-0002"],
  risingForecast: ["CVE-2099-0003"],
};

function makeCheckpoint(args: {
  checkpointDate: string;
  observedAt: string;
  sourcePins: StoredRadarCheckpoint["sourcePins"];
  cutoffT: string;
  cohortId: string;
  cohortCount: number;
  views: StoredRadarCheckpoint["views"];
  items: Record<string, RadarItemSnapshot>;
}): StoredRadarCheckpoint {
  return {
    checkpointDate: args.checkpointDate,
    observedAt: args.observedAt,
    sourcePins: { ...args.sourcePins },
    cohortId: args.cohortId,
    cohortCount: args.cohortCount,
    policyVersion: "v1",
    cutoffT: args.cutoffT,
    boundedTopN: Math.max(
      0,
      args.views.defaultPriority.length,
      args.views.knownExploited.length,
      args.views.highestForecast.length,
      args.views.newCritical.length,
      args.views.risingForecast.length,
    ),
    views: {
      defaultPriority: [...args.views.defaultPriority],
      knownExploited: [...args.views.knownExploited],
      highestForecast: [...args.views.highestForecast],
      newCritical: [...args.views.newCritical],
      risingForecast: [...args.views.risingForecast],
    },
    items: cloneItems(args.items),
    manifestHash: `fixture-retained-${args.checkpointDate}`,
  };
}

export const RADAR_CHECKPOINTS: StoredRadarCheckpoint[] = [
  makeCheckpoint({
    checkpointDate: "2026-10-23",
    observedAt: "2026-10-23T08:00:00.000Z",
    sourcePins: {
      cveRevision: "rev-9f31",
      kevCatalogDate: "2026-10-23T00:00:00.000Z",
      epssScoreDate: "2026-10-23",
      epssModelVersion: MODEL,
    },
    cutoffT: "2026-10-23T08:00:00.000Z",
    cohortId: "published-sha256:fixture-day-one",
    cohortCount: 8,
    views: DAY_ONE_VIEWS,
    items: DAY_ONE_ITEMS,
  }),
  makeCheckpoint({
    checkpointDate: "2026-10-24",
    observedAt: "2026-10-24T08:00:00.000Z",
    sourcePins: {
      cveRevision: "rev-a431",
      kevCatalogDate: "2026-10-24T00:00:00.000Z",
      epssScoreDate: "2026-10-24",
      epssModelVersion: MODEL,
    },
    cutoffT: "2026-10-24T08:00:00.000Z",
    cohortId: "published-sha256:fixture-day-two",
    cohortCount: 7,
    views: DAY_TWO_VIEWS,
    items: DAY_TWO_ITEMS,
  }),
  // Quiet day: items and ordering identical to 2026-10-24, so the detector
  // reports no source changes and the page renders the quiet state.
  makeCheckpoint({
    checkpointDate: "2026-10-25",
    observedAt: "2026-10-25T08:00:00.000Z",
    sourcePins: {
      cveRevision: "rev-a431",
      kevCatalogDate: "2026-10-25T00:00:00.000Z",
      epssScoreDate: "2026-10-25",
      epssModelVersion: MODEL,
    },
    cutoffT: "2026-10-25T08:00:00.000Z",
    cohortId: "published-sha256:fixture-day-two",
    cohortCount: 7,
    views: DAY_TWO_VIEWS,
    items: DAY_TWO_ITEMS,
  }),
];

export type RadarUiKind =
  | "kev-added"
  | "kev-removed"
  | "cna-changed"
  | "forecast-changed"
  | "corrected"
  | "rejected"
  | "list-entered"
  | "list-exited"
  | "rank-moved";

// Text-plus-symbol labels. State is never color alone: every kind carries a
// literal word label and a text symbol prefix.
export const KIND_META: Record<RadarUiKind, { label: string; symbol: string }> = {
  "kev-added": { label: "KEV added", symbol: "[+]" },
  "kev-removed": { label: "KEV removed", symbol: "[-]" },
  "cna-changed": { label: "CNA changed", symbol: "[~]" },
  "forecast-changed": { label: "Forecast changed", symbol: "[~]" },
  corrected: { label: "Corrected", symbol: "[~]" },
  rejected: { label: "Rejected", symbol: "[-]" },
  "list-entered": { label: "List entered", symbol: "[+]" },
  "list-exited": { label: "List exited", symbol: "[-]" },
  "rank-moved": { label: "Rank-only move (no source change)", symbol: "[R]" },
};

export interface RadarFieldRow {
  field: string;
  before: string | null;
  after: string | null;
  change: "unchanged" | "added" | "removed" | "changed" | "unknown";
}

export interface RadarUiEvent {
  eventId: string;
  kind: RadarUiKind;
  cveId: string;
  beforeRank: number | null;
  afterRank: number | null;
  detail: string;
  fields: RadarFieldRow[];
  sourceRevision: string;
}

export interface RadarUiDay {
  beforeDate: string;
  afterDate: string;
  beforeObservedAt: string;
  afterObservedAt: string;
  beforeRevisionLabel: string;
  afterRevisionLabel: string;
  policyChanged: boolean;
  cohortChanged: boolean;
  windowChanged: boolean;
  cohortBefore: number;
  cohortAfter: number;
  events: RadarUiEvent[];
}
