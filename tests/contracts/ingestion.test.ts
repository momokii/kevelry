import { describe, expect, it } from "vitest";

import {
  SUPPORTED_CVE_DATA_VERSIONS,
  type IngestionSourceName,
  type StubCveRecord,
  type StubEpssRow,
  type StubKevEntry,
  type StubPublicationManifest,
  type StubQuarantineEntry,
} from "../../src/lib/ingestion-types";

// ---------------------------------------------------------------------------
// In-test stub importer harness (fixture-driven, no network).
//
// These stubs encode the recovery semantics required by docs/DATA_WORKFLOW.md
// (ingestion/validation/publication, lines 43-101) and docs/research/SOURCES.md
// (delta recovery limits). They fetch nothing and clone nothing: every input is
// an inline fixture using invented CVE-2099 IDs. The real importers (plan todos
// 8-10) must satisfy this same contract suite; the stubs here exist only so the
// contracts are provably green before that implementation lands.
// ---------------------------------------------------------------------------

const CVE_ID_PATTERN = /^CVE-(19|20)\d{2}-\d{4,}$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function isWellFormedTimestamp(value: string): boolean {
  return TIMESTAMP_PATTERN.test(value) && !Number.isNaN(Date.parse(value));
}

function validateCveRecord(record: StubCveRecord): string | null {
  if (!SUPPORTED_CVE_DATA_VERSIONS.includes(record.dataVersion)) {
    return `unsupported dataVersion "${record.dataVersion}"`;
  }
  if (!CVE_ID_PATTERN.test(record.cveId)) {
    return `invalid CVE ID "${record.cveId}"`;
  }
  if (record.datePublished !== undefined && !isWellFormedTimestamp(record.datePublished)) {
    return `malformed datePublished "${record.datePublished}"`;
  }
  if (record.dateUpdated !== undefined && !isWellFormedTimestamp(record.dateUpdated)) {
    return `malformed dateUpdated "${record.dateUpdated}"`;
  }
  return null;
}

interface CveRevisionTree {
  revision: string;
  files: Map<string, StubCveRecord>;
}

function makeTree(revision: string, entries: Array<[string, StubCveRecord]>): CveRevisionTree {
  return { revision, files: new Map(entries) };
}

interface CveImportTransitions {
  added: string[];
  changed: string[];
  deleted: string[];
  rejected: string[];
}

function emptyTransitions(): CveImportTransitions {
  return { added: [], changed: [], deleted: [], rejected: [] };
}

interface CveImportOutcome {
  ok: boolean;
  revision: string;
  reconciledFull: boolean;
  alreadyCurrent: boolean;
  transitions: CveImportTransitions;
  quarantined: StubQuarantineEntry[];
}

interface StubCveStore {
  current: Map<string, StubCveRecord>;
  tombstones: Map<string, { revision: string; reason: string }>;
  checkpoint: string | null;
  lastTree: CveRevisionTree | null;
  lastHealthCheckAt: string | null;
  recordTouchedAt: Map<string, string>;
}

function createCveStore(): StubCveStore {
  return {
    current: new Map(),
    tombstones: new Map(),
    checkpoint: null,
    lastTree: null,
    lastHealthCheckAt: null,
    recordTouchedAt: new Map(),
  };
}

function canonicalTree(tree: CveRevisionTree): string {
  const entries = [...tree.files.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return JSON.stringify({ revision: tree.revision, entries });
}

function publishedIds(store: StubCveStore): string[] {
  return [...store.current.keys()].sort();
}

// Stub CVE revision importer: validate-then-stage-then-publish. Any malformed
// record fails the whole run closed (quarantined, last-known-good preserved);
// the checkpoint advances only on success. `failAfterStaging` is a test-only
// fault hook proving the publish step is atomic.
function importCveRevision(
  store: StubCveStore,
  tree: CveRevisionTree,
  options: { changedPaths: string[] | null; now: string; failAfterStaging?: boolean },
): CveImportOutcome {
  if (
    store.checkpoint === tree.revision &&
    store.lastTree !== null &&
    canonicalTree(store.lastTree) === canonicalTree(tree)
  ) {
    store.lastHealthCheckAt = options.now;
    return {
      ok: true,
      revision: tree.revision,
      reconciledFull: false,
      alreadyCurrent: true,
      transitions: emptyTransitions(),
      quarantined: [],
    };
  }

  const reconciledFull = store.lastTree === null || options.changedPaths === null;
  const scope: string[] = reconciledFull ? [...tree.files.keys()] : (options.changedPaths ?? []);

  const quarantined: StubQuarantineEntry[] = [];
  const deletions: StubCveRecord[] = [];
  const candidates = new Map<string, StubCveRecord>();
  for (const path of scope) {
    const record = tree.files.get(path);
    if (record === undefined) {
      const previous = store.lastTree?.files.get(path);
      if (previous !== undefined) {
        deletions.push(previous);
      }
      continue;
    }
    const reason = validateCveRecord(record);
    if (reason !== null) {
      quarantined.push({ source: "cve", reason, identifier: `${path}:${record.cveId}` });
    } else {
      candidates.set(path, record);
    }
  }
  if (quarantined.length > 0) {
    return {
      ok: false,
      revision: tree.revision,
      reconciledFull,
      alreadyCurrent: false,
      transitions: emptyTransitions(),
      quarantined,
    };
  }

  const staged = reconciledFull ? new Map<string, StubCveRecord>() : new Map(store.current);
  const stagedTombstones = new Map(store.tombstones);
  const transitions = emptyTransitions();

  if (reconciledFull) {
    const previousIds = new Set(store.current.keys());
    const nextIds = new Set<string>();
    for (const record of candidates.values()) {
      nextIds.add(record.cveId);
      if (record.state === "REJECTED") {
        stagedTombstones.set(record.cveId, {
          revision: tree.revision,
          reason: `rejected at ${tree.revision}`,
        });
        if (previousIds.has(record.cveId)) {
          transitions.rejected.push(record.cveId);
        }
        continue;
      }
      staged.set(record.cveId, record);
      const previous = store.current.get(record.cveId);
      if (previous === undefined) {
        transitions.added.push(record.cveId);
      } else if (JSON.stringify(previous) !== JSON.stringify(record)) {
        transitions.changed.push(record.cveId);
      }
    }
    for (const id of previousIds) {
      if (!nextIds.has(id) && !stagedTombstones.has(id)) {
        staged.delete(id);
        stagedTombstones.set(id, {
          revision: tree.revision,
          reason: `deleted at ${tree.revision}`,
        });
        transitions.deleted.push(id);
      }
    }
  } else {
    for (const path of scope) {
      const record = candidates.get(path);
      const previous = store.lastTree?.files.get(path);
      if (record === undefined) {
        if (previous !== undefined && staged.has(previous.cveId)) {
          staged.delete(previous.cveId);
          stagedTombstones.set(previous.cveId, {
            revision: tree.revision,
            reason: `deleted at ${tree.revision}`,
          });
          transitions.deleted.push(previous.cveId);
        }
        continue;
      }
      if (record.state === "REJECTED") {
        staged.delete(record.cveId);
        stagedTombstones.set(record.cveId, {
          revision: tree.revision,
          reason: `rejected at ${tree.revision}`,
        });
        transitions.rejected.push(record.cveId);
        continue;
      }
      if (previous === undefined) {
        staged.set(record.cveId, record);
        transitions.added.push(record.cveId);
      } else if (JSON.stringify(previous) !== JSON.stringify(record)) {
        staged.set(record.cveId, record);
        transitions.changed.push(record.cveId);
      }
    }
  }

  if (options.failAfterStaging === true) {
    throw new Error("stub fault: crash before publish");
  }

  store.current = staged;
  store.tombstones = stagedTombstones;
  store.checkpoint = tree.revision;
  store.lastTree = tree;
  store.lastHealthCheckAt = options.now;
  for (const id of [...transitions.added, ...transitions.changed]) {
    store.recordTouchedAt.set(id, options.now);
  }
  return {
    ok: true,
    revision: tree.revision,
    reconciledFull,
    alreadyCurrent: false,
    transitions,
    quarantined: [],
  };
}

// --- KEV stub ---------------------------------------------------------------

interface KevCatalogFixture {
  catalogVersion: string;
  dateReleased: string;
  declaredCount: number;
  entries: StubKevEntry[];
}

interface KevHistoryRow {
  cveId: string;
  seenIn: string;
  removedIn: string | null;
}

interface StubKevStore {
  current: Map<string, StubKevEntry>;
  history: KevHistoryRow[];
  version: string | null;
  lastError: string | null;
}

function createKevStore(): StubKevStore {
  return { current: new Map(), history: [], version: null, lastError: null };
}

interface KevImportOutcome {
  ok: boolean;
  added: string[];
  removed: string[];
  unmatched: string[];
  error: string | null;
}

// Stub KEV snapshot importer: validate the complete catalog, then replace
// membership atomically. History is append-only; removals flip current
// membership but never erase history.
function importKevCatalog(
  store: StubKevStore,
  catalog: KevCatalogFixture,
  knownCveIds: readonly string[],
): KevImportOutcome {
  const fail = (error: string): KevImportOutcome => {
    store.lastError = error;
    return { ok: false, added: [], removed: [], unmatched: [], error };
  };
  if (!isWellFormedTimestamp(catalog.dateReleased)) {
    return fail(`malformed catalog dateReleased "${catalog.dateReleased}"`);
  }
  if (catalog.entries.length !== catalog.declaredCount) {
    return fail(
      `declared count ${catalog.declaredCount} does not match actual rows ${catalog.entries.length}`,
    );
  }
  const seen = new Set<string>();
  for (const entry of catalog.entries) {
    if (!CVE_ID_PATTERN.test(entry.cveId)) {
      return fail(`invalid KEV CVE ID "${entry.cveId}"`);
    }
    if (!isWellFormedTimestamp(entry.dateAdded)) {
      return fail(`malformed KEV dateAdded "${entry.dateAdded}" for ${entry.cveId}`);
    }
    if (seen.has(entry.cveId)) {
      return fail(`duplicate KEV ID "${entry.cveId}"`);
    }
    seen.add(entry.cveId);
  }

  const previousIds = new Set(store.current.keys());
  const nextIds = new Set(catalog.entries.map((entry) => entry.cveId));
  const added = [...nextIds].filter((id) => !previousIds.has(id)).sort();
  const removed = [...previousIds].filter((id) => !nextIds.has(id)).sort();

  store.current = new Map(catalog.entries.map((entry) => [entry.cveId, entry]));
  for (const id of added) {
    store.history.push({ cveId: id, seenIn: catalog.catalogVersion, removedIn: null });
  }
  for (const id of removed) {
    const row = store.history.find(
      (candidate) => candidate.cveId === id && candidate.removedIn === null,
    );
    if (row !== undefined) {
      row.removedIn = catalog.catalogVersion;
    }
  }
  store.version = catalog.catalogVersion;
  store.lastError = null;
  const known = new Set(knownCveIds);
  const unmatched = [...nextIds].filter((id) => !known.has(id)).sort();
  return { ok: true, added, removed, unmatched, error: null };
}

// --- EPSS stub ---------------------------------------------------------------

interface EpssDailyFixture {
  scoreDate: string;
  modelVersion: string;
  rows: StubEpssRow[];
}

interface EpssDeltaFixture {
  baselineId: string;
  scoreDate: string;
  modelVersion: string;
  rows: StubEpssRow[];
}

interface StubEpssStore {
  acceptedDate: string | null;
  modelVersion: string | null;
  scores: Map<string, number>;
  observations: Map<string, Map<string, number>>;
  modelsByDate: Map<string, string>;
  baselineId: string | null;
  lastError: string | null;
}

function createEpssStore(): StubEpssStore {
  return {
    acceptedDate: null,
    modelVersion: null,
    scores: new Map(),
    observations: new Map(),
    modelsByDate: new Map(),
    baselineId: null,
    lastError: null,
  };
}

function validateEpssRow(row: StubEpssRow): string | null {
  if (!CVE_ID_PATTERN.test(row.cveId)) {
    return `invalid EPSS CVE ID "${row.cveId}"`;
  }
  for (const [name, value] of [
    ["epss", row.epss],
    ["percentile", row.percentile],
  ] as const) {
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
      return `invalid EPSS ${name} ${String(value)} for ${row.cveId}`;
    }
  }
  return null;
}

interface EpssImportOutcome {
  ok: boolean;
  unmatched: string[];
  error: string | null;
}

// Stub EPSS daily importer: validate the complete CSV snapshot, then replace
// scores atomically. Exact source decimals are retained; a missing current row
// is unknown (lookup yields undefined), never zero.
function importEpssDaily(
  store: StubEpssStore,
  daily: EpssDailyFixture,
  knownCveIds: readonly string[],
): EpssImportOutcome {
  const fail = (error: string): EpssImportOutcome => {
    store.lastError = error;
    return { ok: false, unmatched: [], error };
  };
  if (!/^\d{4}-\d{2}-\d{2}$/.test(daily.scoreDate)) {
    return fail(`malformed EPSS scoreDate "${daily.scoreDate}"`);
  }
  const seen = new Set<string>();
  for (const row of daily.rows) {
    const reason = validateEpssRow(row);
    if (reason !== null) {
      return fail(reason);
    }
    if (seen.has(row.cveId)) {
      return fail(`duplicate EPSS ID "${row.cveId}"`);
    }
    seen.add(row.cveId);
  }
  store.scores = new Map(daily.rows.map((row) => [row.cveId, row.epss]));
  for (const row of daily.rows) {
    const perId = store.observations.get(row.cveId) ?? new Map<string, number>();
    perId.set(daily.scoreDate, row.epss);
    store.observations.set(row.cveId, perId);
  }
  store.modelsByDate.set(daily.scoreDate, daily.modelVersion);
  store.acceptedDate = daily.scoreDate;
  store.modelVersion = daily.modelVersion;
  store.baselineId = `${daily.scoreDate}@${daily.modelVersion}`;
  store.lastError = null;
  const known = new Set(knownCveIds);
  return { ok: true, unmatched: [...seen].filter((id) => !known.has(id)).sort(), error: null };
}

// Stub hourly-delta applier: a delta is cumulative since one dated baseline and
// may only apply on its matching established baseline with the same model.
// Day rollover, missed days, expired history, and model transitions are
// rejected — recovery requires a fresh complete baseline, never interpolation.
function applyEpssDelta(
  store: StubEpssStore,
  delta: EpssDeltaFixture,
): { ok: boolean; error: string | null } {
  if (store.baselineId === null) {
    return { ok: false, error: "no established baseline: fetch a fresh complete baseline first" };
  }
  if (delta.baselineId !== store.baselineId) {
    return {
      ok: false,
      error: `baseline mismatch: delta is since ${delta.baselineId} but established baseline is ${store.baselineId}`,
    };
  }
  if (store.modelVersion !== null && delta.modelVersion !== store.modelVersion) {
    return {
      ok: false,
      error: `model transition ${store.modelVersion} to ${delta.modelVersion}: ineligible, no cross-model comparison`,
    };
  }
  for (const row of delta.rows) {
    const reason = validateEpssRow(row);
    if (reason !== null) {
      store.lastError = reason;
      return { ok: false, error: reason };
    }
  }
  for (const row of delta.rows) {
    store.scores.set(row.cveId, row.epss);
  }
  return { ok: true, error: null };
}

// Missing current row is unknown (undefined); a real zero stays a known zero.
function lookupEpss(store: StubEpssStore, cveId: string): number | undefined {
  return store.scores.get(cveId);
}

// Rising-forecast eligibility needs observations on exactly d and d-7 under one
// model. Anything else (gap day, model change) is ineligible, never zero-filled.
function isRisingEligible(
  store: StubEpssStore,
  cveId: string,
  currentDate: string,
  daysBackDate: string,
): boolean {
  const perId = store.observations.get(cveId);
  if (perId === undefined) {
    return false;
  }
  if (perId.get(currentDate) === undefined || perId.get(daysBackDate) === undefined) {
    return false;
  }
  return store.modelsByDate.get(currentDate) === store.modelsByDate.get(daysBackDate);
}

// --- Publication stub --------------------------------------------------------

function buildPublicationManifest(args: {
  cveRevision: string | null;
  kevVersion: string | null;
  epssDate: string | null;
  previous: StubPublicationManifest;
  failed: Record<IngestionSourceName, string | null>;
}): {
  manifest: StubPublicationManifest;
  published: boolean;
  stale: Record<IngestionSourceName, string | null>;
} {
  const manifest: StubPublicationManifest = {
    cveRevision:
      args.failed.cve !== null
        ? args.previous.cveRevision
        : (args.cveRevision ?? args.previous.cveRevision),
    kevVersion:
      args.failed.kev !== null
        ? args.previous.kevVersion
        : (args.kevVersion ?? args.previous.kevVersion),
    epssDate:
      args.failed.epss !== null
        ? args.previous.epssDate
        : (args.epssDate ?? args.previous.epssDate),
  };
  const published =
    manifest.cveRevision !== null && manifest.kevVersion !== null && manifest.epssDate !== null;
  return { manifest, published, stale: args.failed };
}

function emptyManifest(): StubPublicationManifest {
  return { cveRevision: null, kevVersion: null, epssDate: null };
}

function noFailures(): Record<IngestionSourceName, string | null> {
  return { cve: null, kev: null, epss: null };
}

// ---------------------------------------------------------------------------
// Fixture builders (invented CVE-2099 IDs; no network, no upstream clones).
// ---------------------------------------------------------------------------

function publishedRecord(cveId: string, datePublished: string, dataVersion = "5.1"): StubCveRecord {
  return { cveId, dataVersion, state: "PUBLISHED", datePublished };
}

function kevEntry(cveId: string, dateAdded = "2026-10-20T00:00:00.000Z"): StubKevEntry {
  return { cveId, dateAdded };
}

function epssRow(cveId: string, epss: number, percentile = 0.5): StubEpssRow {
  return { cveId, epss, percentile };
}

// ===========================================================================
// CVE ingestion contracts (DATA_WORKFLOW.md 43-64, 82-101)
// ===========================================================================

describe("CVE ingestion contracts", () => {
  it("reimporting the same revision is idempotent: no duplicates, health updated, record dates untouched", () => {
    const store = createCveStore();
    const tree = makeTree("rev-a", [
      [
        "cves/2026/0xxx/CVE-2099-0001.json",
        publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
      ],
      [
        "cves/2026/0xxx/CVE-2099-0002.json",
        publishedRecord("CVE-2099-0002", "2026-10-21T00:00:00.000Z"),
      ],
    ]);
    const first = importCveRevision(store, tree, {
      changedPaths: null,
      now: "2026-10-22T00:00:00.000Z",
    });
    expect(first.ok).toBe(true);
    expect(first.reconciledFull).toBe(true);
    const touchedBefore = new Map(store.recordTouchedAt);

    const second = importCveRevision(store, tree, {
      changedPaths: null,
      now: "2026-10-23T00:00:00.000Z",
    });
    expect(second.ok).toBe(true);
    expect(second.alreadyCurrent).toBe(true);
    expect(second.transitions).toEqual(emptyTransitions());
    expect(publishedIds(store)).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
    expect(store.checkpoint).toBe("rev-a");
    expect(store.lastHealthCheckAt).toBe("2026-10-23T00:00:00.000Z");
    expect(new Map(store.recordTouchedAt)).toEqual(touchedBefore);
  });

  it("applies added, changed, and deleted paths from a changed-path diff", () => {
    const store = createCveStore();
    const revA = makeTree("rev-a", [
      [
        "cves/2026/0xxx/CVE-2099-0001.json",
        publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
      ],
      [
        "cves/2026/0xxx/CVE-2099-0002.json",
        publishedRecord("CVE-2099-0002", "2026-10-20T00:00:00.000Z"),
      ],
      [
        "cves/2026/0xxx/CVE-2099-0003.json",
        publishedRecord("CVE-2099-0003", "2026-10-20T00:00:00.000Z"),
      ],
    ]);
    expect(
      importCveRevision(store, revA, { changedPaths: null, now: "2026-10-21T00:00:00.000Z" }).ok,
    ).toBe(true);

    const revB = makeTree("rev-b", [
      [
        "cves/2026/0xxx/CVE-2099-0001.json",
        publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
      ],
      [
        "cves/2026/0xxx/CVE-2099-0002.json",
        {
          ...publishedRecord("CVE-2099-0002", "2026-10-20T00:00:00.000Z"),
          dateUpdated: "2026-10-22T00:00:00.000Z",
        },
      ],
      [
        "cves/2026/0xxx/CVE-2099-0004.json",
        publishedRecord("CVE-2099-0004", "2026-10-22T00:00:00.000Z"),
      ],
    ]);
    const outcome = importCveRevision(store, revB, {
      changedPaths: [
        "cves/2026/0xxx/CVE-2099-0002.json",
        "cves/2026/0xxx/CVE-2099-0003.json",
        "cves/2026/0xxx/CVE-2099-0004.json",
      ],
      now: "2026-10-22T01:00:00.000Z",
    });
    expect(outcome.ok).toBe(true);
    expect(outcome.reconciledFull).toBe(false);
    expect(outcome.transitions.added).toEqual(["CVE-2099-0004"]);
    expect(outcome.transitions.changed).toEqual(["CVE-2099-0002"]);
    expect(outcome.transitions.deleted).toEqual(["CVE-2099-0003"]);
    expect(publishedIds(store)).toEqual(["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0004"]);
    expect(store.tombstones.get("CVE-2099-0003")).toEqual({
      revision: "rev-b",
      reason: "deleted at rev-b",
    });
    expect(store.checkpoint).toBe("rev-b");
  });

  it("rejected records leave ordinary lists and counts but keep provenance tombstones", () => {
    const store = createCveStore();
    const revA = makeTree("rev-a", [
      [
        "cves/2026/0xxx/CVE-2099-0001.json",
        publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
      ],
      [
        "cves/2026/0xxx/CVE-2099-0002.json",
        publishedRecord("CVE-2099-0002", "2026-10-20T00:00:00.000Z"),
      ],
    ]);
    expect(
      importCveRevision(store, revA, { changedPaths: null, now: "2026-10-21T00:00:00.000Z" }).ok,
    ).toBe(true);

    const revB = makeTree("rev-b", [
      [
        "cves/2026/0xxx/CVE-2099-0001.json",
        publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
      ],
      [
        "cves/2026/0xxx/CVE-2099-0002.json",
        { ...publishedRecord("CVE-2099-0002", "2026-10-20T00:00:00.000Z"), state: "REJECTED" },
      ],
    ]);
    const outcome = importCveRevision(store, revB, {
      changedPaths: ["cves/2026/0xxx/CVE-2099-0002.json"],
      now: "2026-10-22T00:00:00.000Z",
    });
    expect(outcome.ok).toBe(true);
    expect(outcome.transitions.rejected).toEqual(["CVE-2099-0002"]);
    expect(publishedIds(store)).toEqual(["CVE-2099-0001"]);
    expect(store.tombstones.get("CVE-2099-0002")).toEqual({
      revision: "rev-b",
      reason: "rejected at rev-b",
    });
  });

  it("missing history forces a full reconcile, never a partial changed-file publish", () => {
    const store = createCveStore();
    const revA = makeTree("rev-a", [
      [
        "cves/2026/0xxx/CVE-2099-0001.json",
        publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
      ],
    ]);
    expect(
      importCveRevision(store, revA, { changedPaths: null, now: "2026-10-21T00:00:00.000Z" }).ok,
    ).toBe(true);

    // Continuity cannot be established (no usable previous revision): the
    // importer must reconcile the complete pinned tree.
    const revC = makeTree("rev-c", [
      [
        "cves/2026/0xxx/CVE-2099-0001.json",
        publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
      ],
      [
        "cves/2026/0xxx/CVE-2099-0009.json",
        publishedRecord("CVE-2099-0009", "2026-10-23T00:00:00.000Z"),
      ],
    ]);
    const outcome = importCveRevision(store, revC, {
      changedPaths: null,
      now: "2026-10-24T00:00:00.000Z",
    });
    expect(outcome.ok).toBe(true);
    expect(outcome.reconciledFull).toBe(true);
    expect(publishedIds(store)).toEqual(["CVE-2099-0001", "CVE-2099-0009"]);
    expect(store.checkpoint).toBe("rev-c");
  });

  it("quarantines an unsupported dataVersion: never published, checkpoint not advanced", () => {
    const store = createCveStore();
    const revA = makeTree("rev-a", [
      [
        "cves/2026/0xxx/CVE-2099-0001.json",
        publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
      ],
    ]);
    expect(
      importCveRevision(store, revA, { changedPaths: null, now: "2026-10-21T00:00:00.000Z" }).ok,
    ).toBe(true);

    const revB = makeTree("rev-b", [
      [
        "cves/2026/0xxx/CVE-2099-0001.json",
        publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
      ],
      [
        "cves/2026/0xxx/CVE-2099-0002.json",
        publishedRecord("CVE-2099-0002", "2026-10-22T00:00:00.000Z", "4.0"),
      ],
    ]);
    const outcome = importCveRevision(store, revB, {
      changedPaths: ["cves/2026/0xxx/CVE-2099-0002.json"],
      now: "2026-10-22T01:00:00.000Z",
    });
    expect(outcome.ok).toBe(false);
    expect(outcome.quarantined).toHaveLength(1);
    expect(outcome.quarantined[0]?.reason).toMatch(/unsupported dataVersion/);
    expect(publishedIds(store)).toEqual(["CVE-2099-0001"]);
    expect(store.checkpoint).toBe("rev-a");
  });

  it("quarantines an invalid CVE ID and never publishes it", () => {
    const store = createCveStore();
    const tree = makeTree("rev-a", [
      ["cves/2026/0xxx/NOTACVE.json", publishedRecord("NOTACVE", "2026-10-20T00:00:00.000Z")],
    ]);
    const outcome = importCveRevision(store, tree, {
      changedPaths: null,
      now: "2026-10-21T00:00:00.000Z",
    });
    expect(outcome.ok).toBe(false);
    expect(outcome.quarantined).toHaveLength(1);
    expect(outcome.quarantined[0]?.reason).toMatch(/invalid CVE ID/);
    expect(publishedIds(store)).toEqual([]);
    expect(store.checkpoint).toBe(null);
  });

  it("quarantines malformed present timestamps while absent optional dates stay unknown", () => {
    const store = createCveStore();
    const bad = makeTree("rev-bad", [
      ["cves/2026/0xxx/CVE-2099-0001.json", publishedRecord("CVE-2099-0001", "October 20th, 2026")],
    ]);
    const rejected = importCveRevision(store, bad, {
      changedPaths: null,
      now: "2026-10-21T00:00:00.000Z",
    });
    expect(rejected.ok).toBe(false);
    expect(rejected.quarantined[0]?.reason).toMatch(/malformed datePublished/);
    expect(publishedIds(store)).toEqual([]);

    const undated: StubCveRecord = {
      cveId: "CVE-2099-0002",
      dataVersion: "5.0",
      state: "PUBLISHED",
    };
    const good = makeTree("rev-good", [["cves/2026/0xxx/CVE-2099-0002.json", undated]]);
    const accepted = importCveRevision(store, good, {
      changedPaths: null,
      now: "2026-10-22T00:00:00.000Z",
    });
    expect(accepted.ok).toBe(true);
    expect(publishedIds(store)).toEqual(["CVE-2099-0002"]);
    expect(store.current.get("CVE-2099-0002")?.datePublished).toBeUndefined();
  });

  it("rejects a partial publish: a crash after staging leaves dataset and checkpoint unchanged", () => {
    const store = createCveStore();
    const revA = makeTree("rev-a", [
      [
        "cves/2026/0xxx/CVE-2099-0001.json",
        publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
      ],
    ]);
    expect(
      importCveRevision(store, revA, { changedPaths: null, now: "2026-10-21T00:00:00.000Z" }).ok,
    ).toBe(true);

    const revB = makeTree("rev-b", [
      [
        "cves/2026/0xxx/CVE-2099-0001.json",
        publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
      ],
      [
        "cves/2026/0xxx/CVE-2099-0002.json",
        publishedRecord("CVE-2099-0002", "2026-10-22T00:00:00.000Z"),
      ],
    ]);
    expect(() =>
      importCveRevision(store, revB, {
        changedPaths: ["cves/2026/0xxx/CVE-2099-0002.json"],
        now: "2026-10-22T01:00:00.000Z",
        failAfterStaging: true,
      }),
    ).toThrow(/crash before publish/);
    expect(publishedIds(store)).toEqual(["CVE-2099-0001"]);
    expect(store.checkpoint).toBe("rev-a");
  });
});

// ===========================================================================
// KEV ingestion contracts (DATA_WORKFLOW.md 66-80)
// ===========================================================================

describe("KEV ingestion contracts", () => {
  it("replaces membership atomically and preserves history across removals", () => {
    const cve = createCveStore();
    const kev = createKevStore();
    const first = importKevCatalog(
      kev,
      {
        catalogVersion: "2026.10.20",
        dateReleased: "2026-10-20T19:30:00.000Z",
        declaredCount: 2,
        entries: [kevEntry("CVE-2099-0001"), kevEntry("CVE-2099-0002")],
      },
      publishedIds(cve),
    );
    expect(first.ok).toBe(true);
    expect(first.added).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);

    const second = importKevCatalog(
      kev,
      {
        catalogVersion: "2026.10.21",
        dateReleased: "2026-10-21T19:30:00.000Z",
        declaredCount: 2,
        entries: [kevEntry("CVE-2099-0002"), kevEntry("CVE-2099-0003")],
      },
      publishedIds(cve),
    );
    expect(second.ok).toBe(true);
    expect(second.added).toEqual(["CVE-2099-0003"]);
    expect(second.removed).toEqual(["CVE-2099-0001"]);
    expect([...kev.current.keys()].sort()).toEqual(["CVE-2099-0002", "CVE-2099-0003"]);
    const removedRow = kev.history.find((row) => row.cveId === "CVE-2099-0001");
    expect(removedRow).toEqual({
      cveId: "CVE-2099-0001",
      seenIn: "2026.10.20",
      removedIn: "2026.10.21",
    });
    expect(kev.version).toBe("2026.10.21");
  });

  it("aborts on declared/actual count mismatch with last-known-good intact", () => {
    const cve = createCveStore();
    const kev = createKevStore();
    const good = importKevCatalog(
      kev,
      {
        catalogVersion: "2026.10.20",
        dateReleased: "2026-10-20T19:30:00.000Z",
        declaredCount: 1,
        entries: [kevEntry("CVE-2099-0001")],
      },
      publishedIds(cve),
    );
    expect(good.ok).toBe(true);

    const bad = importKevCatalog(
      kev,
      {
        catalogVersion: "2026.10.21",
        dateReleased: "2026-10-21T19:30:00.000Z",
        declaredCount: 3,
        entries: [kevEntry("CVE-2099-0001"), kevEntry("CVE-2099-0002")],
      },
      publishedIds(cve),
    );
    expect(bad.ok).toBe(false);
    expect(bad.error).toMatch(/declared count/);
    expect([...kev.current.keys()]).toEqual(["CVE-2099-0001"]);
    expect(kev.version).toBe("2026.10.20");
    expect(kev.lastError).toMatch(/declared count/);
  });

  it("reports unmatched KEV IDs without manufacturing CVE records", () => {
    const cve = createCveStore();
    expect(
      importCveRevision(
        cve,
        makeTree("rev-a", [
          [
            "cves/2026/0xxx/CVE-2099-0001.json",
            publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
          ],
        ]),
        { changedPaths: null, now: "2026-10-21T00:00:00.000Z" },
      ).ok,
    ).toBe(true);
    const kev = createKevStore();
    const outcome = importKevCatalog(
      kev,
      {
        catalogVersion: "2026.10.20",
        dateReleased: "2026-10-20T19:30:00.000Z",
        declaredCount: 2,
        entries: [kevEntry("CVE-2099-0001"), kevEntry("CVE-2099-0777")],
      },
      publishedIds(cve),
    );
    expect(outcome.ok).toBe(true);
    expect(outcome.unmatched).toEqual(["CVE-2099-0777"]);
    expect(publishedIds(cve)).toEqual(["CVE-2099-0001"]);
  });
});

// ===========================================================================
// EPSS ingestion contracts (DATA_WORKFLOW.md 66-80, SOURCES.md 66-75)
// ===========================================================================

describe("EPSS ingestion contracts", () => {
  it("pairs a day-rollover delta with its matching baseline; a new day needs a new baseline", () => {
    const store = createEpssStore();
    const dayOne = importEpssDaily(
      store,
      {
        scoreDate: "2026-10-22",
        modelVersion: "v2026.06.15",
        rows: [epssRow("CVE-2099-0001", 0.1, 0.8)],
      },
      [],
    );
    expect(dayOne.ok).toBe(true);

    const sameDayDelta = applyEpssDelta(store, {
      baselineId: "2026-10-22@v2026.06.15",
      scoreDate: "2026-10-22",
      modelVersion: "v2026.06.15",
      rows: [epssRow("CVE-2099-0001", 0.12, 0.82)],
    });
    expect(sameDayDelta.ok).toBe(true);
    expect(lookupEpss(store, "CVE-2099-0001")).toBe(0.12);

    const rolloverDelta = applyEpssDelta(store, {
      baselineId: "2026-10-23@v2026.06.15",
      scoreDate: "2026-10-23",
      modelVersion: "v2026.06.15",
      rows: [epssRow("CVE-2099-0001", 0.2, 0.9)],
    });
    expect(rolloverDelta.ok).toBe(false);
    expect(rolloverDelta.error).toMatch(/baseline mismatch/);
    expect(lookupEpss(store, "CVE-2099-0001")).toBe(0.12);

    const freshBaseline = importEpssDaily(
      store,
      {
        scoreDate: "2026-10-23",
        modelVersion: "v2026.06.15",
        rows: [epssRow("CVE-2099-0001", 0.2, 0.9)],
      },
      [],
    );
    expect(freshBaseline.ok).toBe(true);
    expect(lookupEpss(store, "CVE-2099-0001")).toBe(0.2);
  });

  it("recovers missed days and expired history via a fresh baseline, never interpolation", () => {
    const store = createEpssStore();
    expect(
      importEpssDaily(
        store,
        {
          scoreDate: "2026-10-16",
          modelVersion: "v2026.06.15",
          rows: [epssRow("CVE-2099-0001", 0.1)],
        },
        [],
      ).ok,
    ).toBe(true);
    expect(
      importEpssDaily(
        store,
        {
          scoreDate: "2026-10-23",
          modelVersion: "v2026.06.15",
          rows: [epssRow("CVE-2099-0001", 0.18)],
        },
        [],
      ).ok,
    ).toBe(true);

    expect(isRisingEligible(store, "CVE-2099-0001", "2026-10-23", "2026-10-16")).toBe(true);
    expect(isRisingEligible(store, "CVE-2099-0001", "2026-10-23", "2026-10-15")).toBe(false);
  });

  it("treats cross-model comparisons as ineligible, never a spike", () => {
    const store = createEpssStore();
    expect(
      importEpssDaily(
        store,
        {
          scoreDate: "2026-10-16",
          modelVersion: "v2026.06.15",
          rows: [epssRow("CVE-2099-0001", 0.1)],
        },
        [],
      ).ok,
    ).toBe(true);
    expect(
      importEpssDaily(
        store,
        {
          scoreDate: "2026-10-23",
          modelVersion: "v2027.01.01",
          rows: [epssRow("CVE-2099-0001", 0.8)],
        },
        [],
      ).ok,
    ).toBe(true);
    expect(isRisingEligible(store, "CVE-2099-0001", "2026-10-23", "2026-10-16")).toBe(false);

    const crossModelDelta = applyEpssDelta(store, {
      baselineId: "2026-10-23@v2027.01.01",
      scoreDate: "2026-10-23",
      modelVersion: "v2026.06.15",
      rows: [epssRow("CVE-2099-0001", 0.9)],
    });
    expect(crossModelDelta.ok).toBe(false);
    expect(crossModelDelta.error).toMatch(/model transition/);
  });

  it("keeps a missing current row unknown while a real zero stays known", () => {
    const store = createEpssStore();
    expect(
      importEpssDaily(
        store,
        {
          scoreDate: "2026-10-23",
          modelVersion: "v2026.06.15",
          rows: [epssRow("CVE-2099-0001", 0, 0.05)],
        },
        [],
      ).ok,
    ).toBe(true);
    expect(lookupEpss(store, "CVE-2099-0001")).toBe(0);
    expect(lookupEpss(store, "CVE-2099-0002")).toBeUndefined();
  });

  it("reports unmatched EPSS IDs without manufacturing CVE records", () => {
    const cve = createCveStore();
    expect(
      importCveRevision(
        cve,
        makeTree("rev-a", [
          [
            "cves/2026/0xxx/CVE-2099-0001.json",
            publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
          ],
        ]),
        { changedPaths: null, now: "2026-10-21T00:00:00.000Z" },
      ).ok,
    ).toBe(true);
    const store = createEpssStore();
    const outcome = importEpssDaily(
      store,
      {
        scoreDate: "2026-10-23",
        modelVersion: "v2026.06.15",
        rows: [epssRow("CVE-2099-0001", 0.5), epssRow("CVE-2099-0777", 0.7)],
      },
      publishedIds(cve),
    );
    expect(outcome.ok).toBe(true);
    expect(outcome.unmatched).toEqual(["CVE-2099-0777"]);
    expect(publishedIds(cve)).toEqual(["CVE-2099-0001"]);
  });

  it("fails a malformed daily file with last-known-good preserved", () => {
    const store = createEpssStore();
    expect(
      importEpssDaily(
        store,
        {
          scoreDate: "2026-10-22",
          modelVersion: "v2026.06.15",
          rows: [epssRow("CVE-2099-0001", 0.1)],
        },
        [],
      ).ok,
    ).toBe(true);

    const outOfRange = importEpssDaily(
      store,
      {
        scoreDate: "2026-10-23",
        modelVersion: "v2026.06.15",
        rows: [epssRow("CVE-2099-0001", 1.5)],
      },
      [],
    );
    expect(outOfRange.ok).toBe(false);
    expect(outOfRange.error).toMatch(/invalid EPSS epss/);
    expect(store.acceptedDate).toBe("2026-10-22");
    expect(lookupEpss(store, "CVE-2099-0001")).toBe(0.1);

    const duplicated = importEpssDaily(
      store,
      {
        scoreDate: "2026-10-23",
        modelVersion: "v2026.06.15",
        rows: [epssRow("CVE-2099-0002", 0.2), epssRow("CVE-2099-0002", 0.3)],
      },
      [],
    );
    expect(duplicated.ok).toBe(false);
    expect(duplicated.error).toMatch(/duplicate EPSS ID/);
    expect(store.acceptedDate).toBe("2026-10-22");
  });
});

// ===========================================================================
// Publication contracts (DATA_WORKFLOW.md 90-101)
// ===========================================================================

describe("publication contracts", () => {
  it("advances valid sources while a failed source keeps last-known-good plus a stale flag", () => {
    const previous: StubPublicationManifest = {
      cveRevision: "rev-a",
      kevVersion: "2026.10.20",
      epssDate: "2026-10-22",
    };
    const { manifest, published, stale } = buildPublicationManifest({
      cveRevision: "rev-b",
      kevVersion: "2026.10.21",
      epssDate: "2026-10-23",
      previous,
      failed: { ...noFailures(), epss: "truncated CSV: import aborted" },
    });
    expect(published).toBe(true);
    expect(manifest).toEqual({
      cveRevision: "rev-b",
      kevVersion: "2026.10.21",
      epssDate: "2026-10-22",
    });
    expect(stale).toEqual({ cve: null, kev: null, epss: "truncated CSV: import aborted" });
  });

  it("requires an accepted snapshot of each core source before initial publication", () => {
    const { manifest, published } = buildPublicationManifest({
      cveRevision: "rev-a",
      kevVersion: "2026.10.20",
      epssDate: null,
      previous: emptyManifest(),
      failed: noFailures(),
    });
    expect(published).toBe(false);
    expect(manifest.epssDate).toBe(null);
  });

  it("a failed refresh preserves last-known-good data explicitly, without freezing valid feeds", () => {
    const cve = createCveStore();
    const epss = createEpssStore();
    expect(
      importCveRevision(
        cve,
        makeTree("rev-a", [
          [
            "cves/2026/0xxx/CVE-2099-0001.json",
            publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
          ],
        ]),
        { changedPaths: null, now: "2026-10-21T00:00:00.000Z" },
      ).ok,
    ).toBe(true);
    expect(
      importEpssDaily(
        epss,
        {
          scoreDate: "2026-10-22",
          modelVersion: "v2026.06.15",
          rows: [epssRow("CVE-2099-0001", 0.1)],
        },
        publishedIds(cve),
      ).ok,
    ).toBe(true);

    // CVE refresh succeeds while the EPSS refresh fails: CVE advances, EPSS
    // keeps serving its last-known-good snapshot with an explicit error.
    expect(
      importCveRevision(
        cve,
        makeTree("rev-b", [
          [
            "cves/2026/0xxx/CVE-2099-0001.json",
            publishedRecord("CVE-2099-0001", "2026-10-20T00:00:00.000Z"),
          ],
          [
            "cves/2026/0xxx/CVE-2099-0002.json",
            publishedRecord("CVE-2099-0002", "2026-10-23T00:00:00.000Z"),
          ],
        ]),
        {
          changedPaths: ["cves/2026/0xxx/CVE-2099-0002.json"],
          now: "2026-10-23T01:00:00.000Z",
        },
      ).ok,
    ).toBe(true);
    const failedEpss = importEpssDaily(
      epss,
      {
        scoreDate: "2026-10-23",
        modelVersion: "v2026.06.15",
        rows: [{ cveId: "CVE-2099-0001", epss: Number.NaN, percentile: 0.5 }],
      },
      publishedIds(cve),
    );
    expect(failedEpss.ok).toBe(false);

    expect(cve.checkpoint).toBe("rev-b");
    expect(publishedIds(cve)).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
    expect(epss.acceptedDate).toBe("2026-10-22");
    expect(lookupEpss(epss, "CVE-2099-0001")).toBe(0.1);
    expect(epss.lastError).toMatch(/invalid EPSS epss/);

    const { manifest, published } = buildPublicationManifest({
      cveRevision: cve.checkpoint,
      kevVersion: "2026.10.20",
      epssDate: epss.acceptedDate,
      previous: { cveRevision: "rev-a", kevVersion: "2026.10.20", epssDate: "2026-10-22" },
      failed: {
        ...noFailures(),
        epss: epss.lastError,
      },
    });
    expect(published).toBe(true);
    expect(manifest.cveRevision).toBe("rev-b");
    expect(manifest.epssDate).toBe("2026-10-22");
  });
});
